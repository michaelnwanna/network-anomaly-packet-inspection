#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <nlohmann/json.hpp>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <sqlite3.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <vector>
#include <fcntl.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "embedded.hpp"

namespace net = boost::asio;
namespace ssl = net::ssl;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = net::ip::tcp;
using json = nlohmann::json;
using Clock = std::chrono::steady_clock;
using Error = boost::system::error_code;
namespace fs = std::filesystem;

static volatile std::sig_atomic_t interrupted = 0;
static void on_signal(int) { interrupted = 1; }
static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}
static void require(bool good, const std::string& message) {
    if (!good) throw std::runtime_error(message);
}
static std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return value;
}
static std::string normalize(std::string value) {
    value = lower(value);
    if (!value.empty() && value.back() == '.') value.pop_back();
    return value;
}
static bool suffix(const std::string& value, const std::string& end) {
    return value.size() >= end.size() && value.compare(value.size()-end.size(), end.size(), end) == 0;
}
static std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> result;
    std::stringstream in(value);
    std::string part;
    while (std::getline(in, part, delimiter)) result.push_back(part);
    return result;
}
static bool valid_domain(const std::string& host) {
    Error ec;
    net::ip::make_address(host, ec);
    if (!ec || host.empty() || host.size() > 253) return false;
    for (const auto& label : split(host, '.')) {
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return false;
        for (char c : label) if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-') return false;
    }
    return host.back() != '.';
}
static int64_t integer(const std::string& text, int64_t min, int64_t max) {
    require(!text.empty() && std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; }),
            "invalid integer");
    size_t used = 0;
    auto value = std::stoll(text, &used);
    require(used == text.size() && value >= min && value <= max, "integer outside permitted range");
    return value;
}
struct Authority {
    std::string host;
    int port;
    std::string text() const {
        return (host.find(':') == std::string::npos ? host : "["+host+"]")+":"+std::to_string(port);
    }
};
static Authority authority(const std::string& input, int default_port = 0, bool allow_zero = false) {
    require(!input.empty() && input.find_first_of("/?#@\\ \r\n\t") == std::string::npos, "invalid authority");
    std::string host, port;
    if (input.front() == '[') {
        auto end = input.find(']');
        require(end != std::string::npos, "invalid IPv6 authority");
        host = input.substr(1, end-1);
        Error ec;
        require(net::ip::make_address(host, ec).is_v6() && !ec, "invalid IPv6 address");
        if (end+1 < input.size()) {
            require(input[end+1] == ':', "invalid authority");
            port = input.substr(end+2);
        }
    } else {
        auto colon = input.find(':');
        if (colon != std::string::npos) {
            require(input.find(':', colon+1) == std::string::npos, "IPv6 needs brackets");
            host = input.substr(0, colon);
            port = input.substr(colon+1);
        } else host = input;
    }
    host = normalize(host);
    Error ec;
    net::ip::make_address(host, ec);
    require(!ec || valid_domain(host), "invalid destination host");
    int p = port.empty() ? default_port : static_cast<int>(integer(port, allow_zero ? 0 : 1, 65535));
    require(p > 0 || allow_zero, "port required");
    return {host,p};
}
struct Rules {
    json rules;
    explicit Rules(const std::string& data) {
        require(data.size() <= 1048576, "rules exceed 1 MiB");
        rules = json::parse(data);
        require(rules.is_object() && rules.size() == 3 && rules.contains("tracking_domains") &&
            rules.contains("allowed_ports") && rules.contains("large_payload_bytes"), "invalid rules fields");
        require(rules["tracking_domains"].is_array() && rules["allowed_ports"].is_array() &&
            !rules["allowed_ports"].empty() && rules["large_payload_bytes"].is_number_integer() &&
            rules["large_payload_bytes"].get<int64_t>() > 0, "invalid rules");
        for (auto& d : rules["tracking_domains"]) {
            require(d.is_string(), "invalid tracking domain");
            d = normalize(d.get<std::string>());
            require(valid_domain(d.get<std::string>()), "invalid tracking domain");
        }
        for (const auto& p : rules["allowed_ports"])
            require(p.is_number_integer() && p.get<int>() >= 1 && p.get<int>() <= 65535, "invalid allowed port");
    }
    json flags(const std::string& host, int port, int64_t sent, int64_t received) const {
        json result = json::array();
        for (const auto& d : rules["tracking_domains"]) {
            auto domain = d.get<std::string>();
            if (normalize(host) == domain || suffix(normalize(host), "."+domain)) {
                result.push_back("known-tracker"); break;
            }
        }
        int64_t threshold = rules["large_payload_bytes"];
        if (sent > threshold || received > threshold-sent) result.push_back("large-payload");
        bool allowed = false;
        for (const auto& p : rules["allowed_ports"]) if (p == port) allowed = true;
        if (!allowed) result.push_back("unsanctioned-port");
        return result;
    }
};
static std::vector<std::string> parse_scope(const std::string& value) {
    if (value.empty()) return {};
    std::vector<std::string> result;
    for (auto pattern : split(value, ',')) {
        auto begin = pattern.find_first_not_of(" \t");
        auto end = pattern.find_last_not_of(" \t");
        require(begin != std::string::npos, "empty inspection pattern");
        pattern = normalize(pattern.substr(begin,end-begin+1));
        auto base = pattern.rfind("*.",0) == 0 ? pattern.substr(2) : pattern;
        Error ec;
        net::ip::make_address(base,ec);
        require(valid_domain(base) || (!ec && base == pattern), "invalid inspection pattern");
        result.push_back(pattern);
    }
    require(value.back() != ',', "empty inspection pattern");
    return result;
}
static bool matches(const std::vector<std::string>& scope, const std::string& host) {
    for (const auto& p : scope)
        if (normalize(host) == p || (p.rfind("*.",0) == 0 && suffix(normalize(host),p.substr(1)))) return true;
    return false;
}
static int64_t duration_ms(const std::string& input) {
    double seconds = 0;
    size_t pos = 0;
    while (pos < input.size()) {
        auto start = pos;
        while (pos < input.size() && (std::isdigit(static_cast<unsigned char>(input[pos])) || input[pos] == '.')) ++pos;
        require(pos > start, "invalid duration");
        double value = std::stod(input.substr(start,pos-start));
        auto unit = pos;
        while (pos < input.size() && std::isalpha(static_cast<unsigned char>(input[pos]))) ++pos;
        auto u = input.substr(unit,pos-unit);
        double multiplier = u == "h" ? 3600 : u == "m" ? 60 : u == "s" ? 1 : u == "ms" ? .001 : 0;
        require(multiplier > 0, "duration units: h, m, s, ms");
        seconds += value*multiplier;
    }
    require(seconds > 0 && seconds <= 315360000, "invalid retention duration");
    return static_cast<int64_t>(seconds*1000);
}
struct Options {
    std::string listen = "127.0.0.1:8080", dashboard = "127.0.0.1:9090", dir = "./data-cpp";
    std::string rules_file, upstream_ca;
    std::vector<std::string> scope;
    int64_t max_records = 1000000, max_age = 604800000;
    int queue_size = 8192, max_active = 256;
    bool allow_private = false;
    std::string age_text() const {
        auto seconds = max_age/1000;
        return std::to_string(seconds/3600)+"h"+std::to_string(seconds%3600/60)+"m"+
            std::to_string(seconds%60)+"s";
    }
};
static std::string read_file(const fs::path& file, size_t limit = 1048576) {
    std::ifstream in(file, std::ios::binary);
    require(in.good(), "cannot open file: "+file.string());
    std::string data;
    std::array<char,8192> buffer{};
    while (in) {
        in.read(buffer.data(), buffer.size());
        data.append(buffer.data(), static_cast<size_t>(in.gcount()));
        require(data.size() <= limit, "file exceeds size limit");
    }
    return data;
}
static Options parse_options(int argc, char** argv, int start, bool ca) {
    Options o;
    for (int i=start; i<argc; ++i) {
        std::string key = argv[i];
        require(key.rfind("-",0) == 0, "unexpected positional argument");
        key.erase(0, key.rfind("--",0) == 0 ? 2 : 1);
        auto eq = key.find('=');
        std::string value;
        if (eq != std::string::npos) { value = key.substr(eq+1); key.resize(eq); }
        if (key == "allow-private" && !ca) {
            require(value.empty() || value == "true" || value == "false", "invalid boolean");
            o.allow_private = value != "false"; continue;
        }
        if (eq == std::string::npos) { require(i+1<argc,"flag needs value: "+key); value = argv[++i]; }
        if (key == "data-dir") o.dir = value;
        else if (ca) throw std::runtime_error("unknown ca flag: "+key);
        else if (key == "listen") o.listen = value;
        else if (key == "dashboard") o.dashboard = value;
        else if (key == "inspect") o.scope = parse_scope(value);
        else if (key == "upstream-ca") o.upstream_ca = value;
        else if (key == "rules") o.rules_file = value;
        else if (key == "max-records") o.max_records = integer(value,1,INT64_MAX);
        else if (key == "max-age") o.max_age = duration_ms(value);
        else if (key == "queue-size") o.queue_size = static_cast<int>(integer(value,1,1000000));
        else if (key == "max-active") o.max_active = static_cast<int>(integer(value,1,4096));
        else throw std::runtime_error("unknown flag: "+key);
    }
    return o;
}
static void private_dir(const fs::path& path) {
    fs::create_directories(path);
    require(chmod(path.c_str(),0700) == 0,"cannot secure data directory");
}
static std::string random_hex(size_t count) {
    std::vector<unsigned char> bytes(count);
    require(RAND_bytes(bytes.data(),static_cast<int>(bytes.size())) == 1,"random generation failed");
    static const char* alphabet = "0123456789abcdef";
    std::string result;
    for (auto b : bytes) { result += alphabet[b>>4]; result += alphabet[b&15]; }
    return result;
}
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
static Key keygen() {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC,nullptr), EVP_PKEY_CTX_free);
    require(ctx && EVP_PKEY_keygen_init(ctx.get()) == 1 &&
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(),NID_X9_62_prime256v1) == 1, "key generation setup failed");
    EVP_PKEY* key = nullptr;
    require(EVP_PKEY_keygen(ctx.get(),&key) == 1,"key generation failed");
    return Key(key,EVP_PKEY_free);
}
static void extension(X509* cert, X509* issuer, int nid, const std::string& value) {
    X509V3_CTX ctx{};
    X509V3_set_ctx(&ctx,issuer,cert,nullptr,nullptr,0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr,&ctx,nid,value.c_str());
    require(ext != nullptr,"certificate extension failed");
    int ok = X509_add_ext(cert,ext,-1);
    X509_EXTENSION_free(ext);
    require(ok == 1,"certificate extension failed");
}
static Cert certificate(EVP_PKEY* key, X509* issuer, EVP_PKEY* signer, const std::string& host) {
    Cert cert(X509_new(),X509_free);
    require(cert != nullptr,"certificate allocation failed");
    X509_set_version(cert.get(),2);
    std::array<unsigned char,16> serial{};
    require(RAND_bytes(serial.data(),serial.size()) == 1,"serial generation failed");
    serial[0] &= 0x7f;
    BIGNUM* number = BN_bin2bn(serial.data(),serial.size(),nullptr);
    ASN1_INTEGER* asn = BN_to_ASN1_INTEGER(number,nullptr);
    BN_free(number);
    require(asn != nullptr,"serial conversion failed");
    X509_set_serialNumber(cert.get(),asn);
    ASN1_INTEGER_free(asn);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()),-300);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()),issuer ? 24*3600 : 730L*24*3600);
    if (issuer && ASN1_TIME_compare(X509_get0_notAfter(cert.get()),X509_get0_notAfter(issuer)) > 0)
        require(X509_set1_notAfter(cert.get(),X509_get0_notAfter(issuer)) == 1,"leaf validity failed");
    X509_set_pubkey(cert.get(),key);
    auto name = X509_get_subject_name(cert.get());
    auto cn = issuer ? host : "Traceglass C++ local inspection CA";
    require(X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(cn.c_str()),-1,-1,0) == 1,"certificate name failed");
    X509_set_issuer_name(cert.get(),issuer ? X509_get_subject_name(issuer) : name);
    extension(cert.get(),issuer ? issuer : cert.get(),NID_basic_constraints,issuer ? "critical,CA:FALSE" : "critical,CA:TRUE,pathlen:0");
    extension(cert.get(),issuer ? issuer : cert.get(),NID_key_usage,issuer ? "critical,digitalSignature" : "critical,keyCertSign,cRLSign");
    extension(cert.get(),issuer ? issuer : cert.get(),NID_subject_key_identifier,"hash");
    if (issuer) extension(cert.get(),issuer,NID_authority_key_identifier,"keyid:always");
    if (issuer) {
        Error ec;
        net::ip::make_address(host,ec);
        extension(cert.get(),issuer,NID_subject_alt_name,(!ec ? "IP:" : "DNS:")+host);
        extension(cert.get(),issuer,NID_ext_key_usage,"serverAuth");
    }
    require(X509_sign(cert.get(),signer ? signer : key,EVP_sha256()) > 0,"certificate signing failed");
    return cert;
}
static void init_ca(const Options& o) {
    private_dir(o.dir);
    auto cert_path = fs::path(o.dir)/"traceglass-ca.crt";
    auto key_path = fs::path(o.dir)/"traceglass-ca.key";
    require(!fs::exists(cert_path) && !fs::exists(key_path),"CA already exists; refusing to overwrite");
    auto key = keygen();
    auto cert = certificate(key.get(),nullptr,nullptr,"");
    int keyfd = open(key_path.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
    require(keyfd >= 0,"cannot create CA private key");
    FILE* keyfile = fdopen(keyfd,"w");
    require(keyfile != nullptr,"cannot open key stream");
    int ok = PEM_write_PrivateKey(keyfile,key.get(),nullptr,nullptr,0,nullptr,nullptr);
    int closed = fclose(keyfile);
    require(ok == 1 && closed == 0,"cannot write private key");
    int certfd = open(cert_path.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
    require(certfd >= 0,"cannot create CA certificate");
    FILE* certfile = fdopen(certfd,"w");
    require(certfile != nullptr,"cannot open certificate stream");
    ok = PEM_write_X509(certfile,cert.get());
    closed = fclose(certfile);
    require(ok == 1 && closed == 0,"cannot write CA certificate");
    std::cout << "Local CA created: " << cert_path << "\nNo system trust was installed.\n";
}
class CA {
    Key key_{nullptr,EVP_PKEY_free};
    Cert cert_{nullptr,X509_free};
public:
    explicit CA(const std::string& dir) {
        struct stat key_info{};
        require(stat((fs::path(dir)/"traceglass-ca.key").c_str(),&key_info) == 0 &&
            (key_info.st_mode & 0077) == 0,"CA key must have owner-only permissions");
        auto keydata = read_file(fs::path(dir)/"traceglass-ca.key");
        auto certdata = read_file(fs::path(dir)/"traceglass-ca.crt");
        BIO* bio = BIO_new_mem_buf(keydata.data(),static_cast<int>(keydata.size()));
        key_.reset(PEM_read_bio_PrivateKey(bio,nullptr,nullptr,nullptr)); BIO_free(bio);
        bio = BIO_new_mem_buf(certdata.data(),static_cast<int>(certdata.size()));
        cert_.reset(PEM_read_bio_X509(bio,nullptr,nullptr,nullptr)); BIO_free(bio);
        require(key_ && cert_ && X509_check_private_key(cert_.get(),key_.get()) == 1 &&
            X509_verify(cert_.get(),key_.get()) == 1 &&
            X509_check_ca(cert_.get()) > 0 && X509_cmp_current_time(X509_get0_notBefore(cert_.get())) < 0 &&
            X509_cmp_current_time(X509_get0_notAfter(cert_.get())) > 0,"invalid or expired inspection CA");
    }
    std::unique_ptr<ssl::context> context(const std::string& host) const {
        auto key = keygen();
        auto cert = certificate(key.get(),cert_.get(),key_.get(),host);
        auto ctx = std::make_unique<ssl::context>(ssl::context::tls_server);
        SSL_CTX_set_min_proto_version(ctx->native_handle(),TLS1_2_VERSION);
        require(SSL_CTX_use_certificate(ctx->native_handle(),cert.get()) == 1 &&
            SSL_CTX_use_PrivateKey(ctx->native_handle(),key.get()) == 1,"cannot install leaf certificate");
        return ctx;
    }
};

struct Record {
    int64_t timestamp = now_ms();
    std::string method, scheme, host, mode, error_code;
    int port = 0, status = 0;
    int64_t request_bytes = 0, response_bytes = 0, duration = 0;
    json flags = json::array();
    json to_json() const {
        return {{"timestamp",timestamp},{"method",method},{"scheme",scheme},{"host",host},{"port",port},
            {"mode",mode},{"status",status},{"request_bytes",request_bytes},{"response_bytes",response_bytes},
            {"duration_ms",duration},{"flags",flags},{"error_code",error_code}};
    }
};
class Store {
    sqlite3* db_ = nullptr;
    int lock_ = -1;
    Options o_;
    std::mutex db_mutex_, queue_mutex_;
    std::condition_variable cv_;
    std::deque<Record> queue_;
    bool closing_ = false;
    std::thread writer_;
    std::atomic<uint64_t> dropped_{0};
    std::array<int64_t,4> totals_{};
    void exec(const std::string& query) {
        char* error = nullptr;
        int rc = sqlite3_exec(db_,query.c_str(),nullptr,nullptr,&error);
        std::string message = error ? error : "SQLite failure";
        sqlite3_free(error);
        require(rc == SQLITE_OK,message);
    }
    std::array<int64_t,4> totals(const std::string& condition = "") {
        auto query = "SELECT COUNT(*),COALESCE(SUM(flags != '[]'),0),COALESCE(SUM(request_bytes),0),COALESCE(SUM(response_bytes),0) FROM records"+condition;
        sqlite3_stmt* raw = nullptr;
        require(sqlite3_prepare_v2(db_,query.c_str(),-1,&raw,nullptr) == SQLITE_OK,"prepare counters failed");
        std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> stmt(raw,sqlite3_finalize);
        require(sqlite3_step(raw) == SQLITE_ROW,"read counters failed");
        return {sqlite3_column_int64(raw,0),sqlite3_column_int64(raw,1),sqlite3_column_int64(raw,2),sqlite3_column_int64(raw,3)};
    }
    void prune(std::array<int64_t,4>& updated) {
        auto remove = [&](const std::string& condition) {
            auto removed = totals(" WHERE "+condition);
            if (removed[0] == 0) return;
            exec("DELETE FROM records WHERE "+condition);
            for (size_t i = 0; i < updated.size(); ++i) updated[i] -= removed[i];
        };
        remove("timestamp < "+std::to_string(now_ms()-o_.max_age));
        if (updated[0] > o_.max_records)
            remove("id IN (SELECT id FROM records ORDER BY id LIMIT "+std::to_string(updated[0]-o_.max_records)+")");
    }
    void flush(const std::vector<Record>& batch) {
        std::lock_guard<std::mutex> guard(db_mutex_);
        auto updated = totals_;
        exec("BEGIN IMMEDIATE");
        try {
            sqlite3_stmt* raw = nullptr;
            require(sqlite3_prepare_v2(db_,"INSERT INTO records(timestamp,method,scheme,host,port,mode,status,request_bytes,response_bytes,duration_ms,flags,error_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",-1,&raw,nullptr) == SQLITE_OK,"prepare insert failed");
            std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> stmt(raw,sqlite3_finalize);
            for (const auto& r : batch) {
                sqlite3_bind_int64(raw,1,r.timestamp);
                sqlite3_bind_text(raw,2,r.method.c_str(),-1,SQLITE_TRANSIENT);
                sqlite3_bind_text(raw,3,r.scheme.c_str(),-1,SQLITE_TRANSIENT);
                sqlite3_bind_text(raw,4,r.host.c_str(),-1,SQLITE_TRANSIENT);
                sqlite3_bind_int(raw,5,r.port);
                sqlite3_bind_text(raw,6,r.mode.c_str(),-1,SQLITE_TRANSIENT);
                sqlite3_bind_int(raw,7,r.status);
                sqlite3_bind_int64(raw,8,r.request_bytes);
                sqlite3_bind_int64(raw,9,r.response_bytes);
                sqlite3_bind_int64(raw,10,r.duration);
                auto flags = r.flags.dump();
                sqlite3_bind_text(raw,11,flags.c_str(),-1,SQLITE_TRANSIENT);
                sqlite3_bind_text(raw,12,r.error_code.c_str(),-1,SQLITE_TRANSIENT);
                require(sqlite3_step(raw) == SQLITE_DONE,"insert metadata failed");
                ++updated[0];
                if (!r.flags.empty()) ++updated[1];
                updated[2] += r.request_bytes;
                updated[3] += r.response_bytes;
                sqlite3_reset(raw);
                sqlite3_clear_bindings(raw);
            }
            prune(updated);
            exec("COMMIT");
            totals_ = updated;
        } catch (...) { exec("ROLLBACK"); throw; }
    }
    void run() {
        try {
            for (;;) {
                std::vector<Record> batch;
                bool done;
                {
                    std::unique_lock<std::mutex> lock(queue_mutex_);
                    cv_.wait_for(lock,std::chrono::milliseconds(250),[&] { return closing_ || queue_.size() >= 256; });
                    while (!queue_.empty() && batch.size() < 256) {
                        batch.push_back(std::move(queue_.front())); queue_.pop_front();
                    }
                    done = closing_ && queue_.empty();
                }
                flush(batch);
                if (done) break;
            }
        } catch (const std::exception& e) {
            std::cerr << "Fatal metadata writer error: " << e.what() << "\n";
            failed.store(true);
        }
    }
public:
    std::atomic<bool> failed{false};
    explicit Store(const Options& o) : o_(o) {
        private_dir(o.dir);
        auto path = fs::path(o.dir)/"metadata-cpp.db";
        lock_ = open((path.string()+".lock").c_str(),O_CREAT|O_RDWR,0600);
        require(lock_ >= 0 && flock(lock_,LOCK_EX|LOCK_NB) == 0,"data directory already in use");
        int fd = open(path.c_str(),O_CREAT|O_RDWR,0600);
        require(fd >= 0,"cannot create metadata file"); ::close(fd);
        require(chmod(path.c_str(),0600) == 0,"cannot secure metadata file");
        require(sqlite3_open(path.c_str(),&db_) == SQLITE_OK,"cannot open metadata database");
        sqlite3_busy_timeout(db_,5000);
        {
            sqlite3_stmt* raw = nullptr;
            require(sqlite3_prepare_v2(db_,"PRAGMA user_version",-1,&raw,nullptr) == SQLITE_OK,"schema query failed");
            std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> stmt(raw,sqlite3_finalize);
            require(sqlite3_step(raw) == SQLITE_ROW,"schema read failed");
            auto version = sqlite3_column_int(raw,0);
            require(version == 0 || version == 1,"unsupported C++ metadata schema");
        }
        exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"
             "CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY AUTOINCREMENT,"
             "timestamp INTEGER NOT NULL,method TEXT NOT NULL,scheme TEXT NOT NULL,host TEXT NOT NULL,"
             "port INTEGER NOT NULL,mode TEXT NOT NULL,status INTEGER NOT NULL,request_bytes INTEGER NOT NULL,"
             "response_bytes INTEGER NOT NULL,duration_ms INTEGER NOT NULL,flags TEXT NOT NULL,error_code TEXT NOT NULL);"
             "CREATE INDEX IF NOT EXISTS records_timestamp ON records(timestamp); PRAGMA user_version=1;");
        totals_ = totals();
        flush({});
        writer_ = std::thread([this] { run(); });
    }
    ~Store() {
        close();
        if (db_) sqlite3_close(db_);
        if (lock_ >= 0) { flock(lock_,LOCK_UN); ::close(lock_); }
    }
    void close() {
        { std::lock_guard<std::mutex> lock(queue_mutex_); closing_ = true; }
        cv_.notify_one();
        if (writer_.joinable()) writer_.join();
    }
    void enqueue(Record record) {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (queue_.size() >= static_cast<size_t>(o_.queue_size) || closing_ || failed.load()) {
            auto n = ++dropped_;
            if (n == 1 || (n & (n-1)) == 0)
                std::cerr << "Metadata queue overflow/unavailable; dropped=" << n << "\n";
            return;
        }
        queue_.push_back(std::move(record));
        cv_.notify_one();
    }
    json stats() {
        json result;
        {
            std::lock_guard<std::mutex> guard(db_mutex_);
            result = {{"records",totals_[0]},{"flagged",totals_[1]},
                {"request_bytes",totals_[2]},{"response_bytes",totals_[3]}};
        }
        std::lock_guard<std::mutex> lock(queue_mutex_);
        result["dropped"] = dropped_.load();
        result["queued"] = queue_.size();
        return result;
    }
    json records(int limit, int64_t before, const std::string& host, bool flagged) {
        std::lock_guard<std::mutex> guard(db_mutex_);
        sqlite3_stmt* raw = nullptr;
        require(sqlite3_prepare_v2(db_,"SELECT id,timestamp,method,scheme,host,port,mode,status,request_bytes,response_bytes,duration_ms,flags,error_code FROM records WHERE (?=0 OR id<?) AND instr(host,?)>0 AND (?=0 OR flags!='[]') ORDER BY id DESC LIMIT ?",-1,&raw,nullptr) == SQLITE_OK,"records query failed");
        std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> stmt(raw,sqlite3_finalize);
        sqlite3_bind_int64(raw,1,before); sqlite3_bind_int64(raw,2,before);
        sqlite3_bind_text(raw,3,host.c_str(),-1,SQLITE_TRANSIENT);
        sqlite3_bind_int(raw,4,flagged); sqlite3_bind_int(raw,5,limit);
        json rows = json::array();
        int rc;
        auto text = [&](int i) { return std::string(reinterpret_cast<const char*>(sqlite3_column_text(raw,i))); };
        while ((rc = sqlite3_step(raw)) == SQLITE_ROW) {
            rows.push_back({{"id",sqlite3_column_int64(raw,0)},{"timestamp",sqlite3_column_int64(raw,1)},
                {"method",text(2)},{"scheme",text(3)},{"host",text(4)},{"port",sqlite3_column_int(raw,5)},
                {"mode",text(6)},{"status",sqlite3_column_int(raw,7)},{"request_bytes",sqlite3_column_int64(raw,8)},
                {"response_bytes",sqlite3_column_int64(raw,9)},{"duration_ms",sqlite3_column_int64(raw,10)},
                {"flags",json::parse(text(11))},{"error_code",text(12)}});
        }
        require(rc == SQLITE_DONE,"records read failed");
        int64_t next = rows.size() == static_cast<size_t>(limit) ? rows.back()["id"].get<int64_t>() : 0;
        return {{"records",rows},{"next_before",next}};
    }
};

class Connections {
    std::mutex mutex_;
    std::set<int> descriptors_;
    bool stopped_ = false;
public:
    void add(int fd) {
        std::lock_guard<std::mutex> lock(mutex_);
        descriptors_.insert(fd);
        if (stopped_) ::shutdown(fd,SHUT_RDWR);
    }
    void remove(int fd) {
        std::lock_guard<std::mutex> lock(mutex_); descriptors_.erase(fd);
    }
    void stop() {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        for (int fd : descriptors_) ::shutdown(fd,SHUT_RDWR);
    }
};
struct Registration {
    Connections& owner;
    int fd;
    Registration(Connections& owner_, int fd_) : owner(owner_),fd(fd_) { owner.add(fd); }
    ~Registration() { owner.remove(fd); }
};
static void socket_options(tcp::socket& socket) {
    timeval timeout{30,0};
    setsockopt(socket.native_handle(),SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(socket.native_handle(),SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(socket.native_handle(),SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
#endif
}
static bool public_address(net::ip::address address) {
    if (address.is_v6()) {
        auto v6 = address.to_v6();
        if (v6.is_v4_mapped()) {
            auto b = v6.to_bytes();
            return public_address(net::ip::address_v4({{b[12],b[13],b[14],b[15]}}));
        }
        auto b = v6.to_bytes();
        // Only global unicast; exclude documentation, Teredo, 6to4 and protocol assignments.
        return (b[0]&0xe0) == 0x20 && !(b[0] == 0x20 && b[1] == 0x01 &&
            ((b[2] == 0x0d && b[3] == 0xb8) || b[2] <= 1)) && !(b[0] == 0x20 && b[1] == 0x02);
    }
    auto a = address.to_v4().to_uint();
    auto range = [&](uint32_t base, unsigned bits) { return (a>>(32-bits)) == (base>>(32-bits)); };
    return !(range(0x00000000,8) || range(0x0a000000,8) || range(0x64400000,10) ||
        range(0x7f000000,8) || range(0xa9fe0000,16) || range(0xac100000,12) ||
        range(0xc0000000,24) || range(0xc0000200,24) || range(0xc0586300,24) ||
        range(0xc0a80000,16) || range(0xc6120000,15) || range(0xc6336400,24) ||
        range(0xcb007100,24) || range(0xe0000000,3));
}
static std::vector<tcp::endpoint> resolve(net::io_context& io, const Authority& destination, bool allow_private) {
    tcp::resolver resolver(io);
    auto answers = resolver.resolve(destination.host,std::to_string(destination.port));
    std::vector<tcp::endpoint> endpoints;
    for (const auto& answer : answers) {
        require(allow_private || public_address(answer.endpoint().address()),"private/local destination denied");
        endpoints.push_back(answer.endpoint());
    }
    require(!endpoints.empty(),"no destination address");
    return endpoints;
}
static void dial(beast::tcp_stream& stream, const std::vector<tcp::endpoint>& endpoints) {
    // Asio performs a bounded asynchronous connect; subsequent payload I/O is streaming.
    Error result = net::error::timed_out;
    auto& io = static_cast<net::io_context&>(stream.get_executor().context());
    stream.expires_after(std::chrono::seconds(15));
    stream.async_connect(endpoints,[&](Error ec, const tcp::endpoint&) { result = ec; });
    io.restart(); io.run();
    if (result) throw boost::system::system_error(result);
    stream.expires_never();
    socket_options(stream.socket());
}
template<class Stream>
static void reply(Stream& stream, int code, const std::string& body, const std::string& type = "text/plain; charset=utf-8") {
    http::response<http::string_body> response(static_cast<http::status>(code),11);
    response.set(http::field::content_type,type);
    response.set(http::field::cache_control,"no-store");
    response.set("X-Content-Type-Options","nosniff");
    response.set("Referrer-Policy","no-referrer");
    response.set("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
    response.keep_alive(false);
    response.body() = body;
    response.prepare_payload();
    Error ec;
    http::write(stream,response,ec);
}
static bool secret_equal(const std::string& a, const std::string& b) {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(),b.data(),a.size()) == 0;
}
static std::string percent_decode(const std::string& input) {
    std::string result;
    auto digit = [](char c)->int {
        if (c >= '0' && c <= '9') return c-'0';
        if (c >= 'a' && c <= 'f') return c-'a'+10;
        if (c >= 'A' && c <= 'F') return c-'A'+10;
        return -1;
    };
    for (size_t i=0;i<input.size();++i) {
        if (input[i] == '%') {
            require(i+2<input.size() && digit(input[i+1]) >= 0 && digit(input[i+2]) >= 0,"invalid query encoding");
            result += static_cast<char>((digit(input[i+1])<<4)|digit(input[i+2])); i+=2;
        } else result += input[i] == '+' ? ' ' : input[i];
    }
    return result;
}
static std::map<std::string,std::string> query(const std::string& target) {
    std::map<std::string,std::string> result;
    auto mark = target.find('?');
    if (mark == std::string::npos) return result;
    for (const auto& pair : split(target.substr(mark+1),'&')) {
        auto eq = pair.find('=');
        auto key = percent_decode(pair.substr(0,eq));
        require(!result.count(key),"duplicate query filter");
        result[key] = eq == std::string::npos ? "" : percent_decode(pair.substr(eq+1));
    }
    return result;
}
class Application {
    Options o_;
    Rules rules_;
    std::unique_ptr<CA> ca_;
    ssl::context upstream_{ssl::context::tls_client};
    Store store_;
    Connections connections_;
    std::atomic<int> active_{0};
    std::string token_ = random_hex(32), proxy_address_, dashboard_address_;
    struct Completion {
        Application& app;
        Record& record;
        Clock::time_point start = Clock::now();
        ~Completion() {
            record.duration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-start).count();
            record.flags = app.rules_.flags(record.host,record.port,record.request_bytes,record.response_bytes);
            app.store_.enqueue(record);
        }
    };
    static bool unsupported(const http::request<http::buffer_body>& request) {
        return request.find(http::field::upgrade) != request.end() ||
            lower(std::string(request[http::field::connection])).find("upgrade") != std::string::npos;
    }
    template<class Message>
    static void strip_hop(Message& message, bool close = true) {
        auto connection = std::string(message[http::field::connection]);
        for (auto name : split(connection,',')) {
            auto begin = name.find_first_not_of(" \t");
            auto end = name.find_last_not_of(" \t");
            if (begin != std::string::npos) message.erase(name.substr(begin,end-begin+1));
        }
        for (const char* name : {"Connection","Proxy-Connection","Keep-Alive","Proxy-Authorization","Proxy-Authenticate","TE","Trailer","Upgrade"}) message.erase(name);
        if (close) message.keep_alive(false);
    }
    template<class Incoming, class Outgoing, bool Request>
    static void body_stream(Incoming& incoming, Outgoing& outgoing, beast::flat_buffer& buffer,
            http::parser<Request,http::buffer_body>& parser,
            http::serializer<Request,http::buffer_body>& serializer,
            http::message<Request,http::buffer_body>& message, int64_t& count) {
        std::array<char,32768> data{};
        while (!parser.is_done()) {
            parser.get().body().data = data.data();
            parser.get().body().size = data.size();
            Error ec;
            http::read_some(incoming,buffer,parser,ec);
            auto size = data.size()-parser.get().body().size;
            count += static_cast<int64_t>(size);
            if (ec == http::error::need_buffer) ec.clear();
            if (ec) throw boost::system::system_error(ec);
            if (size == 0 && !parser.is_done()) continue;
            message.body().data = data.data();
            message.body().size = size;
            message.body().more = !parser.is_done();
            http::write(outgoing,serializer,ec);
            if (ec == http::error::need_buffer) ec.clear();
            if (ec) throw boost::system::system_error(ec);
        }
        if (!serializer.is_done()) {
            message.body().data = nullptr;
            message.body().size = 0;
            message.body().more = false;
            http::write(outgoing,serializer);
        }
    }
    template<class Client, class Upstream>
    void exchange(Client& client, Upstream& upstream, beast::flat_buffer& client_buffer,
            http::request_parser<http::buffer_body>& parser, const Authority& destination,
            const std::string& target, Record& record) {
        auto& original = parser.get();
        http::request<http::buffer_body> request;
        request.base() = original.base();
        request.target(target);
        request.set(http::field::host,destination.text());
        bool chunked = original.chunked();
        auto length = parser.content_length();
        strip_hop(request,false);
        request.erase(http::field::expect);
        request.erase(http::field::transfer_encoding);
        request.erase(http::field::content_length);
        if (chunked) request.chunked(true);
        else if (length) request.content_length(*length);
        request.body().more = !parser.is_done();
        http::request_serializer<http::buffer_body> serializer(request);
        record.error_code = "upstream-failed";
        http::write_header(upstream,serializer);
        if (!original[http::field::expect].empty()) {
            require(lower(std::string(original[http::field::expect])) == "100-continue","unsupported expectation");
            http::response<http::empty_body> interim(http::status::continue_,11);
            http::write(client,interim);
        }
        beast::flat_buffer upstream_buffer(65536);
        std::unique_ptr<http::response_parser<http::buffer_body>> response_parser;
        // Read the response concurrently with a bounded upload pump, on ONE
        // Asio executor. This also keeps SSL's internal state single-threaded.
        auto& io = static_cast<net::io_context&>(upstream.get_executor().context());
        std::array<char,32768> upload{};
        bool upload_done = parser.is_done(), response_done = false;
        Error upload_error, response_error;
        net::steady_timer deadline(io,std::chrono::seconds(120));
        auto cancel_client = [&] { Error ignored; beast::get_lowest_layer(client).socket().cancel(ignored); };
        auto cancel_upstream = [&] { Error ignored; beast::get_lowest_layer(upstream).socket().cancel(ignored); };
        auto settled = [&] {
            if (upload_done && response_done) { Error ignored; deadline.cancel(ignored); }
        };
        std::function<void()> read_upload, read_response;
        read_upload = [&] {
            if (response_done || upload_error) { upload_done = true; settled(); return; }
            parser.get().body().data = upload.data();
            parser.get().body().size = upload.size();
            http::async_read_some(client,client_buffer,parser,[&](Error ec,size_t) {
                size_t size = upload.size()-parser.get().body().size;
                record.request_bytes += static_cast<int64_t>(size);
                if (ec == http::error::need_buffer) ec.clear();
                if (ec || response_done) {
                    if (!response_done) { upload_error = ec; cancel_upstream(); }
                    upload_done = true; settled(); return;
                }
                if (size == 0 && !parser.is_done()) { read_upload(); return; }
                request.body().data = upload.data();
                request.body().size = size;
                request.body().more = !parser.is_done();
                http::async_write(upstream,serializer,[&](Error write_error,size_t) {
                    if (write_error == http::error::need_buffer) write_error.clear();
                    if (write_error || parser.is_done() || response_done) {
                        if (!response_done && write_error) { upload_error = write_error; cancel_upstream(); }
                        upload_done = true; settled(); return;
                    }
                    read_upload();
                });
            });
        };
        read_response = [&] {
            response_parser = std::make_unique<http::response_parser<http::buffer_body>>();
            response_parser->body_limit((std::numeric_limits<uint64_t>::max)());
            response_parser->header_limit(65536);
            if (original.method() == http::verb::head) response_parser->skip(true);
            http::async_read_header(upstream,upstream_buffer,*response_parser,[&](Error ec,size_t) {
                if (!ec && response_parser->get().result_int() < 200 &&
                    response_parser->get().result_int() != 101) { read_response(); return; }
                response_error = ec;
                response_done = true;
                if (!upload_done) { cancel_client(); cancel_upstream(); }
                settled();
            });
        };
        deadline.async_wait([&](Error ec) {
            if (!ec) { response_error = net::error::timed_out; cancel_client(); cancel_upstream(); }
        });
        record.error_code = "request-body-failed";
        if (!upload_done) read_upload();
        read_response();
        io.restart(); io.run();
        if (response_error) {
            record.error_code = upload_error ? "request-body-failed" : "upstream-failed";
            throw boost::system::system_error(response_error);
        }
        if (response_parser->get().result_int() == 101) {
            record.status = 502; record.error_code = "upgrade-unsupported";
            reply(client,502,"Upstream upgrades are unsupported\n"); return;
        }
        auto& received = response_parser->get();
        record.status = received.result_int();
        http::response<http::buffer_body> response;
        response.base() = received.base();
        bool response_chunked = received.chunked();
        auto response_length = response_parser->content_length();
        strip_hop(response);
        response.erase(http::field::transfer_encoding);
        response.erase(http::field::content_length);
        if (response_chunked) response.chunked(true);
        else if (response_length) response.content_length(*response_length);
        response.body().more = !response_parser->is_done();
        http::response_serializer<http::buffer_body> response_serializer(response);
        record.error_code = "proxy-io-failed";
        http::write_header(client,response_serializer);
        record.error_code = "stream-failed";
        body_stream(upstream,client,upstream_buffer,*response_parser,response_serializer,response,record.response_bytes);
        record.error_code.clear();
    }
    template<class Client>
    void forward(Client& client, beast::flat_buffer& buffer, http::request_parser<http::buffer_body>& parser,
            const Authority& destination, const std::string& target, Record& record, bool tls,
            const std::vector<tcp::endpoint>& endpoints, net::io_context& io) {
        try {
            record.error_code = "upstream-failed";
            if (tls) {
                ssl::stream<beast::tcp_stream> upstream(io,upstream_);
                dial(beast::get_lowest_layer(upstream),endpoints);
                Registration registered(connections_,beast::get_lowest_layer(upstream).socket().native_handle());
                require(SSL_set_tlsext_host_name(upstream.native_handle(),destination.host.c_str()) == 1,"SNI setup failed");
                upstream.set_verify_mode(ssl::verify_peer);
                upstream.set_verify_callback(ssl::host_name_verification(destination.host));
                upstream.handshake(ssl::stream_base::client);
                exchange(client,upstream,buffer,parser,destination,target,record);
            } else {
                beast::tcp_stream upstream(io);
                dial(upstream,endpoints);
                Registration registered(connections_,upstream.socket().native_handle());
                exchange(client,upstream,buffer,parser,destination,target,record);
            }
        } catch (const std::exception&) {
            if (record.status == 0) {
                record.status = 502;
                reply(client,502,"Upstream exchange failed\n");
            }
            // Once headers have been sent, do not terminate a truncated chunked
            // message successfully. Destruction closes the transport instead.
        }
    }
    static void tunnel(beast::tcp_stream& client, beast::tcp_stream& upstream, Record& r) {
        struct Direction {
            int source, destination;
            std::array<char,32768> data{};
            size_t begin = 0, end = 0;
            bool eof = false, write_closed = false;
            int64_t* count;
        };
        int c = client.socket().native_handle(), u = upstream.socket().native_handle();
        fcntl(c,F_SETFL,fcntl(c,F_GETFL)|O_NONBLOCK);
        fcntl(u,F_SETFL,fcntl(u,F_GETFL)|O_NONBLOCK);
        Direction directions[2] = {{c,u,{},0,0,false,false,&r.request_bytes},{u,c,{},0,0,false,false,&r.response_bytes}};
        auto last = Clock::now();
        for (;;) {
            if (interrupted) return;
            bool finished = true;
            pollfd fds[2] = {{c,0,0},{u,0,0}};
            for (int i=0;i<2;++i) {
                auto& d = directions[i];
                if (!d.eof && d.end == 0) fds[i].events |= POLLIN;
                if (d.begin < d.end) fds[1-i].events |= POLLOUT;
                if (d.eof && d.end == 0 && !d.write_closed) {
                    ::shutdown(d.destination,SHUT_WR); d.write_closed = true;
                }
                if (!d.write_closed) finished = false;
            }
            if (finished) return;
            int rc = poll(fds,2,250);
            if (rc < 0 && errno == EINTR) continue;
            if (rc < 0) { r.error_code = "tunnel-io"; return; }
            if (Clock::now()-last > std::chrono::seconds(120)) { r.error_code = "tunnel-io"; return; }
            for (int i=0;i<2;++i) {
                auto& d = directions[i];
                if (!d.eof && d.end == 0 && (fds[i].revents&(POLLIN|POLLHUP|POLLERR))) {
                    ssize_t n = recv(d.source,d.data.data(),d.data.size(),0);
                    if (n > 0) { d.end = static_cast<size_t>(n); *d.count += n; last = Clock::now(); }
                    else if (n == 0) d.eof = true;
                    else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { r.error_code = "tunnel-io"; return; }
                }
                if (d.begin < d.end && (fds[1-i].revents&POLLOUT)) {
                    ssize_t n = send(d.destination,d.data.data()+d.begin,d.end-d.begin,0);
                    if (n > 0) { d.begin += static_cast<size_t>(n); last = Clock::now(); if (d.begin == d.end) d.begin = d.end = 0; }
                    else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { r.error_code = "tunnel-io"; return; }
                }
            }
        }
    }
    void proxy(tcp::socket socket) {
        net::io_context upstream_io;
        auto protocol = socket.local_endpoint().protocol();
        auto fd = socket.release();
        tcp::socket local_socket(upstream_io,protocol,fd);
        socket_options(local_socket);
        Registration registered(connections_,local_socket.native_handle());
        beast::tcp_stream client(std::move(local_socket));
        beast::flat_buffer buffer(65536);
        http::request_parser<http::buffer_body> parser;
        parser.header_limit(65536);
        parser.body_limit((std::numeric_limits<uint64_t>::max)());
        try { http::read_header(client,buffer,parser); }
        catch (...) { reply(client,400,"Malformed request\n"); return; }
        auto& request = parser.get();
        if (request.version() != 11 || request.count(http::field::host) != 1) {
            reply(client,400,"HTTP/1.1 with one Host required\n"); return;
        }
        Authority destination;
        bool connect = request.method() == http::verb::connect;
        std::string target;
        try {
            if (connect) {
                destination = authority(std::string(request.target()));
                auto h = authority(std::string(request[http::field::host]));
                require(h.host == destination.host && h.port == destination.port,"CONNECT Host mismatch");
                require(!request.chunked() && (!parser.content_length() || *parser.content_length() == 0),"CONNECT body unsupported");
            } else {
                auto url = std::string(request.target());
                require(url.rfind("http://",0) == 0,"absolute http URL required");
                auto slash = url.find_first_of("/?#",7);
                auto auth = url.substr(7,slash == std::string::npos ? std::string::npos : slash-7);
                destination = authority(auth,80);
                auto h = authority(std::string(request[http::field::host]),80);
                require(h.host == destination.host && h.port == destination.port,"Host mismatch");
                target = slash == std::string::npos ? "/" : url.substr(slash);
                if (!target.empty() && target.front() == '?') target = "/"+target;
                require(target.find('#') == std::string::npos,"fragment unsupported");
            }
        } catch (...) { reply(client,400,"Invalid proxy authority\n"); return; }
        Record record;
        record.method = std::string(request.method_string());
        record.scheme = connect ? "https" : "http";
        record.host = destination.host; record.port = destination.port;
        record.mode = connect ? (matches(o_.scope,destination.host) ? "inspected" : "tunnel") : "http";
        if (record.method.size() > 32 || !std::all_of(record.method.begin(),record.method.end(),[](char c) { return c >= 'A' && c <= 'Z'; })) {
            reply(client,400,"Invalid method\n"); return;
        }
        if (unsupported(request)) {
            Completion complete{*this,record};
            record.status = 501; record.error_code = "upgrade-unsupported";
            reply(client,501,"Protocol upgrades are unsupported\n"); return;
        }
        std::vector<tcp::endpoint> endpoints;
        try { endpoints = resolve(upstream_io,destination,o_.allow_private); }
        catch (...) {
            Completion complete{*this,record}; record.status = 502;
            record.error_code = connect ? "connect-failed" : "upstream-failed";
            reply(client,502,"Destination unavailable or prohibited\n"); return;
        }
        if (!connect) {
            Completion complete{*this,record};
            forward(client,buffer,parser,destination,target,record,false,endpoints,upstream_io); return;
        }
        if (record.mode == "tunnel") {
            Completion complete{*this,record};
            beast::tcp_stream upstream(upstream_io);
            try {
                dial(upstream,endpoints);
                Registration upstream_registered(connections_,upstream.socket().native_handle());
                http::response<http::empty_body> established(http::status::ok,11);
                http::write(client,established);
                record.status = 200;
                if (buffer.size()) {
                    auto n = net::write(upstream,buffer.data()); record.request_bytes += static_cast<int64_t>(n);
                    buffer.consume(n);
                }
                tunnel(client,upstream,record);
            } catch (...) {
                record.error_code = record.status == 200 ? "tunnel-io" : "connect-failed";
                if (!record.status) { record.status = 502; reply(client,502,"CONNECT failed\n"); }
            }
            return;
        }
        // No leaf cache: memory remains bounded by concurrent inspected connections.
        std::unique_ptr<ssl::context> context;
        try { context = ca_->context(destination.host); }
        catch (...) { reply(client,502,"Certificate generation failed\n"); return; }
        http::response<http::empty_body> established(http::status::ok,11);
        Error ec;
        http::write(client,established,ec);
        if (ec) return;
        ssl::stream<beast::tcp_stream> secure(std::move(client),*context);
        try {
            if (buffer.size()) {
                secure.handshake(ssl::stream_base::server,buffer.data());
                buffer.consume(buffer.size());
            } else secure.handshake(ssl::stream_base::server);
        } catch (...) {
            Completion complete{*this,record}; record.status = 0; record.error_code = "client-tls-failed"; return;
        }
        http::request_parser<http::buffer_body> inner;
        inner.header_limit(65536); inner.body_limit((std::numeric_limits<uint64_t>::max)());
        try { http::read_header(secure,buffer,inner); }
        catch (...) { return; }
        try {
            auto h = authority(std::string(inner.get()[http::field::host]),443);
            target = std::string(inner.get().target());
            require(inner.get().version() == 11 && inner.get().count(http::field::host) == 1 &&
                h.host == destination.host && h.port == destination.port && !target.empty() &&
                target.front() == '/' && target.rfind("//",0) != 0 && target.find('#') == std::string::npos,
                "inner authority mismatch");
            record.method = std::string(inner.get().method_string());
            require(record.method.size() <= 32 &&
                std::all_of(record.method.begin(),record.method.end(),[](char c) { return c >= 'A' && c <= 'Z'; }),"invalid method");
        } catch (...) { reply(secure,421,"Inspection authority mismatch\n"); return; }
        Completion complete{*this,record};
        if (unsupported(inner.get())) {
            record.status = 501; record.error_code = "upgrade-unsupported";
            reply(secure,501,"Protocol upgrades are unsupported\n"); return;
        }
        forward(secure,buffer,inner,destination,target,record,true,endpoints,upstream_io);
        // Close TCP directly; do not wait for an uncooperative TLS close_notify.
    }
    void dashboard(tcp::socket socket) {
        socket_options(socket);
        Registration registered(connections_,socket.native_handle());
        beast::tcp_stream client(std::move(socket));
        beast::flat_buffer buffer(32768);
        http::request_parser<http::empty_body> parser;
        parser.header_limit(16384);
        parser.body_limit(0);
        try { http::read_header(client,buffer,parser); }
        catch (...) { reply(client,400,"Malformed request\n"); return; }
        const auto& request = parser.get();
        if (request.count(http::field::host) != 1 || request[http::field::host] != dashboard_address_ ||
            request.count(http::field::origin) > 1 || (!request[http::field::origin].empty() &&
                request[http::field::origin] != "http://"+dashboard_address_)) {
            reply(client,403,"Unexpected Host or Origin\n"); return;
        }
        if (request.method() != http::verb::get) { reply(client,405,"GET only\n"); return; }
        auto target = std::string(request.target());
        auto path = target.substr(0,target.find('?'));
        if (path.rfind("/api/",0) == 0) {
            if (request.count(http::field::authorization) != 1 ||
                !secret_equal(std::string(request[http::field::authorization]),"Bearer "+token_)) {
                reply(client,401,"Bearer token required\n"); return;
            }
            try {
                if (path == "/api/status") {
                    json status = {{"stats",store_.stats()},{"active",active_.load()},{"proxy",proxy_address_},
                        {"inspect",o_.scope},{"max_records",o_.max_records},{"max_age",o_.age_text()},
                        {"allow_private",o_.allow_private}};
                    reply(client,200,status.dump(),"application/json"); return;
                }
                if (path == "/api/records") {
                    int limit = 100;
                    int64_t before = 0;
                    std::string host;
                    bool flagged = false;
                    try {
                        auto filters = query(target);
                        if (filters.count("limit")) limit = static_cast<int>(integer(filters["limit"],1,200));
                        if (filters.count("before")) before = integer(filters["before"],1,INT64_MAX);
                        if (filters.count("host")) { host = lower(filters["host"]); require(host.size() <= 253,"host too long"); }
                        if (filters.count("flagged")) {
                            require(filters["flagged"] == "true" || filters["flagged"] == "false","invalid flagged filter");
                            flagged = filters["flagged"] == "true";
                        }
                    } catch (...) { reply(client,400,"Invalid record filter\n"); return; }
                    reply(client,200,store_.records(limit,before,host,flagged).dump(),"application/json"); return;
                }
                reply(client,404,"Not found\n"); return;
            } catch (const std::exception&) {
                std::cerr << "Metadata query failed\n";
                reply(client,500,"Metadata query failed\n"); return;
            }
        }
        if (path == "/" || path == "/index.html") reply(client,200,std::string(embedded::index_html),"text/html; charset=utf-8");
        else if (path == "/app.js") reply(client,200,std::string(embedded::app_js),"text/javascript; charset=utf-8");
        else if (path == "/style.css") reply(client,200,std::string(embedded::style_css),"text/css; charset=utf-8");
        else reply(client,404,"Not found\n");
    }
    static tcp::endpoint listener_endpoint(const std::string& value) {
        auto a = authority(value,0,true);
        Error ec;
        auto address = net::ip::make_address(a.host,ec);
        require(!ec && address.is_loopback(),"listeners must use literal loopback addresses");
        return {address,static_cast<unsigned short>(a.port)};
    }
public:
    explicit Application(Options o) : o_(std::move(o)),
        rules_(o_.rules_file.empty() ? std::string(embedded::default_rules) : read_file(o_.rules_file)),store_(o_) {
        if (!o_.scope.empty()) ca_ = std::make_unique<CA>(o_.dir);
        upstream_.set_default_verify_paths();
        if (!o_.upstream_ca.empty()) upstream_.load_verify_file(o_.upstream_ca);
        SSL_CTX_set_min_proto_version(upstream_.native_handle(),TLS1_2_VERSION);
        // Validate both before opening either listener.
        listener_endpoint(o_.listen); listener_endpoint(o_.dashboard);
    }
    int run() {
        net::io_context io;
        tcp::acceptor proxy_listener(io,listener_endpoint(o_.listen));
        tcp::acceptor dashboard_listener(io,listener_endpoint(o_.dashboard));
        proxy_listener.non_blocking(true); dashboard_listener.non_blocking(true);
        proxy_address_ = Authority{proxy_listener.local_endpoint().address().to_string(),proxy_listener.local_endpoint().port()}.text();
        dashboard_address_ = Authority{dashboard_listener.local_endpoint().address().to_string(),dashboard_listener.local_endpoint().port()}.text();
        std::cout << "Traceglass C++ 0.1.0\nProxy: http://" << proxy_address_
            << "\nDashboard: http://" << dashboard_address_ << "/#token=" << token_ << "\n" << std::flush;
        if (o_.allow_private) std::cerr << "Warning: private/local destinations enabled\n";
        struct Work { std::thread thread; std::shared_ptr<std::atomic<bool>> done; };
        std::vector<Work> work;
        std::atomic<int> dashboard_active{0};
        bool listener_failed = false;
        while (!interrupted && !store_.failed.load()) {
            for (auto it=work.begin();it!=work.end();) {
                if (it->done->load()) { it->thread.join(); it = work.erase(it); }
                else ++it;
            }
            for (int kind=0;kind<2;++kind) {
                auto& listener = kind == 0 ? proxy_listener : dashboard_listener;
                tcp::socket socket(io);
                Error ec;
                listener.accept(socket,ec);
                if (ec == net::error::would_block || ec == net::error::try_again) continue;
                if (ec) { std::cerr << "Listener failed\n"; listener_failed = true; interrupted = 1; break; }
                auto& count = kind == 0 ? active_ : dashboard_active;
                auto maximum = kind == 0 ? o_.max_active : 16;
                if (count.load() >= maximum) {
                    // Avoid blocking the accept loop on rejected clients.
                    socket.close(ec); continue;
                }
                ++count;
                auto done = std::make_shared<std::atomic<bool>>(false);
                work.push_back({std::thread([this,kind,s=std::move(socket),done,&count]() mutable {
                    try { if (kind == 0) proxy(std::move(s)); else dashboard(std::move(s)); }
                    catch (const std::exception&) { std::cerr << "Connection ended unexpectedly\n"; }
                    --count; done->store(true);
                }),done});
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        Error ignored;
        proxy_listener.close(ignored); dashboard_listener.close(ignored);
        connections_.stop();
        for (auto& w : work) w.thread.join();
        store_.close();
        return store_.failed.load() || listener_failed ? 1 : 0;
    }
};

static void self_test() {
    auto fixture = json::parse(embedded::conformance);
    Rules contract{fixture["rules"].dump()};
    for (const auto& item : fixture["classifications"])
        require(contract.flags(item["host"].get<std::string>(),item["port"].get<int>(),
            item["sent"].get<int64_t>(),item["received"].get<int64_t>()) == item["flags"],"shared classification vector");
    auto patterns = parse_scope(fixture["inspection_scope"].get<std::string>());
    for (const auto& item : fixture["inspection_matches"])
        require(matches(patterns,item["host"].get<std::string>()) == item["matches"].get<bool>(),"shared scope vector");
    for (const auto& pattern : fixture["invalid_scopes"]) {
        bool rejected = false;
        try { parse_scope(pattern.get<std::string>()); } catch (const std::exception&) { rejected = true; }
        require(rejected,"shared invalid scope vector");
    }
    Rules rules{std::string(embedded::default_rules)};
    require(rules.flags("ads.DOUBLECLICK.net.",443,0,0) == json::array({"known-tracker"}),"domain classification");
    require(rules.flags("notdoubleclick.net",443,0,0).empty(),"domain boundary");
    require(rules.flags("example.com",80,1048576,0).empty(),"payload boundary");
    require(rules.flags("example.com",81,1048576,1) == json::array({"large-payload","unsanctioned-port"}),"payload/port classification");
    auto scope = parse_scope("Example.com,*.example.org,127.0.0.1");
    require(matches(scope,"example.com.") && !matches(scope,"a.example.com") &&
        matches(scope,"a.example.org") && !matches(scope,"example.org") &&
        !matches(scope,"badexample.org") && matches(scope,"127.0.0.1"),"scope boundaries");
    require(!public_address(net::ip::make_address("127.0.0.1")) &&
        !public_address(net::ip::make_address("::ffff:192.168.1.2")) &&
        !public_address(net::ip::make_address("169.254.169.254")) &&
        public_address(net::ip::make_address("8.8.8.8")),"address policy");
    require(authority("[::1]:443").text() == "[::1]:443" && duration_ms("1h30m") == 5400000,"CLI parsing");
    for (const auto& bad : {"*.127.0.0.1","a..com","-x.com","x.com,"}) {
        bool rejected = false;
        try { parse_scope(bad); } catch (...) { rejected = true; }
        require(rejected,"bad scope accepted");
    }
    std::cout << "Native unit tests passed\n";
}
static void help() {
    std::cout << "Traceglass C++ - authorized local traffic inspection\n"
        "  traceglass serve [-listen 127.0.0.1:8080] [-dashboard 127.0.0.1:9090]\n"
        "    [-data-dir ./data-cpp] [-inspect example.com,*.example.org]\n"
        "    [-allow-private] [-upstream-ca roots.pem] [-rules rules.json]\n"
        "    [-max-records 1000000] [-max-age 168h] [-queue-size 8192] [-max-active 256]\n"
        "  traceglass ca init [-data-dir ./data-cpp]\n"
        "  traceglass version | help\n"
        "Empty scope tunnels HTTPS. CA creation is explicit and NEVER installs trust.\n";
}
int main(int argc, char** argv) {
    std::signal(SIGPIPE,SIG_IGN);
    std::signal(SIGINT,on_signal); std::signal(SIGTERM,on_signal);
    try {
        if (argc < 2 || std::string(argv[1]) == "help" || std::string(argv[1]) == "-h" ||
            std::string(argv[1]) == "--help") { help(); return 0; }
        std::string command = argv[1];
        if (command == "version") { std::cout << "Traceglass C++ 0.1.0\n"; return 0; }
        if (command == "self-test") { self_test(); return 0; }
        if (command == "ca") {
            require(argc >= 3 && std::string(argv[2]) == "init","usage: ca init -data-dir DIR");
            init_ca(parse_options(argc,argv,3,true)); return 0;
        }
        require(command == "serve","unknown command");
        for (int i=2;i<argc;++i) if (std::string(argv[i]) == "-h" || std::string(argv[i]) == "--help") { help(); return 0; }
        Application app(parse_options(argc,argv,2,false));
        return app.run();
    } catch (const std::exception& e) {
        std::cerr << "Traceglass C++: " << e.what() << "\n"; return 1;
    }
}
