use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore, ServerConfig,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::Arc,
};

pub const CERT: &str = "traceglass-ca.crt";
pub const KEY: &str = "traceglass-ca.key";

pub fn private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

pub fn init(dir: &Path) -> Result<()> {
    private_dir(dir)?;
    if dir.join(CERT).exists() || dir.join(KEY).exists() {
        bail!("refusing to overwrite existing CA");
    }
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(730);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "Traceglass Rust local inspection CA");
    let cert = params.self_signed(&key)?;
    create(&dir.join(KEY), key.serialize_pem().as_bytes())?;
    create(&dir.join(CERT), cert.pem().as_bytes())?;
    Ok(())
}

pub struct Authority {
    key: KeyPair,
    cert: rcgen::Certificate,
}
impl Authority {
    pub fn load(dir: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(dir.join(KEY))?.permissions().mode() & 0o077 != 0 {
                bail!("CA private key permissions must be owner-only");
            }
        }
        let pem = fs::read_to_string(dir.join(CERT)).context("run ca init first")?;
        let key = KeyPair::from_pem(&fs::read_to_string(dir.join(KEY))?)?;
        let params = CertificateParams::from_ca_cert_pem(&pem)?;
        let now = time::OffsetDateTime::now_utc();
        if !matches!(params.is_ca, IsCa::Ca(_))
            || !params.key_usages.contains(&KeyUsagePurpose::KeyCertSign)
            || params.not_before > now
            || params.not_after <= now + time::Duration::minutes(1)
        {
            bail!("invalid or expired inspection CA");
        }
        let cert = params.self_signed(&key)?;
        // Reject a mismatched certificate/key rather than creating an untrusted signing identity.
        let original = rustls_pemfile::certs(&mut pem.as_bytes())
            .next()
            .context("missing CA certificate")??;
        let regenerated = cert.der();
        use rustls::pki_types::pem::PemObject;
        let _ = CertificateDer::from_pem_slice(pem.as_bytes())?;
        // rcgen parses the CA's public key through x509-parser in the check below.
        if original.as_ref() != regenerated.as_ref() {
            // Certificate signatures may differ (ECDSA); compare SPKI using rustls webpki validation below.
            let mut roots = RootCertStore::empty();
            roots.add(original)?;
            let leaf = leaf(&cert, &key, "traceglass-key-check.invalid")?;
            let verifier =
                rustls::client::WebPkiServerVerifier::builder(Arc::new(roots)).build()?;
            use rustls::client::danger::ServerCertVerifier;
            verifier
                .verify_server_cert(
                    &leaf,
                    &[],
                    &"traceglass-key-check.invalid".try_into()?,
                    &[],
                    rustls::pki_types::UnixTime::now(),
                )
                .context("CA certificate/key mismatch or unusable CA")?;
        }
        Ok(Self { key, cert })
    }

    pub fn server(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
        params.not_after = (time::OffsetDateTime::now_utc() + time::Duration::days(1))
            .min(self.cert.params().not_after);
        if params.not_after <= time::OffsetDateTime::now_utc() {
            bail!("inspection CA has expired");
        }
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &self.cert, &self.key)?;
        let pk = PrivateKeyDer::try_from(key.serialize_der()).map_err(anyhow::Error::msg)?;
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], pk)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

fn leaf(cert: &rcgen::Certificate, key: &KeyPair, host: &str) -> Result<CertificateDer<'static>> {
    let leaf_key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![host.to_owned()])?;
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after =
        (time::OffsetDateTime::now_utc() + time::Duration::days(1)).min(cert.params().not_after);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    Ok(params.signed_by(&leaf_key, cert, key)?.der().clone())
}

pub fn client(extra: Option<&Path>) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        roots.add(cert)?;
    }
    for error in native.errors {
        eprintln!("OS root loading warning: {error}");
    }
    if let Some(path) = extra {
        let data = fs::read(path)?;
        let certs = rustls_pemfile::certs(&mut data.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            bail!("upstream CA file contains no certificates");
        }
        for cert in certs {
            roots.add(cert)?;
        }
    }
    if roots.is_empty() {
        bail!("no upstream trust roots available");
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
