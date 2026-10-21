mod ca;
mod classify;
mod dashboard;
mod proxy;
mod store;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

#[derive(Parser)]
#[command(
    name = "traceglass-rust",
    version,
    about = "Native local-only Traceglass HTTP/CONNECT inspection proxy"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve(Serve),
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    Version,
}
#[derive(Subcommand)]
enum CaCommand {
    Init {
        #[arg(long, default_value = "./data-rust")]
        data_dir: PathBuf,
    },
}

#[derive(Parser)]
struct Serve {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:9090")]
    dashboard: SocketAddr,
    #[arg(long, default_value = "./data-rust")]
    data_dir: PathBuf,
    #[arg(long, default_value = "")]
    inspect: String,
    #[arg(long)]
    rules: Option<PathBuf>,
    #[arg(long)]
    upstream_ca: Option<PathBuf>,
    #[arg(long, default_value = "1000000")]
    max_records: i64,
    #[arg(long,default_value="168h",value_parser=parse_duration)]
    max_age: Duration,
    #[arg(long, default_value = "8192")]
    queue_size: usize,
    #[arg(long, default_value = "256")]
    max_active: usize,
    #[arg(long)]
    allow_private: bool,
}
fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
    let mut remaining = s;
    let mut seconds = 0f64;
    while !remaining.is_empty() {
        let end = remaining
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .ok_or("duration needs units (h, m, s, ms, us, ns)")?;
        if end == 0 {
            return Err("invalid duration".into());
        }
        let number: f64 = remaining[..end].parse().map_err(|_| "invalid duration")?;
        remaining = &remaining[end..];
        let (unit, scale) = if remaining.starts_with("ms") {
            ("ms", 0.001)
        } else if remaining.starts_with("us") {
            ("us", 0.000001)
        } else if remaining.starts_with("ns") {
            ("ns", 0.000000001)
        } else if remaining.starts_with('h') {
            ("h", 3600.)
        } else if remaining.starts_with('m') {
            ("m", 60.)
        } else if remaining.starts_with('s') {
            ("s", 1.)
        } else {
            return Err("invalid duration unit".into());
        };
        seconds += number * scale;
        remaining = &remaining[unit.len()..];
    }
    if !seconds.is_finite() || seconds <= 0. || seconds > 315_360_000. {
        return Err("duration must be positive and at most ten years".into());
    }
    Ok(Duration::from_secs_f64(seconds))
}
fn go_duration(d: Duration) -> String {
    let s = d.as_secs();
    if d.subsec_nanos() != 0 {
        return format!("{}s", d.as_secs_f64());
    }
    if s >= 3600 {
        format!("{}h{}m{}s", s / 3600, (s % 3600) / 60, s % 60)
    } else if s >= 60 {
        format!("{}m{}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Accept Go's single-dash long flags without altering flag values.
    let flags = [
        "listen",
        "dashboard",
        "data-dir",
        "inspect",
        "rules",
        "upstream-ca",
        "max-records",
        "max-age",
        "queue-size",
        "max-active",
        "allow-private",
    ];
    let args = std::env::args().map(|a| {
        let head = a
            .strip_prefix('-')
            .unwrap_or("")
            .split('=')
            .next()
            .unwrap_or("");
        if flags.contains(&head) {
            format!("-{a}")
        } else {
            a
        }
    });
    let cli = Cli::parse_from(args);
    let result=match cli.command {
        Command::Version=>{println!("traceglass-rust {}",env!("CARGO_PKG_VERSION"));Ok(())}
        Command::Ca {command:CaCommand::Init {data_dir}}=>ca::init(&data_dir).map(|()|println!(
            "Local CA created: {}\nPrivate key: {}\nNo trust was installed. Use explicit per-client trust only.",
            data_dir.join(ca::CERT).display(),data_dir.join(ca::KEY).display())),
        Command::Serve(options)=>serve(options).await,
    };
    if let Err(e) = result {
        eprintln!("traceglass-rust stopped: {e:#}");
        std::process::exit(1);
    }
}

async fn signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {r=tokio::signal::ctrl_c()=>r?,_=term.recv()=>{}}
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn serve(o: Serve) -> Result<()> {
    if !o.listen.ip().is_loopback() || !o.dashboard.ip().is_loopback() {
        bail!("listeners must be loopback IP literals");
    }
    if !(1..=4096).contains(&o.max_active)
        || !(1..=1_000_000).contains(&o.queue_size)
        || o.max_records < 1
    {
        bail!("invalid active, queue or retention limits");
    }
    let scope = classify::scope(&o.inspect)?;
    let authority = if scope.is_empty() {
        None
    } else {
        Some(ca::Authority::load(&o.data_dir)?)
    };
    let rules = classify::Rules::load(o.rules.as_deref())?;
    let tls = ca::client(o.upstream_ca.as_deref())?;
    let proxy_listener = TcpListener::bind(o.listen).await.context("bind proxy")?;
    let ui_listener = TcpListener::bind(o.dashboard)
        .await
        .context("bind dashboard")?;
    let proxy_addr = proxy_listener.local_addr()?;
    let ui_addr = ui_listener.local_addr()?;
    let cancel = CancellationToken::new();
    let store = store::Store::open(
        &o.data_dir,
        o.max_records,
        o.max_age,
        o.queue_size,
        cancel.clone(),
    )?;
    let state = Arc::new(proxy::State {
        store: store.clone(),
        rules,
        scope,
        ca: authority,
        tls,
        allow_private: o.allow_private,
        slots: Arc::new(Semaphore::new(o.max_active)),
        max_active: o.max_active,
        cancel: cancel.clone(),
        tasks: TaskTracker::new(),
    });
    let token: String = (0..32)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();
    let config = Arc::new(dashboard::Config {
        host: ui_addr.to_string(),
        proxy: proxy_addr.to_string(),
        token: token.clone(),
        max_records: o.max_records,
        max_age: go_duration(o.max_age),
        allow_private: o.allow_private,
    });
    println!("Traceglass Rust {}\nProxy: http://{}\nDashboard: http://{}/#token={}\nHTTPS inspection scope: {:?}\nData: {}",
        env!("CARGO_PKG_VERSION"),proxy_addr,ui_addr,token,state.scope,o.data_dir.display());
    use std::io::Write;
    std::io::stdout().flush()?;
    if o.allow_private {
        eprintln!("WARNING: private destinations enabled for authorized local testing");
    }
    let connections = Arc::new(Semaphore::new(o.max_active * 2 + 32));
    let result = loop {
        tokio::select! {
            s=signal()=>{break s;}
            _=cancel.cancelled()=>{break Err(anyhow::anyhow!("fatal metadata writer error"));}
            accepted=proxy_listener.accept()=>{
                let (stream,_)=match accepted {Ok(v)=>v,Err(e)=>{break Err(e.into());}};
                let Ok(permit)=connections.clone().try_acquire_owned() else {drop(stream);continue;};
                let cloned=state.clone();
                state.tasks.spawn(async move {
                    let _permit=permit;
                    let service=service_fn(|r|proxy::handle(r,cloned.clone(),None));
                    let connection=hyper::server::conn::http1::Builder::new().max_buf_size(65536)
                        .serve_connection(TokioIo::new(stream),service).with_upgrades();
                    tokio::select! {
                        r=tokio::time::timeout(Duration::from_secs(120),connection)=>match r {
                            Ok(Ok(()))=>{},Ok(Err(e))=>eprintln!("proxy connection ended: {e}"),Err(_)=>eprintln!("proxy connection deadline exceeded"),
                        },
                        _=cloned.cancel.cancelled()=>{},
                    }
                });
            }
            accepted=ui_listener.accept()=>{
                let (stream,_)=match accepted {Ok(v)=>v,Err(e)=>{break Err(e.into());}};
                let Ok(permit)=connections.clone().try_acquire_owned() else {drop(stream);continue;};
                let cloned=state.clone();let config=config.clone();
                state.tasks.spawn(async move {
                    let _permit=permit;
                    let service=service_fn(|r|dashboard::handle(r,cloned.clone(),config.clone()));
                    let connection=hyper::server::conn::http1::Builder::new().max_buf_size(16384)
                        .serve_connection(TokioIo::new(stream),service);
                    tokio::select! {
                        r=tokio::time::timeout(Duration::from_secs(30),connection)=>match r {
                            Ok(Ok(()))=>{},Ok(Err(e))=>eprintln!("dashboard connection ended: {e}"),Err(_)=>eprintln!("dashboard connection deadline exceeded"),
                        },
                        _=cloned.cancel.cancelled()=>{},
                    };
                });
            }
        }
    };
    drop(proxy_listener);
    drop(ui_listener);
    cancel.cancel();
    state.tasks.close();
    state.tasks.wait().await;
    let close = tokio::task::spawn_blocking(move || store.close()).await?;
    result.and(close)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durations() {
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        for invalid in ["0s", "-1h", "nan", "1", "1d"] {
            assert!(parse_duration(invalid).is_err());
        }
        assert_eq!(go_duration(Duration::from_secs(604800)), "168h0m0s");
    }
}
