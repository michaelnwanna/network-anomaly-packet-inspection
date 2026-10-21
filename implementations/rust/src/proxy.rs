use crate::{
    ca::Authority,
    classify,
    store::{self, Record, Store},
};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::{
    body::Incoming,
    header::{HeaderMap, HeaderValue, HOST},
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use rustls::{pki_types::ServerName, ClientConfig};
use std::{
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
pub fn text(status: StatusCode, value: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(
            Full::new(Bytes::from_static(value.as_bytes()))
                .map_err(|e: Infallible| match e {})
                .boxed_unsync(),
        )
        .expect("static response")
}

#[derive(Clone, Debug, PartialEq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}
impl Target {
    pub fn parse(authority: &str, default: u16) -> Result<Self> {
        if authority.contains(['@', '/', '?', '#', '%']) || authority.ends_with(':') {
            bail!("invalid authority");
        }
        let a: hyper::http::uri::Authority = authority.parse()?;
        let host = classify::normalize(a.host().trim_start_matches('[').trim_end_matches(']'));
        if !classify::domain(&host) && host.parse::<IpAddr>().is_err() {
            bail!("invalid host");
        }
        let explicit = if authority.starts_with('[') {
            authority.rsplit_once("]:").map(|(_, port)| port)
        } else {
            authority.split_once(':').map(|(_, port)| port)
        };
        let port = match explicit {
            Some(port) => port.parse::<u16>().context("invalid port")?,
            None => default,
        };
        if port == 0 {
            bail!("invalid port");
        }
        Ok(Self { host, port })
    }
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

pub fn allowed(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_broadcast()
                && (allow_private
                    || !(v.is_private()
                        || v.is_loopback()
                        || v.is_link_local()
                        || v.octets()[0] == 0
                        || (v.octets()[0] == 100 && (64..128).contains(&v.octets()[1]))))
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return allowed(IpAddr::V4(v4), allow_private);
            }
            !v.is_unspecified()
                && !v.is_multicast()
                && (allow_private
                    || !(v.is_loopback()
                        || v.segments()[0] & 0xfe00 == 0xfc00
                        || v.segments()[0] & 0xffc0 == 0xfe80))
        }
    }
}

pub struct State {
    pub store: Arc<Store>,
    pub rules: classify::Rules,
    pub scope: Vec<String>,
    pub ca: Option<Authority>,
    pub tls: Arc<ClientConfig>,
    pub allow_private: bool,
    pub slots: Arc<Semaphore>,
    pub max_active: usize,
    pub cancel: CancellationToken,
    pub tasks: TaskTracker,
}
impl State {
    pub fn active(&self) -> usize {
        self.max_active - self.slots.available_permits()
    }
    async fn dial(&self, target: &Target) -> Result<TcpStream> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let addresses: Vec<SocketAddr> =
                tokio::net::lookup_host((target.host.as_str(), target.port))
                    .await?
                    .collect();
            if addresses.is_empty()
                || addresses
                    .iter()
                    .any(|a| !allowed(a.ip(), self.allow_private))
            {
                bail!("destination denied");
            }
            let mut last = None;
            for addr in addresses {
                match TcpStream::connect(addr).await {
                    Ok(stream) => {
                        stream.set_nodelay(true)?;
                        return Ok(stream);
                    }
                    Err(e) => last = Some(e),
                }
            }
            Err(last.context("no addresses")?.into())
        })
        .await
        .context("destination timeout")?
    }
}

struct Flow {
    state: Arc<State>,
    record: Mutex<Record>,
    sent: AtomicU64,
    received: AtomicU64,
    request_done: AtomicBool,
    started: Instant,
    _permit: Option<OwnedSemaphorePermit>,
}
impl Flow {
    fn new(
        state: Arc<State>,
        method: &str,
        target: &Target,
        scheme: &str,
        mode: &str,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state,
            record: Mutex::new(Record {
                timestamp: store::now(),
                method: method.to_owned(),
                host: target.host.clone(),
                port: target.port,
                scheme: scheme.into(),
                mode: mode.into(),
                ..Default::default()
            }),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            request_done: AtomicBool::new(false),
            started: Instant::now(),
            _permit: permit,
        })
    }
    fn status(&self, code: u16) {
        self.record.lock().expect("record mutex").status = code;
    }
    fn error(&self, error: &str) {
        let mut r = self.record.lock().expect("record mutex");
        if r.error_code.is_empty() {
            r.error_code = error.into();
        }
    }
}
impl Drop for Flow {
    fn drop(&mut self) {
        let mut r = self.record.lock().expect("record mutex").clone();
        if r.method.is_empty() {
            return;
        }
        r.request_bytes = self.sent.load(Ordering::Relaxed);
        r.response_bytes = self.received.load(Ordering::Relaxed);
        r.duration_ms = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        r.flags = self
            .state
            .rules
            .flags(&r.host, r.port, r.request_bytes, r.response_bytes);
        self.state.store.enqueue(r);
    }
}

struct Metered<T> {
    io: T,
    flow: Arc<Flow>,
    upload: bool,
}

impl<T: AsyncRead + Unpin> AsyncRead for Metered<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buffer)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Metered<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.io).poll_write(cx, buffer);
        if let Poll::Ready(Ok(n)) = &result {
            let counter = if self.upload {
                &self.flow.sent
            } else {
                &self.flow.received
            };
            counter.fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

struct Counted {
    body: Incoming,
    flow: Arc<Flow>,
    request: bool,
    done: bool,
}
impl Counted {
    fn new(body: Incoming, flow: Arc<Flow>, request: bool) -> Self {
        let done = body.is_end_stream();
        if request && done {
            flow.request_done.store(true, Ordering::Relaxed);
        }
        Self {
            body,
            flow,
            request,
            done,
        }
    }
}
impl Body for Counted {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        match Pin::new(&mut self.body).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let counter = if self.request {
                        &self.flow.sent
                    } else {
                        &self.flow.received
                    };
                    counter.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                if self.body.is_end_stream() {
                    self.done = true;
                    if self.request {
                        self.flow.request_done.store(true, Ordering::Relaxed);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                self.flow.error(if self.request {
                    "request-body-failed"
                } else {
                    "stream-failed"
                });
                self.done = true;
                Poll::Ready(Some(Err(Box::new(e))))
            }
            Poll::Ready(None) => {
                self.done = true;
                if self.request {
                    self.flow.request_done.store(true, Ordering::Relaxed);
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}
impl Drop for Counted {
    fn drop(&mut self) {
        if !self.done {
            self.flow.error(if self.request {
                "request-body-failed"
            } else {
                "stream-failed"
            });
        }
    }
}

fn strip(headers: &mut HeaderMap) {
    let nominated: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|s| s.split(',').map(|x| x.trim().to_ascii_lowercase()))
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

pub fn handle(
    req: Request<Incoming>,
    state: Arc<State>,
    inner: Option<Target>,
) -> Pin<Box<dyn Future<Output = std::result::Result<Response<ProxyBody>, Infallible>> + Send>> {
    Box::pin(handle_request(req, state, inner))
}

async fn handle_request(
    mut req: Request<Incoming>,
    state: Arc<State>,
    inner: Option<Target>,
) -> std::result::Result<Response<ProxyBody>, Infallible> {
    if state.cancel.is_cancelled() {
        return Ok(text(StatusCode::SERVICE_UNAVAILABLE, "shutting down"));
    }
    if req.method().as_str().len() > 32 {
        return Ok(text(StatusCode::BAD_REQUEST, "method too long"));
    }
    if inner.is_none() && req.method() == Method::CONNECT {
        return Ok(connect(req, state).await);
    }
    let (target, scheme, mode) = if let Some(target) = inner {
        let valid = req.method() != Method::CONNECT
            && req
                .headers()
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .and_then(|h| Target::parse(h, 443).ok())
                .as_ref()
                == Some(&target)
            && (req.uri().authority().is_none()
                || req.uri().scheme_str() == Some("https")
                    && req
                        .uri()
                        .authority()
                        .and_then(|a| Target::parse(a.as_str(), 443).ok())
                        .as_ref()
                        == Some(&target));
        if !valid {
            return Ok(text(
                StatusCode::MISDIRECTED_REQUEST,
                "inspection authority mismatch",
            ));
        }
        (target, "https", "inspected")
    } else {
        if req.uri().scheme_str() != Some("http") {
            return Ok(text(
                StatusCode::BAD_REQUEST,
                "explicit http proxy URI required",
            ));
        }
        let target = match req
            .uri()
            .authority()
            .and_then(|a| Target::parse(a.as_str(), 80).ok())
        {
            Some(t) => t,
            None => return Ok(text(StatusCode::BAD_REQUEST, "invalid destination")),
        };
        (target, "http", "http")
    };
    let permit = if mode == "http" {
        match state.slots.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                return Ok(text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "concurrency limit reached",
                ))
            }
        }
    } else {
        None
    };
    let flow = Flow::new(
        state.clone(),
        req.method().as_str(),
        &target,
        scheme,
        mode,
        permit,
    );
    if req.headers().contains_key("upgrade") {
        flow.status(501);
        flow.error("upgrade-unsupported");
        return Ok(text(StatusCode::NOT_IMPLEMENTED, "upgrades unsupported"));
    }
    let io = match upstream(&state, &target, scheme == "https").await {
        Ok(io) => io,
        Err(_) => {
            flow.status(502);
            flow.error("upstream-failed");
            return Ok(text(StatusCode::BAD_GATEWAY, "upstream failed"));
        }
    };
    let handshake = hyper::client::conn::http1::handshake::<_, ProxyBody>(TokioIo::new(io)).await;
    let (mut sender, conn) = match handshake {
        Ok(pair) => pair,
        Err(_) => {
            flow.status(502);
            flow.error("upstream-failed");
            return Ok(text(StatusCode::BAD_GATEWAY, "upstream failed"));
        }
    };
    let cancel = state.cancel.clone();
    state.tasks.spawn(async move {
        tokio::select! {
            result=conn=>if let Err(e)=result {eprintln!("upstream connection ended: {e}");},
            _=cancel.cancelled()=>{},
        }
    });
    strip(req.headers_mut());
    req.headers_mut().insert(
        HOST,
        HeaderValue::from_str(&target.authority()).expect("validated authority"),
    );
    *req.uri_mut() = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .parse()
        .expect("parsed URI path");
    let (parts, body) = req.into_parts();
    let outgoing =
        Request::from_parts(parts, Counted::new(body, flow.clone(), true).boxed_unsync());
    let response =
        tokio::time::timeout(Duration::from_secs(20), sender.send_request(outgoing)).await;
    match response {
        Ok(Ok(mut response)) => {
            if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                flow.status(501);
                flow.error("upgrade-unsupported");
                return Ok(text(StatusCode::NOT_IMPLEMENTED, "upgrades unsupported"));
            }
            flow.status(response.status().as_u16());
            strip(response.headers_mut());
            // Closing avoids reusing a client connection with an early/incomplete upload.
            response
                .headers_mut()
                .insert("connection", HeaderValue::from_static("close"));
            let (parts, body) = response.into_parts();
            Ok(Response::from_parts(
                parts,
                Counted::new(body, flow, false).boxed_unsync(),
            ))
        }
        _ => {
            flow.status(502);
            flow.error("upstream-failed");
            Ok(text(StatusCode::BAD_GATEWAY, "upstream failed"))
        }
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
async fn upstream(state: &State, target: &Target, tls: bool) -> Result<Box<dyn Io>> {
    let stream = state.dial(target).await?;
    if !tls {
        return Ok(Box::new(stream));
    }
    let name = ServerName::try_from(target.host.clone())?;
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        TlsConnector::from(state.tls.clone()).connect(name, stream),
    )
    .await??;
    Ok(Box::new(stream))
}

async fn connect(mut req: Request<Incoming>, state: Arc<State>) -> Response<ProxyBody> {
    let target = match req
        .uri()
        .authority()
        .and_then(|a| Target::parse(a.as_str(), 443).ok())
    {
        Some(t) => t,
        None => return text(StatusCode::BAD_REQUEST, "invalid CONNECT authority"),
    };
    let permit = match state.slots.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return text(StatusCode::SERVICE_UNAVAILABLE, "concurrency limit reached"),
    };
    let inspected = classify::matches(&state.scope, &target.host);
    let mode = if inspected { "inspected" } else { "tunnel" };
    if inspected {
        let config = match state
            .ca
            .as_ref()
            .context("missing CA")
            .and_then(|ca| ca.server(&target.host))
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("leaf signing failed: {e:#}");
                return text(StatusCode::BAD_GATEWAY, "leaf signing failed");
            }
        };
        let upgrade = hyper::upgrade::on(&mut req);
        let cloned = state.clone();
        state.tasks.spawn(async move {
            let flow=Flow::new(cloned.clone(),"CONNECT",&target,"https",mode,None);
            let _permit=permit;
            tokio::select! {
                _=cloned.cancel.cancelled()=>{flow.error("client-tls-failed");}
                result=async {
                    let upgraded=upgrade.await?;
                    let io=TokioIo::new(upgraded);
                    let tls=tokio::time::timeout(Duration::from_secs(10),TlsAcceptor::from(config).accept(io)).await??;
                    Ok::<_,anyhow::Error>(tls)
                }=>{
                    match result {
                        Ok(tls)=>{
                            // A successful CONNECT handshake is not an extra inspected HTTP exchange.
                            {
                                let mut record=flow.record.lock().expect("record mutex");
                                record.method.clear();
                            }
                            let service=hyper::service::service_fn(|r|handle(r,cloned.clone(),Some(target.clone())));
                            let conn=hyper::server::conn::http1::Builder::new().max_buf_size(65536).serve_connection(TokioIo::new(tls),service);
                            tokio::select! {
                                result=conn=>if let Err(e)=result {eprintln!("inspected connection ended: {e}");},
                                _=cloned.cancel.cancelled()=>{},
                            }
                        }
                        Err(_)=>{flow.status(502);flow.error("client-tls-failed");}
                    }
                }
            }
        });
        text(StatusCode::OK, "")
    } else {
        let flow = Flow::new(
            state.clone(),
            "CONNECT",
            &target,
            "https",
            mode,
            Some(permit),
        );
        let upstream = match state.dial(&target).await {
            Ok(s) => s,
            Err(_) => {
                flow.status(502);
                flow.error("connect-failed");
                return text(StatusCode::BAD_GATEWAY, "connect failed");
            }
        };
        flow.status(200);
        let upgrade = hyper::upgrade::on(&mut req);
        let cloned = state.clone();
        state.tasks.spawn(async move {
            tokio::select! {
                _=cloned.cancel.cancelled()=>{flow.error("tunnel-io");}
                result=async {
                    let upgraded=upgrade.await?;
                    let mut io=Metered {io:TokioIo::new(upgraded),flow:flow.clone(),upload:false};
                    let mut upstream=Metered {io:upstream,flow:flow.clone(),upload:true};
                    tokio::io::copy_bidirectional(&mut io,&mut upstream).await?;
                    Ok::<_,anyhow::Error>(())
                }=>match result {
                    Ok(())=>{},
                    Err(_)=>flow.error("tunnel-io"),
                }
            }
        });
        text(StatusCode::OK, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn destinations() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "::1",
            "::ffff:127.0.0.1",
            "fe80::1",
            "fc00::1",
        ] {
            assert!(!allowed(ip.parse().unwrap(), false), "{ip}");
            assert!(allowed(ip.parse().unwrap(), true), "{ip}");
        }
        assert!(allowed("8.8.8.8".parse().unwrap(), false));
        assert!(!allowed("0.0.0.0".parse().unwrap(), true));
        for bad in [
            "user@host:80",
            "host:0",
            "host:65536",
            "host:",
            "host/path",
            "a%20b:80",
        ] {
            assert!(Target::parse(bad, 80).is_err(), "{bad}");
        }
        assert_eq!(Target::parse("[::1]:443", 80).unwrap().host, "::1");
    }
}
