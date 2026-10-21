use crate::{
    proxy::{text, ProxyBody, State},
    store::Filter,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response, StatusCode};
use serde_json::json;
use std::{convert::Infallible, sync::Arc};
use subtle::ConstantTimeEq;

pub struct Config {
    pub host: String,
    pub proxy: String,
    pub token: String,
    pub max_records: i64,
    pub max_age: String,
    pub allow_private: bool,
}

fn data(content_type: &str, data: Vec<u8>) -> Response<ProxyBody> {
    Response::builder()
        .header("content-type", content_type)
        .body(
            Full::new(Bytes::from(data))
                .map_err(|e: Infallible| match e {})
                .boxed_unsync(),
        )
        .expect("static response")
}
fn filter(query: &str) -> anyhow::Result<Filter> {
    let mut f = Filter {
        limit: 100,
        ..Default::default()
    };
    let mut seen = std::collections::HashSet::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if !seen.insert(key.clone()) {
            continue;
        }
        match key.as_ref() {
            "limit" => {
                f.limit = value.parse()?;
                if !(1..=200).contains(&f.limit) {
                    anyhow::bail!("limit");
                }
            }
            "before" => {
                f.before = value.parse()?;
                if f.before < 1 {
                    anyhow::bail!("before");
                }
            }
            "host" => {
                f.host = value.to_lowercase();
                if f.host.len() > 253 {
                    anyhow::bail!("host");
                }
            }
            "flagged" => match value.as_ref() {
                "true" => f.flagged = true,
                "false" | "" => {}
                _ => anyhow::bail!("flagged"),
            },
            _ => {}
        }
    }
    Ok(f)
}
pub async fn handle(
    req: Request<Incoming>,
    state: Arc<State>,
    config: Arc<Config>,
) -> Result<Response<ProxyBody>, Infallible> {
    let mut response = route(req, state, config).await;
    for (key,value) in [
        ("content-security-policy","default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
        ("x-content-type-options","nosniff"),("referrer-policy","no-referrer"),
        ("x-frame-options","DENY"),("cache-control","no-store"),
    ] {response.headers_mut().insert(key,hyper::header::HeaderValue::from_static(value));}
    Ok(response)
}

async fn route(
    req: Request<Incoming>,
    state: Arc<State>,
    config: Arc<Config>,
) -> Response<ProxyBody> {
    if req.headers().get("host").and_then(|v| v.to_str().ok()) != Some(config.host.as_str()) {
        return text(StatusCode::FORBIDDEN, "unexpected dashboard host");
    }
    if let Some(origin) = req.headers().get("origin") {
        if !origin.is_empty() && origin.as_bytes() != format!("http://{}", config.host).as_bytes() {
            return text(StatusCode::FORBIDDEN, "cross-origin access denied");
        }
    }
    if req.uri().path().starts_with("/api/") {
        let supplied = req
            .headers()
            .get("authorization")
            .map(|v| v.as_bytes())
            .unwrap_or(&[]);
        let expected = format!("Bearer {}", config.token);
        if !bool::from(supplied.ct_eq(expected.as_bytes())) {
            return text(StatusCode::UNAUTHORIZED, "dashboard bearer token required");
        }
        if req.method() != hyper::Method::GET {
            return text(StatusCode::METHOD_NOT_ALLOWED, "read-only API");
        }
        let query = req.uri().query().unwrap_or("").to_owned();
        let path = req.uri().path().to_owned();
        if path == "/api/records" && filter(&query).is_err() {
            return text(StatusCode::BAD_REQUEST, "invalid filters");
        }
        let result=tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
            match path.as_str() {
                "/api/status"=>Ok(json!({
                    "stats":state.store.stats()?,"active":state.active(),"proxy":config.proxy,
                    "inspect":state.scope,"max_records":config.max_records,"max_age":config.max_age,"allow_private":config.allow_private,
                })),
                "/api/records"=>{
                    let f=filter(&query)?;
                    let limit=f.limit;
                    let rows=state.store.list(f)?;
                    let next=if rows.len()==limit {rows.last().expect("full page").id}else{0};
                    Ok(json!({"records":rows,"next_before":next}))
                }
                _=>anyhow::bail!("not-found"),
            }
        }).await;
        return match result {
            Ok(Ok(value)) => data(
                "application/json",
                serde_json::to_vec(&value).expect("JSON value"),
            ),
            Ok(Err(e)) if e.to_string() == "not-found" => text(StatusCode::NOT_FOUND, "not found"),
            error => {
                eprintln!("metadata query failed: {error:?}");
                text(StatusCode::INTERNAL_SERVER_ERROR, "metadata query failed")
            }
        };
    }
    if req.method() != hyper::Method::GET && req.method() != hyper::Method::HEAD {
        return text(StatusCode::METHOD_NOT_ALLOWED, "read-only dashboard");
    }
    let (mime, bytes): (&str, &[u8]) = match req.uri().path() {
        "/" | "/index.html" => (
            "text/html; charset=utf-8",
            include_bytes!("../../../internal/dashboard/web/index.html"),
        ),
        "/app.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../../../internal/dashboard/web/app.js"),
        ),
        "/style.css" => (
            "text/css; charset=utf-8",
            include_bytes!("../../../internal/dashboard/web/style.css"),
        ),
        _ => return text(StatusCode::NOT_FOUND, "not found"),
    };
    data(
        mime,
        if req.method() == hyper::Method::HEAD {
            vec![]
        } else {
            bytes.to_vec()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_filters() {
        for q in [
            "limit=0",
            "limit=201",
            "before=0",
            "before=-1",
            "flagged=yes",
            "limit=1.0",
        ] {
            assert!(filter(q).is_err(), "{q}");
        }
        let f = filter("host=A%25B&flagged=true&limit=2&before=3").unwrap();
        assert_eq!(f.host, "a%b");
        assert_eq!(f.limit, 2);
        assert!(f.flagged);
    }
}
