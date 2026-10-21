use anyhow::{bail, Result};
use serde::Deserialize;
use std::net::IpAddr;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    tracking_domains: Vec<String>,
    allowed_ports: Vec<u16>,
    large_payload_bytes: u64,
}

pub fn normalize(host: &str) -> String {
    host.to_ascii_lowercase().trim_end_matches('.').to_owned()
}

pub fn domain(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

pub fn scope(value: &str) -> Result<Vec<String>> {
    if value.is_empty() {
        return Ok(vec![]);
    }
    value
        .split(',')
        .map(|p| {
            let p = normalize(p.trim());
            let base = p.strip_prefix("*.").unwrap_or(&p);
            if !domain(base) && (base != p || base.parse::<IpAddr>().is_err()) {
                bail!("invalid inspection scope");
            }
            Ok(p)
        })
        .collect()
}

pub fn matches(scope: &[String], host: &str) -> bool {
    let host = normalize(host);
    scope
        .iter()
        .any(|p| p == &host || p.starts_with("*.") && host.ends_with(&p[1..]))
}

impl Rules {
    pub fn load(path: Option<&std::path::Path>) -> Result<Self> {
        let data = match path {
            Some(p) => {
                let f = std::fs::File::open(p)?;
                use std::io::Read;
                let mut data = Vec::new();
                f.take(1_048_577).read_to_end(&mut data)?;
                data
            }
            None => include_bytes!("../../../internal/classify/defaults.json").to_vec(),
        };
        if data.len() > 1_048_576 {
            bail!("rules exceed 1 MiB");
        }
        let mut rules: Self = serde_json::from_slice(&data)?;
        if rules.large_payload_bytes == 0
            || rules.allowed_ports.is_empty()
            || rules.allowed_ports.contains(&0)
        {
            bail!("positive threshold and valid allowed ports required");
        }
        for d in &mut rules.tracking_domains {
            *d = normalize(d);
            if !domain(d) {
                bail!("invalid tracking domain");
            }
        }
        Ok(rules)
    }

    pub fn flags(&self, host: &str, port: u16, sent: u64, received: u64) -> Vec<String> {
        let host = normalize(host);
        let mut flags = vec![];
        if self
            .tracking_domains
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
        {
            flags.push("known-tracker".into());
        }
        if sent.saturating_add(received) > self.large_payload_bytes {
            flags.push("large-payload".into());
        }
        if !self.allowed_ports.contains(&port) {
            flags.push("unsanctioned-port".into());
        }
        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundaries() {
        let r = Rules::load(None).unwrap();
        assert_eq!(
            r.flags("evilgoogle-analytics.com", 80, 0, 0),
            Vec::<String>::new()
        );
        assert_eq!(
            r.flags("X.Google-Analytics.com.", 443, 0, 0),
            vec!["known-tracker"]
        );
        assert!(r.flags("example.com", 443, 1_048_576, 0).is_empty());
        assert_eq!(
            r.flags("example.com", 42, 1_048_576, 1),
            vec!["large-payload", "unsanctioned-port"]
        );
        let s = scope("*.example.com,127.0.0.1").unwrap();
        assert!(!matches(&s, "example.com"));
        assert!(matches(&s, "a.example.com"));
        assert!(!matches(&s, "badexample.com"));
        assert!(scope("*.127.0.0.1").is_err());
    }

    #[test]
    fn shared_vectors() {
        let data: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/conformance/classification.json"
        ))
        .unwrap();
        let rules: Rules = serde_json::from_value(data["rules"].clone()).unwrap();
        for case in data["classifications"].as_array().unwrap() {
            let expected: Vec<String> = serde_json::from_value(case["flags"].clone()).unwrap();
            assert_eq!(
                rules.flags(
                    case["host"].as_str().unwrap(),
                    case["port"].as_u64().unwrap() as u16,
                    case["sent"].as_u64().unwrap(),
                    case["received"].as_u64().unwrap()
                ),
                expected,
                "{}",
                case["name"]
            );
        }
        let patterns = scope(data["inspection_scope"].as_str().unwrap()).unwrap();
        for case in data["inspection_matches"].as_array().unwrap() {
            assert_eq!(
                matches(&patterns, case["host"].as_str().unwrap()),
                case["matches"].as_bool().unwrap()
            );
        }
        for pattern in data["invalid_scopes"].as_array().unwrap() {
            assert!(scope(pattern.as_str().unwrap()).is_err());
        }
    }
}
