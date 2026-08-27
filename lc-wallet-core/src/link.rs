//! App-link and QR payload parsing.
//!
//! Vendored from `sideswap-io/sideswap_rust` (`sideswap_common/src/wallet_connect.rs`,
//! MIT). Both accepted forms carry a `request_id` query parameter:
//!
//! - `liquidconnect://login/?request_id=…` (the registered custom scheme)
//! - `https://app.sideswap.io/login/?request_id=…` (app link)
//!
//! `mobile=true` means a browser on the SAME device is waiting, so the wallet
//! should minimize and hand the person back after acting. A scanned QR must
//! never carry it: the scanning device has no browser to return to.

use std::collections::BTreeMap;
use std::str::FromStr;

use anyhow::{anyhow, bail, ensure, Context as _};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Login,
    Sign,
}

#[derive(Debug)]
pub struct AppLink {
    pub link_type: LinkType,
    pub request_id: String,
    pub is_mobile: bool,
}

pub fn parse_app_link(url: &str) -> Result<AppLink, anyhow::Error> {
    let url = url::Url::parse(url)?;

    let host = url.host().ok_or_else(|| anyhow!("no host"))?;
    let domain = match host {
        url::Host::Domain(domain) => domain.to_owned(),
        url::Host::Ipv4(ipv4_addr) => bail!("ipv4 links are not supported: {ipv4_addr}"),
        url::Host::Ipv6(ipv6_addr) => bail!("ipv6 links are not supported: {ipv6_addr}"),
    };
    ensure!(url.port().is_none());

    let params = url
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<String, String>>();

    let is_mobile = params
        .get("mobile")
        .map(|value| bool::from_str(value))
        .transpose()
        .context("invalid `mobile` query parameter value")?
        .unwrap_or_default();

    let request_id = params
        .get("request_id")
        .ok_or_else(|| anyhow!("invalid link: no request_id query parameter"))?
        .clone();

    let link_type = match (url.scheme(), domain.as_str(), url.path()) {
        ("https", "app.sideswap.io", "/login/") | ("liquidconnect", "login", "/") => {
            LinkType::Login
        }
        ("https", "app.sideswap.io", "/sign/") | ("liquidconnect", "sign", "/") => LinkType::Sign,
        _ => bail!("unsupported URL: {url}"),
    };

    Ok(AppLink {
        link_type,
        request_id,
        is_mobile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_login_forms_parse_and_junk_is_refused() {
        let scheme = parse_app_link("liquidconnect://login/?request_id=abc123").unwrap();
        assert_eq!(scheme.link_type, LinkType::Login);
        assert_eq!(scheme.request_id, "abc123");
        assert!(!scheme.is_mobile);

        let applink =
            parse_app_link("https://app.sideswap.io/login/?request_id=abc123&mobile=true").unwrap();
        assert_eq!(applink.link_type, LinkType::Login);
        assert!(applink.is_mobile);

        assert!(parse_app_link("https://evil.example/login/?request_id=abc").is_err());
        assert!(parse_app_link("liquidconnect://login/").is_err());
    }
}
