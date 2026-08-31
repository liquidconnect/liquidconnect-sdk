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

/// A venue's account-link request: `liquidconnect://venue-login?venue=<host>&link=<code>`.
///
/// Distinct from [`AppLink`] on purpose — a venue login is acted on by
/// the HOST (VenueKey challenge/login against the venue's own API), not
/// fed to the connect session core. `venue` is a bare domain and nothing
/// else: the host constructs `https://<venue>/api/sdk/…` itself, and
/// this parser refuses anything that could steer that URL — a scheme, a
/// port, a path, an IP, userinfo — so a malicious QR cannot point the
/// wallet's login signature at an arbitrary endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VenueLoginLink {
    /// Bare host, e.g. `paper.swaption.io`. https is implied.
    pub venue: String,
    /// The venue's one-time link code, passed through verbatim.
    pub link_code: String,
}

pub fn parse_venue_login_link(url: &str) -> Result<VenueLoginLink, anyhow::Error> {
    let url = url::Url::parse(url)?;
    ensure!(
        url.scheme() == "liquidconnect"
            && url.host_str() == Some("venue-login")
            && matches!(url.path(), "" | "/"),
        "unsupported URL: {url}"
    );

    let params = url
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<String, String>>();

    let venue = params
        .get("venue")
        .ok_or_else(|| anyhow!("invalid link: no venue query parameter"))?
        .to_ascii_lowercase();
    ensure!(
        !venue.is_empty()
            && venue.contains('.')
            && venue
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && !venue.split('.').any(|label| label.is_empty())
            && venue.split('.').all(|label| label.parse::<u8>().is_err()),
        "venue must be a bare domain name"
    );

    let link_code = params
        .get("link")
        .ok_or_else(|| anyhow!("invalid link: no link query parameter"))?
        .clone();
    ensure!(!link_code.is_empty(), "empty link code");

    Ok(VenueLoginLink { venue, link_code })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The venue-login form parses, and everything that could steer the
    /// host's constructed URL is refused.
    #[test]
    fn venue_login_links_parse_and_steering_is_refused() {
        let link = parse_venue_login_link(
            "liquidconnect://venue-login?venue=paper.swaption.io&link=abc123",
        )
        .unwrap();
        assert_eq!(link.venue, "paper.swaption.io");
        assert_eq!(link.link_code, "abc123");

        for bad in [
            "liquidconnect://venue-login?venue=paper.swaption.io",       // no code
            "liquidconnect://venue-login?link=abc",                      // no venue
            "liquidconnect://venue-login?venue=evil.io/paper&link=abc",  // path smuggling
            "liquidconnect://venue-login?venue=evil.io:8443&link=abc",   // port
            "liquidconnect://venue-login?venue=https%3A%2F%2Fevil.io&link=abc", // scheme
            "liquidconnect://venue-login?venue=127.0.0.1&link=abc",      // ip
            "liquidconnect://venue-login?venue=localhost&link=abc",      // no dot
            "liquidconnect://login/?request_id=abc",                     // wrong kind
        ] {
            assert!(parse_venue_login_link(bad).is_err(), "must refuse: {bad}");
        }

        // And the ordinary parser refuses the venue form rather than
        // misreading it as a connect login.
        assert!(parse_app_link(
            "liquidconnect://venue-login?venue=paper.swaption.io&link=abc"
        )
        .is_err());
    }

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
