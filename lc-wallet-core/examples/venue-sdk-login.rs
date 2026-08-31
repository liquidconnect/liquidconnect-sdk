//! Drive the Rolling Future venue's SDK login (`/api/sdk/challenge` +
//! `/api/sdk/login`) with a seed-derived VenueKey — binding the venue
//! leaf key to the account, and (optionally) associating a connect
//! identity key for sign-message routing and a browser link code.
//!
//!     venue-sdk-login <venue_base_url> <seed-hex-32> [identity-hex-32] [link-code]
//!
//! e.g. venue-sdk-login https://paper.swaption.io 5c5c…(64) f3d3…(64) <code>
//!
//! Signs `login_digest(venue_pk, challenge)` (rf/login/v1) with the
//! VenueKey — the same digest the venue's verifier rebuilds.

use lc_wallet_core::key::Network;
use lc_wallet_core::venue;

fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            let ev: String = v
                .bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        (b as char).to_string()
                    }
                    _ => format!("%{b:02X}"),
                })
                .collect();
            format!("{k}={ev}")
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let base = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: venue-sdk-login <base> <seed-hex> [identity] [link]"))?;
    let base = base.trim_end_matches('/').to_owned();
    let seed_hex = args.next().ok_or_else(|| anyhow::anyhow!("seed-hex required"))?;
    let identity = args.next();
    let link = args.next();

    let mut seed = [0u8; 32];
    hex::decode_to_slice(&seed_hex, &mut seed)?;
    let venue_key = venue::VenueKey::from_seed(&seed, Network::LiquidTestnet)?;
    let venue_pk = hex::encode(venue_key.public_key().serialize());
    println!("venue pk: {venue_pk}");

    // Step 1: challenge.
    let challenge: String = ureq::post(&format!("{base}/api/sdk/challenge"))
        .timeout(std::time::Duration::from_secs(20))
        .send_string("")?
        .into_json::<serde_json::Value>()?
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow::anyhow!("no challenge in reply"))?
        .to_owned();
    println!("challenge: {challenge}");

    // Step 2: sign rf/login/v1 and log in.
    let (_digest, sig) = venue::sign_login(&venue_key, &challenge);
    let sig_hex = sig.to_string();
    let mut pairs: Vec<(&str, &str)> = vec![
        ("pk", venue_pk.as_str()),
        ("sig", sig_hex.as_str()),
        ("challenge", challenge.as_str()),
    ];
    if let Some(id) = identity.as_deref() {
        pairs.push(("identity", id));
    }
    if let Some(code) = link.as_deref() {
        pairs.push(("link", code));
    }
    let body = form_encode(&pairs);

    let resp = ureq::post(&format!("{base}/api/sdk/login"))
        .timeout(std::time::Duration::from_secs(20))
        .set("content-type", "application/x-www-form-urlencoded")
        .send_string(&body);
    match resp {
        Ok(r) => {
            let v = r.into_json::<serde_json::Value>()?;
            println!("LOGIN OK: {v}");
        }
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            anyhow::bail!("sdk login refused ({code}): {text}");
        }
        Err(err) => anyhow::bail!("sdk login transport error: {err}"),
    }
    Ok(())
}
