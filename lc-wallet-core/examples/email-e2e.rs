//! Live email e2e against a real identity listener: register a fresh key,
//! trigger the real mail, confirm the typed code. Two invocations share
//! the key via a seed kept for the session (the identity is deliberately
//! deterministic from it, like a wallet's):
//!
//!     cargo run --example email-e2e -- <seed-hex-32-bytes> start   <email>
//!     cargo run --example email-e2e -- <seed-hex-32-bytes> confirm <email> <code>
//!
//! Base URL in LC_IDENTITY_BASE (default the production loopback listener),
//! bearer in LC_IDENTITY_BEARER.

use lc_wallet_core::identity::IdentityClient;
use lc_wallet_core::key::{Network, WalletKey};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let seed_hex = args.next().expect("seed hex is the first argument");
    let verb = args.next().expect("start|confirm is the second argument");
    let email = args.next().expect("email is the third argument");

    let seed = hex_decode(&seed_hex)?;
    anyhow::ensure!(seed.len() == 32, "seed must be 32 bytes of hex");
    let key = WalletKey::new(&seed, Network::LiquidTestnet);
    println!("wallet key: {}", key.public_key());

    let base = std::env::var("LC_IDENTITY_BASE")
        .unwrap_or_else(|_| "http://127.0.0.1:3129/v1/identity".to_owned());
    let bearer = std::env::var("LC_IDENTITY_BEARER").ok();
    let client = IdentityClient::new(&base, bearer);

    match verb.as_str() {
        "start" => {
            let status = client.status(&key)?;
            println!(
                "status before: identity_id={:?} email={}",
                status.identity_id, status.email
            );
            if status.identity_id.is_none() {
                client.set_discoverability(&key, true, false)?;
                println!("registered via email-discoverability opt-in");
            }
            client.email_start(&key, &email)?;
            println!("email_start accepted — a code is on its way to {email}");
        }
        "confirm" => {
            let code = args.next().expect("code is the fourth argument");
            let outcome = client.email_confirm(&key, &email, &code)?;
            println!(
                "email_confirm: verified={} identity_id={:?}",
                outcome.verified, outcome.identity_id
            );
            let status = client.status(&key)?;
            println!(
                "status after: identity_id={:?} email={}",
                status.identity_id, status.email
            );
            anyhow::ensure!(status.email, "listener does not show the email as verified");
            println!("live email e2e complete");
        }
        other => anyhow::bail!("unknown verb {other}; use start or confirm"),
    }
    Ok(())
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}
