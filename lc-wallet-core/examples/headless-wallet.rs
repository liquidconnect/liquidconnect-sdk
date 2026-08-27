//! A headless Liquid Connect wallet: connects, logs in, and drives the
//! whole request lifecycle from stdin. Exists to prove the SDK against
//! the real Connect server and as the smallest complete integration.
//!
//!     cargo run --example headless-wallet -- [wss-url]
//!
//! Commands on stdin:
//!     link <url-or-request-id>       claim a login request (QR payload)
//!     accept <request_id>            approve it (sends the descriptor!)
//!     reject <request_id>
//!     quit
//!
//! The identity is ephemeral: a fresh key each run, so this never
//! collides with a real wallet and leaves nothing worth stealing.

use lc_wallet_core::key::WalletKey;
use lc_wallet_core::transport::{WalletConnect, WalletConnectConfig, WalletEvent};
use lc_wallet_core::wire;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| wire::TESTNET_URL.to_owned());

    let key = WalletKey::ephemeral();
    println!("wallet identity (ephemeral): {}", key.public_key());
    println!("connecting to {url}");

    let (wallet, mut events) = WalletConnect::spawn(WalletConnectConfig {
        url,
        descriptor: String::new(),
        key,
        install_id: wire::InstallId::random(),
    });

    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Some(WalletEvent::LoggedIn) => println!("<- logged in"),
                    Some(WalletEvent::Sessions(s)) => println!("<- sessions: {}", s.len()),
                    Some(WalletEvent::LoginRequested(r)) =>
                        println!("<- login request {} from {} (ttl {}ms)", r.request_id, r.domain, r.ttl.as_millis()),
                    Some(WalletEvent::SignRequested(r)) =>
                        println!("<- SIGN request {} from {} ({} b64 bytes)", r.request_id, r.domain, r.pset.len()),
                    Some(other) => println!("<- {other:?}"),
                    None => break,
                }
            }
            line = lines.next_line() => {
                let Some(line) = line? else { break };
                let mut parts = line.split_whitespace();
                match (parts.next(), parts.next()) {
                    (Some("link"), Some(target)) => {
                        let url = if target.contains("://") {
                            target.to_owned()
                        } else {
                            format!("liquidconnect://login/?request_id={target}")
                        };
                        match wallet.open_link(&url) {
                            Ok(()) => println!("-> linked"),
                            Err(err) => println!("!! {err}"),
                        }
                    }
                    (Some("accept"), Some(id)) => { wallet.accept_login(id); println!("-> accepted {id}"); }
                    (Some("reject"), Some(id)) => { wallet.reject_login(id); println!("-> rejected {id}"); }
                    (Some("quit"), _) => break,
                    _ => println!("commands: link <url|id> | accept <id> | reject <id> | quit"),
                }
            }
        }
    }
    Ok(())
}
