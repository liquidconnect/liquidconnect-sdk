//! A headless wallet that approves everything it is asked — logins,
//! typed venue requests (clear-sign check enforced, VenueKey signs),
//! and opaque sign-messages (identity key signs). FOR TEST BENCHES
//! ONLY: an approve-everything wallet on a real network is a signing
//! oracle.
//!
//!     approve-all-wallet <wallet_ws_url> [seed-hex-32]
//!
//! Prints its identity and venue pubkeys at startup, then serves until
//! killed. Deterministic seed (default 0x5c*32) so a driving test can
//! precompute the venue digest.

use lc_wallet_core::key::{Network, WalletKey};
use lc_wallet_core::transport::{WalletConnect, WalletConnectConfig, WalletEvent};
use lc_wallet_core::{venue, wire};

fn descriptor(seed: &[u8; 32]) -> String {
    use elements::bitcoin::bip32::{Xpriv, Xpub};
    let secp = elements::bitcoin::secp256k1::Secp256k1::new();
    let master = Xpriv::new_master(elements::bitcoin::NetworkKind::Test, seed).expect("seed ok");
    let xpub = Xpub::from_priv(&secp, &master);
    format!("ct(slip77({}),elwpkh({xpub}/<0;1>/*))", hex::encode(seed))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:51235".to_owned());
    let mut seed = [0x5c_u8; 32];
    if let Some(hex_seed) = std::env::args().nth(2) {
        hex::decode_to_slice(&hex_seed, &mut seed)?;
    }

    let identity = WalletKey::new(&seed, Network::LiquidTestnet);
    let venue_key = venue::VenueKey::from_seed(&seed, Network::LiquidTestnet)?;
    let venue_pk = venue_key.public_key().serialize();
    println!("identity: {}", identity.public_key());
    println!("venue:    {}", hex::encode(venue_pk));

    let (wallet, mut events) = WalletConnect::spawn(WalletConnectConfig {
        url,
        descriptor: descriptor(&seed),
        key: WalletKey::new(&seed, Network::LiquidTestnet),
        install_id: wire::InstallId::random(),
    });

    // Links to open (connect-login requests to claim) arrive as lines
    // appended to the file named by LC_LINKS_FILE — a file, not stdin,
    // because a detached container does not wire stdin reliably. Each
    // new line is opened once; the file is created if missing.
    if let Ok(path) = std::env::var("LC_LINKS_FILE") {
        let link_wallet = wallet.clone();
        std::thread::spawn(move || {
            let mut seen = 0usize;
            loop {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    let lines: Vec<&str> = text.lines().collect();
                    for line in lines.iter().skip(seen) {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        match link_wallet.open_link(line) {
                            Ok(()) => println!("link opened: {line}"),
                            Err(err) => println!("bad link {line}: {err}"),
                        }
                    }
                    seen = lines.len();
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        });
    }

    while let Some(event) = events.recv().await {
        match event {
            WalletEvent::LoggedIn => println!("logged in"),
            WalletEvent::LoginRequested(req) => {
                println!("login from {}: accepting", req.domain);
                wallet.accept_login(&req.request_id);
            }
            WalletEvent::SignMessageRequested(req) => {
                match req
                    .description
                    .as_deref()
                    .and_then(venue::parse_typed_description)
                {
                    Some(Ok(typed)) => {
                        let rebuilt = venue::typed_request_digest(&typed, &venue_pk)
                            .unwrap_or([0u8; 32]);
                        if hex::encode(rebuilt) != req.digest.to_lowercase() {
                            println!("typed digest mismatch: rejecting");
                            wallet.reject_sign_message(&req.request_id);
                            continue;
                        }
                        let (_d, signature) = match typed {
                            venue::TypedRequest::Order {
                                side,
                                price,
                                qty,
                                expiry,
                                nonce,
                                ..
                            } => venue::sign_order(&venue_key, side, price, qty, expiry, nonce),
                            venue::TypedRequest::Withdraw { amt, root } => {
                                venue::sign_withdraw(&venue_key, amt, &root)
                            }
                            venue::TypedRequest::Login { challenge } => {
                                venue::sign_login(&venue_key, &challenge)
                            }
                        };
                        println!("typed request verified: venue key signs");
                        wallet.accept_sign_message_signed(&req.request_id, &signature.to_string());
                    }
                    Some(Err(err)) => {
                        println!("malformed typed request ({err}): rejecting");
                        wallet.reject_sign_message(&req.request_id);
                    }
                    None => {
                        println!("opaque request: identity key signs");
                        wallet.accept_sign_message(&req.request_id);
                    }
                }
            }
            other => println!("event: {other:?}"),
        }
    }
    Ok(())
}
