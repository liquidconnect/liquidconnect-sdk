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

    // Seed-derived, so it SURVIVES restarts: the connect server delivers
    // sign requests only to clients whose install_id matches the
    // session's, so a random-per-process id silently orphans the session
    // after the first restart (requests time out; only the removal
    // notifs arrive).
    let mut install = [0u8; 16];
    install.copy_from_slice(&seed[..16]);
    let (wallet, mut events) = WalletConnect::spawn(WalletConnectConfig {
        url,
        descriptor: descriptor(&seed),
        key: WalletKey::new(&seed, Network::LiquidTestnet),
        install_id: wire::InstallId(install),
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
            WalletEvent::Sessions(sessions) => {
                // Bench hygiene: a session whose install_id is not ours
                // (is_local false) is a leftover from a dead process — the
                // server will never route its requests here, so it only
                // misleads. Stop it; the live login stays.
                for session in &sessions {
                    if !session.is_local {
                        println!("stopping stale session {}", session.session_id);
                        wallet.stop_session(&session.session_id);
                    }
                }
                println!("sessions: {sessions:?}");
            }
            WalletEvent::LoginRequested(req) => {
                println!("login from {}: accepting", req.domain);
                wallet.accept_login(&req.request_id);
            }
            WalletEvent::SignRequested(req) => {
                // The venue's deposit PSET spends the bench account's
                // staging coin — a raw-key P2TR of the venue key, which
                // sign_pset_keyspend_inputs satisfies. Anything else in
                // the PSET this bench cannot sign and leaves untouched.
                let mut pset = match lc_wallet_core::approval::decode_pset(&req.pset) {
                    Ok(pset) => pset,
                    Err(err) => {
                        println!("unparseable PSET ({err}): rejecting");
                        wallet.reject_sign(&req.request_id);
                        continue;
                    }
                };
                let genesis = venue::genesis_block_hash(Network::LiquidTestnet)
                    .expect("testnet genesis known");
                match venue_key.sign_pset_keyspend_inputs(&mut pset, genesis) {
                    Ok(0) => {
                        // Nothing here is ours to sign — refuse loudly
                        // rather than return a signature-less PSET the
                        // requester can only watch time out.
                        println!(
                            "sign request from {}: no input pays this venue key's raw P2TR, rejecting",
                            req.domain
                        );
                        wallet.reject_sign(&req.request_id);
                    }
                    Ok(signed) => {
                        use base64::Engine as _;
                        let signed_b64 = base64::engine::general_purpose::STANDARD
                            .encode(elements::encode::serialize(&pset));
                        println!("sign request from {}: signed {signed} venue input(s)", req.domain);
                        wallet.accept_sign(&req.request_id, &signed_b64);
                    }
                    Err(err) => {
                        println!("venue PSET signing failed ({err}): rejecting");
                        wallet.reject_sign(&req.request_id);
                    }
                }
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
                        // The clear-sign check above proves the claim is
                        // internally consistent, not that its destination
                        // is one the user WANTS to pay — in the real app
                        // that judgment is the human reading "To:". A
                        // bench has no human, so it fails closed on any
                        // destination other than the one the drill named
                        // (proven live: a venue bug once asked this bench
                        // to withdraw to another wallet's address, and it
                        // signed).
                        if let venue::TypedRequest::Withdraw { dest, .. } = &typed
                            && let Ok(expected) = std::env::var("LC_EXPECTED_WITHDRAW_DEST")
                            && *dest != expected
                        {
                            println!(
                                "withdraw dest {dest} is not the expected {expected}: rejecting"
                            );
                            wallet.reject_sign_message(&req.request_id);
                            continue;
                        }
                        let (_d, signature) = match venue_key.sign_typed(&typed) {
                            Ok(signed) => signed,
                            Err(err) => {
                                println!("cannot sign typed request ({err}): rejecting");
                                wallet.reject_sign_message(&req.request_id);
                                continue;
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
