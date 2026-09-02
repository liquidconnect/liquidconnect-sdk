//! A headless wallet that can actually PAY: a BIP39 software signer with
//! a standard singlesig wpkh descriptor, synced over Esplora, that
//! accepts every login and signs every PSET whose inputs are its own
//! coins. Built for the sideswap.io web-trading bench (sideswap_web_rp):
//! it plays the SideSwap app's part of the taker flow so the whole chain
//! (page → sidecar → market → wallet → broadcast) can be proven without
//! a phone. FOR TEST BENCHES ONLY — an approve-everything wallet with
//! money in it is a signing oracle.
//!
//!     BENCH_MNEMONIC="..." taker-bench-wallet <wallet_ws_url> [esplora_url]
//!
//! Prints its Connect identity and a receive address (fund it from the
//! liquidtestnet faucet). Links arrive as lines appended to LC_LINKS_FILE
//! (same convention as approve-all-wallet). Every sign request is
//! summarised on stdout before signing, so the run log shows what was
//! approved.

use lc_wallet_core::approval;
use lc_wallet_core::key::{Network, WalletKey};
use lc_wallet_core::transport::{WalletConnect, WalletConnectConfig, WalletEvent};
use lc_wallet_core::wire;
use lwk_common::Signer as _;

async fn sync(
    wollet: &mut lwk_wollet::Wollet,
    esplora: &mut lwk_wollet::asyncr::EsploraClient,
) -> anyhow::Result<()> {
    if let Some(update) = esplora.full_scan(wollet).await? {
        wollet.apply_update(update)?;
    }
    Ok(())
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| wire::TESTNET_URL.to_owned());
    let esplora_url = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "https://blockstream.info/liquidtestnet/api".to_owned());

    let mnemonic = match env("BENCH_MNEMONIC") {
        Some(m) => m,
        None => {
            let (_, m) = lwk_signer::SwSigner::random(false)?;
            println!("BENCH_MNEMONIC not set; generated one — export it to keep this wallet:\n{m}");
            m.to_string()
        }
    };
    let signer = lwk_signer::SwSigner::new(&mnemonic, false)?;
    let desc_str = lwk_common::singlesig_desc(
        &signer,
        lwk_common::Singlesig::Wpkh,
        lwk_common::DescriptorBlindingKey::Slip77,
    )
    .map_err(|e| anyhow::anyhow!("descriptor: {e}"))?;
    let descriptor: lwk_wollet::WolletDescriptor = desc_str.parse()?;
    let network = lwk_wollet::Network::TestnetLiquid;
    let mut wollet = lwk_wollet::WolletBuilder::new(network, descriptor.clone()).build()?;
    let mut esplora = lwk_wollet::asyncr::EsploraClient::new(network, &esplora_url);

    let mbk = signer.slip77_master_blinding_key()?;
    let key = WalletKey::new(mbk.as_bytes(), Network::LiquidTestnet);
    let seed = signer.seed().expect("software signer has a seed");
    let mut install = [0u8; 16];
    install.copy_from_slice(&seed[..16]);

    sync(&mut wollet, &mut esplora).await?;

    println!("identity:   {}", key.public_key());
    println!("descriptor: {desc_str}");
    println!("address:    {}", wollet.address(None)?.address());
    println!("balance:    {:?}", wollet.balance()?);

    let (wallet, mut events) = WalletConnect::spawn(WalletConnectConfig {
        url,
        descriptor: desc_str.clone(),
        key,
        install_id: wire::InstallId(install),
    });

    if let Some(path) = env("LC_LINKS_FILE") {
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
            WalletEvent::LoggedIn => println!("logged in to the connect server"),
            WalletEvent::Sessions(sessions) => {
                for session in &sessions {
                    if !session.is_local {
                        println!("stopping stale session {}", session.session_id);
                        wallet.stop_session(&session.session_id);
                    }
                }
                println!("sessions: {}", sessions.len());
            }
            WalletEvent::LoginRequested(req) => {
                println!("login from {}: accepting", req.domain);
                wallet.accept_login(&req.request_id);
            }
            WalletEvent::SignRequested(req) => {
                println!("sign request from {} ({} ms ttl)", req.domain, req.ttl.as_millis());
                match approval::summarize_pset(&req.pset, Network::LiquidTestnet) {
                    Ok(summary) => println!("  summary: {summary:?}"),
                    Err(err) => println!("  summary unavailable: {err}"),
                }
                let mut pset: elements::pset::PartiallySignedTransaction = match req.pset.parse() {
                    Ok(p) => p,
                    Err(err) => {
                        println!("  invalid PSET ({err}): rejecting");
                        wallet.reject_sign(&req.request_id);
                        continue;
                    }
                };
                let res = async {
                    sync(&mut wollet, &mut esplora).await?;
                    wollet.add_details(&mut pset)?;
                    let n = signer.sign(&mut pset)?;
                    // Finalise our inputs the way the app does (final witness),
                    // the market server broadcasts.
                    wollet.finalize(&mut pset)?;
                    anyhow::Ok(n)
                }
                .await;
                match res {
                    Ok(0) => {
                        println!("  nothing of ours to sign: rejecting");
                        wallet.reject_sign(&req.request_id);
                    }
                    Ok(n) => {
                        println!("  signed {n} input(s): accepting");
                        wallet.accept_sign(&req.request_id, &pset.to_string());
                    }
                    Err(err) => {
                        println!("  signing failed ({err}): rejecting");
                        wallet.reject_sign(&req.request_id);
                    }
                }
            }
            WalletEvent::SignMessageRequested(req) => {
                println!("sign-message from {}: rejecting (bench signs PSETs only)", req.domain);
                wallet.reject_sign_message(&req.request_id);
            }
            other => println!("event: {other:?}"),
        }
    }
    Ok(())
}
