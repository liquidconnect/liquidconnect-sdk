//! Probe the live payjoin service: which assets pay fees, and what an
//! order quote looks like. Read-only in effect — an opened order that is
//! never signed simply expires.
//!
//!     cargo run --example payjoin-probe            # testnet
//!     cargo run --example payjoin-probe -- prod    # mainnet

use lc_wallet_core::payjoin;

fn main() -> anyhow::Result<()> {
    let base = match std::env::args().nth(1).as_deref() {
        Some("prod") => payjoin::BASE_URL_PROD,
        _ => payjoin::BASE_URL_TESTNET,
    };
    println!("payjoin service at {base}");

    let assets = payjoin::accepted_assets(base)?;
    println!("fee assets accepted: {}", assets.len());
    for asset in &assets {
        println!("  {asset}");
    }

    let quote = payjoin::start(base, assets[0], "lc-wallet-core payjoin-probe", None)?;
    println!(
        "order {}: price {} per fee-sat, fixed fee {}, {} server input(s)",
        quote.order_id,
        quote.price,
        quote.fixed_fee,
        quote.utxos.len()
    );
    println!(
        "service fee for a 1000-sat network fee: {} asset-sats",
        payjoin::estimate_service_fee(1_000, quote.price, quote.fixed_fee)
    );
    println!("(order left to expire — nothing was built or signed)");
    Ok(())
}
