//! One-shot recovery signer for a venue withdraw claim: REBUILDS the
//! typed rf/withdraw/v1 digest from the named fields and signs it with
//! the seed-derived VenueKey — never a caller-supplied digest, so the
//! amount and destination are verified here by construction, and a
//! wrong root can only fail on-chain, never redirect funds.
//!
//!     sign-withdraw-claim <seed-hex-32> <amt-sats> <dest-address> <root-hex-32>

use lc_wallet_core::key::Network;
use lc_wallet_core::venue;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let seed_hex = args.next().ok_or_else(|| {
        anyhow::anyhow!("usage: sign-withdraw-claim <seed-hex> <amt> <dest> <root-hex>")
    })?;
    let amt: u64 = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("amt required"))?
        .parse()?;
    let dest = args.next().ok_or_else(|| anyhow::anyhow!("dest required"))?;
    let root_hex = args.next().ok_or_else(|| anyhow::anyhow!("root required"))?;

    let mut seed = [0u8; 32];
    hex::decode_to_slice(&seed_hex, &mut seed)?;
    let mut root = [0u8; 32];
    hex::decode_to_slice(&root_hex, &mut root)?;

    let key = venue::VenueKey::from_seed(&seed, Network::LiquidTestnet)?;
    let claim = venue::TypedRequest::Withdraw {
        amt,
        dest: dest.clone(),
        root,
    };
    let (digest, signature) = key
        .sign_typed(&claim)
        .map_err(|e| anyhow::anyhow!("cannot sign: {e}"))?;
    println!("venue pk:  {}", hex::encode(key.public_key().serialize()));
    println!("amt:       {amt}");
    println!("dest:      {dest}");
    println!("root:      {root_hex}");
    println!("digest:    {}", hex::encode(digest));
    println!("signature: {signature}");
    Ok(())
}
