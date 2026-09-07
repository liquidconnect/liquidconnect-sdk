//! Test vectors for venue signing (and for checking any
//! `StartSignMessage`-style protocol implementation against known-good
//! signatures): a deterministic venue money key signs the Rolling Future
//! venue's rf/* digests exactly as [`lc_wallet_core::venue`] does.
//!
//!     cargo run --example rf-vectors
//!
//! Everything printed is reproducible: the key derives from the fixed
//! wallet seed below via the SDK's production derivation
//! (VenueKey::from_seed — BIP32 hardened path m/19523'/1'/0' on Liquid
//! testnet, from BIP32-master(seed)), and signing is BIP340 with NO aux
//! randomness, so the signatures are byte-stable. Note the venue key is
//! deliberately NOT the Connect identity key: it is seed-derived, never
//! derivable from the master blinding key.

use lc_wallet_core::key::Network;
use lc_wallet_core::venue::{
    login_digest, order_digest, p2tr_spk_hash, sign_login, sign_order, sign_withdraw,
    withdraw_digest, OrderSide, VenueKey,
};

fn main() {
    let seed = [7u8; 32];
    let key = VenueKey::from_seed(&seed, Network::LiquidTestnet).expect("seed is valid");
    let pk = key.public_key().serialize();
    println!("network                : Liquid testnet");
    println!("wallet seed            : {}", hex::encode(seed));
    println!("venue pk (x-only)      : {}", hex::encode(pk));
    println!();

    let (d, s) = sign_login(&key, "c1");
    println!("login   challenge      : \"c1\"");
    println!("        digest         : {}", hex::encode(d));
    debug_assert_eq!(d, login_digest(&pk, "c1"));
    println!("        signature      : {}", s);
    println!();

    for (label, side, price, qty, expiry, nonce) in [
        ("order#1 sell", OrderSide::Sell, 7_700_000_000u64, 1_000u64, 50u32, 1u64),
        ("order#2 buy ", OrderSide::Buy, 11_500_000_000_000, 10_000_000, 100, 7),
    ] {
        let (d, s) = sign_order(&key, side, price, qty, expiry, nonce, None);
        debug_assert_eq!(d, order_digest(&pk, side, price, qty, expiry, nonce, None));
        println!("{label}  price={price} qty={qty} expiry={expiry} nonce={nonce}");
        println!("        digest         : {}", hex::encode(d));
        println!("        signature      : {}", s);
        println!();
    }

    let root = [0xAA_u8; 32];
    let (d, s) = sign_withdraw(&key, 5_000, &root);
    debug_assert_eq!(d, withdraw_digest(&pk, 5_000, &p2tr_spk_hash(&pk), &root));
    println!("withdraw amt=5000 dest_spk_hash={}", hex::encode(p2tr_spk_hash(&pk)));
    println!("        root           : {}", hex::encode(root));
    println!("        digest         : {}", hex::encode(d));
    println!("        signature      : {}", s);
}
