//! Test vectors for the `StartSignMessage` ask (Liquid Connect message
//! signing): a deterministic wallet key signs the Rolling Future venue's
//! rf/* digests exactly as [`lc_wallet_core::venue`] does, so a protocol
//! implementation can be checked against known-good signatures.
//!
//!     cargo run --example rf-vectors
//!
//! Everything printed is reproducible: the key derives from the fixed
//! master blinding key below (WalletKey::new — sk = tagged
//! SHA256("sideswap/wallet_key", testnet_salt || mbk)), and signing is
//! BIP340 with NO aux randomness, so the signatures are byte-stable.

use lc_wallet_core::key::{Network, WalletKey};
use lc_wallet_core::venue::{
    login_digest, order_digest, p2tr_spk_hash, sign_login, sign_order, sign_withdraw,
    withdraw_digest, OrderSide,
};

fn main() {
    let mbk = [7u8; 32];
    let key = WalletKey::new(&mbk, Network::LiquidTestnet);
    let pk = key.public_key().serialize();
    println!("network                : Liquid testnet");
    println!("master blinding key    : {}", hex::encode(mbk));
    println!("wallet pk (x-only)     : {}", hex::encode(pk));
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
        let (d, s) = sign_order(&key, side, price, qty, expiry, nonce);
        debug_assert_eq!(d, order_digest(&pk, side, price, qty, expiry, nonce));
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
