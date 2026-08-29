//! Signing for the Rolling Future venue's covenant digests (`rf/*`).
//!
//! The venue (paper.swaption.io, `sideswap-io/rolling-future`) admits an
//! order or withdrawal from a wallet-key account only with a BIP340
//! signature by the wallet key over a domain-tagged SHA256 digest, and the
//! Simplicity covenant re-verifies the very same signature on-chain when
//! the driver broadcasts the fill or withdraw. This module builds those
//! digests from typed fields — a wallet must know exactly what it signs —
//! and signs them with the wallet's Connect identity key
//! ([`WalletKey::sign_digest`]).
//!
//! This is the pipeline a `StartSignMessage`-style Liquid Connect request
//! drops into: the RP supplies the digest (or the fields to rebuild it),
//! the wallet displays what it is authorising, and the reply carries the
//! same BIP340 signature produced here. The digest vectors below are
//! pinned identically in `rolling-future/server/src/main.rs` — never
//! change one side alone.

use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::schnorr::Signature;

use crate::key::WalletKey;

pub const ORDER_TAG: &[u8] = b"rf/order/v1";
pub const WITHDRAW_TAG: &[u8] = b"rf/withdraw/v1";
pub const LOGIN_TAG: &[u8] = b"rf/login/v1";
pub const PRODUCT: &[u8] = b"RF-BTC-USDT";

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OrderSide {
    Buy,
    Sell,
}

fn sha(m: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(m).to_byte_array()
}

/// The order commitment digest:
/// `SHA256("rf/order/v1" || pk || "RF-BTC-USDT" || side(1) || price_be(8)
///  || qty_be(8) || expiry_be(4) || nonce_be(8))` — price in venue base
/// units per BTC, qty in sats (always positive; side carries direction),
/// expiry an absolute session number, nonce strictly increasing per
/// account.
pub fn order_digest(
    pk: &[u8; 32],
    side: OrderSide,
    price: u64,
    qty: u64,
    expiry: u32,
    nonce: u64,
) -> [u8; 32] {
    let mut m = Vec::with_capacity(ORDER_TAG.len() + 32 + PRODUCT.len() + 29);
    m.extend_from_slice(ORDER_TAG);
    m.extend_from_slice(pk);
    m.extend_from_slice(PRODUCT);
    m.push(match side {
        OrderSide::Buy => 0,
        OrderSide::Sell => 1,
    });
    m.extend_from_slice(&price.to_be_bytes());
    m.extend_from_slice(&qty.to_be_bytes());
    m.extend_from_slice(&expiry.to_be_bytes());
    m.extend_from_slice(&nonce.to_be_bytes());
    sha(&m)
}

/// The withdrawal digest:
/// `SHA256("rf/withdraw/v1" || pk || amt_be(8) || dest_spk_hash || root)`.
/// `root` is the venue's post-replay accounts root (the covenant's
/// committed state at spend time) — fetch it from `/api/withdraw/prepare`;
/// if the venue moves before submission the signature stops matching and
/// the wallet prepares again.
pub fn withdraw_digest(
    pk: &[u8; 32],
    amt: u64,
    dest_spk_hash: &[u8; 32],
    root: &[u8; 32],
) -> [u8; 32] {
    let mut m = Vec::with_capacity(WITHDRAW_TAG.len() + 104);
    m.extend_from_slice(WITHDRAW_TAG);
    m.extend_from_slice(pk);
    m.extend_from_slice(&amt.to_be_bytes());
    m.extend_from_slice(dest_spk_hash);
    m.extend_from_slice(root);
    sha(&m)
}

/// The login digest: `SHA256("rf/login/v1" || pk || challenge_utf8)` over
/// the venue's single-use challenge.
pub fn login_digest(pk: &[u8; 32], challenge: &str) -> [u8; 32] {
    let mut m = Vec::with_capacity(LOGIN_TAG.len() + 32 + challenge.len());
    m.extend_from_slice(LOGIN_TAG);
    m.extend_from_slice(pk);
    m.extend_from_slice(challenge.as_bytes());
    sha(&m)
}

/// sha256 of the raw-x-only P2TR script `51 20 <pk>` — how the covenant
/// commits to a payout destination. Withdrawals pay the wallet key itself.
pub fn p2tr_spk_hash(pk: &[u8; 32]) -> [u8; 32] {
    let mut spk = Vec::with_capacity(34);
    spk.extend_from_slice(&[0x51, 0x20]);
    spk.extend_from_slice(pk);
    sha(&spk)
}

fn wallet_pk(key: &WalletKey) -> [u8; 32] {
    key.public_key().serialize()
}

/// Sign a venue login challenge. Returns `(digest, signature)`.
pub fn sign_login(key: &WalletKey, challenge: &str) -> ([u8; 32], Signature) {
    let d = login_digest(&wallet_pk(key), challenge);
    (d, key.sign_digest(d))
}

/// Sign an order commitment. Returns `(digest, signature)`.
pub fn sign_order(
    key: &WalletKey,
    side: OrderSide,
    price: u64,
    qty: u64,
    expiry: u32,
    nonce: u64,
) -> ([u8; 32], Signature) {
    let d = order_digest(&wallet_pk(key), side, price, qty, expiry, nonce);
    (d, key.sign_digest(d))
}

/// Sign a withdrawal of `amt` base units paid to the wallet key itself.
/// Returns `(digest, signature)`.
pub fn sign_withdraw(key: &WalletKey, amt: u64, root: &[u8; 32]) -> ([u8; 32], Signature) {
    let pk = wallet_pk(key);
    let d = withdraw_digest(&pk, amt, &p2tr_spk_hash(&pk), root);
    (d, key.sign_digest(d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Network;
    use elements::secp256k1_zkp::{Message, SECP256K1};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The rf/* digests, pinned against the vectors the venue pins too
    /// (`rolling-future/server/src/main.rs`, test `shared_digest_vectors`)
    /// — drift on either side becomes a test failure here rather than a
    /// signature that mysteriously stops verifying.
    #[test]
    fn shared_digest_vectors() {
        let pk = [3u8; 32];
        assert_eq!(
            hex(&order_digest(&pk, OrderSide::Buy, 11_500_000_000_000, 10_000_000, 100, 7)),
            "944e4e036d891dd277fee0987c355b2609fb09d6fc149ee2e2fd2b907acf9512"
        );
        assert_eq!(
            hex(&login_digest(&pk, "c1")),
            "04e78310fc229b8d973fcd61744511cbe9182c1b00bcd56eee5f6b7181efdf4d"
        );
        let dest = p2tr_spk_hash(&pk);
        assert_eq!(hex(&dest), "9877030268541635f3a8ca1b8c858314276c1b2c3ebb836e641aa9782e7f58c3");
        assert_eq!(
            hex(&withdraw_digest(&pk, 5000, &dest, &[0xAA; 32])),
            "14cf3b3d26843d9b2b64fb9bb4fd1e5774d626453c79b55d36c68ec1004c7b8a"
        );
    }

    /// Signatures verify against the wallet key over the exact digest and
    /// against nothing else, and are deterministic (no aux randomness) —
    /// the property the Pavel test vectors rely on.
    #[test]
    fn order_signature_verifies_and_is_deterministic() {
        let key = WalletKey::new(&[7u8; 32], Network::LiquidTestnet);
        assert_eq!(
            hex(&key.public_key().serialize()),
            "c430e1683ac5f48d4e058e602b9ee33890830be3a92fea9f524d5763c15369d1"
        );
        let (d, s) = sign_order(&key, OrderSide::Sell, 7_700_000_000, 1_000, 50, 1);
        let (d2, s2) = sign_order(&key, OrderSide::Sell, 7_700_000_000, 1_000, 50, 1);
        assert_eq!((d, s), (d2, s2));
        // byte-stable — the property the rf-vectors example (the
        // StartSignMessage test vectors) relies on
        assert_eq!(hex(&d), "517c14e1fd512ff1dfb107624ded8dd91db233ca5780b936a0bd8f69823ad56a");
        assert_eq!(
            s.to_string(),
            "3211e42407320724a7e9d89bf322da8e25747e36defc42a3955a718a2ef0e493\
             2c0990afbe13dda77e3b4bd7c872e6a907afc7fc5ad80b0e9179d50116197884"
        );
        assert!(SECP256K1
            .verify_schnorr(&s, &Message::from_digest(d), &key.public_key())
            .is_ok());
        let (other, _) = sign_order(&key, OrderSide::Buy, 7_700_000_000, 1_000, 50, 1);
        assert!(SECP256K1
            .verify_schnorr(&s, &Message::from_digest(other), &key.public_key())
            .is_err());
    }
}
