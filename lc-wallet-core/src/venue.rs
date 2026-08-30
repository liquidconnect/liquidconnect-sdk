//! The Rolling Future venue: the money key and covenant-digest signing (`rf/*`).
//!
//! The venue (paper.swaption.io, `sideswap-io/rolling-future`) admits an
//! order or withdrawal from an account only with a BIP340 signature by
//! the account key over a domain-tagged SHA256 digest, and the
//! Simplicity covenant re-verifies the very same signature on-chain when
//! the driver broadcasts the fill or withdraw. This module builds those
//! digests from typed fields — a wallet must know exactly what it signs
//! — and signs them with the venue money key ([`VenueKey`]).
//!
//! ## The money key is not the Connect identity key
//!
//! Withdrawals pay to the raw P2TR of the account key, so the account
//! key is spend-class: it controls on-chain funds. The Connect identity
//! key ([`crate::key::WalletKey`]) derives from the master blinding key
//! — view-tier material that wallets legitimately export to watch-only
//! servers and explorers — so it must never be the account key: anyone
//! holding a wallet's mbk could otherwise derive it and spend.
//! [`VenueKey`] therefore derives from the wallet **seed** via a
//! dedicated hardened BIP32 path (`m/19523'/<network>'/0'`; 19523 =
//! 0x4C43, ASCII "LC"), which is never exportable to view-tier
//! infrastructure. Nothing new to back up — the seed already is.
//!
//! Wallets whose seed lives in a hardware signer cannot construct a
//! [`VenueKey`] here; for those hosts the public digest builders below
//! are the integration surface — build the digest from typed fields,
//! display the fields, and produce the BIP340 signature in the signer.
//! There is deliberately no sign-arbitrary-bytes entry point in the
//! public API: a digest supplied by a remote party could be the sighash
//! of a transaction spending the account's outputs. The wallet always
//! rebuilds digests from fields it can show.
//!
//! The digest vectors below are pinned identically in
//! `rolling-future/server/src/main.rs` — never change one side alone.

use elements::bitcoin::bip32::{ChildNumber, Xpriv};
use elements::bitcoin::secp256k1::Secp256k1;
use elements::bitcoin::NetworkKind;
use elements::hashes::{sha256, Hash};
use elements::schnorr::{Keypair, XOnlyPublicKey};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{Message, SECP256K1};

use crate::key::Network;

pub const ORDER_TAG: &[u8] = b"rf/order/v1";
pub const WITHDRAW_TAG: &[u8] = b"rf/withdraw/v1";
pub const LOGIN_TAG: &[u8] = b"rf/login/v1";
pub const PRODUCT: &[u8] = b"RF-BTC-USDT";

/// BIP43 purpose index of the venue money key's derivation path:
/// 0x4C43, ASCII "LC". The full path is `m/19523'/<network>'/0'` with
/// network 0' Liquid, 1' Liquid testnet, 2' regtest, and the trailing
/// 0' an account slot reserved for future multi-account use.
pub const VENUE_KEY_PURPOSE: u32 = 0x4C43;

/// The venue money key: the account identity on the venue and the key
/// its covenant funds pay out to.
///
/// Derived from the wallet seed (the BIP39 seed bytes — the same secret
/// that roots the wallet's xprv, 16–64 bytes) via the dedicated
/// hardened path documented at [`VENUE_KEY_PURPOSE`]. Deterministic per
/// seed and network, like the identity key — but, unlike the identity
/// key, not derivable from anything a wallet exports to watch-only
/// infrastructure.
pub struct VenueKey {
    keypair: Keypair,
}

impl VenueKey {
    /// The production derivation: BIP32 from the wallet seed, hardened
    /// path `m/19523'/<network>'/0'`.
    pub fn from_seed(seed: &[u8], network: Network) -> anyhow::Result<VenueKey> {
        let secp = Secp256k1::signing_only();
        // NetworkKind only selects xprv serialization version bytes,
        // which never leave this function; network separation is the
        // path's job.
        let master = Xpriv::new_master(NetworkKind::Main, seed)?;
        let net = match network {
            Network::Liquid => 0,
            Network::LiquidTestnet => 1,
            Network::Regtest => 2,
        };
        let path = [
            ChildNumber::from_hardened_idx(VENUE_KEY_PURPOSE).expect("fits 31 bits"),
            ChildNumber::from_hardened_idx(net).expect("fits 31 bits"),
            ChildNumber::from_hardened_idx(0).expect("fits 31 bits"),
        ];
        let child = master.derive_priv(&secp, &path)?;
        let keypair = Keypair::from_seckey_slice(SECP256K1, &child.private_key.secret_bytes())
            .expect("a bip32 child key is a valid secp key");
        Ok(VenueKey { keypair })
    }

    pub fn public_key(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
    }

    /// BIP340 over a venue digest, deterministic (no aux randomness) so
    /// signatures are vector-testable. Private on purpose: every public
    /// signing path goes through the typed builders in this module, so
    /// arbitrary bytes — e.g. a transaction sighash offered as "a
    /// message" — can never reach the key.
    fn sign_digest(&self, digest: [u8; 32]) -> Signature {
        SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &self.keypair)
    }
}

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
/// commits to a payout destination. Withdrawals pay the venue money key
/// itself.
pub fn p2tr_spk_hash(pk: &[u8; 32]) -> [u8; 32] {
    let mut spk = Vec::with_capacity(34);
    spk.extend_from_slice(&[0x51, 0x20]);
    spk.extend_from_slice(pk);
    sha(&spk)
}

fn account_pk(key: &VenueKey) -> [u8; 32] {
    key.public_key().serialize()
}

/// Sign a venue login challenge. Returns `(digest, signature)`.
pub fn sign_login(key: &VenueKey, challenge: &str) -> ([u8; 32], Signature) {
    let d = login_digest(&account_pk(key), challenge);
    (d, key.sign_digest(d))
}

/// Sign an order commitment. Returns `(digest, signature)`.
pub fn sign_order(
    key: &VenueKey,
    side: OrderSide,
    price: u64,
    qty: u64,
    expiry: u32,
    nonce: u64,
) -> ([u8; 32], Signature) {
    let d = order_digest(&account_pk(key), side, price, qty, expiry, nonce);
    (d, key.sign_digest(d))
}

/// Sign a withdrawal of `amt` base units paid to the venue money key
/// itself. Returns `(digest, signature)`.
pub fn sign_withdraw(key: &VenueKey, amt: u64, root: &[u8; 32]) -> ([u8; 32], Signature) {
    let pk = account_pk(key);
    let d = withdraw_digest(&pk, amt, &p2tr_spk_hash(&pk), root);
    (d, key.sign_digest(d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::WalletKey;
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

    /// The money key must never be derivable from view-tier material:
    /// the same 32 bytes fed to the identity derivation and the venue
    /// derivation must land on different keys. And like the identity
    /// key, the venue key is deterministic and network-separated.
    #[test]
    fn venue_key_is_seed_derived_not_the_identity_key() {
        let a = VenueKey::from_seed(&[7u8; 32], Network::LiquidTestnet).unwrap();
        let b = VenueKey::from_seed(&[7u8; 32], Network::LiquidTestnet).unwrap();
        let mainnet = VenueKey::from_seed(&[7u8; 32], Network::Liquid).unwrap();
        let identity = WalletKey::new(&[7u8; 32], Network::LiquidTestnet);
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a.public_key(), mainnet.public_key());
        assert_ne!(a.public_key(), identity.public_key());
    }

    /// The derivation, pinned: an independent implementation (a hardware
    /// host, another SDK) must land on the same account key from the
    /// same seed. m/19523'/<network>'/0' from BIP32-master(seed).
    #[test]
    fn venue_key_derivation_vectors() {
        let testnet = VenueKey::from_seed(&[7u8; 32], Network::LiquidTestnet).unwrap();
        let mainnet = VenueKey::from_seed(&[7u8; 32], Network::Liquid).unwrap();
        assert_eq!(
            hex(&testnet.public_key().serialize()),
            "849904e240e9eb333f1d7889a4ec9b318ab19a877c929728aa511046618b5c33"
        );
        assert_eq!(hex(&mainnet.public_key().serialize()), "PIN_MAINNET");
    }

    /// Signatures verify against the venue key over the exact digest and
    /// against nothing else, and are deterministic (no aux randomness) —
    /// the property the shared test vectors rely on.
    #[test]
    fn order_signature_verifies_and_is_deterministic() {
        let key = VenueKey::from_seed(&[7u8; 32], Network::LiquidTestnet).unwrap();
        let (d, s) = sign_order(&key, OrderSide::Sell, 7_700_000_000, 1_000, 50, 1);
        let (d2, s2) = sign_order(&key, OrderSide::Sell, 7_700_000_000, 1_000, 50, 1);
        assert_eq!((d, s), (d2, s2));
        // byte-stable — the property the rf-vectors example (the venue
        // signing test vectors) relies on
        assert_eq!(hex(&d), "c1e1213719d7a48a911642992a41f0e4e26bd1fdf446394bb7777b98b2fb749b");
        assert_eq!(s.to_string(), "PIN_SIG");
        assert!(SECP256K1
            .verify_schnorr(&s, &Message::from_digest(d), &key.public_key())
            .is_ok());
        let (other, _) = sign_order(&key, OrderSide::Buy, 7_700_000_000, 1_000, 50, 1);
        assert!(SECP256K1
            .verify_schnorr(&s, &Message::from_digest(other), &key.public_key())
            .is_err());
    }
}
