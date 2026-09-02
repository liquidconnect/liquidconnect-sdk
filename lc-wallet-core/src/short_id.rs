//! The shareable form of a wallet identity.
//!
//! The Connect identity is an x-only public key: 64 hex characters that
//! nobody reads aloud or types from a chat message. The **short wallet
//! id** is what people share instead: 8 Crockford-base32 characters —
//! 40 bits of a tagged hash of the key — shown as `K7M3-9PQ2`.
//!
//! - **Derived, never assigned.** A pure function of the public key, so
//!   the wallet computes it offline and every server computes the same
//!   one.
//! - **40 bits, so never trusted alone.** Forty bits is small enough
//!   that a colliding key can be manufactured by brute force, which is
//!   why an id is only payable once the identity directory has **bound
//!   it to the first key that claims it**; any other key presenting the
//!   same id is refused, and that refusal is logged as the attack it is.
//!   The app claims at activation and shows the id only once bound, so
//!   nothing is shared that could still be claimed by someone else.
//! - **A human alphabet.** Crockford base32 has no I, L, O or U and is
//!   case-insensitive; [`normalize`] accepts what people type: lower
//!   case, missing or extra dashes and spaces, I/L as 1 and O as 0.
//!
//! The wire protocol is unchanged: `wallet_id` on every message is still
//! the full x-only key. This is a presentation and lookup form. The same
//! derivation lives in the directory (`identity_core::short_id`) and the
//! hub (`liquidconnect-web/server/wallet-id.mjs`); all three pin the
//! vectors below.

use elements::hashes::{sha256t_hash_newtype, Hash};
use elements::schnorr::XOnlyPublicKey;

sha256t_hash_newtype! {
    pub struct WalletIdTag = hash_str("liquidconnect/wallet-id");
    pub struct WalletIdHash(_);
}

/// Crockford's base32 alphabet: digits, then letters without I, L, O, U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters in a short id, dash excluded.
pub const SHORT_ID_LEN: usize = 8;

/// The short id of a Connect identity, in display form (`XXXX-XXXX`).
pub fn short_wallet_id(public_key: &XOnlyPublicKey) -> String {
    let digest = WalletIdHash::hash(&public_key.serialize()).to_byte_array();
    let mut raw = String::with_capacity(SHORT_ID_LEN);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &byte in &digest[..5] {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            raw.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    debug_assert_eq!(raw.len(), SHORT_ID_LEN);
    group(&raw)
}

/// Canonicalise a typed or pasted short id. Returns the display form,
/// or `None` if the input is not a short id at all.
pub fn normalize(input: &str) -> Option<String> {
    let mut raw = String::with_capacity(SHORT_ID_LEN);
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        };
        if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
            return None;
        }
        raw.push(c);
    }
    (raw.len() == SHORT_ID_LEN).then(|| group(&raw))
}

/// Whether `input`, once normalised, names `public_key`.
pub fn matches(input: &str, public_key: &XOnlyPublicKey) -> bool {
    normalize(input).is_some_and(|id| id == short_wallet_id(public_key))
}

fn group(raw: &str) -> String {
    format!("{}-{}", &raw[0..4], &raw[4..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{Network, WalletKey};
    use std::str::FromStr;

    /// Pinned against the vectors the directory (`identity_core`) and
    /// the hub (`wallet-id.mjs`) pin too: three implementations, one id.
    #[test]
    fn short_id_matches_the_shared_vectors() {
        let pk = XOnlyPublicKey::from_str(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(short_wallet_id(&pk), "ZFKG-NS4S");
        let key = WalletKey::new(&[7u8; 32], Network::LiquidTestnet);
        assert_eq!(
            key.public_key().to_string(),
            "c430e1683ac5f48d4e058e602b9ee33890830be3a92fea9f524d5763c15369d1"
        );
        assert_eq!(key.short_id(), "8BDR-BSWW");
    }

    #[test]
    fn short_id_is_eight_grouped_characters_from_the_alphabet() {
        let key = WalletKey::new(&[7u8; 32], Network::LiquidTestnet);
        let id = short_wallet_id(&key.public_key());
        assert_eq!(id.len(), 9);
        let raw: String = id.chars().filter(|c| *c != '-').collect();
        assert_eq!(raw.len(), SHORT_ID_LEN);
        assert!(raw.bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(id.matches('-').count(), 1);
    }

    #[test]
    fn different_keys_get_different_ids() {
        let a = WalletKey::new(&[1u8; 32], Network::Liquid);
        let b = WalletKey::new(&[2u8; 32], Network::Liquid);
        assert_ne!(a.short_id(), b.short_id());
    }

    #[test]
    fn normalize_forgives_what_people_type() {
        let key = WalletKey::new(&[7u8; 32], Network::LiquidTestnet);
        let id = short_wallet_id(&key.public_key());
        let raw: String = id.chars().filter(|c| *c != '-').collect();
        assert_eq!(normalize(&id), Some(id.clone()));
        assert_eq!(normalize(&raw), Some(id.clone()));
        assert_eq!(normalize(&raw.to_lowercase()), Some(id.clone()));
        assert_eq!(normalize(&format!(" {} ", raw)), Some(id.clone()));
        assert_eq!(normalize("zfkg ns4s"), Some("ZFKG-NS4S".to_owned()));
        assert_eq!(normalize("K7M3-9PO2"), Some("K7M3-9P02".to_owned()));
        assert_eq!(normalize("K7M3-9PL2"), Some("K7M3-9P12".to_owned()));
        assert!(matches(&raw.to_lowercase(), &key.public_key()));
    }

    #[test]
    fn normalize_rejects_what_is_not_a_short_id() {
        assert_eq!(normalize(""), None);
        assert_eq!(normalize("K7M3-9PQ"), None);
        assert_eq!(normalize("K7M3-9PQ2-X"), None);
        assert_eq!(normalize("K7M3-9PQU"), None); // U is not in the alphabet
        assert_eq!(normalize("K7M3-9Pé2"), None);
        assert_eq!(normalize(&"0".repeat(64)), None);
    }
}
