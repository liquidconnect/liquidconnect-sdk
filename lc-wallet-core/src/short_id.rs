//! The shareable form of a wallet identity.
//!
//! The Connect identity is an x-only public key: 64 hex characters that
//! nobody reads aloud or types from a chat message. The **short wallet
//! id** is what people share instead: 16 Crockford-base32 characters —
//! 80 bits of a tagged hash of the key — shown in four groups of four,
//! `K7M3-9PQ2-X4TB-H6WD`.
//!
//! What makes it safe to hand out:
//!
//! - **Derived, never assigned.** A pure function of the public key, so
//!   the wallet computes it offline and every server computes the same
//!   one. There is no registry to drift, leak, or lose.
//! - **80 bits.** Forging a second key with the same short id is a 2^80
//!   search; honest collisions need on the order of 2^40 wallets. A typo
//!   therefore lands in empty space — nothing to pay — and never on
//!   someone else's wallet, which is why no characters are spent on a
//!   check digit.
//! - **A human alphabet.** Crockford base32 has no I, L, O or U, and is
//!   case-insensitive. [`normalize`] accepts what people actually type:
//!   lower case, missing or extra dashes and spaces, I/L read as 1 and
//!   O as 0.
//!
//! Resolving a short id back to a key needs a party that already knows
//! the key — a server with the wallet connected — and matches by
//! recomputing. That is what the hub's pay page does.
//!
//! The wire protocol is unchanged: `wallet_id` on every message is still
//! the full x-only key. This is a presentation and lookup form.

use elements::hashes::{sha256t_hash_newtype, Hash};
use elements::schnorr::XOnlyPublicKey;

sha256t_hash_newtype! {
    pub struct WalletIdTag = hash_str("liquidconnect/wallet-id");
    pub struct WalletIdHash(_);
}

/// Crockford's base32 alphabet: digits, then letters without I, L, O, U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters in a short id, dashes excluded.
pub const SHORT_ID_LEN: usize = 16;

/// The short id of a Connect identity, in display form
/// (`XXXX-XXXX-XXXX-XXXX`, upper case).
pub fn short_wallet_id(public_key: &XOnlyPublicKey) -> String {
    let digest = WalletIdHash::hash(&public_key.serialize()).to_byte_array();
    let mut raw = String::with_capacity(SHORT_ID_LEN);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &byte in &digest[..10] {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            raw.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    debug_assert_eq!(raw.len(), SHORT_ID_LEN);
    group(&raw)
}

/// Canonicalise a typed or pasted short id. Returns the display form,
/// or `None` if the input is not a short id at all (wrong length, or a
/// character outside the alphabet after the usual substitutions).
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
    format!("{}-{}-{}-{}", &raw[0..4], &raw[4..8], &raw[8..12], &raw[12..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{Network, WalletKey};
    use std::str::FromStr;

    /// Pinned against the same vector the hub's JavaScript pins
    /// (`liquidconnect-web/server/wallet-id.mjs`): both sides derive
    /// from the key independently, so drift on either becomes a test
    /// failure rather than a pay page that says "not connected".
    #[test]
    fn short_id_matches_the_shared_vector() {
        let pk = XOnlyPublicKey::from_str(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(short_wallet_id(&pk), "ZFKG-NS4S-5QGG-ER0Z");
        let key = WalletKey::new(&[7u8; 32], Network::LiquidTestnet);
        assert_eq!(
            key.public_key().to_string(),
            "c430e1683ac5f48d4e058e602b9ee33890830be3a92fea9f524d5763c15369d1"
        );
        assert_eq!(key.short_id(), "8BDR-BSWW-V8DR-KZZ9");
    }

    #[test]
    fn short_id_is_sixteen_grouped_characters_from_the_alphabet() {
        let key = WalletKey::new(&[7u8; 32], Network::LiquidTestnet);
        let id = short_wallet_id(&key.public_key());
        assert_eq!(id.len(), 19);
        let raw: String = id.chars().filter(|c| *c != '-').collect();
        assert_eq!(raw.len(), SHORT_ID_LEN);
        assert!(raw.bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(id.matches('-').count(), 3);
        assert_eq!(key.short_id(), id);
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
        let confusable = raw.replace('1', "l").replace('0', "O");
        assert_eq!(normalize(&confusable), Some(id.clone()));
        assert!(matches(&raw.to_lowercase(), &key.public_key()));
    }

    #[test]
    fn normalize_rejects_what_is_not_a_short_id() {
        assert_eq!(normalize(""), None);
        assert_eq!(normalize("K7M3-9PQ2-X4TB"), None);
        assert_eq!(normalize("K7M3-9PQ2-X4TB-H6WD-0"), None);
        assert_eq!(normalize("K7M3-9PQ2-X4TB-H6WU"), None); // U is not in the alphabet
        assert_eq!(normalize("K7M3-9PQ2-X4TB-H6Wé"), None);
        let hex = "0".repeat(64);
        assert_eq!(normalize(&hex), None);
    }
}
