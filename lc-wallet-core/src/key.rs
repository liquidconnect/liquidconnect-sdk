//! The wallet's Liquid Connect identity key.
//!
//! Vendored from `sideswap-io/sideswap_rust` (`sideswap_common/src/wallet_key.rs`,
//! MIT). The x-only public key of this keypair IS the wallet's identity on the
//! Connect server — there is no account or registration, control of the key is
//! the identity. It is deliberately derived from the wallet's master blinding
//! key and a per-network salt, so the same wallet presents the same identity
//! across app reinstalls without a second secret to back up, and presents
//! different identities on different networks.

use elements::bitcoin::{self, secp256k1::Message};
use elements::hashes::{Hash, HashEngine};
use elements::schnorr::{Keypair, XOnlyPublicKey};
use elements::secp256k1_zkp::{self, SECP256K1};

use bitcoin::hashes::sha256t_hash_newtype;

pub struct WalletKey {
    keypair: Keypair,
}

sha256t_hash_newtype! {
    pub struct WalletKeyTag = hash_str("sideswap/wallet_key");
    pub struct WalletKeyHash(_);
}

sha256t_hash_newtype! {
    pub struct WalletSignTag = hash_str("sideswap/sign");
    pub struct WalletSignHash(_);
}

/// The message a wallet signs to log in: a tagged hash over the server's
/// nonce with a fixed human-readable prefix, so the signature can never
/// be replayed as anything but a Connect login.
pub fn get_sign_message_hash(challenge: &str) -> Message {
    let text = format!("sideswap login, nonce: {challenge}");
    let hash = WalletSignHash::hash(text.as_bytes());
    Message::from_digest(hash.to_byte_array())
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Network {
    Liquid,
    LiquidTestnet,
    Regtest,
}

fn network_salt(network: Network) -> &'static [u8; 32] {
    match network {
        Network::Liquid => {
            &hex_literal::hex!("3f101e5de26db05ca3b4dc4e964b7889ff4bcb7006a89b14f5c9f5b7970b66db")
        }
        Network::LiquidTestnet => {
            &hex_literal::hex!("54151998bcf5347784eeda549407815d3390742d451221416a65a3ed7d739a34")
        }
        Network::Regtest => {
            &hex_literal::hex!("c96036d788d756a16fdfb427bc70d0b681315224c3d1c12cc9efc6ace2358c13")
        }
    }
}

impl WalletKey {
    /// The production derivation: from the wallet's master blinding key,
    /// salted per network.
    pub fn new(master_blinding_key: &[u8], network: Network) -> WalletKey {
        let mut engine = WalletKeyHash::engine();
        engine.input(network_salt(network));
        engine.input(master_blinding_key);
        let secret_key = WalletKeyHash::from_engine(engine).to_byte_array();

        let keypair = Keypair::from_seckey_slice(SECP256K1, &secret_key).expect("must not fail");

        WalletKey { keypair }
    }

    /// A throwaway identity for tests and headless tools. Not for real
    /// wallets: it is not derivable again, so the identity dies with the
    /// process unless the seed is kept.
    pub fn ephemeral() -> WalletKey {
        use rand::RngCore as _;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        WalletKey::new(&seed, Network::LiquidTestnet)
    }

    pub fn public_key(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
    }

    pub fn sign_challenge(&self, challenge: &str) -> secp256k1_zkp::schnorr::Signature {
        let message = get_sign_message_hash(challenge);
        SECP256K1.sign_schnorr(&message, &self.keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The identity must be a pure function of key material and network:
    /// same inputs, same identity, across reinstalls and devices.
    #[test]
    fn identity_is_deterministic_and_network_separated() {
        let a = WalletKey::new(&[7u8; 32], Network::LiquidTestnet);
        let b = WalletKey::new(&[7u8; 32], Network::LiquidTestnet);
        let mainnet = WalletKey::new(&[7u8; 32], Network::Liquid);
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a.public_key(), mainnet.public_key());
    }

    /// A login signature verifies against the tagged challenge hash and
    /// against nothing else.
    #[test]
    fn challenge_signature_verifies_and_binds_the_nonce() {
        let key = WalletKey::new(&[9u8; 32], Network::LiquidTestnet);
        let sig = key.sign_challenge("nonce-1");
        let msg = get_sign_message_hash("nonce-1");
        let other = get_sign_message_hash("nonce-2");
        assert!(SECP256K1
            .verify_schnorr(&sig, &msg, &key.public_key())
            .is_ok());
        assert!(SECP256K1
            .verify_schnorr(&sig, &other, &key.public_key())
            .is_err());
    }
}
