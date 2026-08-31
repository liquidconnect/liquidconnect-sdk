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
#[derive(Clone)]
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

    /// Sign a typed request by rebuilding its digest under this key and
    /// signing that — the one path a host should use to sign a
    /// [`TypedRequest`], so order/withdraw/login all commit the exact
    /// fields the wallet verified and displayed (in particular a
    /// withdrawal signs its named destination, not the raw key). Returns
    /// `(digest, signature)`. Errors if the request names something this
    /// build cannot honour (unknown product, malformed dest address).
    pub fn sign_typed(&self, request: &TypedRequest) -> Result<([u8; 32], Signature), String> {
        let digest = typed_request_digest(request, &self.public_key().serialize())?;
        Ok((digest, self.sign_digest(digest)))
    }

    /// BIP340 over a venue digest, deterministic (no aux randomness) so
    /// signatures are vector-testable. Private on purpose: every public
    /// signing path goes through the typed builders in this module, so
    /// arbitrary bytes — e.g. a transaction sighash offered as "a
    /// message" — can never reach the key.
    fn sign_digest(&self, digest: [u8; 32]) -> Signature {
        SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &self.keypair)
    }

    /// The raw-key P2TR script `51 20 <pk>` of the venue money key — the
    /// script [`p2tr_spk_hash`] commits to: where venue withdrawals pay
    /// and what venue deposits spend. Raw x-only output key, no BIP341
    /// tweak, exactly as the covenant pins it.
    pub fn p2tr_script_pubkey(&self) -> elements::Script {
        let mut spk = Vec::with_capacity(34);
        spk.extend_from_slice(&[0x51, 0x20]);
        spk.extend_from_slice(&self.public_key().serialize());
        elements::Script::from(spk)
    }

    /// The venue key's keypair tweaked per BIP341 (keyspend-only, the
    /// TapTweak/elements tag) — the signer for coins at the STANDARD
    /// taproot address of this key, which is where the venue stages
    /// user deposits: a normal wallet must be able to pay and spend the
    /// staging address, so it uses the standard form; the raw form
    /// stays the covenant's internal exit/leaf model.
    fn tweaked_keypair(&self) -> Keypair {
        let tweak = elements::taproot::TapTweakHash::from_key_and_tweak(self.public_key(), None);
        let tweak = elements::secp256k1_zkp::Scalar::from_be_bytes(tweak.to_byte_array())
            .expect("a tagged hash is a valid scalar");
        self.keypair
            .add_xonly_tweak(SECP256K1, &tweak)
            .expect("tap tweak cannot produce an invalid key")
    }

    /// The BIP341-tweaked P2TR script of the venue key — the standard
    /// taproot output every wallet can pay, where the venue's deposit
    /// staging coins sit. Contrast [`VenueKey::p2tr_script_pubkey`],
    /// the raw covenant form.
    pub fn p2tr_tweaked_script_pubkey(&self) -> elements::Script {
        let (output_key, _) = self.tweaked_keypair().x_only_public_key();
        let mut spk = Vec::with_capacity(34);
        spk.extend_from_slice(&[0x51, 0x20]);
        spk.extend_from_slice(&output_key.serialize());
        elements::Script::from(spk)
    }

    /// Sign input `index` of `tx` as a key-path spend of
    /// [`VenueKey::p2tr_script_pubkey`]. `prevouts` must carry every
    /// input's TxOut and `genesis` the chain's genesis hash — Elements
    /// taproot sighashes commit to both. This is spend-class signing:
    /// the host renders and verifies the transaction before asking.
    pub fn sign_p2tr_keyspend(
        &self,
        tx: &elements::Transaction,
        index: usize,
        prevouts: &[elements::TxOut],
        genesis: elements::BlockHash,
    ) -> Signature {
        // The output key is the raw account key (no tweak), so the raw
        // keypair signs the sighash directly.
        Self::sign_keyspend_with(&self.keypair, tx, index, prevouts, genesis)
    }

    fn sign_keyspend_with(
        keypair: &Keypair,
        tx: &elements::Transaction,
        index: usize,
        prevouts: &[elements::TxOut],
        genesis: elements::BlockHash,
    ) -> Signature {
        let mut cache = elements::sighash::SighashCache::new(tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(
                index,
                &elements::sighash::Prevouts::All(prevouts),
                elements::sighash::SchnorrSighashType::Default,
                genesis,
            )
            .expect("prevouts must cover every input");
        SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), keypair)
    }

    /// Satisfy every PSET input that is the raw-key P2TR of this venue
    /// key and not yet final. Returns how many inputs were signed; a PSET
    /// with none is left untouched. Inputs are recognised by
    /// `witness_utxo`, so the wallet needs no index of these UTXOs — but
    /// when any input is ours, every input must carry a `witness_utxo`
    /// (the sighash commits to all prevouts).
    pub fn sign_pset_keyspend_inputs(
        &self,
        pset: &mut elements::pset::PartiallySignedTransaction,
        genesis: elements::BlockHash,
    ) -> anyhow::Result<usize> {
        // This key's coins live under two scripts: the raw covenant form
        // (exit payouts, pool leaves) and the standard tweaked form (the
        // deposit staging address a normal wallet pays). Each input is
        // signed with the keypair its script demands.
        let raw_spk = self.p2tr_script_pubkey();
        let tweaked_spk = self.p2tr_tweaked_script_pubkey();
        let mine: Vec<(usize, bool)> = pset
            .inputs()
            .iter()
            .enumerate()
            .filter(|(_, inp)| inp.final_script_witness.is_none())
            .filter_map(|(i, inp)| {
                let spk = &inp.witness_utxo.as_ref()?.script_pubkey;
                if *spk == raw_spk {
                    Some((i, false))
                } else if *spk == tweaked_spk {
                    Some((i, true))
                } else {
                    None
                }
            })
            .collect();
        if mine.is_empty() {
            return Ok(0);
        }
        let prevouts: Vec<elements::TxOut> = pset
            .inputs()
            .iter()
            .enumerate()
            .map(|(i, inp)| {
                inp.witness_utxo.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "input {i} carries no witness_utxo — required to sign a venue-key input"
                    )
                })
            })
            .collect::<Result<_, _>>()?;
        let tx = pset.extract_tx()?;
        let tweaked = self.tweaked_keypair();
        for (i, needs_tweak) in mine.iter().copied() {
            let keypair = if needs_tweak { &tweaked } else { &self.keypair };
            let sig = Self::sign_keyspend_with(keypair, &tx, i, &prevouts, genesis);
            pset.inputs_mut()[i].final_script_witness = Some(vec![sig.as_ref().to_vec()]);
        }
        Ok(mine.len())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OrderSide {
    Buy,
    Sell,
}

/// The chain's genesis hash — Elements taproot sighashes commit to it,
/// so every venue spend needs it. None for regtest, whose genesis is
/// per-chain.
/// Drive a venue's SDK login over HTTPS: fetch a challenge, clear-sign
/// it as an `rf/login/v1` typed claim with the venue key, and log in —
/// optionally associating a connect identity (for sign-message/pay
/// routing) and consuming a browser link code. `venue_host` must be a
/// BARE host (e.g. from [`crate::link::parse_venue_login_link`], which
/// refuses anything that could steer this URL); https is constructed
/// here and nowhere else. Blocking — hosts call it off their UI thread.
/// Returns the venue's JSON reply (account id, token) on success.
pub fn sdk_login(
    venue_host: &str,
    key: &VenueKey,
    identity_pk_hex: Option<&str>,
    link_code: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    anyhow::ensure!(
        !venue_host.is_empty()
            && venue_host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
        "venue must be a bare domain name"
    );
    let base = format!("https://{venue_host}");

    let challenge = ureq::post(&format!("{base}/api/sdk/challenge"))
        .timeout(std::time::Duration::from_secs(20))
        .send_string("")?
        .into_json::<serde_json::Value>()?
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow::anyhow!("no challenge in the venue's reply"))?
        .to_owned();

    let (_digest, sig) = sign_login(key, &challenge);
    let pk_hex = hex::encode(key.public_key().serialize());
    let sig_hex = sig.to_string();

    let mut pairs: Vec<(&str, &str)> = vec![
        ("pk", pk_hex.as_str()),
        ("sig", sig_hex.as_str()),
        ("challenge", challenge.as_str()),
    ];
    if let Some(id) = identity_pk_hex {
        pairs.push(("identity", id));
    }
    if let Some(code) = link_code {
        pairs.push(("link", code));
    }
    let body = pairs
        .iter()
        .map(|(k, v)| {
            let ev: String = v
                .bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        (b as char).to_string()
                    }
                    _ => format!("%{b:02X}"),
                })
                .collect();
            format!("{k}={ev}")
        })
        .collect::<Vec<_>>()
        .join("&");

    match ureq::post(&format!("{base}/api/sdk/login"))
        .timeout(std::time::Duration::from_secs(20))
        .set("content-type", "application/x-www-form-urlencoded")
        .send_string(&body)
    {
        Ok(r) => {
            let v = r.into_json::<serde_json::Value>()?;
            if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
                anyhow::bail!("venue refused the login: {err}");
            }
            Ok(v)
        }
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            anyhow::bail!("venue refused the login ({code}): {text}")
        }
        Err(err) => anyhow::bail!("could not reach the venue: {err}"),
    }
}

pub fn genesis_block_hash(network: Network) -> Option<elements::BlockHash> {
    let hex = match network {
        Network::Liquid => "1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003",
        Network::LiquidTestnet => "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1",
        Network::Regtest => return None,
    };
    Some(hex.parse().expect("static genesis hex"))
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

/// A typed venue request carried in a `StartSignMessage` description.
///
/// The clear-signing contract: instead of asking the user to approve an
/// opaque digest, the venue puts canonical JSON in the request's
/// `description`; the wallet parses it, REBUILDS the digest from the
/// typed fields with its own account key, and refuses unless the result
/// equals the request's digest. Only then does it render price/qty/side
/// (not a hash) and sign — with the venue money key, not the Connect
/// identity key. The digest equality check is what makes the description
/// trustworthy: a description that lies about the fields cannot hash to
/// the digest being signed.
///
/// The canonical JSON, pinned by tests below (u64 fields are strings so
/// a JavaScript venue can emit them losslessly; `root` is 64 hex chars):
///
/// ```json
/// {"kind":"rf/order/v1","product":"RF-BTC-USDT","side":"sell",
///  "price":"11500000000000","qty":"10000000","expiry":100,"nonce":"7"}
/// {"kind":"rf/withdraw/v1","amt":"5000","dest":"tlq1…(address)","root":"aaaa…(64)"}
/// {"kind":"rf/login/v1","challenge":"c1"}
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedRequest {
    Order {
        product: String,
        side: OrderSide,
        price: u64,
        qty: u64,
        expiry: u32,
        nonce: u64,
    },
    /// A withdrawal paid to `dest` — the wallet's own receive address, so
    /// the funds land where the app's descriptor wallet can see them
    /// (the raw-key P2TR the old flow paid was invisible to it). The
    /// digest commits `dest`'s script; the wallet shows the address it is
    /// withdrawing to and refuses if it does not rebuild the digest.
    Withdraw {
        amt: u64,
        /// Destination address string (an Elements/Liquid address).
        dest: String,
        root: [u8; 32],
    },
    Login { challenge: String },
}

/// Recognise a typed venue description. `None`: not typed — treat the
/// request as an ordinary opaque sign-message. `Some(Err…)`: the
/// description CLAIMS to be typed (`"kind":"rf/…"`) but is malformed —
/// the wallet must refuse, never fall back to opaque signing, or a
/// venue request would get silently signed by the wrong key without
/// clear-signing.
pub fn parse_typed_description(description: &str) -> Option<Result<TypedRequest, String>> {
    let value: serde_json::Value = serde_json::from_str(description.trim()).ok()?;
    let kind = value.get("kind")?.as_str()?;
    if !kind.starts_with("rf/") {
        return None;
    }
    Some(parse_typed_fields(kind, &value))
}

fn parse_typed_fields(kind: &str, value: &serde_json::Value) -> Result<TypedRequest, String> {
    let str_field = |name: &str| -> Result<&str, String> {
        value
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("missing or non-string field: {name}"))
    };
    let u64_field = |name: &str| -> Result<u64, String> {
        str_field(name)?
            .parse::<u64>()
            .map_err(|_| format!("field {name} is not a u64 string"))
    };

    match kind {
        "rf/order/v1" => Ok(TypedRequest::Order {
            product: str_field("product")?.to_owned(),
            side: match str_field("side")? {
                "buy" => OrderSide::Buy,
                "sell" => OrderSide::Sell,
                other => return Err(format!("unknown side: {other}")),
            },
            price: u64_field("price")?,
            qty: u64_field("qty")?,
            expiry: value
                .get("expiry")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                .ok_or("missing or invalid field: expiry")?,
            nonce: u64_field("nonce")?,
        }),
        "rf/withdraw/v1" => {
            let mut root = [0u8; 32];
            hex::decode_to_slice(str_field("root")?, &mut root)
                .map_err(|_| "root is not 32 bytes of hex".to_owned())?;
            Ok(TypedRequest::Withdraw {
                amt: u64_field("amt")?,
                dest: str_field("dest")?.to_owned(),
                root,
            })
        }
        "rf/login/v1" => Ok(TypedRequest::Login {
            challenge: str_field("challenge")?.to_owned(),
        }),
        other => Err(format!("unknown typed request kind: {other}")),
    }
}

/// Rebuild the digest a typed request commits to, under account key
/// `pk`. The wallet compares this against the digest in the
/// `StartSignMessage` request and refuses on mismatch. Errors when the
/// request names a product this build does not trade.
pub fn typed_request_digest(request: &TypedRequest, pk: &[u8; 32]) -> Result<[u8; 32], String> {
    match request {
        TypedRequest::Order {
            product,
            side,
            price,
            qty,
            expiry,
            nonce,
        } => {
            if product.as_bytes() != PRODUCT {
                return Err(format!("unknown product: {product}"));
            }
            Ok(order_digest(pk, *side, *price, *qty, *expiry, *nonce))
        }
        TypedRequest::Withdraw { amt, dest, root } => {
            let address = dest
                .parse::<elements::Address>()
                .map_err(|e| format!("withdraw dest is not a valid address: {e}"))?;
            let dest_spk_hash = sha(address.script_pubkey().as_bytes());
            Ok(withdraw_digest(pk, *amt, &dest_spk_hash, root))
        }
        TypedRequest::Login { challenge } => Ok(login_digest(pk, challenge)),
    }
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

    /// The typed-description contract: canonical JSON parses, rebuilds
    /// to exactly the shared digest vectors, non-typed text is None,
    /// and a malformed typed claim is a hard error — never a fallback.
    #[test]
    fn typed_descriptions_rebuild_the_shared_vectors() {
        let pk = [3u8; 32];

        let order = parse_typed_description(
            r#"{"kind":"rf/order/v1","product":"RF-BTC-USDT","side":"buy","price":"11500000000000","qty":"10000000","expiry":100,"nonce":"7"}"#,
        )
        .expect("typed")
        .expect("well-formed");
        assert_eq!(
            hex(&typed_request_digest(&order, &pk).unwrap()),
            "944e4e036d891dd277fee0987c355b2609fb09d6fc149ee2e2fd2b907acf9512"
        );

        let login =
            parse_typed_description(r#"{"kind":"rf/login/v1","challenge":"c1"}"#)
                .expect("typed")
                .expect("well-formed");
        assert_eq!(
            hex(&typed_request_digest(&login, &pk).unwrap()),
            "04e78310fc229b8d973fcd61744511cbe9182c1b00bcd56eee5f6b7181efdf4d"
        );

        // Withdraw now pays a named address; the digest commits that
        // address's script, so verify against an inline rebuild (the
        // dest varies, so a fixed constant would not generalise).
        let dest_key = VenueKey::from_seed(&[9u8; 32], Network::LiquidTestnet).unwrap();
        let dest = elements::Address::p2tr(
            SECP256K1,
            dest_key.public_key(),
            None,
            None,
            &elements::address::AddressParams::LIQUID_TESTNET,
        );
        let withdraw = parse_typed_description(&format!(
            r#"{{"kind":"rf/withdraw/v1","amt":"5000","dest":"{dest}","root":"{}"}}"#,
            "aa".repeat(32)
        ))
        .expect("typed")
        .expect("well-formed");
        let expected =
            withdraw_digest(&pk, 5000, &sha(dest.script_pubkey().as_bytes()), &[0xaa; 32]);
        assert_eq!(typed_request_digest(&withdraw, &pk).unwrap(), expected);
        // A malformed dest address is a refusal, not a silent raw-key fallback.
        assert!(typed_request_digest(
            &TypedRequest::Withdraw {
                amt: 1,
                dest: "not-an-address".to_owned(),
                root: [0u8; 32]
            },
            &pk
        )
        .is_err());

        // Not typed: ordinary opaque descriptions pass through as None.
        assert!(parse_typed_description("Sell 0.001 BTC").is_none());
        assert!(parse_typed_description(r#"{"note":"hi"}"#).is_none());

        // A typed CLAIM that is malformed is a refusal, not a fallback.
        assert!(parse_typed_description(r#"{"kind":"rf/order/v1"}"#)
            .unwrap()
            .is_err());
        assert!(parse_typed_description(r#"{"kind":"rf/unknown/v9"}"#)
            .unwrap()
            .is_err());

        // A product this build does not trade refuses at digest time.
        let alien = TypedRequest::Order {
            product: "RF-DOGE-USDT".to_owned(),
            side: OrderSide::Buy,
            price: 1,
            qty: 1,
            expiry: 1,
            nonce: 1,
        };
        assert!(typed_request_digest(&alien, &pk).is_err());
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
        assert_eq!(
            hex(&mainnet.public_key().serialize()),
            "ef4de5ec56a30bdcf5a078e0111d3ebadba10350cfcb8a272231563f71c3a00b"
        );
    }

    /// The spend surface: only inputs paying the venue key's raw P2TR are
    /// signed, foreign inputs stay untouched, re-signing is a no-op, and
    /// the witness signature verifies against the raw account key over the
    /// exact Elements taproot sighash — the same script `p2tr_spk_hash`
    /// commits to.
    #[test]
    fn pset_keyspend_signs_only_venue_inputs() {
        let key = VenueKey::from_seed(&[7u8; 32], Network::LiquidTestnet).unwrap();
        let spk = key.p2tr_script_pubkey();
        assert_eq!(spk.len(), 34);
        assert_eq!(
            sha(spk.as_bytes()),
            p2tr_spk_hash(&key.public_key().serialize()),
            "the spend script must be the script the covenant commits to"
        );

        let genesis: elements::BlockHash =
            "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1"
                .parse()
                .unwrap();
        let asset = elements::AssetId::from_slice(&[0xEE; 32]).unwrap();
        let mine = elements::TxOut {
            asset: elements::confidential::Asset::Explicit(asset),
            value: elements::confidential::Value::Explicit(100_000_000),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: spk.clone(),
            witness: elements::TxOutWitness::default(),
        };
        let foreign = elements::TxOut {
            script_pubkey: elements::Script::from(vec![0x51, 0x20, 0xAB]),
            ..mine.clone()
        };
        // The standard tweaked form — the deposit staging address. Must
        // differ from the raw script and be recognised alongside it.
        let tweaked_spk = key.p2tr_tweaked_script_pubkey();
        assert_ne!(tweaked_spk, spk, "tweak must move the output key");
        let staged = elements::TxOut {
            script_pubkey: tweaked_spk.clone(),
            ..mine.clone()
        };

        let mut pset = elements::pset::PartiallySignedTransaction::new_v2();
        for (n, utxo) in [(0x11u8, &mine), (0x22u8, &foreign), (0x33u8, &staged)] {
            let mut inp = elements::pset::Input::from_prevout(elements::OutPoint {
                txid: elements::Txid::from_slice(&[n; 32]).unwrap(),
                vout: 0,
            });
            inp.witness_utxo = Some(utxo.clone());
            pset.add_input(inp);
        }
        pset.add_output(elements::pset::Output::new_explicit(
            spk.clone(),
            199_000_000,
            asset,
            None,
        ));
        pset.add_output(elements::pset::Output::new_explicit(
            elements::Script::new(),
            1_000_000,
            asset,
            None,
        ));

        assert_eq!(key.sign_pset_keyspend_inputs(&mut pset, genesis).unwrap(), 2);
        assert!(pset.inputs()[0].final_script_witness.is_some());
        assert!(pset.inputs()[1].final_script_witness.is_none());
        assert!(pset.inputs()[2].final_script_witness.is_some());
        assert_eq!(key.sign_pset_keyspend_inputs(&mut pset, genesis).unwrap(), 0);

        let tx = pset.extract_tx().unwrap();
        let prevouts = [mine.clone(), foreign.clone(), staged.clone()];
        let mut tweaked_output_key = [0u8; 32];
        tweaked_output_key.copy_from_slice(&tweaked_spk.as_bytes()[2..]);
        let tweaked_output_key = XOnlyPublicKey::from_slice(&tweaked_output_key).unwrap();
        for (index, expect_key) in [(0usize, key.public_key()), (2, tweaked_output_key)] {
            let sig_bytes = &pset.inputs()[index].final_script_witness.as_ref().unwrap()[0];
            let sig = Signature::from_slice(sig_bytes).unwrap();
            let mut cache = elements::sighash::SighashCache::new(&tx);
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    index,
                    &elements::sighash::Prevouts::All(&prevouts),
                    elements::sighash::SchnorrSighashType::Default,
                    genesis,
                )
                .unwrap();
            SECP256K1
                .verify_schnorr(
                    &sig,
                    &Message::from_digest(sighash.to_byte_array()),
                    &expect_key,
                )
                .unwrap();
        }
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
        assert_eq!(
            s.to_string(),
            "d530f38b20a7de17fd3d17a0a250eb4f0a390eba9b64f0f0f0d00aefd3736e72\
             8163fa25f9d03a73a6b7417e509ec1b831355221442ac5b127c2ed5318b4f15c"
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
