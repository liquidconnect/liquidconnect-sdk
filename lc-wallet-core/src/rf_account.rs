//! A Rolling Future margin account as a contract kind: `sw/rf/account/v1`
//! (contract standard §2b criterion J for the venue; positions spec §7.3
//! and §10 brought forward, 2026-09-18, Scott's decision).
//!
//! The venue's pool is ONE explicit USDt output whose script commits to the
//! whole venue state, the bs-channel pattern:
//!
//! ```text
//! script     = nums_script(TapBranch(program_root, TapData(state_hash)))
//! state_hash = SHA256("RFS1" ‖ accounts_root ‖ session(be4) ‖ epoch_end(be4)
//!                     ‖ 0x00 | 0x01 ‖ damaged_at(be4))
//! ```
//!
//! An account is one leaf of the depth-16 account tree (`RFL2`, 213 bytes:
//! owner_pk, trade_pk, cash, rolled_qty, last_session, up to eight fills),
//! and a sixteen-hash sibling path proves it against `accounts_root`. The
//! ten pool programs bake the oracle key in at compile time, so the program
//! root is a constant per venue and network, pinned by review ([`PINS`]).
//!
//! The immutable params of an account are the asset, the program root, the
//! owner key (the wallet's VENUE key, which the covenant pays withdrawals
//! to) and the leaf index. Everything that moves — the root, the session,
//! the epoch, the leaf and its path — is the state, packed ([`AccountState`]),
//! lower-case hex on the wire. The coin is the pool output, shared by every
//! account; its amount is the whole pool.
//!
//! What the wallet checks is what the chain commits to: the DRIVER's mirror
//! of the on-chain leaf set, not the venue's live engine, which advances
//! leaves lazily off chain. Proven byte for byte against the live testnet
//! pool (`b0f83935…:0`, session 349) and the engine's golden vectors; the
//! tests carry both.

use elements::hashes::{Hash as _, sha256};
use elements::{AssetId, Script};

use crate::bs_channel::simplicity_tapleaf;
use crate::key::Network;
use crate::lending::{nums_script, tap_branch, tap_tagged};

/// Tree depth: 2^16 accounts.
pub const DEPTH: usize = 16;
/// Fills a leaf carries at most (`rf_engine::model::K_MAX_FILLS`).
pub const K_MAX_FILLS: usize = 8;
/// `owner_pk(32) ‖ trade_pk(32) ‖ cash(8) ‖ rolled_qty(8) ‖ last_session(4) ‖ n_fills(1) ‖ K×(qty 8 ‖ price 8)`.
pub const LEAF_BYTES: usize = 32 + 32 + 8 + 8 + 4 + 1 + K_MAX_FILLS * 16;

const TAG_LEAF: &[u8] = b"RFL2";
const TAG_EMPTY: &[u8] = b"RFE1";
const TAG_NODE: &[u8] = b"RFN1";
const TAG_STATE: &[u8] = b"RFS1";

/// The engine's tagged hash: plain `SHA256(tag ‖ data)`.
fn tagged(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(tag.len() + data.len());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(data);
    sha256::Hash::hash(&buf).to_byte_array()
}

/// One fill taken this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fill {
    pub qty: i64,
    pub price: u64,
}

/// An account leaf, exactly as the engine serialises it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub owner_pk: [u8; 32],
    pub trade_pk: [u8; 32],
    pub cash: u64,
    pub rolled_qty: i64,
    pub last_session: u32,
    pub fills: Vec<Fill>,
}

impl Leaf {
    pub fn to_bytes(&self) -> [u8; LEAF_BYTES] {
        let mut out = [0u8; LEAF_BYTES];
        out[..32].copy_from_slice(&self.owner_pk);
        out[32..64].copy_from_slice(&self.trade_pk);
        out[64..72].copy_from_slice(&self.cash.to_be_bytes());
        out[72..80].copy_from_slice(&(self.rolled_qty as u64).to_be_bytes());
        out[80..84].copy_from_slice(&self.last_session.to_be_bytes());
        out[84] = self.fills.len() as u8;
        for (i, fill) in self.fills.iter().take(K_MAX_FILLS).enumerate() {
            let o = 85 + i * 16;
            out[o..o + 8].copy_from_slice(&(fill.qty as u64).to_be_bytes());
            out[o + 8..o + 16].copy_from_slice(&fill.price.to_be_bytes());
        }
        out
    }

    /// Strict: the padding past `n_fills` must be zero, so one leaf has one encoding.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != LEAF_BYTES {
            return None;
        }
        let n = b[84] as usize;
        if n > K_MAX_FILLS || b[85 + n * 16..].iter().any(|x| *x != 0) {
            return None;
        }
        let fills = (0..n)
            .map(|i| {
                let o = 85 + i * 16;
                Fill {
                    qty: u64::from_be_bytes(b[o..o + 8].try_into().unwrap()) as i64,
                    price: u64::from_be_bytes(b[o + 8..o + 16].try_into().unwrap()),
                }
            })
            .collect();
        Some(Leaf {
            owner_pk: b[..32].try_into().unwrap(),
            trade_pk: b[32..64].try_into().unwrap(),
            cash: u64::from_be_bytes(b[64..72].try_into().unwrap()),
            rolled_qty: u64::from_be_bytes(b[72..80].try_into().unwrap()) as i64,
            last_session: u32::from_be_bytes(b[80..84].try_into().unwrap()),
            fills,
        })
    }

    /// Net position: what was rolled over plus this session's fills.
    pub fn position(&self) -> i64 {
        self.fills.iter().fold(self.rolled_qty, |p, f| p.saturating_add(f.qty))
    }
}

pub fn leaf_hash(leaf: &Leaf) -> [u8; 32] {
    tagged(TAG_LEAF, &leaf.to_bytes())
}

fn empty_hashes() -> [[u8; 32]; DEPTH + 1] {
    let mut e = [[0u8; 32]; DEPTH + 1];
    e[0] = tagged(TAG_EMPTY, b"");
    for i in 1..=DEPTH {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&e[i - 1]);
        buf[32..].copy_from_slice(&e[i - 1]);
        e[i] = tagged(TAG_NODE, &buf);
    }
    e
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(l);
    buf[32..].copy_from_slice(r);
    tagged(TAG_NODE, &buf)
}

/// The root of the account tree, right-padded with empties (the engine's `accounts_root`).
pub fn accounts_root(leaves: &[Leaf]) -> [u8; 32] {
    let empties = empty_hashes();
    let mut level: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
    for empty in empties.iter().take(DEPTH) {
        if level.is_empty() {
            return empties[DEPTH];
        }
        level = level.chunks(2).map(|pair| node(&pair[0], pair.get(1).unwrap_or(empty))).collect();
    }
    level[0]
}

/// The sibling path (bottom up) of `index` (the engine's `proof`).
pub fn proof(leaves: &[Leaf], index: usize) -> Option<[[u8; 32]; DEPTH]> {
    if index >= leaves.len() {
        return None;
    }
    let empties = empty_hashes();
    let mut level: Vec<[u8; 32]> = leaves.iter().map(leaf_hash).collect();
    let mut path = [[0u8; 32]; DEPTH];
    let mut i = index;
    for (d, slot) in path.iter_mut().enumerate() {
        *slot = if i % 2 == 0 { level.get(i + 1).copied().unwrap_or(empties[d]) } else { level[i - 1] };
        level = level.chunks(2).map(|pair| node(&pair[0], pair.get(1).unwrap_or(&empties[d]))).collect();
        i /= 2;
    }
    Some(path)
}

pub fn verify_proof(root: &[u8; 32], index: u32, leaf: &[u8; 32], path: &[[u8; 32]; DEPTH]) -> bool {
    let mut h = *leaf;
    let mut i = index as usize;
    for sib in path {
        h = if i % 2 == 0 { node(&h, sib) } else { node(sib, &h) };
        i /= 2;
    }
    h == *root
}

/// The global state commitment the pool output carries (engine `merkle::state_hash`).
pub fn state_hash(accounts_root: &[u8; 32], session: u32, epoch_end: u32, damaged_at: Option<u32>) -> [u8; 32] {
    let mut buf = Vec::with_capacity(45);
    buf.extend_from_slice(accounts_root);
    buf.extend_from_slice(&session.to_be_bytes());
    buf.extend_from_slice(&epoch_end.to_be_bytes());
    match damaged_at {
        None => buf.push(0),
        Some(s) => {
            buf.push(1);
            buf.extend_from_slice(&s.to_be_bytes());
        }
    }
    tagged(TAG_STATE, &buf)
}

/// The ten pool programs in the order the program set publishes them
/// (`rolling-future` `covenant/measure/src/lib.rs` `PROG_NAMES`).
pub const PROGRAM_NAMES: [&str; 10] = ["deposit", "withdraw", "advance", "advance_sd", "fill", "exit", "open", "damage", "advance_k", "fill_k"];

/// The fixed branch of the pool's tree from the ten tapleaves, in
/// [`PROGRAM_NAMES`] order (`measure::Pool::tree` minus the state leaf).
pub fn program_root_of_tapleaves(l: &[[u8; 32]; 10]) -> [u8; 32] {
    let (deposit, withdraw, advance, advance_sd, fill, exit, open, damage, advance_k, fill_k) = (l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7], l[8], l[9]);
    let b1 = tap_branch(deposit, withdraw);
    let b2k = tap_branch(tap_branch(advance, advance_sd), advance_k);
    let b3 = tap_branch(fill, exit);
    let b4k = tap_branch(tap_branch(open, damage), fill_k);
    tap_branch(tap_branch(b1, b2k), tap_branch(b3, b4k))
}

/// The same from the ten CMRs (the sidecar's `.cmr-cache-v1.json`).
pub fn program_root(cmrs: &[[u8; 32]; 10]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = cmrs.iter().map(simplicity_tapleaf).collect();
    program_root_of_tapleaves(&leaves.try_into().expect("ten leaves"))
}

/// The pool's scriptPubKey at `state_hash`.
pub fn pool_script(program_root: &[u8; 32], state_hash: &[u8; 32]) -> Script {
    nums_script(tap_branch(*program_root, tap_tagged(b"TapData", &[state_hash])))
}

/// The immutable terms of an account.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountTerms {
    pub asset: AssetId,
    /// The venue's program root; must be a [`PINS`] entry.
    pub program_root: [u8; 32],
    /// The wallet's venue key: the leaf's `owner_pk`, where withdrawals and exits pay.
    pub owner_pk: [u8; 32],
    /// The leaf's index in the account tree.
    pub index: u32,
}

/// The mutable state: the venue's commitment and this account's leaf with
/// its proof. Packed as `root(32) ‖ session(4) ‖ epoch_end(4) ‖ damaged
/// (1 or 5) ‖ leaf(213) ‖ path(16×32)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    pub root: [u8; 32],
    pub session: u32,
    pub epoch_end: u32,
    pub damaged_at: Option<u32>,
    pub leaf: Leaf,
    pub path: [[u8; 32]; DEPTH],
}

impl AccountState {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 4 + 5 + LEAF_BYTES + DEPTH * 32);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.session.to_be_bytes());
        out.extend_from_slice(&self.epoch_end.to_be_bytes());
        match self.damaged_at {
            None => out.push(0),
            Some(s) => {
                out.push(1);
                out.extend_from_slice(&s.to_be_bytes());
            }
        }
        out.extend_from_slice(&self.leaf.to_bytes());
        for sib in &self.path {
            out.extend_from_slice(sib);
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 41 {
            return None;
        }
        let root: [u8; 32] = b[..32].try_into().ok()?;
        let session = u32::from_be_bytes(b[32..36].try_into().ok()?);
        let epoch_end = u32::from_be_bytes(b[36..40].try_into().ok()?);
        let (damaged_at, o) = match b[40] {
            0 => (None, 41),
            1 => (Some(u32::from_be_bytes(b.get(41..45)?.try_into().ok()?)), 45),
            _ => return None,
        };
        let leaf = Leaf::from_bytes(b.get(o..o + LEAF_BYTES)?)?;
        let rest = b.get(o + LEAF_BYTES..)?;
        if rest.len() != DEPTH * 32 {
            return None;
        }
        let mut path = [[0u8; 32]; DEPTH];
        for (i, slot) in path.iter_mut().enumerate() {
            *slot = rest[i * 32..i * 32 + 32].try_into().ok()?;
        }
        Some(AccountState { root, session, epoch_end, damaged_at, leaf, path })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn from_hex(text: &str) -> Option<Self> {
        if text.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        Self::from_bytes(&hex::decode(text).ok()?)
    }

    pub fn state_hash(&self) -> [u8; 32] {
        state_hash(&self.root, self.session, self.epoch_end, self.damaged_at)
    }

    /// The leaf is this account's and sits in the tree the root commits to.
    pub fn proves(&self, terms: &AccountTerms) -> bool {
        self.leaf.owner_pk == terms.owner_pk && verify_proof(&self.root, terms.index, &leaf_hash(&self.leaf), &self.path)
    }
}

/// The pool's scriptPubKey for these terms at this state, if the state
/// proves the account (else `None`: not a state these terms make).
pub fn account_script(terms: &AccountTerms, state: &AccountState) -> Option<Script> {
    state.proves(terms).then(|| pool_script(&terms.program_root, &state.state_hash()))
}

/// One venue's program set on one network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VenuePin {
    pub network: Network,
    pub venue: &'static str,
    pub program_root: [u8; 32],
    /// The oracle key compiled into the programs.
    pub oracle_pk: [u8; 32],
    pub sources: &'static str,
}

/// The program sets a wallet built from this source accepts. The standard's
/// registry (§4) admits Rolling Future v5 for DISPLAY, conditional for the
/// exit (the v6 stale-oracle tear-up branch); a wallet shows the account and
/// says so (2026-09-18).
pub const PINS: &[VenuePin] = &[VenuePin {
    network: Network::LiquidTestnet,
    venue: "Rolling Future",
    // The testnet pool of paper.swaption.io (the "fee" instance), v5 programs
    // as compiled in /srv/apps/rolling-future/covenant (.cmr-cache-v1.json,
    // 2026-09-07); proven against the live pool output 2026-09-18.
    program_root: hex_literal::hex!("ee77a512e5de1f57e8f741c0ac0d0dadc5d3540596ffa1da8734f923d2d1f326"),
    oracle_pk: hex_literal::hex!("3c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1"),
    sources: "https://github.com/sideswap-io/rolling-future (covenant/v5)",
}];

pub fn pin_for(program_root: &[u8; 32]) -> Option<&'static VenuePin> {
    PINS.iter().find(|pin| pin.program_root == *program_root)
}

pub fn pinned(terms: &AccountTerms) -> Option<&'static VenuePin> {
    pin_for(&terms.program_root)
}

#[cfg(test)]
pub(crate) mod vectors {
    use super::*;
    use std::str::FromStr;

    pub const USDT_TESTNET: &str = "b612eb46313a2cd6ebabd8b7a8eed5696e29898b87a43bff41c94f51acef9d73";

    /// The driver's mirror of the live testnet pool at its anchor
    /// (`rf-driver-state-fee.json`, applied 79772, session 349): the fourteen
    /// leaves the on-chain state commits to, and the pool coin.
    pub const ANCHOR_JSON: &str = include_str!("rf_account_anchor.json");
    pub const POOL_SCRIPT: &str = "5120486384762b2953beb1258a1ccb078c68748bbd08db948848abaa4f0e23de4a1a";
    /// The ten CMRs of the pool's program set (`.cmr-cache-v1.json`, `PROGRAM_NAMES` order).
    pub const CMRS: [&str; 10] = [
        "bb3d7a70be89860bd847f230b8222bddb37c0913cb45ac7b2da15054cb1e0ae9",
        "9983b9daa9c769bbe03502bef23cdaf5a62a41ce89d7573685289e493c559576",
        "ef7d3ea6f839094dcad34c4c4dea5f6b5bc2a221a1b6f32198cdf05a5278a0a0",
        "d99f9999d3f733b72f118e36fe7ebac413d6f9c25712169ab24d0288e9e5d514",
        "61879c5241f689b7a15d2cd22b2b406195c68a2fa12159d6061017897ea1164b",
        "508d520d555c288cb293dc9fd5def0432ccf5ac470a4b444b500f1202203f60d",
        "f14dd095629a0eb8281706e4c520da5c25a7c6b12cef1ea8461a2be4666e41ab",
        "4b315b7167bbfa68ebe9f72dd7613dbfcdd33820d624d7260a91d866545a0a51",
        "fe68596a25cc06606d18bfd30c0a069b712e21c7b91ee913f75f2e5a10364c4e",
        "2c5ad13fd73298da00c3241468f2edbc3d9b8dc714f9855ee4704381803b084a",
    ];

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    pub fn anchor() -> (Vec<Leaf>, u32, (elements::Txid, u32, u64)) {
        let v: serde_json::Value = serde_json::from_str(ANCHOR_JSON).unwrap();
        let leaves = v["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| Leaf {
                owner_pk: h32(l["pk"].as_str().unwrap()),
                trade_pk: h32(l["tradePk"].as_str().unwrap()),
                cash: l["cash"].as_u64().unwrap(),
                rolled_qty: l["rolled"].as_i64().unwrap(),
                last_session: l["last"].as_u64().unwrap() as u32,
                fills: l["fills"].as_array().unwrap().iter().map(|f| Fill { qty: f[0].as_i64().unwrap(), price: f[1].as_u64().unwrap() }).collect(),
            })
            .collect();
        let pool = &v["pool"];
        (
            leaves,
            v["session"].as_u64().unwrap() as u32,
            (elements::Txid::from_str(pool[0].as_str().unwrap()).unwrap(), pool[1].as_u64().unwrap() as u32, pool[2].as_u64().unwrap()),
        )
    }

    /// Account 1 of the live pool, as the venue would describe it.
    pub fn account_1() -> (AccountTerms, AccountState) {
        let (leaves, session, _) = anchor();
        let terms = AccountTerms {
            asset: AssetId::from_str(USDT_TESTNET).unwrap(),
            program_root: PINS[0].program_root,
            owner_pk: leaves[1].owner_pk,
            index: 1,
        };
        let state = AccountState {
            root: accounts_root(&leaves),
            session,
            epoch_end: u32::MAX,
            damaged_at: None,
            leaf: leaves[1].clone(),
            path: proof(&leaves, 1).unwrap(),
        };
        (terms, state)
    }
}

#[cfg(test)]
mod tests {
    use super::vectors::*;
    use super::*;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// The engine's golden vectors (`engine/tests/vectors.rs`, RFL2): the
    /// backstop leaf and two fresh accounts, one delegated.
    #[test]
    fn the_engines_golden_vectors_are_reproduced() {
        const USDT: u64 = 100_000_000;
        let fresh = |owner: u8, trade: u8, cash: u64| Leaf { owner_pk: [owner; 32], trade_pk: [trade; 32], cash, rolled_qty: 0, last_session: 0, fills: Vec::new() };
        let leaves = vec![fresh(0, 0, 1_000 * USDT), fresh(1, 0x11, 30_000 * USDT), fresh(2, 2, 30_000 * USDT)];
        let root = accounts_root(&leaves);
        assert_eq!(hex::encode(root), "5c79d0eb6761ca2a1ee9b0493e2210c20dc697a45d717d0b73462714f6a9b4c9");
        assert_eq!(hex::encode(state_hash(&root, 0, 4, None)), "4e2182135b42c5345dcf36bf52f24f6b6600d59bd9f1820536edcbeb654145d0");
        let path = proof(&leaves, 1).unwrap();
        assert!(verify_proof(&root, 1, &leaf_hash(&leaves[1]), &path));
        assert!(!verify_proof(&root, 2, &leaf_hash(&leaves[1]), &path), "another index");
        assert!(proof(&leaves, 3).is_none());
        let bytes = leaves[1].to_bytes();
        assert_eq!(bytes.len(), 213);
        assert_eq!(Leaf::from_bytes(&bytes), Some(leaves[1].clone()));
        let mut padded = bytes;
        padded[212] = 1;
        assert_eq!(Leaf::from_bytes(&padded), None, "one leaf, one encoding");
    }

    /// The live testnet pool: the fourteen mirrored leaves make the root the
    /// pool output commits to, under the pinned program root, at session 349.
    #[test]
    fn the_live_pool_output_is_rebuilt_byte_for_byte() {
        let cmrs: Vec<[u8; 32]> = CMRS.iter().map(|c| h32(c)).collect();
        assert_eq!(program_root(&cmrs.try_into().unwrap()), PINS[0].program_root);
        let (terms, state) = account_1();
        assert!(state.proves(&terms));
        let script = account_script(&terms, &state).unwrap();
        assert_eq!(hex::encode(script.as_bytes()), POOL_SCRIPT);
        // The wire form round-trips and is strict.
        let hex_text = state.to_hex();
        assert_eq!(hex_text.len(), (32 + 4 + 4 + 1 + LEAF_BYTES + DEPTH * 32) * 2);
        assert_eq!(AccountState::from_hex(&hex_text), Some(state.clone()));
        assert_eq!(AccountState::from_hex(&hex_text.to_uppercase()), None);
        assert_eq!(AccountState::from_hex(&hex_text[..hex_text.len() - 2]), None);
        // Another account's leaf, or a wrong index, is not this account's state.
        let (leaves, _, _) = anchor();
        let mut other = state.clone();
        other.leaf = leaves[2].clone();
        other.path = proof(&leaves, 2).unwrap();
        assert!(!other.proves(&terms), "the leaf's owner is not the terms' owner");
        let mut wrong_index = terms.clone();
        wrong_index.index = 2;
        assert!(!state.proves(&wrong_index));
        // A damaged pool is another commitment.
        let mut damaged = state.clone();
        damaged.damaged_at = Some(300);
        assert_ne!(account_script(&terms, &damaged).unwrap(), script);
        assert_eq!(AccountState::from_hex(&damaged.to_hex()), Some(damaged));
        assert_eq!(state.leaf.position(), 0);
        assert_eq!(pinned(&terms).map(|p| p.venue), Some("Rolling Future"));
        let mut unpinned = terms.clone();
        unpinned.program_root[0] ^= 1;
        assert_eq!(pinned(&unpinned), None);
    }
}
