//! Wallet-held covenant positions — phase 0: derive and show.
//!
//! Spec: Dropbox `liquid connect/COVENANT-POSITIONS-SPEC-2026-09-16.md`
//! (revision 3) and `CONTRACT-STANDARD-2026-09-16.md`; a copy lands in
//! docs/ once agreed. This module needs no protocol change: every step the
//! wallet signs already carries the full terms in its typed claim, and the
//! wallet knows the txid at approval (SIGHASH_ALL; witnesses do not enter
//! the txid), so the record of the position is derived from the claim and
//! the funded PSET the host is about to return in `AcceptFundRequest`.
//!
//! What this module gives a host wallet:
//!
//! - [`ContractParams`]: the terms of a contract of a pinned kind, their
//!   canonical JSON, the deterministic [`ContractParams::contract_id`],
//!   the covenant script for a state, and the cutoff height;
//! - [`derive`]: what an accepted typed fund does to the wallet's records
//!   (a new position or offer, a moved or closed one, claim coins gone);
//! - the note ([`position_note`], [`NoteKey`], [`seal_note`],
//!   [`note_script`]): the 79-byte encrypted OP_RETURN the wallet appends
//!   to every fill it funds, so that its own transaction history — which a
//!   seed restore recovers — names every position it created;
//! - [`recover_fill`]: a position back from one of the wallet's own fill
//!   transactions and the note alone, with the script recomputed and
//!   compared, so a wrong key or a tampered note yields nothing;
//! - the reconstruction a restored wallet runs over its own history (spec
//!   §8.1): [`recover_position`] per transaction, [`follow_position`] to
//!   bring it to now through the wallet's own later steps, and
//!   [`recover_claim`] / [`claim_coins`] for what a lender token is owed;
//! - [`ContractRecord::render`]: the person-facing line, from verified
//!   terms only, with the cutoff.
//!
//! What it deliberately does not do: verify a template (that is
//! `lending::verify_typed_fund`, which must have passed first), hold keys
//! (the note key is a 32-byte secret the host derives from the seed on a
//! dedicated hardened path — never from the master blinding key, which is
//! view-tier material and travels inside the descriptor), or persist
//! anything (records are the host's to store).

use std::collections::BTreeMap;

use elements::bitcoin::NetworkKind;
use elements::bitcoin::bip32::{ChildNumber, Xpriv};
use elements::bitcoin::secp256k1::Secp256k1;
use elements::hashes::{Hash as _, HashEngine as _, sha256};
use elements::{AssetId, OutPoint, Script, Txid};

use crate::approval::{OwnedInput, decode_pset};
use crate::bs_channel::{self, ChannelTerms};
use crate::rf_account::{self, AccountTerms};
use crate::key::Network;
use crate::lending::{
    FILL_BORROWER_NFT_OUTPUT, FILL_LENDER_NFT_OUTPUT, FILL_POSITION_OUTPUT, OfferRowClaim, SWAPTION_CLAIM_LEAF,
    SWAPTION_LENDING_V4_LEAF, SWAPTION_LENDING_V5_LEAF, SWAPTION_OFFER_LEAF, TypedFund, claim_script, fmt8, offer_script,
    offer_terms_digest, op_return_payload, v4_position_script, v4_terms_digest, v5_position_script, v5_terms_digest,
};

/// The feature a wallet advertises in `LoginReq.features` once it holds
/// contracts (spec §4.5). Not sent yet: phase 1.
pub const CONTRACTS_FEATURE: &str = "contracts/1";

/// Kind names: the typed-kind vocabulary the SDK already speaks.
pub mod kind {
    pub const LEND_POSITION_V5: &str = "sw/lend/position/v5";
    /// The v4 covenant (all-or-nothing last look): what a venue whose
    /// `dealer.covenant_version` is 4 still creates.
    pub const LEND_POSITION_V4: &str = "sw/lend/position/v4";
    pub const LEND_OFFER_V1: &str = "sw/lend/offer/v1";
    pub const LEND_CLAIM_V1: &str = "sw/lend/claim/v1";
    /// A BetSimply house channel under the v5 program set (`bs_channel`).
    pub const BS_CHANNEL_V5: &str = "bs/channel/v5";
    /// A Rolling Future margin account: a leaf of the venue's pool (`rf_account`).
    pub const RF_ACCOUNT_V1: &str = "sw/rf/account/v1";
}

/// A position's terms: exactly the covenant's witness terms in digest
/// order, shared by the v4 and v5 kinds (v5 adds only the partial last
/// look inside the program; the terms are the same).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PositionTerms {
    pub collateral: AssetId,
    pub cash: AssetId,
    pub size: u64,
    pub buyback: u64,
    pub expiry: u32,
    pub borrower_nft: AssetId,
    pub lender_nft: AssetId,
    /// SHA-256 of the lender payout scriptPubKey (the claim script of
    /// `lender_nft` since v3).
    pub payout: [u8; 32],
    /// SHA-256 of the borrower's payout scriptPubKey (the script its
    /// position token was paid to).
    pub borrower_payout: [u8; 32],
    /// SHA-256 of the venue's last-look scriptPubKey.
    pub lastlook: [u8; 32],
    pub lastlook_height: u32,
}

fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag);
    let mut e = sha256::Hash::engine();
    e.input(t.as_ref());
    e.input(t.as_ref());
    for p in parts {
        e.input(p);
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

pub(crate) fn script_hash(script: &Script) -> [u8; 32] {
    sha256::Hash::hash(script.as_bytes()).to_byte_array()
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// The terms a contract of a pinned kind commits to. Immutable for the
/// life of the contract; the mutable slot (`remaining_debt`, `remaining`)
/// lives in [`ContractRecord::state`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind")]
pub enum ContractParams {
    /// `sw/lend/position/v5`: exactly `PositionParametersV5::witness_terms`
    /// in digest order.
    #[serde(rename = "sw/lend/position/v5")]
    LendPositionV5(PositionTerms),
    /// `sw/lend/position/v4`: the same terms under the v4 program leaf.
    #[serde(rename = "sw/lend/position/v4")]
    LendPositionV4(PositionTerms),
    /// `sw/lend/offer/v1`: `OfferParameters`.
    #[serde(rename = "sw/lend/offer/v1")]
    LendOfferV1 {
        cash: AssetId,
        lender_token: AssetId,
        claim: [u8; 32],
        fee_script: [u8; 32],
        position_leaf: [u8; 32],
        fee_min: u64,
        cutoff: u32,
        rows: Vec<OfferRowClaim>,
    },
    /// `sw/lend/claim/v1`: the claim script of a lender token, where every
    /// position, leftover and expired offer pays the lender.
    #[serde(rename = "sw/lend/claim/v1")]
    LendClaimV1 { lender_token: AssetId },
    /// `bs/channel/v5`: a BetSimply house channel; the person is its owner.
    #[serde(rename = "bs/channel/v5")]
    BsChannelV5(ChannelTerms),
    /// `sw/rf/account/v1`: a Rolling Future account; the person is its owner.
    #[serde(rename = "sw/rf/account/v1")]
    RfAccountV1(AccountTerms),
}

impl ContractParams {
    pub fn kind(&self) -> &'static str {
        match self {
            ContractParams::LendPositionV5(_) => kind::LEND_POSITION_V5,
            ContractParams::LendPositionV4(_) => kind::LEND_POSITION_V4,
            ContractParams::LendOfferV1 { .. } => kind::LEND_OFFER_V1,
            ContractParams::LendClaimV1 { .. } => kind::LEND_CLAIM_V1,
            ContractParams::BsChannelV5(_) => kind::BS_CHANNEL_V5,
            ContractParams::RfAccountV1(_) => kind::RF_ACCOUNT_V1,
        }
    }

    /// The tapleaf hash the SDK pins for this kind: the allowlist. A house
    /// channel's is its program root, pinned per house ([`bs_channel::PINS`],
    /// checked by [`ContractParams::leaf_is_pinned`]).
    pub fn leaf(&self) -> [u8; 32] {
        match self {
            ContractParams::BsChannelV5(t) => t.program_root,
            ContractParams::RfAccountV1(t) => t.program_root,
            ContractParams::LendPositionV5(_) => SWAPTION_LENDING_V5_LEAF,
            ContractParams::LendPositionV4(_) => SWAPTION_LENDING_V4_LEAF,
            ContractParams::LendOfferV1 { .. } => SWAPTION_OFFER_LEAF,
            ContractParams::LendClaimV1 { .. } => SWAPTION_CLAIM_LEAF,
        }
    }

    /// The terms of a position kind, if this is one.
    pub fn position(&self) -> Option<&PositionTerms> {
        match self {
            ContractParams::LendPositionV5(t) | ContractParams::LendPositionV4(t) => Some(t),
            _ => None,
        }
    }

    /// The canonical parameters: keys sorted, no whitespace, u64 as
    /// decimal strings, 32-byte values hex lower — the memo conventions.
    pub fn canonical_json(&self) -> String {
        let mut m: BTreeMap<&'static str, serde_json::Value> = BTreeMap::new();
        let s = |v: u64| serde_json::Value::String(v.to_string());
        let h = |v: u32| serde_json::Value::from(v);
        let a = |v: &AssetId| serde_json::Value::String(v.to_string());
        let x = |v: &[u8; 32]| serde_json::Value::String(hex32(v));
        match self {
            ContractParams::LendPositionV5(t) | ContractParams::LendPositionV4(t) => {
                m.insert("collateral", a(&t.collateral));
                m.insert("cash", a(&t.cash));
                m.insert("size", s(t.size));
                m.insert("buyback", s(t.buyback));
                m.insert("expiry", h(t.expiry));
                m.insert("borrower_nft", a(&t.borrower_nft));
                m.insert("lender_nft", a(&t.lender_nft));
                m.insert("payout", x(&t.payout));
                m.insert("borrower_payout", x(&t.borrower_payout));
                m.insert("lastlook", x(&t.lastlook));
                m.insert("lastlook_height", h(t.lastlook_height));
            }
            ContractParams::LendOfferV1 {
                cash,
                lender_token,
                claim,
                fee_script,
                position_leaf,
                fee_min,
                cutoff,
                rows,
            } => {
                m.insert("cash", a(cash));
                m.insert("lender_token", a(lender_token));
                m.insert("claim", x(claim));
                m.insert("fee_script", x(fee_script));
                m.insert("position_leaf", x(position_leaf));
                m.insert("fee_min", s(*fee_min));
                m.insert("cutoff", h(*cutoff));
                let rows_json: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|r| {
                        let mut row: BTreeMap<&'static str, serde_json::Value> = BTreeMap::new();
                        row.insert("collateral", a(&r.collateral));
                        row.insert("expiry", h(r.expiry));
                        row.insert("price_out", s(r.price_out));
                        row.insert("buyback", s(r.buyback));
                        row.insert("fee_per_unit", s(r.fee_per_unit));
                        row.insert("min_size", s(r.min_size));
                        serde_json::to_value(row).expect("a map serialises")
                    })
                    .collect();
                m.insert("rows", serde_json::Value::Array(rows_json));
            }
            ContractParams::LendClaimV1 { lender_token } => {
                m.insert("lender_token", a(lender_token));
            }
            ContractParams::BsChannelV5(t) => {
                m.insert("asset", a(&t.asset));
                m.insert("channel_id", x(&t.channel_id));
                m.insert("house_pk", x(&t.house_pk));
                m.insert("house_sink", x(&t.house_sink));
                m.insert("owner_pk", x(&t.owner_pk));
                m.insert("bet_pk", x(&t.bet_pk));
                m.insert("program_root", x(&t.program_root));
                m.insert("t_chal", h(t.t_chal));
                m.insert("t_reveal", h(t.t_reveal));
            }
            ContractParams::RfAccountV1(t) => {
                m.insert("asset", a(&t.asset));
                m.insert("index", h(t.index));
                m.insert("owner_pk", x(&t.owner_pk));
                m.insert("program_root", x(&t.program_root));
            }
        }
        serde_json::to_string(&m).expect("a map serialises")
    }

    /// `sha256` tagged `liquidconnect/contract/v1` over `kind ‖ 0x00 ‖
    /// canonical params`. Deterministic on every side.
    pub fn contract_id(&self) -> [u8; 32] {
        tagged(b"liquidconnect/contract/v1", &[self.kind().as_bytes(), &[0u8], self.canonical_json().as_bytes()])
    }

    /// The covenant scriptPubKey for these terms and a one-number `state`
    /// (remaining debt of a position, remaining cash of an offer; `None` for
    /// a claim script). A house channel's state is not one number: use
    /// [`ContractParams::script_state`].
    pub fn script(&self, state: Option<u64>) -> anyhow::Result<Script> {
        self.script_state(state.map(ContractState::Amount).as_ref())
    }

    /// The covenant scriptPubKey for these terms and `state`, whatever
    /// shape the kind gives its mutable slot.
    pub fn script_state(&self, state: Option<&ContractState>) -> anyhow::Result<Script> {
        match self {
            ContractParams::LendPositionV5(t) => {
                let debt = state.and_then(ContractState::amount).ok_or_else(|| anyhow::anyhow!("a position needs its remaining debt"))?;
                let digest = v5_terms_digest(
                    t.collateral,
                    t.cash,
                    t.size,
                    t.buyback,
                    t.expiry,
                    t.borrower_nft,
                    t.lender_nft,
                    &t.payout,
                    &t.borrower_payout,
                    &t.lastlook,
                    t.lastlook_height,
                );
                Ok(v5_position_script(&digest, debt))
            }
            ContractParams::LendPositionV4(t) => {
                let debt = state.and_then(ContractState::amount).ok_or_else(|| anyhow::anyhow!("a position needs its remaining debt"))?;
                let digest = v4_terms_digest(
                    t.collateral,
                    t.cash,
                    t.size,
                    t.buyback,
                    t.expiry,
                    t.borrower_nft,
                    t.lender_nft,
                    &t.payout,
                    &t.borrower_payout,
                    &t.lastlook,
                    t.lastlook_height,
                );
                Ok(v4_position_script(&digest, debt))
            }
            ContractParams::LendOfferV1 {
                cash,
                lender_token,
                claim,
                fee_script,
                position_leaf,
                fee_min,
                cutoff,
                rows,
            } => {
                let remaining = state.and_then(ContractState::amount).ok_or_else(|| anyhow::anyhow!("an offer needs its remaining cash"))?;
                let digest = offer_terms_digest(*cash, *lender_token, claim, fee_script, position_leaf, *fee_min, *cutoff, rows);
                Ok(offer_script(&digest, remaining))
            }
            ContractParams::LendClaimV1 { lender_token } => Ok(claim_script(*lender_token)),
            ContractParams::BsChannelV5(t) => {
                let bytes = state.and_then(ContractState::bytes).ok_or_else(|| anyhow::anyhow!("a channel needs its state"))?;
                let state = bs_channel::ChannelState::from_bytes(bytes).ok_or_else(|| anyhow::anyhow!("a channel state is {} bytes", bs_channel::STATE_LEN))?;
                Ok(bs_channel::channel_script(t, &state))
            }
            ContractParams::RfAccountV1(t) => {
                let bytes = state.and_then(ContractState::bytes).ok_or_else(|| anyhow::anyhow!("an account needs its state"))?;
                let state = rf_account::AccountState::from_bytes(bytes).ok_or_else(|| anyhow::anyhow!("not an account state"))?;
                rf_account::account_script(t, &state).ok_or_else(|| anyhow::anyhow!("the leaf is not this account's, or not in the tree the root commits to"))
            }
        }
    }

    /// Whether the kind has a mutable slot at all (a claim script has none).
    pub fn has_state(&self) -> bool {
        !matches!(self, ContractParams::LendClaimV1 { .. })
    }

    /// The wire form of the mutable slot read back strictly, per kind: the
    /// canonical decimal of a u64 for the lending kinds, the 104 lower-case
    /// hex characters of a channel's 52 state bytes. `None` for anything
    /// else, and for a kind with no slot.
    pub fn parse_state(&self, text: &str) -> Option<ContractState> {
        match self {
            ContractParams::LendClaimV1 { .. } => None,
            ContractParams::BsChannelV5(_) => bs_channel::ChannelState::from_hex(text).map(|s| ContractState::Bytes(s.to_bytes().to_vec())),
            ContractParams::RfAccountV1(_) => rf_account::AccountState::from_hex(text).map(|s| ContractState::Bytes(s.to_bytes())),
            _ => parse_u64(text).map(ContractState::Amount),
        }
    }

    /// Rule 2's pin. The lending kinds' leaf is the constant [`leaf`](Self::leaf)
    /// returns, so the leaf check is the pin. A house channel's leaf is its
    /// program root, which the spec names: it is accepted only when that
    /// root is one of [`bs_channel::PINS`] with the house parameters the
    /// root was compiled with.
    pub fn leaf_is_pinned(&self) -> bool {
        match self {
            ContractParams::BsChannelV5(t) => bs_channel::pinned(t).is_some(),
            ContractParams::RfAccountV1(t) => rf_account::pinned(t).is_some(),
            _ => true,
        }
    }

    /// The cutoff height (contract standard §1): the height from which the
    /// person's exit is open without any third party, and by which the
    /// service must have taken what the deal gives it. A claim script has
    /// none.
    pub fn cutoff(&self) -> Option<u32> {
        match self {
            ContractParams::LendPositionV5(t) | ContractParams::LendPositionV4(t) => Some(t.expiry),
            ContractParams::LendOfferV1 { cutoff, .. } => Some(*cutoff),
            ContractParams::LendClaimV1 { .. } => None,
            // Relative, not a height: T_CHAL blocks after the house's last move.
            ContractParams::BsChannelV5(_) => None,
            // Epoch end is a session, not a height; the exit is the venue's rules.
            ContractParams::RfAccountV1(_) => None,
        }
    }

    /// The lender token a lender-side record hangs on, if any.
    pub fn lender_token(&self) -> Option<AssetId> {
        match self {
            ContractParams::LendPositionV5(t) | ContractParams::LendPositionV4(t) => Some(t.lender_nft),
            ContractParams::LendOfferV1 { lender_token, .. } => Some(*lender_token),
            ContractParams::LendClaimV1 { lender_token } => Some(*lender_token),
            ContractParams::BsChannelV5(_) => None,
            ContractParams::RfAccountV1(_) => None,
        }
    }
}

/// A u64 as the canonical decimal string: digits only, no sign, no leading
/// zero but "0" itself.
pub(crate) fn parse_u64(text: &str) -> Option<u64> {
    let canonical = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0'));
    if canonical { text.parse().ok() } else { None }
}

/// The mutable slot of a record. A lending position or offer has one
/// number (remaining debt, remaining cash), kept as before; a house channel
/// has a packed byte string its kind defines ([`bs_channel::ChannelState`]).
/// On the wire a number travels as its decimal string and bytes as
/// lower-case hex ([`ContractState::wire`]); a stored record keeps the
/// number as a JSON number and the bytes as a hex string, so records
/// written before this type existed read back unchanged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ContractState {
    Amount(u64),
    Bytes(#[serde(with = "hex_vec")] Vec<u8>),
}

mod hex_vec {
    pub fn serialize<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(d)?;
        hex::decode(&text).map_err(serde::de::Error::custom)
    }
}

impl ContractState {
    pub fn amount(&self) -> Option<u64> {
        match self {
            ContractState::Amount(n) => Some(*n),
            ContractState::Bytes(_) => None,
        }
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            ContractState::Amount(_) => None,
            ContractState::Bytes(b) => Some(b),
        }
    }

    /// The wire form: a decimal u64, or lower-case hex.
    pub fn wire(&self) -> String {
        match self {
            ContractState::Amount(n) => n.to_string(),
            ContractState::Bytes(b) => hex::encode(b),
        }
    }

    /// A channel's state, if this is one.
    pub fn channel(&self) -> Option<bs_channel::ChannelState> {
        self.bytes().and_then(bs_channel::ChannelState::from_bytes)
    }

    /// A Rolling Future account's state, if this is one.
    pub fn account(&self) -> Option<rf_account::AccountState> {
        self.bytes().and_then(rf_account::AccountState::from_bytes)
    }
}

impl From<u64> for ContractState {
    fn from(n: u64) -> Self {
        ContractState::Amount(n)
    }
}

/// The wallet's side of a contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Borrower,
    Lender,
    /// A house channel's owner: the wallet whose identity key is `owner_pk`.
    Owner,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Borrower => "borrower",
            Role::Lender => "lender",
            Role::Owner => "owner",
        }
    }

    pub fn parse(text: &str) -> Option<Role> {
        match text {
            "borrower" => Some(Role::Borrower),
            "lender" => Some(Role::Lender),
            "owner" => Some(Role::Owner),
            _ => None,
        }
    }
}

/// A coin the contract's money sits in, explicit on chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContractCoin {
    pub outpoint: OutPoint,
    pub asset: AssetId,
    pub amount: u64,
}

/// Where a record stands (spec §5, the status machine).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    /// The wallet approved the transaction; the coin is not seen on chain yet.
    Pending,
    Active,
    /// Past the kind's cutoff, coin still unspent (a position awaiting its sweep).
    Expired,
    /// `path`: "exercise" | "lapse" | "last_look" | "fill" | "cancel" |
    /// "expire" | "collect" | "sold" | "unknown".
    Closed { path: String },
}

/// One transition the record went through, for the person's history.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContractEvent {
    pub txid: Txid,
    pub path: String,
    pub state_after: Option<ContractState>,
}

/// A contract the wallet is party to, as the host stores it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContractRecord {
    pub contract_id: [u8; 32],
    pub params: ContractParams,
    pub role: Role,
    /// The relying party the record came from (the connect server's word).
    pub domain: String,
    /// The mutable slot, where the kind has one.
    pub state: Option<ContractState>,
    pub coins: Vec<ContractCoin>,
    pub status: ContractStatus,
    /// Wallet-local; never sent anywhere.
    pub hidden: bool,
    pub history: Vec<ContractEvent>,
    /// When the host stored the record (unix seconds; 0 = unknown). A
    /// pending record that never confirms is closed by its age
    /// ([`ContractStore::fail_stale_pending`]): the relying party
    /// broadcasts, so an approval is not yet a transaction on chain.
    #[serde(default)]
    pub created_at: u64,
    /// When a step of the person's last changed the record (unix seconds;
    /// 0 = unknown): what two copies of a store are merged by (spec §8.3),
    /// and how long a step the store claims has had to show on chain.
    #[serde(default)]
    pub updated_at: u64,
}

/// Which stored record a transition applies to. The host keys its store
/// by `contract_id`; these are the facts a signed step exposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Select {
    /// The position whose borrower token is this asset (the token the
    /// wallet spent as owned input 0).
    PositionByBorrowerNft(AssetId),
    /// The offer whose coin was this outpoint.
    OfferByCoin(OutPoint),
    /// The claim record of this lender token.
    ClaimByToken(AssetId),
}

/// What an accepted typed fund does to the wallet's records (spec §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Derived {
    /// A record to insert. A `contract_id` the host already holds is left
    /// as it is (an offer post repeats the claim record of the same token).
    New(ContractRecord),
    /// A stored record moves: `state` and `coins` replace when `Some`;
    /// `coins_removed` leave the record's coin list; `status` replaces
    /// when `Some`. Every transition is appended to the record's history.
    Transition {
        select: Select,
        txid: Txid,
        path: String,
        state: Option<ContractState>,
        coins: Option<Vec<ContractCoin>>,
        coins_removed: Vec<OutPoint>,
        status: Option<ContractStatus>,
    },
}

/// Everything derivation needs, all of it already in the host's hands at
/// `AcceptFundRequest`.
pub struct FundContext<'a> {
    /// The claim `lending::verify_typed_fund` just passed.
    pub claim: &'a TypedFund,
    /// The funded PSET the host returns: the template plus the wallet's
    /// inputs, its change and, for a fill, the note. Its unsigned
    /// transaction fixes the txid.
    pub funded_pset_b64: &'a str,
    pub domain: &'a str,
    pub policy_asset: AssetId,
    /// Template output indexes whose scripts the host recognises as its own.
    pub mine: &'a [usize],
    /// Template inputs the host owns (its position or lender token).
    pub owned: &'a [OwnedInput],
}

fn explicit_output(pset: &elements::pset::PartiallySignedTransaction, i: usize) -> anyhow::Result<(AssetId, u64, Script)> {
    let out = pset.outputs().get(i).ok_or_else(|| anyhow::anyhow!("funded transaction has no output {i}"))?;
    match (out.asset, out.amount) {
        (Some(asset), Some(amount)) => Ok((asset, amount, out.script_pubkey.clone())),
        _ => anyhow::bail!("funded transaction output {i} is not explicit"),
    }
}

fn input_outpoint(pset: &elements::pset::PartiallySignedTransaction, i: usize) -> anyhow::Result<OutPoint> {
    let input = pset.inputs().get(i).ok_or_else(|| anyhow::anyhow!("funded transaction has no input {i}"))?;
    Ok(OutPoint::new(input.previous_txid, input.previous_output_index))
}

/// The txid the funded PSET will have once every input is signed: the
/// wallet's SIGHASH_ALL signatures fix inputs and outputs, and witnesses
/// (the RP's covenant witnesses included) do not enter the txid.
pub fn funded_txid(funded_pset_b64: &str) -> anyhow::Result<Txid> {
    let pset = decode_pset(funded_pset_b64)?;
    let tx = pset.extract_tx().map_err(|e| anyhow::anyhow!("funded PSET does not extract to a transaction: {e}"))?;
    Ok(tx.txid())
}

/// What an accepted typed fund does to the wallet's records. Run after
/// `lending::verify_typed_fund` passed and the host funded the template;
/// claims of kinds without a record (fills v1–v4, a plain send) yield an
/// empty list.
pub fn derive(ctx: &FundContext<'_>) -> anyhow::Result<Vec<Derived>> {
    let pset = decode_pset(ctx.funded_pset_b64)?;
    let txid = pset
        .extract_tx()
        .map_err(|e| anyhow::anyhow!("funded PSET does not extract to a transaction: {e}"))?
        .txid();
    let owned0 = || {
        ctx.owned
            .iter()
            .find(|o| o.index == 0)
            .ok_or_else(|| anyhow::anyhow!("the claim spends an owned input 0 that was not declared"))
    };

    let mut out = Vec::new();
    match ctx.claim {
        TypedFund::FillV4 { .. } | TypedFund::FillV5 { .. } | TypedFund::FillV6 { .. } => {
            let params = fill_params_of(ctx.claim, &pset, ctx.policy_asset)?.expect("a fill claim has a position");
            out.push(new_position(params, txid, ctx.domain));
        }
        TypedFund::Offer {
            cash,
            amounts,
            lender_token,
            claim,
            fee_script,
            position_leaf,
            fee_min,
            cutoff,
            rows,
            ..
        } => {
            let params = ContractParams::LendOfferV1 {
                cash: *cash,
                lender_token: *lender_token,
                claim: *claim,
                fee_script: *fee_script,
                position_leaf: *position_leaf,
                fee_min: *fee_min,
                cutoff: *cutoff,
                rows: rows.clone(),
            };
            // Every offer output was checked to be this covenant for its
            // amount; each coin is its own record (one coin, one contract),
            // sharing the terms and therefore the id — so with more than one
            // coin the host keeps the first insert and the later ones are
            // additional coins of the same record.
            let mut coins = Vec::new();
            for (i, amount) in amounts.iter().enumerate() {
                let (asset, value, _) = explicit_output(&pset, i)?;
                anyhow::ensure!(asset == *cash && value == *amount, "offer output {i} is not the stated coin");
                coins.push(ContractCoin {
                    outpoint: OutPoint::new(txid, i as u32),
                    asset,
                    amount: value,
                });
            }
            let state = amounts.first().copied().map(ContractState::Amount);
            out.push(Derived::New(ContractRecord {
                contract_id: params.contract_id(),
                params,
                role: Role::Lender,
                domain: ctx.domain.to_owned(),
                state: state.clone(),
                coins,
                status: ContractStatus::Pending,
                hidden: false,
                history: vec![ContractEvent {
                    txid,
                    path: "post".to_owned(),
                    state_after: state,
                }],
                created_at: 0,
                updated_at: 0,
            }));
            let claim_params = ContractParams::LendClaimV1 { lender_token: *lender_token };
            out.push(Derived::New(ContractRecord {
                contract_id: claim_params.contract_id(),
                params: claim_params,
                role: Role::Lender,
                domain: ctx.domain.to_owned(),
                state: None,
                coins: Vec::new(),
                status: ContractStatus::Active,
                hidden: false,
                history: Vec::new(),
                created_at: 0,
                updated_at: 0,
            }));
        }
        TypedFund::Exercise {
            remaining, collateral, ..
        } => {
            let token = owned0()?;
            let collateral = collateral.unwrap_or(ctx.policy_asset);
            let (coins, status) = if *remaining > 0 {
                let (asset, value, _) = explicit_output(&pset, 1)?;
                anyhow::ensure!(asset == collateral, "exercise output 1 is not the continuing position");
                (
                    vec![ContractCoin {
                        outpoint: OutPoint::new(txid, 1),
                        asset,
                        amount: value,
                    }],
                    ContractStatus::Active,
                )
            } else {
                (Vec::new(), ContractStatus::Closed { path: "exercise".to_owned() })
            };
            out.push(Derived::Transition {
                select: Select::PositionByBorrowerNft(token.asset),
                txid,
                path: "exercise".to_owned(),
                state: Some(ContractState::Amount(*remaining)),
                coins: Some(coins),
                coins_removed: Vec::new(),
                status: Some(status),
            });
        }
        TypedFund::SellRight { .. } => {
            let token = owned0()?;
            out.push(Derived::Transition {
                select: Select::PositionByBorrowerNft(token.asset),
                txid,
                path: "sold".to_owned(),
                state: None,
                coins: None,
                coins_removed: Vec::new(),
                status: Some(ContractStatus::Closed { path: "sold".to_owned() }),
            });
        }
        TypedFund::OfferCancel { .. } => {
            let _ = owned0()?;
            let offer_coin = input_outpoint(&pset, 1)?;
            out.push(Derived::Transition {
                select: Select::OfferByCoin(offer_coin),
                txid,
                path: "cancel".to_owned(),
                state: Some(ContractState::Amount(0)),
                coins: Some(Vec::new()),
                coins_removed: vec![offer_coin],
                status: Some(ContractStatus::Closed { path: "cancel".to_owned() }),
            });
        }
        TypedFund::Claim { lender_token, .. } => {
            let _ = owned0()?;
            let claim = claim_script(*lender_token);
            let collected: Vec<OutPoint> = pset
                .inputs()
                .iter()
                .filter(|input| input.witness_utxo.as_ref().map(|u| u.script_pubkey == claim).unwrap_or(false))
                .map(|input| OutPoint::new(input.previous_txid, input.previous_output_index))
                .collect();
            anyhow::ensure!(!collected.is_empty(), "collection spends no coin at the lender token's claim script");
            out.push(Derived::Transition {
                select: Select::ClaimByToken(*lender_token),
                txid,
                path: "collect".to_owned(),
                state: None,
                coins: None,
                coins_removed: collected,
                status: None,
            });
        }
        // Positions of covenant versions 1–3 have no contract kind.
        TypedFund::Fill { .. } | TypedFund::FillV2 { .. } | TypedFund::FillV3 { .. } => {}
    }
    Ok(out)
}

/// The position a fill claim creates, from the template (or the funded
/// PSET, whose first rows are the template's) — the terms from the claim,
/// the borrower token and payout from output 1, the lender token from the
/// memo (v6) or output 2 (v5). Output 0 must rebuild from them: a record is
/// only ever of a coin whose script the terms recompute. `None` for a claim
/// that creates no position.
pub fn fill_params(claim: &TypedFund, template_b64: &str, policy_asset: AssetId) -> anyhow::Result<Option<ContractParams>> {
    fill_params_of(claim, &decode_pset(template_b64)?, policy_asset)
}

fn fill_params_of(claim: &TypedFund, pset: &elements::pset::PartiallySignedTransaction, policy_asset: AssetId) -> anyhow::Result<Option<ContractParams>> {
    let lender_from_output2 = || -> anyhow::Result<AssetId> {
        let (lender_nft, one, _) = explicit_output(pset, FILL_LENDER_NFT_OUTPUT)?;
        anyhow::ensure!(one == 1, "fill output 2 is not the lender token");
        Ok(lender_nft)
    };
    let (version, size, buyback, expiry, cash, collateral, payout, lastlook, lastlook_height, lender_nft) = match claim {
        TypedFund::FillV4 {
            size,
            buyback,
            expiry,
            cash,
            collateral,
            payout,
            lastlook,
            lastlook_height,
            ..
        } => (4u8, *size, *buyback, *expiry, *cash, *collateral, payout, lastlook, *lastlook_height, lender_from_output2()?),
        TypedFund::FillV5 {
            size,
            buyback,
            expiry,
            cash,
            collateral,
            payout,
            lastlook,
            lastlook_height,
            ..
        } => (5u8, *size, *buyback, *expiry, *cash, *collateral, payout, lastlook, *lastlook_height, lender_from_output2()?),
        TypedFund::FillV6 {
            size,
            buyback,
            expiry,
            cash,
            collateral,
            payout,
            lastlook,
            lastlook_height,
            lender_nft,
            ..
        } => (5u8, *size, *buyback, *expiry, *cash, *collateral, payout, lastlook, *lastlook_height, *lender_nft),
        _ => return Ok(None),
    };
    let collateral = collateral.unwrap_or(policy_asset);
    let (asset0, value0, script0) = explicit_output(pset, FILL_POSITION_OUTPUT)?;
    anyhow::ensure!(asset0 == collateral && value0 == size, "fill output 0 is not the position coin");
    let (borrower_nft, one, borrower_script) = explicit_output(pset, FILL_BORROWER_NFT_OUTPUT)?;
    anyhow::ensure!(one == 1, "fill output 1 is not the borrower token");
    let terms = PositionTerms {
        collateral,
        cash,
        size,
        buyback,
        expiry,
        borrower_nft,
        lender_nft,
        payout: *payout,
        borrower_payout: script_hash(&borrower_script),
        lastlook: *lastlook,
        lastlook_height,
    };
    let params = if version == 4 {
        ContractParams::LendPositionV4(terms)
    } else {
        ContractParams::LendPositionV5(terms)
    };
    anyhow::ensure!(params.script(Some(buyback))? == script0, "fill output 0 is not the covenant for these terms");
    Ok(Some(params))
}

fn new_position(params: ContractParams, txid: Txid, domain: &str) -> Derived {
    let (collateral, size, buyback) = match params.position() {
        Some(t) => (t.collateral, t.size, t.buyback),
        None => unreachable!("fill_params_of returns a position"),
    };
    Derived::New(ContractRecord {
        contract_id: params.contract_id(),
        params,
        role: Role::Borrower,
        domain: domain.to_owned(),
        state: Some(ContractState::Amount(buyback)),
        coins: vec![ContractCoin {
            outpoint: OutPoint::new(txid, FILL_POSITION_OUTPUT as u32),
            asset: collateral,
            amount: size,
        }],
        status: ContractStatus::Pending,
        hidden: false,
        history: vec![ContractEvent {
            txid,
            path: "fill".to_owned(),
            state_after: Some(ContractState::Amount(buyback)),
        }],
        created_at: 0,
        updated_at: 0,
    })
}

/// The outpoint of a template's input 0: the note's nonce, which the
/// funded transaction keeps at index 0.
pub fn template_input0(template_b64: &str) -> anyhow::Result<OutPoint> {
    input_outpoint(&decode_pset(template_b64)?, 0)
}

// ---------------------------------------------------------------------------
// The store (spec §5 step 7): what the host persists and how a derivation
// lands on it. The host owns persistence; this is the bookkeeping.

/// The wallet's records, keyed for the host. Positions and claims key by
/// their contract id, which is unique by construction (a borrower token,
/// a lender token). An offer's terms may be reposted unchanged, so an
/// offer keys by its id and the coin its post created.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContractStore {
    pub records: BTreeMap<String, ContractRecord>,
}

impl ContractStore {
    pub fn key_of(record: &ContractRecord) -> String {
        let id = hex::encode(record.contract_id);
        match (&record.params, record.coins.first()) {
            // Plain `txid:vout` — elements' Display of an outpoint carries
            // an `[elements]` prefix that has no place in a key.
            (ContractParams::LendOfferV1 { .. }, Some(coin)) => format!("{id}:{}:{}", coin.outpoint.txid, coin.outpoint.vout),
            _ => id,
        }
    }

    pub fn get(&self, key: &str) -> Option<&ContractRecord> {
        self.records.get(key)
    }

    pub fn records(&self) -> impl Iterator<Item = (&String, &ContractRecord)> {
        self.records.iter()
    }

    fn matches(record: &ContractRecord, select: &Select) -> bool {
        match (select, &record.params) {
            (Select::PositionByBorrowerNft(nft), ContractParams::LendPositionV5(t) | ContractParams::LendPositionV4(t)) => {
                t.borrower_nft == *nft && record.role == Role::Borrower
            }
            (Select::OfferByCoin(outpoint), ContractParams::LendOfferV1 { .. }) => record.coins.iter().any(|c| c.outpoint == *outpoint),
            (Select::ClaimByToken(token), ContractParams::LendClaimV1 { lender_token }) => lender_token == token,
            _ => false,
        }
    }

    /// Apply what an accepted step derived; returns the keys of the records
    /// that changed. A `New` of a record already held changes nothing (an
    /// offer post repeats the claim record of the same token). `now` is
    /// the host's clock in unix seconds, stamped on a new record.
    pub fn apply(&mut self, derived: Derived, now: u64) -> Vec<String> {
        match derived {
            Derived::New(mut record) => {
                let key = Self::key_of(&record);
                if self.records.contains_key(&key) {
                    return Vec::new();
                }
                record.created_at = now;
                record.updated_at = now;
                self.records.insert(key.clone(), record);
                vec![key]
            }
            Derived::Transition {
                select,
                txid,
                path,
                state,
                coins,
                coins_removed,
                status,
            } => {
                let keys: Vec<String> = self
                    .records
                    .iter()
                    .filter(|(_, r)| Self::matches(r, &select))
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in &keys {
                    let r = self.records.get_mut(key).expect("listed above");
                    if let Some(s) = &state {
                        r.state = Some(s.clone());
                    }
                    if let Some(c) = &coins {
                        r.coins = c.clone();
                    }
                    r.coins.retain(|c| !coins_removed.contains(&c.outpoint));
                    if let Some(st) = &status {
                        r.status = st.clone();
                    }
                    r.history.push(ContractEvent {
                        txid,
                        path: path.clone(),
                        state_after: r.state.clone(),
                    });
                    r.updated_at = now;
                }
                keys
            }
        }
    }

    /// A transaction the wallet's own history shows confirmed: every
    /// pending record whose coin it created is active now. Returns the
    /// keys that changed.
    pub fn confirm_txid(&mut self, txid: &Txid) -> Vec<String> {
        let mut changed = Vec::new();
        for (key, r) in self.records.iter_mut() {
            if r.status == ContractStatus::Pending && r.coins.iter().any(|c| c.outpoint.txid == *txid) {
                r.status = ContractStatus::Active;
                changed.push(key.clone());
            }
        }
        changed
    }

    /// A pending record whose transaction never reached the chain. The
    /// relying party broadcasts, not the wallet, so an approval can die
    /// after the wallet recorded it (a mempool conflict, a venue that
    /// re-checked its half and declined): past `max_age_secs` without a
    /// confirmation the record is closed as `not_broadcast` and its coin,
    /// which never existed, is dropped. Records without a creation time
    /// are left alone.
    ///
    /// Age alone does not say a transaction is missing: a wallet that was
    /// not running when it confirmed has not seen it yet. A host calls this
    /// only when every confirmation in its history has been applied; one
    /// that learns of confirmations piecemeal asks its whole history per
    /// transaction instead ([`Self::pending_txids`],
    /// [`Self::fail_stale_pending_txid`]).
    pub fn fail_stale_pending(&mut self, now: u64, max_age_secs: u64) -> Vec<String> {
        self.fail_stale_pending_where(now, max_age_secs, |_| true)
    }

    /// [`Self::fail_stale_pending`] for the records that wait on `txid`
    /// alone: the host looked, and its complete history does not have it.
    pub fn fail_stale_pending_txid(&mut self, txid: &Txid, now: u64, max_age_secs: u64) -> Vec<String> {
        self.fail_stale_pending_where(now, max_age_secs, |r| r.coins.iter().any(|c| c.outpoint.txid == *txid))
    }

    fn fail_stale_pending_where(&mut self, now: u64, max_age_secs: u64, waits: impl Fn(&ContractRecord) -> bool) -> Vec<String> {
        let mut changed = Vec::new();
        for (key, r) in self.records.iter_mut() {
            if r.status == ContractStatus::Pending && r.created_at > 0 && now.saturating_sub(r.created_at) > max_age_secs && waits(r) {
                r.status = ContractStatus::Closed { path: "not_broadcast".to_owned() };
                r.coins.clear();
                changed.push(key.clone());
            }
        }
        changed
    }

    /// The transactions the pending records wait on, for the host to look
    /// up in its own history: confirmed there, [`Self::confirm_txid`];
    /// absent, [`Self::fail_stale_pending_txid`]; in the mempool, wait.
    pub fn pending_txids(&self) -> Vec<Txid> {
        let mut txids: Vec<Txid> = self
            .records
            .values()
            .filter(|r| r.status == ContractStatus::Pending)
            .flat_map(|r| r.coins.iter().map(|c| c.outpoint.txid))
            .collect();
        txids.sort();
        txids.dedup();
        txids
    }

    /// A record as the chain has it — found again from the seed
    /// ([`recover_position`], [`recover_claim`]) or re-read from its fill
    /// ([`ContractRecord::as_created`]), and followed to now — meets the
    /// record the store holds (spec §8.4: the chain is the truth, the store
    /// is a cache, and the wallet's own approvals run ahead of the chain by
    /// a block). Returns the keys that changed.
    ///
    /// - The store lacks it: inserted.
    /// - The store closed it as never broadcast: the chain has the
    ///   transaction after all, so the chain's record replaces it.
    /// - The chain's record knows more steps: it replaces the store's (a
    ///   venue's last look, a stale copy that was imported).
    /// - The same steps, the store still pending, the chain confirmed:
    ///   active.
    /// - The steps differ and the store's last change is older than
    ///   `settle_secs`: a step the wallet approved has had its time to show
    ///   and did not (the relying party broadcasts; a sale or a buyback can
    ///   die of a mempool conflict as a fill can), so the chain's record
    ///   replaces it — unless the chain's reading ends in `unknown`, which
    ///   never overrules a record that says more.
    /// - Otherwise the store's record stands: it is the same, or it is
    ///   ahead by a step that is still on its way.
    ///
    /// What is the person's — the site's name, the hidden flag, the day the
    /// record was made — stays through a replacement.
    pub fn restore(&mut self, mut record: ContractRecord, now: u64, settle_secs: u64) -> Vec<String> {
        let key = Self::key_of(&record);
        let Some(held) = self.records.get(&key) else {
            return self.apply(Derived::New(record), now);
        };
        let steps = |r: &ContractRecord| r.history.iter().map(|e| (e.txid, e.path.clone())).collect::<Vec<_>>();
        let never_broadcast = ContractStatus::Closed { path: "not_broadcast".to_owned() };
        let unknown = ContractStatus::Closed { path: "unknown".to_owned() };
        let same_steps = steps(held) == steps(&record);
        if same_steps && held.status == ContractStatus::Pending && record.status == ContractStatus::Active {
            let r = self.records.get_mut(&key).expect("held above");
            r.status = ContractStatus::Active;
            return vec![key];
        }
        let settled = held.updated_at > 0 && now.saturating_sub(held.updated_at) > settle_secs;
        // A reading without steps (a claim script's lookup) says nothing
        // about the steps the store recorded.
        let reads_steps = !record.history.is_empty();
        let replace = held.status == never_broadcast
            || record.history.len() > held.history.len()
            || (reads_steps && !same_steps && settled && record.status != unknown);
        if !replace {
            return Vec::new();
        }
        if record.domain.is_empty() {
            record.domain = held.domain.clone();
        }
        record.hidden = held.hidden;
        record.created_at = held.created_at;
        record.updated_at = now;
        self.records.insert(key.clone(), record);
        vec![key]
    }

    /// The borrower positions a host re-reads from the chain at a rescan,
    /// each as its fill created it ([`ContractRecord::as_created`], status
    /// pending until the host says the fill is confirmed): every live one,
    /// every one closed as never broadcast, and every one the person's own
    /// step closed within [`RESCAN_WINDOW_SECS`] — a step the wallet
    /// approved may have died before it reached the chain. The host follows
    /// each ([`follow_position`]) and hands the result to [`Self::restore`].
    pub fn rescan_candidates(&self, now: u64) -> Vec<ContractRecord> {
        let never_broadcast = ContractStatus::Closed { path: "not_broadcast".to_owned() };
        self.records
            .values()
            .filter(|r| match &r.status {
                ContractStatus::Closed { .. } if r.status != never_broadcast => {
                    r.updated_at > 0 && now.saturating_sub(r.updated_at) <= RESCAN_WINDOW_SECS
                }
                _ => true,
            })
            .filter_map(ContractRecord::as_created)
            .collect()
    }

    /// Two copies of one wallet's records become one (spec §8.3): an
    /// imported export, another install's store. A record only `other` has
    /// is taken as it is. Of a record both have, the one the person's step
    /// changed last wins (`updated_at`; without one, the longer history),
    /// and this store's copy stands on a tie. The hidden flag is this
    /// install's. A host runs its rescan afterwards: both copies may be
    /// behind the chain. Returns the keys added and the keys replaced.
    pub fn merge(&mut self, other: ContractStore) -> (Vec<String>, Vec<String>) {
        let (mut added, mut replaced) = (Vec::new(), Vec::new());
        for (_, mut theirs) in other.records {
            // The key is recomputed, never taken from the copy.
            let key = Self::key_of(&theirs);
            match self.records.get(&key) {
                None => {
                    self.records.insert(key.clone(), theirs);
                    added.push(key);
                }
                Some(ours) => {
                    let newer = match (ours.updated_at, theirs.updated_at) {
                        (0, _) | (_, 0) => theirs.history.len() > ours.history.len(),
                        (a, b) => b > a,
                    };
                    if newer {
                        theirs.hidden = ours.hidden;
                        self.records.insert(key.clone(), theirs);
                        replaced.push(key);
                    }
                }
            }
        }
        (added, replaced)
    }

    /// A record past its cutoff with its coin still unspent, as of `tip`.
    pub fn mark_expired(&mut self, tip: u32) -> Vec<String> {
        let mut changed = Vec::new();
        for (key, r) in self.records.iter_mut() {
            if r.status == ContractStatus::Active && !r.coins.is_empty() && r.params.cutoff().is_some_and(|c| c <= tip) {
                r.status = ContractStatus::Expired;
                changed.push(key.clone());
            }
        }
        changed
    }

    pub fn set_hidden(&mut self, key: &str, hidden: bool) -> bool {
        match self.records.get_mut(key) {
            Some(r) => {
                r.hidden = hidden;
                true
            }
            None => false,
        }
    }

    /// The coins at a lender token's claim script as the chain shows them
    /// now ([`claim_coins`]). Other people's transactions pay there — an
    /// exercise, a lapse, a leftover, an expire sweep — so the wallet's own
    /// approvals only ever remove coins from a claim record; a lookup is
    /// what adds them. Replaces the coin list; returns the keys that changed.
    pub fn set_claim_coins(&mut self, lender_token: AssetId, coins: Vec<ContractCoin>) -> Vec<String> {
        let mut changed = Vec::new();
        for (key, r) in self.records.iter_mut() {
            if Self::matches(r, &Select::ClaimByToken(lender_token)) && r.coins != coins {
                r.coins = coins.clone();
                changed.push(key.clone());
            }
        }
        changed
    }

    /// The lender tokens of the claim records held, for the host's lookup.
    pub fn claim_tokens(&self) -> Vec<AssetId> {
        self.records
            .values()
            .filter_map(|r| match &r.params {
                ContractParams::LendClaimV1 { lender_token } => Some(*lender_token),
                _ => None,
            })
            .collect()
    }

    /// The borrower tokens of the position records held: one-unit assets
    /// the host need not look up as lender tokens.
    pub fn borrower_tokens(&self) -> Vec<AssetId> {
        self.records
            .values()
            .filter(|r| r.role == Role::Borrower)
            .filter_map(|r| r.params.position().map(|t| t.borrower_nft))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The note (spec §6.4)

/// The note's length: one tag byte and a 78-byte body, under Elements'
/// 80-byte OP_RETURN relay limit.
pub const NOTE_LEN: usize = 79;
/// Tag of a `sw/lend/position/v5` note.
pub const NOTE_TAG_POSITION_V5: u8 = 0x01;
/// Tag of a `sw/lend/position/v4` note: the same body under the v4 leaf.
pub const NOTE_TAG_POSITION_V4: u8 = 0x02;

/// BIP43 purpose index of the note key's derivation path: 0x4C4E, ASCII
/// "LN". The full path is `m/19534'/<network>'/0'` with network 0'
/// Liquid, 1' Liquid testnet, 2' regtest — the venue key's scheme
/// (`venue::VENUE_KEY_PURPOSE`) under its own purpose, so the two keys
/// never coincide.
pub const NOTE_KEY_PURPOSE: u32 = 0x4C4E;

/// `m/19534'/<network>'/<index>'` from the wallet seed (the BIP39 seed
/// bytes): index 0 the note key, index 1 the export key.
fn contracts_secret(seed: &[u8], network: Network, index: u32) -> anyhow::Result<[u8; 32]> {
    let secp = Secp256k1::signing_only();
    // NetworkKind only selects xprv serialization bytes, which never
    // leave this function; network separation is the path's job.
    let master = Xpriv::new_master(NetworkKind::Main, seed)?;
    let path = [
        ChildNumber::from_hardened_idx(NOTE_KEY_PURPOSE).expect("fits 31 bits"),
        ChildNumber::from_hardened_idx(network_index(network)).expect("fits 31 bits"),
        ChildNumber::from_hardened_idx(index).expect("fits 31 bits"),
    ];
    let child = master.derive_priv(&secp, &path)?;
    Ok(child.private_key.secret_bytes())
}

fn network_index(network: Network) -> u32 {
    match network {
        Network::Liquid => 0,
        Network::LiquidTestnet => 1,
        Network::Regtest => 2,
    }
}

/// The key the note is sealed under: a 32-byte secret derived from the
/// SEED on a dedicated hardened path (spend tier), never from the master
/// blinding key, which travels inside the descriptor to the connect server
/// and to any watch-only service. Derivable again after a restore.
#[derive(Clone)]
pub struct NoteKey([u8; 32]);

impl NoteKey {
    /// The production derivation: BIP32 from the wallet seed (the BIP39
    /// seed bytes), hardened path `m/19534'/<network>'/0'`.
    pub fn from_seed(seed: &[u8], network: Network) -> anyhow::Result<NoteKey> {
        Ok(NoteKey(contracts_secret(seed, network, 0)?))
    }

    /// A key from a secret the host derived itself (tests, hosts with
    /// their own derivation scheme). The secret must be spend-tier and
    /// derivable again after a restore.
    pub fn from_secret(secret: [u8; 32]) -> NoteKey {
        NoteKey(secret)
    }

    /// SHA-256 in counter mode under the note tag over `key ‖ nonce ‖
    /// counter`; the nonce is the outpoint of the transaction's input 0,
    /// unique per transaction and known before signing and after a restore.
    fn keystream(&self, nonce: &OutPoint, len: usize) -> Vec<u8> {
        let mut stream = Vec::with_capacity(len + 32);
        let mut counter = 0u8;
        while stream.len() < len {
            let block = tagged(
                b"liquidconnect/contract-note/v1",
                &[&self.0, &nonce.txid.to_byte_array(), &nonce.vout.to_be_bytes(), &[counter]],
            );
            stream.extend_from_slice(&block);
            counter += 1;
        }
        stream.truncate(len);
        stream
    }
}

impl std::fmt::Debug for NoteKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoteKey(..)")
    }
}

fn u24(v: u32) -> anyhow::Result<[u8; 3]> {
    anyhow::ensure!(v < (1 << 24), "height {v} does not fit 24 bits");
    let b = v.to_be_bytes();
    Ok([b[1], b[2], b[3]])
}

fn from_u24(b: &[u8]) -> u32 {
    u32::from_be_bytes([0, b[0], b[1], b[2]])
}

/// The plaintext note of a position: what the wallet's own rows of the fill
/// do not already show. Everything else comes back from the transaction
/// itself at recovery ([`recover_fill`]).
///
///     tag (1) ‖ buyback u64 BE (8) ‖ expiry u24 BE (3) ‖ lastlook_height u24 BE (3)
///     ‖ lastlook (32) ‖ lender_nft (32)
pub fn position_note(params: &ContractParams) -> anyhow::Result<[u8; NOTE_LEN]> {
    let (tag, t) = match params {
        ContractParams::LendPositionV5(t) => (NOTE_TAG_POSITION_V5, t),
        ContractParams::LendPositionV4(t) => (NOTE_TAG_POSITION_V4, t),
        _ => anyhow::bail!("only a position has a note"),
    };
    let mut note = [0u8; NOTE_LEN];
    note[0] = tag;
    note[1..9].copy_from_slice(&t.buyback.to_be_bytes());
    note[9..12].copy_from_slice(&u24(t.expiry)?);
    note[12..15].copy_from_slice(&u24(t.lastlook_height)?);
    note[15..47].copy_from_slice(&t.lastlook);
    note[47..79].copy_from_slice(&t.lender_nft.into_inner().0);
    Ok(note)
}

/// Seal (or open — XOR is its own inverse) a note under `key` for the
/// transaction whose input 0 is `input0`.
pub fn seal_note(key: &NoteKey, input0: &OutPoint, note: &[u8; NOTE_LEN]) -> [u8; NOTE_LEN] {
    let stream = key.keystream(input0, NOTE_LEN);
    let mut out = [0u8; NOTE_LEN];
    for i in 0..NOTE_LEN {
        out[i] = note[i] ^ stream[i];
    }
    out
}

/// `OP_RETURN OP_PUSHDATA1 79 <79 bytes>` (82 script bytes, inside the
/// 83-byte relay limit) — the output the host appends after the template's
/// rows and its own change, value 0 in the policy asset (fund-template rule
/// 3a).
pub fn note_script(sealed: &[u8; NOTE_LEN]) -> Script {
    elements::script::Builder::new()
        .push_opcode(elements::opcodes::all::OP_RETURN)
        .push_slice(sealed)
        .into_script()
}

/// The note the host appends to a fill it is funding: the sealed bytes for
/// the position the claim creates, or `None` for a claim without a note.
/// `input0` is the template's input 0 (the dealer's cash coin or the offer
/// coin), which the funded transaction keeps at index 0.
pub fn note_for_fill(key: &NoteKey, params: &ContractParams, input0: &OutPoint) -> anyhow::Result<Option<[u8; NOTE_LEN]>> {
    if params.position().is_none() {
        return Ok(None);
    }
    Ok(Some(seal_note(key, input0, &position_note(params)?)))
}

/// The note as a PSET output the host appends to the template before it
/// funds: explicit, value 0 in the policy asset, the OP_RETURN script.
pub fn note_output(sealed: &[u8; NOTE_LEN], policy_asset: AssetId) -> elements::pset::Output {
    use elements::confidential::{Asset, Nonce, Value};
    let mut out = elements::pset::Output::from_txout(elements::TxOut {
        asset: Asset::Explicit(policy_asset),
        value: Value::Explicit(0),
        nonce: Nonce::Null,
        script_pubkey: note_script(sealed),
        witness: elements::TxOutWitness::default(),
    });
    out.amount = Some(0);
    out
}

/// The position a fill of this wallet's created, recovered from the
/// transaction alone: the note (opened under `key` with input 0 as the
/// nonce) supplies what the wallet's rows do not show, the rows supply the
/// rest, and the position script is recomputed and compared with output 0.
/// `cash` is the asset of the proceeds output the wallet unblinded from its
/// own records. `None` when the transaction carries no note of this
/// wallet's, when a key or nonce is wrong, or when the note lies — the
/// script match is the integrity check.
pub fn recover_fill(key: &NoteKey, tx: &elements::Transaction, cash: AssetId) -> Option<(ContractParams, ContractCoin)> {
    use elements::confidential::{Asset, Value};
    let input0 = tx.input.first()?.previous_output;
    let sealed: &[u8] = tx
        .output
        .iter()
        .rev()
        .find_map(|o| op_return_payload(&o.script_pubkey).filter(|p| p.len() == NOTE_LEN))?;
    let mut sealed_arr = [0u8; NOTE_LEN];
    sealed_arr.copy_from_slice(sealed);
    let note = seal_note(key, &input0, &sealed_arr);
    let tag = note[0];
    if tag != NOTE_TAG_POSITION_V5 && tag != NOTE_TAG_POSITION_V4 {
        return None;
    }
    let buyback = u64::from_be_bytes(note[1..9].try_into().ok()?);
    let expiry = from_u24(&note[9..12]);
    let lastlook_height = from_u24(&note[12..15]);
    let mut lastlook = [0u8; 32];
    lastlook.copy_from_slice(&note[15..47]);
    let lender_nft = AssetId::from_slice(&note[47..79]).ok()?;

    let out0 = tx.output.get(FILL_POSITION_OUTPUT)?;
    let out1 = tx.output.get(FILL_BORROWER_NFT_OUTPUT)?;
    let (collateral, size) = match (out0.asset, out0.value) {
        (Asset::Explicit(a), Value::Explicit(v)) => (a, v),
        _ => return None,
    };
    let borrower_nft = match (out1.asset, out1.value) {
        (Asset::Explicit(a), Value::Explicit(1)) => a,
        _ => return None,
    };
    let payout = script_hash(&claim_script(lender_nft));
    let terms = PositionTerms {
        collateral,
        cash,
        size,
        buyback,
        expiry,
        borrower_nft,
        lender_nft,
        payout,
        borrower_payout: script_hash(&out1.script_pubkey),
        lastlook,
        lastlook_height,
    };
    let params = if tag == NOTE_TAG_POSITION_V4 {
        ContractParams::LendPositionV4(terms)
    } else {
        ContractParams::LendPositionV5(terms)
    };
    if params.script(Some(buyback)).ok()? != out0.script_pubkey {
        return None;
    }
    Some((
        params,
        ContractCoin {
            outpoint: OutPoint::new(tx.txid(), FILL_POSITION_OUTPUT as u32),
            asset: collateral,
            amount: size,
        },
    ))
}

// ---------------------------------------------------------------------------
// Reconstruction from the seed and the chain alone (spec §8.1 steps 1–3,
// and step 4 for what the wallet's own history shows). A seed restore
// recovers every transaction the wallet's scripts took part in; this is
// what the host runs over them, with no relying party and no store.

/// True when `tx` has an output shaped like a note: an OP_RETURN carrying
/// exactly [`NOTE_LEN`] bytes. A cheap filter for a walk over a long
/// history; only [`recover_fill`] says whether the note is this wallet's.
pub fn carries_note(tx: &elements::Transaction) -> bool {
    tx.output
        .iter()
        .any(|o| op_return_payload(&o.script_pubkey).is_some_and(|p| p.len() == NOTE_LEN))
}

/// One of the wallet's own transactions, as a rescan from the seed yields it.
pub struct OwnTx<'a> {
    pub tx: &'a elements::Transaction,
    /// In a block; `false` while it waits in the mempool.
    pub confirmed: bool,
    /// The assets of the outputs of `tx` the wallet unblinded as its own.
    /// One of them is the cash the fill paid out, which the note does not
    /// repeat; a wrong one rebuilds no script, so every one is tried.
    pub own_assets: &'a [AssetId],
}

/// Spec §8.1 step 2: the borrower position one of the wallet's own
/// transactions created, as the record stood at creation — the same record
/// [`derive`] made at approval, so a wallet that still has it finds nothing
/// new. `None` for anything that is not a fill carrying this wallet's note.
/// `domain` is empty after a restore from the chain alone: the note has no
/// room for it, and a relying party's registration names it later.
pub fn recover_position(key: &NoteKey, own: &OwnTx<'_>, domain: &str) -> Option<ContractRecord> {
    if !carries_note(own.tx) {
        return None;
    }
    let (params, coin) = own.own_assets.iter().find_map(|cash| recover_fill(key, own.tx, *cash))?;
    let buyback = params.position()?.buyback;
    let txid = own.tx.txid();
    Some(ContractRecord {
        contract_id: params.contract_id(),
        params,
        role: Role::Borrower,
        domain: domain.to_owned(),
        state: Some(ContractState::Amount(buyback)),
        coins: vec![coin],
        status: if own.confirmed { ContractStatus::Active } else { ContractStatus::Pending },
        hidden: false,
        history: vec![ContractEvent {
            txid,
            path: "fill".to_owned(),
            state_after: Some(ContractState::Amount(buyback)),
        }],
        created_at: 0,
        updated_at: 0,
    })
}

/// How long after the person's own step closed a position a rescan still
/// re-reads it from the chain ([`ContractStore::rescan_candidates`]).
pub const RESCAN_WINDOW_SECS: u64 = 7 * 86_400;

impl ContractRecord {
    /// A borrower position as its fill created it — the full debt, the coin
    /// at the fill's output 0, one event — for a host that re-reads the
    /// chain from there ([`follow_position`]). The status is pending until
    /// the host says the fill is confirmed. `None` for any other record:
    /// an offer and a claim have no such beginning to return to.
    pub fn as_created(&self) -> Option<ContractRecord> {
        if self.role != Role::Borrower {
            return None;
        }
        let t = self.params.position()?;
        let fill = self.history.first().filter(|e| e.path == "fill")?;
        Some(ContractRecord {
            state: Some(ContractState::Amount(t.buyback)),
            coins: vec![ContractCoin {
                outpoint: OutPoint::new(fill.txid, FILL_POSITION_OUTPUT as u32),
                asset: t.collateral,
                amount: t.size,
            }],
            status: ContractStatus::Pending,
            history: vec![fill.clone()],
            ..self.clone()
        })
    }

    /// The transaction that created the record, where it has one.
    pub fn created_by(&self) -> Option<Txid> {
        self.history.first().map(|e| e.txid)
    }
}

/// The wallet's own history as the follow step reads it.
pub trait OwnHistory {
    /// The wallet's own transaction that spends `outpoint`, if there is one.
    fn spender(&self, outpoint: &OutPoint) -> Option<elements::Transaction>;
}

/// No position takes this many steps; the bound only stops a history that
/// answers in circles.
const MAX_FOLLOW_STEPS: usize = 256;

pub(crate) fn explicit_txout(out: &elements::TxOut) -> Option<(AssetId, u64)> {
    use elements::confidential::{Asset, Value};
    match (out.asset, out.value) {
        (Asset::Explicit(a), Value::Explicit(v)) => Some((a, v)),
        _ => None,
    }
}

/// Explicit `asset` that `tx` pays to `script`, summed.
fn paid_to(tx: &elements::Transaction, script: &Script, asset: AssetId) -> u64 {
    tx.output
        .iter()
        .filter(|o| o.script_pubkey == *script)
        .filter_map(explicit_txout)
        .filter(|(a, _)| *a == asset)
        .fold(0u64, |sum, (_, v)| sum.saturating_add(v))
}

fn close_record(record: &mut ContractRecord, txid: Txid, path: &str, coin_spent: bool, state: Option<u64>) {
    if coin_spent {
        record.coins.clear();
    }
    if state.is_some() {
        record.state = state.map(ContractState::Amount);
    }
    record.status = ContractStatus::Closed { path: path.to_owned() };
    record.history.push(ContractEvent {
        txid,
        path: path.to_owned(),
        state_after: record.state.clone(),
    });
}

/// Spec §8.1 step 4, as far as the wallet's own history reaches: bring a
/// recovered borrower position from its creation to now. Every step the
/// wallet signed is in its history — a buyback spends its token and the
/// position together, a sale spends the token alone — and so is a venue's
/// last look, which pays the borrower's share to a script of the wallet's.
/// Each step is read from explicit amounts at the lender's claim script
/// and checked by recomputing the continuing script (the follow rules of
/// §6.3, no witness parsing). A lapse pays the borrower nothing, so it is in
/// the history only of a wallet that is the lender as well; otherwise the
/// record stays open here and expires by height.
///
/// `false` when this is not a record the rules can read (not a borrower's
/// position, or one whose lender is not paid at the claim script of its
/// token): the record is untouched, and "could not follow" must not be
/// taken for "nothing happened".
pub fn follow_position(record: &mut ContractRecord, history: &dyn OwnHistory) -> bool {
    if record.role != Role::Borrower {
        return false;
    }
    let Some(t) = record.params.position().cloned() else {
        return false;
    };
    let Some(fill) = record.history.first().map(|e| e.txid) else {
        return false;
    };
    // Every position since v3 pays the claim script of its lender token;
    // without that there is no script to read a payment at.
    let claim = claim_script(t.lender_nft);
    if script_hash(&claim) != t.payout {
        return false;
    }
    let mut token_at = Some(OutPoint::new(fill, FILL_BORROWER_NFT_OUTPUT as u32));
    for _ in 0..MAX_FOLLOW_STEPS {
        if matches!(record.status, ContractStatus::Closed { .. }) {
            break;
        }
        let Some(coin) = record.coins.first().map(|c| c.outpoint) else {
            break;
        };
        let debt = record.state.as_ref().and_then(ContractState::amount).unwrap_or(t.buyback);
        let (tx, with_token) = match token_at.and_then(|at| history.spender(&at)) {
            Some(tx) => (tx, true),
            None => match history.spender(&coin) {
                Some(tx) => (tx, false),
                None => break,
            },
        };
        let txid = tx.txid();
        let spends_coin = tx.input.iter().any(|i| i.previous_output == coin);
        if with_token && !spends_coin {
            // The token left without the position: the right was sold (or
            // given away). The coin lives on; this wallet's part is over.
            close_record(record, txid, "sold", false, None);
            break;
        }
        let cash_paid = paid_to(&tx, &claim, t.cash);
        if !with_token && cash_paid == 0 && paid_to(&tx, &claim, t.collateral) > 0 {
            close_record(record, txid, "lapse", true, None);
            break;
        }
        let path = if with_token { "exercise" } else { "last_look" };
        let remaining = match debt.checked_sub(cash_paid) {
            Some(remaining) if cash_paid > 0 => remaining,
            _ => {
                close_record(record, txid, "unknown", true, None);
                break;
            }
        };
        if remaining == 0 {
            close_record(record, txid, path, true, Some(0));
            break;
        }
        let next = record.params.script(Some(remaining)).ok().and_then(|script| {
            tx.output.iter().enumerate().find_map(|(vout, o)| {
                let (asset, amount) = explicit_txout(o)?;
                (o.script_pubkey == script && asset == t.collateral).then(|| ContractCoin {
                    outpoint: OutPoint::new(txid, vout as u32),
                    asset,
                    amount,
                })
            })
        });
        let Some(next) = next else {
            close_record(record, txid, "unknown", true, None);
            break;
        };
        record.coins = vec![next];
        record.state = Some(ContractState::Amount(remaining));
        record.history.push(ContractEvent {
            txid,
            path: path.to_owned(),
            state_after: Some(ContractState::Amount(remaining)),
        });
        if with_token {
            token_at = tx.output.iter().enumerate().find_map(|(vout, o)| {
                let (asset, amount) = explicit_txout(o)?;
                (asset == t.borrower_nft && amount == 1 && op_return_payload(&o.script_pubkey).is_none())
                    .then(|| OutPoint::new(txid, vout as u32))
            });
        }
    }
    true
}

/// Spec §8.1 step 3: the coins waiting at a lender token's claim script,
/// from the script's whole history as the chain backend returns it (every
/// transaction that paid the script or spent from it, mempool included).
/// Explicit coins only. The script is a pure function of the token, so
/// this needs nothing but the asset id the seed finds in the wallet.
pub fn claim_coins(lender_token: AssetId, history: &[elements::Transaction]) -> Vec<ContractCoin> {
    let script = claim_script(lender_token);
    let spent: std::collections::BTreeSet<(Txid, u32)> = history
        .iter()
        .flat_map(|tx| tx.input.iter().map(|i| (i.previous_output.txid, i.previous_output.vout)))
        .collect();
    let mut coins: BTreeMap<(Txid, u32), ContractCoin> = BTreeMap::new();
    for tx in history {
        let txid = tx.txid();
        for (vout, out) in tx.output.iter().enumerate() {
            if out.script_pubkey != script || spent.contains(&(txid, vout as u32)) {
                continue;
            }
            if let Some((asset, amount)) = explicit_txout(out) {
                coins.insert(
                    (txid, vout as u32),
                    ContractCoin {
                        outpoint: OutPoint::new(txid, vout as u32),
                        asset,
                        amount,
                    },
                );
            }
        }
    }
    coins.into_values().collect()
}

/// The claim record of a one-unit asset the restored wallet holds, from
/// the history of its claim script. `None` when nothing ever paid that
/// script: a borrower token has no such history, and a lender token that
/// nothing has paid yet has nothing to collect — the next lookup finds it.
pub fn recover_claim(lender_token: AssetId, history: &[elements::Transaction], domain: &str) -> Option<ContractRecord> {
    let script = claim_script(lender_token);
    if !history.iter().any(|tx| tx.output.iter().any(|o| o.script_pubkey == script)) {
        return None;
    }
    let params = ContractParams::LendClaimV1 { lender_token };
    Some(ContractRecord {
        contract_id: params.contract_id(),
        params,
        role: Role::Lender,
        domain: domain.to_owned(),
        state: None,
        coins: claim_coins(lender_token, history),
        status: ContractStatus::Active,
        hidden: false,
        history: Vec::new(),
        created_at: 0,
        updated_at: 0,
    })
}

// ---------------------------------------------------------------------------
// The export (spec §8.3, §11.4): the wallet's records as one line of text
// the person keeps — a file, a paste, a QR when it is small — which depends
// on nobody. It carries what the chain does not say: an open offer's rows,
// the site each record came from, hidden flags, history, and every record
// of a wallet that writes no notes. Opened with the seed it is also what a
// command-line tool needs to build a buyback or a collection.

/// First field of an export: the format and its version.
pub const EXPORT_PREFIX: &str = "LCPOS1";

/// The key an export is sealed under: seed-derived on the note key's
/// purpose, index 1 (`m/19534'/<network>'/1'`). Spend tier for the note's
/// reason: the master blinding key travels inside the descriptor to the
/// connect server and to any watch-only service, and a file sealed under a
/// key derived from it would be theirs to read. A hardware wallet has no
/// seed in software and therefore no export yet.
#[derive(Clone)]
pub struct ExportKey([u8; 32]);

impl ExportKey {
    pub fn from_seed(seed: &[u8], network: Network) -> anyhow::Result<ExportKey> {
        Ok(ExportKey(contracts_secret(seed, network, 1)?))
    }

    /// A key from a secret the host derived itself (tests, hosts with
    /// their own derivation scheme): spend tier, derivable after a restore.
    pub fn from_secret(secret: [u8; 32]) -> ExportKey {
        ExportKey(secret)
    }
}

impl std::fmt::Debug for ExportKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExportKey(..)")
    }
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Liquid => "liquid",
        Network::LiquidTestnet => "liquidtestnet",
        Network::Regtest => "regtest",
    }
}

/// Why an import was refused, in words a host can show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// Not an export at all, or of a version this SDK does not read.
    NotAnExport,
    /// An export of another network's wallet.
    WrongNetwork { found: String },
    /// Sealed under another seed, or altered since it was written.
    WrongWallet,
    /// Opened, but what is inside is not a store of records.
    Corrupt(String),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::NotAnExport => f.write_str("this is not a Liquid Connect positions export"),
            ImportError::WrongNetwork { found } => write!(f, "this export is from a {found} wallet"),
            ImportError::WrongWallet => f.write_str("this export belongs to another wallet, or it was altered"),
            ImportError::Corrupt(what) => write!(f, "this export cannot be read: {what}"),
        }
    }
}

impl std::error::Error for ImportError {}

#[derive(serde::Serialize, serde::Deserialize)]
struct ExportBody {
    exported_at: u64,
    store: ContractStore,
}

/// The store as an export: `LCPOS1.<network>.<base64url>`, the payload a
/// random 12-byte nonce followed by the ChaCha20-Poly1305 ciphertext of the
/// store's JSON, with the first two fields as associated data — so a file
/// cannot be relabelled for another network or version. One line, no
/// padding, safe to paste.
pub fn export_store(store: &ContractStore, key: &ExportKey, network: Network, now: u64) -> anyhow::Result<String> {
    use base64::Engine as _;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let header = format!("{EXPORT_PREFIX}.{}", network_name(network));
    let body = serde_json::to_vec(&ExportBody {
        exported_at: now,
        store: store.clone(),
    })?;
    let nonce: [u8; 12] = rand::random();
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key.0));
    let sealed = cipher
        .encrypt(
            chacha20poly1305::Nonce::from_slice(&nonce),
            Payload {
                msg: &body,
                aad: header.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("sealing the export failed"))?;
    let mut payload = nonce.to_vec();
    payload.extend_from_slice(&sealed);
    Ok(format!("{header}.{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)))
}

/// An export opened with this wallet's key: the records as they were
/// written and when. Every record is checked to be what its id says before
/// it is returned; the host merges it ([`ContractStore::merge`]) and runs
/// its rescan, because the copy may be behind the chain.
pub fn import_store(text: &str, key: &ExportKey, network: Network) -> Result<(ContractStore, u64), ImportError> {
    use base64::Engine as _;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let mut fields = text.splitn(3, '.');
    let (Some(prefix), Some(found), Some(payload)) = (fields.next(), fields.next(), fields.next()) else {
        return Err(ImportError::NotAnExport);
    };
    if prefix != EXPORT_PREFIX {
        return Err(ImportError::NotAnExport);
    }
    if found != network_name(network) {
        return Err(ImportError::WrongNetwork { found: found.to_owned() });
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| ImportError::NotAnExport)?;
    if payload.len() < 12 + 16 {
        return Err(ImportError::NotAnExport);
    }
    let (nonce, sealed) = payload.split_at(12);
    let header = format!("{prefix}.{found}");
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key.0));
    let body = cipher
        .decrypt(
            chacha20poly1305::Nonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: header.as_bytes(),
            },
        )
        .map_err(|_| ImportError::WrongWallet)?;
    let body: ExportBody = serde_json::from_slice(&body).map_err(|e| ImportError::Corrupt(e.to_string()))?;
    for record in body.store.records.values() {
        if record.contract_id != record.params.contract_id() {
            return Err(ImportError::Corrupt("a record is not the contract its id names".to_owned()));
        }
    }
    Ok((body.store, body.exported_at))
}

// ---------------------------------------------------------------------------
// Rendering (spec §6.1)

impl ContractStatus {
    pub fn render(&self) -> String {
        match self {
            ContractStatus::Pending => "awaiting confirmation".to_owned(),
            ContractStatus::Active => "active".to_owned(),
            ContractStatus::Expired => "expired, awaiting the sweep".to_owned(),
            ContractStatus::Closed { path } => match path.as_str() {
                "exercise" => "bought back".to_owned(),
                "lapse" => "lapsed to the lender".to_owned(),
                "last_look" => "exercised for you by the venue".to_owned(),
                "sold" => "right sold".to_owned(),
                "cancel" => "withdrawn".to_owned(),
                "expire" => "returned to your claim".to_owned(),
                "fill" => "filled".to_owned(),
                "collect" => "collected".to_owned(),
                "not_broadcast" => "never reached the chain".to_owned(),
                "close" => "closed with the house".to_owned(),
                "settle" => "settled on chain".to_owned(),
                other => format!("closed ({other})"),
            },
        }
    }
}

impl ContractRecord {
    /// The person-facing line, from verified terms only: the terms with
    /// the cutoff, then the status.
    pub fn render(&self, collateral_symbol: &str, cash_symbol: &str) -> String {
        format!("{} · {}", self.render_terms(collateral_symbol, cash_symbol), self.status.render())
    }

    /// The terms alone, for a host that shows the status in a place of its
    /// own (the hub card printed it twice, 2026-09-17).
    pub fn render_terms(&self, collateral_symbol: &str, cash_symbol: &str) -> String {
        match (&self.params, self.role) {
            (ContractParams::LendPositionV5(t) | ContractParams::LendPositionV4(t), Role::Borrower) => {
                let owed = self.state.as_ref().and_then(ContractState::amount).unwrap_or(t.buyback);
                let owed_text = if owed == t.buyback {
                    format!("buy back for {} {cash_symbol}", fmt8(t.buyback))
                } else {
                    format!("{} {cash_symbol} still owed", fmt8(owed))
                };
                let last_look = if t.lastlook_height > 0 {
                    format!(" · from block {} the venue may exercise for you", t.lastlook_height)
                } else {
                    String::new()
                };
                format!(
                    "Sold {} {collateral_symbol} · {owed_text} until block {expiry}{last_look} · from block {expiry} the collateral goes to the lender",
                    fmt8(t.size),
                    expiry = t.expiry
                )
            }
            (ContractParams::LendPositionV5(t) | ContractParams::LendPositionV4(t), _) => {
                let owed = self.state.as_ref().and_then(ContractState::amount).unwrap_or(t.buyback);
                format!(
                    "Bought {} {collateral_symbol} · the borrower may buy it back for {} {cash_symbol} until block {expiry} · from block {expiry} the collateral is yours",
                    fmt8(t.size),
                    fmt8(owed),
                    expiry = t.expiry
                )
            }
            (ContractParams::LendOfferV1 { rows, cutoff, .. }, _) => {
                let remaining: u64 = self.coins.iter().map(|c| c.amount).sum();
                let rows_text: Vec<String> = rows
                    .iter()
                    .map(|r| {
                        format!(
                            "pay up to {} {cash_symbol} per {collateral_symbol} with buyback at {} {cash_symbol} until block {}",
                            fmt8(r.price_out),
                            fmt8(r.buyback),
                            r.expiry
                        )
                    })
                    .collect();
                format!(
                    "Lend offer on chain: {} {cash_symbol} remaining · {} · withdraw any time · after block {cutoff} it returns to your claim",
                    fmt8(remaining),
                    rows_text.join("; ")
                )
            }
            (ContractParams::LendClaimV1 { .. }, _) => {
                let n = self.coins.len();
                format!(
                    "What your lending paid: {n} coin{} waiting · collect with your lender token",
                    if n == 1 { "" } else { "s" }
                )
            }
            (ContractParams::BsChannelV5(t), _) => {
                // `cash_symbol` is the channel's one asset. Liquid makes a
                // block a minute, so T_CHAL blocks is about T_CHAL minutes.
                let house = bs_channel::pinned(t).map(|pin| pin.house).unwrap_or("House");
                let balance = self.state.as_ref().and_then(ContractState::channel).map(|s| s.player_bal).unwrap_or(0);
                format!(
                    "{house} account · {} {cash_symbol} · yours to withdraw once the house has been silent for {t_chal} block{} (≈ {t_chal} min)",
                    fmt8(balance),
                    if t.t_chal == 1 { "" } else { "s" },
                    t_chal = t.t_chal
                )
            }
            (ContractParams::RfAccountV1(t), _) => {
                // `cash_symbol` is the pool's asset, `collateral_symbol` the contract's unit.
                let venue = rf_account::pinned(t).map(|pin| pin.venue).unwrap_or("Venue");
                let account = self.state.as_ref().and_then(ContractState::account);
                let (cash, position, session) = account.as_ref().map(|s| (s.leaf.cash, s.leaf.position(), s.session)).unwrap_or((0, 0, 0));
                let position_text = if position < 0 { format!("-{}", fmt8(position.unsigned_abs())) } else { fmt8(position as u64) };
                format!(
                    "{venue} account · {} {cash_symbol} cash · position {position_text} {collateral_symbol} · session {session} · shown from the chain; the exit is the venue's rules",
                    fmt8(cash)
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::confidential::{Asset, Value};
    use elements::pset;
    use elements::{AssetId, Script, TxOut, TxOutWitness};
    use std::str::FromStr;

    const LBTC: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
    const USDT: &str = "b612eb46313a2cd6ebabd8b7a8eed5696e29898b87a43bff41c94f51acef9d73";
    const NFT: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const LENDER_TOKEN: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    fn asset(s: &str) -> AssetId {
        AssetId::from_str(s).unwrap()
    }
    fn txout(asset_hex: &str, value: u64, script: Script) -> TxOut {
        TxOut {
            asset: Asset::Explicit(asset(asset_hex)),
            value: Value::Explicit(value),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: script,
            witness: TxOutWitness::default(),
        }
    }
    fn spk(tag: u8) -> Script {
        Script::from(vec![0x51, 0x20].into_iter().chain([tag; 32]).collect::<Vec<u8>>())
    }
    fn b64(tx: &pset::PartiallySignedTransaction) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(elements::encode::serialize(tx))
    }
    fn input(txid_byte: u8, vout: u32, utxo: TxOut) -> pset::Input {
        let mut i = pset::Input::from_prevout(OutPoint::new(elements::Txid::from_str(&format!("{txid_byte:02x}").repeat(32)).unwrap(), vout));
        i.witness_utxo = Some(utxo);
        i
    }
    fn key() -> NoteKey {
        NoteKey::from_secret([7u8; 32])
    }

    fn payout_of(token: &str) -> [u8; 32] {
        script_hash(&claim_script(asset(token)))
    }

    fn v6_claim(payout: &[u8; 32], lastlook: &[u8; 32]) -> TypedFund {
        TypedFund::FillV6 {
            size: 2_000_000,
            sale: 1_200_00000000,
            buyback: 1_242_00000000,
            expiry: 2_600_984,
            cash: asset(USDT),
            collateral: Some(asset(LBTC)),
            fee: 3_00000000,
            payout: *payout,
            lastlook: *lastlook,
            lastlook_height: 2_600_484,
            lender_nft: asset(LENDER_TOKEN),
        }
    }

    /// A funded v6 fill: the template (offer coin, borrower token from the
    /// pool, venue fee coin; position, token to the wallet, continuation,
    /// venue fee, proceeds to the wallet, venue change, fee) plus the
    /// wallet's collateral input, its change and the note.
    fn funded_v6_fill(payout: &[u8; 32], lastlook: &[u8; 32], note: Option<[u8; NOTE_LEN]>) -> pset::PartiallySignedTransaction {
        let borrower_hash = script_hash(&spk(0x01));
        let digest = v5_terms_digest(
            asset(LBTC),
            asset(USDT),
            2_000_000,
            1_242_00000000,
            2_600_984,
            asset(NFT),
            asset(LENDER_TOKEN),
            payout,
            &borrower_hash,
            lastlook,
            2_600_484,
        );
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        tx.add_input(input(0x41, 0, txout(USDT, 25_000_00000000, spk(0xcc)))); // 0 the offer coin
        tx.add_input(input(0x42, 0, txout(NFT, 1, spk(0xaa)))); // 1 borrower token from the pool
        tx.add_input(input(0x43, 0, txout(LBTC, 100_000, spk(0xab)))); // 2 venue fee coin
        tx.add_input(input(0x44, 3, txout(LBTC, 2_500_000, spk(0x01)))); // 3 the wallet's collateral
        tx.add_output(pset::Output::from_txout(txout(LBTC, 2_000_000, v5_position_script(&digest, 1_242_00000000)))); // 0 position
        tx.add_output(pset::Output::from_txout(txout(NFT, 1, spk(0x01)))); // 1 borrower token → mine
        tx.add_output(pset::Output::from_txout(txout(USDT, 25_000_00000000 - 1_203_00000000, spk(0xcd)))); // 2 the offer continues
        tx.add_output(pset::Output::from_txout(txout(USDT, 6_00000000, spk(0xfe)))); // 3 venue fee
        tx.add_output(pset::Output::from_txout(txout(USDT, 1_197_00000000, spk(0x01)))); // 4 proceeds → mine
        tx.add_output(pset::Output::from_txout(txout(LBTC, 100_000 - 450, spk(0xab)))); // 5 venue change
        tx.add_output(pset::Output::from_txout(txout(LBTC, 450, Script::new()))); // 6 fee
        tx.add_output(pset::Output::from_txout(txout(LBTC, 500_000, spk(0x01)))); // 7 the wallet's change
        if let Some(note) = note {
            let mut o = pset::Output::from_txout(txout(LBTC, 0, note_script(&note)));
            o.amount = Some(0);
            tx.add_output(o); // 8 the note
        }
        tx
    }

    fn position_terms(payout: &[u8; 32], lastlook: &[u8; 32]) -> PositionTerms {
        PositionTerms {
            collateral: asset(LBTC),
            cash: asset(USDT),
            size: 2_000_000,
            buyback: 1_242_00000000,
            expiry: 2_600_984,
            borrower_nft: asset(NFT),
            lender_nft: asset(LENDER_TOKEN),
            payout: *payout,
            borrower_payout: script_hash(&spk(0x01)),
            lastlook: *lastlook,
            lastlook_height: 2_600_484,
        }
    }

    fn position_params(payout: &[u8; 32], lastlook: &[u8; 32]) -> ContractParams {
        ContractParams::LendPositionV5(position_terms(payout, lastlook))
    }

    /// A funded v4 fill as a desk fills it on the paper server today:
    /// the same rows as v6, but the lender token at output 2 and the v4
    /// program at output 0.
    fn funded_v4_fill(payout: &[u8; 32], lastlook: &[u8; 32], note: Option<[u8; NOTE_LEN]>) -> pset::PartiallySignedTransaction {
        let borrower_hash = script_hash(&spk(0x01));
        let digest = v4_terms_digest(
            asset(LBTC),
            asset(USDT),
            2_000_000,
            1_242_00000000,
            2_600_984,
            asset(NFT),
            asset(LENDER_TOKEN),
            payout,
            &borrower_hash,
            lastlook,
            2_600_484,
        );
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        tx.add_input(input(0x31, 0, txout(USDT, 1_500_00000000, spk(0xaa)))); // 0 the desk's cash
        tx.add_input(input(0x32, 0, txout(LBTC, 100_000, spk(0xab)))); // 1 venue fee coin
        tx.add_input(input(0x33, 1, txout(LBTC, 2_500_000, spk(0x01)))); // 2 the wallet's collateral
        tx.add_output(pset::Output::from_txout(txout(LBTC, 2_000_000, v4_position_script(&digest, 1_242_00000000)))); // 0 position
        tx.add_output(pset::Output::from_txout(txout(NFT, 1, spk(0x01)))); // 1 borrower token → mine
        tx.add_output(pset::Output::from_txout(txout(LENDER_TOKEN, 1, spk(0xaa)))); // 2 lender token → desk
        tx.add_output(pset::Output::from_txout(txout(USDT, 1_197_00000000, spk(0x01)))); // 3 proceeds → mine
        tx.add_output(pset::Output::from_txout(txout(USDT, 3_00000000, spk(0xfe)))); // 4 venue fee
        tx.add_output(pset::Output::from_txout(txout(USDT, 300_00000000, spk(0xaa)))); // 5 desk change
        tx.add_output(pset::Output::from_txout(txout(LBTC, 100_000 - 450, spk(0xab)))); // 6 venue change
        tx.add_output(pset::Output::from_txout(txout(LBTC, 450, Script::new()))); // 7 fee
        tx.add_output(pset::Output::from_txout(txout(LBTC, 500_000, spk(0x01)))); // 8 the wallet's change
        if let Some(note) = note {
            let mut o = pset::Output::from_txout(txout(LBTC, 0, note_script(&note)));
            o.amount = Some(0);
            tx.add_output(o); // 9 the note
        }
        tx
    }

    #[test]
    fn a_v4_fill_yields_a_v4_position_whose_note_recovers_under_its_own_leaf() {
        let lastlook = [11u8; 32];
        let payout = payout_of(LENDER_TOKEN);
        let claim = TypedFund::FillV4 {
            size: 2_000_000,
            sale: 1_200_00000000,
            buyback: 1_242_00000000,
            expiry: 2_600_984,
            cash: asset(USDT),
            collateral: Some(asset(LBTC)),
            fee: 3_00000000,
            payout,
            lastlook,
            lastlook_height: 2_600_484,
        };
        let template = funded_v4_fill(&payout, &lastlook, None);
        let params = fill_params(&claim, &b64(&template), asset(LBTC)).unwrap().unwrap();
        assert_eq!(params, ContractParams::LendPositionV4(position_terms(&payout, &lastlook)));
        assert_eq!(params.kind(), kind::LEND_POSITION_V4);
        assert_eq!(params.leaf(), SWAPTION_LENDING_V4_LEAF);
        assert_ne!(params.contract_id(), position_params(&payout, &lastlook).contract_id(), "v4 and v5 ids differ by kind");
        assert_eq!(hex::encode(params.script(Some(1_242_00000000)).unwrap().as_bytes()), hex::encode(template.outputs()[0].script_pubkey.as_bytes()));

        let input0 = template_input0(&b64(&template)).unwrap();
        let sealed = note_for_fill(&key(), &params, &input0).unwrap().unwrap();
        assert_eq!(seal_note(&key(), &input0, &sealed)[0], NOTE_TAG_POSITION_V4);
        let funded = funded_v4_fill(&payout, &lastlook, Some(sealed));
        let derived = derive(&FundContext {
            claim: &claim,
            funded_pset_b64: &b64(&funded),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[1, 3, 8],
            owned: &[],
        })
        .unwrap();
        let Derived::New(record) = &derived[0] else { panic!() };
        assert_eq!(record.params, params);
        assert_eq!(record.role, Role::Borrower);
        let tx = funded.extract_tx().unwrap();
        let (recovered, coin) = recover_fill(&key(), &tx, asset(USDT)).expect("the v4 note recovers the position");
        assert_eq!(recovered, params);
        assert_eq!(coin.outpoint, OutPoint::new(tx.txid(), 0));
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains(r#""kind":"sw/lend/position/v4""#), "{json}");
        let back: ContractRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *record);
    }

    #[test]
    fn canonical_json_sorts_keys_and_the_id_binds_kind_and_params() {
        let lastlook = [11u8; 32];
        let payout = payout_of(LENDER_TOKEN);
        let p = position_params(&payout, &lastlook);
        let json = p.canonical_json();
        assert!(json.starts_with(r#"{"borrower_nft":"#), "{json}");
        assert!(!json.contains(' '));
        let id = p.contract_id();
        assert_eq!(id, position_params(&payout, &lastlook).contract_id());
        let mut other = position_params(&payout, &lastlook);
        if let ContractParams::LendPositionV5(t) = &mut other {
            t.buyback += 1;
        }
        assert_ne!(id, other.contract_id());
        let claim = ContractParams::LendClaimV1 { lender_token: asset(LENDER_TOKEN) };
        assert_ne!(id, claim.contract_id());
        assert_eq!(claim.canonical_json(), format!(r#"{{"lender_token":"{LENDER_TOKEN}"}}"#));
        assert_eq!(p.cutoff(), Some(2_600_984));
        assert_eq!(claim.cutoff(), None);
    }

    #[test]
    fn a_funded_v6_fill_yields_a_pending_borrower_position() {
        let lastlook = [11u8; 32];
        let payout = payout_of(LENDER_TOKEN);
        let claim = v6_claim(&payout, &lastlook);
        let funded = funded_v6_fill(&payout, &lastlook, None);
        let derived = derive(&FundContext {
            claim: &claim,
            funded_pset_b64: &b64(&funded),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[1, 4, 7],
            owned: &[],
        })
        .unwrap();
        assert_eq!(derived.len(), 1);
        let Derived::New(record) = &derived[0] else { panic!("expected a new record") };
        assert_eq!(record.params, position_params(&payout, &lastlook));
        assert_eq!(record.role, Role::Borrower);
        assert_eq!(record.state, Some(ContractState::Amount(1_242_00000000)));
        assert_eq!(record.status, ContractStatus::Pending);
        let txid = funded.extract_tx().unwrap().txid();
        assert_eq!(record.coins, vec![ContractCoin { outpoint: OutPoint::new(txid, 0), asset: asset(LBTC), amount: 2_000_000 }]);
        assert_eq!(record.contract_id, position_params(&payout, &lastlook).contract_id());
        let line = record.render("BTC", "USDt");
        assert!(line.starts_with("Sold 0.02 BTC · buy back for 1242 USDt until block 2600984"), "{line}");
        assert!(line.contains("from block 2600484 the venue may exercise for you"), "{line}");
        assert!(line.ends_with("awaiting confirmation"), "{line}");

        // A claim whose lender token is not the one the payout names: the
        // funded output 0 no longer rebuilds, so no record.
        let mut lying = claim.clone();
        if let TypedFund::FillV6 { lender_nft, .. } = &mut lying {
            *lender_nft = asset(NFT);
        }
        let err = derive(&FundContext {
            claim: &lying,
            funded_pset_b64: &b64(&funded),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[1, 4, 7],
            owned: &[],
        })
        .unwrap_err();
        assert!(err.to_string().contains("not the covenant"), "{err}");
    }

    #[test]
    fn the_note_round_trips_and_recovers_the_position_from_the_transaction_alone() {
        let lastlook = [11u8; 32];
        let payout = payout_of(LENDER_TOKEN);
        let params = position_params(&payout, &lastlook);
        let template_input0 = OutPoint::new(elements::Txid::from_str(&"41".repeat(32)).unwrap(), 0);
        let sealed = note_for_fill(&key(), &params, &template_input0).unwrap().unwrap();
        assert_eq!(seal_note(&key(), &template_input0, &sealed), position_note(&params).unwrap());
        // OP_RETURN, OP_PUSHDATA1, the length, 79 bytes: 82 of the 83 the relay allows.
        assert_eq!(note_script(&sealed).as_bytes().len(), 3 + NOTE_LEN);
        assert_eq!(op_return_payload(&note_script(&sealed)), Some(&sealed[..]));
        assert!(note_for_fill(&key(), &ContractParams::LendClaimV1 { lender_token: asset(LENDER_TOKEN) }, &template_input0).unwrap().is_none());

        let funded = funded_v6_fill(&payout, &lastlook, Some(sealed));
        let tx = funded.extract_tx().unwrap();
        let (recovered, coin) = recover_fill(&key(), &tx, asset(USDT)).expect("the note recovers the position");
        assert_eq!(recovered, params);
        assert_eq!(coin, ContractCoin { outpoint: OutPoint::new(tx.txid(), 0), asset: asset(LBTC), amount: 2_000_000 });

        // A wrong key, a wrong cash asset, or no note: nothing, never a wrong record.
        assert!(recover_fill(&NoteKey::from_secret([8u8; 32]), &tx, asset(USDT)).is_none());
        assert!(recover_fill(&key(), &tx, asset(LBTC)).is_none());
        let bare = funded_v6_fill(&payout, &lastlook, None).extract_tx().unwrap();
        assert!(recover_fill(&key(), &bare, asset(USDT)).is_none());
        // A note sealed for another transaction (another input 0) does not open here.
        let other_input0 = OutPoint::new(elements::Txid::from_str(&"41".repeat(32)).unwrap(), 1);
        let wrong_nonce = note_for_fill(&key(), &params, &other_input0).unwrap().unwrap();
        let moved = funded_v6_fill(&payout, &lastlook, Some(wrong_nonce)).extract_tx().unwrap();
        assert!(recover_fill(&key(), &moved, asset(USDT)).is_none());
    }

    fn funded_exercise(remaining: u64) -> pset::PartiallySignedTransaction {
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        tx.add_input(input(0x51, 1, txout(NFT, 1, spk(0x01)))); // 0 the wallet's position token
        tx.add_input(input(0x52, 0, txout(LBTC, 2_000_000, spk(0xc0)))); // 1 the position
        tx.add_input(input(0x53, 0, txout(USDT, 700_00000000, spk(0x01)))); // 2 the wallet's cash
        if remaining > 0 {
            tx.add_output(pset::Output::from_txout(txout(NFT, 1, spk(0x01)))); // 0 token back
            tx.add_output(pset::Output::from_txout(txout(LBTC, 1_000_000, spk(0xc1)))); // 1 continuing position
        } else {
            let mut burn = pset::Output::from_txout(txout(NFT, 0, Script::from(vec![0x6a])));
            burn.amount = Some(0);
            tx.add_output(burn); // 0 token burned
            tx.add_output(pset::Output::from_txout(txout(LBTC, 0, spk(0xc1)))); // 1 nothing continues
        }
        tx.add_output(pset::Output::from_txout(txout(USDT, 621_00000000, spk(0xcc)))); // 2 cash to the lender's claim
        tx.add_output(pset::Output::from_txout(txout(LBTC, 1_000_000, spk(0x01)))); // 3 released collateral → mine
        tx.add_output(pset::Output::from_txout(txout(USDT, 79_00000000, spk(0x01)))); // 4 change
        tx.add_output(pset::Output::from_txout(txout(LBTC, 300, Script::new()))); // 5 fee
        tx
    }

    #[test]
    fn an_exercise_moves_the_position_and_a_full_buyback_closes_it() {
        let owned = [OwnedInput { index: 0, asset: asset(NFT), amount: 1 }];
        let partial = TypedFund::Exercise {
            amount: 621_00000000,
            released: 1_000_000,
            remaining: 621_00000000,
            cash: asset(USDT),
            collateral: Some(asset(LBTC)),
        };
        let funded = funded_exercise(621_00000000);
        let derived = derive(&FundContext {
            claim: &partial,
            funded_pset_b64: &b64(&funded),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[0, 3, 4],
            owned: &owned,
        })
        .unwrap();
        let txid = funded.extract_tx().unwrap().txid();
        assert_eq!(
            derived,
            vec![Derived::Transition {
                select: Select::PositionByBorrowerNft(asset(NFT)),
                txid,
                path: "exercise".to_owned(),
                state: Some(ContractState::Amount(621_00000000)),
                coins: Some(vec![ContractCoin { outpoint: OutPoint::new(txid, 1), asset: asset(LBTC), amount: 1_000_000 }]),
                coins_removed: vec![],
                status: Some(ContractStatus::Active),
            }]
        );

        let full = TypedFund::Exercise {
            amount: 621_00000000,
            released: 1_000_000,
            remaining: 0,
            cash: asset(USDT),
            collateral: Some(asset(LBTC)),
        };
        let funded = funded_exercise(0);
        let derived = derive(&FundContext {
            claim: &full,
            funded_pset_b64: &b64(&funded),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[3, 4],
            owned: &owned,
        })
        .unwrap();
        let Derived::Transition { state, coins, status, .. } = &derived[0] else { panic!("expected a transition") };
        assert_eq!(*state, Some(ContractState::Amount(0)));
        assert_eq!(*coins, Some(vec![]));
        assert_eq!(*status, Some(ContractStatus::Closed { path: "exercise".to_owned() }));

        // Without the owned token the claim cannot name its position.
        assert!(derive(&FundContext {
            claim: &full,
            funded_pset_b64: &b64(&funded),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[3, 4],
            owned: &[],
        })
        .is_err());
    }

    #[test]
    fn an_offer_post_yields_the_offer_and_the_claim_records() {
        let rows = vec![OfferRowClaim {
            collateral: asset(LBTC),
            expiry: 3_200_000,
            price_out: 3_00000000,
            buyback: 4_00000000,
            fee_per_unit: 2_000_000,
            min_size: 1_000,
        }];
        let claim_hash = payout_of(LENDER_TOKEN);
        let digest = offer_terms_digest(asset(USDT), asset(LENDER_TOKEN), &claim_hash, &[12u8; 32], &SWAPTION_LENDING_V5_LEAF, 50, 3_199_000, &rows);
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        tx.add_input(input(0x61, 0, txout(LENDER_TOKEN, 1, spk(0xaa)))); // 0 the token from the pool
        tx.add_input(input(0x62, 0, txout(LBTC, 5_000, spk(0xab)))); // 1 venue fee coin
        tx.add_input(input(0x63, 0, txout(USDT, 30_000_00000000, spk(0x01)))); // 2 the wallet's cash
        tx.add_output(pset::Output::from_txout(txout(USDT, 25_000_00000000, offer_script(&digest, 25_000_00000000)))); // 0 the offer
        tx.add_output(pset::Output::from_txout(txout(LENDER_TOKEN, 1, spk(0x01)))); // 1 the token → mine
        tx.add_output(pset::Output::from_txout(txout(LBTC, 5_000 - 300, spk(0xab)))); // 2 venue change
        tx.add_output(pset::Output::from_txout(txout(LBTC, 300, Script::new()))); // 3 fee
        tx.add_output(pset::Output::from_txout(txout(USDT, 5_000_00000000, spk(0x01)))); // 4 the wallet's change
        let claim = TypedFund::Offer {
            cash: asset(USDT),
            amounts: vec![25_000_00000000],
            lender_token: asset(LENDER_TOKEN),
            claim: claim_hash,
            fee_script: [12u8; 32],
            position_leaf: SWAPTION_LENDING_V5_LEAF,
            fee_min: 50,
            cutoff: 3_199_000,
            rows: rows.clone(),
            token_output: Some(1),
        };
        let derived = derive(&FundContext {
            claim: &claim,
            funded_pset_b64: &b64(&tx),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[1, 4],
            owned: &[],
        })
        .unwrap();
        assert_eq!(derived.len(), 2);
        let txid = tx.extract_tx().unwrap().txid();
        let Derived::New(offer) = &derived[0] else { panic!() };
        assert_eq!(offer.params.kind(), kind::LEND_OFFER_V1);
        assert_eq!(offer.role, Role::Lender);
        assert_eq!(offer.state, Some(ContractState::Amount(25_000_00000000)));
        assert_eq!(offer.coins, vec![ContractCoin { outpoint: OutPoint::new(txid, 0), asset: asset(USDT), amount: 25_000_00000000 }]);
        assert_eq!(offer.params.script(Some(25_000_00000000)).unwrap(), offer_script(&digest, 25_000_00000000));
        assert_eq!(offer.params.cutoff(), Some(3_199_000));
        let line = offer.render("BTC", "USDt");
        assert!(line.starts_with("Lend offer on chain: 25000 USDt remaining"), "{line}");
        assert!(line.contains("after block 3199000 it returns to your claim"), "{line}");
        let Derived::New(claim_record) = &derived[1] else { panic!() };
        assert_eq!(claim_record.params, ContractParams::LendClaimV1 { lender_token: asset(LENDER_TOKEN) });
        assert_eq!(claim_record.params.script(None).unwrap(), claim_script(asset(LENDER_TOKEN)));
        assert_eq!(claim_record.status, ContractStatus::Active);
        assert!(claim_record.coins.is_empty());
        assert_eq!(claim_record.render("BTC", "USDt"), "What your lending paid: 0 coins waiting · collect with your lender token · active");
    }

    #[test]
    fn a_cancel_closes_the_offer_a_collection_removes_claim_coins_and_a_sale_closes_the_borrower_side() {
        let owned = [OwnedInput { index: 0, asset: asset(LENDER_TOKEN), amount: 1 }];
        let mut cancel = pset::PartiallySignedTransaction::new_v2();
        cancel.add_input(input(0x71, 1, txout(LENDER_TOKEN, 1, spk(0x01)))); // 0 the token
        cancel.add_input(input(0x72, 2, txout(USDT, 16_000_00000000, spk(0xcc)))); // 1 the offer coin
        cancel.add_input(input(0x73, 0, txout(LBTC, 1_000, spk(0x01)))); // 2 the wallet's fee input
        cancel.add_output(pset::Output::from_txout(txout(LENDER_TOKEN, 1, spk(0x01))));
        cancel.add_output(pset::Output::from_txout(txout(USDT, 16_000_00000000, spk(0x01))));
        cancel.add_output(pset::Output::from_txout(txout(LBTC, 230, Script::new())));
        cancel.add_output(pset::Output::from_txout(txout(LBTC, 770, spk(0x01))));
        let claim = TypedFund::OfferCancel {
            cash: asset(USDT),
            amount: 16_000_00000000,
            fee: 230,
            lender_token: asset(LENDER_TOKEN),
        };
        let derived = derive(&FundContext {
            claim: &claim,
            funded_pset_b64: &b64(&cancel),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[0, 1, 3],
            owned: &owned,
        })
        .unwrap();
        let offer_coin = OutPoint::new(elements::Txid::from_str(&"72".repeat(32)).unwrap(), 2);
        let Derived::Transition { select, status, coins_removed, .. } = &derived[0] else { panic!() };
        assert_eq!(*select, Select::OfferByCoin(offer_coin));
        assert_eq!(*coins_removed, vec![offer_coin]);
        assert_eq!(*status, Some(ContractStatus::Closed { path: "cancel".to_owned() }));

        let claim_spk = claim_script(asset(LENDER_TOKEN));
        let mut collect = pset::PartiallySignedTransaction::new_v2();
        collect.add_input(input(0x81, 0, txout(LENDER_TOKEN, 1, spk(0x01)))); // 0 the token
        collect.add_input(input(0x82, 0, txout(USDT, 12_000_00000000, claim_spk.clone()))); // 1 a claim coin
        collect.add_input(input(0x83, 0, txout(LBTC, 2_000_000, claim_spk.clone()))); // 2 a claim coin
        collect.add_input(input(0x84, 0, txout(LBTC, 1_000, spk(0x01)))); // 3 the wallet's fee input
        collect.add_output(pset::Output::from_txout(txout(LENDER_TOKEN, 1, spk(0x01))));
        collect.add_output(pset::Output::from_txout(txout(USDT, 12_000_00000000, spk(0x01))));
        collect.add_output(pset::Output::from_txout(txout(LBTC, 2_000_000 + 670, spk(0x01))));
        collect.add_output(pset::Output::from_txout(txout(LBTC, 330, Script::new())));
        let claim = TypedFund::Claim {
            lender_token: asset(LENDER_TOKEN),
            fee: 330,
            receives: vec![(asset(USDT), 12_000_00000000), (asset(LBTC), 2_000_000)],
        };
        let derived = derive(&FundContext {
            claim: &claim,
            funded_pset_b64: &b64(&collect),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[0, 1, 2],
            owned: &owned,
        })
        .unwrap();
        let Derived::Transition { select, coins_removed, status, .. } = &derived[0] else { panic!() };
        assert_eq!(*select, Select::ClaimByToken(asset(LENDER_TOKEN)));
        assert_eq!(
            *coins_removed,
            vec![
                OutPoint::new(elements::Txid::from_str(&"82".repeat(32)).unwrap(), 0),
                OutPoint::new(elements::Txid::from_str(&"83".repeat(32)).unwrap(), 0)
            ]
        );
        assert_eq!(*status, None);

        let owned_nft = [OwnedInput { index: 0, asset: asset(NFT), amount: 1 }];
        let mut sale = pset::PartiallySignedTransaction::new_v2();
        sale.add_input(input(0x91, 1, txout(NFT, 1, spk(0x01)))); // 0 the position token
        sale.add_input(input(0x92, 0, txout(USDT, 50_00000000, spk(0xaa)))); // 1 dealer cash
        sale.add_input(input(0x93, 0, txout(LBTC, 1_000, spk(0x01)))); // 2 the wallet's fee input
        sale.add_output(pset::Output::from_txout(txout(NFT, 1, spk(0xaa))));
        sale.add_output(pset::Output::from_txout(txout(USDT, 50_00000000, spk(0x01))));
        sale.add_output(pset::Output::from_txout(txout(LBTC, 250, Script::new())));
        sale.add_output(pset::Output::from_txout(txout(LBTC, 750, spk(0x01))));
        let claim = TypedFund::SellRight {
            price: 50_00000000,
            cash: asset(USDT),
            fee: 250,
        };
        let derived = derive(&FundContext {
            claim: &claim,
            funded_pset_b64: &b64(&sale),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[1, 3],
            owned: &owned_nft,
        })
        .unwrap();
        let Derived::Transition { select, status, state, coins, .. } = &derived[0] else { panic!() };
        assert_eq!(*select, Select::PositionByBorrowerNft(asset(NFT)));
        assert_eq!(*status, Some(ContractStatus::Closed { path: "sold".to_owned() }));
        assert_eq!(*state, None);
        assert_eq!(*coins, None);
    }

    #[test]
    fn the_store_applies_derivations_confirmations_and_expiry() {
        let lastlook = [11u8; 32];
        let payout = payout_of(LENDER_TOKEN);
        let claim = v6_claim(&payout, &lastlook);
        let funded = funded_v6_fill(&payout, &lastlook, None);
        let fill_txid = funded.extract_tx().unwrap().txid();
        let ctx = FundContext {
            claim: &claim,
            funded_pset_b64: &b64(&funded),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[1, 4, 7],
            owned: &[],
        };
        let mut store = ContractStore::default();
        let derived = derive(&ctx).unwrap();
        let keys = store.apply(derived[0].clone(), 1_000);
        assert_eq!(keys.len(), 1);
        let key = keys[0].clone();
        assert_eq!(key, hex::encode(position_params(&payout, &lastlook).contract_id()));
        assert_eq!(store.get(&key).unwrap().created_at, 1_000);
        // The same derivation again changes nothing.
        assert!(store.apply(derived[0].clone(), 2_000).is_empty());
        assert_eq!(store.get(&key).unwrap().status, ContractStatus::Pending);
        // Young and pending: left alone. (Its staleness is tested below.)
        assert!(store.fail_stale_pending(1_000 + 3_600, 3_600).is_empty());
        // The fill confirms in the wallet's history.
        assert_eq!(store.confirm_txid(&fill_txid), vec![key.clone()]);
        assert_eq!(store.get(&key).unwrap().status, ContractStatus::Active);
        assert!(store.confirm_txid(&fill_txid).is_empty());

        // A partial buyback moves the position; the record's own token names it.
        let owned = [OwnedInput { index: 0, asset: asset(NFT), amount: 1 }];
        let partial = TypedFund::Exercise {
            amount: 621_00000000,
            released: 1_000_000,
            remaining: 621_00000000,
            cash: asset(USDT),
            collateral: Some(asset(LBTC)),
        };
        let exercise = funded_exercise(621_00000000);
        let exercise_txid = exercise.extract_tx().unwrap().txid();
        let derived = derive(&FundContext {
            claim: &partial,
            funded_pset_b64: &b64(&exercise),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[0, 3, 4],
            owned: &owned,
        })
        .unwrap();
        assert_eq!(store.apply(derived[0].clone(), 3_000), vec![key.clone()]);
        let r = store.get(&key).unwrap();
        assert_eq!(r.state, Some(ContractState::Amount(621_00000000)));
        assert_eq!(r.coins, vec![ContractCoin { outpoint: OutPoint::new(exercise_txid, 1), asset: asset(LBTC), amount: 1_000_000 }]);
        assert_eq!(r.history.len(), 2);
        assert_eq!(r.history[1].path, "exercise");
        assert!(r.render("BTC", "USDt").contains("621 USDt still owed"), "{}", r.render("BTC", "USDt"));

        // Past its cutoff with the coin unspent: expired, awaiting the sweep.
        assert!(store.mark_expired(2_600_983).is_empty());
        assert_eq!(store.mark_expired(2_600_984), vec![key.clone()]);
        assert_eq!(store.get(&key).unwrap().status, ContractStatus::Expired);
        assert!(store.set_hidden(&key, true));
        assert!(store.get(&key).unwrap().hidden);
        assert!(!store.set_hidden("nope", true));

        // A record survives a JSON round trip, as the host persists it.
        let json = serde_json::to_string(&store).unwrap();
        assert!(json.contains(r#""kind":"sw/lend/position/v5""#), "{json}");
        let back: ContractStore = serde_json::from_str(&json).unwrap();
        assert_eq!(back, store);
        // A store written before `created_at` existed still parses.
        let old = json.replace(r#""created_at":1000"#, r#""created_at":0"#).replace(r#","created_at":0"#, "");
        let parsed: ContractStore = serde_json::from_str(&old).unwrap();
        assert_eq!(parsed.get(&key).unwrap().created_at, 0);
    }

    /// The relying party broadcasts: an approved fill whose transaction
    /// never reaches the chain (Scott's second fill of 2026-09-17 died of
    /// `txn-mempool-conflict`) must not stay "awaiting confirmation".
    #[test]
    fn a_pending_record_that_never_confirms_is_closed_by_its_age() {
        let lastlook = [11u8; 32];
        let payout = payout_of(LENDER_TOKEN);
        let claim = v6_claim(&payout, &lastlook);
        let funded = funded_v6_fill(&payout, &lastlook, None);
        let derived = derive(&FundContext {
            claim: &claim,
            funded_pset_b64: &b64(&funded),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[1, 4, 7],
            owned: &[],
        })
        .unwrap();
        let mut store = ContractStore::default();
        let key = store.apply(derived[0].clone(), 10_000).remove(0);
        assert!(store.fail_stale_pending(10_000 + 3_600, 3_600).is_empty());
        assert_eq!(store.fail_stale_pending(10_000 + 3_601, 3_600), vec![key.clone()]);
        let r = store.get(&key).unwrap();
        assert_eq!(r.status, ContractStatus::Closed { path: "not_broadcast".to_owned() });
        assert!(r.coins.is_empty());
        assert!(r.render("BTC", "USDt").ends_with("never reached the chain"), "{}", r.render("BTC", "USDt"));
        // Closed stays closed; a confirmation of that txid later changes nothing.
        assert!(store.fail_stale_pending(99_999, 3_600).is_empty());
        assert!(store.confirm_txid(&funded.extract_tx().unwrap().txid()).is_empty());
        // A confirmed record is never failed by age.
        let mut live = ContractStore::default();
        let key = live.apply(derived[0].clone(), 10_000).remove(0);
        live.confirm_txid(&funded.extract_tx().unwrap().txid());
        assert!(live.fail_stale_pending(10_000 + 86_400, 3_600).is_empty());
        assert_eq!(live.get(&key).unwrap().status, ContractStatus::Active);
    }

    #[test]
    fn offer_records_key_by_their_post_coin_and_claim_records_by_their_token() {
        let claim = ContractParams::LendClaimV1 { lender_token: asset(LENDER_TOKEN) };
        let record = |params: ContractParams, coins: Vec<ContractCoin>| ContractRecord {
            contract_id: params.contract_id(),
            params,
            role: Role::Lender,
            domain: "paper.swaption.io".to_owned(),
            state: None,
            coins,
            status: ContractStatus::Active,
            hidden: false,
            history: Vec::new(),
            created_at: 0,
            updated_at: 0,
        };
        let mut store = ContractStore::default();
        assert_eq!(store.apply(Derived::New(record(claim.clone(), vec![])), 1).len(), 1);
        assert!(store.apply(Derived::New(record(claim.clone(), vec![])), 2).is_empty());

        let rows = vec![OfferRowClaim {
            collateral: asset(LBTC),
            expiry: 3_200_000,
            price_out: 3_00000000,
            buyback: 4_00000000,
            fee_per_unit: 2_000_000,
            min_size: 1_000,
        }];
        let offer = ContractParams::LendOfferV1 {
            cash: asset(USDT),
            lender_token: asset(LENDER_TOKEN),
            claim: payout_of(LENDER_TOKEN),
            fee_script: [12u8; 32],
            position_leaf: SWAPTION_LENDING_V5_LEAF,
            fee_min: 50,
            cutoff: 3_199_000,
            rows,
        };
        let coin = |b: u8| ContractCoin {
            outpoint: OutPoint::new(elements::Txid::from_str(&format!("{b:02x}").repeat(32)).unwrap(), 0),
            asset: asset(USDT),
            amount: 25_000_00000000,
        };
        // Two posts with the same terms are two records.
        let k1 = store.apply(Derived::New(record(offer.clone(), vec![coin(0xa1)])), 3);
        let k2 = store.apply(Derived::New(record(offer.clone(), vec![coin(0xa2)])), 4);
        assert_eq!(k1.len(), 1);
        assert_eq!(k2.len(), 1);
        assert_ne!(k1, k2);
        assert!(k1[0].starts_with(&hex::encode(offer.contract_id())));
        // A cancel names its coin and closes that record alone.
        let cancel_txid = elements::Txid::from_str(&"b1".repeat(32)).unwrap();
        let changed = store.apply(Derived::Transition {
            select: Select::OfferByCoin(coin(0xa2).outpoint),
            txid: cancel_txid,
            path: "cancel".to_owned(),
            state: Some(ContractState::Amount(0)),
            coins: Some(vec![]),
            coins_removed: vec![coin(0xa2).outpoint],
            status: Some(ContractStatus::Closed { path: "cancel".to_owned() }),
        }, 5);
        assert_eq!(changed, k2);
        assert_eq!(store.get(&k1[0]).unwrap().status, ContractStatus::Active);
        assert_eq!(store.get(&k2[0]).unwrap().status, ContractStatus::Closed { path: "cancel".to_owned() });
        // A collection removes the claim record's coins.
        let claim_key = hex::encode(claim.contract_id());
        store.records.get_mut(&claim_key).unwrap().coins = vec![coin(0xc1), coin(0xc2)];
        let changed = store.apply(Derived::Transition {
            select: Select::ClaimByToken(asset(LENDER_TOKEN)),
            txid: cancel_txid,
            path: "collect".to_owned(),
            state: None,
            coins: None,
            coins_removed: vec![coin(0xc1).outpoint],
            status: None,
        }, 6);
        assert_eq!(changed, vec![claim_key.clone()]);
        assert_eq!(store.get(&claim_key).unwrap().coins, vec![coin(0xc2)]);
    }

    #[test]
    fn the_note_key_is_seed_derived_network_separated_and_not_the_venue_key() {
        let seed = [3u8; 64];
        let a = NoteKey::from_seed(&seed, Network::LiquidTestnet).unwrap();
        let b = NoteKey::from_seed(&seed, Network::LiquidTestnet).unwrap();
        let mainnet = NoteKey::from_seed(&seed, Network::Liquid).unwrap();
        assert_eq!(a.0, b.0);
        assert_ne!(a.0, mainnet.0);
        // The venue key on the same seed and network is another key entirely.
        let venue = crate::venue::VenueKey::from_seed(&seed, Network::LiquidTestnet).unwrap();
        let note_pk = elements::secp256k1_zkp::Keypair::from_seckey_slice(elements::secp256k1_zkp::SECP256K1, &a.0)
            .unwrap()
            .x_only_public_key()
            .0;
        assert_ne!(note_pk, venue.public_key());
        // fill_params from the template alone equals what derive records.
        let lastlook = [11u8; 32];
        let payout = payout_of(LENDER_TOKEN);
        let claim = v6_claim(&payout, &lastlook);
        let template = funded_v6_fill(&payout, &lastlook, None);
        let params = fill_params(&claim, &b64(&template), asset(LBTC)).unwrap().unwrap();
        assert_eq!(params, position_params(&payout, &lastlook));
        assert_eq!(template_input0(&b64(&template)).unwrap(), OutPoint::new(elements::Txid::from_str(&"41".repeat(32)).unwrap(), 0));
        let sealed = note_for_fill(&a, &params, &template_input0(&b64(&template)).unwrap()).unwrap().unwrap();
        let out = note_output(&sealed, asset(LBTC));
        assert_eq!(out.amount, Some(0));
        assert_eq!(out.asset, Some(asset(LBTC)));
        assert_eq!(op_return_payload(&out.script_pubkey), Some(&sealed[..]));
        assert!(fill_params(&TypedFund::SellRight { price: 1, cash: asset(USDT), fee: 1 }, &b64(&template), asset(LBTC)).unwrap().is_none());
    }

    #[test]
    fn fills_before_v5_and_plain_claims_yield_nothing() {
        let claim = TypedFund::Fill {
            size: 1,
            sale: 2,
            buyback: 3,
            expiry: 4,
            cash: asset(USDT),
            collateral: None,
            fee: 0,
        };
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        tx.add_input(input(0x11, 0, txout(LBTC, 10, spk(0x01))));
        tx.add_output(pset::Output::from_txout(txout(LBTC, 10, spk(0x02))));
        let derived = derive(&FundContext {
            claim: &claim,
            funded_pset_b64: &b64(&tx),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[],
            owned: &[],
        })
        .unwrap();
        assert!(derived.is_empty());
        assert_eq!(funded_txid(&b64(&tx)).unwrap(), tx.extract_tx().unwrap().txid());
    }

    // -----------------------------------------------------------------------
    // Reconstruction (spec §8.1). Layouts as the paper venue builds them on
    // testnet (position 52's fill, its sold right, position 51's buyback,
    // 2026-09-17): a full buyback burns the token at output 0 and pays the
    // claim script at output 1; a partial one returns the token at 0,
    // continues the position at 1 and pays the claim script after it; a
    // sale spends the token alone.

    /// The wallet's own history for the follow step.
    struct History(Vec<elements::Transaction>);
    impl OwnHistory for History {
        fn spender(&self, outpoint: &OutPoint) -> Option<elements::Transaction> {
            self.0.iter().find(|tx| tx.input.iter().any(|i| i.previous_output == *outpoint)).cloned()
        }
    }

    fn spend(txid: elements::Txid, vout: u32) -> pset::Input {
        pset::Input::from_prevout(OutPoint::new(txid, vout))
    }
    fn fresh(txid_byte: u8, vout: u32) -> pset::Input {
        spend(elements::Txid::from_str(&format!("{txid_byte:02x}").repeat(32)).unwrap(), vout)
    }
    fn out(asset_hex: &str, value: u64, script: Script) -> pset::Output {
        pset::Output::from_txout(txout(asset_hex, value, script))
    }
    fn burn() -> Script {
        Script::from(hex::decode("6a046275726e").unwrap())
    }

    /// A v4 fill this wallet funded, note and all, with the terms it created.
    fn noted_v4_fill() -> (elements::Transaction, ContractParams) {
        let lastlook = [11u8; 32];
        let payout = payout_of(LENDER_TOKEN);
        let params = ContractParams::LendPositionV4(position_terms(&payout, &lastlook));
        let template = funded_v4_fill(&payout, &lastlook, None);
        let input0 = template_input0(&b64(&template)).unwrap();
        let sealed = note_for_fill(&key(), &params, &input0).unwrap().unwrap();
        (funded_v4_fill(&payout, &lastlook, Some(sealed)).extract_tx().unwrap(), params)
    }

    /// A buyback of `pay` against the position at `(from, coin_vout)` with
    /// the token at `(from, token_vout)`; `remaining` is what stays owed.
    fn buyback(params: &ContractParams, from: elements::Txid, token_vout: u32, coin_vout: u32, pay: u64, remaining: u64) -> elements::Transaction {
        let claim = claim_script(asset(LENDER_TOKEN));
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        tx.add_input(spend(from, token_vout)); // 0 the wallet's position token
        tx.add_input(spend(from, coin_vout)); // 1 the position
        tx.add_input(fresh(0x53, 0)); // 2 the wallet's cash
        if remaining > 0 {
            tx.add_output(out(NFT, 1, spk(0x01))); // 0 token back
            tx.add_output(out(LBTC, 1_000_000, params.script(Some(remaining)).unwrap())); // 1 the position continues
        } else {
            tx.add_output(out(NFT, 1, burn())); // 0 token burned
        }
        tx.add_output(out(USDT, pay, claim)); // cash to the lender's claim script
        tx.add_output(out(LBTC, 1_000_000, spk(0x01))); // released collateral → mine
        tx.add_output(out(LBTC, 300, Script::new())); // fee
        tx.extract_tx().unwrap()
    }

    #[test]
    fn a_restored_wallet_finds_its_fill_again_from_its_own_history() {
        let (fill, params) = noted_v4_fill();
        let lastlook = [11u8; 32];
        let payout = payout_of(LENDER_TOKEN);
        let bare = funded_v4_fill(&payout, &lastlook, None).extract_tx().unwrap();
        assert!(carries_note(&fill));
        assert!(!carries_note(&bare));

        // The rescan knows the assets of the fill's outputs that are the
        // wallet's: its token, the cash it was paid, its change.
        let own_assets = [asset(NFT), asset(LBTC), asset(USDT)];
        let own = OwnTx { tx: &fill, confirmed: true, own_assets: &own_assets };
        let record = recover_position(&key(), &own, "").expect("the fill is found again");
        assert_eq!(record.params, params);
        assert_eq!(record.role, Role::Borrower);
        assert_eq!(record.state, Some(ContractState::Amount(1_242_00000000)));
        assert_eq!(record.status, ContractStatus::Active);
        assert_eq!(record.domain, "");
        assert_eq!(record.coins, vec![ContractCoin { outpoint: OutPoint::new(fill.txid(), 0), asset: asset(LBTC), amount: 2_000_000 }]);
        assert_eq!(record.history.len(), 1);

        // It is the record the approval derived, under the same key: a
        // wallet that never lost its store finds nothing new.
        let claim = TypedFund::FillV4 {
            size: 2_000_000,
            sale: 1_200_00000000,
            buyback: 1_242_00000000,
            expiry: 2_600_984,
            cash: asset(USDT),
            collateral: Some(asset(LBTC)),
            fee: 3_00000000,
            payout,
            lastlook,
            lastlook_height: 2_600_484,
        };
        let input0 = template_input0(&b64(&funded_v4_fill(&payout, &lastlook, None))).unwrap();
        let sealed = note_for_fill(&key(), &params, &input0).unwrap().unwrap();
        let derived = derive(&FundContext {
            claim: &claim,
            funded_pset_b64: &b64(&funded_v4_fill(&payout, &lastlook, Some(sealed))),
            domain: "paper.swaption.io",
            policy_asset: asset(LBTC),
            mine: &[1, 3, 8],
            owned: &[],
        })
        .unwrap();
        let mut store = ContractStore::default();
        let live_key = store.apply(derived[0].clone(), 1_000).remove(0);
        assert_eq!(ContractStore::key_of(&record), live_key);
        assert!(store.apply(Derived::New(record.clone()), 2_000).is_empty());
        assert_eq!(store.get(&live_key).unwrap().domain, "paper.swaption.io");
        assert_eq!(store.borrower_tokens(), vec![asset(NFT)]);

        // Still in the mempool: pending, like an approval.
        let waiting = recover_position(&key(), &OwnTx { tx: &fill, confirmed: false, own_assets: &own_assets }, "").unwrap();
        assert_eq!(waiting.status, ContractStatus::Pending);
        // The cash not among the wallet's assets, another seed, or no note: nothing, never a wrong record.
        assert!(recover_position(&key(), &OwnTx { tx: &fill, confirmed: true, own_assets: &[asset(NFT), asset(LBTC)] }, "").is_none());
        assert!(recover_position(&NoteKey::from_secret([8u8; 32]), &own, "").is_none());
        assert!(recover_position(&key(), &OwnTx { tx: &bare, confirmed: true, own_assets: &own_assets }, "").is_none());
    }

    #[test]
    fn following_the_wallets_own_history_replays_a_partial_and_a_full_buyback() {
        let (fill, _) = noted_v4_fill();
        let own_assets = [asset(NFT), asset(LBTC), asset(USDT)];
        let recovered = recover_position(&key(), &OwnTx { tx: &fill, confirmed: true, own_assets: &own_assets }, "").unwrap();
        let params = recovered.params.clone();
        let half = 621_00000000u64;
        let partial = buyback(&params, fill.txid(), 1, 0, half, half);
        let full = buyback(&params, partial.txid(), 0, 1, half, 0);

        // Nothing later in the history: the record stands as created.
        let mut untouched = recovered.clone();
        follow_position(&mut untouched, &History(vec![fill.clone()]));
        assert_eq!(untouched, recovered);

        // A partial buyback moves the coin and the debt.
        let mut moved = recovered.clone();
        follow_position(&mut moved, &History(vec![fill.clone(), partial.clone()]));
        assert_eq!(moved.state, Some(ContractState::Amount(half)));
        assert_eq!(moved.status, ContractStatus::Active);
        assert_eq!(moved.coins, vec![ContractCoin { outpoint: OutPoint::new(partial.txid(), 1), asset: asset(LBTC), amount: 1_000_000 }]);
        assert_eq!(moved.history.len(), 2);
        assert_eq!(moved.history[1].path, "exercise");
        assert!(moved.render("BTC", "USDt").contains("621 USDt still owed"), "{}", moved.render("BTC", "USDt"));

        // The full buyback after it closes the record, whatever order the history comes in.
        let mut closed = recovered.clone();
        follow_position(&mut closed, &History(vec![full.clone(), partial.clone(), fill.clone()]));
        assert_eq!(closed.status, ContractStatus::Closed { path: "exercise".to_owned() });
        assert_eq!(closed.state, Some(ContractState::Amount(0)));
        assert!(closed.coins.is_empty());
        assert_eq!(closed.history.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), vec!["fill", "exercise", "exercise"]);

        // A buyback that pays the claim script nothing, or whose continuing
        // script does not rebuild, explains nothing: closed as unknown, never a wrong state.
        let lying = buyback(&params, fill.txid(), 1, 0, half, half - 1);
        let mut unknown = recovered.clone();
        follow_position(&mut unknown, &History(vec![lying]));
        assert_eq!(unknown.status, ContractStatus::Closed { path: "unknown".to_owned() });
        assert!(unknown.coins.is_empty());
    }

    #[test]
    fn a_sold_right_a_last_look_and_a_lapse_close_a_recovered_position() {
        let (fill, _) = noted_v4_fill();
        let own_assets = [asset(NFT), asset(LBTC), asset(USDT)];
        let recovered = recover_position(&key(), &OwnTx { tx: &fill, confirmed: true, own_assets: &own_assets }, "").unwrap();
        let claim = claim_script(asset(LENDER_TOKEN));

        // The token leaves alone: the right was sold. The coin lives on.
        let mut sale = pset::PartiallySignedTransaction::new_v2();
        sale.add_input(spend(fill.txid(), 1)); // 0 the position token
        sale.add_input(fresh(0x92, 0)); // 1 the venue's cash
        sale.add_input(fresh(0x93, 0)); // 2 the wallet's fee input
        sale.add_output(out(NFT, 1, spk(0xaa))); // 0 the token → the venue
        sale.add_output(out(USDT, 50_00000000, spk(0x01))); // 1 the price → mine
        sale.add_output(out(LBTC, 250, Script::new())); // fee
        let sale = sale.extract_tx().unwrap();
        let mut sold = recovered.clone();
        follow_position(&mut sold, &History(vec![sale.clone()]));
        assert_eq!(sold.status, ContractStatus::Closed { path: "sold".to_owned() });
        assert_eq!(sold.coins, recovered.coins);
        assert_eq!(sold.state, recovered.state);
        assert_eq!(sold.history.last().unwrap().txid, sale.txid());

        // The venue's last look: the position spent without the token, the
        // debt paid to the claim script, the borrower's share to the wallet.
        let mut look = pset::PartiallySignedTransaction::new_v2();
        look.add_input(spend(fill.txid(), 0)); // 0 the position
        look.add_input(fresh(0x94, 0)); // 1 the venue's coin at the last-look script
        look.add_output(out(USDT, 1_242_00000000, claim.clone())); // the debt → the lender's claim
        look.add_output(out(USDT, 40_00000000, spk(0x01))); // the borrower's share → mine
        look.add_output(out(LBTC, 250, Script::new())); // fee
        let mut looked = recovered.clone();
        follow_position(&mut looked, &History(vec![look.extract_tx().unwrap()]));
        assert_eq!(looked.status, ContractStatus::Closed { path: "last_look".to_owned() });
        assert!(looked.coins.is_empty());
        assert_eq!(looked.render("BTC", "USDt").rsplit(" · ").next(), Some("exercised for you by the venue"));

        // A lapse seen by a wallet that is the lender too: the collateral to the claim script.
        let mut lapse = pset::PartiallySignedTransaction::new_v2();
        lapse.add_input(spend(fill.txid(), 0)); // 0 the position
        lapse.add_input(fresh(0x95, 0)); // 1 the sweeper's fee coin
        lapse.add_output(out(LBTC, 2_000_000, claim.clone())); // everything → the lender's claim
        lapse.add_output(out(LBTC, 250, Script::new())); // fee
        let mut lapsed = recovered.clone();
        follow_position(&mut lapsed, &History(vec![lapse.extract_tx().unwrap()]));
        assert_eq!(lapsed.status, ContractStatus::Closed { path: "lapse".to_owned() });
        assert_eq!(lapsed.state, recovered.state);
        assert!(lapsed.coins.is_empty());
    }

    #[test]
    fn a_lender_tokens_claim_coins_come_back_from_the_scripts_history() {
        let token = asset(LENDER_TOKEN);
        let claim = claim_script(token);
        // An exercise paid cash there, a lapse paid collateral, and one of
        // the two was collected since.
        let mut exercise = pset::PartiallySignedTransaction::new_v2();
        exercise.add_input(fresh(0xa1, 0));
        exercise.add_output(out(NFT, 1, burn()));
        exercise.add_output(out(USDT, 1_242_00000000, claim.clone()));
        exercise.add_output(out(LBTC, 300, Script::new()));
        let exercise = exercise.extract_tx().unwrap();
        let mut lapse = pset::PartiallySignedTransaction::new_v2();
        lapse.add_input(fresh(0xa2, 0));
        lapse.add_output(out(LBTC, 2_000_000, claim.clone()));
        lapse.add_output(out(LBTC, 300, Script::new()));
        let lapse = lapse.extract_tx().unwrap();
        let mut collect = pset::PartiallySignedTransaction::new_v2();
        collect.add_input(fresh(0xa3, 1)); // 0 the lender token
        collect.add_input(spend(exercise.txid(), 1)); // 1 the claim coin
        collect.add_output(out(LENDER_TOKEN, 1, spk(0x01)));
        collect.add_output(out(USDT, 1_242_00000000, spk(0x01)));
        collect.add_output(out(LBTC, 300, Script::new()));
        let collect = collect.extract_tx().unwrap();

        let waiting = ContractCoin { outpoint: OutPoint::new(lapse.txid(), 0), asset: asset(LBTC), amount: 2_000_000 };
        let paid = ContractCoin { outpoint: OutPoint::new(exercise.txid(), 1), asset: asset(USDT), amount: 1_242_00000000 };
        let mut both = claim_coins(token, &[exercise.clone(), lapse.clone()]);
        both.sort_by_key(|c| c.amount);
        assert_eq!(both, vec![waiting.clone(), paid]);
        assert_eq!(claim_coins(token, &[collect.clone(), exercise.clone(), lapse.clone()]), vec![waiting.clone()]);
        // Another token's script is another script.
        assert!(claim_coins(asset(NFT), &[exercise.clone(), lapse.clone()]).is_empty());

        // A one-unit asset whose claim script has no history is no lender
        // token the wallet is owed on (a borrower token looks like this).
        assert!(recover_claim(asset(NFT), &[], "").is_none());
        assert!(recover_claim(asset(NFT), &[exercise.clone()], "").is_none());
        let record = recover_claim(token, &[exercise.clone(), lapse.clone(), collect.clone()], "").expect("the claim record");
        assert_eq!(record.params, ContractParams::LendClaimV1 { lender_token: token });
        assert_eq!(record.role, Role::Lender);
        assert_eq!(record.status, ContractStatus::Active);
        assert_eq!(record.coins, vec![waiting.clone()]);
        // Everything collected: the record stays, empty.
        let mut sweep = pset::PartiallySignedTransaction::new_v2();
        sweep.add_input(fresh(0xa4, 1));
        sweep.add_input(spend(lapse.txid(), 0));
        sweep.add_output(out(LBTC, 1_999_700, spk(0x01)));
        let sweep = sweep.extract_tx().unwrap();
        let empty = recover_claim(token, &[exercise.clone(), lapse.clone(), collect.clone(), sweep], "").unwrap();
        assert!(empty.coins.is_empty());

        // The store takes the lookup's word for a claim record it holds.
        let mut store = ContractStore::default();
        let key = store.apply(Derived::New(empty), 1).remove(0);
        assert_eq!(store.claim_tokens(), vec![token]);
        assert_eq!(store.set_claim_coins(token, vec![waiting.clone()]), vec![key.clone()]);
        assert!(store.set_claim_coins(token, vec![waiting.clone()]).is_empty());
        assert!(store.set_claim_coins(asset(NFT), vec![waiting.clone()]).is_empty());
        assert_eq!(store.get(&key).unwrap().coins, vec![waiting.clone()]);
        assert_eq!(store.get(&key).unwrap().render("", ""), "What your lending paid: 1 coin waiting · collect with your lender token · active");
        // A later lookup never replaces the record, however old its last
        // step: a lookup reads coins, not the collections the store recorded.
        store.apply(
            Derived::Transition {
                select: Select::ClaimByToken(token),
                txid: collect.txid(),
                path: "collect".to_owned(),
                state: None,
                coins: None,
                coins_removed: Vec::new(),
                status: None,
            },
            2,
        );
        let looked_up = recover_claim(token, &[exercise.clone(), lapse.clone(), collect.clone()], "").unwrap();
        assert!(store.restore(looked_up, 99_999_999, 3_600).is_empty());
        assert_eq!(store.get(&key).unwrap().history.len(), 1);
    }

    /// A phone is in the background seconds after an approval, and by the
    /// time it is opened again the fill is deep in the chain: the pending
    /// record is settled by asking the wallet's whole history, and "never
    /// reached the chain" is said only of a transaction that history lacks.
    #[test]
    fn a_pending_record_is_settled_by_the_wallets_whole_history() {
        let (fill, _) = noted_v4_fill();
        let own_assets = [asset(USDT)];
        let waiting = recover_position(&key(), &OwnTx { tx: &fill, confirmed: false, own_assets: &own_assets }, "paper.swaption.io").unwrap();
        let mut store = ContractStore::default();
        let k = store.apply(Derived::New(waiting.clone()), 10_000).remove(0);
        assert_eq!(store.pending_txids(), vec![fill.txid()]);

        // Another transaction missing says nothing about this record; nor does youth.
        let other = elements::Txid::from_str(&"ee".repeat(32)).unwrap();
        assert!(store.fail_stale_pending_txid(&other, 99_999, 3_600).is_empty());
        assert!(store.fail_stale_pending_txid(&fill.txid(), 10_000 + 3_600, 3_600).is_empty());
        // Hours later the history has it confirmed: active, whatever its age.
        let mut seen = store.clone();
        assert_eq!(seen.confirm_txid(&fill.txid()), vec![k.clone()]);
        assert!(seen.pending_txids().is_empty());
        assert!(seen.fail_stale_pending_txid(&fill.txid(), 99_999, 3_600).is_empty());
        // The history lacks it and the hour has passed: never reached the chain.
        assert_eq!(store.fail_stale_pending_txid(&fill.txid(), 10_000 + 3_601, 3_600), vec![k.clone()]);
        assert!(store.pending_txids().is_empty());
        store.set_hidden(&k, true);
        // Closed as never broadcast, it is still re-read at a rescan.
        assert_eq!(store.rescan_candidates(99_999).len(), 1);

        // A rescan that finds the fill on chain after all puts the record
        // right and keeps what is the person's; a live record is left alone.
        let found = recover_position(&key(), &OwnTx { tx: &fill, confirmed: true, own_assets: &own_assets }, "").unwrap();
        assert_eq!(store.restore(found.clone(), 20_000, 3_600), vec![k.clone()]);
        let r = store.get(&k).unwrap();
        assert_eq!(r.status, ContractStatus::Active);
        assert_eq!(r.coins, found.coins);
        assert_eq!(r.domain, "paper.swaption.io");
        assert!(r.hidden);
        assert_eq!(r.created_at, 10_000);
        assert_eq!(r.updated_at, 20_000);
        assert!(store.restore(found.clone(), 30_000, 3_600).is_empty());
        // A pending record the chain has confirmed turns active on the rescan alone.
        assert_eq!(seen.get(&k).unwrap().status, ContractStatus::Active);
        let mut away = ContractStore::default();
        away.apply(Derived::New(waiting), 10_000);
        assert_eq!(away.restore(found.clone(), 10_060, 3_600), vec![k.clone()]);
        assert_eq!(away.get(&k).unwrap().status, ContractStatus::Active);
        assert_eq!(away.get(&k).unwrap().domain, "paper.swaption.io");
        // And a store that never had it takes it as found.
        let mut empty = ContractStore::default();
        assert_eq!(empty.restore(found, 40_000, 3_600), vec![k.clone()]);
        assert_eq!(empty.get(&k).unwrap().domain, "");
        assert_eq!(empty.get(&k).unwrap().created_at, 40_000);
    }

    /// The chain is the truth and the store is a cache, but the wallet's
    /// own approvals run ahead of the chain by a block: which record stands
    /// when a rescan's reading meets the store's.
    #[test]
    fn a_rescan_wins_where_it_knows_more_and_where_a_step_never_showed() {
        let (fill, _) = noted_v4_fill();
        let own_assets = [asset(USDT)];
        let created = recover_position(&key(), &OwnTx { tx: &fill, confirmed: true, own_assets: &own_assets }, "paper.swaption.io").unwrap();
        let params = created.params.clone();
        let half = 621_00000000u64;
        let partial = buyback(&params, fill.txid(), 1, 0, half, half);
        let mut store = ContractStore::default();
        let k = store.apply(Derived::New(created.clone()), 1_000).remove(0);

        // What the store re-reads from: the record as its fill created it.
        let again = store.rescan_candidates(2_000);
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].status, ContractStatus::Pending);
        assert_eq!(again[0].coins, created.coins);
        assert_eq!(again[0].state, Some(ContractState::Amount(1_242_00000000)));
        assert_eq!(again[0].domain, "paper.swaption.io");
        assert_eq!(again[0].created_by(), Some(fill.txid()));

        // The chain knows a step the store does not (a stale copy, a
        // venue's last look): the chain's record replaces it at once.
        let mut followed = created.clone();
        assert!(follow_position(&mut followed, &History(vec![partial.clone()])));
        assert_eq!(store.restore(followed.clone(), 2_000, 3_600), vec![k.clone()]);
        assert_eq!(store.get(&k).unwrap().state, Some(ContractState::Amount(half)));
        assert_eq!(store.get(&k).unwrap().updated_at, 2_000);
        assert!(store.restore(followed.clone(), 3_000, 3_600).is_empty());

        // The store is ahead by a step the wallet has just approved (a sale
        // whose transaction is on its way): the store's record stands…
        let sale_txid = elements::Txid::from_str(&"5a".repeat(32)).unwrap();
        store.apply(
            Derived::Transition {
                select: Select::PositionByBorrowerNft(asset(NFT)),
                txid: sale_txid,
                path: "sold".to_owned(),
                state: None,
                coins: None,
                coins_removed: Vec::new(),
                status: Some(ContractStatus::Closed { path: "sold".to_owned() }),
            },
            10_000,
        );
        assert!(store.restore(followed.clone(), 10_000 + 3_600, 3_600).is_empty());
        assert_eq!(store.get(&k).unwrap().status, ContractStatus::Closed { path: "sold".to_owned() });
        // …it is re-read while the step is young, and once the step has had
        // its hour without showing, the chain's record takes its place: the
        // sale died, the position is still the person's to buy back.
        assert_eq!(store.rescan_candidates(10_000 + RESCAN_WINDOW_SECS).len(), 1);
        assert!(store.rescan_candidates(10_000 + RESCAN_WINDOW_SECS + 1).is_empty());
        assert_eq!(store.restore(followed.clone(), 10_000 + 3_601, 3_600), vec![k.clone()]);
        assert_eq!(store.get(&k).unwrap().status, ContractStatus::Active);
        assert_eq!(store.get(&k).unwrap().history.len(), 2);

        // A reading that ends in `unknown` never overrules a record that says more.
        let mut vague = followed.clone();
        vague.history[1].path = "unknown".to_owned();
        vague.status = ContractStatus::Closed { path: "unknown".to_owned() };
        assert!(store.restore(vague, 99_999_999, 3_600).is_empty());

        // An offer and a claim have no beginning to return to; nor has a lender's position.
        let claim = recover_claim(asset(LENDER_TOKEN), &[partial], "").unwrap();
        assert!(claim.as_created().is_none());
        let mut lender_side = created.clone();
        lender_side.role = Role::Lender;
        assert!(lender_side.as_created().is_none());
        assert!(!follow_position(&mut lender_side, &History(vec![])));
    }

    #[test]
    fn an_export_opens_only_with_its_own_wallet_and_network_and_merges_by_the_last_step() {
        let (fill, _) = noted_v4_fill();
        let own_assets = [asset(USDT)];
        let record = recover_position(&key(), &OwnTx { tx: &fill, confirmed: true, own_assets: &own_assets }, "paper.swaption.io").unwrap();
        let mut store = ContractStore::default();
        let k = store.apply(Derived::New(record.clone()), 1_000).remove(0);
        store.set_hidden(&k, true);

        let seed = [3u8; 64];
        let export_key = ExportKey::from_seed(&seed, Network::LiquidTestnet).unwrap();
        // Its own key: not the note key of the same seed, not another network's.
        assert_ne!(export_key.0, NoteKey::from_seed(&seed, Network::LiquidTestnet).unwrap().0);
        assert_ne!(export_key.0, ExportKey::from_seed(&seed, Network::Liquid).unwrap().0);

        let text = export_store(&store, &export_key, Network::LiquidTestnet, 5_000).unwrap();
        assert!(text.starts_with("LCPOS1.liquidtestnet."), "{text}");
        assert!(!text.contains(char::is_whitespace) && !text.contains('='), "{text}");
        assert!(!text.contains("paper.swaption.io"));
        // Sealed with a fresh nonce every time.
        assert_ne!(text, export_store(&store, &export_key, Network::LiquidTestnet, 5_000).unwrap());

        // It comes back whole, through whatever a paste adds.
        let pasted = format!("  {}\n{}\r\n", &text[..40], &text[40..]);
        let (back, exported_at) = import_store(&pasted, &export_key, Network::LiquidTestnet).unwrap();
        assert_eq!(back, store);
        assert_eq!(exported_at, 5_000);

        // Another seed, another network's wallet, a relabelled or altered file, junk: refused in words.
        let other = ExportKey::from_secret([9u8; 32]);
        assert_eq!(import_store(&text, &other, Network::LiquidTestnet).unwrap_err(), ImportError::WrongWallet);
        assert_eq!(
            import_store(&text, &export_key, Network::Liquid).unwrap_err(),
            ImportError::WrongNetwork { found: "liquidtestnet".to_owned() }
        );
        let relabelled = text.replacen("liquidtestnet", "liquid", 1);
        assert_eq!(import_store(&relabelled, &export_key, Network::Liquid).unwrap_err(), ImportError::WrongWallet);
        let mut altered: Vec<char> = text.chars().collect();
        let i = altered.len() - 10;
        altered[i] = if altered[i] == 'A' { 'B' } else { 'A' };
        let altered: String = altered.into_iter().collect();
        assert_eq!(import_store(&altered, &export_key, Network::LiquidTestnet).unwrap_err(), ImportError::WrongWallet);
        assert_eq!(import_store("liquidconnect://login?x=1", &export_key, Network::LiquidTestnet).unwrap_err(), ImportError::NotAnExport);
        assert_eq!(import_store("LCPOS2.liquidtestnet.AAAA", &export_key, Network::LiquidTestnet).unwrap_err(), ImportError::NotAnExport);
        assert_eq!(import_store("LCPOS1.liquidtestnet.AAAA", &export_key, Network::LiquidTestnet).unwrap_err(), ImportError::NotAnExport);
        assert_eq!(ImportError::WrongWallet.to_string(), "this export belongs to another wallet, or it was altered");

        // Merging: a record only the copy has is taken as it is…
        let mut fresh = ContractStore::default();
        assert_eq!(fresh.merge(back.clone()), (vec![k.clone()], vec![]));
        assert_eq!(fresh, store);
        // …of a record both have, the one the person's step changed last
        // wins, this install's hidden flag stays, and a tie changes nothing.
        assert_eq!(fresh.merge(back.clone()), (vec![], vec![]));
        let mut newer = back.clone();
        {
            let r = newer.records.get_mut(&k).unwrap();
            r.status = ContractStatus::Closed { path: "sold".to_owned() };
            r.updated_at = 9_000;
            r.hidden = false;
        }
        assert_eq!(fresh.merge(newer), (vec![], vec![k.clone()]));
        assert_eq!(fresh.get(&k).unwrap().status, ContractStatus::Closed { path: "sold".to_owned() });
        assert!(fresh.get(&k).unwrap().hidden);
        assert_eq!(fresh.merge(back), (vec![], vec![]));
    }

    // -----------------------------------------------------------------------
    // The venue's own transactions (Liquid testnet, paper.swaption.io,
    // 2026-09-17; src/testdata/README.md), so that what the fixtures above
    // assume about layouts is what a venue builds. Terms from the lending
    // server's books.

    fn real_tx(hex_str: &str, txid: &str) -> elements::Transaction {
        let tx: elements::Transaction = elements::encode::deserialize(&hex::decode(hex_str.trim()).unwrap()).unwrap();
        assert_eq!(tx.txid().to_string(), txid);
        tx
    }

    fn sha(script_hex: &str) -> [u8; 32] {
        script_hash(&Script::from(hex::decode(script_hex).unwrap()))
    }

    /// A position of the paper venue's as the wallet records it at the fill.
    fn paper_position(fill: &elements::Transaction, buyback: u64, borrower_nft: &str, lender_nft: &str, borrower_script: &str, payout_script: &str) -> ContractRecord {
        let params = ContractParams::LendPositionV4(PositionTerms {
            collateral: asset(LBTC),
            cash: asset(USDT),
            size: 1_000_000,
            buyback,
            expiry: 2_632_781,
            borrower_nft: asset(borrower_nft),
            lender_nft: asset(lender_nft),
            payout: sha(payout_script),
            borrower_payout: sha(borrower_script),
            lastlook: sha("001432c4fbef1dd471fca2d52a6f8654e4a39d96ba2c"),
            lastlook_height: 2_632_766,
        });
        // The terms rebuild the coin on chain, and the lender is paid at
        // the claim script of its token: what the follow step reads by.
        assert_eq!(hex::encode(params.script(Some(buyback)).unwrap().as_bytes()), hex::encode(fill.output[0].script_pubkey.as_bytes()));
        assert_eq!(hex::encode(claim_script(asset(lender_nft)).as_bytes()), payout_script);
        let Derived::New(record) = new_position(params, fill.txid(), "paper.swaption.io") else {
            unreachable!("new_position yields a new record")
        };
        record
    }

    #[test]
    fn the_paper_venues_real_transactions_follow_as_the_fixtures_do() {
        let fill51 = real_tx(
            include_str!("testdata/paper-testnet-2026-09-17-fill51.nowitness.hex"),
            "1083eed00824b5e1852097e8994fc0088cb6506771930a446afea7e93230216b",
        );
        let buyback51 = real_tx(
            include_str!("testdata/paper-testnet-2026-09-17-buyback51.nowitness.hex"),
            "2fdd553413f9ad32708d2ffc88e5a33164f04dd45fa39b241071576633b6f7ef",
        );
        let fill52 = real_tx(
            include_str!("testdata/paper-testnet-2026-09-17-fill52.nowitness.hex"),
            "c5cfe2b4ef68528cc9d4b8b86edbba623586c016f50eec04fd4796622e6a7115",
        );
        let sellright52 = real_tx(
            include_str!("testdata/paper-testnet-2026-09-17-sellright52.nowitness.hex"),
            "0a05f392712d98cfac58b72d4e4b760fc700ffcaf417a0404b55df5bf2814d06",
        );

        // Position 51: filled before the wallet wrote notes, bought back in full.
        assert!(!carries_note(&fill51));
        let mut p51 = paper_position(
            &fill51,
            456_85276800,
            "b29c1ca49115a770e304c57af9871dfe61835bf98fe8c7f62a0cc7308358f183",
            "03c5b3692f0051c5075c8b3ddd3ea68e51cd05d12b1d5f1e9ff3c80e10915a7e",
            "0014b0a920bbed9e09fc64fa3cc50c4e5ea6e801c907",
            "512080f7930adc0dbb8df44c73de3f3f52199b057dcfea6da49b48b34ea748a7d483",
        );
        follow_position(&mut p51, &History(vec![fill51.clone(), buyback51.clone()]));
        assert_eq!(p51.status, ContractStatus::Closed { path: "exercise".to_owned() });
        assert_eq!(p51.state, Some(ContractState::Amount(0)));
        assert!(p51.coins.is_empty());
        assert_eq!(p51.history.last().unwrap().txid, buyback51.txid());

        // Position 52: the first fill to carry a note — sealed under the
        // phone's seed, so not this key's to open — and its right sold
        // eighteen seconds later. The venue bought it back afterwards; that
        // is no longer this wallet's business.
        assert!(carries_note(&fill52));
        assert!(recover_position(&key(), &OwnTx { tx: &fill52, confirmed: true, own_assets: &[asset(USDT)] }, "").is_none());
        let mut p52 = paper_position(
            &fill52,
            461_17756200,
            "0a7a3a011b06d571cf4fdf53e10e0fab14cf4571d7fcf4b06b589455c69dd72f",
            "d49cfb9aef7644c6a35cafc97238643069a540483b69a79b4df6897a9331f772",
            "001434669754d0ffc82a91f03f72459cf07fd0ade5e6",
            "5120a438622cbec3e5133d4dbbe072475c61212981999b0e65accec503c70f2c55ee",
        );
        let created = p52.clone();
        follow_position(&mut p52, &History(vec![sellright52.clone(), fill52.clone()]));
        assert_eq!(p52.status, ContractStatus::Closed { path: "sold".to_owned() });
        assert_eq!(p52.coins, created.coins);
        assert_eq!(p52.history.last().unwrap().txid, sellright52.txid());
    }

    #[test]
    fn render_is_the_terms_and_then_the_status() {
        let (fill, _) = noted_v4_fill();
        let own_assets = [asset(USDT)];
        let record = recover_position(&key(), &OwnTx { tx: &fill, confirmed: false, own_assets: &own_assets }, "").unwrap();
        let terms = record.render_terms("BTC", "USDt");
        assert!(terms.ends_with("from block 2600984 the collateral goes to the lender"), "{terms}");
        assert!(!terms.contains("awaiting"), "{terms}");
        assert_eq!(record.render("BTC", "USDt"), format!("{terms} · awaiting confirmation"));
    }
}
