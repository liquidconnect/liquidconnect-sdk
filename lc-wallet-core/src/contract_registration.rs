//! Registration — contracts the wallet did not sign (spec §4 and §5, phase 1).
//!
//! Spec: Dropbox `liquid connect/COVENANT-POSITIONS-SPEC-2026-09-16.md`.
//! Every step the wallet signs yields its record inside the wallet
//! ([`crate::contracts::derive`]). What it did not sign — a lender's
//! position created by a borrower's fill, coins paid to a claim script, a
//! transition the venue built, everything after a restore — a relying party
//! describes in a [`ContractSpec`], and the wallet stores it only after it
//! has checked, by itself, that the contract is real and binds money to
//! THIS wallet. A relying party that lies loses only the registration.
//!
//! The order of the checks is the spec's (§5) and the first failure is the
//! answer: kind and leaf, id, script, role, coins. Consent (rule 1) is the
//! host's to check before it calls [`register`]. Nothing here holds keys,
//! talks to a network or keeps state: the wallet's own facts and the
//! chain's come through [`WalletView`] and [`ChainView`].
//!
//! The other direction is the statement ([`statement`]): everything this
//! wallet holds of one domain's contracts, complete, replacing the last.

use std::str::FromStr;

use elements::{AssetId, OutPoint, Txid};
use serde::{Deserialize, Serialize};

use crate::contracts::{
    ContractCoin, ContractEvent, ContractParams, ContractRecord, ContractStatus, ContractStore, PositionTerms, Role, explicit_txout, kind, script_hash,
};
use crate::lending::{OfferRowClaim, SWAPTION_LENDING_V5_LEAF, claim_script};

/// Relay and wallet bounds (spec §4.6). The connect server checks shape
/// and size; the wallet checks again, because the server is not the judge.
pub const MAX_SPECS_PER_REQUEST: usize = 32;
pub const MAX_PARAMS_LEN: usize = 4_096;
pub const MAX_KIND_LEN: usize = 64;
pub const MAX_LABEL_LEN: usize = 64;
pub const MAX_COINS: usize = 64;
pub const MAX_STATEMENT_ENTRIES: usize = 4_096;

/// One contract as a relying party describes it. `params` is the kind's
/// canonical object: keys as in [`ContractParams::canonical_json`], u64 as
/// decimal strings, 32-byte values and asset ids as lower-case hex, heights
/// as numbers. Anything else is not the canonical form and is refused, so
/// that one contract has one id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSpec {
    /// Hex of [`ContractParams::contract_id`]; the wallet recomputes it.
    pub contract_id: String,
    pub kind: String,
    /// Hex tapleaf hash; must equal the wallet's pin for `kind`.
    pub leaf: String,
    pub params: serde_json::Map<String, serde_json::Value>,
    /// "borrower" | "lender".
    pub role: String,
    /// The mutable slot as a u64 string, where the kind has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Where the contract's money sits now.
    pub coins: Vec<SpecCoin>,
    /// The site's words for it. Display only, never used for any number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecCoin {
    pub txid: String,
    pub vout: u32,
    pub asset: String,
    pub amount: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractResult {
    pub contract_id: String,
    pub outcome: ContractOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractOutcome {
    /// A new record was stored.
    Registered,
    /// A known record's state or coins moved.
    Updated,
    /// A known record, nothing new.
    Unchanged,
    /// One of the fixed reasons of [`Reject`].
    Rejected { reason: String },
}

/// The wallet's word about one contract of one domain (the statement).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEntry {
    pub contract_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    pub status: EntryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryStatus {
    Pending,
    Active,
    Expired,
    Closed { path: String },
}

/// Why a spec was refused: the fixed strings of spec §4.6, which the
/// connect server passes through to the relying party.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    UnknownKind,
    LeafMismatch,
    IdMismatch,
    ScriptMismatch,
    RoleNotBound,
    CoinMismatch,
    NotExplicit,
    ChainUnavailable,
    NotAllowed,
    TooMany,
    UserDeclined,
}

impl Reject {
    pub fn as_str(&self) -> &'static str {
        match self {
            Reject::UnknownKind => "unknown_kind",
            Reject::LeafMismatch => "leaf_mismatch",
            Reject::IdMismatch => "id_mismatch",
            Reject::ScriptMismatch => "script_mismatch",
            Reject::RoleNotBound => "role_not_bound",
            Reject::CoinMismatch => "coin_mismatch",
            Reject::NotExplicit => "not_explicit",
            Reject::ChainUnavailable => "chain_unavailable",
            Reject::NotAllowed => "not_allowed",
            Reject::TooMany => "too_many",
            Reject::UserDeclined => "user_declined",
        }
    }
}

impl From<Reject> for ContractOutcome {
    fn from(reject: Reject) -> Self {
        ContractOutcome::Rejected {
            reason: reject.as_str().to_owned(),
        }
    }
}

/// What the wallet knows of itself, for the role check (spec §5 rule 5):
/// a role is bound to this wallet cryptographically, never by the relying
/// party's word.
pub trait WalletView {
    /// One of this wallet's scriptPubKeys hashes (SHA-256) to `hash`.
    fn owns_script_hash(&self, hash: &[u8; 32]) -> bool;
    /// The wallet holds exactly one unit of `asset`.
    fn holds_token(&self, asset: AssetId) -> bool;
}

/// The chain backend cannot answer now; the relying party tries later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainUnavailable;

/// An output as the chain (mempool included) has it.
#[derive(Debug, Clone)]
pub struct ChainOutput {
    pub txout: elements::TxOut,
    pub confirmed: bool,
    /// The transaction that spends it, if one does.
    pub spent_by: Option<Txid>,
}

pub trait ChainView {
    /// The output at `outpoint`; `Ok(None)` when the chain has no such output.
    fn output(&self, outpoint: &OutPoint) -> Result<Option<ChainOutput>, ChainUnavailable>;
}

// ---------------------------------------------------------------------------
// The canonical parameters, read back strictly.

type Params = serde_json::Map<String, serde_json::Value>;

fn field<'a>(params: &'a Params, key: &str) -> Result<&'a serde_json::Value, Reject> {
    params.get(key).ok_or(Reject::IdMismatch)
}

fn text<'a>(params: &'a Params, key: &str) -> Result<&'a str, Reject> {
    field(params, key)?.as_str().ok_or(Reject::IdMismatch)
}

/// A u64 as the canonical decimal string: digits only, no sign, no leading
/// zero but "0" itself.
fn parse_u64(text: &str) -> Option<u64> {
    let canonical = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0'));
    if canonical { text.parse().ok() } else { None }
}

fn amount(params: &Params, key: &str) -> Result<u64, Reject> {
    parse_u64(text(params, key)?).ok_or(Reject::IdMismatch)
}

fn height(params: &Params, key: &str) -> Result<u32, Reject> {
    field(params, key)?
        .as_u64()
        .and_then(|h| u32::try_from(h).ok())
        .ok_or(Reject::IdMismatch)
}

fn parse_hash32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || text.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(text).ok()?.try_into().ok()
}

fn hash32(params: &Params, key: &str) -> Result<[u8; 32], Reject> {
    parse_hash32(text(params, key)?).ok_or(Reject::IdMismatch)
}

fn parse_asset(text: &str) -> Option<AssetId> {
    if text.len() != 64 || text.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    AssetId::from_str(text).ok()
}

fn asset(params: &Params, key: &str) -> Result<AssetId, Reject> {
    parse_asset(text(params, key)?).ok_or(Reject::IdMismatch)
}

fn exact_keys(params: &Params, count: usize) -> Result<(), Reject> {
    if params.len() == count { Ok(()) } else { Err(Reject::IdMismatch) }
}

/// The terms a spec names, read back from their canonical object. An
/// unknown kind is [`Reject::UnknownKind`]; anything that is not exactly
/// the kind's canonical object is [`Reject::IdMismatch`], since no id can
/// be recomputed from it.
pub fn params_from_spec(kind_name: &str, params: &Params) -> Result<ContractParams, Reject> {
    match kind_name {
        kind::LEND_POSITION_V5 | kind::LEND_POSITION_V4 => {
            exact_keys(params, 11)?;
            let terms = PositionTerms {
                collateral: asset(params, "collateral")?,
                cash: asset(params, "cash")?,
                size: amount(params, "size")?,
                buyback: amount(params, "buyback")?,
                expiry: height(params, "expiry")?,
                borrower_nft: asset(params, "borrower_nft")?,
                lender_nft: asset(params, "lender_nft")?,
                payout: hash32(params, "payout")?,
                borrower_payout: hash32(params, "borrower_payout")?,
                lastlook: hash32(params, "lastlook")?,
                lastlook_height: height(params, "lastlook_height")?,
            };
            Ok(if kind_name == kind::LEND_POSITION_V4 {
                ContractParams::LendPositionV4(terms)
            } else {
                ContractParams::LendPositionV5(terms)
            })
        }
        kind::LEND_OFFER_V1 => {
            exact_keys(params, 8)?;
            let rows = field(params, "rows")?.as_array().ok_or(Reject::IdMismatch)?;
            if rows.is_empty() || rows.len() > 4 {
                return Err(Reject::IdMismatch);
            }
            let rows = rows
                .iter()
                .map(|row| {
                    let row = row.as_object().ok_or(Reject::IdMismatch)?;
                    exact_keys(row, 6)?;
                    Ok(OfferRowClaim {
                        collateral: asset(row, "collateral")?,
                        expiry: height(row, "expiry")?,
                        price_out: amount(row, "price_out")?,
                        buyback: amount(row, "buyback")?,
                        fee_per_unit: amount(row, "fee_per_unit")?,
                        min_size: amount(row, "min_size")?,
                    })
                })
                .collect::<Result<Vec<_>, Reject>>()?;
            Ok(ContractParams::LendOfferV1 {
                cash: asset(params, "cash")?,
                lender_token: asset(params, "lender_token")?,
                claim: hash32(params, "claim")?,
                fee_script: hash32(params, "fee_script")?,
                position_leaf: hash32(params, "position_leaf")?,
                fee_min: amount(params, "fee_min")?,
                cutoff: height(params, "cutoff")?,
                rows,
            })
        }
        kind::LEND_CLAIM_V1 => {
            exact_keys(params, 1)?;
            Ok(ContractParams::LendClaimV1 {
                lender_token: asset(params, "lender_token")?,
            })
        }
        _ => Err(Reject::UnknownKind),
    }
}

/// A record as a relying party would describe it: what a wallet's own
/// record looks like on the wire, and what a relying party's server builds
/// from its books. The inverse of [`params_from_spec`] for the terms.
pub fn spec_of(record: &ContractRecord) -> ContractSpec {
    let params = serde_json::from_str::<serde_json::Value>(&record.params.canonical_json())
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    ContractSpec {
        contract_id: hex::encode(record.contract_id),
        kind: record.params.kind().to_owned(),
        leaf: hex::encode(record.params.leaf()),
        params,
        role: match record.role {
            Role::Borrower => "borrower".to_owned(),
            Role::Lender => "lender".to_owned(),
        },
        state: record.state.map(|state| state.to_string()),
        coins: record
            .coins
            .iter()
            .map(|coin| SpecCoin {
                txid: coin.outpoint.txid.to_string(),
                vout: coin.outpoint.vout,
                asset: coin.asset.to_string(),
                amount: coin.amount.to_string(),
            })
            .collect(),
        label: None,
    }
}

// ---------------------------------------------------------------------------
// Verification and storage (spec §5 rules 2–8).

fn parse_role(role: &str) -> Option<Role> {
    match role {
        "borrower" => Some(Role::Borrower),
        "lender" => Some(Role::Lender),
        _ => None,
    }
}

/// Rule 5: the role is bound to this wallet by what the wallet holds.
fn role_is_bound(params: &ContractParams, role: Role, wallet: &dyn WalletView) -> bool {
    match (params, role) {
        // The borrower's payout is a script of this wallet's, and the
        // wallet holds the position token the buyback needs.
        (ContractParams::LendPositionV5(t) | ContractParams::LendPositionV4(t), Role::Borrower) => {
            wallet.owns_script_hash(&t.borrower_payout) && wallet.holds_token(t.borrower_nft)
        }
        // The lender is paid at the claim script of a token this wallet holds.
        (ContractParams::LendPositionV5(t) | ContractParams::LendPositionV4(t), Role::Lender) => {
            wallet.holds_token(t.lender_nft) && t.payout == script_hash(&claim_script(t.lender_nft))
        }
        (
            ContractParams::LendOfferV1 {
                lender_token,
                claim,
                position_leaf,
                ..
            },
            Role::Lender,
        ) => wallet.holds_token(*lender_token) && *claim == script_hash(&claim_script(*lender_token)) && *position_leaf == SWAPTION_LENDING_V5_LEAF,
        (ContractParams::LendClaimV1 { lender_token }, Role::Lender) => wallet.holds_token(*lender_token),
        _ => false,
    }
}

fn parse_coin(coin: &SpecCoin) -> Result<ContractCoin, Reject> {
    let txid = Txid::from_str(&coin.txid).map_err(|_| Reject::CoinMismatch)?;
    Ok(ContractCoin {
        outpoint: OutPoint::new(txid, coin.vout),
        asset: parse_asset(&coin.asset).ok_or(Reject::CoinMismatch)?,
        amount: parse_u64(&coin.amount).ok_or(Reject::CoinMismatch)?,
    })
}

/// Rule 6 for one coin: it exists at `script`, explicit, unspent, with the
/// stated asset and amount. Returns whether it is confirmed.
fn coin_on_chain(coin: &ContractCoin, script: &elements::Script, chain: &dyn ChainView) -> Result<bool, Reject> {
    let output = chain
        .output(&coin.outpoint)
        .map_err(|ChainUnavailable| Reject::ChainUnavailable)?
        .ok_or(Reject::CoinMismatch)?;
    if output.txout.script_pubkey != *script {
        return Err(Reject::ScriptMismatch);
    }
    let (asset, amount) = explicit_txout(&output.txout).ok_or(Reject::NotExplicit)?;
    if asset != coin.asset || amount != coin.amount || output.spent_by.is_some() {
        return Err(Reject::CoinMismatch);
    }
    Ok(output.confirmed)
}

fn spender(outpoint: &OutPoint, chain: &dyn ChainView) -> Result<Option<Txid>, Reject> {
    Ok(chain
        .output(outpoint)
        .map_err(|ChainUnavailable| Reject::ChainUnavailable)?
        .and_then(|output| output.spent_by))
}

/// The store key of the record a spec speaks of, if the store holds it. A
/// position and a claim key by their id. Offers with the same terms share
/// an id and key by their post coin: the one meant is the one whose coin
/// the spec names, or whose coin the spec's coin's transaction spent.
fn held_key(store: &ContractStore, params: &ContractParams, coins: &[ContractCoin], chain: &dyn ChainView) -> Result<Option<String>, Reject> {
    let id = hex::encode(params.contract_id());
    if !matches!(params, ContractParams::LendOfferV1 { .. }) {
        return Ok(store.get(&id).map(|_| id));
    }
    let same_terms: Vec<(&String, &ContractRecord)> = store.records().filter(|(_, r)| r.contract_id == params.contract_id()).collect();
    if let Some(coin) = coins.first() {
        if let Some((key, _)) = same_terms.iter().find(|(_, r)| r.coins.iter().any(|c| c.outpoint == coin.outpoint)) {
            return Ok(Some((*key).clone()));
        }
        for (key, record) in &same_terms {
            if let Some(old) = record.coins.first() {
                if spender(&old.outpoint, chain)? == Some(coin.outpoint.txid) {
                    return Ok(Some((*key).clone()));
                }
            }
        }
        return Ok(None);
    }
    // An offer reported gone names no coin: it is the one whose coin is spent.
    for (key, record) in &same_terms {
        if let Some(old) = record.coins.first() {
            if spender(&old.outpoint, chain)?.is_some() {
                return Ok(Some((*key).clone()));
            }
        }
    }
    Ok(None)
}

fn try_register(store: &mut ContractStore, spec: &ContractSpec, domain: &str, now: u64, wallet: &dyn WalletView, chain: &dyn ChainView) -> Result<ContractOutcome, Reject> {
    // Rule 2: a kind the SDK has a verifier for, under the leaf it pins.
    if spec.kind.len() > MAX_KIND_LEN {
        return Err(Reject::UnknownKind);
    }
    if spec.coins.len() > MAX_COINS {
        return Err(Reject::TooMany);
    }
    let params = params_from_spec(&spec.kind, &spec.params)?;
    if params.canonical_json().len() > MAX_PARAMS_LEN {
        return Err(Reject::IdMismatch);
    }
    if spec.leaf != hex::encode(params.leaf()) {
        return Err(Reject::LeafMismatch);
    }
    // Rule 3: the id is the wallet's to compute.
    if spec.contract_id != hex::encode(params.contract_id()) {
        return Err(Reject::IdMismatch);
    }
    // Rule 4: the script these terms and this state make.
    let state = match &spec.state {
        Some(state) => Some(parse_u64(state).ok_or(Reject::ScriptMismatch)?),
        None => None,
    };
    let is_claim = matches!(params, ContractParams::LendClaimV1 { .. });
    if is_claim == state.is_some() {
        return Err(Reject::ScriptMismatch);
    }
    let script = params.script(state).map_err(|_| Reject::ScriptMismatch)?;
    // Rule 5: the role is this wallet's by what it holds.
    let role = parse_role(&spec.role).ok_or(Reject::RoleNotBound)?;
    if !role_is_bound(&params, role, wallet) {
        return Err(Reject::RoleNotBound);
    }
    // Rule 6: the coins are on chain, where the terms say, as stated.
    let coins = spec.coins.iter().map(parse_coin).collect::<Result<Vec<_>, _>>()?;
    if !is_claim && coins.len() > 1 {
        return Err(Reject::CoinMismatch);
    }
    let expected_asset = match &params {
        ContractParams::LendPositionV5(t) | ContractParams::LendPositionV4(t) => Some(t.collateral),
        ContractParams::LendOfferV1 { cash, .. } => Some(*cash),
        ContractParams::LendClaimV1 { .. } => None,
    };
    let mut all_confirmed = true;
    for coin in &coins {
        if expected_asset.is_some_and(|asset| asset != coin.asset) {
            return Err(Reject::CoinMismatch);
        }
        all_confirmed &= coin_on_chain(coin, &script, chain)?;
    }
    let live = if all_confirmed { ContractStatus::Active } else { ContractStatus::Pending };

    // Rule 7: store, silently.
    let Some(key) = held_key(store, &params, &coins, chain)? else {
        // A contract that is already over is history, not a registration.
        if !is_claim && coins.is_empty() {
            return Err(Reject::CoinMismatch);
        }
        let history = coins
            .first()
            .map(|coin| ContractEvent {
                txid: coin.outpoint.txid,
                path: "registered".to_owned(),
                state_after: state,
            })
            .into_iter()
            .collect();
        let record = ContractRecord {
            contract_id: params.contract_id(),
            params,
            role,
            domain: domain.to_owned(),
            state,
            coins,
            status: if is_claim { ContractStatus::Active } else { live },
            hidden: false,
            history,
            created_at: 0,
            updated_at: 0,
        };
        return Ok(if store.apply(crate::contracts::Derived::New(record), now).is_empty() {
            ContractOutcome::Unchanged
        } else {
            ContractOutcome::Registered
        });
    };

    let held = store.get(&key).expect("found above").clone();
    if held.role != role {
        return Err(Reject::RoleNotBound);
    }
    let same_coins = {
        let mut a: Vec<_> = held.coins.iter().map(|c| (c.outpoint.txid, c.outpoint.vout)).collect();
        let mut b: Vec<_> = coins.iter().map(|c| (c.outpoint.txid, c.outpoint.vout)).collect();
        a.sort();
        b.sort();
        a == b
    };
    let mut record = held.clone();
    // A record found again from the chain alone has no site; the first
    // site that registers it, and proves it, names it.
    if record.domain.is_empty() {
        record.domain = domain.to_owned();
    }
    let outcome = if same_coins && held.state == state {
        if record.status == ContractStatus::Pending && live == ContractStatus::Active {
            record.status = ContractStatus::Active;
        }
        ContractOutcome::Unchanged
    } else if is_claim {
        // Other people's transactions pay a claim script; each coin was
        // checked above, and that is all a claim's update has to show.
        record.coins = coins;
        record.updated_at = now;
        ContractOutcome::Updated
    } else {
        // A state can only move along the chain: what carries the new
        // coin, or ended the contract, spent the coin the record had.
        let moved_by = match held.coins.first() {
            Some(old) => spender(&old.outpoint, chain)?,
            None => None,
        };
        match (coins.first(), moved_by) {
            (Some(new), Some(by)) if by == new.outpoint.txid => {
                record.history.push(ContractEvent {
                    txid: by,
                    path: "registered".to_owned(),
                    state_after: state,
                });
                record.status = live;
            }
            // The store had closed it as never broadcast, or had no coin:
            // the coin proven above is where the contract is.
            (Some(new), None) if held.coins.is_empty() => {
                record.history.push(ContractEvent {
                    txid: new.outpoint.txid,
                    path: "registered".to_owned(),
                    state_after: state,
                });
                record.status = live;
            }
            (None, Some(by)) => {
                record.history.push(ContractEvent {
                    txid: by,
                    path: "unknown".to_owned(),
                    state_after: state,
                });
                record.status = ContractStatus::Closed { path: "unknown".to_owned() };
            }
            _ => return Err(Reject::CoinMismatch),
        }
        record.state = state;
        record.coins = coins;
        record.updated_at = now;
        ContractOutcome::Updated
    };
    if record != held {
        store.records.insert(key, record);
    }
    Ok(outcome)
}

/// Verify one spec and, if it holds, store it (spec §5 rules 2–8). The
/// answer is the wire's: what the relying party is told. A spec that fails
/// is refused and nothing is stored "for display".
pub fn register(store: &mut ContractStore, spec: &ContractSpec, domain: &str, now: u64, wallet: &dyn WalletView, chain: &dyn ChainView) -> ContractResult {
    let outcome = try_register(store, spec, domain, now, wallet, chain).unwrap_or_else(ContractOutcome::from);
    ContractResult {
        contract_id: spec.contract_id.clone(),
        outcome,
    }
}

/// A whole request: at most [`MAX_SPECS_PER_REQUEST`] specs, each answered
/// on its own, so a batch may be partly refused. `allowed` is rule 1: the
/// domain holds the person's consent.
pub fn register_all(store: &mut ContractStore, specs: &[ContractSpec], domain: &str, allowed: bool, now: u64, wallet: &dyn WalletView, chain: &dyn ChainView) -> Vec<ContractResult> {
    specs
        .iter()
        .enumerate()
        .map(|(index, spec)| {
            if !allowed {
                return ContractResult {
                    contract_id: spec.contract_id.clone(),
                    outcome: Reject::NotAllowed.into(),
                };
            }
            if index >= MAX_SPECS_PER_REQUEST {
                return ContractResult {
                    contract_id: spec.contract_id.clone(),
                    outcome: Reject::TooMany.into(),
                };
            }
            register(store, spec, domain, now, wallet, chain)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The statement (spec §4.4, §5): the wallet's word about what it holds.

impl From<&ContractStatus> for EntryStatus {
    fn from(status: &ContractStatus) -> Self {
        match status {
            ContractStatus::Pending => EntryStatus::Pending,
            ContractStatus::Active => EntryStatus::Active,
            ContractStatus::Expired => EntryStatus::Expired,
            ContractStatus::Closed { path } => EntryStatus::Closed { path: path.clone() },
        }
    }
}

/// Everything this wallet holds of `domain`'s contracts, complete, hidden
/// ones included (hiding is the person's view, not the wallet's holding).
/// It replaces the last statement; an empty list says the wallet holds
/// nothing of this domain. Live records come first, so the cap never
/// drops one for the sake of history.
pub fn statement(store: &ContractStore, domain: &str) -> Vec<ContractEntry> {
    let mut records: Vec<&ContractRecord> = store.records().map(|(_, r)| r).filter(|r| r.domain == domain).collect();
    records.sort_by_key(|r| matches!(r.status, ContractStatus::Closed { .. }));
    records
        .into_iter()
        .take(MAX_STATEMENT_ENTRIES)
        .map(|r| ContractEntry {
            contract_id: hex::encode(r.contract_id),
            kind: r.params.kind().to_owned(),
            state: r.state.map(|state| state.to_string()),
            status: EntryStatus::from(&r.status),
        })
        .collect()
}

/// The domains the wallet has a statement for: every one a record names.
/// A record found again from the chain alone names none until a site's
/// registration does.
pub fn statement_domains(store: &ContractStore) -> Vec<String> {
    let mut domains: Vec<String> = store.records().map(|(_, r)| r.domain.clone()).filter(|d| !d.is_empty()).collect();
    domains.sort();
    domains.dedup();
    domains
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::Derived;
    use crate::lending::SWAPTION_LENDING_V4_LEAF;
    use elements::confidential::{Asset, Nonce, Value};
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    const LBTC: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
    const USDT: &str = "b612eb46313a2cd6ebabd8b7a8eed5696e29898b87a43bff41c94f51acef9d73";
    const BORROWER_TOKEN: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const LENDER_TOKEN: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    fn asset_id(hex_str: &str) -> AssetId {
        AssetId::from_str(hex_str).unwrap()
    }
    fn txid(byte: u8) -> Txid {
        Txid::from_str(&format!("{byte:02x}").repeat(32)).unwrap()
    }
    fn spk(tag: u8) -> elements::Script {
        elements::Script::from(vec![0x00, 0x14].into_iter().chain([tag; 20]).collect::<Vec<u8>>())
    }

    #[derive(Default)]
    struct Wallet {
        scripts: BTreeSet<[u8; 32]>,
        tokens: BTreeSet<AssetId>,
    }
    impl WalletView for Wallet {
        fn owns_script_hash(&self, hash: &[u8; 32]) -> bool {
            self.scripts.contains(hash)
        }
        fn holds_token(&self, asset: AssetId) -> bool {
            self.tokens.contains(&asset)
        }
    }

    #[derive(Default)]
    struct Chain {
        outputs: RefCell<BTreeMap<(Txid, u32), ChainOutput>>,
        down: bool,
    }
    impl Chain {
        fn put(&self, txid: Txid, vout: u32, asset: &str, amount: u64, script: elements::Script) {
            self.outputs.borrow_mut().insert(
                (txid, vout),
                ChainOutput {
                    txout: elements::TxOut {
                        asset: Asset::Explicit(asset_id(asset)),
                        value: Value::Explicit(amount),
                        nonce: Nonce::Null,
                        script_pubkey: script,
                        witness: Default::default(),
                    },
                    confirmed: true,
                    spent_by: None,
                },
            );
        }
        fn spend(&self, txid: Txid, vout: u32, by: Txid) {
            self.outputs.borrow_mut().get_mut(&(txid, vout)).unwrap().spent_by = Some(by);
        }
    }
    impl ChainView for Chain {
        fn output(&self, outpoint: &OutPoint) -> Result<Option<ChainOutput>, ChainUnavailable> {
            if self.down {
                return Err(ChainUnavailable);
            }
            Ok(self.outputs.borrow().get(&(outpoint.txid, outpoint.vout)).cloned())
        }
    }

    fn terms() -> PositionTerms {
        PositionTerms {
            collateral: asset_id(LBTC),
            cash: asset_id(USDT),
            size: 1_000_000,
            buyback: 461_17756200,
            expiry: 2_632_781,
            borrower_nft: asset_id(BORROWER_TOKEN),
            lender_nft: asset_id(LENDER_TOKEN),
            payout: script_hash(&claim_script(asset_id(LENDER_TOKEN))),
            borrower_payout: script_hash(&spk(0x01)),
            lastlook: script_hash(&spk(0xee)),
            lastlook_height: 2_632_766,
        }
    }

    /// A lender's position as the lending server would describe it after a
    /// borrower filled the wallet's offer: nothing the wallet signed.
    fn lender_position(chain: &Chain) -> (ContractSpec, ContractParams) {
        let params = ContractParams::LendPositionV4(terms());
        let coin = ContractCoin {
            outpoint: OutPoint::new(txid(0x52), 0),
            asset: asset_id(LBTC),
            amount: 1_000_000,
        };
        chain.put(txid(0x52), 0, LBTC, 1_000_000, params.script(Some(461_17756200)).unwrap());
        let record = ContractRecord {
            contract_id: params.contract_id(),
            params: params.clone(),
            role: Role::Lender,
            domain: String::new(),
            state: Some(461_17756200),
            coins: vec![coin],
            status: ContractStatus::Active,
            hidden: false,
            history: Vec::new(),
            created_at: 0,
            updated_at: 0,
        };
        (spec_of(&record), params)
    }

    fn lender() -> Wallet {
        Wallet {
            scripts: BTreeSet::new(),
            tokens: BTreeSet::from([asset_id(LENDER_TOKEN)]),
        }
    }

    #[test]
    fn a_spec_is_the_canonical_object_and_reads_back_strictly() {
        let chain = Chain::default();
        let (spec, params) = lender_position(&chain);
        assert_eq!(spec.kind, "sw/lend/position/v4");
        assert_eq!(spec.leaf, hex::encode(SWAPTION_LENDING_V4_LEAF));
        assert_eq!(spec.contract_id, hex::encode(params.contract_id()));
        assert_eq!(spec.state.as_deref(), Some("46117756200"));
        assert_eq!(spec.params["size"], serde_json::json!("1000000"));
        assert_eq!(spec.params["expiry"], serde_json::json!(2_632_781));
        assert_eq!(params_from_spec(&spec.kind, &spec.params).unwrap(), params);
        // The same terms under the v5 name are another contract.
        assert_ne!(params_from_spec(kind::LEND_POSITION_V5, &spec.params).unwrap().contract_id(), params.contract_id());

        // Not the canonical form: a number for an amount, a leading zero,
        // upper-case hex, a missing key, an extra key. No id recomputes.
        let mut m = spec.params.clone();
        m.insert("size".to_owned(), serde_json::json!(1_000_000));
        assert_eq!(params_from_spec(&spec.kind, &m), Err(Reject::IdMismatch));
        let mut m = spec.params.clone();
        m.insert("size".to_owned(), serde_json::json!("01000000"));
        assert_eq!(params_from_spec(&spec.kind, &m), Err(Reject::IdMismatch));
        let mut m = spec.params.clone();
        m.insert("payout".to_owned(), serde_json::json!(hex::encode(terms().payout).to_uppercase()));
        assert_eq!(params_from_spec(&spec.kind, &m), Err(Reject::IdMismatch));
        let mut m = spec.params.clone();
        m.remove("lastlook");
        assert_eq!(params_from_spec(&spec.kind, &m), Err(Reject::IdMismatch));
        let mut m = spec.params.clone();
        m.insert("note".to_owned(), serde_json::json!("hello"));
        assert_eq!(params_from_spec(&spec.kind, &m), Err(Reject::IdMismatch));
        assert_eq!(params_from_spec("sw/pm/holder/v1", &spec.params), Err(Reject::UnknownKind));

        // The wire shapes a relying party and a connect server will see.
        let json = serde_json::to_string(&ContractResult {
            contract_id: "ab".repeat(32),
            outcome: Reject::RoleNotBound.into(),
        })
        .unwrap();
        assert_eq!(json, format!(r#"{{"contract_id":"{}","outcome":{{"Rejected":{{"reason":"role_not_bound"}}}}}}"#, "ab".repeat(32)));
        assert_eq!(serde_json::to_string(&ContractOutcome::Registered).unwrap(), r#""Registered""#);
        let entry = ContractEntry {
            contract_id: "cd".repeat(32),
            kind: kind::LEND_CLAIM_V1.to_owned(),
            state: None,
            status: EntryStatus::Closed { path: "exercise".to_owned() },
        };
        assert_eq!(
            serde_json::to_string(&entry).unwrap(),
            format!(r#"{{"contract_id":"{}","kind":"sw/lend/claim/v1","status":{{"Closed":{{"path":"exercise"}}}}}}"#, "cd".repeat(32))
        );
    }

    #[test]
    fn a_lenders_position_registers_only_when_it_is_real_and_this_wallets() {
        let chain = Chain::default();
        let (spec, params) = lender_position(&chain);
        let mut store = ContractStore::default();
        let register_as = |store: &mut ContractStore, spec: &ContractSpec, wallet: &Wallet, chain: &Chain| register(store, spec, "paper.swaption.io", 1_000, wallet, chain).outcome;

        // The first failure is the answer, in the spec's order.
        let mut lie = spec.clone();
        lie.leaf = hex::encode(SWAPTION_LENDING_V5_LEAF);
        assert_eq!(register_as(&mut store, &lie, &lender(), &chain), Reject::LeafMismatch.into());
        let mut lie = spec.clone();
        lie.contract_id = "00".repeat(32);
        assert_eq!(register_as(&mut store, &lie, &lender(), &chain), Reject::IdMismatch.into());
        // A wallet that does not hold the lender token is not the lender,
        // whatever the site says; nor is the lender the borrower.
        assert_eq!(register_as(&mut store, &spec, &Wallet::default(), &chain), Reject::RoleNotBound.into());
        let mut lie = spec.clone();
        lie.role = "borrower".to_owned();
        assert_eq!(register_as(&mut store, &lie, &lender(), &chain), Reject::RoleNotBound.into());
        // A state the coin's script was not made from.
        let mut lie = spec.clone();
        lie.state = Some("46117756199".to_owned());
        assert_eq!(register_as(&mut store, &lie, &lender(), &chain), Reject::ScriptMismatch.into());
        // A coin that is not there, an amount that is not the coin's.
        let mut lie = spec.clone();
        lie.coins[0].vout = 7;
        assert_eq!(register_as(&mut store, &lie, &lender(), &chain), Reject::CoinMismatch.into());
        let mut lie = spec.clone();
        lie.coins[0].amount = "999999".to_owned();
        assert_eq!(register_as(&mut store, &lie, &lender(), &chain), Reject::CoinMismatch.into());
        // A chain backend that cannot answer now: the site tries later.
        let down = Chain { down: true, ..Chain::default() };
        assert_eq!(register_as(&mut store, &spec, &lender(), &down), Reject::ChainUnavailable.into());
        assert!(store.records().next().is_none(), "nothing is stored for display");

        // The truth registers, once.
        assert_eq!(register_as(&mut store, &spec, &lender(), &chain), ContractOutcome::Registered);
        let key = hex::encode(params.contract_id());
        let record = store.get(&key).unwrap().clone();
        assert_eq!(record.role, Role::Lender);
        assert_eq!(record.domain, "paper.swaption.io");
        assert_eq!(record.status, ContractStatus::Active);
        assert_eq!(record.created_at, 1_000);
        assert_eq!(spec_of(&record), spec);
        assert_eq!(register_as(&mut store, &spec, &lender(), &chain), ContractOutcome::Unchanged);

        // Without consent nothing is looked at, and a batch is answered spec by spec.
        let refused = register_all(&mut store, &[spec.clone()], "paper.swaption.io", false, 2_000, &lender(), &chain);
        assert_eq!(refused[0].outcome, Reject::NotAllowed.into());
    }

    #[test]
    fn a_state_moves_only_along_the_chain() {
        let chain = Chain::default();
        let (spec, params) = lender_position(&chain);
        let mut store = ContractStore::default();
        let key = hex::encode(params.contract_id());
        assert_eq!(register(&mut store, &spec, "paper.swaption.io", 1_000, &lender(), &chain).outcome, ContractOutcome::Registered);

        // The borrower bought half back: the position continues at a new
        // coin under the remaining debt. Before the chain shows the old
        // coin spent by that transaction, the update is not believed.
        let half = 230_58878100u64;
        let mut moved = spec.clone();
        moved.state = Some(half.to_string());
        moved.coins = vec![SpecCoin {
            txid: txid(0x53).to_string(),
            vout: 1,
            asset: LBTC.to_owned(),
            amount: "500000".to_owned(),
        }];
        chain.put(txid(0x53), 1, LBTC, 500_000, params.script(Some(half)).unwrap());
        assert_eq!(register(&mut store, &moved, "paper.swaption.io", 2_000, &lender(), &chain).outcome, Reject::CoinMismatch.into());
        chain.spend(txid(0x52), 0, txid(0x99));
        assert_eq!(register(&mut store, &moved, "paper.swaption.io", 2_000, &lender(), &chain).outcome, Reject::CoinMismatch.into());
        chain.spend(txid(0x52), 0, txid(0x53));
        assert_eq!(register(&mut store, &moved, "paper.swaption.io", 2_000, &lender(), &chain).outcome, ContractOutcome::Updated);
        let record = store.get(&key).unwrap();
        assert_eq!(record.state, Some(half));
        assert_eq!(record.coins[0].outpoint, OutPoint::new(txid(0x53), 1));
        assert_eq!(record.updated_at, 2_000);
        assert_eq!(record.history.len(), 2);

        // It is over (a lapse, a last look, the rest bought back): no coin
        // is named, and the coin the record had must be spent.
        let mut over = moved.clone();
        over.coins.clear();
        assert_eq!(register(&mut store, &over, "paper.swaption.io", 3_000, &lender(), &chain).outcome, Reject::CoinMismatch.into());
        chain.spend(txid(0x53), 1, txid(0x54));
        assert_eq!(register(&mut store, &over, "paper.swaption.io", 3_000, &lender(), &chain).outcome, ContractOutcome::Updated);
        let record = store.get(&key).unwrap();
        assert_eq!(record.status, ContractStatus::Closed { path: "unknown".to_owned() });
        assert!(record.coins.is_empty());
        // A contract that is already over is history, not a registration.
        let mut fresh = ContractStore::default();
        assert_eq!(register(&mut fresh, &over, "paper.swaption.io", 3_000, &lender(), &chain).outcome, Reject::CoinMismatch.into());
    }

    #[test]
    fn a_claim_grows_by_what_others_paid_and_a_recovered_record_gets_its_site() {
        let chain = Chain::default();
        let token = asset_id(LENDER_TOKEN);
        let claim = claim_script(token);
        let params = ContractParams::LendClaimV1 { lender_token: token };
        let key = hex::encode(params.contract_id());
        // The wallet found its claim record again from the chain alone: no site.
        let mut store = ContractStore::default();
        store.apply(
            Derived::New(ContractRecord {
                contract_id: params.contract_id(),
                params: params.clone(),
                role: Role::Lender,
                domain: String::new(),
                state: None,
                coins: Vec::new(),
                status: ContractStatus::Active,
                hidden: false,
                history: Vec::new(),
                created_at: 0,
                updated_at: 0,
            }),
            500,
        );
        assert!(statement_domains(&store).is_empty());

        chain.put(txid(0x61), 1, USDT, 456_85276800, claim.clone());
        chain.put(txid(0x62), 0, LBTC, 1_000_000, claim.clone());
        let mut spec = spec_of(store.get(&key).unwrap());
        spec.coins = vec![
            SpecCoin { txid: txid(0x61).to_string(), vout: 1, asset: USDT.to_owned(), amount: "45685276800".to_owned() },
            SpecCoin { txid: txid(0x62).to_string(), vout: 0, asset: LBTC.to_owned(), amount: "1000000".to_owned() },
        ];
        assert_eq!(register(&mut store, &spec, "paper.swaption.io", 1_000, &lender(), &chain).outcome, ContractOutcome::Updated);
        let record = store.get(&key).unwrap();
        assert_eq!(record.coins.len(), 2);
        assert_eq!(record.domain, "paper.swaption.io", "the site that proved it names it");
        assert_eq!(statement_domains(&store), vec!["paper.swaption.io".to_owned()]);
        // A coin at another script is not a claim coin; a collected one is gone.
        chain.put(txid(0x63), 0, USDT, 1, spk(0x09));
        let mut lie = spec.clone();
        lie.coins.push(SpecCoin { txid: txid(0x63).to_string(), vout: 0, asset: USDT.to_owned(), amount: "1".to_owned() });
        assert_eq!(register(&mut store, &lie, "paper.swaption.io", 2_000, &lender(), &chain).outcome, Reject::ScriptMismatch.into());
        chain.spend(txid(0x61), 1, txid(0x70));
        assert_eq!(register(&mut store, &spec, "paper.swaption.io", 2_000, &lender(), &chain).outcome, Reject::CoinMismatch.into());
        // A claim has no state slot.
        let mut lie = spec.clone();
        lie.state = Some("1".to_owned());
        assert_eq!(register(&mut store, &lie, "paper.swaption.io", 2_000, &lender(), &chain).outcome, Reject::ScriptMismatch.into());

        // The statement: everything of the domain, live first, as the wire carries it.
        let entries = statement(&store, "paper.swaption.io");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, kind::LEND_CLAIM_V1);
        assert_eq!(entries[0].status, EntryStatus::Active);
        assert!(statement(&store, "lending.example").is_empty());
    }

    #[test]
    fn a_borrower_is_bound_by_its_payout_script_and_its_token() {
        let chain = Chain::default();
        let (mut spec, _) = lender_position(&chain);
        spec.role = "borrower".to_owned();
        let mut store = ContractStore::default();
        let mut wallet = Wallet::default();
        assert_eq!(register(&mut store, &spec, "paper.swaption.io", 1, &wallet, &chain).outcome, Reject::RoleNotBound.into());
        wallet.scripts.insert(script_hash(&spk(0x01)));
        assert_eq!(register(&mut store, &spec, "paper.swaption.io", 1, &wallet, &chain).outcome, Reject::RoleNotBound.into(), "the right was sold: no token, no role");
        wallet.tokens.insert(asset_id(BORROWER_TOKEN));
        assert_eq!(register(&mut store, &spec, "paper.swaption.io", 1, &wallet, &chain).outcome, ContractOutcome::Registered);
    }
}
