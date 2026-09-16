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
use crate::key::Network;
use crate::lending::{
    FILL_BORROWER_NFT_OUTPUT, FILL_LENDER_NFT_OUTPUT, FILL_POSITION_OUTPUT, OfferRowClaim, SWAPTION_CLAIM_LEAF,
    SWAPTION_LENDING_V5_LEAF, SWAPTION_OFFER_LEAF, TypedFund, claim_script, fmt8, offer_script, offer_terms_digest,
    op_return_payload, v5_position_script, v5_terms_digest,
};

/// The feature a wallet advertises in `LoginReq.features` once it holds
/// contracts (spec §4.5). Not sent yet: phase 1.
pub const CONTRACTS_FEATURE: &str = "contracts/1";

/// Kind names: the typed-kind vocabulary the SDK already speaks.
pub mod kind {
    pub const LEND_POSITION_V5: &str = "sw/lend/position/v5";
    pub const LEND_OFFER_V1: &str = "sw/lend/offer/v1";
    pub const LEND_CLAIM_V1: &str = "sw/lend/claim/v1";
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

fn script_hash(script: &Script) -> [u8; 32] {
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
    LendPositionV5 {
        collateral: AssetId,
        cash: AssetId,
        size: u64,
        buyback: u64,
        expiry: u32,
        borrower_nft: AssetId,
        lender_nft: AssetId,
        /// SHA-256 of the lender payout scriptPubKey (the claim script of
        /// `lender_nft` since v3).
        payout: [u8; 32],
        /// SHA-256 of the borrower's payout scriptPubKey (the script its
        /// position token was paid to).
        borrower_payout: [u8; 32],
        /// SHA-256 of the venue's last-look scriptPubKey.
        lastlook: [u8; 32],
        lastlook_height: u32,
    },
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
}

impl ContractParams {
    pub fn kind(&self) -> &'static str {
        match self {
            ContractParams::LendPositionV5 { .. } => kind::LEND_POSITION_V5,
            ContractParams::LendOfferV1 { .. } => kind::LEND_OFFER_V1,
            ContractParams::LendClaimV1 { .. } => kind::LEND_CLAIM_V1,
        }
    }

    /// The tapleaf hash the SDK pins for this kind: the allowlist.
    pub fn leaf(&self) -> [u8; 32] {
        match self {
            ContractParams::LendPositionV5 { .. } => SWAPTION_LENDING_V5_LEAF,
            ContractParams::LendOfferV1 { .. } => SWAPTION_OFFER_LEAF,
            ContractParams::LendClaimV1 { .. } => SWAPTION_CLAIM_LEAF,
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
            ContractParams::LendPositionV5 {
                collateral,
                cash,
                size,
                buyback,
                expiry,
                borrower_nft,
                lender_nft,
                payout,
                borrower_payout,
                lastlook,
                lastlook_height,
            } => {
                m.insert("collateral", a(collateral));
                m.insert("cash", a(cash));
                m.insert("size", s(*size));
                m.insert("buyback", s(*buyback));
                m.insert("expiry", h(*expiry));
                m.insert("borrower_nft", a(borrower_nft));
                m.insert("lender_nft", a(lender_nft));
                m.insert("payout", x(payout));
                m.insert("borrower_payout", x(borrower_payout));
                m.insert("lastlook", x(lastlook));
                m.insert("lastlook_height", h(*lastlook_height));
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
        }
        serde_json::to_string(&m).expect("a map serialises")
    }

    /// `sha256` tagged `liquidconnect/contract/v1` over `kind ‖ 0x00 ‖
    /// canonical params`. Deterministic on every side.
    pub fn contract_id(&self) -> [u8; 32] {
        tagged(b"liquidconnect/contract/v1", &[self.kind().as_bytes(), &[0u8], self.canonical_json().as_bytes()])
    }

    /// The covenant scriptPubKey for these terms and `state` (the mutable
    /// slot: remaining debt of a position, remaining cash of an offer;
    /// `None` for a claim script).
    pub fn script(&self, state: Option<u64>) -> anyhow::Result<Script> {
        match self {
            ContractParams::LendPositionV5 {
                collateral,
                cash,
                size,
                buyback,
                expiry,
                borrower_nft,
                lender_nft,
                payout,
                borrower_payout,
                lastlook,
                lastlook_height,
            } => {
                let debt = state.ok_or_else(|| anyhow::anyhow!("a position needs its remaining debt"))?;
                let digest = v5_terms_digest(
                    *collateral,
                    *cash,
                    *size,
                    *buyback,
                    *expiry,
                    *borrower_nft,
                    *lender_nft,
                    payout,
                    borrower_payout,
                    lastlook,
                    *lastlook_height,
                );
                Ok(v5_position_script(&digest, debt))
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
                let remaining = state.ok_or_else(|| anyhow::anyhow!("an offer needs its remaining cash"))?;
                let digest = offer_terms_digest(*cash, *lender_token, claim, fee_script, position_leaf, *fee_min, *cutoff, rows);
                Ok(offer_script(&digest, remaining))
            }
            ContractParams::LendClaimV1 { lender_token } => Ok(claim_script(*lender_token)),
        }
    }

    /// The cutoff height (contract standard §1): the height from which the
    /// person's exit is open without any third party, and by which the
    /// service must have taken what the deal gives it. A claim script has
    /// none.
    pub fn cutoff(&self) -> Option<u32> {
        match self {
            ContractParams::LendPositionV5 { expiry, .. } => Some(*expiry),
            ContractParams::LendOfferV1 { cutoff, .. } => Some(*cutoff),
            ContractParams::LendClaimV1 { .. } => None,
        }
    }

    /// The lender token a lender-side record hangs on, if any.
    pub fn lender_token(&self) -> Option<AssetId> {
        match self {
            ContractParams::LendPositionV5 { lender_nft, .. } => Some(*lender_nft),
            ContractParams::LendOfferV1 { lender_token, .. } => Some(*lender_token),
            ContractParams::LendClaimV1 { lender_token } => Some(*lender_token),
        }
    }
}

/// The wallet's side of a contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Borrower,
    Lender,
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
    pub state_after: Option<u64>,
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
    pub state: Option<u64>,
    pub coins: Vec<ContractCoin>,
    pub status: ContractStatus,
    /// Wallet-local; never sent anywhere.
    pub hidden: bool,
    pub history: Vec<ContractEvent>,
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
        state: Option<u64>,
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
        TypedFund::FillV5 { .. } | TypedFund::FillV6 { .. } => {
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
            let state = amounts.first().copied();
            out.push(Derived::New(ContractRecord {
                contract_id: params.contract_id(),
                params,
                role: Role::Lender,
                domain: ctx.domain.to_owned(),
                state,
                coins,
                status: ContractStatus::Pending,
                hidden: false,
                history: vec![ContractEvent {
                    txid,
                    path: "post".to_owned(),
                    state_after: state,
                }],
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
                state: Some(*remaining),
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
                state: Some(0),
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
        // Positions of covenant versions 1–4 have no contract kind.
        TypedFund::Fill { .. } | TypedFund::FillV2 { .. } | TypedFund::FillV3 { .. } | TypedFund::FillV4 { .. } => {}
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
    let (size, buyback, expiry, cash, collateral, payout, lastlook, lastlook_height, lender_nft) = match claim {
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
        } => {
            let (lender_nft, one, _) = explicit_output(pset, FILL_LENDER_NFT_OUTPUT)?;
            anyhow::ensure!(one == 1, "fill output 2 is not the lender token");
            (*size, *buyback, *expiry, *cash, *collateral, payout, lastlook, *lastlook_height, lender_nft)
        }
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
        } => (*size, *buyback, *expiry, *cash, *collateral, payout, lastlook, *lastlook_height, *lender_nft),
        _ => return Ok(None),
    };
    let collateral = collateral.unwrap_or(policy_asset);
    let (asset0, value0, script0) = explicit_output(pset, FILL_POSITION_OUTPUT)?;
    anyhow::ensure!(asset0 == collateral && value0 == size, "fill output 0 is not the position coin");
    let (borrower_nft, one, borrower_script) = explicit_output(pset, FILL_BORROWER_NFT_OUTPUT)?;
    anyhow::ensure!(one == 1, "fill output 1 is not the borrower token");
    let params = ContractParams::LendPositionV5 {
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
    anyhow::ensure!(params.script(Some(buyback))? == script0, "fill output 0 is not the covenant for these terms");
    Ok(Some(params))
}

fn new_position(params: ContractParams, txid: Txid, domain: &str) -> Derived {
    let (collateral, size, buyback) = match &params {
        ContractParams::LendPositionV5 { collateral, size, buyback, .. } => (*collateral, *size, *buyback),
        _ => unreachable!("fill_params_of returns a position"),
    };
    Derived::New(ContractRecord {
        contract_id: params.contract_id(),
        params,
        role: Role::Borrower,
        domain: domain.to_owned(),
        state: Some(buyback),
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
            state_after: Some(buyback),
        }],
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
            (Select::PositionByBorrowerNft(nft), ContractParams::LendPositionV5 { borrower_nft, .. }) => {
                borrower_nft == nft && record.role == Role::Borrower
            }
            (Select::OfferByCoin(outpoint), ContractParams::LendOfferV1 { .. }) => record.coins.iter().any(|c| c.outpoint == *outpoint),
            (Select::ClaimByToken(token), ContractParams::LendClaimV1 { lender_token }) => lender_token == token,
            _ => false,
        }
    }

    /// Apply what an accepted step derived; returns the keys of the records
    /// that changed. A `New` of a record already held changes nothing (an
    /// offer post repeats the claim record of the same token).
    pub fn apply(&mut self, derived: Derived) -> Vec<String> {
        match derived {
            Derived::New(record) => {
                let key = Self::key_of(&record);
                if self.records.contains_key(&key) {
                    return Vec::new();
                }
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
                    if let Some(s) = state {
                        r.state = Some(s);
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
                        state_after: r.state,
                    });
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
}

// ---------------------------------------------------------------------------
// The note (spec §6.4)

/// The note's length: one tag byte and a 78-byte body, under Elements'
/// 80-byte OP_RETURN relay limit.
pub const NOTE_LEN: usize = 79;
/// Tag of a `sw/lend/position/v5` note — the only kind with a note.
pub const NOTE_TAG_POSITION_V5: u8 = 0x01;

/// BIP43 purpose index of the note key's derivation path: 0x4C4E, ASCII
/// "LN". The full path is `m/19534'/<network>'/0'` with network 0'
/// Liquid, 1' Liquid testnet, 2' regtest — the venue key's scheme
/// (`venue::VENUE_KEY_PURPOSE`) under its own purpose, so the two keys
/// never coincide.
pub const NOTE_KEY_PURPOSE: u32 = 0x4C4E;

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
        let secp = Secp256k1::signing_only();
        // NetworkKind only selects xprv serialization bytes, which never
        // leave this function; network separation is the path's job.
        let master = Xpriv::new_master(NetworkKind::Main, seed)?;
        let net = match network {
            Network::Liquid => 0,
            Network::LiquidTestnet => 1,
            Network::Regtest => 2,
        };
        let path = [
            ChildNumber::from_hardened_idx(NOTE_KEY_PURPOSE).expect("fits 31 bits"),
            ChildNumber::from_hardened_idx(net).expect("fits 31 bits"),
            ChildNumber::from_hardened_idx(0).expect("fits 31 bits"),
        ];
        let child = master.derive_priv(&secp, &path)?;
        Ok(NoteKey(child.private_key.secret_bytes()))
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
    let ContractParams::LendPositionV5 {
        buyback,
        expiry,
        lastlook_height,
        lastlook,
        lender_nft,
        ..
    } = params
    else {
        anyhow::bail!("only a position has a note");
    };
    let mut note = [0u8; NOTE_LEN];
    note[0] = NOTE_TAG_POSITION_V5;
    note[1..9].copy_from_slice(&buyback.to_be_bytes());
    note[9..12].copy_from_slice(&u24(*expiry)?);
    note[12..15].copy_from_slice(&u24(*lastlook_height)?);
    note[15..47].copy_from_slice(lastlook);
    note[47..79].copy_from_slice(&lender_nft.into_inner().0);
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
    if !matches!(params, ContractParams::LendPositionV5 { .. }) {
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
    if note[0] != NOTE_TAG_POSITION_V5 {
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
    let params = ContractParams::LendPositionV5 {
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
                other => format!("closed ({other})"),
            },
        }
    }
}

impl ContractRecord {
    /// The person-facing line, from verified terms only, ending with the
    /// cutoff: the block from which the person can recover alone.
    pub fn render(&self, collateral_symbol: &str, cash_symbol: &str) -> String {
        let status = self.status.render();
        match (&self.params, self.role) {
            (
                ContractParams::LendPositionV5 {
                    size,
                    buyback,
                    expiry,
                    lastlook_height,
                    ..
                },
                Role::Borrower,
            ) => {
                let owed = self.state.unwrap_or(*buyback);
                let owed_text = if owed == *buyback {
                    format!("buy back for {} {cash_symbol}", fmt8(*buyback))
                } else {
                    format!("{} {cash_symbol} still owed", fmt8(owed))
                };
                let last_look = if *lastlook_height > 0 {
                    format!(" · from block {lastlook_height} the venue may exercise for you")
                } else {
                    String::new()
                };
                format!(
                    "Sold {} {collateral_symbol} · {owed_text} until block {expiry}{last_look} · from block {expiry} the collateral goes to the lender · {status}",
                    fmt8(*size)
                )
            }
            (
                ContractParams::LendPositionV5 {
                    size, buyback, expiry, ..
                },
                Role::Lender,
            ) => {
                let owed = self.state.unwrap_or(*buyback);
                format!(
                    "Bought {} {collateral_symbol} · the borrower may buy it back for {} {cash_symbol} until block {expiry} · from block {expiry} the collateral is yours · {status}",
                    fmt8(*size),
                    fmt8(owed)
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
                    "Lend offer on chain: {} {cash_symbol} remaining · {} · withdraw any time · after block {cutoff} it returns to your claim · {status}",
                    fmt8(remaining),
                    rows_text.join("; ")
                )
            }
            (ContractParams::LendClaimV1 { .. }, _) => {
                let n = self.coins.len();
                format!(
                    "What your lending paid: {n} coin{} waiting · collect with your lender token · {status}",
                    if n == 1 { "" } else { "s" }
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

    fn position_params(payout: &[u8; 32], lastlook: &[u8; 32]) -> ContractParams {
        ContractParams::LendPositionV5 {
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
        if let ContractParams::LendPositionV5 { buyback, .. } = &mut other {
            *buyback += 1;
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
        assert_eq!(record.state, Some(1_242_00000000));
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
                state: Some(621_00000000),
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
        assert_eq!(*state, Some(0));
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
        assert_eq!(offer.state, Some(25_000_00000000));
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
        let keys = store.apply(derived[0].clone());
        assert_eq!(keys.len(), 1);
        let key = keys[0].clone();
        assert_eq!(key, hex::encode(position_params(&payout, &lastlook).contract_id()));
        // The same derivation again changes nothing.
        assert!(store.apply(derived[0].clone()).is_empty());
        assert_eq!(store.get(&key).unwrap().status, ContractStatus::Pending);
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
        assert_eq!(store.apply(derived[0].clone()), vec![key.clone()]);
        let r = store.get(&key).unwrap();
        assert_eq!(r.state, Some(621_00000000));
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
        };
        let mut store = ContractStore::default();
        assert_eq!(store.apply(Derived::New(record(claim.clone(), vec![]))).len(), 1);
        assert!(store.apply(Derived::New(record(claim.clone(), vec![]))).is_empty());

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
        let k1 = store.apply(Derived::New(record(offer.clone(), vec![coin(0xa1)])));
        let k2 = store.apply(Derived::New(record(offer.clone(), vec![coin(0xa2)])));
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
            state: Some(0),
            coins: Some(vec![]),
            coins_removed: vec![coin(0xa2).outpoint],
            status: Some(ContractStatus::Closed { path: "cancel".to_owned() }),
        });
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
        });
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
}
