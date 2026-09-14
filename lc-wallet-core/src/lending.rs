//! Swaption lending on Liquid Connect: typed `sw/lend/*` fund claims.
//!
//! A lending step is a `StartFund` whose memo carries a canonical JSON
//! claim about the template (spec: docs/lending-fund-spec.md). The
//! wallet parses the claim, checks it against template rows it can read
//! by itself — explicit amounts, its own outputs, the on-chain metadata —
//! and renders the fields it verified. A memo that claims to be typed
//! (`"kind":"sw/…"`) but does not parse or verify is a refusal, never a
//! fallback to plain rendering.
//!
//! The covenant itself is not recomputed here (the wallet has no
//! Simplicity compiler); what is bound is the wallet's own money — the
//! fund-template rules cap its outflow at `amount` plus the owned inputs
//! it names — and the terms recorded in the fill's OP_RETURN metadata.

use crate::approval::{OwnedInput, decode_pset};

/// One typed lending claim, parsed from `FundRequest.memo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedFund {
    /// The borrower sells `size` of the collateral for `sale` of `cash`
    /// and may buy it back for `buyback` until block `expiry`; `fee` is
    /// the venue's fill fee, taken from the sale proceeds. `collateral`
    /// is the asset sold (memo field added 2026-09-05; absent = the
    /// policy asset, L-BTC, as every fill was before).
    Fill {
        size: u64,
        sale: u64,
        buyback: u64,
        expiry: u32,
        cash: elements::AssetId,
        collateral: Option<elements::AssetId>,
        fee: u64,
    },
    /// Like `Fill`, for the v2 covenant (one constant program): the wallet
    /// rebuilds the position script from the terms and the pinned program
    /// leaf, so the covenant itself is verified, not just the metadata.
    /// `payout` is the SHA-256 of the lender's payout scriptPubKey.
    FillV2 {
        size: u64,
        sale: u64,
        buyback: u64,
        expiry: u32,
        cash: elements::AssetId,
        collateral: Option<elements::AssetId>,
        fee: u64,
        payout: [u8; 32],
    },
    /// Like `FillV2`, for the v3 covenant: after expiry anyone may sweep
    /// the collateral, but only to the lender's payout script, and that
    /// script must be the CLAIM script of the lender token (so the lender
    /// side is transferable). The wallet checks both.
    FillV3 {
        size: u64,
        sale: u64,
        buyback: u64,
        expiry: u32,
        cash: elements::AssetId,
        collateral: Option<elements::AssetId>,
        fee: u64,
        payout: [u8; 32],
    },
    /// Like `FillV3`, for the v4 covenant: the venue may take a LAST LOOK
    /// from `lastlook_height` — exercise a forgotten in-the-money right on
    /// the borrower's behalf, paying the lender in full; what the venue
    /// pays the borrower is policy. The wallet checks the borrower payout
    /// in the terms is its own token output's script.
    FillV4 {
        size: u64,
        sale: u64,
        buyback: u64,
        expiry: u32,
        cash: elements::AssetId,
        collateral: Option<elements::AssetId>,
        fee: u64,
        payout: [u8; 32],
        lastlook: [u8; 32],
        lastlook_height: u32,
    },
    FillV5 {
        size: u64,
        sale: u64,
        buyback: u64,
        expiry: u32,
        cash: elements::AssetId,
        collateral: Option<elements::AssetId>,
        fee: u64,
        payout: [u8; 32],
        lastlook: [u8; 32],
        lastlook_height: u32,
    },
    /// Like `FillV5`, for a fill drawn from a lender's OFFER coin on chain
    /// (`sw/lend/fill/v6`): the cash comes from an explicit covenant input
    /// and no output carries the lender token, so the memo names it
    /// (`lender_nft`); the wallet still requires the payout to be that
    /// token's claim script and rebuilds the position script with it.
    /// Output 2 is the offer continuing, a leftover, or the fee.
    FillV6 {
        size: u64,
        sale: u64,
        buyback: u64,
        expiry: u32,
        cash: elements::AssetId,
        collateral: Option<elements::AssetId>,
        fee: u64,
        payout: [u8; 32],
        lastlook: [u8; 32],
        lastlook_height: u32,
        lender_nft: elements::AssetId,
    },
    /// The wallet LENDS: it escrows `amounts` (one coin each) of `cash` in
    /// offer covenants with these terms, which any borrower may fill with
    /// its own signature alone. The wallet rebuilds every offer output's
    /// script from the terms and the pinned offer program. On a first post
    /// output `token_output` pays it its lender token — the withdrawal key
    /// of its offers and the claim key of every position it lends on.
    Offer {
        cash: elements::AssetId,
        amounts: Vec<u64>,
        lender_token: elements::AssetId,
        claim: [u8; 32],
        fee_script: [u8; 32],
        position_leaf: [u8; 32],
        fee_min: u64,
        cutoff: u32,
        rows: Vec<OfferRowClaim>,
        token_output: Option<u32>,
    },
    /// The wallet withdraws an offer: owned input 0 is its lender token
    /// (returned at output 0), `amount` of `cash` comes back to it, and it
    /// funds only the network `fee` in the policy asset.
    OfferCancel {
        cash: elements::AssetId,
        amount: u64,
        fee: u64,
        lender_token: elements::AssetId,
    },
    /// The wallet collects what its lending paid to its lender token's
    /// claim script: owned input 0 is the token (returned at output 0), it
    /// receives `receives`, and funds only the network `fee`.
    Claim {
        lender_token: elements::AssetId,
        fee: u64,
        receives: Vec<(elements::AssetId, u64)>,
    },
    /// The borrower sells its buyback right (the position token, owned
    /// input 0) to the dealer for `price` of `cash`, funding only the
    /// network `fee` in the policy asset. The position closes for the
    /// borrower.
    SellRight {
        price: u64,
        cash: elements::AssetId,
        fee: u64,
    },
    /// The borrower pays `amount` of `cash`; `released` of the collateral
    /// comes back; `remaining` is the debt left (0 = full). `collateral`
    /// as for `Fill` (absent = L-BTC).
    Exercise {
        amount: u64,
        released: u64,
        remaining: u64,
        cash: elements::AssetId,
        collateral: Option<elements::AssetId>,
    },
}

/// One quote row of an offer (`sw/lend/offer/v1`), exactly what the offer
/// covenant commits to per row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferRowClaim {
    pub collateral: elements::AssetId,
    pub expiry: u32,
    /// Cash sats the covenant releases per whole unit of collateral (the
    /// sale price plus the lender's venue fee per unit).
    pub price_out: u64,
    pub buyback: u64,
    /// The venue fee per whole unit the covenant demands (both sides).
    pub fee_per_unit: u64,
    pub min_size: u64,
}

/// Recognise a typed lending memo. `None`: not typed — render the memo
/// as text. `Some(Err…)`: claims to be typed but is malformed — refuse.
pub fn parse_typed_fund(memo: &str) -> Option<Result<TypedFund, String>> {
    let value: serde_json::Value = serde_json::from_str(memo.trim()).ok()?;
    let kind = value.get("kind")?.as_str()?;
    if !kind.starts_with("sw/") {
        return None;
    }
    Some(parse_fields(kind, &value))
}

fn parse_fields(kind: &str, value: &serde_json::Value) -> Result<TypedFund, String> {
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
    let asset_field = |name: &str| -> Result<elements::AssetId, String> {
        use std::str::FromStr as _;
        elements::AssetId::from_str(str_field(name)?)
            .map_err(|_| format!("field {name} is not an asset id"))
    };
    // Optional: absent means the policy asset; present but malformed is a refusal.
    let opt_asset_field = |name: &str| -> Result<Option<elements::AssetId>, String> {
        match value.get(name) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(_) => asset_field(name).map(Some),
        }
    };

    match kind {
        "sw/lend/fill/v1" => Ok(TypedFund::Fill {
            size: u64_field("size")?,
            sale: u64_field("sale")?,
            buyback: u64_field("buyback")?,
            expiry: value
                .get("expiry")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                .ok_or("missing or invalid field: expiry")?,
            cash: asset_field("cash")?,
            collateral: opt_asset_field("collateral")?,
            fee: u64_field("fee")?,
        }),
        "sw/lend/fill/v2" => {
            let mut payout = [0u8; 32];
            hex::decode_to_slice(str_field("payout")?, &mut payout).map_err(|_| "payout is not 32 bytes of hex".to_owned())?;
            Ok(TypedFund::FillV2 {
                size: u64_field("size")?,
                sale: u64_field("sale")?,
                buyback: u64_field("buyback")?,
                expiry: value
                    .get("expiry")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("missing or invalid field: expiry")?,
                cash: asset_field("cash")?,
                collateral: opt_asset_field("collateral")?,
                fee: u64_field("fee")?,
                payout,
            })
        }
        "sw/lend/fill/v3" => {
            let mut payout = [0u8; 32];
            hex::decode_to_slice(str_field("payout")?, &mut payout).map_err(|_| "payout is not 32 bytes of hex".to_owned())?;
            Ok(TypedFund::FillV3 {
                size: u64_field("size")?,
                sale: u64_field("sale")?,
                buyback: u64_field("buyback")?,
                expiry: value
                    .get("expiry")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("missing or invalid field: expiry")?,
                cash: asset_field("cash")?,
                collateral: opt_asset_field("collateral")?,
                fee: u64_field("fee")?,
                payout,
            })
        }
        "sw/lend/fill/v4" => {
            let mut payout = [0u8; 32];
            hex::decode_to_slice(str_field("payout")?, &mut payout).map_err(|_| "payout is not 32 bytes of hex".to_owned())?;
            let mut lastlook = [0u8; 32];
            hex::decode_to_slice(str_field("lastlook")?, &mut lastlook).map_err(|_| "lastlook is not 32 bytes of hex".to_owned())?;
            Ok(TypedFund::FillV4 {
                size: u64_field("size")?,
                sale: u64_field("sale")?,
                buyback: u64_field("buyback")?,
                expiry: value
                    .get("expiry")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("missing or invalid field: expiry")?,
                cash: asset_field("cash")?,
                collateral: opt_asset_field("collateral")?,
                fee: u64_field("fee")?,
                payout,
                lastlook,
                lastlook_height: value
                    .get("lastlook_height")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("missing or invalid field: lastlook_height")?,
            })
        }
        "sw/lend/fill/v5" => {
            let mut payout = [0u8; 32];
            hex::decode_to_slice(str_field("payout")?, &mut payout).map_err(|_| "payout is not 32 bytes of hex".to_owned())?;
            let mut lastlook = [0u8; 32];
            hex::decode_to_slice(str_field("lastlook")?, &mut lastlook).map_err(|_| "lastlook is not 32 bytes of hex".to_owned())?;
            Ok(TypedFund::FillV5 {
                size: u64_field("size")?,
                sale: u64_field("sale")?,
                buyback: u64_field("buyback")?,
                expiry: value
                    .get("expiry")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("missing or invalid field: expiry")?,
                cash: asset_field("cash")?,
                collateral: opt_asset_field("collateral")?,
                fee: u64_field("fee")?,
                payout,
                lastlook,
                lastlook_height: value
                    .get("lastlook_height")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("missing or invalid field: lastlook_height")?,
            })
        }
        "sw/lend/fill/v6" => {
            let mut payout = [0u8; 32];
            hex::decode_to_slice(str_field("payout")?, &mut payout).map_err(|_| "payout is not 32 bytes of hex".to_owned())?;
            let mut lastlook = [0u8; 32];
            hex::decode_to_slice(str_field("lastlook")?, &mut lastlook).map_err(|_| "lastlook is not 32 bytes of hex".to_owned())?;
            Ok(TypedFund::FillV6 {
                size: u64_field("size")?,
                sale: u64_field("sale")?,
                buyback: u64_field("buyback")?,
                expiry: value
                    .get("expiry")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("missing or invalid field: expiry")?,
                cash: asset_field("cash")?,
                collateral: opt_asset_field("collateral")?,
                fee: u64_field("fee")?,
                payout,
                lastlook,
                lastlook_height: value
                    .get("lastlook_height")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("missing or invalid field: lastlook_height")?,
                lender_nft: asset_field("lender_nft")?,
            })
        }
        "sw/lend/offer/v1" => {
            let hex32 = |name: &str| -> Result<[u8; 32], String> {
                let mut out = [0u8; 32];
                hex::decode_to_slice(str_field(name)?, &mut out).map_err(|_| format!("{name} is not 32 bytes of hex"))?;
                Ok(out)
            };
            let amounts: Vec<u64> = value
                .get("amounts")
                .and_then(|v| v.as_array())
                .ok_or("missing or invalid field: amounts")?
                .iter()
                .map(|a| a.as_str().and_then(|s| s.parse::<u64>().ok()).ok_or_else(|| "amounts must be u64 strings".to_owned()))
                .collect::<Result<_, _>>()?;
            let rows_json = value.get("rows").and_then(|v| v.as_array()).ok_or("missing or invalid field: rows")?;
            let mut rows = Vec::new();
            for row in rows_json {
                let s = |name: &str| -> Result<&str, String> { row.get(name).and_then(|v| v.as_str()).ok_or_else(|| format!("row field missing or non-string: {name}")) };
                let n = |name: &str| -> Result<u64, String> { s(name)?.parse::<u64>().map_err(|_| format!("row field {name} is not a u64 string")) };
                use std::str::FromStr as _;
                rows.push(OfferRowClaim {
                    collateral: elements::AssetId::from_str(s("collateral")?).map_err(|_| "row collateral is not an asset id".to_owned())?,
                    expiry: row
                        .get("expiry")
                        .and_then(|v| v.as_u64())
                        .and_then(|v| u32::try_from(v).ok())
                        .ok_or("row field missing or invalid: expiry")?,
                    price_out: n("price_out")?,
                    buyback: n("buyback")?,
                    fee_per_unit: n("fee_per_unit")?,
                    min_size: n("min_size")?,
                });
            }
            Ok(TypedFund::Offer {
                cash: asset_field("cash")?,
                amounts,
                lender_token: asset_field("lender_token")?,
                claim: hex32("claim")?,
                fee_script: hex32("fee_script")?,
                position_leaf: hex32("position_leaf")?,
                fee_min: u64_field("fee_min")?,
                cutoff: value
                    .get("cutoff")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("missing or invalid field: cutoff")?,
                rows,
                token_output: match value.get("token_output") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => Some(v.as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("token_output is not an output index")?),
                },
            })
        }
        "sw/lend/offer-cancel/v1" => Ok(TypedFund::OfferCancel {
            cash: asset_field("cash")?,
            amount: u64_field("amount")?,
            fee: u64_field("fee")?,
            lender_token: asset_field("lender_token")?,
        }),
        "sw/lend/claim/v1" => {
            use std::str::FromStr as _;
            let receives = value
                .get("receives")
                .and_then(|v| v.as_array())
                .ok_or("missing or invalid field: receives")?
                .iter()
                .map(|r| {
                    let asset = r.get("asset").and_then(|v| v.as_str()).and_then(|s| elements::AssetId::from_str(s).ok()).ok_or_else(|| "receives: asset is not an asset id".to_owned())?;
                    let amount = r.get("amount").and_then(|v| v.as_str()).and_then(|s| s.parse::<u64>().ok()).ok_or_else(|| "receives: amount is not a u64 string".to_owned())?;
                    Ok((asset, amount))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(TypedFund::Claim {
                lender_token: asset_field("lender_token")?,
                fee: u64_field("fee")?,
                receives,
            })
        }
        "sw/lend/sellright/v1" => Ok(TypedFund::SellRight {
            price: u64_field("price")?,
            cash: asset_field("cash")?,
            fee: u64_field("fee")?,
        }),
        "sw/lend/exercise/v1" => Ok(TypedFund::Exercise {
            amount: u64_field("amount")?,
            released: u64_field("released")?,
            remaining: u64_field("remaining")?,
            cash: asset_field("cash")?,
            collateral: opt_asset_field("collateral")?,
        }),
        other => Err(format!("unknown typed fund kind: {other}")),
    }
}

/// Fill output layout, pinned by the covenant wrapper
/// (`lending_contracts` `SwaptionPosition::attach_fill`).
pub const FILL_POSITION_OUTPUT: usize = 0;
pub const FILL_BORROWER_NFT_OUTPUT: usize = 1;
pub const FILL_LENDER_NFT_OUTPUT: usize = 2;
pub const FILL_METADATA_OUTPUT: usize = 3;
/// Creation metadata: program_id 4 · cash 32 · buyback u64 LE · expiry
/// u32 LE · lender payout script hash 32 = 80 bytes.
pub const METADATA_LEN: usize = 80;

/// What the wallet verified, to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedFundCheck {
    pub claim: TypedFund,
    /// Amount of the policy asset this wallet receives (exercise) or the
    /// cash it receives (fill) — read from the template's own rows.
    pub receives: u64,
}

/// Check a typed claim against the template it describes.
///
/// `asset_id`/`amount` are the fund request's; `policy_asset` the
/// network's L-BTC; `mine` the template output indexes whose scripts the
/// host recognises as its own; `owned` the template inputs the host
/// owns (see `approval::verify_fund_template_owned`, which must have
/// passed first).
pub fn verify_typed_fund(
    claim: &TypedFund,
    template_b64: &str,
    asset_id: &str,
    amount: u64,
    policy_asset: elements::AssetId,
    mine: &[usize],
    owned: &[OwnedInput],
) -> anyhow::Result<TypedFundCheck> {
    use std::str::FromStr as _;
    let requested = elements::AssetId::from_str(asset_id)
        .map_err(|_| anyhow::anyhow!("asset_id is not a 64-hex asset id"))?;
    let pset = decode_pset(template_b64)?;
    let outputs = pset.outputs();

    let explicit = |i: usize| -> anyhow::Result<(elements::AssetId, u64)> {
        let out = outputs
            .get(i)
            .ok_or_else(|| anyhow::anyhow!("template has no output {i}"))?;
        match (out.asset, out.amount) {
            (Some(asset), Some(amount)) => Ok((asset, amount)),
            _ => anyhow::bail!("template output {i} is not explicit"),
        }
    };
    let is_mine = |i: usize| mine.contains(&i);
    let mine_paying = |asset: elements::AssetId| -> Vec<u64> {
        mine.iter()
            .filter_map(|&i| explicit(i).ok())
            .filter(|(a, _)| *a == asset)
            .map(|(_, v)| v)
            .collect()
    };

    match claim {
        TypedFund::Fill {
            size,
            sale,
            buyback,
            expiry,
            cash,
            collateral,
            fee,
        } => {
            let collateral = collateral.unwrap_or(policy_asset);
            anyhow::ensure!(requested == collateral, "fill: the funded asset must be the collateral asset");
            anyhow::ensure!(amount == *size, "fill: stated size {size} does not equal the funded amount {amount}");
            anyhow::ensure!(*buyback > *sale, "fill: buyback must exceed the sale price");

            let (asset, value) = explicit(FILL_POSITION_OUTPUT)?;
            anyhow::ensure!(
                asset == collateral && value == *size,
                "fill: output 0 is not {size} of the collateral asset"
            );
            let (_, nft) = explicit(FILL_BORROWER_NFT_OUTPUT)?;
            anyhow::ensure!(
                nft == 1 && is_mine(FILL_BORROWER_NFT_OUTPUT),
                "fill: output 1 must pay this wallet its position token"
            );

            let meta = outputs
                .get(FILL_METADATA_OUTPUT)
                .and_then(|o| op_return_payload(&o.script_pubkey))
                .ok_or_else(|| anyhow::anyhow!("fill: output 3 is not the creation metadata"))?;
            anyhow::ensure!(meta.len() == METADATA_LEN, "fill: metadata is {} bytes, expected {METADATA_LEN}", meta.len());
            let meta_cash = elements::AssetId::from_slice(&meta[4..36])?;
            let meta_buyback = u64::from_le_bytes(meta[36..44].try_into().expect("8 bytes"));
            let meta_expiry = u32::from_le_bytes(meta[44..48].try_into().expect("4 bytes"));
            anyhow::ensure!(meta_cash == *cash, "fill: metadata names a different cash asset");
            anyhow::ensure!(meta_buyback == *buyback, "fill: metadata buyback {meta_buyback} does not match the claim {buyback}");
            anyhow::ensure!(meta_expiry == *expiry, "fill: metadata expiry {meta_expiry} does not match the claim {expiry}");

            let proceeds = sale
                .checked_sub(*fee)
                .ok_or_else(|| anyhow::anyhow!("fill: fee exceeds the sale price"))?;
            anyhow::ensure!(
                mine_paying(*cash).contains(&proceeds),
                "fill: no output pays this wallet the sale proceeds ({proceeds})"
            );

            Ok(TypedFundCheck {
                claim: claim.clone(),
                receives: proceeds,
            })
        }

        TypedFund::FillV2 {
            size,
            sale,
            buyback,
            expiry,
            cash,
            collateral,
            fee,
            payout,
        } => {
            let collateral = collateral.unwrap_or(policy_asset);
            anyhow::ensure!(requested == collateral, "fill: the funded asset must be the collateral asset");
            anyhow::ensure!(amount == *size, "fill: stated size {size} does not equal the funded amount {amount}");
            anyhow::ensure!(*buyback > *sale, "fill: buyback must exceed the sale price");

            let (asset, value) = explicit(FILL_POSITION_OUTPUT)?;
            anyhow::ensure!(asset == collateral && value == *size, "fill: output 0 is not {size} of the collateral asset");
            let (borrower_nft, nft) = explicit(FILL_BORROWER_NFT_OUTPUT)?;
            anyhow::ensure!(nft == 1 && is_mine(FILL_BORROWER_NFT_OUTPUT), "fill: output 1 must pay this wallet its position token");
            let (lender_nft, nft2) = explicit(FILL_LENDER_NFT_OUTPUT)?;
            anyhow::ensure!(nft2 == 1, "fill: output 2 must be the lender's token");

            // THE covenant check: the position output must be the constant
            // program with exactly these terms and the full debt.
            let digest = v2_terms_digest(collateral, *cash, *size, *buyback, *expiry, borrower_nft, lender_nft, payout);
            let expected = v2_position_script(&digest, *buyback);
            let out0 = outputs.get(FILL_POSITION_OUTPUT).expect("checked above");
            anyhow::ensure!(
                out0.script_pubkey == expected,
                "fill: output 0 is not the lending covenant for the stated terms"
            );

            let proceeds = sale
                .checked_sub(*fee)
                .ok_or_else(|| anyhow::anyhow!("fill: fee exceeds the sale price"))?;
            anyhow::ensure!(mine_paying(*cash).contains(&proceeds), "fill: no output pays this wallet the sale proceeds ({proceeds})");

            Ok(TypedFundCheck {
                claim: claim.clone(),
                receives: proceeds,
            })
        }

        TypedFund::FillV3 {
            size,
            sale,
            buyback,
            expiry,
            cash,
            collateral,
            fee,
            payout,
        } => {
            let collateral = collateral.unwrap_or(policy_asset);
            anyhow::ensure!(requested == collateral, "fill: the funded asset must be the collateral asset");
            anyhow::ensure!(amount == *size, "fill: stated size {size} does not equal the funded amount {amount}");
            anyhow::ensure!(*buyback > *sale, "fill: buyback must exceed the sale price");

            let (asset, value) = explicit(FILL_POSITION_OUTPUT)?;
            anyhow::ensure!(asset == collateral && value == *size, "fill: output 0 is not {size} of the collateral asset");
            let (borrower_nft, nft) = explicit(FILL_BORROWER_NFT_OUTPUT)?;
            anyhow::ensure!(nft == 1 && is_mine(FILL_BORROWER_NFT_OUTPUT), "fill: output 1 must pay this wallet its position token");
            let (lender_nft, nft2) = explicit(FILL_LENDER_NFT_OUTPUT)?;
            anyhow::ensure!(nft2 == 1, "fill: output 2 must be the lender's token");
            // The lender is paid at the claim script of its token, so the
            // lender side is a transferable claim, not a fixed address.
            {
                use elements::hashes::{Hash as _, sha256};
                let claim = sha256::Hash::hash(claim_script(lender_nft).as_bytes()).to_byte_array();
                anyhow::ensure!(claim == *payout, "fill: the lender payout is not the claim script of the lender token");
            }

            // THE covenant check: the position output must be the constant
            // program with exactly these terms and the full debt.
            let digest = v2_terms_digest(collateral, *cash, *size, *buyback, *expiry, borrower_nft, lender_nft, payout);
            let expected = v3_position_script(&digest, *buyback);
            let out0 = outputs.get(FILL_POSITION_OUTPUT).expect("checked above");
            anyhow::ensure!(
                out0.script_pubkey == expected,
                "fill: output 0 is not the lending covenant for the stated terms"
            );

            let proceeds = sale
                .checked_sub(*fee)
                .ok_or_else(|| anyhow::anyhow!("fill: fee exceeds the sale price"))?;
            anyhow::ensure!(mine_paying(*cash).contains(&proceeds), "fill: no output pays this wallet the sale proceeds ({proceeds})");

            Ok(TypedFundCheck {
                claim: claim.clone(),
                receives: proceeds,
            })
        }

        TypedFund::FillV4 {
            size,
            sale,
            buyback,
            expiry,
            cash,
            collateral,
            fee,
            payout,
            lastlook,
            lastlook_height,
        } => {
            let collateral = collateral.unwrap_or(policy_asset);
            anyhow::ensure!(requested == collateral, "fill: the funded asset must be the collateral asset");
            anyhow::ensure!(amount == *size, "fill: stated size {size} does not equal the funded amount {amount}");
            anyhow::ensure!(*buyback > *sale, "fill: buyback must exceed the sale price");

            let (asset, value) = explicit(FILL_POSITION_OUTPUT)?;
            anyhow::ensure!(asset == collateral && value == *size, "fill: output 0 is not {size} of the collateral asset");
            let (borrower_nft, nft) = explicit(FILL_BORROWER_NFT_OUTPUT)?;
            anyhow::ensure!(nft == 1 && is_mine(FILL_BORROWER_NFT_OUTPUT), "fill: output 1 must pay this wallet its position token");
            let (lender_nft, nft2) = explicit(FILL_LENDER_NFT_OUTPUT)?;
            anyhow::ensure!(nft2 == 1, "fill: output 2 must be the lender's token");
            // The lender is paid at the claim script of its token, so the
            // lender side is a transferable claim, not a fixed address.
            {
                use elements::hashes::{Hash as _, sha256};
                let claim = sha256::Hash::hash(claim_script(lender_nft).as_bytes()).to_byte_array();
                anyhow::ensure!(claim == *payout, "fill: the lender payout is not the claim script of the lender token");
            }

            // THE covenant check: the position output must be the constant
            // program with exactly these terms and the full debt.
            // The borrower payout in the terms must be THIS wallet's script: the
            // one its position token goes to (output 1).
            let borrower_script = outputs
                .get(FILL_BORROWER_NFT_OUTPUT)
                .map(|o| o.script_pubkey.clone())
                .ok_or_else(|| anyhow::anyhow!("template has no output 1"))?;
            let borrower_hash = {
                use elements::hashes::{Hash as _, sha256};
                sha256::Hash::hash(borrower_script.as_bytes()).to_byte_array()
            };
            anyhow::ensure!(
                *lastlook_height == 0 || *lastlook_height < *expiry,
                "fill: the last-look height must be before expiry"
            );
            let digest = v4_terms_digest(collateral, *cash, *size, *buyback, *expiry, borrower_nft, lender_nft, payout, &borrower_hash, lastlook, *lastlook_height);
            let expected = v4_position_script(&digest, *buyback);
            let out0 = outputs.get(FILL_POSITION_OUTPUT).expect("checked above");
            anyhow::ensure!(
                out0.script_pubkey == expected,
                "fill: output 0 is not the lending covenant for the stated terms"
            );

            let proceeds = sale
                .checked_sub(*fee)
                .ok_or_else(|| anyhow::anyhow!("fill: fee exceeds the sale price"))?;
            anyhow::ensure!(mine_paying(*cash).contains(&proceeds), "fill: no output pays this wallet the sale proceeds ({proceeds})");

            Ok(TypedFundCheck {
                claim: claim.clone(),
                receives: proceeds,
            })
        }

        TypedFund::FillV5 {
            size,
            sale,
            buyback,
            expiry,
            cash,
            collateral,
            fee,
            payout,
            lastlook,
            lastlook_height,
        } => {
            let collateral = collateral.unwrap_or(policy_asset);
            anyhow::ensure!(requested == collateral, "fill: the funded asset must be the collateral asset");
            anyhow::ensure!(amount == *size, "fill: stated size {size} does not equal the funded amount {amount}");
            anyhow::ensure!(*buyback > *sale, "fill: buyback must exceed the sale price");

            let (asset, value) = explicit(FILL_POSITION_OUTPUT)?;
            anyhow::ensure!(asset == collateral && value == *size, "fill: output 0 is not {size} of the collateral asset");
            let (borrower_nft, nft) = explicit(FILL_BORROWER_NFT_OUTPUT)?;
            anyhow::ensure!(nft == 1 && is_mine(FILL_BORROWER_NFT_OUTPUT), "fill: output 1 must pay this wallet its position token");
            let (lender_nft, nft2) = explicit(FILL_LENDER_NFT_OUTPUT)?;
            anyhow::ensure!(nft2 == 1, "fill: output 2 must be the lender's token");
            // The lender is paid at the claim script of its token, so the
            // lender side is a transferable claim, not a fixed address.
            {
                use elements::hashes::{Hash as _, sha256};
                let claim = sha256::Hash::hash(claim_script(lender_nft).as_bytes()).to_byte_array();
                anyhow::ensure!(claim == *payout, "fill: the lender payout is not the claim script of the lender token");
            }

            // THE covenant check: the position output must be the constant
            // program with exactly these terms and the full debt.
            // The borrower payout in the terms must be THIS wallet's script: the
            // one its position token goes to (output 1).
            let borrower_script = outputs
                .get(FILL_BORROWER_NFT_OUTPUT)
                .map(|o| o.script_pubkey.clone())
                .ok_or_else(|| anyhow::anyhow!("template has no output 1"))?;
            let borrower_hash = {
                use elements::hashes::{Hash as _, sha256};
                sha256::Hash::hash(borrower_script.as_bytes()).to_byte_array()
            };
            anyhow::ensure!(
                *lastlook_height == 0 || *lastlook_height < *expiry,
                "fill: the last-look height must be before expiry"
            );
            let digest = v5_terms_digest(collateral, *cash, *size, *buyback, *expiry, borrower_nft, lender_nft, payout, &borrower_hash, lastlook, *lastlook_height);
            let expected = v5_position_script(&digest, *buyback);
            let out0 = outputs.get(FILL_POSITION_OUTPUT).expect("checked above");
            anyhow::ensure!(
                out0.script_pubkey == expected,
                "fill: output 0 is not the lending covenant for the stated terms"
            );

            let proceeds = sale
                .checked_sub(*fee)
                .ok_or_else(|| anyhow::anyhow!("fill: fee exceeds the sale price"))?;
            anyhow::ensure!(mine_paying(*cash).contains(&proceeds), "fill: no output pays this wallet the sale proceeds ({proceeds})");

            Ok(TypedFundCheck {
                claim: claim.clone(),
                receives: proceeds,
            })
        }

        TypedFund::FillV6 {
            size,
            sale,
            buyback,
            expiry,
            cash,
            collateral,
            fee,
            payout,
            lastlook,
            lastlook_height,
            lender_nft,
        } => {
            let collateral = collateral.unwrap_or(policy_asset);
            anyhow::ensure!(requested == collateral, "fill: the funded asset must be the collateral asset");
            anyhow::ensure!(amount == *size, "fill: stated size {size} does not equal the funded amount {amount}");
            anyhow::ensure!(*buyback > *sale, "fill: buyback must exceed the sale price");

            let (asset, value) = explicit(FILL_POSITION_OUTPUT)?;
            anyhow::ensure!(asset == collateral && value == *size, "fill: output 0 is not {size} of the collateral asset");
            let (borrower_nft, nft) = explicit(FILL_BORROWER_NFT_OUTPUT)?;
            anyhow::ensure!(nft == 1 && is_mine(FILL_BORROWER_NFT_OUTPUT), "fill: output 1 must pay this wallet its position token");
            // No lender token output: the offer's token is named in the memo,
            // and the lender must be paid at that token's claim script.
            {
                use elements::hashes::{Hash as _, sha256};
                let claim = sha256::Hash::hash(claim_script(*lender_nft).as_bytes()).to_byte_array();
                anyhow::ensure!(claim == *payout, "fill: the lender payout is not the claim script of the lender token");
            }
            let borrower_script = outputs
                .get(FILL_BORROWER_NFT_OUTPUT)
                .map(|o| o.script_pubkey.clone())
                .ok_or_else(|| anyhow::anyhow!("template has no output 1"))?;
            let borrower_hash = {
                use elements::hashes::{Hash as _, sha256};
                sha256::Hash::hash(borrower_script.as_bytes()).to_byte_array()
            };
            anyhow::ensure!(*lastlook_height == 0 || *lastlook_height < *expiry, "fill: the last-look height must be before expiry");
            let digest = v5_terms_digest(collateral, *cash, *size, *buyback, *expiry, borrower_nft, *lender_nft, payout, &borrower_hash, lastlook, *lastlook_height);
            let expected = v5_position_script(&digest, *buyback);
            let out0 = outputs.get(FILL_POSITION_OUTPUT).expect("checked above");
            anyhow::ensure!(out0.script_pubkey == expected, "fill: output 0 is not the lending covenant for the stated terms");

            let proceeds = sale
                .checked_sub(*fee)
                .ok_or_else(|| anyhow::anyhow!("fill: fee exceeds the sale price"))?;
            anyhow::ensure!(mine_paying(*cash).contains(&proceeds), "fill: no output pays this wallet the sale proceeds ({proceeds})");

            Ok(TypedFundCheck {
                claim: claim.clone(),
                receives: proceeds,
            })
        }

        TypedFund::Offer {
            cash,
            amounts,
            lender_token,
            claim: claim_hash,
            fee_script,
            position_leaf,
            fee_min,
            cutoff,
            rows,
            token_output,
        } => {
            anyhow::ensure!(requested == *cash, "offer: the funded asset must be the cash asset");
            anyhow::ensure!(!amounts.is_empty() && amounts.len() <= 4, "offer: one to four coins");
            let total: u64 = amounts.iter().try_fold(0u64, |acc, a| acc.checked_add(*a)).ok_or_else(|| anyhow::anyhow!("offer: amounts overflow"))?;
            anyhow::ensure!(amount == total, "offer: stated amounts ({total}) do not equal the funded amount {amount}");
            anyhow::ensure!(!rows.is_empty() && rows.len() <= 4, "offer: one to four rows");
            for r in rows {
                anyhow::ensure!(r.expiry > 0 && r.price_out > 0 && r.buyback > 0 && r.min_size > 0, "offer: a row with a zero term");
            }
            // The offer may only create the position program this wallet
            // knows, and must pay this wallet's token's claim script.
            anyhow::ensure!(*position_leaf == SWAPTION_LENDING_V5_LEAF, "offer: the position program is not the one this wallet verifies");
            {
                use elements::hashes::{Hash as _, sha256};
                let expected = sha256::Hash::hash(claim_script(*lender_token).as_bytes()).to_byte_array();
                anyhow::ensure!(*claim_hash == expected, "offer: the claim script is not the lender token's");
            }
            let digest = offer_terms_digest(*cash, *lender_token, claim_hash, fee_script, position_leaf, *fee_min, *cutoff, rows);
            for (i, a) in amounts.iter().enumerate() {
                let (asset, value) = explicit(i)?;
                anyhow::ensure!(asset == *cash && value == *a, "offer: output {i} is not {a} of the cash asset");
                let expected = offer_script(&digest, *a);
                let out = outputs.get(i).expect("checked above");
                anyhow::ensure!(out.script_pubkey == expected, "offer: output {i} is not the offer covenant for the stated terms");
            }
            if let Some(t) = token_output {
                let t = *t as usize;
                let (asset, value) = explicit(t)?;
                anyhow::ensure!(asset == *lender_token && value == 1 && is_mine(t), "offer: output {t} must pay this wallet its lender token");
            }
            Ok(TypedFundCheck {
                claim: claim.clone(),
                receives: 0,
            })
        }

        TypedFund::OfferCancel {
            cash,
            amount: back,
            fee,
            lender_token,
        } => {
            let token = owned
                .iter()
                .find(|o| o.index == 0)
                .ok_or_else(|| anyhow::anyhow!("offer cancel: input 0 must be this wallet's lender token"))?;
            anyhow::ensure!(token.amount == 1 && token.asset == *lender_token, "offer cancel: input 0 is not the lender token");
            anyhow::ensure!(requested == policy_asset && amount == *fee, "offer cancel: the wallet funds only the network fee ({fee}), stated amount {amount}");
            anyhow::ensure!(*fee <= 5_000, "offer cancel: network fee {fee} is unreasonable");
            let (a0, v0) = explicit(0)?;
            anyhow::ensure!(a0 == *lender_token && v0 == 1 && is_mine(0), "offer cancel: output 0 must return the lender token to this wallet");
            let got = mine_paying(*cash)
                .into_iter()
                .filter(|v| *v >= *back)
                .max()
                .ok_or_else(|| anyhow::anyhow!("offer cancel: no output pays this wallet at least {back} of cash"))?;
            Ok(TypedFundCheck {
                claim: claim.clone(),
                receives: got,
            })
        }

        TypedFund::Claim { lender_token, fee, receives } => {
            let token = owned
                .iter()
                .find(|o| o.index == 0)
                .ok_or_else(|| anyhow::anyhow!("claim: input 0 must be this wallet's lender token"))?;
            anyhow::ensure!(token.amount == 1 && token.asset == *lender_token, "claim: input 0 is not the lender token");
            anyhow::ensure!(requested == policy_asset && amount == *fee, "claim: the wallet funds only the network fee ({fee}), stated amount {amount}");
            anyhow::ensure!(*fee <= 20_000, "claim: network fee {fee} is unreasonable");
            anyhow::ensure!(!receives.is_empty(), "claim: nothing received");
            let (a0, v0) = explicit(0)?;
            anyhow::ensure!(a0 == *lender_token && v0 == 1 && is_mine(0), "claim: output 0 must return the lender token to this wallet");
            for (asset, amt) in receives {
                anyhow::ensure!(
                    mine_paying(*asset).into_iter().any(|v| v >= *amt),
                    "claim: no output pays this wallet at least {amt} of {asset}"
                );
            }
            Ok(TypedFundCheck {
                claim: claim.clone(),
                receives: receives.first().map(|(_, a)| *a).unwrap_or(0),
            })
        }

        TypedFund::SellRight { price, cash, fee } => {
            let token = owned
                .iter()
                .find(|o| o.index == 0)
                .ok_or_else(|| anyhow::anyhow!("sell right: input 0 must be this wallet's position token"))?;
            anyhow::ensure!(token.amount == 1, "sell right: input 0 is not a one-unit token");
            anyhow::ensure!(
                requested == policy_asset && amount == *fee,
                "sell right: the wallet funds only the network fee ({fee}), stated amount {amount}"
            );
            anyhow::ensure!(*fee <= 5_000, "sell right: network fee {fee} is unreasonable");
            anyhow::ensure!(*price > 0, "sell right: price must be positive");
            let got = mine_paying(*cash)
                .into_iter()
                .filter(|v| *v >= *price)
                .max()
                .ok_or_else(|| anyhow::anyhow!("sell right: no output pays this wallet at least {price} of cash"))?;
            Ok(TypedFundCheck {
                claim: claim.clone(),
                receives: got,
            })
        }

        TypedFund::Exercise {
            amount: pay,
            released,
            remaining,
            cash,
            collateral,
        } => {
            let collateral = collateral.unwrap_or(policy_asset);
            anyhow::ensure!(requested == *cash, "exercise: the funded asset must be the cash asset");
            anyhow::ensure!(amount == *pay, "exercise: stated amount {pay} does not equal the funded amount {amount}");

            let token = owned
                .iter()
                .find(|o| o.index == 0)
                .ok_or_else(|| anyhow::anyhow!("exercise: input 0 must be this wallet's position token"))?;
            anyhow::ensure!(token.amount == 1, "exercise: input 0 is not a one-unit token");

            if *remaining > 0 {
                let (asset, value) = explicit(0)?;
                let burned = outputs
                    .get(0)
                    .map(|o| op_return_payload(&o.script_pubkey).is_some())
                    .unwrap_or(true);
                anyhow::ensure!(
                    asset == token.asset && value == 1 && is_mine(0) && !burned,
                    "exercise: output 0 must return the position token to this wallet"
                );
                let (asset, _) = explicit(1)?;
                anyhow::ensure!(asset == collateral, "exercise: output 1 must be the continuing position");
            } else {
                let out = outputs.get(0).ok_or_else(|| anyhow::anyhow!("template has no output 0"))?;
                anyhow::ensure!(
                    op_return_payload(&out.script_pubkey).is_some() && out.asset == Some(token.asset),
                    "exercise: a full buyback must burn the position token at output 0"
                );
            }

            let got = mine_paying(collateral)
                .into_iter()
                .filter(|v| *v >= *released)
                .max()
                .ok_or_else(|| anyhow::anyhow!("exercise: no output pays this wallet at least {released} of collateral"))?;

            Ok(TypedFundCheck {
                claim: claim.clone(),
                receives: got,
            })
        }
    }
}

/// Tapleaf hash of the constant v2 lending program (`swaption_lending_v2.simf`
/// in rf-swaption_be `lending_contracts`, Simplicity leaf version 0xbe).
/// Pinned: a new program is a new product, not a silent upgrade.
pub const SWAPTION_LENDING_V2_LEAF: [u8; 32] = hex_literal::hex!("41d218d4f2b492a9afb9e179ab76cd5d96a4977d2d266d558f7dd87c7df4522c");

/// Tapleaf hash of the constant v3 lending program (`swaption_lending_v3.simf`):
/// v2 with a permissionless lapse that must pay the lender's payout script.
pub const SWAPTION_LENDING_V3_LEAF: [u8; 32] = hex_literal::hex!("880d441e2d854331fd1d5c48afac9fd8b705c5c001f48587325820dc10ee73a8");

/// Tapleaf hash of the constant v4 lending program (`swaption_lending_v4.simf`):
/// v3 plus the venue's last look before expiry.
pub const SWAPTION_LENDING_V4_LEAF: [u8; 32] = hex_literal::hex!("939c233fc8ebbd59cce2ec10ef7bbf681dd933fa6431e4d58dc013b728d9ef1a");

/// Tapleaf hash of the constant v5 lending program (`swaption_lending_v5.simf`,
/// source and regtest suite: https://github.com/liquidconnect/swaption-covenants):
/// v4 plus a PARTIAL last look (the venue may take a position off in rounds).
pub const SWAPTION_LENDING_V5_LEAF: [u8; 32] = hex_literal::hex!("da43157b075c4c18c1f7354ada37455fdfbd7eb481d6762a9f1843896d659725");

/// Tapleaf hash of the constant claim program (`swaption_claim.simf` in
/// https://github.com/liquidconnect/swaption-covenants): a
/// coin spendable by whoever spends one unit of the lender token as input 0.
pub const SWAPTION_CLAIM_LEAF: [u8; 32] = hex_literal::hex!("51f916310d382610bf7efd7b345d9641b3dc93917d2afb77289add911f3403e1");

/// Tapleaf hash of the constant offer program (`swaption_offer.simf` in
/// https://github.com/liquidconnect/swaption-covenants): a
/// lender's cash escrowed at post time, fillable by any borrower alone;
/// slot 0 the terms digest, slot 1 the remaining cash (the position tree).
pub const SWAPTION_OFFER_LEAF: [u8; 32] = hex_literal::hex!("881b1416b04e9fb47b6ecde9701880470713c37b5b99388da973d4e0d508f41f");

/// SHA-256 over an offer's terms in the covenant's witness order (integers
/// big-endian, four rows, unused rows all zero) — what its slot 0 holds.
#[allow(clippy::too_many_arguments)]
pub fn offer_terms_digest(
    cash: elements::AssetId,
    lender_token: elements::AssetId,
    claim_script_hash: &[u8; 32],
    fee_script_hash: &[u8; 32],
    position_leaf: &[u8; 32],
    fee_min: u64,
    cutoff_height: u32,
    rows: &[OfferRowClaim],
) -> [u8; 32] {
    use elements::hashes::{Hash as _, sha256};
    let mut m = Vec::with_capacity(32 * 5 + 12 + 4 * 68);
    m.extend_from_slice(&cash.into_inner().0);
    m.extend_from_slice(&lender_token.into_inner().0);
    m.extend_from_slice(claim_script_hash);
    m.extend_from_slice(fee_script_hash);
    m.extend_from_slice(position_leaf);
    m.extend_from_slice(&fee_min.to_be_bytes());
    m.extend_from_slice(&cutoff_height.to_be_bytes());
    for i in 0..4 {
        match rows.get(i) {
            Some(r) => {
                m.extend_from_slice(&r.collateral.into_inner().0);
                m.extend_from_slice(&r.expiry.to_be_bytes());
                m.extend_from_slice(&r.price_out.to_be_bytes());
                m.extend_from_slice(&r.buyback.to_be_bytes());
                m.extend_from_slice(&r.fee_per_unit.to_be_bytes());
                m.extend_from_slice(&r.min_size.to_be_bytes());
            }
            None => m.extend_from_slice(&[0u8; 68]),
        }
    }
    sha256::Hash::hash(&m).to_byte_array()
}

/// The offer scriptPubKey for a terms digest and the remaining cash: the
/// same three-leaf tree as a position, under the offer program.
pub fn offer_script(digest: &[u8; 32], remaining: u64) -> elements::Script {
    position_script(SWAPTION_OFFER_LEAF, digest, remaining)
}

/// SHA-256 over the terms in the covenant's witness order, integers
/// big-endian — what storage slot 0 holds.
#[allow(clippy::too_many_arguments)]
pub fn v2_terms_digest(
    collateral: elements::AssetId,
    cash: elements::AssetId,
    collateral_amount: u64,
    buyback_amount: u64,
    expiry_height: u32,
    borrower_nft: elements::AssetId,
    lender_nft: elements::AssetId,
    payout_script_hash: &[u8; 32],
) -> [u8; 32] {
    use elements::hashes::{Hash as _, sha256};
    let mut m = Vec::with_capacity(32 * 5 + 20);
    m.extend_from_slice(&collateral.into_inner().0);
    m.extend_from_slice(&cash.into_inner().0);
    m.extend_from_slice(&collateral_amount.to_be_bytes());
    m.extend_from_slice(&buyback_amount.to_be_bytes());
    m.extend_from_slice(&expiry_height.to_be_bytes());
    m.extend_from_slice(&borrower_nft.into_inner().0);
    m.extend_from_slice(&lender_nft.into_inner().0);
    m.extend_from_slice(payout_script_hash);
    sha256::Hash::hash(&m).to_byte_array()
}

/// The v4 terms digest: the v2/v3 preimage followed by the borrower
/// payout script hash, the last-look script hash and the last-look height.
#[allow(clippy::too_many_arguments)]
pub fn v4_terms_digest(
    collateral: elements::AssetId,
    cash: elements::AssetId,
    collateral_amount: u64,
    buyback_amount: u64,
    expiry_height: u32,
    borrower_nft: elements::AssetId,
    lender_nft: elements::AssetId,
    payout_script_hash: &[u8; 32],
    borrower_payout_script_hash: &[u8; 32],
    last_look_script_hash: &[u8; 32],
    last_look_height: u32,
) -> [u8; 32] {
    use elements::hashes::{Hash as _, sha256};
    let mut m = Vec::with_capacity(32 * 7 + 24);
    m.extend_from_slice(&collateral.into_inner().0);
    m.extend_from_slice(&cash.into_inner().0);
    m.extend_from_slice(&collateral_amount.to_be_bytes());
    m.extend_from_slice(&buyback_amount.to_be_bytes());
    m.extend_from_slice(&expiry_height.to_be_bytes());
    m.extend_from_slice(&borrower_nft.into_inner().0);
    m.extend_from_slice(&lender_nft.into_inner().0);
    m.extend_from_slice(payout_script_hash);
    m.extend_from_slice(borrower_payout_script_hash);
    m.extend_from_slice(last_look_script_hash);
    m.extend_from_slice(&last_look_height.to_be_bytes());
    sha256::Hash::hash(&m).to_byte_array()
}

/// The v4 position scriptPubKey for a terms digest and a remaining debt.
pub fn v4_position_script(digest: &[u8; 32], remaining_debt: u64) -> elements::Script {
    position_script(SWAPTION_LENDING_V4_LEAF, digest, remaining_debt)
}

/// The v5 position scriptPubKey for a terms digest and a remaining debt.
pub fn v5_position_script(digest: &[u8; 32], remaining_debt: u64) -> elements::Script {
    position_script(SWAPTION_LENDING_V5_LEAF, digest, remaining_debt)
}

/// v5 commits to exactly the v4 terms (same digest preimage).
#[allow(clippy::too_many_arguments)]
pub fn v5_terms_digest(
    collateral: elements::AssetId,
    cash: elements::AssetId,
    collateral_amount: u64,
    buyback_amount: u64,
    expiry_height: u32,
    borrower_nft: elements::AssetId,
    lender_nft: elements::AssetId,
    payout_script_hash: &[u8; 32],
    borrower_payout_script_hash: &[u8; 32],
    last_look_script_hash: &[u8; 32],
    last_look_height: u32,
) -> [u8; 32] {
    v4_terms_digest(collateral, cash, collateral_amount, buyback_amount, expiry_height, borrower_nft, lender_nft, payout_script_hash, borrower_payout_script_hash, last_look_script_hash, last_look_height)
}

/// The v2 position scriptPubKey for a terms digest and a remaining debt.
pub fn v2_position_script(digest: &[u8; 32], remaining_debt: u64) -> elements::Script {
    position_script(SWAPTION_LENDING_V2_LEAF, digest, remaining_debt)
}

/// The v3 position scriptPubKey for a terms digest and a remaining debt.
pub fn v3_position_script(digest: &[u8; 32], remaining_debt: u64) -> elements::Script {
    position_script(SWAPTION_LENDING_V3_LEAF, digest, remaining_debt)
}

/// A position scriptPubKey from hashes alone: taproot tree
/// branch(branch(program, digest), debt) over the NUMS key, exactly as
/// the covenant recomputes it.
pub fn position_script(program_leaf: [u8; 32], digest: &[u8; 32], remaining_debt: u64) -> elements::Script {
    let mut debt_slot = [0u8; 32];
    debt_slot[24..32].copy_from_slice(&remaining_debt.to_be_bytes());
    let node = tap_branch(
        tap_branch(program_leaf, tap_tagged(b"TapData", &[digest])),
        tap_tagged(b"TapData", &[&debt_slot]),
    );
    nums_script(node)
}

/// The claim scriptPubKey of a lender token: tree branch(claim program,
/// token) over the NUMS key. Exercise cash and lapsed collateral of a v3
/// position are paid here, so whoever holds the token owns the claim.
pub fn claim_script(lender_nft: elements::AssetId) -> elements::Script {
    let node = tap_branch(SWAPTION_CLAIM_LEAF, tap_tagged(b"TapData", &[&lender_nft.into_inner().0]));
    nums_script(node)
}

fn tap_tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use elements::hashes::{Hash as _, HashEngine as _, sha256};
    let t = sha256::Hash::hash(tag);
    let mut e = sha256::Hash::engine();
    e.input(t.as_ref());
    e.input(t.as_ref());
    for p in parts {
        e.input(p);
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

fn tap_branch(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let (l, r) = if a <= b { (a, b) } else { (b, a) };
    tap_tagged(b"TapBranch/elements", &[&l, &r])
}

fn nums_script(node: [u8; 32]) -> elements::Script {
    use elements::hashes::Hash as _;
    use elements::secp256k1_zkp::{SECP256K1, XOnlyPublicKey};
    use elements::taproot::{TapNodeHash, TapTweakHash};
    let nums = XOnlyPublicKey::from_slice(&hex_literal::hex!(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    ))
    .expect("nums");
    let tweak = TapTweakHash::from_key_and_tweak(nums, Some(TapNodeHash::from_byte_array(node)));
    let (key, _) = nums.add_tweak(SECP256K1, &tweak.to_scalar()).expect("tweak");
    elements::script::Builder::new()
        .push_opcode(elements::opcodes::all::OP_PUSHNUM_1)
        .push_slice(&key.serialize())
        .into_script()
}

/// Payload of an OP_RETURN script (`OP_RETURN <push>`), if it is one.
pub fn op_return_payload(script: &elements::Script) -> Option<&[u8]> {
    let b = script.as_bytes();
    if b.first() != Some(&0x6a) {
        return None;
    }
    match b.get(1)? {
        n @ 1..=75 => {
            let n = *n as usize;
            (b.len() == 2 + n).then(|| &b[2..])
        }
        0x4c => {
            let n = *b.get(2)? as usize;
            (b.len() == 3 + n).then(|| &b[3..])
        }
        _ => None,
    }
}

impl TypedFund {
    /// Text for the approval dialog, from the verified fields, for a
    /// claim whose collateral is L-BTC (shown as BTC). Prefer
    /// `render_with`, which names the collateral: since 2026-09-05 a
    /// position may hold USDt or DePix instead.
    pub fn render(&self, cash_symbol: &str) -> String {
        self.render_with("BTC", cash_symbol)
    }

    /// The collateral the claim names, if it names one (absent = the
    /// policy asset, L-BTC).
    pub fn collateral(&self) -> Option<elements::AssetId> {
        match self {
            TypedFund::Fill { collateral, .. }
            | TypedFund::FillV2 { collateral, .. }
            | TypedFund::FillV3 { collateral, .. }
            | TypedFund::FillV4 { collateral, .. }
            | TypedFund::FillV5 { collateral, .. }
            | TypedFund::FillV6 { collateral, .. }
            | TypedFund::Exercise { collateral, .. } => *collateral,
            // An offer's rows may name several collaterals; the host
            // renders them by the first row (`Offer` rows carry the ids).
            TypedFund::Offer { rows, .. } => rows.first().map(|r| r.collateral),
            TypedFund::SellRight { .. } | TypedFund::OfferCancel { .. } | TypedFund::Claim { .. } => None,
        }
    }

    /// Text for the approval dialog, from the verified fields.
    pub fn render_with(&self, collateral_symbol: &str, cash_symbol: &str) -> String {
        match self {
            TypedFund::Fill {
                size,
                sale,
                buyback,
                expiry,
                fee,
                ..
            } => format!(
                "Sell {} {collateral_symbol} for {} {cash_symbol} · buy back for {} {cash_symbol} until block {} · fee {} {cash_symbol}",
                fmt8(*size),
                fmt8(*sale),
                fmt8(*buyback),
                expiry,
                fmt8(*fee)
            ),
            TypedFund::FillV2 {
                size,
                sale,
                buyback,
                expiry,
                fee,
                ..
            } => format!(
                "Sell {} {collateral_symbol} for {} {cash_symbol} · buy back for {} {cash_symbol} until block {} · fee {} {cash_symbol}",
                fmt8(*size),
                fmt8(*sale),
                fmt8(*buyback),
                expiry,
                fmt8(*fee)
            ),
            TypedFund::FillV3 {
                size,
                sale,
                buyback,
                expiry,
                fee,
                ..
            } => format!(
                "Sell {} {collateral_symbol} for {} {cash_symbol} · buy back for {} {cash_symbol} until block {} · fee {} {cash_symbol}",
                fmt8(*size),
                fmt8(*sale),
                fmt8(*buyback),
                expiry,
                fmt8(*fee)
            ),
            TypedFund::FillV4 {
                size,
                sale,
                buyback,
                expiry,
                fee,
                lastlook_height,
                ..
            } => format!(
                "Sell {} {collateral_symbol} for {} {cash_symbol} · buy back for {} {cash_symbol} until block {} · fee {} {cash_symbol} · from block {} Swaption may exercise an unused in-the-money right for you and pay you the surplus less its fee",
                fmt8(*size),
                fmt8(*sale),
                fmt8(*buyback),
                expiry,
                fmt8(*fee),
                lastlook_height
            ),
            TypedFund::FillV5 {
                size,
                sale,
                buyback,
                expiry,
                fee,
                lastlook_height,
                ..
            } => format!(
                "Sell {} {collateral_symbol} for {} {cash_symbol} · buy back for {} {cash_symbol} until block {} · fee {} {cash_symbol} · from block {} Swaption may exercise an unused in-the-money right for you and pay you the surplus less its fee",
                fmt8(*size),
                fmt8(*sale),
                fmt8(*buyback),
                expiry,
                fmt8(*fee),
                lastlook_height
            ),
            TypedFund::FillV6 {
                size,
                sale,
                buyback,
                expiry,
                fee,
                lastlook_height,
                ..
            } => format!(
                "Sell {} {collateral_symbol} for {} {cash_symbol} · buy back for {} {cash_symbol} until block {} · fee {} {cash_symbol} · from block {} Swaption may exercise an unused in-the-money right for you and pay you the surplus less its fee · the cash comes from a lender's offer on chain",
                fmt8(*size),
                fmt8(*sale),
                fmt8(*buyback),
                expiry,
                fmt8(*fee),
                lastlook_height
            ),
            TypedFund::Offer {
                amounts,
                rows,
                cutoff,
                token_output,
                ..
            } => {
                let total: u64 = amounts.iter().sum();
                let rows_text: Vec<String> = rows
                    .iter()
                    .map(|r| {
                        format!(
                            "pay up to {} {cash_symbol} per {collateral_symbol} (Swaption's fee included) with buyback at {} {cash_symbol} until block {}",
                            fmt8(r.price_out),
                            fmt8(r.buyback),
                            r.expiry
                        )
                    })
                    .collect();
                let coins = if amounts.len() > 1 { format!(" in {} coins", amounts.len()) } else { String::new() };
                let token = if token_output.is_some() { " · you receive your lender token: it withdraws your offers and collects what your lending pays, keep it" } else { "" };
                format!(
                    "Lend {} {cash_symbol} on chain{coins}: {} · anyone may fill it with no further approval from you · withdraw any time; after block {} it returns to your claim{token}",
                    fmt8(total),
                    rows_text.join("; "),
                    cutoff
                )
            }
            TypedFund::OfferCancel { amount, fee, .. } => format!(
                "Withdraw your lend offer: {} {cash_symbol} back to this wallet · you pay the {} sat network fee",
                fmt8(*amount),
                fee
            ),
            TypedFund::Claim { fee, receives, .. } => format!(
                "Collect what your lending paid into this wallet ({} coin{}) · you pay the {} sat network fee",
                receives.len(),
                if receives.len() == 1 { "" } else { "s" },
                fee
            ),
            TypedFund::SellRight { price, fee, .. } => format!(
                "Sell your buyback right for {} {cash_symbol} · you pay the {} sat network fee · the position closes for you",
                fmt8(*price),
                fee
            ),
            TypedFund::Exercise {
                amount,
                released,
                remaining,
                ..
            } => {
                let tail = if *remaining > 0 {
                    format!("{} {cash_symbol} still owed after", fmt8(*remaining))
                } else {
                    "position closed".to_owned()
                };
                format!(
                    "Buy back {} {collateral_symbol} for {} {cash_symbol} · {tail}",
                    fmt8(*released),
                    fmt8(*amount)
                )
            }
        }
    }

    pub fn cash(&self) -> elements::AssetId {
        match self {
            TypedFund::Fill { cash, .. }
            | TypedFund::FillV2 { cash, .. }
            | TypedFund::FillV3 { cash, .. }
            | TypedFund::FillV4 { cash, .. }
            | TypedFund::FillV5 { cash, .. }
            | TypedFund::FillV6 { cash, .. }
            | TypedFund::Offer { cash, .. }
            | TypedFund::OfferCancel { cash, .. }
            | TypedFund::SellRight { cash, .. }
            | TypedFund::Exercise { cash, .. } => *cash,
            // A collection may carry several assets; the first is what the host names.
            TypedFund::Claim { receives, lender_token, .. } => receives.first().map(|(a, _)| *a).unwrap_or(*lender_token),
        }
    }
}

/// 8-decimal satoshi formatting with trailing zeros trimmed: 50000000 → "0.5".
pub fn fmt8(sats: u64) -> String {
    let whole = sats / 100_000_000;
    let frac = sats % 100_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let s = format!("{whole}.{frac:08}");
    s.trim_end_matches('0').to_owned()
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

    fn txout(asset: &str, value: u64, script: Script) -> TxOut {
        TxOut {
            asset: Asset::Explicit(AssetId::from_str(asset).unwrap()),
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
    fn metadata(cash: &str, buyback: u64, expiry: u32) -> Script {
        let mut m = vec![1u8, 2, 3, 4];
        m.extend_from_slice(&AssetId::from_str(cash).unwrap().into_inner().0);
        m.extend_from_slice(&buyback.to_le_bytes());
        m.extend_from_slice(&expiry.to_le_bytes());
        m.extend_from_slice(&[9u8; 32]);
        assert_eq!(m.len(), 80);
        let mut s = vec![0x6a, 0x4c, 80];
        s.extend_from_slice(&m);
        Script::from(s)
    }

    /// A fill template as the RP builds it: dealer cash in, position out,
    /// NFTs out, metadata, proceeds to the borrower, dealer change, fee.
    fn fill_template() -> pset::PartiallySignedTransaction {
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        let mut cash_in = pset::Input::from_prevout(elements::OutPoint::new(
            elements::Txid::from_str(&"11".repeat(32)).unwrap(),
            0,
        ));
        cash_in.witness_utxo = Some(txout(USDT, 40_000_00000000, spk(0xaa)));
        tx.add_input(cash_in);
        let mut fee_in = pset::Input::from_prevout(elements::OutPoint::new(
            elements::Txid::from_str(&"12".repeat(32)).unwrap(),
            0,
        ));
        fee_in.witness_utxo = Some(txout(LBTC, 1_000, spk(0xab)));
        tx.add_input(fee_in);
        tx.add_output(pset::Output::from_txout(txout(LBTC, 50_000_000, spk(0xc0)))); // 0 position
        tx.add_output(pset::Output::from_txout(txout(NFT, 1, spk(0x01)))); // 1 borrower NFT → mine
        tx.add_output(pset::Output::from_txout(txout(NFT, 1, spk(0xaa)))); // 2 lender NFT
        let mut meta = pset::Output::from_txout(txout(LBTC, 0, metadata(USDT, 31_000_00000000, 3_200_000)));
        meta.amount = Some(0);
        tx.add_output(meta); // 3 metadata
        tx.add_output(pset::Output::from_txout(txout(USDT, 29_970_00000000, spk(0x01)))); // 4 proceeds → mine
        tx.add_output(pset::Output::from_txout(txout(USDT, 10_030_00000000, spk(0xaa)))); // 5 dealer change
        tx.add_output(pset::Output::from_txout(txout(LBTC, 1_000, Script::new()))); // 6 fee
        tx
    }

    fn fill_claim() -> String {
        format!(
            r#"{{"kind":"sw/lend/fill/v1","size":"50000000","sale":"3000000000000","buyback":"3100000000000","expiry":3200000,"cash":"{USDT}","fee":"3000000000"}}"#
        )
    }

    #[test]
    fn fill_claim_verifies_against_its_template_and_renders() {
        let claim = parse_typed_fund(&fill_claim()).unwrap().unwrap();
        let check = verify_typed_fund(
            &claim,
            &b64(&fill_template()),
            LBTC,
            50_000_000,
            AssetId::from_str(LBTC).unwrap(),
            &[1, 4],
            &[],
        )
        .unwrap();
        assert_eq!(check.receives, 29_970_00000000);
        assert_eq!(
            claim.render("USDt"),
            "Sell 0.5 BTC for 30000 USDt · buy back for 31000 USDt until block 3200000 · fee 30 USDt"
        );
    }

    #[test]
    fn fill_claim_is_refused_when_metadata_or_proceeds_disagree() {
        let claim = parse_typed_fund(&fill_claim()).unwrap().unwrap();
        let lbtc = AssetId::from_str(LBTC).unwrap();

        // Metadata says a different buyback than the memo.
        let mut tx = fill_template();
        tx.outputs_mut()[3].script_pubkey = metadata(USDT, 32_000_00000000, 3_200_000);
        let err = verify_typed_fund(&claim, &b64(&tx), LBTC, 50_000_000, lbtc, &[1, 4], &[]).unwrap_err();
        assert!(err.to_string().contains("buyback"), "{err}");

        // Proceeds short by one satoshi.
        let mut tx = fill_template();
        tx.outputs_mut()[4].amount = Some(29_970_00000000 - 1);
        let err = verify_typed_fund(&claim, &b64(&tx), LBTC, 50_000_000, lbtc, &[1, 4], &[]).unwrap_err();
        assert!(err.to_string().contains("proceeds"), "{err}");

        // The NFT does not come to this wallet.
        let err = verify_typed_fund(&claim, &b64(&fill_template()), LBTC, 50_000_000, lbtc, &[4], &[]).unwrap_err();
        assert!(err.to_string().contains("position token"), "{err}");

        // Funded amount differs from the stated size.
        let err = verify_typed_fund(&claim, &b64(&fill_template()), LBTC, 49_000_000, lbtc, &[1, 4], &[]).unwrap_err();
        assert!(err.to_string().contains("size"), "{err}");
    }

    /// A partial exercise: owned NFT in at 0 and back out at 0, the
    /// position continues at 1, the lender is paid at 2, collateral
    /// returns to the wallet at 3, fee netted from it.
    fn exercise_template(remaining: bool) -> pset::PartiallySignedTransaction {
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        let mut nft_in = pset::Input::from_prevout(elements::OutPoint::new(
            elements::Txid::from_str(&"21".repeat(32)).unwrap(),
            1,
        ));
        nft_in.witness_utxo = Some(txout(NFT, 1, spk(0x01))); // explicit here; confidential in life
        tx.add_input(nft_in);
        let mut pos_in = pset::Input::from_prevout(elements::OutPoint::new(
            elements::Txid::from_str(&"22".repeat(32)).unwrap(),
            0,
        ));
        pos_in.witness_utxo = Some(txout(LBTC, 50_000_000, spk(0xc0)));
        tx.add_input(pos_in);
        if remaining {
            tx.add_output(pset::Output::from_txout(txout(NFT, 1, spk(0x01)))); // 0 NFT back
            tx.add_output(pset::Output::from_txout(txout(LBTC, 25_000_000, spk(0xc1)))); // 1 position
            tx.add_output(pset::Output::from_txout(txout(USDT, 15_500_00000000, spk(0xaa)))); // 2 lender
            tx.add_output(pset::Output::from_txout(txout(LBTC, 25_000_000 - 500, spk(0x01)))); // 3 released
        } else {
            let mut burn = pset::Output::from_txout(txout(NFT, 1, Script::from(vec![0x6a, 0x04, b'b', b'u', b'r', b'n'])));
            burn.amount = Some(1);
            tx.add_output(burn); // 0 burn
            tx.add_output(pset::Output::from_txout(txout(USDT, 31_000_00000000, spk(0xaa)))); // 1 lender
            tx.add_output(pset::Output::from_txout(txout(LBTC, 50_000_000 - 500, spk(0x01)))); // 2 released
        }
        tx.add_output(pset::Output::from_txout(txout(LBTC, 500, Script::new()))); // fee
        tx
    }

    fn owned_nft() -> Vec<OwnedInput> {
        vec![OwnedInput {
            index: 0,
            asset: AssetId::from_str(NFT).unwrap(),
            amount: 1,
        }]
    }

    #[test]
    fn exercise_claims_verify_partial_and_full() {
        let lbtc = AssetId::from_str(LBTC).unwrap();
        let partial = parse_typed_fund(&format!(
            r#"{{"kind":"sw/lend/exercise/v1","amount":"1550000000000","released":"24999500","remaining":"1550000000000","cash":"{USDT}"}}"#
        ))
        .unwrap()
        .unwrap();
        let check = verify_typed_fund(&partial, &b64(&exercise_template(true)), USDT, 15_500_00000000, lbtc, &[0, 3], &owned_nft()).unwrap();
        assert_eq!(check.receives, 24_999_500);
        assert_eq!(partial.render("USDt"), "Buy back 0.249995 BTC for 15500 USDt · 15500 USDt still owed after");

        let full = parse_typed_fund(&format!(
            r#"{{"kind":"sw/lend/exercise/v1","amount":"3100000000000","released":"49999500","remaining":"0","cash":"{USDT}"}}"#
        ))
        .unwrap()
        .unwrap();
        let check = verify_typed_fund(&full, &b64(&exercise_template(false)), USDT, 31_000_00000000, lbtc, &[2], &owned_nft()).unwrap();
        assert_eq!(check.receives, 49_999_500);
        assert!(full.render("USDt").ends_with("position closed"));
    }

    #[test]
    fn exercise_claim_is_refused_without_the_owned_token_or_with_short_release() {
        let lbtc = AssetId::from_str(LBTC).unwrap();
        let partial = parse_typed_fund(&format!(
            r#"{{"kind":"sw/lend/exercise/v1","amount":"1550000000000","released":"24999500","remaining":"1550000000000","cash":"{USDT}"}}"#
        ))
        .unwrap()
        .unwrap();
        let err = verify_typed_fund(&partial, &b64(&exercise_template(true)), USDT, 15_500_00000000, lbtc, &[0, 3], &[]).unwrap_err();
        assert!(err.to_string().contains("position token"), "{err}");

        // Released collateral does not reach this wallet.
        let err = verify_typed_fund(&partial, &b64(&exercise_template(true)), USDT, 15_500_00000000, lbtc, &[0], &owned_nft()).unwrap_err();
        assert!(err.to_string().contains("collateral"), "{err}");

        // A partial claim against a full (burn) template.
        let err = verify_typed_fund(&partial, &b64(&exercise_template(false)), USDT, 15_500_00000000, lbtc, &[0, 2], &owned_nft()).unwrap_err();
        assert!(err.to_string().contains("return the position token"), "{err}");
    }

    /// A USDt-collateral position (USDt/L-BTC market) bought back with
    /// L-BTC, partial: the dealer pays the network fee from its own coin
    /// (input 2) and takes the fee's value back in USDt (output 4); the
    /// released USDt reaches the wallet whole less that holdback.
    fn exercise_template_usdt_collateral() -> pset::PartiallySignedTransaction {
        const DEALER_LBTC_IN: u64 = 5_000;
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        let mut nft_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&"21".repeat(32)).unwrap(), 1));
        nft_in.witness_utxo = Some(txout(NFT, 1, spk(0x01)));
        tx.add_input(nft_in);
        let mut pos_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&"22".repeat(32)).unwrap(), 0));
        pos_in.witness_utxo = Some(txout(USDT, 1_000_00000000, spk(0xc0)));
        tx.add_input(pos_in);
        let mut fee_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&"23".repeat(32)).unwrap(), 0));
        fee_in.witness_utxo = Some(txout(LBTC, DEALER_LBTC_IN, spk(0xab)));
        tx.add_input(fee_in);
        tx.add_output(pset::Output::from_txout(txout(NFT, 1, spk(0x01)))); // 0 NFT back
        tx.add_output(pset::Output::from_txout(txout(USDT, 500_00000000, spk(0xc1)))); // 1 position continues (USDt)
        tx.add_output(pset::Output::from_txout(txout(LBTC, 600_000, spk(0xaa)))); // 2 lender paid in L-BTC
        tx.add_output(pset::Output::from_txout(txout(USDT, 500_00000000 - 30_000_000, spk(0x01)))); // 3 released USDt to the wallet
        tx.add_output(pset::Output::from_txout(txout(USDT, 30_000_000, spk(0xab)))); // 4 fee holdback to the dealer
        tx.add_output(pset::Output::from_txout(txout(LBTC, DEALER_LBTC_IN - 270, spk(0xab)))); // 5 dealer L-BTC change
        tx.add_output(pset::Output::from_txout(txout(LBTC, 270, Script::new()))); // 6 fee
        tx
    }

    #[test]
    fn exercise_of_a_non_lbtc_collateral_names_the_collateral() {
        let lbtc = AssetId::from_str(LBTC).unwrap();
        let named = parse_typed_fund(&format!(
            r#"{{"kind":"sw/lend/exercise/v1","amount":"600000","released":"49970000000","remaining":"500000000000","cash":"{LBTC}","collateral":"{USDT}"}}"#
        ))
        .unwrap()
        .unwrap();
        assert_eq!(named.collateral(), Some(AssetId::from_str(USDT).unwrap()));
        let check = verify_typed_fund(&named, &b64(&exercise_template_usdt_collateral()), LBTC, 600_000, lbtc, &[0, 3], &owned_nft()).unwrap();
        assert_eq!(check.receives, 49_970_000_000);
        assert_eq!(named.render_with("USDt", "BTC"), "Buy back 499.7 USDt for 0.006 BTC · 5000 BTC still owed after");

        // The same memo without `collateral` is an L-BTC claim: the
        // continuing position is not L-BTC, so a pre-2026-09-05 wallet refuses.
        let legacy = parse_typed_fund(&format!(
            r#"{{"kind":"sw/lend/exercise/v1","amount":"600000","released":"49970000000","remaining":"500000000000","cash":"{LBTC}"}}"#
        ))
        .unwrap()
        .unwrap();
        assert_eq!(legacy.collateral(), None);
        let err = verify_typed_fund(&legacy, &b64(&exercise_template_usdt_collateral()), LBTC, 600_000, lbtc, &[0, 3], &owned_nft()).unwrap_err();
        assert!(err.to_string().contains("continuing position"), "{err}");

        // A malformed collateral id is a refusal, not a fallback.
        assert!(parse_typed_fund(r#"{"kind":"sw/lend/exercise/v1","amount":"1","released":"1","remaining":"0","cash":"00","collateral":"zz"}"#).unwrap().is_err());
    }

    #[test]
    fn untyped_and_malformed_memos_are_told_apart() {
        assert!(parse_typed_fund("Deposit for order 7").is_none());
        assert!(parse_typed_fund(r#"{"kind":"rf/order/v1"}"#).is_none());
        assert!(parse_typed_fund(r#"{"kind":"sw/lend/fill/v1"}"#).unwrap().is_err());
        assert!(parse_typed_fund(r#"{"kind":"sw/lend/unknown/v1"}"#).unwrap().is_err());
    }

    #[test]
    fn op_return_payloads_and_amount_formatting() {
        assert_eq!(op_return_payload(&Script::from(vec![0x6a, 0x02, 7, 8])), Some(&[7u8, 8][..]));
        assert_eq!(op_return_payload(&metadata(USDT, 1, 1)).map(|p| p.len()), Some(80));
        assert!(op_return_payload(&spk(1)).is_none());
        assert_eq!(fmt8(50_000_000), "0.5");
        assert_eq!(fmt8(3_000_000_000_000), "30000");
        assert_eq!(fmt8(1), "0.00000001");
    }

    /// Pinned against `lending_contracts` (swaption_lending_v2 core tests,
    /// `print_program_leaf`): the hash-only reconstruction must land on
    /// the script Simplex computes for the same terms and state.
    #[test]
    fn v2_position_script_matches_the_contracts_crate() {
        let asset = |b: u8| AssetId::from_slice(&[b; 32]).unwrap();
        let digest = v2_terms_digest(asset(1), asset(2), 50_000_000, 3_100_000_000_000, 3_200_000, asset(3), asset(4), &[9u8; 32]);
        assert_eq!(hex::encode(digest), "bda46f0bcef2adbddb585b1f42219062f169a3b120fdd12296c30832b9f2f9a7");
        assert_eq!(hex::encode(v2_position_script(&digest, 3_100_000_000_000).as_bytes()), "5120c32f2167a9d3dba8c997402074198ad98dd34d9f0a484677a69664c2b94bdfec");
        assert_eq!(hex::encode(v2_position_script(&digest, 7).as_bytes()), "51202e465deaebad6d5cc81bbf4abeb935183a48ce8827d5ee55dad2cbc10cc53c61");
    }

    /// Pinned against `lending_contracts` (swaption_lending_v3 and
    /// swaption_claim core tests, `print_program_leaf`).
    #[test]
    fn v3_position_and_claim_scripts_match_the_contracts_crate() {
        let asset = |b: u8| AssetId::from_slice(&[b; 32]).unwrap();
        let digest = v2_terms_digest(asset(1), asset(2), 50_000_000, 3_100_000_000_000, 3_200_000, asset(3), asset(4), &[9u8; 32]);
        assert_eq!(hex::encode(v3_position_script(&digest, 3_100_000_000_000).as_bytes()), "51202e0466fd296c985554b9b5b0a6076e0c51b24daa2ec4cd0463d2a47b4c8aadc8");
        assert_eq!(hex::encode(v3_position_script(&digest, 7).as_bytes()), "51202c181ce24fc01923dfdfd4366a3f38d5748e12dedab88caf12509f4746b6ec54");
        assert_eq!(hex::encode(claim_script(asset(4)).as_bytes()), "51200ec1e15d74191de822cca78f3d28fe219f18bc8992716191368a387ebdddf88d");
    }

    /// Pinned against `lending_contracts` (swaption_lending_v4 core tests,
    /// `print_program_leaf`).
    #[test]
    fn v5_position_script_matches_the_contracts_crate() {
        let asset = |b: u8| elements::AssetId::from_slice(&[b; 32]).unwrap();
        let digest = v5_terms_digest(asset(1), asset(2), 50_000_000, 3_100_000_000_000, 3_200_000, asset(3), asset(4), &[9u8; 32], &[10u8; 32], &[11u8; 32], 3_199_500);
        assert_eq!(hex::encode(digest), "d9699f759118692dced610a96f6bf6ce2955da0c67263db3a00eaa39bc9d5d5f");
        assert_eq!(hex::encode(v5_position_script(&digest, 3_100_000_000_000).as_bytes()), "5120b4f37558ccf48acde731baab3dcaf0490f1d30c5f1427b4c74aced3ce50e0a60");
        assert_eq!(hex::encode(v5_position_script(&digest, 7).as_bytes()), "51209c434397f08fc4a6094d8556a39a8829b3fe69c328045696f1ab818ba6a98f11");
    }

    // ---- Lend offers escrowed on chain (sw/lend/offer/v1, fill/v6, offer-cancel/v1, claim/v1) ----

    const LENDER_TOKEN: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    fn offer_rows() -> Vec<OfferRowClaim> {
        vec![OfferRowClaim {
            collateral: AssetId::from_slice(&[1u8; 32]).unwrap(),
            expiry: 3_200_000,
            price_out: 300_000_000,
            buyback: 400_000_000,
            fee_per_unit: 2_000_000,
            min_size: 1_000,
        }]
    }

    /// Pinned against `lending_contracts` (swaption_offer core tests,
    /// `print_program_leaf`): the same params as the crate's `params()`.
    #[test]
    fn offer_script_matches_the_contracts_crate() {
        let asset = |b: u8| AssetId::from_slice(&[b; 32]).unwrap();
        let digest = offer_terms_digest(asset(2), asset(4), &[9u8; 32], &[12u8; 32], &SWAPTION_LENDING_V5_LEAF, 50, 3_199_000, &offer_rows());
        assert_eq!(hex::encode(digest), "0aa14f32b317261a0ad1b6155f73bc367bbc49743b2915f4ff9aa3990abcab98");
        assert_eq!(hex::encode(offer_script(&digest, 25_000).as_bytes()), "512029d292a118d9cfb92fcfee045bda0487a5729e2915549700cb407448f21b6be1");
        assert_eq!(hex::encode(offer_script(&digest, 1).as_bytes()), "51205ec5e2f39b6239dfc75f4b47afd84097b567cede67eb2cbb4677ecc912f4747c");
    }

    fn offer_claim_json(amounts: &[u64], token_output: Option<u32>) -> String {
        let claim_hash = {
            use elements::hashes::{Hash as _, sha256};
            hex::encode(sha256::Hash::hash(claim_script(AssetId::from_str(LENDER_TOKEN).unwrap()).as_bytes()).to_byte_array())
        };
        let amounts: Vec<String> = amounts.iter().map(|a| format!("\"{a}\"")).collect();
        format!(
            r#"{{"kind":"sw/lend/offer/v1","cash":"{USDT}","amounts":[{}],"lender_token":"{LENDER_TOKEN}","claim":"{claim_hash}","fee_script":"{}","position_leaf":"{}","fee_min":"50","cutoff":3199000,"rows":[{{"collateral":"{LBTC}","expiry":3200000,"price_out":"300000000","buyback":"400000000","fee_per_unit":"2000000","min_size":"1000"}}],"token_output":{}}}"#,
            amounts.join(","),
            hex::encode([12u8; 32]),
            hex::encode(SWAPTION_LENDING_V5_LEAF),
            token_output.map(|t| t.to_string()).unwrap_or_else(|| "null".to_owned())
        )
    }

    /// A first post as the RP builds it: the venue's token coin and fee
    /// coin in; two offer coins, the token to the wallet, the venue's
    /// change and the fee out. The wallet's deficit is the cash.
    fn offer_template(amounts: &[u64], token_output: bool) -> pset::PartiallySignedTransaction {
        let claim = parse_typed_fund(&offer_claim_json(amounts, token_output.then_some(amounts.len() as u32))).unwrap().unwrap();
        let TypedFund::Offer { cash, lender_token, claim: claim_hash, fee_script, position_leaf, fee_min, cutoff, rows, .. } = &claim else { panic!("offer") };
        let digest = offer_terms_digest(*cash, *lender_token, claim_hash, fee_script, position_leaf, *fee_min, *cutoff, rows);
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        if token_output {
            let mut token_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&"31".repeat(32)).unwrap(), 0));
            token_in.witness_utxo = Some(txout(LENDER_TOKEN, 1, spk(0xaa)));
            tx.add_input(token_in);
        }
        let mut fee_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&"32".repeat(32)).unwrap(), 0));
        fee_in.witness_utxo = Some(txout(LBTC, 100_000, spk(0xab)));
        tx.add_input(fee_in);
        for a in amounts {
            tx.add_output(pset::Output::from_txout(txout(USDT, *a, offer_script(&digest, *a))));
        }
        if token_output {
            tx.add_output(pset::Output::from_txout(txout(LENDER_TOKEN, 1, spk(0x01)))); // token → mine
        }
        tx.add_output(pset::Output::from_txout(txout(LBTC, 100_000 - 700, spk(0xab))));
        tx.add_output(pset::Output::from_txout(txout(LBTC, 700, Script::new())));
        tx
    }

    #[test]
    fn offer_claim_verifies_against_its_template_and_renders() {
        let lbtc = AssetId::from_str(LBTC).unwrap();
        let amounts = [20_000u64, 5_000];
        let claim = parse_typed_fund(&offer_claim_json(&amounts, Some(2))).unwrap().unwrap();
        let mine = [2usize];
        let check = verify_typed_fund(&claim, &b64(&offer_template(&amounts, true)), USDT, 25_000, lbtc, &mine, &[]).unwrap();
        assert_eq!(check.receives, 0);
        let text = claim.render_with("BTC", "USDt");
        assert!(text.starts_with("Lend 0.00025 USDt on chain in 2 coins: pay up to 3 USDt per BTC"), "{text}");
        assert!(text.contains("you receive your lender token"), "{text}");

        // A later post: no token output, one coin.
        let claim = parse_typed_fund(&offer_claim_json(&[25_000], None)).unwrap().unwrap();
        let check = verify_typed_fund(&claim, &b64(&offer_template(&[25_000], false)), USDT, 25_000, lbtc, &[], &[]).unwrap();
        assert_eq!(check.receives, 0);
        assert!(!claim.render("USDt").contains("lender token"));
    }

    #[test]
    fn offer_claim_is_refused_when_the_covenant_or_token_disagree() {
        let lbtc = AssetId::from_str(LBTC).unwrap();
        let amounts = [20_000u64, 5_000];
        let claim = parse_typed_fund(&offer_claim_json(&amounts, Some(2))).unwrap().unwrap();

        // An offer output that is not the covenant for the stated terms.
        let mut tx = offer_template(&amounts, true);
        tx.outputs_mut()[1].script_pubkey = spk(0xee);
        let err = verify_typed_fund(&claim, &b64(&tx), USDT, 25_000, lbtc, &[2], &[]).unwrap_err();
        assert!(err.to_string().contains("offer covenant"), "{err}");

        // The token does not come to this wallet.
        let err = verify_typed_fund(&claim, &b64(&offer_template(&amounts, true)), USDT, 25_000, lbtc, &[], &[]).unwrap_err();
        assert!(err.to_string().contains("lender token"), "{err}");

        // Funded amount differs from the coins.
        let err = verify_typed_fund(&claim, &b64(&offer_template(&amounts, true)), USDT, 24_999, lbtc, &[2], &[]).unwrap_err();
        assert!(err.to_string().contains("amounts"), "{err}");

        // A position program this wallet does not know.
        let json = offer_claim_json(&amounts, Some(2)).replace(&hex::encode(SWAPTION_LENDING_V5_LEAF), &hex::encode([7u8; 32]));
        let claim = parse_typed_fund(&json).unwrap().unwrap();
        let err = verify_typed_fund(&claim, &b64(&offer_template(&amounts, true)), USDT, 25_000, lbtc, &[2], &[]).unwrap_err();
        assert!(err.to_string().contains("position program"), "{err}");
    }

    /// A fill drawn from an offer coin: the offer in at 0 (explicit cash),
    /// the borrower token and the venue's fee coin, then the position, the
    /// token to the wallet, the offer continuing, the fee, the proceeds.
    fn fill_v6_template(payout: &[u8; 32], lastlook: &[u8; 32]) -> pset::PartiallySignedTransaction {
        let lbtc = AssetId::from_str(LBTC).unwrap();
        let usdt = AssetId::from_str(USDT).unwrap();
        let borrower_hash = {
            use elements::hashes::{Hash as _, sha256};
            sha256::Hash::hash(spk(0x01).as_bytes()).to_byte_array()
        };
        let digest = v5_terms_digest(lbtc, usdt, 2_000_000, 1_242_00000000, 2_600_984, AssetId::from_str(NFT).unwrap(), AssetId::from_str(LENDER_TOKEN).unwrap(), payout, &borrower_hash, lastlook, 2_600_484);
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        let mut offer_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&"41".repeat(32)).unwrap(), 0));
        offer_in.witness_utxo = Some(txout(USDT, 25_000_00000000, spk(0xcc)));
        tx.add_input(offer_in);
        let mut nft_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&"42".repeat(32)).unwrap(), 0));
        nft_in.witness_utxo = Some(txout(NFT, 1, spk(0xaa)));
        tx.add_input(nft_in);
        let mut fee_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&"43".repeat(32)).unwrap(), 0));
        fee_in.witness_utxo = Some(txout(LBTC, 100_000, spk(0xab)));
        tx.add_input(fee_in);
        tx.add_output(pset::Output::from_txout(txout(LBTC, 2_000_000, v5_position_script(&digest, 1_242_00000000)))); // 0 position
        tx.add_output(pset::Output::from_txout(txout(NFT, 1, spk(0x01)))); // 1 borrower token → mine
        tx.add_output(pset::Output::from_txout(txout(USDT, 25_000_00000000 - 1_203_00000000, spk(0xcd)))); // 2 the offer continues
        tx.add_output(pset::Output::from_txout(txout(USDT, 6_00000000, spk(0xfe)))); // 3 venue fee (both sides)
        tx.add_output(pset::Output::from_txout(txout(USDT, 1_197_00000000, spk(0x01)))); // 4 proceeds → mine
        tx.add_output(pset::Output::from_txout(txout(LBTC, 100_000 - 450, spk(0xab)))); // 5 venue change
        tx.add_output(pset::Output::from_txout(txout(LBTC, 450, Script::new()))); // 6 fee
        tx
    }

    #[test]
    fn fill_v6_claim_verifies_with_the_lender_token_from_the_memo() {
        let lbtc = AssetId::from_str(LBTC).unwrap();
        let payout = {
            use elements::hashes::{Hash as _, sha256};
            sha256::Hash::hash(claim_script(AssetId::from_str(LENDER_TOKEN).unwrap()).as_bytes()).to_byte_array()
        };
        let lastlook = [11u8; 32];
        let json = format!(
            r#"{{"kind":"sw/lend/fill/v6","size":"2000000","sale":"120000000000","buyback":"124200000000","expiry":2600984,"cash":"{USDT}","collateral":"{LBTC}","fee":"300000000","payout":"{}","lastlook":"{}","lastlook_height":2600484,"lender_nft":"{LENDER_TOKEN}"}}"#,
            hex::encode(payout),
            hex::encode(lastlook)
        );
        let claim = parse_typed_fund(&json).unwrap().unwrap();
        let check = verify_typed_fund(&claim, &b64(&fill_v6_template(&payout, &lastlook)), LBTC, 2_000_000, lbtc, &[1, 4], &[]).unwrap();
        assert_eq!(check.receives, 1_197_00000000);
        assert!(claim.render("USDt").contains("from a lender's offer on chain"));

        // A payout that is not the named token's claim script.
        let bad = json.replace(&hex::encode(payout), &hex::encode([5u8; 32]));
        let claim = parse_typed_fund(&bad).unwrap().unwrap();
        let err = verify_typed_fund(&claim, &b64(&fill_v6_template(&[5u8; 32], &lastlook)), LBTC, 2_000_000, lbtc, &[1, 4], &[]).unwrap_err();
        assert!(err.to_string().contains("claim script"), "{err}");
    }

    fn owned_lender_token() -> Vec<OwnedInput> {
        vec![OwnedInput {
            index: 0,
            asset: AssetId::from_str(LENDER_TOKEN).unwrap(),
            amount: 1,
        }]
    }

    /// Cancel: the token in at 0 and back at 0, the offer coin in at 1,
    /// the cash back to the wallet at 1, the fee the wallet funds.
    fn cancel_template() -> pset::PartiallySignedTransaction {
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        let mut token_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&"51".repeat(32)).unwrap(), 1));
        token_in.witness_utxo = Some(txout(LENDER_TOKEN, 1, spk(0x01)));
        tx.add_input(token_in);
        let mut offer_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&"52".repeat(32)).unwrap(), 2));
        offer_in.witness_utxo = Some(txout(USDT, 16_000_00000000, spk(0xcc)));
        tx.add_input(offer_in);
        tx.add_output(pset::Output::from_txout(txout(LENDER_TOKEN, 1, spk(0x01)))); // 0 token back
        tx.add_output(pset::Output::from_txout(txout(USDT, 16_000_00000000, spk(0x01)))); // 1 cash back
        tx.add_output(pset::Output::from_txout(txout(LBTC, 230, Script::new()))); // 2 fee
        tx
    }

    #[test]
    fn offer_cancel_and_claim_verify_with_the_owned_token() {
        let lbtc = AssetId::from_str(LBTC).unwrap();
        let cancel = parse_typed_fund(&format!(
            r#"{{"kind":"sw/lend/offer-cancel/v1","cash":"{USDT}","amount":"1600000000000","fee":"230","lender_token":"{LENDER_TOKEN}"}}"#
        ))
        .unwrap()
        .unwrap();
        let check = verify_typed_fund(&cancel, &b64(&cancel_template()), LBTC, 230, lbtc, &[0, 1], &owned_lender_token()).unwrap();
        assert_eq!(check.receives, 16_000_00000000);
        assert_eq!(cancel.render("USDt"), "Withdraw your lend offer: 16000 USDt back to this wallet · you pay the 230 sat network fee");
        // Without the owned token, or with the token not returned.
        assert!(verify_typed_fund(&cancel, &b64(&cancel_template()), LBTC, 230, lbtc, &[0, 1], &[]).is_err());
        assert!(verify_typed_fund(&cancel, &b64(&cancel_template()), LBTC, 230, lbtc, &[1], &owned_lender_token()).is_err());

        // A collection: the token in and back, two claim coins, two assets out to the wallet.
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        let mut token_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&"61".repeat(32)).unwrap(), 0));
        token_in.witness_utxo = Some(txout(LENDER_TOKEN, 1, spk(0x01)));
        tx.add_input(token_in);
        for (i, (asset, value)) in [(USDT, 12_000_00000000u64), (LBTC, 2_000_000)].iter().enumerate() {
            let mut claim_in = pset::Input::from_prevout(elements::OutPoint::new(elements::Txid::from_str(&format!("{:02x}", 0x62 + i).repeat(32)).unwrap(), 0));
            claim_in.witness_utxo = Some(txout(asset, *value, spk(0xcc)));
            tx.add_input(claim_in);
        }
        tx.add_output(pset::Output::from_txout(txout(LENDER_TOKEN, 1, spk(0x01))));
        tx.add_output(pset::Output::from_txout(txout(USDT, 12_000_00000000, spk(0x01))));
        tx.add_output(pset::Output::from_txout(txout(LBTC, 2_000_000, spk(0x01))));
        tx.add_output(pset::Output::from_txout(txout(LBTC, 330, Script::new())));
        let claim = parse_typed_fund(&format!(
            r#"{{"kind":"sw/lend/claim/v1","lender_token":"{LENDER_TOKEN}","fee":"330","receives":[{{"asset":"{USDT}","amount":"1200000000000"}},{{"asset":"{LBTC}","amount":"2000000"}}]}}"#
        ))
        .unwrap()
        .unwrap();
        let check = verify_typed_fund(&claim, &b64(&tx), LBTC, 330, lbtc, &[0, 1, 2], &owned_lender_token()).unwrap();
        assert_eq!(check.receives, 12_000_00000000);
        assert_eq!(claim.render("USDt"), "Collect what your lending paid into this wallet (2 coins) · you pay the 330 sat network fee");
        // A received amount that does not reach the wallet.
        assert!(verify_typed_fund(&claim, &b64(&tx), LBTC, 330, lbtc, &[0, 1], &owned_lender_token()).is_err());
    }

    #[test]
    fn v4_position_script_matches_the_contracts_crate() {
        let asset = |b: u8| AssetId::from_slice(&[b; 32]).unwrap();
        let digest = v4_terms_digest(asset(1), asset(2), 50_000_000, 3_100_000_000_000, 3_200_000, asset(3), asset(4), &[9u8; 32], &[10u8; 32], &[11u8; 32], 3_199_500);
        assert_eq!(hex::encode(digest), "d9699f759118692dced610a96f6bf6ce2955da0c67263db3a00eaa39bc9d5d5f");
        assert_eq!(hex::encode(v4_position_script(&digest, 3_100_000_000_000).as_bytes()), "5120c673923a74662e7076360c5b980185abc469518fbdf3d1af55ffe24439ccd276");
        assert_eq!(hex::encode(v4_position_script(&digest, 7).as_bytes()), "5120cf07fbf5bd572d39f0089dc3d6b72bf72c3e9db5e54fdbb9df9e140402a28048");
    }
}
