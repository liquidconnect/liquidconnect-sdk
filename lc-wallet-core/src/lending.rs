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
    /// The borrower sells `size` of the policy asset for `sale` of `cash`
    /// and may buy it back for `buyback` until block `expiry`; `fee` is
    /// the venue's fill fee, taken from the sale proceeds.
    Fill {
        size: u64,
        sale: u64,
        buyback: u64,
        expiry: u32,
        cash: elements::AssetId,
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
        fee: u64,
        payout: [u8; 32],
        lastlook: [u8; 32],
        lastlook_height: u32,
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
    /// The borrower pays `amount` of `cash`; `released` of the policy
    /// asset comes back; `remaining` is the debt left (0 = full).
    Exercise {
        amount: u64,
        released: u64,
        remaining: u64,
        cash: elements::AssetId,
    },
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
            fee,
        } => {
            anyhow::ensure!(requested == policy_asset, "fill: the funded asset must be the collateral asset");
            anyhow::ensure!(amount == *size, "fill: stated size {size} does not equal the funded amount {amount}");
            anyhow::ensure!(*buyback > *sale, "fill: buyback must exceed the sale price");

            let (asset, value) = explicit(FILL_POSITION_OUTPUT)?;
            anyhow::ensure!(
                asset == policy_asset && value == *size,
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
            fee,
            payout,
        } => {
            anyhow::ensure!(requested == policy_asset, "fill: the funded asset must be the collateral asset");
            anyhow::ensure!(amount == *size, "fill: stated size {size} does not equal the funded amount {amount}");
            anyhow::ensure!(*buyback > *sale, "fill: buyback must exceed the sale price");

            let (asset, value) = explicit(FILL_POSITION_OUTPUT)?;
            anyhow::ensure!(asset == policy_asset && value == *size, "fill: output 0 is not {size} of the collateral asset");
            let (borrower_nft, nft) = explicit(FILL_BORROWER_NFT_OUTPUT)?;
            anyhow::ensure!(nft == 1 && is_mine(FILL_BORROWER_NFT_OUTPUT), "fill: output 1 must pay this wallet its position token");
            let (lender_nft, nft2) = explicit(FILL_LENDER_NFT_OUTPUT)?;
            anyhow::ensure!(nft2 == 1, "fill: output 2 must be the lender's token");

            // THE covenant check: the position output must be the constant
            // program with exactly these terms and the full debt.
            let digest = v2_terms_digest(policy_asset, *cash, *size, *buyback, *expiry, borrower_nft, lender_nft, payout);
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
            fee,
            payout,
        } => {
            anyhow::ensure!(requested == policy_asset, "fill: the funded asset must be the collateral asset");
            anyhow::ensure!(amount == *size, "fill: stated size {size} does not equal the funded amount {amount}");
            anyhow::ensure!(*buyback > *sale, "fill: buyback must exceed the sale price");

            let (asset, value) = explicit(FILL_POSITION_OUTPUT)?;
            anyhow::ensure!(asset == policy_asset && value == *size, "fill: output 0 is not {size} of the collateral asset");
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
            let digest = v2_terms_digest(policy_asset, *cash, *size, *buyback, *expiry, borrower_nft, lender_nft, payout);
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
            fee,
            payout,
            lastlook,
            lastlook_height,
        } => {
            anyhow::ensure!(requested == policy_asset, "fill: the funded asset must be the collateral asset");
            anyhow::ensure!(amount == *size, "fill: stated size {size} does not equal the funded amount {amount}");
            anyhow::ensure!(*buyback > *sale, "fill: buyback must exceed the sale price");

            let (asset, value) = explicit(FILL_POSITION_OUTPUT)?;
            anyhow::ensure!(asset == policy_asset && value == *size, "fill: output 0 is not {size} of the collateral asset");
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
            let digest = v4_terms_digest(policy_asset, *cash, *size, *buyback, *expiry, borrower_nft, lender_nft, payout, &borrower_hash, lastlook, *lastlook_height);
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
            fee,
            payout,
            lastlook,
            lastlook_height,
        } => {
            anyhow::ensure!(requested == policy_asset, "fill: the funded asset must be the collateral asset");
            anyhow::ensure!(amount == *size, "fill: stated size {size} does not equal the funded amount {amount}");
            anyhow::ensure!(*buyback > *sale, "fill: buyback must exceed the sale price");

            let (asset, value) = explicit(FILL_POSITION_OUTPUT)?;
            anyhow::ensure!(asset == policy_asset && value == *size, "fill: output 0 is not {size} of the collateral asset");
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
            let digest = v5_terms_digest(policy_asset, *cash, *size, *buyback, *expiry, borrower_nft, lender_nft, payout, &borrower_hash, lastlook, *lastlook_height);
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
        } => {
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
                anyhow::ensure!(asset == policy_asset, "exercise: output 1 must be the continuing position");
            } else {
                let out = outputs.get(0).ok_or_else(|| anyhow::anyhow!("template has no output 0"))?;
                anyhow::ensure!(
                    op_return_payload(&out.script_pubkey).is_some() && out.asset == Some(token.asset),
                    "exercise: a full buyback must burn the position token at output 0"
                );
            }

            let got = mine_paying(policy_asset)
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

/// Tapleaf hash of the constant v5 lending program (`swaption_lending_v5.simf`):
/// v4 plus a PARTIAL last look (the venue may take a position off in rounds).
pub const SWAPTION_LENDING_V5_LEAF: [u8; 32] = hex_literal::hex!("da43157b075c4c18c1f7354ada37455fdfbd7eb481d6762a9f1843896d659725");

/// Tapleaf hash of the constant claim program (`swaption_claim.simf`): a
/// coin spendable by whoever spends one unit of the lender token as input 0.
pub const SWAPTION_CLAIM_LEAF: [u8; 32] = hex_literal::hex!("51f916310d382610bf7efd7b345d9641b3dc93917d2afb77289add911f3403e1");

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
    /// Text for the approval dialog, from the verified fields.
    pub fn render(&self, cash_symbol: &str) -> String {
        match self {
            TypedFund::Fill {
                size,
                sale,
                buyback,
                expiry,
                fee,
                ..
            } => format!(
                "Sell {} BTC for {} {cash_symbol} · buy back for {} {cash_symbol} until block {} · fee {} {cash_symbol}",
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
                "Sell {} BTC for {} {cash_symbol} · buy back for {} {cash_symbol} until block {} · fee {} {cash_symbol}",
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
                "Sell {} BTC for {} {cash_symbol} · buy back for {} {cash_symbol} until block {} · fee {} {cash_symbol}",
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
                "Sell {} BTC for {} {cash_symbol} · buy back for {} {cash_symbol} until block {} · fee {} {cash_symbol} · from block {} Swaption may exercise an unused in-the-money right for you and pay you the surplus less its fee",
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
                "Sell {} BTC for {} {cash_symbol} · buy back for {} {cash_symbol} until block {} · fee {} {cash_symbol} · from block {} Swaption may exercise an unused in-the-money right for you and pay you the surplus less its fee",
                fmt8(*size),
                fmt8(*sale),
                fmt8(*buyback),
                expiry,
                fmt8(*fee),
                lastlook_height
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
                    "Buy back {} BTC for {} {cash_symbol} · {tail}",
                    fmt8(*released),
                    fmt8(*amount)
                )
            }
        }
    }

    pub fn cash(&self) -> elements::AssetId {
        match self {
            TypedFund::Fill { cash, .. } | TypedFund::FillV2 { cash, .. } | TypedFund::FillV3 { cash, .. } | TypedFund::FillV4 { cash, .. } | TypedFund::FillV5 { cash, .. } | TypedFund::SellRight { cash, .. } | TypedFund::Exercise { cash, .. } => *cash,
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

    #[test]
    fn v4_position_script_matches_the_contracts_crate() {
        let asset = |b: u8| AssetId::from_slice(&[b; 32]).unwrap();
        let digest = v4_terms_digest(asset(1), asset(2), 50_000_000, 3_100_000_000_000, 3_200_000, asset(3), asset(4), &[9u8; 32], &[10u8; 32], &[11u8; 32], 3_199_500);
        assert_eq!(hex::encode(digest), "d9699f759118692dced610a96f6bf6ce2955da0c67263db3a00eaa39bc9d5d5f");
        assert_eq!(hex::encode(v4_position_script(&digest, 3_100_000_000_000).as_bytes()), "5120c673923a74662e7076360c5b980185abc469518fbdf3d1af55ffe24439ccd276");
        assert_eq!(hex::encode(v4_position_script(&digest, 7).as_bytes()), "5120cf07fbf5bd572d39f0089dc3d6b72bf72c3e9db5e54fdbb9df9e140402a28048");
    }
}
