//! What a sign request asks for, as structure to render — the beginning
//! of the SDK's approval-safety surface.
//!
//! The wallet's decode of the PSET is the entire security boundary of a
//! Liquid Connect sign request: the person approves what the screen
//! shows, and the screen shows what this module extracts. Version 0.1
//! reports what is explicit in the PSET — output scripts and addresses,
//! explicit amounts and assets, the fee — and is honest about what it
//! cannot read: a confidential output is marked `confidential`, never
//! guessed. A wallet with its own blinding keys unblinds those outputs
//! itself and should treat `fully_explicit == false` as "my own decode
//! must fill the gaps before anyone approves".

use elements::hex::ToHex as _;
use elements::pset;
use elements::AddressParams;

use crate::key::Network;

#[derive(Debug, Clone)]
pub struct OutputSummary {
    /// Rendered address, when the script has an address form on this
    /// network.
    pub address: Option<String>,
    pub script_hex: String,
    /// Hex asset id, when explicit.
    pub asset: Option<String>,
    /// Satoshis, when explicit.
    pub amount: Option<u64>,
    /// The Liquid fee output: empty script, always explicit.
    pub is_fee: bool,
    /// The payjoin service-fee output, when a payjoin context has been
    /// applied — the declared thing it is, so the honest flow does not
    /// render as an unexplained extra leg. See [`TransactionSummary::annotate_payjoin`].
    pub is_payjoin_service_fee: bool,
    /// True when amount or asset is blinded and this summary therefore
    /// cannot say what the output moves.
    pub confidential: bool,
}

#[derive(Debug, Clone)]
pub struct TransactionSummary {
    pub input_count: usize,
    pub outputs: Vec<OutputSummary>,
    /// The explicit fee in satoshis, when exactly one fee output exists.
    pub fee: Option<u64>,
    /// True when every output was readable. When false, render nothing
    /// as a total: partial sums presented as totals are how a person
    /// approves more than they saw.
    pub fully_explicit: bool,
}

/// What a payjoin order adds to a transaction, for the approval screen.
#[derive(Debug, Clone)]
pub struct PayjoinContext {
    /// The order's `fee_address` — where the service fee goes.
    pub fee_address: String,
}

impl TransactionSummary {
    /// Mark the payjoin service-fee output so it renders as the declared
    /// thing it is ("network fee paid via payjoin") instead of an
    /// unexplained extra leg. Returns how many outputs matched — 0 means
    /// the claimed context does not describe this transaction, which the
    /// caller should treat as a mismatch, not silence.
    pub fn annotate_payjoin(&mut self, ctx: &PayjoinContext) -> anyhow::Result<usize> {
        use std::str::FromStr as _;
        let fee_addr = elements::Address::from_str(&ctx.fee_address)?;
        let fee_script = fee_addr.script_pubkey().to_hex();
        let mut marked = 0;
        for output in &mut self.outputs {
            if output.script_hex == fee_script {
                output.is_payjoin_service_fee = true;
                marked += 1;
            }
        }
        Ok(marked)
    }
}

fn address_params(network: Network) -> &'static AddressParams {
    match network {
        Network::Liquid => &AddressParams::LIQUID,
        Network::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
        Network::Regtest => &AddressParams::ELEMENTS,
    }
}

pub fn decode_pset(pset_b64: &str) -> anyhow::Result<pset::PartiallySignedTransaction> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD.decode(pset_b64)?;
    Ok(elements::encode::deserialize(&bytes)?)
}

pub fn summarize_pset(pset_b64: &str, network: Network) -> anyhow::Result<TransactionSummary> {
    let pset = decode_pset(pset_b64)?;
    let mut outputs = Vec::new();
    let mut fee = None;
    let mut fee_outputs = 0usize;
    let mut fully_explicit = true;

    for o in pset.outputs() {
        let is_fee = o.script_pubkey.is_empty();
        let confidential = o.amount.is_none() || o.asset.is_none();
        if confidential {
            fully_explicit = false;
        }
        if is_fee {
            fee_outputs += 1;
            fee = o.amount;
        }
        let address = if is_fee {
            None
        } else {
            elements::Address::from_script(&o.script_pubkey, None, address_params(network))
                .map(|a| a.to_string())
        };
        outputs.push(OutputSummary {
            address,
            script_hex: o.script_pubkey.to_hex(),
            asset: o.asset.map(|a| a.to_string()),
            amount: o.amount,
            is_fee,
            is_payjoin_service_fee: false,
            confidential,
        });
    }
    if fee_outputs != 1 {
        fee = None;
    }

    Ok(TransactionSummary {
        input_count: pset.inputs().len(),
        outputs,
        fee,
        fully_explicit,
    })
}

/// What a fund-request template asks for, verified arithmetically.
/// Returned only when every rule held; the numbers are the wallet's own
/// computation, never the relying party's words.
#[derive(Debug, Clone)]
pub struct FundTemplateSummary {
    pub input_count: usize,
    pub output_count: usize,
    /// The template's explicit fee output, satoshis.
    pub fee: u64,
    /// The template's deficit for the requested asset — equal to the
    /// stated amount by construction (a mismatch is a refusal).
    pub deficit: u64,
    /// Rows that were confidential on the wire and whose amount and asset
    /// this function verified through their blind proofs. Hosts may
    /// render these as "amount verified by proof"; zero means the whole
    /// template was explicit.
    pub proven_rows: usize,
}

/// Verify a fund-request template against the RP's claim
/// (spec: docs/fund-template-spec.md, "The wallet's safety rules").
///
/// Enforced here, for every host wallet, before anything renders:
/// 1. every template input carries a witness_utxo and every row is
///    EXPLICIT — or, if confidential, states its amount and asset and
///    carries blind value/asset proofs that verify against the row's
///    commitments (docs/fund-template-confidential-proofs.md); anything
///    confidential without verifying proofs is refused. The fee output
///    is always explicit;
/// 2. the template's deficit for `asset_id` (outputs − inputs) equals
///    `amount` exactly — the stated amount is arithmetic, not advisory;
/// 3. for every other asset the template covers itself (deficit ≤ 0),
///    including exactly one explicit fee output — the wallet contributes
///    only `asset_id`.
///
/// What the host adds afterwards (its own confidential inputs and one
/// blinded change output) is the host's construction; these rules bound
/// its net outflow to exactly `amount` because its signatures commit to
/// the whole transaction (SIGHASH_ALL).
pub fn verify_fund_template(
    template_b64: &str,
    asset_id: &str,
    amount: u64,
) -> anyhow::Result<FundTemplateSummary> {
    use elements::confidential::{Asset, Value};
    use elements::{BlindAssetProofs as _, BlindValueProofs as _};
    use std::collections::BTreeMap;
    use std::str::FromStr as _;

    anyhow::ensure!(amount > 0, "zero amount");
    let want_asset = elements::AssetId::from_str(asset_id)
        .map_err(|_| anyhow::anyhow!("asset_id is not a 64-hex asset id"))?;

    let pset = decode_pset(template_b64)?;
    anyhow::ensure!(
        !pset.outputs().is_empty(),
        "template has no outputs"
    );

    let secp = elements::secp256k1_zkp::SECP256K1;

    // (in, out) sums per asset, checked arithmetic throughout. Every
    // number that enters here is either explicit on the row or bound to
    // the row's commitments by a proof this function verified — never
    // the relying party's word (docs/fund-template-confidential-proofs.md).
    let mut sums: BTreeMap<elements::AssetId, (u64, u64)> = BTreeMap::new();
    let mut proven_rows = 0usize;

    for (i, input) in pset.inputs().iter().enumerate() {
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("template input {i} has no witness_utxo"))?;
        let (asset, value) = match (utxo.asset, utxo.value) {
            (Asset::Explicit(asset), Value::Explicit(value)) => (asset, value),
            (Asset::Confidential(asset_gen), Value::Confidential(value_commit)) => {
                let (Some(asset), Some(value), Some(asset_proof), Some(value_proof)) = (
                    input.asset,
                    input.amount,
                    input.blind_asset_proof.as_ref(),
                    input.blind_value_proof.as_ref(),
                ) else {
                    anyhow::bail!("template input {i} is confidential — unverifiable, refused");
                };
                anyhow::ensure!(
                    asset_proof.blind_asset_proof_verify(secp, asset, asset_gen),
                    "template input {i}: asset proof does not verify against the commitment"
                );
                anyhow::ensure!(
                    value_proof.blind_value_proof_verify(secp, value, asset_gen, value_commit),
                    "template input {i}: value proof does not verify against the commitment"
                );
                proven_rows += 1;
                (asset, value)
            }
            _ => anyhow::bail!("template input {i} is confidential — unverifiable, refused"),
        };
        let entry = sums.entry(asset).or_default();
        entry.0 = entry
            .0
            .checked_add(value)
            .ok_or_else(|| anyhow::anyhow!("input sum overflow"))?;
    }

    let mut fee = None;
    let mut fee_outputs = 0usize;
    for (i, output) in pset.outputs().iter().enumerate() {
        let (asset, value) = match (output.asset_comm, output.amount_comm) {
            (None, None) => match (output.asset, output.amount) {
                (Some(asset), Some(value)) => (asset, value),
                _ => anyhow::bail!("template output {i} is confidential — unverifiable, refused"),
            },
            (Some(asset_gen), Some(value_commit)) => {
                let (Some(asset), Some(value), Some(asset_proof), Some(value_proof)) = (
                    output.asset,
                    output.amount,
                    output.blind_asset_proof.as_ref(),
                    output.blind_value_proof.as_ref(),
                ) else {
                    anyhow::bail!("template output {i} is confidential — unverifiable, refused");
                };
                anyhow::ensure!(
                    !output.script_pubkey.is_empty(),
                    "template output {i}: the fee output must be explicit"
                );
                anyhow::ensure!(
                    asset_proof.blind_asset_proof_verify(secp, asset, asset_gen),
                    "template output {i}: asset proof does not verify against the commitment"
                );
                anyhow::ensure!(
                    value_proof.blind_value_proof_verify(secp, value, asset_gen, value_commit),
                    "template output {i}: value proof does not verify against the commitment"
                );
                proven_rows += 1;
                (asset, value)
            }
            // one commitment without the other: not a state a blinder
            // produces, and nothing a proof could bind — unverifiable.
            _ => anyhow::bail!("template output {i} is confidential — unverifiable, refused"),
        };
        if output.script_pubkey.is_empty() {
            fee_outputs += 1;
            fee = Some(value);
        }
        let entry = sums.entry(asset).or_default();
        entry.1 = entry
            .1
            .checked_add(value)
            .ok_or_else(|| anyhow::anyhow!("output sum overflow"))?;
    }
    anyhow::ensure!(
        fee_outputs == 1,
        "template must carry exactly one fee output (found {fee_outputs}) — the template pays its own fee"
    );
    let fee = fee.expect("fee_outputs == 1");
    anyhow::ensure!(fee > 0, "template fee output is zero");

    let (asset_in, asset_out) = sums.remove(&want_asset).unwrap_or((0, 0));
    let deficit = asset_out
        .checked_sub(asset_in)
        .ok_or_else(|| anyhow::anyhow!(
            "template has a surplus of the requested asset — nothing to fund"
        ))?;
    anyhow::ensure!(
        deficit == amount,
        "stated amount {amount} does not equal the template's deficit {deficit} for the requested asset"
    );

    for (asset, (asset_in, asset_out)) in sums {
        anyhow::ensure!(
            asset_out <= asset_in,
            "template asks for undeclared funding: asset {asset} outputs {asset_out} exceed inputs {asset_in}"
        );
    }

    Ok(FundTemplateSummary {
        input_count: pset.inputs().len(),
        output_count: pset.outputs().len(),
        fee,
        deficit,
        proven_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::confidential::{Asset, Value};
    use elements::{AssetId, Script, TxOut, TxOutWitness};
    use std::str::FromStr;

    const TESTNET_LBTC: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

    fn explicit_txout(asset: &str, value: u64, script: Script) -> TxOut {
        TxOut {
            asset: Asset::Explicit(AssetId::from_str(asset).unwrap()),
            value: Value::Explicit(value),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: script,
            witness: TxOutWitness::default(),
        }
    }

    /// An explicit send + fee reads back exactly; the fee is the empty
    /// script, and nothing is marked confidential.
    #[test]
    fn explicit_outputs_and_fee_read_back() {
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        let dest = Script::from(vec![0x00, 0x14].into_iter().chain([7u8; 20]).collect::<Vec<u8>>());
        tx.add_output(pset::Output::from_txout(explicit_txout(
            TESTNET_LBTC,
            1_000,
            dest,
        )));
        tx.add_output(pset::Output::from_txout(explicit_txout(
            TESTNET_LBTC,
            100,
            Script::new(),
        )));

        use base64::Engine as _;
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(elements::encode::serialize(&tx));
        let summary = summarize_pset(&b64, Network::LiquidTestnet).unwrap();

        assert_eq!(summary.outputs.len(), 2);
        assert!(summary.fully_explicit);
        assert_eq!(summary.fee, Some(100));
        let payment = &summary.outputs[0];
        assert!(!payment.is_fee);
        assert!(payment.address.is_some());
        assert_eq!(payment.amount, Some(1_000));
        assert_eq!(payment.asset.as_deref(), Some(TESTNET_LBTC));
        assert!(summary.outputs[1].is_fee);
    }

    /// The payjoin service-fee output is marked by script match, and a
    /// context that matches nothing says so instead of succeeding.
    #[test]
    fn payjoin_annotation_marks_by_script_and_reports_misses() {
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        let dest = Script::from(vec![0x00, 0x14].into_iter().chain([7u8; 20]).collect::<Vec<u8>>());
        tx.add_output(pset::Output::from_txout(explicit_txout(
            TESTNET_LBTC,
            1_000,
            dest,
        )));
        use base64::Engine as _;
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(elements::encode::serialize(&tx));
        let mut summary = summarize_pset(&b64, Network::LiquidTestnet).unwrap();

        let fee_address = summary.outputs[0].address.clone().unwrap();
        let marked = summary
            .annotate_payjoin(&PayjoinContext { fee_address })
            .unwrap();
        assert_eq!(marked, 1);
        assert!(summary.outputs[0].is_payjoin_service_fee);

        // A context naming an address this transaction never pays.
        let other = elements::Address::from_script(
            &Script::from(vec![0x00, 0x14].into_iter().chain([9u8; 20]).collect::<Vec<u8>>()),
            None,
            address_params(Network::LiquidTestnet),
        )
        .unwrap()
        .to_string();
        let marked = summary
            .annotate_payjoin(&PayjoinContext { fee_address: other })
            .unwrap();
        assert_eq!(marked, 0, "a mismatch must be visible, not silent");
    }

    const POOL_ASSET: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn pset_b64(tx: &pset::PartiallySignedTransaction) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(elements::encode::serialize(tx))
    }

    fn template_input(asset: &str, value: u64) -> pset::Input {
        let outpoint = elements::OutPoint::new(elements::Txid::from_str(&"11".repeat(32)).unwrap(), 0);
        let mut input = pset::Input::from_prevout(outpoint);
        input.witness_utxo = Some(explicit_txout(asset, value, Script::from(vec![0x51])));
        input
    }

    /// A covenant-deposit-shaped template: pool input + fee input, pool
    /// output grown by the deposit, fee change, explicit fee. The
    /// stated amount must be the template's own arithmetic.
    fn deposit_template() -> pset::PartiallySignedTransaction {
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        tx.add_input(template_input(POOL_ASSET, 500));
        tx.add_input(template_input(TESTNET_LBTC, 1_000));
        tx.add_output(pset::Output::from_txout(explicit_txout(
            POOL_ASSET,
            750,
            Script::from(vec![0x51, 0x20].into_iter().chain([3u8; 32]).collect::<Vec<u8>>()),
        )));
        tx.add_output(pset::Output::from_txout(explicit_txout(
            TESTNET_LBTC,
            100,
            Script::from(vec![0x00, 0x14].into_iter().chain([4u8; 20]).collect::<Vec<u8>>()),
        )));
        tx.add_output(pset::Output::from_txout(explicit_txout(
            TESTNET_LBTC,
            900,
            Script::new(),
        )));
        tx
    }

    /// The template's deficit IS the stated amount; everything else is a
    /// refusal, in the template's own numbers.
    #[test]
    fn fund_template_deficit_is_arithmetic_not_advisory() {
        let b64 = pset_b64(&deposit_template());
        let summary = verify_fund_template(&b64, POOL_ASSET, 250).unwrap();
        assert_eq!(summary.deficit, 250);
        assert_eq!(summary.fee, 900);
        assert_eq!(summary.input_count, 2);
        assert_eq!(summary.output_count, 3);

        // The RP's word does not override the arithmetic.
        let err = verify_fund_template(&b64, POOL_ASSET, 100).unwrap_err();
        assert!(err.to_string().contains("deficit"), "{err}");
        // Zero amount is meaningless.
        assert!(verify_fund_template(&b64, POOL_ASSET, 0).is_err());
    }

    /// Anything confidential in the template is unverifiable: refuse.
    #[test]
    fn fund_template_refuses_confidential_and_missing_utxos() {
        // Input with no witness_utxo.
        let mut tx = deposit_template();
        tx.inputs_mut()[0].witness_utxo = None;
        let err = verify_fund_template(&pset_b64(&tx), POOL_ASSET, 250).unwrap_err();
        assert!(err.to_string().contains("witness_utxo"), "{err}");

        // Confidential output.
        use elements::secp256k1_zkp::{Generator, PedersenCommitment, Tag, Tweak, SECP256K1};
        let mut tx = deposit_template();
        let generator = Generator::new_unblinded(SECP256K1, Tag::from([2u8; 32]));
        let blinding = Tweak::from_slice(&[1u8; 32]).unwrap();
        tx.outputs_mut()[1].amount = None;
        tx.outputs_mut()[1].amount_comm =
            Some(PedersenCommitment::new(SECP256K1, 100, blinding, generator));
        let err = verify_fund_template(&pset_b64(&tx), POOL_ASSET, 250).unwrap_err();
        assert!(err.to_string().contains("confidential"), "{err}");
    }

    /// The template funds itself in every asset but the requested one —
    /// a hidden L-BTC ask is a refusal, and so is a missing or doubled
    /// fee output.
    #[test]
    fn fund_template_refuses_undeclared_asks() {
        // L-BTC outputs exceed L-BTC inputs: an undeclared ask.
        let mut tx = deposit_template();
        tx.outputs_mut()[1].amount = Some(500);
        let err = verify_fund_template(&pset_b64(&tx), POOL_ASSET, 250).unwrap_err();
        assert!(err.to_string().contains("undeclared"), "{err}");

        // No fee output: the template must pay its own fee.
        let mut tx = deposit_template();
        tx.outputs_mut()[2].script_pubkey = Script::from(vec![0x51]);
        let err = verify_fund_template(&pset_b64(&tx), POOL_ASSET, 250).unwrap_err();
        assert!(err.to_string().contains("fee output"), "{err}");
    }

    /// A blinded output must be reported as unreadable, and the summary
    /// as not fully explicit — never a partial number shown as a total.
    #[test]
    fn confidential_outputs_are_marked_not_guessed() {
        use elements::secp256k1_zkp::{Generator, PedersenCommitment, Tag, Tweak, SECP256K1};
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        let mut out = pset::Output::from_txout(explicit_txout(
            TESTNET_LBTC,
            1_000,
            Script::from(vec![0x51]),
        ));
        // A real value commitment, so the PSET stays serializable while
        // the amount is genuinely unreadable.
        let generator = Generator::new_unblinded(SECP256K1, Tag::from([2u8; 32]));
        let blinding = Tweak::from_slice(&[1u8; 32]).unwrap();
        out.amount = None;
        out.amount_comm = Some(PedersenCommitment::new(SECP256K1, 1_000, blinding, generator));
        tx.add_output(out);

        use base64::Engine as _;
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(elements::encode::serialize(&tx));
        let summary = summarize_pset(&b64, Network::LiquidTestnet).unwrap();
        assert!(!summary.fully_explicit);
        assert!(summary.outputs[0].confidential);
        assert_eq!(summary.outputs[0].amount, None);
    }

    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
    use elements::secp256k1_zkp::{Generator, PedersenCommitment, RangeProof, SurjectionProof, SECP256K1};
    use elements::{BlindAssetProofs as _, BlindValueProofs as _};

    /// A confidential row the way a relying party would ship it: fresh
    /// blinding factors, real commitments, and the two proofs that bind
    /// the explicit amount and asset to them.
    fn proven_confidential(asset: &str, value: u64) -> (TxOut, RangeProof, SurjectionProof) {
        let mut rng = rand::thread_rng();
        let asset_id = AssetId::from_str(asset).unwrap();
        let abf = AssetBlindingFactor::new(&mut rng);
        let vbf = ValueBlindingFactor::new(&mut rng);
        let asset_gen = Generator::new_blinded(SECP256K1, asset_id.into_tag(), abf.into_inner());
        let value_commit = PedersenCommitment::new(SECP256K1, value, vbf.into_inner(), asset_gen);
        let value_proof =
            RangeProof::blind_value_proof(&mut rng, SECP256K1, value, value_commit, asset_gen, vbf).unwrap();
        let asset_proof = SurjectionProof::blind_asset_proof(&mut rng, SECP256K1, asset_id, abf).unwrap();
        let txout = TxOut {
            asset: Asset::Confidential(asset_gen),
            value: Value::Confidential(value_commit),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: TxOutWitness::default(),
        };
        (txout, value_proof, asset_proof)
    }

    fn proven_input(asset: &str, value: u64, claimed: u64) -> pset::Input {
        let (utxo, value_proof, asset_proof) = proven_confidential(asset, value);
        let outpoint = elements::OutPoint::new(elements::Txid::from_str(&"22".repeat(32)).unwrap(), 1);
        let mut input = pset::Input::from_prevout(outpoint);
        input.witness_utxo = Some(utxo);
        input.amount = Some(claimed);
        input.asset = Some(AssetId::from_str(asset).unwrap());
        input.blind_value_proof = Some(Box::new(value_proof));
        input.blind_asset_proof = Some(Box::new(asset_proof));
        input
    }

    fn proven_output(asset: &str, value: u64) -> pset::Output {
        let (utxo, value_proof, asset_proof) = proven_confidential(asset, value);
        let mut output = pset::Output::from_txout(utxo);
        output.amount = Some(value);
        output.asset = Some(AssetId::from_str(asset).unwrap());
        output.blind_value_proof = Some(Box::new(value_proof));
        output.blind_asset_proof = Some(Box::new(asset_proof));
        output
    }

    /// Option B: the deposit template with the pool input and the pool
    /// output confidential-with-proofs. Same arithmetic, two proven rows.
    #[test]
    fn fund_template_accepts_confidential_rows_with_verifying_proofs() {
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        tx.add_input(proven_input(POOL_ASSET, 500, 500));
        tx.add_input(template_input(TESTNET_LBTC, 1_000));
        tx.add_output(proven_output(POOL_ASSET, 750));
        tx.add_output(pset::Output::from_txout(explicit_txout(
            TESTNET_LBTC,
            100,
            Script::from(vec![0x00, 0x14].into_iter().chain([4u8; 20]).collect::<Vec<u8>>()),
        )));
        tx.add_output(pset::Output::from_txout(explicit_txout(TESTNET_LBTC, 900, Script::new())));

        let summary = verify_fund_template(&pset_b64(&tx), POOL_ASSET, 250).unwrap();
        assert_eq!(summary.deficit, 250);
        assert_eq!(summary.proven_rows, 2);
        assert_eq!(summary.fee, 900);
    }

    /// A proof binds ONE amount: claiming a different explicit amount
    /// beside a valid commitment is refused, as is a confidential row
    /// with no proofs at all, and a "fee" that hides behind commitments.
    #[test]
    fn fund_template_refuses_wrong_or_missing_proofs() {
        let mut tx = pset::PartiallySignedTransaction::new_v2();
        tx.add_input(proven_input(POOL_ASSET, 500, 600));
        tx.add_input(template_input(TESTNET_LBTC, 1_000));
        tx.add_output(pset::Output::from_txout(explicit_txout(POOL_ASSET, 750, Script::from(vec![0x51]))));
        tx.add_output(pset::Output::from_txout(explicit_txout(TESTNET_LBTC, 900, Script::new())));
        let err = verify_fund_template(&pset_b64(&tx), POOL_ASSET, 150).unwrap_err();
        assert!(err.to_string().contains("value proof does not verify"), "{err}");

        let mut tx = pset::PartiallySignedTransaction::new_v2();
        let mut bare = proven_input(POOL_ASSET, 500, 500);
        bare.blind_value_proof = None;
        bare.blind_asset_proof = None;
        tx.add_input(bare);
        tx.add_input(template_input(TESTNET_LBTC, 1_000));
        tx.add_output(pset::Output::from_txout(explicit_txout(POOL_ASSET, 750, Script::from(vec![0x51]))));
        tx.add_output(pset::Output::from_txout(explicit_txout(TESTNET_LBTC, 900, Script::new())));
        let err = verify_fund_template(&pset_b64(&tx), POOL_ASSET, 250).unwrap_err();
        assert!(err.to_string().contains("confidential — unverifiable"), "{err}");

        let mut tx = pset::PartiallySignedTransaction::new_v2();
        tx.add_input(template_input(POOL_ASSET, 500));
        tx.add_input(template_input(TESTNET_LBTC, 1_000));
        tx.add_output(pset::Output::from_txout(explicit_txout(POOL_ASSET, 750, Script::from(vec![0x51]))));
        let mut hidden_fee = proven_output(TESTNET_LBTC, 900);
        hidden_fee.script_pubkey = Script::new();
        tx.add_output(hidden_fee);
        let err = verify_fund_template(&pset_b64(&tx), POOL_ASSET, 250).unwrap_err();
        assert!(err.to_string().contains("fee output must be explicit"), "{err}");
    }
}
