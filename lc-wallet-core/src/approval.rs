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
}
