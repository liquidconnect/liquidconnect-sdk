//! Client for SideSwap's payjoin service: pay Liquid network fees in an
//! asset (USDt) instead of L-BTC, so a wallet holding only that asset is
//! never stranded.
//!
//! Wire types vendored from `sideswap-io/sideswap_rust`
//! (`sideswap_payjoin/src/server_api.rs`, MIT). The flow is three HTTP
//! calls to `{base}/payjoin`:
//!
//! 1. [`accepted_assets`] — which assets may pay fees.
//! 2. [`start`] — opens an order: the server quotes a price and a fixed
//!    fee, and contributes its own L-BTC UTXOs *with blinding data* so
//!    the client can build a combined transaction.
//! 3. The client builds and blinds the PSET — its fee-asset inputs plus
//!    the server's L-BTC inputs; outputs to the recipients, its own
//!    change, the service fee to `fee_address`, the server's change to
//!    `change_address`; then [`sign`] returns the server's signatures
//!    over its own inputs. The client signs its inputs and broadcasts.
//!
//! This module is deliberately the *protocol* client only. Transaction
//! construction and blinding belong to the wallet's own machinery (every
//! real wallet has one); the reference construction lives upstream in
//! `sideswap_payjoin::create_payjoin`, and the selection rules in
//! `sideswap_common/src/utxo_select/payjoin.rs`. What a correct client
//! must reproduce from them: the service fee is
//! `ceil(network_fee × price) + fixed_fee` in the fee asset
//! ([`estimate_service_fee`]), explicit values are stripped from the
//! PSET sent to [`sign`], and the server's signatures are copied into
//! the client's fully-blinded copy.

use serde::{Deserialize, Serialize};

pub const BASE_URL_PROD: &str = "https://api.sideswap.io";
pub const BASE_URL_TESTNET: &str = "https://api-testnet.sideswap.io";

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptedAssetsRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptedAssetsResponse {
    pub accepted_asset: Vec<AcceptedAsset>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptedAsset {
    pub asset_id: elements::AssetId,
}

/// A server-contributed L-BTC input, blinding data included — the whole
/// point of the service: these pay the network fee.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Utxo {
    pub txid: elements::Txid,
    pub vout: u32,
    pub script_pub_key: elements::script::Script,
    pub asset_id: elements::AssetId,
    pub value: u64,
    pub asset_bf: elements::confidential::AssetBlindingFactor,
    pub value_bf: elements::confidential::ValueBlindingFactor,
    pub asset_commitment: elements::secp256k1_zkp::Generator,
    pub value_commitment: elements::secp256k1_zkp::PedersenCommitment,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StartRequest {
    pub asset_id: elements::AssetId,
    pub user_agent: String,
    pub api_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StartResponse {
    pub order_id: String,
    pub expires_at: u64,
    /// Fee-asset units per L-BTC satoshi of network fee.
    pub price: f64,
    /// Flat service fee in fee-asset satoshis, on top of the converted
    /// network fee.
    pub fixed_fee: u64,
    pub fee_address: elements::Address,
    pub change_address: elements::Address,
    pub utxos: Vec<Utxo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub order_id: String,
    /// Base64 PSET with explicit values stripped — the server signs its
    /// own inputs and sees nothing else in the clear.
    pub pset: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub pset: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Request {
    AcceptedAssets(AcceptedAssetsRequest),
    Start(StartRequest),
    Sign(SignRequest),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Response {
    AcceptedAssets(AcceptedAssetsResponse),
    Start(StartResponse),
    Sign(SignResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerError {
    pub error: String,
}

/// The service fee for an order, in fee-asset satoshis. The minimum the
/// server accepts; a client that can produce a changeless transaction
/// may pay the surplus as fee instead (see the upstream selection).
pub fn estimate_service_fee(network_fee_sats: u64, price: f64, fixed_fee: u64) -> u64 {
    (network_fee_sats as f64 * price) as u64 + fixed_fee
}

fn call(base_url: &str, request: &Request) -> anyhow::Result<Response> {
    let url = format!("{base_url}/payjoin");
    let response = ureq::post(&url)
        .timeout(std::time::Duration::from_secs(30))
        .send_json(request);
    match response {
        Ok(body) => Ok(body.into_json()?),
        Err(ureq::Error::Status(code, body)) => {
            let detail = body
                .into_json::<ServerError>()
                .map(|e| e.error)
                .unwrap_or_else(|_| "unreadable error body".to_owned());
            anyhow::bail!("payjoin server refused ({code}): {detail}");
        }
        Err(err) => Err(err.into()),
    }
}

pub fn accepted_assets(base_url: &str) -> anyhow::Result<Vec<elements::AssetId>> {
    match call(base_url, &Request::AcceptedAssets(AcceptedAssetsRequest {}))? {
        Response::AcceptedAssets(resp) => {
            anyhow::ensure!(!resp.accepted_asset.is_empty(), "empty payjoin asset list");
            Ok(resp.accepted_asset.into_iter().map(|a| a.asset_id).collect())
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub fn start(
    base_url: &str,
    asset_id: elements::AssetId,
    user_agent: &str,
    api_key: Option<String>,
) -> anyhow::Result<StartResponse> {
    match call(
        base_url,
        &Request::Start(StartRequest {
            asset_id,
            user_agent: user_agent.to_owned(),
            api_key,
        }),
    )? {
        Response::Start(resp) => {
            anyhow::ensure!(resp.fee_address.is_blinded(), "fee address not blinded");
            anyhow::ensure!(
                resp.change_address.is_blinded(),
                "change address not blinded"
            );
            anyhow::ensure!(!resp.utxos.is_empty(), "server contributed no inputs");
            Ok(resp)
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

pub fn sign(base_url: &str, order_id: &str, pset_b64: &str) -> anyhow::Result<String> {
    match call(
        base_url,
        &Request::Sign(SignRequest {
            order_id: order_id.to_owned(),
            pset: pset_b64.to_owned(),
        }),
    )? {
        Response::Sign(resp) => Ok(resp.pset),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The envelope is snake_case-tagged JSON; pinned like the connect
    /// wire, because it is someone else's server.
    #[test]
    fn request_envelope_shape_is_pinned() {
        let req = Request::AcceptedAssets(AcceptedAssetsRequest {});
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"accepted_assets":{}}"#
        );
    }

    /// The reference formula from upstream utxo_select/payjoin.rs.
    #[test]
    fn service_fee_matches_the_upstream_formula() {
        // network_fee=1000 sats, price=0.05 USDt-sats per L-BTC-sat,
        // fixed_fee=100 → 50 + 100.
        assert_eq!(estimate_service_fee(1_000, 0.05, 100), 150);
        assert_eq!(estimate_service_fee(0, 0.05, 100), 100);
    }
}
