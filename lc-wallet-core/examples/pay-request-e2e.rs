//! Live end-to-end proof of the StartPay relay against a real connect
//! server: this example plays BOTH roles over real websockets — an RP
//! (speaking the server's rp_api JSON) that logs in, links a session,
//! and starts a pay request; and the SDK wallet transport that receives
//! the intent and answers with a host-built txid.
//!
//! The SDK never builds transactions, so the "host build" here is a
//! stand-in txid — what is being proven is the RELAY: intent out to the
//! wallet with every field intact, txid back to the RP with client_data
//! echoed, and a malformed intent refused before any wallet sees it.
//! The real build+sign+broadcast lives in the app's send machinery and
//! is exercised there.
//!
//! Run against a local throwaway connect server (swaption_be
//! `connect_server`, `env = "LocalTestnet"`):
//!
//!     pay-request-e2e [wallet_ws] [rp_ws]
//!     (defaults ws://127.0.0.1:51235 ws://127.0.0.1:51236)

use futures::{SinkExt, StreamExt};
use lc_wallet_core::key::{Network, WalletKey};
use lc_wallet_core::transport::{WalletConnect, WalletConnectConfig, WalletEvent};
use lc_wallet_core::wire;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

const SEED: [u8; 32] = [0x6d; 32];

fn descriptor(seed: &[u8; 32]) -> String {
    use elements::bitcoin::bip32::{Xpriv, Xpub};
    let secp = elements::bitcoin::secp256k1::Secp256k1::new();
    let master = Xpriv::new_master(elements::bitcoin::NetworkKind::Test, seed).expect("seed ok");
    let xpub = Xpub::from_priv(&secp, &master);
    format!("ct(slip77({}),elwpkh({xpub}/<0;1>/*))", hex::encode(seed))
}

struct Rp {
    sink: futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    source: futures::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    next_id: i64,
}

impl Rp {
    async fn connect(url: &str) -> anyhow::Result<Rp> {
        let (stream, _) = tokio_tungstenite::connect_async(url).await?;
        let (sink, source) = stream.split();
        Ok(Rp {
            sink,
            source,
            next_id: 1,
        })
    }

    async fn request(&mut self, req: Value) -> anyhow::Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let frame = json!({"Req": {"id": id, "req": req}});
        self.sink
            .send(Message::Text(frame.to_string().into()))
            .await?;
        loop {
            let msg = self.recv().await?;
            if let Some(resp) = msg.pointer("/Resp") {
                anyhow::ensure!(
                    resp.get("id").and_then(Value::as_i64) == Some(id),
                    "response id mismatch: {resp}"
                );
                return Ok(resp.get("resp").cloned().unwrap_or(Value::Null));
            }
            if let Some(err) = msg.pointer("/Error") {
                anyhow::bail!("rp request failed: {err}");
            }
        }
    }

    async fn recv(&mut self) -> anyhow::Result<Value> {
        loop {
            match self.source.next().await {
                Some(Ok(Message::Text(text))) => return Ok(serde_json::from_str(&text)?),
                Some(Ok(Message::Ping(_))) | Some(Ok(_)) => continue,
                Some(Err(err)) => anyhow::bail!("rp socket error: {err}"),
                None => anyhow::bail!("rp socket closed"),
            }
        }
    }

    async fn wait_notif(&mut self, kind: &str) -> anyhow::Result<Value> {
        loop {
            let msg = self.recv().await?;
            if let Some(notif) = msg.pointer(&format!("/Notif/notif/{kind}")) {
                return Ok(notif.clone());
            }
        }
    }

    /// Wait for this pay request to leave `Active`, skipping unrelated
    /// notifications. Returns the whole request object so the caller can
    /// check the client_data echo alongside the status.
    async fn wait_pay_terminal(&mut self, request_id: &str) -> anyhow::Result<Value> {
        loop {
            let notif = self.wait_notif("PayRequestUpdated").await?;
            let request = &notif["pay_request"];
            if request["request_id"].as_str() == Some(request_id)
                && request["status"].as_str() != Some("Active")
            {
                return Ok(request.clone());
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let wallet_ws = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:51235".to_owned());
    let rp_ws = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "ws://127.0.0.1:51236".to_owned());

    let identity_pk = WalletKey::new(&SEED, Network::LiquidTestnet)
        .public_key()
        .to_string();
    println!("wallet identity: {identity_pk}");

    let recipient = elements::Address::p2sh(
        &Default::default(),
        None,
        &elements::AddressParams::ELEMENTS,
    )
    .to_string();
    let asset_id = "22".repeat(32);
    let amount = 100_000u64;
    let memo = "RF deposit";
    let client_data = r#"{"venueAccount":7,"nonce":"abc123"}"#;
    let host_txid = "cd".repeat(32);

    // The wallet role: the SDK transport; the "host build" is a stand-in
    // txid, delivered only after checking the intent arrived intact.
    let expect_recipient = recipient.clone();
    let expect_asset = asset_id.clone();
    let reply_txid = host_txid.clone();
    let (wallet, mut events) = WalletConnect::spawn(WalletConnectConfig {
        url: wallet_ws,
        descriptor: descriptor(&SEED),
        key: WalletKey::new(&SEED, Network::LiquidTestnet),
        install_id: wire::InstallId::random(),
    });
    let wallet_task = wallet.clone();
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                WalletEvent::LoginRequested(req) => {
                    println!("wallet: login request from {}, accepting", req.domain);
                    wallet_task.accept_login(&req.request_id);
                }
                WalletEvent::PayRequested(req) => {
                    println!(
                        "wallet: pay request from {}: {} of {} to {}, memo {:?}",
                        req.domain, req.amount, req.asset_id, req.recipient, req.memo
                    );
                    if req.recipient != expect_recipient
                        || req.asset_id != expect_asset
                        || req.amount != 100_000
                        || req.memo.as_deref() != Some("RF deposit")
                    {
                        println!("wallet: intent did not arrive intact, rejecting");
                        wallet_task.reject_pay(&req.request_id);
                        continue;
                    }
                    // Host build stand-in: sign+send would happen here.
                    wallet_task.accept_pay(&req.request_id, &reply_txid);
                }
                other => log::debug!("wallet event: {other:?}"),
            }
        }
    });

    // The RP role.
    let mut rp = Rp::connect(&rp_ws).await?;
    rp.request(json!({"Login": {"domain": "paper.swaption.io"}}))
        .await?;
    let start_login = rp
        .request(json!({"StartLogin": {"client_data": null}}))
        .await?;
    let request_id = start_login["StartLogin"]["login_request"]["request_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no request_id in {start_login}"))?
        .to_owned();
    println!("rp: login request {request_id}, handing link to the wallet");
    wallet.open_link(&format!("liquidconnect://login/?request_id={request_id}"))?;

    let session = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        rp.wait_notif("SessionCreated"),
    )
    .await??;
    let session_id = session["session"]["session_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no session_id in {session}"))?
        .to_owned();
    let wallet_id = session["session"]["wallet_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    println!("rp: session {session_id} for wallet {wallet_id}");
    anyhow::ensure!(wallet_id == identity_pk, "session bound to the wrong key");

    // 1. A malformed intent is refused before any wallet sees it.
    let bad = rp
        .request(json!({"StartPay": {
            "session_id": session_id,
            "recipient": "not-an-address",
            "asset_id": asset_id,
            "amount": amount,
            "memo": memo,
            "client_data": client_data,
            "ttl": 60000,
        }}))
        .await;
    anyhow::ensure!(bad.is_err(), "malformed recipient must be refused");
    println!("PASS malformed intent refused: {}", bad.unwrap_err());

    // 2. The real intent round-trips: out intact, txid back, client_data
    // echoed on the terminal status.
    let resp = rp
        .request(json!({"StartPay": {
            "session_id": session_id,
            "recipient": recipient,
            "asset_id": asset_id,
            "amount": amount,
            "memo": memo,
            "client_data": client_data,
            "ttl": 60000,
        }}))
        .await?;
    let pay_request_id = resp["StartPay"]["pay_request"]["request_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no pay request id in {resp}"))?
        .to_owned();
    println!("rp: pay request {pay_request_id} started");

    let terminal = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        rp.wait_pay_terminal(&pay_request_id),
    )
    .await??;
    let txid = terminal["status"]["Succeed"]["txid"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("pay request did not succeed: {terminal}"))?;
    anyhow::ensure!(txid == host_txid, "txid did not round-trip: {txid}");
    anyhow::ensure!(
        terminal["client_data"].as_str() == Some(client_data),
        "client_data was not echoed: {terminal}"
    );
    println!("PASS pay request: intent relayed intact, txid returned, client_data echoed");

    println!("pay-request relay proven end to end");
    Ok(())
}
