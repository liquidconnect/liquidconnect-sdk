//! Live end-to-end proof of the StartSignMessage relay against a real
//! connect server: this example plays BOTH roles over real websockets —
//! an RP (speaking the server's rp_api JSON) that logs in, links a
//! session, and starts sign-message requests; and the SDK wallet
//! transport that receives and approves them.
//!
//! Two requests are proven:
//! 1. a TYPED venue order (canonical JSON description): the wallet
//!    rebuilds the digest from the fields under its venue key, refuses
//!    mismatches, clear-signs with the venue money key;
//! 2. an OPAQUE request: the session core signs its stored digest with
//!    the Connect identity key.
//! The RP verifies each returned BIP340 signature against the right key.
//!
//! Run against a local throwaway connect server (swaption_be
//! `connect_server`, `env = "LocalTestnet"`):
//!
//!     sign-message-e2e [wallet_ws] [rp_ws]
//!     (defaults ws://127.0.0.1:51235 ws://127.0.0.1:51236)

use futures::{SinkExt, StreamExt};
use lc_wallet_core::key::{Network, WalletKey};
use lc_wallet_core::transport::{WalletConnect, WalletConnectConfig, WalletEvent};
use lc_wallet_core::{venue, wire};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

const SEED: [u8; 32] = [0x5c; 32];

fn descriptor(seed: &[u8; 32]) -> String {
    use elements::bitcoin::bip32::{Xpriv, Xpub};
    let secp = elements::bitcoin::secp256k1::Secp256k1::new();
    let master = Xpriv::new_master(elements::bitcoin::NetworkKind::Test, seed).expect("seed ok");
    let xpub = Xpub::from_priv(&secp, &master);
    // The slip77 key doubles as the Connect identity input, so the
    // descriptor and the wallet key describe one wallet.
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
        self.sink.send(Message::Text(frame.to_string().into())).await?;
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
            // Notifs while waiting for the response are fine to skip
            // here; the dedicated waiters below read them.
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

    /// Wait for this sign-message request to leave `Active`, skipping
    /// unrelated notifications.
    async fn wait_sign_message_terminal(&mut self, request_id: &str) -> anyhow::Result<Value> {
        loop {
            let notif = self.wait_notif("SignMessageRequestUpdated").await?;
            let request = &notif["sign_message_request"];
            if request["request_id"].as_str() == Some(request_id)
                && request["status"].as_str() != Some("Active")
            {
                return Ok(request["status"].clone());
            }
        }
    }
}

fn verify(signature_hex: &str, digest: &[u8; 32], pk_hex: &str) -> anyhow::Result<()> {
    use elements::secp256k1_zkp::{schnorr::Signature, Message as SecpMessage, SECP256K1};
    let signature = Signature::from_slice(&hex::decode(signature_hex)?)?;
    let pk = elements::schnorr::XOnlyPublicKey::from_slice(&hex::decode(pk_hex)?)?;
    SECP256K1.verify_schnorr(&signature, &SecpMessage::from_digest(*digest), &pk)?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let wallet_ws = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:51235".to_owned());
    let rp_ws = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "ws://127.0.0.1:51236".to_owned());

    let identity_key = WalletKey::new(&SEED, Network::LiquidTestnet);
    let identity_pk = identity_key.public_key().to_string();
    let venue_key = venue::VenueKey::from_seed(&SEED, Network::LiquidTestnet)?;
    let venue_pk = venue_key.public_key().serialize();
    println!("wallet identity: {identity_pk}");
    println!("venue account:   {}", hex::encode(venue_pk));

    // The wallet role: the SDK transport, approving what arrives.
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
                WalletEvent::SignMessageRequested(req) => {
                    let typed = req
                        .description
                        .as_deref()
                        .and_then(venue::parse_typed_description);
                    match typed {
                        Some(Ok(typed_request)) => {
                            // Clear-sign: rebuild the digest from the typed
                            // fields, refuse mismatches, sign with the
                            // venue money key.
                            let rebuilt =
                                venue::typed_request_digest(&typed_request, &venue_pk).unwrap();
                            if hex::encode(rebuilt) != req.digest.to_lowercase() {
                                println!("wallet: typed digest mismatch, rejecting");
                                wallet_task.reject_sign_message(&req.request_id);
                                continue;
                            }
                            let venue_key =
                                venue::VenueKey::from_seed(&SEED, Network::LiquidTestnet).unwrap();
                            let (_digest, signature) = match venue_key.sign_typed(&typed_request) {
                                Ok(signed) => signed,
                                Err(err) => {
                                    println!("wallet: cannot sign typed request ({err}), rejecting");
                                    wallet_task.reject_sign_message(&req.request_id);
                                    continue;
                                }
                            };
                            println!("wallet: typed venue request verified, clear-signing");
                            wallet_task
                                .accept_sign_message_signed(&req.request_id, &signature.to_string());
                        }
                        Some(Err(err)) => {
                            println!("wallet: malformed typed request ({err}), rejecting");
                            wallet_task.reject_sign_message(&req.request_id);
                        }
                        None => {
                            println!(
                                "wallet: opaque request \"{}\", identity key signs",
                                req.description.as_deref().unwrap_or("")
                            );
                            wallet_task.accept_sign_message(&req.request_id);
                        }
                    }
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

    // 1. The typed venue order, clear-signed with the venue key.
    let (side, price, qty, expiry, nonce) = (venue::OrderSide::Sell, 7_700_000_000u64, 1_000u64, 50u32, 1u64);
    let digest = venue::order_digest(&venue_pk, side, price, qty, expiry, nonce, None);
    let description = format!(
        r#"{{"kind":"rf/order/v1","product":"RF-BTC-USDT","side":"sell","price":"{price}","qty":"{qty}","expiry":{expiry},"nonce":"{nonce}"}}"#
    );
    let resp = rp
        .request(json!({"StartSignMessage": {
            "session_id": session_id,
            "digest": hex::encode(digest),
            "description": description,
            "client_data": null,
            "ttl": 60000,
        }}))
        .await?;
    let typed_request_id = resp["StartSignMessage"]["sign_message_request"]["request_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no sign request id in {resp}"))?
        .to_owned();
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        rp.wait_sign_message_terminal(&typed_request_id),
    )
    .await??;
    let signature = status["Succeed"]["signature"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("typed request did not succeed: {status}"))?;
    verify(signature, &digest, &hex::encode(venue_pk))?;
    println!("PASS typed venue order: signature verifies against the venue key");

    // 2. The opaque request, signed by the identity key.
    let opaque_digest = [0x42u8; 32];
    let resp = rp
        .request(json!({"StartSignMessage": {
            "session_id": session_id,
            "digest": hex::encode(opaque_digest),
            "description": "Test opaque approval",
            "client_data": null,
            "ttl": 60000,
        }}))
        .await?;
    let opaque_request_id = resp["StartSignMessage"]["sign_message_request"]["request_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no sign request id in {resp}"))?
        .to_owned();
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        rp.wait_sign_message_terminal(&opaque_request_id),
    )
    .await??;
    let signature = status["Succeed"]["signature"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("opaque request did not succeed: {status}"))?;
    verify(signature, &opaque_digest, &identity_pk)?;
    println!("PASS opaque message: signature verifies against the identity key");

    println!("sign-message relay proven end to end");
    Ok(())
}
