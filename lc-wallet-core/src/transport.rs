//! A ready-made tokio transport for integrations that do not bring their
//! own networking: owns the WebSocket, reconnects with backoff, sends
//! keepalive pings, and drives the sans-io core. Everything it does can
//! be done by driving [`crate::core::WalletConnectCore`] directly.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::core::{Effect, Input, TransportEvent, WalletConnectCore};
use crate::key::WalletKey;
use crate::wire;

const PING_INTERVAL: Duration = Duration::from_secs(30);
const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(60);

/// What the integration renders. A direct mapping of the core's UI
/// effects plus connection state, because an approval screen that cannot
/// say "offline" shows stale requests as live ones.
#[derive(Debug)]
pub enum WalletEvent {
    Connected,
    LoggedIn,
    Disconnected,

    LoginRequested(wire::LoginRequest),
    LoginRequestRemoved { request_id: String },

    SignRequested(wire::SignRequest),
    SignRequestRemoved { request_id: String },

    SignMessageRequested(wire::SignMessageRequest),
    ReceiveAddressRequested(wire::ReceiveAddressRequest),
    ReceiveAddressRequestRemoved {
        request_id: String,
    },
    SignMessageRequestRemoved { request_id: String },

    PayRequested(wire::PayRequest),
    PayRequestRemoved { request_id: String },

    FundRequested(wire::FundRequest),
    FundRequestRemoved { request_id: String },

    Sessions(Vec<wire::Session>),

    /// The server refused an action this wallet sent (e.g. a link for an
    /// unknown or expired login request) — render it, don't swallow it.
    ActionFailed {
        action: wire::UserAction,
        message: String,
    },
    SessionCreated(wire::Session),
    SessionRemoved { session_id: String },

    MinimizeMobileApp,
}

pub struct WalletConnectConfig {
    /// `wire::MAINNET_URL` or `wire::TESTNET_URL` for the public servers.
    pub url: String,
    pub descriptor: String,
    pub key: WalletKey,
    /// Persist and reuse: the server keys push registration on it.
    pub install_id: wire::InstallId,
}

/// Handle for feeding user decisions in. Dropping it stops the actor.
#[derive(Clone)]
pub struct WalletConnect {
    input_tx: mpsc::UnboundedSender<Input>,
}

impl WalletConnect {
    pub fn spawn(config: WalletConnectConfig) -> (Self, mpsc::UnboundedReceiver<WalletEvent>) {
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        tokio::spawn(run(config, input_rx, event_tx));
        (WalletConnect { input_tx }, event_rx)
    }

    /// Feed a scanned QR payload or opened app link.
    pub fn open_link(&self, url: &str) -> anyhow::Result<()> {
        let app_link = crate::link::parse_app_link(url)?;
        self.send(Input::AppLink { app_link });
        Ok(())
    }

    pub fn accept_login(&self, request_id: &str) {
        self.send(Input::LoginAccepted {
            request_id: request_id.to_owned(),
            service_binding: None,
        });
    }

    /// Approve a login that asked for a service-key binding, supplying
    /// the key and the signature this integration made over
    /// `venue::service_login_digest` (see `WalletEvent::LoginRequested`'s
    /// `service_challenge`).
    pub fn accept_login_with_service_key(
        &self,
        request_id: &str,
        key: &str,
        signature: &str,
    ) {
        self.send(Input::LoginAccepted {
            request_id: request_id.to_owned(),
            service_binding: Some(crate::core::ServiceBinding {
                key: key.to_owned(),
                signature: signature.to_owned(),
            }),
        });
    }

    pub fn reject_login(&self, request_id: &str) {
        self.send(Input::LoginRejected {
            request_id: request_id.to_owned(),
        });
    }

    /// The wallet signs the PSET itself, with its own keys, after its own
    /// verification — this only delivers the result.
    pub fn accept_sign(&self, request_id: &str, signed_pset: &str) {
        self.send(Input::SignAccepted {
            request_id: request_id.to_owned(),
            signed_pset: signed_pset.to_owned(),
        });
    }

    pub fn reject_sign(&self, request_id: &str) {
        self.send(Input::SignRejected {
            request_id: request_id.to_owned(),
        });
    }

    /// Approve a message-signing request by id. The core signs the digest
    /// it stored from the server's request with the wallet key — the host
    /// never supplies the bytes to sign.
    pub fn accept_sign_message(&self, request_id: &str) {
        self.send(Input::SignMessageAccepted {
            request_id: request_id.to_owned(),
        });
    }

    /// Approve a message-signing request with a signature produced in
    /// another signer (the venue money key after a typed clear-sign, or
    /// a hardware signer). 64-byte BIP340 signature over the request's
    /// digest, hex-encoded.
    pub fn accept_sign_message_signed(&self, request_id: &str, signature: &str) {
        self.send(Input::SignMessageSigned {
            request_id: request_id.to_owned(),
            signature: signature.to_owned(),
        });
    }

    pub fn reject_sign_message(&self, request_id: &str) {
        self.send(Input::SignMessageRejected {
            request_id: request_id.to_owned(),
        });
    }

    /// Approve a pay request with the txid of the payment the wallet
    /// built, signed and broadcast itself. This SDK never builds the
    /// transaction — the host's send machinery does, renders the real
    /// recipient/amount/fee for the user, and hands back only the txid.
    /// Answer a receive-address request. The address MUST be fresh and in
    /// the session's network — this crate does not manage the address
    /// chain and cannot check either (docs/receive-address-spec.md).
    pub fn provide_receive_address(&self, request_id: &str, address: &str) {
        self.send(Input::ReceiveAddressProvided {
            request_id: request_id.to_owned(),
            address: address.to_owned(),
        });
    }

    pub fn reject_receive_address(&self, request_id: &str) {
        self.send(Input::ReceiveAddressRejected {
            request_id: request_id.to_owned(),
        });
    }

    pub fn accept_pay(&self, request_id: &str, txid: &str) {
        self.send(Input::PayBuilt {
            request_id: request_id.to_owned(),
            txid: txid.to_owned(),
        });
    }

    pub fn reject_pay(&self, request_id: &str) {
        self.send(Input::PayRejected {
            request_id: request_id.to_owned(),
        });
    }

    /// Approve a fund request with the HOST-funded template: wallet
    /// inputs and one blinded change added, wallet inputs signed. Run
    /// `approval::verify_fund_template` before ever showing the request.
    pub fn accept_fund(&self, request_id: &str, pset: &str) {
        self.send(Input::FundSigned {
            request_id: request_id.to_owned(),
            pset: pset.to_owned(),
        });
    }

    pub fn reject_fund(&self, request_id: &str) {
        self.send(Input::FundRejected {
            request_id: request_id.to_owned(),
        });
    }

    pub fn stop_session(&self, session_id: &str) {
        self.send(Input::StopSession {
            session_id: session_id.to_owned(),
        });
    }

    pub fn register_fcm_token(&self, token: &str) {
        self.send(Input::RegisterFcmToken {
            token: token.to_owned(),
        });
    }

    fn send(&self, input: Input) {
        // The actor outlives every clone of the handle unless the runtime
        // is shutting down, in which case there is nobody to tell.
        let _ = self.input_tx.send(input);
    }
}

fn apply_effects(
    effects: Vec<Effect>,
    outgoing: &mut Vec<String>,
    event_tx: &mpsc::UnboundedSender<WalletEvent>,
) {
    for effect in effects {
        let event = match effect {
            Effect::Send { data } => {
                outgoing.push(data);
                continue;
            }
            Effect::AddLoginRequest { request } => WalletEvent::LoginRequested(request),
            Effect::RemoveLoginRequest { request_id } => {
                WalletEvent::LoginRequestRemoved { request_id }
            }
            Effect::AddSignRequest { request } => WalletEvent::SignRequested(request),
            Effect::RemoveSignRequest { request_id } => {
                WalletEvent::SignRequestRemoved { request_id }
            }
            Effect::AddSignMessageRequest { request } => {
                WalletEvent::SignMessageRequested(request)
            }
            Effect::AddReceiveAddressRequest { request } => {
                WalletEvent::ReceiveAddressRequested(request)
            }
            Effect::RemoveReceiveAddressRequest { request_id } => {
                WalletEvent::ReceiveAddressRequestRemoved { request_id }
            }
            Effect::RemoveSignMessageRequest { request_id } => {
                WalletEvent::SignMessageRequestRemoved { request_id }
            }
            Effect::AddPayRequest { request } => WalletEvent::PayRequested(request),
            Effect::RemovePayRequest { request_id } => {
                WalletEvent::PayRequestRemoved { request_id }
            }
            Effect::AddFundRequest { request } => WalletEvent::FundRequested(request),
            Effect::RemoveFundRequest { request_id } => {
                WalletEvent::FundRequestRemoved { request_id }
            }
            Effect::SessionList { sessions } => WalletEvent::Sessions(sessions),
            Effect::SessionCreated { session } => WalletEvent::SessionCreated(session),
            Effect::SessionRemoved { session_id } => WalletEvent::SessionRemoved { session_id },
            Effect::MinimizeMobileApp => WalletEvent::MinimizeMobileApp,
            Effect::ActionFailed { action, message } => {
                WalletEvent::ActionFailed { action, message }
            }
        };
        let _ = event_tx.send(event);
    }
}

async fn run(
    config: WalletConnectConfig,
    mut input_rx: mpsc::UnboundedReceiver<Input>,
    event_tx: mpsc::UnboundedSender<WalletEvent>,
) {
    let mut core = WalletConnectCore::new(config.install_id, config.descriptor, config.key);
    let mut delay = RECONNECT_MIN;

    loop {
        let stream = match tokio_tungstenite::connect_async(&config.url).await {
            Ok((stream, _)) => stream,
            Err(err) => {
                log::warn!("connect to {} failed: {err}", config.url);
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(RECONNECT_MAX);
                continue;
            }
        };
        delay = RECONNECT_MIN;
        let (mut sink, mut source) = stream.split();

        let mut outgoing = Vec::new();
        apply_effects(
            core.handle(Input::Transport {
                event: TransportEvent::Connected,
            }),
            &mut outgoing,
            &event_tx,
        );
        let _ = event_tx.send(WalletEvent::Connected);
        for frame in outgoing.drain(..) {
            if sink.send(Message::Text(frame.into())).await.is_err() {
                break;
            }
        }

        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut was_logged_in = false;

        'connected: loop {
            let mut outgoing = Vec::new();
            tokio::select! {
                msg = source.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            apply_effects(
                                core.handle(Input::Transport {
                                    event: TransportEvent::Recv { text: text.to_string() },
                                }),
                                &mut outgoing,
                                &event_tx,
                            );
                            if core.is_logged_in() && !was_logged_in {
                                was_logged_in = true;
                                let _ = event_tx.send(WalletEvent::LoggedIn);
                            }
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            let _ = sink.send(Message::Pong(payload)).await;
                        }
                        Some(Ok(_)) => {}
                        Some(Err(err)) => {
                            log::warn!("websocket error: {err}");
                            break 'connected;
                        }
                        None => break 'connected,
                    }
                }
                input = input_rx.recv() => {
                    match input {
                        Some(input) => {
                            apply_effects(core.handle(input), &mut outgoing, &event_tx);
                        }
                        // Every handle dropped: the integration is gone.
                        None => return,
                    }
                }
                _ = ping.tick() => {
                    if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break 'connected;
                    }
                }
            }
            for frame in outgoing {
                if sink.send(Message::Text(frame.into())).await.is_err() {
                    break 'connected;
                }
            }
        }

        apply_effects(
            core.handle(Input::Transport {
                event: TransportEvent::Disconnected,
            }),
            &mut Vec::new(),
            &event_tx,
        );
        let _ = event_tx.send(WalletEvent::Disconnected);
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(RECONNECT_MAX);
    }
}
