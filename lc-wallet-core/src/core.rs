//! The sans-io wallet-connect state machine.
//!
//! Vendored from `sideswap-io/sideswap_rust` (`sideswap_common/src/wallet_connect.rs`,
//! MIT), decoupled from that repo's transport: inputs go in, effects come out,
//! and nothing here touches a socket, a clock, or a thread. The `transport`
//! module drives it over tokio; an integration that has its own networking
//! (mobile runtimes often do) can drive this directly.
//!
//! Pending user actions are queued while disconnected and replayed after the
//! next successful login, so an approval tapped during a network blip is not
//! lost.

use std::collections::{BTreeMap, BTreeSet};

use crate::key::WalletKey;
use crate::link::{AppLink, LinkType};
use crate::wire;

/// What the transport tells the core.
#[derive(Debug)]
pub enum TransportEvent {
    Connected,
    Recv { text: String },
    Disconnected,
}

#[derive(Debug)]
pub enum Input {
    Transport { event: TransportEvent },

    AppLink { app_link: AppLink },

    /// Approve a login. `service_binding` answers a request that carried
    /// a `service_challenge`: the (key, signature) the HOST produced
    /// with its service key over `venue::service_login_digest`. This
    /// crate never holds that key — the same rule as SignMessageSigned.
    /// A request that asked for a binding and is accepted without one is
    /// refused rather than sent unbound, or the RP would be told the
    /// login succeeded and left without the key it asked for.
    LoginAccepted {
        request_id: String,
        service_binding: Option<ServiceBinding>,
    },

    LoginRejected { request_id: String },

    SignAccepted { request_id: String, signed_pset: String },

    SignRejected { request_id: String },

    /// Approve a message-signing request. The core signs the digest it
    /// stored from the server's request with the wallet key — the host
    /// approves by id and never supplies bytes to sign.
    SignMessageAccepted { request_id: String },

    /// Approve a message-signing request with a signature the host
    /// produced in another signer — the venue money key after a typed
    /// clear-sign (`crate::venue::parse_typed_description`), or a
    /// hardware signer. The host supplies a finished signature, never
    /// bytes for this crate's keys to sign; the request must still be
    /// live, or nothing is sent.
    SignMessageSigned {
        request_id: String,
        /// 64-byte BIP340 signature over the request's digest, hex.
        signature: String,
    },

    SignMessageRejected { request_id: String },

    /// Answer a receive-address request with an address the HOST derived
    /// from its own wallet. This crate does not manage the address chain,
    /// so the host supplies the address exactly as it supplies a txid for
    /// a pay request; the request must still be live, or nothing is sent.
    ///
    /// The host is responsible for two things this crate cannot check:
    /// the address must be FRESH (an unused one, so separate payouts are
    /// not linked on chain) and it must be in the session's network.
    /// See docs/receive-address-spec.md.
    ReceiveAddressProvided {
        request_id: String,
        address: String,
    },

    ReceiveAddressRejected { request_id: String },

    /// Answer an asset-balance request with the amount the HOST summed
    /// from its own coins, in the asset's base units. This crate holds no
    /// coins, so the host supplies the number exactly as it supplies an
    /// address; the request must still be live, or nothing is sent.
    /// See docs/asset-balance-spec.md.
    AssetBalanceProvided { request_id: String, amount: u64 },

    AssetBalanceRejected { request_id: String },

    /// Approve a pay request with the txid of the payment the HOST built,
    /// signed and broadcast from the wallet's own coins. This crate never
    /// builds transactions: the host's send machinery constructs the spend,
    /// renders the real recipient/amount/fee for the user, and hands back
    /// only the broadcast txid. The request must still be live, or nothing
    /// is sent.
    PayBuilt {
        request_id: String,
        /// Txid of the broadcast payment, hex-encoded (64 chars).
        txid: String,
    },

    PayRejected { request_id: String },

    /// Approve a fund request with the funded template the HOST built:
    /// the wallet's confidential inputs and single blinded change added,
    /// the wallet's own inputs signed (SIGHASH_ALL), nothing else
    /// touched. This crate never builds transactions — the host runs
    /// `approval::verify_fund_template` before showing anything and its
    /// own machinery funds the template; the RP finalises its inputs and
    /// broadcasts. The request must still be live, or nothing is sent.
    FundSigned {
        request_id: String,
        /// The funded template, PSET base64.
        pset: String,
    },

    FundRejected { request_id: String },

    RegisterFcmToken { token: String },

    StopSession { session_id: String },
}

/// A service key bound during login: the host's own key for this RP and
/// its signature over `venue::service_login_digest`.
#[derive(Debug, Clone)]
pub struct ServiceBinding {
    pub key: String,
    pub signature: String,
}

#[must_use]
#[derive(Debug)]
pub enum Effect {
    /// Send this frame to the server. The only effect with a side beyond
    /// the integrator's own UI.
    Send { data: String },

    AddLoginRequest { request: wire::LoginRequest },
    RemoveLoginRequest { request_id: String },

    AddSignRequest { request: wire::SignRequest },
    RemoveSignRequest { request_id: String },

    AddSignMessageRequest { request: wire::SignMessageRequest },
    RemoveSignMessageRequest { request_id: String },
    AddReceiveAddressRequest { request: wire::ReceiveAddressRequest },
    RemoveReceiveAddressRequest { request_id: String },
    AddAssetBalanceRequest { request: wire::AssetBalanceRequest },
    RemoveAssetBalanceRequest { request_id: String },

    /// An RP's holdings for this wallet changed (or arrived at login).
    /// Nothing to answer; the host renders it (docs/held-balances-spec.md).
    SetHoldings { report: wire::HoldingsReport },
    ClearHoldings { domain: String },

    AddPayRequest { request: wire::PayRequest },
    RemovePayRequest { request_id: String },

    AddFundRequest { request: wire::FundRequest },
    RemoveFundRequest { request_id: String },

    SessionList { sessions: Vec<wire::Session> },
    SessionCreated { session: wire::Session },
    SessionRemoved { session_id: String },

    /// A mobile-originated request finished; hand the person back to the
    /// browser that is waiting on this same device.
    MinimizeMobileApp,

    /// A user action the wallet sent was refused by the server. The host
    /// must be able to tell the person — a swallowed refusal left a
    /// wrong-network deep link dying in silence (the server said
    /// "unknown or expired login request" and the wallet rendered
    /// nothing, 2026-08-31).
    ActionFailed {
        action: wire::UserAction,
        message: String,
    },
}

pub struct WalletConnectCore {
    install_id: wire::InstallId,
    connected: bool,
    login_succeed: bool,

    descriptor: String,
    wallet_key: WalletKey,

    login_requests: BTreeMap<String, wire::LoginRequest>,
    sign_requests: BTreeMap<String, wire::SignRequest>,
    sign_message_requests: BTreeMap<String, wire::SignMessageRequest>,
    receive_address_requests: BTreeMap<String, wire::ReceiveAddressRequest>,
    asset_balance_requests: BTreeMap<String, wire::AssetBalanceRequest>,
    /// domain -> what that RP last reported holding for this wallet
    holdings: BTreeMap<String, wire::HoldingsReport>,
    pay_requests: BTreeMap<String, wire::PayRequest>,
    fund_requests: BTreeMap<String, wire::FundRequest>,

    user_actions: BTreeMap<wire::ReqId, wire::UserAction>,
    next_action_id: wire::ReqId,

    mobile_requests: BTreeSet<String>,

    fcm_token: Option<String>,
}

fn send(id: wire::ReqId, req: wire::Req) -> Effect {
    let to = wire::To::Req { id, req };
    let data = serde_json::to_string(&to).expect("must not fail");
    Effect::Send { data }
}

impl WalletConnectCore {
    pub fn new(install_id: wire::InstallId, descriptor: String, wallet_key: WalletKey) -> Self {
        Self {
            install_id,
            connected: false,
            login_succeed: false,
            descriptor,
            wallet_key,
            login_requests: BTreeMap::new(),
            sign_requests: BTreeMap::new(),
            sign_message_requests: BTreeMap::new(),
            receive_address_requests: BTreeMap::new(),
            asset_balance_requests: BTreeMap::new(),
            holdings: BTreeMap::new(),
            pay_requests: BTreeMap::new(),
            fund_requests: BTreeMap::new(),
            user_actions: BTreeMap::new(),
            // User actions start at 1: id 0 is used by fire-and-forget
            // requests (challenge, login, fcm) whose responses carry no
            // state to clean up.
            next_action_id: 1,
            mobile_requests: BTreeSet::new(),
            fcm_token: None,
        }
    }

    pub fn is_logged_in(&self) -> bool {
        self.connected && self.login_succeed
    }

    fn sync_sign_requests(
        &mut self,
        sign_requests: Vec<wire::SignRequest>,
        effects: &mut Vec<Effect>,
    ) {
        let old_request_ids = self.sign_requests.keys().cloned().collect::<BTreeSet<_>>();
        let new_request_ids = sign_requests
            .iter()
            .map(|req| req.request_id.clone())
            .collect::<BTreeSet<_>>();

        for req_id in old_request_ids.difference(&new_request_ids) {
            self.sign_requests.remove(req_id);
            effects.push(Effect::RemoveSignRequest {
                request_id: req_id.clone(),
            });
        }

        for sign_req in sign_requests {
            if !self.sign_requests.contains_key(&sign_req.request_id) {
                self.sign_requests
                    .insert(sign_req.request_id.clone(), sign_req.clone());
                effects.push(Effect::AddSignRequest { request: sign_req });
            }
        }
    }

    fn sync_sign_message_requests(
        &mut self,
        sign_message_requests: Vec<wire::SignMessageRequest>,
        effects: &mut Vec<Effect>,
    ) {
        let old_request_ids = self
            .sign_message_requests
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let new_request_ids = sign_message_requests
            .iter()
            .map(|req| req.request_id.clone())
            .collect::<BTreeSet<_>>();

        for req_id in old_request_ids.difference(&new_request_ids) {
            self.sign_message_requests.remove(req_id);
            effects.push(Effect::RemoveSignMessageRequest {
                request_id: req_id.clone(),
            });
        }

        for sign_req in sign_message_requests {
            if !self.sign_message_requests.contains_key(&sign_req.request_id) {
                self.sign_message_requests
                    .insert(sign_req.request_id.clone(), sign_req.clone());
                effects.push(Effect::AddSignMessageRequest { request: sign_req });
            }
        }
    }

    fn sync_pay_requests(
        &mut self,
        pay_requests: Vec<wire::PayRequest>,
        effects: &mut Vec<Effect>,
    ) {
        let old_request_ids = self.pay_requests.keys().cloned().collect::<BTreeSet<_>>();
        let new_request_ids = pay_requests
            .iter()
            .map(|req| req.request_id.clone())
            .collect::<BTreeSet<_>>();

        for req_id in old_request_ids.difference(&new_request_ids) {
            self.pay_requests.remove(req_id);
            effects.push(Effect::RemovePayRequest {
                request_id: req_id.clone(),
            });
        }

        for pay_req in pay_requests {
            if !self.pay_requests.contains_key(&pay_req.request_id) {
                self.pay_requests
                    .insert(pay_req.request_id.clone(), pay_req.clone());
                effects.push(Effect::AddPayRequest { request: pay_req });
            }
        }
    }

    fn sync_fund_requests(
        &mut self,
        fund_requests: Vec<wire::FundRequest>,
        effects: &mut Vec<Effect>,
    ) {
        let old_request_ids = self.fund_requests.keys().cloned().collect::<BTreeSet<_>>();
        let new_request_ids = fund_requests
            .iter()
            .map(|req| req.request_id.clone())
            .collect::<BTreeSet<_>>();

        for req_id in old_request_ids.difference(&new_request_ids) {
            self.fund_requests.remove(req_id);
            effects.push(Effect::RemoveFundRequest {
                request_id: req_id.clone(),
            });
        }

        for fund_req in fund_requests {
            if !self.fund_requests.contains_key(&fund_req.request_id) {
                self.fund_requests
                    .insert(fund_req.request_id.clone(), fund_req.clone());
                effects.push(Effect::AddFundRequest { request: fund_req });
            }
        }
    }

    fn sync_receive_address_requests(
        &mut self,
        receive_address_requests: Vec<wire::ReceiveAddressRequest>,
        effects: &mut Vec<Effect>,
    ) {
        let old_request_ids = self
            .receive_address_requests
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let new_request_ids = receive_address_requests
            .iter()
            .map(|req| req.request_id.clone())
            .collect::<BTreeSet<_>>();

        for req_id in old_request_ids.difference(&new_request_ids) {
            self.receive_address_requests.remove(req_id);
            effects.push(Effect::RemoveReceiveAddressRequest {
                request_id: req_id.clone(),
            });
        }

        for req in receive_address_requests {
            if !self
                .receive_address_requests
                .contains_key(&req.request_id)
            {
                self.receive_address_requests
                    .insert(req.request_id.clone(), req.clone());
                effects.push(Effect::AddReceiveAddressRequest { request: req });
            }
        }
    }

    /// Login carries every RP's last holdings report: what the server
    /// holds is the truth, so an entry the server no longer has is
    /// cleared and every one it has is (re)stated — the host redraws.
    fn sync_holdings(&mut self, reports: Vec<wire::HoldingsReport>, effects: &mut Vec<Effect>) {
        let new_domains = reports
            .iter()
            .map(|r| r.domain.clone())
            .collect::<BTreeSet<_>>();
        let gone = self
            .holdings
            .keys()
            .filter(|d| !new_domains.contains(*d))
            .cloned()
            .collect::<Vec<_>>();
        for domain in gone {
            self.holdings.remove(&domain);
            effects.push(Effect::ClearHoldings { domain });
        }
        for report in reports {
            if report.holdings.is_empty() {
                continue;
            }
            self.holdings.insert(report.domain.clone(), report.clone());
            effects.push(Effect::SetHoldings { report });
        }
    }

    fn sync_asset_balance_requests(
        &mut self,
        asset_balance_requests: Vec<wire::AssetBalanceRequest>,
        effects: &mut Vec<Effect>,
    ) {
        let old_request_ids = self
            .asset_balance_requests
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let new_request_ids = asset_balance_requests
            .iter()
            .map(|req| req.request_id.clone())
            .collect::<BTreeSet<_>>();

        for req_id in old_request_ids.difference(&new_request_ids) {
            self.asset_balance_requests.remove(req_id);
            effects.push(Effect::RemoveAssetBalanceRequest {
                request_id: req_id.clone(),
            });
        }

        for req in asset_balance_requests {
            if !self.asset_balance_requests.contains_key(&req.request_id) {
                self.asset_balance_requests
                    .insert(req.request_id.clone(), req.clone());
                effects.push(Effect::AddAssetBalanceRequest { request: req });
            }
        }
    }

    fn sign_message_digest(&self, request_id: &str) -> Result<String, String> {
        let request = self
            .sign_message_requests
            .get(request_id)
            .ok_or("request already removed")?;
        let mut digest = [0u8; 32];
        hex::decode_to_slice(&request.digest, &mut digest)
            .map_err(|_| "digest is not 32 bytes of hex")?;
        Ok(self.wallet_key.sign_digest(digest).to_string())
    }

    fn handle_response(&mut self, id: wire::ReqId, resp: wire::Resp, effects: &mut Vec<Effect>) {
        match resp {
            wire::Resp::Challenge(resp) => {
                effects.push(send(
                    0,
                    wire::Req::Login(wire::LoginReq {
                        public_key: self.wallet_key.public_key(),
                        signature: self.wallet_key.sign_challenge(&resp.challenge),
                        install_id: Some(self.install_id),
                    }),
                ));
            }

            wire::Resp::Login(wire::LoginResp {
                sessions,
                sign_requests,
                sign_message_requests,
                pay_requests,
                fund_requests,
                receive_address_requests,
                asset_balance_requests,
                holdings,
            }) => {
                self.login_succeed = true;

                // Replay actions the user took while offline.
                for (&req_id, action) in &self.user_actions {
                    effects.push(send(
                        req_id,
                        wire::Req::UserAction(wire::UserActionReq {
                            action: action.clone(),
                        }),
                    ));
                }

                self.sync_sign_requests(sign_requests, effects);
                self.sync_sign_message_requests(sign_message_requests, effects);
                self.sync_pay_requests(pay_requests, effects);
                self.sync_fund_requests(fund_requests, effects);
                self.sync_receive_address_requests(receive_address_requests, effects);
                self.sync_asset_balance_requests(asset_balance_requests, effects);
                self.sync_holdings(holdings, effects);
                effects.push(Effect::SessionList { sessions });
                self.send_fcm_token(effects);
            }

            wire::Resp::UserAction(_) => {
                self.user_actions.remove(&id);
            }

            wire::Resp::RegisterFcm(_) => {}
        }
    }

    fn handle_notification(&mut self, notif: wire::Notif, effects: &mut Vec<Effect>) {
        match notif {
            wire::Notif::SessionCreated(notif) => {
                effects.push(Effect::SessionCreated {
                    session: notif.session,
                });
            }

            wire::Notif::SessionRemoved(notif) => {
                effects.push(Effect::SessionRemoved {
                    session_id: notif.session_id,
                });
            }

            wire::Notif::LoginRequestCreated(notif) => {
                self.login_requests
                    .insert(notif.request.request_id.clone(), notif.request.clone());

                effects.push(Effect::AddLoginRequest {
                    request: notif.request,
                });
            }

            wire::Notif::LoginRequestRemoved(notif) => {
                self.login_requests.remove(&notif.request_id);
                effects.push(Effect::RemoveLoginRequest {
                    request_id: notif.request_id,
                });
            }

            wire::Notif::SignRequestCreated(notif) => {
                self.sign_requests
                    .insert(notif.request.request_id.clone(), notif.request.clone());

                effects.push(Effect::AddSignRequest {
                    request: notif.request,
                });
            }

            wire::Notif::SignRequestRemoved(n) => {
                self.sign_requests.remove(&n.request_id);
                effects.push(Effect::RemoveSignRequest {
                    request_id: n.request_id,
                });
            }

            wire::Notif::SignMessageRequestCreated(notif) => {
                self.sign_message_requests
                    .insert(notif.request.request_id.clone(), notif.request.clone());
                effects.push(Effect::AddSignMessageRequest {
                    request: notif.request,
                });
            }

            wire::Notif::SignMessageRequestRemoved(n) => {
                self.sign_message_requests.remove(&n.request_id);
                effects.push(Effect::RemoveSignMessageRequest {
                    request_id: n.request_id,
                });
            }

            wire::Notif::ReceiveAddressRequestCreated(notif) => {
                self.receive_address_requests
                    .insert(notif.request.request_id.clone(), notif.request.clone());
                effects.push(Effect::AddReceiveAddressRequest {
                    request: notif.request,
                });
            }

            wire::Notif::ReceiveAddressRequestRemoved(n) => {
                self.receive_address_requests.remove(&n.request_id);
                effects.push(Effect::RemoveReceiveAddressRequest {
                    request_id: n.request_id,
                });
            }

            wire::Notif::AssetBalanceRequestCreated(notif) => {
                self.asset_balance_requests
                    .insert(notif.request.request_id.clone(), notif.request.clone());
                effects.push(Effect::AddAssetBalanceRequest {
                    request: notif.request,
                });
            }

            wire::Notif::AssetBalanceRequestRemoved(n) => {
                self.asset_balance_requests.remove(&n.request_id);
                effects.push(Effect::RemoveAssetBalanceRequest {
                    request_id: n.request_id,
                });
            }

            wire::Notif::HoldingsUpdated(n) => {
                if n.report.holdings.is_empty() {
                    // an empty report is a clear, whichever way it is sent
                    self.holdings.remove(&n.report.domain);
                    effects.push(Effect::ClearHoldings {
                        domain: n.report.domain,
                    });
                } else {
                    self.holdings
                        .insert(n.report.domain.clone(), n.report.clone());
                    effects.push(Effect::SetHoldings { report: n.report });
                }
            }

            wire::Notif::HoldingsRemoved(n) => {
                if self.holdings.remove(&n.domain).is_some() {
                    effects.push(Effect::ClearHoldings { domain: n.domain });
                }
            }

            wire::Notif::PayRequestCreated(notif) => {
                self.pay_requests
                    .insert(notif.request.request_id.clone(), notif.request.clone());
                effects.push(Effect::AddPayRequest {
                    request: notif.request,
                });
            }

            wire::Notif::PayRequestRemoved(n) => {
                self.pay_requests.remove(&n.request_id);
                effects.push(Effect::RemovePayRequest {
                    request_id: n.request_id,
                });
            }

            wire::Notif::FundRequestCreated(notif) => {
                self.fund_requests
                    .insert(notif.request.request_id.clone(), notif.request.clone());
                effects.push(Effect::AddFundRequest {
                    request: notif.request,
                });
            }

            wire::Notif::FundRequestRemoved(n) => {
                self.fund_requests.remove(&n.request_id);
                effects.push(Effect::RemoveFundRequest {
                    request_id: n.request_id,
                });
            }
        }
    }

    fn add_user_action(&mut self, action: wire::UserAction, effects: &mut Vec<Effect>) {
        let id = self.next_action_id;
        self.next_action_id += 1;

        self.user_actions.insert(id, action.clone());

        if self.connected {
            effects.push(send(
                id,
                wire::Req::UserAction(wire::UserActionReq { action }),
            ));
        }
    }

    fn handle_server_message(&mut self, from: wire::From, effects: &mut Vec<Effect>) {
        match from {
            wire::From::Resp { id, resp } => {
                self.handle_response(id, resp, effects);
            }

            wire::From::Error { id, err } => {
                log::debug!("wallet-connect request failed: id={id}, err={err:?}");
                if let Some(action) = self.user_actions.remove(&id) {
                    effects.push(Effect::ActionFailed {
                        action,
                        message: err.message,
                    });
                }
            }

            wire::From::Notif { notif } => {
                self.handle_notification(notif, effects);
            }
        }
    }

    fn finish_request(&mut self, request_id: String, effects: &mut Vec<Effect>) {
        if self.mobile_requests.remove(&request_id) {
            effects.push(Effect::MinimizeMobileApp);
        }
    }

    fn send_fcm_token(&mut self, effects: &mut Vec<Effect>) {
        if let Some(token) = self.fcm_token.as_ref() {
            if self.connected && self.login_succeed {
                effects.push(send(
                    0,
                    wire::Req::RegisterFcm(wire::RegisterFcmReq {
                        token: token.clone(),
                    }),
                ));
            }
        }
    }

    #[must_use]
    pub fn handle(&mut self, input: Input) -> Vec<Effect> {
        let mut effects = Vec::new();

        match input {
            Input::Transport { event } => match event {
                TransportEvent::Connected => {
                    self.connected = true;
                    effects.push(send(0, wire::Req::Challenge(wire::ChallengeReq {})));
                }
                TransportEvent::Recv { text } => {
                    let res = serde_json::from_str::<wire::From>(&text);
                    match res {
                        Ok(from) => {
                            self.handle_server_message(from, &mut effects);
                        }
                        Err(err) => {
                            log::error!("invalid server response: {err}");
                        }
                    }
                }
                TransportEvent::Disconnected => {
                    self.connected = false;
                    self.login_succeed = false;
                }
            },

            Input::LoginAccepted {
                request_id,
                service_binding,
            } => {
                let wanted = self
                    .login_requests
                    .get(&request_id)
                    .map(|request| request.service_challenge.is_some())
                    .unwrap_or(false);
                if wanted && service_binding.is_none() {
                    effects.push(Effect::ActionFailed {
                        action: wire::UserAction::CancelLoginRequest {
                            request_id: request_id.clone(),
                        },
                        message: "this login needs a service key and none was supplied"
                            .to_owned(),
                    });
                    return effects;
                }
                let (service_key, service_signature) = match service_binding {
                    Some(ServiceBinding { key, signature }) => (Some(key), Some(signature)),
                    None => (None, None),
                };
                self.add_user_action(
                    wire::UserAction::AcceptLoginRequest {
                        request_id: request_id.clone(),
                        descriptor: self.descriptor.clone(),
                        service_key,
                        service_signature,
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::LoginRejected { request_id } => {
                self.add_user_action(
                    wire::UserAction::CancelLoginRequest {
                        request_id: request_id.clone(),
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::SignAccepted {
                request_id,
                signed_pset,
            } => {
                self.add_user_action(
                    wire::UserAction::AcceptSignRequest {
                        request_id: request_id.clone(),
                        pset: signed_pset,
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::SignRejected { request_id } => {
                self.add_user_action(
                    wire::UserAction::CancelSignRequest {
                        request_id: request_id.clone(),
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::SignMessageAccepted { request_id } => {
                match self.sign_message_digest(&request_id) {
                    Ok(signature) => {
                        self.add_user_action(
                            wire::UserAction::AcceptSignMessageRequest {
                                request_id: request_id.clone(),
                                signature,
                            },
                            &mut effects,
                        );
                    }
                    Err(err) => {
                        // A malformed digest should never reach here (the
                        // connect server validates it), so drop the approval
                        // rather than sign something unintended.
                        log::error!("cannot sign message request {request_id}: {err}");
                    }
                }
                self.finish_request(request_id, &mut effects);
            }

            Input::SignMessageSigned {
                request_id,
                signature,
            } => {
                if self.sign_message_requests.contains_key(&request_id) {
                    self.add_user_action(
                        wire::UserAction::AcceptSignMessageRequest {
                            request_id: request_id.clone(),
                            signature,
                        },
                        &mut effects,
                    );
                } else {
                    log::error!("sign message request {request_id} is not live, dropping signature");
                }
                self.finish_request(request_id, &mut effects);
            }

            Input::SignMessageRejected { request_id } => {
                self.add_user_action(
                    wire::UserAction::CancelSignMessageRequest {
                        request_id: request_id.clone(),
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::PayBuilt { request_id, txid } => {
                if self.pay_requests.contains_key(&request_id) {
                    self.add_user_action(
                        wire::UserAction::AcceptPayRequest {
                            request_id: request_id.clone(),
                            txid,
                        },
                        &mut effects,
                    );
                } else {
                    log::error!("pay request {request_id} is not live, dropping txid");
                }
                self.finish_request(request_id, &mut effects);
            }

            Input::ReceiveAddressProvided {
                request_id,
                address,
            } => {
                if self.receive_address_requests.contains_key(&request_id) {
                    self.add_user_action(
                        wire::UserAction::AcceptReceiveAddressRequest {
                            request_id: request_id.clone(),
                            address,
                        },
                        &mut effects,
                    );
                } else {
                    log::error!("receive-address request {request_id} is not live, dropping address");
                }
                self.finish_request(request_id, &mut effects);
            }

            Input::ReceiveAddressRejected { request_id } => {
                self.add_user_action(
                    wire::UserAction::CancelReceiveAddressRequest {
                        request_id: request_id.clone(),
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::AssetBalanceProvided { request_id, amount } => {
                if self.asset_balance_requests.contains_key(&request_id) {
                    self.add_user_action(
                        wire::UserAction::AcceptAssetBalanceRequest {
                            request_id: request_id.clone(),
                            amount,
                        },
                        &mut effects,
                    );
                } else {
                    log::error!("asset-balance request {request_id} is not live, dropping answer");
                }
                self.finish_request(request_id, &mut effects);
            }

            Input::AssetBalanceRejected { request_id } => {
                self.add_user_action(
                    wire::UserAction::CancelAssetBalanceRequest {
                        request_id: request_id.clone(),
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::PayRejected { request_id } => {
                self.add_user_action(
                    wire::UserAction::CancelPayRequest {
                        request_id: request_id.clone(),
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::FundSigned { request_id, pset } => {
                if self.fund_requests.contains_key(&request_id) {
                    self.add_user_action(
                        wire::UserAction::AcceptFundRequest {
                            request_id: request_id.clone(),
                            pset,
                        },
                        &mut effects,
                    );
                } else {
                    log::error!("fund request {request_id} is not live, dropping funded pset");
                }
                self.finish_request(request_id, &mut effects);
            }

            Input::FundRejected { request_id } => {
                self.add_user_action(
                    wire::UserAction::CancelFundRequest {
                        request_id: request_id.clone(),
                    },
                    &mut effects,
                );
                self.finish_request(request_id, &mut effects);
            }

            Input::RegisterFcmToken { token } => {
                self.fcm_token = Some(token.clone());
                self.send_fcm_token(&mut effects);
            }

            Input::StopSession { session_id } => {
                self.add_user_action(wire::UserAction::StopSession { session_id }, &mut effects);
            }

            Input::AppLink {
                app_link:
                    AppLink {
                        link_type,
                        request_id,
                        is_mobile,
                    },
            } => {
                if is_mobile {
                    self.mobile_requests.insert(request_id.clone());
                }

                match link_type {
                    // Nothing to send: the request is already in hand. The
                    // is_mobile insert above is the whole effect — answer
                    // it and the app hands back to the browser.
                    LinkType::Open => {}
                    LinkType::Login => {
                        self.add_user_action(
                            wire::UserAction::LinkLoginRequest { request_id },
                            &mut effects,
                        );
                    }
                    LinkType::Sign => {
                        // Nothing to do: the sign request itself arrives
                        // as a server notification.
                    }
                }
            }
        }

        effects
    }

    pub fn get_login_request(&self, request_id: &str) -> Option<&wire::LoginRequest> {
        self.login_requests.get(request_id)
    }

    pub fn get_sign_request(&self, request_id: &str) -> Option<&wire::SignRequest> {
        self.sign_requests.get(request_id)
    }

    pub fn get_sign_message_request(
        &self,
        request_id: &str,
    ) -> Option<&wire::SignMessageRequest> {
        self.sign_message_requests.get(request_id)
    }

    pub fn get_pay_request(&self, request_id: &str) -> Option<&wire::PayRequest> {
        self.pay_requests.get(request_id)
    }

    pub fn get_fund_request(&self, request_id: &str) -> Option<&wire::FundRequest> {
        self.fund_requests.get(request_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core() -> WalletConnectCore {
        WalletConnectCore::new(
            wire::InstallId([1u8; 16]),
            "ct(dummy-descriptor)".to_owned(),
            WalletKey::new(&[7u8; 32], crate::key::Network::LiquidTestnet),
        )
    }

    fn sent_frames(effects: &[Effect]) -> Vec<&str> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Send { data } => Some(data.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Connect → challenge is asked; challenge → login is answered with
    /// a signature over the nonce.
    #[test]
    fn connect_drives_challenge_then_login() {
        let mut core = core();
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });
        let frames = sent_frames(&effects);
        assert_eq!(frames, [r#"{"Req":{"id":0,"req":{"Challenge":{}}}}"#]);

        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Resp":{"id":0,"resp":{"Challenge":{"challenge":"n1"}}}}"#.to_owned(),
            },
        });
        let frames = sent_frames(&effects);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("\"Login\""));
        assert!(frames[0].contains("public_key"));
        assert!(frames[0].contains("install_id"));
    }

    /// An approval taken while offline is queued, not lost, and replays
    /// after the next login.
    #[test]
    fn offline_approvals_replay_after_login() {
        let mut core = core();
        let effects = core.handle(Input::LoginAccepted {
            request_id: "r1".to_owned(),
            service_binding: None,
        });
        assert!(sent_frames(&effects).is_empty(), "offline: nothing sent yet");

        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Resp":{"id":0,"resp":{"Login":{"sessions":[],"sign_requests":[]}}}}"#
                    .to_owned(),
            },
        });
        let frames = sent_frames(&effects);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("AcceptLoginRequest"));
        assert!(frames[0].contains("dummy-descriptor"));
    }

    /// The descriptor leaves only on an explicit approval, never on
    /// link or login.
    #[test]
    fn descriptor_travels_only_on_accept() {
        let mut core = core();
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });
        let link = core.handle(Input::AppLink {
            app_link: crate::link::parse_app_link("liquidconnect://login/?request_id=r9").unwrap(),
        });
        for frame in sent_frames(&link) {
            assert!(!frame.contains("descriptor"), "leak in: {frame}");
        }
        let accept = core.handle(Input::LoginAccepted {
            request_id: "r9".to_owned(),
            service_binding: None,
        });
        assert!(sent_frames(&accept)[0].contains("dummy-descriptor"));
    }

    /// A sign-message approval signs the digest STORED from the server's
    /// request — and the signature verifies against the wallet key over
    /// exactly that digest. Rejection cancels; an unknown id signs nothing.
    #[test]
    fn sign_message_approval_signs_the_stored_digest() {
        let mut core = core();
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });

        let digest_hex = "11".repeat(32);
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: format!(
                    r#"{{"Notif":{{"notif":{{"SignMessageRequestCreated":{{"request":{{"request_id":"s1","domain":"swaption.io","digest":"{digest_hex}","description":"Sell 0.001 BTC","ttl":60000}}}}}}}}}}"#
                ),
            },
        });
        assert!(effects
            .iter()
            .any(|e| matches!(e, Effect::AddSignMessageRequest { .. })));
        assert_eq!(
            core.get_sign_message_request("s1").unwrap().digest,
            digest_hex
        );

        // Unknown id: no frame leaves, nothing is signed.
        let effects = core.handle(Input::SignMessageAccepted {
            request_id: "nope".to_owned(),
        });
        assert!(sent_frames(&effects).is_empty());

        let effects = core.handle(Input::SignMessageAccepted {
            request_id: "s1".to_owned(),
        });
        let frames = sent_frames(&effects);
        assert_eq!(frames.len(), 1);
        let frame: wire::To = serde_json::from_str(frames[0]).unwrap();
        let wire::To::Req { req, .. } = frame;
        let signature = match req {
            wire::Req::UserAction(wire::UserActionReq {
                action:
                    wire::UserAction::AcceptSignMessageRequest {
                        request_id,
                        signature,
                    },
            }) => {
                assert_eq!(request_id, "s1");
                signature
            }
            other => panic!("wrong frame: {other:?}"),
        };
        let signature =
            elements::secp256k1_zkp::schnorr::Signature::from_slice(
                &hex::decode(signature).unwrap(),
            )
            .unwrap();
        let digest = elements::secp256k1_zkp::Message::from_digest([0x11; 32]);
        elements::secp256k1_zkp::SECP256K1
            .verify_schnorr(
                &signature,
                &digest,
                &WalletKey::new(&[7u8; 32], crate::key::Network::LiquidTestnet).public_key(),
            )
            .expect("signature must verify against the login key over the digest");

        // A host-supplied signature (venue key / hardware) rides the same
        // accept action verbatim; a dead request id sends nothing.
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: format!(
                    r#"{{"Notif":{{"notif":{{"SignMessageRequestCreated":{{"request":{{"request_id":"s9","domain":"swaption.io","digest":"{digest_hex}","description":"typed order","ttl":60000}}}}}}}}}}"#
                ),
            },
        });
        let effects = core.handle(Input::SignMessageSigned {
            request_id: "s9".to_owned(),
            signature: "cd".repeat(64),
        });
        let frames = sent_frames(&effects);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains(&"cd".repeat(64)));
        let effects = core.handle(Input::SignMessageSigned {
            request_id: "gone".to_owned(),
            signature: "cd".repeat(64),
        });
        assert!(sent_frames(&effects).is_empty());

        // Rejection produces a cancel, not a signature.
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: format!(
                    r#"{{"Notif":{{"notif":{{"SignMessageRequestCreated":{{"request":{{"request_id":"s2","domain":"swaption.io","digest":"{digest_hex}","description":null,"ttl":60000}}}}}}}}}}"#
                ),
            },
        });
        let effects = core.handle(Input::SignMessageRejected {
            request_id: "s2".to_owned(),
        });
        assert!(sent_frames(&effects)[0].contains("CancelSignMessageRequest"));
    }

    /// Pending sign-message requests arrive in LoginResp and sync like
    /// PSET sign requests: new ones surface, gone ones are removed.
    #[test]
    fn login_resp_syncs_sign_message_requests() {
        let mut core = core();
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });
        let digest_hex = "22".repeat(32);
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: format!(
                    r#"{{"Resp":{{"id":0,"resp":{{"Login":{{"sessions":[],"sign_requests":[],"sign_message_requests":[{{"request_id":"p1","domain":"swaption.io","digest":"{digest_hex}","description":"pending order","ttl":60000}}]}}}}}}}}"#
                ),
            },
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::AddSignMessageRequest { request } if request.request_id == "p1"
        )));

        // Relogin without it: the stale request is removed.
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Disconnected,
        });
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Resp":{"id":0,"resp":{"Login":{"sessions":[],"sign_requests":[]}}}}"#
                    .to_owned(),
            },
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::RemoveSignMessageRequest { request_id } if request_id == "p1"
        )));
    }

    /// Holdings are the RP's word, stated at login and restated on every
    /// change: a report sets the entry, an empty report or a Removed
    /// clears it, and a relogin that no longer carries a domain clears it
    /// too. Nothing is ever sent back (docs/held-balances-spec.md).
    #[test]
    fn holdings_follow_login_and_notifications() {
        let mut core = core();
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });
        let report = r#"{"domain":"paper.swaption.io","as_of":1788619197000,"holdings":[{"label":"Margin balance","kind":"balance","asset_id":null,"unit":"USDt","amount":999417000000,"precision":8}]}"#;
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: format!(
                    r#"{{"Resp":{{"id":0,"resp":{{"Login":{{"sessions":[],"sign_requests":[],"holdings":[{report}]}}}}}}}}"#
                ),
            },
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::SetHoldings { report } if report.domain == "paper.swaption.io" && report.holdings[0].amount == 999_417_000_000
        )));
        assert!(sent_frames(&effects).iter().all(|f| !f.contains("Holdings")));

        // a change arrives as a notification and replaces the entry
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Notif":{"notif":{"HoldingsUpdated":{"report":{"domain":"paper.swaption.io","as_of":1788619200000,"holdings":[{"label":"Position","kind":"position","asset_id":null,"unit":"BTC","amount":-5,"precision":8}]}}}}}"#.to_owned(),
            },
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::SetHoldings { report } if report.holdings.len() == 1 && report.holdings[0].amount == -5
        )));
        assert_eq!(core.holdings["paper.swaption.io"].holdings[0].label, "Position");

        // an empty report clears
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Notif":{"notif":{"HoldingsUpdated":{"report":{"domain":"paper.swaption.io","as_of":1788619300000,"holdings":[]}}}}}"#.to_owned(),
            },
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::ClearHoldings { domain } if domain == "paper.swaption.io"
        )));
        assert!(core.holdings.is_empty());

        // set again, then a relogin without it clears it
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: format!(r#"{{"Notif":{{"notif":{{"HoldingsUpdated":{{"report":{report}}}}}}}}}"#),
            },
        });
        assert_eq!(core.holdings.len(), 1);
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Disconnected,
        });
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Resp":{"id":0,"resp":{"Login":{"sessions":[],"sign_requests":[]}}}}"#
                    .to_owned(),
            },
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::ClearHoldings { domain } if domain == "paper.swaption.io"
        )));
        assert!(core.holdings.is_empty());
    }

    /// A pay approval sends the HOST-built txid on the accept action — the
    /// core stores the intent, never builds anything, refuses a dead id,
    /// and cancels on rejection.
    #[test]
    fn pay_approval_relays_the_host_built_txid() {
        let mut core = core();
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });

        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Notif":{"notif":{"PayRequestCreated":{"request":{"request_id":"p1","domain":"swaption.io","recipient":"tlq1qqw508d6qejxtdg4y5r3zarvary0c5xw7kct5v9fs","asset_id":"2222222222222222222222222222222222222222222222222222222222222222","amount":100000,"memo":"RF deposit","ttl":120000}}}}}"#.to_owned(),
            },
        });
        assert!(effects
            .iter()
            .any(|e| matches!(e, Effect::AddPayRequest { request } if request.request_id == "p1")));
        let stored = core.get_pay_request("p1").unwrap();
        assert_eq!(stored.amount, 100_000);
        assert_eq!(stored.memo.as_deref(), Some("RF deposit"));

        // Unknown id: no frame leaves.
        let effects = core.handle(Input::PayBuilt {
            request_id: "nope".to_owned(),
            txid: "cd".repeat(32),
        });
        assert!(sent_frames(&effects).is_empty());

        let effects = core.handle(Input::PayBuilt {
            request_id: "p1".to_owned(),
            txid: "cd".repeat(32),
        });
        let frames = sent_frames(&effects);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("AcceptPayRequest"));
        assert!(frames[0].contains(&"cd".repeat(32)));

        // Rejection produces a cancel, not an accept.
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Notif":{"notif":{"PayRequestCreated":{"request":{"request_id":"p2","domain":"swaption.io","recipient":"tlq1qqw508d6qejxtdg4y5r3zarvary0c5xw7kct5v9fs","asset_id":"2222222222222222222222222222222222222222222222222222222222222222","amount":1,"memo":null,"ttl":120000}}}}}"#.to_owned(),
            },
        });
        let effects = core.handle(Input::PayRejected {
            request_id: "p2".to_owned(),
        });
        assert!(sent_frames(&effects)[0].contains("CancelPayRequest"));
    }

    /// A fund approval sends the HOST-funded PSET on the accept action —
    /// the core never builds or blinds; it relays what the host funded,
    /// and only for a live request.
    #[test]
    fn fund_approval_relays_the_host_funded_pset() {
        let mut core = core();
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });

        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Notif":{"notif":{"FundRequestCreated":{"request":{"request_id":"f1","domain":"paper.swaption.io","template":"cHNldP8BAgQCAAAA","asset_id":"2222222222222222222222222222222222222222222222222222222222222222","amount":2499000000,"memo":"Deposit 24.99 USDT into Rolling Future","ttl":180000}}}}}"#.to_owned(),
            },
        });
        assert!(effects
            .iter()
            .any(|e| matches!(e, Effect::AddFundRequest { request } if request.request_id == "f1")));
        let stored = core.get_fund_request("f1").unwrap();
        assert_eq!(stored.amount, 2_499_000_000);
        assert_eq!(stored.template, "cHNldP8BAgQCAAAA");

        // Unknown id: no frame leaves.
        let effects = core.handle(Input::FundSigned {
            request_id: "nope".to_owned(),
            pset: "AAAA".to_owned(),
        });
        assert!(sent_frames(&effects).is_empty());

        let effects = core.handle(Input::FundSigned {
            request_id: "f1".to_owned(),
            pset: "ZnVuZGVk".to_owned(),
        });
        let frames = sent_frames(&effects);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("AcceptFundRequest"));
        assert!(frames[0].contains("ZnVuZGVk"));

        // Rejection produces a cancel, not an accept.
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Notif":{"notif":{"FundRequestCreated":{"request":{"request_id":"f2","domain":"paper.swaption.io","template":"cHNldP8BAgQCAAAA","asset_id":"2222222222222222222222222222222222222222222222222222222222222222","amount":1,"memo":null,"ttl":180000}}}}}"#.to_owned(),
            },
        });
        let effects = core.handle(Input::FundRejected {
            request_id: "f2".to_owned(),
        });
        assert!(sent_frames(&effects)[0].contains("CancelFundRequest"));
    }

    /// Pending pay requests arrive in LoginResp and sync like the other
    /// request kinds: new ones surface, gone ones are removed.
    #[test]
    fn login_resp_syncs_pay_requests() {
        let mut core = core();
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Resp":{"id":0,"resp":{"Login":{"sessions":[],"sign_requests":[],"pay_requests":[{"request_id":"p1","domain":"swaption.io","recipient":"tlq1qqw508d6qejxtdg4y5r3zarvary0c5xw7kct5v9fs","asset_id":"2222222222222222222222222222222222222222222222222222222222222222","amount":100000,"memo":null,"ttl":60000}]}}}}"#.to_owned(),
            },
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::AddPayRequest { request } if request.request_id == "p1"
        )));

        // Relogin without it: the stale request is removed.
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Disconnected,
        });
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Resp":{"id":0,"resp":{"Login":{"sessions":[],"sign_requests":[]}}}}"#
                    .to_owned(),
            },
        });
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::RemovePayRequest { request_id } if request_id == "p1"
        )));
    }

    /// A mobile-originated request hands the person back to the browser;
    /// a scanned one does not.
    #[test]
    fn minimize_fires_only_for_mobile_links() {
        let mut core = core();
        let _ = core.handle(Input::AppLink {
            app_link: crate::link::parse_app_link(
                "liquidconnect://login/?request_id=m1&mobile=true",
            )
            .unwrap(),
        });
        let effects = core.handle(Input::LoginAccepted {
            request_id: "m1".to_owned(),
            service_binding: None,
        });
        assert!(effects
            .iter()
            .any(|e| matches!(e, Effect::MinimizeMobileApp)));

        let _ = core.handle(Input::AppLink {
            app_link: crate::link::parse_app_link("liquidconnect://login/?request_id=q1").unwrap(),
        });
        let effects = core.handle(Input::LoginAccepted {
            request_id: "q1".to_owned(),
            service_binding: None,
        });
        assert!(!effects
            .iter()
            .any(|e| matches!(e, Effect::MinimizeMobileApp)));
    }

    /// A server refusal of a wallet-sent action surfaces as ActionFailed
    /// — the host must be able to render it. A swallowed refusal left a
    /// wrong-network deep link dying in silence.
    #[test]
    fn refused_action_surfaces_with_its_action() {
        let mut core = core();
        let _ = core.handle(Input::Transport {
            event: TransportEvent::Connected,
        });
        // User actions number from 1 (0 = fire-and-forget challenge/login),
        // so the link-login action rides req id 1.
        let _ = core.handle(Input::AppLink {
            app_link: crate::link::parse_app_link("liquidconnect://login/?request_id=nope")
                .unwrap(),
        });
        let effects = core.handle(Input::Transport {
            event: TransportEvent::Recv {
                text: r#"{"Error":{"id":1,"err":{"code":"InvalidRequest","message":"protocol error: unknown or expired login request — ask the site for a fresh link"}}}"#.to_owned(),
            },
        });
        let failed = effects.iter().find_map(|e| match e {
            Effect::ActionFailed { action, message } => Some((action, message)),
            _ => None,
        });
        let (action, message) = failed.expect("refusal must surface");
        assert!(matches!(
            action,
            wire::UserAction::LinkLoginRequest { request_id } if request_id == "nope"
        ));
        assert!(message.contains("unknown or expired login request"));
    }
}
