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

    LoginAccepted { request_id: String },

    LoginRejected { request_id: String },

    SignAccepted { request_id: String, signed_pset: String },

    SignRejected { request_id: String },

    /// Approve a message-signing request. The core signs the digest it
    /// stored from the server's request with the wallet key — the host
    /// approves by id and never supplies bytes to sign.
    SignMessageAccepted { request_id: String },

    SignMessageRejected { request_id: String },

    RegisterFcmToken { token: String },

    StopSession { session_id: String },
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

    SessionList { sessions: Vec<wire::Session> },
    SessionCreated { session: wire::Session },
    SessionRemoved { session_id: String },

    /// A mobile-originated request finished; hand the person back to the
    /// browser that is waiting on this same device.
    MinimizeMobileApp,
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
                self.user_actions.remove(&id);
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

            Input::LoginAccepted { request_id } => {
                self.add_user_action(
                    wire::UserAction::AcceptLoginRequest {
                        request_id: request_id.clone(),
                        descriptor: self.descriptor.clone(),
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

            Input::SignMessageRejected { request_id } => {
                self.add_user_action(
                    wire::UserAction::CancelSignMessageRequest {
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
        });
        assert!(effects
            .iter()
            .any(|e| matches!(e, Effect::MinimizeMobileApp)));

        let _ = core.handle(Input::AppLink {
            app_link: crate::link::parse_app_link("liquidconnect://login/?request_id=q1").unwrap(),
        });
        let effects = core.handle(Input::LoginAccepted {
            request_id: "q1".to_owned(),
        });
        assert!(!effects
            .iter()
            .any(|e| matches!(e, Effect::MinimizeMobileApp)));
    }
}
