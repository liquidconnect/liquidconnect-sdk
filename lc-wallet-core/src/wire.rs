//! The Liquid Connect wallet-side wire protocol.
//!
//! Vendored from `sideswap-io/sideswap_rust` (`sideswap_api/src/connect_api.rs`,
//! MIT) and made self-contained: the `sideswap_types` helpers are inlined so
//! this crate carries the whole wire format. JSON over WebSocket, externally
//! tagged enums — see the round-trip tests at the bottom, which pin the exact
//! frame shapes so a refactor here cannot silently change the protocol.

use elements::schnorr::XOnlyPublicKey;
use elements::secp256k1_zkp::schnorr::Signature;
use serde::{Deserialize, Serialize};

pub type ReqId = i32;

/// Milliseconds on the wire, as a bare integer.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DurationMs(pub u64);

impl DurationMs {
    pub fn as_millis(self) -> u64 {
        self.0
    }
}

/// Sixteen bytes, hex on the wire. Identifies one app installation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct InstallId(pub [u8; 16]);

impl InstallId {
    /// A fresh random installation id; persist it and reuse it, because
    /// the server keys push registrations and session bookkeeping on it.
    pub fn random() -> Self {
        use rand::RngCore as _;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        InstallId(bytes)
    }
}

impl std::fmt::Display for InstallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl Serialize for InstallId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for InstallId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let mut bytes = [0u8; 16];
        hex::decode_to_slice(&text, &mut bytes).map_err(serde::de::Error::custom)?;
        Ok(InstallId(bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub domain: String,
    pub is_local: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub request_id: String,
    pub domain: String,
    pub ttl: DurationMs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub request_id: String,
    pub domain: String,
    pub pset: String,
    pub ttl: DurationMs,
}

/// A request to sign a 32-byte message digest with the wallet's Connect
/// identity key (no PSET, no transaction). `description` is text the wallet
/// shows so the user knows what the signature authorises; the wallet signs
/// `digest` and returns a BIP340 signature verifiable against the
/// `public_key` it logged in with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMessageRequest {
    pub request_id: String,
    pub domain: String,
    /// 32-byte digest, hex-encoded (64 chars).
    pub digest: String,
    pub description: Option<String>,
    pub ttl: DurationMs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserAction {
    LinkLoginRequest {
        request_id: String,
    },

    AcceptLoginRequest {
        request_id: String,
        descriptor: String,
    },

    CancelLoginRequest {
        request_id: String,
    },

    AcceptSignRequest {
        request_id: String,
        pset: String,
    },

    CancelSignRequest {
        request_id: String,
    },

    AcceptSignMessageRequest {
        request_id: String,
        /// 64-byte BIP340 signature over the request's digest, hex-encoded.
        signature: String,
    },

    CancelSignMessageRequest {
        request_id: String,
    },

    StopSession {
        session_id: String,
    },
}

// Requests

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeReq {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResp {
    pub challenge: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginReq {
    pub public_key: XOnlyPublicKey,
    pub signature: Signature,
    /// Unique id of the app installation. Optional only because the
    /// first shipped app version predates it; always set it.
    pub install_id: Option<InstallId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResp {
    pub sessions: Vec<Session>,
    pub sign_requests: Vec<SignRequest>,
    /// Pending message-signing requests for this wallet. Defaulted for
    /// compatibility with pre-message connect servers.
    #[serde(default)]
    pub sign_message_requests: Vec<SignMessageRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserActionReq {
    pub action: UserAction,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserActionResp {}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFcmReq {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFcmResp {}

// Notifications

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionCreatedNotif {
    pub session: Session,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionRemovedNotif {
    pub session_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequestCreatedNotif {
    pub request: LoginRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequestRemovedNotif {
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequestCreatedNotif {
    pub request: SignRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequestRemovedNotif {
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessageRequestCreatedNotif {
    pub request: SignMessageRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessageRequestRemovedNotif {
    pub request_id: String,
}

// Errors

/// Matches the deployed connect server's wallet-side `ErrorCode`
/// (`sideswap_api::connect_api`); the catch-all keeps a new server-side
/// code from turning an error frame into a parse failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Something wrong with the request arguments.
    InvalidRequest,
    /// Server error.
    Server,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
}

// Envelopes

#[derive(Debug, Serialize, Deserialize)]
pub enum Req {
    Challenge(ChallengeReq),
    Login(LoginReq),
    UserAction(UserActionReq),
    RegisterFcm(RegisterFcmReq),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Resp {
    Challenge(ChallengeResp),
    Login(LoginResp),
    UserAction(UserActionResp),
    RegisterFcm(RegisterFcmResp),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Notif {
    SessionCreated(SessionCreatedNotif),
    SessionRemoved(SessionRemovedNotif),
    LoginRequestCreated(LoginRequestCreatedNotif),
    LoginRequestRemoved(LoginRequestRemovedNotif),
    SignRequestCreated(SignRequestCreatedNotif),
    SignRequestRemoved(SignRequestRemovedNotif),
    SignMessageRequestCreated(SignMessageRequestCreatedNotif),
    SignMessageRequestRemoved(SignMessageRequestRemovedNotif),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum To {
    Req { id: ReqId, req: Req },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum From {
    Resp { id: ReqId, resp: Resp },
    Error { id: ReqId, err: Error },
    Notif { notif: Notif },
}

/// The public Connect servers' wallet endpoints.
pub const MAINNET_URL: &str = "wss://api.sideswap.io/wallet-connect";
pub const TESTNET_URL: &str = "wss://api-testnet.sideswap.io/wallet-connect";

#[cfg(test)]
mod tests {
    use super::*;

    /// The frame shapes, pinned. These strings are the protocol; if a
    /// change here breaks one, the change breaks every deployed peer.
    #[test]
    fn frame_shapes_are_exactly_the_wire_format() {
        let to = To::Req {
            id: 0,
            req: Req::Challenge(ChallengeReq {}),
        };
        assert_eq!(
            serde_json::to_string(&to).unwrap(),
            r#"{"Req":{"id":0,"req":{"Challenge":{}}}}"#
        );

        let action = To::Req {
            id: 3,
            req: Req::UserAction(UserActionReq {
                action: UserAction::LinkLoginRequest {
                    request_id: "r1".to_owned(),
                },
            }),
        };
        assert_eq!(
            serde_json::to_string(&action).unwrap(),
            r#"{"Req":{"id":3,"req":{"UserAction":{"action":{"LinkLoginRequest":{"request_id":"r1"}}}}}}"#
        );

        let from: From = serde_json::from_str(
            r#"{"Notif":{"notif":{"SignRequestCreated":{"request":{"request_id":"s1","domain":"example.com","pset":"cHNldP8=","ttl":60000}}}}}"#,
        )
        .unwrap();
        match from {
            From::Notif {
                notif: Notif::SignRequestCreated(n),
            } => {
                assert_eq!(n.request.request_id, "s1");
                assert_eq!(n.request.ttl.as_millis(), 60_000);
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    /// The message-signing frames, pinned to the exact fixtures in
    /// `sideswap_rust`'s `sideswap_api/src/connect_api.rs` — two crates,
    /// one wire. Never change one side alone.
    #[test]
    fn sign_message_wire_shapes() {
        let to = To::Req {
            id: 5,
            req: Req::UserAction(UserActionReq {
                action: UserAction::AcceptSignMessageRequest {
                    request_id: "r1".to_owned(),
                    signature: "ab".repeat(64),
                },
            }),
        };
        assert_eq!(
            serde_json::to_string(&to).unwrap(),
            format!(
                r#"{{"Req":{{"id":5,"req":{{"UserAction":{{"action":{{"AcceptSignMessageRequest":{{"request_id":"r1","signature":"{}"}}}}}}}}}}}}"#,
                "ab".repeat(64)
            )
        );

        let from: From = serde_json::from_str(
            r#"{"Notif":{"notif":{"SignMessageRequestCreated":{"request":{"request_id":"s1","domain":"swaption.io","digest":"1111111111111111111111111111111111111111111111111111111111111111","description":"Sell 0.001 BTC","ttl":60000}}}}}"#,
        )
        .unwrap();
        match from {
            From::Notif {
                notif: Notif::SignMessageRequestCreated(n),
            } => {
                assert_eq!(n.request.request_id, "s1");
                assert_eq!(n.request.description.as_deref(), Some("Sell 0.001 BTC"));
                assert_eq!(n.request.ttl.as_millis(), 60_000);
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    /// A pre-message LoginResp (no sign_message_requests field) still parses.
    #[test]
    fn login_resp_back_compat() {
        let resp: LoginResp =
            serde_json::from_str(r#"{"sessions":[],"sign_requests":[]}"#).unwrap();
        assert!(resp.sign_message_requests.is_empty());
    }

    /// Error frames parse even when the server grows a new code.
    #[test]
    fn unknown_error_code_still_parses() {
        let from: From = serde_json::from_str(
            r#"{"Error":{"id":7,"err":{"code":"SomethingNew","message":"m"}}}"#,
        )
        .unwrap();
        match from {
            From::Error { id, err } => {
                assert_eq!(id, 7);
                assert!(matches!(err.code, ErrorCode::Unknown));
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    #[test]
    fn install_id_is_hex_on_the_wire() {
        let id = InstallId([0xab; 16]);
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            "\"abababababababababababababababab\""
        );
        let back: InstallId =
            serde_json::from_str("\"abababababababababababababababab\"").unwrap();
        assert_eq!(back, id);
    }
}
