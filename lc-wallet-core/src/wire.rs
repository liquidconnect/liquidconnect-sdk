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
    /// The RP asks this login to ALSO prove control of the wallet's
    /// service key for its domain — one request, one approval, instead
    /// of a login followed by a separate signing round trip. Opaque
    /// bytes chosen by the RP; the wallet signs a digest it builds
    /// itself over a fixed tag, the domain the CONNECT SERVER knows for
    /// this RP, and this challenge (`venue::service_login_digest`), so
    /// the RP can never steer what gets signed and the result cannot be
    /// replayed at another RP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_challenge: Option<String>,
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

/// A relying party's request for ONE address to pay this wallet at
/// (docs/receive-address-spec.md).
///
/// It exists so an RP that must name a destination — a venue withdrawal
/// commits the payout script in the digest the user approves — does not
/// have to be handed a watch-only DESCRIPTOR to find one. The RP learns
/// one address for one payout instead of the whole wallet forever.
///
/// The wallet answers with a FRESH unused address, so separate payouts
/// are not linked on chain, and refuses when the session's network is not
/// its own. There is no proof of ownership and none is needed: the wallet
/// is the payee, so a lie costs only the liar, and the user approves the
/// address where it is displayed (in the RP's own claim) regardless.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveAddressRequest {
    pub request_id: String,
    pub domain: String,
    /// What the RP wants it for ("Rolling Future withdrawal"). Shown if
    /// the wallet shows anything; never parsed, never trusted.
    pub description: Option<String>,
    pub ttl: DurationMs,
}

/// A relying party's request for this wallet's balance of ONE asset
/// (docs/asset-balance-spec.md).
///
/// It exists so an RP that shows "what you could still send over" — the
/// venue's "USDT in your wallet" row — does not need the wallet's
/// watch-only descriptor to know it. The RP learns one number for one
/// asset for the life of the session, instead of every address, balance
/// and transaction forever.
///
/// The wallet answers from its own coins, with no dialog: the user
/// consented to the session at login and the disclosure is bounded to the
/// named asset. It may refuse; an RP treats refusal, timeout and an app
/// too old to know the request alike — no number. There is no proof
/// attached: the RP can act on the answer only by asking the wallet to
/// pay, which the user then approves on the real transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetBalanceRequest {
    pub request_id: String,
    pub domain: String,
    /// What the RP wants it for ("Rolling Future — USDT you could
    /// deposit"). Shown if the wallet shows anything; never parsed.
    pub description: Option<String>,
    /// The Liquid asset id, 64 hex chars. ONE asset per request.
    pub asset_id: String,
    pub ttl: DurationMs,
}

/// One line of what a relying party holds FOR this wallet: a venue's
/// margin balance, its open position, a lending desk's collateral. Amounts
/// are integers in the asset's base units (`10^precision` per whole unit),
/// signed so a short position reads as negative. `asset_id` names a Liquid
/// asset when there is one; a synthetic figure (a BTC-denominated position
/// at a USDt-margined venue) has none and is described by `unit` alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holding {
    /// "Margin balance", "Position", "Collateral" — the RP's words, shown
    /// as given, never parsed.
    pub label: String,
    /// A coarse kind the wallet may group or icon by: "balance",
    /// "position", "collateral", "credit". Unknown kinds render as text.
    pub kind: String,
    pub asset_id: Option<String>,
    pub unit: String,
    pub amount: i64,
    pub precision: u8,
}

/// What ONE relying party holds for this wallet, as that RP last reported
/// it. Reported by the RP unprompted whenever it changes — there is no
/// request and nothing to approve: the person consented to the session,
/// and this only tells them what the site already knows about their own
/// account there. The wallet cannot derive these numbers from the chain
/// (a venue leaf sits inside a blinded pool output), so the RP's word is
/// what there is; `as_of` lets the wallet say how old that word is. An RP
/// that reports an empty list clears its entry. See
/// docs/held-balances-spec.md.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldingsReport {
    pub domain: String,
    pub holdings: Vec<Holding>,
    /// When the RP computed the figures (unix ms).
    pub as_of: i64,
}

/// A relying party's request that the wallet PAY: build a transaction to
/// `recipient` for `amount` of `asset_id` from the wallet's own coins, show
/// the real constructed send (recipient, amount, network fee) for approval,
/// sign and broadcast it. The intent is advisory — the wallet renders what it
/// actually built; only the wallet holds the keys and blinding factors, so
/// nothing else can construct this spend. The reply is the broadcast txid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayRequest {
    pub request_id: String,
    pub domain: String,
    /// Liquid address (confidential or not) the payment goes to.
    pub recipient: String,
    /// Asset id, hex-encoded (64 chars).
    pub asset_id: String,
    /// Amount in the asset's satoshi units.
    pub amount: u64,
    /// Free text shown to the user (e.g. what the payment is for).
    pub memo: Option<String>,
    pub ttl: DurationMs,
}

/// A relying party's request that the wallet FUND a transaction template
/// the RP built: add its own confidential inputs and exactly one blinded
/// change output, sign only its own inputs (SIGHASH_ALL), and return the
/// funded PSET for the RP to complete and broadcast. The template must be
/// fully explicit and its per-asset arithmetic must equal the stated
/// `amount` — see `approval::verify_fund_template`, which every host runs
/// before showing anything. Spec: docs/fund-template-spec.md.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundRequest {
    pub request_id: String,
    pub domain: String,
    /// The RP-built transaction template, PSET base64.
    pub template: String,
    /// Asset id the wallet is asked to contribute, hex-encoded (64 chars).
    pub asset_id: String,
    /// Amount in the asset's satoshi units — must equal the template's
    /// computed deficit for `asset_id` exactly.
    pub amount: u64,
    /// Free text shown to the user (e.g. what the funding is for).
    pub memo: Option<String>,
    pub ttl: DurationMs,
}

/// A relying party's description of contracts this wallet is party to but
/// did not sign (a lender's positions, coins paid to a claim script, a
/// transition the venue built, everything after a restore). Untrusted: the
/// host verifies every spec against the wallet's own facts and the chain
/// (`contract_registration::register_all`) and answers spec by spec. No
/// dialog, unless the domain has not been granted yet. Sent only to an
/// install that advertised `contracts/1` (`LoginReq::features`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterContractsRequest {
    pub request_id: String,
    /// The connect server's word for who asks, never the relying party's.
    pub domain: String,
    pub contracts: Vec<crate::contract_registration::ContractSpec>,
    /// Shown in the wallet's log, e.g. "Your lending positions".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    pub ttl: DurationMs,
}

impl RegisterContractsRequest {
    /// The `contracts` array as JSON text, for a binding that hands the
    /// specs across a language boundary as they arrived.
    pub fn contracts_json(&self) -> String {
        serde_json::to_string(&self.contracts).unwrap_or_else(|_| "[]".to_owned())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserAction {
    LinkLoginRequest {
        request_id: String,
    },

    AcceptLoginRequest {
        request_id: String,
        descriptor: String,
        /// The wallet's service key for this RP (x-only pubkey, hex) and
        /// its BIP340 signature over `service_login_digest`. Present
        /// only when the request carried a `service_challenge`. The
        /// connect server verifies both before the session exists, so an
        /// RP is told a key it can rely on rather than one it must
        /// re-check.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service_signature: Option<String>,
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

    /// Answer a [`ReceiveAddressRequest`] with one address in the
    /// session's network. Carries no signature by design — see the type.
    AcceptReceiveAddressRequest {
        request_id: String,
        address: String,
    },

    CancelReceiveAddressRequest {
        request_id: String,
    },

    /// Answer an [`AssetBalanceRequest`] with the wallet's confirmed
    /// balance of that asset, in the asset's base units.
    AcceptAssetBalanceRequest {
        request_id: String,
        amount: u64,
    },

    CancelAssetBalanceRequest {
        request_id: String,
    },

    CancelSignMessageRequest {
        request_id: String,
    },

    AcceptPayRequest {
        request_id: String,
        /// Txid of the broadcast payment, hex-encoded (64 chars).
        txid: String,
    },

    CancelPayRequest {
        request_id: String,
    },

    AcceptFundRequest {
        request_id: String,
        /// The funded template: wallet inputs and blinded change added,
        /// wallet inputs signed. PSET base64. The RP finalises its own
        /// inputs and broadcasts.
        pset: String,
    },

    CancelFundRequest {
        request_id: String,
    },

    /// Answer a [`RegisterContractsRequest`]: one result per spec, in the
    /// request's order. A batch may be partly refused.
    AcceptRegisterContractsRequest {
        request_id: String,
        results: Vec<crate::contract_registration::ContractResult>,
    },

    CancelRegisterContractsRequest {
        request_id: String,
    },

    /// The statement: everything this wallet holds of `domain`'s contracts,
    /// complete, replacing the last one. Sent after login for every domain
    /// the wallet has records for, and whenever a record of that domain
    /// changes. Empty = the wallet holds nothing of this domain (a wallet
    /// restored from its seed says exactly that, and the relying party
    /// registers again). `as_of` is unix milliseconds; the newest wins.
    /// The connect server keeps it only while the wallet has a session with
    /// `domain` and refuses it otherwise, so the core says it again when a
    /// session with the domain is created.
    ReportContracts {
        domain: String,
        contracts: Vec<crate::contract_registration::ContractEntry>,
        as_of: i64,
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
    /// What this install can do beyond the base protocol, as
    /// `name/version` strings (sideswap_rust docs/connect.md, "Features").
    /// Additive fields are invisible to an old wallet, so a relying party
    /// must be able to tell whether a new kind of request will be honoured
    /// before it sends one; the connect server copies the list of the
    /// install that linked a session into the relying party's view of it.
    /// Defaulted and omitted when empty: the frame a wallet without
    /// features sends is byte for byte the one it sent before the list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResp {
    pub sessions: Vec<Session>,
    pub sign_requests: Vec<SignRequest>,
    /// Pending message-signing requests for this wallet. Defaulted for
    /// compatibility with pre-message connect servers.
    #[serde(default)]
    pub sign_message_requests: Vec<SignMessageRequest>,
    /// Pending pay requests for this wallet. Defaulted for compatibility
    /// with pre-pay connect servers.
    #[serde(default)]
    pub pay_requests: Vec<PayRequest>,
    /// Pending receive-address requests. Defaulted for compatibility with
    /// connect servers that predate them.
    #[serde(default)]
    pub receive_address_requests: Vec<ReceiveAddressRequest>,
    /// Pending asset-balance requests. Defaulted for compatibility with
    /// connect servers that predate them.
    #[serde(default)]
    pub asset_balance_requests: Vec<AssetBalanceRequest>,
    /// Pending fund requests for this wallet. Defaulted for compatibility
    /// with pre-fund connect servers.
    #[serde(default)]
    pub fund_requests: Vec<FundRequest>,
    /// What each relying party last reported holding for this wallet.
    /// Defaulted for connect servers that predate holdings.
    #[serde(default)]
    pub holdings: Vec<HoldingsReport>,
    /// Pending registration requests for this install. Defaulted for
    /// connect servers that predate contracts.
    #[serde(default)]
    pub register_contracts_requests: Vec<RegisterContractsRequest>,
    /// What this connect server relays beyond the base protocol, as
    /// `name/version` strings: the wallet's side of the features list. A
    /// wallet states what it holds (`UserAction::ReportContracts`) only to
    /// a server that names `contracts/1`. Defaulted: a server that
    /// predates the list names nothing.
    #[serde(default)]
    pub features: Vec<String>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiveAddressRequestCreatedNotif {
    pub request: ReceiveAddressRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiveAddressRequestRemovedNotif {
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssetBalanceRequestCreatedNotif {
    pub request: AssetBalanceRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssetBalanceRequestRemovedNotif {
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HoldingsUpdatedNotif {
    pub report: HoldingsReport,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HoldingsRemovedNotif {
    pub domain: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PayRequestCreatedNotif {
    pub request: PayRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PayRequestRemovedNotif {
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FundRequestCreatedNotif {
    pub request: FundRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FundRequestRemovedNotif {
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterContractsRequestCreatedNotif {
    pub request: RegisterContractsRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterContractsRequestRemovedNotif {
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
    ReceiveAddressRequestCreated(ReceiveAddressRequestCreatedNotif),
    ReceiveAddressRequestRemoved(ReceiveAddressRequestRemovedNotif),
    AssetBalanceRequestCreated(AssetBalanceRequestCreatedNotif),
    AssetBalanceRequestRemoved(AssetBalanceRequestRemovedNotif),
    PayRequestCreated(PayRequestCreatedNotif),
    PayRequestRemoved(PayRequestRemovedNotif),
    FundRequestCreated(FundRequestCreatedNotif),
    FundRequestRemoved(FundRequestRemovedNotif),
    /// An RP reported what it holds for this wallet (docs/held-balances-spec.md).
    HoldingsUpdated(HoldingsUpdatedNotif),
    HoldingsRemoved(HoldingsRemovedNotif),
    /// A relying party describes contracts for the wallet to verify and
    /// keep. Only ever sent to an install that advertised `contracts/1`.
    RegisterContractsRequestCreated(RegisterContractsRequestCreatedNotif),
    RegisterContractsRequestRemoved(RegisterContractsRequestRemovedNotif),
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

        // Receive-address: the request carries NO digest and the answer
        // carries NO signature — if either ever appears here, someone has
        // confused this with sign-message (docs/receive-address-spec.md).
        let addr_action = To::Req {
            id: 7,
            req: Req::UserAction(UserActionReq {
                action: UserAction::AcceptReceiveAddressRequest {
                    request_id: "ra1".to_owned(),
                    address: "tlq1qexample".to_owned(),
                },
            }),
        };
        assert_eq!(
            serde_json::to_string(&addr_action).unwrap(),
            r#"{"Req":{"id":7,"req":{"UserAction":{"action":{"AcceptReceiveAddressRequest":{"request_id":"ra1","address":"tlq1qexample"}}}}}}"#
        );

        let addr_notif: From = serde_json::from_str(
            r#"{"Notif":{"notif":{"ReceiveAddressRequestCreated":{"request":{"request_id":"ra1","domain":"paper.swaption.io","description":"Rolling Future withdrawal","ttl":60000}}}}}"#,
        )
        .unwrap();
        match addr_notif {
            From::Notif {
                notif: Notif::ReceiveAddressRequestCreated(n),
            } => {
                assert_eq!(n.request.request_id, "ra1");
                assert_eq!(n.request.domain, "paper.swaption.io");
                assert_eq!(n.request.ttl.as_millis(), 60_000);
            }
            other => panic!("wrong parse: {other:?}"),
        }

        // Asset-balance: ONE asset in, ONE integer out, no signature and
        // no proof — an RP acts on the number only by asking the wallet to
        // pay, which the user approves on the real transaction
        // (docs/asset-balance-spec.md).
        let bal_action = To::Req {
            id: 8,
            req: Req::UserAction(UserActionReq {
                action: UserAction::AcceptAssetBalanceRequest {
                    request_id: "ab1".to_owned(),
                    amount: 1_234_567_890,
                },
            }),
        };
        assert_eq!(
            serde_json::to_string(&bal_action).unwrap(),
            r#"{"Req":{"id":8,"req":{"UserAction":{"action":{"AcceptAssetBalanceRequest":{"request_id":"ab1","amount":1234567890}}}}}}"#
        );

        let bal_notif: From = serde_json::from_str(
            r#"{"Notif":{"notif":{"AssetBalanceRequestCreated":{"request":{"request_id":"ab1","domain":"paper.swaption.io","description":"USDT you could deposit","asset_id":"b612eb46313a2cd6ebabd8b7a8eed5696e29898b87a43bff41c94f51acef9d73","ttl":15000}}}}}"#,
        )
        .unwrap();
        match bal_notif {
            From::Notif {
                notif: Notif::AssetBalanceRequestCreated(n),
            } => {
                assert_eq!(n.request.request_id, "ab1");
                assert_eq!(n.request.asset_id.len(), 64);
                assert_eq!(n.request.ttl.as_millis(), 15_000);
            }
            other => panic!("wrong parse: {other:?}"),
        }

        // A connect server that predates receive-address omits the field
        // entirely; login must still parse.
        let old_login: Resp = serde_json::from_str(
            r#"{"Login":{"sessions":[],"sign_requests":[],"sign_message_requests":[],"pay_requests":[],"fund_requests":[]}}"#,
        )
        .unwrap();
        match old_login {
            Resp::Login(l) => {
                assert!(l.receive_address_requests.is_empty());
                assert!(l.asset_balance_requests.is_empty());
                assert!(l.holdings.is_empty());
            }
            other => panic!("wrong parse: {other:?}"),
        }

        // Holdings: reported by the RP, nothing to answer; a short
        // position is a negative amount (docs/held-balances-spec.md).
        let hold: From = serde_json::from_str(
            r#"{"Notif":{"notif":{"HoldingsUpdated":{"report":{"domain":"paper.swaption.io","as_of":1788619197000,"holdings":[{"label":"Margin balance","kind":"balance","asset_id":"b612eb46313a2cd6ebabd8b7a8eed5696e29898b87a43bff41c94f51acef9d73","unit":"USDt","amount":999417000000,"precision":8},{"label":"Position","kind":"position","asset_id":null,"unit":"BTC","amount":-115997507,"precision":8}]}}}}}"#,
        )
        .unwrap();
        match hold {
            From::Notif {
                notif: Notif::HoldingsUpdated(n),
            } => {
                assert_eq!(n.report.domain, "paper.swaption.io");
                assert_eq!(n.report.holdings.len(), 2);
                assert_eq!(n.report.holdings[1].amount, -115_997_507);
                assert!(n.report.holdings[1].asset_id.is_none());
            }
            other => panic!("wrong parse: {other:?}"),
        }
        let gone: From = serde_json::from_str(
            r#"{"Notif":{"notif":{"HoldingsRemoved":{"domain":"paper.swaption.io"}}}}"#,
        )
        .unwrap();
        assert!(matches!(gone, From::Notif { notif: Notif::HoldingsRemoved(n) } if n.domain == "paper.swaption.io"));

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

    /// The features list: a login without one is the frame it always was
    /// (so an old connect server sees nothing new), a login with one names
    /// them, and a server that predates the list ignores the field — it is
    /// the pinned fixture of `sideswap_rust`'s `connect_api::LoginReq`.
    #[test]
    fn login_req_features_wire_shapes() {
        let key = crate::key::WalletKey::new(&[7u8; 32], crate::key::Network::LiquidTestnet);
        let login = |features: Vec<String>| LoginReq {
            public_key: key.public_key(),
            signature: key.sign_challenge("abc"),
            install_id: None,
            features,
        };
        let bare = serde_json::to_value(login(vec![])).unwrap();
        assert!(bare.get("features").is_none(), "{bare}");
        assert_eq!(bare.as_object().unwrap().len(), 3);
        let named = serde_json::to_value(login(vec!["contracts/1".to_owned()])).unwrap();
        assert_eq!(named["features"], serde_json::json!(["contracts/1"]));
        // What an install built before the list sends still parses, as none.
        let old: LoginReq = serde_json::from_value(bare).unwrap();
        assert!(old.features.is_empty());
        let back: LoginReq = serde_json::from_value(named).unwrap();
        assert_eq!(back.features, vec!["contracts/1".to_owned()]);
    }

    /// A pre-message LoginResp (no sign_message_requests field) still parses.
    #[test]
    fn login_resp_back_compat() {
        let resp: LoginResp =
            serde_json::from_str(r#"{"sessions":[],"sign_requests":[]}"#).unwrap();
        assert!(resp.sign_message_requests.is_empty());
        assert!(resp.pay_requests.is_empty());
    }

    /// The pay-request frames, pinned to the exact fixtures in
    /// `sideswap_rust`'s `sideswap_api/src/connect_api.rs` — two crates,
    /// one wire. Never change one side alone.
    #[test]
    fn pay_request_wire_shapes() {
        // Wallet -> server: the payment was built, signed and broadcast.
        let to = To::Req {
            id: 7,
            req: Req::UserAction(UserActionReq {
                action: UserAction::AcceptPayRequest {
                    request_id: "p1".to_owned(),
                    txid: "cd".repeat(32),
                },
            }),
        };
        assert_eq!(
            serde_json::to_string(&to).unwrap(),
            format!(
                r#"{{"Req":{{"id":7,"req":{{"UserAction":{{"action":{{"AcceptPayRequest":{{"request_id":"p1","txid":"{}"}}}}}}}}}}}}"#,
                "cd".repeat(32)
            )
        );

        // Server -> wallet: a created request carrying the pay intent.
        let from: From = serde_json::from_str(
            r#"{"Notif":{"notif":{"PayRequestCreated":{"request":{"request_id":"p1","domain":"swaption.io","recipient":"tlq1qqw508d6qejxtdg4y5r3zarvary0c5xw7kct5v9fs","asset_id":"2222222222222222222222222222222222222222222222222222222222222222","amount":100000,"memo":"RF deposit","ttl":120000}}}}}"#,
        )
        .unwrap();
        match from {
            From::Notif {
                notif: Notif::PayRequestCreated(n),
            } => {
                assert_eq!(n.request.request_id, "p1");
                assert_eq!(n.request.amount, 100_000);
                assert_eq!(n.request.memo.as_deref(), Some("RF deposit"));
                assert_eq!(n.request.ttl.as_millis(), 120_000);
            }
            other => panic!("wrong parse: {other:?}"),
        }
    }

    /// The fund-request frames, pinned like the pay frames — two crates,
    /// one wire (`sideswap_api/src/connect_api.rs`). Never change one
    /// side alone.
    #[test]
    fn fund_request_wire_shapes() {
        // Wallet -> server: the template was funded and the wallet's own
        // inputs signed; the RP finalises and broadcasts.
        let to = To::Req {
            id: 9,
            req: Req::UserAction(UserActionReq {
                action: UserAction::AcceptFundRequest {
                    request_id: "f1".to_owned(),
                    pset: "cHNldP8BAgQCAAAA".to_owned(),
                },
            }),
        };
        assert_eq!(
            serde_json::to_string(&to).unwrap(),
            r#"{"Req":{"id":9,"req":{"UserAction":{"action":{"AcceptFundRequest":{"request_id":"f1","pset":"cHNldP8BAgQCAAAA"}}}}}}"#,
        );

        // Server -> wallet: a created request carrying the template and
        // the RP's claim about it.
        let from: From = serde_json::from_str(
            r#"{"Notif":{"notif":{"FundRequestCreated":{"request":{"request_id":"f1","domain":"paper.swaption.io","template":"cHNldP8BAgQCAAAA","asset_id":"2222222222222222222222222222222222222222222222222222222222222222","amount":2499000000,"memo":"Deposit 24.99 USDT into Rolling Future","ttl":180000}}}}}"#,
        )
        .unwrap();
        match from {
            From::Notif {
                notif: Notif::FundRequestCreated(n),
            } => {
                assert_eq!(n.request.request_id, "f1");
                assert_eq!(n.request.template, "cHNldP8BAgQCAAAA");
                assert_eq!(n.request.amount, 2_499_000_000);
                assert_eq!(n.request.ttl.as_millis(), 180_000);
            }
            other => panic!("wrong parse: {other:?}"),
        }

        // A pre-fund LoginResp still parses (serde default).
        let resp: LoginResp = serde_json::from_str(
            r#"{"sessions":[],"sign_requests":[]}"#,
        )
        .unwrap();
        assert!(resp.fund_requests.is_empty());
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

    /// The contracts frames (phase 1), pinned. `sideswap_rust`'s
    /// `connect_api` carries the same shapes; never change one side alone.
    #[test]
    fn register_contracts_wire_shapes() {
        use crate::contract_registration::{ContractEntry, ContractOutcome, ContractResult, EntryStatus};

        // Server -> wallet: a relying party's description, to be verified.
        let from: From = serde_json::from_str(
            r#"{"Notif":{"notif":{"RegisterContractsRequestCreated":{"request":{"request_id":"c1","domain":"paper.swaption.io","contracts":[{"contract_id":"abababababababababababababababababababababababababababababababab","kind":"sw/lend/claim/v1","leaf":"51f916310d382610bf7efd7b345d9641b3dc93917d2afb77289add911f3403e1","params":{"lender_token":"4444444444444444444444444444444444444444444444444444444444444444"},"role":"lender","coins":[{"txid":"6161616161616161616161616161616161616161616161616161616161616161","vout":1,"asset":"b612eb46313a2cd6ebabd8b7a8eed5696e29898b87a43bff41c94f51acef9d73","amount":"45685276800"}]}],"memo":"Your lending positions","ttl":60000}}}}}"#,
        )
        .unwrap();
        match from {
            From::Notif {
                notif: Notif::RegisterContractsRequestCreated(n),
            } => {
                assert_eq!(n.request.domain, "paper.swaption.io");
                assert_eq!(n.request.contracts.len(), 1);
                assert_eq!(n.request.contracts[0].kind, "sw/lend/claim/v1");
                assert!(n.request.contracts[0].state.is_none());
                assert_eq!(n.request.contracts[0].coins[0].amount, "45685276800");
                assert_eq!(n.request.memo.as_deref(), Some("Your lending positions"));
            }
            other => panic!("wrong parse: {other:?}"),
        }

        // Wallet -> server: one result per spec, a batch may be partly refused.
        let to = To::Req {
            id: 11,
            req: Req::UserAction(UserActionReq {
                action: UserAction::AcceptRegisterContractsRequest {
                    request_id: "c1".to_owned(),
                    results: vec![
                        ContractResult {
                            contract_id: "ab".repeat(32),
                            outcome: ContractOutcome::Registered,
                        },
                        ContractResult {
                            contract_id: "cd".repeat(32),
                            outcome: ContractOutcome::Rejected {
                                reason: "coin_mismatch".to_owned(),
                            },
                        },
                    ],
                },
            }),
        };
        assert_eq!(
            serde_json::to_string(&to).unwrap(),
            format!(
                r#"{{"Req":{{"id":11,"req":{{"UserAction":{{"action":{{"AcceptRegisterContractsRequest":{{"request_id":"c1","results":[{{"contract_id":"{}","outcome":"Registered"}},{{"contract_id":"{}","outcome":{{"Rejected":{{"reason":"coin_mismatch"}}}}}}]}}}}}}}}}}}}"#,
                "ab".repeat(32),
                "cd".repeat(32)
            )
        );

        // Wallet -> server: the statement. Empty is a statement too.
        let to = To::Req {
            id: 12,
            req: Req::UserAction(UserActionReq {
                action: UserAction::ReportContracts {
                    domain: "paper.swaption.io".to_owned(),
                    contracts: vec![ContractEntry {
                        contract_id: "ab".repeat(32),
                        kind: "sw/lend/position/v4".to_owned(),
                        state: Some("46117756200".to_owned()),
                        status: EntryStatus::Active,
                    }],
                    as_of: 1_789_624_000_000,
                },
            }),
        };
        assert_eq!(
            serde_json::to_string(&to).unwrap(),
            format!(
                r#"{{"Req":{{"id":12,"req":{{"UserAction":{{"action":{{"ReportContracts":{{"domain":"paper.swaption.io","contracts":[{{"contract_id":"{}","kind":"sw/lend/position/v4","state":"46117756200","status":"Active"}}],"as_of":1789624000000}}}}}}}}}}}}"#,
                "ab".repeat(32)
            )
        );

        // A connect server that predates contracts sends no such list.
        let resp: LoginResp = serde_json::from_str(r#"{"sessions":[],"sign_requests":[]}"#).unwrap();
        assert!(resp.register_contracts_requests.is_empty());
    }
}
