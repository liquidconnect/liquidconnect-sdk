//! uniffi surface over `lc-wallet-core`, for Kotlin (Android) and Swift
//! (iOS) wallet integrations.
//!
//! Shape rules: everything crossing the boundary is strings, integers,
//! records and enums — no chain types leak through. The wallet object
//! owns its own tokio runtime, because a mobile host has none to offer,
//! and delivers events through a foreign-implemented listener. Signing
//! stays on the host side: `accept_sign` takes a PSET the wallet has
//! already verified and signed with its own machinery.

use std::sync::Arc;

use lc_wallet_core::identity;
use lc_wallet_core::key::WalletKey;
use lc_wallet_core::transport;
use lc_wallet_core::wire;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum LcError {
    #[error("{0}")]
    Failure(String),
}

impl From<anyhow::Error> for LcError {
    fn from(err: anyhow::Error) -> Self {
        LcError::Failure(format!("{err:#}"))
    }
}

#[derive(uniffi::Enum, Clone, Copy)]
pub enum Network {
    Liquid,
    LiquidTestnet,
    Regtest,
}

impl From<Network> for lc_wallet_core::key::Network {
    fn from(n: Network) -> Self {
        match n {
            Network::Liquid => lc_wallet_core::key::Network::Liquid,
            Network::LiquidTestnet => lc_wallet_core::key::Network::LiquidTestnet,
            Network::Regtest => lc_wallet_core::key::Network::Regtest,
        }
    }
}

#[derive(uniffi::Record)]
pub struct LoginRequestInfo {
    pub request_id: String,
    pub domain: String,
    pub ttl_ms: u64,
}

#[derive(uniffi::Record)]
pub struct SignRequestInfo {
    pub request_id: String,
    pub domain: String,
    pub pset: String,
    pub ttl_ms: u64,
}

#[derive(uniffi::Record)]
pub struct SignMessageRequestInfo {
    pub request_id: String,
    pub domain: String,
    /// 32-byte digest, hex-encoded. The host renders the domain and
    /// description; the digest's meaning is the requesting service's to
    /// define and bind.
    pub digest: String,
    pub description: Option<String>,
    pub ttl_ms: u64,
}

#[derive(uniffi::Record)]
pub struct PayRequestInfo {
    pub request_id: String,
    pub domain: String,
    /// Liquid address the payment goes to. The intent is advisory: the
    /// host builds the real spend from the wallet's own coins and renders
    /// what it actually built (recipient, amount, fee) for approval.
    pub recipient: String,
    /// Asset id, hex-encoded (64 chars).
    pub asset_id: String,
    /// Amount in the asset's satoshi units.
    pub amount: u64,
    pub memo: Option<String>,
    pub ttl_ms: u64,
}

#[derive(uniffi::Record)]
pub struct FundRequestInfo {
    pub request_id: String,
    pub domain: String,
    /// The RP-built transaction template, PSET base64. Hosts MUST run the
    /// SDK's `verify_fund_template` (rules: explicit-only template,
    /// deficit == amount, every other asset self-covered) before showing
    /// anything, then fund with their own coins + one blinded change and
    /// sign only their own inputs.
    pub template: String,
    /// Asset id, hex-encoded (64 chars).
    pub asset_id: String,
    /// Amount in the asset's satoshi units — the template's deficit.
    pub amount: u64,
    pub memo: Option<String>,
    pub ttl_ms: u64,
}

#[derive(uniffi::Record)]
pub struct SessionInfo {
    pub session_id: String,
    pub domain: String,
    pub is_local: bool,
}

#[derive(uniffi::Enum)]
pub enum WalletEvent {
    Connected,
    LoggedIn,
    Disconnected,
    LoginRequested { request: LoginRequestInfo },
    LoginRequestRemoved { request_id: String },
    SignRequested { request: SignRequestInfo },
    SignRequestRemoved { request_id: String },
    SignMessageRequested { request: SignMessageRequestInfo },
    SignMessageRequestRemoved { request_id: String },
    /// An RP asked for ONE address to pay this wallet at. The host
    /// answers with a FRESH unused address in the session's network, or
    /// rejects — see docs/receive-address-spec.md.
    ReceiveAddressRequested { request: ReceiveAddressRequestInfo },
    ReceiveAddressRequestRemoved { request_id: String },
    /// An RP asked for this wallet's balance of ONE asset. The host
    /// answers with the confirmed amount in base units, or rejects — see
    /// docs/asset-balance-spec.md.
    AssetBalanceRequested { request: AssetBalanceRequestInfo },
    AssetBalanceRequestRemoved { request_id: String },
    /// An RP reported what it holds for this wallet (a venue's margin
    /// balance and position, a lending desk's collateral). Nothing to
    /// answer: show it under the RP's name, with its age — see
    /// docs/held-balances-spec.md. An update replaces the whole entry.
    HoldingsUpdated { report: HoldingsReportInfo },
    HoldingsRemoved { domain: String },
    PayRequested { request: PayRequestInfo },
    PayRequestRemoved { request_id: String },
    FundRequested { request: FundRequestInfo },
    FundRequestRemoved { request_id: String },
    Sessions { sessions: Vec<SessionInfo> },
    SessionCreated { session: SessionInfo },
    SessionRemoved { session_id: String },
    /// The connect server REFUSED an action this wallet sent (an accept,
    /// a cancel, a link login, a session stop). The host must render it:
    /// a swallowed refusal is how a wrong-network deep link died in
    /// silence. `action` is a stable kind label and `subject_id` the
    /// request (or session) it concerned, so a host can tie the failure
    /// back to the thing the user was looking at without parsing prose.
    ActionFailed {
        action: String,
        subject_id: String,
        message: String,
    },
    MinimizeMobileApp,
}

/// A stable label + subject id for a refused action. Kept deliberately
/// coarse: hosts branch on the label, and the message carries the detail.
fn action_parts(action: wire::UserAction) -> (String, String) {
    use wire::UserAction as A;
    let (label, id) = match action {
        A::LinkLoginRequest { request_id } => ("link_login_request", request_id),
        A::AcceptLoginRequest { request_id, .. } => ("accept_login_request", request_id),
        A::CancelLoginRequest { request_id } => ("cancel_login_request", request_id),
        A::AcceptSignRequest { request_id, .. } => ("accept_sign_request", request_id),
        A::CancelSignRequest { request_id } => ("cancel_sign_request", request_id),
        A::AcceptSignMessageRequest { request_id, .. } => {
            ("accept_sign_message_request", request_id)
        }
        A::CancelSignMessageRequest { request_id } => ("cancel_sign_message_request", request_id),
        A::AcceptPayRequest { request_id, .. } => ("accept_pay_request", request_id),
        A::CancelPayRequest { request_id } => ("cancel_pay_request", request_id),
        A::AcceptFundRequest { request_id, .. } => ("accept_fund_request", request_id),
        A::CancelFundRequest { request_id } => ("cancel_fund_request", request_id),
        A::AcceptReceiveAddressRequest { request_id, .. } => {
            ("accept_receive_address_request", request_id)
        }
        A::CancelReceiveAddressRequest { request_id } => {
            ("cancel_receive_address_request", request_id)
        }
        A::AcceptAssetBalanceRequest { request_id, .. } => {
            ("accept_asset_balance_request", request_id)
        }
        A::CancelAssetBalanceRequest { request_id } => {
            ("cancel_asset_balance_request", request_id)
        }
        A::StopSession { session_id } => ("stop_session", session_id),
    };
    (label.to_owned(), id)
}

#[derive(uniffi::Record)]
pub struct ReceiveAddressRequestInfo {
    pub request_id: String,
    pub domain: String,
    pub description: Option<String>,
    pub ttl_ms: u64,
}

#[derive(uniffi::Record)]
pub struct AssetBalanceRequestInfo {
    pub request_id: String,
    pub domain: String,
    pub description: Option<String>,
    /// Liquid asset id, 64 hex chars.
    pub asset_id: String,
    pub ttl_ms: u64,
}

#[derive(uniffi::Record)]
pub struct HoldingInfo {
    pub label: String,
    /// "balance", "position", "collateral", "credit" — or anything else
    pub kind: String,
    pub asset_id: Option<String>,
    pub unit: String,
    /// base units, signed (a short position is negative)
    pub amount: i64,
    pub precision: u8,
}

#[derive(uniffi::Record)]
pub struct HoldingsReportInfo {
    pub domain: String,
    pub holdings: Vec<HoldingInfo>,
    /// unix ms, as the RP stamped it
    pub as_of_ms: i64,
}

fn holdings_info(r: wire::HoldingsReport) -> HoldingsReportInfo {
    HoldingsReportInfo {
        domain: r.domain,
        as_of_ms: r.as_of,
        holdings: r
            .holdings
            .into_iter()
            .map(|h| HoldingInfo {
                label: h.label,
                kind: h.kind,
                asset_id: h.asset_id,
                unit: h.unit,
                amount: h.amount,
                precision: h.precision,
            })
            .collect(),
    }
}

fn session_info(s: wire::Session) -> SessionInfo {
    SessionInfo {
        session_id: s.session_id,
        domain: s.domain,
        is_local: s.is_local,
    }
}

fn map_event(event: transport::WalletEvent) -> WalletEvent {
    match event {
        transport::WalletEvent::Connected => WalletEvent::Connected,
        transport::WalletEvent::LoggedIn => WalletEvent::LoggedIn,
        transport::WalletEvent::Disconnected => WalletEvent::Disconnected,
        transport::WalletEvent::LoginRequested(r) => WalletEvent::LoginRequested {
            request: LoginRequestInfo {
                request_id: r.request_id,
                domain: r.domain,
                ttl_ms: r.ttl.as_millis(),
            },
        },
        transport::WalletEvent::LoginRequestRemoved { request_id } => {
            WalletEvent::LoginRequestRemoved { request_id }
        }
        transport::WalletEvent::SignRequested(r) => WalletEvent::SignRequested {
            request: SignRequestInfo {
                request_id: r.request_id,
                domain: r.domain,
                pset: r.pset,
                ttl_ms: r.ttl.as_millis(),
            },
        },
        transport::WalletEvent::SignRequestRemoved { request_id } => {
            WalletEvent::SignRequestRemoved { request_id }
        }
        transport::WalletEvent::SignMessageRequested(r) => WalletEvent::SignMessageRequested {
            request: SignMessageRequestInfo {
                request_id: r.request_id,
                domain: r.domain,
                digest: r.digest,
                description: r.description,
                ttl_ms: r.ttl.as_millis(),
            },
        },
        transport::WalletEvent::SignMessageRequestRemoved { request_id } => {
            WalletEvent::SignMessageRequestRemoved { request_id }
        }
        transport::WalletEvent::PayRequested(r) => WalletEvent::PayRequested {
            request: PayRequestInfo {
                request_id: r.request_id,
                domain: r.domain,
                recipient: r.recipient,
                asset_id: r.asset_id,
                amount: r.amount,
                memo: r.memo,
                ttl_ms: r.ttl.as_millis(),
            },
        },
        transport::WalletEvent::PayRequestRemoved { request_id } => {
            WalletEvent::PayRequestRemoved { request_id }
        }
        transport::WalletEvent::FundRequested(r) => WalletEvent::FundRequested {
            request: FundRequestInfo {
                request_id: r.request_id,
                domain: r.domain,
                template: r.template,
                asset_id: r.asset_id,
                amount: r.amount,
                memo: r.memo,
                ttl_ms: r.ttl.as_millis(),
            },
        },
        transport::WalletEvent::FundRequestRemoved { request_id } => {
            WalletEvent::FundRequestRemoved { request_id }
        }
        transport::WalletEvent::Sessions(s) => WalletEvent::Sessions {
            sessions: s.into_iter().map(session_info).collect(),
        },
        transport::WalletEvent::SessionCreated(s) => WalletEvent::SessionCreated {
            session: session_info(s),
        },
        transport::WalletEvent::SessionRemoved { session_id } => {
            WalletEvent::SessionRemoved { session_id }
        }
        transport::WalletEvent::ReceiveAddressRequested(r) => {
            WalletEvent::ReceiveAddressRequested {
                request: ReceiveAddressRequestInfo {
                    request_id: r.request_id,
                    domain: r.domain,
                    description: r.description,
                    ttl_ms: r.ttl.as_millis(),
                },
            }
        }
        transport::WalletEvent::ReceiveAddressRequestRemoved { request_id } => {
            WalletEvent::ReceiveAddressRequestRemoved { request_id }
        }
        transport::WalletEvent::AssetBalanceRequested(r) => {
            WalletEvent::AssetBalanceRequested {
                request: AssetBalanceRequestInfo {
                    request_id: r.request_id,
                    domain: r.domain,
                    description: r.description,
                    asset_id: r.asset_id,
                    ttl_ms: r.ttl.as_millis(),
                },
            }
        }
        transport::WalletEvent::AssetBalanceRequestRemoved { request_id } => {
            WalletEvent::AssetBalanceRequestRemoved { request_id }
        }
        transport::WalletEvent::HoldingsUpdated(r) => WalletEvent::HoldingsUpdated {
            report: holdings_info(r),
        },
        transport::WalletEvent::HoldingsRemoved { domain } => {
            WalletEvent::HoldingsRemoved { domain }
        }
        transport::WalletEvent::ActionFailed { action, message } => {
            let (action, subject_id) = action_parts(action);
            WalletEvent::ActionFailed {
                action,
                subject_id,
                message,
            }
        }
        transport::WalletEvent::MinimizeMobileApp => WalletEvent::MinimizeMobileApp,
    }
}

/// Implemented by the host app; events arrive on a runtime thread, so
/// hop to the UI thread before touching views.
#[uniffi::export(with_foreign)]
pub trait WalletEventListener: Send + Sync {
    fn on_event(&self, event: WalletEvent);
}

/// One connected wallet. Owns its runtime and its connection; drop it
/// (release it on the host side) to disconnect.
#[derive(uniffi::Object)]
pub struct LiquidConnectWallet {
    handle: transport::WalletConnect,
    _runtime: tokio::runtime::Runtime,
}

#[uniffi::export]
impl LiquidConnectWallet {
    /// `master_blinding_key` derives the wallet's Connect identity —
    /// nothing new to back up. `install_id_hex` is 32 hex chars;
    /// generate one with [`random_install_id_hex`] and persist it.
    #[uniffi::constructor]
    pub fn new(
        url: String,
        descriptor: String,
        master_blinding_key: Vec<u8>,
        network: Network,
        install_id_hex: String,
        listener: Arc<dyn WalletEventListener>,
    ) -> Result<Arc<Self>, LcError> {
        let mut install = [0u8; 16];
        hex::decode_to_slice(&install_id_hex, &mut install)
            .map_err(|e| LcError::Failure(format!("install_id_hex: {e}")))?;
        let key = WalletKey::new(&master_blinding_key, network.into());

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| LcError::Failure(format!("runtime: {e}")))?;

        let (handle, mut events) = {
            let _guard = runtime.enter();
            transport::WalletConnect::spawn(transport::WalletConnectConfig {
                url,
                descriptor,
                key,
                install_id: wire::InstallId(install),
            })
        };
        runtime.spawn(async move {
            while let Some(event) = events.recv().await {
                listener.on_event(map_event(event));
            }
        });

        Ok(Arc::new(LiquidConnectWallet {
            handle,
            _runtime: runtime,
        }))
    }

    /// Feed a scanned QR payload or opened `liquidconnect://` link.
    pub fn open_link(&self, url: String) -> Result<(), LcError> {
        self.handle.open_link(&url).map_err(LcError::from)
    }

    pub fn accept_login(&self, request_id: String) {
        self.handle.accept_login(&request_id);
    }

    pub fn reject_login(&self, request_id: String) {
        self.handle.reject_login(&request_id);
    }

    /// The PSET must already be verified and signed by the host wallet.
    pub fn accept_sign(&self, request_id: String, signed_pset: String) {
        self.handle.accept_sign(&request_id, &signed_pset);
    }

    /// Approve a message-signing request by id after showing the user the
    /// domain and description. The core signs the digest it stored from
    /// the server's request with the wallet key — the host never supplies
    /// the bytes to sign.
    pub fn accept_sign_message(&self, request_id: String) {
        self.handle.accept_sign_message(&request_id);
    }

    /// Approve a message-signing request with a signature the host
    /// produced in another signer (venue money key, hardware signer):
    /// 64-byte BIP340 over the request's digest, hex-encoded.
    pub fn accept_sign_message_signed(&self, request_id: String, signature: String) {
        self.handle.accept_sign_message_signed(&request_id, &signature);
    }

    pub fn reject_sign_message(&self, request_id: String) {
        self.handle.reject_sign_message(&request_id);
    }

    /// Approve a pay request with the txid of the payment the host wallet
    /// built, signed and broadcast itself from its own coins. The SDK
    /// never builds the transaction.
    /// Answer a receive-address request with an address from this
    /// wallet. Give a FRESH unused one: reusing an address links every
    /// payout the RP makes to you into one on-chain cluster, which is
    /// most of what this request exists to avoid.
    pub fn provide_receive_address(&self, request_id: String, address: String) {
        self.handle.provide_receive_address(&request_id, &address);
    }

    pub fn reject_receive_address(&self, request_id: String) {
        self.handle.reject_receive_address(&request_id);
    }

    /// Answer an asset-balance request with this wallet's confirmed
    /// balance of the named asset, in base units. Confirmed coins only:
    /// the RP shows what could be sent over now, not what is in flight.
    pub fn provide_asset_balance(&self, request_id: String, amount: u64) {
        self.handle.provide_asset_balance(&request_id, amount);
    }

    pub fn reject_asset_balance(&self, request_id: String) {
        self.handle.reject_asset_balance(&request_id);
    }

    pub fn accept_pay(&self, request_id: String, txid: String) {
        self.handle.accept_pay(&request_id, &txid);
    }

    pub fn reject_pay(&self, request_id: String) {
        self.handle.reject_pay(&request_id);
    }

    /// Approve a fund request with the funded template the host wallet
    /// built: its own confidential inputs and single blinded change
    /// added, its own inputs signed, nothing else touched. The SDK never
    /// builds the funding; run `verify_fund_template` before showing.
    pub fn accept_fund(&self, request_id: String, pset: String) {
        self.handle.accept_fund(&request_id, &pset);
    }

    pub fn reject_fund(&self, request_id: String) {
        self.handle.reject_fund(&request_id);
    }

    pub fn reject_sign(&self, request_id: String) {
        self.handle.reject_sign(&request_id);
    }

    pub fn stop_session(&self, session_id: String) {
        self.handle.stop_session(&session_id);
    }

    pub fn register_fcm_token(&self, token: String) {
        self.handle.register_fcm_token(&token);
    }
}

// --- approval summaries -------------------------------------------------

#[derive(uniffi::Record)]
pub struct OutputSummary {
    pub address: Option<String>,
    pub script_hex: String,
    pub asset: Option<String>,
    pub amount: Option<u64>,
    pub is_fee: bool,
    pub is_payjoin_service_fee: bool,
    pub confidential: bool,
}

#[derive(uniffi::Record)]
pub struct TransactionSummary {
    pub input_count: u32,
    pub outputs: Vec<OutputSummary>,
    pub fee: Option<u64>,
    /// When false, the host wallet's own decode must fill the gaps
    /// before anyone is asked to approve — never render partial sums as
    /// totals.
    pub fully_explicit: bool,
}

/// What a sign request's PSET does, as structure to render. Pass the
/// payjoin order's fee address to have the service-fee output marked as
/// the declared thing it is; a payjoin context that matches no output is
/// an error, because a claimed context that describes nothing is a
/// mismatch, not a decoration.
#[uniffi::export]
pub fn summarize_pset(
    pset_b64: String,
    network: Network,
    payjoin_fee_address: Option<String>,
) -> Result<TransactionSummary, LcError> {
    let mut summary = lc_wallet_core::approval::summarize_pset(&pset_b64, network.into())?;
    if let Some(fee_address) = payjoin_fee_address {
        let marked = summary
            .annotate_payjoin(&lc_wallet_core::approval::PayjoinContext { fee_address })?;
        if marked == 0 {
            return Err(LcError::Failure(
                "payjoin context matched no output in this transaction".to_owned(),
            ));
        }
    }
    Ok(TransactionSummary {
        input_count: summary.input_count as u32,
        outputs: summary
            .outputs
            .into_iter()
            .map(|o| OutputSummary {
                address: o.address,
                script_hex: o.script_hex,
                asset: o.asset,
                amount: o.amount,
                is_fee: o.is_fee,
                is_payjoin_service_fee: o.is_payjoin_service_fee,
                confidential: o.confidential,
            })
            .collect(),
        fee: summary.fee,
        fully_explicit: summary.fully_explicit,
    })
}

/// What a fund-request template asks for, verified arithmetically —
/// the numbers are this SDK's computation, never the relying party's.
#[derive(uniffi::Record)]
pub struct FundTemplateSummary {
    pub input_count: u32,
    pub output_count: u32,
    /// The template's explicit fee output, satoshis.
    pub fee: u64,
    /// The template's deficit for the requested asset — equal to the
    /// stated amount by construction (a mismatch is an error).
    pub deficit: u64,
}

/// Verify a fund-request template against the RP's claim BEFORE showing
/// anything (spec: docs/fund-template-spec.md): explicit-only template,
/// deficit for `asset_id` exactly `amount`, every other asset (and the
/// fee) self-covered. An error is a refusal — do not render the request.
#[uniffi::export]
pub fn verify_fund_template(
    template_b64: String,
    asset_id: String,
    amount: u64,
) -> Result<FundTemplateSummary, LcError> {
    let summary =
        lc_wallet_core::approval::verify_fund_template(&template_b64, &asset_id, amount)?;
    Ok(FundTemplateSummary {
        input_count: summary.input_count as u32,
        output_count: summary.output_count as u32,
        fee: summary.fee,
        deficit: summary.deficit,
    })
}

/// A fresh installation id. Generate once, persist, reuse — the server
/// keys push registration on it.
#[uniffi::export]
pub fn random_install_id_hex() -> String {
    wire::InstallId::random().to_string()
}

// --- identity -----------------------------------------------------------

#[derive(uniffi::Record)]
pub struct IdentityStatusInfo {
    pub identity_id: Option<String>,
    pub email: bool,
    pub phone: bool,
    pub handle: Option<String>,
    /// Opt-in discovery switches, as the directory holds them now.
    pub discoverable_by_contact: bool,
    pub discoverable_by_handle: bool,
}

#[derive(uniffi::Record)]
pub struct VerifyOutcomeInfo {
    pub verified: bool,
    pub identity_id: Option<String>,
    pub txid: Option<String>,
}

#[derive(uniffi::Record)]
pub struct ConnectHintInfo {
    pub request_id: String,
    /// Open it like a scanned QR payload ([`LiquidConnectWallet::open_link`]).
    pub link: String,
}

#[derive(uniffi::Record)]
pub struct PhoneQuoteInfo {
    pub order_id: String,
    pub price_sats: u64,
    pub asset_id: String,
    pub connected: bool,
    /// Present when the wallet must approve a connection first.
    pub connect: Option<ConnectHintInfo>,
}

#[derive(uniffi::Record)]
pub struct PhoneStageInfo {
    /// awaiting_payment | awaiting_approval | paid | sms_sent | done
    pub stage: String,
    pub txid: Option<String>,
}

#[derive(uniffi::Record)]
pub struct ContactEntry {
    pub channel: String,
    pub value: String,
}

#[derive(uniffi::Record)]
pub struct ContactMatchInfo {
    pub input_index: u32,
    pub identity_id: String,
}

#[derive(uniffi::Record)]
pub struct DiscoverOutcomeInfo {
    pub matched: Vec<ContactMatchInfo>,
    pub unparsed_input_indexes: Vec<u32>,
}

#[derive(uniffi::Record)]
pub struct ContactInfo {
    pub identity_id: String,
    pub handle: Option<String>,
}

fn verify_outcome_info(o: identity::VerifyOutcome) -> VerifyOutcomeInfo {
    VerifyOutcomeInfo {
        verified: o.verified,
        identity_id: o.identity_id,
        txid: o.txid,
    }
}

/// The identity API for the connected wallet's user: verified email
/// (free), verified phone (paid from the wallet itself as an ordinary
/// sign request), contact discovery and pay-to-contact. Constructed
/// from the same master blinding key as [`LiquidConnectWallet`], so it
/// speaks as the same identity. Every call blocks on the network —
/// call off the UI thread.
#[derive(uniffi::Object)]
pub struct IdentityService {
    client: identity::IdentityClient,
    key: WalletKey,
}

#[uniffi::export]
impl IdentityService {
    /// `base_url` ends at the route prefix — through the public gateway
    /// that is `https://…/api/identity` — and `gateway_bearer` is the
    /// deployment's front-door bearer when it has one. The wallet-key
    /// signature inside every request is the caller's real
    /// authentication either way.
    #[uniffi::constructor]
    pub fn new(
        base_url: String,
        gateway_bearer: Option<String>,
        master_blinding_key: Vec<u8>,
        network: Network,
    ) -> Arc<Self> {
        Arc::new(IdentityService {
            client: identity::IdentityClient::new(base_url, gateway_bearer),
            key: WalletKey::new(&master_blinding_key, network.into()),
        })
    }

    pub fn status(&self) -> Result<IdentityStatusInfo, LcError> {
        let s = self.client.status(&self.key)?;
        Ok(IdentityStatusInfo {
            identity_id: s.identity_id,
            email: s.email,
            phone: s.phone,
            handle: s.handle,
            discoverable_by_contact: s.discoverability.by_contact_hash,
            discoverable_by_handle: s.discoverability.by_handle,
        })
    }

    pub fn email_start(&self, email: String) -> Result<(), LcError> {
        self.client.email_start(&self.key, &email)?;
        Ok(())
    }

    pub fn email_confirm(&self, email: String, code: String) -> Result<VerifyOutcomeInfo, LcError> {
        Ok(verify_outcome_info(
            self.client.email_confirm(&self.key, &email, &code)?,
        ))
    }

    pub fn phone_start(&self, phone: String) -> Result<PhoneQuoteInfo, LcError> {
        let q = self.client.phone_start(&self.key, &phone)?;
        Ok(PhoneQuoteInfo {
            order_id: q.order_id,
            price_sats: q.price_sats,
            asset_id: q.asset_id,
            connected: q.connected,
            connect: q.connect.map(|c| ConnectHintInfo {
                request_id: c.request_id,
                link: c.link,
            }),
        })
    }

    /// Puts the fee payment on the wallet as an ordinary sign request;
    /// the user approves it on their own device. Nothing here handles
    /// money.
    pub fn phone_pay(&self, order_id: String) -> Result<(), LcError> {
        self.client.phone_pay(&self.key, &order_id)?;
        Ok(())
    }

    pub fn phone_status(&self, order_id: String) -> Result<PhoneStageInfo, LcError> {
        let s = self.client.phone_status(&self.key, &order_id)?;
        Ok(PhoneStageInfo {
            stage: s.stage,
            txid: s.txid,
        })
    }

    pub fn phone_sms(&self, order_id: String) -> Result<(), LcError> {
        self.client.phone_sms(&self.key, &order_id)?;
        Ok(())
    }

    pub fn phone_confirm(
        &self,
        order_id: String,
        code: String,
    ) -> Result<VerifyOutcomeInfo, LcError> {
        Ok(verify_outcome_info(
            self.client.phone_confirm(&self.key, &order_id, &code)?,
        ))
    }

    pub fn set_discoverability(
        &self,
        by_contact_hash: bool,
        by_handle: bool,
    ) -> Result<(), LcError> {
        self.client
            .set_discoverability(&self.key, by_contact_hash, by_handle)?;
        Ok(())
    }

    pub fn contacts_discover(
        &self,
        contacts: Vec<ContactEntry>,
    ) -> Result<DiscoverOutcomeInfo, LcError> {
        let pairs: Vec<(String, String)> = contacts
            .into_iter()
            .map(|c| (c.channel, c.value))
            .collect();
        let o = self.client.contacts_discover(&self.key, &pairs)?;
        Ok(DiscoverOutcomeInfo {
            matched: o
                .matched
                .into_iter()
                .map(|m| ContactMatchInfo {
                    input_index: m.input_index as u32,
                    identity_id: m.identity_id,
                })
                .collect(),
            unparsed_input_indexes: o
                .unparsed_input_indexes
                .into_iter()
                .map(|i| i as u32)
                .collect(),
        })
    }

    pub fn contacts_save(&self, channel: String, value: String) -> Result<(), LcError> {
        self.client.contacts_save(&self.key, &channel, &value)?;
        Ok(())
    }

    pub fn contacts_list(&self) -> Result<Vec<ContactInfo>, LcError> {
        Ok(self
            .client
            .contacts_list(&self.key)?
            .into_iter()
            .map(|c| ContactInfo {
                identity_id: c.identity_id,
                handle: c.handle,
            })
            .collect())
    }

    pub fn contact_address(&self, identity_id: String) -> Result<String, LcError> {
        Ok(self.client.contact_address(&self.key, &identity_id)?)
    }
}
