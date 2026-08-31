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
    PayRequested { request: PayRequestInfo },
    PayRequestRemoved { request_id: String },
    Sessions { sessions: Vec<SessionInfo> },
    SessionCreated { session: SessionInfo },
    SessionRemoved { session_id: String },
    MinimizeMobileApp,
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
        transport::WalletEvent::Sessions(s) => WalletEvent::Sessions {
            sessions: s.into_iter().map(session_info).collect(),
        },
        transport::WalletEvent::SessionCreated(s) => WalletEvent::SessionCreated {
            session: session_info(s),
        },
        transport::WalletEvent::SessionRemoved { session_id } => {
            WalletEvent::SessionRemoved { session_id }
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
    pub fn accept_pay(&self, request_id: String, txid: String) {
        self.handle.accept_pay(&request_id, &txid);
    }

    pub fn reject_pay(&self, request_id: String) {
        self.handle.reject_pay(&request_id);
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
