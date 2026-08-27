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
