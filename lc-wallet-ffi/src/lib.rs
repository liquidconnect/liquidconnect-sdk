//! uniffi surface over `lc-wallet-core`, for Kotlin (Android) and Swift
//! (iOS) wallet integrations.
//!
//! Shape rules: everything crossing the boundary is strings, integers,
//! records and enums — no chain types leak through. The wallet object
//! owns its own tokio runtime, because a mobile host has none to offer,
//! and delivers events through a foreign-implemented listener. Signing
//! stays on the host side: `accept_sign` takes a PSET the wallet has
//! already verified and signed with its own machinery.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

use lc_wallet_core::contract_registration::{
    self, ChainUnavailable, ChainView, ContractEntry, ContractOutcome, ContractResult, WalletView,
};
use lc_wallet_core::contract_views::{FactsWalletView, HistoryChainView, HistoryTx, ScriptHistory};
use lc_wallet_core::contracts::{ContractRecord, ContractStatus, ContractStore, Role};
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
    /// A relying party describes contracts this wallet is party to but did
    /// not sign, for the wallet to verify and keep (covenant positions,
    /// phase 1). The connect server sends it only to a wallet built with
    /// [`LiquidConnectWallet::new_with_contracts`], which names
    /// `contracts/1`. Decide whether the person lets this domain record
    /// positions in the wallet, then answer with
    /// [`LiquidConnectWallet::register_contracts`]. Nothing in
    /// `contracts_json` is trusted before that call has checked it.
    RegisterContractsRequested { request: RegisterContractsRequestInfo },
    RegisterContractsRequestRemoved { request_id: String },
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
        A::AcceptRegisterContractsRequest { request_id, .. } => {
            ("accept_register_contracts_request", request_id)
        }
        A::CancelRegisterContractsRequest { request_id } => {
            ("cancel_register_contracts_request", request_id)
        }
        // The statement concerns a domain, not a request.
        A::ReportContracts { domain, .. } => ("report_contracts", domain),
        A::StopSession { session_id } => ("stop_session", session_id),
    };
    (label.to_owned(), id)
}

/// A relying party's description of contracts, as it arrived. `contracts_json`
/// is the request's `contracts` array (`ContractSpec` objects) as JSON text.
#[derive(uniffi::Record)]
pub struct RegisterContractsRequestInfo {
    pub request_id: String,
    pub domain: String,
    pub contracts_json: String,
    pub memo: Option<String>,
    pub ttl_ms: u64,
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
        transport::WalletEvent::RegisterContractsRequested(r) => {
            let contracts_json = r.contracts_json();
            WalletEvent::RegisterContractsRequested {
                request: RegisterContractsRequestInfo {
                    request_id: r.request_id,
                    domain: r.domain,
                    contracts_json,
                    memo: r.memo,
                    ttl_ms: r.ttl.as_millis(),
                },
            }
        }
        transport::WalletEvent::RegisterContractsRequestRemoved { request_id } => {
            WalletEvent::RegisterContractsRequestRemoved { request_id }
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
    /// The contract book, the requests it can answer and what was stated
    /// from it, for a wallet built with `new_with_contracts`.
    contracts: Option<Arc<ContractsBinding>>,
    _runtime: tokio::runtime::Runtime,
}

impl LiquidConnectWallet {
    fn build(
        url: String,
        descriptor: String,
        master_blinding_key: Vec<u8>,
        network: Network,
        install_id_hex: String,
        book: Option<Arc<ContractBook>>,
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

        let contracts = book.map(|book| Arc::new(ContractsBinding::new(book)));
        let features = match contracts {
            Some(_) => vec![lc_wallet_core::contracts::CONTRACTS_FEATURE.to_owned()],
            None => Vec::new(),
        };
        let (handle, mut events) = {
            let _guard = runtime.enter();
            transport::WalletConnect::spawn_with_features(
                transport::WalletConnectConfig {
                    url,
                    descriptor,
                    key,
                    install_id: wire::InstallId(install),
                },
                features,
            )
        };
        let statements = contracts.clone().map(|binding| (binding, handle.clone()));
        runtime.spawn(async move {
            while let Some(event) = events.recv().await {
                // Before the host hears of it: a request the host answers
                // must be known here, and a site the wallet connected to is
                // told at once what the book holds of it.
                if let Some((binding, handle)) = &statements {
                    for (domain, entries) in binding.observe(&event) {
                        handle.report_contracts(&domain, entries, unix_now().as_millis() as i64);
                    }
                }
                listener.on_event(map_event(event));
            }
        });

        Ok(Arc::new(LiquidConnectWallet {
            handle,
            contracts,
            _runtime: runtime,
        }))
    }
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
        Self::build(
            url,
            descriptor,
            master_blinding_key,
            network,
            install_id_hex,
            None,
            listener,
        )
    }

    /// The same wallet, keeping the contracts it did not sign in `book`. It
    /// names `contracts/1` at login, so a site may describe positions to it
    /// ([`WalletEvent::RegisterContractsRequested`], answered with
    /// [`LiquidConnectWallet::register_contracts`]). And it tells every site
    /// it is connected to what `book` holds of that site's contracts, an
    /// empty list where it holds nothing: that empty list is how a wallet
    /// restored from its seed is told again what is live, because a site
    /// cannot tell silence from a wallet that has not spoken yet.
    #[uniffi::constructor]
    pub fn new_with_contracts(
        url: String,
        descriptor: String,
        master_blinding_key: Vec<u8>,
        network: Network,
        install_id_hex: String,
        book: Arc<ContractBook>,
        listener: Arc<dyn WalletEventListener>,
    ) -> Result<Arc<Self>, LcError> {
        Self::build(
            url,
            descriptor,
            master_blinding_key,
            network,
            install_id_hex,
            Some(book),
            listener,
        )
    }

    /// Verify a site's registration request and answer it. BLOCKS on the
    /// chain lookups: call it off the UI thread. `allowed` is the person's
    /// grant for this domain; when it is false nothing is looked up and every
    /// description is refused as `not_allowed`. What holds is kept in the
    /// book, the site is answered description by description, and what the
    /// wallet holds of the domain is stated again. Save the book's
    /// `to_json()` afterwards.
    ///
    /// Errors, and nothing is answered: the wallet was built without a
    /// book, the request is no longer live (it ran out, or the site
    /// withdrew it), or `facts` holds a script or an asset id that is not
    /// hex.
    pub fn register_contracts(
        &self,
        request_id: String,
        allowed: bool,
        facts: WalletFacts,
        chain: Arc<dyn ContractChain>,
    ) -> Result<Vec<ContractResultInfo>, LcError> {
        let binding = self.contracts.as_ref().ok_or_else(|| {
            LcError::Failure("this wallet keeps no contract book: build it with new_with_contracts".to_owned())
        })?;
        let wallet = facts.view()?;
        let backend = HostChain(chain.as_ref());
        let chain = HistoryChainView::new(&backend);
        let (results, due) =
            binding.register(&request_id, allowed, &wallet, &chain, unix_now().as_secs())?;
        self.handle
            .answer_register_contracts(&request_id, results.clone());
        for (domain, entries) in due {
            self.handle
                .report_contracts(&domain, entries, unix_now().as_millis() as i64);
        }
        Ok(results.into_iter().map(ContractResultInfo::from).collect())
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

// --- contracts the wallet did not sign ----------------------------------
//
// Covenant positions, phase 1. A relying party describes contracts this
// wallet is party to but did not sign: a lender's position created by a
// borrower's fill of its offer, coins other people paid to its claim
// script, everything live after a restore from the seed. The wallet keeps
// one only after it has checked by itself that the contract is real and
// binds money to THIS wallet (`lc_wallet_core::contract_registration`), so a
// site that describes something false loses only that registration.
//
// A host keeps a `ContractBook`, builds the wallet with
// `LiquidConnectWallet::new_with_contracts`, and answers every
// `WalletEvent::RegisterContractsRequested` with `register_contracts`,
// handing over the wallet's facts and its chain backend. The rules of the
// check, the reading of a script's history and the statement to every
// connected site stay on this side of the boundary.

fn unix_now() -> std::time::Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

/// What the wallet is, for the role check: a role is bound by a script that
/// is the wallet's or a token the wallet holds, never by the site's word.
#[derive(uniffi::Record)]
pub struct WalletFacts {
    /// Every scriptPubKey the wallet has derived, used or not, hex-encoded.
    /// An address handed to a site long ago and never paid must be among
    /// them.
    pub scripts: Vec<String>,
    /// What the wallet holds, per coin or per asset (amounts of one asset
    /// are added up). A position token or a lender token is held when the
    /// wallet holds exactly one unit of it.
    pub balances: Vec<AssetAmount>,
}

#[derive(uniffi::Record)]
pub struct AssetAmount {
    /// Asset id, hex-encoded (64 chars).
    pub asset_id: String,
    /// Base units.
    pub amount: u64,
}

impl WalletFacts {
    fn view(&self) -> Result<FactsWalletView, LcError> {
        let scripts = self
            .scripts
            .iter()
            .map(|script| {
                hex::decode(script)
                    .map(elements::Script::from)
                    .map_err(|e| LcError::Failure(format!("facts: script {script}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let balances = self
            .balances
            .iter()
            .map(|balance| {
                elements::AssetId::from_str(&balance.asset_id)
                    .map(|asset| (asset, balance.amount))
                    .map_err(|e| LcError::Failure(format!("facts: asset {}: {e}", balance.asset_id)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FactsWalletView::new(scripts.iter(), balances))
    }
}

/// A transaction in a script's history, as the host's chain backend has it.
#[derive(uniffi::Record)]
pub struct ChainTx {
    /// The whole transaction, consensus-encoded, hex. Its id is computed
    /// from these bytes, never taken from the backend.
    pub transaction_hex: String,
    /// In a block. A mempool transaction belongs in the history too,
    /// unconfirmed: a spend still in the mempool is a spend.
    pub confirmed: bool,
}

/// Why the host's chain backend gave no history.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ChainError {
    /// The backend cannot answer now (offline, timed out, overloaded). The
    /// site is told `chain_unavailable` and asks again later; nothing is
    /// refused for good.
    #[error("the chain backend cannot answer now: {reason}")]
    Unavailable { reason: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for ChainError {
    fn from(err: uniffi::UnexpectedUniFFICallbackError) -> Self {
        // A host callback that threw anything else cannot answer either.
        ChainError::Unavailable { reason: err.reason }
    }
}

/// The chain as the coin check needs it, implemented by the host over the
/// backend it already uses. It is asked by script, as an Electrum or an
/// Esplora server is indexed, and each script once per registration.
#[uniffi::export(with_foreign)]
pub trait ContractChain: Send + Sync {
    /// Every transaction that pays `script_hex` (a scriptPubKey, hex) or
    /// spends a coin of it, mempool included, each whole. Electrum:
    /// `blockchain.scripthash.get_history` (the scripthash is the SHA-256 of
    /// the script, byte-reversed), then `blockchain.transaction.get` for
    /// each; a height above 0 is confirmed. An empty list is an answer, and
    /// it means there is no such coin. Throw `ChainError.Unavailable` when
    /// the backend cannot say.
    fn script_history(&self, script_hex: String) -> Result<Vec<ChainTx>, ChainError>;
}

/// The host's backend behind the SDK's script-history view. A history that
/// does not decode is a backend that cannot answer, never "no such coin".
struct HostChain<'a>(&'a dyn ContractChain);

impl ScriptHistory for HostChain<'_> {
    fn history(&self, script: &elements::Script) -> Result<Vec<HistoryTx>, ChainUnavailable> {
        let txs = self
            .0
            .script_history(hex::encode(script.as_bytes()))
            .map_err(|err| {
                log::warn!("contracts: the host's chain gave no history: {err}");
                ChainUnavailable
            })?;
        txs.into_iter()
            .map(|chain_tx| {
                let tx = hex::decode(&chain_tx.transaction_hex)
                    .ok()
                    .and_then(|bytes| elements::encode::deserialize::<elements::Transaction>(&bytes).ok())
                    .ok_or_else(|| {
                        log::warn!("contracts: the host's chain gave a transaction that does not decode");
                        ChainUnavailable
                    })?;
                Ok(HistoryTx {
                    tx,
                    confirmed: chain_tx.confirmed,
                })
            })
            .collect()
    }
}

/// How the wallet answered one description.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum ContractOutcomeInfo {
    /// Verified and kept as a new record.
    Registered,
    /// Verified, and a record the wallet had moved on (its state or coins).
    Updated,
    /// Verified, and nothing new.
    Unchanged,
    /// Refused: `unknown_kind`, `leaf_mismatch`, `id_mismatch`,
    /// `script_mismatch`, `role_not_bound`, `coin_mismatch`,
    /// `not_explicit`, `chain_unavailable` (the site asks again later),
    /// `not_allowed`, `too_many`.
    Rejected { reason: String },
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct ContractResultInfo {
    pub contract_id: String,
    pub outcome: ContractOutcomeInfo,
}

impl From<ContractResult> for ContractResultInfo {
    fn from(result: ContractResult) -> Self {
        ContractResultInfo {
            contract_id: result.contract_id,
            outcome: match result.outcome {
                ContractOutcome::Registered => ContractOutcomeInfo::Registered,
                ContractOutcome::Updated => ContractOutcomeInfo::Updated,
                ContractOutcome::Unchanged => ContractOutcomeInfo::Unchanged,
                ContractOutcome::Rejected { reason } => ContractOutcomeInfo::Rejected { reason },
            },
        }
    }
}

/// One record, as a host shows it.
#[derive(uniffi::Record)]
pub struct ContractRecordInfo {
    /// Unique in the book.
    pub key: String,
    pub contract_id: String,
    /// "sw/lend/position/v5", "sw/lend/offer/v1", "sw/lend/claim/v1", …
    pub kind: String,
    /// "borrower" or "lender".
    pub role: String,
    /// The site that registered it, as the connect server names it.
    pub domain: String,
    /// The mutable slot as a decimal string, where the kind has one: a
    /// position's remaining debt, the cash an offer still holds.
    pub state: Option<String>,
    pub status: ContractStatusInfo,
    /// Where the contract's money sits.
    pub coins: Vec<ContractCoinInfo>,
    /// The terms, as the kind's canonical JSON object.
    pub params_json: String,
    /// The person hid it. It is still held, and still stated.
    pub hidden: bool,
    /// Unix seconds; 0 when unknown.
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(uniffi::Enum)]
pub enum ContractStatusInfo {
    /// Approved, the coin not seen on chain yet.
    Pending,
    Active,
    /// Past the kind's cutoff, the coin still unspent.
    Expired,
    /// Over. `path` says how: "exercise", "lapse", "last_look", "fill",
    /// "cancel", "expire", "collect", "sold" or "unknown".
    Closed { path: String },
}

#[derive(uniffi::Record)]
pub struct ContractCoinInfo {
    pub txid: String,
    pub vout: u32,
    /// Asset id, hex.
    pub asset_id: String,
    /// Base units.
    pub amount: u64,
}

impl ContractRecordInfo {
    fn of(key: &str, record: &ContractRecord) -> Self {
        ContractRecordInfo {
            key: key.to_owned(),
            contract_id: hex::encode(record.contract_id),
            kind: record.params.kind().to_owned(),
            role: match record.role {
                Role::Borrower => "borrower",
                Role::Lender => "lender",
            }
            .to_owned(),
            domain: record.domain.clone(),
            state: record.state.map(|state| state.to_string()),
            status: match &record.status {
                ContractStatus::Pending => ContractStatusInfo::Pending,
                ContractStatus::Active => ContractStatusInfo::Active,
                ContractStatus::Expired => ContractStatusInfo::Expired,
                ContractStatus::Closed { path } => ContractStatusInfo::Closed { path: path.clone() },
            },
            coins: record
                .coins
                .iter()
                .map(|coin| ContractCoinInfo {
                    txid: coin.outpoint.txid.to_string(),
                    vout: coin.outpoint.vout,
                    asset_id: coin.asset.to_string(),
                    amount: coin.amount,
                })
                .collect(),
            params_json: record.params.canonical_json(),
            hidden: record.hidden,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }
}

/// The wallet's records of the contracts it did not sign, each verified
/// before it was kept. Keep one per wallet: save `to_json()` after every
/// registration and load it with `from_json` when the app starts.
#[derive(uniffi::Object)]
pub struct ContractBook {
    store: Mutex<ContractStore>,
}

#[uniffi::export]
impl ContractBook {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(ContractBook {
            store: Mutex::new(ContractStore::default()),
        })
    }

    /// A book saved with `to_json`.
    #[uniffi::constructor]
    pub fn from_json(json: String) -> Result<Arc<Self>, LcError> {
        let store = serde_json::from_str::<ContractStore>(&json)
            .map_err(|e| LcError::Failure(format!("not a contract book: {e}")))?;
        Ok(Arc::new(ContractBook {
            store: Mutex::new(store),
        }))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&*self.lock()).expect("a contract book serialises")
    }

    /// Every record, hidden ones included, for a host that shows them.
    pub fn records(&self) -> Vec<ContractRecordInfo> {
        self.lock()
            .records()
            .map(|(key, record)| ContractRecordInfo::of(key, record))
            .collect()
    }
}

impl ContractBook {
    fn lock(&self) -> MutexGuard<'_, ContractStore> {
        // A panic on another thread must not cost the wallet its records.
        self.store.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A wallet's book, the registration requests it can answer, and what it
/// last stated to each site. Locks are taken in one order, this state first
/// and then the book.
struct ContractsBinding {
    book: Arc<ContractBook>,
    state: Mutex<BindingState>,
}

#[derive(Default)]
struct BindingState {
    /// Live registration requests, as they arrived.
    requests: BTreeMap<String, wire::RegisterContractsRequest>,
    /// Every session the wallet has, session id to domain.
    sessions: BTreeMap<String, String>,
    /// What was last handed over for each domain.
    stated: BTreeMap<String, Vec<ContractEntry>>,
}

impl ContractsBinding {
    fn new(book: Arc<ContractBook>) -> Self {
        ContractsBinding {
            book,
            state: Mutex::new(BindingState::default()),
        }
    }

    fn state(&self) -> MutexGuard<'_, BindingState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Follow the event stream: the requests there are to answer, and the
    /// sites the wallet is connected to. Returns the statements due.
    fn observe(&self, event: &transport::WalletEvent) -> Vec<(String, Vec<ContractEntry>)> {
        let mut state = self.state();
        match event {
            transport::WalletEvent::RegisterContractsRequested(request) => {
                state
                    .requests
                    .insert(request.request_id.clone(), request.clone());
                Vec::new()
            }
            transport::WalletEvent::RegisterContractsRequestRemoved { request_id } => {
                state.requests.remove(request_id);
                Vec::new()
            }
            transport::WalletEvent::Sessions(sessions) => {
                state.sessions = sessions
                    .iter()
                    .map(|session| (session.session_id.clone(), session.domain.clone()))
                    .collect();
                self.due(&mut state)
            }
            transport::WalletEvent::SessionCreated(session) => {
                state
                    .sessions
                    .insert(session.session_id.clone(), session.domain.clone());
                self.due(&mut state)
            }
            transport::WalletEvent::SessionRemoved { session_id } => {
                state.sessions.remove(session_id);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// For every domain the book names and every site the wallet is
    /// connected to, what the book holds of it, where that is not what was
    /// handed over last. The connect core says it all again after every
    /// login by itself.
    fn due(&self, state: &mut BindingState) -> Vec<(String, Vec<ContractEntry>)> {
        let store = self.book.lock();
        let domains = contract_registration::statement_domains(&store)
            .into_iter()
            .chain(state.sessions.values().cloned())
            .collect::<BTreeSet<_>>();
        let mut due = Vec::new();
        for domain in domains {
            let entries = contract_registration::statement(&store, &domain);
            if state.stated.get(&domain) != Some(&entries) {
                state.stated.insert(domain.clone(), entries.clone());
                due.push((domain, entries));
            }
        }
        due
    }

    /// Verify a live request against a COPY of the book, so that the chain
    /// lookups hold no lock, and take the outcome in unless a record moved
    /// meanwhile (`contract_registration::adopt_registered`). Returns the
    /// answer and the statements due.
    #[allow(clippy::type_complexity)]
    fn register(
        &self,
        request_id: &str,
        allowed: bool,
        wallet: &dyn WalletView,
        chain: &dyn ChainView,
        now: u64,
    ) -> Result<(Vec<ContractResult>, Vec<(String, Vec<ContractEntry>)>), LcError> {
        let request = self
            .state()
            .requests
            .get(request_id)
            .cloned()
            .ok_or_else(|| LcError::Failure(format!("registration request {request_id} is not live")))?;
        let before = self.book.lock().clone();
        let mut after = before.clone();
        let results = contract_registration::register_all(
            &mut after,
            &request.contracts,
            &request.domain,
            allowed,
            now,
            wallet,
            chain,
        );
        contract_registration::adopt_registered(&mut self.book.lock(), &before, &after);
        let due = self.due(&mut self.state());
        Ok((results, due))
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use elements::hashes::{sha256, Hash};
    use lc_wallet_core::contracts::{ContractCoin, ContractParams, PositionTerms};

    use super::*;

    const LBTC: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
    const USDT: &str = "b612eb46313a2cd6ebabd8b7a8eed5696e29898b87a43bff41c94f51acef9d73";
    const LENDER_TOKEN: &str = "03c5b3692f0051c5075c8b3ddd3ea68e51cd05d12b1d5f1e9ff3c80e10915a7e";
    const SITE: &str = "paper.swaption.io";

    /// The fill of position 51 of the paper venue (Liquid testnet,
    /// 2026-09-17), the vector the SDK pins its own rules against.
    fn fill_51() -> elements::Transaction {
        let hex_tx = include_str!(
            "../../lc-wallet-core/src/testdata/paper-testnet-2026-09-17-fill51.nowitness.hex"
        );
        let tx: elements::Transaction =
            elements::encode::deserialize(&hex::decode(hex_tx.trim()).unwrap()).unwrap();
        assert_eq!(
            tx.txid().to_string(),
            "1083eed00824b5e1852097e8994fc0088cb6506771930a446afea7e93230216b"
        );
        tx
    }

    fn hash_of(script_hex: &str) -> [u8; 32] {
        sha256::Hash::hash(&hex::decode(script_hex).unwrap()).to_byte_array()
    }

    /// Position 51 as the venue that lent it from a wallet describes it: the
    /// SDK's own description of the venue's record (the lending server's
    /// books, `contracts-phase1-lending`).
    fn position_51_request(request_id: &str) -> wire::RegisterContractsRequest {
        let asset = |hex_str: &str| elements::AssetId::from_str(hex_str).unwrap();
        let params = ContractParams::LendPositionV4(PositionTerms {
            collateral: asset(LBTC),
            cash: asset(USDT),
            size: 1_000_000,
            buyback: 456_85276800,
            expiry: 2_632_781,
            borrower_nft: asset("b29c1ca49115a770e304c57af9871dfe61835bf98fe8c7f62a0cc7308358f183"),
            lender_nft: asset(LENDER_TOKEN),
            payout: hash_of("512080f7930adc0dbb8df44c73de3f3f52199b057dcfea6da49b48b34ea748a7d483"),
            borrower_payout: hash_of("0014b0a920bbed9e09fc64fa3cc50c4e5ea6e801c907"),
            lastlook: hash_of("001432c4fbef1dd471fca2d52a6f8654e4a39d96ba2c"),
            lastlook_height: 2_632_766,
        });
        let record = ContractRecord {
            contract_id: params.contract_id(),
            params,
            role: Role::Lender,
            domain: String::new(),
            state: Some(456_85276800),
            coins: vec![ContractCoin {
                outpoint: elements::OutPoint::new(fill_51().txid(), 0),
                asset: asset(LBTC),
                amount: 1_000_000,
            }],
            status: ContractStatus::Active,
            hidden: false,
            history: Vec::new(),
            created_at: 0,
            updated_at: 0,
        };
        serde_json::from_value(serde_json::json!({
            "request_id": request_id,
            "domain": SITE,
            "contracts": [contract_registration::spec_of(&record)],
            "memo": "Your lending positions",
            "ttl": 120_000,
        }))
        .unwrap()
    }

    /// A host's chain that knows one transaction: the real fill.
    struct OneFill {
        fill: elements::Transaction,
        down: bool,
        asked: AtomicUsize,
    }

    impl OneFill {
        fn new(down: bool) -> Self {
            OneFill {
                fill: fill_51(),
                down,
                asked: AtomicUsize::new(0),
            }
        }
    }

    impl ContractChain for OneFill {
        fn script_history(&self, script_hex: String) -> Result<Vec<ChainTx>, ChainError> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            if self.down {
                return Err(ChainError::Unavailable {
                    reason: "offline".to_owned(),
                });
            }
            let pays = self
                .fill
                .output
                .iter()
                .any(|out| hex::encode(out.script_pubkey.as_bytes()) == script_hex);
            Ok(match pays {
                true => vec![ChainTx {
                    transaction_hex: elements::encode::serialize_hex(&self.fill),
                    confirmed: true,
                }],
                false => Vec::new(),
            })
        }
    }

    fn lender_facts() -> WalletFacts {
        WalletFacts {
            scripts: vec!["0014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()],
            balances: vec![
                AssetAmount {
                    asset_id: LENDER_TOKEN.to_owned(),
                    amount: 1,
                },
                AssetAmount {
                    asset_id: LBTC.to_owned(),
                    amount: 50_000,
                },
            ],
        }
    }

    #[allow(clippy::type_complexity)]
    fn answer(
        binding: &ContractsBinding,
        request_id: &str,
        allowed: bool,
        facts: WalletFacts,
        chain: &OneFill,
    ) -> (ContractOutcomeInfo, Vec<(String, Vec<ContractEntry>)>) {
        binding.observe(&transport::WalletEvent::RegisterContractsRequested(
            position_51_request(request_id),
        ));
        let backend = HostChain(chain);
        let (results, due) = binding
            .register(request_id, allowed, &facts.view().unwrap(), &HistoryChainView::new(&backend), 1_789_300_000)
            .unwrap();
        (ContractResultInfo::from(results[0].clone()).outcome, due)
    }

    fn rejected(reason: &str) -> ContractOutcomeInfo {
        ContractOutcomeInfo::Rejected {
            reason: reason.to_owned(),
        }
    }

    /// The whole answer through the binding, for a REAL position against the
    /// REAL fill that made it, read the way a host's backend hands it over:
    /// the lender's wallet keeps it and tells the site; a wallet without the
    /// lender token keeps nothing; a backend that cannot answer is "ask
    /// again later"; a site the person has not allowed is refused before
    /// anything is looked up; a request that is gone is not answered.
    #[test]
    fn a_description_is_checked_against_the_chain_the_host_hands_over() {
        let book = ContractBook::new();
        let binding = ContractsBinding::new(book.clone());
        let chain = OneFill::new(false);

        let (outcome, due) = answer(&binding, "r1", true, lender_facts(), &chain);
        assert_eq!(outcome, ContractOutcomeInfo::Registered);
        let records = book.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, "sw/lend/position/v4");
        assert_eq!(records[0].role, "lender");
        assert_eq!(records[0].domain, SITE);
        assert_eq!(records[0].state.as_deref(), Some("45685276800"));
        assert!(matches!(records[0].status, ContractStatusInfo::Active));
        assert_eq!(due.len(), 1, "the site is told what the wallet now holds");
        assert_eq!(due[0].0, SITE);
        assert_eq!(due[0].1.len(), 1);
        assert_eq!(due[0].1[0].contract_id, records[0].contract_id);

        // Described again: nothing new, nothing more to say.
        let (outcome, due) = answer(&binding, "r2", true, lender_facts(), &chain);
        assert_eq!(outcome, ContractOutcomeInfo::Unchanged);
        assert!(due.is_empty());

        // The saved book is the same book.
        let reloaded = ContractBook::from_json(book.to_json()).unwrap();
        assert_eq!(reloaded.to_json(), book.to_json());
        assert!(ContractBook::from_json("not a book".to_owned()).is_err());

        // A wallet without the lender token keeps nothing, whatever the site
        // says, and its chain is not asked.
        let stranger_book = ContractBook::new();
        let stranger = ContractsBinding::new(stranger_book.clone());
        let facts = WalletFacts {
            balances: Vec::new(),
            ..lender_facts()
        };
        let untouched = OneFill::new(false);
        assert_eq!(answer(&stranger, "r3", true, facts, &untouched).0, rejected("role_not_bound"));
        assert_eq!(untouched.asked.load(Ordering::SeqCst), 0);

        // A backend that cannot answer is "ask again later", never a refusal.
        let down = OneFill::new(true);
        assert_eq!(answer(&stranger, "r4", true, lender_facts(), &down).0, rejected("chain_unavailable"));

        // Not allowed: refused, and nothing is looked up.
        let untouched = OneFill::new(false);
        assert_eq!(answer(&stranger, "r5", false, lender_facts(), &untouched).0, rejected("not_allowed"));
        assert_eq!(untouched.asked.load(Ordering::SeqCst), 0);
        assert!(stranger_book.records().is_empty());

        // A request that ran out or was withdrawn is not answered.
        binding.observe(&transport::WalletEvent::RegisterContractsRequestRemoved {
            request_id: "r1".to_owned(),
        });
        let backend = HostChain(&chain);
        assert!(binding
            .register("r1", true, &lender_facts().view().unwrap(), &HistoryChainView::new(&backend), 0)
            .is_err());
        // Facts that are not hex are the host's mistake, told as one.
        let garbled = WalletFacts {
            scripts: vec!["not hex".to_owned()],
            balances: Vec::new(),
        };
        assert!(garbled.view().is_err());
    }

    fn session(session_id: &str, domain: &str) -> wire::Session {
        wire::Session {
            session_id: session_id.to_owned(),
            domain: domain.to_owned(),
            is_local: false,
        }
    }

    /// Every site the wallet is connected to hears what the book holds of it,
    /// an empty list where it holds nothing, once, and again only when that
    /// changes. That empty list is how a wallet restored from its seed is told
    /// again what is live (decision 49 of the covenant positions log).
    #[test]
    fn every_connected_site_is_told_what_the_book_holds_of_it() {
        let book = ContractBook::new();
        let binding = ContractsBinding::new(book.clone());
        let said = |due: Vec<(String, Vec<ContractEntry>)>| {
            due.into_iter()
                .map(|(domain, entries)| (domain, entries.len()))
                .collect::<Vec<_>>()
        };

        // Logged in with two sessions: both told, nothing held.
        let due = binding.observe(&transport::WalletEvent::Sessions(vec![
            session("s1", SITE),
            session("s2", "other.example"),
        ]));
        assert_eq!(said(due), vec![("other.example".to_owned(), 0), (SITE.to_owned(), 0)]);
        // A second session with a site already told, and events that are
        // not about sites: nothing.
        assert!(binding
            .observe(&transport::WalletEvent::SessionCreated(session("s3", SITE)))
            .is_empty());
        assert!(binding
            .observe(&transport::WalletEvent::SessionRemoved {
                session_id: "s3".to_owned()
            })
            .is_empty());
        assert!(binding.observe(&transport::WalletEvent::Connected).is_empty());
        // A site connected for the first time is told at once.
        let due = binding.observe(&transport::WalletEvent::SessionCreated(session("s4", "new.example")));
        assert_eq!(said(due), vec![("new.example".to_owned(), 0)]);

        // A registration changes what the site is told, and only that site.
        let (_, due) = answer(&binding, "r1", true, lender_facts(), &OneFill::new(false));
        assert_eq!(said(due), vec![(SITE.to_owned(), 1)]);
        // Logged in again: the connect core says it all again by itself, so
        // nothing is handed over twice.
        let due = binding.observe(&transport::WalletEvent::Sessions(vec![
            session("s1", SITE),
            session("s2", "other.example"),
            session("s4", "new.example"),
        ]));
        assert!(due.is_empty());
    }
}
