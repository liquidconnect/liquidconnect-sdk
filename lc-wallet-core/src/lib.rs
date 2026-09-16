//! # lc-wallet-core — the Liquid Connect wallet SDK
//!
//! Everything a wallet needs to become a Liquid Connect wallet:
//!
//! - [`wire`] — the wallet-side wire protocol (JSON over WebSocket),
//!   with the frame shapes pinned by tests.
//! - [`key`] — the wallet's Connect identity: an x-only key derived from
//!   the master blinding key and a network salt; challenge-login signing.
//! - [`link`] — QR payload / app-link parsing (`liquidconnect://…`).
//! - [`venue`] — Rolling Future venue digests (rf/order/v1 etc.) and
//!   wallet-key signing of them.
//! - [`core`] — the sans-io session state machine: inputs in, effects
//!   out, no sockets or clocks. Bring your own transport, or:
//! - [`transport`] *(feature `transport`, default on)* — a tokio driver
//!   with reconnect, keepalive, and an event stream to render.
//! - [`approval`] — a sign request's PSET as structure to render,
//!   honest about what is confidential.
//! - [`contracts`] — wallet-held covenant positions: records derived
//!   from the wallet's own typed fund approvals, the encrypted note that
//!   makes them recoverable from the seed, and their rendering.
//! - [`lending`] — Swaption lending: typed `sw/lend/*` fund claims
//!   checked against the template rows the wallet can read itself.
//!
//! What is deliberately absent: key custody and transaction signing.
//! The wallet signs with its own machinery after its own verification;
//! this crate only carries requests and results.
//!
//! Portions vendored from [`sideswap-io/sideswap_rust`] (MIT) — see
//! NOTICE.md.
//!
//! [`sideswap-io/sideswap_rust`]: https://github.com/sideswap-io/sideswap_rust

pub mod approval;
pub mod contracts;
pub mod core;
pub mod identity;
pub mod key;
pub mod lending;
pub mod link;
pub mod payjoin;
pub mod short_id;
pub mod venue;
#[cfg(feature = "transport")]
pub mod transport;
pub mod wire;
