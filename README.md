# liquidconnect-sdk

The wallet-side SDK for [Liquid Connect](https://test.liquidconnect.io): everything a Liquid wallet needs to let its users connect to Liquid Connect applications — trading, payments, contract flows — while keys never leave the wallet.

Status: v0.1 — wallet core, Kotlin/Swift bindings (uniffi), and the optional identity module (verified email free; phone reachability 0.5 USDT, payable over Liquid itself with payjoin so a USDt-only wallet is never stranded). Joining the project? Read  after this page.

## What integrating gets your users

- Connect to any Liquid Connect application by scanning a QR or tapping a link.
- Approve logins and transaction signing on their own device — the wallet is the only party that can sign, and the Connect server never holds keys.
- (Coming with the identity module) be findable and payable by the contacts they choose: verified email or phone, hashed discovery, mutual-contact payments.

## The five-minute tour

```rust
use lc_wallet_core::key::{Network, WalletKey};
use lc_wallet_core::transport::{WalletConnect, WalletConnectConfig, WalletEvent};
use lc_wallet_core::{approval, wire};

// 1. The wallet's Connect identity, derived from key material you
//    already have — nothing new to back up.
let key = WalletKey::new(master_blinding_key, Network::Liquid);

// 2. Connect. Reconnection, keepalive, and challenge-login are handled.
let (wallet, mut events) = WalletConnect::spawn(WalletConnectConfig {
    url: wire::MAINNET_URL.to_owned(),
    descriptor: wallet_descriptor,   // shared with the Connect server on approval, never with applications
    key,
    install_id,                      // persist InstallId::random() once
});

// 3. A scanned QR / tapped link claims the pending request.
wallet.open_link(&scanned_text)?;

// 4. Render requests from the event stream; approvals are explicit.
while let Some(event) = events.recv().await {
    match event {
        WalletEvent::LoginRequested(req) => {
            // show req.domain, then:
            wallet.accept_login(&req.request_id);
        }
        WalletEvent::SignRequested(req) => {
            // What am I being asked to sign?
            let summary = approval::summarize_pset(&req.pset, Network::Liquid)?;
            // Render summary; verify with your own decode; sign with your
            // own signer; then deliver the result:
            wallet.accept_sign(&req.request_id, &signed_pset);
        }
        WalletEvent::SignMessageRequested(req) => {
            // No PSET: a service asks for a BIP340 signature over a
            // 32-byte digest by the wallet's Connect identity key. Show
            // req.domain and req.description; on accept the SDK signs
            // the digest it stored from the server's request — you never
            // pass bytes to sign.
            wallet.accept_sign_message(&req.request_id);
        }
        _ => {}
    }
}
```

Try it against the public testnet server without writing any code:

```
cargo run --example headless-wallet
```

then open https://test.liquidconnect.io, start a connection, and `link` the `request_id` it shows.

## Crate layout

| Module | What it is |
| --- | --- |
| `wire` | The wallet-side wire protocol, frame shapes pinned by tests |
| `key` | Connect identity key + challenge-login signing — mbk-derived, deliberately never spend-class; also signs `StartSignMessage` digests, but only through the session core's approval path |
| `link` | `liquidconnect://` / app-link parsing |
| `core` | Sans-io session state machine — bring your own transport if you have one |
| `transport` | Ready-made tokio transport (default feature) |
| `approval` | A sign request's PSET as structure to render, honest about confidential fields; payjoin-aware annotation |
| `payjoin` | Client for SideSwap's payjoin service: pay network fees in USDt, no L-BTC needed |
| `venue` | Rolling Future venue: the seed-derived money key (`VenueKey`, hardened path m/19523'/net'/0'), covenant-digest builders and typed signing (`rf/order/v1`, `rf/withdraw/v1`, `rf/login/v1`), and the spend surface for its raw-key P2TR (deposits spend what withdrawals pay) - vectors pinned against the venue server |

## Flutter

A Flutter app with a Rust core (the SideSwap pattern) consumes this SDK
as a plain crate: link `lc-wallet-core` into that core and let events
ride your existing Dart bridge. The bindings below are for wallets
without a Rust core; a flutter_rust_bridge package is available on
demand.

## Kotlin and Swift

`lc-wallet-ffi` is the uniffi surface over the core — `LiquidConnectWallet`,
`WalletEventListener`, `summarizePset` — with generated bindings committed
under `bindings/` so the host-language API is reviewable as-is. See
`bindings/README.md` for linking instructions and regeneration.

Probe the live payjoin service (an unfinished order expires harmlessly):

```
cargo run --example payjoin-probe
```

## What this SDK will never do

Hold your wallet's keys, sign transactions, or approve anything. The wallet signs with its own machinery after its own verification. Two narrow, deliberate exceptions, each a dedicated key the SDK derives itself. The Connect identity key (`key::WalletKey`, mbk-derived, view-tier — never money) signs logins, identity calls, and — through the session core's approval path only — `StartSignMessage` digests: the core signs the digest it stored from a live server request after the host's explicit accept, and there is no entry point through which a host can hand this key arbitrary bytes. The venue money key (`venue::VenueKey`, seed-derived on its own hardened path) signs typed `rf/*` digests the SDK builds itself, and key-path-spends PSET inputs paying its own raw P2TR — spend-class by design, so the host renders and verifies the transaction before asking; a digest offered from outside can still never reach it as "a message". Wallets with hardware-custodied seeds skip `VenueKey` and sign the public digest builders' output in their own signer. `approval::summarize_pset` reports exactly what is explicit in a PSET and marks everything else `confidential` — when `fully_explicit` is false, your own decode must fill the gaps before a person is asked to approve.

## Protocol references

- Spec: [`sideswap_rust/docs/connect.md`](https://github.com/sideswap-io/sideswap_rust/blob/main/docs/connect.md)
- Wire types upstream: `sideswap_api/src/connect_api.rs`

Portions of this SDK are vendored from [sideswap_rust](https://github.com/sideswap-io/sideswap_rust) (MIT) — see `NOTICE.md`.
