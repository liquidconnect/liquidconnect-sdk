# liquidconnect-sdk

The wallet-side SDK for [Liquid Connect](https://test.liquidconnect.io): everything a Liquid wallet needs to let its users connect to Liquid Connect applications — trading, payments, contract flows — while keys never leave the wallet.

Status: v0.1, wallet core. Rust today; Kotlin/Swift bindings (uniffi) are the next milestone, followed by the optional identity module (verified email free; phone reachability 0.5 USDT, payable over Liquid itself with payjoin so a USDt-only wallet is never stranded).

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
| `key` | Connect identity key + challenge-login signing |
| `link` | `liquidconnect://` / app-link parsing |
| `core` | Sans-io session state machine — bring your own transport if you have one |
| `transport` | Ready-made tokio transport (default feature) |
| `approval` | A sign request's PSET as structure to render, honest about confidential fields; payjoin-aware annotation |
| `payjoin` | Client for SideSwap's payjoin service: pay network fees in USDt, no L-BTC needed |

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

Hold keys, sign transactions, or approve anything. The wallet signs with its own machinery after its own verification. `approval::summarize_pset` reports exactly what is explicit in a PSET and marks everything else `confidential` — when `fully_explicit` is false, your own decode must fill the gaps before a person is asked to approve.

## Protocol references

- Spec: [`sideswap_rust/docs/connect.md`](https://github.com/sideswap-io/sideswap_rust/blob/main/docs/connect.md)
- Wire types upstream: `sideswap_api/src/connect_api.rs`

Portions of this SDK are vendored from [sideswap_rust](https://github.com/sideswap-io/sideswap_rust) (MIT) — see `NOTICE.md`.
