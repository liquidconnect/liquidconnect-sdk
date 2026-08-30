# Orientation — for a developer joining the SDK

Read `README.md` first for the five-minute tour and the crate layout.
This note is what the README does not say: where the code came from, the
invariants that are easy to break from one side, what is already proven
live, and where the open edges are. Current as of 2026-08-28.

## Where this came from, and the one rule

The SDK was extracted from the SideSwap wallet's own Connect code
(`sideswap_rust`, MIT — see `NOTICE.md`), reshaped into a library any
Liquid wallet can embed. History is preserved so a PR upstream remains
possible; until then the repo is private and standalone.

The one rule everything else follows from: **the SDK never holds keys,
never signs, never approves**. It renders, verifies shape, and carries
messages. The host wallet signs with its own machinery after its own
verification. If a change would give the SDK a signing path, it is the
wrong change.

## The identity key — and the trap on both its sides

`key::WalletKey` derives the wallet's identity from the master blinding
key plus a per-network salt: nothing new to back up, different identity
per network. The x-only public key **is** the identity — for Connect
logins and for the identity API alike, which is why a key-proved
identity and a login-bound one land on the same server-side record.

Cross-repo pinned invariants — the SDK is now one side of pins in
**three** repos (`agentic-wallet-server` for identity,
`rolling-future` for the venue digests). The rule is always the same:
**never change one side alone.**

- `sign_identity` signs a tagged digest over challenge + action + value.
  The digest test vector (`aa28e11b…`) lives in
  `lc-wallet-core/src/key.rs` here and `wallet_server/src/identity_api.rs`
  there. **Never change one side alone.**
- When comparing hashes in tests, compare **bytes**
  (`to_byte_array`/`Message::as_ref`), not `Display` — hash newtypes may
  render byte-reversed and the strings will lie to you.
- `venue` builds the Rolling Future covenant digests (`rf/*`) from typed
  fields and signs them with `WalletKey::sign_digest`; the vectors are
  pinned identically in `rolling-future/server`. External services keep
  arriving as consumers of this signing surface — TetherSwap intends to
  verify LC-produced signatures **server-side** (pipe-closure signatures
  on Liquid destination addresses), so keep digest building and signing
  language-neutral and never assume the verifier is a mobile app.

## The identity client, in one paragraph

`identity::IdentityClient` is base-relative: direct against a wallet
server it is `http://127.0.0.1:3129/v1/identity`; through the public
gateway it is `https://test.liquidconnect.io/api/identity` (plus the
gateway bearer — transport gating only; the wallet-key signature inside
each request is the real authentication). Every call fetches a
single-use challenge and signs it together with the action and its
primary value; replay is refused by the server and there is a test that
proves it. Email verification is free. Phone is paid (0.5 USDT) and the
fee rides the wallet's own rail as an ordinary SignRequest the user
approves on device — the client never sees payment terms in a request
field, and a server-side test forbids them. Contacts: discovery is by
keyed hash (the server matches and discards, it does not store your
address book), a one-sided save is invisible to the other party, and a
payment address resolves only through a mutual edge.

## What is already proven live (so trust it, don't re-derive it)

- Wallet core against the production testnet Connect server
  (`agentic-dev.sideswap.io`) — `headless-wallet` example.
- Payjoin protocol client against the live service — `payjoin-probe`.
- The identity email tier end to end against the production wallet
  server (2026-08-28): fresh key → registered → real mail → typed code →
  verified anchor. The `email-e2e` example is that run; it takes a seed
  so two invocations share one key while you wait for the mail.
- `identity-probe` drives the protocol and, deliberately, the refusal
  paths — run it against a throwaway server instance, not production.

## Day-to-day

- `cargo test` — 16 tests. The wire shapes (Connect frames, payjoin
  envelope) are pinned because they are someone else's server: treat a
  failing pin as "the world changed", not "loosen the test".
- FFI: `lc-wallet-ffi` is the uniffi surface (`LiquidConnectWallet`,
  `WalletEventListener`, `summarizePset`, `IdentityService`). Everything
  crossing the boundary is strings, integers, records and enums — keep
  it that way. Generated Kotlin/Swift bindings are **committed** under
  `bindings/` so the host API is reviewable without a Rust toolchain;
  regenerate with the commands in `bindings/README.md`, never hand-edit.
- `approval::summarize_pset` is honest about confidential fields: when
  `fully_explicit` is false, the host wallet's own decode must fill the
  gaps before a person is asked to approve. Never render partial sums as
  totals.

## Consuming this from Flutter (the SideSwap way)

SideSwap projects are Flutter over a Rust core (`sideswap_client`:
cdylib + allo-isolate posting messages into Dart). For those projects
**do not reach for the Kotlin/Swift bindings at all** — consume this SDK
as a plain Rust crate inside that existing core: add `lc-wallet-core`
to the workspace, drive it from the worker, and let its events ride the
allo-isolate channel the app already has. The uniffi bindings exist for
third-party wallets with no Rust core of their own; a pure-Dart
binding (flutter_rust_bridge) is deliberately deferred until a
Rust-less Flutter wallet actually asks for it.

## Open edges (good first work)

- Wire `lc-wallet-core` (transport + identity) into a Flutter app's
  Rust core along the path above — the first real host integration and
  the identity module's first proof from an app.
- Per-platform binding binaries for the third-party story: `cargo-ndk`
  for Android ABIs, an XCFramework for iOS — CI work, since the dev
  host has neither NDK nor Xcode. `bindings/README.md` sketches the
  shape.
- The server counterpart lives in `sideswap-io/agentic-wallet-server`;
  the public gateway pages in `sideswap-io/liquidconnect-web`. Ask for
  access if your work touches either.
