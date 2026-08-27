# Notices

This repository vendors and adapts code from
[sideswap-io/sideswap_rust](https://github.com/sideswap-io/sideswap_rust),
licensed under the MIT license:

- `lc-wallet-core/src/wire.rs` — from `sideswap_api/src/connect_api.rs`
- `lc-wallet-core/src/key.rs` — from `sideswap_common/src/wallet_key.rs`
- `lc-wallet-core/src/link.rs` and `lc-wallet-core/src/core.rs` — from
  `sideswap_common/src/wallet_connect.rs`

Changes: types made self-contained (inlined `sideswap_types` helpers),
the state machine decoupled from that repo's transport, and tests added.
The wire format is unchanged and pinned by tests.
