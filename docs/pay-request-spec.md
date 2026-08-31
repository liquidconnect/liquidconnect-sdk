# Liquid Connect "pay request" — design spec

Status: SPEC, not built. Scott's direction 2026-08-31. This is the
primitive that lets a relying party ask a connected wallet to pay an
address, with the wallet building the transaction. It closes the
"deposit from the app wallet" gap (paper.swaption.io) and generalises to
any RP checkout/commerce flow.

## The problem it solves

Two existing Liquid Connect requests move value:

- `StartSign` — the RP hands over a finished PSET; the wallet signs it.
- `StartSignMessage` — the wallet signs a 32-byte digest (typed venue
  orders ride this).

Neither lets an RP say "pay this address N of this asset from the
connected wallet." `StartSign` can't, because **only the wallet holds
the two things needed to build a Liquid spend: the private keys and the
UTXO blinding factors.** The RP, the browser, and the connect server
have neither. The wallet-server has the descriptor (it can unblind) but
no spend keys, and building spends there would break its deliberate
"never constructs a spend" boundary. So the RP cannot build the PSET,
and the deposit button on paper.swaption.io currently does nothing
useful (deposit-prepare needs a coin already at a staging address).

## The primitive: PayRequest

The RP sends an **intent**, not a transaction:

    { recipient: <address>, asset_id: <hex>, amount: <u64>, memo: <text> }

The **wallet** builds the PSET from its own UTXOs, blinds it, renders
the real send (recipient, amount, network fee) for the user to approve,
signs, and **broadcasts** it, returning the txid. The RP watches the
chain for the resulting UTXO (for a deposit, at its staging address).

Deposit-from-wallet is just this with `recipient` = the venue's staging
address. It is not special-cased.

### Why the wallet builds (and broadcasts)

- Privacy/correctness: only the wallet can build a confidential spend
  from its own coins. Nothing else sees blinding factors.
- Clear-signing: the wallet shows the *actual* send it constructed —
  recipient, amount, fee — not something the RP asserted. The RP's
  intent is advisory; the wallet renders the truth and the user approves
  that. (Amount-confirmation discipline applies: the wallet displays the
  amount it will send; the user is approving that number.)
- Broadcast by the payer: the wallet is the spender, so it broadcasts
  and hands back a txid, exactly like the app's normal send flow. (An
  alternative — return the signed PSET for the RP to broadcast — is
  possible but pointless here and leaks the signed tx to the RP early;
  default to wallet-broadcasts, txid back.)

### The SDK does NOT build the transaction

`lc-wallet-core`'s invariant stands: it never builds transactions or
holds keys; signing and construction are the host wallet's. So the SDK
adds the **plumbing** (a PayRequest message: transport in, a rendered
event out, a host-supplied-result accept path) and the **host wallet
builds it**. This is exactly the shape of the sign-message flow already
shipped (`Input::SignMessageSigned` carries a host-produced result); the
pay flow's accept carries a host-produced **txid** (or signed PSET).

For the SideSwap app, the host build is the existing send machinery
(`sideswap_client` `build_asset_send` / `create_tx` / the send worker) —
proven code, wired to a new request source. A third-party SDK wallet
plugs in its own builder.

## What each layer needs (build checklist)

### 1. SDK `lc-wallet-core`
- `wire.rs`: `PayRequest { request_id, domain, recipient, asset_id,
  amount, memo, ttl }`; `UserAction::AcceptPayRequest { request_id,
  txid }` (or `signed_pset`) + `CancelPayRequest`; `PayRequestCreated/
  Removed` notifs; `LoginResp.pay_requests` (serde-defaulted). Pin the
  frames to fixtures shared with the app's `connect_api.rs` (the
  cross-crate byte-for-byte pin rule).
- `core.rs`: store pay requests; `Input::PayBuilt { request_id, txid }`
  (host supplies the result of building+broadcasting) → emit the accept
  action; `Input::PayRejected`. New `Effect::AddPayRequest/RemovePayRequest`.
- `transport.rs` + FFI: surface `WalletEvent::PayRequested(..)` and
  `accept_pay(request_id, txid)` / `reject_pay`.
- Approval-safety: none needed beyond rendering the intent — the *host*
  builds and re-renders the real PSET via `approval::summarize_pset`
  before asking. Optionally add a helper that checks the built PSET pays
  `recipient` the stated `amount` of `asset_id` and flags any mismatch.

### 2. `swaption_be` `connect_server` + `rp_api`
- Relay the pay request RP → wallet, like `StartSignMessage`: `rp_api`
  `StartPay`/`PayRequest(Status)`/`CancelPayRequest`; `connect_server`
  state machine validates the intent shape (address, asset hex, amount)
  and relays opaquely; result status carries the txid.

### 3. `agentic-wallet-server`
- Relay route `/v1/connect/pay/{start,status}` mirroring the
  sign-message relay (bearer-authed, non-spending — it only carries the
  intent and reports the txid; the *wallet* spends). `start` takes
  `{wallet_id, recipient, asset_id, amount, memo, ttl}`, `status`
  returns `pending|paid{txid}|denied|failed`. Update the route-count and
  no-spend guard tests (the relay carries an intent, still never builds
  or signs).

### 4. App `sideswap_client`
- Wire `PayRequested` to the send flow: build the send to `recipient`
  for `amount`/`asset_id` via `build_asset_send`, render a pay dialog
  (recipient, amount, fee — reuse the sign-request PSET summary UI),
  on approve sign + broadcast, feed the txid back via `Input::PayBuilt`.
- Hardware wallets: build unsigned, sign in-signer, broadcast — same as
  any send.

### 5. Venue `rolling-future`
- Deposit button → RP `POST /api/deposit/start` → wallet-server
  `/v1/connect/pay/start` with `recipient` = the account's staging
  address, `asset_id`/`amount` from the user; poll status for the txid;
  ingest via deposit-prepare/covenant. (Owned by the venue session.)

## Open questions for Pavel (it's a new LC primitive)

- Wire naming and shape: `StartPay`/`PayRequest` vs a more general
  `SendRequest`; whether it's a new capability or rides the existing
  relay surface.
- Broadcast-by-wallet (txid back) vs return-signed-PSET — this spec
  recommends wallet-broadcasts.
- ELIP-36 alignment (the wire-format track) so this doesn't need
  reworking later.
- Whether the intent should carry an optional `client_data`/order-binding
  so a deposit can be tied to a venue account without a second call.

## Scope estimate

Comparable to the sign-message build (which is done and live): a wire +
core + FFI addition in the SDK, a relay in swaption_be, a relay route in
the wallet-server, the app send-flow wiring + a dialog, and the venue's
deposit button. Do it as one coordinated pass, cross-crate frame pins
included, on private repos only until Pavel merges (repo rule).
