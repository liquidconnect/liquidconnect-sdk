# Liquid Connect "fund request" (fund-this-template) — design spec

Status: ALL FIVE LAYERS BUILT 2026-08-31, same evening as Scott's go.
SDK wire/core/transport/FFI + `approval::verify_fund_template` (this
repo `dc66fb3`, 36 tests); connect-server relay (`swaption_be`
`rf-pay-request-deploy` `d9d2656`, deployed to the testnet rf-connect);
wallet-server `/v1/connect/fund/{start,status}`
(`liquidconnect-server` `0f7cd42`, compose 0.13.0 — LIVE at the next
sudo install, the one remaining gate); app funding engine
(`rf-sideswap_rust` lc-sdk `49e125d` `fund_pset`/`try_fund_template`,
`rf-sideswapclient` `ba86f43` deposit dialog); venue
`deposit-template`/`deposit-finish` + `/api/deposit/template` +
`fund-status` (`rolling-future` `232de37`, deployed —
falls back to pay-request until the wallet server carries the fund
relay). Successor to and
generalisation of the staging-address deposit;
`docs/pay-request-spec.md` is the direct predecessor and this follows
its conventions. Private repos only until Pavel merges (repo rule).

Resolved at design time (driver-side reconnaissance of
`rolling-future`): the covenant witness is transaction-independent
(leaf/root/amount only) and the covenant input carries no signature at
all — its validity is program execution — so the covenant half is fully
buildable before any funding exists and attachable after, and the
wallet's SIGHASH_ALL cannot be invalidated by it. The DRIVER pays the
network fee from its own L-BTC (the wallet may hold none); the wallet's
change is CONFIDENTIAL (its coins are confidential; the change absorbs
the blinding-factor sum) while every TEMPLATE row stays explicit —
`v5/deposit.simf` inspects only input 0 and output 0. Crediting keys on
`request_id` (double-submit guard) plus the final txid (re-approval
guard), and the venue broadcasts synchronously at finish before
journaling — which also retires today's prepare/submit races (the
seq-9275 class and the driver fee-UTXO substitution hatch).

This is the primitive that lets a relying party hand a connected wallet
a **partially-built transaction template** and ask the wallet to FUND
it: add its own confidential inputs and blinded change, sign only its
own inputs, and return the funded PSET for the RP to complete and
broadcast. It collapses the venue's two-step deposit (pay to a staging
address, then deposit the staged coin) into **one on-chain transaction
with no staging address**, and generalises to any flow where the RP
must construct part of the transaction (covenant transitions, swaps,
issuances) and the wallet must pay into it.

## Why the staging address existed, and why it can go

The covenant deposit program (`rolling-future` `v5/deposit.simf`)
imposes **no constraint on the funding input** — its own header says
"no authorisation"; it checks only the leaf update against the merkle
root and output 0 being the new pool at `pool + amount`, same asset.
The staging hop was plumbing: an explicit coin at the account's own key
was something the driver could see on esplora, attribute, and spend
without collaborative construction. None of that is protocol.

What direct funding actually requires is collaboration over blinding:
the RP cannot see the wallet's UTXOs or blinding factors; the wallet
cannot build the covenant half (it has neither the pool state nor the
program witness). So each side builds exactly the half only it can
build. Elements makes the merge sound: a transaction may spend
confidential inputs into explicit outputs as long as one confidential
output absorbs the blinding-factor sum — which is precisely the
wallet's change.

## The primitive: FundRequest

The RP sends a **template plus its claim about it**:

    { template: <PSET, base64>, asset_id: <hex>, amount: <u64>,
      memo: <text>, client_data: <opaque>, ttl_ms }

The **wallet** verifies the claim arithmetically, funds the template
from its own coins, clear-shows the deposit, signs only its own inputs,
and returns the funded PSET. The **RP** completes its own input(s)
(e.g. attaches the covenant witness) and broadcasts. Status reports the
txid.

### The wallet's safety rules (normative — the heart of the design)

1. **Explicit template only.** Every input and output already in the
   template MUST be explicit (unblinded asset and amount). Anything
   confidential in the template is unverifiable and is refused.
2. **The stated amount is arithmetic, not advisory.** The wallet
   recomputes the template's per-asset deficit:
   `sum(outputs) − sum(inputs)` for `asset_id` MUST equal `amount`
   exactly. For every other asset (including L-BTC and the explicit fee
   output) the deficit MUST be ≤ 0 — the template pays its own fee.
   Mismatch ⇒ refuse. The user approves a number the wallet computed,
   never one the RP asserted.
3. **The wallet contributes only `asset_id`.** It adds confidential
   inputs totalling ≥ `amount` and **exactly one confidential change
   output** to a fresh address of its own for the surplus. Change MUST
   be present (it absorbs the blinding-factor sum); coin selection adds
   a further coin rather than produce zero change.
4. **SIGHASH_ALL.** The wallet signs its inputs committing to all
   inputs and outputs. After approval nothing about the transaction can
   change; the RP can only attach witness data to its own inputs.
   Bounded exposure: whatever the rest of the template does, the
   wallet's net outflow is exactly `amount` of `asset_id`.
5. **Clear display.** The dialog renders the wallet's own arithmetic —
   "Deposit {amount} {asset} into {domain}" + memo + "change returns to
   this wallet" — in the style of the typed venue clear-signing: the
   wallet refuses rather than display a claim it cannot rebuild.

### Why the RP broadcasts (unlike pay-request)

The wallet cannot broadcast: the template's own inputs (the covenant)
are unsatisfied until the RP attaches their witness, which may only be
computable against live venue state. So the funded PSET goes back, the
RP finalises and broadcasts, and the status carries the txid. The
wallet's signatures make the returned PSET useless for anything except
exactly the approved transaction.

### Failure and the moving covenant

The template binds venue state that can move while a human approves
(a fill advances the pool root). On return the RP MUST re-verify its
half before finalising and fail closed — status `failed { reason }` —
and MAY immediately offer a fresh template (a fresh consent; never
reuse the old approval). The wallet-side TTL bounds the human window;
the RP-side re-check bounds the race. A returned-but-stale funded PSET
is discarded — the wallet's coins are unspent and unlocked, nothing
needs recovery.

## What each layer needs (build checklist)

### 1. SDK `lc-wallet-core`
- `wire.rs`: `FundRequest { request_id, domain, template, asset_id,
  amount, memo, ttl }`; `UserAction::AcceptFundRequest { request_id,
  pset }` + `CancelFundRequest`; created/removed notifs;
  `LoginResp.fund_requests` (serde-defaulted). Frames pinned to
  fixtures shared with the app's `connect_api.rs` (cross-crate
  byte-for-byte rule).
- `core.rs`: store fund requests; `Input::FundSigned { request_id,
  pset }` (host supplies the funded PSET) → accept action;
  `Input::FundRejected`. `Effect::AddFundRequest/RemoveFundRequest`.
- A **verification helper** hosts share: parse the template, enforce
  rules 1–2 above, and return the computed deficit — so every host
  wallet gets the arithmetic check for free even though construction
  stays host-side. (The SDK still builds nothing and holds no keys.)
- `transport.rs` + FFI mirror of the pay surface.

### 2. `liquidconnect-server` `connect/connect_server` + `connect/rp_api`
(imported from `sideswap-io/swaption_be` `rf-pay-request-deploy`)
- `StartFund` / `FundRequestStatus` / `CancelFundRequest`, relayed
  opaquely like `StartPay`; size cap sized for a realistic template
  (covenant deposit PSET is kilobytes — cap generously and test the
  largest real template against the cap; MAX_DESCRIPTION taught us).
- Deploy branch off `rf-pay-request-deploy`, never main.

### 3. `liquidconnect-server`
- `/v1/connect/fund/{start,status}` mirroring the pay relay: bearer-
  authed, non-spending, carries the template in and the funded PSET /
  txid out, `client_data` echoed on every status. Status vocabulary
  `pending | funded { pset } | denied | timeout | failed | unknown`.
  Route-count and no-spend guard tests updated (the relay still never
  builds, signs, or broadcasts).

### 4. App `sideswap_client`
- On `FundRequest` arrival: run the SDK verification helper, select
  coins, derive the change address, and pre-build the funding so the
  dialog shows real numbers (`SignerRequest.Fund` proto: domain, asset,
  amount, memo). On approve: blind, sign own inputs, feed
  `Input::FundSigned`. This reuses the send machinery's selection/
  blinding/signing pieces against a template instead of a fresh tx —
  the one genuinely new construction path in the whole build.
- Hardware wallets: unsigned funding first, sign in-signer, return.

### 5. Venue `rolling-future`
- Driver mode `deposit-template <ownerPk> <amount>`: build the covenant
  half — pool input, driver L-BTC fee input, new-pool output, fee
  output — as an unsigned PSET, no user coin, no user change.
- `/api/deposit/start` prefers fund-template when the wallet-server
  answers the fund route; falls back to pay-request, then manual (the
  staging address remains the wallet-agnostic fallback for external
  wallets and faucets).
- On `funded`: re-verify state, attach covenant witness, broadcast,
  credit on the request's `client_data` + txid (dedup by request, not
  funding outpoint — the outpoint is the wallet's and unknown until
  funded).

## Open questions for Pavel

- Naming and generality: `StartFund` as specified, or fold pay and fund
  into one request with an optional template (this spec keeps them
  separate: pay's contract is "wallet builds everything", fund's is
  "wallet completes exactly this"; merging blurs both).
- ELIP-36 alignment for the template encoding.
- Whether the verification helper's rules 1–2 should become a stated
  LC-wide invariant for any future template-carrying request.

## Scope estimate

One coordinated pass like sign-message/pay-request for four of the five
layers (wire + relay + route + venue). The app's template-funding
construction is the lump — new code against the wallet's blinding
internals — and is why this spec pins the safety rules tightly enough
that the construction can be reviewed against them line by line.
