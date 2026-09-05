# Liquid Connect "held balances" report — design spec

Status: SDK layer BUILT 2026-09-05 on Scott's direction ("go with the
Liquid Connect route" for showing the Rolling Future margin account in
the SideSwap app). The other layers follow the ordering in
`asset-balance-spec.md` and are listed at the end with their state.

## The problem, precisely

A person's Rolling Future margin — the USDt they deposited and the BTC
position it carries — lives in the account's leaf inside the venue's
covenant pool. The wallet cannot read it from the chain: the leaf sits
inside a blinded pool output and its state is a journal the venue
mirrors. So the app can only show it if the venue says it, and today it
does not: the person opens paper.swaption.io to learn what they hold
there. The same is true of a lending position or a prediction-market
stake. "Can the margin wallet be shown in the SideSwap app?" — only with
a channel from the relying party to the wallet.

Two routes were weighed. The app could log in to each venue over the SDK
with the venue key it already derives and read the venue's own API; that
works today for Rolling Future and puts venue-specific code in the app
for every venue that follows. Or the Connect protocol gains one
message in the direction it did not have yet — relying party TO wallet,
unprompted, a statement rather than a request — and every RP that holds
something for a wallet uses it. Scott chose the second.

## What is actually needed

A short list of labelled integers per relying party, restated whenever
they change, with the time they were computed. Nothing to approve and
nothing to sign: the person consented to the session at login, and this
only tells them what the site already knows about their own account.

## The report

Carried on the RP's existing server socket and on the wallet's existing
client socket. No request id, no TTL, no user action.

RP → connect server (`rp_api`):

```rust
ServerAction::ReportHoldings {
    wallet_id: XOnlyPublicKey,       // whose account
    holdings: Vec<Holding>,          // empty = clear my entry
    as_of: TimestampMs,              // when the RP computed them
}
```

Connect server → wallet (`connect_api` / SDK `wire`):

```rust
pub struct Holding {
    pub label: String,          // "Margin balance", "Position" — shown as given
    pub kind: String,           // "balance" | "position" | "collateral" | "credit" | …
    pub asset_id: Option<String>,   // a Liquid asset when there is one
    pub unit: String,           // "USDt", "BTC"
    pub amount: i64,            // base units, signed: a short is negative
    pub precision: u8,          // 8 for sats-style units
}
pub struct HoldingsReport { pub domain: String, pub holdings: Vec<Holding>, pub as_of: i64 }
Notif::HoldingsUpdated { report }     // set / replace the domain's entry
Notif::HoldingsRemoved { domain }     // clear it
LoginResp.holdings: Vec<HoldingsReport>   // every domain's last report, at login
```

The domain is the connect server's word, from the RP's verified login —
never a field the RP fills in.

## Decisions

1. **A statement, not a request.** Nothing waits on the wallet; there is
   no TTL, no accept, no reject, no FCM. A phone that is asleep learns
   the figures at its next login from `LoginResp.holdings`.
2. **Replace, never merge.** Each report is the RP's complete view for
   that wallet. The connect server keeps ONE record per (domain, wallet)
   and overwrites it; an empty list deletes it and the wallet is told
   `HoldingsRemoved`. A wallet never has to reconcile two reports.
3. **Signed integers in base units, with the precision stated.** A short
   position is a negative amount. The wallet formats; it never computes
   anything from these numbers.
4. **`kind` is a hint, `label` is the text.** The wallet may group or
   icon by kind; an unknown kind renders as text. The RP's label is shown
   as given and never parsed.
5. **`as_of` is the RP's clock.** The wallet shows the age ("2 min ago")
   so a stale venue is visible as stale, not wrong.
6. **No proof.** These are the RP's claim about its own books. A wallet
   that wants more can, for a covenant venue, check the account journal
   root on chain later — out of scope here. The number is never an input
   to a signature: the only thing a wallet does with it is display it.
7. **Login carries the snapshot and is authoritative.** A relogin whose
   `holdings` omits a domain clears that domain in the core; the host
   redraws from the events. A connect server that predates holdings
   omits the field entirely and login still parses.
8. **Rate.** An RP reports on change, and at most once per few seconds
   per wallet; the connect server may drop reports above that. A venue
   whose figures move every tick (mark-to-market) reports the settled
   figures it would show on its own page, not every tick.

## Privacy, stated as a comparison

The RP already holds these figures and shows them to the same person on
its own page after the same login. Sending them to the wallet adds one
copy, in the connect server's store, keyed by wallet id and domain, for
as long as the RP keeps reporting — the same store that already holds
the RP's sessions for that wallet. Nothing new is learned by anyone.

## RP-side rules

- Report after every event that changes the figures: deposit,
  withdrawal, fill, roll, delegation. Batch within a few seconds.
- Report ALL the lines each time — the entry is replaced.
- Report an empty list when the account closes or its balance and
  position both reach zero, so the wallet stops showing the RP.
- Use the same units and labels as your own page, so the person sees
  one truth in two places.

## Layers

| Layer | Repo | State |
|---|---|---|
| SDK (`lc-wallet-core` wire/core/transport, `lc-wallet-ffi`) | `liquidconnect/liquidconnect-sdk` | **built** 2026-09-05: `Holding`, `HoldingsReport`, `Notif::HoldingsUpdated/Removed`, `LoginResp.holdings`, `Effect::SetHoldings/ClearHoldings`, `WalletEvent::HoldingsUpdated/Removed`, FFI `HoldingsReportInfo`; wire + core tests |
| Connect server (`rp_api` action, `connect_api` notif, domain store, login snapshots) | `swaption_be` `connect_server` + `sideswap_rust` `connect_api` | next |
| Venue (report on change) | `rolling-future` | next |
| App (Rust event → Flutter, "Held at …" section) | `rf-sideswap_rust` / `rf-sideswapclient` `lc-sdk` | next |
| Wallet server (`liquidconnect-server`) | `liquidconnect/liquidconnect-server` | optional: expose `/v1/connect/holdings` for agent reads |
