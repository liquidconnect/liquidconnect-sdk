# Liquid Connect "asset balance" request — design spec

Status: BUILT across all five layers 2026-09-02 on Scott's direction
("fix so that they see the correct wallet balance at all times, not
just 0"). Successor in convention to `receive-address-spec.md`; this
follows its layering exactly. Private repos only until Pavel merges
(repo rule).

## The problem, precisely

paper.swaption.io shows a row "USDT in your wallet" — what the user
could still send over. Until now the venue read it from the payment
service's per-wallet UTXO list, which knows coins only for wallets that
**paired** (handed over a watch-only descriptor). Two failure shapes
followed, and Scott hit both:

- an unpaired wallet with no wallet-server session rendered "—";
- an unpaired wallet that DID hold a wallet-server session (a login
  relayed through it) rendered **0.00**, because the UTXO report lists
  the wallet with an empty coin list — "unknown" was indistinguishable
  from "holds nothing".

Deposits and withdrawals stopped needing the pairing on 2026-09-01
(fund-template + receive-address). The balance row was the last read
that still did, and a number that is wrong is worse than a dash.

## What is actually needed

One integer: the wallet's confirmed balance of ONE named asset, now.
Not the descriptor, not other assets, not history, not addresses.

## The request

Symmetric with `StartReceiveAddress`, carried on the same socket.

RP → connect server:

```rust
pub struct StartAssetBalanceReq {
    pub session_id: String,
    pub description: Option<String>,
    /// Liquid asset id, 64 hex chars. ONE asset per request.
    pub asset_id: String,
    pub client_data: Option<String>,
    pub ttl: DurationMs,
}
```

Wallet → connect server (a `UserAction`):

```rust
AcceptAssetBalanceRequest { request_id: String, amount: u64 },
CancelAssetBalanceRequest { request_id: String },
```

The RP reads the answer from the request's terminal status
(`Succeed { amount }`), the same way it reads an address today.

## Decisions

**1. Confirmed coins, base units, one asset.** The wallet sums its own
UTXO set for the named asset. Unconfirmed change is excluded because
the RP shows what could be sent over *now*; the venue's deposit path
needs a confirmed coin anyway. A wallet that holds none of the asset
answers `0` — that is a fact, and refusing instead would say the same
thing more slowly.

**2. No dialog.** The user consented to the session at login, the
disclosure is bounded to the asset the RP trades, and the row is
refreshed on a timer — a tap per refresh would be absurd and a tap once
would teach people to tap through. The login consent text names it.

**3. No FCM wakeup.** This is the one deliberate departure from
receive-address. A balance row polls; waking a phone from deep sleep
once a minute for a courtesy number is wrong. If the wallet's socket is
not live the request simply times out and the RP shows its last known
value, marked as such. Pushes remain for things that need the person.

**4. The wallet may refuse**, and an older app will not recognise the
request. Both are the same case to the RP: no number.

**5. No proof.** A wallet could lie. The only thing an RP can do with
the number is ask the wallet to pay, which the user approves on the
real constructed transaction. Nobody should add a signature here.

**6. Which coins.** The app answers from its main (native segwit)
account, the account the fund-template deposit spends from — so the
number is exactly what the Deposit button can move. AMP coins are not
counted; they could not be deposited from that flow anyway.

## Privacy, stated as a comparison

| | descriptor pairing | this request |
|---|---|---|
| RP learns | every address, balance, txn, forever | one asset's balance, while logged in |
| Duration | permanent | that session |
| Revocable | unpair | disconnect |
| Needed for the row | yes | no — login is enough |

## RP-side rules

- **Coalesce.** The venue caches an answer for a few seconds so a page
  that double-polls does not double-ask, and keeps the last good number
  per wallet to serve when a request fails — flagged `stale` with its
  timestamp so the page can say so.
- **Short TTL.** 15 s. A balance request that nobody answered in 15 s is
  worthless; do not leave it queued for a phone that wakes later.
- **Never read the descriptor path for an unpaired wallet.** The legacy
  UTXO read is consulted only for a wallet the payment service actually
  lists as paired (it has a `recv_address`); a session without a
  descriptor produces the false zero this spec exists to kill.

## Layers

1. **SDK** (`lc-wallet-core`): wire types, the two `UserAction`s, core
   handling and effect, FFI event. Mirrors receive-address.
2. **Connect server** (`liquidconnect-server` `connect/rp_api` + relay): `Req`/`Resp`/
   `Notif` variants and the relay path. Validates the asset id shape on
   the way in; the amount is a `u64` and needs no check. No FCM.
3. **Wallet server** (`liquidconnect-server`): `/v1/connect/asset-balance/
   {start,status}` for RPs on the relay path.
4. **App**: sum the main account's confirmed coins for the asset; answer
   silently; reject on any failure so the RP does not wait out the TTL.
5. **Venue** (`rolling-future`): `/api/wallet/balance` asks over LC (own
   socket, then relay), serves a short cache and a last-known value,
   and falls back to the UTXO read only for paired wallets.
