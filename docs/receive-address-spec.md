# Liquid Connect "receive address" request — design spec

Status: DESIGN, not started. Written 2026-09-01 on Scott's direction,
after he hit the symptom: having logged in to paper.swaption.io, he
still had to enable payment requests before he could withdraw.
Successor in convention to `pay-request-spec.md` and
`fund-template-spec.md`; this follows their layering. Private repos
only until Pavel merges (repo rule).

Scott's framing, which is the design: *"we may not need to share the
full descriptor if the Liquid Connect service can offer the details
over its API."* Exactly right, and it is also why the descriptor route
was never made permanent — see "What this retires".

## The problem, precisely

A venue withdrawal is clear-signed. The claim the wallet renders and
rebuilds is

    {"kind":"rf/withdraw/v1","amt":"…","dest":"<address>","root":"…"}

so the digest COMMITS the destination and the user approves a named
address. That is the property worth keeping: the covenant enforces
payment to exactly the script the owner signed for.

But it means the RP must know **one address the user's wallet watches**.
Today it learns that in exactly one way — `payout_dest()` asks the
wallet server for `/v1/agent/wallets` and reads `recv_address` — and
that endpoint only knows wallets that have **paired with the payment
service**. Pairing is the consent that shares a watch-only
**descriptor**.

So login (identity + venue key, enough to trade) does not let you
withdraw, and the user is asked for a second, much larger consent to
get their own money out. That is the wrong shape: we are demanding the
whole wallet to answer "where do I send this one payout?".

## What is actually needed

One Liquid address, belonging to the logged-in wallet, that the wallet's
app watches. Nothing else. Not balances, not history, not future
addresses.

## The request

A new RP request, symmetric with `StartSignMessage` and `StartFund` and
carried on the same socket.

RP → connect server:

```rust
pub struct StartReceiveAddressReq {
    pub session_id: String,
    /// Why the RP wants it, shown if the wallet chooses to show it
    /// ("Rolling Future withdrawal"). Never trusted, never parsed.
    pub description: Option<String>,
    pub client_data: Option<String>,
    pub ttl: DurationMs,
}

pub struct StartReceiveAddressResp {
    pub receive_address_request: ReceiveAddressRequest,
}
```

Wallet → connect server (a `UserAction`, exactly as sign-message):

```rust
AcceptReceiveAddressRequest {
    request_id: String,
    /// One Liquid address, in the session's network.
    address: String,
},
CancelReceiveAddressRequest { request_id: String },
```

The RP reads the answer from the request's terminal status, the same
way it reads a signature today.

## Decisions

**1. A fresh, unused address per request.** Not a stable per-RP address.
The wallet already manages a gap limit, and reusing one address would
link every withdrawal a user ever makes into a single on-chain cluster —
which is most of what we are trying to avoid by not shipping the
descriptor. Consequence for RPs, and it is load-bearing: **the address
must not be cached across withdrawals.** `payout_dest`'s current
permanent per-account cache becomes per-withdrawal.

**2. No separate approval dialog.** The wallet answers from its own key
material and decides what to give; an address is not money and not a
secret. More importantly the very next step already shows the user that
exact address inside the withdraw claim, which they must approve. A
second dialog here would be a tap that teaches people to tap through,
which is how consent fatigue starts. It IS disclosed in the login
consent text ("this site can ask your wallet for an address to pay
you"), because a linkability handle is not nothing.

**3. The wallet may refuse**, and an older wallet simply will not
recognise the request. Both are the same case to the RP: no address.

**4. Network is checked wallet-side.** The address encodes its network;
the wallet must refuse when the session's network is not its own. This
is the same class as the wrong-network venue login already closed, and
the cheapest place to close it is where the address is minted.

**5. No proof of ownership, deliberately.** The RP does not need the
wallet to prove the address is its own: the wallet is the payee, so a
lie only costs the liar, and the user sees and approves the address in
the withdraw claim regardless. Anyone tempted to add a signature here
should read this paragraph first.

## Privacy, stated as a comparison

| | descriptor pairing (today) | this request |
|---|---|---|
| RP learns | every past and future address, balances | one address |
| Duration | permanent | that withdrawal |
| Links withdrawals to each other | yes | no (fresh each time) |
| Revocable | unpair | nothing to revoke |
| Needed to withdraw | yes | no — login is enough |

## Failure handling — do not silently degrade

When no address comes back, the RP has two honest choices and one
dishonest one.

- **Refuse** (recommended default, and what `/api/withdraw/sign/start`
  does today): tell the user their wallet cannot supply an address.
- **Offer the fallback explicitly**: withdraw to the venue key's raw
  P2TR, with the claim and the UI saying plainly that it will not be
  visible in the app.
- **Never** fall back to the raw key silently. `/api/withdraw/prepare`
  and `/api/withdraw` do exactly that today (`unwrap_or_else(||
  p2tr_spk_hash(&pk))`) and it should be fixed with this work — money
  landing somewhere the user cannot see is worse than an error.

## What this retires

- `RpApi`'s `__descriptor` on login-succeeded — marked *"Experimental.
  Only set on testnet for now. TODO: Remove this"*. This request is what
  makes removing it possible rather than merely intended: it serves the
  one detail that field was being used to derive.
- The payment-service pairing as a **precondition for withdrawal**.
  Pairing remains what it should be — the consent for operations that
  genuinely need the wallet's coins and descriptor — and stops being a
  toll on getting your own money out.

## Layers

1. **SDK** (`lc-wallet-core`): wire types, the two `UserAction`s, core
   handling and effect, FFI event. Mirrors sign-message throughout.
2. **Connect server** (`swaption_be` `rp_api` + relay): the new
   `Req`/`Resp`/`Notif` variants and the relay path. Shape validation
   only — it never inspects the address.
3. **Wallet server** (`agentic_wallet`): `/v1/connect/receive-address/
   {start,status}` for RPs on the relay path, exactly as sign-message.
4. **App**: answer with the next unused address from the active wallet;
   network check; no dialog.
5. **Venue** (`rolling-future`): `payout_dest` asks over LC instead of
   `/v1/agent/wallets`; per-withdrawal instead of cached; `RF_SPKHELPER`
   still converts the address to (spk, spk hash) for the digest.

## What does NOT change

The `rf/withdraw/v1` digest, the typed claim, and the covenant. The
destination is still an owner-signed witness the program checks against
the payout output. **So this ships independently of the delegated-key
cutover — it needs no new pool.**
