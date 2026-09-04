# Short wallet id and handles — what people share to get paid

**Status: built 2026-09-02.** SDK (`lc-wallet-core/src/short_id.rs`,
`identity.rs`), directory (`agentic_wallet` `identity_core/src/short_id.rs`,
wallet_server identity API), SideSwap app (`lc-sdk` branches), hub
(`liquidconnect-web`). Wire protocol untouched: `wallet_id` on every
message is still the full x-only key.

## The two shareable forms

| Form | Example | Where it comes from |
|---|---|---|
| **Handle** | `@scott` | Chosen by the owner in the app, unique in the directory, 3–30 of `a-z 0-9 _`, letter first. The thing a person says. |
| **Short wallet id** | `K7M3-9PQ2` | Derived from the key: 8 Crockford-base32 characters (40 bits of a tagged SHA-256). Every wallet has one from the start. |

Handle beats id wherever the app shows something to share; the id is
what a wallet has before it picks a name.

## The id

```
short_id = crockford_base32( tagged_sha256("liquidconnect/wallet-id", pubkey)[0..5] )
display  = XXXX-XXXX
```

`pubkey` is the 32-byte x-only key; `tagged_sha256` is the BIP340
construction `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ pubkey)`; the alphabet
is `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O, U). Input is
normalised by dropping dashes and spaces, upper-casing, and reading
I/L as 1 and O as 0.

### Why 8 characters is safe: first-come binding

Forty bits is small enough to **manufacture a colliding key**: generate
keys until one hashes to a chosen id — about a trillion tries, minutes
on a GPU — then connect it with the open SDK. Liquid Connect accepts
any key that can sign a login; that is the point of the SDK, so the
rendezvous cannot tell a manufactured wallet from a real one. If ids
were resolved by recomputing them across connected wallets, two wallets
would match and whichever was seen first would be paid.

So an id is **never resolved by recomputation**. The identity directory
binds each id to the **first key that claims it** and refuses every
other key that presents the same id; the refusal is logged as the
collision attempt it is. Resolution goes through that binding only.
The manufactured key gets refused at the door.

The remaining window is an id shared *before* it is bound: an attacker
who sees it could bind a manufactured key first, and the real owner
would then be the one refused. The rule that closes it: **the app
claims at activation and shows the id only once the directory has
confirmed the binding.** Where there is no directory at all (dev
environments) the app shows the derived id, and there is nothing to
pay it through anyway.

Honest collisions: birthday at ~2^20 wallets, so two real users may
one day derive the same id. The second one to claim is refused with
the same 409 and can use a handle; the log line distinguishes the
cases by hand. This is accepted for the length.

### Test vectors (pinned in all three implementations)

| x-only pubkey (hex) | short id |
|---|---|
| `0000…0001` (31 zero bytes, then 0x01) | `ZFKG-NS4S` |
| `c430e1683ac5f48d4e058e602b9ee33890830be3a92fea9f524d5763c15369d1` (= `WalletKey::new(&[7u8; 32], LiquidTestnet)`) | `8BDR-BSWW` |

## The protocol pieces

| Layer | What |
|---|---|
| **Directory** (`agentic_wallet`) | `IdentityRecord.short_id`, `Directory::claim_short_id` (first come, idempotent for the holder), `request_payment_address_by_short_id`; identity API `POST /v1/identity/id` (challenge-signed, action `id`, value = the id as the wallet computed it; the server recomputes from the proved key and refuses a mismatch; 409 when bound elsewhere) and `POST /v1/identity/handle` (action `handle`); `status` reports `short_id` once bound; payers resolve either via `GET /v1/owner/payment_address?id=` or `?handle=`. |
| **SDK** | `short_id` module, `WalletKey::short_id()`, `IdentityClient::claim_short_id` / `claim_handle`, `IdentityStatus.short_id`. |
| **App** | Worker claims the id on every identity status refresh until bound and sends `LcIdentityState.short_id` only when the directory confirmed it (the locally derived id only when `available == false`). `To.LcIdentityClaimHandle` for handles. Settings › Liquid Connect ID shows the id (or "Registering…") and the Pay handle section; the activation dialog and the Swaption "Get paid" block show the handle first, else the bound id. |
| **Hub** | Pay page accepts `@handle`, a bare handle, a short id, or a full key; short ids and handles resolve through the directory, a full key against connected wallets. A bare 8-character word that could be either is tried as an id first, then as a handle. |

## History

- 2026-09-01: 16-character (80-bit) derived id, resolved by
  recomputation over connected wallets — safe without a registry,
  but too long to say.
- 2026-09-02: handles added for phone wallets; then, on Scott's
  point that uniqueness enforced at the directory is what actually
  closes the collision attack, the id went to 8 characters with
  first-come binding.
