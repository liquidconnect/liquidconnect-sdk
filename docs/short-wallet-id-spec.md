# Short wallet id — the Liquid Connect ID people share

**Status: built 2026-09-01** in the SDK (`lc-wallet-core/src/short_id.rs`),
the SideSwap app worker + UI (`lc-sdk` branches), and the hub
(`liquidconnect-web`, pay page). Wire protocol untouched.

## The problem

A wallet's Connect identity is an x-only public key, and the app showed
it raw: 64 hex characters under "Wallet ID — share this to get paid".
Nobody reads that aloud, types it from a chat message, or spots a wrong
character in it. Scott 2026-09-01: make it much shorter, so people can
share it with ease.

## The id

```
short_id = crockford_base32( tagged_sha256("liquidconnect/wallet-id", pubkey)[0..10] )
display  = XXXX-XXXX-XXXX-XXXX          e.g. 8BDR-BSWW-V8DR-KZZ9
```

- `pubkey` is the 32-byte x-only key (the value every protocol message
  calls `wallet_id`).
- `tagged_sha256` is the BIP340 construction:
  `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ pubkey)` — the same
  `sha256t_hash_newtype!` form the key module already uses for its other
  tags, so no new primitive.
- The first **10 bytes (80 bits)** are encoded with Crockford's base32
  alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O, U), giving
  exactly 16 characters, displayed upper-case in four groups of four.

### Why these choices

**Derived, never assigned.** A pure function of the key. The wallet
computes it offline the moment it has its key; every server that knows
the key computes the same one. No registry to create, sync, lose, or
attack; nothing changes for wallets that already exist.

**80 bits, no check digit.** The id resolves only against keys a server
already holds (connected wallets), so a mistyped id lands in *empty
space* — "no such wallet" — never on a neighbour. Forging a key whose id
collides with a chosen victim's is a 2^80 search over EC key
derivations; honest collisions need on the order of 2^40 wallets. That
is why the characters go to identity rather than to a checksum: with
this much space, the checksum's job (turn a typo into a refusal instead
of a misdirected payment) is already done.

**Crockford base32.** Case-insensitive, no ambiguous letters, and a
defined forgiveness rule: `I`/`L` read as `1`, `O` as `0`. Sixteen
characters in groups of four is licence-key shape — people already know
how to read those out.

### Normalisation (input side)

Strip dashes and spaces, upper-case, map I/L→1 and O→0, then require
exactly 16 alphabet characters. Anything else is *not a short id*.
Implementations: `short_id::normalize` (Rust) and
`normalizeShortWalletId` (JS). A 64-hex string is not a short id; the
hub's `parseWalletIdInput` recognises both forms so ids copied from
older app builds keep working.

## Test vectors (pinned in both implementations)

| x-only pubkey (hex) | short id |
|---|---|
| `0000…0001` (31 zero bytes, then 0x01) | `ZFKG-NS4S-5QGG-ER0Z` |
| `c430e1683ac5f48d4e058e602b9ee33890830be3a92fea9f524d5763c15369d1` (= `WalletKey::new(&[7u8; 32], LiquidTestnet)`) | `8BDR-BSWW-V8DR-KZZ9` |

Rust: `cargo test -p lc-wallet-core short_id`. JS:
`node --test server/wallet-id.test.mjs` in liquidconnect-web.

## Where it lives

| Layer | What changed |
|---|---|
| **SDK** `lc-wallet-core` | `short_id` module (`short_wallet_id`, `normalize`, `matches`), `WalletKey::short_id()`. |
| **App worker** `sideswap_rust` `lc-sdk` | `LcEnrollmentState.short_id` (field 4) and `LcIdentityState.short_id` (field 10), both `optional string`, derived next to `identity_pk`. `wallet_id` still carries the full key. |
| **App UI** `sideswapclient` `lc-sdk` | Settings › Liquid Connect ID, the activation dialog, and the Swaption sessions "Get paid" block show and copy the short id (full key only from a worker that predates the field). |
| **Hub** `liquidconnect-web` | `server/wallet-id.mjs` twin; `/api/pay/address` accepts short id or full key; the connected-wallet line shows the short id; pay page placeholder. |

Not changed, on purpose: the connect server, `rp_api::Wallet`, and the
wallet server's `/v1/agent/wallets` all keep reporting the full key —
the hub derives the short id per wallet and matches. Any RP that wants
to display or accept a short id does the same (16 lines of code, vectors
above). `lc-wallet-ffi` does not yet expose it to host apps.

## Follow-ups

- FFI: a `LiquidConnectWallet.short_id()` export for SDK host apps.
- The identity server could store `short_id` next to `identity_id` so
  `/v1/owner/contacts` can search by it — not needed for pay-by-id.

## Handles: the thing people actually share (2026-09-02)

Scott, after seeing the 16-character id: 8 characters would be nicer.
A *derived* id cannot go that short (40 bits is forgeable in minutes on
a GPU), so the shareable name is a **handle** — `@scott` — which the
identity directory already modelled for its own wallet: 3–30 of
`a-z 0-9 _`, letter first, case-insensitive, unique, opt-in public.
What was missing was the phone-wallet path:

| Layer | Added |
|---|---|
| wallet_server identity API | `POST /v1/identity/handle` (challenge-signed, action `handle`, value = the handle as typed), `App::claim_handle_for`; a rename releases the old name. Resolution for payers was already there: `GET /v1/owner/payment_address?handle=`. |
| SDK | `IdentityClient::claim_handle`. |
| App | `To.LcIdentityClaimHandle`; Settings › Liquid Connect ID has a "Pay handle" section; the activation dialog and Swaption "Get paid" show `@handle` first, the short id as fallback. |
| Hub | Pay page accepts `@handle`, a handle, a short id, or a full key. A 16-character alphanumeric that could be either is tried as an id first, then as a handle. |

The short id stays as the no-registry fallback: it works before a
handle is claimed and in environments with no identity service.
