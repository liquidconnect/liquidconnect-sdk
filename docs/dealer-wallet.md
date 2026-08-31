# The dealer wallet on the Liquid Connect structure

Scott's direction 2026-08-31, part of the paper.swaption.io reset: the
venue's dealer is an ORDINARY SDK wallet — a BIP39 mnemonic Scott
holds, imported into any wallet that carries the SDK structure — so
dealer funds are controllable from an external wallet whenever needed,
with no venue-internal key material.

## Key structure (nothing new — exactly the app's model)

One mnemonic yields everything, all seed-derived:

- **Seed**: BIP39 mnemonic → seed (empty passphrase).
- **Connect identity**: the wallet descriptor's slip77 master blinding
  key → `WalletKey` — logs in to Liquid Connect, receives sign
  requests, owns the identity record. Never touches money (the
  descriptor travels to the connect server, so this key is
  server-derivable — the recorded disqualification).
- **Venue money key**: seed → `VenueKey` (hardened path m/19523') —
  signs venue orders/withdrawals (typed clear-signing) and spends both
  of its script forms: the raw covenant P2TR (exit payouts, pool
  leaves) and the BIP341-tweaked standard form (deposit staging).
- **Wallet coins**: the ordinary descriptor (`elwpkh`) — where
  withdrawals land (`rf/withdraw/v1` commits the named destination).

## Setting the dealer up (Scott + venue operator)

1. **Scott generates the mnemonic** in the wallet itself (SideSwap test
   build ≥ `c399f6d`: create new wallet) or any BIP39 generator he
   trusts. The mnemonic is his alone — never in a session log, chat,
   or file.
2. Pair the wallet with Liquid Connect (the app's LC hub → pair, or
   test.liquidconnect.io) — this registers the identity and gives the
   wallet server the watch-only descriptor, which is what makes
   `GET /v1/agent/wallets` able to serve the dealer's receive address
   to the venue.
3. Venue link: `/api/link/start` code → the wallet's venue login binds
   the VenueKey as the dealer account's key (key-agnostic
   `/api/sdk/login`, identity associated for sign-message routing).
4. The venue operator marks that account as THE dealer in venue config.
5. Fund by depositing from the wallet (the pay-request deposit button,
   or a plain send to the account's staging address + deposit flow).

Recovery/external control is the same mnemonic in any SDK wallet: it
re-derives the VenueKey (venue account rebinds by pk) and the
descriptor (chain coins). Nothing about the dealer lives only at the
venue.

## The connection gate ("latest SDK structure only")

Venue-side (rolling-future) policy, agreed 2026-08-31: new wallet
connections must come through the key-agnostic SDK login and be capable
of typed clear-signing; legacy identity-key venue accounts and
pre-typed opaque-digest signing are refused. The venue cannot
distinguish key derivations cryptographically — the gate is the FLOW
(sdk-login challenge + typed `rf/*` claims), plus the reset itself:
no grandfathered accounts exist to serve.
