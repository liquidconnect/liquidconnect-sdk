# Lending on Liquid Connect — fund templates with owned inputs, and typed `sw/lend/*` claims

Status: DESIGN + SDK IMPLEMENTATION 2026-09-02 (lc-wallet-core
`approval::verify_fund_template_owned`, `lending` module). App and RP
sides follow. Product spec: Dropbox `Swaption/Lending/06 Product spec v1 -
sale and buyback.md`; covenant: `rf-swaption_be` `lending-v1`
`lending_contracts/simf/swaption_lending.simf`.

## What lending needs from the wallet that nothing else did

Every Swaption lending step is a `StartFund` (docs/fund-template-spec.md):
the RP builds the covenant half, the wallet funds and signs. Two things
are new.

**1. The wallet must sign a template input it already owns.** The
position roles are one-unit NFTs sitting at the wallet's own address.
Exercise spends the borrower NFT at input 0 (the covenant pins the
index). The RP therefore places that input in the template — outpoint
and `witness_utxo` are public — and the wallet must recognise it as its
own, count it in the arithmetic, balance its blinding factor, and sign
it. Fund-template rule 1 ("every template row explicit or proven")
cannot hold for it: the NFT output was blinded by the wallet at fill and
only the wallet can unblind it. So:

> Rule 1a (owned rows). A template input whose outpoint the host wallet
> recognises as one of its own coins MAY be confidential. The host
> supplies the unblinded asset and amount from its own records and the
> verifier treats the row as explicit. Every such row is one the host
> will sign (SIGHASH_ALL) and one whose secrets enter the host's blinder
> so the wallet's single change output still absorbs the sum. The RP
> never learns anything it did not already know: the outpoint was its
> own output.

Rule 2 is unchanged: the deficit for `asset_id` must equal `amount`. An
owned NFT input that round-trips (input 0 → output 0) contributes 1 in
and 1 out of the NFT asset and nets to zero under rule 3; a full
exercise burns it (1 in, 1 to OP_RETURN) — also zero. The wallet's
stated contribution stays exactly `amount` of `asset_id` **plus the
named owned inputs**, which the dialog must list.

**2. The memo must be checkable, not just readable.** `StartFund` renders
"Deposit {amount} {asset} into {domain}" + memo. For a sale-with-buyback
the person must see the terms — size, cash, buyback price, expiry — and
the wallet must refuse a memo that lies. The `rf/*` clear-signing
contract does this for digests (rebuild, compare). For a template the
analogue is: rebuild the claim from **template rows the wallet can read
by itself** and refuse on mismatch.

## Typed fund claims (`sw/lend/*`)

Canonical JSON in `FundRequest.memo` (u64 fields as strings, hex lower):

    {"kind":"sw/lend/fill/v1","size":"50000000","sale":"3000000000000",
     "buyback":"3100000000000","expiry":3200000,
     "cash":"<asset id hex>","fee":"3000000000"}
    {"kind":"sw/lend/exercise/v1","amount":"1550000000000",
     "released":"25000000","remaining":"1550000000000","cash":"<asset id hex>"}

`fill`: the borrower sells `size` L-BTC for `sale` of `cash`, may buy
back for `buyback` until block `expiry`; `fee` is Swaption's fill fee
taken from the borrower's cash. `exercise`: the borrower pays `amount`
of `cash` and `released` L-BTC come back; `remaining` is the debt left
after (0 = full).

`sw/lend/fill/v2` adds `payout` (hex SHA-256 of the lender payout
scriptPubKey); the wallet rebuilds the v2 position script from the terms
and the pinned program leaf and refuses a template whose output 0 differs.
`sw/lend/fill/v3` has the same fields for the v3 program (permissionless
lapse to the payout script) and additionally requires `payout` to be the
claim script of the lender token found in output 2 (`lending::claim_script`),
so the lender side is a transferable claim rather than a fixed address.

A memo that parses as JSON with a `kind` starting `sw/` but fails to
parse or verify is a **refusal**, never a fallback to plain rendering
(same rule as `rf/*`).

### What the wallet checks (`lending::verify_typed_fund`)

Inputs to the check: the parsed claim, the decoded template, the fund
request's `asset_id`/`amount`, and the set of output indexes the host
recognises as paying its own addresses (`mine`).

| Claim | Check |
|---|---|
| fill | `asset_id` is the collateral (policy) asset and `amount == size`; output 0 (the position) is `size` of the policy asset; output 3 is an OP_RETURN whose 80-byte payload has `cash`, `buyback`, `expiry` at the metadata offsets (`lending_contracts` `SwaptionPositionCreationMetadata`: program_id 4 · cash 32 · buyback u64 LE · expiry u32 LE · lender script hash 32); some output in `mine` pays exactly `sale − fee` of `cash`; output 1 (borrower NFT) is in `mine` |
| exercise | `asset_id == cash` and `amount == claim.amount`; owned input 0 is a 1-unit asset (the borrower NFT); if `remaining > 0`: output 0 in `mine` carries that same asset (round-trip) and output 1 is the policy asset; else output 0 is an OP_RETURN (burn); some output in `mine` pays ≥ `released` of the policy asset (the template may net the fee from it — the wallet shows the number it found) |

What the wallet cannot check and does not pretend to: that output 0's
script is the covenant for exactly these terms (it cannot compile
Simplicity). The metadata output binds the terms on chain, the fill fee
and the sale proceeds are its own money and are checked, and the
SIGHASH_ALL signature means nothing changes afterwards. A dishonest RP
can build a bad covenant, but not take more than `amount + owned inputs`
from this wallet — the fund-template bound holds regardless.

### Rendering (`TypedFund::render`)

- fill: "Sell 0.5 BTC for 30,000 USDt · buy back for 31,000 USDt until block 3,200,000 · Swaption fee 30 USDt"
- exercise: "Buy back 0.25 BTC for 15,500 USDt · 15,500 USDt still owed after" / "… · position closed"

The host substitutes this for the memo text in its dialog and adds
"also spends: your position token" when owned inputs are present.

## Who signs what, and the two-wallet fill

Exercise and lapse are single-wallet. **Fill has two funders.** Two app
wallets cannot both SIGHASH_ALL a growing transaction: the second
wallet's inputs and change would invalidate the first's signatures. v1
therefore fills against **dealer-side lenders**: a dealer is a server
process with explicit coins that places its cash inputs and change in
the template up front (rule 1 holds: explicit rows), the borrower's
wallet funds and signs last, and the dealer signs its inputs after
(nothing changes after the wallet's signature; the dealer signs the
same transaction). App-wallet *lending* (a person as maker) needs a
prepare-then-sign fund variant and is deferred; the book still shows
their orders only when a dealer stands behind them. Selling the
borrower's call is the same problem (NFT for cash, two wallets) and is
deferred with it — v1 sells calls to dealers only.

## Layers

1. **SDK** (this change): `approval::OwnedInput`,
   `verify_fund_template_owned`, `FundTemplateSummary.owned_inputs`;
   `lending::{TypedFund, parse_typed_fund, verify_typed_fund}`; tests.
2. **App** (`rf-sideswap_rust` lc-sdk): in `add_fund_request`, look up
   every template input's outpoint in `wallet_utxos`; pass their
   secrets as owned inputs to the verifier; hand the same secrets to
   `fund_pset` so the change balances (today it assumes zero blinders
   for template inputs); run `verify_typed_fund` with the outputs whose
   scripts are the wallet's; show `render()`; signing needs no change —
   `try_sign_pset_software` already signs any input matching a wallet
   coin.
3. **Connect server / rp_api**: nothing — memo is free text.
4. **RP** (`lending_server`): build templates in the layouts above; put
   the claim JSON in `memo`; pay the borrower's proceeds and released
   collateral to an address obtained with `StartReceiveAddress`.
