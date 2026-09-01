# Fund request, option B: confidential template rows with proofs — proposal

Status: PROPOSAL, 2026-09-02 (overnight). Nothing built. Written for
Scott's phase-3 decision in `rolling-future`/`rf-swaption_be`
`docs/DELIVERY-PLAN.md` ("Phase 3 design fork"): moving Swaption's
Bull/Bear coinjoin onto `StartFund` without giving up its privacy.
Amends `fund-template-spec.md` rule 1; every other rule stands.

## The problem

`approval::verify_fund_template` refuses any template input or output
that is not explicit (rule 1: "anything confidential in the template is
unverifiable"). That is exactly right for what it can see today: a
confidential row carries only Pedersen commitments, so the wallet cannot
recompute the deficit and would be approving a number the RP asserted.

The Swaption trading contract is confidential end to end — the dealer's
coins are blinded, the contract UTXO is blinded (its own blinding key per
contract), change is blinded. Under rule 1 the RP would have to make the
dealer's inputs, the contract output and the server-fee output explicit,
publishing every stake and payout on chain. That is a product regression
the fund request should not force.

## The fix: the RP proves the amounts it hides

PSET v2 already has the fields for this, and our `elements 0.25`
dependency exposes them:

| Row | Explicit fields | Proof fields | Verified against |
|---|---|---|---|
| input | `amount: Option<u64>`, `asset: Option<AssetId>` | `blind_value_proof`, `blind_asset_proof` | `witness_utxo.value` / `witness_utxo.asset` commitments |
| output | `amount`, `asset` | `blind_value_proof`, `blind_asset_proof` | the output's `value_comm` / `asset_comm` |

(`elements::pset::map::{Input,Output}`; verification via
`secp256k1_zkp::RangeProof::verify` and `SurjectionProof::verify`,
present in `secp256k1-zkp 0.11`. `RangeProof::blind_value_proof` is the
constructor the RP uses; a "blind value proof" is a single-value
rangeproof, so verification succeeds iff min == max == the stated
amount.)

Rule 1 becomes:

> 1′. Every template input and output MUST be explicit **or carry the
> explicit amount and asset together with proofs that verify against
> its commitments**. A row that is confidential without proofs, or
> whose proofs do not verify, is refused.

Rules 2–5 are unchanged and keep their meaning: the deficit is computed
from verified amounts; the wallet contributes only `asset_id`; SIGHASH_ALL
binds everything; the dialog renders the wallet's own arithmetic.

## What the RP must do (and only the RP can)

Blinding factors must sum to zero across the transaction. Two parties
cannot share factors through the template, so **each party balances its
own half**: the RP blinds its inputs and outputs so that its own
value/asset blinding factors net to zero (this is how Swaption's coinjoin
is blinded today — the server holds the factors for its side), and the
wallet's single change output balances the wallet's own inputs, exactly
as in the existing spec. Explicit rows contribute zero. If both halves
balance, the transaction balances; the wallet does not need any RP
factor and gets none.

Consequences the spec must state:

- The RP finalises its blinding BEFORE sending the template. The
  wallet's signatures commit to the commitments; any later
  re-randomisation invalidates them.
- The RP's proofs are for the wallet's eyes; they are not part of the
  broadcast transaction (PSET-only fields), so on-chain privacy is
  unchanged.
- Output proofs reveal the amount of the RP's blinded outputs to the
  wallet — which is the point: the user sees what the contract holds.
  The RP's change output amount is disclosed to the user too. Acceptable
  (the dealer's change is not secret from its counterparty).

## SDK changes

- `approval::verify_fund_template`: accept proven rows; the summary
  gains `proven_rows: usize` and the per-row `Explicit | Proven`
  marker so hosts can render "amount verified by proof".
- New unit tests: proven input, proven output, proof for the wrong
  amount (refused), proof against the wrong commitment (refused), row
  without proofs (refused, rule 1 message unchanged).
- Fixture: one real blinded Liquid-testnet PSET with proofs, pinned.

## App / wallet-side changes

`rf-sideswap_rust` `fund_pset`: none in construction — the wallet still
selects its inputs, blinds its one change, signs SIGHASH_ALL. It must
call the updated verifier (it does today) and render the marker.

## Connect server / relay

None: the template is opaque to the relay beyond size. Check
`MAX_TEMPLATE_LEN` against a real Bull/Bear template with proofs
(rangeproofs are ~2–4 KB each; a template with four proven rows is
around 20 KB of base64).

## RP-side work (swaption_server)

The template builder is the existing `contract_pset::construct` minus
the client inputs: dealer inputs (proven), server fee input (explicit),
contract output (proven), server-fee output (proven or explicit), dealer
change (proven), fee output (explicit). Return: on `Succeed { pset }`,
re-verify the wallet's contribution against the contract terms, add the
dealer's and the server's signatures, finalise, broadcast — the same
sequence the descriptor flow runs today after StartSign. The client's
UTXO bookkeeping (`UpdateUtxos`, reservations) goes away for the wallet
side; the payout address comes from `StartReceiveAddress`.

## What to decide

Adopting this keeps trading confidential and lets every product use the
same primitive. The alternative (option A, explicit contracts) needs no
SDK change and ships sooner, at the cost of on-chain visibility of every
stake. Recommendation stands: B for trading, A for lending and the
prediction market whose covenants are explicit anyway.
