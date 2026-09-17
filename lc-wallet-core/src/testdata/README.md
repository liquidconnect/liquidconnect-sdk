# testdata

Real transactions the `contracts` tests pin their layouts against, so that what the hand-built
fixtures assume is what a venue builds.

`paper-testnet-2026-09-17-*.nowitness.hex`: four Liquid testnet transactions of the Swaption paper
venue (paper.swaption.io), 2026-09-17, covenant v4, taken from
`https://blockstream.info/liquidtestnet/api/tx/<txid>/hex` with every input and output witness
cleared. Witnesses do not enter a txid and no follow rule reads them; the tests assert each txid, so
a file that was altered fails.

| file | txid | what it is |
|---|---|---|
| `fill51` | `1083eed00824b5e1852097e8994fc0088cb6506771930a446afea7e93230216b` | a desk fill, before the wallet wrote notes |
| `buyback51` | `2fdd553413f9ad32708d2ffc88e5a33164f04dd45fa39b241071576633b6f7ef` | its full buyback: token burned at output 0, the debt paid to the lender's claim script at output 1 |
| `fill52` | `c5cfe2b4ef68528cc9d4b8b86edbba623586c016f50eec04fd4796622e6a7115` | the first fill to carry a note (output 8, 82 script bytes), sealed under the borrower's seed |
| `sellright52` | `0a05f392712d98cfac58b72d4e4b760fc700ffcaf417a0404b55df5bf2814d06` | the sale of that position's right: the token spent alone |

The terms in the test (`paper_position`) are the lending server's own record of positions 51 and 52.
