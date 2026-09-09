# Flow 1.35.1 measured release candidate

This unsigned candidate passes the six-class evidence checks for the exact
local wheel. It is ready for release review. Publication and admission remain
false.

The source commit is `aed32758b7342c61787a3b56fe940e1e9f2d648a`. The retained
manifest digest is
`sha256:2cd3b47a9c1fc3d81b1207e7f64441d82ad7f0f62babf49d8ffde6ae2ac2c7ca`.
The verifier checks all 1,617 inventoried artifacts and 36 selected trial groups.

| Class | Selected groups | Required outcome |
| --- | ---: | --- |
| Healthy | 6 | Verified effect |
| Safe halt | 15 | Refusal before an unsafe effect |
| Uncertain delivery | 6 | Reconciliation required, without retry or replay |
| Idempotency replay | 3 | One verified write, then same-key refusal with unchanged input and effect records |
| Declared attended | 3 | Bound synthetic decision, live revalidation, and verified final effect |
| Governed repair | 3 | Reviewed and approved candidate, complete campaigns, retained proof, and verified canary |

Each of the 12 selected task-condition cells has three groups. The 42 complete
raw groups retain 54 native phase reports. The six excluded groups are the three
moderate-display trials, whose declared contract permits a verified effect or a
safe halt, and three retained-write timeout trials, whose complete effect proof
permits `VERIFIED`. The selected uncertain-delivery class requires
`RECONCILIATION_REQUIRED`. Two incomplete repair instrumentation/restart attempts
remain retained and excluded. Classes are distinct, but outcome indicators can
overlap across phases; these counts don't define an overall success percentage.

The scope is synthetic pixels, local SQLite, and synthetic reviewer inputs.
The actual repair refreshes the typed field's OCR anchor at step 002. The
hidden-Save halt is a separate refusal check. No customer qualification or
actual human approval is established. Compact scaled identity regions and the
excluded moderate-display identity-tokenization case can still refuse. Their
exact evidence remains in the manifest; no threshold was relaxed.

The source, wheel, sdist, and measured evidence require review before the
protected-main qualification and publication steps. A changed published wheel
requires new exact-byte evidence. The existing issuer must then bind the
reviewed release and workflow contracts before any signed admission or live
projection changes. The published Flow admission still names 1.34.0.
