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

## Issue a measured admission

`issue.py` accepts a separate one-task, one-bundle campaign and a reviewed private
mapping. The comparative study above stays supplementary. Keep the mapping,
contract openings, encrypted bundle, and trial evidence in their private
location. Each file reference binds its relative path, SHA-256, and byte size.
The adapter checks the published wheel and sdist against both publishers.

Prepare one phase at a time: `receipt`, `workflow`, `manifest`, `summary`, then
`release`. Each phase request supplies `issuer_source_commit`, `issued_at`,
`expires_at`, and a unique `request_handle` (`qair_` followed by 43 URL-safe
characters). Set `references` to the required registered regular-object
references. The manifest phase also needs `acceptance_issuer_source_commit`.
The issuer derives workflow and release expiry from their signed dependencies.

From the repository root, set these variables to your private paths and the
reviewed mapping digest, including its `sha256:` prefix:

```bash
python local-candidates/flow-1.35.1-measured/issue.py \
  --mapping "$MEASURED_MAPPING" --mapping-sha256 "$MAPPING_SHA256" \
  --phase-request "$PHASE_REQUEST" --output "$UNSIGNED_PLAN"
```

The default writes an unsigned plan. Review its exact bytes and retain the
printed `plan_sha256`. To sign that plan with the existing Keychain key, repeat
those inputs and choose a permanent state directory and a separate output
directory:

```bash
python local-candidates/flow-1.35.1-measured/issue.py \
  --mapping "$MEASURED_MAPPING" --mapping-sha256 "$MAPPING_SHA256" \
  --phase-request "$PHASE_REQUEST" --output "$SIGNED_OUTPUT" \
  --sign --reviewed-plan-sha256 "$PLAN_SHA256" --state-dir "$ADMISSION_STATE"
```

Add `--stage-registry /path/to/evidence-registry.json` to append the signed pair
through the existing staging tool. Commit the pair before using its reference.
The script doesn't commit or push.

Use current `.github` main for receipt, workflow, release, and outer signing
sources. The receipt must reach `.github` main before workflow issuance, and the
summary must reach main before release issuance. Intermediate workflow and
manifest storage references can name committed branch objects; preserve those
commits in the reviewed merge. Acceptance uses the reviewed `openadapt-evals`
main source. A storage commit never substitutes for an issuer source.

Collect fresh publication staging after the campaign, receipt, and workflow
are complete, just before preparing the acceptance manifest. Preserve the
frozen campaign records and earlier signed objects. The manifest and summary
bind that staging digest, so refreshing only the release request won't extend
its window.

Keep issue times within the last hour and finish release issuance within the
publication observation's one-hour window. If it expires, stop for review of a
new acceptance issuance; preserve all signed objects and one-use state. Before
consumption, changed inputs require another unsigned plan and review.

Keep the state directory and its request journals permanently. After an
interruption, read the original result without a key or network call:

```bash
python local-candidates/flow-1.35.1-measured/issue.py \
  --reconcile-journal "$REQUEST_JOURNAL" --state-dir "$ADMISSION_STATE" \
  --output "$RECONCILIATION_OUTPUT"
```

Reconciliation returns the consumed unsigned result. An unknown result requires
investigation; don't delete the journal or retry with a new handle.
