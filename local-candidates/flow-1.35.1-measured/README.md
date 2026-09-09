# Flow 1.35.1 measured release evidence

Flow 1.35.1 is published on PyPI and GitHub from source
`44e99a48ebf048c18892aa17cef6ae594db0d0c2`. Both publishers supply these exact
artifacts:

| Artifact | SHA-256 |
| --- | --- |
| `openadapt_flow-1.35.1-py3-none-any.whl` | `sha256:cfbc89acc6a2e3bcb5502a4d1fb29e985a03149a7f14c32c259254676bb3f11d` |
| `openadapt_flow-1.35.1.tar.gz` | `sha256:c5c6c437472b23999223b0d2473dbf21de2ca05274c270ae3854adeda6b07dca` |

The September 9 campaign measured the published wheel with one sealed synthetic
reference workflow and 18 fresh trial groups. Each of the six classes has three
groups: healthy, safe halt, uncertain delivery, idempotency replay, declared
attended, and governed repair. All 18 groups passed their declared checks.
The measured manifest is
`sha256:8167536c8cc0c6dcdae8a54a2843b3a71920baa7eaf401bbc9149ecc1e29b996`;
it inventories 831 artifacts, including all 27 native phase reports.

The 18 primary outcomes are 12 `VERIFIED`, three `HALTED_BEFORE_EFFECT`, and
three `RECONCILIATION_REQUIRED`. Retained database and input records supply the
effect checks. Silent incorrect success, over-halt, unsafe effect, blind retry,
replay dispatch, and unplanned intervention counts are zero. All 27 native
phase reports record zero model calls. Native external network-call counts
remain `unknown`. The outcome categories don't define an aggregate success
percentage.

This campaign covers one task, one sealed bundle, synthetic pixels, local
SQLite, and the exact fixture geometry. The operator and reviewer principals
are simulated. It doesn't establish customer qualification, actual human
approval, broader display support, hosted execution, or product-wide Production.

Workflow admission
`sha256:fd6ec7bcddbd9a40bcb7f9999d4fc9c91513cef9255b62e857918bf1ad0ffb5d`
is registered through [PR #42](https://github.com/OpenAdaptAI/.github/pull/42)
at main `f0fb9cc812c0d1653b1ec2998749b078f244308e`. It binds the measured
workflow to the published wheel. The product release admission is a separate
step.

Release admission
`sha256:279d6e0a9728be2d6466106b07a23a45cb6dd8acf0c4f4bcc2047d09468cabb1`
binds this exact published release. Its signed object is
`sha256:0edd19d51d449e3eaba21463117fb19148553a817e03c8c5b804953a26bcbb51`.
The issuer checked the complete registered evidence chain and current trust
before issuance. Its required expiry field is `null` under the existing
until-revoked authority. Current use still requires the canonical verifier to
check the release identity, artifact bytes, active authority, and revocation
state. A stored admission alone doesn't establish current validity.

The acceptance path uses the existing `already-published-pypi` contract with
exact artifact and tag controls. GitHub release `385710075` reports
`immutable:false`. The repository's immutable-release setting applies to future
releases; it doesn't make this existing release immutable.

## Historical September 8 candidate study

The unsigned candidate from September 8 passed the six-class evidence checks
for its exact local wheel and was ready for release review. Publication and
admission were still false.

Its source commit was `aed32758b7342c61787a3b56fe940e1e9f2d648a`. The retained
manifest digest is
`sha256:2cd3b47a9c1fc3d81b1207e7f64441d82ad7f0f62babf49d8ffde6ae2ac2c7ca`.
The verifier checked all 1,617 inventoried artifacts and 36 selected trial groups.

| Class | Selected groups | Required outcome |
| --- | ---: | --- |
| Healthy | 6 | Verified effect |
| Safe halt | 15 | Refusal before an unsafe effect |
| Uncertain delivery | 6 | Reconciliation required, without retry or replay |
| Idempotency replay | 3 | One verified write, then same-key refusal with unchanged input and effect records |
| Declared attended | 3 | Bound synthetic decision, live revalidation, and verified final effect |
| Governed repair | 3 | Reviewed and approved candidate, complete campaigns, retained proof, and verified canary |

Each of the 12 selected task-condition cells had three groups. The 42 complete
raw groups retained 54 native phase reports. The six excluded groups were the
three moderate-display trials, whose declared contract permitted a verified
effect or a safe halt, and three retained-write timeout trials, whose complete
effect proof permitted `VERIFIED`. The selected uncertain-delivery class
required `RECONCILIATION_REQUIRED`. Two incomplete repair
instrumentation/restart attempts were retained and excluded. Classes were
distinct, but outcome indicators could overlap across phases; these counts
don't define an overall success percentage.

The scope was synthetic pixels, local SQLite, and synthetic reviewer inputs.
The repair refreshed the typed field's OCR anchor at step 002. The hidden-Save
halt was a separate refusal check. The study established no customer
qualification or actual human approval. Compact scaled identity regions and
the excluded moderate-display identity-tokenization case could still refuse.
Their exact evidence remains in the historical manifest; no threshold was
relaxed.

At that point, the source, wheel, sdist, and measured evidence still required
review before protected-main qualification and publication. A changed published
wheel required new exact-byte evidence. The issuer still had to bind the
reviewed release and workflow contracts before signed admission or live
projection changes. The published Flow admission then named 1.34.0.

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

Use five sequential registry PRs: receipt, workflow, manifest, summary, then
release and the matching ledgers. Stage one signed pair per PR, with one registry
revision increment and the actual previous registry head. Merge each phase
before preparing the next phase's registered references. In the release PR,
commit the registered pair first, then append its exact release reference and
the workflow reference to the ledgers in a later commit with the registry
unchanged. Preserve all referenced storage commits in the merge.

Use current `.github` main for receipt, workflow, release, and outer signing
sources. Acceptance uses the reviewed `openadapt-evals` main source. A storage
commit never substitutes for an issuer source.

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
