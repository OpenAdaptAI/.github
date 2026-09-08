# Flow 1.35.0 measured admission candidate

This directory prepares an unsigned release candidate for review. `prepare.py`
checks the published wheel and sdist, their GitHub asset digests, the annotated
tag, and the successful qualification and three-OS lifecycle runs for source
`6d1f80aa4775e6aa398c3251c8d53e7ec61d0c0c`.

The measured evidence must come from the installed 1.35.0 wheel. The script
checks every retained file against its manifest, rejects repeated trial
identities and reused observations, and derives the campaign totals from the
individual trials. Missing classes, omitted counters, altered files, an
incorrect runtime, or a failed admission condition stop preparation.

```bash
python local-candidates/flow-1.35.0-measured/prepare.py \
  --measured-manifest /absolute/path/to/measured-manifest.json \
  --out local-candidates/flow-1.35.0-measured/candidate.json
```

Without `--measured-manifest`, the output is an `evidence-incomplete` release
inventory. It cannot assert measured acceptance. The tests in
`tests/test_measured_flow_candidate.py` exercise the validator with explicit
test fixtures; they aren't qualification trials.

The evidence scope is the local synthetic SQLite and pixel fixture. Synthetic
reviewer inputs exercise the real decision APIs. They do not establish customer
qualification, an actual human review, or approval to issue an admission.

`prepare.py` never reads a signing key or changes a registry. After review, the
existing issuer must bind the exact retained manifest and contract digests,
preserve the previous admission in sequence, and issue the matching signed
objects. The live ledger and its projections require a separate reviewed
change. Flow 1.34.0 remains the published admission until that change succeeds.
