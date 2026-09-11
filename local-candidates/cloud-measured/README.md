# Measured Cloud admission

`issue.py` prepares the existing five admission objects from one hosted campaign
and its exact deployment. Run it from the reviewed canonical checkout with the
GitHub CLI version pinned in `production-evidence-policy.json`. Preparation is
unsigned by default.

```sh
python local-candidates/cloud-measured/issue.py \
  --mapping /secure/evidence/admission-mapping.json \
  --mapping-sha256 sha256:<reviewed-mapping-file-hash> \
  --phase-request /secure/evidence/receipt-request.json \
  --output /secure/evidence/receipt-unsigned-plan.json
```

The mapping uses `openadapt.measured-cloud-admission-mapping/v1` and has exactly
`candidate`, `derivative`, `provenance`, `retained_files`, and
`publication_staging`, plus `schema_version`. Each file reference contains
`path`, `sha256` (with the `sha256:` prefix), and `size_bytes`. Paths are relative
to the mapping's directory. Keep the mapping above its retained files; traversal
and symlinks are refused.

The candidate uses `openadapt.measured-cloud-release-candidate/v1` with
`target: cloud`, `state: ready-for-review`, the canonical `release` and
`artifact_inventory`, and `proposed_release_identity` from the current Cloud
ledger. It supplies no trial totals. The only release artifact is the exact
signed deployment manifest. Its `deployment_id` is the completed protected
deployment workflow's run ID; the manifest also binds the run attempt, source,
and provider identities. Package `version` and `tag` are null. The staging tag
`v0.0.0-deployment.<run-id>` is schema metadata. Don't create or look up a Git or
PyPI release tag for it.

The fixed Internal workflow attests the closed derivative's exact bytes using
standard GitHub SLSA provenance. `provenance` references its `attestation`,
`workflow_source`, `workflow_run`, and `protected_main`. The verifier checks the
subject, certificate, repository IDs, source, workflow, run and attempt, then
compares retained records with GitHub. This authenticates evidence derivation.
The current canonical authority still controls admission issuance.

Keep the raw evidence in private storage. The derivative binds all 18 receipt
opening files and every referenced native phase and observer record. The private
producer verifies the original contracts, signatures, dispatch and effect
semantics before it emits the derivative. Contract-opening wrappers identify
their semantic components; their file hashes must not be substituted for native
contract identities. The public adapter opens retained bytes and recomputes all
17 campaign counters from the closed groups. Cell and trial totals are derived.
All six canonical classes must pass; each declared cell needs three trials.

Required named raw roles include `runtime_build_identity`, `evidence_identity`,
`runtime_version`, `deployment_readback`, `deployment_workflow_run`, and
`deployment_workflow_source`. The completed deployment run response is collected
after the deploy job. Its in-job provider readback cannot prove workflow
completion. The native bundle digest, sealed archive hash, runtime-build domain
hash, component-manifest domain hash, and runtime-version canonical JSON hash
remain separate. The adapter checks those bindings before it prepares an issuer
request.

Use the existing receipt, workflow, manifest, summary and release request shapes
in the [shared issuer](../flow-1.35.1-measured/issue.py). Each next phase names
object/bundle pairs at their actual containing commits. The immediate receipt
reference for workflow issuance and summary reference for release issuance must
already be on protected main. Issuer source commits always name actual reviewed
main. Register one pair per registry revision and preserve referenced commits
through the merge. Collect fresh staging before the acceptance manifest, then
finish summary and release issuance within its unchanged observation window.

After review of the exact unsigned plan, use the same command with `--sign`,
`--reviewed-plan-sha256`, and the existing permanent `--state-dir`. Signing uses
the current Keychain key and authority. Keep that directory across every phase
and attempt. If a result is unknown, use `--reconcile-journal` with the same state
directory and a new output path. Don't delete state or retry an unknown effect.
`--stage-registry` explicitly stages an append after signing; this script never
commits, pushes, merges or deploys.
