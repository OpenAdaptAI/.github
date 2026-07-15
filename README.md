# OpenAdaptAI Organization Configuration

This repository owns the public organization profile and the lifecycle registry.
It does not change GitHub organization settings automatically.

The cross-repository delivery sequence and acceptance criteria are maintained in
[LAUNCH_PLAN.md](LAUNCH_PLAN.md).

## Manual GitHub Actions

Organization owners should apply these settings after this branch is merged:

1. Set the organization description to: `Deterministic, governed automation for repeated work trapped behind GUIs.`
2. Change the `OpenAdapt` repository description to: `Beta launcher for openadapt-flow: compile demonstrated GUI workflows into deterministic, governed local replay.`
3. Change the `openadapt-flow` description to: `Canonical OpenAdapt engine: compile demonstrated GUI workflows, replay locally without model calls on healthy runs, and govern repair and refusal.`
4. Change the `openadapt-desktop` description to: `Experimental desktop authoring and teaching surface for OpenAdapt workflows.`
5. Change the `openadapt-cloud` description to: `OpenAdapt Cloud: managed execution of locally authored, attested browser workflows, with billing and structural reports.`
6. Unpin `openadapt-retrieval` and `openadapt-grounding`; pin `openadapt-flow`, `openadapt-cloud`, and `openadapt-desktop` instead.
7. Use this interim six-repository pin set: `OpenAdapt`, `openadapt-flow`, `openadapt-cloud`, `openadapt-desktop`, `openadapt-evals`, `openadapt-privacy`.
8. When public `openadapt-docs` and `openadapt-examples` repositories exist, replace `openadapt-evals` and `openadapt-privacy` in the pin set.
9. Apply the archive queue in [REPOSITORY_LIFECYCLE.md](REPOSITORY_LIFECYCLE.md) only after each repository has an archive notice and any dirty local work is preserved.

The current public organization tagline, `AI for Desktops.`, and several
repository descriptions are GitHub settings. Editing `profile/README.md` cannot
change them.
