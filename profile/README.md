# OpenAdapt.AI

**Compile repeated GUI work into deterministic, governed workflows.**

OpenAdapt compiles demonstrated GUI workflows into deterministic, locally
executable programs. Healthy runs make no model calls. When interfaces drift,
OpenAdapt re-resolves from retained evidence or proposes a governed repair and
halts when verification fails.

OpenAdapt is for repeated work trapped behind browser and desktop interfaces:
too visual or variable for brittle selectors, but too consequential to hand to
a free-form computer-use agent on every run.

[Install OpenAdapt](https://github.com/OpenAdaptAI/OpenAdapt) ·
[Read the docs](https://docs.openadapt.ai) ·
[See current limits](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/docs/LIMITS.md) ·
[Visit openadapt.ai](https://openadapt.ai/)

## Start Locally

```bash
pip install openadapt
openadapt flow demo-record --out rec
openadapt flow compile rec --out bundle --name mockmed-triage
openadapt flow certify bundle --policy permissive
openadapt flow replay bundle --run-dir run
```

This runs the bundled MockMed example and writes a human-readable `REPORT.md`.
Use the [five-minute guide](https://docs.openadapt.ai/get-started/) to add lint,
policy certification, drift, repair, and deployment.

## Evidence

Published comparisons of compiled replay against a computer-use agent, with the
same external success check on both arms:

- **Live third-party EMR** (OpenEMR public demo, fake patients, 18-step
  add-patient-note workflow): compiled replay went **20/20 at 39.2s p50 with
  zero model calls**; the agent went 10/10 at 70.4s p50 at about $0.55 of model
  charge per run. Small sample on a shared, daily-resetting demo — not
  CI-reproducible.
  [Methodology and caveats](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/benchmark/openemr/BENCHMARK.md).
- **CI-reproducible control** (bundled MockMed task): both arms passed every
  run (100/100 compiled, 20/20 agent), so the result is cost and latency, not
  success rate — 4.9s p50 with zero model calls versus 37.5s p50 for the agent.
  [Methodology and caveats](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/benchmark/BENCHMARK.md).

Zero model calls on a healthy run means no model-API charge on that run; it
excludes authoring, review, maintenance, and infrastructure, and it is not a
production-reliability or clinical-safety claim. Read the
[limits](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/docs/LIMITS.md)
before extrapolating either result.

## Six Public Surfaces

| Surface | Lifecycle | Start here |
|---|---|---|
| **Engine** | **Beta** | [`openadapt-flow`](https://github.com/OpenAdaptAI/openadapt-flow) is the canonical demonstration compiler and governed runtime. |
| **Desktop authoring** | **Experimental** | [`openadapt-desktop`](https://github.com/OpenAdaptAI/openadapt-desktop) is the local recording and teaching interface. Native release artifacts are not yet publicly available. |
| **Hosted browser workflows** | **Beta** | [`app.openadapt.ai`](https://app.openadapt.ai/) provides managed browser recording, execution, billing, usage, and structural reports; its implementation repository is private. |
| **Documentation** | **Beta** | [`docs.openadapt.ai`](https://docs.openadapt.ai) is the canonical journey-led site; [`openadapt-ops`](https://github.com/OpenAdaptAI/openadapt-ops) is its **Internal** publishing source. |
| **Evaluation** | **Research** | [`openadapt-evals`](https://github.com/OpenAdaptAI/openadapt-evals) contains evaluation infrastructure. Research results do not expand product maturity by implication. |
| **Examples** | **Beta** | Runnable examples currently live in [`openadapt-flow/docs/showcase`](https://github.com/OpenAdaptAI/openadapt-flow/tree/main/docs/showcase), with methods and evidence under [`benchmark`](https://github.com/OpenAdaptAI/openadapt-flow/tree/main/benchmark). There is no standalone `openadapt-examples` repository today. |

`OpenAdapt` is the Beta launcher and unified CLI; `openadapt-flow` remains the
engine. Browser record, compile, replay, reporting, and bounded deterministic
repair are the reference path. Desktop and remote-display backends retain their
separate Experimental or Research labels.

Runnable is not the same as certified safe. Review identity coverage,
postconditions, system-of-record effects, policy, and the published
[limits](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/docs/LIMITS.md)
for each consequential workflow.

## Research and Labs

Model training, retrieval, grounding, and general computer-use work remain
Research: [`openadapt-ml`](https://github.com/OpenAdaptAI/openadapt-ml),
[`openadapt-retrieval`](https://github.com/OpenAdaptAI/openadapt-retrieval), and
[`openadapt-grounding`](https://github.com/OpenAdaptAI/openadapt-grounding).
They are not required for healthy deterministic replay.

OmniMCP, SoM, and PydanticPrompt are **Labs**, not product dependencies.
Historical, Superseded, Deprecated, Archived, and Internal repositories are
classified in the public
[lifecycle registry](https://github.com/OpenAdaptAI/.github/blob/main/REPOSITORY_LIFECYCLE.md)
rather than presented as the product.

## Contribute

Product-engine changes belong in
[`openadapt-flow`](https://github.com/OpenAdaptAI/openadapt-flow). Packaging and
launcher changes belong in [`OpenAdapt`](https://github.com/OpenAdaptAI/OpenAdapt).
Use each repository's issues for scoped work, or visit
[`openadapt.ai`](https://openadapt.ai/) for deployment inquiries.

Unless a repository says otherwise, OpenAdapt.AI code is MIT licensed.
