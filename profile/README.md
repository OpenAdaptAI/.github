# OpenAdapt

**Every app on earth, one verified API. Compile, verify, and self-heal any GUI workflow or AI agent with before-click checks, read-back verification, and signed Ed25519 receipts.**

[Website](https://openadapt.ai/) ·
[Docs](https://docs.openadapt.ai) ·
[Live Demo](https://app.openadapt.ai/demo) ·
[Starter Skills](https://app.openadapt.ai/registry) ·
[Hugging Face (Veto-4B-r6)](https://huggingface.co/OpenAdapt/openadapt-veto-4b-r6) ·
[Discord](https://discord.gg/yF527cQbDG)

<a href="https://github.com/OpenAdaptAI/OpenAdapt/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-10b981?style=flat-square" alt="MIT License" /></a>
<a href="https://pypi.org/project/openadapt/"><img src="https://img.shields.io/pypi/v/openadapt?style=flat-square&color=2563eb" alt="PyPI" /></a>
<a href="https://huggingface.co/OpenAdapt/openadapt-veto-4b-r6"><img src="https://img.shields.io/badge/Hugging%20Face-Veto--4B--r6-f59e0b?style=flat-square" alt="Veto-4B-r6 on Hugging Face" /></a>
<a href="https://openadapt.ai/proof"><img src="https://img.shields.io/badge/verified%20proof-openadapt.ai%2Fproof-10b981?style=flat-square" alt="Verified proof on openadapt.ai" /></a>

---

OpenAdapt wraps any closed-source or open-source AI agent (Claude Code, Codex, Gemini, browser-use, or custom Python) or compiles a single demonstration into a deterministic local tool. Repeat runs execute at `$0` in model fees with before-click checks, independent read-back verification, bounded UI-drift repair, and offline-verifiable Ed25519 receipts.

## What changes for your team

Unwrapped computer-use agents guess when a UI changes and report success after clicking Save. OpenAdapt compiles repeating workflows, reads saved records back independently, and stops for review when reality disagrees.

### Verified Clean-Room Results

| Evaluation | Scope | Measured Outcome |
|---|---|---|
| **4-App Real-Upgrade UI Drift** | Gitea, Vikunja, Memos, Mealie (`N = 60`, 100-run amortized, 60/60 Ed25519 receipts) | **0% silent errors (`0/60`)** vs `18.3%` ASI programmatic synthesis (`p = 0.000977`), `15%` unwrapped `gpt-5.4` (`3/20`), and `3.3%` Stagehand unverified self-heal (`2/60`). **1,188x cheaper** (`$0.000015/run` vs `$0.017824/run`) and **5.1x faster** (`1.88 s` warm p50 vs `9.53 s`) once compiled. |
| **Multi-Tab HealthAdminBench** | Paired frontier runs (`gpt-5.4` & `claude-sonnet-5-5`, 0 leaked hints) | **+25.0 pp Verified Completion recovery** (`20.8% -> 45.8%`), **5x fewer false escalations** (`20.8% -> 4.2%`), and **0 regressions**. Single-tab paired (`N = 24`): **-25.0 pp silent errors** (`70.8% -> 45.8%`, `p = 0.031`). |
| **Veto-4B-r6 Local Safety Sidecar** | 4 unseen desktop apps on-premise ([Hugging Face](https://huggingface.co/OpenAdapt/openadapt-veto-4b-r6)) | **OOD AUROC `0.627 -> 0.791`** (`p = 0.0051`), **OOD FPR `37.9% -> 6.9%`** at `357 ms` in `3.15 GB` VRAM with zero screenshot egress. |

Full raw tables, error floors, and interactive WebCrypto Ed25519 verification: [openadapt.ai/proof](https://openadapt.ai/proof). To see which EHR tasks have a public API and which still end at a screen, browse the [EHR Integration Directory](https://ehrintegrationdirectory.com) ([source](https://github.com/OpenAdaptAI/ehr-integration-directory)).

## How a run ends

Every run writes a signed, itemized receipt with one of five plain outcomes:

| Result | What it means |
|---|---|
| **Done and checked** | The program saved the entry and an independent read-back confirmed every checked field. |
| **Stopped before saving** | Target identity or a policy rule did not match, so execution paused before writing. Nothing was changed. |
| **Check the record** | A write was sent and the outcome could not be confirmed. A person reviews the record before any retry. |
| **Finished, not checked** | The steps ran without a configured read-back check (for example, a practice run). |
| **Didn't finish** | Execution stopped early; the report records exactly what happened before the stop. |

## Two ways to start

### Hand off a workflow

Start with a bounded 1-week [Proof Pilot](https://openadapt.ai/pilot) on your staging system or [book a 30-minute call](https://openadapt.ai/book). We wrap your existing agent or compile the workflow, bind an independent read-back check, test planted faults, and deliver signed Ed25519 receipts before production cutover. See [services](https://openadapt.ai/services) and [pricing](https://openadapt.ai/pricing).

### Run it yourself

OpenAdapt is MIT-licensed and free to run locally with zero API keys required:

```bash
# 30-second local demo (no API key): compiles, replays 5x, catches a silent save error
uvx --python 3.12 openadapt@latest quickstart

# Wrap Claude Code
uvx --python 3.12 openadapt@latest wrap -- claude -p "submit the invoice"

# Wrap Codex
uvx --python 3.12 openadapt@latest wrap -- codex "update the claim status"

# Wrap any Python or browser-use agent
uvx --python 3.12 openadapt@latest wrap -- python my_agent.py
```

Or install directly with `pip` (Python 3.10 to 3.12) and run the planted-fault check:

```bash
python -m pip install --upgrade openadapt
openadapt quickstart --break-it
```

Follow the full setup guide at [docs.openadapt.ai/get-started/](https://docs.openadapt.ai/get-started/) or inspect live capabilities in [CAPABILITIES.md](https://github.com/OpenAdaptAI/OpenAdapt/blob/main/CAPABILITIES.md).

## For developers

OpenAdapt compiles demonstrations into governed workflows across browser, native desktop, RDP, and Citrix. The default healthy path executes deterministically and makes no generative-model API calls. Consequential actions are identity-gated, results are checked against the workflow's evidence contract, and uncertainty halts for review instead of being reported as success.

### Core Ecosystem & Execution Modes

- **Monorepo (`OpenAdaptAI/OpenAdapt`):** `openadapt` CLI launcher, `openadapt-flow` deterministic compiler and runtime, `openadapt-kernel` minimal Shadow-to-Autopilot kernel, `openadapt-verify` independent read-back verifier, and `openadapt-agent` local MCP & Agent Skills bridge.
- **Desktop (`openadapt-desktop` 0.35.0):** Local recorder, step diff viewer, replay console, and offline Ed25519 receipt inspector.
- **Local Safety Sidecar (`OpenAdapt/openadapt-veto-4b-r6`):** Open-source 4B QLoRA verifier (`3.15 GB` VRAM, `357 ms`) running solely on OpenAdapt's own local sidecar with zero access to your agent's weights.
- **OpenAdapt Cloud (`app.openadapt.ai`):** Three execution modes: **OpenAdapt Hosted** (managed Linux browser billed only on verified runs), **BYOC Connector** (`openadapt connect` inside your own Windows/Linux/VPC boundary), and **Bring Your Own Sandbox** (Browserbase, E2B, Daytona, or Browser Use streaming signed receipts to `/receipts` and staged diffs to `/inbox`).

### Engine Outcome Contract

Each plain outcome in [How a run ends](#how-a-run-ends) maps to a strict engine outcome. Callers must never report a halt as success:

| Plain Result | Engine Outcome |
|---|---|
| Done and checked | `VERIFIED` |
| Stopped before saving | `HALTED` with transaction outcome `HALTED_BEFORE_EFFECT` |
| Check the record | `HALTED` with transaction outcome `RECONCILIATION_REQUIRED`, or any uncertain delivery |
| Finished, not checked | `COMPLETED_UNVERIFIED` |
| Didn't finish | `FAILED` |

## Product surfaces

| Target | Role |
|---|---|
| `openadapt` | [`OpenAdapt`](https://github.com/OpenAdaptAI/OpenAdapt) installs the `openadapt` command, `openadapt-kernel`, `openadapt-verify`, and the core engine. |
| `flow` | [`openadapt-flow`](https://github.com/OpenAdaptAI/OpenAdapt/tree/main/packages/flow) is the compiler and governed runtime under `packages/flow`. |
| `cloud` | [`app.openadapt.ai`](https://app.openadapt.ai/) runs hosted browser workflows, BYOC connectors, starter skills (`/registry`), escalation diffs (`/inbox`), and signed receipts (`/receipts`). |
| `desktop` | [`openadapt-desktop`](https://github.com/OpenAdaptAI/openadapt-desktop) (v0.35.0) records, tests, runs, and reviews workflows locally and handles approved repairs. |
| `capture` | [`openadapt-capture`](https://github.com/OpenAdaptAI/openadapt-capture) records screen, input, timing, and window evidence for Desktop and Flow. |
| `agent` | [`openadapt-agent`](https://github.com/OpenAdaptAI/OpenAdapt/tree/main/packages/agent) exposes compiled Flow workflows to AI agents as local MCP tools and Agent Skills. |
| `docs` | [`docs.openadapt.ai`](https://docs.openadapt.ai) is the documentation site, published from [`openadapt-ops`](https://github.com/OpenAdaptAI/openadapt-ops). |

Qualification is per workflow. A product release admission doesn't qualify any workflow. Current signed admissions are published in the [live record](https://docs.openadapt.ai/production-lifecycle.json).

## Evidence

Both pinned studies grade each run with a check that doesn't depend on the thing being tested.

### Fault test

We injected faults into saves that our own engine made to a test record system: nine injected faults and one clean control, nine runs each. In 72 of 90 runs, the record ended up wrong: missing, partial, duplicated, on the wrong record, or with other records deleted or added.

| Check | Wrong records it passed |
|---|---|
| Look only at the screen after saving | 54 of 72 (75.0%) |
| One separate read of the record | 9 of 72 (12.5%) |
| A read of every table in the test database | 0 of 72 |

The 9 that one separate read passed were all one kind: a write to a billing table that read didn't cover. The zero covers only the audited test database. Every check also stopped 9 of 18 runs that had saved correctly, because the client never got the server's reply. This test covers a fixed list of faults and doesn't measure a real-world error rate. [Method and caveats](https://github.com/OpenAdaptAI/OpenAdapt/blob/main/packages/flow/benchmark/effect_e2e/EFFECT_E2E.md).

### OpenEMR field test

On the shared OpenEMR public demo, with fake patients and an 18-step task that adds a patient note, compiled replay finished 19/20 runs at 39.2s median with no model calls. A computer-use agent finished 10/10 runs at 70.4s median, at about $0.55 a run at the July 2026 list price. The one compiled run that didn't finish stopped at step 17, before saving, instead of reporting success. Measured on 2026-07-08 with a development build of Flow 0.1.0; small sample on a demo that resets daily. OpenAdapt isn't affiliated with the OpenEMR project. [Method and caveats](https://github.com/OpenAdaptAI/OpenAdapt/blob/main/packages/flow/benchmark/openemr/BENCHMARK.md).

Read [LIMITS.md](https://github.com/OpenAdaptAI/OpenAdapt/blob/main/packages/flow/docs/LIMITS.md) before extrapolating. Runnable references are in [`packages/flow/docs/showcase`](https://github.com/OpenAdaptAI/OpenAdapt/tree/main/packages/flow/docs/showcase) and [`benchmark`](https://github.com/OpenAdaptAI/OpenAdapt/tree/main/packages/flow/benchmark).

## Research and labs

- **Safety models:** [`OpenAdapt/openadapt-veto-4b-r6`](https://huggingface.co/OpenAdapt/openadapt-veto-4b-r6) on Hugging Face (MIT-licensed local 4B QLoRA verifier).
- **Research repositories:** [`openadapt-evals`](https://github.com/OpenAdaptAI/openadapt-evals), [`openadapt-ml`](https://github.com/OpenAdaptAI/openadapt-ml), [`openadapt-retrieval`](https://github.com/OpenAdaptAI/openadapt-retrieval), and [`openadapt-grounding`](https://github.com/OpenAdaptAI/openadapt-grounding).
- **Lifecycle registry:** [`REPOSITORY_LIFECYCLE.md`](https://github.com/OpenAdaptAI/.github/blob/main/REPOSITORY_LIFECYCLE.md) classifies every repository in the organization.
