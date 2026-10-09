# OpenAdapt

**OpenAdapt enters approved information into the systems your team already uses, and then it checks that the entry saved.**

It takes this last manual step in EMRs, payer portals, and desktop apps,
including apps your staff reach through Citrix or remote desktop. When
something doesn't match, it stops and asks a person instead of guessing.

[Watch the live demo](https://app.openadapt.ai/demo) ·
[Discuss your workflow](https://openadapt.ai/book) ·
[Run it yourself](#run-it-yourself) ·
[Visit openadapt.ai](https://openadapt.ai/)

The live demo plays recorded runs that use synthetic data.

## What changes for your team

Take a faxed referral that staff enter into the EMR.

| | Today | With OpenAdapt |
|---|---|---|
| Entering it | A staff member keys each referral by hand. Two hospital time studies put one faxed referral at about 10 to 12 minutes of staff time. | OpenAdapt enters the approved fields in the same EMR screens your staff use. |
| Knowing it saved | Someone sees "Saved" and moves on. | OpenAdapt reads the saved record back and compares it with what it entered. |
| When something's off | It turns up later, at booking or billing. | The run stops before it guesses, and a person decides what happens next. |
| Your staff's part | Type every referral. | Review the runs that OpenAdapt stops on. |

The time studies are from
[UCSF, JAMIA Open 2020](https://pmc.ncbi.nlm.nih.gov/articles/PMC7660949/)
(its mean includes a call to the patient) and
[Calderdale and Huddersfield NHS Foundation Trust, HFMA 2024](https://www.hfma.org.uk/system/files/2024-04/Using%20digital%20technologies%20to%20process%20admin%20tasks%20Case%20Study%20v7.pdf).
No OpenAdapt customer has measured an "after" time yet, so this table doesn't
claim a time saving.

OpenAdapt doesn't need an EMR integration. The record check needs a second way
to read the record, such as a report, an API, or a read-only login. To see
which EHR tasks have a public API and which still end at a screen, browse the
[EHR Integration Directory](https://ehrintegrationdirectory.com) that we
publish ([source](https://github.com/OpenAdaptAI/ehr-integration-directory)).
An EHR listed there isn't an OpenAdapt partner.

## How a run ends

Every run ends with one of these results, and every run leaves a report.

| Result | What it means |
|---|---|
| Done and checked | It saved the entry and read the record back to confirm it. |
| Stopped before saving | Something didn't match, so it stopped before it changed anything and asked a person. Nothing was written. |
| Check the record | A save may have gone through. A person checks the record before anything is retried. |
| Finished, not checked | It did the steps but didn't confirm the saved result, as in a practice run. |
| Didn't finish | It couldn't complete the task. Its report says what's known about whether anything was written. |

It runs on a computer you control, or on one we host. A routine run makes no
AI model calls.

## Two ways to start

Hand the workflow to us, or run the open-source engine yourself.

### Hand off a workflow

Tell us about a task your team repeats:
[discuss your workflow](https://openadapt.ai/book).

1. You show us the task once, on your own system.
2. We build the automation and test it with your own cases before it goes
   live.
3. We keep it working. When a screen changes, we propose a fix, and a person
   on your team approves it.

We scope [services](https://openadapt.ai/services) per workflow. One customer
story, a monthly billing audit at a US cardiology practice, is
[written up here](https://openadapt.ai/customers/rvu-audit-heart-care). Its
figures are preliminary. If your own AI product decides what to enter,
OpenAdapt can make that final entry and return the result to your product. See
[OpenAdapt Execute](https://openadapt.ai/execute).

### Run it yourself

The engine is free and open source under the MIT license. With Python 3.10,
3.11, or 3.12, run:

```bash
python -m pip install --upgrade openadapt
openadapt quickstart --break-it
```

This runs a synthetic clinic task twice on your computer. The first run is
done and checked. In the second run, the test server rejects the save after
the app shows that it saved. The record check finds no saved record, so the
run stops and leaves the record for a person to check. On Python 3.13 or
newer, install with `uv tool install --python 3.12 openadapt` instead.

To record your own task, follow the
[walkthrough](https://docs.openadapt.ai/get-started/). To have us run the
computer for browser workflows, see the hosted plans on the
[pricing page](https://openadapt.ai/pricing).

## For developers

OpenAdapt compiles demonstrations into governed workflows across browser,
native desktop, RDP, and Citrix. The default healthy path executes
deterministically and makes no generative-model API calls. Consequential
actions are identity-gated, results are checked against the workflow's
evidence contract, and uncertainty halts for review instead of being reported
as success.

Each result in [How a run ends](#how-a-run-ends) comes from the engine's
outcome. Both kinds of stop report `HALTED`, so read the transaction outcome
before you tell anyone whether something was written.

| Result | Engine outcome |
|---|---|
| Done and checked | `VERIFIED` |
| Stopped before saving | `HALTED` with transaction outcome `HALTED_BEFORE_EFFECT` |
| Check the record | `HALTED` with transaction outcome `RECONCILIATION_REQUIRED`, or any uncertain delivery |
| Finished, not checked | `COMPLETED_UNVERIFIED` |
| Didn't finish | `FAILED` |

A caller must report a halt as a halt, never as success.

## Product surfaces

| Target | Role |
|---|---|
| `openadapt` | [`OpenAdapt`](https://github.com/OpenAdaptAI/OpenAdapt) installs the `openadapt` command and the engine. |
| `flow` | [`openadapt-flow`](https://github.com/OpenAdaptAI/openadapt-flow) is the compiler and governed runtime. Engine changes go here. |
| `cloud` | [`app.openadapt.ai`](https://app.openadapt.ai/) runs hosted browser workflows and manages runs on computers you control. Its source is private. |
| `desktop` | [`openadapt-desktop`](https://github.com/OpenAdaptAI/openadapt-desktop) records, tests, runs, and reviews workflows on your own computer, and handles approved fixes. |
| `capture` | [`openadapt-capture`](https://github.com/OpenAdaptAI/openadapt-capture) records screen, input, timing, and window evidence for Desktop and Flow. |
| `agent` | [`openadapt-agent`](https://github.com/OpenAdaptAI/openadapt-agent) gives agents governed Flow workflows as local MCP tools and Agent Skills. |
| `docs` | [`docs.openadapt.ai`](https://docs.openadapt.ai) is the documentation site. The Support repository [`openadapt-ops`](https://github.com/OpenAdaptAI/openadapt-ops) publishes it. |

These targets form one product across browser, Windows, macOS, Linux, RDP, and
Citrix or other virtual desktops. Qualification is per workflow. A product
release admission doesn't qualify any workflow. Current signed admissions are
in the [live record](https://docs.openadapt.ai/production-lifecycle.json).

## Evidence

Both studies grade each run with a check that doesn't depend on the thing
being tested.

### Fault test

We injected faults into saves that our own engine made to a test record
system: nine injected faults and one clean control, nine runs each. In 72 of
90 runs, the record ended up wrong: missing, partial, duplicated, or on the
wrong record. The table shows how many of those runs each kind of check still
passed.

| Check | Wrong records it passed |
|---|---|
| Trust the app's success banner | 54 of 72 (75.0%) |
| One separate read of the record | 9 of 72 (12.5%) |
| A read of every table in the test database | 0 of 72 |

The 9 that one separate read passed were all one kind: a write to a billing
table that read didn't cover. The zero covers only the audited test database.
Every check also stopped 9 of 18 runs that had saved correctly, because the
client never got the server's reply. This is a coverage test over a fixed
fault list, not a real-world error rate.
[Method and caveats](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/benchmark/effect_e2e/EFFECT_E2E.md).

### OpenEMR field test

On the shared OpenEMR public demo, with fake patients and an 18-step task that
adds a patient note, compiled replay finished 19/20 runs at 39.2s median with
no model calls. A computer-use agent finished 10/10 runs at 70.4s median, at
about $0.55 a run at the July 2026 list price. The one compiled run that didn't
finish stopped at step 17, before saving, instead of reporting success. We
measured this on 2026-07-08 with Flow 0.1.0. It's a small sample on a demo
that resets daily, so CI can't reproduce it. OpenAdapt isn't affiliated with
the OpenEMR project.
[Method and caveats](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/benchmark/openemr/BENCHMARK.md).

Neither study is a production reliability or clinical safety claim. The model
charge leaves out authoring, review, maintenance, and infrastructure. Read the
[limits](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/docs/LIMITS.md)
before you extrapolate. Runnable references are in
[`openadapt-flow/docs/showcase`](https://github.com/OpenAdaptAI/openadapt-flow/tree/main/docs/showcase),
and each method is under
[`benchmark`](https://github.com/OpenAdaptAI/openadapt-flow/tree/main/benchmark).

## Research and labs

Model training, retrieval, grounding, and general computer-use work are
Research: [`openadapt-ml`](https://github.com/OpenAdaptAI/openadapt-ml),
[`openadapt-retrieval`](https://github.com/OpenAdaptAI/openadapt-retrieval),
[`openadapt-grounding`](https://github.com/OpenAdaptAI/openadapt-grounding),
and [`openadapt-evals`](https://github.com/OpenAdaptAI/openadapt-evals), which
scores agents and OpenAdapt programs on public benchmarks. You don't need any
of them to record, build, or run an automation.

OmniMCP, SoM, and PydanticPrompt are Labs projects. The product doesn't depend
on them. The public
[lifecycle registry](https://github.com/OpenAdaptAI/.github/blob/main/REPOSITORY_LIFECYCLE.md)
classifies every other repository as Support, Experimental, Historical,
Superseded, Deprecated, Archived, or Internal.

## Contribute

Engine changes belong in
[`openadapt-flow`](https://github.com/OpenAdaptAI/openadapt-flow). Packaging
and launcher changes belong in
[`OpenAdapt`](https://github.com/OpenAdaptAI/OpenAdapt). Use each repository's
issues for scoped work. Unless a repository says otherwise, OpenAdapt code is
MIT licensed.
