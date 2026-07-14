# OpenAdapt.AI

**Show it once. It runs forever. On your premises.**

OpenAdapt is an open-source **demonstration compiler** for desktop and web GUIs.
Record a workflow once, and OpenAdapt compiles it into a deterministic,
self-healing automation that replays locally at near-zero cost, verifies its own
effects, and halts rather than guessing when the screen stops matching. No API
required, no per-run model calls, and on the default path no data leaves your
machine.

Every automation tool assumes an API. The systems that actually run regulated
work often don't: legacy EMRs, Citrix desktops, and the internal apps a team
still drives by hand. OpenAdapt learns them from a single demonstration and runs
them where your data already lives.

- **Website:** [openadapt.ai](https://openadapt.ai/)
- **Docs:** [docs.openadapt.ai](https://docs.openadapt.ai)
- **Discord:** [join the community](https://discord.gg/yF527cQbDG)

## Why a compiler

For workflows you run over and over, re-reasoning through every step with a
large model is slow, expensive, and non-deterministic, and a wrong click writes
to the wrong record. OpenAdapt takes the opposite path:

1. **Record once.** Do the task while OpenAdapt watches your screen and your
   clicks.
2. **Compile.** The recording becomes a script you can read, edit, and reuse.
   Each step carries a template crop, an OCR label, geometry landmarks, and
   postconditions derived from what the demo changed on screen.
3. **Replay, deterministic and $0.** A resolution ladder (local match, global
   match, OCR, landmark geometry, then optionally a grounding model) runs
   healthy steps in milliseconds with no model calls on the hot path.
4. **Self-heal.** When the UI drifts, a lower rung re-resolves the target and
   the fix lands back in the bundle as a reviewable diff.
5. **Effect-verify and halt on ambiguity.** Every run confirms what it changed
   and leaves a step-by-step report; when the screen stops matching
   expectations, it halts instead of guessing, and identity-verified steps
   refuse to act on a low-confidence match.

## Quick start

```bash
pip install openadapt                            # CLI + demonstration compiler

openadapt flow record --url <app> --out rec      # record a workflow once
openadapt flow compile rec --out bundle          # compile it
openadapt flow replay bundle                     # run it, local, $0

openadapt flow lint bundle                        # report coverage gaps
openadapt flow certify bundle --policy clinical-write   # enforce a safety policy
```

`openadapt flow <verb>` is the recommended path; the standalone `openadapt-flow`
package on PyPI behaves identically. Compiled workflows can also be emitted as
Agent Skills or MCP servers so other agents can invoke them.

## Maturity

We keep this honest.

- **Web (headless browser) path: usable today.** It runs entirely in CI with no
  OS permissions, and it is the reference backend for the compiler.
- **Desktop, Citrix, and RDP backends: validating with design partners.** These
  adapters are in progress, not yet production paths.
- **ML and training: research.** The demonstration-conditioned model work is a
  research line, not part of the shipping compiler.

## The product

The supported product is the compiler and the governed runtime around it:

| Repository | Role |
|------------|------|
| **[openadapt](https://github.com/OpenAdaptAI/OpenAdapt)** ⭐ | Install + unified CLI (`openadapt flow …`) |
| **[openadapt-flow](https://github.com/OpenAdaptAI/openadapt-flow)** | Demonstration compiler + governed runtime (replay, self-heal, effect-verify, halt-on-ambiguity, policies) |
| **[openadapt-capture](https://github.com/OpenAdaptAI/openadapt-capture)** | Optional native recorder for desktop GUI events |
| **[openadapt-privacy](https://github.com/OpenAdaptAI/openadapt-privacy)** | Optional PII/PHI scrubbing (Presidio-backed) |

## Research (not the product)

These repositories explore whether human demonstrations can improve the accuracy
of general computer-use models. They are **research**, not required to record,
compile, or replay a workflow:

| Repository | Focus |
|------------|-------|
| **[openadapt-ml](https://github.com/OpenAdaptAI/openadapt-ml)** | Training and inference for multimodal GUI-action models |
| **[openadapt-evals](https://github.com/OpenAdaptAI/openadapt-evals)** | Benchmark evaluation for GUI agents |
| **[openadapt-retrieval](https://github.com/OpenAdaptAI/openadapt-retrieval)** | Multimodal demonstration retrieval |
| **[openadapt-grounding](https://github.com/OpenAdaptAI/openadapt-grounding)** | UI element localization / grounding models |

> **[openadapt-agent](https://github.com/OpenAdaptAI/openadapt-agent)** is
> **deprecated** and folding into `openadapt-flow`; its runtime, safety gates,
> and sessions duplicate the governed runtime that now lives in the compiler.
>
> Internal tooling (dev automation, social posts, approval bot, multi-model
> consensus, telemetry, viewer, desktop/tray shells) lives in other
> `openadapt-*` repositories. It supports development and operations and is not
> part of the compiler product.

## Contributing

We welcome contributions. Most product work happens in
[openadapt-flow](https://github.com/OpenAdaptAI/openadapt-flow) and
[openadapt](https://github.com/OpenAdaptAI/OpenAdapt).

1. [Join Discord](https://discord.gg/yF527cQbDG)
2. Pick an issue from the relevant repository
3. Submit a PR (see each repository's CONTRIBUTING.md)

## Project status

OpenAdapt is in **active development**. The web compiler path is usable today;
desktop/Citrix/RDP backends are validating with design partners; the ML line is
research. See the [website](https://openadapt.ai/) for current benchmarks and
limits.

## Enterprise and support

Professional implementation and design-partner engagements are available.
Contact info@openadapt.ai, or support development via
[GitHub Sponsors](https://github.com/sponsors/OpenAdaptAI).

## License

All OpenAdapt.AI repositories are licensed under the MIT License unless otherwise
specified. See individual repository LICENSE files for details.
