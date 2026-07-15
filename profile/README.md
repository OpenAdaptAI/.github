# OpenAdapt.AI

**Compile repeated GUI work into deterministic, governed workflows.**

OpenAdapt compiles demonstrated GUI workflows into deterministic, locally
executable programs. Healthy runs make no model calls. When interfaces drift,
OpenAdapt re-resolves from retained evidence or proposes a governed repair and
halts when verification fails.

The launch path is browser automation, available locally or through OpenAdapt
Cloud. Cloud checkout uses the product and price configured in Stripe rather
than a duplicated amount in this profile. Native desktop and remote-display
backends remain experimental and are not included by implication.

- **Install and unified CLI:** [OpenAdapt](https://github.com/OpenAdaptAI/OpenAdapt)
- **Canonical engine:** [openadapt-flow](https://github.com/OpenAdaptAI/openadapt-flow)
- **Website:** [openadapt.ai](https://openadapt.ai/)
- **Documentation:** [docs.openadapt.ai](https://docs.openadapt.ai)
- **Known limits:** [openadapt-flow/LIMITS.md](https://github.com/OpenAdaptAI/openadapt-flow/blob/main/docs/LIMITS.md)

## Try the Proven Path

```bash
pip install openadapt

openadapt flow demo-record --out rec
openadapt flow compile rec --out bundle --name mockmed-triage
openadapt flow certify bundle --policy permissive
openadapt flow replay bundle --run-dir run-baseline
openadapt flow replay bundle --drift theme --run-dir run-drift \
  --save-healed-to bundle-healed
```

The bundled MockMed demo is reproducible and writes an illustrated `REPORT.md`
for each run. The drift run demonstrates bounded deterministic re-resolution;
it is not a claim that arbitrary UI changes can be repaired.

Run the deployment gates separately:

```bash
openadapt flow lint bundle
openadapt flow certify bundle --policy clinical-write
```

Both currently exit nonzero by design. The demo is runnable under the
permissive policy, but the strict clinical-write policy refuses it because its
identity, postcondition, and system-of-record effect coverage is incomplete.
A policy pass means only that the bundle satisfies that named policy.

For the hosted path, create a sanitized derivative locally, review it, approve
its exact archive hash, and upload only those frozen bytes:

```bash
openadapt flow sanitize rec --kind recording --out rec-sanitized
openadapt flow review-sanitized rec-sanitized --original rec
openadapt flow approve-sanitized rec-sanitized --original rec --reviewer "$USER"
openadapt flow login --token oai_ingest_...
openadapt flow push rec-sanitized --kind recording
```

That recording push registers the approved source provenance; it is not yet a
runnable hosted workflow. Continue with local compile, strict lint,
certification, successful replay, bundle sanitation/approval,
`validate-hosted`, and the attested bundle push in the
[hosted browser guide](https://docs.openadapt.ai/guides/hosted/).

Sanitizing a design-time artifact does not sanitize live execution. Runtime
screens and observations can contain PHI again and must stay inside the declared
managed, customer-controlled, or on-prem execution boundary.

## Product Maturity

| Capability | Lifecycle | What that means today |
|------------|-----------|-----------------------|
| Browser record, compile, lint, certify, replay | **Beta** | Canonical end-to-end path; exercised in CI and against a bounded third-party workflow |
| `OpenAdapt` installer and unified CLI | **Beta** | Launcher/meta-package for `openadapt-flow`, not a separate engine |
| Native capture and privacy packages | **Experimental** | Optional components; install only when needed |
| Desktop authoring UI and native backends | **Experimental** | Active integration work, not a production path |
| RDP and Citrix-style pixel backends | **Research spike** | Mocked/offline evidence only; no validated Citrix integration |
| Hosted browser control plane and execution | **Beta** | Account, configured Stripe checkout, sanitized ingest, real runner dispatch, authenticated callbacks, structural reports, validated replacement activation, and usage; authoring and repair remain local, with no implied SLA or regulated certification |
| ML training, retrieval, grounding, and agent evals | **Research** | Separate research line; not required to compile or replay workflows |

Runnable is not the same as certified safe. Identity checks cover only armed
steps, screen postconditions do not prove a consequential write committed, and
effect verification requires an application-specific system-of-record verifier.
The engine publishes these gaps rather than hiding them.

## Repository Map

### Active Product

| Repository | Lifecycle | Role |
|------------|-----------|------|
| **[OpenAdapt](https://github.com/OpenAdaptAI/OpenAdapt)** | **Beta** | High-visibility install, unified CLI, compatibility meta-package |
| **[openadapt-flow](https://github.com/OpenAdaptAI/openadapt-flow)** | **Beta** | Canonical compiler and governed runtime |
| **[openadapt-cloud](https://github.com/OpenAdaptAI/openadapt-cloud)** | **Beta** | Hosted browser-workflow control plane, execution, billing, structural reports, and validated replacement activation |
| **[openadapt-desktop](https://github.com/OpenAdaptAI/openadapt-desktop)** | **Experimental** | Desktop authoring and teaching surface under active integration |

### Optional Supporting Components

| Repository | Lifecycle | Role |
|------------|-----------|------|
| [openadapt-capture](https://github.com/OpenAdaptAI/openadapt-capture) | **Experimental** | Native event and media capture |
| [openadapt-privacy](https://github.com/OpenAdaptAI/openadapt-privacy) | **Experimental** | PII/PHI scrubbing |
| [openadapt-types](https://github.com/OpenAdaptAI/openadapt-types) | **Experimental** | Shared interoperability schemas |

### Research, History, and Internal Tools

- **Research:** `openadapt-ml`, `openadapt-evals`, `openadapt-retrieval`, and
  `openadapt-grounding` study general computer-use agents and supporting models.
- **Deprecated:** `openadapt-agent` has been superseded by the governed runtime
  in `openadapt-flow`; new integrations should not target it.
- **Historical:** the pre-1.0 monolith is frozen under `OpenAdapt/legacy`.
- **Internal tooling:** Wright, Herald, Crier, Consilium, Presenter, telemetry,
  viewer, and repository-operations projects support the team; they are not
  product dependencies.
- **Labs/forks:** OmniMCP, SoM, and PydanticPrompt are adjacent experiments;
  Labs does not mean deprecated.
- **Historical/superseded:** OpenAdapter and OpenReflector represent earlier
  product directions; OpenSanitizer was superseded by `openadapt-privacy`.
  None is a supported product surface today.

See the checked-in
[repository lifecycle registry](https://github.com/OpenAdaptAI/.github/blob/main/REPOSITORY_LIFECYCLE.md)
for status definitions and the public retirement queue.

## Contributing and Enterprise Work

Product-engine contributions belong in
[openadapt-flow](https://github.com/OpenAdaptAI/openadapt-flow); launcher and
packaging changes belong in [OpenAdapt](https://github.com/OpenAdaptAI/OpenAdapt).
Research repositories maintain their own scopes.

Hosted browser subscriptions and scoped enterprise deployments are available at
[openadapt.ai](https://openadapt.ai/). Checkout does not itself promise a
service level, regulated certification, or support for experimental backends.

Unless a repository says otherwise, OpenAdapt.AI code is MIT licensed.
