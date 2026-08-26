# OpenAdaptAI Organization Configuration

This repository owns the public organization profile, lifecycle registry, and
the intended GitHub metadata for the repositories presented as the product. It
does not change GitHub organization settings automatically.

The durable cross-repository launch acceptance contract is maintained in
[LAUNCH_PLAN.md](LAUNCH_PLAN.md). Current execution state belongs in the
workspace `STATUS.md`, not in this public repository.

## Manual GitHub Actions

Organization owners should apply these settings after this branch is merged:

1. Set the organization description to the `organization_description` value in
   [`repository-lifecycle.yml`](repository-lifecycle.yml).
2. Apply the exact `repository_descriptions` values from that file. They keep
   the Desktop, native Capture, and agent-bridge descriptions aligned with the
   lifecycle registry.
3. Pin the exact `pinned_repositories` list. It keeps the 1.6k+ stars correctly
   attached to the overall `OpenAdapt` project while putting the canonical
   engine and Desktop cockpit beside it.
4. The Cloud implementation repository is private and cannot be a public
   organization pin. The documentation implementation is a public Support
   repository and remains reachable through the docs link instead of occupying
   a product pin.
5. Apply the archive queue in
   [REPOSITORY_LIFECYCLE.md](REPOSITORY_LIFECYCLE.md) only after each repository
   has an archive notice and any dirty local work is preserved.

Organization descriptions, repository descriptions, and pins are GitHub
settings. Editing `profile/README.md` does not change them; an organization
owner must apply the machine-readable values after merge.
