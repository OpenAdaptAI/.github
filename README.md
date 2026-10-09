# OpenAdaptAI organization configuration

This repository holds the public organization profile, the repository
lifecycle registry, and the GitHub settings that visitors see for each
repository. The profile in [`profile/README.md`](profile/README.md) goes live
when a change merges. The GitHub settings don't: an organization owner applies
them.

The durable cross-repository launch acceptance contract is maintained in
[LAUNCH_PLAN.md](LAUNCH_PLAN.md). Current execution state belongs in the
workspace `STATUS.md`, not in this public repository.

## Apply the GitHub settings after a merge

[`repository-lifecycle.yml`](repository-lifecycle.yml) is the source of truth
for the organization description and website, the profile headline, the
pinned repositories, and each listed repository's description, website, and
topics. [`scripts/check_profile.py`](scripts/check_profile.py) checks these
values on every pull request.

An organization owner applies them:

1. Review the exact commands. Run `.overhaul/APPLY.sh`. This dry run prints
   each `gh` command and its request body, and it doesn't call GitHub.
2. Apply them. Run `.overhaul/APPLY.sh --apply`. It needs `gh` signed in as an
   owner of the organization, with the `admin:org` and `repo` scopes. It
   changes nothing if the account isn't an owner. After the changes, it reads
   every value back from GitHub and lists each one that differs.
3. Pin the repositories by hand, in the order that `pinned_repositories`
   lists them. GitHub has no API for organization pins.
4. Confirm. Run `.overhaul/APPLY.sh --verify`. It exits 0 only when every
   value on GitHub matches the registry, and 2 when only the pins are left.

After you edit the registry, render the script again. The profile check fails
until the script matches the registry.

```bash
python3 scripts/github_metadata.py render-apply --output .overhaul/APPLY.sh
```

The Cloud source repository is private, so it can't be a public pin. The
documentation source, `openadapt-ops`, is a public Support repository that the
profile links instead of pinning. Each repository's social preview image is
also set by hand, in that repository's settings.

Apply the archive queue in [REPOSITORY_LIFECYCLE.md](REPOSITORY_LIFECYCLE.md)
only after each repository has an archive notice and any uncommitted local work
is preserved.
