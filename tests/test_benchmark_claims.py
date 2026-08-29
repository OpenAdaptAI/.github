"""Fail-closed tests for the published-benchmark-figure binding."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_benchmark_claims as claims  # noqa: E402

SURFACE = "profile/README.md"
SNAPSHOT = "benchmark-claims/upstream/example/results.json"
ARTIFACT = {"arms": {"compiled": {"n": 20, "success_count": 19, "wall_s_p50": 39.17}}}


def digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def run(root: Path, *arguments: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = claims.main(["--root", str(root), *arguments])
    return code, out.getvalue(), err.getvalue()


def synthetic_registry() -> dict:
    payload = json.dumps(ARTIFACT, indent=2).encode() + b"\n"
    return {
        "$comment": "A synthetic fixture used only by the tests.",
        "schema_version": claims.REGISTRY_SCHEMA,
        "upstream": {
            "repository": "OpenAdaptAI/openadapt-flow",
            "commit": "a" * 40,
            "sources": [
                {
                    "id": "example",
                    "path": "benchmark/example/results.json",
                    "git_blob": "b" * 40,
                    "sha256": digest(payload),
                    "size_bytes": len(payload),
                    "snapshot": SNAPSHOT,
                }
            ],
        },
        "surfaces": [SURFACE],
        "claims": [
            {
                "id": "example-compiled-success",
                "surface": SURFACE,
                "context": "compiled replay went 19/20 on the demo.",
                "text": "19/20",
                "renderer": "ratio",
                "decimals": None,
                "source": "example",
                "pointers": [
                    "/arms/compiled/success_count",
                    "/arms/compiled/n",
                ],
                "status": "bound",
                "drift": None,
            }
        ],
        "non_benchmark_figures": [],
    }


class Fixture:
    """A throwaway repository holding one surface and one pinned artifact."""

    def __init__(self, directory: str) -> None:
        self.root = Path(directory)
        self.registry = synthetic_registry()
        self.surface_text = (
            "# Example\n\nThe compiled replay went 19/20 on the demo.\n"
        )

    def write(self) -> Path:
        payload = json.dumps(ARTIFACT, indent=2).encode() + b"\n"
        snapshot = self.root / SNAPSHOT
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(payload)
        surface = self.root / SURFACE
        surface.parent.mkdir(parents=True, exist_ok=True)
        surface.write_text(self.surface_text, encoding="utf-8")
        (self.root / "benchmark-claims.json").write_text(
            json.dumps(self.registry, indent=2) + "\n", encoding="utf-8"
        )
        return self.root


class RendererTests(unittest.TestCase):
    def test_every_renderer_matches_the_way_a_front_page_writes_it(self) -> None:
        self.assertEqual(claims.render("ratio", [19, 20], None), "19/20")
        self.assertEqual(claims.render("count_of", [54, 90], None), "54 of 90")
        self.assertEqual(claims.render("percent", [0.75], 1), "75.0%")
        self.assertEqual(claims.render("percent", [0.0], 0), "0%")
        self.assertEqual(claims.render("seconds", [39.170917561999886], 1), "39.2s")
        self.assertEqual(claims.render("usd", [0.552150765], 2), "$0.55")
        self.assertEqual(claims.render("integer", [18], None), "18")

    def test_a_boolean_is_not_a_measurement(self) -> None:
        with self.assertRaises(TypeError):
            claims.render("ratio", [True, 20], None)
        with self.assertRaises(TypeError):
            claims.render("percent", [True], 1)

    def test_every_renderer_is_reachable_from_the_pointer_contract(self) -> None:
        self.assertEqual(set(claims.RENDERERS), set(claims.POINTER_COUNTS))


class PointerTests(unittest.TestCase):
    def test_an_unbound_pointer_raises_instead_of_returning_none(self) -> None:
        with self.assertRaises(KeyError):
            claims.resolve_pointer(ARTIFACT, "/arms/compiled/missing")
        with self.assertRaises(KeyError):
            claims.resolve_pointer(ARTIFACT, "/arms/compiled/n/deeper")

    def test_a_list_index_resolves(self) -> None:
        self.assertEqual(claims.resolve_pointer({"a": [7, 8]}, "/a/1"), 8)


class SyntheticGuardTests(unittest.TestCase):
    def build(self, mutate=None) -> Path:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        fixture = Fixture(directory)
        if mutate is not None:
            mutate(fixture)
        return fixture.write()

    def test_a_faithful_surface_passes(self) -> None:
        code, out, _ = run(self.build())
        self.assertEqual(code, 0)
        self.assertIn("Bound 1 published figures", out)

    def test_an_edited_snapshot_cannot_bless_a_figure(self) -> None:
        root = self.build()
        snapshot = root / SNAPSHOT
        snapshot.write_bytes(snapshot.read_bytes().replace(b"19", b"20"))
        code, _, err = run(root)
        self.assertEqual(code, 1)
        self.assertIn("has digest", err)
        self.assertIn("the registry pins", err)

    def test_an_unregistered_figure_fails_closed(self) -> None:
        def mutate(fixture: Fixture) -> None:
            fixture.surface_text += "\nA later edit added 7/8 and nobody bound it.\n"

        code, _, err = run(self.build(mutate))
        self.assertEqual(code, 1)
        self.assertIn("'7/8' is not claimed by any", err)

    def test_a_wrong_published_figure_fails(self) -> None:
        def mutate(fixture: Fixture) -> None:
            fixture.surface_text = fixture.surface_text.replace("19/20", "20/20")
            claim = fixture.registry["claims"][0]
            claim["context"] = claim["context"].replace("19/20", "20/20")
            claim["text"] = "20/20"

        code, _, err = run(self.build(mutate))
        self.assertEqual(code, 1)
        self.assertIn("publishes '20/20'", err)
        self.assertIn("renders '19/20'", err)

    def test_every_sweep_pattern_is_caught_when_unregistered(self) -> None:
        for figure in ("7/8", "12.5%", "$3.10", "4.9s", "9 of 90"):
            with self.subTest(figure=figure):

                def mutate(fixture: Fixture, figure: str = figure) -> None:
                    fixture.surface_text += f"\nAn unbound {figure} slipped in.\n"

                code, _, err = run(self.build(mutate))
                self.assertEqual(code, 1)
                self.assertIn(f"{figure!r} is not claimed", err)

    def test_an_exemption_covers_a_non_benchmark_figure(self) -> None:
        def mutate(fixture: Fixture) -> None:
            fixture.surface_text += "\nThe launcher pins version 2/3 of the schema.\n"
            fixture.registry["non_benchmark_figures"].append(
                {
                    "id": "schema-version-fragment",
                    "surface": SURFACE,
                    "context": "pins version 2/3 of the schema",
                    "text": "2/3",
                    "reason": "A schema version, not a measured benchmark result.",
                }
            )

        code, out, _ = run(self.build(mutate))
        self.assertEqual(code, 0)
        self.assertIn("Bound 2 published figures", out)

    def test_a_stale_exemption_does_not_rot_in_place(self) -> None:
        def mutate(fixture: Fixture) -> None:
            fixture.registry["non_benchmark_figures"].append(
                {
                    "id": "removed-version-fragment",
                    "surface": SURFACE,
                    "context": "pins version 2/3 of the schema",
                    "text": "2/3",
                    "reason": "A schema version, not a measured benchmark result.",
                }
            )

        code, _, err = run(self.build(mutate))
        self.assertEqual(code, 1)
        self.assertIn("appears 0 times", err)

    def test_an_ambiguous_context_is_refused(self) -> None:
        def mutate(fixture: Fixture) -> None:
            fixture.surface_text += "\nThe compiled replay went 19/20 on the demo.\n"

        code, _, err = run(self.build(mutate))
        self.assertEqual(code, 1)
        self.assertIn("appears 2 times", err)


class RecordedDriftTests(unittest.TestCase):
    def build(self, mutate=None) -> Path:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        fixture = Fixture(directory)
        fixture.surface_text = fixture.surface_text.replace("19/20", "20/20")
        claim = fixture.registry["claims"][0]
        claim["context"] = claim["context"].replace("19/20", "20/20")
        claim["text"] = "20/20"
        claim["status"] = "drift_open"
        claim["drift"] = {
            "upstream_text": "19/20",
            "recorded_on": "2026-08-28",
            "expires_on": "2026-09-25",
            "owner": "the agent that owns org front-page corrections",
            "reason": (
                "The published figure is wrong and the correction is tracked "
                "elsewhere; this guard reports it rather than editing the prose."
            ),
        }
        if mutate is not None:
            mutate(fixture)
        return fixture.write()

    def test_a_recorded_drift_fails_by_default(self) -> None:
        code, _, err = run(self.build(), "--today", "2026-08-28")
        self.assertEqual(code, 1)
        self.assertIn("DRIFT:", err)
        self.assertIn("--allow-recorded-drift", err)

    def test_a_recorded_drift_is_always_printed_even_when_allowed(self) -> None:
        code, out, err = run(
            self.build(), "--today", "2026-08-28", "--allow-recorded-drift"
        )
        self.assertEqual(code, 0)
        self.assertIn("DRIFT:", err)
        self.assertIn("1 dated drift record(s) still open", out)

    def test_an_expired_drift_fails_even_when_allowed(self) -> None:
        code, _, err = run(
            self.build(), "--today", "2026-09-26", "--allow-recorded-drift"
        )
        self.assertEqual(code, 1)
        self.assertIn("expired on 2026-09-25", err)

    def test_a_drift_that_no_longer_drifts_must_be_promoted(self) -> None:
        def mutate(fixture: Fixture) -> None:
            fixture.surface_text = fixture.surface_text.replace("20/20", "19/20")
            claim = fixture.registry["claims"][0]
            claim["context"] = claim["context"].replace("20/20", "19/20")
            claim["text"] = "19/20"

        code, _, err = run(
            self.build(mutate), "--today", "2026-08-28", "--allow-recorded-drift"
        )
        self.assertEqual(code, 1)
        self.assertIn("Change status to 'bound'", err)

    def test_a_changed_artifact_invalidates_the_drift_record(self) -> None:
        def mutate(fixture: Fixture) -> None:
            fixture.registry["claims"][0]["drift"]["upstream_text"] = "18/20"

        code, _, err = run(
            self.build(mutate), "--today", "2026-08-28", "--allow-recorded-drift"
        )
        self.assertEqual(code, 1)
        self.assertIn("Re-adjudicate the drift", err)

    def test_a_drift_may_not_run_without_an_end(self) -> None:
        def mutate(fixture: Fixture) -> None:
            fixture.registry["claims"][0]["drift"]["expires_on"] = "2027-08-28"

        code, _, err = run(
            self.build(mutate), "--today", "2026-08-28", "--allow-recorded-drift"
        )
        self.assertEqual(code, 1)
        self.assertIn(f"more than {claims.MAX_DRIFT_DAYS} days", err)


class RegistryShapeTests(unittest.TestCase):
    def load(self, mutate) -> None:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        fixture = Fixture(directory)
        mutate(fixture)
        root = fixture.write()
        with self.assertRaises(claims.RegistryError):
            claims.load_registry(root / "benchmark-claims.json")

    def test_an_unknown_top_level_key_is_refused(self) -> None:
        self.load(lambda fixture: fixture.registry.update({"extra": True}))

    def test_a_missing_comment_is_refused(self) -> None:
        self.load(lambda fixture: fixture.registry.update({"$comment": "  "}))

    def test_a_short_commit_is_refused(self) -> None:
        self.load(lambda fixture: fixture.registry["upstream"].update({"commit": "aee0941"}))

    def test_a_snapshot_outside_the_vendored_tree_is_refused(self) -> None:
        self.load(
            lambda fixture: fixture.registry["upstream"]["sources"][0].update(
                {"snapshot": "../escape.json"}
            )
        )

    def test_a_claim_naming_an_unregistered_surface_is_refused(self) -> None:
        self.load(
            lambda fixture: fixture.registry["claims"][0].update({"surface": "OTHER.md"})
        )

    def test_a_claim_naming_an_unknown_source_is_refused(self) -> None:
        self.load(
            lambda fixture: fixture.registry["claims"][0].update({"source": "nowhere"})
        )

    def test_a_ratio_needs_two_pointers(self) -> None:
        self.load(
            lambda fixture: fixture.registry["claims"][0].update(
                {"pointers": ["/arms/compiled/success_count"]}
            )
        )

    def test_a_bound_claim_may_not_carry_a_drift(self) -> None:
        self.load(
            lambda fixture: fixture.registry["claims"][0].update(
                {"drift": {"upstream_text": "19/20"}}
            )
        )

    def test_a_context_that_omits_its_text_is_refused(self) -> None:
        self.load(
            lambda fixture: fixture.registry["claims"][0].update(
                {"context": "no figure here"}
            )
        )

    def test_an_exemption_without_a_reason_is_refused(self) -> None:
        self.load(
            lambda fixture: fixture.registry["non_benchmark_figures"].append(
                {
                    "id": "thin",
                    "surface": SURFACE,
                    "context": "19/20",
                    "text": "19/20",
                    "reason": "no",
                }
            )
        )


class OnlineTests(unittest.TestCase):
    def registry(self) -> dict:
        return copy.deepcopy(synthetic_registry())

    def test_an_unreachable_github_warns_and_does_not_fail(self) -> None:
        errors: list[str] = []
        warnings: list[str] = []
        with mock.patch.object(
            claims, "fetch", side_effect=urllib.error.URLError("down")
        ):
            verified = claims.check_online(self.registry(), errors, warnings)
        self.assertEqual(verified, 0)
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("unreachable", warnings[0])

    def test_a_timeout_warns_and_does_not_fail(self) -> None:
        errors: list[str] = []
        warnings: list[str] = []
        with mock.patch.object(claims, "fetch", side_effect=TimeoutError("slow")):
            claims.check_online(self.registry(), errors, warnings)
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)

    def test_a_digest_mismatch_fails(self) -> None:
        errors: list[str] = []
        warnings: list[str] = []
        with mock.patch.object(claims, "fetch", return_value=b"different bytes"):
            claims.check_online(self.registry(), errors, warnings)
        self.assertEqual(warnings, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("no longer describes the upstream bytes", errors[0])

    def test_a_matching_fetch_verifies(self) -> None:
        errors: list[str] = []
        warnings: list[str] = []
        payload = json.dumps(ARTIFACT, indent=2).encode() + b"\n"
        with mock.patch.object(claims, "fetch", return_value=payload) as fetched:
            verified = claims.check_online(self.registry(), errors, warnings)
        self.assertEqual((verified, errors, warnings), (1, [], []))
        self.assertEqual(
            fetched.call_args.args[0],
            f"{claims.RAW_GITHUB_ORIGIN}/OpenAdaptAI/openadapt-flow/"
            f"{'a' * 40}/benchmark/example/results.json",
        )


class PublishedRegistryTests(unittest.TestCase):
    def copy_repository(self) -> Path:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        root = Path(directory)
        shutil.copytree(ROOT / "benchmark-claims", root / "benchmark-claims")
        shutil.copy2(ROOT / "benchmark-claims.json", root / "benchmark-claims.json")
        registry = json.loads((ROOT / "benchmark-claims.json").read_text())
        for surface in registry["surfaces"]:
            target = root / surface
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / surface, target)
        return root

    def test_the_published_registry_is_structurally_valid(self) -> None:
        registry = claims.load_registry(ROOT / "benchmark-claims.json")
        self.assertEqual(registry["upstream"]["repository"], "OpenAdaptAI/openadapt-flow")
        self.assertTrue(registry["claims"])

    def test_every_published_figure_is_bound_or_recorded(self) -> None:
        code, out, _ = run(ROOT, "--allow-recorded-drift")
        self.assertEqual(code, 0)
        self.assertIn("Bound 17 published figures", out)

    def test_the_published_surfaces_cover_both_front_pages(self) -> None:
        registry = claims.load_registry(ROOT / "benchmark-claims.json")
        self.assertEqual(set(registry["surfaces"]), {"README.md", "profile/README.md"})

    def test_every_open_drift_states_who_fixes_it_and_by_when(self) -> None:
        registry = claims.load_registry(ROOT / "benchmark-claims.json")
        for claim in registry["claims"]:
            if claim["status"] != "drift_open":
                continue
            drift = claim["drift"]
            self.assertTrue(drift["owner"].strip(), claim["id"])
            self.assertGreater(len(drift["reason"]), 80, claim["id"])
            self.assertLessEqual(
                (
                    date.fromisoformat(drift["expires_on"])
                    - date.fromisoformat(drift["recorded_on"])
                ).days,
                claims.MAX_DRIFT_DAYS,
                claim["id"],
            )

    def test_a_new_unregistered_figure_on_a_real_surface_fails(self) -> None:
        root = self.copy_repository()
        surface = root / "README.md"
        surface.write_text(
            surface.read_text(encoding="utf-8")
            + "\nAn unbound compiled replay went 19/20.\n",
            encoding="utf-8",
        )
        code, _, err = run(root, "--allow-recorded-drift")
        self.assertEqual(code, 1)
        self.assertIn("README.md: the figure '19/20' is not claimed", err)

    def test_a_tampered_published_snapshot_fails(self) -> None:
        root = self.copy_repository()
        registry = json.loads((root / "benchmark-claims.json").read_text())
        snapshot = next(
            root / source["snapshot"]
            for source in registry["upstream"]["sources"]
            if source["id"] == "openemr"
        )
        snapshot.write_bytes(
            snapshot.read_bytes().replace(
                b'"success_count": 19', b'"success_count": 20'
            )
        )
        code, _, err = run(root, "--allow-recorded-drift")
        self.assertEqual(code, 1)
        self.assertIn("snapshot", err)
        self.assertIn("the registry pins", err)

    def test_the_comparison_artifact_must_agree_with_its_sources(self) -> None:
        root = self.copy_repository()
        registry = json.loads((root / "benchmark-claims.json").read_text())
        source = next(
            item for item in registry["upstream"]["sources"] if item["id"] == "comparison"
        )
        snapshot = root / source["snapshot"]
        document = json.loads(snapshot.read_text(encoding="utf-8"))
        document["benchmarks"]["openemr"]["arms"]["compiled"]["success_count"] = 20
        payload = json.dumps(document, indent=2).encode() + b"\n"
        snapshot.write_bytes(payload)
        source["sha256"] = digest(payload)
        source["size_bytes"] = len(payload)
        (root / "benchmark-claims.json").write_text(
            json.dumps(registry, indent=2) + "\n", encoding="utf-8"
        )
        code, _, err = run(root, "--allow-recorded-drift")
        self.assertEqual(code, 1)
        self.assertIn("openemr compiled success_count", err)


class WorkflowWiringTests(unittest.TestCase):
    def workflow(self) -> str:
        return (ROOT / ".github" / "workflows" / "profile-consistency.yml").read_text(
            encoding="utf-8"
        )

    def test_the_offline_half_runs_on_every_pull_request(self) -> None:
        content = self.workflow()
        job = content.split("  validate-profile:", 1)[1].split("\n  report-", 1)[0]
        self.assertIn("scripts/check_benchmark_claims.py", job)

    def test_the_online_half_runs_only_on_the_daily_schedule(self) -> None:
        content = self.workflow()
        step = content.split(
            "      - name: Re-fetch the pinned benchmark artifacts\n", 1
        )[1].split("      - name:", 1)[0]
        self.assertIn("--online", step)
        self.assertIn("github.event_name == 'schedule'", step)

    def test_profile_test_dependency_install_is_exact_and_pinned(self) -> None:
        content = self.workflow()
        install = (
            "python3 -m pip install --requirement "
            "requirements/profile-consistency.txt"
        )
        self.assertEqual(content.count("pip install"), 1)
        self.assertIn(install, content)
        self.assertNotIn("pip install --upgrade", content)
        requirements = (
            ROOT / "requirements" / "profile-consistency.txt"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            requirements.splitlines(),
            [
                "cryptography==43.0.3",
                "jsonschema==4.23.0",
                "referencing==0.30.2",
            ],
        )


if __name__ == "__main__":
    unittest.main()
