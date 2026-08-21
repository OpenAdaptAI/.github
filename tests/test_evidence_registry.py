"""Fail-closed tests for the content-addressed evidence registry."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import validate_evidence_registry as registry  # noqa: E402


def make_entry(sequence: int = 1, prior: str | None = None, **overrides) -> dict:
    entry = registry.build_entry(
        sequence=sequence,
        kind=overrides.pop("kind", "evidence-summary"),
        url=overrides.pop(
            "url", "https://evidence.openadapt.ai/objects/" + "a" * 64 + "/summary.json"
        ),
        sha256=overrides.pop("sha256", "sha256:" + "b" * 64),
        size_bytes=overrides.pop("size_bytes", 128),
        recorded_at=overrides.pop("recorded_at", "2026-08-21T00:00:00.000Z"),
        prior_entry_sha256=prior,
    )
    entry.update(overrides)
    return entry


def wrap(entries: list[dict]) -> dict:
    head = entries[-1]["entry_sha256"] if entries else None
    return {
        "$schema": "schemas/evidence-registry.schema.json",
        "schema_version": registry.REGISTRY_SCHEMA,
        "head_entry_sha256": head,
        "entries": entries,
    }


class EvidenceRegistryTests(unittest.TestCase):
    def test_empty_registry_is_valid(self) -> None:
        self.assertEqual(registry.validate_registry(wrap([])), [])

    def test_chained_entries_are_valid(self) -> None:
        first = make_entry(1, None)
        second = make_entry(2, first["entry_sha256"])
        third = make_entry(3, second["entry_sha256"], kind="attestation-bundle")
        result = registry.validate_registry(wrap([first, second, third]))
        self.assertEqual(len(result), 3)

    def test_broken_chain_is_refused(self) -> None:
        first = make_entry(1, None)
        second = make_entry(2, "sha256:" + "0" * 64)
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "chain"):
            registry.validate_registry(wrap([first, second]))

    def test_stale_head_is_refused(self) -> None:
        first = make_entry(1, None)
        document = wrap([first])
        document["head_entry_sha256"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "head"):
            registry.validate_registry(document)

    def test_sequence_gap_is_refused(self) -> None:
        first = make_entry(1, None)
        second = make_entry(3, first["entry_sha256"])
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "sequence"):
            registry.validate_registry(wrap([first, second]))

    def test_tampered_digest_breaks_the_chain(self) -> None:
        first = make_entry(1, None)
        tampered = dict(first)
        tampered["sha256"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "chained digest"):
            registry.validate_registry(wrap([tampered]))

    def test_non_https_url_is_refused(self) -> None:
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "HTTPS"):
            make_entry(1, None, url="http://evidence.openadapt.ai/summary.json")

    def test_unsupported_kind_is_refused(self) -> None:
        entry = make_entry(1, None)
        entry["kind"] = "screenshot"
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "kind"):
            registry.validate_registry(wrap([entry]))

    def test_closed_schema_refuses_extra_fields(self) -> None:
        document = wrap([make_entry(1, None)])
        document["extra"] = True
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "unexpected"):
            registry.validate_registry(document)

    def test_require_registered_matches_exact_pair(self) -> None:
        entry = make_entry(1, None)
        entries = registry.validate_registry(wrap([entry]))
        registry.require_registered(
            entries,
            url=entry["url"],
            sha256=entry["sha256"],
            kind="evidence-summary",
            label="case summary",
        )
        with self.assertRaisesRegex(
            registry.EvidenceRegistryError, "not registered"
        ):
            registry.require_registered(
                entries,
                url=entry["url"],
                sha256="sha256:" + "9" * 64,
                kind="evidence-summary",
                label="case summary",
            )
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "kind"):
            registry.require_registered(
                entries,
                url=entry["url"],
                sha256=entry["sha256"],
                kind="attestation-bundle",
                label="case bundle",
            )

    def test_rewritten_history_is_refused(self) -> None:
        first = make_entry(1, None)
        second = make_entry(2, first["entry_sha256"])
        rewritten_first = dict(first)
        rewritten_first["recorded_at"] = "2026-08-20T00:00:00.000Z"
        # Rebuilding history from the edited first entry produces a different
        # chained digest than the recorded one.
        forged_second = registry.build_entry(
            sequence=2,
            kind="evidence-summary",
            url=second["url"],
            sha256=second["sha256"],
            size_bytes=second["size_bytes"],
            recorded_at=second["recorded_at"],
            prior_entry_sha256=rewritten_first["entry_sha256"],
        )
        document = wrap([rewritten_first, forged_second])
        with self.assertRaisesRegex(registry.EvidenceRegistryError, "chained digest"):
            registry.validate_registry(document)

    def test_repository_file_is_valid_and_empty(self) -> None:
        raw = (ROOT / "evidence-registry.json").read_text(encoding="utf-8")
        value = json.loads(raw)
        self.assertEqual(value["entries"], [])
        self.assertIsNone(value["head_entry_sha256"])
        registry.validate_registry(copy.deepcopy(value))


if __name__ == "__main__":
    unittest.main()
