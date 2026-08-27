"""Tests for qualification worker task and condition identities."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import qualification_worker_task_contract as task_contract


def sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def selector() -> dict:
    value = {
        "schema_version": task_contract.TASK_SELECTOR_SCHEMA,
        "campaign_artifact_sha256": sha("campaign"),
        "task_source_sha256": sha("private-task-source"),
        "task_ordinal": 7,
        "task_id_sha256": sha("pending-task"),
    }
    value["task_id_sha256"] = task_contract.digest(
        task_contract.TASK_SELECTOR_DOMAIN,
        task_contract.task_selector_projection(value),
    )
    return value


def condition(task: dict | None = None) -> dict:
    selected_task = selector() if task is None else task
    value = {
        "schema_version": task_contract.TASK_CONDITION_SCHEMA,
        "task_id_sha256": selected_task["task_id_sha256"],
        "condition_source_sha256": sha("private-condition-source"),
        "condition_ordinal": 3,
        "task_condition_sha256": sha("pending-condition"),
    }
    value["task_condition_sha256"] = task_contract.digest(
        task_contract.TASK_CONDITION_DOMAIN,
        task_contract.task_condition_projection(value),
    )
    return value


def schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text())


class QualificationWorkerTaskContractTests(unittest.TestCase):
    def test_domains_projections_and_digests_are_frozen(self) -> None:
        selected_task = selector()
        selected_condition = condition(selected_task)
        self.assertEqual(
            task_contract.TASK_SELECTOR_DOMAIN,
            b"OpenAdapt qualification worker task selector v1\0",
        )
        self.assertEqual(
            task_contract.TASK_CONDITION_DOMAIN,
            b"OpenAdapt qualification worker task condition v1\0",
        )
        self.assertEqual(
            task_contract.canonical(
                task_contract.task_selector_projection(selected_task)
            ),
            (
                b'{"campaign_artifact_sha256":"sha256:3dc260b2472062d9c57b'
                b'd930b02f23831d917b8f3e3234b6d63964a53c31d3aa","schema_version"'
                b':"openadapt.qualification-worker-task-selector/v1","task_ordinal"'
                b':7,"task_source_sha256":"sha256:8057301060c8a6a36e2b425e4d26'
                b'eb10a6d110cdaffe5c80ebe1c515286c3e17"}'
            ),
        )
        self.assertEqual(
            selected_task["task_id_sha256"],
            "sha256:3e688825cd4e6ce312d15f47ddb1d3fa57441e3b0c3a5ca9ccc2f1f285a52cc7",
        )
        self.assertEqual(
            task_contract.canonical(
                task_contract.task_condition_projection(selected_condition)
            ),
            (
                b'{"condition_ordinal":3,"condition_source_sha256":"sha256:'
                b'b9079b50782122c328dae360cb2d9766601668d1e1842bc4f73d0a0404b'
                b'f38df","schema_version":"openadapt.qualification-worker-task-condition'
                b'/v1","task_id_sha256":"sha256:3e688825cd4e6ce312d15f47ddb1d3'
                b'fa57441e3b0c3a5ca9ccc2f1f285a52cc7"}'
            ),
        )
        self.assertEqual(
            selected_condition["task_condition_sha256"],
            "sha256:e09987d522fd290c2d07994428027bebd5deabcf2156258dd9633a465095b16f",
        )

    def test_closed_objects_validate_and_cross_bind(self) -> None:
        selected_task = selector()
        selected_condition = condition(selected_task)
        self.assertEqual(
            task_contract.validate_task_contract(
                selected_task,
                selected_condition,
                campaign_artifact_sha256=sha("campaign"),
            ),
            (selected_task, selected_condition),
        )
        Draft202012Validator(
            schema("qualification-worker-task-selector.schema.json")
        ).validate(selected_task)
        Draft202012Validator(
            schema("qualification-worker-task-condition.schema.json")
        ).validate(selected_condition)

    def test_task_selector_tamper_is_refused(self) -> None:
        for field, replacement in (
            ("campaign_artifact_sha256", sha("other-campaign")),
            ("task_source_sha256", sha("other-task-source")),
            ("task_ordinal", 8),
        ):
            changed = copy.deepcopy(selector())
            changed[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(
                task_contract.QualificationWorkerTaskContractError,
                "task identity differs",
            ):
                task_contract.validate_task_selector(changed)

    def test_task_condition_tamper_is_refused(self) -> None:
        for field, replacement in (
            ("task_id_sha256", sha("other-task")),
            ("condition_source_sha256", sha("other-condition-source")),
            ("condition_ordinal", 4),
        ):
            changed = copy.deepcopy(condition())
            changed[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(
                task_contract.QualificationWorkerTaskContractError,
                "task condition identity differs",
            ):
                task_contract.validate_task_condition(changed)

    def test_recomputed_cross_contract_substitution_is_refused(self) -> None:
        selected_task = selector()
        different_task = copy.deepcopy(selected_task)
        different_task["task_ordinal"] = 8
        different_task["task_id_sha256"] = task_contract.digest(
            task_contract.TASK_SELECTOR_DOMAIN,
            task_contract.task_selector_projection(different_task),
        )
        substituted = condition(different_task)
        task_contract.validate_task_condition(substituted)
        with self.assertRaisesRegex(
            task_contract.QualificationWorkerTaskContractError,
            "selects a different task identity",
        ):
            task_contract.validate_task_condition_binding(
                selected_task, substituted
            )

        different_campaign = copy.deepcopy(selected_task)
        different_campaign["campaign_artifact_sha256"] = sha("other-campaign")
        different_campaign["task_id_sha256"] = task_contract.digest(
            task_contract.TASK_SELECTOR_DOMAIN,
            task_contract.task_selector_projection(different_campaign),
        )
        different_campaign_condition = condition(different_campaign)
        with self.assertRaisesRegex(
            task_contract.QualificationWorkerTaskContractError,
            "different campaign artifact",
        ):
            task_contract.validate_task_contract(
                different_campaign,
                different_campaign_condition,
                campaign_artifact_sha256=sha("campaign"),
            )

    def test_invalid_digest_ordinal_and_shape_are_refused(self) -> None:
        for invalid in (0, -1, True, "1"):
            changed = selector()
            changed["task_ordinal"] = invalid
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                task_contract.QualificationWorkerTaskContractError,
                "positive integer",
            ):
                task_contract.validate_task_selector(changed)

            changed_condition = condition()
            changed_condition["condition_ordinal"] = invalid
            with self.subTest(condition_invalid=invalid), self.assertRaisesRegex(
                task_contract.QualificationWorkerTaskContractError,
                "positive integer",
            ):
                task_contract.validate_task_condition(changed_condition)

        invalid_digest = selector()
        invalid_digest["task_source_sha256"] = "sha256:" + "A" * 64
        with self.assertRaisesRegex(
            task_contract.QualificationWorkerTaskContractError,
            "lowercase sha256 digest",
        ):
            task_contract.validate_task_selector(invalid_digest)

        extra = condition()
        extra["private_condition"] = "must-not-egress"
        with self.assertRaisesRegex(
            task_contract.QualificationWorkerTaskContractError,
            "must contain exactly",
        ):
            task_contract.validate_task_condition(extra)

    def test_json_schemas_refuse_extra_fields_and_nonpositive_ordinals(self) -> None:
        selector_validator = Draft202012Validator(
            schema("qualification-worker-task-selector.schema.json")
        )
        condition_validator = Draft202012Validator(
            schema("qualification-worker-task-condition.schema.json")
        )

        changed_selector = selector()
        changed_selector["task_ordinal"] = 0
        self.assertTrue(list(selector_validator.iter_errors(changed_selector)))

        changed_condition = condition()
        changed_condition["condition_ordinal"] = True
        self.assertTrue(list(condition_validator.iter_errors(changed_condition)))

        changed_condition = condition()
        changed_condition["raw_condition"] = {"secret": "must-not-egress"}
        self.assertTrue(list(condition_validator.iter_errors(changed_condition)))


if __name__ == "__main__":
    unittest.main()
