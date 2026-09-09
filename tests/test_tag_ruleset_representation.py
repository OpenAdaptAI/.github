"""The two exact GitHub tag update forms preserve the same release controls."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from test_production_trust import rulesets, trust

ROOT = Path(__file__).resolve().parents[1]
EXPLICIT_FALSE = {
    "type": "update",
    "parameters": {"update_allows_fetch_and_merge": False},
}


class TagRulesetRepresentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema = json.loads(
            (ROOT / "schemas/qualification-release.schema.json").read_text()
        )
        cls.validator = Draft202012Validator(
            {
                "$schema": schema["$schema"],
                "$defs": schema["$defs"],
                **schema["$defs"]["publication_staging"]["properties"]["tag_rulesets"],
            }
        )

    def validate_runtime(self, value):
        return trust.validate_tag_rulesets(
            value,
            repository="OpenAdaptAI/openadapt-capture",
            repository_id="1115283835",
        )

    def assert_refused(self, value):
        with self.assertRaises(trust.TrustError):
            self.validate_runtime(value)
        self.assertFalse(self.validator.is_valid(value))

    def test_both_exact_tag_update_forms_preserve_observed_bytes(self) -> None:
        for update in ({"type": "update"}, EXPLICIT_FALSE):
            with self.subTest(update=update):
                value = rulesets()
                value[1]["rules"][2] = copy.deepcopy(update)
                before = json.dumps(value, sort_keys=True).encode()
                digest = trust.digest_bytes(trust.TAG_RULESETS_DOMAIN, value)
                self.assertIs(self.validate_runtime(value), value)
                self.validator.validate(value)
                self.assertEqual(json.dumps(value, sort_keys=True).encode(), before)
                self.assertEqual(
                    trust.digest_bytes(trust.TAG_RULESETS_DOMAIN, value), digest
                )

    def test_update_rule_rejects_non_boolean_false_and_extra_fields(self) -> None:
        invalid = [
            {"type": "update", "parameters": {"update_allows_fetch_and_merge": flag}}
            for flag in (True, None, 0, 1, 0.0, "false", "False", "0", [], {})
        ]
        invalid.extend(
            [
                {"type": "update", "parameters": None},
                {"type": "update", "parameters": {}},
                {"type": "update", "parameters": []},
                {"type": "update", "extra": False},
                {**EXPLICIT_FALSE, "extra": False},
                {
                    "type": "update",
                    "parameters": {
                        "update_allows_fetch_and_merge": False,
                        "extra": False,
                    },
                },
                {"parameters": {"update_allows_fetch_and_merge": False}},
            ]
        )
        for update in invalid:
            with self.subTest(update=update):
                value = rulesets()
                value[1]["rules"][2] = update
                self.assert_refused(value)

    def test_both_forms_keep_all_protection_boundaries(self) -> None:
        for update in ({"type": "update"}, EXPLICIT_FALSE):
            original = rulesets()
            original[1]["rules"][2] = copy.deepcopy(update)
            mutations = [
                ("missing deletion", lambda v: v[1]["rules"].pop(0)),
                ("missing non-fast-forward", lambda v: v[1]["rules"].pop(1)),
                ("missing update", lambda v: v[1]["rules"].pop(2)),
                ("extra rule", lambda v: v[1]["rules"].append({"type": "creation"})),
                (
                    "duplicate update",
                    lambda v: v[1]["rules"].append(copy.deepcopy(v[1]["rules"][2])),
                ),
                ("reordered rules", lambda v: v[1]["rules"].reverse()),
                (
                    "extra deletion field",
                    lambda v: v[1]["rules"][0].update(extra=False),
                ),
                (
                    "immutability bypass",
                    lambda v: v[1]["bypass_actors"].extend(v[0]["bypass_actors"]),
                ),
                ("missing creation authority", lambda v: v[0]["bypass_actors"].clear()),
                (
                    "different creation authority",
                    lambda v: v[0]["bypass_actors"][0].update(actor_id="123"),
                ),
                ("missing creation", lambda v: v[0]["rules"].clear()),
                (
                    "extra creation rule",
                    lambda v: v[0]["rules"].append({"type": "update"}),
                ),
                ("branch target", lambda v: v[1].update(target="branch")),
                ("inactive ruleset", lambda v: v[1].update(enforcement="disabled")),
                (
                    "wider tag scope",
                    lambda v: v[1]["conditions"]["ref_name"].update(
                        include=["refs/tags/*"]
                    ),
                ),
                (
                    "excluded tag",
                    lambda v: v[1]["conditions"]["ref_name"].update(
                        exclude=["refs/tags/v1.0.0"]
                    ),
                ),
                ("extra ruleset", lambda v: v.append(copy.deepcopy(v[1]))),
                ("missing ruleset", lambda v: v.pop(1)),
            ]
            for label, mutate in mutations:
                with self.subTest(update=update, mutation=label):
                    value = copy.deepcopy(original)
                    mutate(value)
                    self.assert_refused(value)


if __name__ == "__main__":
    unittest.main()
