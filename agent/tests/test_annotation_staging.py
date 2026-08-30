from __future__ import annotations

import unittest

from aether_ghidra.features.annotation.staging import MutationStaging


ROOT = {"space": "ram", "offset": "1000"}
ENTRY = {"address": ROOT, "name": "entry"}


class MutationStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = {
            "functions": [{
                "name": "entry",
                "address": ROOT,
                "variables": [{"name": "arg", "storage": "r0"}],
            }],
            "code_units": [{"address": {"space": "ram", "offset": "1004"}}],
        }

    def test_annotation_tools_stage_only_frozen_targets(self) -> None:
        staging = MutationStaging(self.context)
        resolver = lambda name: None
        staging.stage_function("rename_function", ENTRY, "decode", resolver)
        staging.stage_function("set_function_comment", ENTRY, "draws widgets", resolver)
        staging.stage_variable(ENTRY, "arg", "payload", resolver)
        staging.stage_code_comment({"space": "ram", "offset": "1004"}, "eol", "loads input")
        self.assertEqual(len(staging.operations), 4)
        with self.assertRaisesRegex(ValueError, "frozen annotation context"):
            staging.stage_function("rename_function", {"address": {"space": "ram", "offset": "2000"}}, "nope", resolver)

    def test_duplicate_target_is_rejected_without_mutating(self) -> None:
        staging = MutationStaging(self.context)
        staging.stage_function("rename_function", ENTRY, "first", lambda _: None)
        with self.assertRaisesRegex(ValueError, "already staged"):
            staging.stage_function("rename_function", ENTRY, "second", lambda _: None)
        self.assertEqual(len(staging.operations), 1)

    def test_auto_parameter_cannot_be_renamed(self) -> None:
        context = {
            "functions": [{
                "name": "entry",
                "address": ROOT,
                "variables": [{"name": "this", "parameter": True, "auto_parameter": True}],
            }],
        }
        staging = MutationStaging(context)

        with self.assertRaisesRegex(ValueError, "auto-parameter"):
            staging.stage_variable(ENTRY, "this", "context", lambda _: None)

        self.assertIn("retype_variable", staging.stage_variable_type(
            ENTRY, "this", "/Types/MyClass *", lambda _: None))

    def test_parameter_retype_is_staged(self) -> None:
        staging = MutationStaging(self.context)
        result = staging.stage_variable_type(ENTRY, "arg", "/builtin/uint32_t", lambda _: None)
        self.assertIn("retype_variable", result)
        self.assertEqual(staging.operations[0]["value"], "/builtin/uint32_t")

    def test_function_definition_supports_storage_and_varargs(self) -> None:
        staging = MutationStaging(self.context)
        staging.stage_function_definition(
            ENTRY, "int", [{
                "name": "arg", "data_type_path": "/builtin/uint32_t",
                "storage": {"register": "R0"},
            }], True, lambda _: None,
        )
        operation = staging.operations[0]
        self.assertEqual(operation["definition"]["varargs"], True)
        self.assertEqual(operation["definition"]["parameters"][0]["storage"]["register"], "R0")

    def test_function_definition_normalizes_return_and_parameter_type_paths(self) -> None:
        staging = MutationStaging(self.context)
        staging.stage_function_definition(
            ENTRY, {"data_type_path": "/Types/Result"}, [{
                "name": "arg", "data_type_path": {"path": "/Types/Input"},
            }], resolver=lambda _target: None,
        )

        definition = staging.operations[0]["definition"]
        self.assertEqual(definition["return_type"], "/Types/Result")
        self.assertEqual(definition["parameters"][0]["data_type"], "/Types/Input")

    def test_function_definition_conflicts_with_variable_mutation(self) -> None:
        staging = MutationStaging(self.context)
        staging.stage_variable_type(ENTRY, "arg", "/builtin/uint32_t", lambda _: None)
        with self.assertRaisesRegex(ValueError, "conflicts"):
            staging.stage_function_definition(ENTRY, "int", [], False, lambda _: None)

    def test_function_rename_is_applied_immediately(self) -> None:
        applied = []

        def rename(operation):
            applied.append(operation)
            return {"batch_id": "immediate-1", "operations": [{
                "id": operation["id"], "kind": operation["kind"],
                "target": operation["target"], "before": "entry", "after": operation["value"],
            }]}

        staging = MutationStaging(self.context, immediate_rename=rename)
        result = staging.stage_function("rename_function", ENTRY, "decode", lambda _: None)

        self.assertIn("Applied rename_function", result)
        self.assertEqual(len(applied), 1)
        self.assertEqual(staging.commit(lambda *_: self.fail("rename must not be committed again"))["operations"][0]["after"], "decode")

    def test_commit_is_one_batch(self) -> None:
        staging = MutationStaging(self.context)
        staging.stage_function("rename_function", ENTRY, "decode", lambda _: None)
        calls = []
        result = staging.commit(lambda capability, arguments: calls.append((capability, arguments)) or {"batch_id": "b1"})
        self.assertEqual(result, {"batch_id": "b1", "operations": []})
        self.assertEqual(calls[0][0], "apply_annotation_batch")
        self.assertEqual(len(calls[0][1]["operations"]), 1)

    def test_bare_function_name_is_rejected_before_resolver(self) -> None:
        staging = MutationStaging(self.context)
        resolver = lambda _target: self.fail("name-only target reached resolver")
        with self.assertRaisesRegex(ValueError, "function_ref"):
            staging.stage_function("rename_function", "entry", "decode", resolver)

    def test_bare_code_comment_location_is_rejected(self) -> None:
        staging = MutationStaging(self.context)
        with self.assertRaisesRegex(ValueError, "structured address"):
            staging.stage_code_comment("1004", "eol", "comment")


if __name__ == "__main__":
    unittest.main()
