from __future__ import annotations

import unittest

from aether_ghidra.integrations.ghidra.identity import (
    function_address,
    normalize_bridge_arguments,
    structured_address,
)


class StructuredAddressTests(unittest.TestCase):
    def test_object_address_forms_are_normalized(self) -> None:
        cases = [
            (
                {"space": "ram", "offset": "00542150"},
                {"space": "ram", "offset": "00542150"},
            ),
            ({"offset": "101230"}, {"offset": "101230"}),
            (
                {"address": {"space": "ram", "offset": "101230"}},
                {"space": "ram", "offset": "101230"},
            ),
            (
                '{"space": "ram", "offset": "00542150"}',
                {"space": "ram", "offset": "00542150"},
            ),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(structured_address(value), expected)

    def test_string_address_formats(self) -> None:
        cases = [
            ("ram:0x542150", {"space": "ram", "offset": "542150"}),
            ("ram:00542150", {"space": "ram", "offset": "00542150"}),
            ("0x542150", {"offset": "542150"}),
            ("00542150", {"offset": "00542150"}),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(structured_address(value), expected)

    def test_integer_address_forms_are_normalized(self) -> None:
        cases = [
            (0x542150, {"offset": "542150"}),
            ({"space": "ram", "offset": 0x542150}, {"space": "ram", "offset": "542150"}),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(structured_address(value), expected)

    def test_invalid_address_forms_report_expected_errors(self) -> None:
        cases = [
            ("ram:zzzz", "location", "not a valid hex offset"),
            ({"space": "ram", "offset": "  "}, "location", "non-empty offset"),
            (None, "function_address", "function_address.*got NoneType"),
            ({"offset": "nothex"}, "caller_address", "caller_address"),
        ]
        for value, label, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, message):
                    structured_address(value, label)


class ApplyAnnotationBatchNormalizationTests(unittest.TestCase):
    def test_function_address_forms_are_normalized(self) -> None:
        cases = [
            (
                "rename_function",
                {"space": "ram", "offset": "00542150"},
                {"space": "ram", "offset": "00542150"},
            ),
            (
                "rename_function",
                "ram:0x542150",
                {"space": "ram", "offset": "542150"},
            ),
            (
                "set_function_comment",
                '{"space": "ram", "offset": "00542150"}',
                {"space": "ram", "offset": "00542150"},
            ),
        ]
        for kind, value, expected in cases:
            with self.subTest(value=value):
                result = normalize_bridge_arguments("apply_annotation_batch", {"operations": [
                    {"kind": kind, "target": {"function_address": value}, "value": "value"},
                ]})
                self.assertEqual(
                    result["operations"][0]["target"]["function_address"],
                    expected,
                )

    def test_function_ref_form_is_normalized(self) -> None:
        result = normalize_bridge_arguments("apply_annotation_batch", {"operations": [
            {"kind": "rename_variable",
             "target": {"function_ref": {"address": {"space": "ram", "offset": "101230"},
                                         "name": "entry"},
                                        "variable_name": "old"},
             "value": "new"},
        ]})
        target = result["operations"][0]["target"]
        self.assertEqual(target["function_address"], {"space": "ram", "offset": "101230"})
        self.assertNotIn("function_ref", target)
        self.assertEqual(target["variable_name"], "old")

    def test_code_unit_comment_accepts_address_string(self) -> None:
        result = normalize_bridge_arguments("apply_annotation_batch", {"operations": [
            {"kind": "set_code_unit_comment",
             "target": {"address": "0x101234"},
             "comment_kind": "eol",
             "value": "note"},
        ]})
        self.assertEqual(
            result["operations"][0]["target"]["address"],
            {"offset": "101234"},
        )

    def test_name_only_function_ref_still_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "function_ref.address"):
            function_address({"name": "entry"})

    def test_malformed_function_address_reports_expected_shape(self) -> None:
        with self.assertRaisesRegex(ValueError, "function_address"):
            normalize_bridge_arguments("apply_annotation_batch", {"operations": [
                {"kind": "rename_function", "target": {"function_address": 3.14}, "value": "x"},
            ]})


if __name__ == "__main__":
    unittest.main()
