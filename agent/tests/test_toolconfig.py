from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aether_ghidra.config.tool_policy import capability_enabled, load_tool_config


GROUPS = {
    "list_functions": "program_read",
    "rename_function": "program_write",
    "rename_variable": "program_write",
    "set_function_comment": "program_write",
    "set_code_unit_comment": "program_write",
    "apply_annotation_batch": "annotation_write",
}


class ToolConfigTests(unittest.TestCase):
    def test_program_write_is_disabled_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tools.json"
            with patch("aether_ghidra.config.tool_policy.TOOL_CONFIG_PATH", path):
                config = load_tool_config(GROUPS, GROUPS)

        self.assertTrue(config["list_functions"])
        self.assertFalse(config["rename_function"])
        self.assertFalse(config["apply_annotation_batch"])

    def test_legacy_per_tool_config_is_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tools.json"
            path.write_text(json.dumps({"list_functions": False}))
            with patch("aether_ghidra.config.tool_policy.TOOL_CONFIG_PATH", path):
                config = load_tool_config(GROUPS, GROUPS)
                migrated = json.loads(path.read_text())

        self.assertFalse(config["list_functions"])
        self.assertFalse(config["rename_function"])
        self.assertEqual(migrated["version"], 2)
        self.assertFalse(migrated["tools"]["list_functions"])

    def test_group_override_applies_to_direct_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tools.json"
            path.write_text(json.dumps({
                "version": 2,
                "groups": {"program_read": True, "program_write": True},
                "tools": {},
            }))
            with patch("aether_ghidra.config.tool_policy.TOOL_CONFIG_PATH", path):
                self.assertTrue(capability_enabled("rename_function", {"rename_function": "rename_function"}, GROUPS))


if __name__ == "__main__":
    unittest.main()
