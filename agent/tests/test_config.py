from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aether_ghidra.config.settings import load_config, save_config


class ConfigTests(unittest.TestCase):
    def test_persisted_gui_values_override_environment_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"OPENAI_API_KEY": "saved-key", "OPENAI_MODEL": "saved-model"}))
            with patch("aether_ghidra.config.settings.CONFIG_PATH", path), patch.dict(
                "os.environ",
                {"OPENAI_API_KEY": "environment-key", "OPENAI_MODEL": "environment-model"},
                clear=False,
            ):
                config = load_config()

        self.assertEqual(config["OPENAI_API_KEY"], "saved-key")
        self.assertEqual(config["OPENAI_MODEL"], "saved-model")

    def test_saved_empty_value_also_blocks_environment_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            with patch("aether_ghidra.config.settings.CONFIG_PATH", path), patch.dict(
                "os.environ", {"OPENAI_API_KEY": "environment-key"}, clear=False
            ):
                save_config({"OPENAI_API_KEY": ""})
                config = load_config()

        self.assertEqual(config["OPENAI_API_KEY"], "")


if __name__ == "__main__":
    unittest.main()
