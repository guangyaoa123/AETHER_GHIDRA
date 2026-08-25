from __future__ import annotations

import logging
import unittest
from unittest.mock import patch

from aether_ghidra.observability.logging import configure_logging


class LoggingConfigurationTests(unittest.TestCase):
    def test_debug_environment_enables_debug_logging(self) -> None:
        with patch.dict("os.environ", {"AETHER_GHIDRA_DEBUG": "1"}):
            logger = configure_logging({"DEBUG": False})
        self.assertEqual(logger.level, logging.DEBUG)

        configure_logging({"DEBUG": False})
        self.assertEqual(logger.level, logging.INFO)


if __name__ == "__main__":
    unittest.main()
