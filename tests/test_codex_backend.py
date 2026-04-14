#!/usr/bin/env python3

import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.agent_backends.codex_backend import CodexBackend, get_local_codex_model


class CodexBackendLocalConfigTest(unittest.TestCase):
    def _write_config(self, root: str) -> Path:
        config_dir = Path(root) / ".codex"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "config.toml"
        config_path.write_text(
            '\n'.join(
                [
                    'model = "gpt-5.4"',
                    'model_reasoning_effort = "xhigh"',
                    "",
                    "[windows]",
                    'sandbox = "unelevated"',
                    "",
                    '[projects."/root/qlcoder"]',
                    'trust_level = "trusted"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return config_path

    def test_reads_model_from_existing_codex_config(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = self._write_config(tmp_dir)
            self.assertEqual("gpt-5.4", get_local_codex_model(str(config_path)))

    def test_local_config_mode_uses_existing_model_and_omits_model_flag(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = self._write_config(tmp_dir)
            backend = CodexBackend(
                "gpt-5",
                logging.getLogger("codex-test"),
                use_local_config=True,
                codex_config_path=str(config_path),
            )

            cmd = backend._build_exec_command()

            self.assertEqual("gpt-5.4", backend.model)
            self.assertNotIn("-m", cmd)
            self.assertEqual("exec", cmd[1])

    def test_setup_workspace_preserves_local_model_and_project_settings(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = self._write_config(tmp_dir)
            fake_bin = Path(tmp_dir) / "chroma-mcp"
            fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_bin.chmod(0o755)
            backend = CodexBackend(
                "gpt-5",
                logging.getLogger("codex-test"),
                use_local_config=True,
                codex_config_path=str(config_path),
            )

            with patch.dict(
                os.environ,
                {
                    "CHROMA_MCP_PATH": str(fake_bin),
                },
                clear=False,
            ):
                backend.setup_workspace(output_dir=tmp_dir, task=None)
                rendered = config_path.read_text(encoding="utf-8")

            self.assertIn('model = "gpt-5.4"', rendered)
            self.assertIn('model_reasoning_effort = "xhigh"', rendered)
            self.assertIn('[projects."/root/qlcoder"]', rendered)
            self.assertIn("[mcp_servers.chroma]", rendered)
            self.assertIn("[mcp_servers.codeql]", rendered)
            self.assertIn(f'command = "{fake_bin}"', rendered)
            self.assertIn('"--client-type", "persistent"', rendered)


if __name__ == "__main__":
    unittest.main()
