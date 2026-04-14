#!/usr/bin/env python3

import unittest
from pathlib import Path

from scripts.build_codeql_dbs import find_project_source_directory


ROOT_DIR = Path(__file__).resolve().parent.parent


class BuildCodeqlDbsSourceSelectionTest(unittest.TestCase):
    def test_inlong_manager_pojo_is_selected_for_single_module_fix(self):
        cve_dir = ROOT_DIR / "cves" / "CVE-2025-27522"
        if not cve_dir.exists():
            self.skipTest("VarQL intentionally omits the large cves/ directory")
        source_dir = find_project_source_directory(str(cve_dir), cve_id="CVE-2025-27522")
        self.assertIsNotNone(source_dir)
        self.assertTrue(source_dir.endswith("inlong/inlong-manager/manager-pojo"))

    def test_inlong_manager_root_is_selected_for_multi_module_fix(self):
        cve_dir = ROOT_DIR / "cves" / "CVE-2025-27531"
        if not cve_dir.exists():
            self.skipTest("VarQL intentionally omits the large cves/ directory")
        source_dir = find_project_source_directory(str(cve_dir), cve_id="CVE-2025-27531")
        self.assertIsNotNone(source_dir)
        self.assertTrue(source_dir.endswith("inlong/inlong-manager"))


if __name__ == "__main__":
    unittest.main()
