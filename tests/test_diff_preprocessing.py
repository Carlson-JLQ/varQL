#!/usr/bin/env python3

import unittest
from pathlib import Path

from src.diff_preprocessing import DEFAULT_MAX_DIFF_CHARS, preprocess_diff_for_prompt


ROOT_DIR = Path(__file__).resolve().parent.parent


class DiffPreprocessingTest(unittest.TestCase):
    def test_small_diff_is_unchanged(self):
        raw_diff = """diff --git a/src/main/java/A.java b/src/main/java/A.java
--- a/src/main/java/A.java
+++ b/src/main/java/A.java
@@ -1,1 +1,1 @@
-old
+new
"""
        processed, metadata = preprocess_diff_for_prompt(raw_diff, max_chars=10_000)
        self.assertEqual(raw_diff, processed)
        self.assertFalse(metadata["truncated"])

    def test_large_diff_prefers_code_related_patches(self):
        big_java_body = "x" * 2_000
        big_xml_body = "y" * 6_000
        raw_diff = (
            "diff --git a/src/main/java/A.java b/src/main/java/A.java\n"
            "--- a/src/main/java/A.java\n"
            "+++ b/src/main/java/A.java\n"
            "@@ -1,1 +1,1 @@\n"
            f"+{big_java_body}\n"
            "diff --git a/config/policy.xml b/config/policy.xml\n"
            "--- a/config/policy.xml\n"
            "+++ b/config/policy.xml\n"
            "@@ -1,1 +1,1 @@\n"
            f"+{big_xml_body}\n"
        )

        processed, metadata = preprocess_diff_for_prompt(raw_diff, max_chars=3_500)
        self.assertTrue(metadata["truncated"])
        self.assertIn("Diff preprocessing summary", processed)
        self.assertIn("src/main/java/A.java", processed)
        self.assertIn("config/policy.xml", metadata["omitted_files"])
        self.assertNotIn(big_xml_body[:500], processed)

    def test_real_antisamy_diff_is_reduced_below_budget(self):
        diff_path = ROOT_DIR / "cves" / "CVE-2017-14735" / "CVE-2017-14735.diff"
        if not diff_path.exists():
            self.skipTest("VarQL intentionally omits the large cves/ directory")
        raw_diff = diff_path.read_text(encoding="utf-8", errors="replace")

        processed, metadata = preprocess_diff_for_prompt(raw_diff)
        self.assertTrue(metadata["truncated"])
        self.assertLessEqual(len(processed), DEFAULT_MAX_DIFF_CHARS)
        self.assertIn("Diff preprocessing summary", processed)
        self.assertIn("src/main/java/org/owasp/validator/html/Policy.java", processed)
        self.assertIn(".github/workflows/codeql-analysis.yml", metadata["omitted_files"])


if __name__ == "__main__":
    unittest.main()
