#!/usr/bin/env python3

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


CODE_RELATED_EXTENSIONS = {
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".groovy",
    ".jsp",
    ".jspx",
    ".tag",
    ".tld",
    ".js",
    ".ts",
}

DEFAULT_MAX_DIFF_CHARS = 350_000


@dataclass(frozen=True)
class DiffPatch:
    path: str
    text: str
    size: int
    extension: str
    is_code_related: bool
    is_test_like: bool


def _split_unified_diff(diff_text: str) -> List[DiffPatch]:
    parts = re.split(r"(?=^diff --git a/)", diff_text, flags=re.M)
    patches: List[DiffPatch] = []

    for part in parts:
        if not part.strip():
            continue

        match = re.match(r"^diff --git a/(.*?) b/(.*?)$", part, flags=re.M)
        if not match:
            continue

        path = match.group(2)
        extension = Path(path).suffix.lower()
        lowered = path.lower()
        is_test_like = any(token in lowered for token in ("/test/", "/tests/", "test.java"))

        patches.append(
            DiffPatch(
                path=path,
                text=part,
                size=len(part),
                extension=extension,
                is_code_related=extension in CODE_RELATED_EXTENSIONS,
                is_test_like=is_test_like,
            )
        )

    return patches


def _patch_priority(patch: DiffPatch) -> Tuple[int, int, int, str]:
    code_rank = 0 if patch.is_code_related else 1
    test_rank = 1 if patch.is_test_like else 0
    return (code_rank, test_rank, -patch.size, patch.path)


def preprocess_diff_for_prompt(
    diff_text: str,
    *,
    max_chars: int = DEFAULT_MAX_DIFF_CHARS,
) -> Tuple[str, Dict[str, object]]:
    if len(diff_text) <= max_chars:
        return diff_text, {
            "original_chars": len(diff_text),
            "processed_chars": len(diff_text),
            "original_patch_count": 0,
            "included_patch_count": 0,
            "code_patch_count": 0,
            "non_code_patch_count": 0,
            "truncated": False,
            "filtered_non_code": False,
            "included_files": [],
            "omitted_files": [],
        }

    patches = _split_unified_diff(diff_text)
    if not patches:
        return diff_text[:max_chars], {
            "original_chars": len(diff_text),
            "processed_chars": min(len(diff_text), max_chars),
            "original_patch_count": 0,
            "included_patch_count": 0,
            "code_patch_count": 0,
            "non_code_patch_count": 0,
            "truncated": True,
            "filtered_non_code": False,
            "included_files": [],
            "omitted_files": [],
        }

    code_patches = [patch for patch in patches if patch.is_code_related]
    candidate_patches = code_patches or patches
    sorted_patches = sorted(candidate_patches, key=_patch_priority)

    included: List[DiffPatch] = []
    current_size = 0
    for patch in sorted_patches:
        if included and current_size + patch.size > max_chars:
            continue
        included.append(patch)
        current_size += patch.size
        if current_size >= max_chars:
            break

    if not included:
        first_patch = sorted_patches[0]
        included = [first_patch]
        current_size = first_patch.size

    included_files = [patch.path for patch in included]
    omitted_files = [patch.path for patch in patches if patch.path not in set(included_files)]

    omitted_examples = ", ".join(omitted_files[:8])
    included_examples = ", ".join(included_files[:8])
    summary_lines = [
        "# Diff preprocessing summary",
        f"# Original diff size: {len(diff_text):,} chars across {len(patches)} file patches.",
        (
            f"# Kept {len(included)} code-relevant patches "
            f"({sum(1 for patch in included if patch.is_code_related)} code-related, "
            f"{sum(1 for patch in included if patch.is_test_like)} test-like) "
            f"to fit a {max_chars:,}-char prompt budget."
        ),
    ]
    if code_patches:
        summary_lines.append(
            f"# Filtered out {len(patches) - len(code_patches)} non-code patches before truncation."
        )
    if included_examples:
        summary_lines.append(f"# Included files: {included_examples}")
    if omitted_examples:
        summary_lines.append(f"# Omitted files (examples): {omitted_examples}")

    summary_text = "\n".join(summary_lines) + "\n\n"
    remaining_budget = max(0, max_chars - len(summary_text))

    rendered_parts: List[str] = []
    rendered_size = 0
    for patch in included:
        if rendered_parts and rendered_size + patch.size > remaining_budget:
            continue
        if not rendered_parts and patch.size > remaining_budget:
            rendered_parts.append(patch.text[:remaining_budget])
            rendered_size = remaining_budget
            break
        rendered_parts.append(patch.text)
        rendered_size += patch.size

    processed_diff = summary_text + "".join(rendered_parts)
    processed_diff = processed_diff[:max_chars]

    metadata = {
        "original_chars": len(diff_text),
        "processed_chars": len(processed_diff),
        "original_patch_count": len(patches),
        "included_patch_count": len(included),
        "code_patch_count": len(code_patches),
        "non_code_patch_count": len(patches) - len(code_patches),
        "truncated": True,
        "filtered_non_code": bool(code_patches),
        "included_files": included_files,
        "omitted_files": omitted_files,
    }
    return processed_diff, metadata
