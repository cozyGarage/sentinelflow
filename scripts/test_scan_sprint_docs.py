#!/usr/bin/env python3
"""Regression tests for the scan-sprint documentation/Actions coverage check."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check-scan-sprint-docs.py"
FIXTURE_FILES = (
    ".github/workflows/ci.yml",
    "docs/sprint/scan-correctness-backlog.md",
    "docs/sprint/scan-correctness-acceptance.md",
    "docs/sprint/README.md",
    "docs/sprint/next-assignment.md",
)


class SprintDocsCheckTests(unittest.TestCase):
    def fixture(self) -> tempfile.TemporaryDirectory[str]:
        temp_root = ROOT / ".tmp"
        temp_root.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=temp_root)
        fixture_root = Path(temporary.name)
        for relative in FIXTURE_FILES:
            destination = fixture_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        return temporary

    def run_checker(self, root: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(CHECKER), "--root", root],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_complete_core_evidence_passes(self) -> None:
        with self.fixture() as temporary:
            result = self.run_checker(temporary)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("32 core items", result.stdout)

    def test_missing_acceptance_row_fails(self) -> None:
        with self.fixture() as temporary:
            report = Path(temporary) / "docs/sprint/scan-correctness-acceptance.md"
            report.write_text(
                "\n".join(
                    line for line in report.read_text().splitlines()
                    if not line.startswith("| SC-001 |")
                ) + "\n",
                encoding="utf-8",
            )
            result = self.run_checker(temporary)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SC-001", result.stderr)

    def test_missing_named_action_job_fails(self) -> None:
        with self.fixture() as temporary:
            workflow = Path(temporary) / ".github/workflows/ci.yml"
            workflow.write_text(
                "\n".join(
                    line for line in workflow.read_text().splitlines()
                    if "Scan correctness / SC-001 /" not in line
                ) + "\n",
                encoding="utf-8",
            )
            result = self.run_checker(temporary)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SC-001", result.stderr)

    def test_duplicate_acceptance_row_fails(self) -> None:
        with self.fixture() as temporary:
            report = Path(temporary) / "docs/sprint/scan-correctness-acceptance.md"
            contents = report.read_text(encoding="utf-8")
            row = next(line for line in contents.splitlines() if line.startswith("| SC-001 |"))
            report.write_text(contents + "\n" + row + "\n", encoding="utf-8")
            result = self.run_checker(temporary)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate acceptance rows: SC-001", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
