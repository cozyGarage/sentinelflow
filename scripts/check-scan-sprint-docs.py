#!/usr/bin/env python3
"""Check that every scan-correctness core item has acceptance and Actions coverage."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


CORE_ROW = re.compile(r"^\| (SC-\d{3}) \| C \|", re.MULTILINE)
ACCEPTANCE_ROW = re.compile(r"^\| (SC-\d{3}) \|", re.MULTILINE)
ACTION_ID = re.compile(r"\bid: (SC-\d{3})\b|Scan correctness / (SC-\d{3}) /")


def duplicates(items: list[str]) -> set[str]:
    seen: set[str] = set()
    repeated: set[str] = set()
    for item in items:
        if item in seen:
            repeated.add(item)
        seen.add(item)
    return repeated


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    root = parser.parse_args().root

    backlog_path = root / "docs/sprint/scan-correctness-backlog.md"
    acceptance_path = root / "docs/sprint/scan-correctness-acceptance.md"
    readme_path = root / "docs/sprint/README.md"
    handoff_path = root / "docs/sprint/next-assignment.md"
    workflow_path = root / ".github/workflows/ci.yml"
    paths = (backlog_path, acceptance_path, readme_path, handoff_path, workflow_path)
    missing_files = [str(path.relative_to(root)) for path in paths if not path.is_file()]
    if missing_files:
        print("missing sprint evidence files: " + ", ".join(missing_files), file=sys.stderr)
        return 1

    backlog = backlog_path.read_text(encoding="utf-8")
    acceptance = acceptance_path.read_text(encoding="utf-8")
    readme = readme_path.read_text(encoding="utf-8")
    workflow = workflow_path.read_text(encoding="utf-8")

    core_rows = CORE_ROW.findall(backlog)
    core = set(core_rows)
    accepted_rows = ACCEPTANCE_ROW.findall(acceptance)
    accepted = set(accepted_rows)
    action_ids = {
        first or second for first, second in ACTION_ID.findall(workflow)
    }

    problems: list[str] = []
    for label, rows in (("backlog", core_rows), ("acceptance", accepted_rows)):
        repeated = sorted(duplicates(rows))
        if repeated:
            problems.append(f"duplicate {label} rows: {', '.join(repeated)}")

    if not core:
        problems.append("no core backlog items found")
    absent_acceptance = sorted(core - accepted)
    extra_acceptance = sorted(accepted - core)
    absent_actions = sorted(core - action_ids)
    if absent_acceptance:
        problems.append("missing acceptance rows: " + ", ".join(absent_acceptance))
    if extra_acceptance:
        problems.append("acceptance rows outside core: " + ", ".join(extra_acceptance))
    if absent_actions:
        problems.append("missing named Actions evidence: " + ", ".join(absent_actions))
    if "scan-correctness-acceptance.md" not in readme or "next-assignment.md" not in readme:
        problems.append("README must link the acceptance report and next assignment")

    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1

    print(f"PASS {len(core)} core items have backlog, acceptance, and named Actions coverage")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
