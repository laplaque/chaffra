"""Deterministic tests for the chaffra coverage checker.

The tests drive the same `main(argv)` entry point that CI invokes. There are
two fixture styles:

* **Unit cases** (the `CheckerTestCase` subclasses) construct small synthetic
  LCOV / policy / diff strings inline, so each table of cases is reviewable in
  one place.
* **Integration cases** (the `RealGitTestCase` subclasses) build a real
  temporary git repository and copy checked-in fixtures from
  `scripts/tests/fixtures/integration/` (Rust source, LCOV, policy), per
  CONTRIBUTING.md's "Fixture-based for integration tests ... Never generate
  fixture content at runtime." Only git metadata is created at runtime.

Run locally with::

    python3 -m unittest discover -s scripts/tests
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path

# Load the checker module directly from its file so the test suite does not
# depend on `scripts/` being importable as a package or on sys.path being
# mutated mid-file (which would force a static-analysis suppression).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_CHECKER_PATH = _REPO_ROOT / "scripts" / "coverage_check.py"
_spec = importlib.util.spec_from_file_location("coverage_check", _CHECKER_PATH)
assert _spec is not None and _spec.loader is not None
coverage_check = importlib.util.module_from_spec(_spec)
sys.modules["coverage_check"] = coverage_check
_spec.loader.exec_module(coverage_check)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


BASIC_TRUST_BOUNDARY_FILE = "crates/chaffra-core/src/config.rs"
NON_TRUST_BOUNDARY_FILE = "crates/chaffra-cli/src/main.rs"


def basic_policy(thresholds: dict | None = None) -> str:
    t = {
        "overall": 85.0,
        "aggregate_changed": 95.0,
        "per_file_changed": 90.0,
        "trust_boundary_changed": 100.0,
    }
    if thresholds:
        t.update(thresholds)
    return textwrap.dedent(
        f"""\
        policy_version = 1

        [thresholds]
        overall = {t["overall"]}
        aggregate_changed = {t["aggregate_changed"]}
        per_file_changed = {t["per_file_changed"]}
        trust_boundary_changed = {t["trust_boundary_changed"]}

        [[trust_boundaries]]
        purpose = "configuration parsing"
        patterns = ["{BASIC_TRUST_BOUNDARY_FILE}"]
        """
    )


def lcov_file_block(path: str, lines: list[tuple[int, int]]) -> str:
    """Build a single SF…end_of_record block from (line, hits) pairs."""
    out = [f"SF:{path}"]
    for ln, hits in lines:
        out.append(f"DA:{ln},{hits}")
    out.append(f"LF:{len(lines)}")
    out.append(f"LH:{sum(1 for _, h in lines if h > 0)}")
    out.append("end_of_record")
    return "\n".join(out) + "\n"


def lcov_text(blocks: list[tuple[str, list[tuple[int, int]]]]) -> str:
    return "".join(lcov_file_block(p, lines) for p, lines in blocks)


def diff_text(file_hunks: list[tuple[str, list[tuple[int, int]]]],
              renames: list[tuple[str, str]] | None = None,
              deleted: list[str] | None = None) -> str:
    """Build a unified=0 diff text.

    file_hunks: list of (path, [(start, count), ...])
    renames: list of (old, new) — emitted before file_hunks entries by the caller.
    deleted: list of paths to emit as deleted-only hunks (count = 0).
    """
    out: list[str] = []
    for path, hunks in file_hunks:
        out.append(f"diff --git a/{path} b/{path}")
        out.append("index 0000000..1111111 100644")
        out.append(f"--- a/{path}")
        out.append(f"+++ b/{path}")
        for start, count in hunks:
            if count == 1:
                out.append(f"@@ -0,0 +{start} @@")
            else:
                out.append(f"@@ -0,0 +{start},{count} @@")
    for old, new in renames or []:
        out.append(f"diff --git a/{old} b/{new}")
        out.append("similarity index 100%")
        out.append(f"rename from {old}")
        out.append(f"rename to {new}")
    for path in deleted or []:
        out.append(f"diff --git a/{path} b/{path}")
        out.append("deleted file mode 100644")
        out.append(f"--- a/{path}")
        out.append("+++ /dev/null")
        out.append("@@ -1,5 +0,0 @@")
    return "\n".join(out) + "\n"


def write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------


class CheckerTestCase(unittest.TestCase):
    """Base class that wires up a tmpdir and the standard argv builder."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cov-check-"))
        # Synthetic repo-files list so the checker never shells out to git.
        self.repo_files_path = write(
            self.tmp / "repo-files.txt",
            "\n".join(
                [
                    BASIC_TRUST_BOUNDARY_FILE,
                    NON_TRUST_BOUNDARY_FILE,
                    "crates/chaffra-core/src/diagnostic.rs",
                ]
            )
            + "\n",
        )

    def tearDown(self) -> None:
        for p in sorted(self.tmp.rglob("*"), reverse=True):
            if p.is_file():
                p.unlink()
            else:
                p.rmdir()
        self.tmp.rmdir()

    def run_check(
        self,
        *,
        lcov: str,
        policy: str,
        diff: str,
        mode: str = "pr",
        base: str = "aaaaaaa",
        head: str = "bbbbbbb",
    ) -> tuple[int, dict, str]:
        lcov_path = write(self.tmp / "lcov.info", lcov)
        policy_path = write(self.tmp / "coverage-policy.toml", policy)
        diff_path = write(self.tmp / "diff.txt", diff)
        json_out = self.tmp / "out.json"
        md_out = self.tmp / "out.md"
        rc = coverage_check.main(
            [
                "--lcov",
                str(lcov_path),
                "--policy",
                str(policy_path),
                "--diff",
                str(diff_path),
                "--base-sha",
                base,
                "--head-sha",
                head,
                "--json-out",
                str(json_out),
                "--markdown-out",
                str(md_out),
                "--repo-files",
                str(self.repo_files_path),
                "--repo-root",
                str(self.tmp),
                "--mode",
                mode,
                # Tests work in a tmp dir that is not a git repository; the
                # head-drift contract only applies to CI runs that produce
                # LCOV against a real checkout.
                "--allow-head-drift",
            ]
        )
        report_text = json_out.read_text(encoding="utf-8") if json_out.exists() else "{}"
        report = json.loads(report_text)
        md = md_out.read_text(encoding="utf-8") if md_out.exists() else ""
        return rc, report, md


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAllGatesPass(CheckerTestCase):
    def test_clean_pr(self) -> None:
        lcov = lcov_text(
            [
                (
                    BASIC_TRUST_BOUNDARY_FILE,
                    [(10, 5), (11, 5), (12, 5)],
                ),
                (
                    NON_TRUST_BOUNDARY_FILE,
                    [(100, 2), (101, 2), (102, 2), (103, 2), (104, 2), (105, 2), (106, 2), (107, 2), (108, 2), (109, 2)],
                ),
            ]
        )
        diff = diff_text(
            [
                (BASIC_TRUST_BOUNDARY_FILE, [(10, 3)]),
                (NON_TRUST_BOUNDARY_FILE, [(100, 10)]),
            ]
        )
        rc, report, md = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_OK, report)
        self.assertTrue(report["passed"])
        self.assertEqual(report["base_sha"], "aaaaaaa")
        self.assertEqual(report["head_sha"], "bbbbbbb")
        self.assertIn("aaaaaaa", md)
        self.assertIn("bbbbbbb", md)


class TestNoExecutableLinesBlock(CheckerTestCase):
    def test_lf0_lh0_zero_da_block_accepted(self) -> None:
        # cargo-llvm-cov emits LF:0/LH:0 with no DA records for a file that
        # has no executable lines (e.g. a `pub mod` re-export). The parser
        # must accept it (contributing 0 to overall), not reject the report.
        lcov = (
            "SF:crates/chaffra-cli/src/main.rs\nLF:0\nLH:0\nend_of_record\n"
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nDA:2,1\nLF:2\nLH:2\nend_of_record\n"
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_OK, report.get("gates"))
        # Only config.rs's 2 instrumented lines count toward overall.
        self.assertEqual(report["overall"]["instrumented_lines"], 2)
        self.assertEqual(report["overall"]["covered_lines"], 2)


class TestMultiTargetMerge(CheckerTestCase):
    """The multi-target matrix passes one LCOV per target OS/arch; the checker
    merges them so a line is instrumented if ANY target compiled it and
    covered if ANY target exercised it. This is what lets the single 100%
    trust-boundary gate enforce coverage on `#[cfg(target_os = "...")]`-gated
    code (chaffra#49 / H4): no one build instruments every target, but the
    union of the per-target builds does."""

    def run_check_multi(
        self, *, lcovs: list[str], policy: str, diff: str
    ) -> tuple[int, dict, str]:
        policy_path = write(self.tmp / "coverage-policy.toml", policy)
        diff_path = write(self.tmp / "diff.txt", diff)
        json_out = self.tmp / "out.json"
        md_out = self.tmp / "out.md"
        lcov_args: list[str] = []
        for i, text in enumerate(lcovs):
            lcov_args += [str(write(self.tmp / f"lcov-{i}.info", text))]
        rc = coverage_check.main(
            [
                "--lcov", *lcov_args,
                "--policy", str(policy_path),
                "--diff", str(diff_path),
                "--base-sha", "aaaaaaa",
                "--head-sha", "bbbbbbb",
                "--json-out", str(json_out),
                "--markdown-out", str(md_out),
                "--repo-files", str(self.repo_files_path),
                "--repo-root", str(self.tmp),
                "--mode", "pr",
                "--allow-head-drift",
            ]
        )
        report = json.loads(json_out.read_text(encoding="utf-8")) if json_out.exists() else {}
        md = md_out.read_text(encoding="utf-8") if md_out.exists() else ""
        return rc, report, md

    def test_line_covered_on_any_target_is_covered_in_merge(self) -> None:
        # Target A instruments config.rs lines 1-3 with only line 1 covered;
        # target B with only lines 2-3 covered. Each line is covered on some
        # target, so the merged trust-boundary file is 100% — the gate passes.
        # Exercises every merge branch: first-map insert (existing is None),
        # same-path remerge with a smaller hit (line 1: 1 then 0 → max stays
        # 1) and a larger hit (lines 2,3: 0 then 1 → max becomes 1).
        target_a = lcov_text(
            [
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1), (2, 0), (3, 0)]),
                (NON_TRUST_BOUNDARY_FILE, [(n, 1) for n in range(10, 20)]),
            ]
        )
        target_b = lcov_text(
            [(BASIC_TRUST_BOUNDARY_FILE, [(1, 0), (2, 1), (3, 1)])]
        )
        diff = diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(1, 3)])])
        rc, report, _ = self.run_check_multi(
            lcovs=[target_a, target_b], policy=basic_policy(), diff=diff
        )
        self.assertEqual(rc, coverage_check.EXIT_OK, report.get("gates"))
        tb = next(g for g in report["gates"] if g["name"] == "trust_boundary_changed")
        self.assertTrue(tb["passed"], tb)
        block = next(f for f in report["files"] if f["path"] == BASIC_TRUST_BOUNDARY_FILE)
        self.assertEqual(block["changed_instrumented"], 3)
        self.assertEqual(block["changed_covered"], 3)

    def test_line_uncovered_on_all_targets_stays_uncovered(self) -> None:
        # The union must not fabricate coverage: a changed line that is
        # uncovered on every target stays uncovered, so the trust-boundary
        # gate fails. Line 2 is 0 on both targets.
        both = lcov_text(
            [
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1), (2, 0)]),
                (NON_TRUST_BOUNDARY_FILE, [(n, 1) for n in range(10, 30)]),
            ]
        )
        diff = diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(1, 2)])])
        rc, report, _ = self.run_check_multi(
            lcovs=[both, both], policy=basic_policy(), diff=diff
        )
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        tb = next(g for g in report["gates"] if g["name"] == "trust_boundary_changed")
        self.assertFalse(tb["passed"], tb)
        block = next(f for f in report["files"] if f["path"] == BASIC_TRUST_BOUNDARY_FILE)
        self.assertEqual(block["uncovered_lines"], [2])


class TestDeclaredSummaryCannotInflateOverall(CheckerTestCase):
    """Overall is the DA-coherent metric Σ(covered DA) / Σ(unique DA): both
    sides come from the concrete DA records, so a declared summary that
    overstates LH cannot inflate the score past what the DA records
    demonstrate. The structural reconciliation bound
    (LH-covered_DA) ≤ (LF-unique_DA) still rejects malformed summaries
    (the bound is in the parser, see TestMalformedLcovTable)."""

    def test_unseen_equal_pair_does_not_inflate_overall(self) -> None:
        # The previous round's ΣLH/ΣLF metric reported 100% on this input
        # (DA:1,1; LF:N; LH:N — unseen_hits=N-1, unseen_inst=N-1 passes the
        # bound but the summary is inflatable to N/N=100% with one real hit).
        # The DA-coherent metric reports 1/1=100% which IS demonstrated, and
        # crucially adding a second tracked file with low coverage pulls the
        # score down honestly (no fake denominator from declared LF).
        lcov = (
            "SF:crates/chaffra-core/src/config.rs\n"
            "DA:1,1\nLF:1000\nLH:1000\nend_of_record\n"
            "SF:crates/chaffra-cli/src/main.rs\n"
            "DA:1,0\nDA:2,0\nDA:3,0\nLF:3\nLH:0\nend_of_record\n"
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        # Only the visible DA evidence drives arithmetic: 1 covered of 4
        # unique DA lines = 25%. The inflated LF:1000 contributes nothing.
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertEqual(report["overall"]["instrumented_lines"], 4)
        self.assertEqual(report["overall"]["covered_lines"], 1)
        self.assertAlmostEqual(report["overall"]["percent"], 25.0, places=2)

    def test_inflated_unseen_hits_rejected_by_parser(self) -> None:
        # LF:10/LH:10 with `DA:1,1; DA:2,0`: unseen_hits = 10-1 = 9,
        # unseen_inst = 10-2 = 8 → 9 > 8 → parser rejects as malformed.
        lcov = (
            "SF:crates/chaffra-core/src/config.rs\n"
            "DA:1,1\nDA:2,0\nLF:10\nLH:10\nend_of_record\n"
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        self.assertEqual(report["status"], "malformed_input")
        self.assertIn("hits unaccounted", report["detail"])


class TestSyntheticSfPathsAreDropped(CheckerTestCase):
    """H5: a producer that emits an in-tree-looking but untracked SF path
    cannot inflate overall coverage. The checker arithmetic restricts to
    files present in `repo_files` (HEAD's tracked .rs set in CI)."""

    def test_synthetic_path_dropped_from_overall(self) -> None:
        # `fake.rs` is NOT in the tracked-files universe written by
        # CheckerTestCase.setUp(); its 100/100 contribution must be ignored
        # even though the path resolves inside repo_root.
        lcov = lcov_text(
            [
                # Real tracked file with 1/2 covered → 50%.
                (NON_TRUST_BOUNDARY_FILE, [(1, 1), (2, 0)]),
                # Synthetic in-tree path with fully-covered records.
                ("crates/chaffra-cli/src/fake.rs", [(1, 1), (2, 1), (3, 1), (4, 1)]),
                # TB file present so the policy's glob inventory matches.
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        # Overall is 2/3 (50% from main.rs + 1/1 from config.rs), not
        # inflated to ~85% by the synthetic 4/4.
        overall = report["overall"]
        self.assertEqual(overall["instrumented_lines"], 3)
        self.assertEqual(overall["covered_lines"], 2)
        self.assertIn("crates/chaffra-cli/src/fake.rs", overall["dropped_synthetic_sf_paths"])
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)  # 66.67% < 85%

    def test_all_synthetic_lcov_is_malformed_not_vacuous_pass(self) -> None:
        # If EVERY SF block is synthetic (none match tracked rs files), the
        # overall denominator would be zero. Pre-fix that meant overall=100%
        # → vacuous gate pass. Now it's MalformedInput → exit 2 with failure
        # artifact, preventing a malicious LCOV from passing all four gates
        # by emitting only un-tracked SF paths.
        lcov = lcov_text(
            [
                ("crates/chaffra-cli/src/synthetic_a.rs", [(1, 1)]),
                ("crates/chaffra-cli/src/synthetic_b.rs", [(1, 1)]),
            ]
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        # Failure artifact must be schema-compatible: every top-level key the
        # success path emits is present (with null/empty placeholders) plus
        # the failure-specific status/detail fields.
        self.assertEqual(report["status"], "malformed_input")
        for required in (
            "tool_version",
            "policy_version",
            "base_sha",
            "head_sha",
            "thresholds",
            "overall",
            "aggregate_changed",
            "files",
            "gates",
            "passed",
            "status",
            "detail",
        ):
            self.assertIn(required, report, f"missing {required!r} in failure payload")
        self.assertEqual(report["files"], [])
        self.assertEqual(report["gates"], [])
        self.assertIn("synthetic_a.rs", report["detail"])


class TestOverallFails(CheckerTestCase):
    def test_overall_below_threshold(self) -> None:
        # 4/10 = 40%
        lcov = lcov_text(
            [
                (
                    NON_TRUST_BOUNDARY_FILE,
                    [(n, 1 if n < 14 else 0) for n in range(10, 20)],
                ),
                (
                    BASIC_TRUST_BOUNDARY_FILE,
                    [(10, 1)],
                ),
            ]
        )
        # Trust boundary not touched.
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(10, 1)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        gate_names = {g["name"]: g for g in report["gates"]}
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertFalse(gate_names["overall"]["passed"])
        # Per-file passes because the one changed line is covered.
        self.assertTrue(gate_names["per_file_changed"]["passed"])


class TestAggregateFails(CheckerTestCase):
    def test_aggregate_changed_below_threshold(self) -> None:
        # Two non-TB files with low coverage on changed lines.
        lcov = lcov_text(
            [
                (
                    NON_TRUST_BOUNDARY_FILE,
                    [(n, 0) for n in range(10, 30)] + [(50, 1) for _ in range(1)],
                ),
                (
                    "crates/chaffra-core/src/diagnostic.rs",
                    [(n, 0) for n in range(10, 30)] + [(50, 1)],
                ),
                (
                    BASIC_TRUST_BOUNDARY_FILE,
                    [(1, 1)],
                ),
            ]
        )
        diff = diff_text(
            [
                (NON_TRUST_BOUNDARY_FILE, [(10, 20)]),
                ("crates/chaffra-core/src/diagnostic.rs", [(10, 20)]),
            ]
        )
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        gate_names = {g["name"]: g for g in report["gates"]}
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertFalse(gate_names["aggregate_changed"]["passed"])


class TestPerFileFails(CheckerTestCase):
    def test_single_file_below_per_file_threshold(self) -> None:
        # Bad file: 7/10 = 70% (below 90%). Good file: 100/100 = 100%.
        # Aggregate: 107/110 = 97.3% — passes the 95% gate, so this case
        # isolates a per-file failure.
        bad_lines = [(n, 1 if n < 17 else 0) for n in range(10, 20)]
        good_lines = [(n, 1) for n in range(10, 110)]
        lcov = lcov_text(
            [
                (NON_TRUST_BOUNDARY_FILE, bad_lines),
                ("crates/chaffra-core/src/diagnostic.rs", good_lines),
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = diff_text(
            [
                (NON_TRUST_BOUNDARY_FILE, [(10, 10)]),
                ("crates/chaffra-core/src/diagnostic.rs", [(10, 100)]),
            ]
        )
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        gate_names = {g["name"]: g for g in report["gates"]}
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertTrue(gate_names["aggregate_changed"]["passed"], gate_names["aggregate_changed"])
        self.assertFalse(gate_names["per_file_changed"]["passed"])
        self.assertIn(NON_TRUST_BOUNDARY_FILE, gate_names["per_file_changed"]["detail"])


class TestAddedFile(CheckerTestCase):
    def test_added_file_changed_lines_counted(self) -> None:
        new_path = "crates/chaffra-core/src/diagnostic.rs"
        lcov = lcov_text(
            [
                (new_path, [(n, 1) for n in range(1, 11)]),
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = (
            "diff --git a/{p} b/{p}\nnew file mode 100644\nindex 0000000..1111111\n"
            "--- /dev/null\n+++ b/{p}\n@@ -0,0 +1,10 @@\n".format(p=new_path)
        )
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_OK)
        file_paths = {f["path"]: f for f in report["files"]}
        self.assertIn(new_path, file_paths)
        self.assertEqual(file_paths[new_path]["changed_instrumented"], 10)


class TestRenamedFile(CheckerTestCase):
    def test_renamed_file_uses_new_path(self) -> None:
        new_path = "crates/chaffra-core/src/diagnostic.rs"
        lcov = lcov_text(
            [
                (new_path, [(n, 1) for n in range(1, 4)]),
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = (
            "diff --git a/old/path.rs b/{p}\nsimilarity index 90%\n"
            "rename from old/path.rs\nrename to {p}\nindex aaa..bbb 100644\n"
            "--- a/old/path.rs\n+++ b/{p}\n@@ -0,0 +1,3 @@\n".format(p=new_path)
        )
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_OK)
        paths = [f["path"] for f in report["files"]]
        self.assertIn(new_path, paths)


class TestDeletedOnlyHunks(CheckerTestCase):
    def test_deleted_only_hunks_contribute_no_changes(self) -> None:
        lcov = lcov_text(
            [(BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]), (NON_TRUST_BOUNDARY_FILE, [(1, 1)])]
        )
        diff = textwrap.dedent(
            f"""\
            diff --git a/{NON_TRUST_BOUNDARY_FILE} b/{NON_TRUST_BOUNDARY_FILE}
            index aaa..bbb 100644
            --- a/{NON_TRUST_BOUNDARY_FILE}
            +++ b/{NON_TRUST_BOUNDARY_FILE}
            @@ -10,5 +9,0 @@
            """
        )
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_OK)
        # No file should appear in the per-file table because the only hunk was deleted-only.
        self.assertEqual(report["files"], [])


class TestPathsWithSpaces(CheckerTestCase):
    def test_path_with_spaces(self) -> None:
        path = "crates/chaffra-core/src/has space.rs"
        # Add the path to the repo-files universe so trust-boundary expansion still passes.
        write(
            self.repo_files_path,
            "\n".join(
                [BASIC_TRUST_BOUNDARY_FILE, NON_TRUST_BOUNDARY_FILE, path]
            )
            + "\n",
        )
        lcov = lcov_text(
            [
                (path, [(1, 1), (2, 1)]),
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = (
            f"diff --git a/{path} b/{path}\n"
            "index aaa..bbb 100644\n"
            f"--- a/{path}\n+++ b/{path}\n@@ -0,0 +1,2 @@\n"
        )
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_OK)
        paths = [f["path"] for f in report["files"]]
        self.assertIn(path, paths)


class TestNonInstrumentedChangedLines(CheckerTestCase):
    def test_non_instrumented_lines_reported_not_counted_as_covered(self) -> None:
        # Changed line 12 is not present in LCOV.
        lcov = lcov_text(
            [
                (NON_TRUST_BOUNDARY_FILE, [(10, 1), (11, 1)]),
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(10, 3)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_OK)
        file_blocks = {f["path"]: f for f in report["files"]}
        block = file_blocks[NON_TRUST_BOUNDARY_FILE]
        self.assertEqual(block["non_instrumented_lines"], [12])
        # Coverage is computed only over instrumented changed lines: 2/2 = 100%.
        self.assertEqual(block["changed_instrumented"], 2)
        self.assertEqual(block["changed_covered"], 2)


class TestMalformedPolicyTable(CheckerTestCase):
    """Table-driven: malformed/invalid policies exit 2. (Malformed-LCOV cases
    live in TestMalformedLcovTable.)"""

    _MISSING_TB_GROUP = textwrap.dedent(
        """\
        policy_version = 1
        [thresholds]
        overall = 85.0
        aggregate_changed = 95.0
        per_file_changed = 90.0
        trust_boundary_changed = 100.0
        """
    )

    _BASE_THRESHOLDS = (
        "[thresholds]\noverall = 85.0\naggregate_changed = 95.0\n"
        "per_file_changed = 90.0\ntrust_boundary_changed = 100.0\n"
    )

    def cases(self) -> list[tuple[str, str]]:
        tb = '[[trust_boundaries]]\npurpose = "x"\npatterns = ["a.rs"]\n'
        return [
            ("threshold out of range", basic_policy({"overall": 150.0})),
            ("missing trust-boundary group", self._MISSING_TB_GROUP),
            ("non-integer policy_version", 'policy_version = "x"\n' + self._BASE_THRESHOLDS + tb),
            ("missing [thresholds] table", "policy_version = 1\n" + tb),
            (
                "non-numeric threshold value",
                'policy_version = 1\n[thresholds]\noverall = "x"\n'
                "aggregate_changed = 95.0\nper_file_changed = 90.0\n"
                "trust_boundary_changed = 100.0\n" + tb,
            ),
            (
                "trust_boundaries not an array",
                "policy_version = 1\n" + self._BASE_THRESHOLDS + 'trust_boundaries = "x"\n',
            ),
            (
                "trust_boundary entry missing purpose",
                "policy_version = 1\n" + self._BASE_THRESHOLDS
                + '[[trust_boundaries]]\npatterns = ["a.rs"]\n',
            ),
            (
                "trust_boundary patterns not a list",
                "policy_version = 1\n" + self._BASE_THRESHOLDS
                + '[[trust_boundaries]]\npurpose = "x"\npatterns = "a.rs"\n',
            ),
            ("not valid TOML", "this is = = not toml [[[\n"),
        ]

    def test_every_invalid_policy_exits_2(self) -> None:
        lcov = lcov_text([(BASIC_TRUST_BOUNDARY_FILE, [(1, 1)])])
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        for label, policy in self.cases():
            with self.subTest(case=label):
                rc, _, _ = self.run_check(lcov=lcov, policy=policy, diff=diff)
                self.assertEqual(rc, coverage_check.EXIT_MALFORMED, label)


class TestTrustBoundaryPatternMatchesNothing(CheckerTestCase):
    def test_pattern_with_no_match_exits_2(self) -> None:
        policy = textwrap.dedent(
            """\
            policy_version = 1
            [thresholds]
            overall = 85.0
            aggregate_changed = 95.0
            per_file_changed = 90.0
            trust_boundary_changed = 100.0

            [[trust_boundaries]]
            purpose = "obsolete"
            patterns = ["crates/never/existed.rs"]
            """
        )
        lcov = lcov_text([(BASIC_TRUST_BOUNDARY_FILE, [(1, 1)])])
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, _, _ = self.run_check(lcov=lcov, policy=policy, diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)


class TestOutputsCarrySha(CheckerTestCase):
    def test_json_and_markdown_contain_exact_shas_and_uncovered(self) -> None:
        lcov = lcov_text(
            [
                # 1 of the 2 changed lines uncovered → per-file fails (50%).
                (NON_TRUST_BOUNDARY_FILE, [(10, 0), (11, 1)]),
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(10, 2)])])
        rc, report, md = self.run_check(
            lcov=lcov,
            policy=basic_policy(),
            diff=diff,
            base="deadbeefcafe",
            head="feedface1234",
        )
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertEqual(report["base_sha"], "deadbeefcafe")
        self.assertEqual(report["head_sha"], "feedface1234")
        self.assertIn("deadbeefcafe", md)
        self.assertIn("feedface1234", md)
        block = next(f for f in report["files"] if f["path"] == NON_TRUST_BOUNDARY_FILE)
        self.assertEqual(block["uncovered_lines"], [10])


class TestDiffPathTrailingTab(CheckerTestCase):
    def test_plus_b_line_with_trailing_tab_metadata(self) -> None:
        # Some diff producers (GNU diff(1), `git format-patch` consumers)
        # append a tab plus metadata to the `+++ b/` line. The path must be
        # captured cleanly so downstream lcov.get() finds the records.
        path = NON_TRUST_BOUNDARY_FILE
        lcov = lcov_text(
            [
                (path, [(10, 1), (11, 1)]),
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = (
            f"diff --git a/{path} b/{path}\n"
            "index aaa..bbb 100644\n"
            f"--- a/{path}\t2026-06-21 00:00:00 +0000\n"
            f"+++ b/{path}\t2026-06-21 00:00:01 +0000\n"
            "@@ -0,0 +10,2 @@\n"
        )
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_OK)
        block = next(f for f in report["files"] if f["path"] == path)
        self.assertEqual(block["changed_instrumented"], 2)
        self.assertEqual(block["changed_covered"], 2)


class TestDeletedFile(CheckerTestCase):
    def test_deleted_file_mode_does_not_contribute_changes(self) -> None:
        # A fully-deleted file emits `deleted file mode 100644` and a
        # `@@ -1,N +0,0 @@` hunk. The deletion marker must short-circuit so
        # the file does not appear in report.files.
        lcov = lcov_text(
            [(BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]), (NON_TRUST_BOUNDARY_FILE, [(1, 1)])]
        )
        diff = (
            f"diff --git a/{NON_TRUST_BOUNDARY_FILE} b/{NON_TRUST_BOUNDARY_FILE}\n"
            "deleted file mode 100644\n"
            "index aaa..0000000\n"
            f"--- a/{NON_TRUST_BOUNDARY_FILE}\n"
            "+++ /dev/null\n"
            "@@ -1,5 +0,0 @@\n"
        )
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_OK)
        self.assertEqual(report["files"], [])


class TestTrustBoundaryDaMembership(CheckerTestCase):
    """Table-driven: trust-boundary gate defers to the LCOV DA records — the
    coverage build is the authority on which changed lines are executable.
    Each row pairs a setup with an expected gate outcome."""

    def _baseline_lcov(self, tb_pairs: list[tuple[int, int]]) -> str:
        return lcov_text(
            [(BASIC_TRUST_BOUNDARY_FILE, tb_pairs), (NON_TRUST_BOUNDARY_FILE, [(1, 1)])]
        )

    def cases(
        self,
    ) -> list[tuple[str, str, str, str, int, bool, float | None, str]]:
        # (label, policy, lcov, diff, rc, passed, measured, detail_substring)
        tb95 = basic_policy({"trust_boundary_changed": 95.0})
        below95 = self._baseline_lcov([(n, 1 if n < 19 else 0) for n in range(10, 20)])
        return [
            (
                "only non-instrumented lines changed → pass",
                basic_policy(),
                self._baseline_lcov([(1, 1), (2, 1), (3, 1)]),
                diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(50, 3)])]),
                coverage_check.EXIT_OK,
                True,
                None,
                "no trust-boundary files changed or all fully covered",
            ),
            (
                "instrumented uncovered changed line → fail",
                basic_policy(),
                self._baseline_lcov([(50, 0), (51, 1)]),
                diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(50, 2)])]),
                coverage_check.EXIT_GATE_FAIL,
                False,
                50.0,
                "50",
            ),
            (
                "TB file absent from LCOV → fail",
                basic_policy(),
                lcov_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])]),
                diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(50, 2)])]),
                coverage_check.EXIT_GATE_FAIL,
                False,
                0.0,
                "no LCOV records",
            ),
            (
                "detail reports the configured (non-100) threshold",
                tb95,
                below95,
                diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(10, 10)])]),
                coverage_check.EXIT_GATE_FAIL,
                False,
                90.0,
                "95.00%",
            ),
        ]

    def test_each_row(self) -> None:
        for label, policy, lcov, diff, rc_exp, passed_exp, measured_exp, detail in self.cases():
            with self.subTest(case=label):
                rc, report, _ = self.run_check(lcov=lcov, policy=policy, diff=diff)
                self.assertEqual(rc, rc_exp, label)
                gate = next(
                    g for g in report["gates"] if g["name"] == "trust_boundary_changed"
                )
                self.assertEqual(gate["passed"], passed_exp, label)
                self.assertEqual(gate["measured"], measured_exp, label)
                self.assertIn(detail, gate["detail"], label)


class TestPushMode(CheckerTestCase):
    def test_push_mode_does_not_enforce_changed_gates(self) -> None:
        lcov = lcov_text(
            [
                (NON_TRUST_BOUNDARY_FILE, [(10, 0)]),
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(10, 1)])])
        rc, report, _ = self.run_check(
            lcov=lcov, policy=basic_policy(), diff=diff, mode="push"
        )
        # Overall is 1/2 = 50% → still fails. The per-file gate isn't included.
        gate_names = {g["name"] for g in report["gates"]}
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertEqual(gate_names, {"overall"})


class TestMalformedLcovTable(CheckerTestCase):
    """Table-driven: every reject case must surface as exit 2 with a clear stderr.

    Per CONTRIBUTING.md > Style: one assertion loop, N rows for repeated
    inputs. New malformed-LCOV cases land as rows here, not new classes.
    """

    # Active SF blocks require exactly one LF and exactly one LH, validated
    # under: LH<=LF; LF>=unique DA lines; LH>=unique hit DA lines; and the
    # reconciliation bound (LH - covered_DA) <= (LF - unique_DA). Violations
    # exit 2 with a failure artifact. See parse_lcov's docstring for the
    # full contract.
    CASES: list[tuple[str, str]] = [
        ("non-numeric DA hits", "SF:foo.rs\nDA:1,not-a-number\nend_of_record\n"),
        ("missing end_of_record", "SF:foo.rs\nDA:1,1\nLF:1\nLH:1\n"),
        ("zero DA but LF>0 (contradiction)", "SF:foo.rs\nLF:5\nLH:0\nend_of_record\n"),
        ("new SF before end_of_record", "SF:a.rs\nDA:1,1\nSF:b.rs\nend_of_record\n"),
        ("malformed LF record", "SF:foo.rs\nDA:1,1\nLF:abc\nend_of_record\n"),
        ("malformed LH record", "SF:foo.rs\nDA:1,1\nLF:1\nLH:abc\nend_of_record\n"),
        ("missing LF/LH summary", "SF:foo.rs\nDA:1,1\nend_of_record\n"),
        ("duplicate LF record", "SF:foo.rs\nDA:1,1\nLF:1\nLF:1\nLH:1\nend_of_record\n"),
        ("duplicate LH record", "SF:foo.rs\nDA:1,1\nLF:1\nLH:1\nLH:1\nend_of_record\n"),
        ("LH > LF", "SF:foo.rs\nDA:1,1\nLF:1\nLH:5\nend_of_record\n"),
        ("LF below unique DA lines", "SF:foo.rs\nDA:1,1\nDA:2,1\nLF:1\nLH:2\nend_of_record\n"),
        ("LH below unique hit DA lines", "SF:foo.rs\nDA:1,1\nDA:2,1\nLF:2\nLH:1\nend_of_record\n"),
        # Reconciliation bound: unseen_hits=LH-covered_DA (2-0=2) must
        # not exceed unseen_inst=LF-unique_DA (2-1=1). Producer claims hits
        # behind the DA records that exceed the undeclared instrumentation.
        ("unseen hits exceed unseen instrumented", "SF:foo.rs\nDA:1,0\nLF:2\nLH:2\nend_of_record\n"),
        ("duplicate DA for same line", "SF:foo.rs\nDA:1,1\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"),
        (
            "duplicate SF path",
            "SF:foo.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\nSF:foo.rs\nDA:2,1\nLF:1\nLH:1\nend_of_record\n",
        ),
        ("no records at all", "TN:test\n"),
        # Skipped (out-of-repo) block must still validate record syntax:
        ("malformed DA inside out-of-repo SF", "SF:/etc/passwd\nDA:1,not-a-number\nend_of_record\n"),
        ("out-of-repo SF missing end_of_record", "SF:/etc/passwd\nDA:1,1\n"),
        ("empty SF path", "SF:\nDA:1,1\nend_of_record\n"),
    ]

    def test_every_malformed_input_exits_2(self) -> None:
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        for name, lcov in self.CASES:
            with self.subTest(case=name):
                rc, _, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
                self.assertEqual(
                    rc,
                    coverage_check.EXIT_MALFORMED,
                    f"case {name!r}: expected EXIT_MALFORMED, got {rc}",
                )


class TestMarkdownUncoveredDetail(CheckerTestCase):
    """M2: the Markdown report (not just the JSON) must surface uncovered
    and non-instrumented changed-line detail per file."""

    def test_markdown_contains_uncovered_and_noninstrumented_lines(self) -> None:
        # Line 10 covered, 11 uncovered, 13 changed but non-instrumented.
        lcov = lcov_text(
            [
                (NON_TRUST_BOUNDARY_FILE, [(10, 1), (11, 0)]),
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(10, 4)])])
        rc, _report, md = self.run_check(
            lcov=lcov, policy=basic_policy(), diff=diff
        )
        # Slice the Markdown to the per-file section so the assertion targets
        # the table row, not gate-detail rows that may also mention the file.
        section = md.split("## Per-file changed-line coverage", 1)[1].split(
            "## Overall workspace coverage", 1
        )[0]
        row_line = next(
            line for line in section.splitlines() if NON_TRUST_BOUNDARY_FILE in line
        )
        # Uncovered (11) and non-instrumented (12, 13) numbers must appear
        # in the rendered per-file row.
        self.assertIn("11", row_line, row_line)
        self.assertIn("12", row_line, row_line)
        self.assertIn("13", row_line, row_line)
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)


import shutil


@unittest.skipUnless(shutil.which("git"), "git binary not available")
class RealGitTestCase(unittest.TestCase):
    """Shared harness for the tests that need a real git repository.

    Provides an isolated temporary repo, an env-isolated ``git`` runner, and
    a helper that lays down the checked-in integration fixtures (Rust source,
    LCOV, policy) and produces a two-commit base/head history. Only git
    metadata (init + commits) is generated at runtime; all reviewable content
    comes from ``scripts/tests/fixtures/integration`` per CONTRIBUTING.md's
    "Fixture-based for integration tests ... Never generate fixture content
    at runtime."
    """

    FIXTURES = Path(__file__).resolve().parent / "fixtures" / "integration"
    REL = "crates/chaffra-core/src/config.rs"

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cov-git-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, *args: str) -> str:
        # Inherit the caller env first so PATH reaches git, THEN apply the
        # isolation overrides (otherwise an inherited GIT_CONFIG_GLOBAL
        # escapes the /dev/null isolation). GIT_CONFIG_COUNT=0 blocks per-key
        # config injection.
        env = dict(os.environ)
        env.update(
            {
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "GIT_CONFIG_COUNT": "0",
                "GIT_AUTHOR_NAME": "test",
                "GIT_AUTHOR_EMAIL": "test@example.com",
                "GIT_COMMITTER_NAME": "test",
                "GIT_COMMITTER_EMAIL": "test@example.com",
            }
        )
        return subprocess.check_output(
            ["git", *args], cwd=self.tmp, text=True, env=env
        ).strip()

    def build_fixture_repo(self) -> tuple[str, str]:
        """Lay down the checked-in fixtures and return (base_sha, head_sha)."""
        self.git("init", "-q", "-b", "main")
        (self.tmp / "crates/chaffra-core/src").mkdir(parents=True)
        shutil.copyfile(self.FIXTURES / "config_base.rs", self.tmp / self.REL)
        self.git("add", ".")
        self.git("commit", "-q", "-m", "base")
        base_sha = self.git("rev-parse", "HEAD")
        shutil.copyfile(self.FIXTURES / "config_head.rs", self.tmp / self.REL)
        self.git("add", self.REL)
        self.git("commit", "-q", "-m", "head")
        head_sha = self.git("rev-parse", "HEAD")
        shutil.copyfile(self.FIXTURES / "lcov.info", self.tmp / "lcov.info")
        shutil.copyfile(self.FIXTURES / "policy.toml", self.tmp / "policy.toml")
        return base_sha, head_sha

    def run_main(self, *, base_sha: str, head_sha: str) -> int:
        return coverage_check.main(
            [
                "--lcov", str(self.tmp / "lcov.info"),
                "--policy", str(self.tmp / "policy.toml"),
                "--repo-root", str(self.tmp),
                "--base-sha", base_sha,
                "--head-sha", head_sha,
                "--json-out", str(self.tmp / "out.json"),
                "--markdown-out", str(self.tmp / "out.md"),
                "--mode", "pr",
            ]
        )

    def report(self) -> dict:
        return json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))


class TestMainGitIntegration(RealGitTestCase):
    """M1: drive main() through the production acquisition path
    (`git diff base...head`, `git ls-tree`) with neither --diff nor
    --repo-files supplied."""

    def test_end_to_end_via_git(self) -> None:
        base_sha, head_sha = self.build_fixture_repo()
        rc = self.run_main(base_sha=base_sha, head_sha=head_sha)
        self.assertEqual(rc, coverage_check.EXIT_OK)
        report = self.report()
        self.assertEqual(report["base_sha"], base_sha)
        self.assertEqual(report["head_sha"], head_sha)
        self.assertEqual([f["path"] for f in report["files"]], [self.REL])


class TestStagedFileNotEligible(RealGitTestCase):
    """H5: a generated .rs file staged into the index after the head commit
    must NOT become an eligible coverage source. The universe is derived
    from `git ls-tree <head_sha>` (immutable tree), not `git ls-files`
    (mutable index)."""

    def test_staged_generated_file_dropped_from_overall(self) -> None:
        base_sha, head_sha = self.build_fixture_repo()
        # Simulate a build script staging a generated, fully-covered .rs file
        # that is NOT in the head commit. All fixture content — both the
        # staged Rust source and the LCOV that includes a block for it —
        # comes from the checked-in `scripts/tests/fixtures/integration/`
        # directory per CONTRIBUTING.md's "Never generate fixture content
        # at runtime"; only the `git add` of the file is dynamic.
        gen_rel = "crates/chaffra-core/src/generated.rs"
        shutil.copyfile(self.FIXTURES / "staged_generated.rs", self.tmp / gen_rel)
        self.git("add", gen_rel)  # staged, but never committed → not in head tree
        shutil.copyfile(self.FIXTURES / "staged_lcov.info", self.tmp / "lcov.info")
        rc = self.run_main(base_sha=base_sha, head_sha=head_sha)
        report = self.report()
        # The staged file's records must be dropped, not counted toward overall.
        self.assertIn(gen_rel, report["overall"]["dropped_synthetic_sf_paths"])
        self.assertEqual(rc, coverage_check.EXIT_OK)
        # Overall denominator is only the committed file's 2 lines.
        self.assertEqual(report["overall"]["instrumented_lines"], 2)


class TestExactHeadValidation(RealGitTestCase):
    """H6: the `git rev-parse HEAD == --head-sha` check must reject a
    mismatched head_sha with a failure artifact, not just guard the happy
    path. Reuses the shared fixture repo and harness."""

    def test_mismatched_head_sha_exits_2_with_failure_artifact(self) -> None:
        base_sha, head_sha = self.build_fixture_repo()
        bogus = "0" * 40
        rc = self.run_main(base_sha=base_sha, head_sha=bogus)
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        payload = self.report()
        self.assertEqual(payload["status"], "malformed_input")
        self.assertEqual(payload["head_sha"], bogus)
        # Detail must name the actual HEAD so the mismatch is auditable.
        self.assertIn(head_sha, payload["detail"])
        self.assertIn("MALFORMED INPUT", (self.tmp / "out.md").read_text(encoding="utf-8"))


class TestMalformedDiffTable(CheckerTestCase):
    """Table-driven: malformed unified-diff inputs exit 2."""

    CASES: list[tuple[str, str]] = [
        ("bad diff --git header", "diff --git garbage\n"),
        ("bad +++ line", "diff --git a/x.rs b/x.rs\n+++ nonsense\n"),
        (
            "bad hunk header",
            "diff --git a/x.rs b/x.rs\n--- a/x.rs\n+++ b/x.rs\n@@ broken @@\n",
        ),
        (
            "hunk before any file header",
            "@@ -0,0 +1,2 @@\n",
        ),
    ]

    def test_every_malformed_diff_exits_2(self) -> None:
        lcov = lcov_text([(BASIC_TRUST_BOUNDARY_FILE, [(1, 1)])])
        for name, diff in self.CASES:
            with self.subTest(case=name):
                rc, _, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
                self.assertEqual(rc, coverage_check.EXIT_MALFORMED, name)


class TestMainIoErrorPaths(CheckerTestCase):
    """The main() error branches each produce a failure artifact and exit 2.

    These drive the production argument-handling paths (unreadable lcov,
    policy, diff, repo-files) that the synthetic happy-path tests do not."""

    def _argv(self, **overrides: str) -> list[str]:
        lcov_path = write(self.tmp / "lcov.info", lcov_text([(BASIC_TRUST_BOUNDARY_FILE, [(1, 1)])]))
        policy_path = write(self.tmp / "policy.toml", basic_policy())
        diff_path = write(self.tmp / "diff.txt", diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])]))
        argv = {
            "--lcov": str(lcov_path),
            "--policy": str(policy_path),
            "--diff": str(diff_path),
            "--base-sha": "aaaa",
            "--head-sha": "bbbb",
            "--repo-files": str(self.repo_files_path),
            "--repo-root": str(self.tmp),
            "--json-out": str(self.tmp / "out.json"),
            "--markdown-out": str(self.tmp / "out.md"),
            "--mode": "pr",
        }
        argv.update(overrides)
        out: list[str] = ["--allow-head-drift"]
        for k, v in argv.items():
            out += [k, v]
        return out

    def test_unreadable_lcov_exits_2(self) -> None:
        rc = coverage_check.main(self._argv(**{"--lcov": str(self.tmp / "nope.info")}))
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        payload = json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))
        self.assertIn("cannot read lcov", payload["detail"])

    def test_unreadable_diff_exits_2(self) -> None:
        rc = coverage_check.main(self._argv(**{"--diff": str(self.tmp / "nope.txt")}))
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        self.assertIn("cannot read diff", json.loads(
            (self.tmp / "out.json").read_text(encoding="utf-8"))["detail"])

    def test_unreadable_policy_exits_2(self) -> None:
        rc = coverage_check.main(self._argv(**{"--policy": str(self.tmp / "nope.toml")}))
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        self.assertIn("invalid policy", json.loads(
            (self.tmp / "out.json").read_text(encoding="utf-8"))["detail"])

    def test_unreadable_repo_files_exits_2(self) -> None:
        rc = coverage_check.main(self._argv(**{"--repo-files": str(self.tmp / "nope.txt")}))
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        self.assertIn("cannot read repo-files", json.loads(
            (self.tmp / "out.json").read_text(encoding="utf-8"))["detail"])


class TestShortListTruncation(CheckerTestCase):
    def test_more_than_20_uncovered_lines_truncated_in_output(self) -> None:
        # 25 changed lines, all uncovered → _short_list truncates to 20 + "(+5)".
        lines = [(n, 0) for n in range(10, 35)]
        lcov = lcov_text(
            [(NON_TRUST_BOUNDARY_FILE, lines), (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)])]
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(10, 25)])])
        rc, _report, md = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertIn("(+5)", md)


class TestGitAcquisitionFailures(RealGitTestCase):
    """The production git paths (ls-tree, diff) raise MalformedInput → exit 2
    with a failure artifact when run outside a usable repo state."""

    def test_missing_repo_files_and_diff_uses_git_and_can_fail(self) -> None:
        # A real repo, but request a base SHA that does not exist → the
        # `git diff base...head` acquisition path raises MalformedInput.
        base_sha, head_sha = self.build_fixture_repo()
        rc = coverage_check.main(
            [
                "--lcov", str(self.tmp / "lcov.info"),
                "--policy", str(self.tmp / "policy.toml"),
                "--repo-root", str(self.tmp),
                "--base-sha", "0" * 40,  # nonexistent base → git diff fails
                "--head-sha", head_sha,
                "--json-out", str(self.tmp / "out.json"),
                "--markdown-out", str(self.tmp / "out.md"),
                "--mode", "pr",
                # No --diff and no --repo-files: exercise both git paths.
            ]
        )
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        self.assertEqual(self.report()["status"], "malformed_input")


class TestSecurityBranchCoverage(CheckerTestCase):
    """Drives the remaining input-validation / path-safety / integrity
    branches of the checker so its security-relevant code reaches 100%.
    Every case uses a real input (no mocks)."""

    def test_blank_line_in_lcov_is_skipped(self) -> None:
        lcov = (
            "\n\nSF:crates/chaffra-core/src/config.rs\n\nDA:1,1\n\n"
            "LF:1\nLH:1\nend_of_record\n\n"
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, _r, _m = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        # config.rs fully covered (1/1); overall passes, no TB change.
        self.assertEqual(rc, coverage_check.EXIT_OK)

    def test_end_of_record_outside_sf_block_is_malformed(self) -> None:
        rc, report, _ = self.run_check(
            lcov="end_of_record\n", policy=basic_policy(),
            diff=diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])]),
        )
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        self.assertIn("end_of_record outside SF block", report["detail"])

    def test_lf_below_unique_da_lines_is_malformed(self) -> None:
        # LF=1 < 2 unique DA lines, with LH=1<=LF and LH>=unique hit (1) so
        # the LF<unique-DA branch is the one that fires.
        lcov = "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nDA:2,0\nLF:1\nLH:1\nend_of_record\n"
        rc, report, _ = self.run_check(
            lcov=lcov, policy=basic_policy(),
            diff=diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])]),
        )
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        self.assertIn("below", report["detail"])

    def test_absolute_in_repo_sf_path_is_normalized(self) -> None:
        # An absolute SF path inside repo_root exercises the absolute-path
        # branch of _normalize_path (resolve + relative_to + as_posix).
        abs_path = str(self.tmp / NON_TRUST_BOUNDARY_FILE)
        lcov = (
            f"SF:{abs_path}\nDA:1,1\nDA:2,0\nLF:2\nLH:1\nend_of_record\n"
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(10, 1)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        # The absolute path normalized to the repo-relative key, so main.rs
        # is an eligible file (2 instrumented lines counted).
        self.assertEqual(report["overall"]["instrumented_lines"], 3)

    def test_backslash_sf_path_normalizes_to_posix_key(self) -> None:
        # cargo-llvm-cov on Windows emits SF paths with backslash separators.
        # _normalize_path converts them so the block keys to the same
        # repo-relative POSIX path the policy and diff use, rather than a
        # single opaque filename that would be dropped.
        lcov = (
            "SF:crates\\chaffra-core\\src\\config.rs\nDA:1,1\nDA:2,1\nLF:2\nLH:2\nend_of_record\n"
        )
        diff = diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(1, 2)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        # The backslash path matched config.rs, so its 2 lines count and the
        # trust-boundary changed lines are fully covered.
        self.assertEqual(report["overall"]["instrumented_lines"], 2)
        block = next(f for f in report["files"] if f["path"] == BASIC_TRUST_BOUNDARY_FILE)
        self.assertEqual(block["changed_covered"], 2)
        self.assertEqual(rc, coverage_check.EXIT_OK)

    def test_sf_path_with_null_byte_is_dropped(self) -> None:
        # A null byte makes Path.resolve() raise ValueError; _normalize_path
        # must return None (drop the block) rather than crash — the path
        # below also keeps a valid block so total_lf != 0.
        lcov = (
            "SF:crates/chaffra-core/src/bad\x00name.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        # Only the valid config.rs block contributes.
        self.assertEqual(report["overall"]["instrumented_lines"], 1)

    # NB: top-level keys (`trust_boundaries`) must precede the [thresholds]
    # table header, else TOML scopes them inside that table.
    def test_trust_boundaries_not_an_array_is_invalid(self) -> None:
        policy = (
            'policy_version = 1\ntrust_boundaries = "x"\n'
            "[thresholds]\noverall = 85.0\naggregate_changed = 95.0\n"
            "per_file_changed = 90.0\ntrust_boundary_changed = 100.0\n"
        )
        rc, report, _ = self.run_check(
            lcov=lcov_text([(BASIC_TRUST_BOUNDARY_FILE, [(1, 1)])]),
            policy=policy, diff=diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])]),
        )
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        self.assertIn("must be an array", report["detail"])

    def test_trust_boundary_entry_not_a_table_is_invalid(self) -> None:
        policy = (
            'policy_version = 1\ntrust_boundaries = ["x"]\n'
            "[thresholds]\noverall = 85.0\naggregate_changed = 95.0\n"
            "per_file_changed = 90.0\ntrust_boundary_changed = 100.0\n"
        )
        rc, report, _ = self.run_check(
            lcov=lcov_text([(BASIC_TRUST_BOUNDARY_FILE, [(1, 1)])]),
            policy=policy, diff=diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])]),
        )
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        self.assertIn("must be a table", report["detail"])


class TestBranchCompleteness(CheckerTestCase):
    """Closes the remaining benign fall-through branches so the checker
    reaches 100% line+branch coverage (it is security/validation code, held
    to the 100% trust-boundary standard, not the 95% delta standard)."""

    def test_ignored_lcov_records_fall_through(self) -> None:
        # FN/FNDA/BRDA records inside an active block are ignored — exercise
        # the "other record" fall-through that real cargo-llvm-cov emits.
        lcov = (
            "SF:crates/chaffra-core/src/config.rs\n"
            "FN:1,some_fn\nFNDA:1,some_fn\nBRDA:1,0,0,1\n"
            "DA:1,1\nLF:1\nLH:1\nend_of_record\n"
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, _r, _m = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_OK)

    def test_empty_rename_target_falls_through(self) -> None:
        # `rename to ` with no target does not match the rename regex; the
        # parser must fall through without recording a rename.
        diff = (
            "diff --git a/old.rs b/new.rs\n"
            "rename from old.rs\n"
            "rename to \n"  # empty target → no regex match
            "diff --git a/crates/chaffra-cli/src/main.rs b/crates/chaffra-cli/src/main.rs\n"
            "--- a/crates/chaffra-cli/src/main.rs\n"
            "+++ b/crates/chaffra-cli/src/main.rs\n"
            "@@ -0,0 +1 @@\n"
        )
        lcov = lcov_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)]), (BASIC_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, _r, _m = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        self.assertEqual(rc, coverage_check.EXIT_OK)

    def test_second_trust_boundary_file_does_not_lower_worst(self) -> None:
        # Two changed TB files: the first is below 100%, the second is fully
        # covered, exercising the `worst is None or percent < worst` false
        # branch (second file's percent does not lower the worst).
        policy = basic_policy()
        # Override the policy to make both files trust boundaries.
        policy = policy.replace(
            'patterns = ["crates/chaffra-core/src/config.rs"]',
            'patterns = ["crates/chaffra-core/src/config.rs", '
            '"crates/chaffra-cli/src/main.rs"]',
        )
        # file_results is sorted by path: `chaffra-cli/...main.rs` sorts
        # before `chaffra-core/...config.rs`, so the FIRST-iterated TB file
        # must be the worst to reach the `percent < worst` false branch on
        # the second file.
        lcov = lcov_text(
            [
                (NON_TRUST_BOUNDARY_FILE, [(20, 0), (21, 1)]),    # cli/main.rs: 50%, worst, first
                (BASIC_TRUST_BOUNDARY_FILE, [(10, 1), (11, 1)]),  # core/config.rs: 100%, second
            ]
        )
        diff = diff_text(
            [
                (BASIC_TRUST_BOUNDARY_FILE, [(10, 2)]),
                (NON_TRUST_BOUNDARY_FILE, [(20, 2)]),
            ]
        )
        rc, report, _ = self.run_check(lcov=lcov, policy=policy, diff=diff)
        gate = next(g for g in report["gates"] if g["name"] == "trust_boundary_changed")
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertEqual(gate["measured"], 50.0)  # worst stayed at the first file

    def test_runs_without_optional_output_paths(self) -> None:
        # Success path and the malformed path with neither --json-out nor
        # --markdown-out — exercises the optional-output None branches.
        lcov_path = write(self.tmp / "lcov.info", lcov_text([(BASIC_TRUST_BOUNDARY_FILE, [(1, 1)])]))
        policy_path = write(self.tmp / "policy.toml", basic_policy())
        diff_path = write(self.tmp / "diff.txt", diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])]))
        common = [
            "--lcov", str(lcov_path), "--policy", str(policy_path),
            "--base-sha", "aaaa", "--head-sha", "bbbb",
            "--repo-files", str(self.repo_files_path), "--repo-root", str(self.tmp),
            "--mode", "pr", "--allow-head-drift",
        ]
        # Success, no output files requested.
        rc_ok = coverage_check.main(common + ["--diff", str(diff_path)])
        self.assertEqual(rc_ok, coverage_check.EXIT_OK)
        # Malformed, no output files requested (fail_malformed None branches).
        rc_bad = coverage_check.main(
            ["--lcov", str(self.tmp / "missing.info")] + common[2:] + ["--diff", str(diff_path)]
        )
        self.assertEqual(rc_bad, coverage_check.EXIT_MALFORMED)


class TestMainGitFailurePaths(unittest.TestCase):
    """The git-acquisition and artifact-write failure branches in main(),
    driven with real broken states (a non-git directory, an unwritable
    output path) — no mocks."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cov-fail-"))
        self.lcov = write(self.tmp / "lcov.info", "SF:a.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n")
        self.policy = write(
            self.tmp / "p.toml",
            "policy_version = 1\n[thresholds]\noverall = 85.0\n"
            "aggregate_changed = 95.0\nper_file_changed = 90.0\n"
            'trust_boundary_changed = 100.0\n[[trust_boundaries]]\n'
            'purpose = "x"\npatterns = ["a.rs"]\n',
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _base_argv(self) -> list[str]:
        return [
            "--lcov", str(self.lcov),
            "--policy", str(self.policy),
            "--repo-root", str(self.tmp),
            "--base-sha", "aaaa",
            "--head-sha", "bbbb",
            "--json-out", str(self.tmp / "out.json"),
            "--markdown-out", str(self.tmp / "out.md"),
            "--mode", "pr",
        ]

    @unittest.skipUnless(shutil.which("git"), "git binary not available")
    def test_ls_tree_failure_in_non_git_dir(self) -> None:
        # No --repo-files and --allow-head-drift: list_tracked_rs_files runs
        # `git ls-tree` in a non-git directory → CalledProcessError →
        # MalformedInput → fail_malformed.
        rc = coverage_check.main(self._base_argv() + ["--allow-head-drift", "--diff",
                                                      str(write(self.tmp / "d.txt", ""))])
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        payload = json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))
        self.assertIn("git ls-tree failed", payload["detail"])

    @unittest.skipUnless(shutil.which("git"), "git binary not available")
    def test_head_drift_check_fails_in_non_git_dir(self) -> None:
        # Without --allow-head-drift, `git rev-parse HEAD` runs in a non-git
        # directory and fails → fail_malformed.
        rc = coverage_check.main(self._base_argv())
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        payload = json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))
        self.assertIn("cannot read repo HEAD", payload["detail"])

    def test_failure_artifact_write_error_is_warned_not_fatal(self) -> None:
        # A malformed input plus an unwritable --json-out path exercises the
        # OSError handler in fail_malformed: the run still exits 2 (it does
        # not crash on the secondary write failure).
        argv = [
            "--lcov", str(self.tmp / "missing.info"),  # malformed: unreadable
            "--policy", str(self.policy),
            "--repo-root", str(self.tmp),
            "--base-sha", "aaaa", "--head-sha", "bbbb",
            "--json-out", str(self.tmp / "no_such_dir" / "out.json"),  # unwritable
            "--markdown-out", str(self.tmp / "no_such_dir" / "out.md"),
            "--mode", "pr", "--allow-head-drift",
        ]
        rc = coverage_check.main(argv)
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)


@unittest.skipUnless(shutil.which("git"), "git binary not available")
class TestSourceLineCountsAndH7(RealGitTestCase):
    """H7: a producer cannot fabricate covered evidence at DA coordinates that
    do not exist in the immutable head_sha:path blob. `get_source_line_counts`
    reads each blob via `git cat-file --batch` and `evaluate` rejects DA lines
    that are line 0 or beyond the blob's range. Drives the helper's edge
    cases plus the end-to-end refusal via the real-git harness."""

    def test_empty_paths_returns_empty_dict(self) -> None:
        self.build_fixture_repo()
        self.assertEqual(
            coverage_check.get_source_line_counts(self.tmp, "HEAD", []), {}
        )

    def test_missing_path_omitted(self) -> None:
        # A `<spec> missing` header in `git cat-file --batch` output must not
        # raise; the path is simply omitted from the result. Eligibility has
        # already filtered out unknown paths in the production flow, so this
        # is only reachable when something concurrent advances HEAD between
        # ls-tree and cat-file — but we still handle it defensively.
        self.build_fixture_repo()
        counts = coverage_check.get_source_line_counts(
            self.tmp, "HEAD", [self.REL, "does/not/exist.rs"]
        )
        self.assertIn(self.REL, counts)
        self.assertNotIn("does/not/exist.rs", counts)

    def test_blob_without_trailing_newline_counts_trailer(self) -> None:
        # Two-line file with no final newline → 2, exercising the
        # `if blob and not blob.endswith(b"\\n"): line_count += 1` branch.
        # The integration fixture `config_head.rs` is exactly this shape, so
        # the integration test path also covers it; this guards the line
        # number against rot.
        self.build_fixture_repo()
        counts = coverage_check.get_source_line_counts(self.tmp, "HEAD", [self.REL])
        self.assertEqual(counts[self.REL], 2)

    # Table-driven: H7 rejects DA coordinates that the immutable head_sha:path
    # blob cannot contain. Each row is (label, lcov_body) where the body is
    # an SF block referencing `self.REL` (2 lines at HEAD).
    _OUT_OF_RANGE_DA_CASES: tuple[tuple[str, str], ...] = (
        ("DA line beyond blob range",
         "DA:1,1\nDA:999,1\nLF:2\nLH:2\nend_of_record\n"),
        ("DA line zero (LCOV is 1-based)",
         "DA:0,1\nDA:1,1\nLF:2\nLH:2\nend_of_record\n"),
        ("DA line exactly max+1",
         "DA:1,1\nDA:3,1\nLF:2\nLH:2\nend_of_record\n"),
    )

    def test_out_of_range_da_lines_are_malformed(self) -> None:
        base_sha, head_sha = self.build_fixture_repo()
        for label, body in self._OUT_OF_RANGE_DA_CASES:
            with self.subTest(case=label):
                (self.tmp / "lcov.info").write_text(
                    f"SF:{self.REL}\n{body}", encoding="utf-8"
                )
                rc = self.run_main(base_sha=base_sha, head_sha=head_sha)
                self.assertEqual(rc, coverage_check.EXIT_MALFORMED, label)
                detail = self.report()["detail"]
                self.assertIn("outside source range", detail, label)

    def test_unknown_head_sha_emits_missing_for_all_paths(self) -> None:
        # `cat-file --batch` writes "<spec> missing\n" (and returns 0) for an
        # unknown sha. The helper drops missing entries, returning an empty
        # dict; the H7 gate then refuses to validate (max_line is None →
        # MalformedInput in evaluate, exercised by
        # TestH7MaxLineNoneInEvaluate below).
        self.build_fixture_repo()
        counts = coverage_check.get_source_line_counts(
            self.tmp, "0" * 40, [self.REL]
        )
        self.assertEqual(counts, {})

    def test_oserror_bad_cwd_surfaces_as_malformed(self) -> None:
        # subprocess.run raises FileNotFoundError (subclass of OSError) when
        # cwd does not exist — the helper must convert it to MalformedInput
        # so a malformed-artifact path is produced rather than a Python
        # traceback escaping main().
        with self.assertRaises(coverage_check.MalformedInput) as ctx:
            coverage_check.get_source_line_counts(
                Path("/no/such/path"), "HEAD", ["a.rs"]
            )
        self.assertIn("cat-file", str(ctx.exception))

    def test_nonzero_returncode_in_non_git_dir_is_malformed(self) -> None:
        # cat-file in a real-but-not-a-git directory returns 128 with
        # `fatal: not a git repository`. The helper must raise MalformedInput
        # rather than silently returning empty counts (which would let an
        # attacker present any DA coordinates as "outside no range").
        tmp = Path(tempfile.mkdtemp(prefix="cov-nogit-"))
        try:
            with self.assertRaises(coverage_check.MalformedInput) as ctx:
                coverage_check.get_source_line_counts(tmp, "HEAD", ["a.rs"])
            self.assertIn("cat-file", str(ctx.exception))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_non_blob_spec_is_malformed(self) -> None:
        # Passing a path that resolves to a tree (not a blob) is malformed:
        # the parser cannot count source lines for a tree, and silently
        # skipping it would let a future caller's offset accounting desync.
        self.build_fixture_repo()
        # `crates/chaffra-core/src` is the directory holding REL; the spec
        # `<head>:crates/chaffra-core/src` resolves to a tree.
        with self.assertRaises(coverage_check.MalformedInput) as ctx:
            coverage_check.get_source_line_counts(
                self.tmp, "HEAD", ["crates/chaffra-core/src"]
            )
        self.assertIn("blob header", str(ctx.exception))

    def test_truncated_cat_file_output_is_malformed(self) -> None:
        # Defensive: if cat-file's stdout is truncated mid-record (the kernel
        # killed the subprocess between writes, a pipe broke), the helper
        # must raise MalformedInput rather than misalign the parse. Real
        # subprocess.run will never produce this, so the only deterministic
        # way to exercise the branch is to stub the subprocess call. Stdlib
        # unittest.mock keeps the test self-contained.
        import unittest.mock as _mock
        class _FakeProc:
            returncode = 0
            stdout = b"deadbeef blob"  # no terminating newline at all
            stderr = b""
        self.build_fixture_repo()
        with _mock.patch.object(coverage_check.subprocess, "run", return_value=_FakeProc()):
            with self.assertRaises(coverage_check.MalformedInput) as ctx:
                coverage_check.get_source_line_counts(self.tmp, "HEAD", [self.REL])
        self.assertIn("truncated", str(ctx.exception))

    def test_blob_without_trailing_newline_counts_trailer_real_git(self) -> None:
        # cargo-llvm-cov emits DA records up to the last source line, so a
        # file without a final newline must count its trailing line. Commit
        # a file ending mid-line and verify the count is 3, not 2.
        self.build_fixture_repo()
        no_trailer = self.tmp / "crates/chaffra-core/src/no_trailing_newline.rs"
        no_trailer.write_text("a\nb\nc", encoding="utf-8")  # 3 lines, no \n at end
        self.git("add", str(no_trailer.relative_to(self.tmp)))
        self.git("commit", "-q", "-m", "no-trailer")
        counts = coverage_check.get_source_line_counts(
            self.tmp,
            "HEAD",
            ["crates/chaffra-core/src/no_trailing_newline.rs"],
        )
        self.assertEqual(counts["crates/chaffra-core/src/no_trailing_newline.rs"], 3)


@unittest.skipUnless(shutil.which("git"), "git binary not available")
class TestH7MaxLineNoneInEvaluate(RealGitTestCase):
    """H7 also fires in `evaluate` when a tracked file is in eligible_lcov
    but absent from source_line_counts — e.g. a race between ls-tree and
    cat-file. The path is reachable end-to-end by supplying --repo-files
    that lists a path NOT present in the head tree blob (so cat-file returns
    `missing` for it), while the LCOV references that path."""

    def test_eligible_path_missing_from_source_counts_is_malformed(self) -> None:
        base_sha, head_sha = self.build_fixture_repo()
        # repo-files claims `ghost.rs` is tracked; the head tree does not
        # contain it. cat-file therefore returns missing for it, so
        # source_line_counts has no entry for `ghost.rs` — but evaluate sees
        # it in eligible_lcov and raises MalformedInput rather than silently
        # accepting unbounded DA coordinates.
        repo_files = self.tmp / "repo-files.txt"
        repo_files.write_text("ghost.rs\n" + self.REL + "\n", encoding="utf-8")
        (self.tmp / "lcov.info").write_text(
            "SF:ghost.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"
            "SF:" + self.REL + "\nDA:1,1\nDA:2,1\nLF:2\nLH:2\nend_of_record\n",
            encoding="utf-8",
        )
        rc = coverage_check.main(
            [
                "--lcov", str(self.tmp / "lcov.info"),
                "--policy", str(self.tmp / "policy.toml"),
                "--repo-root", str(self.tmp),
                "--base-sha", base_sha,
                "--head-sha", head_sha,
                "--repo-files", str(repo_files),
                "--json-out", str(self.tmp / "out.json"),
                "--markdown-out", str(self.tmp / "out.md"),
                "--mode", "pr",
            ]
        )
        self.assertEqual(rc, coverage_check.EXIT_MALFORMED)
        payload = json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))
        self.assertIn("source line count missing", payload["detail"])
        self.assertIn("ghost.rs", payload["detail"])


class TestSkippedBlockInvariants(CheckerTestCase):
    """M13: out-of-repo (SKIPPED) blocks must satisfy the same LF/LH
    structural invariants the in-repo (ACTIVE) blocks do. A malformed summary
    inside a skipped block was previously discarded silently."""

    CASES: list[tuple[str, str]] = [
        (
            "skipped block missing LF/LH",
            "SF:/etc/passwd\nDA:1,1\nend_of_record\n"
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n",
        ),
        (
            "skipped block duplicate LF",
            "SF:/etc/passwd\nDA:1,1\nLF:1\nLF:1\nLH:1\nend_of_record\n"
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n",
        ),
        (
            "skipped block duplicate LH",
            "SF:/etc/passwd\nDA:1,1\nLF:1\nLH:1\nLH:1\nend_of_record\n"
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n",
        ),
        (
            "skipped block LH > LF",
            "SF:/etc/passwd\nDA:1,1\nLF:1\nLH:5\nend_of_record\n"
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n",
        ),
        (
            "skipped block LF below unique DA",
            "SF:/etc/passwd\nDA:1,1\nDA:2,1\nLF:1\nLH:2\nend_of_record\n"
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n",
        ),
        (
            "skipped block LF:0 with DA contradicts",
            "SF:/etc/passwd\nLF:5\nLH:0\nend_of_record\n"
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n",
        ),
        (
            "skipped block unseen-hits exceeds unseen-instrumented",
            "SF:/etc/passwd\nDA:1,0\nLF:2\nLH:2\nend_of_record\n"
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n",
        ),
    ]

    def test_every_skipped_invariant_rejected(self) -> None:
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        for label, lcov in self.CASES:
            with self.subTest(case=label):
                rc, _r, _m = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
                self.assertEqual(
                    rc, coverage_check.EXIT_MALFORMED,
                    f"case {label!r}: expected EXIT_MALFORMED, got {rc}",
                )

    def test_skipped_lf0_lh0_no_da_accepted(self) -> None:
        # Symmetric to the ACTIVE case: an SF with zero executable lines
        # (LF:0/LH:0, no DA) is legitimate and the SKIPPED variant must NOT
        # be rejected — it just contributes nothing.
        lcov = (
            "SF:/etc/passwd\nLF:0\nLH:0\nend_of_record\n"
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        # Only the valid in-repo block contributes (1/1 = 100%); overall passes.
        self.assertEqual(rc, coverage_check.EXIT_OK, report.get("gates"))
        self.assertEqual(report["overall"]["instrumented_lines"], 1)


# ---------------------------------------------------------------------------
# Structural cfg parser support (H4a)
# ---------------------------------------------------------------------------
#
# The H4a guard parses Rust `cfg(...)` predicates structurally rather than
# scraping them with a regex (which had several documented blind spots:
# nested predicates truncated at the first `)`, multi-line forms missed
# entirely, `cfg_attr` ignored, only a subset of `target_*` predicates
# recognized). The AST and helpers below are scoped to the test file because
# the production checker never inspects source — only LCOV — so the parser
# has no place in `coverage_check.py`.


class _CfgParseError(Exception):
    """Raised by the H4a structural parser; treated as a fail-closed offender."""


class _CfgPred:
    """Marker base class for parsed cfg predicates (no behavior of its own)."""


class _CfgLiteral(_CfgPred):
    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:  # pragma: no cover  (diagnostic only)
        return f"Literal({self.name!r})"


class _CfgEquals(_CfgPred):
    __slots__ = ("key", "value")

    def __init__(self, key: str, value: str) -> None:
        self.key = key
        self.value = value

    def __repr__(self) -> str:  # pragma: no cover  (diagnostic only)
        return f"Equals({self.key!r}, {self.value!r})"


class _CfgNot(_CfgPred):
    __slots__ = ("child",)

    def __init__(self, child: _CfgPred) -> None:
        self.child = child


class _CfgAny(_CfgPred):
    __slots__ = ("children",)

    def __init__(self, children: list[_CfgPred]) -> None:
        self.children = children


class _CfgAll(_CfgPred):
    __slots__ = ("children",)

    def __init__(self, children: list[_CfgPred]) -> None:
        self.children = children


def _split_top_level_comma(text: str) -> tuple[str, str]:
    """Split ``text`` at the FIRST top-level comma (outside string/paren).

    Returns ``(before, after)``. If no top-level comma exists, ``after`` is
    the empty string. Used by the `cfg_attr(P, attr)` extractor to isolate
    the gating predicate P from the conditionally-applied attribute.
    """
    depth = 0
    in_str = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            return text[:i], text[i + 1 :]
        i += 1
    return text, ""


class TestPolicyAndCiInvariants(unittest.TestCase):
    """Regression guards that keep the multi-target coverage mechanism honest
    (chaffra#49 / H4).

    H4 is closed by two orthogonal exhaustiveness mechanisms, each sourced
    from an authority rather than a hand-maintained table:

      * **Targets** — the `coverage-instrument` matrix runs `cargo llvm-cov`
        once per target the workspace builds on (linux + macos). The guard
        derives each leg's active cfg from ``rustc --print cfg --target
        <triple>`` (rustc is the authority), so a trust-boundary cfg that no
        leg can satisfy is flagged.
      * **Features** — each leg drives coverage through
        ``cargo hack --feature-powerset``, instrumenting EVERY feature
        combination, so both ``cfg(feature = "x")`` and
        ``cfg(not(feature = "x"))`` (and all combinations for N>1 features)
        reach LCOV by construction. The guard treats a crate's defined
        features as free variables when testing cfg satisfiability.

    The guard therefore fails the build iff a trust-boundary file contains a
    cfg that is unsatisfiable across (every matrix leg) × (the feature
    powerset) — i.e. genuinely un-instrumentable executable code — or a
    conditional form the structural parser cannot understand (fail closed).
    """

    WORKSPACE = Path(__file__).resolve().parents[2]

    @staticmethod
    def _expand_policy_paths() -> set[str]:
        """Return the union of trust-boundary file paths the policy matches.

        Reuses the checker's own policy loader and glob expansion against
        the immutable tracked-file set at HEAD (``git ls-tree -r``), so a
        policy entry written as a glob (``crates/.../backends/*.rs``) is
        treated identically here and at gate time. Previously this helper
        regex-scraped literal-looking path tokens out of the TOML, which
        silently dropped any sanctioned glob.
        """
        workspace = TestPolicyAndCiInvariants.WORKSPACE
        policy = coverage_check.load_policy(workspace / ".github" / "coverage-policy.toml")
        tracked = coverage_check.list_tracked_rs_files(workspace, "HEAD")
        matched, _ = coverage_check.expand_trust_boundary_files(policy, tracked)
        return matched

    @staticmethod
    def _matrix_target_triples() -> list[str]:
        """Return the rustc target triple of each coverage-instrument leg.

        Parsed from the `triple:` field on each matrix entry in ci.yml
        (comment lines are ignored so a prose mention cannot inject a leg).
        The triple is authoritative: the guard feeds it to ``rustc --print
        cfg --target <triple>`` for the exact cfg rustc activates, and CI's
        self-verify step asserts the runner's ``rustc -vV`` host equals it —
        so there is no hand-maintained target→cfg table to drift.
        """
        ci_path = TestPolicyAndCiInvariants.WORKSPACE / ".github" / "workflows" / "ci.yml"
        triples: list[str] = []
        for raw in ci_path.read_text(encoding="utf-8").splitlines():
            stripped = raw.strip()
            if stripped.startswith("#"):
                continue
            m = re.match(r'triple:\s*"?([A-Za-z0-9_.-]+)"?$', stripped)
            if m:
                triples.append(m.group(1))
        return triples

    @staticmethod
    def _rustc_target_cfg(triple: str) -> tuple[frozenset[str], dict[str, frozenset[str]]]:
        """Return ``(names, pairs)`` of the cfg rustc activates for ``triple``.

        ``names`` is the set of bare cfg atoms (``unix``, ``windows``, ...);
        ``pairs`` maps each keyed cfg (``target_os``, ``target_arch``,
        ``target_feature``, ...) to the set of values rustc prints — a key
        like ``target_feature`` legitimately has many values. Sourced from
        ``rustc --print cfg --target <triple>``, which computes the target's
        cfg without the target's std being installed, so a Linux host can
        answer for the macOS leg. This is the authoritative replacement for
        the hand-maintained target table that round-6 review flagged as
        incomplete.
        """
        out = subprocess.check_output(
            ["rustc", "--print", "cfg", "--target", triple], text=True
        )
        names: set[str] = set()
        pairs: dict[str, set[str]] = {}
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            if "=" in line:
                # `key="value"`. Split on the FIRST `=` (rustc never emits a
                # bare `=` in a key) and strip exactly ONE surrounding quote
                # pair from the value — not all quote characters — so an
                # (unlikely) value containing a literal quote is preserved.
                key, _, val = line.partition("=")
                val = val.strip()
                if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
                    val = val[1:-1]
                pairs.setdefault(key.strip(), set()).add(val)
            else:
                names.add(line)
        return frozenset(names), {k: frozenset(v) for k, v in pairs.items()}

    @staticmethod
    def _parse_workspace_features() -> dict[str, frozenset[str]]:
        """Return ``{crate: frozenset[defined_feature_name]}`` for the workspace.

        Every feature in a crate's ``[features]`` table (including the
        implicit ``default``) is a name the feature powerset can toggle, so
        a ``cfg(feature = "x")`` is reachable iff ``x`` is in this set. Read
        from the checked-out ``crates/*/Cargo.toml``; in CI that is the clean
        immutable HEAD tree, so it matches the blob-sourced trust-boundary
        reads. A ``cfg(feature = ...)`` naming a feature NOT defined here is
        never compiled by any powerset combination, so it stays fail-closed.
        """
        out: dict[str, frozenset[str]] = {}
        crates_dir = TestPolicyAndCiInvariants.WORKSPACE / "crates"
        for cargo_toml in sorted(crates_dir.glob("*/Cargo.toml")):
            data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
            features = data.get("features")
            if not isinstance(features, dict):
                out[cargo_toml.parent.name] = frozenset()
                continue
            out[cargo_toml.parent.name] = frozenset(features.keys())
        return out

    @staticmethod
    def _file_crate(rel: str) -> str | None:
        """Return the crate name for a `crates/<crate>/...` repo-relative path."""
        parts = rel.split("/", 3)
        if len(parts) >= 2 and parts[0] == "crates":
            return parts[1]
        return None

    # Atom cfg names that are active in every coverage build regardless of
    # target or feature selection (the build is a debug test build). rustc's
    # ``--print cfg`` does not list these, so the evaluator adds them.
    _ALWAYS_ACTIVE = frozenset({"test", "debug_assertions"})

    # --- structural cfg parser ----------------------------------------------
    #
    # Replaces the regex scan that motivated H4a. Tokenizer + recursive
    # descent parser handle inner cfg attributes, multi-line forms, `any` /
    # `all` / `not` combinators, `target_*` predicates including
    # `target_pointer_width` / `target_feature` / `target_endian` /
    # `target_has_atomic`, the `feature` predicate, and atom shorthands like
    # `unix` / `windows` / `test`. `cfg_attr(P, attr)` is recognized: if the
    # nested attribute is itself a cfg gate (`cfg(...)`) or a `path = ...`
    # selector, the cfg_attr is treated as a coverage gate; otherwise it is
    # not (cfg_attr does not remove code from the build by itself). Any form
    # the parser cannot structurally handle raises CfgParseError, which the
    # caller treats as a fail-closed offender.

    @staticmethod
    def _tokenize_cfg(src: str) -> list[tuple[str, str]]:
        tokens: list[tuple[str, str]] = []
        i = 0
        n = len(src)
        while i < n:
            ch = src[i]
            if ch.isspace():
                i += 1
                continue
            if ch in "(),=":
                tokens.append((ch, ch))
                i += 1
                continue
            if ch == '"':
                j = src.find('"', i + 1)
                if j < 0:
                    raise _CfgParseError(f"unterminated string at offset {i}")
                tokens.append(("STR", src[i + 1 : j]))
                i = j + 1
                continue
            if ch.isalpha() or ch == "_":
                j = i
                while j < n and (src[j].isalnum() or src[j] == "_"):
                    j += 1
                tokens.append(("NAME", src[i:j]))
                i = j
                continue
            raise _CfgParseError(f"unexpected character {ch!r} at offset {i}")
        return tokens

    @classmethod
    def _parse_cfg(cls, src: str) -> "_CfgPred":
        """Parse the inside of `cfg(...)` into an AST. Raises CfgParseError on
        any form the grammar does not accept (so the H4a guard fails closed)."""
        tokens = cls._tokenize_cfg(src)
        pred, i = cls._parse_pred(tokens, 0)
        if i != len(tokens):
            raise _CfgParseError(
                f"trailing tokens after predicate: {tokens[i:]!r}"
            )
        return pred

    @classmethod
    def _parse_pred(cls, tokens: list[tuple[str, str]], i: int) -> tuple["_CfgPred", int]:
        if i >= len(tokens) or tokens[i][0] != "NAME":
            raise _CfgParseError(f"expected NAME at token {i}, got {tokens[i:]!r}")
        name = tokens[i][1]
        i += 1
        if i < len(tokens) and tokens[i][0] == "=":
            i += 1
            if i >= len(tokens) or tokens[i][0] != "STR":
                raise _CfgParseError(f"expected STR after `=` at token {i}")
            value = tokens[i][1]
            return _CfgEquals(name, value), i + 1
        if i < len(tokens) and tokens[i][0] == "(":
            i += 1
            args: list[_CfgPred] = []
            while True:
                if i < len(tokens) and tokens[i][0] == ")":
                    break
                arg, i = cls._parse_pred(tokens, i)
                args.append(arg)
                if i < len(tokens) and tokens[i][0] == ",":
                    i += 1
                    continue
                if i < len(tokens) and tokens[i][0] == ")":
                    break
                raise _CfgParseError(
                    f"expected `,` or `)` at token {i}, got {tokens[i:]!r}"
                )
            if i >= len(tokens) or tokens[i][0] != ")":
                raise _CfgParseError(f"expected `)` at token {i}")
            i += 1
            if name == "any":
                return _CfgAny(args), i
            if name == "all":
                return _CfgAll(args), i
            if name == "not":
                if len(args) != 1:
                    raise _CfgParseError(
                        f"`not` takes exactly 1 argument, got {len(args)}"
                    )
                return _CfgNot(args[0]), i
            if name == "cfg":
                # Inner cfg: `#[cfg(cfg(P))]` is unusual but legal. The inner
                # predicate is the gate; lift it.
                if len(args) != 1:
                    raise _CfgParseError(
                        f"`cfg` wrapper takes 1 argument, got {len(args)}"
                    )
                return args[0], i
            raise _CfgParseError(f"unknown combinator {name!r}")
        return _CfgLiteral(name), i

    @classmethod
    def _feature_atoms(cls, pred: "_CfgPred", defined: frozenset[str]) -> list[str]:
        """Collect the distinct DEFINED features `pred` references.

        Only features in ``defined`` are free variables (the powerset toggles
        them). A ``feature = "x"`` naming an undefined feature is not free —
        it is fixed off, because no powerset combination enables a feature
        that does not exist.
        """
        found: set[str] = set()

        def walk(p: _CfgPred) -> None:
            if isinstance(p, _CfgEquals):
                if p.key == "feature" and p.value in defined:
                    found.add(p.value)
            elif isinstance(p, _CfgNot):
                walk(p.child)
            elif isinstance(p, (_CfgAny, _CfgAll)):
                for c in p.children:
                    walk(c)

        walk(pred)
        return sorted(found)

    @classmethod
    def _eval_cfg(
        cls,
        pred: "_CfgPred",
        names: frozenset[str],
        pairs: dict[str, frozenset[str]],
        feature_on: frozenset[str],
    ) -> bool:
        """Evaluate `pred` under one leg's rustc cfg (``names``/``pairs``) and
        a concrete feature assignment (``feature_on`` = enabled features;
        anything absent is disabled)."""
        if isinstance(pred, _CfgEquals):
            if pred.key == "feature":
                return pred.value in feature_on
            return pred.value in pairs.get(pred.key, frozenset())
        if isinstance(pred, _CfgLiteral):
            return pred.name in names or pred.name in cls._ALWAYS_ACTIVE
        if isinstance(pred, _CfgNot):
            return not cls._eval_cfg(pred.child, names, pairs, feature_on)
        if isinstance(pred, _CfgAny):
            return any(cls._eval_cfg(c, names, pairs, feature_on) for c in pred.children)
        if isinstance(pred, _CfgAll):
            return all(cls._eval_cfg(c, names, pairs, feature_on) for c in pred.children)
        raise _CfgParseError(f"unknown predicate node {pred!r}")

    @classmethod
    def _coverable(
        cls,
        pred: "_CfgPred",
        legs_cfg: list[tuple[frozenset[str], dict[str, frozenset[str]]]],
        defined: frozenset[str],
    ) -> bool:
        """Is `pred` satisfiable on SOME leg under SOME feature assignment the
        powerset covers?

        Brute-forces the (small) powerset of the predicate's free defined
        features against each leg's authoritative rustc cfg. Coverable means
        cargo-hack's powerset compiles the gated code on at least one leg, so
        it reaches LCOV; not coverable means no built (leg × feature-combo)
        compiles it — a genuine coverage gap → offender.
        """
        feats = cls._feature_atoms(pred, defined)
        for names, pairs in legs_cfg:
            for bits in itertools.product((False, True), repeat=len(feats)):
                feature_on = frozenset(f for f, on in zip(feats, bits) if on)
                if cls._eval_cfg(pred, names, pairs, feature_on):
                    return True
        return False

    # Markers for the H4a scanner: outer (`#[...]`) and inner (`#![...]`)
    # forms of `cfg(...)` and `cfg_attr(P, ...)`. The inner form gates an
    # entire enclosing scope (module / crate) when it appears at the top of
    # a file, so missing it would silently let `#![cfg(target_os = "x")]`
    # block-gate a whole trust-boundary file past the guard.
    _CFG_MARKERS: tuple[tuple[str, bool], ...] = (
        ("#[cfg(", False),
        ("#![cfg(", False),
        ("#[cfg_attr(", True),
        ("#![cfg_attr(", True),
    )

    @classmethod
    def _scan_cfg_attributes(cls, source: str) -> list[str]:
        """Find every `cfg(...)` and `cfg_attr(P, inner)` attribute.

        Covers both outer (``#[...]``) and inner (``#![...]``) attribute
        forms; the inner form gates the entire enclosing scope and would
        otherwise let `#![cfg(target_os = "x")]` block-gate a whole
        trust-boundary file invisibly to the guard. Returns the inside of
        each attribute (between the outer ``(`` and ``)``) as a single
        string, suitable for :meth:`_parse_cfg`. Uses a paren-balanced scan
        so nested parentheses cannot truncate the capture the way the prior
        non-greedy regex did. ``cfg_attr`` returns the FIRST argument (the
        gating predicate); a ``cfg_attr(P, ...)`` applies its inner
        attribute only when P holds, so P is the effective coverage gate.
        """
        out: list[str] = []
        n = len(source)
        i = 0
        while i < n:
            best_start: int | None = None
            best_marker: str | None = None
            best_is_attr = False
            for marker, is_attr in cls._CFG_MARKERS:
                j = source.find(marker, i)
                if j < 0:
                    continue
                # `#[cfg(` is a prefix of `#[cfg_attr(` and `#![cfg(` is a
                # prefix of `#![cfg_attr(`, so for the same start offset the
                # longer marker wins.
                if best_start is None or j < best_start or (
                    j == best_start and len(marker) > len(best_marker or "")
                ):
                    best_start = j
                    best_marker = marker
                    best_is_attr = is_attr
            if best_start is None or best_marker is None:
                break
            start = best_start
            inside_offset = len(best_marker)
            is_attr = best_is_attr
            # Scan forward to the matching close-paren, respecting strings.
            depth = 1
            k = start + inside_offset
            in_str = False
            while k < n and depth > 0:
                ch = source[k]
                if in_str:
                    if ch == "\\" and k + 1 < n:
                        k += 2
                        continue
                    if ch == '"':
                        in_str = False
                elif ch == '"':
                    in_str = True
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            if depth != 0:
                # Unbalanced attribute → treat as fail-closed parse error so
                # the caller flags this file.
                raise _CfgParseError(
                    f"unbalanced parens in attribute starting at offset {start}"
                )
            inside = source[start + inside_offset : k]
            if is_attr:
                # `cfg_attr(P, attr)` only gates code from compilation when
                # `attr` is itself a `cfg(...)` (effective predicate is
                # `all(P, Q)` where Q is the inner cfg). For ANY other inner
                # attribute (`inline`, `derive(Debug)`, `allow(...)`, etc.)
                # cfg_attr just conditionally APPLIES the attribute — the
                # code is compiled either way, so it is NOT a coverage gate
                # and must not be a guard offender. Drop it. `path = "..."`
                # is the other code-gating form (it swaps the source file);
                # the practical effect on coverage is that the alternative
                # file gets the gate, not the file containing the cfg_attr,
                # so it remains out of scope for THIS guard.
                p_text, rest = _split_top_level_comma(inside)
                inner = rest.strip()
                if inner.startswith("cfg(") and inner.endswith(")"):
                    q_text = inner[len("cfg(") : -1]
                    out.append(f"all({p_text}, {q_text})")
                # else: cfg_attr is not a code-gate → drop it silently.
            else:
                out.append(inside)
            i = k + 1
        return out

    @classmethod
    def _read_blobs(cls, paths: list[str]) -> dict[str, str]:
        """Return ``{rel: blob_text}`` for ``paths`` at the immutable HEAD.

        Batches every read through one ``git cat-file --batch`` invocation
        — the same pattern the production helper :func:`get_source_line_counts`
        uses — so the guard's cost stays O(1 git fork) regardless of how
        many trust-boundary files the policy expands to, rather than the
        O(N) shell-out the previous per-file ``git show HEAD:<rel>`` paid.
        Paths missing from HEAD are omitted from the result.
        """
        if not paths:
            return {}
        request = "".join(f"HEAD:{p}\n" for p in paths).encode("utf-8")
        try:
            proc = subprocess.run(
                ["git", "cat-file", "--batch"],
                input=request,
                cwd=cls.WORKSPACE,
                check=False,
                capture_output=True,
            )
        except OSError:
            return {}
        if proc.returncode != 0:
            return {}
        out = proc.stdout
        blobs: dict[str, str] = {}
        pos = 0
        for path in paths:
            nl = out.find(b"\n", pos)
            if nl < 0:
                break
            header = out[pos:nl].decode("utf-8", "replace")
            pos = nl + 1
            if header.endswith(" missing"):
                continue
            parts = header.split()
            if len(parts) != 3 or parts[1] != "blob":
                # Skip non-blob entries; this should not occur because the
                # caller filters to .rs files, but the offset must still
                # advance past the body so subsequent paths align.
                size = int(parts[2]) if len(parts) == 3 and parts[2].isdigit() else 0
                pos += size + 1
                continue
            size = int(parts[2])
            blobs[path] = out[pos : pos + size].decode("utf-8", "replace")
            pos += size + 1
        return blobs

    @unittest.skipUnless(shutil.which("rustc"), "rustc not available")
    def test_trust_boundary_target_cfg_is_covered_by_matrix(self) -> None:
        """H4a: every `cfg` / `cfg_attr` in a trust-boundary file must be
        coverable by (some matrix leg) × (the feature powerset).

          * **Targets** come from ``rustc --print cfg --target <triple>``
            per leg — authoritative, no hand-maintained table.
          * **Features** are free variables (cargo-hack instruments the full
            powerset), bounded to each crate's defined features.
          * **Policy globs are expanded** via the checker's own glob
            expansion against the immutable head tree.
          * **Structural cfg parsing** (tokenizer + recursive descent)
            handles any/all/not, inner cfg, `cfg_attr`, multi-line forms,
            and every `target_*` predicate; anything it cannot understand
            fails closed.
          * **Immutable source** — each file is read from the HEAD blob, so
            a dirty worktree cannot falsify the guard.
        """
        triples = self._matrix_target_triples()
        self.assertTrue(triples, "no matrix target triples parsed from ci.yml")
        legs_cfg = [self._rustc_target_cfg(t) for t in triples]
        workspace_features = self._parse_workspace_features()

        tb_paths = self._expand_policy_paths()
        self.assertTrue(tb_paths, "policy paths set is empty — parser regression")
        # Batched read of every trust-boundary blob in one `cat-file --batch`
        # invocation — see `_read_blobs` for rationale.
        blobs = self._read_blobs(sorted(tb_paths))

        offenders: list[tuple[str, str]] = []
        for rel in sorted(tb_paths):
            source = blobs.get(rel)
            if source is None:
                # The path resolved through the policy but is not present at
                # HEAD — this is a separate fail mode (the unmatched-glob
                # check would have already fired), but be defensive.
                offenders.append((rel, "missing from head tree"))
                continue
            crate = self._file_crate(rel)
            defined = workspace_features.get(crate, frozenset()) if crate else frozenset()
            try:
                attrs = self._scan_cfg_attributes(source)
            except _CfgParseError as exc:
                offenders.append((rel, f"attribute scan: {exc}"))
                continue
            for attr_src in attrs:
                try:
                    pred = self._parse_cfg(attr_src)
                except _CfgParseError as exc:
                    offenders.append((rel, f"cfg({attr_src}): {exc}"))
                    continue
                if not self._coverable(pred, legs_cfg, defined):
                    offenders.append((rel, f"cfg({attr_src}) not coverable by the matrix"))
        self.assertEqual(
            offenders,
            [],
            "trust-boundary file contains a cfg no (matrix leg × feature "
            "combination) compiles, so its lines reach no LCOV — or a "
            "conditional form this guard cannot understand (fail-closed). "
            "Add a matrix leg in .github/workflows/ci.yml (with a matching "
            "`triple:` field), split the cfg, or remove the unsupported "
            f"form.\nOffenders: {offenders}",
        )

    @staticmethod
    def _non_comment_text(text: str) -> str:
        """Drop comment/prose lines (`#`, `//`) so a mention in a comment or
        Markdown paragraph cannot satisfy a structural CI-command check."""
        return "\n".join(
            raw for raw in text.splitlines()
            if not raw.lstrip().startswith(("#", "//"))
        )

    def test_scan_cfg_attributes_finds_inner_attribute_form(self) -> None:
        # Regression guard: `#![cfg(...)]` (inner attribute) gates an entire
        # enclosing module/crate. An earlier draft of the scanner looked only
        # for `#[cfg(` / `#[cfg_attr(`, so a file beginning with
        # `#![cfg(target_os = "freebsd")]` would have escaped the H4a guard
        # entirely. Both outer and inner forms — and the code-gating
        # `cfg_attr(P, cfg(Q))` form — must now be recognized.
        cases: list[tuple[str, list[str]]] = [
            ('#[cfg(test)]\nfn x() {}', ['test']),
            ('#![cfg(test)]\nfn x() {}', ['test']),
            # cfg_attr with a non-cfg inner attribute does NOT gate code from
            # compilation, so it must be DROPPED (otherwise the guard would
            # fail-closed on legitimate benign cfg_attr like #[derive] /
            # #[inline] / #[allow] — a false positive regression).
            ('#[cfg_attr(test, derive(Debug))]', []),
            ('#![cfg_attr(test, allow(dead_code))]', []),
            ('#[cfg_attr(target_os = "windows", inline)]', []),
            # cfg_attr with an inner cfg DOES gate; the effective predicate
            # is `all(P, Q)` and that's what the scanner emits.
            (
                '#[cfg_attr(target_os = "linux", cfg(test))]',
                ['all(target_os = "linux", test)'],
            ),
            # The inner-cfg gate at file top still must surface so the
            # H4a evaluator can refuse a target the matrix does not build.
            ('#![cfg(target_os = "freebsd")]', ['target_os = "freebsd"']),
            # Outer + inner mixed in one file.
            (
                '#![cfg(unix)]\n#[cfg(target_os = "linux")] fn x() {}',
                ['unix', 'target_os = "linux"'],
            ),
        ]
        for src, expected in cases:
            with self.subTest(src=src):
                self.assertEqual(self._scan_cfg_attributes(src), expected)

    def test_coverage_build_uses_feature_powerset(self) -> None:
        # H4b: feature exhaustiveness is delegated to `cargo hack
        # --feature-powerset`, which instruments EVERY feature combination
        # (so both `cfg(feature="x")` and `cfg(not(feature="x"))`, and all
        # combinations for N>1 features, reach LCOV). This replaces the
        # earlier hand-enumerated `--features` list that only covered a fixed
        # N=1 pair and silently regressed when a second feature landed. The
        # check is structural: the powerset driver and the report step must
        # appear in the actual command (comment/prose lines are stripped so a
        # mention cannot satisfy it), and no restricting `--features` is
        # passed to the powerset driver (which would defeat exhaustiveness).
        for path_rel, label in (
            (".github/workflows/ci.yml", "ci.yml"),
            ("CONTRIBUTING.md", "CONTRIBUTING.md"),
        ):
            text = (TestPolicyAndCiInvariants.WORKSPACE / path_rel).read_text(encoding="utf-8")
            cmd = self._non_comment_text(text)
            with self.subTest(file=label):
                self.assertIn(
                    "cargo hack --feature-powerset",
                    cmd,
                    f"{label}: the coverage build must drive `cargo llvm-cov` "
                    "through `cargo hack --feature-powerset` so every feature "
                    "combination is instrumented; a hand-enumerated --features "
                    "list silently regresses when a second non-default feature "
                    "is added.",
                )
                self.assertIn(
                    "cargo llvm-cov report --lcov",
                    cmd,
                    f"{label}: feature-powerset coverage accumulates per-combo "
                    "profraw via `--no-report`; the merged LCOV must be produced "
                    "by `cargo llvm-cov report --lcov`.",
                )
                # The powerset driver line must not also pin `--features`,
                # which would collapse the powerset to a single combination.
                for line in cmd.splitlines():
                    if "cargo hack --feature-powerset" in line:
                        self.assertNotIn(
                            "--features",
                            line,
                            f"{label}: `cargo hack --feature-powerset` must not "
                            "also pass `--features` — that pins one combination "
                            "and defeats the powerset.",
                        )
                # The guard hardcodes `debug_assertions` as active (the
                # coverage build is a debug test build). Pin that assumption:
                # a `--release` coverage build would drop `cfg(debug_assertions)`
                # code from every LCOV while the guard still treats it as
                # always-covered — a silent false negative. Fail loudly if the
                # coverage command ever goes release.
                for line in cmd.splitlines():
                    if "cargo hack" in line or "cargo llvm-cov" in line:
                        self.assertNotIn(
                            "--release",
                            line,
                            f"{label}: the coverage build must stay a debug "
                            "build — the H4a guard assumes `debug_assertions` "
                            "is active. A release coverage build would silently "
                            "drop `cfg(debug_assertions)` trust-boundary code.",
                        )

    def test_merge_job_leg_count_matches_triples(self) -> None:
        # The merge job refuses a partial LCOV set by comparing the number of
        # downloaded LCOVs to a shell `grep -cE '^[[:space:]]+triple:'` over
        # ci.yml. That shell counter and the Python `_matrix_target_triples`
        # parser use different matching rules; if they ever disagree the merge
        # job could reject a complete set (or accept a partial one). Pin them
        # to the same answer by replicating the shell count here.
        ci_path = TestPolicyAndCiInvariants.WORKSPACE / ".github" / "workflows" / "ci.yml"
        text = ci_path.read_text(encoding="utf-8")
        shell_count = sum(
            1 for raw in text.splitlines() if re.match(r"[ \t]+triple:", raw)
        )
        python_count = len(self._matrix_target_triples())
        self.assertEqual(
            shell_count,
            python_count,
            "the merge job's `grep -cE '^[[:space:]]+triple:'` leg count "
            f"({shell_count}) disagrees with `_matrix_target_triples()` "
            f"({python_count}). Both must resolve to exactly the matrix legs; "
            "a divergence makes the merge job's partial-data check wrong.",
        )

    def test_feature_powerset_size_is_bounded(self) -> None:
        # `cargo hack --feature-powerset` runs 2**N instrumented builds for a
        # crate with N features, and the guard's `_coverable` brute-forces the
        # same 2**N per predicate. Both are fine for the current workspace
        # (max is chaffra-telemetry at 2 features), but a crate that grows many
        # features would explode CI time and the guard. Make that cost
        # assumption explicit: a crate exceeding the bound must consciously cap
        # the powerset (e.g. `cargo hack --depth`) rather than silently blow
        # the `coverage-instrument` timeout.
        max_features = 6  # 2**6 = 64 combos/crate — generous headroom over 2
        offenders = {
            crate: len(feats)
            for crate, feats in self._parse_workspace_features().items()
            if len(feats) > max_features
        }
        self.assertEqual(
            offenders,
            {},
            f"crate(s) define more than {max_features} features, so the "
            "feature powerset (2**N per crate) would explode the coverage "
            f"build and the guard: {offenders}. Cap the powerset depth in the "
            "coverage command and revisit this bound.",
        )


def _have_powerset_tools() -> bool:
    return all(shutil.which(t) for t in ("cargo", "cargo-hack", "cargo-llvm-cov"))


@unittest.skipUnless(
    _have_powerset_tools(), "cargo + cargo-hack + cargo-llvm-cov required"
)
class TestPowersetAccumulationRegression(unittest.TestCase):
    """Load-bearing regression for the feature-exhaustiveness guarantee.

    The whole design rests on cargo-llvm-cov RETAINING profraw across the
    per-combo ``--no-report`` runs that ``cargo hack --feature-powerset``
    drives — documented behavior, not a contract. This runs the EXACT CI
    recipe on a checked-in 2-combo fixture crate (one feature `fa`, so the
    powerset is {} and {fa}) and asserts the merged LCOV contains BOTH the
    ``cfg(feature = "fa")`` and the ``cfg(not(feature = "fa"))`` function. A
    regression in accumulation (e.g. a tool-version bump that re-enables
    per-run cleaning) would leave only the last combo's function and fail
    here, rather than silently shrinking coverage in production.
    """

    FIXTURE = Path(__file__).resolve().parent / "fixtures" / "powerset_crate"

    def test_powerset_merges_both_feature_branches(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="cov-powerset-"))
        try:
            crate = tmp / "powerset_crate"
            shutil.copytree(self.FIXTURE, crate)
            env = dict(os.environ, CARGO_TERM_COLOR="never")

            def run(*args: str) -> None:
                subprocess.run(args, cwd=crate, env=env, check=True, capture_output=True)

            # The exact CI recipe (.github/workflows/ci.yml, Generate LCOV).
            run("cargo", "llvm-cov", "clean", "--workspace")
            run("cargo", "hack", "--feature-powerset", "llvm-cov", "--no-report")
            lcov = crate / "merged.lcov"
            run("cargo", "llvm-cov", "report", "--lcov", "--output-path", str(lcov))

            covered_fns: list[str] = []
            for line in lcov.read_text(encoding="utf-8").splitlines():
                if line.startswith("FNDA:"):
                    hits_str, _, name = line[len("FNDA:"):].partition(",")
                    if int(hits_str) > 0:
                        covered_fns.append(name)

            # Mangled symbol names carry the source fn name as a suffix token.
            self.assertTrue(
                any("branch_with_fa" in n for n in covered_fns),
                "cfg(feature=\"fa\") branch missing/uncovered in merged LCOV; "
                f"covered fns: {covered_fns}",
            )
            self.assertTrue(
                any("branch_without_fa" in n for n in covered_fns),
                "cfg(not(feature=\"fa\")) branch missing/uncovered in merged "
                "LCOV — feature-powerset accumulation regressed (only the last "
                f"combo's code survived the merge); covered fns: {covered_fns}",
            )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
