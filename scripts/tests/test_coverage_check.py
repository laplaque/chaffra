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


class TestPolicyAndCiInvariants(unittest.TestCase):
    """Regression guards that keep the multi-target coverage mechanism honest
    (chaffra#49 / H4).

    H4 is closed by the `coverage-instrument` matrix: `cargo llvm-cov` runs
    once per target OS/arch and the per-leg LCOV is merged before the gate, so
    `#[cfg(target_os = "...")]`-gated trust-boundary code is instrumented on
    the matching leg. Two invariants keep that real, enforced mechanically so
    a future PR cannot silently re-open the gap:

      * every target-`cfg` in a trust-boundary file must name a target the
        matrix actually builds (else its code reaches no LCOV), and
      * the coverage build must enumerate every non-default feature by name.
    """

    WORKSPACE = Path(__file__).resolve().parents[2]

    @staticmethod
    def _read_policy_paths() -> set[str]:
        policy_path = TestPolicyAndCiInvariants.WORKSPACE / ".github" / "coverage-policy.toml"
        text = policy_path.read_text(encoding="utf-8")
        # Extract every literal path token from `patterns = [...]` blocks.
        return set(re.findall(r'"((?:crates|docs)[^"]+\.rs)"', text))

    @staticmethod
    def _matrix_legs() -> list[set[str]]:
        """Per-leg sets of cfg target tokens the coverage matrix builds.

        Parsed from the `covers: "..."` field on each `coverage-instrument`
        matrix entry in ci.yml. Each returned set is one leg's tokens (e.g.
        ``{"target_os=linux", "target_arch=x86_64"}``), so a multi-token cfg
        can be checked for co-location on a single leg rather than merely
        token-by-token across different legs.
        """
        ci_path = TestPolicyAndCiInvariants.WORKSPACE / ".github" / "workflows" / "ci.yml"
        text = ci_path.read_text(encoding="utf-8")
        return [
            set(m.group(1).split())
            for m in re.finditer(r'covers:\s*"([^"]*)"', text)
        ]

    @staticmethod
    def _parse_non_default_features() -> dict[str, list[str]]:
        """Return {crate_name: [non_default_feature, ...]} for the workspace.

        Parses `[features]` tables in every `crates/*/Cargo.toml`. A feature
        is non-default iff it is not in the `default = [...]` list.
        """
        out: dict[str, list[str]] = {}
        crates_dir = TestPolicyAndCiInvariants.WORKSPACE / "crates"
        for cargo_toml in sorted(crates_dir.glob("*/Cargo.toml")):
            data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
            features = data.get("features")
            if not isinstance(features, dict):
                continue
            crate_name = cargo_toml.parent.name
            default = set(features.get("default", []))
            non_default = [k for k in features if k != "default" and k not in default]
            if non_default:
                out[crate_name] = sorted(non_default)
        return out

    # Unix-family target_os values the project would build on a unix leg.
    # `#[cfg(unix)]` code compiles on any of these, so it is covered if the
    # matrix has a leg for any one of them.
    _UNIX_TARGET_OS = frozenset({"linux", "macos"})

    def test_trust_boundary_target_cfg_is_covered_by_matrix(self) -> None:
        # H4 closure guard: a trust-boundary file MAY gate code on a target
        # `cfg`, but only on a target the coverage matrix builds — otherwise
        # the gated code reaches no LCOV and the 100% gate cannot see it.
        # For each `#[cfg(...)]` attribute we collect the target predicates it
        # names and require the matrix to cover them. `target_X = "..."` tokens
        # in one attribute must be covered by ONE leg together (conservative:
        # an `any(...)` of two targets is treated like `all(...)`, so the worst
        # case is a build failure saying "widen the matrix or split the cfg" —
        # never a silently un-instrumented line). The `windows` / `unix`
        # shorthands are also recognized, since they gate compilation just like
        # the explicit `target_os` form.
        legs = self._matrix_legs()
        self.assertTrue(legs, "no coverage matrix legs parsed from ci.yml")
        covered_os = {
            tok.split("=", 1)[1] for leg in legs for tok in leg if tok.startswith("target_os=")
        }
        tb_paths = self._read_policy_paths()
        self.assertTrue(tb_paths, "policy paths set is empty — parser regression")
        # Match a whole `#[cfg(...)]` attribute. DOTALL so a rustfmt-wrapped
        # multi-line cfg is scanned too; non-greedy so each attribute is
        # captured minimally. `cfg_attr` is intentionally NOT matched: it
        # conditionally applies an attribute, it does not remove code from the
        # build, so it is never a coverage gap.
        cfg_attr = re.compile(r"#\[cfg\((.*?)\)\]", re.DOTALL)
        target_tok = re.compile(r'target_(os|arch|family|env|vendor)\s*=\s*"([^"]+)"')
        # Bare platform shorthands appearing as a cfg predicate (a whole word
        # not part of a `target_* = "..."` literal).
        shorthand = re.compile(r"\b(windows|unix)\b")
        offenders: list[tuple[str, list[str]]] = []
        for rel in sorted(tb_paths):
            f = self.WORKSPACE / rel
            if not f.is_file():
                continue
            for attr in cfg_attr.findall(f.read_text(encoding="utf-8")):
                tokens = {f"target_{k}={v}" for k, v in target_tok.findall(attr)}
                unmet = sorted(tokens) if tokens and not any(tokens <= leg for leg in legs) else []
                # Strip the explicit `target_* = "..."` literals before looking
                # for bare shorthands so e.g. `target_os = "windows"` is not
                # double-counted as the `windows` shorthand.
                bare = target_tok.sub("", attr)
                for word in set(shorthand.findall(bare)):
                    if word == "windows" and "windows" not in covered_os:
                        unmet.append("cfg(windows)")
                    elif word == "unix" and not (self._UNIX_TARGET_OS & covered_os):
                        unmet.append("cfg(unix)")
                if unmet:
                    offenders.append((rel, sorted(unmet)))
        self.assertEqual(
            offenders,
            [],
            "trust-boundary file gates code on a target the coverage matrix "
            "does not build, so its lines reach no LCOV. Add a matrix leg in "
            ".github/workflows/ci.yml (with a matching `covers:` field) or "
            f"split the cfg.\nOffenders: {offenders}",
        )

    def test_ci_coverage_command_enumerates_every_non_default_feature(self) -> None:
        # The H4 narrowing depends on `cargo llvm-cov` instrumenting
        # every non-default feature in the workspace. CONTRIBUTING.md
        # asks contributors to add new features to the CI command; this
        # test enforces it.
        non_default = self._parse_non_default_features()
        ci_path = TestPolicyAndCiInvariants.WORKSPACE / ".github" / "workflows" / "ci.yml"
        ci_text = ci_path.read_text(encoding="utf-8")
        # Same check on the documented local command so docs and CI agree.
        contrib_path = TestPolicyAndCiInvariants.WORKSPACE / "CONTRIBUTING.md"
        contrib_text = contrib_path.read_text(encoding="utf-8")
        missing_ci: list[str] = []
        missing_contrib: list[str] = []
        for crate, features in non_default.items():
            for feat in features:
                token = f"{crate}/{feat}"
                if token not in ci_text:
                    missing_ci.append(token)
                if token not in contrib_text:
                    missing_contrib.append(token)
        self.assertEqual(
            missing_ci,
            [],
            f"non-default features missing from CI --features: {missing_ci}. "
            "Add them to .github/workflows/ci.yml's `cargo llvm-cov` "
            "invocation so their executable code reaches the LCOV DA records.",
        )
        self.assertEqual(
            missing_contrib,
            [],
            f"non-default features missing from CONTRIBUTING.md: {missing_contrib}. "
            "Add them to the documented local command.",
        )


if __name__ == "__main__":
    unittest.main()
