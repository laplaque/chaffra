"""Deterministic tests for the chaffra coverage checker.

The tests drive the same `main(argv)` entry point that CI invokes. Synthetic
LCOV, policy, and diff fixtures are constructed inline so the table of cases
is reviewable in one place and the suite has no external dependencies.

Run locally with::

    python3 -m unittest discover -s scripts/tests
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import textwrap
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


class TestDeclaredTotalsCannotInflateOverall(CheckerTestCase):
    def test_inflated_lf_lh_ignored_overall_from_da(self) -> None:
        # A block declaring LF:100/LH:100 with a single covered DA record is
        # structurally accepted (LF>=DA, LH>=hits, LH<=LF) but overall is
        # computed from the DA records (1/1), NOT the inflated declaration.
        # Two uncovered DA lines on a second file pull overall below 85%.
        lcov = (
            "SF:crates/chaffra-core/src/config.rs\nDA:1,1\nLF:100\nLH:100\nend_of_record\n"
            "SF:crates/chaffra-cli/src/main.rs\nDA:1,0\nDA:2,0\nLF:2\nLH:0\nend_of_record\n"
        )
        diff = diff_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        overall = next(g for g in report["gates"] if g["name"] == "overall")
        # 1 covered of 3 instrumented DA lines = 33.33%, not the declared 100%.
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertFalse(overall["passed"])
        self.assertAlmostEqual(report["overall"]["percent"], 100.0 / 3, places=2)


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


class TestTrustBoundaryGateFails(CheckerTestCase):
    def test_trust_boundary_below_100(self) -> None:
        # Trust-boundary file: 9/10 = 90%, must be 100%.
        tb_lines = [(n, 1 if n < 19 else 0) for n in range(10, 20)]
        lcov = lcov_text(
            [
                (BASIC_TRUST_BOUNDARY_FILE, tb_lines),
                (NON_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(10, 10)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        gate_names = {g["name"]: g for g in report["gates"]}
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertFalse(gate_names["trust_boundary_changed"]["passed"])
        self.assertIn(BASIC_TRUST_BOUNDARY_FILE, gate_names["trust_boundary_changed"]["detail"])


class TestTrustBoundaryNoCoverageRecords(CheckerTestCase):
    def test_trust_boundary_file_missing_from_lcov(self) -> None:
        # No LCOV records for the trust-boundary file at all.
        lcov = lcov_text(
            [
                (NON_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(10, 5)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        gate_names = {g["name"]: g for g in report["gates"]}
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertFalse(gate_names["trust_boundary_changed"]["passed"])
        self.assertIn("no LCOV records", gate_names["trust_boundary_changed"]["detail"])


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

    def cases(self) -> list[tuple[str, str]]:
        return [
            ("threshold out of range", basic_policy({"overall": 150.0})),
            ("missing trust-boundary group", self._MISSING_TB_GROUP),
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


class TestTrustBoundaryDetailUsesPolicyThreshold(CheckerTestCase):
    def test_detail_string_reports_configured_threshold(self) -> None:
        policy = basic_policy({"trust_boundary_changed": 95.0})
        # 9/10 = 90% trust-boundary coverage, below 95% threshold.
        tb_lines = [(n, 1 if n < 19 else 0) for n in range(10, 20)]
        lcov = lcov_text(
            [(BASIC_TRUST_BOUNDARY_FILE, tb_lines), (NON_TRUST_BOUNDARY_FILE, [(1, 1)])]
        )
        diff = diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(10, 10)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=policy, diff=diff)
        gate = next(g for g in report["gates"] if g["name"] == "trust_boundary_changed")
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertFalse(gate["passed"])
        # Must mention the configured 95%, not a hard-coded 100%.
        self.assertIn("95.00%", gate["detail"])


class TestTrustBoundaryDaMembership(CheckerTestCase):
    """The trust-boundary gate defers to the LCOV DA records — the coverage
    build is the authority on which changed lines are executable. Changed
    lines llvm did not instrument (braces, declarations, comments) pass;
    instrumented changed lines must reach 100%; a changed TB file with no
    LCOV records at all fails."""

    def test_only_non_instrumented_changes_pass(self) -> None:
        # Changed lines 50-52 are absent from the DA records → llvm did not
        # instrument them → they pass without any source classification.
        lcov = lcov_text(
            [
                (BASIC_TRUST_BOUNDARY_FILE, [(1, 1), (2, 1), (3, 1)]),
                (NON_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(50, 3)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        gate = next(g for g in report["gates"] if g["name"] == "trust_boundary_changed")
        self.assertEqual(rc, coverage_check.EXIT_OK, gate)
        self.assertTrue(gate["passed"])
        block = next(f for f in report["files"] if f["path"] == BASIC_TRUST_BOUNDARY_FILE)
        self.assertEqual(block["non_instrumented_lines"], [50, 51, 52])

    def test_instrumented_changed_line_uncovered_fails(self) -> None:
        # Line 50 IS a DA record but uncovered (hits 0) → must fail at 100%.
        lcov = lcov_text(
            [
                (BASIC_TRUST_BOUNDARY_FILE, [(50, 0), (51, 1)]),
                (NON_TRUST_BOUNDARY_FILE, [(1, 1)]),
            ]
        )
        diff = diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(50, 2)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        gate = next(g for g in report["gates"] if g["name"] == "trust_boundary_changed")
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["measured"], 50.0)
        self.assertIn("50", gate["detail"])

    def test_file_absent_from_lcov_fails(self) -> None:
        # TB file changed but has no SF block at all → cannot prove coverage.
        lcov = lcov_text([(NON_TRUST_BOUNDARY_FILE, [(1, 1)])])
        diff = diff_text([(BASIC_TRUST_BOUNDARY_FILE, [(50, 2)])])
        rc, report, _ = self.run_check(lcov=lcov, policy=basic_policy(), diff=diff)
        gate = next(g for g in report["gates"] if g["name"] == "trust_boundary_changed")
        self.assertEqual(rc, coverage_check.EXIT_GATE_FAIL)
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["measured"], 0.0)
        self.assertIn("no LCOV records", gate["detail"])


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

    CASES: list[tuple[str, str]] = [
        ("non-numeric DA hits", "SF:foo.rs\nDA:1,not-a-number\nend_of_record\n"),
        ("missing end_of_record", "SF:foo.rs\nDA:1,1\n"),
        ("empty SF block (no DA)", "SF:foo.rs\nLF:0\nLH:0\nend_of_record\n"),
        (
            "LH > LF",
            "SF:foo.rs\nDA:1,1\nDA:2,1\nLF:2\nLH:5\nend_of_record\n",
        ),
        (
            "unique DA lines exceed declared LF",
            "SF:foo.rs\nDA:1,1\nDA:2,1\nDA:3,1\nLF:1\nLH:1\nend_of_record\n",
        ),
        (
            "unique hit DA lines exceed declared LH",
            "SF:foo.rs\nDA:1,1\nDA:2,1\nLF:2\nLH:0\nend_of_record\n",
        ),
        ("new SF before end_of_record", "SF:a.rs\nDA:1,1\nSF:b.rs\nend_of_record\n"),
        ("malformed LF record", "SF:foo.rs\nDA:1,1\nLF:abc\nend_of_record\n"),
        ("malformed LH record", "SF:foo.rs\nDA:1,1\nLF:1\nLH:abc\nend_of_record\n"),
        ("missing LF/LH summary", "SF:foo.rs\nDA:1,1\nend_of_record\n"),
        ("duplicate DA for same line", "SF:foo.rs\nDA:1,1\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"),
        ("duplicate LF record", "SF:foo.rs\nDA:1,1\nLF:1\nLF:1\nLH:1\nend_of_record\n"),
        ("duplicate SF path", "SF:foo.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\nSF:foo.rs\nDA:2,1\nLF:1\nLH:1\nend_of_record\n"),
        ("no records at all", "TN:test\n"),
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
class TestMainGitIntegration(unittest.TestCase):
    """M1: drive main() through the production acquisition path that uses
    `git diff base...head` and `git ls-files`, with neither --diff nor
    --repo-files supplied. Uses a temporary git repository so the test stays
    deterministic and self-contained. Skipped on runners without git."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="cov-git-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _git(self, *args: str) -> str:
        import subprocess as sp

        # Inherit the caller env first so PATH and similar essentials reach
        # git, THEN apply the isolation overrides. The previous order put
        # /dev/null first and let inherited GIT_CONFIG_GLOBAL escape the
        # isolation. GIT_CONFIG_COUNT=0 prevents per-key config injection.
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
        return sp.check_output(
            ["git", *args], cwd=self.tmp, text=True, env=env
        ).strip()

    def test_end_to_end_via_git_diff_and_ls_files(self) -> None:
        # Initialize a tiny repo with one Rust file, then add coverage for
        # the changed lines and verify main() returns 0.
        self._git("init", "-q", "-b", "main")
        rel = "crates/chaffra-core/src/config.rs"
        (self.tmp / "crates/chaffra-core/src").mkdir(parents=True)
        (self.tmp / rel).write_text(
            "fn original() {}\n", encoding="utf-8"
        )
        (self.tmp / "other.txt").write_text("noise\n", encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "-q", "-m", "base")
        base_sha = self._git("rev-parse", "HEAD")
        (self.tmp / rel).write_text(
            "fn original() {}\nfn added() { x(); }\n", encoding="utf-8"
        )
        self._git("add", rel)
        self._git("commit", "-q", "-m", "head")
        head_sha = self._git("rev-parse", "HEAD")

        # LCOV that covers BOTH lines of the new file so the gate passes.
        lcov = lcov_file_block(rel, [(1, 1), (2, 1)])
        lcov_path = write(self.tmp / "lcov.info", lcov)
        policy_path = write(
            self.tmp / "policy.toml",
            textwrap.dedent(
                f"""\
                policy_version = 1
                [thresholds]
                overall = 85.0
                aggregate_changed = 95.0
                per_file_changed = 90.0
                trust_boundary_changed = 100.0

                [[trust_boundaries]]
                purpose = "configuration parsing"
                patterns = ["{rel}"]
                """
            ),
        )
        rc = coverage_check.main(
            [
                "--lcov",
                str(lcov_path),
                "--policy",
                str(policy_path),
                "--repo-root",
                str(self.tmp),
                "--base-sha",
                base_sha,
                "--head-sha",
                head_sha,
                "--json-out",
                str(self.tmp / "out.json"),
                "--markdown-out",
                str(self.tmp / "out.md"),
                "--mode",
                "pr",
            ]
        )
        self.assertEqual(rc, coverage_check.EXIT_OK)
        report = json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))
        self.assertEqual(report["base_sha"], base_sha)
        self.assertEqual(report["head_sha"], head_sha)
        # The change set must include the .rs file but exclude other.txt.
        paths = [f["path"] for f in report["files"]]
        self.assertEqual(paths, [rel])


if __name__ == "__main__":
    unittest.main()
