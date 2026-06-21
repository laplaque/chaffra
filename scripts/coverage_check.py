#!/usr/bin/env python3
"""Coverage checker for chaffra CI.

Reads an LCOV file produced by ``cargo llvm-cov --lcov``, a coverage policy
TOML file, and a base/head git SHA pair. Computes overall, aggregate
changed-line, per-file changed-line, and trust-boundary changed-line
coverage. Emits a JSON result document and a Markdown summary suitable for
``GITHUB_STEP_SUMMARY``.

Exit codes
----------
0  All configured gates pass.
1  At least one gate fails.
2  Malformed input (LCOV, policy, diff), invalid configuration, or a
   trust-boundary glob that matches no current file.

The tool deliberately uses only the Python standard library so that CI does
not depend on a third-party package index. The CI workflow invokes
``main(sys.argv[1:])``; tests call the same entry point with constructed
argv lists, never a parallel calculation path.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

try:
    import tomllib  # Python >= 3.11
except ModuleNotFoundError:  # pragma: no cover - tomli fallback for older runners
    import tomli as tomllib  # type: ignore[no-redef]


VERSION = "1.0.0"

EXIT_OK = 0
EXIT_GATE_FAIL = 1
EXIT_MALFORMED = 2

RUST_EXT = ".rs"


class MalformedInput(Exception):
    """Raised when the LCOV, policy, or diff cannot be parsed."""


class InvalidPolicy(Exception):
    """Raised when the policy file is structurally valid but semantically wrong."""


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Thresholds:
    overall: float
    aggregate_changed: float
    per_file_changed: float
    trust_boundary_changed: float


@dataclass
class TrustBoundaryGroup:
    purpose: str
    patterns: list[str]


@dataclass
class Policy:
    version: int
    thresholds: Thresholds
    trust_boundaries: list[TrustBoundaryGroup]

    def all_patterns(self) -> list[str]:
        out: list[str] = []
        for group in self.trust_boundaries:
            out.extend(group.patterns)
        return out


@dataclass
class FileCoverage:
    """LCOV records for a single source file."""

    path: str
    # line -> hits
    lines: dict[int, int] = field(default_factory=dict)

    def instrumented_lines(self) -> set[int]:
        return set(self.lines.keys())

    def covered_lines(self) -> set[int]:
        return {ln for ln, hits in self.lines.items() if hits > 0}


@dataclass
class ChangedLines:
    """Added/modified line numbers per file from a git diff."""

    by_file: dict[str, set[int]] = field(default_factory=dict)

    def files(self) -> list[str]:
        return sorted(self.by_file.keys())


@dataclass
class FileResult:
    path: str
    is_trust_boundary: bool
    changed_total: int
    changed_instrumented: int
    changed_covered: int
    non_instrumented_lines: list[int]
    uncovered_lines: list[int]
    has_lcov_records: bool

    @property
    def percent(self) -> float | None:
        if self.changed_instrumented == 0:
            return None
        return 100.0 * self.changed_covered / self.changed_instrumented


@dataclass
class GateResult:
    name: str
    threshold: float
    measured: float | None
    passed: bool
    detail: str


@dataclass
class Report:
    version: str
    base_sha: str
    head_sha: str
    policy_version: int
    thresholds: Thresholds
    overall: dict
    aggregate_changed: dict
    file_results: list[FileResult]
    gates: list[GateResult]
    passed: bool

    def to_json(self) -> dict:
        return {
            "tool_version": self.version,
            "policy_version": self.policy_version,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "thresholds": {
                "overall": self.thresholds.overall,
                "aggregate_changed": self.thresholds.aggregate_changed,
                "per_file_changed": self.thresholds.per_file_changed,
                "trust_boundary_changed": self.thresholds.trust_boundary_changed,
            },
            "overall": self.overall,
            "aggregate_changed": self.aggregate_changed,
            "files": [
                {
                    "path": fr.path,
                    "is_trust_boundary": fr.is_trust_boundary,
                    "changed_total": fr.changed_total,
                    "changed_instrumented": fr.changed_instrumented,
                    "changed_covered": fr.changed_covered,
                    "non_instrumented_lines": fr.non_instrumented_lines,
                    "uncovered_lines": fr.uncovered_lines,
                    "has_lcov_records": fr.has_lcov_records,
                    "percent_changed": fr.percent,
                }
                for fr in self.file_results
            ],
            "gates": [
                {
                    "name": g.name,
                    "threshold": g.threshold,
                    "measured": g.measured,
                    "passed": g.passed,
                    "detail": g.detail,
                }
                for g in self.gates
            ],
            "passed": self.passed,
        }


# ---------------------------------------------------------------------------
# LCOV parser
# ---------------------------------------------------------------------------


_LCOV_DA = re.compile(r"^DA:(\d+),(\d+)(?:,[^,]*)?$")
_LCOV_LF = re.compile(r"^LF:(\d+)$")
_LCOV_LH = re.compile(r"^LH:(\d+)$")


def parse_lcov(text: str, repo_root: Path) -> dict[str, FileCoverage]:
    """Parse LCOV text into a map of repository-relative path -> FileCoverage.

    Raises ``MalformedInput`` on missing ``end_of_record`` markers, unparseable
    DA/LF/LH records, or duplicate SF blocks for the same path without a clean
    record terminator.
    """

    files: dict[str, FileCoverage] = {}
    current: FileCoverage | None = None
    seen_record_terminators = 0
    line_no = 0
    for raw in text.splitlines():
        line_no += 1
        line = raw.strip()
        if not line:
            continue
        if line.startswith("SF:"):
            if current is not None:
                raise MalformedInput(
                    f"line {line_no}: new SF before end_of_record for {current.path}"
                )
            sf_path = line[len("SF:") :]
            rel = _normalize_path(sf_path, repo_root)
            existing = files.get(rel)
            if existing is not None:
                current = existing
            else:
                current = FileCoverage(path=rel)
                files[rel] = current
            continue
        if line == "end_of_record":
            if current is None:
                raise MalformedInput(f"line {line_no}: end_of_record outside SF block")
            current = None
            seen_record_terminators += 1
            continue
        if current is None:
            # Records outside an SF block (TN:, etc.) are ignored.
            continue
        if line.startswith("DA:"):
            m = _LCOV_DA.match(line)
            if not m:
                raise MalformedInput(f"line {line_no}: malformed DA record: {line!r}")
            ln = int(m.group(1))
            hits = int(m.group(2))
            previous = current.lines.get(ln, 0)
            # When the same line appears more than once we sum hits (LCOV
            # allows merged reports). This is unambiguous because hits are
            # non-negative integers.
            current.lines[ln] = previous + hits
            continue
        if line.startswith("LF:"):
            # Validate the structural shape but rely on the DA records for
            # totals so a merged report with overlapping SF blocks stays
            # consistent: LF/LH would double-count, DA-based totals do not.
            if not _LCOV_LF.match(line):
                raise MalformedInput(f"line {line_no}: malformed LF record: {line!r}")
            continue
        if line.startswith("LH:"):
            if not _LCOV_LH.match(line):
                raise MalformedInput(f"line {line_no}: malformed LH record: {line!r}")
            continue
        # Other records (FN/FNDA/BRDA/BRF/BRH) are ignored — this tool only
        # gates on line coverage, matching the LCOV LF/LH semantics.
    if current is not None:
        raise MalformedInput("LCOV ends without end_of_record")
    if seen_record_terminators == 0:
        raise MalformedInput("LCOV contains no end_of_record markers")
    return files


def _normalize_path(path: str, repo_root: Path) -> str:
    """Normalize a path to a repository-relative POSIX string.

    LCOV files may contain absolute paths (typical for cargo-llvm-cov) or
    already-relative ones. Paths outside the repo are returned as-is so that
    the caller can distinguish them in the output.
    """

    p = Path(path)
    if p.is_absolute():
        try:
            rel = p.resolve().relative_to(repo_root.resolve())
        except ValueError:
            return p.as_posix()
        return rel.as_posix()
    return p.as_posix()


# ---------------------------------------------------------------------------
# Git diff parser
# ---------------------------------------------------------------------------


_DIFF_FILE_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+?)$")
_DIFF_RENAME_TO = re.compile(r"^rename to (.+)$")
_DIFF_NEW_FILE = re.compile(r"^new file mode \d+$")
_DIFF_DELETED_FILE = re.compile(r"^deleted file mode \d+$")
# Path captures are non-greedy and explicitly tolerate the optional `\t<meta>`
# tail that the unified-diff convention permits (GNU diff(1) appends a tab
# plus the timestamp; `git diff` normally omits it but external tools and
# `git format-patch` callers can produce it).
_DIFF_PLUS_FILE = re.compile(r"^\+\+\+ (?:b/(.+?)|/dev/null)(?:\t.*)?$")
_DIFF_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(text: str) -> ChangedLines:
    """Parse a unified diff (``--unified=0``) into a ChangedLines map.

    Only added/modified lines on the ``+`` side are reported. Deleted-only
    hunks contribute no changed lines. Renames are tracked under the new
    path. Non-Rust files are returned as-is — filtering is the caller's job.
    """

    changes: dict[str, set[int]] = {}
    current_path: str | None = None
    rename_target: str | None = None
    is_deleted = False
    line_no = 0
    for raw in text.splitlines():
        line_no += 1
        if raw.startswith("diff --git "):
            m = _DIFF_FILE_HEADER.match(raw)
            if not m:
                raise MalformedInput(f"diff line {line_no}: bad header {raw!r}")
            current_path = m.group(2)
            rename_target = None
            is_deleted = False
            continue
        if raw.startswith("deleted file mode"):
            is_deleted = True
            continue
        if raw.startswith("new file mode"):
            is_deleted = False
            continue
        if raw.startswith("rename to "):
            m = _DIFF_RENAME_TO.match(raw)
            if m:
                rename_target = m.group(1)
            continue
        if raw.startswith("+++ "):
            m = _DIFF_PLUS_FILE.match(raw)
            if not m:
                # Unknown +++ line — treat as malformed to avoid silent drops.
                raise MalformedInput(f"diff line {line_no}: bad +++ {raw!r}")
            if m.group(1):
                current_path = m.group(1)
            continue
        if raw.startswith("@@"):
            if is_deleted:
                continue
            m = _DIFF_HUNK.match(raw)
            if not m:
                raise MalformedInput(f"diff line {line_no}: bad hunk {raw!r}")
            start = int(m.group(1))
            count_str = m.group(2)
            count = int(count_str) if count_str is not None else 1
            if count == 0:
                # Deleted-only hunk; nothing to record on the + side.
                continue
            path = rename_target or current_path
            if path is None:
                raise MalformedInput(f"diff line {line_no}: hunk before file header")
            bucket = changes.setdefault(path, set())
            for ln in range(start, start + count):
                bucket.add(ln)
            continue
        # Body lines under --unified=0 should not appear, but if they do they
        # are ignored — the hunk header already records the line range.
    return ChangedLines(by_file={k: v for k, v in changes.items() if v})


# ---------------------------------------------------------------------------
# Policy loader
# ---------------------------------------------------------------------------


def load_policy(path: Path) -> Policy:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise InvalidPolicy(f"cannot read policy {path}: {exc}") from exc

    version = data.get("policy_version", 1)
    if not isinstance(version, int):
        raise InvalidPolicy("policy_version must be an integer")

    thresholds_raw = data.get("thresholds")
    if not isinstance(thresholds_raw, dict):
        raise InvalidPolicy("missing [thresholds] table")
    try:
        thresholds = Thresholds(
            overall=float(thresholds_raw["overall"]),
            aggregate_changed=float(thresholds_raw["aggregate_changed"]),
            per_file_changed=float(thresholds_raw["per_file_changed"]),
            trust_boundary_changed=float(thresholds_raw["trust_boundary_changed"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidPolicy(f"invalid thresholds: {exc}") from exc
    for name, value in (
        ("overall", thresholds.overall),
        ("aggregate_changed", thresholds.aggregate_changed),
        ("per_file_changed", thresholds.per_file_changed),
        ("trust_boundary_changed", thresholds.trust_boundary_changed),
    ):
        if not (0.0 <= value <= 100.0):
            raise InvalidPolicy(f"threshold {name}={value} outside 0..100")

    groups_raw = data.get("trust_boundaries", [])
    if not isinstance(groups_raw, list):
        raise InvalidPolicy("trust_boundaries must be an array of tables")
    groups: list[TrustBoundaryGroup] = []
    for i, entry in enumerate(groups_raw):
        if not isinstance(entry, dict):
            raise InvalidPolicy(f"trust_boundaries[{i}] must be a table")
        purpose = entry.get("purpose")
        if not isinstance(purpose, str) or not purpose:
            raise InvalidPolicy(f"trust_boundaries[{i}].purpose must be a non-empty string")
        patterns = entry.get("patterns")
        if not isinstance(patterns, list) or not patterns or not all(
            isinstance(p, str) and p for p in patterns
        ):
            raise InvalidPolicy(
                f"trust_boundaries[{i}].patterns must be a non-empty list of strings"
            )
        groups.append(TrustBoundaryGroup(purpose=purpose, patterns=list(patterns)))

    if not groups:
        raise InvalidPolicy("at least one [[trust_boundaries]] group is required")
    return Policy(version=version, thresholds=thresholds, trust_boundaries=groups)


# ---------------------------------------------------------------------------
# Trust-boundary matching
# ---------------------------------------------------------------------------


def expand_trust_boundary_files(
    policy: Policy, repo_files: Iterable[str]
) -> tuple[set[str], dict[str, list[str]]]:
    """Return (matched_files, pattern_to_matches) for all trust-boundary patterns.

    ``repo_files`` is the universe of repository-relative paths considered
    in scope (all tracked ``*.rs`` files). The returned set is the union of
    all matches across all patterns. Patterns that match nothing are
    reported via the second return value (an empty list signals failure).
    """

    rs_files = [p for p in repo_files if p.endswith(RUST_EXT)]
    matches: set[str] = set()
    by_pattern: dict[str, list[str]] = {}
    for group in policy.trust_boundaries:
        for pattern in group.patterns:
            hit = [f for f in rs_files if fnmatch.fnmatchcase(f, pattern)]
            by_pattern[pattern] = hit
            matches.update(hit)
    return matches, by_pattern


def list_tracked_rs_files(repo_root: Path) -> list[str]:
    try:
        out = subprocess.check_output(
            ["git", "ls-files", "--", "*.rs"],
            cwd=repo_root,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise MalformedInput(f"git ls-files failed: {exc}") from exc
    return [line.strip() for line in out.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Diff acquisition
# ---------------------------------------------------------------------------


def get_diff_text(repo_root: Path, base: str, head: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "diff", "--unified=0", f"{base}...{head}", "--", "*.rs"],
            cwd=repo_root,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise MalformedInput(f"git diff failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(
    lcov: dict[str, FileCoverage],
    diff: ChangedLines,
    policy: Policy,
    base_sha: str,
    head_sha: str,
    trust_boundary_files: set[str],
    enforce_changed: bool,
) -> Report:
    # Overall coverage from LCOV totals.
    total_lf = 0
    total_lh = 0
    for fc in lcov.values():
        total_lf += len(fc.lines)
        total_lh += len(fc.covered_lines())
    overall_percent = 100.0 * total_lh / total_lf if total_lf else 100.0
    overall_block = {
        "lf": total_lf,
        "lh": total_lh,
        "percent": overall_percent,
    }

    file_results: list[FileResult] = []
    rs_files = [f for f in diff.files() if f.endswith(RUST_EXT)]
    for path in sorted(rs_files):
        changed_lines = diff.by_file[path]
        fc = lcov.get(path)
        instrumented_for_file = fc.instrumented_lines() if fc else set()
        covered_for_file = fc.covered_lines() if fc else set()
        instrumented_changed = changed_lines & instrumented_for_file
        covered_changed = instrumented_changed & covered_for_file
        uncovered = instrumented_changed - covered_for_file
        non_instrumented = changed_lines - instrumented_for_file
        file_results.append(
            FileResult(
                path=path,
                is_trust_boundary=path in trust_boundary_files,
                changed_total=len(changed_lines),
                changed_instrumented=len(instrumented_changed),
                changed_covered=len(covered_changed),
                non_instrumented_lines=sorted(non_instrumented),
                uncovered_lines=sorted(uncovered),
                has_lcov_records=fc is not None,
            )
        )

    agg_inst = sum(fr.changed_instrumented for fr in file_results)
    agg_cov = sum(fr.changed_covered for fr in file_results)
    agg_percent = 100.0 * agg_cov / agg_inst if agg_inst else None
    aggregate_block = {
        "changed_instrumented": agg_inst,
        "changed_covered": agg_cov,
        "percent": agg_percent,
    }

    gates: list[GateResult] = []

    gates.append(
        GateResult(
            name="overall",
            threshold=policy.thresholds.overall,
            measured=overall_percent,
            passed=overall_percent >= policy.thresholds.overall,
            detail=f"{total_lh}/{total_lf} lines covered",
        )
    )

    if enforce_changed:
        # Aggregate.
        if agg_inst == 0:
            agg_passed = True
            agg_detail = "no instrumented changed lines"
        else:
            agg_passed = agg_percent is not None and agg_percent >= policy.thresholds.aggregate_changed
            agg_detail = f"{agg_cov}/{agg_inst} changed instrumented lines covered"
        gates.append(
            GateResult(
                name="aggregate_changed",
                threshold=policy.thresholds.aggregate_changed,
                measured=agg_percent,
                passed=agg_passed,
                detail=agg_detail,
            )
        )

        # Per-file. The measured value reported is the worst-file percent so
        # the JSON gives reviewers a single number to track; the detail names
        # every failing file when any are below the threshold.
        percents = [
            (fr.path, fr.percent)
            for fr in file_results
            if fr.changed_instrumented > 0 and fr.percent is not None
        ]
        if percents:
            worst_path, worst_percent = min(percents, key=lambda x: x[1])
            failing = sorted(
                path for path, pct in percents if pct < policy.thresholds.per_file_changed
            )
        else:
            worst_path, worst_percent = None, None
            failing = []
        if failing:
            per_file_detail = "files below threshold: " + ", ".join(failing)
        elif worst_path is not None:
            per_file_detail = f"worst file {worst_path} at {worst_percent:.2f}%"
        else:
            per_file_detail = "no instrumented changed lines"
        gates.append(
            GateResult(
                name="per_file_changed",
                threshold=policy.thresholds.per_file_changed,
                measured=worst_percent,
                passed=not failing,
                detail=per_file_detail,
            )
        )

        # Trust-boundary.
        #
        # A trust-boundary file fails the gate when either
        #   (a) it has executable changed lines and the coverage of those
        #       lines is below the threshold, or
        #   (b) it was changed but is absent from the LCOV report entirely
        #       (so we cannot prove the changes are non-executable).
        # A file whose changed lines are all non-instrumented (comments,
        # whitespace, doc strings) passes — the LCOV report establishes
        # that the file is instrumented and those lines carry no risk.
        tb_passed = True
        tb_details: list[str] = []
        tb_worst: float | None = None
        for fr in file_results:
            if not fr.is_trust_boundary:
                continue
            if fr.changed_total == 0:
                continue
            if not fr.has_lcov_records:
                tb_passed = False
                tb_details.append(f"{fr.path}: no LCOV records for changed lines")
                continue
            if fr.changed_instrumented == 0:
                # File is instrumented overall, but none of the changed lines
                # are executable. Treat as compliant.
                continue
            percent = fr.percent
            if percent is None:
                continue
            if tb_worst is None or percent < tb_worst:
                tb_worst = percent
            if percent < policy.thresholds.trust_boundary_changed:
                tb_passed = False
                tb_details.append(
                    f"{fr.path}: {percent:.2f}% < "
                    f"{policy.thresholds.trust_boundary_changed:.2f}%"
                )
        if tb_passed and not tb_details:
            tb_details.append("no trust-boundary files changed or all fully covered")
        gates.append(
            GateResult(
                name="trust_boundary_changed",
                threshold=policy.thresholds.trust_boundary_changed,
                measured=tb_worst,
                passed=tb_passed,
                detail="; ".join(tb_details),
            )
        )

    passed = all(g.passed for g in gates)
    return Report(
        version=VERSION,
        base_sha=base_sha,
        head_sha=head_sha,
        policy_version=policy.version,
        thresholds=policy.thresholds,
        overall=overall_block,
        aggregate_changed=aggregate_block,
        file_results=file_results,
        gates=gates,
        passed=passed,
    )


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------


def render_markdown(report: Report) -> str:
    out: list[str] = []
    overall_status = "PASS" if report.passed else "FAIL"
    out.append(f"# Coverage report — {overall_status}")
    out.append("")
    out.append(
        f"- tool version: `{report.version}`  ·  policy version: `{report.policy_version}`"
    )
    out.append(f"- base sha: `{report.base_sha}`")
    out.append(f"- head sha: `{report.head_sha}`")
    out.append("")
    out.append("## Gates")
    out.append("")
    out.append("| Gate | Threshold | Measured | Status | Detail |")
    out.append("|---|---:|---:|:---:|---|")
    for g in report.gates:
        measured = "n/a" if g.measured is None else f"{g.measured:.2f}%"
        status = "PASS" if g.passed else "FAIL"
        out.append(
            f"| `{g.name}` | {g.threshold:.2f}% | {measured} | {status} | {g.detail} |"
        )
    out.append("")
    if report.file_results:
        out.append("## Per-file changed-line coverage")
        out.append("")
        out.append("| File | TB | Changed | Instrumented | Covered | % | Uncovered lines | Non-instrumented |")
        out.append("|---|:---:|---:|---:|---:|---:|---|---|")
        for fr in report.file_results:
            percent = "n/a" if fr.percent is None else f"{fr.percent:.2f}%"
            tb = "yes" if fr.is_trust_boundary else ""
            uncov = _short_list(fr.uncovered_lines)
            noninst = _short_list(fr.non_instrumented_lines)
            out.append(
                f"| `{fr.path}` | {tb} | {fr.changed_total} | {fr.changed_instrumented} | {fr.changed_covered} | {percent} | {uncov} | {noninst} |"
            )
        out.append("")
    out.append(
        f"## Overall workspace coverage: {report.overall['percent']:.2f}% "
        f"({report.overall['lh']}/{report.overall['lf']} lines)"
    )
    out.append("")
    return "\n".join(out)


def _short_list(items: list[int], limit: int = 20) -> str:
    if not items:
        return "—"
    if len(items) <= limit:
        return ", ".join(str(i) for i in items)
    head = ", ".join(str(i) for i in items[:limit])
    return f"{head}, … (+{len(items) - limit})"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="chaffra coverage checker")
    parser.add_argument("--lcov", required=True, help="Path to lcov.info")
    parser.add_argument("--policy", required=True, help="Path to coverage-policy.toml")
    parser.add_argument("--repo-root", default=".", help="Repository root (default: cwd)")
    parser.add_argument("--base-sha", required=True, help="Base commit SHA")
    parser.add_argument("--head-sha", required=True, help="Head commit SHA")
    parser.add_argument(
        "--diff",
        default=None,
        help="Path to a unified=0 diff. If omitted, the tool runs git diff itself.",
    )
    parser.add_argument(
        "--json-out", default=None, help="Optional path to write JSON output"
    )
    parser.add_argument(
        "--markdown-out", default=None, help="Optional path to write Markdown output"
    )
    parser.add_argument(
        "--repo-files",
        default=None,
        help=(
            "Optional path to a newline-separated list of repository files to use "
            "as the universe for trust-boundary glob matching. When omitted, the "
            "tool calls 'git ls-files -- *.rs' inside --repo-root."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("pr", "push"),
        default="pr",
        help=(
            "pr: enforce overall + changed-line gates. push: enforce overall only "
            "(changed-line gates are computed for the JSON/markdown output but "
            "not used to fail the build)."
        ),
    )
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    try:
        lcov_text = Path(args.lcov).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read lcov: {exc}", file=sys.stderr)
        return EXIT_MALFORMED

    try:
        policy = load_policy(Path(args.policy))
    except InvalidPolicy as exc:
        print(f"error: invalid policy: {exc}", file=sys.stderr)
        return EXIT_MALFORMED

    try:
        lcov = parse_lcov(lcov_text, repo_root)
    except MalformedInput as exc:
        print(f"error: malformed lcov: {exc}", file=sys.stderr)
        return EXIT_MALFORMED

    if args.diff is not None:
        try:
            diff_text = Path(args.diff).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot read diff: {exc}", file=sys.stderr)
            return EXIT_MALFORMED
    else:
        try:
            diff_text = get_diff_text(repo_root, args.base_sha, args.head_sha)
        except MalformedInput as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_MALFORMED

    try:
        diff = parse_unified_diff(diff_text)
    except MalformedInput as exc:
        print(f"error: malformed diff: {exc}", file=sys.stderr)
        return EXIT_MALFORMED

    if args.repo_files is not None:
        try:
            repo_files = [
                line.strip()
                for line in Path(args.repo_files).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except OSError as exc:
            print(f"error: cannot read repo-files: {exc}", file=sys.stderr)
            return EXIT_MALFORMED
    else:
        try:
            repo_files = list_tracked_rs_files(repo_root)
        except MalformedInput as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_MALFORMED

    matched, by_pattern = expand_trust_boundary_files(policy, repo_files)
    unmatched = sorted(p for p, hits in by_pattern.items() if not hits)
    if unmatched:
        print(
            "error: trust-boundary patterns matched no current files: "
            + ", ".join(unmatched),
            file=sys.stderr,
        )
        return EXIT_MALFORMED

    report = evaluate(
        lcov=lcov,
        diff=diff,
        policy=policy,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        trust_boundary_files=matched,
        enforce_changed=args.mode == "pr",
    )

    json_text = json.dumps(report.to_json(), indent=2, sort_keys=True)
    md_text = render_markdown(report)
    if args.json_out:
        Path(args.json_out).write_text(json_text + "\n", encoding="utf-8")
    if args.markdown_out:
        Path(args.markdown_out).write_text(md_text + "\n", encoding="utf-8")
    # Always echo the markdown to stdout so the workflow can capture it.
    print(md_text)
    return EXIT_OK if report.passed else EXIT_GATE_FAIL


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
