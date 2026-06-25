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

Scope: this gate is Rust-only (``RUST_EXT``). It never classifies source
text — the LCOV DA records are the sole authority on which changed lines
are executable and must be covered. A changed line absent from the DA
records is a line the coverage build did not instrument (a brace,
declaration, comment, blank line). Target-`cfg`-gated code reaches the DA
records via the per-target instrumentation matrix in CI; feature-`cfg`-gated
code reaches them via ``cargo hack --feature-powerset``, which instruments
EVERY feature combination of every workspace crate (so both
``cfg(feature = "x")`` and ``cfg(not(feature = "x"))``, and all combinations
for N≥2 features, are covered by construction). Both mechanisms are
documented in CONTRIBUTING.md (Coverage > Multi-target instrumentation) and
policed by ``scripts/tests/test_coverage_check.py`` (see
``TestPolicyAndCiInvariants``).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


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


@dataclass
class FileCoverage:
    """LCOV records for a single source file.

    ``lines`` maps DA line numbers to hits. Both gates compute over the DA
    records directly — overall uses ``Σ(unique DA) / Σ(unique covered DA)``
    (the DA-coherent metric); changed-line gates use the DA records for
    per-line resolution. The producer's declared ``LF``/``LH`` summary is
    structurally validated by :func:`parse_lcov` (``LH<=LF``, ``LF>=unique-DA``,
    and the unseen-hits reconciliation bound) but is *not* an input to the
    arithmetic, so an overstated summary cannot inflate the score past what
    the DA records demonstrate. ``LH`` is NOT required to be
    ``>= unique-hit-DA``: LLVM's ``llvm-cov export`` can undercount that
    summary under powerset accumulation, which the parser tolerates by
    clamping the effective ``LH`` up to the DA hit count (the undercount is
    the opposite of inflation and cannot lift the score). The fields are
    retained on the dataclass for diagnostics / merge bookkeeping only.
    """

    path: str
    lines: dict[int, int] = field(default_factory=dict)
    declared_lf: int = 0
    declared_lh: int = 0

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
    # Changed lines absent from the LCOV DA records — llvm did not instrument
    # them (braces, declarations, comments, blank lines). Reported for
    # transparency; not treated as failures, since llvm is the authority on
    # which lines are executable.
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

    Per-block invariants for ACTIVE (in-repo) blocks — any violation raises
    ``MalformedInput`` (exit 2):

      * exactly one ``LF`` and one ``LH`` record (reject missing / duplicate),
      * ``LH <= LF``,
      * ``LF >= unique DA lines`` — the DA instrumentation detail must be a
        subset of the declared instrumented summary (reconciliation),
      * ``(effective_LH - covered_DA) <= (LF - unique_DA)`` — the *unseen*
        hits a producer claims must not exceed the *unseen* instrumented
        lines. This catches the inflation/strict-overrun case (e.g.
        ``LF:10 LH:10 DA:1,1 DA:2,0`` → unseen_hits=9 > unseen_inst=8). It
        does NOT catch the equal-pair case (``DA:1,1; LF:N; LH:N`` for any N —
        unseen_hits = unseen_inst = N-1 passes). That case is instead defanged
        by the arithmetic choice in :func:`evaluate`, which uses the
        DA-coherent metric ``Σ(covered DA) / Σ(unique DA)`` and so never reads
        ``LH``; the producer's high declared LH cannot lift the score past the
        DA records' demonstrated coverage.
      * no duplicate DA record for the same line,
      * at least one DA record per ACTIVE block,
      * ``end_of_record`` terminates the block.

    ``LH`` is NOT required to be ``>= unique hit DA lines``. LLVM's
    ``llvm-cov export`` (the toolchain producer beneath cargo-llvm-cov) can
    emit an ``LH`` summary that UNDERCOUNTS the DA hit detail — observed as an
    off-by-one under feature-powerset profraw accumulation, reproduced
    identically across cargo-llvm-cov 0.6.21 and 0.8.7. An ``LH`` below the DA
    hit count is the opposite of coverage inflation and cannot affect the
    DA-derived score, so the parser clamps the effective ``LH`` up to the
    authoritative DA hit count rather than rejecting. Only ``LH`` OVERclaiming
    (the inflation direction) is rejected, via ``LH <= LF`` and the unseen-hits
    bound above.

    The remaining bounds are the strongest the producer satisfies:
    empirically it declares ``LF`` strictly greater than the number of
    serialised DA lines in 72 / 88 workspace blocks, so a strict
    ``LF == DA-count`` equality would reject legitimate output.

    Two SF blocks that normalise to the same repository-relative path are
    rejected as a collision. SF paths that escape ``repo_root`` start a
    *skipped* block: the parser still validates record syntax and
    ``end_of_record`` termination inside it, but does not enforce the
    LF/LH/DA-count invariants and discards the data.
    """

    files: dict[str, FileCoverage] = {}
    # Parser states: IDLE (between blocks), ACTIVE (inside an in-repo SF),
    # SKIPPED (inside an out-of-repo SF — validate structure, discard data).
    state = "IDLE"
    current: FileCoverage | None = None
    block_da_lines: set[int] = set()
    block_hit_lines: set[int] = set()
    block_lf: int | None = None
    block_lh: int | None = None
    seen_record_terminators = 0
    line_no = 0

    def reset_block() -> None:
        nonlocal block_da_lines, block_hit_lines, block_lf, block_lh
        block_da_lines = set()
        block_hit_lines = set()
        block_lf = None
        block_lh = None

    for raw in text.splitlines():
        line_no += 1
        line = raw.strip()
        if not line:
            continue
        if line.startswith("SF:"):
            if state != "IDLE":
                where = current.path if current is not None else "<skipped block>"
                raise MalformedInput(
                    f"line {line_no}: new SF before end_of_record for {where}"
                )
            sf_path = line[len("SF:") :]
            if not sf_path.strip():
                raise MalformedInput(f"line {line_no}: empty SF path")
            rel = _normalize_path(sf_path, repo_root)
            if rel is None:
                # Out-of-repo SF (e.g. vendored crate under
                # ~/.cargo/registry/). Enter SKIPPED state so a missing
                # end_of_record or a malformed record inside this block is
                # still detected; the data is just not stored.
                state = "SKIPPED"
                current = None
                reset_block()
                continue
            if rel in files:
                raise MalformedInput(
                    f"line {line_no}: duplicate SF block for normalized path {rel!r}"
                )
            current = FileCoverage(path=rel)
            files[rel] = current
            state = "ACTIVE"
            reset_block()
            continue
        if line == "end_of_record":
            if state == "IDLE":
                raise MalformedInput(f"line {line_no}: end_of_record outside SF block")
            # SKIPPED blocks were treated permissively in an earlier revision
            # — only their record syntax was validated, while LF/LH/DA bounds
            # were skipped. That let a malformed out-of-repo SF carry the
            # parser past inputs the contract calls "malformed or ambiguous
            # LCOV." Apply the same per-block invariants to both states; only
            # ACTIVE blocks then persist their declared totals.
            where = current.path if state == "ACTIVE" else "<skipped block>"
            if block_lf is None or block_lh is None:
                raise MalformedInput(
                    f"line {line_no}: SF block for {where!r} missing LF/LH summary"
                )
            if not block_da_lines:
                # A file with no executable lines (e.g. a `pub mod` re-export
                # module) is emitted by cargo-llvm-cov as LF:0/LH:0 with no
                # DA records. Accept it (ACTIVE contributes 0 to overall;
                # SKIPPED is dropped) only when LF:0/LH:0; a zero-DA block
                # that claims instrumented lines is internally contradictory.
                if block_lf != 0 or block_lh != 0:
                    raise MalformedInput(
                        f"line {line_no}: SF block for {where!r} has no DA records "
                        f"but declares LF={block_lf}/LH={block_lh}"
                    )
                if state == "ACTIVE":
                    assert current is not None
                    current.declared_lf = 0
                    current.declared_lh = 0
                current = None
                reset_block()
                state = "IDLE"
                seen_record_terminators += 1
                continue
            if block_lh > block_lf:
                raise MalformedInput(
                    f"line {line_no}: LH={block_lh} > LF={block_lf} for {where!r}"
                )
            if block_lf < len(block_da_lines):
                raise MalformedInput(
                    f"line {line_no}: LF={block_lf} below {len(block_da_lines)} "
                    f"unique DA lines for {where!r}"
                )
            # LH may UNDERCOUNT the DA detail. LLVM's `llvm-cov export`
            # (the toolchain producer beneath cargo-llvm-cov) can emit an LH
            # summary one or more below the number of DA lines with a nonzero
            # hit count — observed as an off-by-one on
            # `crates/chaffra-mcp/src/tools.rs` under the feature-powerset
            # profraw accumulation, and reproduced identically across
            # cargo-llvm-cov 0.6.21 and 0.8.7 (so it is an LLVM-level summary
            # quirk, not a cargo-llvm-cov one). This is BENIGN and must not be
            # rejected:
            #   * The DA records are authoritative. The coverage score is
            #     computed from them (`FileCoverage.covered_lines` /
            #     `instrumented_lines` in `evaluate`), and `merge_lcov`
            #     recomputes `declared_lh` from DA — the parsed LH is advisory
            #     and never reaches the score.
            #   * An LH BELOW the DA-hit count is the opposite of coverage
            #     inflation; it cannot lift a file past its demonstrated
            #     coverage. (Inflation — LH too HIGH — is still rejected by the
            #     `LH <= LF` check above and the unseen-hits upper bound below.)
            # So clamp the effective LH up to the authoritative DA-hit count
            # rather than rejecting. A bounded threshold on the undercount is
            # deliberately avoided: any constant would itself be a magic value
            # that could reject legitimate producer output, which is the bug
            # this guards against.
            effective_lh = max(block_lh, len(block_hit_lines))
            # Reconciliation bound between the (clamped) summary and the
            # detail: the producer's *unseen* hits (effective LH − covered DA
            # lines) must not exceed the producer's *unseen* instrumented
            # lines (LF − unique DA lines). A producer cannot claim more hits
            # behind the DA records than there is undeclared instrumentation
            # behind them. This rejects, e.g., `LF:10 LH:10 DA:1,1 DA:2,0`
            # (unseen_hits=9 > unseen_inst=8). Clamping never lowers a high LH
            # (max with the hit count), so an inflated LH is still caught here.
            unseen_inst = block_lf - len(block_da_lines)
            unseen_hits = effective_lh - len(block_hit_lines)
            if unseen_hits > unseen_inst:
                raise MalformedInput(
                    f"line {line_no}: LH={block_lh} claims {unseen_hits} hits "
                    f"unaccounted for in DA but LF={block_lf} accounts for only "
                    f"{unseen_inst} instrumented lines outside DA for {where!r}"
                )
            if state == "ACTIVE":
                assert current is not None
                current.declared_lf = block_lf
                current.declared_lh = effective_lh
            current = None
            reset_block()
            state = "IDLE"
            seen_record_terminators += 1
            continue
        if state == "IDLE":
            # Records outside an SF block (TN:, etc.) are ignored.
            continue
        if line.startswith("DA:"):
            m = _LCOV_DA.match(line)
            if not m:
                raise MalformedInput(f"line {line_no}: malformed DA record: {line!r}")
            ln = int(m.group(1))
            hits = int(m.group(2))
            if ln in block_da_lines:
                where = current.path if current is not None else "<skipped block>"
                raise MalformedInput(
                    f"line {line_no}: duplicate DA record for line {ln} in {where}"
                )
            block_da_lines.add(ln)
            if hits > 0:
                block_hit_lines.add(ln)
            if state == "ACTIVE":
                assert current is not None
                current.lines[ln] = hits
            continue
        if line.startswith("LF:"):
            m_lf = _LCOV_LF.match(line)
            if not m_lf:
                raise MalformedInput(f"line {line_no}: malformed LF record: {line!r}")
            if block_lf is not None:
                where = current.path if state == "ACTIVE" else "<skipped block>"
                raise MalformedInput(
                    f"line {line_no}: duplicate LF record for {where!r}"
                )
            block_lf = int(m_lf.group(1))
            continue
        if line.startswith("LH:"):
            m_lh = _LCOV_LH.match(line)
            if not m_lh:
                raise MalformedInput(f"line {line_no}: malformed LH record: {line!r}")
            if block_lh is not None:
                where = current.path if state == "ACTIVE" else "<skipped block>"
                raise MalformedInput(
                    f"line {line_no}: duplicate LH record for {where!r}"
                )
            block_lh = int(m_lh.group(1))
            continue
        # Other records (FN/FNDA/BRDA/BRF/BRH) are ignored — this tool gates
        # only on line coverage from DA records.
    if state != "IDLE":
        where = current.path if current is not None else "<skipped block>"
        raise MalformedInput(f"LCOV ends without end_of_record (last block: {where})")
    if seen_record_terminators == 0:
        raise MalformedInput("LCOV contains no end_of_record markers")
    return files


def _normalize_path(path: str, repo_root: Path) -> str | None:
    """Normalize a path to a repository-relative POSIX string.

    Returns ``None`` when the path resolves outside ``repo_root`` so the
    caller drops the corresponding SF block before arithmetic. This forces
    every coverage figure to be computed over the repository tree only —
    vendored crates under ``~/.cargo/registry/`` and aliased ``./..`` paths
    cannot contribute to overall or changed-line gates.
    """

    # cargo-llvm-cov on Windows emits SF paths with backslash separators. The
    # CI matrix relativizes each leg's LCOV on its own runner before upload,
    # but normalize here too so a backslash relative path (e.g. a hand-written
    # fixture or a producer the workflow did not pre-clean) still keys to the
    # same repository-relative POSIX path rather than a single opaque
    # filename. Backslash is not a legal path separator on POSIX and does not
    # occur in the repository's tracked names, so this rewrite is loss-free.
    path = path.replace("\\", "/")
    p = Path(path)
    repo_real = repo_root.resolve()
    if p.is_absolute():
        try:
            rel = p.resolve().relative_to(repo_real)
        except ValueError:
            return None
        return rel.as_posix()
    # For a repository-relative entry, resolve through repo_root so
    # `./a.rs` and `a.rs` canonicalize to the same key and `../escape.rs`
    # is rejected as out-of-tree.
    try:
        candidate = (repo_root / p).resolve()
        rel = candidate.relative_to(repo_real)
    except (OSError, ValueError):
        return None
    return rel.as_posix()


def merge_lcov(maps: list[dict[str, FileCoverage]]) -> dict[str, FileCoverage]:
    """Merge per-target LCOV maps into one with union/best-hit semantics.

    The multi-target coverage matrix runs ``cargo llvm-cov`` once per runner
    OS, so trust-boundary code gated behind ``#[cfg(target_os = "windows")]``
    is instrumented only in the Windows map, code behind
    ``#[cfg(target_os = "linux")]`` only in the Linux map, and so on. Merging
    is what lets the single 100% trust-boundary gate see all of it: no single
    build can instrument every target's code, but the union of the per-target
    builds can.

    Merge rules, applied per repository-relative path:

      * **Instrumented lines are unioned.** A line present in any target's DA
        records is instrumented in the merge — that is the whole point: a
        line only one target compiles is still an executable line.
      * **A line is covered if it is covered on any target** (merged hit count
        is the max across targets). A line hit on Linux but compiled-and-cold
        on macOS counts as covered, which matches the gate's question — "is
        this changed line exercised by *some* part of the test suite?" — not
        "is it exercised on every OS".

    Within a single map, :func:`parse_lcov` has already rejected a duplicate
    SF block. Across maps the same path is the merge point, not a collision.
    A single-element ``maps`` list returns the equivalent of that one map, so
    the non-matrix (single ``--lcov``) caller is unaffected.

    The merged ``declared_lf`` / ``declared_lh`` are recomputed from the
    unioned DA records (they are summaries of the merged detail, not of any
    one producer's run). Downstream arithmetic reads the DA records directly
    via :meth:`FileCoverage.instrumented_lines` / ``covered_lines`` and never
    the declared summary, so this only keeps the dataclass self-consistent.
    """

    merged: dict[str, FileCoverage] = {}
    for one in maps:
        for path, fc in one.items():
            existing = merged.get(path)
            if existing is None:
                # Fresh FileCoverage so the caller's objects are never mutated.
                existing = FileCoverage(path=path)
                merged[path] = existing
            for ln, hits in fc.lines.items():
                prev = existing.lines.get(ln)
                existing.lines[ln] = hits if prev is None else max(prev, hits)
    for fc in merged.values():
        fc.declared_lf = len(fc.lines)
        fc.declared_lh = len(fc.covered_lines())
    return merged


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


def list_tracked_rs_files(repo_root: Path, head_sha: str) -> list[str]:
    """List ``*.rs`` paths in the immutable tree at ``head_sha``.

    Uses ``git ls-tree`` against the commit rather than ``git ls-files``
    (which reads the mutable index/worktree). A build script that stages a
    generated ``.rs`` path during ``cargo llvm-cov`` cannot then make its SF
    records eligible: the file does not exist in the reviewed commit tree.
    """

    # NB: `git ls-tree`'s pathspec is not a shell glob (unlike `git
    # ls-files`), so `-- '*.rs'` would match nothing — list the whole tree
    # and filter in Python. `-z` emits NUL-terminated raw paths; combined
    # with `core.quotePath=false` this avoids git's default C-quoting of
    # non-ASCII names (which would otherwise append a `"` and silently drop
    # a tracked file from the eligibility set, inflating overall coverage).
    try:
        out = subprocess.check_output(
            [
                "git",
                "-c",
                "core.quotePath=false",
                "ls-tree",
                "-r",
                "-z",
                "--name-only",
                head_sha,
            ],
            cwd=repo_root,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise MalformedInput(f"git ls-tree failed: {exc}") from exc
    return [path for path in out.split("\0") if path.endswith(RUST_EXT)]


def get_source_line_counts(
    repo_root: Path, head_sha: str, paths: list[str]
) -> dict[str, int]:
    """Return ``{path: line_count}`` for ``paths`` in the immutable head tree.

    Reads each blob via ``git cat-file --batch`` against ``head_sha:path``
    and counts the lines that exist in the reviewed commit, NOT the mutable
    worktree. This is the authority the DA-line-range gate validates against:
    a producer that emits ``DA:999999,1`` for a tracked path whose blob has
    20 lines cannot inflate coverage by claiming coordinates that don't
    exist. ``cat-file --batch`` streams one process for all paths so the
    cost is one git invocation per gate run.

    ``paths`` are repository-relative POSIX strings. A path missing from the
    head tree is omitted from the result, so the caller's DA-line check
    skips it (eligibility already drops untracked paths before this helper
    is reached).

    Line counting follows POSIX convention: the count is the number of
    trailing-newline-terminated lines plus 1 if a final non-newline-
    terminated trailer exists. cargo-llvm-cov emits DA records for the
    1-based line number of each instrumented statement, so this metric is
    the upper bound a DA line number may take.
    """

    if not paths:
        return {}
    request = "".join(f"{head_sha}:{p}\n" for p in paths).encode("utf-8")
    try:
        proc = subprocess.run(
            ["git", "cat-file", "--batch"],
            input=request,
            cwd=repo_root,
            check=False,
            capture_output=True,
        )
    except OSError as exc:
        # `cwd` does not exist → FileNotFoundError; `git` binary missing →
        # PermissionError or FileNotFoundError. Either way, no source range
        # can be validated, so this is malformed for the gate's purposes.
        raise MalformedInput(f"git cat-file failed: {exc}") from exc
    if proc.returncode != 0:
        # cat-file in a non-git directory exits 128 with `fatal: not a git
        # repository`; any other non-zero is also a hard error because the
        # H7 gate cannot enforce DA-line bounds without a trusted blob view.
        raise MalformedInput(
            f"git cat-file --batch exited {proc.returncode}: "
            f"{proc.stderr.decode('utf-8', 'replace')!r}"
        )
    out = proc.stdout
    counts: dict[str, int] = {}
    pos = 0
    for path in paths:
        nl = out.find(b"\n", pos)
        if nl < 0:
            raise MalformedInput(
                f"git cat-file output truncated before header for {path!r}"
            )
        header = out[pos:nl].decode("utf-8", "replace")
        pos = nl + 1
        # Missing entries print "<spec> missing\n" with no blob body.
        if header.endswith(" missing"):
            continue
        parts = header.split()
        # Expect exactly "<sha> blob <size>". `cat-file --batch` produces
        # exactly that format for a blob; eligibility has already restricted
        # us to .rs files, so a non-blob (e.g. a tree spec) is a malformed
        # input rather than something to skip. Raising here ensures the
        # subsequent body offset (pos += size + 1) cannot desync the loop.
        if len(parts) != 3 or parts[1] != "blob":
            raise MalformedInput(
                f"git cat-file: expected blob header for {path!r}, "
                f"got {header!r}"
            )
        # `parts[2]` is the size cat-file printed; it is always a non-negative
        # decimal integer for a blob, so an exception here would mean git's
        # output contract changed — fail closed.
        size = int(parts[2])
        blob = out[pos : pos + size]
        pos += size + 1  # the blob is followed by a trailing newline
        line_count = blob.count(b"\n")
        if blob and not blob.endswith(b"\n"):
            line_count += 1
        counts[path] = line_count
    return counts


# ---------------------------------------------------------------------------
# Diff acquisition
# ---------------------------------------------------------------------------


def get_diff_text(repo_root: Path, base: str, head: str) -> str:
    # core.quotePath=false so non-ASCII paths in `+++ b/...` headers are not
    # C-quoted (which the unified-diff parser would carry literally).
    try:
        return subprocess.check_output(
            [
                "git",
                "-c",
                "core.quotePath=false",
                "diff",
                "--unified=0",
                f"{base}...{head}",
                "--",
                "*.rs",
            ],
            cwd=repo_root,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise MalformedInput(f"git diff failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _trust_boundary_gate(
    file_results: list[FileResult], thresholds: Thresholds
) -> GateResult:
    """Compute the trust-boundary gate.

    A trust-boundary file fails when either:
      * it has changed lines but no LCOV records at all — the file was not
        instrumented, so the change cannot be shown to be covered, or
      * its instrumented changed lines (the lines llvm emitted DA records
        for) are below the 100% threshold.

    Changed lines that llvm did not instrument (braces, declarations,
    comments, blank lines) are not failures: the coverage build is the
    authority on which lines are executable. Target-`cfg`-gated code is
    handled by the per-target matrix in CI (linux+macos legs, merged by
    :func:`merge_lcov`); feature-`cfg`-gated code is handled by
    ``cargo hack --feature-powerset``, which instruments every feature
    combination. Both mechanisms are policed by ``TestPolicyAndCiInvariants``
    so a future addition cannot silently fall outside coverage.

    ``measured`` is the worst per-file changed-line percentage, or 0.0 when
    a file failed for lack of any records, so the value is a usable scalar.
    """

    passed = True
    details: list[str] = []
    worst: float | None = None
    for fr in file_results:
        if not fr.is_trust_boundary or fr.changed_total == 0:
            continue
        if not fr.has_lcov_records:
            passed = False
            worst = 0.0
            details.append(f"{fr.path}: no LCOV records for a changed trust-boundary file")
            continue
        if fr.changed_instrumented == 0:
            # Only non-instrumented (brace/decl/comment) lines changed.
            continue
        # changed_instrumented > 0 here, so fr.percent is never None.
        percent = fr.percent
        assert percent is not None
        if worst is None or percent < worst:
            worst = percent
        if percent < thresholds.trust_boundary_changed:
            passed = False
            details.append(
                f"{fr.path}: {percent:.2f}% < "
                f"{thresholds.trust_boundary_changed:.2f}% "
                f"(uncovered changed lines: {_short_list(fr.uncovered_lines)})"
            )
    if not details:
        details.append("no trust-boundary files changed or all fully covered")
    return GateResult(
        name="trust_boundary_changed",
        threshold=thresholds.trust_boundary_changed,
        measured=worst,
        passed=passed,
        detail="; ".join(details),
    )


def evaluate(
    lcov: dict[str, FileCoverage],
    diff: ChangedLines,
    policy: Policy,
    base_sha: str,
    head_sha: str,
    trust_boundary_files: set[str],
    tracked_rs_files: set[str],
    enforce_changed: bool,
    source_line_counts: dict[str, int] | None = None,
) -> Report:
    # Restrict the LCOV records to TRACKED Rust files at HEAD. A producer
    # that emits SF blocks for synthetic in-tree paths (e.g. ``SF:fake.rs``)
    # cannot inflate the reported percentage — the unknown path is dropped
    # before arithmetic. ``eligible_lcov`` is the authoritative LCOV view
    # for every downstream gate computation in this function.
    eligible_lcov = {p: fc for p, fc in lcov.items() if p in tracked_rs_files}
    dropped_synthetic = sorted(set(lcov) - set(eligible_lcov))
    # H7: reject DA coordinates that the immutable head_sha:path blob cannot
    # contain (line 0 is never valid; line > blob_line_count means the
    # producer fabricated a coordinate inside a tracked file). Done after
    # eligibility so we only spend git on paths whose data is going to
    # influence arithmetic. ``source_line_counts`` is None in test mode
    # (``--allow-head-drift``) where the head_sha is synthetic; callers MUST
    # pass it in production runs.
    if source_line_counts is not None:
        for path, fc in eligible_lcov.items():
            max_line = source_line_counts.get(path)
            if max_line is None:
                # Tracked at head but missing a blob count means the cat-file
                # batch did not return its size — refuse to gate against an
                # unknown source range rather than silently letting any DA
                # line through.
                raise MalformedInput(
                    f"source line count missing for tracked file {path!r}; "
                    "cannot validate DA coordinates against head blob"
                )
            invalid = sorted(
                ln for ln in fc.lines if ln < 1 or ln > max_line
            )
            if invalid:
                raise MalformedInput(
                    f"file {path!r}: DA line numbers {invalid} outside source "
                    f"range 1..{max_line} for head_sha {head_sha}"
                )
    # Overall is the **DA-coherent** metric: both numerator and denominator
    # come from the concrete DA records. Numerator = unique covered DA
    # lines; denominator = unique instrumented DA lines. This is one of the
    # two coherent representations the assignment accepts (the other being
    # ΣLH/ΣLF) and is chosen for non-inflatability: the producer cannot
    # contribute to the numerator without also emitting a visible DA line
    # in the denominator, so a high declared LH cannot lift the score past
    # what the DA records demonstrate. The declared LH would be inflatable
    # at the limit `DA:1,1; LF:N; LH:N` (passes the reconciliation bound
    # and yields N/N=100%); the DA-coherent metric pins the limit at 1/1
    # for that input, exactly what a single covered visible line shows.
    #
    # parse_lcov already enforces structural reconciliation against the
    # declared LF/LH (LH<=LF, LF>=unique DA, unseen_hits<=unseen_inst), so a
    # malformed-on-the-overclaim-side summary is still rejected; an LH below
    # the DA hit count is tolerated as a producer quirk and clamped up. The
    # arithmetic just doesn't depend on the summary values either way.
    total_lf = 0
    total_lh = 0
    for fc in eligible_lcov.values():
        total_lf += len(fc.lines)
        total_lh += len(fc.covered_lines())
    if total_lf == 0:
        # Zero eligible instrumented lines means the LCOV had no SF block for
        # any tracked Rust file: every block was either out-of-repo or
        # synthetic. A vacuous 100% would let a malicious or broken producer
        # pass the overall gate with no real coverage — raise so the
        # malformed-input path writes a failure artifact instead.
        raise MalformedInput(
            "no LCOV records match any tracked Rust file at head_sha "
            f"(dropped synthetic/out-of-repo SF paths: "
            f"{', '.join(dropped_synthetic) if dropped_synthetic else '<none>'})"
        )
    overall_percent = 100.0 * total_lh / total_lf
    overall_block = {
        # Honest key names: the denominator is the producer's declared
        # instrumented-line count (Σ LF); the numerator is the count of DA
        # lines demonstrated covered. They are deliberately NOT a declared
        # LF/LH pair, so the keys are named for what they hold.
        "instrumented_lines": total_lf,
        "covered_lines": total_lh,
        "percent": overall_percent,
        "dropped_synthetic_sf_paths": dropped_synthetic,
    }

    file_results: list[FileResult] = []
    rs_files = [f for f in diff.files() if f.endswith(RUST_EXT)]
    for path in sorted(rs_files):
        changed_lines = diff.by_file[path]
        fc = eligible_lcov.get(path)
        instrumented_for_file = fc.instrumented_lines() if fc else set()
        covered_for_file = fc.covered_lines() if fc else set()
        instrumented_changed = changed_lines & instrumented_for_file
        covered_changed = instrumented_changed & covered_for_file
        uncovered = instrumented_changed - covered_for_file
        # Lines llvm did not instrument (DA-absent): closing braces, struct
        # fields, comments, blank lines. Target-cfg and feature-cfg code
        # reach llvm via the matrix and the feature powerset respectively and
        # so are NOT in this bucket. We defer the "is this line executable"
        # judgment to llvm rather than re-deriving it from a hand-rolled lexer
        # (which was unsound in both directions). See the trust-boundary gate
        # below for how absence is treated.
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

        gates.append(_trust_boundary_gate(file_results, policy.thresholds))

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
        f"({report.overall['covered_lines']}/{report.overall['instrumented_lines']} lines)"
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
    parser.add_argument(
        "--lcov",
        required=True,
        nargs="+",
        metavar="LCOV",
        help=(
            "Path(s) to lcov.info. Pass one file for a single-target run, or "
            "several (one per target OS/arch from the coverage matrix) to merge "
            "them: a line is instrumented if any target instrumented it and "
            "covered if any target covered it. Merging is how inactive-target "
            "cfg code reaches the trust-boundary gate."
        ),
    )
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
            "as the universe for trust-boundary glob matching and coverage "
            "eligibility. When omitted, the tool reads the immutable tree at "
            "--head-sha via 'git ls-tree -r <head_sha>' inside --repo-root (NOT "
            "the mutable index), filtering for '.rs'."
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
    parser.add_argument(
        "--allow-head-drift",
        action="store_true",
        help=(
            "Skip the `git rev-parse HEAD == --head-sha` startup check. CI must "
            "never set this — the worktree drift it covers is exactly the "
            "scenario the check exists to catch. Tests pass this flag because "
            "their fixture trees are not git repositories."
        ),
    )
    args = parser.parse_args(argv)

    def fail_malformed(detail: str) -> int:
        """Emit failure JSON and Markdown to the configured paths and exit 2.

        The artifact upload step in CI uses ``if: always()``, so the LCOV
        upload reaches the artifact even on a malformed-input exit. Without
        this helper, ``result.json`` and ``result.md`` would be absent from
        that artifact, leaving reviewers no exact-SHA structured diagnostic.

        The JSON payload mirrors :meth:`Report.to_json`'s top-level keys so
        downstream consumers (badge generators, PR-comment renderers) can
        read ``payload["overall"]``, ``payload["gates"]``, etc. without
        ``KeyError`` on a malformed run. Success-path numeric fields are
        ``null``; the failure-specific fields ``status`` and ``detail``
        identify the cause.
        """

        print(f"error: {detail}", file=sys.stderr)
        payload = {
            "tool_version": VERSION,
            "policy_version": None,
            "base_sha": args.base_sha,
            "head_sha": args.head_sha,
            "thresholds": None,
            "overall": None,
            "aggregate_changed": None,
            "files": [],
            "gates": [],
            "passed": False,
            "status": "malformed_input",
            "detail": detail,
        }
        md = (
            f"# Coverage report — MALFORMED INPUT\n\n"
            f"- tool version: `{VERSION}`\n"
            f"- base sha: `{args.base_sha}`\n"
            f"- head sha: `{args.head_sha}`\n\n"
            f"Checker exited 2 before computing gates.\n\n"
            f"**Detail:** {detail}\n"
        )
        try:
            if args.json_out:
                Path(args.json_out).write_text(
                    json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            if args.markdown_out:
                Path(args.markdown_out).write_text(md, encoding="utf-8")
        except OSError as write_err:
            print(
                f"warning: could not write failure artifact: {write_err}",
                file=sys.stderr,
            )
        return EXIT_MALFORMED

    repo_root = Path(args.repo_root).resolve()
    if not args.allow_head_drift:
        try:
            current_head = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo_root, text=True
            ).strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            return fail_malformed(
                f"cannot read repo HEAD ({exc}); pass --allow-head-drift to skip"
            )
        if current_head != args.head_sha:
            return fail_malformed(
                f"worktree HEAD ({current_head}) != --head-sha ({args.head_sha}); "
                "classification would read the wrong tree"
            )
    lcov_maps: list[dict[str, FileCoverage]] = []
    for lcov_path in args.lcov:
        try:
            lcov_text = Path(lcov_path).read_text(encoding="utf-8")
        except OSError as exc:
            return fail_malformed(f"cannot read lcov {lcov_path}: {exc}")
        try:
            lcov_maps.append(parse_lcov(lcov_text, repo_root))
        except MalformedInput as exc:
            return fail_malformed(f"malformed lcov {lcov_path}: {exc}")
    lcov = merge_lcov(lcov_maps)

    try:
        policy = load_policy(Path(args.policy))
    except InvalidPolicy as exc:
        return fail_malformed(f"invalid policy: {exc}")

    if args.diff is not None:
        try:
            diff_text = Path(args.diff).read_text(encoding="utf-8")
        except OSError as exc:
            return fail_malformed(f"cannot read diff: {exc}")
    else:
        try:
            diff_text = get_diff_text(repo_root, args.base_sha, args.head_sha)
        except MalformedInput as exc:
            return fail_malformed(str(exc))

    try:
        diff = parse_unified_diff(diff_text)
    except MalformedInput as exc:
        return fail_malformed(f"malformed diff: {exc}")

    if args.repo_files is not None:
        try:
            repo_files = [
                line.strip()
                for line in Path(args.repo_files).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except OSError as exc:
            return fail_malformed(f"cannot read repo-files: {exc}")
    else:
        try:
            repo_files = list_tracked_rs_files(repo_root, args.head_sha)
        except MalformedInput as exc:
            return fail_malformed(str(exc))

    matched, by_pattern = expand_trust_boundary_files(policy, repo_files)
    unmatched = sorted(p for p, hits in by_pattern.items() if not hits)
    if unmatched:
        return fail_malformed(
            "trust-boundary patterns matched no current files: " + ", ".join(unmatched)
        )

    tracked_rs_set = {f for f in repo_files if f.endswith(RUST_EXT)}
    try:
        # H7: compute the immutable per-file line count for every eligible
        # LCOV path so `evaluate` can reject DA coordinates beyond the
        # source. ``--allow-head-drift`` (tests) means the head_sha is
        # synthetic and cat-file would error; suppress the check there.
        if args.allow_head_drift:
            source_line_counts: dict[str, int] | None = None
        else:
            eligible_paths = sorted(p for p in lcov.keys() if p in tracked_rs_set)
            source_line_counts = get_source_line_counts(
                repo_root, args.head_sha, eligible_paths
            )
        report = evaluate(
            lcov=lcov,
            diff=diff,
            policy=policy,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            trust_boundary_files=matched,
            tracked_rs_files=tracked_rs_set,
            enforce_changed=args.mode == "pr",
            source_line_counts=source_line_counts,
        )
    except MalformedInput as exc:
        return fail_malformed(f"malformed lcov: {exc}")

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
