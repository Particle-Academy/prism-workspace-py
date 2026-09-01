"""Fire the whole escape corpus at a REAL workspace and report what happened.

    from prism_workspace.corpus import CorpusRunner

    report = CorpusRunner().against(workspace)
    if not report.passed():
        raise RuntimeError(report.summary())

This is the module that makes the package's central claim checkable by someone
who does not trust it. Our CI proves the boundary holds on OUR disk; yours might
use a different root, a network share, a case-insensitive volume -- and a
security property is only true of the configuration it was measured on. So the
corpus ships, and you can measure yours.

It is safe to run against a live workspace: every attempt is expected to be
refused, so a passing run writes nothing at all. The marker is per-run and
random, so a stray found afterwards is unambiguously from THIS run.

## Two checks, not one

Every attempt must be refused with the code the corpus names -- and then the
directories AROUND the workspace are swept for the marker. The second catches
what the first cannot: a guard that refuses everything correctly, paired with a
workspace root assembled wrongly, passes every unit test in this package and
still writes into the wrong place.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass, field
from enum import Enum
from importlib.resources import files
from pathlib import Path
from typing import Any, TypedDict, cast

from prism_workspace import PathRefused, SyncWorkspace

__all__ = [
    "CorpusOutcome",
    "CorpusReport",
    "CorpusResult",
    "CorpusRunner",
    "EscapeAttempt",
    "corpus_version",
    "escape_corpus",
]

#: How many levels above the workspace to sweep.
SWEEP_LEVELS = 3

#: A ceiling, so sweeping a large disk cannot become the slowest thing in a suite.
SWEEP_FILE_LIMIT = 20000


class CorpusOutcome(str, Enum):
    #: Refused, with the code the corpus names. The only passing outcome.
    REFUSED = "refused"
    #: Refused, but as something else. A FAILURE, not a warning -- which refusal
    #: fires is what a consumer alerts on, and "an agent tried to leave its
    #: workspace" and "the name has a trailing dot" are different pages in the
    #: middle of the night.
    WRONG_CODE = "wrong-code"
    #: Accepted. The boundary did not hold.
    ACCEPTED = "accepted"
    #: Something else went wrong, which is not a pass either.
    ERRORED = "errored"


class EscapeAttempt(TypedDict):
    id: str
    path_base64: str
    hazard: str
    refusal: str


@dataclass(frozen=True)
class CorpusResult:
    attempt: EscapeAttempt
    outcome: CorpusOutcome
    refusal: str | None
    detail: str

    def passed(self) -> bool:
        return self.outcome is CorpusOutcome.REFUSED

    def describe(self) -> str:
        return f"{self.attempt['id']} ({self.attempt['hazard']}): {self.detail}"


_document = cast(
    dict[str, Any],
    json.loads(
        files("prism_workspace.security").joinpath("escape-corpus.json").read_text(encoding="utf-8")
    ),
)

#: The shipped corpus: 134 adversarial paths across twelve hazard classes.
escape_corpus: list[EscapeAttempt] = cast(list[EscapeAttempt], _document["cases"])
corpus_version: str = cast(str, _document["corpus_version"])


@dataclass(frozen=True)
class CorpusReport:
    results: list[CorpusResult]
    #: Files found OUTSIDE the workspace carrying this run's marker. Empty is
    #: the only acceptable answer.
    strays: list[str]
    #: Whether the surrounding directories could be swept at all.
    swept: bool
    #: Whether the sweep reached the END of the surrounding tree.
    #:
    #: False means it hit the file ceiling and stopped early, so ``strays`` is
    #: "nothing found in the part I looked at" rather than "nothing escaped".
    #: The reference does not carry this flag and reports a truncated sweep as a
    #: clean one -- a security check that silently half-runs and then says it
    #: passed. Recorded in the port gaps register as a divergence the reference
    #: should adopt.
    sweep_complete: bool = True
    corpus_version: str = field(default=corpus_version)

    def passed(self) -> bool:
        """Both halves have to hold, and the sweep has to have FINISHED.

        A truncated sweep is not a pass: the half of the check that would catch
        a wrongly assembled root never ran to completion.
        """
        return not self.failures() and not self.strays and self.sweep_complete

    def failures(self) -> list[CorpusResult]:
        return [result for result in self.results if not result.passed()]

    def summary(self) -> str:
        failures = self.failures()
        headline = (
            f"prism-workspace escape corpus v{self.corpus_version}: "
            f"{len(self.results)} attempts, {len(self.results) - len(failures)} refused "
            f"correctly, {len(failures)} failed."
        )
        lines = [
            headline,
            f"Swept the surrounding directories: {len(self.strays)} stray file(s)."
            if self.swept
            else "Surrounding directories NOT swept -- containment checked by refusal only.",
        ]

        if not self.sweep_complete:
            lines.append(
                f"  SWEEP INCOMPLETE: stopped at the {SWEEP_FILE_LIMIT}-file ceiling, so "
                '"no strays" means "none in the part that was searched". Place the workspace '
                "somewhere with a smaller surrounding tree, or treat the containment half as "
                "unverified."
            )

        lines.extend(f"  {failure.describe()}" for failure in failures)
        lines.extend(f"  ESCAPED THE WORKSPACE: {stray}" for stray in self.strays)

        return "\n".join(lines)


class CorpusRunner:
    def against(self, workspace: SyncWorkspace, marker: str | None = None) -> CorpusReport:
        """Fire every case at ``workspace``.

        :param marker: Override the per-run marker. For testing the RUNNER
            itself -- planting a known marker outside the workspace is the only
            way to prove the sweep can find one, and a sweep that has never
            found anything is not a check, it is a habit.
        """
        token = marker or f"prism-workspace-escape-marker-{secrets.token_hex(16)}"
        results = [self._attempt(workspace, attempt, token) for attempt in escape_corpus]
        strays, complete = self._sweep(Path(workspace.root), token)

        return CorpusReport(results=results, strays=strays, swept=True, sweep_complete=complete)

    def _attempt(
        self, workspace: SyncWorkspace, attempt: EscapeAttempt, marker: str
    ) -> CorpusResult:
        try:
            # The RAW BYTES, not decoded text. Several corpus cases are invalid
            # UTF-8 on purpose, and decoding them first would quietly test a
            # different path than the one the case names.
            workspace.write(base64.b64decode(attempt["path_base64"]), marker)
        except PathRefused as refused:
            if refused.code.value == attempt["refusal"]:
                return CorpusResult(
                    attempt, CorpusOutcome.REFUSED, refused.code.value, "refused as expected"
                )
            return CorpusResult(
                attempt,
                CorpusOutcome.WRONG_CODE,
                refused.code.value,
                f"refused as [{refused.code.value}], expected [{attempt['refusal']}]",
            )
        except Exception as error:  # noqa: BLE001 - any other failure is not a pass
            # Something failed for a reason the boundary did not choose, which
            # means the boundary was not what stopped it -- and on a differently
            # configured disk it might not stop it at all.
            return CorpusResult(
                attempt,
                CorpusOutcome.ERRORED,
                None,
                f"threw {type(error).__name__}: {error}",
            )

        return CorpusResult(
            attempt,
            CorpusOutcome.ACCEPTED,
            None,
            f"was ACCEPTED; expected refusal [{attempt['refusal']}]",
        )

    def _sweep(self, root: Path, marker: str) -> tuple[list[str], bool]:
        top = root
        for _ in range(SWEEP_LEVELS):
            if top.parent == top:
                break
            top = top.parent

        strays: list[str] = []
        length = len(marker.encode("utf-8"))
        seen = 0
        truncated = False

        stack = [top]
        while stack:
            directory = stack.pop()
            try:
                entries = list(directory.iterdir())
            except OSError:
                # A directory we cannot read is not evidence of an escape, and a
                # sweep that raised would turn an unreadable sibling into a
                # failed security check.
                continue

            for entry in entries:
                seen += 1
                if seen > SWEEP_FILE_LIMIT:
                    truncated = True
                    return strays, False

                try:
                    if entry.is_dir():
                        if not entry.is_symlink():
                            stack.append(entry)
                        continue
                    if not entry.is_file():
                        continue
                    # The marker is the WHOLE content of anything an attempt
                    # wrote, so anything the wrong size cannot be one. That check
                    # is what keeps this from reading an entire storage tree.
                    if entry.stat().st_size != length:
                        continue
                    if entry.read_text(encoding="utf-8", errors="replace") == marker:
                        strays.append(str(entry))
                except OSError:
                    continue

        return strays, not truncated
