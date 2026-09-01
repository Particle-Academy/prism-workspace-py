"""The corpus fired at a REAL workspace. Mirrors prism-workspace-ts/test/corpus-runner.test.ts."""

from __future__ import annotations

import tempfile
from pathlib import Path

from prism_workspace import SyncWorkspace
from prism_workspace.corpus import (
    CorpusOutcome,
    CorpusReport,
    CorpusResult,
    CorpusRunner,
    corpus_version,
)


def a_workspace() -> SyncWorkspace:
    """A workspace nested deep enough that the sweep's three levels stay inside our own temp dir.

    NOT incidental. Placing a workspace directly in the system temp directory
    puts the user profile three levels up, and the sweep then hits its file
    ceiling long before it reaches anything a test planted -- reporting a clean
    run because it gave up, not because nothing escaped. That is the failure
    ``sweep_complete`` now surfaces, and it is a real deployment caveat rather
    than a test artefact.
    """
    top = Path(tempfile.mkdtemp(prefix="prism-workspace-py-corpus-"))
    base = top / "one" / "two"
    base.mkdir(parents=True, exist_ok=True)
    workspace = SyncWorkspace(base, "agent-1")
    workspace.write("seed.txt", "seed")
    return workspace


def test_fires_the_whole_shipped_corpus_at_a_real_workspace_and_passes() -> None:
    # This is the claim the package exists to make checkable by someone who does
    # not trust it. Until now the corpus only ever ran against the bare PathGuard
    # -- never against a workspace on a real disk, which is where a wrongly
    # assembled root would show up.
    report = CorpusRunner().against(a_workspace())

    assert len(report.results) == 134
    assert report.failures() == []
    assert report.strays == []
    assert report.passed() is True


def test_reports_the_corpus_version_it_ran() -> None:
    report = CorpusRunner().against(a_workspace())

    assert report.corpus_version == corpus_version
    assert "134 attempts" in report.summary()


def test_finds_a_planted_stray_so_the_sweep_is_a_check_and_not_a_habit() -> None:
    # A sweep that has never found anything proves nothing. Planting a known
    # marker outside the workspace is the only way to show it can find one --
    # which is exactly why `against()` takes a marker override.
    workspace = a_workspace()
    marker = "prism-workspace-escape-marker-planted-for-this-test"
    (Path(workspace.root).parent / "planted.txt").write_text(marker, encoding="utf-8")

    report = CorpusRunner().against(workspace, marker)

    assert report.strays
    assert any(stray.endswith("planted.txt") for stray in report.strays)
    assert report.passed() is False
    assert "ESCAPED THE WORKSPACE" in report.summary()


def test_a_wrong_refusal_code_fails_the_report() -> None:
    # Which refusal fires is what a consumer alerts on, so a wrong code is a
    # failure rather than a warning.
    report = CorpusRunner().against(a_workspace())
    wrong_coded = CorpusResult(
        report.results[0].attempt,
        CorpusOutcome.WRONG_CODE,
        "path_is_empty",
        "refused as [path_is_empty], expected [path_traverses_outside_workspace]",
    )
    mutated = CorpusReport(results=[wrong_coded], strays=[], swept=True)

    assert mutated.passed() is False
    assert len(mutated.failures()) == 1


def test_an_incomplete_sweep_is_not_a_pass() -> None:
    # A security check that gave up early must not report success. The reference
    # reports the truncated sweep as a clean one; both ports refuse to.
    report = CorpusReport(results=[], strays=[], swept=True, sweep_complete=False)

    assert report.passed() is False
    assert "SWEEP INCOMPLETE" in report.summary()
