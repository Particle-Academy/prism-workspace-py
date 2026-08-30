import asyncio
from pathlib import Path

import pytest

from prism_workspace import PathRefused, Refusal, SyncWorkspace, Workspace, workspace_address


def test_stable_address() -> None:
    assert workspace_address("session:ABC:one") == "session-abc-one-ad223950606ee044"


def test_sync_workspace_operations(tmp_path: Path) -> None:
    workspace = SyncWorkspace(tmp_path, "agent-1")
    workspace.write("reports/q1.md", "one").append("reports/q1.md", " two")
    assert workspace.read("reports/q1.md") == "one two"
    assert workspace.size("reports/q1.md") == 7
    workspace.copy("reports/q1.md", "reports/copy.md").move("reports/copy.md", "final.md")
    assert {entry.path for entry in workspace.list()} >= {"reports", "reports/q1.md", "final.md"}
    workspace.delete("final.md")
    assert not workspace.exists("final.md")


def test_async_workspace_is_primary_api(tmp_path: Path) -> None:
    async def exercise() -> None:
        workspace = Workspace(tmp_path, "async-agent")
        await workspace.write("notes.md", "hello")
        assert await workspace.read("notes.md") == "hello"
        assert [entry.path async for entry in workspace.list()] == ["notes.md"]

    asyncio.run(exercise())


def test_refuses_read_and_write_through_external_symlink(tmp_path: Path) -> None:
    base = tmp_path / "base"
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace = SyncWorkspace(base, "linked")
    workspace.write("seed.txt", "x")
    try:
        (workspace.root / "reports").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("platform does not permit symlink creation")
    with pytest.raises(PathRefused) as read_error:
        workspace.read("reports/secret.txt")
    assert read_error.value.code is Refusal.ESCAPES_VIA_LINK
    with pytest.raises(PathRefused) as write_error:
        workspace.write("reports/planted.txt", "planted")
    assert write_error.value.code is Refusal.ESCAPES_VIA_LINK
    assert not (outside / "planted.txt").exists()


def test_allows_symlink_that_stays_inside_workspace(tmp_path: Path) -> None:
    workspace = SyncWorkspace(tmp_path, "linked-inside")
    workspace.write("real/notes.md", "inside")
    try:
        (workspace.root / "shortcut").symlink_to(workspace.root / "real", target_is_directory=True)
    except OSError:
        pytest.skip("platform does not permit symlink creation")
    assert workspace.read("shortcut/notes.md") == "inside"
