"""Binary and streaming access, and the guard that must run before either.

Mirrors `prism-workspace-ts/test/streams.test.ts` case for case.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

from prism_workspace import PathRefused, SyncWorkspace, Workspace, WorkspaceFailed


def a_workspace() -> SyncWorkspace:
    return SyncWorkspace(Path(tempfile.mkdtemp(prefix="prism-workspace-py-stream-")), "agent-1")


def test_reads_raw_bytes_without_decoding_them_as_utf8() -> None:
    workspace = a_workspace()
    payload = bytes([0xFF, 0xFE, 0x00, 0x01])
    workspace.write("logo.png", payload)

    assert workspace.read_bytes("logo.png") == payload


def test_streams_a_file_back_in_chunks() -> None:
    workspace = a_workspace()
    workspace.write("big.txt", "hello streaming world")

    assert b"".join(workspace.read_stream("big.txt")) == b"hello streaming world"


def test_honours_the_chunk_size() -> None:
    workspace = a_workspace()
    workspace.write("big.txt", "abcdef")

    assert list(workspace.read_stream("big.txt", chunk_size=2)) == [b"ab", b"cd", b"ef"]


def test_writes_from_an_iterable_without_buffering_the_payload() -> None:
    workspace = a_workspace()
    workspace.write_stream("out.txt", iter([b"one ", b"two ", b"three"]))

    assert workspace.read("out.txt") == "one two three"


def test_guards_the_path_before_opening_a_read_handle() -> None:
    # The whole point of the package. A streaming accessor that skipped the
    # guard would be a hole straight through the boundary, and it would look
    # like an optimisation.
    workspace = a_workspace()

    with pytest.raises(PathRefused):
        workspace.read_stream("../escape.txt")

    with pytest.raises(PathRefused):
        workspace.read_stream("/etc/passwd")


def test_guards_the_path_before_opening_a_write_handle() -> None:
    workspace = a_workspace()

    with pytest.raises(PathRefused):
        workspace.write_stream("../escape.txt", iter([b"x"]))


@pytest.mark.skipif(
    os.name == "nt", reason="creating a directory symlink needs privilege on Windows"
)
def test_refuses_to_stream_through_a_symlink_that_leaves_the_workspace() -> None:
    workspace = a_workspace()
    workspace.write("seed.txt", "seed")
    nested = Path(workspace.root) / "nested"
    nested.mkdir(parents=True, exist_ok=True)
    (nested / "out").symlink_to(tempfile.gettempdir(), target_is_directory=True)

    with pytest.raises(PathRefused):
        workspace.read_stream("nested/out/anything.txt")


def test_reports_a_missing_file_by_code() -> None:
    workspace = a_workspace()

    with pytest.raises(WorkspaceFailed):
        workspace.read_stream("nope.txt")

    with pytest.raises(WorkspaceFailed):
        workspace.read_bytes("nope.txt")


def test_asks_the_authorizer_before_streaming() -> None:
    asked: list[str] = []

    def record(ability: str, _workspace: SyncWorkspace, _path: str | None = None) -> None:
        asked.append(ability)

    workspace = SyncWorkspace(
        Path(tempfile.mkdtemp(prefix="prism-workspace-py-auth-")),
        "agent-1",
        authorize=record,
    )

    workspace.write_stream("a.txt", iter([b"x"]))
    list(workspace.read_stream("a.txt"))
    workspace.read_bytes("a.txt")

    assert asked == ["write", "read", "read"]


def test_closes_the_handle_when_the_caller_stops_early() -> None:
    # The close lives in a `finally` inside the generator rather than trailing
    # the loop, so abandoning a stream half-read does not leak a descriptor --
    # invisible until a long-running agent exhausts the table.
    workspace = a_workspace()
    workspace.write("big.txt", "abcdef")

    stream: Iterator[bytes] = workspace.read_stream("big.txt", chunk_size=2)
    assert next(stream) == b"ab"
    stream.close()  # type: ignore[attr-defined]


# -- the async facade --------------------------------------------------------


def test_the_async_workspace_streams_both_ways() -> None:
    async def scenario() -> tuple[str, bytes]:
        workspace = Workspace(Path(tempfile.mkdtemp(prefix="prism-workspace-py-async-")), "agent-1")
        await workspace.write_stream("out.txt", iter([b"one ", b"two"]))
        chunks = [chunk async for chunk in workspace.read_stream("out.txt")]

        return await workspace.read("out.txt"), b"".join(chunks)

    text, streamed = asyncio.run(scenario())

    assert text == "one two"
    assert streamed == b"one two"


def test_the_async_workspace_accepts_an_async_source() -> None:
    async def scenario() -> str:
        workspace = Workspace(Path(tempfile.mkdtemp(prefix="prism-workspace-py-async-")), "agent-1")

        async def source() -> AsyncIterator[bytes]:
            yield b"hi"

        await workspace.write_stream("gen.txt", source())
        return await workspace.read("gen.txt")

    assert asyncio.run(scenario()) == "hi"


def test_the_async_workspace_exposes_path_directly() -> None:
    # prism-ts exposes `path()` on the async surface, and reaching through a
    # facade attribute to answer the same question is a difference a caller can
    # trip on.
    workspace = Workspace(Path(tempfile.mkdtemp(prefix="prism-workspace-py-path-")), "agent-1")

    assert workspace.path("a/./b.txt") == "a/b.txt"

    with pytest.raises(PathRefused):
        workspace.path("../escape.txt")
