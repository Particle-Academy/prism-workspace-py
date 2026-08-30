from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, TypeAlias


class Refusal(str, Enum):
    TRAVERSAL = "path_traverses_outside_workspace"
    ABSOLUTE = "path_is_absolute"
    UNC = "path_is_unc_or_device_namespace"
    NULL_BYTE = "path_contains_null_byte"
    CONTROL_CHARACTER = "path_contains_control_character"
    INVISIBLE_CHARACTER = "path_contains_invisible_character"
    SEPARATOR_HOMOGLYPH = "path_contains_separator_homoglyph"
    INVALID_ENCODING = "path_is_not_valid_utf8"
    ENCODED_SEPARATOR = "path_contains_encoded_separator"
    ALTERNATE_DATA_STREAM = "path_contains_alternate_data_stream"
    RESERVED_DEVICE_NAME = "path_is_reserved_device_name"
    EDGE_DOT_OR_SPACE = "path_has_edge_dot_or_space"
    SHORT_NAME_ALIAS = "path_uses_short_name_alias"
    HOME_EXPANSION = "path_uses_home_expansion"
    EMPTY_PATH = "path_is_empty"
    TOO_LONG = "path_too_long"
    SEGMENT_TOO_LONG = "path_segment_too_long"
    ESCAPES_VIA_LINK = "path_escapes_workspace_via_link"


class PathRefused(ValueError):
    def __init__(self, code: Refusal, path: str | bytes) -> None:
        self.code = code
        self.path = path
        super().__init__(f"Workspace path refused ({code.value}).")


_DEVICES = {
    "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$",
    *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10)),
    "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
}
_INVISIBLE = re.compile("[\\u00ad\\u061c\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]")
_HOMOGLYPH = re.compile("[\\u2044\\u2215\\u29f5\\u29f8\\ufe68\\uff0f\\uff3c]")
_ENCODED = re.compile(
    r"%(?:00|25|2e|2f|5c|[89a-f][0-9a-f])|%u[0-9a-f]{4}", re.IGNORECASE
)
_SHORT_ALIAS = re.compile(r"^[^./]{1,6}~[0-9]{1,4}(?:\.[^./]{1,3})?$")
_HOME = re.compile(r"^~[\w.-]*$")


class PathGuard:
    """Pure lexical path guard; filesystem/symlink containment is a separate boundary."""

    def __init__(self, max_path_bytes: int = 1024, max_segment_bytes: int = 255) -> None:
        self.max_path_bytes = max_path_bytes
        self.max_segment_bytes = max_segment_bytes

    def guard(self, path: str | bytes) -> str:
        if path in ("", b""): self._refuse(Refusal.EMPTY_PATH, path)
        if isinstance(path, bytes):
            if len(path) > self.max_path_bytes: self._refuse(Refusal.TOO_LONG, path)
            if b"\0" in path: self._refuse(Refusal.NULL_BYTE, path)
            try: text = path.decode("utf-8")
            except UnicodeDecodeError: self._refuse(Refusal.INVALID_ENCODING, path)
        else:
            text = path
        # Preserve PHP's contract order: the byte budget is checked before
        # invalid UTF-8. surrogatepass gives Python's otherwise-unencodable
        # code points a deterministic byte count without admitting them.
        measured_path = text.encode("utf-8", errors="surrogatepass")
        if len(measured_path) > self.max_path_bytes: self._refuse(Refusal.TOO_LONG, text)
        if "\0" in text: self._refuse(Refusal.NULL_BYTE, text)
        try: text.encode("utf-8")
        except UnicodeEncodeError: self._refuse(Refusal.INVALID_ENCODING, text)
        if _INVISIBLE.search(text): self._refuse(Refusal.INVISIBLE_CHARACTER, text)
        if _HOMOGLYPH.search(text): self._refuse(Refusal.SEPARATOR_HOMOGLYPH, text)
        if any(0 < ord(char) < 32 or ord(char) == 127 for char in text):
            self._refuse(Refusal.CONTROL_CHARACTER, text)
        if _ENCODED.search(text): self._refuse(Refusal.ENCODED_SEPARATOR, text)
        if text.startswith(("\\\\", "//")): self._refuse(Refusal.UNC, text)
        if re.match(r"^[A-Za-z]:", text): self._refuse(Refusal.ABSOLUTE, text)
        folded = text.replace("\\", "/")
        if folded.startswith("/"): self._refuse(Refusal.ABSOLUTE, text)
        kept: list[str] = []
        for segment in folded.split("/"):
            if segment in ("", "."): continue
            self._guard_segment(text, segment, not kept)
            kept.append(segment)
        if not kept: self._refuse(Refusal.EMPTY_PATH, text)
        return "/".join(kept)

    def _guard_segment(self, path: str, segment: str, leading: bool) -> None:
        if segment.startswith(".."): self._refuse(Refusal.TRAVERSAL, path)
        if ":" in segment: self._refuse(Refusal.ALTERNATE_DATA_STREAM, path)
        if segment.endswith((".", " ")) or segment.startswith(" "):
            self._refuse(Refusal.EDGE_DOT_OR_SPACE, path)
        if leading and _HOME.match(segment): self._refuse(Refusal.HOME_EXPANSION, path)
        if _SHORT_ALIAS.match(segment): self._refuse(Refusal.SHORT_NAME_ALIAS, path)
        if segment.split(".", 1)[0].upper() in _DEVICES:
            self._refuse(Refusal.RESERVED_DEVICE_NAME, path)
        if len(segment.encode("utf-8")) > self.max_segment_bytes:
            self._refuse(Refusal.SEGMENT_TOO_LONG, path)

    @staticmethod
    def _refuse(code: Refusal, path: str | bytes) -> None:
        raise PathRefused(code, path)


class Fault(str, Enum):
    FILE_MISSING = "workspace_file_missing"
    WRITE_FAILED = "workspace_write_failed"
    DELETE_FAILED = "workspace_delete_failed"
    OWNER_NOT_ADDRESSABLE = "workspace_owner_not_addressable"


class WorkspaceFailed(RuntimeError):
    def __init__(self, fault: Fault, message: str) -> None:
        self.fault = fault
        super().__init__(message)


class WorkspaceOwner(Protocol):
    def workspace_key(self) -> str: ...


class KeyedOwner(Protocol):
    def key(self) -> str: ...


WorkspaceIdentity: TypeAlias = str | WorkspaceOwner | KeyedOwner


def workspace_address(owner: WorkspaceIdentity, guard: PathGuard | None = None) -> str:
    if isinstance(owner, str):
        key = owner
    elif hasattr(owner, "workspace_key"):
        key = owner.workspace_key()
    else:
        key = owner.key()
    if not key:
        raise WorkspaceFailed(Fault.OWNER_NOT_ADDRESSABLE, "Workspace owner key cannot be empty.")
    slug = re.sub(r"[^A-Za-z0-9]+", "-", key).lower().strip("-")[:48].rstrip("-") or "w"
    digest = hashlib.sha256(key.encode()).hexdigest()[:16]
    return (guard or PathGuard()).guard(f"{slug}-{digest}")


class LocalBoundary:
    """Filesystem half of containment. Input must already be lexically guarded."""

    def __init__(self, root: Path, windows_max_path: int | None = 259) -> None:
        if not root.is_absolute():
            raise ValueError("LocalBoundary root must be absolute.")
        self.root = root
        self.windows_max_path = windows_max_path

    def admit(self, relative_path: str) -> None:
        target = self.root.joinpath(*relative_path.split("/"))
        if (
            os.name == "nt"
            and self.windows_max_path is not None
            and len(str(target)) > self.windows_max_path
        ):
            raise PathRefused(Refusal.TOO_LONG, relative_path)
        if not self.root.exists():
            return
        root = self.root.resolve(strict=True)
        candidate = target
        for _ in range(64):
            try:
                resolved = candidate.resolve(strict=True)
            except (FileNotFoundError, NotADirectoryError):
                parent = candidate.parent
                if parent == candidate or not self._lexically_within(parent):
                    return
                candidate = parent
                continue
            if not self._within(root, resolved):
                raise PathRefused(Refusal.ESCAPES_VIA_LINK, relative_path)
            return

    def _lexically_within(self, candidate: Path) -> bool:
        try:
            candidate.relative_to(self.root)
            return True
        except ValueError:
            return candidate == self.root

    @staticmethod
    def _within(root: Path, candidate: Path) -> bool:
        try:
            return os.path.commonpath((os.path.normcase(root), os.path.normcase(candidate))) == os.path.normcase(root)
        except ValueError:
            return False


@dataclass(frozen=True, slots=True)
class WorkspaceEntry:
    path: str
    is_directory: bool
    size: int | None = None
    last_modified: int | None = None

    @property
    def is_file(self) -> bool:
        return not self.is_directory

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


Ability: TypeAlias = str
Authorizer: TypeAlias = Callable[[Ability, "SyncWorkspace", str | None], None]


class SyncWorkspace:
    """Blocking facade. Prefer :class:`Workspace` in async applications."""

    def __init__(
        self,
        base_directory: str | Path,
        owner: WorkspaceIdentity,
        *,
        guard: PathGuard | None = None,
        authorize: Authorizer | None = None,
        windows_max_path: int | None = 259,
    ) -> None:
        self.guard = guard or PathGuard()
        self.address = workspace_address(owner, self.guard)
        self.root = Path(base_directory).absolute() / self.address
        self.boundary = LocalBoundary(self.root, windows_max_path)
        self.authorize = authorize

    def path(self, path: str) -> str:
        return self.guard.guard(path)

    def exists(self, path: str) -> bool:
        return self._absolute(self._admit(path, "read")).exists()

    def read(self, path: str) -> str:
        try:
            return self._absolute(self._admit(path, "read")).read_text(encoding="utf-8")
        except FileNotFoundError as error:
            raise WorkspaceFailed(Fault.FILE_MISSING, f"There is no [{path}] in this workspace.") from error

    def read_bytes(self, path: str) -> bytes:
        try:
            return self._absolute(self._admit(path, "read")).read_bytes()
        except FileNotFoundError as error:
            raise WorkspaceFailed(Fault.FILE_MISSING, f"There is no [{path}] in this workspace.") from error

    def write(self, path: str, contents: str | bytes) -> SyncWorkspace:
        target = self._absolute(self._admit(path, "write"))
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(contents, str): target.write_text(contents, encoding="utf-8")
            else: target.write_bytes(contents)
            return self
        except OSError as error:
            raise WorkspaceFailed(Fault.WRITE_FAILED, f"Could not write [{path}].") from error

    def append(self, path: str, contents: str) -> SyncWorkspace:
        target = self._absolute(self._admit(path, "write"))
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("a", encoding="utf-8") as stream: stream.write(contents)
            return self
        except OSError as error:
            raise WorkspaceFailed(Fault.WRITE_FAILED, f"Could not append [{path}].") from error

    def copy(self, source: str, destination: str) -> SyncWorkspace:
        source_path = self._absolute(self._admit(source, "read"))
        destination_path = self._absolute(self._admit(destination, "write"))
        try:
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, destination_path)
            return self
        except OSError as error:
            raise WorkspaceFailed(Fault.WRITE_FAILED, f"Could not copy [{source}] to [{destination}].") from error

    def move(self, source: str, destination: str) -> SyncWorkspace:
        source_path = self._absolute(self._admit(source, "write"))
        destination_path = self._absolute(self._admit(destination, "write"))
        try:
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.replace(destination_path)
            return self
        except OSError as error:
            raise WorkspaceFailed(Fault.WRITE_FAILED, f"Could not move [{source}] to [{destination}].") from error

    def delete(self, path: str) -> SyncWorkspace:
        target = self._absolute(self._admit(path, "delete"))
        try:
            target.unlink(missing_ok=True)
            return self
        except OSError as error:
            raise WorkspaceFailed(Fault.DELETE_FAILED, f"Could not delete [{path}].") from error

    def make_directory(self, path: str) -> SyncWorkspace:
        try:
            self._absolute(self._admit(path, "write")).mkdir(parents=True, exist_ok=True)
            return self
        except OSError as error:
            raise WorkspaceFailed(Fault.WRITE_FAILED, f"Could not create [{path}].") from error

    def delete_directory(self, path: str) -> SyncWorkspace:
        try:
            shutil.rmtree(self._absolute(self._admit(path, "delete")), ignore_errors=False)
            return self
        except FileNotFoundError:
            return self
        except OSError as error:
            raise WorkspaceFailed(Fault.DELETE_FAILED, f"Could not delete [{path}].") from error

    def size(self, path: str) -> int:
        try: return self._absolute(self._admit(path, "read")).stat().st_size
        except FileNotFoundError as error:
            raise WorkspaceFailed(Fault.FILE_MISSING, f"There is no [{path}] in this workspace.") from error

    def last_modified(self, path: str) -> int:
        try: return int(self._absolute(self._admit(path, "read")).stat().st_mtime)
        except FileNotFoundError as error:
            raise WorkspaceFailed(Fault.FILE_MISSING, f"There is no [{path}] in this workspace.") from error

    def list(self, directory: str = "", recursive: bool = True) -> Iterator[WorkspaceEntry]:
        location = "" if directory == "" else self._admit(directory, "list")
        if directory == "" and self.authorize: self.authorize("list", self, None)
        start = self.root if location == "" else self._absolute(location)
        if not start.exists(): return
        iterator = start.rglob("*") if recursive else start.iterdir()
        for child in iterator:
            relative_path = child.relative_to(self.root).as_posix()
            is_directory = child.is_dir()
            yield WorkspaceEntry(relative_path, is_directory)

    def clear(self) -> SyncWorkspace:
        if self.authorize: self.authorize("delete", self, None)
        if not self.root.exists(): return self
        for child in self.root.iterdir():
            if child.is_dir() and not child.is_symlink(): shutil.rmtree(child)
            else: child.unlink()
        return self

    def _admit(self, path: str, ability: Ability) -> str:
        guarded = self.guard.guard(path)
        if self.authorize: self.authorize(ability, self, guarded)
        self.boundary.admit(guarded)
        return guarded

    def _absolute(self, path: str) -> Path:
        return self.root.joinpath(*path.split("/"))


class Workspace:
    """Async-first local workspace; blocking operations run in worker threads."""

    def __init__(
        self,
        base_directory: str | Path,
        owner: WorkspaceIdentity,
        *,
        guard: PathGuard | None = None,
        authorize: Authorizer | None = None,
        windows_max_path: int | None = 259,
    ) -> None:
        self.sync = SyncWorkspace(
            base_directory,
            owner,
            guard=guard,
            authorize=authorize,
            windows_max_path=windows_max_path,
        )
        self.address = self.sync.address
        self.root = self.sync.root

    async def exists(self, path: str) -> bool: return await asyncio.to_thread(self.sync.exists, path)
    async def read(self, path: str) -> str: return await asyncio.to_thread(self.sync.read, path)
    async def read_bytes(self, path: str) -> bytes: return await asyncio.to_thread(self.sync.read_bytes, path)
    async def write(self, path: str, contents: str | bytes) -> Workspace:
        await asyncio.to_thread(self.sync.write, path, contents); return self
    async def append(self, path: str, contents: str) -> Workspace:
        await asyncio.to_thread(self.sync.append, path, contents); return self
    async def copy(self, source: str, destination: str) -> Workspace:
        await asyncio.to_thread(self.sync.copy, source, destination); return self
    async def move(self, source: str, destination: str) -> Workspace:
        await asyncio.to_thread(self.sync.move, source, destination); return self
    async def delete(self, path: str) -> Workspace:
        await asyncio.to_thread(self.sync.delete, path); return self
    async def make_directory(self, path: str) -> Workspace:
        await asyncio.to_thread(self.sync.make_directory, path); return self
    async def delete_directory(self, path: str) -> Workspace:
        await asyncio.to_thread(self.sync.delete_directory, path); return self
    async def size(self, path: str) -> int: return await asyncio.to_thread(self.sync.size, path)
    async def last_modified(self, path: str) -> int:
        return await asyncio.to_thread(self.sync.last_modified, path)
    async def list(self, directory: str = "", recursive: bool = True) -> AsyncIterator[WorkspaceEntry]:
        iterator = self.sync.list(directory, recursive)
        while True:
            entry = await asyncio.to_thread(_next_entry, iterator)
            if entry is None: return
            yield entry
    async def clear(self) -> Workspace:
        await asyncio.to_thread(self.sync.clear); return self


def _next_entry(iterator: Iterator[WorkspaceEntry]) -> WorkspaceEntry | None:
    try: return next(iterator)
    except StopIteration: return None


__all__ = [
    "Fault", "LocalBoundary", "PathGuard", "PathRefused", "Refusal", "SyncWorkspace",
    "Workspace", "WorkspaceEntry", "WorkspaceFailed", "workspace_address",
]
