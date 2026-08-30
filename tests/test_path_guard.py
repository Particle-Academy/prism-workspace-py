import pytest

from prism_workspace import PathGuard, PathRefused, Refusal

GUARD = PathGuard()
REFUSED = [
    ("", Refusal.EMPTY_PATH), ("../secret", Refusal.TRAVERSAL),
    ("/etc/passwd", Refusal.ABSOLUTE), ("C:\\secret", Refusal.ABSOLUTE),
    ("\\\\server\\share", Refusal.UNC), ("a\0b", Refusal.NULL_BYTE),
    ("a\nb", Refusal.CONTROL_CHARACTER), ("a\u200bb", Refusal.INVISIBLE_CHARACTER),
    ("a\u2215b", Refusal.SEPARATOR_HOMOGLYPH), ("%2e%2e/report", Refusal.ENCODED_SEPARATOR),
    ("report:secret", Refusal.ALTERNATE_DATA_STREAM), ("nul.txt", Refusal.RESERVED_DEVICE_NAME),
    ("draft. ", Refusal.EDGE_DOT_OR_SPACE), ("draft~1.txt", Refusal.SHORT_NAME_ALIAS),
    ("~/secret", Refusal.HOME_EXPANSION), ("..cache/notes", Refusal.TRAVERSAL),
]


@pytest.mark.parametrize(("path", "code"), REFUSED)
def test_refuses_with_stable_code(path: str, code: Refusal) -> None:
    with pytest.raises(PathRefused) as caught:
        GUARD.guard(path)
    assert caught.value.code is code


@pytest.mark.parametrize(("path", "expected"), [
    ("reports/q1.md", "reports/q1.md"), ("reports\\q1.md", "reports/q1.md"),
    ("./reports//q1.md", "reports/q1.md"), ("50% off.md", "50% off.md"),
])
def test_normalizes(path: str, expected: str) -> None:
    assert GUARD.guard(path) == expected


def test_overlapping_failures_keep_reference_order() -> None:
    with pytest.raises(PathRefused) as caught:
        GUARD.guard("\ud800" * 400)
    assert caught.value.code is Refusal.TOO_LONG
