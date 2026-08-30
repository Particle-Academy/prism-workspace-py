import base64
import json
from importlib.resources import files
from typing import TypedDict, cast

import pytest

from prism_workspace import PathGuard, PathRefused, Refusal


class CorpusCase(TypedDict):
    id: str
    path_base64: str
    refusal: str


document = json.loads(
    files("prism_workspace.security").joinpath("escape-corpus.json").read_text(encoding="utf-8")
)
cases = cast(list[CorpusCase], document["cases"])


def test_complete_php_v1_corpus_is_shipped() -> None:
    assert len(cases) == 134


@pytest.mark.parametrize("case", cases, ids=[case["id"] for case in cases])
def test_refusal_code_matches_reference(case: CorpusCase) -> None:
    with pytest.raises(PathRefused) as caught:
        PathGuard().guard(base64.b64decode(case["path_base64"], validate=True))
    assert caught.value.code is Refusal(case["refusal"])
