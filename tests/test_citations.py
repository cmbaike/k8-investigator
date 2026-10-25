from app.citations import (
    extract_citations,
    invalid_citations,
    valid_source_labels,
)


SOURCES = [
    {
        "filename": "runbook.pdf",
        "page_number": 6,
        "chunk_index": 12,
        "content": "Red means at least one primary shard is unassigned.",
        "similarity": 0.84,
    },
    {
        "filename": "runbook.pdf",
        "page_number": 9,
        "chunk_index": 19,
        "content": "Production restarts require human approval.",
        "similarity": 0.72,
    },
]


def test_extract_citations():
    answer = (
        "Red means a primary shard is unassigned. "
        "[SOURCE: runbook.pdf#page-6-chunk-12]"
    )

    assert extract_citations(answer) == [
        "runbook.pdf#page-6-chunk-12"
    ]


def test_valid_source_labels():
    assert valid_source_labels(SOURCES) == {
        "runbook.pdf#page-6-chunk-12",
        "runbook.pdf#page-9-chunk-19",
    }


def test_retrieved_citation_is_valid():
    answer = (
        "Red means a primary shard is unassigned. "
        "[SOURCE: runbook.pdf#page-6-chunk-12]"
    )

    assert invalid_citations(answer, SOURCES) == []


def test_non_retrieved_citation_is_invalid():
    answer = (
        "Unsupported claim. "
        "[SOURCE: other.pdf#page-99-chunk-999]"
    )

    assert invalid_citations(answer, SOURCES) == [
        "other.pdf#page-99-chunk-999"
    ]


def test_multiple_citations_are_checked():
    answer = (
        "Claim one. [SOURCE: runbook.pdf#page-6-chunk-12] "
        "Claim two. [SOURCE: fake.pdf#page-1-chunk-0]"
    )

    assert invalid_citations(answer, SOURCES) == [
        "fake.pdf#page-1-chunk-0"
    ]


def test_refusal_has_no_citations():
    answer = (
        "I don't have sufficient evidence in the "
        "retrieved sources to answer this question."
    )

    assert extract_citations(answer) == []

def test_extract_citation_allows_whitespace():
    answer = (
        "Answer. "
        "[ SOURCE: runbook.pdf#page-6-chunk-12 ]"
    )

    assert extract_citations(answer) == [
        "runbook.pdf#page-6-chunk-12"
    ]