import re

from app.provenance import source_label


SOURCE_PATTERN = re.compile(
    r"\[\s*SOURCE:\s*([^\]]+?)\s*\]",
)

def extract_citations(answer: str) -> list[str]:
    return [
        match.strip()
        for match in SOURCE_PATTERN.findall(answer)
    ]


def valid_source_labels(
    sources: list[dict],
) -> set[str]:
    return {
        source_label(source)
        for source in sources
    }


def invalid_citations(
    answer: str,
    sources: list[dict],
) -> list[str]:
    valid = valid_source_labels(sources)

    return [
        citation
        for citation in extract_citations(answer)
        if citation not in valid
    ]
