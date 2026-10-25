import json

import pytest

from app.value_extraction import ValueExtractionResult


def fail_closed() -> ValueExtractionResult:
    return ValueExtractionResult(
        attribute=None,
        value=None,
        evidence_quote=None,
    )


def parse_result(
    content: str,
    finish_reason: str,
) -> ValueExtractionResult:
    if finish_reason != "stop":
        return fail_closed()

    if not content:
        return fail_closed()

    try:
        data = json.loads(content)
        return ValueExtractionResult.model_validate(data)
    except (json.JSONDecodeError, ValueError):
        return fail_closed()


@pytest.mark.parametrize(
    ("content", "finish_reason"),
    [
        ("", "length"),
        ("", "stop"),
        ("not json", "stop"),
        ('{"attribute":', "stop"),
    ],
)
def test_invalid_or_incomplete_output_fails_closed(
    content,
    finish_reason,
):
    result = parse_result(content, finish_reason)

    assert result.attribute is None
    assert result.value is None
    assert result.evidence_quote is None


def test_valid_output_is_preserved():
    result = parse_result(
        (
            '{"attribute":"production RTO",'
            '"value":"60 minutes",'
            '"evidence_quote":"The production RTO is 60 minutes."}'
        ),
        "stop",
    )

    assert result.attribute == "production RTO"
    assert result.value == "60 minutes"
    assert (
        result.evidence_quote
        == "The production RTO is 60 minutes."
    )
