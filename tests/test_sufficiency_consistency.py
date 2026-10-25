from app.sufficiency import SufficiencyResult
from app.sufficiency_consistency import apply_consistency_guard


def test_rejects_not_provided_contradiction():
    result = SufficiencyResult(
        sufficient=True,
        reason="The specific RTO value is not provided in the evidence.",
    )

    guarded = apply_consistency_guard(result)

    assert guarded.sufficient is False


def test_preserves_supported_negative_answer():
    result = SufficiencyResult(
        sufficient=True,
        reason=(
            "The evidence explicitly states that production "
            "restarts require human approval."
        ),
    )

    guarded = apply_consistency_guard(result)

    assert guarded.sufficient is True


def test_preserves_normal_sufficient_result():
    result = SufficiencyResult(
        sufficient=True,
        reason=(
            "The evidence explicitly states that backups "
            "are retained for 35 days."
        ),
    )

    guarded = apply_consistency_guard(result)

    assert guarded.sufficient is True


def test_preserves_existing_insufficient_result():
    result = SufficiencyResult(
        sufficient=False,
        reason="The production region is not stated.",
    )

    guarded = apply_consistency_guard(result)

    assert guarded.sufficient is False
