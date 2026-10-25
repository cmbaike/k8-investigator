"""Citation-count handling for AI hypotheses.

The limit (MAX_REFERENCES) is a SIZE rule. It omits ONE hypothesis with a fixed
reason code and never truncates its references. It must never mask a
provenance failure: an unknown, malformed, duplicated or cross-resource
reference still rejects the whole response, whatever the count.
"""

import json

import pytest

from app.reports.enrichment import add_ai_hypotheses
from app.reports.grounding import build_grounded_report
from app.reports.hypotheses import (
    MAX_REFERENCES,
    HypothesisValidationError,
    parse_hypothesis_response,
)
from app.reports.models import OMISSION_REASON_CODES
from app.reports.qwen_hypotheses import QwenHypothesisProvider
from tests.test_ai_hypotheses import (  # noqa: F401  (fixtures)
    NS,
    OTHER_POD,
    POD,
    SENTINEL,
    completion_returning,
    ctx,
    ev,
    hypothesis,
    hypothesis_input,
    parse_batch,
    payload,
    registry,
    rejected,
    snapshot,
)

SECOND = (
    "The application may be failing on start because of a code error, which "
    "could explain the repeated restarts."
)
THIRD = (
    "The container may be hitting a resource limit shortly after it starts, "
    "which could explain the restarts."
)
OVER_LIMIT_TEXT = (
    "The container may be restarting because of a misconfigured startup "
    "sequence, OVERLIMIT-MARKER-5521 included."
)


def pod_refs(snapshot, pod=POD):
    """Every evidence id that cites `pod` (all valid, all same-pod)."""
    return [item.evidence_id for item in snapshot.evidence if item.pod == pod]


def cited(snapshot, count):
    refs = pod_refs(snapshot)

    assert len(refs) >= count, "fixture must supply enough valid citations"

    return refs[:count]


def one(snapshot, count, **overrides):
    fields = {"evidence": cited(snapshot, count), "reported": None, "resource": None}
    fields.update(overrides)

    return hypothesis(**fields)


# ------------------------------------------------------------ the size rule


def test_exactly_the_limit_is_accepted_in_full(registry, snapshot):
    assert MAX_REFERENCES == 6

    batch = parse_batch(payload(one(snapshot, 6)), registry)

    assert len(batch.hypotheses) == 1 and batch.omitted == 0
    assert batch.hypotheses[0].evidence_refs == cited(snapshot, 6)


@pytest.mark.parametrize("count", [7, 8])
def test_over_the_limit_omits_only_that_hypothesis_with_a_fixed_code(
    registry, snapshot, count
):
    batch = parse_batch(payload(one(snapshot, count)), registry)

    assert batch.hypotheses == []
    assert batch.omitted == 1
    assert batch.omission_reasons == {"too_many_references": 1}


def test_every_valid_citation_the_snapshot_holds_is_still_only_an_omission(
    registry, snapshot
):
    everything = pod_refs(snapshot)

    assert len(everything) > MAX_REFERENCES
    batch = parse_batch(
        payload(hypothesis(evidence=everything, reported=None, resource=None)),
        registry,
    )

    assert batch.omission_reasons == {"too_many_references": 1}


def test_the_reason_code_is_part_of_the_fixed_omission_vocabulary():
    assert "too_many_references" in OMISSION_REASON_CODES


def test_a_safe_batch_survives_one_over_limit_candidate(registry, snapshot):
    batch = parse_batch(
        payload(
            one(snapshot, 3),
            one(snapshot, 8, possible_explanation=OVER_LIMIT_TEXT),
            one(snapshot, 6, possible_explanation=SECOND),
        ),
        registry,
    )

    assert len(batch.hypotheses) == 2
    assert batch.omitted == 1
    assert batch.omission_reasons == {"too_many_references": 1}
    # Accepted hypotheses keep EXACTLY the references they cited (no trimming).
    assert [len(h.evidence_refs) for h in batch.hypotheses] == [3, 6]
    assert all(OVER_LIMIT_TEXT != h.possible_explanation for h in batch.hypotheses)


def test_over_limit_references_are_never_truncated_into_an_accepted_hypothesis(
    registry, snapshot
):
    batch = parse_batch(payload(one(snapshot, 9)), registry)

    assert batch.hypotheses == []  # not accepted as a 6-reference version


def test_an_empty_citation_list_is_still_a_whole_response_failure(registry):
    rejected(payload(hypothesis(evidence=[], resource=None)), registry, "reference_count")


# --------------------------------- provenance is never masked by the size rule


def over_limit_with(snapshot, bad_ref, position=3):
    refs = cited(snapshot, 7)
    refs.insert(position, bad_ref)

    return hypothesis(evidence=refs, reported=None, resource=None)


def test_an_unknown_reference_in_an_over_limit_hypothesis_still_rejects_everything(
    registry, snapshot
):
    rejected(
        payload(one(snapshot, 2), over_limit_with(snapshot, "ev-9999")),
        registry,
        "unknown_reference",
    )


def test_a_foreign_investigation_log_reference_still_rejects_everything(
    registry, snapshot
):
    rejected(
        payload(over_limit_with(snapshot, "log-0099")), registry, "unknown_reference"
    )


@pytest.mark.parametrize("bad", ["EV-0003", "ev-3", "ev-0003; drop", 3, None])
def test_a_malformed_reference_in_an_over_limit_hypothesis_still_rejects_everything(
    registry, snapshot, bad
):
    rejected(payload(over_limit_with(snapshot, bad)), registry, "malformed_reference")


def test_duplicate_references_are_rejected_even_when_over_the_limit(
    registry, snapshot
):
    refs = cited(snapshot, 7) + [cited(snapshot, 1)[0]]

    rejected(
        payload(hypothesis(evidence=refs, reported=None, resource=None)),
        registry,
        "duplicate_reference",
    )
    rejected(
        payload(hypothesis(evidence=["ev-0001"] * 7, reported=None, resource=None)),
        registry,
        "duplicate_reference",
    )


def test_cross_resource_citations_are_rejected_even_when_over_the_limit(
    registry, snapshot
):
    other = ev(snapshot, "pods[].name", pod=OTHER_POD, tool="k8s.get_pods")
    refs = cited(snapshot, 7) + [other]

    rejected(
        payload(hypothesis(evidence=refs, reported=None, resource=None)),
        registry,
        "resource_mismatch",
    )


def test_a_declared_resource_mismatch_is_rejected_even_when_over_the_limit(
    registry, snapshot
):
    rejected(
        payload(one(snapshot, 8, resource={"namespace": NS, "pod": OTHER_POD})),
        registry,
        "resource_mismatch",
    )


def test_security_failures_still_reject_everything_for_an_over_limit_hypothesis(
    registry, snapshot
):
    rejected(
        payload(one(snapshot, 8, possible_explanation="It may fail ``` rm -rf")),
        registry,
        "unsafe_text",
    )


# --------------------------------------------- end to end, and no raw output


def provider_for(content):
    return QwenHypothesisProvider(completion=completion_returning(content))


def test_the_pipeline_accepts_the_safe_hypotheses_and_discloses_the_omission(
    ctx, snapshot
):
    content = payload(
        one(snapshot, 4),
        one(snapshot, 8, possible_explanation=OVER_LIMIT_TEXT),
    )
    report = add_ai_hypotheses(
        build_grounded_report(snapshot),
        snapshot=snapshot,
        context=ctx,
        provider=provider_for(content),
    )

    analysis = report.ai_analysis

    assert analysis.state == "generated"
    assert analysis.reason is None and analysis.rejection_category is None
    assert analysis.hypotheses_proposed == 2 and analysis.hypotheses_omitted == 1
    assert analysis.omission_reasons == {"too_many_references": 1}
    assert len(report.ai_hypotheses) == 1


def test_a_batch_of_only_over_limit_hypotheses_is_all_omitted_not_unavailable(
    ctx, snapshot
):
    report = add_ai_hypotheses(
        build_grounded_report(snapshot),
        snapshot=snapshot,
        context=ctx,
        provider=provider_for(payload(one(snapshot, 7), one(snapshot, 9, possible_explanation=SECOND))),
    )

    assert report.ai_analysis.state == "all_omitted"
    assert report.ai_analysis.omission_reasons == {"too_many_references": 2}
    assert report.ai_hypotheses == []


def test_a_provenance_failure_in_an_over_limit_hypothesis_is_unavailable_not_omitted(
    ctx, snapshot
):
    report = add_ai_hypotheses(
        build_grounded_report(snapshot),
        snapshot=snapshot,
        context=ctx,
        provider=provider_for(payload(one(snapshot, 2), over_limit_with(snapshot, "ev-9999"))),
    )

    assert report.ai_analysis.state == "unavailable"
    assert report.ai_analysis.rejection_category == "provenance"
    assert report.ai_hypotheses == []


def test_no_raw_model_output_survives_in_the_report_or_its_status(ctx, snapshot):
    over_limit = one(snapshot, 8, possible_explanation=OVER_LIMIT_TEXT)
    over_limit["not_yet_verified"] = (
        "OVERLIMIT-NOTVERIFIED-9917 has not yet been verified or checked."
    )
    report = add_ai_hypotheses(
        build_grounded_report(snapshot),
        snapshot=snapshot,
        context=ctx,
        provider=provider_for(payload(one(snapshot, 2), over_limit)),
    )
    persisted = report.model_dump_json()

    assert "OVERLIMIT-MARKER-5521" not in persisted
    assert "OVERLIMIT-NOTVERIFIED-9917" not in persisted
    assert SENTINEL not in persisted  # log text never enters a report either
    # Only the accepted hypothesis' own validated references are stored.
    stored_refs = {
        ref for h in report.ai_hypotheses for ref in h.evidence_refs
    }
    assert stored_refs <= set(cited(snapshot, 2))
    assert json.loads(persisted)["ai_analysis"]["omission_reasons"] == {
        "too_many_references": 1
    }


def test_the_error_for_an_over_limit_response_never_carries_model_text(
    registry, snapshot
):
    with pytest.raises(HypothesisValidationError) as caught:
        parse_hypothesis_response(
            payload(over_limit_with(snapshot, "ev-9999")),
            registry=registry,
            expected_investigation_id="inv-ai",
        )

    assert "ev-9999" not in str(caught.value) and caught.value.code == "unknown_reference"


def test_the_prompt_tells_the_model_the_limit(ctx, snapshot):
    from app.reports.qwen_hypotheses import HYPOTHESIS_SYSTEM_PROMPT

    assert f"at most {MAX_REFERENCES} distinct ids" in HYPOTHESIS_SYSTEM_PROMPT
