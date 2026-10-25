"""Scheduling diagnosis correctness.

Kubernetes semantics: NODES have taints, labels and allocatable capacity; PODS
have tolerations, node selectors and resource requests. A model that reverses
the taint/toleration relationship must not reach a report, in an explanation
or in a recommended check, and a correct statement must never be rejected.

Also covers the structured constraint rows the application mints from
validated scheduler signals, and that the highest-ranked accepted hypothesis
stays consistent with the constraints Kubernetes actually reported.
"""

import json
import re

import pytest
from pydantic import ValidationError

from app.reports.evidence_focus import build_focus_groups
from app.reports.hypotheses import (
    HypothesisEvidenceRegistry,
    parse_hypothesis_response,
    revalidate_hypotheses,
)
from app.reports.hypothesis_ranking import rank_hypotheses
from app.reports.models import (
    AIHypothesis,
    OMISSION_REASON_CODES,
    SCHEDULING_CONSTRAINT_LABELS,
    EvidenceReference,
    InvestigationFinding,
    InvestigationReport,
    SchedulingConstraint,
)
from app.reports.pod_health_grounding import SCHEDULING_LABELS, _SCHEDULING_CHECKS
from app.reports.qwen_hypotheses import HYPOTHESIS_SYSTEM_PROMPT
from app.reports.qwen_report import ReportFormatError, parse_report
from app.reports.scheduling_semantics import (
    INVERTED_SCHEDULING_TERMS,
    inverted_taint_toleration,
)
from app.reports.validation import ReportEvidenceError, validate_report_snapshot
from app.tools.event_signals import SCHEDULING_CONSTRAINTS
from tests.pod_scenarios import NS, investigate
from tests.test_pod_level_health import SCHED_MESSAGE, unschedulable

MIXED_MESSAGE = (
    "0/2 nodes are available: 1 Insufficient cpu, 1 Insufficient memory, "
    "1 node(s) had untolerated taint {node-role.kubernetes.io/control-plane: }. "
    "preemption: 0/2 nodes are available: 2 Preemption is not helpful for scheduling."
)
SELECTOR_MESSAGE = (
    "0/1 nodes are available: 1 node(s) didn't match Pod's node affinity/selector. "
    "preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling."
)
TAINT_MESSAGE = (
    "0/1 nodes are available: 1 node(s) had untolerated taint {dedicated: gpu}. "
    "preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling."
)

NOT_VERIFIED = "The underlying cause has not been verified."
CHECK_OK = (
    "Compare the taints on the nodes with the tolerations the pod declares "
    "(read-only)."
)

RESOURCES = (
    "The requested CPU and memory may exceed what any node can allocate, which "
    "could explain why the pod is Pending."
)
TAINTS = (
    "The nodes may carry taints that the pod does not tolerate, which could "
    "explain why the pod is Pending."
)
SELECTOR = (
    "The pod's node selector may match the labels of no node, which could "
    "explain why the pod is Pending."
)

# The wording the model actually produced for impossible-pod.
REPORTED_EXPLANATION = (
    "The pod may not be schedulable because it contains a taint that no node "
    "in the cluster tolerates."
)
REPORTED_CHECK = (
    "Check the taints on the pod and the tolerations on the nodes (read-only)."
)


# ===================================================== the narrow semantic rule

INVERTED = [
    REPORTED_EXPLANATION,
    REPORTED_CHECK,
    "Verify the taints on the pod and the tolerations on the nodes.",
    "The nodes do not tolerate the taint.",
    "No node in the cluster tolerates it.",
    "The taint is not tolerated by any node.",
    "The pod's taints may prevent it from being scheduled.",
    "The pod may carry a taint.",
    "The pod might contain taints.",
    "Review the taints the pod declares.",
    "The pod is tainted.",
    "Inspect each node's tolerations.",
    "Compare node tolerations with the pod.",
    "Look at the tolerations of the nodes.",
]

CORRECT = [
    "The nodes may carry taints that the pod does not tolerate.",
    "Compare the taints on the nodes with the tolerations declared by the pod (read-only).",
    "Review the taints on the nodes and the tolerations the pod declares (read-only).",
    "The pod may lack a toleration for a node taint.",
    "The pod's tolerations may not match the taints on the cluster's nodes.",
    "The pod may not tolerate the taints on the control-plane node.",
    "Tolerations on the pod may be missing.",
    "Check taints on the node hosting the pod.",
    "Node taints that the pod does not tolerate may prevent scheduling.",
    "The pod has no toleration for the taint on the node.",
    "Nodes in the cluster may carry taints, and the pod tolerates none of them.",
    "The requested memory may exceed what any node can offer.",
    "The node selector may match no node.",
    "Compare the pod's CPU request with the allocatable CPU of the nodes.",
]


@pytest.mark.parametrize("text", INVERTED)
def test_reversed_taint_toleration_wording_is_detected(text):
    assert inverted_taint_toleration([text]) is True


@pytest.mark.parametrize("text", CORRECT)
def test_correct_taint_toleration_wording_is_never_flagged(text):
    assert inverted_taint_toleration([text]) is False


def test_the_rule_ignores_empty_and_missing_text():
    assert inverted_taint_toleration([None, "", "   "]) is False
    assert inverted_taint_toleration([]) is False


def test_the_rule_is_narrow_and_leaves_other_scheduling_claims_alone():
    # It is not general semantic validation: unrelated or merely dubious
    # scheduling statements pass here (other checks and tests cover them).
    for text in (
        "The node selector may be too restrictive.",
        "The cluster may be out of quota.",
        "The pod may request more than any node allocates.",
        "A taint may exist.",
    ):
        assert inverted_taint_toleration([text]) is False


def test_every_application_authored_scheduling_string_uses_correct_terms():
    strings = [*SCHEDULING_LABELS.values(), *_SCHEDULING_CHECKS.values(),
               *SCHEDULING_CONSTRAINT_LABELS.values()]

    assert strings and not inverted_taint_toleration(strings)

    for message in (SCHED_MESSAGE, MIXED_MESSAGE, SELECTOR_MESSAGE, TAINT_MESSAGE):
        _, _, report, _ = investigate(unschedulable(message=message))

        assert not inverted_taint_toleration(
            [*report.suggested_checks, *report.uncertainties, report.summary,
             *(f.description for f in report.findings),
             *(f.title for f in report.findings)]
        )


# ============================================================ through the stack


def build(message=MIXED_MESSAGE, **overrides):
    ctx, snapshot, report, _ = investigate(unschedulable(message=message, **overrides))
    registry = HypothesisEvidenceRegistry(
        investigation_id=ctx.investigation_id,
        authorized_namespace=NS,
        snapshot=snapshot,
        log_entries=ctx.log_entries,
    )

    return ctx, snapshot, report, registry


def status_ids(snapshot):
    return next(g for g in build_focus_groups(snapshot) if g["focus"] == "scheduling_status")[
        "evidence_ids"
    ]


def hyp(ids, possible, *, check=CHECK_OK, not_verified=NOT_VERIFIED):
    return {
        "reported": None,
        "possible_explanation": possible,
        "not_yet_verified": not_verified,
        "evidence": ids,
        "resource": {"namespace": NS, "pod": "big", "container": None},
        "verification_check": check,
    }


def parse(ctx, registry, *items):
    return parse_hypothesis_response(
        json.dumps({"investigation_id": ctx.investigation_id, "hypotheses": list(items)}),
        registry=registry,
        expected_investigation_id=ctx.investigation_id,
    )


def test_the_reported_reversed_hypothesis_is_omitted_not_shown():
    ctx, snapshot, _, registry = build()
    batch = parse(ctx, registry, hyp(status_ids(snapshot), REPORTED_EXPLANATION))

    assert batch.hypotheses == []
    assert batch.omitted == 1
    assert batch.omission_reasons == {INVERTED_SCHEDULING_TERMS: 1}
    assert INVERTED_SCHEDULING_TERMS in OMISSION_REASON_CODES


def test_the_reported_reversed_check_is_withheld_and_the_sound_hypothesis_kept():
    ctx, snapshot, _, registry = build()
    ids = status_ids(snapshot)

    # The explanation is correct; only the recommended check is reversed.
    batch = parse(ctx, registry, hyp(ids, TAINTS, check=REPORTED_CHECK))
    (kept,) = batch.hypotheses

    assert batch.omitted == 0
    assert kept.possible_explanation == TAINTS
    # Never shown, never rewritten into a different check.
    assert kept.verification_check is None
    assert kept.check_withheld_reason == INVERTED_SCHEDULING_TERMS
    assert "tolerations on the nodes" not in kept.model_dump_json()
    assert parse(ctx, registry, hyp(ids, TAINTS)).hypotheses[0].verification_check == CHECK_OK


def test_a_withheld_check_survives_revalidation_and_cannot_be_restored():
    ctx, snapshot, _, registry = build()
    ids = status_ids(snapshot)
    (kept,) = parse(ctx, registry, hyp(ids, TAINTS, check=REPORTED_CHECK)).hypotheses

    # The enrichment stage re-validates every provider-built hypothesis.
    again = revalidate_hypotheses([kept], registry=registry)

    assert again.omitted == 0 and again.hypotheses[0].verification_check is None
    assert again.hypotheses[0].check_withheld_reason == INVERTED_SCHEDULING_TERMS

    # A withheld hypothesis with its reason removed is not valid as such.
    with pytest.raises(ValidationError):
        AIHypothesis.model_validate(
            {**kept.model_dump(), "check_withheld_reason": None}
        )


def test_the_unverified_note_is_checked_too():
    ctx, snapshot, _, registry = build()
    batch = parse(
        ctx, registry,
        hyp(status_ids(snapshot), TAINTS,
            not_verified="It has not been verified which taints the pod carries."),
    )

    assert batch.omission_reasons == {INVERTED_SCHEDULING_TERMS: 1}


def test_a_reversed_hypothesis_does_not_discard_its_correct_siblings():
    ctx, snapshot, _, registry = build()
    ids = status_ids(snapshot)

    batch = parse(
        ctx, registry,
        hyp(ids, REPORTED_EXPLANATION), hyp(ids, TAINTS), hyp(ids, RESOURCES),
    )

    assert [h.possible_explanation for h in batch.hypotheses] == [TAINTS, RESOURCES]
    assert batch.omitted == 1


def test_correct_taint_toleration_hypotheses_and_checks_are_accepted():
    ctx, snapshot, _, registry = build()
    ids = status_ids(snapshot)

    for possible, check in (
        (TAINTS, CHECK_OK),
        (RESOURCES, "Compare the pod's CPU and memory requests with the allocatable "
                    "capacity of the nodes (read-only)."),
        (TAINTS, "Review the taints on the nodes and the tolerations the pod "
                 "declares (read-only)."),
    ):
        batch = parse(ctx, registry, hyp(ids, possible, check=check))

        assert len(batch.hypotheses) == 1 and batch.omitted == 0


def test_provider_built_hypotheses_are_revalidated_for_inverted_terms():
    ctx, snapshot, _, registry = build()
    ids = status_ids(snapshot)
    accepted = parse(ctx, registry, hyp(ids, TAINTS)).hypotheses[0]

    forged = accepted.model_copy(update={"verification_check": REPORTED_CHECK})
    batch = revalidate_hypotheses([forged], registry=registry)

    # The reversed check never survives re-validation; the explanation does.
    assert batch.omitted == 0 and len(batch.hypotheses) == 1
    assert batch.hypotheses[0].verification_check is None
    assert batch.hypotheses[0].check_withheld_reason == INVERTED_SCHEDULING_TERMS

    # A reversed EXPLANATION is still omitted.
    reversed_explanation = accepted.model_copy(
        update={"possible_explanation": REPORTED_EXPLANATION}
    )
    assert revalidate_hypotheses([reversed_explanation], registry=registry).hypotheses == []
    assert len(revalidate_hypotheses([accepted], registry=registry).hypotheses) == 1


def test_the_prompt_teaches_nodes_have_taints_and_pods_have_tolerations():
    prompt = " ".join(HYPOTHESIS_SYSTEM_PROMPT.split())

    assert "Nodes have taints" in prompt
    assert "pods have tolerations" in prompt
    assert "A pod never has a taint and a node never tolerates anything" in prompt
    assert "node taints the pod does not tolerate" in prompt
    assert "requests (not its limits)" in prompt


# ===================================================== legacy model-written report


def _report_json(snapshot, **finding):
    ref = snapshot.evidence[0].evidence_id

    return json.dumps(
        {
            "investigation_id": snapshot.investigation_id,
            "summary": "s",
            "findings": [
                {"title": "t", "description": "d", "severity": "info",
                 "evidence": [{"evidence_id": ref}], **finding}
            ],
            "uncertainties": [],
            "suggested_checks": [REPORTED_CHECK],
        }
    )


def test_a_model_written_report_with_a_reversed_check_is_refused():
    _, snapshot, _, _ = build()

    with pytest.raises(ReportFormatError):
        parse_report(_report_json(snapshot), snapshot=snapshot,
                     expected_investigation_id=snapshot.investigation_id)


def test_a_model_written_report_may_not_supply_constraint_rows():
    _, snapshot, _, _ = build()
    ref = snapshot.evidence[0].evidence_id
    rows = [{"signal": "insufficient_cpu", "label": "Insufficient CPU", "evidence_ids": [ref]}]
    content = json.loads(_report_json(snapshot, scheduling_constraints=rows))
    content["suggested_checks"] = [CHECK_OK]

    with pytest.raises(ReportFormatError):
        parse_report(json.dumps(content), snapshot=snapshot,
                     expected_investigation_id=snapshot.investigation_id)


# ===================================================== structured constraint rows


def constraint_rows(report):
    finding = next(f for f in report.findings if f.title == "Pod could not be scheduled")

    return finding, finding.scheduling_constraints


def test_mixed_constraints_become_ordered_fixed_vocabulary_rows():
    _, snapshot, report, _ = build(MIXED_MESSAGE)
    finding, rows = constraint_rows(report)
    by_id = {item.evidence_id: item for item in snapshot.evidence}

    assert [r.signal for r in rows] == [
        "insufficient_cpu", "insufficient_memory", "untolerated_taint"
    ]
    assert [r.label for r in rows] == [
        "Insufficient CPU", "Insufficient memory", "Untolerated node taints"
    ]

    cited = {e.evidence_id for e in finding.evidence}

    for row in rows:
        assert row.label == SCHEDULING_CONSTRAINT_LABELS[row.signal]
        assert set(row.evidence_ids) <= cited

        for ref in row.evidence_ids:
            assert by_id[ref].field.endswith(f".signal[{row.signal}]")
            assert by_id[ref].value is True


def test_rows_never_carry_event_message_text():
    marker = "MARKER-MESSAGE-5530"
    _, _, report, _ = build(MIXED_MESSAGE + " " + marker)
    _, rows = constraint_rows(report)
    dumped = json.dumps([r.model_dump() for r in rows])

    assert marker not in dumped and "control-plane" not in dumped and "preemption" not in dumped


@pytest.mark.parametrize(
    "message, signals",
    [
        (SCHED_MESSAGE, ["insufficient_memory"]),
        (SELECTOR_MESSAGE, ["node_selector_mismatch"]),
        (TAINT_MESSAGE, ["untolerated_taint"]),
        ("0/1 nodes are available: 1 Too many pods.", ["too_many_pods"]),
    ],
    ids=["insufficient-resources", "node-selector", "untolerated-taint", "pod-limit"],
)
def test_each_scheduling_scenario_reports_only_the_signals_kubernetes_gave(message, signals):
    _, _, report, _ = build(message)
    _, rows = constraint_rows(report)

    assert [r.signal for r in rows] == signals


def test_an_unclassified_scheduler_message_yields_no_rows_but_keeps_the_finding():
    _, _, report, _ = build("0/1 nodes are available: something this build does not know.")
    finding, rows = constraint_rows(report)

    assert rows == [] and finding.severity == "critical"
    assert "could not be scheduled" in finding.title


def test_the_full_finding_and_its_evidence_stay_complete():
    _, _, report, _ = build(MIXED_MESSAGE)
    finding, rows = constraint_rows(report)

    assert "insufficient CPU" in finding.description
    assert "node taints the pod does not tolerate" in finding.description
    assert "on the nodes" not in finding.description.split("reports")[1].split(".")[0]
    assert len(finding.evidence) >= len({r for row in rows for r in row.evidence_ids})


def test_constraint_rows_are_validated_by_the_report_model():
    ref = "ev-0001"
    ok = {"signal": "insufficient_cpu", "label": "Insufficient CPU", "evidence_ids": [ref]}
    base = dict(title="t", description="d", severity="critical",
                evidence=[EvidenceReference(evidence_id=ref)])

    assert InvestigationFinding(**base, scheduling_constraints=[ok]).scheduling_constraints

    for bad in (
        {**ok, "label": "The pod contains a taint"},      # a label the app did not write
        {**ok, "signal": "made_up_signal"},                # outside the vocabulary
        {**ok, "evidence_ids": ["ev-0002"]},               # not the finding's evidence
        {**ok, "evidence_ids": []},
        {**ok, "evidence_ids": ["log-0001"]},
    ):
        with pytest.raises(ValidationError):
            InvestigationFinding(**base, scheduling_constraints=[bad])

    with pytest.raises(ValidationError):
        InvestigationFinding(**base, scheduling_constraints=[ok, ok])

    with pytest.raises(ValidationError):
        SchedulingConstraint(signal="x", label="x", evidence_ids=[ref])


def test_a_constraint_must_rest_on_the_matching_recorded_signal():
    ctx, snapshot, report, _ = build(MIXED_MESSAGE)
    finding, rows = constraint_rows(report)
    validate_report_snapshot(report, snapshot, expected_investigation_id=ctx.investigation_id)

    # Point the CPU row at the memory signal's observation: not that signal.
    memory = next(r for r in rows if r.signal == "insufficient_memory")
    cpu = next(r for r in rows if r.signal == "insufficient_cpu")
    swapped = cpu.model_copy(update={"evidence_ids": memory.evidence_ids})
    forged_finding = finding.model_copy(
        update={"scheduling_constraints": [swapped, *[r for r in rows if r is not cpu]]}
    )
    forged = report.model_copy(update={"findings": [forged_finding]})

    with pytest.raises(ReportEvidenceError):
        validate_report_snapshot(forged, snapshot, expected_investigation_id=ctx.investigation_id)


def test_reports_without_constraint_rows_still_load():
    payload = {
        "investigation_id": "i",
        "summary": "s",
        "findings": [{"title": "t", "description": "d", "severity": "info",
                      "evidence": [{"evidence_id": "ev-0001"}]}],
    }

    report = InvestigationReport.model_validate(payload)

    assert report.findings[0].scheduling_constraints == []


def test_the_row_vocabulary_is_exactly_the_classifiers():
    assert set(SCHEDULING_CONSTRAINT_LABELS) == set(SCHEDULING_CONSTRAINTS)
    assert set(SCHEDULING_LABELS) == set(SCHEDULING_CONSTRAINTS)


# ======================================= the top hypothesis matches the constraints

TOPICS = {
    "resources": re.compile(r"cpu|memory|resources?|requests?|capacity", re.IGNORECASE),
    "taints": re.compile(r"taint|toleration", re.IGNORECASE),
    "selector": re.compile(r"selector|affinity|label", re.IGNORECASE),
}
FAMILY = {
    "insufficient_cpu": "resources", "insufficient_memory": "resources",
    "untolerated_taint": "taints", "node_selector_mismatch": "selector",
}


def top_family(text):
    return next(name for name, pattern in TOPICS.items() if pattern.search(text))


@pytest.mark.parametrize(
    "message, expected",
    [
        (SCHED_MESSAGE, "resources"),
        (SELECTOR_MESSAGE, "selector"),
        (TAINT_MESSAGE, "taints"),
    ],
    ids=["insufficient-resources", "node-selector", "untolerated-taint"],
)
def test_the_top_hypothesis_addresses_a_constraint_kubernetes_reported(message, expected):
    ctx, snapshot, report, registry = build(message)
    ids = status_ids(snapshot)
    # Proposed in an order that does NOT match the evidence, every time.
    proposals = {"taints": TAINTS, "resources": RESOURCES, "selector": SELECTOR}
    order = [name for name in proposals if name != expected] + [expected]
    batch = parse(ctx, registry, *[hyp(ids, proposals[name]) for name in order])

    assert len(batch.hypotheses) == 3 and batch.omitted == 0

    ranked = rank_hypotheses(batch.hypotheses, registry)
    _, rows = constraint_rows(report)

    assert top_family(ranked[0].possible_explanation) == expected
    assert expected in {FAMILY[r.signal] for r in rows}
    # Lower-ranked hypotheses are kept, not dropped.
    assert {h.possible_explanation for h in ranked} == set(proposals.values())


def test_with_several_reported_constraints_any_of_them_may_lead_but_not_an_unreported_one():
    ctx, snapshot, _, registry = build(MIXED_MESSAGE)
    ids = status_ids(snapshot)
    batch = parse(ctx, registry, hyp(ids, SELECTOR), hyp(ids, TAINTS), hyp(ids, RESOURCES))
    ranked = rank_hypotheses(batch.hypotheses, registry)

    # The node selector is not among the reported constraints (CPU, memory,
    # untolerated taints), so that hypothesis ranks last; the others keep the
    # model's relative order.
    assert [top_family(h.possible_explanation) for h in ranked] == [
        "taints", "resources", "selector"
    ]
    assert rank_hypotheses(ranked, registry) == ranked


def test_ranking_falls_back_to_scheduling_topics_when_no_signal_was_classified():
    ctx, snapshot, _, registry = build("0/1 nodes are available: nothing recognisable.")
    ids = status_ids(snapshot)
    batch = parse(ctx, registry, hyp(ids, SELECTOR), hyp(ids, RESOURCES))

    assert registry.scheduling_signals("big") == frozenset()
    assert [h.possible_explanation for h in rank_hypotheses(batch.hypotheses, registry)] == [
        SELECTOR, RESOURCES
    ]


def test_citing_a_containers_request_does_not_demote_a_pod_level_hypothesis():
    # Resource requests are declared per container, so a resources hypothesis
    # cites a container-scoped field. The pod never ran: its hypotheses are one
    # group, ordered by what the scheduler reported, not split by that field.
    ctx, snapshot, _, registry = build(SCHED_MESSAGE)
    ids = status_ids(snapshot)
    request = next(
        i.evidence_id for i in snapshot.evidence if i.field.endswith("resources.memory_request")
    )
    resources = hyp([*ids[:4], request], RESOURCES)
    taints = hyp(ids[:5], TAINTS)

    # The unreported-constraint hypothesis is proposed first.
    batch = parse(ctx, registry, taints, resources)
    ranked = rank_hypotheses(batch.hypotheses, registry)

    assert [h.possible_explanation for h in ranked] == [RESOURCES, TAINTS]
    assert ranked[0].resource.container == "app" and ranked[1].resource.container is None
