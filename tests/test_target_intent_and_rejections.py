"""Target intent, audited proposal rejection, and model-order ranking ties.

Three corrections, each tested through the real components (question
classification, controller, orchestrator, coverage policy, durable audit writer
with a faked database connection, report builder, hypothesis validator and
ranker). Only the Kubernetes executor is a stub, and it records every call it
is asked to run, so the tests can prove what was and was not executed.
"""

import itertools
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.reports.hypothesis_ranking import rank_hypotheses
from app.tools import handlers
from app.tools.coverage import SUPPLEMENTARY_TOOLS, CoverageProvider
from app.tools.investigation_audit import write_investigation_audit_event
from app.tools.investigation_controller import (
    InvestigationStep,
    InvestigationStopReason,
    run_investigation,
)
from app.tools.investigation_scope import (
    SCOPE_REJECTION_MESSAGES,
    InvestigationScopeCreationError,
    create_bound_investigation_context,
)
from app.tools.models import ToolCall
from app.tools.orchestrator import execute_investigation_step
from app.tools.proposal_rejection import (
    MAX_REJECTED_PROPOSALS,
    REJECTION_REASONS,
    safe_proposal_arguments,
)
from app.tools.workload_target import (
    PodOwner,
    ScopeIntent,
    TargetQuestionError,
    TargetStatus,
    WorkloadTarget,
    classify_question_target,
    resolve_target,
)
from tests.test_target_binding_and_readiness import (
    BAD,
    BROKEN,
    CANARY,
    GENERIC,
    GET_PODS,
    NS,
    TARGETED_BAD,
    Cluster,
    describe,
    ev,
    hypo,
    investigate,
    not_ready_pod,
    parse,
    registry_for,
    event,
    scripted,
)


def intent(question):
    return classify_question_target(question, namespace=NS)


# ======================================================== Phase 1: target intent


@pytest.mark.parametrize(
    "question, name",
    [
        ("Why is payments-api failing?", "payments-api"),
        ("Investigate payments-api", "payments-api"),
        ("Why is bad-readiness not ready?", "bad-readiness"),
        ("Diagnose memory-hog", "memory-hog"),
        ("memory-hog keeps crashing, what is going on", "memory-hog"),
        ("Why is checkout failing?", "checkout"),
        ("Investigate checkout", "checkout"),
        ("Please debug the broken-image rollout", "broken-image"),
    ],
)
def test_a_named_resource_is_targeted_without_a_resource_noun(question, name):
    result = intent(question)

    assert result.scope is ScopeIntent.TARGETED
    assert result.target == WorkloadTarget(name, None)


@pytest.mark.parametrize(
    "question",
    [
        "Why are the pods failing?",
        "Why is the readiness probe failing?",
        "Why is latency high?",
        "Why is memory usage growing?",
        "Is the network healthy?",
        "Check the logs for errors",
        "Why are pods hitting out-of-memory kills?",
        "Is the read-only filesystem the problem?",
        "Check DATABASE_URL",
        "Why is MAX_RETRIES unset?",
        "Why does it say 'connection refused'?",
        "Review the deployment health and pod status",
        "Why is the pod failing?",
    ],
)
def test_unrelated_words_and_dns_like_vocabulary_are_not_workload_identities(question):
    result = intent(question)

    assert result.scope is not ScopeIntent.TARGETED and result.target is None


@pytest.mark.parametrize(
    "question",
    [
        "Investigate the health of the platform",
        "Investigate the ai-ops-demo namespace",
        "Why is everything failing in the namespace?",
        "Review all pods",
    ],
)
def test_explicitly_broad_questions_are_broad_and_say_so(question):
    result = intent(question)

    assert result.scope is ScopeIntent.BROAD_EXPLICIT and result.target is None


def test_a_question_naming_nothing_is_broad_but_unspecified():
    assert intent("Any problems?").scope is ScopeIntent.BROAD_UNSPECIFIED


@pytest.mark.parametrize(
    "question",
    [
        "Why is 'payments-api' failing?",
        'Check "payments-api"',
        "Why is `payments-api` failing?",
    ],
)
def test_quoted_identifiers_bind_the_unquoted_name(question):
    assert intent(question).target == WorkloadTarget("payments-api", None)


@pytest.mark.parametrize(
    "question",
    [
        "Why is payments_api failing?",
        "Investigate 'payments_api'",
        "Check the payments_api service",
        "Why is payments.api failing?" if False else "Check 'payments.api'",
    ],
)
def test_a_name_that_cannot_be_a_resource_name_requires_clarification(question):
    with pytest.raises(TargetQuestionError) as caught:
        intent(question)

    assert caught.value.code == "invalid_target_name"


def test_a_pod_name_is_an_identity_and_resolves_to_exactly_that_pod():
    pod = "payments-api-7d9f8c-x2x2x"
    result = intent(f"Investigate {pod}")

    assert result.target == WorkloadTarget(pod, None)

    resolution = resolve_target(
        result.target,
        [pod, "payments-api-7d9f8c-zzzzz"],
        {pod: PodOwner("Deployment", "payments-api", True)},
    )

    assert resolution.status is TargetStatus.RESOLVED
    assert resolution.pods == (pod,)


@pytest.mark.parametrize(
    "question",
    [
        "Compare payments-api and orders-api",
        "Why are payments-api and orders-api failing?",
        "Investigate payments-api and the orders-api workload",
    ],
)
def test_multiple_named_targets_are_rejected_not_guessed(question):
    with pytest.raises(TargetQuestionError) as caught:
        intent(question)

    assert caught.value.code == "multiple_targets"


def test_a_named_target_plus_a_request_for_the_rest_is_ambiguous():
    with pytest.raises(TargetQuestionError) as caught:
        intent("Why is payments-api failing, and is everything else healthy?")

    assert caught.value.code == "ambiguous_scope"


def test_all_pods_of_one_named_workload_is_still_that_workload():
    assert intent("Why are all pods of payments-api failing?").target == (
        WorkloadTarget("payments-api", None)
    )


def test_an_identifier_matching_a_pod_and_a_workload_is_ambiguous_at_resolution():
    owners = {
        "api": PodOwner("Pod", "api", True),
        "api-7d9f-xyz": PodOwner("Deployment", "api", True),
    }

    result = resolve_target(WorkloadTarget("api"), list(owners), owners)

    assert result.status is TargetStatus.AMBIGUOUS and result.pods == ()


@pytest.mark.parametrize(
    "question, code",
    [
        ("Compare payments-api and orders-api", "multiple_targets"),
        ("Why is payments-api failing and is everything else ok?", "ambiguous_scope"),
        ("Why is payments_api failing?", "invalid_target_name"),
    ],
)
def test_unbindable_questions_become_a_fixed_clarification_not_an_investigation(
    question, code
):
    with pytest.raises(InvestigationScopeCreationError) as caught:
        create_bound_investigation_context(question, namespace=NS)

    assert caught.value.code == code
    assert code in SCOPE_REJECTION_MESSAGES
    assert "payments" not in SCOPE_REJECTION_MESSAGES[code]


def test_every_question_error_code_has_a_fixed_response_message():
    for code in ("multiple_targets", "ambiguous_scope", "invalid_target_name"):
        assert SCOPE_REJECTION_MESSAGES[code]


def test_a_noun_less_named_workload_is_bound_and_only_it_is_inspected():
    run = investigate("Why is bad-readiness not ready?")

    assert run.ctx.target == WorkloadTarget("bad-readiness", None)
    assert run.snapshot.scope.status == "resolved"
    assert run.cluster.inspected_pods() == {BAD}


def test_a_named_workload_that_does_not_exist_is_a_limitation_never_a_broad_run():
    run = investigate("Why is payments-api failing?")  # only a -canary exists

    assert run.snapshot.scope.mode == "workload"
    assert run.snapshot.scope.status == "not_found"
    assert run.cluster.inspected_pods() == set()
    assert not run.cluster.called("k8s.describe_pod")
    assert any("could not be found" in u for u in run.report.uncertainties)


def test_an_unresolved_target_is_a_limitation_even_when_the_model_wanders():
    run = investigate(
        "Investigate checkout",
        proposals=(describe(BAD), describe(CANARY)),
    )

    assert run.snapshot.scope.status == "not_found"
    assert run.cluster.inspected_pods() == set()
    assert run.ctx.rejected_proposal_count == 1
    assert run.snapshot.scope.rejected_reasons == ("target_unresolved",)
    assert ("rejected", "target_unresolved") in {
        (e.phase, e.detail) for e in run.audit
    }


def test_an_explicitly_broad_investigation_says_broadness_was_asked_for():
    explicit = investigate("Investigate the health of the platform", max_steps=4)

    assert explicit.snapshot.scope.broad_explicit is True
    assert "asked about the namespace as a whole" in (explicit.report.summary or "")


def test_an_unspecified_question_is_refused_not_investigated_broadly():
    with pytest.raises(InvestigationScopeCreationError) as caught:
        create_bound_investigation_context("Any problems?", namespace=NS)

    assert caught.value.code == "scope_unspecified"


def test_namespace_authorization_is_unchanged_by_target_binding():
    with pytest.raises(InvestigationScopeCreationError) as caught:
        create_bound_investigation_context(
            "Why is payments-api failing in namespace kube-system?", namespace=NS
        )

    assert caught.value.code == "namespace_conflict"

    ctx = create_bound_investigation_context("Why is payments-api failing?", namespace=NS)

    with pytest.raises(Exception, match="outside the authorized"):
        ctx.validate_execution_scope(
            ToolCall(name="k8s.get_pods", arguments={"namespace": "kube-system"})
        )


# ================================================== Phase 2: audited rejections


def audit_pairs(run, tool, *, pod=None):
    return [
        e for e in run.audit
        if e.tool == tool and (pod is None or e.arguments.get("pod") == pod)
    ]


def test_out_of_target_proposal_is_audited_counted_disclosed_and_never_executed():
    run = investigate(
        TARGETED_BAD,
        proposals=(GET_PODS, describe(BROKEN)),
    )

    events = audit_pairs(run, "k8s.describe_pod", pod=BROKEN)

    assert [(e.phase, e.status, e.detail) for e in events] == [
        ("proposed", "received", None),
        ("rejected", "denied", "outside_target"),
    ]
    assert BROKEN not in run.cluster.inspected_pods()
    assert run.ctx.rejected_proposal_count == 1
    assert run.snapshot.scope.rejected_proposals == 1
    assert run.snapshot.scope.rejected_reasons == ("outside_target",)
    assert any(
        "refused before execution" in u and "outside_target" in u
        for u in run.report.uncertainties
    )


def test_the_investigation_continues_safely_after_a_rejection():
    run = investigate(
        TARGETED_BAD,
        proposals=(GET_PODS, describe(BROKEN)),
    )

    assert run.result.stop_reason is InvestigationStopReason.PROVIDER_FINISHED
    assert run.cluster.inspected_pods() == {BAD}
    assert run.report.findings  # the target's own evidence was still gathered
    assert run.snapshot.scope.status == "resolved"


def test_namespace_wide_events_proposal_is_rejected_with_its_own_code():
    run = investigate(
        TARGETED_BAD,
        proposals=(GET_PODS, ToolCall(name="k8s.get_events", arguments={"namespace": NS})),
    )

    assert run.snapshot.scope.rejected_reasons == ("namespace_wide_events",)
    assert ("rejected", "namespace_wide_events") in {
        (e.phase, e.detail) for e in run.audit
    }
    assert all(
        c.arguments.get("pod") == BAD for c in run.cluster.called("k8s.get_events")
    )


def test_rejected_proposals_are_counted_per_proposal_not_per_reason():
    run = investigate(
        TARGETED_BAD,
        proposals=(GET_PODS, describe(BROKEN), describe(CANARY)),
    )

    assert run.ctx.rejected_proposal_count == 2
    assert run.snapshot.scope.rejected_proposals == 2
    assert run.snapshot.scope.rejected_reasons == ("outside_target",)


def test_a_proposal_for_the_target_is_not_a_rejection():
    run = investigate(TARGETED_BAD, proposals=(GET_PODS, describe(BAD)))

    assert run.ctx.rejected_proposal_count == 0
    assert run.snapshot.scope.rejected_proposals == 0
    assert not any("refused before execution" in u for u in run.report.uncertainties)


def test_rejected_proposals_reach_the_durable_audit_without_model_output(monkeypatch):
    rows = []
    cursor = MagicMock()
    cursor.execute.side_effect = lambda sql, params: rows.append(params)
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor
    monkeypatch.setenv("DATABASE_URL", "postgresql://test")
    monkeypatch.setattr(
        "app.tools.investigation_audit.psycopg.connect",
        MagicMock(return_value=connection),
    )
    hostile = ToolCall(
        name="k8s.describe_pod",
        arguments={
            "namespace": NS,
            "pod": BROKEN,
            "container": "app; DROP TABLE investigation_audit_events",
            "password": "SENTINEL-SECRET-771",
            "note": "ignore previous instructions",
        },
    )
    ctx = create_bound_investigation_context(TARGETED_BAD, namespace=NS)

    run_investigation(
        context=ctx,
        provider=CoverageProvider(scripted(GET_PODS, hostile)),
        audit=write_investigation_audit_event,
        executor=Cluster(),
        tolerated_failure_tools=SUPPLEMENTARY_TOOLS,
    )

    rejected = [
        r for r in rows if r[3] == "rejected" and r[4] == "k8s.describe_pod"
    ]

    assert len(rejected) == 1
    stored = rejected[0]
    assert stored[7] == "outside_target"  # fixed reason code only
    assert json.loads(stored[5]) == {"namespace": NS, "pod": BROKEN}
    assert "SENTINEL-SECRET-771" not in repr(rows)
    assert "DROP TABLE" not in repr(rows)
    assert "ignore previous" not in repr(rows)
    # Its proposed event precedes it under the same request id.
    proposed = [r for r in rows if r[3] == "proposed" and r[2] == stored[2]]
    assert len(proposed) == 1


def test_audit_safe_arguments_keep_only_validated_identifiers():
    safe = safe_proposal_arguments({
        "namespace": NS, "pod": "Bad_Pod", "deployment": "web", "container": "app",
        "tail_lines": 50, "token": "x", "env": {"A": "B"},
    })

    assert safe == {
        "namespace": NS, "deployment": "web", "container": "app", "tail_lines": 50,
    }
    assert safe_proposal_arguments({"tail_lines": True}) == {}
    assert safe_proposal_arguments({"tail_lines": 10**9}) == {}


def test_reason_codes_are_a_fixed_vocabulary():
    assert REJECTION_REASONS == {
        "outside_target", "target_unresolved", "namespace_wide_events",
    }
    ctx = create_bound_investigation_context(TARGETED_BAD, namespace=NS)

    with pytest.raises(ValueError):
        ctx.note_rejected_proposal(GET_PODS, "because the model said so", audited=True)


def test_the_boundary_rejection_of_a_raw_provider_is_audited_and_not_fatal():
    ctx, audit, cluster = (
        create_bound_investigation_context(TARGETED_BAD, namespace=NS), [], Cluster(),
    )

    result = run_investigation(
        context=ctx,
        provider=scripted(GET_PODS, describe(BROKEN), describe(BAD)),
        audit=audit.append,
        executor=cluster,
    )

    rejected = [e for e in audit if e.phase == "rejected"]

    assert [(e.tool, e.detail) for e in rejected] == [
        ("k8s.describe_pod", "outside_target")
    ]
    assert BROKEN not in cluster.inspected_pods()
    assert cluster.inspected_pods() == {BAD}
    assert ctx.rejected_proposal_count == 1
    assert result.stop_reason is InvestigationStopReason.PROVIDER_FINISHED
    # Never authorized or started: it stopped at validation.
    assert not [
        e for e in audit
        if e.phase in {"authorized", "execution_started", "completed"}
        and e.arguments.get("pod") == BROKEN
    ]


def test_a_rejection_consumes_no_step_so_the_step_limit_still_binds():
    ctx, cluster = create_bound_investigation_context(
        TARGETED_BAD, namespace=NS, max_steps=2
    ), Cluster()

    result = run_investigation(
        context=ctx,
        provider=scripted(
            GET_PODS, describe(BROKEN), describe(BAD), describe(CANARY),
            ToolCall(name="k8s.get_events", arguments={"namespace": NS, "pod": BAD}),
        ),
        audit=[].append,
        executor=cluster,
    )

    assert ctx.completed_steps == 2
    assert result.stop_reason is InvestigationStopReason.STEP_BUDGET_EXHAUSTED
    assert len(cluster.calls) == 2
    assert ctx.rejected_proposal_count == 1


def test_a_model_that_keeps_proposing_out_of_target_calls_is_cut_off():
    ctx, audit, cluster = (
        create_bound_investigation_context(TARGETED_BAD, namespace=NS), [], Cluster(),
    )
    proposed = []

    def stubborn(_context, steps):
        proposed.append(1)

        return GET_PODS if not steps else describe(BROKEN)

    result = run_investigation(
        context=ctx, provider=stubborn, audit=audit.append, executor=cluster,
    )

    assert result.stop_reason is InvestigationStopReason.PROVIDER_FINISHED
    assert ctx.rejected_proposal_count == MAX_REJECTED_PROPOSALS
    assert len([e for e in audit if e.phase == "rejected"]) == MAX_REJECTED_PROPOSALS
    assert len(proposed) == 1 + MAX_REJECTED_PROPOSALS
    assert cluster.inspected_pods() == set()
    assert ctx.completed_steps == 1


def test_each_boundary_rejection_has_its_own_request_id_and_steps_keep_their_numbering():
    ctx, audit = create_bound_investigation_context(TARGETED_BAD, namespace=NS), []

    run_investigation(
        context=ctx,
        provider=scripted(
            GET_PODS, describe(BROKEN), describe(CANARY), describe(BAD)
        ),
        audit=audit.append,
        executor=Cluster(),
        request_id_factory=lambda: "run",
    )

    rejected_ids = [e.request_id for e in audit if e.phase == "rejected"]
    proposed_ids = {
        e.request_id for e in audit
        if e.phase == "proposed" and e.arguments.get("pod") in {BROKEN, CANARY}
    }

    assert len(set(rejected_ids)) == 2
    assert proposed_ids == set(rejected_ids)  # proposed/rejected pair up per proposal
    # An executed step keeps a stable, qualified id; no id is ever shared.
    assert "run-step-1" in {e.request_id for e in audit}
    ids_by_call = {(e.request_id, e.tool) for e in audit if e.phase == "completed"}
    assert len({i for i, _ in ids_by_call}) == len(ids_by_call)


def test_the_coverage_policy_stops_consulting_a_model_at_the_rejection_limit():
    ctx = create_bound_investigation_context(TARGETED_BAD, namespace=NS)
    cluster = Cluster()
    listing = execute_investigation_step(
        context=ctx, request_id="r-list", proposed_call=GET_PODS,
        audit=[].append, executor=cluster,
    )
    steps = (InvestigationStep("r-list", GET_PODS, listing),)

    for _ in range(MAX_REJECTED_PROPOSALS):
        ctx.note_rejected_proposal(describe(BROKEN), "outside_target", audited=True)

    consulted = []

    def inner(*_):
        consulted.append(1)

        return describe(BROKEN)

    proposal = CoverageProvider(inner)(ctx, steps)

    assert not consulted
    # Only deterministic coverage of the target remains.
    assert proposal is None or proposal.arguments.get("pod") == BAD


def test_a_failed_audit_write_for_a_rejection_stops_the_run_before_anything_else():
    ctx, cluster = create_bound_investigation_context(TARGETED_BAD, namespace=NS), Cluster()

    def failing_sink(event_):
        if event_.phase == "rejected":
            raise RuntimeError("audit store unavailable")

    with pytest.raises(RuntimeError, match="audit store unavailable"):
        run_investigation(
            context=ctx,
            provider=CoverageProvider(scripted(GET_PODS, describe(BROKEN))),
            audit=failing_sink,
            executor=cluster,
            tolerated_failure_tools=SUPPLEMENTARY_TOOLS,
        )

    assert BROKEN not in cluster.inspected_pods()


def test_namespace_violations_remain_fatal_and_are_not_counted_as_rejections():
    ctx = create_bound_investigation_context(TARGETED_BAD, namespace=NS)

    with pytest.raises(Exception, match="outside the authorized"):
        run_investigation(
            context=ctx,
            provider=scripted(
                ToolCall(name="k8s.get_pods", arguments={"namespace": "kube-system"})
            ),
            audit=[].append,
            executor=Cluster(),
        )

    assert ctx.rejected_proposal_count == 0


def test_mutating_and_unlisted_tools_remain_fatal_at_the_boundary():
    ctx = create_bound_investigation_context(TARGETED_BAD, namespace=NS)
    cluster = Cluster()

    with pytest.raises(Exception, match="allowlist"):
        run_investigation(
            context=ctx,
            provider=scripted(
                ToolCall(name="k8s.delete_pod", arguments={"namespace": NS, "pod": BAD})
            ),
            audit=[].append,
            executor=cluster,
        )

    assert cluster.calls == []


# ------------------------------------------------------- the audit boundary


def _replica_pod(name, replica_set, uid):
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name=name, namespace=NS,
            owner_references=[SimpleNamespace(
                kind="ReplicaSet", name=replica_set, controller=True, uid=uid,
            )],
        ),
        spec=SimpleNamespace(node_name="n1"),
        status=SimpleNamespace(phase="Running", pod_ip="10.0.0.1", container_statuses=[]),
    )


def _fake_clients(replica_sets):
    reads = []

    def read_replica_set(*, name, namespace, **_):
        reads.append((name, namespace))

        return SimpleNamespace(metadata=SimpleNamespace(
            name=name, namespace=namespace, uid=f"uid-{name}",
            owner_references=[SimpleNamespace(
                kind="Deployment", name=name.rsplit("-", 1)[0], controller=True,
            )],
        ))

    pods = [_replica_pod(f"{rs}-p", rs, f"uid-{rs}") for rs in replica_sets]
    core = SimpleNamespace(list_namespaced_pod=lambda **_: SimpleNamespace(
        items=pods, metadata=SimpleNamespace(_continue=None)))
    apps = SimpleNamespace(read_namespaced_replica_set=read_replica_set)

    return core, apps, reads


def test_audit_boundary_owner_lookups_are_inside_one_get_pods_event_set():
    """The audit trail records TOOL CALLS, not the Kubernetes requests a
    handler makes. A get_pods call is one proposed/authorized/started/completed
    set; the one list request plus the bounded ReplicaSet reads inside it are
    NOT individually audited. They are namespace-bound and capped."""
    names = [f"app{i}-5d9f" for i in range(MAX_OWNER_LOOKUPS_PLUS_ONE)]
    core, apps, reads = _fake_clients(names)
    ctx, audit = create_bound_investigation_context(TARGETED_BAD, namespace=NS), []

    with patch.object(handlers, "core_v1", return_value=core), patch.object(
        handlers, "apps_v1", return_value=apps
    ):
        execute_investigation_step(
            context=ctx, request_id="r-list", proposed_call=GET_PODS,
            audit=audit.append,
        )

    assert [e.phase for e in audit] == [
        "proposed", "authorized", "execution_started", "completed",
    ]
    assert {e.tool for e in audit} == {"k8s.get_pods"}
    assert len(reads) == handlers.MAX_OWNER_LOOKUPS  # capped, one per ReplicaSet
    assert {namespace for _name, namespace in reads} == {NS}
    assert len(audit) < len(reads) + 1  # reads are demonstrably not 1:1 audited


def test_owner_lookups_beyond_the_cap_leave_pods_unverified_never_guessed():
    names = [f"app{i}-5d9f" for i in range(MAX_OWNER_LOOKUPS_PLUS_ONE)]
    core, apps, _reads = _fake_clients(names)
    ctx = create_bound_investigation_context("Investigate app0", namespace=NS)

    with patch.object(handlers, "core_v1", return_value=core), patch.object(
        handlers, "apps_v1", return_value=apps
    ):
        execute_investigation_step(
            context=ctx, request_id="r-list", proposed_call=GET_PODS,
            audit=[].append,
        )

    last = ctx.target_resolution
    last_ctx = create_bound_investigation_context(
        f"Investigate app{MAX_OWNER_LOOKUPS_PLUS_ONE - 1}", namespace=NS
    )

    with patch.object(handlers, "core_v1", return_value=core), patch.object(
        handlers, "apps_v1", return_value=apps
    ):
        execute_investigation_step(
            context=last_ctx, request_id="r-list", proposed_call=GET_PODS,
            audit=[].append,
        )

    # app0 is within the cap and verified; the last is beyond it and unverifiable.
    assert last.status is TargetStatus.RESOLVED
    assert last_ctx.target_resolution.status is TargetStatus.UNVERIFIABLE


MAX_OWNER_LOOKUPS_PLUS_ONE = handlers.MAX_OWNER_LOOKUPS + 1


# ============================================= Phase 3: ties keep model order


def _tied(run):
    """Three hypotheses the application cannot tell apart (same group, same
    evidence tier), worded so alphabetical order differs from generation order."""
    return parse(
        run,
        hypo(run, "Zeta behaviour in an unrelated subsystem may be involved."),
        hypo(run, "Alpha behaviour in an unrelated subsystem may be involved."),
        hypo(run, "Mid behaviour in an unrelated subsystem may be involved."),
    ).hypotheses


def _ranked_run():
    return investigate(
        TARGETED_BAD,
        Cluster([not_ready_pod(events=[event("Warning", "Unhealthy", 14, BAD)])]),
    )


def ranked(run, hypotheses):
    return [
        h.possible_explanation for h in rank_hypotheses(hypotheses, registry_for(run))
    ]


def test_equal_evidence_hypotheses_keep_the_models_order_not_alphabetical_order():
    run = _ranked_run()
    tied = _tied(run)

    assert len(tied) == 3
    assert ranked(run, tied) == [h.possible_explanation for h in tied]
    assert ranked(run, tied)[0].startswith("Zeta")  # alphabetical would be Alpha


def test_every_ordering_of_tied_hypotheses_is_preserved():
    run = _ranked_run()

    for permutation in itertools.permutations(_tied(run)):
        assert ranked(run, list(permutation)) == [
            h.possible_explanation for h in permutation
        ]


def test_evidence_tiers_still_override_model_order_and_ties_stay_in_model_order():
    run = _ranked_run()
    state = [ev(run, "containers[app].ready"), ev(run, "containers[app].state")]
    probe = [
        ev(run, "events[Unhealthy].count", "k8s.get_events"),
        ev(run, "containers[app].readiness_probe.declared",
           "k8s.describe_workload_config"),
    ]
    batch = parse(
        run,
        hypo(run, "Zeta behaviour in an unrelated subsystem may be involved.",
             evidence=state),
        hypo(run, "Alpha behaviour in an unrelated subsystem may be involved.",
             evidence=state),
        hypo(run, "The readiness probe may be failing.", evidence=state + probe),
    ).hypotheses

    assert ranked(run, batch) == [
        "The readiness probe may be failing.",
        "Zeta behaviour in an unrelated subsystem may be involved.",
        "Alpha behaviour in an unrelated subsystem may be involved.",
    ]


def test_ranking_carries_no_score_or_confidence():
    run = _ranked_run()

    assert not hasattr(_tied(run)[0], "confidence")
    assert not hasattr(_tied(run)[0], "score")
    assert GENERIC  # imported fixture text still valid for the shared harness
