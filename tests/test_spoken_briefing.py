"""Spoken briefings stay short, and they stay inside the validated report.

The OOMKilled, image-pull, scheduling, readiness, crash-loop, and volume cases
run the real report builder against fake Kubernetes objects. Only the spoken
text is under test. Workload names here are fixtures, not assumptions baked
into the briefing.
"""

import re

from app.reports.models import AIHypothesis, EvidenceReference, HypothesisResource, InvestigationFinding, InvestigationReport, SchedulingConstraint
from app.speech.briefing import build_spoken_briefing
from tests.pod_scenarios import (
    NS,
    Cluster,
    container_spec,
    container_status,
    event,
    investigate,
    pod,
    volume,
)

_WORD = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*")
_BANNED = (
    "Spoken briefing",
    "The primary verified finding is",
    "The most relevant AI hypothesis",
    "unverified, not a verified finding",
    "It suggests",
    "A read-only check to consider",
    "No AI hypothesis was accepted",
)
SCHED_SENTINEL = "SENTINEL-SCHED-SHOULD-NOT-BE-SPOKEN"
MOUNT_SENTINEL = "private-object-name"
IMAGE_SENTINEL = "ghost.example.invalid/app:999"


def words(text: str) -> int:
    return len(_WORD.findall(text))


def assert_speakable(text: str) -> None:
    assert text.endswith(".")
    assert "..." not in text
    assert "kubectl" not in text

    for phrase in _BANNED:
        assert phrase not in text

    for sentence in text.split(". "):
        assert sentence.strip()
        assert not sentence.endswith(",")

    lowered = text.lower()
    assert "termination termination" not in lowered
    assert "one three seven" not in lowered
    assert ", configuration," not in lowered


def speak(report, *, name: str, kind: str = "Deployment", stop_reason: str = "provider_finished") -> str:
    return build_spoken_briefing(
        status="completed",
        stop_reason=stop_reason,
        namespace=NS,
        scope_mode="workload",
        scope_kind=kind,
        scope_name=name,
        report=report,
    )


def accept(report, explanation: str, check: str | None, pod_name: str):
    evidence = next(ref.evidence_id for finding in report.findings for ref in finding.evidence)
    hypothesis = AIHypothesis(
        explanation="Possible explanation, unverified.",
        possible_explanation=explanation,
        not_yet_verified="This has not been checked against another observation.",
        evidence_refs=[evidence],
        resource=HypothesisResource(namespace=NS, pod=pod_name, container="app"),
        verification_check=check,
        check_withheld_reason=None if check else "remediation_in_check",
    )

    return report.model_copy(update={"ai_hypotheses": [hypothesis]})


def test_oomkilled_briefing_states_the_termination_without_the_paragraph():
    pod_name = "payments-api-5d6b7c8d9-k7m2p"
    cluster = Cluster(
        [
            pod(
                pod_name,
                phase="Running",
                scheduled=("True", None),
                containers=[container_spec(memory_limit="32Mi", memory_request="16Mi")],
                statuses=[
                    container_status(
                        ready=False,
                        restarts=5,
                        state="waiting",
                        reason="CrashLoopBackOff",
                        last_exit=137,
                        last_reason="OOMKilled",
                    )
                ],
            )
        ]
    )
    _ctx, _snapshot, report, _audit = investigate(cluster)
    text = speak(
        accept(
            report,
            "The process may be retaining more memory than the limit allows.",
            "Compare the declared memory limit with recent container usage.",
            pod_name,
        ),
        name="payments-api",
    )

    assert_speakable(text)
    verified = text.split("A possible explanation is")[0]
    assert "payments-api-5d6b7c8d9-k7m2p" not in text
    assert "namespace" not in text.lower()
    assert "Container app in Deployment payments-api" in text
    assert "killed for running out of memory" in text
    assert "crash-looping" in text
    assert "exit code 137" in text
    assert "32 mebibytes" in text
    assert "That is not a measurement of how much memory was used." in text
    assert "exceeded" not in verified.lower()
    assert "OOMKilled" not in text
    assert "32Mi" not in text
    assert "CrashLoopBackOff" not in text
    assert "A possible explanation is" in text
    assert text.index("killed for running out of memory") < text.index("A possible explanation")
    assert "Next, compare the declared memory limit" in text
    assert 40 <= words(text) <= 75


def test_image_pull_briefing_does_not_invent_a_missing_image():
    pod_name = "checkout-img-6c8d9e0f1-q4w2r"
    cluster = Cluster(
        [
            pod(
                pod_name,
                phase="Pending",
                scheduled=("True", None),
                statuses=[
                    container_status(ready=False, restarts=0, state="waiting", reason="ImagePullBackOff")
                ],
            )
        ]
    )
    _ctx, _snapshot, report, _audit = investigate(cluster)
    plain = speak(report, name="checkout-img")
    text = speak(
        accept(
            report,
            "The image tag may not exist in the registry.",
            "Compare the declared image reference with the registry tags.",
            pod_name,
        ),
        name="checkout-img",
    )

    assert_speakable(plain)
    assert_speakable(text)
    assert "has not started" in text
    assert "pulling the image failed" in text
    assert "backing off" in text
    assert "ImagePullBackOff" not in text
    assert "image pull back-off" not in plain or "pulling the image failed" in plain
    assert "does not exist" not in plain
    assert "free text" not in text
    assert IMAGE_SENTINEL not in text
    assert "A possible explanation is" in text
    assert "hasn't been confirmed" in plain
    assert "A possible explanation" not in plain
    assert "checkout-img" in text
    assert 40 <= words(text) <= 75


def test_unschedulable_briefing_uses_the_classified_constraint_only():
    pod_name = "worker-big"
    message = (
        "0/1 nodes are available: 1 Insufficient memory. preemption: 0/1 nodes are "
        f"available: 1 No preemption victims found for incoming pod. {SCHED_SENTINEL}"
    )
    cluster = Cluster(
        [
            pod(
                pod_name,
                scheduler_message=message,
                containers=[container_spec(memory_request="900Gi")],
            )
        ],
        {
            pod_name: [
                event(
                    pod_name=pod_name,
                    reason="FailedScheduling",
                    message=message,
                    component="default-scheduler",
                )
            ]
        },
    )
    _ctx, _snapshot, report, _audit = investigate(cluster)
    text = speak(
        accept(
            report,
            "The pod memory request may be larger than any node can provide.",
            "Inspect the pod memory request and the node allocatable memory.",
            pod_name,
        ),
        name=pod_name,
        kind="Pod",
    )

    assert_speakable(text)
    assert "Pod worker-big could not be scheduled" in text
    assert "namespace" not in text.lower()
    assert "insufficient memory" in text
    assert "Container app" not in text
    assert "no container has run" in text
    assert SCHED_SENTINEL not in text
    assert "0/1 nodes" not in text
    assert "preemption" not in text
    assert "A possible explanation is" in text
    assert "worker-big" in text
    assert "900Gi" not in text
    assert "900 gibibytes" not in text or "memory request" in text
    assert 40 <= words(text) <= 75


def test_readiness_briefing_does_not_treat_a_probe_path_as_verified():
    pod_name = "ledger-api-7b8c9d0e1-n5p3s"
    cluster = Cluster(
        [
            pod(
                pod_name,
                phase="Running",
                scheduled=("True", None),
                statuses=[container_status(ready=False, restarts=0, state="running", reason=None)],
            )
        ]
    )
    _ctx, _snapshot, report, _audit = investigate(cluster)
    text = speak(
        accept(
            report,
            "The readiness probe may be failing because its path is wrong.",
            "Inspect the declared readiness probe path and port.",
            pod_name,
        ),
        name="ledger-api",
    )

    assert_speakable(text)
    assert "is running but not ready" in text
    assert "readiness is false" in text
    assert "not receiving traffic" in text
    assert "A possible explanation is" in text
    assert text.index("is running but not ready") < text.index("path is wrong")
    assert "Next, inspect the declared readiness probe" in text
    assert "ledger-api" in text
    verified = text.split("A possible explanation is")[0]
    assert "path is wrong" not in verified
    assert 40 <= words(text) <= 75


def test_volume_mount_briefing_does_not_read_the_kubelet_message():
    pod_name = "archive-api"
    message = (
        'MountVolume.SetUp failed for volume "cfg" : configmap '
        f'"{MOUNT_SENTINEL}" not found'
    )
    cluster = Cluster(
        [
            pod(
                pod_name,
                scheduled=("True", None),
                statuses=[container_status()],
                volumes=[volume("cfg")],
                age=120,
            )
        ],
        {
            pod_name: [
                event(pod_name=pod_name, reason="FailedMount", message=message, component="kubelet")
            ]
        },
    )
    _ctx, _snapshot, report, _audit = investigate(cluster)
    text = speak(report, name=pod_name, kind="Pod")

    assert_speakable(text)
    assert "volume failed to mount" in text
    assert "was scheduled" in text
    assert MOUNT_SENTINEL not in text
    assert "MountVolume" not in text
    assert "hasn't been confirmed" in text
    assert "archive-api" in text
    assert "Next, confirm that each declared volume refers to an object that exists." in text
    assert "Secret" not in text


def test_crash_loop_without_an_oom_does_not_become_an_out_of_memory_story():
    pod_name = "notifier-api-8c9d0e1f2-h6j4k"
    cluster = Cluster(
        [
            pod(
                pod_name,
                phase="Running",
                scheduled=("True", None),
                statuses=[
                    container_status(
                        ready=False,
                        restarts=4,
                        state="waiting",
                        reason="CrashLoopBackOff",
                        last_exit=1,
                        last_reason="Error",
                    )
                ],
                containers=[container_spec()],
                age=900,
            )
        ]
    )
    _ctx, _snapshot, report, _audit = investigate(cluster)
    text = speak(report, name="notifier-api")

    assert_speakable(text)
    assert "crash-looping" in text or "crash loop back-off" in text
    assert "out of memory" not in text
    assert "out-of-memory" not in text
    assert "OOMKilled" not in text
    assert "CrashLoopBackOff" not in text
    assert "hasn't been confirmed" in text
    assert "notifier-api" in text
    assert "probe" not in text.lower()
    assert "image pull" not in text.lower()


def test_a_long_hypothesis_is_left_out_whole():
    finding = InvestigationFinding(
        title="Container is running but not ready",
        description="Container 'app' is running but not ready. Resource: namespace 'ai-ops-demo', pod 'ledger-api-aaa'.",
        severity="warning",
        evidence=[EvidenceReference(evidence_id="ev-0004")],
    )
    padding = " ".join(["slowly"] * 28)
    report = InvestigationReport(
        investigation_id="inv-long",
        summary="Verified findings only.",
        findings=[finding],
        ai_hypotheses=[
            AIHypothesis(
                explanation="Possible explanation, unverified.",
                possible_explanation=(
                    f"The process may be retaining buffers {padding} until the limit is crossed."
                ),
                not_yet_verified="The buffer growth has not been measured.",
                evidence_refs=["ev-0004"],
                resource=HypothesisResource(namespace=NS, pod="ledger-api-aaa", container="app"),
                verification_check="Inspect the declared readiness probe.",
            )
        ],
    )
    text = speak(report, name="ledger-api")

    assert_speakable(text)
    assert "slowly" not in text
    assert "The underlying cause hasn't been confirmed." in text
    assert "Next, inspect the declared readiness probe." in text


def test_a_generic_runtime_failure_is_not_given_an_oom_cause():
    finding = InvestigationFinding(
        title="Container failed at runtime",
        description=(
            "Container 'worker' started and then failed: Kubernetes reports it not ready, "
            "state 'terminated', reason 'Error'. Its previous termination reported "
            "reason 'Error' and exit code 1. Resource: namespace 'ai-ops-demo', pod 'batch-job-0'."
        ),
        severity="warning",
        evidence=[EvidenceReference(evidence_id="ev-0006")],
    )
    report = InvestigationReport(
        investigation_id="inv-generic",
        summary="Verified findings only.",
        findings=[finding],
    )
    text = speak(report, name="batch-job", kind="Pod")

    assert_speakable(text)
    assert "failed after it started" in text
    assert "out of memory" not in text
    assert "out-of-memory" not in text
    assert "batch-job-0" in text
    assert "hasn't been confirmed" in text


def test_quantity_pronunciation_does_not_rewrite_a_hyphenated_name():
    finding = InvestigationFinding(
        title="Container previously terminated as OOMKilled",
        description=(
            "Kubernetes reported that container 'app' was previously terminated with "
            "reason 'OOMKilled' (exit code 137), meaning it was killed for running out of memory. "
            "The pod spec declares a memory limit of 32Mi. "
            "Resource: namespace 'ai-ops-demo', pod 'cache-32Mi-abc'."
        ),
        severity="warning",
        evidence=[EvidenceReference(evidence_id="ev-0007")],
    )
    report = InvestigationReport(
        investigation_id="inv-name",
        summary="Verified findings only.",
        findings=[finding],
    )
    text = speak(report, name="cache-32Mi-abc", kind="Pod")

    assert "cache-32Mi-abc" in text
    assert "32 mebibytes" in text
    assert "OOMKilled" not in text
    assert "termination termination" not in text.lower()


def test_several_scheduling_constraints_are_not_reduced_to_one_cause():
    finding = InvestigationFinding(
        title="Pod could not be scheduled",
        description="Pod 'worker-big' is Pending and could not be scheduled.",
        severity="critical",
        evidence=[EvidenceReference(evidence_id="ev-0008"), EvidenceReference(evidence_id="ev-0009")],
        scheduling_constraints=[
            SchedulingConstraint(signal="insufficient_memory", label="Insufficient memory", evidence_ids=["ev-0008"]),
            SchedulingConstraint(signal="untolerated_taint", label="Untolerated node taints", evidence_ids=["ev-0009"]),
        ],
    )
    report = InvestigationReport(
        investigation_id="inv-sched",
        summary="Verified findings only.",
        findings=[finding],
    )
    text = speak(report, name="worker-big", kind="Pod")

    assert "2 scheduling constraints, including insufficient memory" in text
    assert "only cause" not in text
    assert "Untolerated node taints" not in text.split("including")[0]


def test_a_historical_restart_is_not_spoken_as_a_current_failure():
    finding = InvestigationFinding(
        title="Container restarted earlier and is running now",
        description=(
            "Container 'app' is running and ready now. Kubernetes records 3 earlier restarts. "
            "Resource: namespace 'ai-ops-demo', pod 'ledger-api-7b8c9d0e1-n5p3s'."
        ),
        severity="warning",
        evidence=[EvidenceReference(evidence_id="ev-0012")],
    )
    report = InvestigationReport(
        investigation_id="inv-restart",
        summary="Verified findings only.",
        findings=[finding],
    )
    text = speak(report, name="ledger-api")

    assert_speakable(text)
    assert "is running now" in text
    assert "earlier restart" in text
    assert "not established" in text
    assert "ledger-api-7b8c9d0e1-n5p3s" not in text
    assert "crash-looping" not in text


def test_oomkilled_termination_is_not_doubled_when_the_hypothesis_uses_both_words():
    finding = InvestigationFinding(
        title="Container previously terminated as OOMKilled",
        description=(
            "Kubernetes reported that container 'app' was previously terminated with "
            "reason 'OOMKilled' (exit code 137), meaning it was killed for running out of memory. "
            "Resource: namespace 'ai-ops-demo', pod 'payments-api-5d6b7c8d9-k7m2p'."
        ),
        severity="critical",
        evidence=[EvidenceReference(evidence_id="ev-0011")],
    )
    report = InvestigationReport(
        investigation_id="inv-double",
        summary="Verified findings only.",
        findings=[finding],
        ai_hypotheses=[
            AIHypothesis(
                explanation="Possible explanation, unverified.",
                possible_explanation="The OOMKilled termination may have followed a memory leak.",
                not_yet_verified="No memory profile has been compared with the termination.",
                evidence_refs=["ev-0011"],
                resource=HypothesisResource(namespace=NS, pod="payments-api-5d6b7c8d9-k7m2p", container="app"),
                verification_check="Read the container's recent application logs.",
            )
        ],
    )
    text = speak(report, name="payments-api")

    assert_speakable(text)
    assert "termination termination" not in text.lower()
    assert "out-of-memory kill termination" not in text.lower()
    assert "A possible explanation is" in text
    assert "memory leak" in text
    assert "payments-api-5d6b7c8d9-k7m2p" not in text


def test_a_verbose_log_check_is_spoken_without_the_replica_or_the_tool():
    pod_name = "payments-api-5d6b7c8d9-k7m2p"
    cluster = Cluster(
        [
            pod(
                pod_name,
                phase="Running",
                scheduled=("True", None),
                containers=[container_spec(memory_limit="32Mi")],
                statuses=[
                    container_status(
                        ready=False,
                        restarts=5,
                        state="waiting",
                        reason="CrashLoopBackOff",
                        last_exit=137,
                        last_reason="OOMKilled",
                    )
                ],
            )
        ]
    )
    _ctx, _snapshot, report, _audit = investigate(cluster)
    text = speak(report, name="payments-api")

    assert_speakable(text)
    assert "Next, read the container's recent application logs." in text
    assert pod_name not in text
    assert "tool" not in text.lower()
    assert "That is not a measurement of how much memory was used." in text
    assert "hasn't been confirmed" in text


def test_a_command_check_is_not_replaced_with_a_different_action():
    finding = InvestigationFinding(
        title="Container is running but not ready",
        description="Container 'app' is running but not ready. Resource: namespace 'ai-ops-demo', pod 'ledger-api-aaa'.",
        severity="warning",
        evidence=[EvidenceReference(evidence_id="ev-0010")],
    )
    report = InvestigationReport(
        investigation_id="inv-check",
        summary="Verified findings only.",
        findings=[finding],
        suggested_checks=["Run kubectl delete pod ledger-api-aaa"],
        ai_hypotheses=[
            AIHypothesis(
                explanation="Possible explanation, unverified.",
                possible_explanation="The readiness probe may be aimed at the wrong port.",
                not_yet_verified="The port has not been compared with the process.",
                evidence_refs=["ev-0010"],
                resource=HypothesisResource(namespace=NS, pod="ledger-api-aaa", container="app"),
                verification_check="Run kubectl describe pod ledger-api-aaa",
            )
        ],
    )
    text = speak(report, name="ledger-api")

    assert "kubectl" not in text
    assert "delete" not in text
    assert "describe" not in text
    assert "hasn't been confirmed" not in text or "A possible explanation is" in text
    assert "wrong port" in text
    assert not text.startswith("Next")
