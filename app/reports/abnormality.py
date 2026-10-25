"""The established abnormality, written by the application for the hypothesis stage.

Given the flat evidence snapshot a model tends to fill its quota of hypotheses
with plausible Kubernetes problems that are unrelated to this failure (a
scheduling constraint for a pod that WAS scheduled, a probe for a pod that
declares none). It is told, per pod and container, in a fixed vocabulary:

  * which STAGE of the pod lifecycle is abnormal (scheduling, volume mount,
    image pull, container creation, container runtime, readiness, past
    restart), with the Kubernetes reason and the previous termination;
  * which stages COMPLETED (so no hypothesis may claim a failure there);
  * which declarations are verified ABSENT (so none may be blamed);
  * what the abnormality does and does not establish (the termination reason's
    meaning; what remains unestablished).

Every statement is a pure function of application-minted observations. It
names no cause, so it never reduces the model's room to propose one: an
unfamiliar cause is still welcome when an observation supports it. It grants no
trust and changes no validation (see `stage_consistency` for the narrow
contradictions the application enforces itself); it only organises what the
model is shown.
"""

from typing import Any

from app.reports.health_grounding import _collect
from app.reports.pod_health_grounding import classify_pods, collect_pod_facts
from app.reports.probe_declarations import describe_pod_probe, describe_readiness
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.reports.config_grounding import collect_configuration
from app.tools.container_health import HealthCategory, classify_container
from app.tools.pod_health import PodCategory

MAX_ITEMS = 10

IMAGE_REASONS = frozenset(
    {
        "ImagePullBackOff",
        "ErrImagePull",
        "ErrImageNeverPull",
        "InvalidImageName",
        "ImageInspectError",
        "RegistryUnavailable",
    }
)

# What each stage establishes and what it does not (application-authored).
STAGE_MEANING = {
    "scheduling": (
        "The scheduler could not place the pod on any node, so no container "
        "exists. The constraints the scheduler reported are listed."
    ),
    "volume_mount": (
        "The pod was scheduled but Kubernetes records volume mount failures, "
        "so its containers cannot be created and none ran."
    ),
    "image_pull": (
        "Pulling the container image failed, so the container never ran. This "
        "names the failed operation, not why it failed."
    ),
    "container_creation": (
        "The container could not be created, so it never ran. This names the "
        "failed operation, not why it failed."
    ),
    "readiness": (
        "The container is running but Kubernetes reports it not ready, so it "
        "receives no traffic. Readiness never restarts a container."
    ),
    "past_restart": (
        "The container is running and ready now. Kubernetes records that it "
        "was restarted after the previous termination below; the restart is "
        "history, not a current failure."
    ),
    "container_runtime": (
        "The container ran and then terminated or is crash-looping. The "
        "previous termination below is established; its underlying cause is "
        "not."
    ),
}

OPEN_QUESTION = {
    "scheduling": "why the scheduler could not place the pod beyond the constraints it reported",
    "volume_mount": "why the volume mount failed",
    "image_pull": "why the image pull failed",
    "container_creation": "why the container could not be created",
    "readiness": "why Kubernetes reports the container not ready",
    "past_restart": "why the container was restarted",
    "container_runtime": "why the container terminated",
}

# What a termination reason means. Kubernetes' own vocabulary; no cause beyond
# what the reason itself says.
TERMINATION_MEANING = {
    "OOMKilled": (
        "The kernel's out-of-memory killer terminated the container's process: "
        "a memory event. It is not a probe, image-pull or scheduling event."
    ),
    "Completed": (
        "The process ended with exit code 0, reporting no error. That does "
        "not by itself show a crash, an out-of-memory kill or resource "
        "exhaustion. Kubernetes restarts an exited container according to the "
        "pod's restart policy, which was not observed."
    ),
    "Error": (
        "The process exited with a non-zero exit code. Kubernetes does not "
        "report why."
    ),
}


def _ids(*groups: list[str | None]) -> list[str]:
    seen: dict[str, None] = {}

    for group in groups:
        for ref in group:
            if ref:
                seen.setdefault(ref)

    return list(seen)


def _container_stage(assessment, values: dict[str, Any]) -> str | None:
    category = assessment.category

    if category is HealthCategory.PRE_START_FAILURE:
        return "image_pull" if assessment.reason in IMAGE_REASONS else "container_creation"

    if category is HealthCategory.RUNTIME_FAILURE:
        return "container_runtime"

    if category is HealthCategory.NOT_READY:
        return "readiness"

    if category is HealthCategory.RESTARTED_RUNNING:
        return "past_restart"

    return None


def _completed_stages(pod_facts, container, assessment) -> list[dict[str, Any]]:
    done: list[dict[str, Any]] = []
    scheduled = pod_facts.scheduled_status if pod_facts else None

    if scheduled is not None and scheduled[0] == "True":
        done.append(
            {
                "stage": "scheduling",
                "statement": "the pod was scheduled to a node",
                "evidence_ids": [scheduled[1]],
            }
        )

    if container is None:
        return done

    refs, values = container.refs, container.values
    started = (
        assessment.ran_before
        or values.get("state") in {"running", "terminated"}
    )

    if started:
        proof = _ids(
            [refs.get("last_termination.reason")]
            if assessment.ran_before and "last_termination.reason" in refs
            else [refs.get("restart_count")] if assessment.ran_before else [],
            [refs.get("state")] if values.get("state") == "running" else [],
        )
        done.append(
            {
                "stage": "container_started",
                "statement": "the image was pulled and the container started",
                "evidence_ids": proof[:3],
            }
        )

    if values.get("state") == "running" and values.get("ready") is True:
        done.append(
            {
                "stage": "readiness",
                "statement": "the container is ready now",
                "evidence_ids": _ids([refs.get("ready")]),
            }
        )

    return done


def _declared_absent(
    snapshot, key, name, pod_facts, config
) -> list[dict[str, Any]]:
    absent: list[dict[str, Any]] = []

    for label, found in (
        ("liveness_probe", describe_pod_probe(snapshot, key, name, "liveness")),
        ("readiness_probe", describe_readiness(snapshot, key, name, config)),
    ):
        if found is not None and found[0].startswith("declares no "):
            absent.append({"item": label, "evidence_ids": found[1][:1]})

    return absent


def _placement_absent(pod_facts) -> list[dict[str, Any]]:
    absent: list[dict[str, Any]] = []

    if pod_facts is None:
        return absent

    for label, fact in (
        ("node_selector", pod_facts.node_selector),
        ("affinity", pod_facts.affinity),
    ):
        if fact is not None and fact[0] is False:
            absent.append({"item": label, "evidence_ids": [fact[1]]})

    return absent


def build_established_abnormality(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[dict[str, Any]]:
    """One entry per abnormal pod or container, in a fixed vocabulary."""
    containers = _collect(snapshot)
    pods = classify_pods(snapshot)
    facts = collect_pod_facts(snapshot)
    configuration, _ = collect_configuration(snapshot)
    items: list[dict[str, Any]] = []

    # Pod-level: the pod never ran.
    for (namespace, pod), (assessment, pod_facts) in sorted(pods.items()):
        unschedulable = assessment.category is PodCategory.UNSCHEDULABLE
        stage = "scheduling" if unschedulable else "volume_mount"
        item: dict[str, Any] = {
            "namespace": namespace,
            "pod": pod,
            "container": None,
            "abnormal_stage": stage,
            "what_it_establishes": STAGE_MEANING[stage],
            "completed_stages": _completed_stages(pod_facts, None, assessment)
            if not unschedulable
            else [],
            "verified_not_declared": [],
            "open_question": OPEN_QUESTION[stage],
        }

        if unschedulable:
            signals = sorted(pod_facts.scheduling_signals)

            for event in pod_facts.events:
                if event.reason == "FailedScheduling":
                    signals.extend(name for name, _ref in event.signals)

            item["scheduler_reported_constraints"] = sorted(set(signals))
            item["verified_not_declared"] = _placement_absent(pod_facts)

        items.append(item)

    # Container-level.
    for (namespace, pod, name), container in sorted(containers.items()):
        assessment = classify_container(container.values)
        stage = _container_stage(assessment, container.values)

        if stage is None:
            continue

        key = (namespace, pod)
        values = container.values
        pod_facts = facts.get(key)
        config_pod = configuration.get(key)
        config = config_pod.containers.get(name) if config_pod else None
        termination: dict[str, Any] = {}

        if "last_termination.reason" in values:
            termination["reason"] = values["last_termination.reason"]

        if "last_termination.exit_code" in values:
            termination["exit_code"] = values["last_termination.exit_code"]

        item = {
            "namespace": namespace,
            "pod": pod,
            "container": name,
            "abnormal_stage": stage,
            "kubernetes_reason": assessment.reason,
            "what_it_establishes": STAGE_MEANING[stage],
            "completed_stages": _completed_stages(pod_facts, container, assessment),
            # A probe can only be blamed for a container that ran.
            "verified_not_declared": (
                _declared_absent(snapshot, key, name, pod_facts, config)
                if stage in {"container_runtime", "past_restart", "readiness"}
                else []
            ),
            "open_question": OPEN_QUESTION[stage],
        }

        restarts = values.get("restart_count")

        if type(restarts) is int:
            item["restart_count"] = restarts

        if termination:
            item["previous_termination"] = termination
            meaning = TERMINATION_MEANING.get(termination.get("reason", ""))

            if meaning:
                item["previous_termination_means"] = meaning

        items.append(item)

    # The statements are the application's own; their evidence ids are left
    # out so the model is not invited to cite them as decoration. (Each one
    # rests on an observation in 'kubernetes_verified_observations'.)
    for item in items:
        for key in ("completed_stages", "verified_not_declared"):
            item[key] = [
                {k: v for k, v in entry.items() if k != "evidence_ids"}
                for entry in item[key]
            ]

    return items[:MAX_ITEMS]
