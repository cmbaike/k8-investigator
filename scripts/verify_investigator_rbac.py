#!/usr/bin/env python3
"""Verify the investigator identity is least-privilege against a live cluster.

Run with KUBECONFIG pointing at the dedicated investigator kubeconfig:

    KUBECONFIG=~/.kube/private-ai-investigator.kubeconfig \
        .venv/bin/python scripts/verify_investigator_rbac.py --namespace ai-ops-demo

It exercises the application's OWN handlers (not kubectl) so the result
reflects what the API process can actually do. Mutation attempts are sent with
server-side dry-run, so they cannot change cluster state even if authorization
were unexpectedly granted. Output is PASS/FAIL lines and HTTP status codes
only: no log text, no resource contents, no credentials.
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kubernetes import client  # noqa: E402
from kubernetes.client.exceptions import ApiException  # noqa: E402

from app.tools import handlers  # noqa: E402
from app.tools.arguments import (  # noqa: E402
    DeploymentArguments,
    LogsArguments,
    NamespaceArguments,
    PodArguments,
)
from app.tools.kubernetes_client import apps_v1, core_v1  # noqa: E402

DENIED_CHECKS = [
    # (verb, resource, group, subresource, in_namespace?)
    ("get", "secrets", "", None, True),
    ("list", "secrets", "", None, True),
    ("get", "configmaps", "", None, True),
    ("list", "configmaps", "", None, True),
    ("get", "services", "", None, True),
    ("create", "pods", "", "exec", True),
    ("create", "pods", "", "attach", True),
    ("create", "pods", "", "portforward", True),
    ("create", "pods", "", None, True),
    ("delete", "pods", "", None, True),
    ("patch", "pods", "", None, True),
    ("update", "pods", "", None, True),
    ("create", "deployments", "apps", None, True),
    ("delete", "deployments", "apps", None, True),
    ("patch", "deployments", "apps", None, True),
    ("update", "deployments", "apps", None, True),
    ("update", "deployments", "apps", "scale", True),
    ("patch", "deployments", "apps", "scale", True),
    ("list", "deployments", "apps", None, True),
    ("list", "replicasets", "apps", None, True),
    ("watch", "pods", "", None, True),
    ("get", "events", "", None, True),
    ("create", "rolebindings", "rbac.authorization.k8s.io", None, True),
    ("create", "serviceaccounts", "", "token", True),
    # Cluster scope.
    ("list", "pods", "", None, False),
    ("list", "namespaces", "", None, False),
    ("list", "nodes", "", None, False),
    ("list", "secrets", "", None, False),
    ("get", "clusterroles", "rbac.authorization.k8s.io", None, False),
]

results: list[tuple[bool, str]] = []


def record(ok: bool, label: str, detail: str = "") -> None:
    results.append((ok, label))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" - {detail}" if detail else ""))


def status_of(exc: Exception) -> str:
    if isinstance(exc, ApiException):
        return f"HTTP {exc.status}"

    cause = exc.__cause__
    if isinstance(cause, ApiException):
        return f"HTTP {cause.status}"

    return type(exc).__name__


def expect_ok(label, fn):
    try:
        out = fn()
        record(True, label)
        return out
    except Exception as exc:  # noqa: BLE001
        record(False, label, status_of(exc))
        return None


def expect_forbidden(label, fn):
    try:
        fn()
        record(False, label, "unexpectedly succeeded")
    except Exception as exc:  # noqa: BLE001
        code = status_of(exc)
        record(code == "HTTP 403", label, code)


def access_allowed(namespace, verb, resource, group, subresource, scoped) -> bool:
    attributes = client.V1ResourceAttributes(
        verb=verb,
        resource=resource,
        group=group,
        subresource=subresource,
        namespace=namespace if scoped else None,
    )
    review = client.AuthorizationV1Api().create_self_subject_access_review(
        client.V1SelfSubjectAccessReview(
            spec=client.V1SelfSubjectAccessReviewSpec(resource_attributes=attributes)
        )
    )

    return bool(review.status.allowed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--namespace", default="ai-ops-demo")
    parser.add_argument("--other-namespace", default="kube-system")
    parser.add_argument(
        "--expected-identity",
        default="system:serviceaccount:{namespace}:private-ai-investigator",
    )
    args = parser.parse_args()

    expected = args.expected_identity.format(namespace=args.namespace)
    namespace, other = args.namespace, args.other_namespace

    print(f"KUBECONFIG={'set' if os.environ.get('KUBECONFIG') else 'NOT SET (default kubeconfig!)'}")

    # --- identity -----------------------------------------------------------
    from app.tools.kubernetes_client import load_kubernetes_config

    load_kubernetes_config()
    review = client.AuthenticationV1Api().create_self_subject_review(
        client.V1SelfSubjectReview()
    )
    username = review.status.user_info.username
    record(username == expected, "execution identity is the dedicated investigator", username)
    record(
        "system:masters" not in (review.status.user_info.groups or [])
        and "kubeadm:cluster-admins" not in (review.status.user_info.groups or []),
        "identity is not a cluster administrator group",
    )

    # --- allowed: the application's own read-only handlers ---------------------
    pods = expect_ok(
        "handler k8s.get_pods (in-namespace)",
        lambda: handlers.get_pods(NamespaceArguments(namespace=namespace)),
    )
    names = [p["name"] for p in (pods or {}).get("pods", [])]
    record(bool(names), "at least one pod is visible", f"{len(names)} pod(s)")

    if names:
        pod = names[0]
        expect_ok(
            "handler k8s.describe_pod",
            lambda: handlers.describe_pod(PodArguments(namespace=namespace, pod=pod)),
        )
        config = expect_ok(
            "handler k8s.describe_workload_config (Pod -> ReplicaSet -> Deployment)",
            lambda: handlers.describe_workload_config(
                PodArguments(namespace=namespace, pod=pod)
            ),
        )
        expect_ok(
            "handler k8s.get_logs",
            lambda: handlers.get_logs(
                LogsArguments(namespace=namespace, pod=pod, tail=1)
            ),
        )
        if config:
            deployment = config["workload"]["name"]
            record(config["workload"]["ownership_verified"] is True, "ownership verified by owner references")
            expect_ok(
                "handler k8s.get_deployment",
                lambda: handlers.get_deployment(
                    DeploymentArguments(namespace=namespace, deployment=deployment)
                ),
            )

    expect_ok(
        "handler k8s.get_events (in-namespace)",
        lambda: handlers.get_events(NamespaceArguments(namespace=namespace)),
    )

    # --- denied: cross-namespace via the same handlers -------------------------
    expect_forbidden(
        f"handler k8s.get_pods in {other} is forbidden",
        lambda: handlers.get_pods(NamespaceArguments(namespace=other)),
    )
    expect_forbidden(
        f"handler k8s.get_events in {other} is forbidden",
        lambda: handlers.get_events(NamespaceArguments(namespace=other)),
    )
    expect_forbidden(
        f"handler k8s.describe_pod in {other} is forbidden",
        lambda: handlers.describe_pod(PodArguments(namespace=other, pod="any")),
    )
    expect_forbidden(
        f"handler k8s.get_deployment in {other} is forbidden",
        lambda: handlers.get_deployment(
            DeploymentArguments(namespace=other, deployment="any")
        ),
    )
    expect_forbidden(
        f"handler k8s.get_logs in {other} is forbidden",
        lambda: handlers.get_logs(LogsArguments(namespace=other, pod="any", tail=1)),
    )

    # --- denied: authorization reviews for sensitive and mutating access -------
    for verb, resource, group, sub, scoped in DENIED_CHECKS:
        target = f"{resource}/{sub}" if sub else resource
        scope = namespace if scoped else "cluster-wide"
        try:
            allowed = access_allowed(namespace, verb, resource, group, sub, scoped)
            record(not allowed, f"cannot {verb} {target} ({scope})")
        except Exception as exc:  # noqa: BLE001
            record(False, f"cannot {verb} {target} ({scope})", status_of(exc))

    # In another namespace, even the granted verbs are denied.
    for verb, resource, group, sub in (
        ("list", "pods", "", None),
        ("get", "pods", "", "log"),
        ("get", "deployments", "apps", None),
    ):
        allowed = access_allowed(other, verb, resource, group, sub, True)
        record(not allowed, f"cannot {verb} {resource}{'/' + sub if sub else ''} in {other}")

    # --- denied: real mutation attempts, server-side dry-run only ---------------
    target_pod = names[0] if names else "none"
    expect_forbidden(
        "dry-run delete pod is forbidden",
        lambda: core_v1().delete_namespaced_pod(
            name=target_pod, namespace=namespace, dry_run="All"
        ),
    )
    expect_forbidden(
        "dry-run patch pod is forbidden",
        lambda: core_v1().patch_namespaced_pod(
            name=target_pod, namespace=namespace, body={"metadata": {"labels": {"x": "y"}}},
            dry_run="All",
        ),
    )
    if config:
        expect_forbidden(
            "dry-run scale deployment is forbidden",
            lambda: apps_v1().patch_namespaced_deployment_scale(
                name=deployment, namespace=namespace, body={"spec": {"replicas": 0}},
                dry_run="All",
            ),
        )
        expect_forbidden(
            "dry-run patch deployment (rollout restart) is forbidden",
            lambda: apps_v1().patch_namespaced_deployment(
                name=deployment, namespace=namespace,
                body={"spec": {"template": {"metadata": {"annotations": {"x": "y"}}}}},
                dry_run="All",
            ),
        )
    expect_forbidden(
        "read Secret is forbidden",
        lambda: core_v1().list_namespaced_secret(namespace=namespace),
    )
    expect_forbidden(
        "read ConfigMap is forbidden",
        lambda: core_v1().list_namespaced_config_map(namespace=namespace),
    )

    failed = [label for ok, label in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed.")

    for label in failed:
        print(f"FAILED: {label}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
