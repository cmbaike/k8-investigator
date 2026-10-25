"""Pin the lab investigator RBAC to exactly what the read-only tools need.

Offline: parses the manifest only. The live counterpart is
scripts/verify_investigator_rbac.py.
"""

from pathlib import Path

import pytest
import yaml

MANIFEST = Path("k8s/lab/private-ai-investigator-rbac.yaml")

# (apiGroup, resource, verb) triples required by app/tools/handlers.py.
REQUIRED = {
    ("", "pods", "list"),            # get_pods
    ("", "pods", "get"),             # describe_pod, describe_workload_config
    ("", "pods/log", "get"),         # get_logs, get_previous_logs
    ("", "events", "list"),          # get_events
    ("apps", "deployments", "get"),  # get_deployment, ownership verification
    ("apps", "replicasets", "get"),  # ownership verification
}

FORBIDDEN_RESOURCES = {
    "secrets", "configmaps", "pods/exec", "pods/attach", "pods/portforward",
    "serviceaccounts", "serviceaccounts/token", "roles", "rolebindings",
    "clusterroles", "clusterrolebindings", "nodes", "namespaces",
}
FORBIDDEN_VERBS = {
    "create", "update", "patch", "delete", "deletecollection", "watch",
    "impersonate", "bind", "escalate", "*",
}


@pytest.fixture(scope="module")
def documents():
    return {
        doc["kind"]: doc
        for doc in yaml.safe_load_all(MANIFEST.read_text())
        if doc
    }


def granted(documents):
    triples = set()

    for rule in documents["Role"]["rules"]:
        for group in rule["apiGroups"]:
            for resource in rule["resources"]:
                for verb in rule["verbs"]:
                    triples.add((group, resource, verb))

    return triples


def test_role_grants_exactly_what_the_tools_require(documents):
    assert granted(documents) == REQUIRED


def test_role_has_no_wildcards_sensitive_resources_or_mutating_verbs(documents):
    for group, resource, verb in granted(documents):
        assert "*" not in (group, resource, verb)
        assert resource not in FORBIDDEN_RESOURCES
        assert verb not in FORBIDDEN_VERBS

    assert not any("nonResourceURLs" in rule for rule in documents["Role"]["rules"])


def test_scope_is_one_namespace_with_no_cluster_wide_objects(documents):
    assert set(documents) == {"ServiceAccount", "Role", "RoleBinding"}
    assert "ClusterRole" not in documents and "ClusterRoleBinding" not in documents

    namespaces = {doc["metadata"]["namespace"] for doc in documents.values()}
    assert namespaces == {"ai-ops-demo"}

    binding = documents["RoleBinding"]
    assert binding["roleRef"] == {
        "kind": "Role",
        "name": "private-ai-investigator",
        "apiGroup": "rbac.authorization.k8s.io",
    }
    assert [(s["kind"], s["name"], s["namespace"]) for s in binding["subjects"]] == [
        ("ServiceAccount", "private-ai-investigator", "ai-ops-demo")
    ]


def test_service_account_token_is_not_auto_mounted(documents):
    assert documents["ServiceAccount"]["automountServiceAccountToken"] is False


def test_every_kubernetes_call_in_handlers_is_covered_by_the_role():
    """Fail if a handler starts using an API call the Role does not grant."""
    import re

    source = Path("app/tools/handlers.py").read_text()
    calls = set(re.findall(r"(?:core_v1|apps_v1)\(\)\.([a-z_]+)\(", source))

    assert calls == {
        "read_namespaced_pod_log",
        "list_namespaced_pod",
        "read_namespaced_pod",
        "list_namespaced_event",
        "read_namespaced_deployment",
        "read_namespaced_replica_set",
    }
