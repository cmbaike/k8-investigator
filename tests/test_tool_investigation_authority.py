import pytest

from app.tools.investigation_authority import (
    InvestigationAuthorityError,
    InvestigationKind,
    infer_investigation_authority,
    validate_investigation_operation,
)
from app.tools.models import ToolCall


def test_investigate_workload_grants_k8s_workload_authority():
    authority = infer_investigation_authority(
        "Investigate the failing workload in namespace ai-ops-demo."
    )

    assert authority is not None
    assert authority.kind == InvestigationKind.K8S_WORKLOAD


def test_diagnose_pod_grants_workload_authority():
    authority = infer_investigation_authority(
        "Diagnose the failing pod in namespace ai-ops-demo."
    )

    assert authority is not None


def test_troubleshoot_service_grants_workload_authority():
    authority = infer_investigation_authority(
        "Troubleshoot the payments service."
    )

    assert authority is not None


def test_generic_investigate_does_not_grant_authority():
    assert infer_investigation_authority(
        "Investigate this problem."
    ) is None


def test_workload_mention_without_investigation_does_not_grant_authority():
    assert infer_investigation_authority(
        "Tell me about the workload."
    ) is None


@pytest.mark.parametrize(
    "tool_name",
    [
        "k8s.get_pods",
        "k8s.describe_pod",
        "k8s.get_logs",
        "k8s.get_previous_logs",
        "k8s.get_events",
        "k8s.get_deployment",
    ],
)
def test_supported_read_only_tools_are_authorized(tool_name):
    authority = infer_investigation_authority(
        "Investigate the failing workload."
    )

    assert authority is not None

    validate_investigation_operation(
        ToolCall(
            name=tool_name,
            arguments={},
        ),
        authority,
    )


@pytest.mark.parametrize(
    "tool_name",
    [
        "k8s.rollout_restart",
        "k8s.delete_pod",
        "k8s.exec",
        "shell.exec",
    ],
)
def test_state_changing_or_unknown_tools_are_rejected(tool_name):
    authority = infer_investigation_authority(
        "Investigate the failing workload."
    )

    assert authority is not None

    with pytest.raises(InvestigationAuthorityError):
        validate_investigation_operation(
            ToolCall(
                name=tool_name,
                arguments={},
            ),
            authority,
        )
        
@pytest.mark.parametrize(
    "text",
    [
        "Do not investigate the workload.",
        "Don't diagnose the failing pod.",
        "Never troubleshoot this service.",
        "Avoid investigating the deployment.",
        "Assume we investigate the workload.",
        "Suppose we diagnose the pod.",
        "Imagine troubleshooting the service.",
        "Pretend to investigate the workload.",
        "Hypothetically investigate the deployment.",
        "What if we investigate the workload?",
        "Investigative notes about the workload.",
        "The pod investigation report is available.",
        "Please investigate this problem.",
        "Investigate the billing system.",
    ],
)
def test_ambiguous_or_untrusted_intent_does_not_grant_authority(text):
    assert infer_investigation_authority(text) is None
    
            
@pytest.mark.parametrize(
    "text",
    [
        "Investigate the failing workload in namespace ai-ops-demo.",
        "Diagnose the failing pod in namespace ai-ops-demo.",
        "Troubleshoot the payments service.",
        "Investigate the deployment.",
    ],
)
def test_explicit_workload_investigation_grants_authority(text):
    assert infer_investigation_authority(text) is not None