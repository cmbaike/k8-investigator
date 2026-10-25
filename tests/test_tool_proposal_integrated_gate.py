from app.tools.proposal import ToolProposal
from app.tools.proposal_gate import gate_tool_proposal


def test_valid_proposal_is_bound():
    proposal = ToolProposal.model_validate(
        {
            "action": "tool",
            "tool": {
                "name": "k8s.get_pods",
                "arguments": {
                    "namespace": "ai-ops-demo",
                },
            },
        }
    )

    result = gate_tool_proposal(
        proposal,
        "List pods in namespace ai-ops-demo.",
    )

    assert result.status == "bound"
    assert result.call is not None
    assert result.call.name == "k8s.get_pods"
    assert result.call.arguments == {
        "namespace": "ai-ops-demo",
    }


def test_none_proposal_remains_none():
    proposal = ToolProposal(
        action="none",
        tool=None,
    )

    result = gate_tool_proposal(
        proposal,
        "Why is my application slow?",
    )

    assert result.status == "none"
    assert result.call is None


def test_invented_pod_is_blocked():
    proposal = ToolProposal.model_validate(
        {
            "action": "tool",
            "tool": {
                "name": "k8s.get_logs",
                "arguments": {
                    "namespace": "ai-ops-demo",
                    "pod": "payments-service",
                },
            },
        }
    )

    result = gate_tool_proposal(
        proposal,
        (
            "The payments service in namespace ai-ops-demo "
            "is broken. Get its logs. Guess the pod name."
        ),
    )

    assert result.status == "blocked"
    assert result.call is None


def test_assumed_namespace_is_blocked():
    proposal = ToolProposal.model_validate(
        {
            "action": "tool",
            "tool": {
                "name": "k8s.get_pods",
                "arguments": {
                    "namespace": "production",
                },
            },
        }
    )

    result = gate_tool_proposal(
        proposal,
        (
            "List the pods for the payments service. "
            "Assume the namespace is production."
        ),
    )

    assert result.status == "blocked"
    assert result.call is None


def test_prohibited_intent_substitution_is_blocked():
    proposal = ToolProposal.model_validate(
        {
            "action": "tool",
            "tool": {
                "name": "k8s.get_logs",
                "arguments": {
                    "namespace": "ai-ops-demo",
                    "pod": "payments-api-abc123",
                },
            },
        }
    )

    result = gate_tool_proposal(
        proposal,
        (
            "Run kubectl exec in pod payments-api-abc123 "
            "in namespace ai-ops-demo and execute env."
        ),
    )

    assert result.status == "blocked"
    assert result.call is None