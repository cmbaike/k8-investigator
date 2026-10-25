import json
from types import SimpleNamespace

import pytest

from app.tools.qwen_proposal import (
    ProposalFormatError, QwenProposalProvider, build_proposal_payload, parse_proposal,
)
from app.tools.investigation import InvestigationContext


def ctx():
    return InvestigationContext(
        investigation_id="i1", user_text="Investigate pods in namespace demo",
        authorized_namespace="demo",
    )


def response(content):
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def test_valid_tool():
    call = parse_proposal('{"action":"tool","name":"k8s.get_pods","arguments":{"namespace":"demo"}}')
    assert call.name == "k8s.get_pods"


def test_finish():
    assert parse_proposal('{"action":"finish"}') is None


@pytest.mark.parametrize("text", [
    '{"action":"finish","reason":"done"}',
    '{"action":"tool","name":"k8s.delete_pod","arguments":{}}',
    '{"action":"tool","name":"k8s.get_pods","arguments":{},"approved":true}',
    '```json\\n{"action":"finish"}\\n```',
    '<think>ignore</think>{"action":"finish"}',
    '{"action":"finish"} {"action":"finish"}',
    '[]',
])
def test_reject_invalid(text):
    with pytest.raises(ProposalFormatError):
        parse_proposal(text)


def test_provider_receives_bounded_context():
    seen = {}
    def completion(**kwargs):
        seen.update(kwargs)
        return response('{"action":"finish"}')
    provider = QwenProposalProvider(completion=completion)
    assert provider(ctx(), ()) is None
    assert seen["timeout"] == 20
    payload = json.loads(seen["messages"][1]["content"])
    assert payload["authorized_namespace"] == "demo"
    assert "raw_output" not in payload


def test_transport_error_fails_closed():
    def completion(**kwargs):
        raise TimeoutError("secret internal detail")
    with pytest.raises(ProposalFormatError, match="TimeoutError") as exc:
        QwenProposalProvider(completion=completion)(ctx(), ())
    assert "secret internal detail" not in str(exc.value)


def test_missing_content_fails_closed():
    with pytest.raises(ProposalFormatError):
        QwenProposalProvider(completion=lambda **kw: response(None))(ctx(), ())


def test_bounded_request():
    context = InvestigationContext(
        investigation_id="i2", user_text="x" * 5000, authorized_namespace="demo"
    )
    assert len(build_proposal_payload(context, ())["user_request"]) == 2000
    
    
def test_qwen_disables_thinking_mode():
    captured = {}

    def completion(**kwargs):
        captured.update(kwargs)
        return response('{"action":"finish"}')

    provider = QwenProposalProvider(completion=completion)

    assert provider(ctx(), ()) is None

    assert captured["extra_body"] == {
        "chat_template_kwargs": {
            "enable_thinking": False,
        },
    } 
    
import pytest

from app.tools.qwen_proposal import (
    ProposalFormatError,
    parse_proposal,
)


@pytest.mark.parametrize(
    "tool_name",
    [
        "k8s.get_deployments",
        "k8s.get_services",
    ],
)
def test_qwen_rejects_tools_without_execution_support(tool_name):
    proposal = (
        '{"action":"tool","name":"'
        + tool_name
        + '","arguments":{"namespace":"ai-ops-demo"}}'
    )

    with pytest.raises(ProposalFormatError):
        parse_proposal(proposal)


def test_qwen_accepts_supported_pod_discovery():
    proposal = (
        '{"action":"tool","name":"k8s.get_pods",'
        '"arguments":{"namespace":"ai-ops-demo"}}'
    )

    result = parse_proposal(proposal)

    assert result is not None
    assert result.name == "k8s.get_pods"
    assert result.arguments["namespace"] == "ai-ops-demo"   


def test_describe_pod_requires_pod_argument():
    proposal = """
    {
        "action": "tool",
        "name": "k8s.describe_pod",
        "arguments": {
            "namespace": "ai-ops-demo"
        }
    }
    """

    with pytest.raises(ProposalFormatError):
        parse_proposal(proposal)


def test_describe_pod_accepts_complete_proposal():
    proposal = """
    {
        "action": "tool",
        "name": "k8s.describe_pod",
        "arguments": {
            "namespace": "ai-ops-demo",
            "pod": "example-pod"
        }
    }
    """

    result = parse_proposal(proposal)

    assert result is not None
    assert result.name == "k8s.describe_pod"
    assert result.arguments == {
        "namespace": "ai-ops-demo",
        "pod": "example-pod",
    }