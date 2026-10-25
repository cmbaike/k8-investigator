import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.tools.proposal import propose_tool



def response_with(content, finish_reason="stop"):
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                finish_reason=finish_reason,
                message=SimpleNamespace(content=content),
            )
        ]
    )    


def test_valid_tool_proposal():
    payload = {
        "action": "tool",
        "tool": {
            "name": "k8s.get_pods",
            "arguments": {
                "namespace": "ai-ops-demo",
            },
        },
    }

    with patch(
        "app.tools.proposal.client.chat.completions.create",
        return_value=response_with(json.dumps(payload)),
    ) as mock_create:
        result = propose_tool(
        "List pods in namespace ai-ops-demo."
    )

    mock_create.assert_called_once()

    kwargs = mock_create.call_args.kwargs

    assert kwargs["extra_body"] == {
       "chat_template_kwargs": {
        "enable_thinking": False,
    }
  }
    
    assert result.action == "tool"
    assert result.tool is not None
    assert result.tool.name == "k8s.get_pods"
    assert result.tool.arguments == {
       "namespace": "ai-ops-demo",
    }
    


def test_none_proposal():
    payload = {
        "action": "none",
        "tool": None,
    }

    with patch(
        "app.tools.proposal.client.chat.completions.create",
        return_value=response_with(json.dumps(payload)),
    ):
        result = propose_tool(
            "Why is my application slow?"
        )

    assert result.action == "none"
    assert result.tool is None


def test_invalid_json_fails_closed():
    with patch(
        "app.tools.proposal.client.chat.completions.create",
        return_value=response_with("not-json"),
    ):
        with pytest.raises(ValueError):
            propose_tool("anything")


def test_tool_action_without_tool_fails_closed():
    payload = {
        "action": "tool",
        "tool": None,
    }

    with patch(
        "app.tools.proposal.client.chat.completions.create",
        return_value=response_with(json.dumps(payload)),
    ):
        with pytest.raises(ValueError):
            propose_tool("anything")


def test_none_action_with_tool_fails_closed():
    payload = {
        "action": "none",
        "tool": {
            "name": "k8s.get_pods",
            "arguments": {
                "namespace": "ai-ops-demo",
            },
        },
    }

    with patch(
        "app.tools.proposal.client.chat.completions.create",
        return_value=response_with(json.dumps(payload)),
    ):
        with pytest.raises(ValueError):
            propose_tool("anything")
            
        
def test_think_block_is_removed_before_json_parsing():
    content = """<think>
I should use the explicitly provided namespace.
</think>

{
  "action": "tool",
  "tool": {
    "name": "k8s.get_pods",
    "arguments": {
      "namespace": "ai-ops-demo"
    }
  }
}
"""

    with patch(
        "app.tools.proposal.client.chat.completions.create",
        return_value=response_with(content),
    ):
        result = propose_tool(
            "List pods in namespace ai-ops-demo."
        )

    assert result.action == "tool"
    assert result.tool is not None
    assert result.tool.name == "k8s.get_pods"
    assert result.tool.arguments == {
        "namespace": "ai-ops-demo",
    }


def test_non_stop_finish_reason_fails_closed():
    content = """{
      "action": "none",
      "tool": null
    }"""

    with patch(
        "app.tools.proposal.client.chat.completions.create",
        return_value=response_with(
            content,
            finish_reason="length",
        ),
    ):
        with pytest.raises(
            ValueError,
            match="did not finish normally",
        ):
            propose_tool("anything")        


def test_arbitrary_prose_before_json_is_rejected():
    content = """I recommend using this tool.

{
  "action": "tool",
  "tool": {
    "name": "k8s.get_pods",
    "arguments": {
      "namespace": "ai-ops-demo"
    }
  }
}
"""

    with patch(
        "app.tools.proposal.client.chat.completions.create",
        return_value=response_with(content),
    ):
        with pytest.raises(
            ValueError,
            match="invalid JSON",
        ):
            propose_tool(
                "List pods in namespace ai-ops-demo."
            )
            
def test_unknown_tool_fails_closed():
    payload = {
        "action": "tool",
        "tool": {
            "name": "shell.exec",
            "arguments": {
                "command": "whoami",
            },
        },
    }

    with patch(
        "app.tools.proposal.client.chat.completions.create",
        return_value=response_with(json.dumps(payload)),
    ):
        with pytest.raises(
            ValueError,
            match="unknown tool",
        ):
            propose_tool("Run whoami.")


def test_state_changing_tool_fails_closed():
    payload = {
        "action": "tool",
        "tool": {
            "name": "k8s.restart_deployment",
            "arguments": {
                "namespace": "production",
                "deployment": "payments-api",
            },
        },
    }

    with patch(
        "app.tools.proposal.client.chat.completions.create",
        return_value=response_with(json.dumps(payload)),
    ):
        with pytest.raises(
            ValueError,
            match="non-read-only",
        ):
            propose_tool(
                "Restart payments-api in production."
            ) 
                                       