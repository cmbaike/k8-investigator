import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.llm import VLLM_MODEL, client
from app.model_output import strip_think_blocks
from app.tools.models import ToolCall
from app.tools.models import ToolRisk
from app.tools.registry import get_tool


class ToolProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["tool", "none"]
    tool: ToolCall | None = None


SYSTEM_PROMPT = """
You select read-only operational tools for a DevOps/SRE assistant.

You do not execute tools.
You do not decide whether a tool is authorized.
You may propose at most one tool call.

Available tools:

k8s.get_pods
  arguments:
    namespace: string

k8s.describe_pod
  arguments:
    namespace: string
    pod: string

k8s.get_events
  arguments:
    namespace: string

k8s.get_deployment
  arguments:
    namespace: string
    deployment: string

k8s.get_logs
  arguments:
    namespace: string
    pod: string
    container: optional string
    tail: integer from 1 to 1000

k8s.get_previous_logs
  arguments:
    namespace: string
    pod: string
    container: optional string
    tail: integer from 1 to 1000

Rules:

- Propose only one of the tools listed above.
- Never invent a pod, deployment, namespace, or container name.
- Use only identifiers explicitly provided in the user request or observations.
- If a required identifier is unknown, return action "none".
- Do not propose state-changing operations.
- Do not propose shell commands.
- Return JSON only.

Schema:

{
  "action": "tool" | "none",
  "tool": {
    "name": "tool name",
    "arguments": {}
  } | null
}
""".strip()


def propose_tool(question: str) -> ToolProposal:
    response = client.chat.completions.create(
    model=VLLM_MODEL,
    temperature=0,
    max_tokens=800,
    extra_body={
        "chat_template_kwargs": {
            "enable_thinking": False,
        }
    },
    messages=[
        {
            "role": "system",
            "content": SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": question,
        },
    ],
)
    
    choice = response.choices[0]
    
    if choice.finish_reason != "stop":
     raise ValueError(
        f"Tool proposal model did not finish normally: "
        f"{choice.finish_reason!r}."
    )

    content = choice.message.content
    
    if not content:
      raise ValueError("Tool proposal model returned empty content.")

    content = strip_think_blocks(content).strip()

    if not content:
     raise ValueError(
        "Tool proposal model returned no content after reasoning removal."
    )
    
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Tool proposal model returned invalid JSON."
        ) from exc

    proposal = ToolProposal.model_validate(payload)
    if proposal.action == "tool" and proposal.tool is None:
     raise ValueError(
        "Tool proposal action requires a tool call."
    )
    if proposal.action == "none" and proposal.tool is not None:
     raise ValueError(
        "Tool proposal must not contain a tool when action is none."
    )
    if proposal.action == "tool":
    # Safe because the invariant above has already been validated.
      tool = proposal.tool

      definition = get_tool(tool.name)

      if definition is None:
        raise ValueError(
            f"Tool proposal referenced unknown tool: "
            f"{tool.name!r}."
        )

      if definition.risk != ToolRisk.READ_ONLY:
        raise ValueError(
            "Tool proposal referenced a non-read-only tool."
        )
    return proposal
