import json
import os
import re

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel

from app.provenance import source_label


load_dotenv()

VLLM_BASE_URL = os.getenv(
    "VLLM_BASE_URL",
    "http://localhost:8000/v1",
)

VLLM_API_KEY = os.getenv(
    "VLLM_API_KEY",
    "local",
)

VLLM_MODEL = os.getenv(
    "VLLM_MODEL",
    "Qwen/Qwen3-4B",
)


client = OpenAI(
    base_url=VLLM_BASE_URL,
    api_key=VLLM_API_KEY,
)


class SufficiencyResult(BaseModel):
    sufficient: bool
    reason: str


SYSTEM_PROMPT =  """
You are an evidence sufficiency classifier.

Your task is NOT to answer the user's question.

Determine whether the supplied evidence explicitly contains enough
information to fully answer the entire question.

Use only the supplied evidence.

A decision of sufficient=true means that another model could answer
the complete question using only this evidence, without guessing,
inferring missing facts, or using outside knowledge.

Rules:

1. Every material part of the question must be supported by the
   supplied evidence.

2. If the question asks for a specific value, number, version, name,
   region, date, duration, quantity, credential, SLA, RTO, RPO, or
   retention period, that specific requested information must appear
   explicitly in the evidence.

3. Evidence saying where a fact can be found is NOT evidence of the
   fact itself.

4. Evidence about a related environment, system, object, metric, role,
   or policy is NOT sufficient for the requested one.

   Examples:
   - staging is not production
   - log retention is not backup retention
   - backup frequency is not backup retention
   - an internal availability target is not a contractual SLA
   - a kubectl client version is not a cluster version
   - a disaster recovery region is not necessarily the production region

5. For multi-part questions, evidence must support ALL material parts.
   If one requested part is missing, return sufficient=false.

6. Partial procedures are insufficient when the question asks for a
   procedure containing additional steps or information not present
   in the evidence.

7. Do not treat implications, likely conclusions, semantic similarity,
   or related troubleshooting knowledge as explicit evidence.

8. Do not fill gaps using your own technical knowledge.

9. Evidence may be sufficient even when the supported answer is "no".
   For example, an explicit statement that production restarts require
   human approval is sufficient evidence to answer whether the AI may
   restart production autonomously.

10. When uncertain whether the complete question is explicitly
    supported, return sufficient=false.
    
11. Before returning the final decision, perform these checks in order:

    a. Identify every material part of the question.

    b. For each material part, determine whether the evidence
       explicitly provides the information needed to answer it.

    c. Do not count information that is merely implied, inferred,
       suggested, referenced as existing elsewhere, or obtainable
       from another source.

    d. If ANY material part is not explicitly supported,
       sufficient MUST be false.

    e. Before returning JSON, check that the boolean agrees with
       your reason. If your reason says information is missing,
       absent, not provided, not stated, only implied, inferred,
       or insufficient, sufficient MUST be false.

    f. sufficient=true is allowed only when every material part
       can be answered directly from the supplied evidence.  

Return ONLY one JSON object in exactly this form:

{"sufficient": true, "reason": "brief explanation"}

or:

{"sufficient": false, "reason": "brief explanation"}

Do not output Markdown.
Do not output prose before or after the JSON object.
Do not output key=value syntax.
"""


def assess_sufficiency(
    question: str,
    sources: list[dict],
) -> SufficiencyResult:

    evidence = "\n\n".join(
        f"[SOURCE: {source_label(source)}]\n"
        f"{source['content']}"
        for source in sources
    )

    response = client.chat.completions.create(
        model=VLLM_MODEL,
        temperature=0,
        max_tokens=500,
        response_format={
        "type": "json_schema",
        "json_schema": {
            "name": "sufficiency_result",
            "schema": {
                "type": "object",
                "properties": {
                    "sufficient": {
                        "type": "boolean"
                    },
                    "reason": {
                        "type": "string"
                    },
                },
                "required": [
                    "sufficient",
                    "reason",
                ],
                "additionalProperties": False,
            },
        },
        },
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT + "\n\n/no_think",
            },
            {
                "role": "user",
                "content": (
                    f"QUESTION:\n{question}\n\n"
                    f"EVIDENCE:\n{evidence}"
                ),
            },
        ],
    )
    
    content = (
    response.choices[0]
    .message.content
    or ""
    ).strip()

    content = (
    response.choices[0]
    .message.content
    or ""
     ).strip()
    
    if not content:
     raise RuntimeError(
        "Sufficiency model returned empty content. "
        f"Response: {response}"
    )
     
    content = re.sub(
    r"<think>.*?</think>",
    "",
    content,
    flags=re.DOTALL,
    ).strip()
    
     
    if not content:
     raise RuntimeError(
        "Sufficiency model returned no content "
        "after removing reasoning wrapper."
    )
     
    try:
      data = json.loads(content)
    except json.JSONDecodeError as exc:
     raise RuntimeError(
        "Sufficiency model returned invalid JSON.\n"
        f"Raw content: {content!r}"
    ) from exc


    return SufficiencyResult.model_validate(data)