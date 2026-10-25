import json
import os
import re
from typing import Literal

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel


load_dotenv()

client = OpenAI(
    base_url=os.getenv("OPENAI_BASE_URL", "http://localhost:8000/v1"),
    api_key=os.getenv("OPENAI_API_KEY", "local"),
)

MODEL = os.getenv("LLM_MODEL", "Qwen/Qwen3-4B")


RequirementType = Literal[
    "value",
    "fact",
    "boolean",
    "procedure",
    "explanation",
]


class TypedRequirement(BaseModel):
    text: str
    type: RequirementType


class TypedDecompositionResult(BaseModel):
    requirements: list[TypedRequirement]


SYSTEM_PROMPT = """
Decompose the user's question into the minimum set of material
requirements that must ALL be supported by evidence.

For every requirement, classify what kind of answer it requires.

Allowed types:

"value"
The question requires a specific value such as a number, duration,
date, time, version, quantity, percentage, region, identifier,
credential, retention period, RTO, RPO, SLA, port, or named owner.

"boolean"
The question asks whether something is allowed, required, true,
false, permitted, prohibited, or recommended.

"procedure"
The question asks how to perform, inspect, diagnose, investigate,
check, remediate, or execute something.

"explanation"
The question asks what something means, why something happened,
or for an explanation or cause.

"fact"
A requested factual answer that does not fit the categories above.

Rules:

1. Preserve exactly what the user asks.
2. Prefer one requirement.
3. Split only explicit independently answerable components.
4. Preserve subject, environment, scope, and qualifiers.
5. Do not invent related requirements.
6. Do not answer the question.
7. Do not use outside knowledge.
8. Choose the type based on the answer the question requires,
   not merely words appearing in the question.

Examples:

Question:
"What is the production database RPO?"

Output:
{"requirements":[
  {"text":"the production database RPO","type":"value"}
]}

Question:
"How do I check filesystem capacity and inode exhaustion?"

Output:
{"requirements":[
  {"text":"how to check filesystem capacity","type":"procedure"},
  {"text":"how to check inode exhaustion","type":"procedure"}
]}

Question:
"May AI restart production without human approval?"

Output:
{"requirements":[
  {
    "text":"whether AI may restart production without human approval",
    "type":"boolean"
  }
]}

Return JSON only:
{"requirements":[{"text":"...","type":"..."}]}
"""


def decompose_typed_question(
    question: str,
) -> TypedDecompositionResult:
    response = client.chat.completions.create(
        model=MODEL,
        temperature=0,
        max_tokens=600,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"/no_think\nQuestion:\n{question}",
            },
        ],
    )

    content = response.choices[0].message.content or ""

    content = re.sub(
        r"<think>.*?</think>",
        "",
        content,
        flags=re.DOTALL,
    ).strip()

    data = json.loads(content)

    result = TypedDecompositionResult.model_validate(data)

    if not result.requirements:
        raise ValueError(
            "Typed question decomposition returned no requirements"
        )

    return result
