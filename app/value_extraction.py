import json
import os
import re

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel


load_dotenv()

client = OpenAI(
    base_url=os.getenv(
        "VALUE_JUDGE_BASE_URL",
        "http://localhost:11434/v1",
    ),
    api_key=os.getenv(
        "VALUE_JUDGE_API_KEY",
        "ollama",
    ),
)

MODEL = os.getenv(
    "VALUE_JUDGE_MODEL",
    "gpt-oss:20b",
)


class ValueExtractionResult(BaseModel):
    attribute: str | None
    value: str | None
    evidence_quote: str | None


SYSTEM_PROMPT  ="""
Extract an explicit attribute-value binding from the supplied evidence.

The requirement identifies an attribute whose actual value is requested.

Return a result ONLY when one evidence statement explicitly binds
that requested attribute to its value.

Rules:

1. Identify the requested attribute from the requirement.

2. Find a statement in the evidence that explicitly assigns or states
   the value of that same attribute.

3. The attribute and value must be bound together by the evidence.
   Do not take a value from another sentence or another attribute.

4. Mentioning the requested attribute without giving its value is not
   sufficient.

5. Saying where an attribute is defined, documented, stored,
   configured, maintained, or retrieved does not provide its value.

6. A value belonging to another attribute must never be returned.

Examples:
- acknowledgement time = 15 minutes does NOT provide RTO
- backup frequency = 30 minutes does NOT provide backup retention
- staging region does NOT provide production region
- kubectl client version does NOT provide cluster version

7. Preserve all scope and qualifiers exactly.

8. Copy attribute, value, and evidence quote from the supplied evidence.
   Do not infer, calculate, transform, or use outside knowledge.

9. If there is no explicit binding for the requested attribute,
   return all fields as null.

Return JSON only:

{"attribute": null, "value": null, "evidence_quote": null}

or

{"attribute": "...", "value": "...", "evidence_quote": "..."}
"""


def parse_extraction_response(
    content: str,
    finish_reason: str | None,
) -> ValueExtractionResult:
    if finish_reason != "stop":
        return ValueExtractionResult(
            attribute=None,
            value=None,
            evidence_quote=None,
        )

    if not content:
        return ValueExtractionResult(
            attribute=None,
            value=None,
            evidence_quote=None,
        )

    try:
        data = json.loads(content)
        return ValueExtractionResult.model_validate(data)
    except (json.JSONDecodeError, ValueError):
        return ValueExtractionResult(
            attribute=None,
            value=None,
            evidence_quote=None,
        )
        
        

def extract_value(
    requirement: str,
    sources: list[dict],
) -> ValueExtractionResult:
    evidence = "\n\n".join(
        source["content"]
        for source in sources
    )

    response = client.chat.completions.create(
        model=MODEL,
        temperature=0,
        max_tokens=500,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Required value:\n{requirement}\n\n"
                    f"Evidence:\n{evidence}"
                ),
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

    if response.choices[0].finish_reason != "stop":
      return ValueExtractionResult(
        attribute=None,
        value=None,
        evidence_quote=None,
     )
    
    if not content:
      return ValueExtractionResult(
        attribute=None,
        value=None,
        evidence_quote=None,
    )
      
    return parse_extraction_response(
        content,
        response.choices[0].finish_reason,
   )


def _normalize(text: str) -> str:
    return " ".join(text.lower().split())


def validate_grounding(
    result: ValueExtractionResult,
    sources: list[dict],
) -> bool:
    if (
        result.attribute is None
        or result.value is None
        or result.evidence_quote is None
    ):
        return False

    evidence = "\n\n".join(
        source["content"]
        for source in sources
    )

    value = _normalize(result.value)
    quote = _normalize(result.evidence_quote)
    evidence = _normalize(evidence)

    return (
        value in quote
        and quote in evidence
    )