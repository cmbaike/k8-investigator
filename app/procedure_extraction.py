import json
import os
import re

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel


load_dotenv()


client = OpenAI(
    base_url=os.getenv(
        "PROCEDURE_JUDGE_BASE_URL",
        "http://localhost:11434/v1",
    ),
    api_key=os.getenv(
        "PROCEDURE_JUDGE_API_KEY",
        "ollama",
    ),
)

MODEL = os.getenv(
    "PROCEDURE_JUDGE_MODEL",
    "gpt-oss:20b",
)


class ProcedureExtractionResult(BaseModel):
    requested_operation: str | None
    procedure: str | None
    evidence_quote: str | None


SYSTEM_PROMPT = """
You are an evidence extraction system.

Given one requested procedure and supplied evidence, extract a procedure
only when the evidence explicitly states how to perform the exact
requested operation.

Rules:

1. The evidence must explicitly support the requested operation.

2. A procedure for a related operation is not sufficient.

3. Preserve important scope and qualifiers such as environment,
   system, resource, object, metric, and time context.

4. Do not use outside technical knowledge.

5. Do not infer that a command, tool, or procedure performs an
   operation unless the supplied evidence explicitly binds it to that
   operation.

6. Definitions, explanations, symptoms, or descriptions are not
   procedures unless they explicitly state how to perform the requested
   operation.

7. Copy the procedure from the supplied evidence. Do not invent or
   complete commands using outside knowledge.

8. Copy an evidence quote that explicitly binds the requested operation
   to the extracted procedure.

9. If the evidence does not explicitly contain a procedure for the
   requested operation, return null for all fields.

Return JSON only:

{
  "requested_operation": "..." or null,
  "procedure": "..." or null,
  "evidence_quote": "..." or null
}
"""


def _strip_think(content: str) -> str:
    return re.sub(
        r"<think>.*?</think>",
        "",
        content,
        flags=re.DOTALL,
    ).strip()


def _null_result() -> ProcedureExtractionResult:
    return ProcedureExtractionResult(
        requested_operation=None,
        procedure=None,
        evidence_quote=None,
    )


def _normalize(text: str) -> str:
    return " ".join(text.lower().split())


def parse_procedure_response(
    content: str,
    finish_reason: str | None,
) -> ProcedureExtractionResult:
    if finish_reason != "stop":
        return _null_result()

    content = _strip_think(content)

    if not content:
        return _null_result()

    try:
        data = json.loads(content)
        return ProcedureExtractionResult.model_validate(data)
    except (json.JSONDecodeError, ValueError):
        return _null_result()


def extract_procedure(
    requirement: str,
    sources: list[dict],
) -> ProcedureExtractionResult:
    evidence = "\n\n".join(
        source["content"]
        for source in sources
    )

    response = client.chat.completions.create(
        model=MODEL,
        temperature=0,
        max_tokens=1000,
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": (
                    f"Requested procedure:\n{requirement}\n\n"
                    f"Evidence:\n{evidence}"
                ),
            },
        ],
    )

    choice = response.choices[0]

    return parse_procedure_response(
        choice.message.content or "",
        choice.finish_reason,
    )


def validate_procedure_grounding(
    result: ProcedureExtractionResult,
    sources: list[dict],
) -> bool:
    if (
        result.requested_operation is None
        or result.procedure is None
        or result.evidence_quote is None
    ):
        return False

    evidence = "\n\n".join(
        source["content"]
        for source in sources
    )

    procedure = _normalize(result.procedure)
    quote = _normalize(result.evidence_quote)
    evidence = _normalize(evidence)

    return (
        procedure in quote
        and quote in evidence
    )
