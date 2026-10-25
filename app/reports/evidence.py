from pydantic import BaseModel, ConfigDict, Field

from app.tools.investigation import InvestigationContext


class ReportEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(pattern=r"^ev-[0-9]{4}$")
    request_id: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    field: str = Field(min_length=1)
    value: str | int | float | bool | None
    
    namespace: str | None = None
    pod: str | None = None


def build_report_evidence(
    context: InvestigationContext,
) -> tuple[ReportEvidence, ...]:
    """Project a bounded snapshot of trusted investigation observations."""

    evidence: list[ReportEvidence] = []

    for observation in context.observations:
        if len(evidence) >= 100:
            break

        # A targeted investigation reports only its resolved workload: evidence
        # about any other pod never enters findings or the model's payload.
        if not context.in_target_scope(observation.pod):
            continue

        value = observation.value

        if type(value) not in (str, int, float, bool, type(None)):
            continue

        evidence.append(
            ReportEvidence(
                evidence_id=f"ev-{len(evidence) + 1:04d}",
                request_id=observation.request_id,
                tool=observation.tool,
                field=observation.field,
                value=value,
                namespace=observation.namespace,
                pod=observation.pod,
            )
        )

    return tuple(evidence)