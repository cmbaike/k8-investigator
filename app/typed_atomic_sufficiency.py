from pydantic import BaseModel

from app.sufficiency import (
    SufficiencyResult,
    assess_sufficiency,
)
from app.sufficiency_consistency import apply_consistency_guard
from app.typed_question_decomposition import (
    TypedRequirement,
    decompose_typed_question,
)
from app.value_extraction import (
    extract_value,
    validate_grounding,
)

from app.procedure_extraction import (
    extract_procedure,
    validate_procedure_grounding,
)


class RequirementAssessment(BaseModel):
    requirement: str
    requirement_type: str
    sufficient: bool
    method: str
    reason: str | None = None
    extracted_value: str | None = None
    evidence_quote: str | None = None
    guard_triggered: bool = False


class TypedAtomicSufficiencyResult(BaseModel):
    sufficient: bool
    requirements: list[RequirementAssessment]


def assess_value_requirement(
    requirement: TypedRequirement,
    sources: list[dict],
) -> RequirementAssessment:
    extraction = extract_value(
        requirement.text,
        sources,
    )

    grounded = validate_grounding(
        extraction,
        sources,
    )

    return RequirementAssessment(
        requirement=requirement.text,
        requirement_type=requirement.type,
        sufficient=grounded,
        method="value_extraction",
        extracted_value=extraction.value,
        evidence_quote=extraction.evidence_quote,
    )


def assess_generic_requirement(
    requirement: TypedRequirement,
    sources: list[dict],
) -> RequirementAssessment:
    raw: SufficiencyResult = assess_sufficiency(
        requirement.text,
        sources,
    )

    guarded = apply_consistency_guard(raw)

    return RequirementAssessment(
        requirement=requirement.text,
        requirement_type=requirement.type,
        sufficient=guarded.sufficient,
        method="generic_sufficiency",
        reason=raw.reason,
        guard_triggered=(
            raw.sufficient != guarded.sufficient
        ),
    )


def assess_typed_atomic_sufficiency(
    question: str,
    sources: list[dict],
) -> TypedAtomicSufficiencyResult:
    decomposition = decompose_typed_question(question)

    assessments: list[RequirementAssessment] = []

    for requirement in decomposition.requirements:
        if requirement.type == "value":
            assessment = assess_value_requirement(requirement, sources)
        elif requirement.type == "procedure":
            extraction = extract_procedure(
                requirement.text,
                sources,
            )
            sufficient = validate_procedure_grounding(
                extraction,
                sources,
            )
            assessment = RequirementAssessment(
                requirement=requirement.text,
                requirement_type=requirement.type,
                sufficient=sufficient,
                method="procedure_extraction",
                evidence_quote=extraction.evidence_quote,
            )
        else:
            assessment = assess_generic_requirement(requirement, sources)

        assessments.append(assessment)

    sufficient = (
        bool(assessments)
        and all(
            assessment.sufficient
            for assessment in assessments
        )
    )

    return TypedAtomicSufficiencyResult(
        sufficient=sufficient,
        requirements=assessments,
    )