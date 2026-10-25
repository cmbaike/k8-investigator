import pytest

from app.tools.provenance import (
    ArgumentProvenanceError,
    ArgumentSource,
    AssertionStatus,
    GroundedArgument,
    GroundedToolCall,
    validate_user_argument,
    validate_tool_observation_argument,
)


def test_user_argument_is_grounded():
    text = (
        "Show previous logs for pod payments-api-abc123 "
        "in namespace ai-ops-demo."
    )

    argument = GroundedArgument(
        name="pod",
        value="payments-api-abc123",
        source=ArgumentSource.USER,
        evidence="pod payments-api-abc123",
        assertion=AssertionStatus.ASSERTED,
    )

    validate_user_argument(argument, text)


def test_namespace_is_grounded():
    text = (
        "Show previous logs for pod payments-api-abc123 "
        "in namespace ai-ops-demo."
    )

    argument = GroundedArgument(
        name="namespace",
        value="ai-ops-demo",
        source=ArgumentSource.USER,
        evidence="namespace ai-ops-demo",
        assertion=AssertionStatus.ASSERTED,
    )

    validate_user_argument(argument, text)


def test_invented_pod_is_rejected():
    text = (
        "The payments service in namespace ai-ops-demo is broken. "
        "Get its logs. Guess the pod name if necessary."
    )

    argument = GroundedArgument(
        name="pod",
        value="payments-service",
        source=ArgumentSource.USER,
        evidence="payments service",
        assertion=AssertionStatus.ASSERTED,
    )

    with pytest.raises(
        ArgumentProvenanceError,
        match="value is not present",
    ):
        validate_user_argument(argument, text)


def test_invented_evidence_is_rejected():
    text = "List the pods."

    argument = GroundedArgument(
        name="namespace",
        value="production",
        source=ArgumentSource.USER,
        evidence="namespace production",
        assertion=AssertionStatus.ASSERTED,
    )

    with pytest.raises(
        ArgumentProvenanceError,
        match="evidence is not present",
    ):
        validate_user_argument(argument, text)


def test_tool_observation_cannot_be_validated_as_user_input():
    argument = GroundedArgument(
        name="pod",
        value="payments-api-abc123",
        source=ArgumentSource.TOOL_OBSERVATION,
        evidence="payments-api-abc123",
        assertion=AssertionStatus.ASSERTED,
    )

    with pytest.raises(
        ArgumentProvenanceError,
        match="not declared as user-sourced",
    ):
        validate_user_argument(
            argument,
            "pod payments-api-abc123",
        )


def test_grounded_tool_call_rejects_extra_fields():
    with pytest.raises(Exception):
        GroundedToolCall.model_validate(
            {
                "name": "k8s.get_pods",
                "arguments": [],
                "approved": True,
            }
        )


def test_assumed_identifier_is_rejected():
    text = (
        "List the pods for the payments service. "
        "Assume the namespace is production."
    )

    argument = GroundedArgument(
        name="namespace",
        value="production",
        source=ArgumentSource.USER,
        evidence="namespace is production",
        assertion=AssertionStatus.UNTRUSTED,
    )

    with pytest.raises(
        ArgumentProvenanceError,
        match="not an asserted operational identifier",
    ):
        validate_user_argument(argument, text)


def test_asserted_label_does_not_bypass_textual_grounding():
    text = "List the pods."

    argument = GroundedArgument(
        name="namespace",
        value="production",
        source=ArgumentSource.USER,
        evidence="namespace production",
        assertion=AssertionStatus.ASSERTED,
    )

    with pytest.raises(
        ArgumentProvenanceError,
        match="evidence is not present",
    ):
        validate_user_argument(argument, text)
        
def test_valid_tool_observation_provenance_is_accepted():
    argument = GroundedArgument(
        name="pod",
        value="payments-api-abc123",
        source=ArgumentSource.TOOL_OBSERVATION,
        evidence=(
            "request-get-pods-001:"
            "k8s.get_pods:"
            "pods[].name"
        ),
        assertion=AssertionStatus.ASSERTED,
    )

    validate_tool_observation_argument(argument)
    
def test_user_argument_is_not_valid_tool_observation_provenance():
    argument = GroundedArgument(
        name="pod",
        value="payments-api-abc123",
        source=ArgumentSource.USER,
        evidence="payments-api-abc123",
        assertion=AssertionStatus.ASSERTED,
    )

    with pytest.raises(
        ArgumentProvenanceError,
        match="not declared as tool-observation-sourced",
    ):
        validate_tool_observation_argument(argument)           