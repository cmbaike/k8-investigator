from app.tools.identifiers import (
    extract_user_identifiers,
    find_asserted_user_identifier,
)
from app.tools.provenance import AssertionStatus
from app.tools.identifiers import _IDENTIFIER_PATTERNS


def test_extracts_asserted_namespace():
    identifiers = extract_user_identifiers(
        "List pods in namespace ai-ops-demo."
    )

    assert len(identifiers) == 1
    assert identifiers[0].name == "namespace"
    assert identifiers[0].value == "ai-ops-demo"
    assert identifiers[0].assertion == AssertionStatus.ASSERTED


def test_extracts_asserted_pod_and_namespace():
    identifiers = extract_user_identifiers(
        "Show logs for pod payments-api-abc123 "
        "in namespace ai-ops-demo."
    )

    values = {
        (item.name, item.value, item.assertion)
        for item in identifiers
    }

    assert (
        "pod",
        "payments-api-abc123",
        AssertionStatus.ASSERTED,
    ) in values

    assert (
        "namespace",
        "ai-ops-demo",
        AssertionStatus.ASSERTED,
    ) in values


def test_assumed_namespace_is_untrusted():
    identifiers = extract_user_identifiers(
        "List the pods for the payments service. "
        "Assume the namespace is production."
    )

    namespace = next(
        item
        for item in identifiers
        if item.name == "namespace"
    )
    print(f"=======${namespace.value}")
    assert namespace.value == "production"
    assert namespace.assertion == AssertionStatus.UNTRUSTED


def test_guessed_pod_is_untrusted():
    identifiers = extract_user_identifiers(
        "Guess the pod payments-api-abc123 and show its logs."
    )

    pod = next(
        item
        for item in identifiers
        if item.name == "pod"
    )

    assert pod.assertion == AssertionStatus.UNTRUSTED


def test_asserted_lookup_ignores_untrusted_identifier():
    identifiers = extract_user_identifiers(
        "Assume the namespace is production."
    )

    result = find_asserted_user_identifier(
        identifiers,
        "namespace",
        "production",
    )

    assert result is None
    
def test_namespace_with_is_captures_identifier_not_is():
    identifiers = extract_user_identifiers(
        "The namespace is production."
    )

    assert len(identifiers) == 1
    assert identifiers[0].name == "namespace"
    assert identifiers[0].value == "production"
    
    
def test_all_identifier_patterns_define_value_group():
    for name, pattern in _IDENTIFIER_PATTERNS.items():
        assert "value" in pattern.groupindex, (
            f"{name} identifier pattern must define "
            "a named 'value' capture group"
        )        