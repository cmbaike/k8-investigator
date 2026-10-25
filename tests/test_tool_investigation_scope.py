import pytest

from app.tools.binder import (
    ToolBindingError,
    bind_proposed_user_tool_call,
)
from app.tools.investigation import InvestigationScopeError
from app.tools.investigation_scope import (
    InvestigationScopeCreationError,
    create_investigation_context,
    extract_authorized_namespace,
)
from app.tools.models import ToolCall
from app.tools.investigation_authority import (
    infer_investigation_authority,
)


USER_TEXT = (
    "Investigate the failing workload "
    "in namespace ai-ops-demo."
)


def test_extracts_explicit_namespace():
    assert extract_authorized_namespace(
        USER_TEXT
    ) == "ai-ops-demo"


def test_rejects_missing_namespace():
    with pytest.raises(InvestigationScopeCreationError):
        create_investigation_context(
            "Investigate the failing workload."
        )


def test_rejects_multiple_namespace_mentions():
    with pytest.raises(InvestigationScopeCreationError):
        create_investigation_context(
            "Investigate workload in namespace ai-ops-demo "
            "and namespace production."
        )


def test_context_captures_namespace():
    context = create_investigation_context(USER_TEXT)

    assert context.authorized_namespace == "ai-ops-demo"


def test_initial_pod_listing_within_scope():
    context = create_investigation_context(USER_TEXT)

    proposed = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "ai-ops-demo",
        },
    )

    bound = bind_proposed_user_tool_call(
        proposed,
        USER_TEXT,
        context=context,
    )

    assert bound.arguments["namespace"] == "ai-ops-demo"


def test_cross_namespace_pod_listing_is_rejected():
    context = create_investigation_context(USER_TEXT)

    proposed = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "production",
        },
    )

    with pytest.raises(InvestigationScopeError):
        bind_proposed_user_tool_call(
            proposed,
            USER_TEXT,
            context=context,
        )


def test_missing_namespace_is_rejected():
    context = create_investigation_context(USER_TEXT)

    proposed = ToolCall(
        name="k8s.get_pods",
        arguments={},
    )

    with pytest.raises(InvestigationScopeError):
        bind_proposed_user_tool_call(
            proposed,
            USER_TEXT,
            context=context,
        )


def test_context_from_different_request_is_rejected():
    context = create_investigation_context(USER_TEXT)

    with pytest.raises(ToolBindingError):
        bind_proposed_user_tool_call(
            ToolCall(
                name="k8s.get_pods",
                arguments={
                    "namespace": "ai-ops-demo",
                },
            ),
            (
                "Investigate the failing pod "
                "in namespace ai-ops-demo."
            ),
            context=context,
        )
