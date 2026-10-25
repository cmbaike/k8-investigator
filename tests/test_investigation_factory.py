from unittest.mock import Mock, patch

from app.investigations.factory import build_investigation_service
from app.investigations.service import InvestigationService
from app.tools.coverage import SUPPLEMENTARY_TOOLS, CoverageProvider
from app.tools.investigation_audit import write_investigation_audit_event
from app.tools.investigation_controller import run_investigation


def test_factory_wires_production_investigation_dependencies():
    repository = Mock()

    with patch(
        "app.investigations.factory.QwenProposalProvider"
    ) as provider_class:
        provider = provider_class.return_value

        service = build_investigation_service(
            repository=repository,
        )

    assert isinstance(service, InvestigationService)
    assert service.repository is repository
    # The model proposes; the deterministic coverage policy wraps it.
    assert isinstance(service.provider, CoverageProvider)
    assert service.provider._inner is provider
    assert service.runner.func is run_investigation
    assert service.runner.keywords == {
        "tolerated_failure_tools": SUPPLEMENTARY_TOOLS
    }
    assert service.audit is write_investigation_audit_event

    provider_class.assert_called_once_with()
