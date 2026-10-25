"""Production dependency wiring for investigation execution."""

import os
from functools import partial

from app.investigations.repository import InvestigationRepository
from app.investigations.service import InvestigationService
from app.reports.qwen_hypotheses import QwenHypothesisProvider
from app.tools.coverage import CoverageProvider, SUPPLEMENTARY_TOOLS
from app.tools.investigation_audit import write_investigation_audit_event
from app.tools.investigation_controller import run_investigation
from app.tools.qwen_proposal import QwenProposalProvider

AI_HYPOTHESES_ENV = "PRIVATE_AI_HYPOTHESES"


def ai_hypotheses_enabled() -> bool:
    """Enabled unless explicitly turned off (off/false/0/no/disabled)."""
    return os.environ.get(AI_HYPOTHESES_ENV, "on").strip().lower() not in {
        "off", "false", "0", "no", "disabled",
    }


def build_investigation_service(
    *,
    repository: InvestigationRepository,
) -> InvestigationService:
    return InvestigationService(
        repository=repository,
        # The model proposes; the coverage policy guarantees that a failing
        # container's logs and workload configuration are examined. Both go
        # through the same authorization, budget and audit boundary.
        provider=CoverageProvider(QwenProposalProvider()),
        runner=partial(
            run_investigation, tolerated_failure_tools=SUPPLEMENTARY_TOOLS
        ),
        audit=write_investigation_audit_event,
        hypothesis_provider=(
            QwenHypothesisProvider() if ai_hypotheses_enabled() else None
        ),
    )
