from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.investigations.models import (
    InvestigationRecord,
    InvestigationStatus,
)


def test_pending_investigation_record():
    record = InvestigationRecord(
        investigation_id="inv-001",
        authorized_namespace="ai-ops-demo",
        status=InvestigationStatus.PENDING,
        created_at=datetime.now(timezone.utc),
    )

    assert record.status == InvestigationStatus.PENDING
    assert record.started_at is None
    assert record.finished_at is None
    assert record.stop_reason is None


def test_investigation_record_is_immutable():
    record = InvestigationRecord(
        investigation_id="inv-001",
        authorized_namespace="ai-ops-demo",
        status=InvestigationStatus.PENDING,
        created_at=datetime.now(timezone.utc),
    )

    with pytest.raises(ValidationError):
        record.status = InvestigationStatus.RUNNING


def test_investigation_record_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        InvestigationRecord(
            investigation_id="inv-001",
            authorized_namespace="ai-ops-demo",
            status=InvestigationStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            arbitrary_field="untrusted",
        )


@pytest.mark.parametrize(
    "invalid_id",
    ["", None],
)
def test_investigation_record_rejects_invalid_id(invalid_id):
    with pytest.raises(ValidationError):
        InvestigationRecord(
            investigation_id=invalid_id,
            authorized_namespace="ai-ops-demo",
            status=InvestigationStatus.PENDING,
            created_at=datetime.now(timezone.utc),
        )
