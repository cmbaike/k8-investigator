from unittest.mock import patch

import pytest

from app.investigations.repository import InvestigationRepository


def test_repository_configures_postgresql_timeouts():
    repository = InvestigationRepository(
        database_url="postgresql://example.invalid/test",
        connect_timeout_seconds=3,
        statement_timeout_ms=4000,
        lock_timeout_ms=1500,
    )

    with patch(
        "app.investigations.repository.psycopg.connect"
    ) as connect:
        repository._connect()

    connect.assert_called_once_with(
        "postgresql://example.invalid/test",
        connect_timeout=3,
        options=(
            "-c statement_timeout=4000 "
            "-c lock_timeout=1500"
        ),
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"connect_timeout_seconds": 0},
        {"statement_timeout_ms": 0},
        {"lock_timeout_ms": 0},
    ],
)
def test_repository_rejects_invalid_timeouts(kwargs):
    with pytest.raises(ValueError):
        InvestigationRepository(
            database_url="postgresql://example.invalid/test",
            **kwargs,
        )
