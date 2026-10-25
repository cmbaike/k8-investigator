"""Background renewal of a PostgreSQL investigation execution lease."""

from __future__ import annotations

from threading import Event, Lock, Thread
from uuid import UUID

from app.investigations.repository import InvestigationRepository



class InvestigationLeaseLostError(RuntimeError):
    """The worker can no longer establish ownership of an investigation."""


class InvestigationLeaseHeartbeat:
    def __init__(
        self,
        *,
        repository: InvestigationRepository,
        investigation_id: str,
        authorized_namespace: str,
        lease_token: UUID,
        lease_seconds: int = 120,
        interval_seconds: float = 30.0,
        shutdown_timeout_seconds: float = 8.0,
    ) -> None:
        if not 1 <= lease_seconds <= 3600:
            raise ValueError("Lease duration must be between 1 and 3600 seconds.")

        if not 0 < interval_seconds < lease_seconds:
            raise ValueError("Heartbeat interval must be shorter than lease duration.")
        
        if shutdown_timeout_seconds <= 0:
            raise ValueError("Heartbeat shutdown timeout must be positive.")

        self.repository = repository
        self.investigation_id = investigation_id
        self.authorized_namespace = authorized_namespace
        self.lease_token = lease_token
        self.lease_seconds = lease_seconds
        self.interval_seconds = interval_seconds
        self.shutdown_timeout_seconds = shutdown_timeout_seconds

        self._stop = Event()
        self._lock = Lock()
        self._failure: Exception | None = None
        self._thread: Thread | None = None

    def check(self) -> None:
        """Fail closed if a background renewal has failed."""
        with self._lock:
            failure = self._failure

        if failure is not None:
            raise InvestigationLeaseLostError(
                "Investigation execution lease is no longer verified."
            ) from failure

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                self.repository.renew_investigation_lease(
                    investigation_id=self.investigation_id,
                    authorized_namespace=self.authorized_namespace,
                    lease_token=self.lease_token,
                    lease_seconds=self.lease_seconds,
                )
            except Exception as exc:
                with self._lock:
                    self._failure = exc

                self._stop.set()
                return

    def __enter__(self) -> InvestigationLeaseHeartbeat:
        self._thread = Thread(
            target=self._run,
            name="investigation-lease-heartbeat",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._stop.set()

        if self._thread is None:
            return
        self._thread.join(timeout=self.shutdown_timeout_seconds)
        if self._thread.is_alive():
            raise InvestigationLeaseLostError(
                "Heartbeat shutdown timed out; execution ownership "
                "cannot be safely verified."
            )
        self.check()    
