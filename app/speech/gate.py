"""One in-flight speech job, with a hard wait.

The worker is not killed on timeout (native model calls cannot be cancelled
safely). The slot stays taken until that call returns, and further requests
are refused instead of queued.
"""

import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout

from app.speech.problems import SpeechProblem


class ExecutionGate:
    def __init__(self, *, timeout: float, busy: str, timed_out: str, unavailable: str) -> None:
        if timeout <= 0:
            raise ValueError("Timeout must be positive.")

        self._timeout = timeout
        self._busy = busy
        self._timed_out = timed_out
        self._unavailable = unavailable
        self._semaphore = threading.BoundedSemaphore(1)
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="speech")

    def run(self, function, *args):
        if not self._semaphore.acquire(blocking=False):
            raise SpeechProblem(503, self._busy)

        released = False

        def release(_future=None) -> None:
            nonlocal released

            if not released:
                released = True
                self._semaphore.release()

        future = self._pool.submit(function, *args)

        try:
            result = future.result(timeout=self._timeout)
        except SpeechProblem:
            release()
            raise
        except FuturesTimeout:
            future.add_done_callback(release)
            raise SpeechProblem(504, self._timed_out) from None
        except Exception:
            release()
            raise SpeechProblem(503, self._unavailable) from None
        else:
            release()
            return result

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
