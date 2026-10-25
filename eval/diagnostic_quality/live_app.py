"""The production ASGI app, with the hypothesis model call recorded.

Only used by `live.py`: every request to the hypothesis stage (messages in,
raw model text out) is appended to `$DQ_CAPTURE_DIR/hypothesis-calls.jsonl`, so
the exact inputs and raw outputs of a live run are preserved for comparison.
Nothing else is changed, and the recording never alters what the model returns.
"""

import json
import os
import time
from pathlib import Path

from app.llm import client
from app.reports.qwen_hypotheses import HYPOTHESIS_SYSTEM_PROMPT

_original = client.chat.completions.create
_capture = Path(os.environ.get("DQ_CAPTURE_DIR", "."))


def _recording_create(**kwargs):
    started = time.monotonic()
    response = _original(**kwargs)
    messages = kwargs.get("messages") or []

    if messages and messages[0].get("content") == HYPOTHESIS_SYSTEM_PROMPT:
        try:
            content = response.choices[0].message.content
        except Exception:
            content = None

        with (_capture / "hypothesis-calls.jsonl").open("a") as handle:
            handle.write(
                json.dumps(
                    {
                        "messages": messages,
                        "content": content,
                        "latency_s": round(time.monotonic() - started, 3),
                    }
                )
                + "\n"
            )

    return response


client.chat.completions.create = _recording_create

from app.api import app  # noqa: E402  (imported after the recorder is installed)
