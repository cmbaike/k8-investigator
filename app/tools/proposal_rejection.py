"""Rejected model proposals: a fixed-vocabulary, bounded, safe record.

A proposal that reaches target validation and is refused (it would inspect
something other than the bound workload) must leave an auditable trace, must
never execute, and must not abort an otherwise safe investigation. This module
holds only the DATA for that: it authorizes nothing and executes nothing.

  reason     one of REJECTION_REASONS (never free text, never an exception
             message, never anything the model wrote);
  arguments  only the Kubernetes identifier keys below, each re-validated here
             as a plain resource name or small integer. Everything else the
             model supplied is discarded, so arbitrary model output and
             sensitive-looking values never reach the audit trail.

The number of rejections an investigation tolerates is bounded by
MAX_REJECTED_PROPOSALS: a model that keeps proposing out-of-target calls
cannot keep the run alive.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

# Reasons `call_outside_target` can return, plus nothing else.
REJECTION_REASONS = frozenset(
    {"outside_target", "target_unresolved", "namespace_wide_events"}
)

MAX_REJECTED_PROPOSALS = 5

_SAFE_NAME_KEYS = ("namespace", "pod", "deployment", "container")
_RESOURCE_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$")
_MAX_TAIL_LINES = 10_000


def safe_proposal_arguments(arguments: Mapping[str, Any]) -> dict[str, str | int]:
    """The audit-safe subset of a model-proposed call's arguments."""
    safe: dict[str, str | int] = {}

    for key in _SAFE_NAME_KEYS:
        value = arguments.get(key)

        if isinstance(value, str) and _RESOURCE_NAME.fullmatch(value):
            safe[key] = value

    tail = arguments.get("tail_lines")

    if type(tail) is int and 0 < tail <= _MAX_TAIL_LINES:
        safe["tail_lines"] = tail

    return safe


@dataclass(frozen=True)
class RejectedProposal:
    ordinal: int  # 1-based, per investigation
    tool: str
    arguments: dict[str, str | int]
    reason: str
