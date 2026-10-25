import json
import os
import re
from collections.abc import Mapping

from app.security.api_keys import APIKeyPrincipal


_NAMESPACE_PATTERN = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$"
)

# Lab namespaces the console can investigate when nothing else is configured.
_DEFAULT_NAMESPACES = (
    "ai-ops-demo",
    "scenario-configmap",
    "scenario-port",
    "scenario-network",
)


def _valid(namespace: object) -> str | None:
    if (
        isinstance(namespace, str)
        and len(namespace) <= 63
        and _NAMESPACE_PATTERN.fullmatch(namespace)
    ):
        return namespace

    return None


def load_demo_namespaces(environment: Mapping[str, str]) -> frozenset[str]:
    """Namespaces offered in the console.

    `PRIVATE_AI_DEMO_NAMESPACES` is a comma-separated list. When it is unset,
    namespaces are taken from an existing `PRIVATE_AI_API_KEYS_JSON` allow-list
    so a server that already has that file keeps the same scope. Keys in that
    file are ignored.
    """

    names: list[str] = []
    raw = environment.get("PRIVATE_AI_DEMO_NAMESPACES", "").strip()

    if raw:
        names = [part.strip() for part in raw.split(",") if part.strip()]
    else:
        encoded = environment.get("PRIVATE_AI_API_KEYS_JSON")

        if encoded:
            try:
                entries = json.loads(encoded)
            except (TypeError, ValueError):
                entries = []

            if isinstance(entries, list):
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue

                    for namespace in entry.get("allowed_namespaces") or []:
                        names.append(namespace)

    chosen: list[str] = []

    for namespace in names:
        valid = _valid(namespace)

        if valid and valid not in chosen:
            chosen.append(valid)

    if not chosen:
        chosen = list(_DEFAULT_NAMESPACES)

    return frozenset(chosen)


def demo_principal(environment: Mapping[str, str] | None = None) -> APIKeyPrincipal:
    source = os.environ if environment is None else environment

    return APIKeyPrincipal(
        principal_id="demo",
        allowed_namespaces=load_demo_namespaces(source),
    )
