from dataclasses import dataclass


class NamespaceAuthorizationError(Exception):
    """The requested namespace is outside the demo allow-list."""


@dataclass(frozen=True)
class APIKeyPrincipal:
    """Caller identity used to scope investigations.

    The hackathon demo has no login. This object still carries the namespaces
    the console may investigate.
    """

    principal_id: str
    allowed_namespaces: frozenset[str]


def authorize_namespace(
    principal: APIKeyPrincipal,
    namespace: str,
) -> None:
    if namespace not in principal.allowed_namespaces:
        raise NamespaceAuthorizationError(
            "Namespace access denied."
        )
