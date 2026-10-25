import json

from app.security.config import demo_principal, load_demo_namespaces


def test_explicit_namespace_list_is_used():
    namespaces = load_demo_namespaces({
        "PRIVATE_AI_DEMO_NAMESPACES": "ai-ops-demo, scenario-port",
    })

    assert namespaces == frozenset({"ai-ops-demo", "scenario-port"})


def test_existing_key_file_contributes_namespaces_and_ignores_the_key():
    environment = {
        "PRIVATE_AI_API_KEYS_JSON": json.dumps([
            {
                "principal_id": "beta-user-1",
                "key_sha256": "a" * 64,
                "allowed_namespaces": ["ai-ops-demo", "staging"],
            }
        ])
    }

    principal = demo_principal(environment)

    assert principal.principal_id == "demo"
    assert principal.allowed_namespaces == frozenset({"ai-ops-demo", "staging"})


def test_missing_configuration_uses_the_lab_namespaces():
    namespaces = load_demo_namespaces({})

    assert "ai-ops-demo" in namespaces
