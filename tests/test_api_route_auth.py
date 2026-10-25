from fastapi.testclient import TestClient

from app.api import app


def test_routes_do_not_require_an_api_key():
    app.dependency_overrides.clear()

    with TestClient(app) as client:
        routes = [
            ("POST", "/tools/run"),
            ("POST", "/ask"),
            ("POST", "/documents"),
            ("GET", "/documents"),
            ("GET", "/documents/1"),
            ("DELETE", "/documents/1"),
        ]

        for method, path in routes:
            response = client.request(method, path)

            assert response.status_code != 401, (
                method,
                path,
                response.status_code,
            )
