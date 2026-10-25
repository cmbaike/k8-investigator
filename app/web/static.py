"""Serve the built single-page app (frontend/dist) under /console.

Nothing is served unless the build exists. The app lives under /console so its
client-side routes (for example /console/investigations/new) can never shadow
the API routes (/investigations/...). Unknown paths under /console return the
app shell so deep links and refreshes work; paths that look like files that do
not exist return 404.
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, RedirectResponse

DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
BASE = "/console"

# The app is a static bundle with no inline scripts; the policy keeps it that
# way. 'unsafe-inline' is allowed for styles only (Tailwind/Radix set style
# attributes).
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


def mount_frontend(app: FastAPI, dist: Path = DIST) -> bool:
    index = dist / "index.html"

    if not index.is_file():
        return False

    root = dist.resolve()

    @app.get("/", include_in_schema=False)
    def root_redirect():
        return RedirectResponse(f"{BASE}/")

    @app.get(BASE, include_in_schema=False)
    @app.get(BASE + "/{path:path}", include_in_schema=False)
    def console(path: str = ""):
        candidate = (root / path).resolve()

        if path and candidate.is_file() and root in candidate.parents:
            headers = dict(HEADERS)

            if path.startswith("assets/"):
                headers["Cache-Control"] = "public, max-age=31536000, immutable"

            return FileResponse(candidate, headers=headers)

        if "." in path.rsplit("/", 1)[-1]:
            raise HTTPException(status_code=404)

        return FileResponse(index, headers={**HEADERS, "Cache-Control": "no-store"})

    return True
