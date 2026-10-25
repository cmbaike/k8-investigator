# Private AI SRE console

A read-only web console for the investigation API. It shows persisted,
evidence-grounded reports: verified findings, unverified AI hypotheses, the
evidence trail, the audit trail and the limitations of each investigation.

It never changes a cluster. There is no execute, apply, restart or delete
control anywhere in it.

Stack: React 19, TypeScript (strict), Vite, Tailwind, TanStack Query, React
Router, Lucide, Vitest and React Testing Library.

## How it fits together

```
browser ──▶ FastAPI  /api/*      open demo routes
                     /console/*  the built SPA (only if frontend/dist exists)
```

- There is no login, API key, or session cookie.
- The namespace list comes from `GET /api/access`.
- The only browser storage is the theme preference (`pai-theme`) and the
  spoken-summary preference (`pai-spoken`).
- The SPA is served under `/console` so it can never shadow an API route.
- There is no second backend. `app.api:app` serves the API and the console.

## Routes

| Path | Purpose |
| --- | --- |
| `/console/` | Overview: backend-derived counts and recent investigations |
| `/console/investigations/new` | Create and start one investigation |
| `/console/investigations` | History with status filter and pagination |
| `/console/investigations/:id` | The persisted report, evidence and audit trail |

## Endpoints used

`GET /api/access`, `GET /api/health`, `GET /api/investigations/stats`, `GET /api/investigations`,
`GET /api/investigations/{id}/summary`, `/report`, `/audit`,
`POST /api/investigations`, `POST /api/investigations/{id}/execute`.

## Run it

Prerequisites: the database and model serving the API already needs, and a
Kubernetes investigator kubeconfig (`scripts/lab_investigator_kubeconfig.sh`).
Optional: `PRIVATE_AI_DEMO_NAMESPACES` (comma-separated). When it is unset,
namespaces are read from `PRIVATE_AI_API_KEYS_JSON` if that file is still
present. Keys in that file are ignored.

Serve the built console from the API (one process):

```bash
cd frontend
npm ci
npm run build
cd ..
scripts/run_lab_api.sh          # then open http://127.0.0.1:8080/console/
```

Develop with hot reload. Vite proxies only `/api` to the backend:

```bash
scripts/run_lab_api.sh          # backend on 127.0.0.1:8080
cd frontend && npm run dev      # http://127.0.0.1:5173/console/
```

To point the dev server elsewhere, set `PRIVATE_AI_BACKEND_URL`.

The namespaces offered in the form are the demo allow-list. The server
re-checks them. No sign-in.

## Checks

```bash
npm run typecheck
npm test
npm run build
```

The tests cover the API client (sanitised errors, timeouts), the dashboard
states, the creation form (explicit target,
namespace-wide scope, no duplicate create, no retry of an uncertain create),
the report (findings vs unverified hypotheses, evidence, audit, polling,
failed, not found, hostile report text) and a static scan of `src` for
credentials, storage and HTML injection.

## Five-minute walkthrough

Use three lab scenarios from `k8s/lab/`. The console shows only real
persisted data. It has no sample mode.

1. **ImagePullBackOff** (`scenario-imagepullbackoff.yaml`). New investigation,
   Deployment, enter the workload name. Show the scope header, the verified
   finding, and open an evidence reference.
2. **OOMKilled** (`scenario-oom.yaml`). Show that the finding comes from
   container state, then the unverified hypotheses (or the "none passed
   validation" message) and the Limitations section.
3. **Running but not ready** (`scenario-readinessprobefailure.yaml`). Show the
   audit trail, including any proposal the application rejected.

Applying scenarios needs an administrator kubeconfig, which the console and
the investigator identity deliberately do not have.

## Known limitations

- The API returns evidence ids only. The console resolves an id by the
  findings and hypotheses that cite it and otherwise says "details
  unavailable". Observation values are not shown.
- The report has no structured target field. The scope header is derived from
  the persisted question by the backend; the report text states the verified
  target.
- Health reports the API and database only, not model availability.
- Execution is synchronous. If you leave the page, the investigation keeps
  running and the page picks it up from history.

## Troubleshooting

- **Blank page at `/`**: the console lives at `/console/`.
- **404 at `/console/`**: run `npm run build` first.
- **"We could not confirm whether the investigation was created"**: check
  History before retrying. The console never retries a create.
