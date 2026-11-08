# Development

## Compose workflow

Docker Compose is the supported full-stack development environment. Use `surfacemap start`, `surfacemap logs api`, and `surfacemap stop`. Rebuild after editing a service with `docker compose up -d --build <service>`. Database changes belong in Alembic migrations under `backend/migrations/versions/`; update SQLAlchemy models and schemas in the same change.

## Backend

Python 3.12 is used in the API and worker images. For isolated API work, create a virtual environment, install `backend/requirements.txt`, set `DATABASE_URL`, then run `alembic upgrade head` and `uvicorn app.main:app --reload` from `backend/`. Redis is required for Celery background execution. Run backend tests with `pytest -q` from `backend/`.

## Frontend

Use Node.js to install dependencies and run `npm run dev` from `frontend/`. The Vite development server proxies API requests to the backend. Production uses the Nginx image in `frontend/Dockerfile`.

## Integration details

The adapter manifest, safety rules, managed paths, output parser mapping, and installer behavior are documented in [tool-adapters.md](tool-adapters.md). Imports use the same parse and persistence service as scan job output. Keep importer changes aligned with [import-formats.md](import-formats.md). Never pass user-controlled command text through a shell; expand adapter flags only through the server allowlist.
