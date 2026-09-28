# AI Cybersecurity Platform

Next.js UI -> FastAPI -> PostgreSQL + pgvector. OpenAI powers embeddings (RAG) and a tool-calling agent
(`SearchKB`, `LookupCVE`). JWT auth with admin / analyst / viewer roles, audit log, JSON logs, Prometheus metrics.

## Run
    cp .env.example .env      # fill in OPENAI_API_KEY and JWT_SECRET
    docker compose up --build
    # UI http://localhost:3000   API docs http://localhost:8000/docs

The first registered user becomes `admin`; everyone after is `viewer`
(promote with `PATCH /users/{id}/role?role=analyst`).

    curl -X POST localhost:8000/auth/register -H 'Content-Type: application/json' \
         -d '{"email":"you@example.com","password":"a-long-password"}'

Load knowledge (analyst/admin): `POST /kb {"source":"ir-playbook","text":"..."}`, then ask questions in the UI.

## Layout
    backend/app/core.py   settings, models, DB      backend/app/ai.py    RAG + agent
    backend/app/auth.py   JWT + RBAC                backend/app/main.py  REST routes, logging, metrics
    frontend/app          login + chat UI

## AWS
ECR (2 images) -> ECS Fargate (frontend public behind ALB; backend private via Service Connect,
build the frontend with `--build-arg BACKEND_URL=http://backend:8000`) -> RDS PostgreSQL 16 (pgvector supported;
run `CREATE EXTENSION vector` once) . OPENAI_API_KEY / JWT_SECRET / DATABASE_URL from Secrets Manager.
Logs: `awslogs` driver -> CloudWatch (already JSON). Metrics: scrape `/metrics` with ADOT/Prometheus.

## Before production
Rate-limit auth + chat (slowapi), Alembic migrations, HNSW index on `chunk.embedding`, pin dependencies,
HTTPS + secure token storage (httpOnly cookie), tests.
