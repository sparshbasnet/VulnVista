#!/usr/bin/env sh
set -e

# The database schema is owned by Alembic migrations (backend/alembic); the app
# no longer creates tables at runtime. Apply any pending migrations before the
# app starts so a fresh database is provisioned automatically. Set
# RUN_MIGRATIONS=0 to skip (e.g. when migrations are applied out of band).
if [ "${RUN_MIGRATIONS:-1}" = "1" ]; then
  echo "[entrypoint] applying database migrations: alembic upgrade head"
  uv run alembic upgrade head
fi

exec "$@"
