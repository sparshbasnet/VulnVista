#!/usr/bin/env bash
# Idempotent local bootstrap for VulnVista.
# - Creates the host-backed persistent storage directories.
# - Copies .env.example to .env if .env doesn't exist yet.
# - Pre-creates the shared Docker network so lab/docker-compose.yml can be
#   started independently of the root stack's startup order.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p storage/postgres storage/uploads storage/lab/juice-shop
echo "Storage directories ready under ./storage"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example — review it before running docker compose up."
else
  echo ".env already exists, leaving it as-is."
fi

if ! docker network inspect vulnvista_net >/dev/null 2>&1; then
  docker network create vulnvista_net
  echo "Created Docker network vulnvista_net"
else
  echo "Docker network vulnvista_net already exists."
fi

echo "Setup complete. Next: docker compose up --build"
