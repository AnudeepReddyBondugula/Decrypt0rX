#!/usr/bin/env bash
# Prints the secrets docker-compose requires. Append to .env once:
#   ./deploy/generate-secrets.sh >> .env
#
# Re-running produces NEW values. Replacing DECRYPT0RX_MASTER_KEY makes every
# stored CA private key undecryptable, so keep the original safe.
set -euo pipefail

gen() { openssl rand -base64 32 | tr -d '\n'; }

cat <<VARS

# --- generated $(date -u +%Y-%m-%dT%H:%M:%SZ) ---
DECRYPT0RX_MASTER_KEY=$(gen)
DECRYPT0RX_JWT_SECRET=$(gen)
POSTGRES_PASSWORD=$(openssl rand -hex 16)
MINIO_ROOT_USER=decrypt0rx
MINIO_ROOT_PASSWORD=$(openssl rand -hex 24)
VARS
