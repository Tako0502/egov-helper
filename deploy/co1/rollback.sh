#!/usr/bin/env bash
# Rollback the signer on atasuai-co-1 to a previously-deployed VERSION.
#
# Usage:
#   ssh atasuai-co-1
#   ~/sign.atasuai.com/egov-helper/deploy/co1/rollback.sh 0.1.0
#
# What it does:
#   1. git checkout signer-vX.Y.Z   (must already exist — created by deploy-signer.yml)
#   2. docker compose build signer
#   3. docker compose up -d signer
#   4. wait for healthy + external probe
#
# To return to current main:
#   ~/sign.atasuai.com/egov-helper/deploy/co1/rollback.sh main

set -euo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <version | main>"
  echo
  echo "Available deployed versions (most recent first):"
  cd ~/sign.atasuai.com/egov-helper
  git fetch --tags --quiet
  git tag --list 'signer-v*' --sort=-creatordate | head -10 | sed 's/^signer-v/  /'
  exit 1
fi

cd ~/sign.atasuai.com/egov-helper
git fetch --all --tags --prune --quiet

if [ "$TARGET" = "main" ]; then
  REF="origin/main"
  LABEL="main (HEAD)"
else
  REF="signer-v${TARGET}"
  if ! git rev-parse "refs/tags/$REF" >/dev/null 2>&1; then
    echo "✗ tag $REF does not exist."
    echo "Did you mean one of these?"
    git tag --list 'signer-v*' --sort=-creatordate | head -10 | sed 's/^/  /'
    exit 1
  fi
  LABEL="signer-v${TARGET}"
fi

echo "Rolling back to: $LABEL  ($REF)"
git reset --hard "$REF"

cd ~/sign.atasuai.com
export APP_VERSION=$(tr -d '[:space:]' < egov-helper/VERSION 2>/dev/null || echo unknown)
COMPOSE_BAKE=false DOCKER_BUILDKIT=0 docker compose build signer
docker compose up -d signer

for i in $(seq 1 30); do
  STATUS=$(docker inspect -f '{{.State.Health.Status}}' egov-signer 2>/dev/null || echo none)
  if [ "$STATUS" = "healthy" ]; then
    echo "✓ signer healthy"
    break
  fi
  sleep 2
done

for i in $(seq 1 10); do
  RESP=$(curl -fsSL -m 10 https://co1-api-sign.atasuai.com/health || true)
  if echo "$RESP" | grep -q '"ok":true'; then
    echo "✓ live: $RESP"
    exit 0
  fi
  sleep 3
done

echo "✗ external health check failed — investigate:"
echo "  docker logs --tail 80 egov-signer"
exit 1
