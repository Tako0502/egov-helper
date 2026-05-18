#!/usr/bin/env bash
# One-command bootstrap for a fresh Linux server.
#
# Run on the server (Ubuntu / Debian / similar):
#   curl -fsSL https://raw.githubusercontent.com/Tako0502/egov-helper/main/deploy/install.sh | bash
#
# Or after cloning the repo:
#   cd deploy && ./install.sh
#
# What it does:
#   1. Installs Docker + docker-compose plugin if missing
#   2. Clones the repo if you ran the curl version
#   3. Walks you through dropping in the Kalkan JARs (which are licensed and can't be
#      bundled — you have to get them from sdk.pki.gov.kz)
#   4. Brings up the production stack (Caddy + signer)
#   5. Waits for /health and prints the URL

set -e

REPO_URL="${REPO_URL:-https://github.com/Tako0502/egov-helper.git}"
BRANCH="${BRANCH:-main}"
DOMAIN="${DOMAIN:-sign.3100.kz}"

echo "═══════════════════════════════════════════════════════════════"
echo "  egov-helper-signer  →  $DOMAIN"
echo "═══════════════════════════════════════════════════════════════"

# ─── 1. Docker ────────────────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  echo ""
  echo "[1/5] Installing Docker…"
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER" || true
  echo "  ⚠️  Log out and back in for docker group membership to take effect."
else
  echo "[1/5] Docker ✓  ($(docker --version))"
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "  ✗ docker compose plugin missing — install with: sudo apt install docker-compose-plugin"
  exit 1
fi

# ─── 2. Clone repo (if not running from inside one) ───────────────────────
if [ ! -f "../packages/java/egov-helper-signer/Dockerfile" ]; then
  TARGET="${TARGET:-$HOME/egov-helper}"
  echo ""
  echo "[2/5] Cloning $REPO_URL → $TARGET"
  if [ -d "$TARGET" ]; then
    echo "  ($TARGET already exists, pulling latest)"
    git -C "$TARGET" pull
  else
    git clone --branch "$BRANCH" "$REPO_URL" "$TARGET"
  fi
  cd "$TARGET/deploy"
else
  echo "[2/5] Repo already present ✓"
fi

LIBS_DIR="$(cd .. && pwd)/packages/java/egov-helper-signer/libs"

# ─── 3. Kalkan JARs ───────────────────────────────────────────────────────
echo ""
echo "[3/5] Checking Kalkan JARs…"
NEEDED=(
  "$LIBS_DIR/knca_provider_jce_kalkan-0.7.5.jar"
  "$LIBS_DIR/knca_provider_util-0.8.5.jar"
)

MISSING=0
for f in "${NEEDED[@]}"; do
  if [ ! -s "$f" ]; then
    echo "  ✗ missing or empty: $(basename "$f")"
    MISSING=$((MISSING + 1))
  else
    echo "  ✓ $(basename "$f")  ($(stat -c%s "$f" 2>/dev/null || stat -f%z "$f") bytes)"
  fi
done

if [ "$MISSING" -gt 0 ]; then
  cat <<EOF

You need the Kalkan JARs before continuing. They're licensed by NUC RK and
can't be redistributed — you have to apply for SDK access at:

  https://sdk.pki.gov.kz/

Once approved (1-3 business days), download the SDK, extract with \`unar\`
(NOT macOS Archive Utility — it produces 0-byte files for this archive),
and copy these two JARs to the server:

  scp SDK\\ 2.0/Java/provider/knca_provider_jce_kalkan-0.7.5.jar  user@$(hostname):${NEEDED[0]}
  scp SDK\\ 2.0/Java/utils/knca_provider_util-0.8.5.jar           user@$(hostname):${NEEDED[1]}

Then re-run this script.
EOF
  exit 2
fi

# ─── 4. .env ──────────────────────────────────────────────────────────────
echo ""
echo "[4/5] Configuration…"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "  Created .env from template. Edit it now if your origin isn't https://3100.kz:"
  echo "    nano .env"
  read -rp "  Press ENTER when done, or Ctrl-C to bail…"
else
  echo "  .env already exists ✓"
fi

# ─── 5. Up ────────────────────────────────────────────────────────────────
echo ""
echo "[5/5] Bringing up the production stack…"
docker compose -f docker-compose.production.yml up -d --build

echo ""
echo "Waiting for the signer to report healthy (~30s for Caddy to grab a TLS cert)…"

ATTEMPTS=0
until curl -fsSL "https://$DOMAIN/health" >/dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [ "$ATTEMPTS" -gt 30 ]; then
    echo ""
    echo "✗ Service not reachable at https://$DOMAIN/health after 60s."
    echo "  Check:"
    echo "    docker compose -f docker-compose.production.yml logs caddy"
    echo "    docker compose -f docker-compose.production.yml logs signer"
    exit 1
  fi
  sleep 2
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "✓ Live at:  https://$DOMAIN"
echo ""
curl -s "https://$DOMAIN/health"
echo ""
echo ""
echo "Use from your frontend:"
echo "  signDocument(p12, password, doc, { backendUrl: 'https://$DOMAIN' })"
echo "═══════════════════════════════════════════════════════════════"
