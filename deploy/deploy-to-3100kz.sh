#!/usr/bin/env bash
# One-command deploy to sign.3100.kz, run from your laptop.
#
# What it does (in order):
#   1. Builds the fat JAR locally (idempotent — skipped if already built)
#   2. Uploads the JAR to /home/cloud-user/www/sign.3100.kz/
#   3. Installs java-17-openjdk-headless on the server (one-time)
#   4. Writes /etc/systemd/system/egov-signer.service
#   5. Writes /etc/caddy/sites/sign.3100.kz.caddy
#   6. systemctl daemon-reload + enable --now egov-signer
#   7. systemctl reload caddy
#   8. Smoke-tests https://sign.3100.kz/health
#
# Touches: only the four NEW files listed above. Does not modify the existing
# Caddyfile, any existing service, or any port currently in use.
#
# Run from the repo root:
#   bash deploy/deploy-to-3100kz.sh

set -euo pipefail

KEY="${KEY:-$HOME/Downloads/atasuai.test.server.key}"
HOST="${HOST:-cloud-user@45.82.31.47}"
DOMAIN="${DOMAIN:-sign.3100.kz}"
PORT_INTERNAL="${PORT_INTERNAL:-7676}"
ALLOWED_ORIGIN="${ALLOWED_ORIGIN:-https://3100.kz}"

JAR_LOCAL="packages/java/egov-helper-signer/target/egov-helper-signer.jar"
APP_DIR_REMOTE="/home/cloud-user/www/$DOMAIN"

ssh_run() { ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=20 "$HOST" "$@"; }
scp_to()  { scp -i "$KEY" -o BatchMode=yes -o ConnectTimeout=20 "$1" "$HOST:$2"; }

echo "════════════════════════════════════════════════════════════"
echo "  Deploying  egov-helper-signer  →  https://$DOMAIN"
echo "════════════════════════════════════════════════════════════"

# ─── 1. Build the JAR locally if missing ──────────────────────────────────
if [ ! -s "$JAR_LOCAL" ]; then
  echo ""
  echo "[1/8] Building fat JAR locally…"
  ( cd packages/java/egov-helper-signer && ./build.sh )
fi
echo "[1/8] JAR: $(ls -lh "$JAR_LOCAL" | awk '{print $5}')"

# ─── 2. Upload the JAR ────────────────────────────────────────────────────
echo ""
echo "[2/8] Creating $APP_DIR_REMOTE and uploading JAR…"
ssh_run "mkdir -p '$APP_DIR_REMOTE'"
scp_to "$JAR_LOCAL" "$APP_DIR_REMOTE/egov-helper-signer.jar"

# ─── 3. Install Java 17 ───────────────────────────────────────────────────
echo ""
echo "[3/8] Ensuring Java 17 is installed…"
ssh_run "command -v java >/dev/null 2>&1 || sudo dnf install -y java-17-openjdk-headless"
ssh_run "java -version 2>&1 | head -1"

# ─── 4. systemd service file ──────────────────────────────────────────────
echo ""
echo "[4/8] Writing /etc/systemd/system/egov-signer.service…"
ssh_run "sudo tee /etc/systemd/system/egov-signer.service >/dev/null" <<EOF
[Unit]
Description=egov-helper-signer (Kalkan-backed CMS signer for $DOMAIN)
After=network.target

[Service]
Type=simple
User=cloud-user
WorkingDirectory=$APP_DIR_REMOTE
Environment=PORT=$PORT_INTERNAL
Environment=ALLOWED_ORIGIN=$ALLOWED_ORIGIN
Environment=MAX_BODY_MB=8
Environment=REQUIRE_HTTPS=true
Environment=DEBUG_DUMP_REQS=false
ExecStart=/usr/bin/java -Xms128m -Xmx512m -jar $APP_DIR_REMOTE/egov-helper-signer.jar
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# ─── 5. Caddy site file ───────────────────────────────────────────────────
echo ""
echo "[5/8] Writing /etc/caddy/sites/$DOMAIN.caddy…"
ssh_run "sudo tee /etc/caddy/sites/$DOMAIN.caddy >/dev/null" <<EOF
$DOMAIN {
    encode gzip zstd

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options    "nosniff"
        X-Frame-Options           "DENY"
        Referrer-Policy           "no-referrer"
        -Server
    }

    reverse_proxy 127.0.0.1:$PORT_INTERNAL {
        header_up X-Forwarded-Proto https
    }

    request_body {
        max_size 8MB
    }

    log {
        output stdout
    }
}
EOF

# ─── 6. Enable + start the signer ─────────────────────────────────────────
echo ""
echo "[6/8] Starting egov-signer.service…"
ssh_run "sudo systemctl daemon-reload"
ssh_run "sudo systemctl enable --now egov-signer.service"
sleep 3
ssh_run "systemctl is-active egov-signer.service" || (
  echo "✗ service failed to start. Logs:"
  ssh_run "sudo journalctl -u egov-signer.service -n 40 --no-pager"
  exit 1
)

# Verify it's serving on the internal port before touching Caddy.
echo ""
echo "[7/8] Probing local health on 127.0.0.1:$PORT_INTERNAL…"
ssh_run "curl -fsSL http://127.0.0.1:$PORT_INTERNAL/health"
echo ""

# ─── 7. Reload Caddy (graceful — no downtime for other sites) ─────────────
echo ""
echo "[7/8] Reloading Caddy (graceful)…"
ssh_run "sudo systemctl reload caddy"

# ─── 8. External smoke test ───────────────────────────────────────────────
echo ""
echo "[8/8] Waiting for HTTPS cert + first external request…"
ATTEMPTS=0
until curl -fsSL "https://$DOMAIN/health" >/dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [ "$ATTEMPTS" -gt 30 ]; then
    echo "✗ https://$DOMAIN/health unreachable after 60s. Check:"
    echo "    ssh -i $KEY $HOST sudo journalctl -u caddy -n 30 --no-pager"
    exit 1
  fi
  sleep 2
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✓ Live at:  https://$DOMAIN"
echo ""
curl -s "https://$DOMAIN/health"
echo ""
echo ""
echo "Configure your frontends with:"
echo "  backendUrl: 'https://$DOMAIN'"
echo "════════════════════════════════════════════════════════════"
