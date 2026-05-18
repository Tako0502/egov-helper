# Production deployment — sign.3100.kz

What you'll end up with: an HTTPS signer service at `https://sign.3100.kz`, auto-renewing TLS cert, no Java/Maven on the host (Docker handles it), `~30s` cold start.

```
Internet ──:443──▶ Caddy ──(private docker net)──▶ Kalkan signer
                    │  Let's Encrypt auto cert       :7676 internal
                    │  TLS termination
                    │  HTTPS redirect + HSTS
                    └  Reverse proxy to signer
```

---

## Prerequisites

- A Linux server (any cloud or bare metal). 1 vCPU / 1 GB RAM is plenty for small load.
- **DNS A record**: `sign.3100.kz` → your server's public IP.
- **Firewall / security group**: ports `80` and `443` open inbound.
- **Kalkan JARs** from <https://sdk.pki.gov.kz/> (developer approval required, 1–3 days).
- Optional: a non-root user with sudo.

---

## One-command deploy

On a fresh server:

```bash
curl -fsSL https://raw.githubusercontent.com/Tako0502/egov-helper/main/deploy/install.sh \
  | DOMAIN=sign.3100.kz bash
```

This installs Docker (if missing), clones the repo, walks you through dropping in the Kalkan JARs, brings up the stack, and waits for HTTPS to be live. Expect to see:

```
✓ Live at:  https://sign.3100.kz
{"ok":true,"kalkan":"KALKAN/0.7"}
```

---

## Manual deploy (if you'd rather see every step)

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker

# 2. Clone the repo
git clone https://github.com/Tako0502/egov-helper.git
cd egov-helper

# 3. Drop in the Kalkan JARs (you need both — see the SDK request flow above)
# Copy from your laptop to the server:
#   scp SDK\ 2.0/Java/provider/knca_provider_jce_kalkan-0.7.5.jar  user@server:~/egov-helper/packages/java/egov-helper-signer/libs/
#   scp SDK\ 2.0/Java/utils/knca_provider_util-0.8.5.jar           user@server:~/egov-helper/packages/java/egov-helper-signer/libs/

# 4. Configure
cd deploy
cp .env.example .env
nano .env    # set ALLOWED_ORIGIN to the frontend(s) that will call this service

# 5. Up
docker compose -f docker-compose.production.yml up -d --build

# 6. Watch the logs (first run grabs a TLS cert from Let's Encrypt)
docker compose -f docker-compose.production.yml logs -f
```

After ~30 seconds you should see Caddy report a successful TLS handshake and the signer log `Listening on http://0.0.0.0:7676`.

Verify from anywhere:

```bash
curl https://sign.3100.kz/health
# {"ok":true,"kalkan":"KALKAN/0.7"}
```

---

## Point your frontends at it

```ts
import { signDocument, checkBin } from '@smoker_winston/egov-helper';

await signDocument(p12, password, doc, {
  backendUrl: 'https://sign.3100.kz',
});
```

Every consumer in your team uses the same URL. No client-side TLS plumbing, no API keys, no per-app config.

---

## Operations

| Task | Command |
|---|---|
| **Logs (live)** | `docker compose -f docker-compose.production.yml logs -f` |
| **Restart** | `docker compose -f docker-compose.production.yml restart signer` |
| **Update to a newer version** | `git pull && docker compose -f docker-compose.production.yml up -d --build` |
| **Stop everything** | `docker compose -f docker-compose.production.yml down` |
| **Stop and wipe TLS state** (last resort) | `docker compose -f docker-compose.production.yml down -v` |
| **Check disk** | `docker system df` |
| **Renew TLS** | nothing — Caddy auto-renews 30 days before expiry |

---

## What's protected and what isn't

### Protected by this setup

- HTTPS termination via Let's Encrypt (TLS 1.3, modern ciphers)
- HSTS preload-quality header
- The signer is NOT directly exposed — only Caddy is
- Request body cap (8 MB)
- `REQUIRE_HTTPS=true` rejects any HTTP that slips through
- CORS allowlist enforced by the signer based on `ALLOWED_ORIGIN`
- `signer` container runs as an unprivileged user (the Dockerfile does this)
- No logs of `.p12` or password bodies, ever

### Not protected by this setup (do separately)

- **Rate limiting**: Caddy doesn't have built-in rate limit. If you anticipate abuse, put Cloudflare in front, or switch the proxy to nginx with `limit_req`.
- **DDoS**: Same answer — Cloudflare / your cloud provider's WAF.
- **OS firewall**: `ufw enable && ufw allow 22,80,443/tcp` if you haven't already.
- **System updates**: set up `unattended-upgrades` for kernel + Docker patches.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `connection refused` on first attempt | TLS provisioning still running | wait 30s, retry |
| `Let's Encrypt ratelimit hit` in Caddy logs | brought stack up and down many times | wait 1 hour, or use the [Let's Encrypt staging environment](https://letsencrypt.org/docs/staging-environment/) first |
| `Kalkan provider class not found on classpath` | `libs/` JARs missing or empty | `ls -la ../packages/java/egov-helper-signer/libs/` — both files must be > 0 bytes |
| `Wrong password or corrupted PKCS#12 file` from client | password wrong, or `.p12` corrupted | nothing to fix server-side — caller's input is bad |
| CORS preflight fails from browser | `ALLOWED_ORIGIN` doesn't match the calling page's origin exactly | check `.env`, restart: `docker compose -f docker-compose.production.yml up -d` |
| Signer takes >1 minute to respond | JVM cold start + first sign of a key triggers Kalkan provider init | warm up by hitting `/health` after deploy |

For verbose request-shape debugging (NEVER in real prod), set `DEBUG_DUMP_REQS=true` in `.env` and restart. Don't forget to flip back to `false`.

---

## Adding `www.sign.3100.kz` or other domains

Edit the `Caddyfile` site header:

```
sign.3100.kz, www.sign.3100.kz {
    ...
}
```

Both get the same TLS cert (Caddy uses SAN). Restart Caddy: `docker compose -f docker-compose.production.yml restart caddy`.

---

## Backup

The only thing on disk worth backing up is `caddy_data` — that's where TLS certs and the Let's Encrypt account key live. Losing it means re-issuing certs (no data loss, but you hit Let's Encrypt rate limits if you re-issue too often).

```bash
docker run --rm -v egov_caddy_data:/data -v $(pwd):/backup alpine \
  tar czf /backup/caddy-data-$(date +%F).tar.gz -C /data .
```

That's the only stateful piece. The signer is fully stateless.
