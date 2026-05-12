# How to use egov-helper

Pick the section that matches what you're doing.

---

## 🟢 I'm a developer in another project — I just want to sign documents

You don't need this repo. You need:

1. **A running Kalkan signer service somewhere** (your team's ops, or local Docker — see further down).
2. **`npm install @smoker_winston/egov-helper`** in your project.

Then:

```ts
import { checkBin, signDocument } from '@smoker_winston/egov-helper';

const BACKEND = 'http://signer.your-team.kz';  // wherever the signing service lives

// 1) Before signing, confirm the .p12 belongs to the BIN the user typed
const check = await checkBin(p12File, password, '190440033661', { backendUrl: BACKEND });
if (!check.match) throw new Error(`Cert BIN is ${check.certBin}, not the one entered`);

// 2) Sign the contract
const sig = await signDocument(p12File, password, contractBytes, { backendUrl: BACKEND });

// 3) Send to your backend for storage and chain verification
await fetch('/api/contracts/store', {
  method: 'POST',
  body: JSON.stringify({
    contractId,
    signatureBase64: sig.signatureBase64,
    signerBin: sig.certInfo.bin,
  }),
});
```

That's it. Stack-specific snippets are in [`examples/`](examples/) (Vue, React, Razor-MVC).

---

## 🟡 I'm a teammate who just got handed this repo

Goal: get the signer running locally + the tester UI open in a browser.

### Prereqs

- macOS / Linux / Windows with **Docker**
- ~~Maven / Java~~ — only if you want to run without Docker
- A **Kalkan SDK JAR** — see the next step

### Step 1: get the Kalkan JARs

The Kalkan JCE provider is what makes GOST signing possible. NUC RK distributes it but doesn't allow redistribution — every developer has to request it themselves.

1. Go to <https://sdk.pki.gov.kz/>.
2. Sign up.
3. **Submit the developer-access form** (this is separate from just creating an account — without it you get a "public preview" SDK where every binary is 0 bytes).
4. Wait 1–3 business days for approval.
5. Download the approved SDK — it's a `.7z` (actually a RAR archive despite the extension; extract with `unar` on macOS, `7-zip` on Windows, `unrar` on Linux). **macOS's built-in Archive Utility doesn't handle this format and produces empty files** — use `brew install unar` and then `unar SDK.7z`.
6. Copy these two files into `packages/java/egov-helper-signer/libs/`:
   - `SDK 2.0/Java/provider/knca_provider_jce_kalkan-0.7.5.jar` (~2 MB)
   - `SDK 2.0/Java/utils/knca_provider_util-0.8.5.jar` (~140 KB)

Sanity-check:

```bash
cd packages/java/egov-helper-signer
./scripts/check-kalkan-jars.sh
```

It will scream at you if the JARs are 0 bytes or missing.

### Step 2: start the signer service

From the repo root:

```bash
docker compose up --build
```

Listen for `egov-helper-signer listening on http://0.0.0.0:7676 (Kalkan provider: KALKAN/0.7)` in the logs, then in another terminal:

```bash
curl http://localhost:7676/health
# { "ok": true, "kalkan": "KALKAN/0.7" }
```

### Step 3: try it via the tester UI

The tester is a Vite + Vue 3 app that exercises every library function.

```bash
cd examples/vue
npm install
npm run dev
```

Open <http://localhost:5174>. Backend URL is already pre-filled at `http://localhost:7676`.

Pick your `.p12`, type the password, type a BIN — both `checkBin` and `signDocument` should work for both RSA and GOST keys.

---

## 🟠 I'm operating the signer in production

The signer is a stateless HTTP service. It briefly holds the user's `.p12` and password in memory while signing, then drops them. It logs nothing about request bodies.

### Recommended deployment shape

```
Internet ──HTTPS──▶ nginx/caddy/ALB ──HTTP──▶ egov-signer:7676
                       │
                       └─ TLS terminator
                          rate-limit
                          set X-Forwarded-Proto
```

### Required env vars in production

| Variable | Recommended value |
|---|---|
| `ALLOWED_ORIGIN` | Your real frontend origin (e.g. `https://app.atasuai.kz`). **Don't leave as `*` in production.** |
| `REQUIRE_HTTPS` | `true` (when behind a TLS terminator) |
| `MAX_BODY_MB` | `8` is plenty for typical contracts; lower bounds blast radius |
| `DEBUG_DUMP_REQS` | `false` |

### Health check

`GET /health` returns 200 with `{ ok: true, kalkan: "KALKAN/0.7" }`. Use for liveness probes.

### Hardening checklist

- [ ] TLS in front
- [ ] Rate limit (1–5 req/s per IP is generous for an actual user)
- [ ] `Origin` allowlist tight, no `*`
- [ ] Service runs as the unprivileged `egov` user (the Dockerfile already does this)
- [ ] Container has `--read-only` if your orchestrator supports it
- [ ] CRL / OCSP fetch is reachable from the container (Kalkan validates cert chains during signing)
- [ ] Audit logs don't include request bodies or passwords

---

## 🔵 I'm hacking on the library itself

```bash
# JS lib
npm install
npm run build
npm run test           # 27-assertion smoke test + the e2e against mock backend
npm run dev            # tsup --watch

# Java service
cd packages/java/egov-helper-signer
./build.sh             # installs Kalkan into local maven repo + mvn package
java -jar target/egov-helper-signer.jar

# Tester UI
cd examples/vue
npm install && npm run dev

# Mock backend (for testing the wire protocol with RSA — no Kalkan needed)
node scripts/mock-backend.mjs
```

The wire protocol the JS lib speaks is documented in
[`packages/java/egov-helper-signer/openapi.yaml`](packages/java/egov-helper-signer/openapi.yaml).

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| "GOST cryptography, which this library does not support" | You're on `0.1.x` or `0.2.x` with `transport: 'browser'`. Upgrade to `0.3.0` and pass `backendUrl`. |
| `mvn package` fails with "Could not find artifact kz.gov.pki" | Use `./build.sh`, not `mvn package` directly. It installs the JARs into your local Maven repo first. |
| `Kalkan provider class not found on classpath` | The JARs in `libs/` are missing or 0 bytes. Re-extract the SDK with `unar` (macOS) — Archive Utility produces empty files. |
| `Backend signing returned HTTP 400: Wrong password or corrupted PKCS#12 file` | Self-explanatory. Double-check the password — there's no recovery path. |
| "Could not reach the signing service at http://..." | Service isn't running, or you're behind a different network / origin / port. `curl http://<url>/health` to confirm. |
| CORS preflight fails from browser | `ALLOWED_ORIGIN` env on the signer doesn't match the calling page's origin. Set it explicitly. |
| GOST cert + correct password but `info` returns 400 | The .p12 might be an old PKCS#12 dialect Kalkan rejects — re-issue from egov.kz. |
