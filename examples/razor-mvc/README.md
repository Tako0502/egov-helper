# ASP.NET Core MVC integration

Drop-in Razor + JS snippet that signs a contract entirely client-side using
`@smoker_winston/egov-helper`'s standalone IIFE bundle, then POSTs the resulting CMS
to a `[HttpPost]` controller that verifies with `Tako0502.EgovHelper`.

This isn't a runnable standalone project — it's the **exact code shape** to drop into
your existing `AtasuSite` / `AtasuWeb` / similar projects.

## Files

| File | Where to put it in your real project |
|---|---|
| [`Controllers/ContractController.cs`](Controllers/ContractController.cs) | `Controllers/` |
| [`Views/Contract/Sign.cshtml`](Views/Contract/Sign.cshtml) | `Views/Contract/Sign.cshtml` |
| [`wwwroot/lib/egov-helper.min.js`](wwwroot/lib/) | copy from `node_modules/@smoker_winston/egov-helper/dist/egov-helper.min.js` |

## Steps to integrate

1. **Install the .NET package** for backend verification:
   ```bash
   dotnet add package Tako0502.EgovHelper
   ```

2. **Copy the IIFE bundle into `wwwroot/lib/`** (so the Razor view can load it
   with `<script src>` — no npm pipeline required for classic Razor projects):
   ```bash
   # one-time from your project root
   npm install @smoker_winston/egov-helper
   cp node_modules/@smoker_winston/egov-helper/dist/egov-helper.min.js wwwroot/lib/
   ```
   Or pull from a CDN (`https://unpkg.com/@smoker_winston/egov-helper/dist/egov-helper.min.js`).

3. **Point the JS at your Kalkan signer service.** In `Sign.cshtml`, the `BACKEND_URL`
   constant defaults to `http://localhost:7676`. Change it for production.

4. **Run a Kalkan signer somewhere** — either:
   - Locally for dev: `docker compose up` at the egov-helper repo root.
   - In production: deploy the `egov-helper-signer` Docker image behind your TLS terminator.

## What the flow looks like

```
User → /Contract/Sign (GET)        → shows the form, picks .p12 + password + doc
User → submits in browser          → JS calls window.EgovHelper.signDocument()
JS → POST /sign on Kalkan service   → returns CMS + cert info
JS → POST /Contract/Sign (your app) → submits {signatureBase64, ...}
Server → EgovSignatureVerifier.Verify(...) → 200/400
```

The backend verification is what counts for legal/audit. The browser-side
flow is just UX — the user picks their `.p12`, the browser hands off to Kalkan,
gets back a CMS, ships it to you. Your `[HttpPost]` is where you decide whether
to trust the contract.
