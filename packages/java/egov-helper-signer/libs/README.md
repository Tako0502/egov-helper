# Drop the Kalkan JARs here

This folder must contain the real Kalkan JARs **with non-zero file sizes** before the
project can be built.

## Files needed

| Filename | Source folder in SDK | Approx. size when real |
|---|---|---|
| `knca_provider_jce_kalkan-0.7.5.jar` | `SDK 2.0/Java/provider/` | 3–5 MB |
| `knca_provider_util-0.8.5.jar` | `SDK 2.0/Java/utils/` | ~500 KB |

If NUC RK ships you newer versions, update the `<systemPath>` lines in `../pom.xml`
and the filenames in `../Dockerfile`.

## The "0-byte JAR" trap

The version of the SDK that sdk.pki.gov.kz hands out **without dev approval** contains the
correct folder structure with empty placeholders for every binary file (.jar / .dll / .so).
You can browse it but you can't build anything. Confirm yours is real with:

```bash
ls -la libs/*.jar
# Files should be > 0 bytes. If they're 0, you have the preview-only SDK.
```

To get the real JARs:

1. Sign up at <https://sdk.pki.gov.kz/> with your company / individual identification.
2. **Submit the developer access form** (not just register the account) — there's a separate
   approval flow that grants access to the binary distribution. Approval is usually 1–3
   business days.
3. The approved download is a different file from the public preview; verify the JARs are
   not 0 bytes before continuing.

## Verifying it loaded

After `mvn package` and `java -jar target/egov-helper-signer.jar`, hit `/health`:

```bash
curl http://localhost:7575/health
```

You should see:

```json
{ "ok": true, "kalkan": "KALKAN/1.0" }
```

If `kalkan` is `"(not loaded)"`, the JARs are missing or the class lookup
(`kz.gov.pki.kalkan.jce.provider.KalkanProvider`) failed.

## Why not commit them to the repo

Kalkan is distributed under NUC RK's terms which don't permit redistribution. Each developer
or operator must request access from `sdk.pki.gov.kz` individually.
