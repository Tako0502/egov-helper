# Drop the Kalkan JAR here

This folder must contain `kalkancrypt.jar` (NUC RK's KalkanCrypt JCE provider) before the
project can be built.

## Get it

1. Go to <https://sdk.pki.gov.kz/> and sign up. You'll need company / individual identification.
2. Once approved, download the latest `kalkan-crypt-X.Y.Z.jar` (Java SE flavour, not the
   `.dll` or `.so` native variants).
3. Rename / symlink it to **`kalkancrypt.jar`** in this folder.

The `pom.xml` references `${project.basedir}/libs/kalkancrypt.jar` as a system-scope
dependency. If you keep a different filename, update the `<systemPath>` line in `pom.xml`.

## Why isn't it in the repo?

Kalkan is distributed under NUC RK's terms which don't permit redistribution. Each developer
or operator must request access from `sdk.pki.gov.kz` individually.

## Verifying it loaded

After `mvn package`, run the signer once and hit `/health`. The response includes the
Kalkan provider's reported version:

```json
{ "ok": true, "kalkan": "KALKAN/1.0" }
```

If it says `(not loaded)`, the JAR is missing from this folder or doesn't expose the
`kz.gov.pki.kalkan.jce.provider.KalkanProvider` class.
