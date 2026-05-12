#!/usr/bin/env bash
# Sanity-check the Kalkan JARs before invoking maven. Saves you the slow Maven failure
# when the SDK download went bad.
#
# Run from the egov-helper-signer/ folder:
#   ./scripts/check-kalkan-jars.sh
#
# Exits 0 if all JARs are present and non-empty; non-zero otherwise.

set -e

LIBS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/libs"

REQUIRED=(
  "knca_provider_jce_kalkan-0.7.5.jar"
  "knca_provider_util-0.8.5.jar"
)

echo "Checking Kalkan JARs in $LIBS_DIR …"

missing=0
zerobyte=0

for f in "${REQUIRED[@]}"; do
  path="$LIBS_DIR/$f"
  if [ ! -f "$path" ]; then
    echo "  ✗ MISSING:   $f"
    missing=$((missing + 1))
    continue
  fi
  size=$(stat -f%z "$path" 2>/dev/null || stat -c%s "$path" 2>/dev/null)
  if [ -z "$size" ] || [ "$size" -lt 1024 ]; then
    echo "  ✗ EMPTY:     $f  ($size bytes — looks like a public-preview placeholder)"
    zerobyte=$((zerobyte + 1))
  else
    # Quick check that it really is a JAR (PK ZIP magic)
    magic=$(head -c 2 "$path" 2>/dev/null | xxd -p 2>/dev/null || true)
    if [ "$magic" != "504b" ]; then
      echo "  ?  not a JAR: $f  (no PK magic — corrupted download?)"
    else
      echo "  ✓ OK:        $f  ($size bytes)"
    fi
  fi
done

if [ "$missing" -gt 0 ] || [ "$zerobyte" -gt 0 ]; then
  echo
  echo "$missing missing, $zerobyte empty."
  echo
  echo "→ The 'public preview' SDK at sdk.pki.gov.kz ships 0-byte JAR placeholders."
  echo "  You need the *approved developer* SDK to get real binaries."
  echo "  Submit the developer-access form on the SDK site (separate from account signup)."
  exit 1
fi

echo
echo "All Kalkan JARs look good. Run: mvn package"
