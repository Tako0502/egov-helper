#!/usr/bin/env bash
# Refresh the NUC RK root + intermediate CA certificates from pki.gov.kz.
#
# These are public, government-published certificates — no auth needed.
# They're bundled inside the .NET package as embedded resources, but if pki.gov.kz
# rotates them (next root rollover is ~2045), run this script to update.
#
# Usage:
#   scripts/fetch-nuc-roots.sh
#   scripts/fetch-nuc-roots.sh /custom/output/dir   # default: packages/dotnet/EgovHelper.Net/Resources

set -euo pipefail

OUT_DIR="${1:-packages/dotnet/EgovHelper.Net/Resources}"

mkdir -p "$OUT_DIR"

CERTS=(
  "root_rsa_2020"   # NUC RK root CA, RSA, valid until 2045
  "root_gost_2022"  # NUC RK root CA, GOST, valid until 2045
  "nca_rsa_2022"    # NUC RK intermediate, RSA, valid until 2045
  "nca_gost_2022"   # NUC RK intermediate, GOST, valid until 2045
)

echo "Fetching NUC RK CA certificates → $OUT_DIR/"

for name in "${CERTS[@]}"; do
  url="https://pki.gov.kz/cert/${name}.cer"
  dst="$OUT_DIR/${name}.cer"
  printf "  %-25s " "$name.cer"
  if curl -fsSL --max-time 30 -o "$dst" "$url"; then
    # Sanity check — make sure we got DER, not an HTML error page.
    if openssl x509 -inform DER -in "$dst" -noout 2>/dev/null; then
      subject=$(openssl x509 -inform DER -in "$dst" -noout -subject 2>/dev/null | sed 's/^subject= *//')
      printf "ok\n    %s\n" "$subject"
    else
      printf "FAIL — downloaded file is not a valid DER certificate\n"
      rm -f "$dst"
      exit 1
    fi
  else
    printf "FAIL — could not download from %s\n" "$url"
    exit 1
  fi
done

echo
echo "Done. If this is for the .NET package, rebuild it:"
echo "  dotnet build -c Release packages/dotnet/EgovHelper.Net"
