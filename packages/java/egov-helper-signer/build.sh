#!/usr/bin/env bash
# Build wrapper for the Kalkan signer.
#
# Why this exists: Kalkan JARs aren't on Maven Central, so Maven can't resolve them as
# normal `compile`-scope deps. This script installs them into your local Maven repo first,
# then builds. Result: a self-contained shaded .jar in target/ that you can run with
# `java -jar target/egov-helper-signer.jar` (no classpath gymnastics).
#
# Usage:
#   ./build.sh           # install Kalkan into local repo + mvn package
#   ./build.sh clean     # also remove target/ first

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

# Sanity-check the JARs exist
./scripts/check-kalkan-jars.sh

echo
echo "Installing Kalkan JARs into local Maven repo…"
mvn -q install:install-file \
  -Dfile=libs/knca_provider_jce_kalkan-0.7.5.jar \
  -DgroupId=kz.gov.pki \
  -DartifactId=knca_provider_jce_kalkan \
  -Dversion=0.7.5 \
  -Dpackaging=jar

mvn -q install:install-file \
  -Dfile=libs/knca_provider_util-0.8.5.jar \
  -DgroupId=kz.gov.pki \
  -DartifactId=knca_provider_util \
  -Dversion=0.8.5 \
  -Dpackaging=jar

echo
if [ "${1:-}" = "clean" ]; then
  echo "Cleaning target/…"
  mvn -q clean
fi

echo "Building shaded JAR…"
mvn -q -DskipTests package

echo
echo "✓ Done. Run with:"
echo "  java -jar target/egov-helper-signer.jar"
echo
echo "Then check it's up:"
echo "  curl http://localhost:7676/health"
