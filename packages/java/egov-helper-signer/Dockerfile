# Multi-stage build.
#
# Stage 1: build the shaded JAR. Requires the Kalkan JAR to already be in libs/.
# Stage 2: minimal runtime image (Eclipse Temurin JRE, ~80 MB) running the shaded JAR.

FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /work
COPY pom.xml .
COPY libs ./libs
COPY src ./src
# Fail loudly if Kalkan JARs are missing OR are 0-byte placeholders (a real gotcha — the
# public-preview SDK ships empty JARs and you only get real binaries after dev approval).
RUN set -e; \
    for f in libs/knca_provider_jce_kalkan-0.7.5.jar libs/knca_provider_util-0.8.5.jar; do \
      if [ ! -f "$f" ]; then echo "ERROR: $f is missing. Apply at https://sdk.pki.gov.kz/ and drop the real JARs into libs/." && exit 1; fi; \
      if [ ! -s "$f" ]; then echo "ERROR: $f is a 0-byte placeholder — you got the public-preview SDK, not the approved one. Request developer access at sdk.pki.gov.kz to get real binaries." && exit 1; fi; \
    done
RUN mvn -q -DskipTests package

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /work/target/egov-helper-signer.jar app.jar

ENV PORT=7575
EXPOSE 7575

# Run as non-root.
RUN addgroup -S egov && adduser -S egov -G egov && chown -R egov:egov /app
USER egov

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- "http://localhost:${PORT}/health" >/dev/null 2>&1 || exit 1

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
