# Multi-stage build.
#
# Stage 1: build the shaded JAR. Requires the Kalkan JAR to already be in libs/.
# Stage 2: minimal runtime image (Eclipse Temurin JRE, ~80 MB) running the shaded JAR.

FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /work
COPY pom.xml .
COPY libs ./libs
COPY src ./src
COPY scripts ./scripts
COPY build.sh .
RUN chmod +x build.sh scripts/check-kalkan-jars.sh && ./build.sh

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
