package kz.atasuai.egovsigner;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.javalin.Javalin;
import io.javalin.json.JavalinJackson;
import kz.atasuai.egovsigner.dto.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Entry point for the Kalkan-backed CMS signing service.
 *
 * Configure via environment variables:
 *   PORT             — HTTP port (default 7575)
 *   ALLOWED_ORIGIN   — CORS Access-Control-Allow-Origin (default *)
 *   MAX_BODY_MB      — request body size cap in MB (default 32)
 *   REQUIRE_HTTPS    — refuse plain HTTP if "true" (default false; set true in production
 *                      when behind a TLS terminator that sets X-Forwarded-Proto)
 *   DEBUG_DUMP_REQS  — log redacted request summaries if "true" (default false; never log
 *                      passwords or .p12 bytes regardless of this flag)
 */
public final class Application {
    private static final Logger log = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        int port = envInt("PORT", 7575);
        String allowedOrigin = envStr("ALLOWED_ORIGIN", "*");
        int maxBodyMb = envInt("MAX_BODY_MB", 32);
        boolean requireHttps = envBool("REQUIRE_HTTPS", false);
        boolean debugDump = envBool("DEBUG_DUMP_REQS", false);
        String appVersion = envStr("APP_VERSION", "dev");

        // Register the Kalkan JCE provider early so any later signing call can find it.
        KalkanSigner.registerProvider();

        ObjectMapper om = new ObjectMapper().registerModule(new JavaTimeModule());

        Javalin app = Javalin.create(config -> {
            config.jsonMapper(new JavalinJackson(om));
            config.http.maxRequestSize = (long) maxBodyMb * 1024 * 1024;
            config.plugins.enableCors(cors -> cors.add(it -> {
                if (allowedOrigin.equals("*")) it.anyHost();
                else it.allowHost(allowedOrigin);
            }));
        });

        app.get("/health", ctx -> ctx.json(new java.util.LinkedHashMap<String, Object>() {{
            put("ok", true);
            put("kalkan", KalkanSigner.kalkanVersion());
            put("version", appVersion);
        }}));

        // Sign: load .p12, sign document, return CMS.
        SigningHandler signHandler = new SigningHandler(debugDump);
        app.post("/", signHandler::handle);
        app.post("/sign", signHandler::handle);

        // Info: load .p12, return cert info only (no signing). Used by checkBin().
        CertInfoHandler infoHandler = new CertInfoHandler(debugDump);
        app.post("/info", infoHandler::handle);

        // CMS inspect: parse a CMS blob, return the signer's cert info. Used by
        // checkBinViaQr() — the JS lib chains this after a SIGEX eGov-Mobile sign.
        CmsInspectHandler cmsInspectHandler = new CmsInspectHandler(debugDump);
        app.post("/cms/inspect", cmsInspectHandler::handle);

        app.before(ctx -> {
            if (requireHttps && !"https".equalsIgnoreCase(ctx.header("X-Forwarded-Proto"))) {
                // Javalin 5.x: throw HttpResponseException to abort the chain
                throw new io.javalin.http.HttpResponseException(400,
                    "This endpoint requires HTTPS. Place a TLS terminator " +
                    "in front (nginx, caddy, etc.) and forward X-Forwarded-Proto.",
                    java.util.Map.of());
            }
        });

        app.exception(Exception.class, (e, ctx) -> {
            log.error("unhandled exception in {}", ctx.path(), e);
            ctx.status(500);
            ctx.json(new ErrorResponse("internal error"));
        });

        app.start(port);
        log.info("egov-helper-signer listening on http://0.0.0.0:{} (Kalkan provider: {})",
            port, KalkanSigner.kalkanVersion());
        log.info("CORS allowed origin: {}", allowedOrigin);
        log.info("max request body:    {} MB", maxBodyMb);
    }

    private static String envStr(String name, String def) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? def : v;
    }

    private static int envInt(String name, int def) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) return def;
        try { return Integer.parseInt(v); } catch (NumberFormatException e) { return def; }
    }

    private static boolean envBool(String name, boolean def) {
        String v = System.getenv(name);
        if (v == null) return def;
        return "true".equalsIgnoreCase(v) || "1".equals(v) || "yes".equalsIgnoreCase(v);
    }
}
