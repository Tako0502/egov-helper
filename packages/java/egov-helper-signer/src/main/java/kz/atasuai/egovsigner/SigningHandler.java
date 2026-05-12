package kz.atasuai.egovsigner;

import io.javalin.http.Context;
import io.javalin.http.HttpStatus;
import kz.atasuai.egovsigner.dto.ErrorResponse;
import kz.atasuai.egovsigner.dto.SignRequest;
import kz.atasuai.egovsigner.dto.SignResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;
import java.util.Locale;

/**
 * POST handler. Decodes the JSON request, signs via {@link KalkanSigner}, returns JSON.
 *
 * Security:
 *   - Password is never logged.
 *   - .p12 bytes are never logged.
 *   - Password char[] is zeroed in a finally block (defensive — JVM GC eventually clears,
 *     but explicit zeroing reduces the window).
 *   - Document size is bounded by the global maxRequestSize set in Application (default 32 MB).
 */
public final class SigningHandler {
    private static final Logger log = LoggerFactory.getLogger(SigningHandler.class);
    private final boolean debugDump;

    public SigningHandler(boolean debugDump) { this.debugDump = debugDump; }

    public void handle(Context ctx) {
        SignRequest req;
        try {
            req = ctx.bodyAsClass(SignRequest.class);
        } catch (Exception e) {
            badRequest(ctx, "Request body is not valid JSON: " + e.getMessage());
            return;
        }

        if (req.p12Base64 == null || req.password == null || req.documentBase64 == null) {
            badRequest(ctx, "Missing one of: p12Base64, password, documentBase64");
            return;
        }

        if (debugDump) log.info("sign request: {}", req);

        byte[] p12Bytes;
        byte[] document;
        try {
            p12Bytes = Base64.getDecoder().decode(req.p12Base64);
            document = Base64.getDecoder().decode(req.documentBase64);
        } catch (IllegalArgumentException e) {
            badRequest(ctx, "p12Base64 or documentBase64 is not valid base64");
            return;
        }

        char[] password = req.password.toCharArray();
        try {
            SignResponse res = KalkanSigner.sign(
                p12Bytes,
                password,
                document,
                req.detached,
                req.hashAlgorithm == null ? "auto" : req.hashAlgorithm
            );
            ctx.status(HttpStatus.OK);
            ctx.json(res);
        } catch (java.security.UnrecoverableKeyException e) {
            badRequest(ctx, "Wrong password or corrupted PKCS#12 file");
        } catch (java.io.IOException e) {
            // KeyStore.load wraps the bad-password case as an IOException whose cause is
            // UnrecoverableKeyException — pick that up here.
            String msg = e.getMessage() == null ? "" : e.getMessage().toLowerCase(Locale.ROOT);
            if (msg.contains("password") || msg.contains("mac") || msg.contains("hmac")) {
                badRequest(ctx, "Wrong password or corrupted PKCS#12 file");
            } else {
                badRequest(ctx, "Could not open PKCS#12 file: " + e.getMessage());
            }
        } catch (IllegalArgumentException e) {
            // Unsupported algorithm, malformed key, etc. Caller-controllable input.
            badRequest(ctx, e.getMessage());
        } catch (Exception e) {
            log.error("signing failed", e);
            ctx.status(HttpStatus.INTERNAL_SERVER_ERROR);
            ctx.json(new ErrorResponse("internal error during signing"));
        } finally {
            // Best-effort password wipe.
            java.util.Arrays.fill(password, '\0');
        }
    }

    private static void badRequest(Context ctx, String msg) {
        ctx.status(HttpStatus.BAD_REQUEST);
        ctx.json(new ErrorResponse(msg));
    }
}
