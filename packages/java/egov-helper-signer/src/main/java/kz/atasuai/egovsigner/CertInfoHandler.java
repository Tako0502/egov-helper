package kz.atasuai.egovsigner;

import io.javalin.http.Context;
import io.javalin.http.HttpStatus;
import kz.atasuai.egovsigner.dto.CertInfoDto;
import kz.atasuai.egovsigner.dto.ErrorResponse;
import kz.atasuai.egovsigner.dto.SignRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Locale;

/**
 * POST /info — parse a .p12 with Kalkan, return just the cert info (no signing).
 * Used by the JS lib's `checkBin()` to support GOST keys without forcing a full
 * sign round-trip. Same wire request shape as /sign (we reuse {@link SignRequest})
 * but only {@code p12Base64} and {@code password} are used; the document fields
 * are ignored.
 */
public final class CertInfoHandler {
    private static final Logger log = LoggerFactory.getLogger(CertInfoHandler.class);
    private static final String KALKAN_PROVIDER_CLASS = "kz.gov.pki.kalkan.jce.provider.KalkanProvider";
    private static volatile Provider kalkanProvider = null;

    private final boolean debugDump;

    public CertInfoHandler(boolean debugDump) { this.debugDump = debugDump; }

    public void handle(Context ctx) {
        SignRequest req;
        try {
            req = ctx.bodyAsClass(SignRequest.class);
        } catch (Exception e) {
            badRequest(ctx, "Request body is not valid JSON: " + e.getMessage());
            return;
        }

        if (req.p12Base64 == null || req.password == null) {
            badRequest(ctx, "Missing p12Base64 or password");
            return;
        }

        if (debugDump) log.info("info request: p12 base64 length={}, password set={}", req.p12Base64.length(), req.password.length() > 0);

        byte[] p12Bytes;
        try {
            p12Bytes = Base64.getDecoder().decode(req.p12Base64);
        } catch (IllegalArgumentException e) {
            badRequest(ctx, "p12Base64 is not valid base64");
            return;
        }

        char[] password = req.password.toCharArray();
        try {
            CertInfoDto info = extract(p12Bytes, password);
            ctx.status(HttpStatus.OK);
            ctx.json(info);
        } catch (java.security.UnrecoverableKeyException e) {
            badRequest(ctx, "Wrong password or corrupted PKCS#12 file");
        } catch (java.io.IOException e) {
            String msg = e.getMessage() == null ? "" : e.getMessage().toLowerCase(Locale.ROOT);
            if (msg.contains("password") || msg.contains("mac") || msg.contains("hmac")) {
                badRequest(ctx, "Wrong password or corrupted PKCS#12 file");
            } else {
                badRequest(ctx, "Could not open PKCS#12 file: " + e.getMessage());
            }
        } catch (IllegalArgumentException e) {
            badRequest(ctx, e.getMessage());
        } catch (Exception e) {
            log.error("info handler failed", e);
            ctx.status(HttpStatus.INTERNAL_SERVER_ERROR);
            ctx.json(new ErrorResponse("internal error during cert parse"));
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private static CertInfoDto extract(byte[] p12Bytes, char[] password) throws Exception {
        registerProvider();
        KeyStore ks = KeyStore.getInstance("PKCS12", kalkanProvider);
        try (ByteArrayInputStream in = new ByteArrayInputStream(p12Bytes)) {
            ks.load(in, password);
        }

        String alias = null;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (ks.isKeyEntry(a)) { alias = a; break; }
        }
        if (alias == null) {
            throw new IllegalArgumentException("PKCS#12 contains no key entry");
        }

        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        return CertInfoExtractor.extract(cert);
    }

    private static synchronized void registerProvider() throws Exception {
        if (kalkanProvider != null) return;
        Class<?> clazz = Class.forName(KALKAN_PROVIDER_CLASS);
        Provider provider = (Provider) clazz.getDeclaredConstructor().newInstance();
        if (Security.getProvider(provider.getName()) == null) {
            Security.addProvider(provider);
        }
        kalkanProvider = provider;
    }

    private static void badRequest(Context ctx, String msg) {
        ctx.status(HttpStatus.BAD_REQUEST);
        ctx.json(new ErrorResponse(msg));
    }
}
