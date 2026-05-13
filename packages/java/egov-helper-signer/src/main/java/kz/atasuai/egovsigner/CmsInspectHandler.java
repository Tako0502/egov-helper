package kz.atasuai.egovsigner;

import io.javalin.http.Context;
import io.javalin.http.HttpStatus;
import kz.atasuai.egovsigner.dto.CertInfoDto;
import kz.atasuai.egovsigner.dto.ErrorResponse;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.provider.utils.CMSUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * POST /cms/inspect — parse a CMS / PKCS#7 SignedData blob, return the signer's
 * certificate info (BIN/IIN/CN/etc.). Does NOT verify the signature value — purely
 * a "what's in this CMS" query.
 *
 * Used by the JS lib's `checkBinViaQr` to extract cert info from a CMS produced by
 * eGov Mobile via the SIGEX QR flow, so we can compare BIN/IIN against the typed value
 * without ever asking the user to upload a .p12.
 */
public final class CmsInspectHandler {
    private static final Logger log = LoggerFactory.getLogger(CmsInspectHandler.class);
    private static final String KALKAN_PROVIDER_CLASS = "kz.gov.pki.kalkan.jce.provider.KalkanProvider";
    private static volatile Provider kalkanProvider = null;

    private final boolean debugDump;

    public CmsInspectHandler(boolean debugDump) { this.debugDump = debugDump; }

    public static final class CmsInspectRequest {
        public String cmsBase64;
    }

    public void handle(Context ctx) {
        CmsInspectRequest req;
        try {
            req = ctx.bodyAsClass(CmsInspectRequest.class);
        } catch (Exception e) {
            badRequest(ctx, "Request body is not valid JSON: " + e.getMessage());
            return;
        }

        if (req.cmsBase64 == null || req.cmsBase64.isEmpty()) {
            badRequest(ctx, "Missing cmsBase64");
            return;
        }

        if (debugDump) {
            log.info("cms inspect request: cms base64 length={}", req.cmsBase64.length());
        }

        byte[] cmsBytes;
        try {
            cmsBytes = Base64.getDecoder().decode(req.cmsBase64);
        } catch (IllegalArgumentException e) {
            badRequest(ctx, "cmsBase64 is not valid base64");
            return;
        }

        try {
            registerProvider();

            CMSSignedData cms = CMSUtil.parseAsCMS(cmsBytes);
            List<X509Certificate> signerCerts = CMSUtil.getSignerCertificates(cms, kalkanProvider);
            if (signerCerts == null || signerCerts.isEmpty()) {
                badRequest(ctx, "CMS contains no signer certificate");
                return;
            }

            CertInfoDto info = CertInfoExtractor.extract(signerCerts.get(0));
            ctx.status(HttpStatus.OK);
            ctx.json(info);
        } catch (IllegalArgumentException e) {
            badRequest(ctx, e.getMessage());
        } catch (Exception e) {
            log.error("CMS inspect failed", e);
            ctx.status(HttpStatus.BAD_REQUEST);
            ctx.json(new ErrorResponse("Could not parse the CMS blob: " + e.getMessage()));
        }
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
