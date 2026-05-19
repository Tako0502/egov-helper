package kz.atasuai.egovsigner;

import io.javalin.http.Context;
import io.javalin.http.HttpStatus;
import kz.atasuai.egovsigner.dto.CertInfoDto;
import kz.atasuai.egovsigner.dto.CmsVerifyResponse;
import kz.atasuai.egovsigner.dto.ErrorResponse;
import kz.gov.pki.kalkan.asn1.ASN1OctetString;
import kz.gov.pki.kalkan.asn1.DEREncodable;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.cms.CMSAttributes;
import kz.gov.pki.kalkan.asn1.cms.Time;
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore;
import kz.gov.pki.provider.utils.CMSUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

/**
 * POST /cms/verify — answer "did THIS signer sign THIS document?"
 *
 * Three checks per signer, returned independently so the caller can tell which one
 * actually failed:
 *   1. {@code signatureValid}            — the signature over signedAttrs verifies against
 *                                          the embedded cert's public key (proves: holder of
 *                                          the matching private key authored these attrs).
 *   2. {@code documentDigestMatches}     — hash of the document the caller passed equals
 *                                          the {@code messageDigest} signed attribute in the
 *                                          CMS (proves: the signer committed to THIS doc).
 *   3. {@code certValidAtSigningTime}    — the {@code signingTime} attribute is within the
 *                                          cert's NotBefore/NotAfter window (proves: the
 *                                          cert wasn't expired when they used it).
 *
 * Note we deliberately do NOT do cert-chain validation against NUC RK roots here, and we
 * do NOT do OCSP/CRL revocation checks. Both are deployment-specific (trust anchors,
 * network egress, caching) and are best layered on at the integration site. The three
 * checks above are the cryptographic core: if any fails, the signature is meaningless;
 * if all pass, the only remaining question is "do I trust the cert?" — answered out-of-band.
 *
 * Detached CMS (the eGov Mobile case — {@code signMethod: CMS_SIGN_ONLY}) requires the
 * caller to pass {@code documentBase64}; we reconstruct the CMS with the document attached
 * before letting Kalkan verify. Attached CMS ({@code CMS_WITH_DATA}) ignores the field.
 */
public final class CmsVerifyHandler {
    private static final Logger log = LoggerFactory.getLogger(CmsVerifyHandler.class);
    private static final String KALKAN_PROVIDER_CLASS = "kz.gov.pki.kalkan.jce.provider.KalkanProvider";
    private static volatile Provider kalkanProvider = null;

    private final boolean debugDump;
    private final LegalDocFetcher legalDocFetcher;

    public CmsVerifyHandler(boolean debugDump, LegalDocFetcher legalDocFetcher) {
        this.debugDump = debugDump;
        this.legalDocFetcher = legalDocFetcher;
    }

    public static final class CmsVerifyRequest {
        public String cmsBase64;
        /**
         * Optional. Required when the CMS is detached (no eContent embedded) UNLESS the
         * legal-doc params below are present — in which case the doc is fetched server-side.
         */
        public String documentBase64;

        /* ── Atasuai legal-doc integration ────────────────────────────────────────
         * When all four are present, the server fetches the canonical PDF from
         * `LEGAL_DOC_BASE_URL?role=…&type=…&version=…&language=…` and verifies the CMS
         * against it. Lets clients verify without ever shipping the doc bytes — and
         * guarantees the doc the signature is checked against is the one the legal
         * service considers canonical.
         */
        public String role;
        public String type;
        public String version;
        public String language;
    }

    public void handle(Context ctx) {
        CmsVerifyRequest req;
        try {
            req = ctx.bodyAsClass(CmsVerifyRequest.class);
        } catch (Exception e) {
            badRequest(ctx, "Request body is not valid JSON: " + e.getMessage());
            return;
        }

        if (req.cmsBase64 == null || req.cmsBase64.isEmpty()) {
            badRequest(ctx, "Missing cmsBase64");
            return;
        }

        byte[] cmsBytes;
        try {
            cmsBytes = Base64.getDecoder().decode(req.cmsBase64);
        } catch (IllegalArgumentException e) {
            badRequest(ctx, "cmsBase64 is not valid base64");
            return;
        }

        byte[] documentBytes = null;
        String documentSource = "none";

        // Priority 1: caller passed the document inline.
        if (req.documentBase64 != null && !req.documentBase64.isEmpty()) {
            try {
                documentBytes = Base64.getDecoder().decode(req.documentBase64);
                documentSource = "inline";
            } catch (IllegalArgumentException e) {
                badRequest(ctx, "documentBase64 is not valid base64");
                return;
            }
        }
        // Priority 2: caller wants us to fetch the canonical legal doc.
        else if (anyLegalDocParamPresent(req)) {
            if (!legalDocFetcher.isConfigured()) {
                badRequest(ctx, "Server is not configured for legal-doc fetch. " +
                    "Either set LEGAL_DOC_BASE_URL, or pass documentBase64.");
                return;
            }
            try {
                documentBytes = legalDocFetcher.fetch(req.role, req.type, req.version, req.language);
                documentSource = "legal:" + req.role + "/" + req.type + "/" + req.language
                    + (notBlank(req.version) ? "/v" + req.version : "");
            } catch (IllegalArgumentException e) {
                badRequest(ctx, e.getMessage());
                return;
            } catch (java.io.IOException e) {
                ctx.status(HttpStatus.BAD_GATEWAY);
                ctx.json(new ErrorResponse("Failed to fetch legal doc: " + e.getMessage()));
                return;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                ctx.status(HttpStatus.BAD_GATEWAY);
                ctx.json(new ErrorResponse("Legal-doc fetch was interrupted"));
                return;
            }
        }

        if (debugDump) {
            log.info("cms verify request: cms base64 length={}, doc source={}, doc bytes={}",
                req.cmsBase64.length(),
                documentSource,
                documentBytes == null ? 0 : documentBytes.length);
        }

        try {
            registerProvider();

            CMSSignedData cms = CMSUtil.parseAsCMS(cmsBytes);

            // Detect attached vs detached by checking whether the CMS carries encapsulated content.
            boolean isAttached = cms.getSignedContent() != null;
            if (!isAttached) {
                if (documentBytes == null) {
                    badRequest(ctx,
                        "CMS is detached (no encapsulated content) — pass documentBase64 to verify");
                    return;
                }
                // Reconstruct with the document so Kalkan's verify() can compute the digest internally.
                cms = new CMSSignedData(new CMSProcessableByteArray(documentBytes), cmsBytes);
            }

            // Even when attached, we still want to expose documentDigestMatches if the caller
            // gave us a document — useful for "the CMS says it embeds doc X; the user uploaded
            // doc Y; do they actually agree?" cross-checks.
            byte[] docForDigestCompare = isAttached
                ? extractEmbeddedContent(cms)
                : documentBytes;

            CmsVerifyResponse resp = new CmsVerifyResponse();
            resp.detached = !isAttached;
            resp.documentSource = documentBytes != null ? documentSource
                : (isAttached ? "embedded" : "none");
            resp.valid = true;  // flip to false the moment any per-signer check fails

            @SuppressWarnings("unchecked")
            Collection<SignerInformation> signerInfos = (Collection<SignerInformation>)
                cms.getSignerInfos().getSigners();

            if (signerInfos.isEmpty()) {
                badRequest(ctx, "CMS contains no signers");
                return;
            }

            List<X509Certificate> signerCerts = CMSUtil.getSignerCertificates(cms, kalkanProvider);

            int signerIdx = 0;
            for (SignerInformation signer : signerInfos) {
                CmsVerifyResponse.SignerVerifyResult srow = new CmsVerifyResponse.SignerVerifyResult();

                X509Certificate cert = signerIdx < signerCerts.size() ? signerCerts.get(signerIdx) : null;
                if (cert == null) {
                    srow.signatureValid = false;
                    srow.certInfo = null;
                    resp.signers.add(srow);
                    resp.valid = false;
                    signerIdx++;
                    continue;
                }

                srow.certInfo = CertInfoExtractor.extract(cert);
                srow.digestAlgorithmOid = signer.getDigestAlgOID();

                // 1. Signature verification — pure cryptographic check.
                // We use the PublicKey overload (not the X509Certificate one) so that an expired
                // cert does NOT cause this to fail. Expiry is a separate concern surfaced via
                // certValidAtSigningTime below — a signature can be mathematically valid even
                // after the cert expires (it just may have lost legal force).
                try {
                    srow.signatureValid = signer.verify(cert.getPublicKey(), kalkanProvider.getName());
                } catch (Exception e) {
                    log.debug("signer.verify threw — treating as invalid signature", e);
                    srow.signatureValid = false;
                }

                // 2. Explicit document-digest check. Redundant with signer.verify() in the
                // happy path, but disambiguates "sig forged" from "doc tampered" when verify() fails.
                srow.documentDigestMatches = compareDocumentDigest(signer, docForDigestCompare);

                // 3. Read signedAttrs.signingTime, then check cert validity at that instant.
                Instant signedAt = readSigningTime(signer);
                if (signedAt != null) {
                    srow.signedAtIso = DateTimeFormatter.ISO_INSTANT.format(signedAt);
                    srow.certValidAtSigningTime =
                        !signedAt.isBefore(cert.getNotBefore().toInstant())
                        && !signedAt.isAfter(cert.getNotAfter().toInstant());
                } else {
                    // No signingTime attribute — fall back to checking against current time.
                    Instant now = Instant.now();
                    srow.certValidAtSigningTime =
                        !now.isBefore(cert.getNotBefore().toInstant())
                        && !now.isAfter(cert.getNotAfter().toInstant());
                }

                resp.signers.add(srow);

                boolean perSignerOk = srow.signatureValid
                    && (srow.documentDigestMatches == null || srow.documentDigestMatches)
                    && (srow.certValidAtSigningTime == null || srow.certValidAtSigningTime);
                if (!perSignerOk) resp.valid = false;
                signerIdx++;
            }

            ctx.status(HttpStatus.OK);
            ctx.json(resp);
        } catch (IllegalArgumentException e) {
            badRequest(ctx, e.getMessage());
        } catch (Exception e) {
            log.error("CMS verify failed", e);
            ctx.status(HttpStatus.BAD_REQUEST);
            ctx.json(new ErrorResponse("Could not verify the CMS: " + e.getMessage()));
        }
    }

    /** Extract the embedded eContent from an attached CMS, or null if extraction fails. */
    private static byte[] extractEmbeddedContent(CMSSignedData cms) {
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            cms.getSignedContent().write(out);
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Hash {@code docBytes} with the signer's digest algorithm and compare to the
     * messageDigest signed attribute. Returns null if either side is unavailable (we
     * shouldn't claim a mismatch when we couldn't actually run the check).
     */
    private static Boolean compareDocumentDigest(SignerInformation signer, byte[] docBytes) {
        if (docBytes == null) return null;
        AttributeTable signedAttrs = signer.getSignedAttributes();
        if (signedAttrs == null) return null;
        Attribute mdAttr = signedAttrs.get(CMSAttributes.messageDigest);
        if (mdAttr == null) return null;
        DEREncodable mdValue = mdAttr.getAttrValues().getObjectAt(0);
        if (!(mdValue instanceof ASN1OctetString)) return null;
        byte[] expected = ((ASN1OctetString) mdValue).getOctets();

        try {
            MessageDigest md = MessageDigest.getInstance(signer.getDigestAlgOID(), kalkanProvider);
            byte[] actual = md.digest(docBytes);
            return constantTimeEquals(expected, actual);
        } catch (Exception e) {
            log.debug("MessageDigest for OID {} failed", signer.getDigestAlgOID(), e);
            return null;
        }
    }

    /** Pull the ISO signing time out of the signedAttrs, or null if absent / unparseable. */
    private static Instant readSigningTime(SignerInformation signer) {
        try {
            AttributeTable signedAttrs = signer.getSignedAttributes();
            if (signedAttrs == null) return null;
            Attribute stAttr = signedAttrs.get(CMSAttributes.signingTime);
            if (stAttr == null) return null;
            DEREncodable v = stAttr.getAttrValues().getObjectAt(0);
            Time t = Time.getInstance(v);
            return t.getDate().toInstant();
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean anyLegalDocParamPresent(CmsVerifyRequest req) {
        return notBlank(req.role) || notBlank(req.type) || notBlank(req.version) || notBlank(req.language);
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int r = 0;
        for (int i = 0; i < a.length; i++) r |= a[i] ^ b[i];
        return r == 0;
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
