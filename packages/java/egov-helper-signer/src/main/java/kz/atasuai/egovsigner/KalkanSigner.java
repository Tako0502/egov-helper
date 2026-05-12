package kz.atasuai.egovsigner;

import kz.atasuai.egovsigner.dto.SignResponse;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.provider.utils.CMSUtil;
import kz.gov.pki.reference.KalkanHashAlgorithm;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Enumeration;

/**
 * Loads a NUC RK .p12 via the Kalkan JCE provider (supports RSA and KZ GOST variants)
 * and produces a CAdES-BES CMS / PKCS#7 SignedData blob via {@link CMSUtil#createCAdES}.
 *
 * Kalkan ships its own repackaged BouncyCastle at {@code kz.gov.pki.kalkan.*}, separate
 * from upstream {@code org.bouncycastle.*}. We use Kalkan's classes throughout, which
 * means signatures produced here are immediately verifiable by anything using Kalkan
 * (NCALayer, KalkanCrypt, this lib itself).
 *
 * Hash selection:
 *   - RSA key                          → SHA-256
 *   - GOST 34.10-2012 (KZ + RU)        → Stribog-512 (HASH_GOST3411_2015_512)
 *   - GOST 34.10-2001 (legacy)         → GOST-34.11 (HASH_GOST34311)
 * Caller's `requestedHash` is honoured for RSA only; for GOST keys the hash is
 * mandated by the curve and overriding it would produce a verifier rejection.
 */
public final class KalkanSigner {
    private static final String KALKAN_PROVIDER_CLASS = "kz.gov.pki.kalkan.jce.provider.KalkanProvider";

    private static volatile Provider kalkanProvider = null;
    private static volatile String registeredVersion = null;

    /** Idempotent. Registers Kalkan's JCE provider so PKCS#12 + KZ algorithms resolve. */
    public static synchronized void registerProvider() {
        if (kalkanProvider != null) return;
        try {
            Class<?> kalkanClass = Class.forName(KALKAN_PROVIDER_CLASS);
            Provider provider = (Provider) kalkanClass.getDeclaredConstructor().newInstance();
            if (Security.getProvider(provider.getName()) == null) {
                Security.addProvider(provider);
            }
            kalkanProvider = provider;
            registeredVersion = provider.getName() + "/" + provider.getVersionStr();
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(
                "Kalkan provider class not found on classpath. Drop the real " +
                "knca_provider_jce_kalkan-*.jar into libs/ — see the project README.", e);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to register Kalkan JCE provider", e);
        }
    }

    /** Best-effort version string for /health and logs. */
    public static String kalkanVersion() {
        return registeredVersion == null ? "(not loaded)" : registeredVersion;
    }

    /** Top-level entry. Loads .p12, picks hash, signs, returns ready-to-serialize DTO. */
    public static SignResponse sign(byte[] p12Bytes, char[] password, byte[] document,
                                    boolean detached, String requestedHash) throws Exception {
        registerProvider();

        KeyStore ks = KeyStore.getInstance("PKCS12", kalkanProvider);
        try (ByteArrayInputStream in = new ByteArrayInputStream(p12Bytes)) {
            ks.load(in, password);
        }

        String alias = findKeyAlias(ks);
        if (alias == null) {
            throw new IllegalArgumentException("PKCS#12 contains no key entry");
        }

        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        KalkanHashAlgorithm hash = pickHashAlgorithm(cert, requestedHash);

        // CMSUtil.createCAdES signature:
        //   (KeyStore, alias, password, data, encapsulate, hash, TSAPolicy?, KNCAServiceRequestMethod?, Provider)
        // Note: 5th param is `encapsulate` (true = attached signature). Our `detached` flag is the inverse.
        CMSSignedData signed = CMSUtil.createCAdES(
            ks, alias, password, document,
            !detached,        // encapsulate
            hash,
            null,             // TSAPolicy — no timestamp at this stage (use addTimestamp on JS side or extend here)
            null,             // KNCAServiceRequestMethod — use defaults
            kalkanProvider
        );

        byte[] cmsBytes = signed.getEncoded();

        SignResponse res = new SignResponse();
        res.signatureBase64 = Base64.getEncoder().encodeToString(cmsBytes);
        res.signedAtIso = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        res.detached = detached;
        res.certInfo = CertInfoExtractor.extract(cert);
        return res;
    }

    /** Pick the right hash for the signing algorithm. RSA respects caller; GOST is fixed by curve. */
    private static KalkanHashAlgorithm pickHashAlgorithm(X509Certificate cert, String requested) {
        String pkAlg = cert.getPublicKey().getAlgorithm().toUpperCase();
        if (pkAlg.startsWith("RSA")) {
            // Kalkan's reference enum only includes SHA-1 and SHA-256 — the createCAdES signature
            // requires this exact enum, so SHA-384 / SHA-512 will fall through to SHA-256.
            // If a teammate needs other RSA hashes, extend Kalkan or do RSA signing in-browser.
            return KalkanHashAlgorithm.HASH_SHA256;
        }
        // GOST — branch on the cert's signatureAlgorithm OID.
        String sigOid = cert.getSigAlgOID();
        if (sigOid == null) return KalkanHashAlgorithm.HASH_SHA256;
        if (sigOid.startsWith("1.2.398.3.10")) {
            // KZ ST RK GOST R 34.10-2015 — the modern Kazakhstan variant
            return KalkanHashAlgorithm.HASH_GOST3411_2015_512;
        }
        if (sigOid.startsWith("1.2.643.7")) {
            // Russian GOST R 34.10-2012
            return KalkanHashAlgorithm.HASH_GOST3411_2015_512;
        }
        if (sigOid.startsWith("1.2.643.2.2")) {
            // Legacy GOST R 34.10-2001
            return KalkanHashAlgorithm.HASH_GOST34311;
        }
        return KalkanHashAlgorithm.HASH_SHA256;
    }

    private static String findKeyAlias(KeyStore ks) throws Exception {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (ks.isKeyEntry(a)) return a;
        }
        return null;
    }

    private KalkanSigner() {}
}
