package kz.atasuai.egovsigner;

import kz.atasuai.egovsigner.dto.CertInfoDto;
import kz.atasuai.egovsigner.dto.SignResponse;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.security.Hashtable;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

/**
 * Loads a NUC RK .p12 via the Kalkan JCE provider (which supports both RSA and KZ GOST)
 * and produces a CAdES-BES CMS / PKCS#7 SignedData blob.
 *
 * The Kalkan JAR ships its own bundled BouncyCastle classes (org.bouncycastle.*) — that's
 * how it does CMS generation. So `import org.bouncycastle.cms.*` here resolves against
 * Kalkan's bundled BC at compile time once kalkancrypt.jar is in libs/.
 *
 * Algorithm choice:
 *   - RSA key + caller-asked-SHA-X   → SHA-Xwith RSA
 *   - RSA key + "auto"               → SHA256withRSA
 *   - GOST 34.10-2012-256 key        → "ECGOST3410-2012-256" (Stribog-256 hash)
 *   - GOST 34.10-2012-512 key        → "ECGOST3410-2012-512" (Stribog-512 hash)
 *
 * IMPORTANT: the Kalkan SDK is the source of truth for exact algorithm names. The strings
 * above match the JCA name conventions Kalkan documents; verify against your SDK release
 * notes if a signing call fails with `NoSuchAlgorithmException`.
 */
public final class KalkanSigner {

    private static final String KALKAN_PROVIDER_CLASS = "kz.gov.pki.kalkan.jce.provider.KalkanProvider";
    private static final String KALKAN_PROVIDER_NAME = "KALKAN";

    private static volatile String registeredVersion = null;

    /** Idempotent. Add Kalkan's JCE provider so PKCS#12 + signing algorithms resolve. */
    public static synchronized void registerProvider() {
        if (registeredVersion != null) return;
        try {
            Class<?> kalkan = Class.forName(KALKAN_PROVIDER_CLASS);
            java.security.Provider provider = (java.security.Provider) kalkan
                .getDeclaredConstructor().newInstance();
            if (Security.getProvider(provider.getName()) == null) {
                Security.addProvider(provider);
            }
            registeredVersion = provider.getName() + "/" + provider.getVersionStr();
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(
                "Kalkan provider class not found on classpath. " +
                "Drop the kalkancrypt JAR into libs/ — see the project README.", e);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to register Kalkan JCE provider", e);
        }
    }

    /** Best-effort version string for /health and logs. Empty if Kalkan isn't loaded yet. */
    public static String kalkanVersion() {
        return registeredVersion == null ? "(not loaded)" : registeredVersion;
    }

    /** Top-level entry. Loads .p12, picks algorithm, signs. Returns ready-to-serialize DTO. */
    public static SignResponse sign(byte[] p12Bytes, char[] password, byte[] document,
                                    boolean detached, String requestedHash) throws Exception {

        KeyStore ks = KeyStore.getInstance("PKCS12", KALKAN_PROVIDER_NAME);
        try (ByteArrayInputStream in = new ByteArrayInputStream(p12Bytes)) {
            ks.load(in, password);
        }

        String alias = findKeyAlias(ks);
        if (alias == null) {
            throw new IllegalArgumentException("PKCS#12 contains no key entry");
        }

        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password);
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        SigAlg sigAlg = pickAlgorithm(cert, requestedHash);
        byte[] cmsBytes = produceCms(privateKey, cert, document, detached, sigAlg);

        SignResponse res = new SignResponse();
        res.signatureBase64 = Base64.getEncoder().encodeToString(cmsBytes);
        res.signedAtIso = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        res.detached = detached;
        res.certInfo = CertInfoExtractor.extract(cert);
        return res;
    }

    private static String findKeyAlias(KeyStore ks) throws Exception {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (ks.isKeyEntry(a)) return a;
        }
        return null;
    }

    /** Tuple of signature algorithm + matching digest algorithm name. */
    private record SigAlg(String signatureAlgo, String digestAlgo) {}

    private static SigAlg pickAlgorithm(X509Certificate cert, String requested) {
        PublicKey pk = cert.getPublicKey();
        String alg = pk.getAlgorithm().toUpperCase();

        if (alg.startsWith("RSA")) {
            String hash = (requested == null || "auto".equalsIgnoreCase(requested))
                ? "SHA-256"
                : requested;
            return new SigAlg(hash.replace("-", "") + "withRSA", hash);
        }

        // GOST: pick by curve size. RFC 7091 / 7836 OIDs.
        // 1.2.643.7.1.1.1.1 → 256-bit, 1.2.643.7.1.1.1.2 → 512-bit
        String oid = ((sun.security.x509.AlgorithmId) tryAlgId(pk)).getOID().toString();
        if ("1.2.643.7.1.1.1.1".equals(oid)) {
            return new SigAlg("ECGOST3410-2012-256", "GOST3411-2012-256");
        }
        if ("1.2.643.7.1.1.1.2".equals(oid)) {
            return new SigAlg("ECGOST3410-2012-512", "GOST3411-2012-512");
        }

        // Legacy GOST 34.10-2001 (1.2.643.2.2.19) — included for completeness.
        if ("1.2.643.2.2.19".equals(oid)) {
            return new SigAlg("ECGOST3410", "GOST3411");
        }

        throw new IllegalArgumentException(
            "Unsupported public key algorithm: " + alg + " (OID " + oid + "). " +
            "Expected RSA or GOST 34.10-2001 / 34.10-2012.");
    }

    /** Reflective getter — Kalkan certs may not expose getAlgId() directly. */
    private static Object tryAlgId(PublicKey pk) {
        try {
            // sun.security.x509.X509Key has getAlgorithmId()
            return pk.getClass().getMethod("getAlgorithmId").invoke(pk);
        } catch (Exception e) {
            // Fall back to parsing the SubjectPublicKeyInfo manually if needed.
            // For Kalkan-issued keys this branch shouldn't trigger.
            throw new IllegalStateException("Cannot extract public key OID from " + pk.getClass(), e);
        }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static byte[] produceCms(PrivateKey privateKey, X509Certificate cert,
                                     byte[] document, boolean detached, SigAlg sigAlg) throws Exception {

        // CAdES-BES requires the signingCertificateV2 (ESS, RFC 5035) attribute.
        byte[] certDer = cert.getEncoded();
        MessageDigest digest = MessageDigest.getInstance(sigAlg.digestAlgo(), KALKAN_PROVIDER_NAME);
        byte[] certHash = digest.digest(certDer);

        AlgorithmIdentifier digestAlgId =
            new DefaultDigestAlgorithmIdentifierFinder().find(sigAlg.digestAlgo());
        ESSCertIDv2 essCertId = new ESSCertIDv2(digestAlgId, certHash);
        SigningCertificateV2 sigCertV2 = new SigningCertificateV2(new ESSCertIDv2[]{essCertId});

        Hashtable<org.bouncycastle.asn1.ASN1ObjectIdentifier, Attribute> extraAttrs = new Hashtable<>();
        extraAttrs.put(
            PKCSObjectIdentifiers.id_aa_signingCertificateV2,
            new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(sigCertV2))
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg.signatureAlgo())
            .setProvider(KALKAN_PROVIDER_NAME)
            .build(privateKey);

        SignerInfoGenerator signerInfo = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(KALKAN_PROVIDER_NAME).build())
            .setSignedAttributeGenerator(
                new DefaultSignedAttributeTableGenerator(new AttributeTable(extraAttrs)))
            .build(contentSigner, cert);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(signerInfo);
        gen.addCertificates(new JcaCertStore(List.of(cert)));

        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(document), !detached);
        return signed.getEncoded();
    }

    private KalkanSigner() {}
}
