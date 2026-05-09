import forge from 'node-forge';

const asn1 = forge.asn1;
const Class = asn1.Class;
const Type = asn1.Type;

// Well-known OIDs used across sign / inspect / timestamp.
export const OID = {
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  // RFC 3161 TimeStampToken — embedded in unsigned attributes for CAdES-T
  timeStampToken: '1.2.840.113549.1.9.16.2.14',
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  sha384WithRSA: '1.2.840.113549.1.1.12',
  sha512WithRSA: '1.2.840.113549.1.1.13',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
} as const;

export type Hash = 'SHA-256' | 'SHA-384' | 'SHA-512';

export function hashOid(hash: Hash): string {
  switch (hash) {
    case 'SHA-256': return OID.sha256;
    case 'SHA-384': return OID.sha384;
    case 'SHA-512': return OID.sha512;
  }
}

export function hashFromOid(oid: string): Hash | null {
  switch (oid) {
    case OID.sha256: return 'SHA-256';
    case OID.sha384: return 'SHA-384';
    case OID.sha512: return 'SHA-512';
    default: return null;
  }
}

export function mdFor(hash: Hash): forge.md.MessageDigest {
  switch (hash) {
    case 'SHA-256': return forge.md.sha256.create();
    case 'SHA-384': return forge.md.sha384.create();
    case 'SHA-512': return forge.md.sha512.create();
  }
}

export function bytesToUint8Array(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export function uint8ArrayToBinaryString(u8: Uint8Array): string {
  let str = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) {
    str += String.fromCharCode(...u8.subarray(i, i + CHUNK));
  }
  return str;
}

export function base64ToUint8Array(b64: string): Uint8Array {
  const cleaned = b64.replace(/\s+/g, '');
  const binary =
    typeof atob === 'function'
      ? atob(cleaned)
      : Buffer.from(cleaned, 'base64').toString('binary');
  return bytesToUint8Array(binary);
}

export function uint8ArrayToBase64(u8: Uint8Array): string {
  const bin = uint8ArrayToBinaryString(u8);
  return typeof btoa === 'function' ? btoa(bin) : Buffer.from(bin, 'binary').toString('base64');
}

// AlgorithmIdentifier ::= SEQUENCE { OID, params? }
// For digest algorithms, RFC 5754 says no params. node-forge & most CMS verifiers
// also accept (and many produce) NULL params, so we include NULL by default for
// maximum compatibility with KalkanCrypt and friends.
export function algorithmIdentifier(oid: string, includeNull = true): forge.asn1.Asn1 {
  const children: forge.asn1.Asn1[] = [
    asn1.create(Class.UNIVERSAL, Type.OID, false, asn1.oidToDer(oid).getBytes()),
  ];
  if (includeNull) {
    children.push(asn1.create(Class.UNIVERSAL, Type.NULL, false, ''));
  }
  return asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, children);
}

// IssuerAndSerialNumber ::= SEQUENCE { Name, INTEGER }
export function issuerAndSerialNumber(cert: forge.pki.Certificate): forge.asn1.Asn1 {
  const issuerAsn1 = forge.pki.distinguishedNameToAsn1(cert.issuer);
  // cert.serialNumber is a hex string (as forge stores it). Convert to ASN.1 INTEGER.
  // forge's util.hexToBytes gives raw bytes; if MSB is set, RFC 3280 says we'd need a leading 0
  // to keep the integer positive — but cert serial numbers are already positive in DER.
  const serialBytes = forge.util.hexToBytes(cert.serialNumber);
  return asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    issuerAsn1,
    asn1.create(Class.UNIVERSAL, Type.INTEGER, false, serialBytes),
  ]);
}

// X.509 time encoding rules: years 1950–2049 → UTCTime, else GeneralizedTime.
export function timeAsn1(date: Date): forge.asn1.Asn1 {
  const year = date.getUTCFullYear();
  if (year >= 1950 && year < 2050) {
    return asn1.create(Class.UNIVERSAL, Type.UTCTIME, false, asn1.dateToUtcTime(date));
  }
  return asn1.create(
    Class.UNIVERSAL,
    Type.GENERALIZEDTIME,
    false,
    asn1.dateToGeneralizedTime(date),
  );
}

// Build the signingCertificateV2 (RFC 5035, ESS) attribute.
//
// Attribute ::= SEQUENCE { OID, SET OF AttributeValue }
// SigningCertificateV2 ::= SEQUENCE {
//     certs SEQUENCE OF ESSCertIDv2,
//     policies SEQUENCE OF PolicyInformation OPTIONAL
// }
// ESSCertIDv2 ::= SEQUENCE {
//     hashAlgorithm AlgorithmIdentifier DEFAULT { algorithm id-sha256 },
//     certHash OCTET STRING,
//     issuerSerial IssuerSerial OPTIONAL
// }
export function signingCertificateV2Attr(
  cert: forge.pki.Certificate,
  hash: Hash,
): forge.asn1.Asn1 {
  const certDer = asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const md = mdFor(hash);
  md.update(certDer);
  const certHashBytes = md.digest().getBytes();

  const essCertIdV2Children: forge.asn1.Asn1[] = [];
  // Per RFC 5035, hashAlgorithm has DEFAULT id-sha256. DER says "omit defaults",
  // so when hash is SHA-256 we don't emit the algorithm identifier.
  if (hash !== 'SHA-256') {
    essCertIdV2Children.push(algorithmIdentifier(hashOid(hash)));
  }
  essCertIdV2Children.push(
    asn1.create(Class.UNIVERSAL, Type.OCTETSTRING, false, certHashBytes),
  );

  const essCertIdV2 = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, essCertIdV2Children);
  const certsSequence = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [essCertIdV2]);
  const signingCertV2 = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [certsSequence]);

  return asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    asn1.create(Class.UNIVERSAL, Type.OID, false, asn1.oidToDer(OID.signingCertificateV2).getBytes()),
    asn1.create(Class.UNIVERSAL, Type.SET, true, [signingCertV2]),
  ]);
}

// DER's SET OF requires elements to be sorted by their full DER encoding.
// RFC 5652 says signedAttrs is a SET OF Attribute, and the DER encoding (with universal tag 0x31)
// is what's hashed for signature computation. So we must sort.
export function sortAttributesForDer(attrs: forge.asn1.Asn1[]): forge.asn1.Asn1[] {
  return [...attrs].sort((a, b) => {
    const aBytes = asn1.toDer(a).getBytes();
    const bBytes = asn1.toDer(b).getBytes();
    if (aBytes < bBytes) return -1;
    if (aBytes > bBytes) return 1;
    return 0;
  });
}

// Recompute the bytes-to-be-signed for SignedAttributes per RFC 5652 §5.4:
// "A separate encoding of the signedAttrs field is performed for message digest calculation.
//  The IMPLICIT [0] tag in the signedAttrs is not used for the DER encoding,
//  rather an EXPLICIT SET OF tag is used."
export function signedAttrsTbsBytes(attrs: forge.asn1.Asn1[]): string {
  const set = asn1.create(
    Class.UNIVERSAL,
    Type.SET,
    true,
    sortAttributesForDer(attrs),
  );
  return asn1.toDer(set).getBytes();
}

/** Find a single attribute (by OID) in a list of Attribute SEQUENCEs. */
export function findAttribute(
  attrs: forge.asn1.Asn1[],
  oid: string,
): forge.asn1.Asn1 | null {
  for (const attr of attrs) {
    if (!Array.isArray(attr.value) || attr.value.length < 1) continue;
    const oidNode = attr.value[0] as forge.asn1.Asn1 | undefined;
    if (!oidNode || typeof oidNode.value !== 'string') continue;
    const parsedOid = asn1.derToOid(oidNode.value);
    if (parsedOid === oid) return attr;
  }
  return null;
}

/** Get the inner AttributeValue(s) of an attribute SEQUENCE { OID, SET OF AttributeValue }. */
export function attributeValues(attr: forge.asn1.Asn1): forge.asn1.Asn1[] {
  if (!Array.isArray(attr.value) || attr.value.length < 2) return [];
  const set = attr.value[1] as forge.asn1.Asn1 | undefined;
  if (!set || !Array.isArray(set.value)) return [];
  return set.value as forge.asn1.Asn1[];
}
