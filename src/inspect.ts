import forge from 'node-forge';
import type {
  CertInfo,
  InspectOptions,
  SignatureInspection,
  SignerInspection,
} from './types';
import { extractCertInfo } from './parse';
import {
  OID,
  type Hash,
  hashFromOid,
  mdFor,
  base64ToUint8Array,
  bytesToUint8Array,
  uint8ArrayToBase64,
  uint8ArrayToBinaryString,
  signedAttrsTbsBytes,
  findAttribute,
  attributeValues,
} from './internal/asn1';

const asn1 = forge.asn1;

/**
 * Decode a CMS / PKCS#7 SignedData blob (the bytes returned by signDocument()) and report
 * everything that's actually inside it: signer cert info, signed time, hash algorithm,
 * whether it's CAdES-BES, whether it's been timestamped (CAdES-T), and whether the
 * signature value verifies against the embedded certificate.
 *
 * Accepts a base64 string, a hex string, an ArrayBuffer, or a Uint8Array.
 *
 * If you have the original document and the signature is detached, pass it as
 * `options.document` to also confirm the messageDigest matches.
 */
export async function inspectSignature(
  input: string | ArrayBuffer | Uint8Array,
  options: InspectOptions = {},
): Promise<SignatureInspection> {
  const bytes = inputToUint8Array(input);
  const binary = uint8ArrayToBinaryString(bytes);

  let outerAsn1: forge.asn1.Asn1;
  try {
    outerAsn1 = asn1.fromDer(binary);
  } catch (e) {
    throw new Error(`Not a valid DER blob: ${(e as Error).message}`);
  }

  const { signedData, embeddedContent } = unwrapContentInfo(outerAsn1);

  const certificates = parseCertificates(signedData);
  const signerInfos = parseSignerInfos(signedData);

  const signers: SignerInspection[] = [];
  let hasTimestamp = false;
  let timestampAt: Date | null = null;

  for (const si of signerInfos) {
    const cert = matchCertForSigner(si, certificates);
    if (!cert) {
      throw new Error(
        'Signer references a certificate (by issuer + serial) that is not embedded in the CMS',
      );
    }
    const certInfo = extractCertInfo(cert);

    const signedAttrs = si.signedAttrs ?? [];
    const signedAt = readSigningTime(signedAttrs);
    const messageDigestBase64 = readMessageDigestBase64(signedAttrs);
    const hasSigningCertificateV2 = !!findAttribute(signedAttrs, OID.signingCertificateV2);

    const signatureValid = verifySignerSignature(si, cert);

    signers.push({
      certInfo,
      signedAt,
      messageDigestBase64,
      hashAlgorithm: si.digestAlgorithm,
      hasSigningCertificateV2,
      signatureValid,
    });

    // CAdES-T: timestamp tokens live as unsigned attributes on the SignerInfo.
    const tsAttr = findAttribute(si.unsignedAttrs ?? [], OID.timeStampToken);
    if (tsAttr) {
      hasTimestamp = true;
      const tsTime = tryReadTsaTime(tsAttr);
      if (tsTime) timestampAt = tsTime;
    }
  }

  // documentDigestMatches: only meaningful if the caller gave us the document
  let documentDigestMatches: boolean | null = null;
  if (options.document !== undefined && signers.length > 0) {
    const docBinary = documentToBinary(options.document);
    const firstSigner = signers[0];
    if (firstSigner) {
      const hash = parseHashAlg(firstSigner.hashAlgorithm);
      if (hash && firstSigner.messageDigestBase64) {
        const md = mdFor(hash);
        md.update(docBinary);
        const computed = uint8ArrayToBase64(bytesToUint8Array(md.digest().getBytes()));
        documentDigestMatches = computed === firstSigner.messageDigestBase64;
      }
    }
  }

  return {
    attached: embeddedContent !== null,
    embeddedContent,
    signers,
    hasTimestamp,
    timestampAt,
    documentDigestMatches,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Internal: ASN.1 traversal

interface ParsedSignerInfo {
  version: number;
  /** Issuer DN ASN.1 + serial number bytes (for matching cert in certificates set) */
  issuerAsn1: forge.asn1.Asn1 | null;
  serialBytes: string | null;
  digestAlgorithmOid: string;
  /** Friendly name: 'SHA-256' / 'SHA-384' / 'SHA-512' / fallback to OID */
  digestAlgorithm: string;
  signedAttrs: forge.asn1.Asn1[] | null;
  /** Raw bytes of the signed attrs as encoded in the wire (with [0] IMPLICIT tag).
      We re-encode with universal SET tag for digest verification. */
  signatureAlgorithmOid: string;
  signatureBytes: string;
  unsignedAttrs: forge.asn1.Asn1[] | null;
}

function unwrapContentInfo(outer: forge.asn1.Asn1): {
  signedData: forge.asn1.Asn1;
  embeddedContent: Uint8Array | null;
} {
  // ContentInfo = SEQUENCE { OID, [0] EXPLICIT ANY }
  if (!Array.isArray(outer.value) || outer.value.length < 2) {
    throw new Error('Not a CMS ContentInfo (missing children)');
  }
  const oidNode = outer.value[0] as forge.asn1.Asn1 | undefined;
  const contentNode = outer.value[1] as forge.asn1.Asn1 | undefined;
  if (!oidNode || typeof oidNode.value !== 'string') {
    throw new Error('Not a CMS ContentInfo (missing content type OID)');
  }
  const contentTypeOid = asn1.derToOid(oidNode.value);
  if (contentTypeOid !== OID.signedData) {
    throw new Error(`Not a SignedData CMS (got contentType ${contentTypeOid})`);
  }
  if (!contentNode || !Array.isArray(contentNode.value) || contentNode.value.length < 1) {
    throw new Error('CMS ContentInfo content is empty');
  }
  const signedData = contentNode.value[0] as forge.asn1.Asn1;

  // SignedData[2] is encapContentInfo: SEQUENCE { eContentType, [0] EXPLICIT OCTET STRING OPTIONAL }
  let embeddedContent: Uint8Array | null = null;
  if (Array.isArray(signedData.value) && signedData.value.length >= 3) {
    const eci = signedData.value[2] as forge.asn1.Asn1;
    if (Array.isArray(eci.value) && eci.value.length >= 2) {
      const eContent = eci.value[1] as forge.asn1.Asn1;
      // [0] EXPLICIT OCTET STRING — eContent.value[0] is the inner OCTET STRING
      if (Array.isArray(eContent.value) && eContent.value.length >= 1) {
        const inner = eContent.value[0] as forge.asn1.Asn1;
        if (typeof inner.value === 'string') {
          embeddedContent = bytesToUint8Array(inner.value);
        }
      } else if (typeof eContent.value === 'string') {
        // Some encoders use IMPLICIT — fall through to using the raw value
        embeddedContent = bytesToUint8Array(eContent.value);
      }
    }
  }

  return { signedData, embeddedContent };
}

function parseCertificates(signedData: forge.asn1.Asn1): forge.pki.Certificate[] {
  if (!Array.isArray(signedData.value)) return [];
  const out: forge.pki.Certificate[] = [];
  // Walk children: digestAlgs (SET), encapContentInfo (SEQUENCE), then optional [0] certificates,
  // optional [1] crls, then signerInfos (SET).
  for (const child of signedData.value as forge.asn1.Asn1[]) {
    if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && child.type === 0) {
      // [0] IMPLICIT CertificateSet
      if (!Array.isArray(child.value)) continue;
      for (const certAsn1 of child.value as forge.asn1.Asn1[]) {
        try {
          out.push(forge.pki.certificateFromAsn1(certAsn1));
        } catch {
          // skip non-cert choices (attribute certs, other revocations, etc.)
        }
      }
    }
  }
  return out;
}

function parseSignerInfos(signedData: forge.asn1.Asn1): ParsedSignerInfo[] {
  if (!Array.isArray(signedData.value)) return [];
  // signerInfos is the LAST child of SignedData and is a UNIVERSAL SET.
  const last = (signedData.value as forge.asn1.Asn1[])[signedData.value.length - 1];
  if (!last || last.tagClass !== asn1.Class.UNIVERSAL || last.type !== asn1.Type.SET) {
    throw new Error('SignedData is missing the signerInfos SET');
  }
  if (!Array.isArray(last.value)) return [];
  return (last.value as forge.asn1.Asn1[]).map(parseSignerInfo);
}

function parseSignerInfo(si: forge.asn1.Asn1): ParsedSignerInfo {
  if (!Array.isArray(si.value)) {
    throw new Error('Malformed SignerInfo (not a sequence)');
  }
  const children = si.value as forge.asn1.Asn1[];
  // Required positions:
  //   [0] version (INTEGER)
  //   [1] sid (SEQUENCE — IssuerAndSerialNumber, OR [0] IMPLICIT — SubjectKeyIdentifier)
  //   [2] digestAlgorithm (SEQUENCE)
  // Optional context-specific [0] signedAttrs comes next.
  //   then signatureAlgorithm (SEQUENCE)
  //   then signature (OCTET STRING)
  // Optional context-specific [1] unsignedAttrs at the end.

  const versionNode = children[0];
  if (!versionNode || typeof versionNode.value !== 'string') {
    throw new Error('Malformed SignerInfo (missing version)');
  }
  const version = readIntegerByte(versionNode.value);

  const sidNode = children[1];
  let issuerAsn1: forge.asn1.Asn1 | null = null;
  let serialBytes: string | null = null;
  if (sidNode && sidNode.tagClass === asn1.Class.UNIVERSAL && sidNode.type === asn1.Type.SEQUENCE) {
    const sidChildren = sidNode.value as forge.asn1.Asn1[];
    issuerAsn1 = sidChildren[0] ?? null;
    const serialNode = sidChildren[1];
    serialBytes = typeof serialNode?.value === 'string' ? serialNode.value : null;
  }

  const digestAlgNode = children[2];
  const digestOidNode = digestAlgNode && Array.isArray(digestAlgNode.value)
    ? (digestAlgNode.value as forge.asn1.Asn1[])[0]
    : null;
  const digestAlgorithmOid =
    digestOidNode && typeof digestOidNode.value === 'string'
      ? asn1.derToOid(digestOidNode.value)
      : '';

  // Find optional [0] signedAttrs
  let signedAttrs: forge.asn1.Asn1[] | null = null;
  let cursor = 3;
  const maybeSigned = children[cursor];
  if (maybeSigned && maybeSigned.tagClass === asn1.Class.CONTEXT_SPECIFIC && maybeSigned.type === 0) {
    signedAttrs = (maybeSigned.value as forge.asn1.Asn1[]) ?? [];
    cursor++;
  }

  const sigAlgNode = children[cursor];
  const sigOidNode = sigAlgNode && Array.isArray(sigAlgNode.value)
    ? (sigAlgNode.value as forge.asn1.Asn1[])[0]
    : null;
  const signatureAlgorithmOid =
    sigOidNode && typeof sigOidNode.value === 'string' ? asn1.derToOid(sigOidNode.value) : '';
  cursor++;

  const sigNode = children[cursor];
  const signatureBytes = sigNode && typeof sigNode.value === 'string' ? sigNode.value : '';
  cursor++;

  let unsignedAttrs: forge.asn1.Asn1[] | null = null;
  const maybeUnsigned = children[cursor];
  if (maybeUnsigned && maybeUnsigned.tagClass === asn1.Class.CONTEXT_SPECIFIC && maybeUnsigned.type === 1) {
    unsignedAttrs = (maybeUnsigned.value as forge.asn1.Asn1[]) ?? [];
  }

  return {
    version,
    issuerAsn1,
    serialBytes,
    digestAlgorithmOid,
    digestAlgorithm: hashFromOid(digestAlgorithmOid) ?? (digestAlgorithmOid || 'unknown'),
    signedAttrs,
    signatureAlgorithmOid,
    signatureBytes,
    unsignedAttrs,
  };
}

function matchCertForSigner(
  si: ParsedSignerInfo,
  certs: forge.pki.Certificate[],
): forge.pki.Certificate | null {
  if (!si.serialBytes || !si.issuerAsn1) {
    // Couldn't read sid; fall back to the first cert if there's only one
    return certs.length === 1 ? certs[0] ?? null : null;
  }
  const wantSerialHex = forge.util.bytesToHex(si.serialBytes).replace(/^0+/, '').toLowerCase();
  const wantIssuerDer = asn1.toDer(si.issuerAsn1).getBytes();

  for (const cert of certs) {
    const certSerialHex = cert.serialNumber.replace(/^0+/, '').toLowerCase();
    if (certSerialHex !== wantSerialHex) continue;
    const certIssuerDer = asn1.toDer(forge.pki.distinguishedNameToAsn1(cert.issuer)).getBytes();
    if (certIssuerDer === wantIssuerDer) return cert;
  }
  // Fallback: serial-only match (issuer DN encoding can differ in unicode form)
  for (const cert of certs) {
    if (cert.serialNumber.replace(/^0+/, '').toLowerCase() === wantSerialHex) return cert;
  }
  return null;
}

function readSigningTime(attrs: forge.asn1.Asn1[]): Date | null {
  const a = findAttribute(attrs, OID.signingTime);
  if (!a) return null;
  const values = attributeValues(a);
  const v = values[0];
  if (!v || typeof v.value !== 'string') return null;
  if (v.type === asn1.Type.UTCTIME) return asn1.utcTimeToDate(v.value);
  if (v.type === asn1.Type.GENERALIZEDTIME) return asn1.generalizedTimeToDate(v.value);
  return null;
}

function readMessageDigestBase64(attrs: forge.asn1.Asn1[]): string | null {
  const a = findAttribute(attrs, OID.messageDigest);
  if (!a) return null;
  const values = attributeValues(a);
  const v = values[0];
  if (!v || typeof v.value !== 'string') return null;
  return uint8ArrayToBase64(bytesToUint8Array(v.value));
}

function tryReadTsaTime(tsAttr: forge.asn1.Asn1): Date | null {
  // The unsigned attr's value is a TimeStampToken (a CMS ContentInfo wrapping a TSTInfo).
  // We don't fully validate it here — just dig for the genTime.
  try {
    const values = attributeValues(tsAttr);
    const tst = values[0];
    if (!tst) return null;
    // Walk: ContentInfo → [0] explicit → SignedData → encapContentInfo → eContent (TSTInfo DER)
    // TSTInfo = SEQUENCE { version INT, policy OID, messageImprint, serial INT, genTime GENERALIZEDTIME, ... }
    const stack: forge.asn1.Asn1[] = [tst];
    while (stack.length > 0) {
      const cur = stack.pop();
      if (!cur) continue;
      if (cur.type === asn1.Type.GENERALIZEDTIME && typeof cur.value === 'string') {
        return asn1.generalizedTimeToDate(cur.value);
      }
      if (Array.isArray(cur.value)) stack.push(...(cur.value as forge.asn1.Asn1[]));
    }
  } catch {
    // best-effort
  }
  return null;
}

function verifySignerSignature(si: ParsedSignerInfo, cert: forge.pki.Certificate): boolean {
  try {
    const hash = parseHashAlg(si.digestAlgorithm);
    if (!hash) return false;

    // Bytes-to-be-verified:
    //   - if signedAttrs are present, it's their re-encoded SET (universal tag 0x31)
    //   - otherwise it's the eContent itself (rare in CAdES flows)
    // We only handle the signedAttrs path here.
    if (!si.signedAttrs) return false;

    const tbsBytes = signedAttrsTbsBytes(si.signedAttrs);
    const md = mdFor(hash);
    md.update(tbsBytes);
    const digest = md.digest().getBytes();

    const publicKey = cert.publicKey as forge.pki.rsa.PublicKey;
    return publicKey.verify(digest, si.signatureBytes);
  } catch {
    return false;
  }
}

function readIntegerByte(s: string): number {
  // node-forge stores ASN.1 INTEGER value as raw bytes; for small ints (version), one byte.
  if (!s) return 0;
  return s.charCodeAt(s.length - 1);
}

function parseHashAlg(name: string): Hash | null {
  switch (name) {
    case 'SHA-256': return 'SHA-256';
    case 'SHA-384': return 'SHA-384';
    case 'SHA-512': return 'SHA-512';
    default: return null;
  }
}

function inputToUint8Array(input: string | ArrayBuffer | Uint8Array): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (typeof input === 'string') {
    // Heuristic: pure base64 is ~A-Z0-9+/= and base64-decoded length must be > 0.
    const cleaned = input.trim();
    if (/^[A-Za-z0-9+/=\s]+$/.test(cleaned) && cleaned.length % 4 === 0) {
      return base64ToUint8Array(cleaned);
    }
    if (/^[0-9a-fA-F\s]+$/.test(cleaned)) {
      const hex = cleaned.replace(/\s+/g, '');
      const out = new Uint8Array(hex.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
      return out;
    }
    throw new Error('Unrecognized signature string format (expected base64 or hex)');
  }
  throw new Error('Unsupported signature input type');
}

function documentToBinary(doc: ArrayBuffer | Uint8Array | string): string {
  if (typeof doc === 'string') return forge.util.encodeUtf8(doc);
  const bytes = doc instanceof Uint8Array ? doc : new Uint8Array(doc);
  let str = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    str += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return str;
}

// Re-export so callers can build a CertInfo from a forge cert directly if needed.
export type { CertInfo };
