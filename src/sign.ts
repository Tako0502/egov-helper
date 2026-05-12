import forge from 'node-forge';
import type { P12Input, SignOptions, SignResult, CertInfo } from './types';
import { parseP12 } from './parse';
import {
  OID,
  type Hash,
  hashOid,
  mdFor,
  bytesToUint8Array,
  uint8ArrayToBase64,
  base64ToUint8Array,
  algorithmIdentifier,
  issuerAndSerialNumber,
  timeAsn1,
  signingCertificateV2Attr,
  sortAttributesForDer,
  signedAttrsTbsBytes,
} from './internal/asn1';

const asn1 = forge.asn1;
const Class = asn1.Class;
const Type = asn1.Type;

/**
 * Sign a document with the user's NUC RK certificate from a .p12 file.
 *
 * Routes between three transports based on `options.transport`:
 *   - 'browser' — sign in-browser with node-forge. RSA only; throws on GOST.
 *   - 'backend' — POST {p12, password, document} to your Kalkan-backed signing service.
 *   - 'auto' (default) — browser first, fall back to backend on GOST detection if
 *                       `backendSignUrl` is provided.
 *
 * Output: a CAdES-BES (RFC 5126) compliant CMS / PKCS#7 SignedData blob (DER-encoded),
 * including the mandatory `signingCertificateV2` (RFC 5035 / ESS) attribute. KalkanCrypt's
 * `verifyData` and System.Security.Cryptography.Pkcs.SignedCms both accept this format.
 *
 * For the 'browser' transport, the private key never leaves the JS runtime that calls
 * this function. For 'backend', the .p12 + password are POSTed over TLS — see the
 * README and `EgovSigningOptions` for security guidance.
 */
export async function signDocument(
  p12: P12Input,
  password: string,
  document: ArrayBuffer | Uint8Array | string,
  options: SignOptions = {},
): Promise<SignResult> {
  const transport = options.transport ?? 'auto';

  if (transport === 'backend') {
    if (!options.backendSignUrl) {
      throw new Error("transport='backend' requires options.backendSignUrl to be set");
    }
    return signViaBackend(p12, password, document, options, options.backendSignUrl);
  }

  if (transport === 'browser') {
    return signInBrowser(p12, password, document, options);
  }

  // transport === 'auto' — try browser, fall back to backend on GOST if URL set.
  try {
    return await signInBrowser(p12, password, document, options);
  } catch (e) {
    const msg = (e as Error)?.message ?? '';
    const isGost = /GOST/i.test(msg);
    if (isGost && options.backendSignUrl) {
      return signViaBackend(p12, password, document, options, options.backendSignUrl);
    }
    throw e;
  }
}

/** In-browser signing path (the original implementation). RSA only. */
async function signInBrowser(
  p12: P12Input,
  password: string,
  document: ArrayBuffer | Uint8Array | string,
  options: SignOptions,
): Promise<SignResult> {
  const detached = options.detached !== false; // default: detached
  const hashAlg: Hash = options.hashAlgorithm ?? 'SHA-256';

  const { certificate, privateKey, certInfo } = await parseP12(p12, password);
  const docBinary = documentToBinary(document);
  const signedAt = new Date();

  // 1. Hash of the document content.
  const docMd = mdFor(hashAlg);
  docMd.update(docBinary);
  const messageDigestBytes = docMd.digest().getBytes();

  // 2. Build SignedAttributes (4 entries — CAdES-BES requires the first 3 plus signingCertificateV2).
  const signedAttrs: forge.asn1.Asn1[] = [
    contentTypeAttr(OID.data),
    signingTimeAttr(signedAt),
    messageDigestAttr(messageDigestBytes),
    signingCertificateV2Attr(certificate, hashAlg),
  ];

  // 3. The bytes-to-be-signed for the signature value.
  // Per RFC 5652 §5.4 — use the EXPLICIT SET tag (0x31), NOT the IMPLICIT [0] tag (0xA0)
  // that will be used in the actual SignerInfo encoding. Elements must also be sorted in DER.
  const tbsBytes = signedAttrsTbsBytes(signedAttrs);

  // 4. RSA-sign the digest of the to-be-signed bytes.
  const tbsMd = mdFor(hashAlg);
  tbsMd.update(tbsBytes);
  const rsaKey = privateKey as forge.pki.rsa.PrivateKey;
  const signatureBytes = rsaKey.sign(tbsMd);

  // 5. Build SignerInfo.
  // SignerInfo ::= SEQUENCE {
  //   version       CMSVersion,             -- 1 when sid is IssuerAndSerialNumber
  //   sid           SignerIdentifier,
  //   digestAlgorithm DigestAlgorithmIdentifier,
  //   signedAttrs   [0] IMPLICIT SignedAttributes OPTIONAL,
  //   signatureAlgorithm SignatureAlgorithmIdentifier,
  //   signature     SignatureValue,         -- OCTET STRING
  //   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
  // }
  const signerInfo = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    asn1.create(Class.UNIVERSAL, Type.INTEGER, false, String.fromCharCode(1)),
    issuerAndSerialNumber(certificate),
    algorithmIdentifier(hashOid(hashAlg)),
    asn1.create(Class.CONTEXT_SPECIFIC, 0, true, sortAttributesForDer(signedAttrs)),
    algorithmIdentifier(OID.rsaEncryption),
    asn1.create(Class.UNIVERSAL, Type.OCTETSTRING, false, signatureBytes),
  ]);

  // 6. Build SignedData.
  // SignedData ::= SEQUENCE {
  //   version          CMSVersion,                                  -- 1
  //   digestAlgorithms DigestAlgorithmIdentifiers,                  -- SET OF
  //   encapContentInfo EncapsulatedContentInfo,
  //   certificates     [0] IMPLICIT CertificateSet OPTIONAL,
  //   crls             [1] IMPLICIT RevocationInfoChoices OPTIONAL,
  //   signerInfos      SignerInfos                                  -- SET OF SignerInfo
  // }
  const signedData = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    asn1.create(Class.UNIVERSAL, Type.INTEGER, false, String.fromCharCode(1)),
    asn1.create(Class.UNIVERSAL, Type.SET, true, [algorithmIdentifier(hashOid(hashAlg))]),
    encapContentInfo(detached, docBinary),
    asn1.create(Class.CONTEXT_SPECIFIC, 0, true, [forge.pki.certificateToAsn1(certificate)]),
    asn1.create(Class.UNIVERSAL, Type.SET, true, [signerInfo]),
  ]);

  // 7. Wrap in ContentInfo with the signedData OID.
  // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
  const contentInfo = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    asn1.create(Class.UNIVERSAL, Type.OID, false, asn1.oidToDer(OID.signedData).getBytes()),
    asn1.create(Class.CONTEXT_SPECIFIC, 0, true, [signedData]),
  ]);

  const der = asn1.toDer(contentInfo).getBytes();
  const signature = bytesToUint8Array(der);

  return {
    signature,
    signatureBase64: uint8ArrayToBase64(signature),
    signedAt,
    detached,
    certInfo,
  };
}

function contentTypeAttr(contentTypeOid: string): forge.asn1.Asn1 {
  return asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    asn1.create(Class.UNIVERSAL, Type.OID, false, asn1.oidToDer(OID.contentType).getBytes()),
    asn1.create(Class.UNIVERSAL, Type.SET, true, [
      asn1.create(Class.UNIVERSAL, Type.OID, false, asn1.oidToDer(contentTypeOid).getBytes()),
    ]),
  ]);
}

function signingTimeAttr(date: Date): forge.asn1.Asn1 {
  return asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    asn1.create(Class.UNIVERSAL, Type.OID, false, asn1.oidToDer(OID.signingTime).getBytes()),
    asn1.create(Class.UNIVERSAL, Type.SET, true, [timeAsn1(date)]),
  ]);
}

function messageDigestAttr(digestBytes: string): forge.asn1.Asn1 {
  return asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    asn1.create(Class.UNIVERSAL, Type.OID, false, asn1.oidToDer(OID.messageDigest).getBytes()),
    asn1.create(Class.UNIVERSAL, Type.SET, true, [
      asn1.create(Class.UNIVERSAL, Type.OCTETSTRING, false, digestBytes),
    ]),
  ]);
}

// EncapsulatedContentInfo ::= SEQUENCE {
//   eContentType ContentType (OID),
//   eContent     [0] EXPLICIT OCTET STRING OPTIONAL
// }
// For a detached signature, we omit eContent. For attached, we include the document bytes.
function encapContentInfo(detached: boolean, docBinary: string): forge.asn1.Asn1 {
  const children: forge.asn1.Asn1[] = [
    asn1.create(Class.UNIVERSAL, Type.OID, false, asn1.oidToDer(OID.data).getBytes()),
  ];
  if (!detached) {
    children.push(
      asn1.create(Class.CONTEXT_SPECIFIC, 0, true, [
        asn1.create(Class.UNIVERSAL, Type.OCTETSTRING, false, docBinary),
      ]),
    );
  }
  return asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, children);
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

// ────────────────────────────────────────────────────────────────────────
// Backend-transport implementation

/** Wire shape of the request sent to the backend signing endpoint. */
interface BackendSignRequest {
  p12Base64: string;
  password: string;
  documentBase64: string;
  detached: boolean;
  hashAlgorithm: 'auto' | 'SHA-256' | 'SHA-384' | 'SHA-512';
}

/** Wire shape of the response from the backend signing endpoint. */
interface BackendSignResponse {
  signatureBase64: string;
  signedAtIso: string;
  detached: boolean;
  certInfo: BackendCertInfo;
}

interface BackendCertInfo {
  bin: string | null;
  iin: string | null;
  commonName: string | null;
  surname: string | null;
  givenName: string | null;
  organization: string | null;
  email: string | null;
  keyUsage: 'AUTH' | 'SIGN' | 'UNKNOWN';
  validFromIso: string;
  validToIso: string;
  serialNumberHex: string;
  certificatePem: string;
}

async function signViaBackend(
  p12: P12Input,
  password: string,
  document: ArrayBuffer | Uint8Array | string,
  options: SignOptions,
  url: string,
): Promise<SignResult> {
  if (typeof fetch !== 'function') {
    throw new Error(
      'fetch() is not available in this runtime — Node ≥18 has it natively. Upgrade or polyfill.',
    );
  }

  const p12Bytes = await p12ToUint8Array(p12);
  const docBytes = documentToUint8Array(document);

  const body: BackendSignRequest = {
    p12Base64: uint8ArrayToBase64(p12Bytes),
    password,
    documentBase64: uint8ArrayToBase64(docBytes),
    detached: options.detached !== false,
    hashAlgorithm: options.hashAlgorithm ?? 'auto',
  };

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      body: JSON.stringify(body),
      ...options.fetchInit,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(options.fetchInit?.headers ?? {}),
      },
    });
  } catch (e) {
    throw new Error(
      `Backend signing call to ${url} failed: ${(e as Error).message}. ` +
        'Check the URL, CORS configuration, and that the Kalkan signer service is running.',
    );
  }

  if (!response.ok) {
    let detail = '';
    try {
      const errBody = (await response.json()) as { error?: string };
      detail = errBody?.error ? `: ${errBody.error}` : '';
    } catch {
      /* response wasn't JSON */
    }
    throw new Error(`Backend signing returned HTTP ${response.status}${detail}`);
  }

  const json = (await response.json()) as BackendSignResponse;
  if (!json?.signatureBase64) {
    throw new Error('Backend signing response is missing signatureBase64');
  }

  const signature = base64ToUint8Array(json.signatureBase64);
  return {
    signature,
    signatureBase64: json.signatureBase64,
    signedAt: new Date(json.signedAtIso),
    detached: json.detached,
    certInfo: hydrateCertInfo(json.certInfo),
  };
}

async function p12ToUint8Array(input: P12Input): Promise<Uint8Array> {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (typeof File !== 'undefined' && input instanceof File) {
    return new Uint8Array(await input.arrayBuffer());
  }
  throw new Error('Unsupported p12 input: expected File, ArrayBuffer, or Uint8Array');
}

function documentToUint8Array(doc: ArrayBuffer | Uint8Array | string): Uint8Array {
  if (typeof doc === 'string') return new TextEncoder().encode(doc);
  if (doc instanceof Uint8Array) return doc;
  return new Uint8Array(doc);
}

function hydrateCertInfo(wire: BackendCertInfo): CertInfo {
  return {
    bin: wire.bin,
    iin: wire.iin,
    commonName: wire.commonName,
    surname: wire.surname,
    givenName: wire.givenName,
    organization: wire.organization,
    email: wire.email,
    keyUsage: wire.keyUsage,
    validFrom: new Date(wire.validFromIso),
    validTo: new Date(wire.validToIso),
    serialNumberHex: wire.serialNumberHex,
    certificatePem: wire.certificatePem,
  };
}
