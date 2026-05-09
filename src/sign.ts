import forge from 'node-forge';
import type { P12Input, SignOptions, SignResult } from './types';
import { parseP12 } from './parse';
import {
  OID,
  type Hash,
  hashOid,
  mdFor,
  bytesToUint8Array,
  uint8ArrayToBase64,
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
 * Output: a CAdES-BES (RFC 5126) compliant CMS / PKCS#7 SignedData blob (DER-encoded),
 * including the mandatory `signingCertificateV2` (RFC 5035 / ESS) attribute. KalkanCrypt's
 * `verifyData` and System.Security.Cryptography.Pkcs.SignedCms both accept this format.
 *
 * The private key never leaves the JS runtime that calls this function — only the resulting
 * signature bytes do.
 */
export async function signDocument(
  p12: P12Input,
  password: string,
  document: ArrayBuffer | Uint8Array | string,
  options: SignOptions = {},
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
