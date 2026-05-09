import forge from 'node-forge';
import type { TimestampOptions } from './types';
import {
  OID,
  type Hash,
  hashOid,
  mdFor,
  bytesToUint8Array,
  uint8ArrayToBinaryString,
  algorithmIdentifier,
} from './internal/asn1';

const asn1 = forge.asn1;
const Class = asn1.Class;
const Type = asn1.Type;

/**
 * Add an RFC 3161 timestamp to an existing CMS signature, upgrading it from CAdES-BES to CAdES-T.
 *
 * Flow:
 *   1. Find the SignerInfo's signature value in the input CMS.
 *   2. Hash it with the requested algorithm and POST a TimeStampReq to the TSA.
 *   3. Receive a TimeStampResp containing a TimeStampToken (a CMS).
 *   4. Embed the TimeStampToken as an unsigned attribute (id-aa-timeStampToken,
 *      OID 1.2.840.113549.1.9.16.2.14) on the SignerInfo and re-emit the CMS.
 *
 * IMPORTANT — CORS:
 *   Public TSAs (including KZ's https://tsp.pki.gov.kz/tsp) do not return CORS headers,
 *   so this call will fail from a browser unless you proxy through your own backend.
 *   Recommended pattern:
 *     - browser calls signDocument(...) → POST signature to your backend
 *     - your backend (Node.js) calls addTimestamp(...) — this works there directly
 *     - backend stores the timestamped CMS
 */
export async function addTimestamp(
  signature: Uint8Array,
  options: TimestampOptions,
): Promise<Uint8Array> {
  const hash: Hash = options.hashAlgorithm ?? 'SHA-256';

  // 1. Decode the input CMS far enough to grab the signature OCTET STRING from SignerInfo[0].
  const cmsBinary = uint8ArrayToBinaryString(signature);
  let outer: forge.asn1.Asn1;
  try {
    outer = asn1.fromDer(cmsBinary);
  } catch (e) {
    throw new Error(`Input is not a valid CMS DER blob: ${(e as Error).message}`);
  }
  const signerInfo = locateSignerInfo(outer);
  const signerSigBytes = readSignerSignatureBytes(signerInfo);

  // 2. Hash the signature value (NOT the original document) — this is what an RFC 3161 TSA
  //    timestamps when used for "signature-timestamp" / unsignedSignatureProperties.
  const md = mdFor(hash);
  md.update(signerSigBytes);
  const imprintBytes = md.digest().getBytes();

  // 3. Build TimeStampReq DER and POST it.
  const tspRequestDer = buildTspRequestDer(imprintBytes, hash);
  const tstToken = await postTspRequest(options.tsaUrl, tspRequestDer, options.fetchInit);

  // 4. Inject the TimeStampToken as an unsigned attribute on SignerInfo.
  injectTimestampAttribute(signerInfo, tstToken);

  // 5. Re-emit the entire CMS as DER.
  const newDer = asn1.toDer(outer).getBytes();
  return bytesToUint8Array(newDer);
}

// ────────────────────────────────────────────────────────────────────────────

function locateSignerInfo(outer: forge.asn1.Asn1): forge.asn1.Asn1 {
  // ContentInfo → [0] EXPLICIT → SignedData → ... → SET OF SignerInfo (last child) → first signer
  if (!Array.isArray(outer.value) || outer.value.length < 2) {
    throw new Error('CMS ContentInfo is malformed');
  }
  const explicitContent = outer.value[1] as forge.asn1.Asn1;
  if (!Array.isArray(explicitContent.value) || explicitContent.value.length < 1) {
    throw new Error('CMS ContentInfo has no inner content');
  }
  const signedData = explicitContent.value[0] as forge.asn1.Asn1;
  if (!Array.isArray(signedData.value) || signedData.value.length === 0) {
    throw new Error('SignedData has no children');
  }
  const last = signedData.value[signedData.value.length - 1] as forge.asn1.Asn1;
  if (last.tagClass !== Class.UNIVERSAL || last.type !== Type.SET) {
    throw new Error('SignedData has no signerInfos SET');
  }
  if (!Array.isArray(last.value) || last.value.length === 0) {
    throw new Error('signerInfos SET is empty');
  }
  return last.value[0] as forge.asn1.Asn1;
}

function readSignerSignatureBytes(signerInfo: forge.asn1.Asn1): string {
  // SignerInfo: version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature, [1] unsignedAttrs?
  // The signature OCTET STRING is the last UNIVERSAL OCTET STRING child before any [1] tag.
  if (!Array.isArray(signerInfo.value)) throw new Error('SignerInfo is malformed');
  for (const child of signerInfo.value as forge.asn1.Asn1[]) {
    if (
      child.tagClass === Class.UNIVERSAL &&
      child.type === Type.OCTETSTRING &&
      typeof child.value === 'string'
    ) {
      // First OCTET STRING in a SignerInfo is the signature value.
      return child.value;
    }
  }
  throw new Error('Could not locate signature OCTET STRING in SignerInfo');
}

function buildTspRequestDer(imprintBytes: string, hash: Hash): Uint8Array {
  // TimeStampReq ::= SEQUENCE {
  //   version       INTEGER (v1(1)),
  //   messageImprint MessageImprint,
  //   reqPolicy     OBJECT IDENTIFIER OPTIONAL,
  //   nonce         INTEGER OPTIONAL,
  //   certReq       BOOLEAN DEFAULT FALSE,
  //   extensions    [0] IMPLICIT Extensions OPTIONAL
  // }
  // MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }
  const messageImprint = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    algorithmIdentifier(hashOid(hash)),
    asn1.create(Class.UNIVERSAL, Type.OCTETSTRING, false, imprintBytes),
  ]);

  const nonceBytes = randomNonceBytes();

  const req = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    asn1.create(Class.UNIVERSAL, Type.INTEGER, false, String.fromCharCode(1)),
    messageImprint,
    asn1.create(Class.UNIVERSAL, Type.INTEGER, false, nonceBytes),
    // certReq = TRUE so the TSA returns its certificate inside the token (handy for inspection)
    asn1.create(Class.UNIVERSAL, Type.BOOLEAN, false, String.fromCharCode(0xff)),
  ]);

  return bytesToUint8Array(asn1.toDer(req).getBytes());
}

function randomNonceBytes(): string {
  // 8 random bytes, ensure leading bit is zero so the INTEGER stays positive in DER.
  const buf = new Uint8Array(8);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < buf.length; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  buf[0] = (buf[0] ?? 0) & 0x7f;
  let s = '';
  for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i] ?? 0);
  return s;
}

async function postTspRequest(
  tsaUrl: string,
  reqDer: Uint8Array,
  fetchInit?: RequestInit,
): Promise<forge.asn1.Asn1> {
  if (typeof fetch !== 'function') {
    throw new Error(
      'fetch() is not available in this runtime — node ≥18 has it natively. Upgrade or polyfill.',
    );
  }

  const response = await fetch(tsaUrl, {
    method: 'POST',
    // Cast through BodyInit: newer TS lib generics on Uint8Array make BufferSource picky.
    body: reqDer as unknown as BodyInit,
    ...fetchInit,
    headers: {
      'Content-Type': 'application/timestamp-query',
      Accept: 'application/timestamp-reply',
      ...(fetchInit?.headers ?? {}),
    },
  });

  if (!response.ok) {
    throw new Error(`TSA ${tsaUrl} responded with HTTP ${response.status}`);
  }

  const buf = new Uint8Array(await response.arrayBuffer());
  const respAsn1 = asn1.fromDer(uint8ArrayToBinaryString(buf));

  // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }
  if (!Array.isArray(respAsn1.value) || respAsn1.value.length < 1) {
    throw new Error('TSA response is not a valid TimeStampResp');
  }
  const statusInfo = respAsn1.value[0] as forge.asn1.Asn1;
  const statusValue = readPkiStatus(statusInfo);
  if (statusValue !== 0 && statusValue !== 1) {
    // 0 = granted, 1 = grantedWithMods. Anything else is a failure.
    throw new Error(`TSA refused to issue timestamp (PKIStatus=${statusValue})`);
  }
  if (respAsn1.value.length < 2) {
    throw new Error('TSA returned a "granted" status but no TimeStampToken');
  }
  return respAsn1.value[1] as forge.asn1.Asn1;
}

function readPkiStatus(statusInfo: forge.asn1.Asn1): number {
  if (!Array.isArray(statusInfo.value) || statusInfo.value.length < 1) return -1;
  const statusNode = statusInfo.value[0] as forge.asn1.Asn1;
  if (typeof statusNode.value !== 'string' || statusNode.value.length === 0) return -1;
  return statusNode.value.charCodeAt(statusNode.value.length - 1);
}

function injectTimestampAttribute(
  signerInfo: forge.asn1.Asn1,
  tstToken: forge.asn1.Asn1,
): void {
  // Build the Attribute SEQUENCE { id-aa-timeStampToken, SET OF { TimeStampToken } }.
  const tsAttr = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    asn1.create(Class.UNIVERSAL, Type.OID, false, asn1.oidToDer(OID.timeStampToken).getBytes()),
    asn1.create(Class.UNIVERSAL, Type.SET, true, [tstToken]),
  ]);

  if (!Array.isArray(signerInfo.value)) {
    throw new Error('SignerInfo is malformed');
  }
  const children = signerInfo.value as forge.asn1.Asn1[];

  // Look for an existing [1] IMPLICIT unsignedAttrs.
  for (const child of children) {
    if (child.tagClass === Class.CONTEXT_SPECIFIC && child.type === 1) {
      if (Array.isArray(child.value)) {
        (child.value as forge.asn1.Asn1[]).push(tsAttr);
      } else {
        child.value = [tsAttr];
      }
      return;
    }
  }
  // No existing unsignedAttrs — append a new [1] IMPLICIT SET.
  children.push(asn1.create(Class.CONTEXT_SPECIFIC, 1, true, [tsAttr]));
}
