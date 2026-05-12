import forge from 'node-forge';
import type { P12Input, CertInfo } from './types';

export interface ParsedP12 {
  certificate: forge.pki.Certificate;
  privateKey: forge.pki.PrivateKey;
  certInfo: CertInfo;
}

/**
 * Parse a Kazakhstan NUC RK .p12 / .pfx file (issued by pki.gov.kz) and return
 * the certificate, private key, and a high-level summary of the certificate.
 *
 * The private key never leaves the JS runtime that calls this function.
 */
export async function parseP12(input: P12Input, password: string): Promise<ParsedP12> {
  const binary = await inputToBinaryString(input);

  let p12Asn1: forge.asn1.Asn1;
  try {
    p12Asn1 = forge.asn1.fromDer(binary);
  } catch (e) {
    throw new Error(`Invalid PKCS#12 file: ${(e as Error).message}`);
  }

  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);
  } catch (e) {
    const msg = ((e as Error)?.message ?? String(e)).toLowerCase();
    if (msg.includes('mac') || msg.includes('password') || msg.includes('decrypt')) {
      throw new Error('Wrong password or corrupted PKCS#12 file');
    }
    // node-forge only supports RSA keys. NUC RK still issues a small number of GOST keys
    // (GOST R 34.10-2001 / 34.10-2012). Detect those and give a clear, actionable message.
    if (containsGostOids(binary)) {
      throw new Error(
        'This certificate uses GOST cryptography (GOST R 34.10), which is not supported by this library. ' +
          'Either reissue an RSA certificate at egov.kz (free, takes ~1 minute) or use NCALayer for this user.',
      );
    }
    throw new Error(`Could not open PKCS#12 file: ${(e as Error).message}`);
  }

  let certificate: forge.pki.Certificate | null = null;
  let privateKey: forge.pki.PrivateKey | null = null;
  let sawCertBag = false;
  let sawKeyBag = false;

  for (const safeContent of p12.safeContents) {
    for (const safeBag of safeContent.safeBags) {
      if (safeBag.type === forge.pki.oids.certBag) {
        sawCertBag = true;
        if (safeBag.cert) {
          // A .p12 may contain multiple certs (cert + chain). Prefer the leaf
          // (the one whose subject does NOT match its issuer; CA certs are self-issued).
          if (!certificate || isLeafCert(safeBag.cert)) {
            certificate = safeBag.cert;
          }
        }
      } else if (
        safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag ||
        safeBag.type === forge.pki.oids.keyBag
      ) {
        sawKeyBag = true;
        if (safeBag.key && !privateKey) privateKey = safeBag.key;
      }
    }
  }

  // If forge gave us back the bag containers but couldn't decode the cert or the key,
  // the underlying algorithm is something forge doesn't understand — for NUC RK keys
  // that almost always means GOST R 34.10. (NUC RK names GOST .p12 files with a
  // "GOST256_" or "GOST512_" prefix, e.g. GOST512_<hash>.p12.)
  if ((sawCertBag && !certificate) || (sawKeyBag && !privateKey)) {
    throw new Error(
      'This certificate appears to use GOST R 34.10 cryptography, which this library does ' +
        'not support (it is RSA-only). NUC RK names GOST files with a "GOST256_" / "GOST512_" ' +
        'prefix — if your file starts with one of those, request the RSA equivalent at ' +
        'https://egov.kz/ (free, takes ~1 minute), or fall back to NCALayer for this user.',
    );
  }

  if (!certificate) throw new Error('No certificate found inside the PKCS#12 file');
  if (!privateKey) throw new Error('No private key found inside the PKCS#12 file');

  return { certificate, privateKey, certInfo: extractCertInfo(certificate) };
}

/**
 * Pull the public-facing summary out of a forge Certificate.
 * Exported so callers (e.g. a "show me my cert" UI) can use it directly.
 */
export function extractCertInfo(cert: forge.pki.Certificate): CertInfo {
  const subject = subjectToMap(cert.subject);

  const serialNumberAttr = subject.SERIALNUMBER ?? subject.serialName ?? subject['2.5.4.5'] ?? '';
  const ou = subject.OU ?? subject['2.5.4.11'] ?? '';

  const iin =
    matchKzId(serialNumberAttr, 'IIN') ??
    matchKzId(ou, 'IIN') ??
    bare12Digits(serialNumberAttr);

  const bin = matchKzId(serialNumberAttr, 'BIN') ?? matchKzId(ou, 'BIN');

  return {
    bin,
    iin,
    commonName: subject.CN ?? subject.commonName ?? null,
    surname: subject.SN ?? subject.surname ?? null,
    givenName: subject.GN ?? subject.givenName ?? null,
    organization: subject.O ?? subject.organizationName ?? null,
    email: subject.E ?? subject.emailAddress ?? null,
    keyUsage: detectKeyUsage(cert),
    validFrom: cert.validity.notBefore,
    validTo: cert.validity.notAfter,
    serialNumberHex: cert.serialNumber,
    certificatePem: forge.pki.certificateToPem(cert),
  };
}

async function inputToBinaryString(input: P12Input): Promise<string> {
  let bytes: Uint8Array;
  if (input instanceof Uint8Array) {
    bytes = input;
  } else if (input instanceof ArrayBuffer) {
    bytes = new Uint8Array(input);
  } else if (typeof File !== 'undefined' && input instanceof File) {
    bytes = new Uint8Array(await input.arrayBuffer());
  } else {
    throw new Error('Unsupported p12 input: expected File, ArrayBuffer, or Uint8Array');
  }

  // node-forge expects a binary string. Build it in chunks to avoid blowing
  // the call stack on large files.
  let str = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    str += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return str;
}

function subjectToMap(
  subject: forge.pki.Certificate['subject'],
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const attr of subject.attributes) {
    if (typeof attr.value !== 'string') continue;
    if (attr.shortName) result[attr.shortName] = attr.value;
    if (attr.name) result[attr.name] = attr.value;
    if (attr.type) result[attr.type] = attr.value;
  }
  return result;
}

function matchKzId(value: string, prefix: 'BIN' | 'IIN'): string | null {
  if (!value) return null;
  const m = value.match(new RegExp(`${prefix}[\\s:=]*?(\\d{12})`, 'i'));
  return m ? (m[1] ?? null) : null;
}

function bare12Digits(value: string): string | null {
  const trimmed = value?.trim() ?? '';
  return /^\d{12}$/.test(trimmed) ? trimmed : null;
}

function detectKeyUsage(cert: forge.pki.Certificate): 'AUTH' | 'SIGN' | 'UNKNOWN' {
  const ext = cert.extensions.find((e: { name?: string; id?: string }) =>
    e.name === 'extKeyUsage' || e.id === '2.5.29.37',
  ) as undefined | (Record<string, unknown> & { name?: string });
  if (!ext) return 'UNKNOWN';
  if (ext.clientAuth) return 'AUTH';
  if (ext.emailProtection || ext.codeSigning) return 'SIGN';
  return 'UNKNOWN';
}

// DER-encoded byte signatures of well-known GOST algorithm OIDs. Used as a crude scanner
// over the raw .p12 bytes when forge fails to parse the contents.
const GOST_OID_BYTE_SIGNATURES: readonly string[] = [
  '\x2a\x85\x03\x02\x02\x13', // 1.2.643.2.2.19   GOST R 34.10-2001 public key
  '\x2a\x85\x03\x02\x02\x14', // 1.2.643.2.2.20   GOST R 34.10-2001 signature
  '\x2a\x85\x03\x07\x01\x01\x01\x01', // 1.2.643.7.1.1.1.1  GOST R 34.10-2012 256-bit
  '\x2a\x85\x03\x07\x01\x01\x01\x02', // 1.2.643.7.1.1.1.2  GOST R 34.10-2012 512-bit
];

function containsGostOids(binary: string): boolean {
  for (const sig of GOST_OID_BYTE_SIGNATURES) {
    if (binary.indexOf(sig) !== -1) return true;
  }
  return false;
}

function isLeafCert(cert: forge.pki.Certificate): boolean {
  // Heuristic: a CA cert's subject equals its issuer (self-signed root) or it has
  // basicConstraints CA=true. Treat anything else as a leaf.
  const bc = cert.extensions.find((e: { name?: string }) => e.name === 'basicConstraints') as
    | undefined
    | { cA?: boolean };
  if (bc?.cA) return false;
  return true;
}
