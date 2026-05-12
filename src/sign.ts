import type { P12Input, SignOptions, SignResult, CertInfo } from './types';

/**
 * Sign a document with the user's NUC RK certificate.
 *
 * Routes every call to your Kalkan-backed Java service. Works for both RSA and KZ GOST
 * keys (Kalkan handles them all). The `.p12` and password transit to your backend over
 * TLS; the backend signs in memory and never persists the key.
 *
 * Output is a CAdES-BES (RFC 5126) CMS / PKCS#7 SignedData blob — verifiable by anything
 * that speaks CMS (KalkanCrypt, NCALayer, .NET SignedCms, OpenSSL, etc.).
 */
export async function signDocument(
  p12: P12Input,
  password: string,
  document: ArrayBuffer | Uint8Array | string,
  options: SignOptions,
): Promise<SignResult> {
  if (!options?.backendUrl) {
    throw new Error('signDocument requires options.backendUrl (the URL of your Kalkan signing service)');
  }
  if (typeof fetch !== 'function') {
    throw new Error('fetch() is not available in this runtime — Node ≥18 has it natively. Upgrade or polyfill.');
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

  const url = joinUrl(options.backendUrl, '/sign');
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
      `Could not reach the signing service at ${url}: ${(e as Error).message}. ` +
        'Check the backend URL, CORS configuration, and that egov-helper-signer is running.',
    );
  }

  if (!response.ok) {
    let detail = '';
    try {
      const errBody = (await response.json()) as { error?: string };
      detail = errBody?.error ? `: ${errBody.error}` : '';
    } catch {
      /* not JSON */
    }
    throw new Error(`Signing failed (HTTP ${response.status})${detail}`);
  }

  const json = (await response.json()) as BackendSignResponse;
  if (!json?.signatureBase64) {
    throw new Error('Signing service response is missing signatureBase64');
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

// ────────────────────────────────────────────────────────────────────────
// Internal helpers (also imported by bin.ts)

export interface BackendSignRequest {
  p12Base64: string;
  password: string;
  documentBase64: string;
  detached: boolean;
  hashAlgorithm: 'auto' | 'SHA-256' | 'SHA-384' | 'SHA-512';
}

export interface BackendSignResponse {
  signatureBase64: string;
  signedAtIso: string;
  detached: boolean;
  certInfo: BackendCertInfo;
}

export interface BackendCertInfo {
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

export function hydrateCertInfo(wire: BackendCertInfo): CertInfo {
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

/** Join a base URL and a path, handling trailing/leading slashes. */
export function joinUrl(base: string, path: string): string {
  const cleanBase = base.replace(/\/+$/, '');
  const cleanPath = path.startsWith('/') ? path : '/' + path;
  return cleanBase + cleanPath;
}

export async function p12ToUint8Array(input: P12Input): Promise<Uint8Array> {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (typeof File !== 'undefined' && input instanceof File) {
    return new Uint8Array(await input.arrayBuffer());
  }
  throw new Error('Unsupported p12 input: expected File, ArrayBuffer, or Uint8Array');
}

export function documentToUint8Array(doc: ArrayBuffer | Uint8Array | string): Uint8Array {
  if (typeof doc === 'string') return new TextEncoder().encode(doc);
  if (doc instanceof Uint8Array) return doc;
  return new Uint8Array(doc);
}

export function uint8ArrayToBase64(u8: Uint8Array): string {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) {
    bin += String.fromCharCode(...u8.subarray(i, i + CHUNK));
  }
  return typeof btoa === 'function' ? btoa(bin) : Buffer.from(bin, 'binary').toString('base64');
}

export function base64ToUint8Array(b64: string): Uint8Array {
  const cleaned = b64.replace(/\s+/g, '');
  const bin =
    typeof atob === 'function' ? atob(cleaned) : Buffer.from(cleaned, 'base64').toString('binary');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
