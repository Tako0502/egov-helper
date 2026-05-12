import type { P12Input, CheckBinResult, CheckBinOptions } from './types';
import {
  p12ToUint8Array,
  uint8ArrayToBase64,
  joinUrl,
  hydrateCertInfo,
  type BackendCertInfo,
} from './sign';

/**
 * Verify that a typed BIN (or IIN) matches the one inside the user's `.p12` certificate.
 *
 * Posts the `.p12` and password to your Kalkan-backed `/info` endpoint, which extracts
 * the cert subject and returns BIN/IIN/CN/etc. without performing a full signing
 * operation. This is what makes `checkBin` work for both RSA and GOST keys — Kalkan
 * parses everything KZ uses.
 *
 * @param p12          .p12 / .pfx file
 * @param password     password for the .p12
 * @param typedValue   12-digit BIN or IIN the user typed (non-digits stripped)
 * @param options      `backendUrl` is required — base URL of the signing service
 */
export async function checkBin(
  p12: P12Input,
  password: string,
  typedValue: string,
  options: CheckBinOptions,
): Promise<CheckBinResult> {
  if (!options?.backendUrl) {
    throw new Error('checkBin requires options.backendUrl (the URL of your Kalkan signing service)');
  }
  if (typeof fetch !== 'function') {
    throw new Error('fetch() is not available in this runtime — Node ≥18 has it natively. Upgrade or polyfill.');
  }

  const normalized = (typedValue ?? '').replace(/\D/g, '');
  if (normalized.length !== 12) {
    throw new Error(
      `Typed BIN/IIN must be exactly 12 digits (got ${normalized.length} digit(s) after stripping non-numeric characters)`,
    );
  }

  const p12Bytes = await p12ToUint8Array(p12);
  const url = joinUrl(options.backendUrl, '/info');

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      body: JSON.stringify({
        p12Base64: uint8ArrayToBase64(p12Bytes),
        password,
        // /info ignores these but the DTO requires them shaped — send empty values
        documentBase64: '',
        detached: true,
        hashAlgorithm: 'auto',
      }),
      ...options.fetchInit,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(options.fetchInit?.headers ?? {}),
      },
    });
  } catch (e) {
    throw new Error(
      `Could not reach the cert-info service at ${url}: ${(e as Error).message}. ` +
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
    throw new Error(`checkBin failed (HTTP ${response.status})${detail}`);
  }

  const wire = (await response.json()) as BackendCertInfo;
  const certInfo = hydrateCertInfo(wire);

  let match = false;
  let matchedField: 'BIN' | 'IIN' | null = null;
  if (certInfo.bin && certInfo.bin === normalized) {
    match = true;
    matchedField = 'BIN';
  } else if (certInfo.iin && certInfo.iin === normalized) {
    match = true;
    matchedField = 'IIN';
  }

  return {
    match,
    certBin: certInfo.bin,
    certIin: certInfo.iin,
    matchedField,
    certInfo,
  };
}
