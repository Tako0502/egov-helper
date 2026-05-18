import type {
  P12Input,
  CheckBinResult,
  CheckBinOptions,
  CheckBinViaQrOptions,
} from './types';
import {
  p12ToUint8Array,
  uint8ArrayToBase64,
  joinUrl,
  hydrateCertInfo,
  type BackendCertInfo,
} from './sign';
import { signDocumentViaQr } from './qr';

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

/**
 * Verify a typed BIN/IIN against the user's eGov Mobile certificate — no `.p12` upload.
 *
 * Flow:
 *   1. Generate a short throwaway challenge ("BIN verification at <timestamp>").
 *   2. Ask SIGEX to start a QR signing session — user scans with eGov Mobile and signs the challenge.
 *   3. Take the resulting CMS, POST to `${backendUrl}/cms/inspect`.
 *   4. The backend extracts the signer cert (Kalkan parses GOST CMS), returns BIN/IIN/CN.
 *   5. Compare to the typed value and return a `CheckBinResult` identical in shape to `checkBin`.
 *
 * The signature is never stored or treated as legally binding — it's a one-shot identity check.
 *
 * @param typedValue The 12-digit BIN/IIN the user typed in your form.
 * @param options    `backendUrl` is required (URL of your Kalkan signer); `onQrReady` is the
 *                   render hook you almost always want to provide.
 */
export async function checkBinViaQr(
  typedValue: string,
  options: CheckBinViaQrOptions,
): Promise<CheckBinResult> {
  if (!options?.backendUrl) {
    throw new Error('checkBinViaQr requires options.backendUrl (the URL of your Kalkan signing service)');
  }

  const normalized = (typedValue ?? '').replace(/\D/g, '');
  if (normalized.length !== 12) {
    throw new Error(
      `Typed BIN/IIN must be exactly 12 digits (got ${normalized.length} digit(s) after stripping non-numeric characters)`,
    );
  }

  // 1. Sign a throwaway challenge via SIGEX QR + eGov Mobile.
  const challenge = `BIN verification — ${new Date().toISOString()}`;
  const sig = await signDocumentViaQr(challenge, {
    sigexHub: options.sigexHub,
    description: options.description ?? 'BIN verification',
    documentName: 'identity-check',
    onQrReady: options.onQrReady,
    onDataSent: options.onDataSent,
    onPollError: options.onPollError,
    logo: options.logo,
  });

  // 2. Ask the Kalkan backend to extract the signer's cert info from the CMS.
  const url = joinUrl(options.backendUrl, '/cms/inspect');
  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      body: JSON.stringify({ cmsBase64: sig.signatureBase64 }),
      ...options.fetchInit,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(options.fetchInit?.headers ?? {}),
      },
    });
  } catch (e) {
    throw new Error(
      `Could not reach the cert-inspect service at ${url}: ${(e as Error).message}`,
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
    throw new Error(`Cert inspect failed (HTTP ${response.status})${detail}`);
  }

  const wire = (await response.json()) as BackendCertInfo;
  const certInfo = hydrateCertInfo(wire);

  // 3. Same comparison logic as checkBin.
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
