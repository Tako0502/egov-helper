import { QRSigningClientCMS } from 'sigex-qr-signing-client';
import type { QrSignOptions, QrSignResult, QrInfo } from './types';
import { documentToUint8Array, uint8ArrayToBase64, base64ToUint8Array } from './sign';

/**
 * Sign a document via SIGEX QR + eGov Mobile.
 *
 * No `.p12`, no password — the user signs with their phone. Two flows:
 *
 *   - **Desktop**: render the QR code returned in `onQrReady`. The user opens eGov Mobile
 *     on their phone and scans. The phone signs locally with their already-installed key,
 *     uploads the CMS to the SIGEX hub, we poll until it arrives.
 *   - **Mobile**: don't render the QR — the same page is open on the phone. We return a
 *     deeplink (`qr.eGovMobileLink`) that you redirect to with `window.location.href = …`.
 *     eGov Mobile opens, signs, returns to your tab.
 *
 * The browser is the orchestrator — SIGEX is the relay. Nothing on YOUR backend has to
 * know about this flow (unlike the Kalkan signer). For storage, take the resulting CMS
 * and POST to your existing /api/contracts/store endpoint just like with `signDocument`.
 *
 * Browser-only. SIGEX's client uses `window.btoa` and `fetch`.
 */
export async function signDocumentViaQr(
  document: ArrayBuffer | Uint8Array | string,
  options: QrSignOptions = {},
): Promise<QrSignResult> {
  if (typeof window === 'undefined' || typeof fetch !== 'function') {
    throw new Error(
      'signDocumentViaQr requires a browser environment (uses window.btoa and fetch). ' +
        'For Node.js you can polyfill window and call SIGEX directly, but the typical use ' +
        'case is browser-side.',
    );
  }

  const description = options.description ?? 'Document signing via egov-helper';
  const docName = options.documentName ?? 'document';
  const baseUrl = options.sigexHub ?? 'https://sigex.kz';
  const attached = options.attached === true;

  const docBytes = documentToUint8Array(document);
  const docBase64 = uint8ArrayToBase64(docBytes);

  const client = new QRSigningClientCMS(description, attached, baseUrl);

  // Localised names: [ru, kk, en]. We use the same string for all three — caller can
  // override by passing { documentNames: ['kk', 'ru', 'en'] } in options.
  const names = options.documentNames ?? [docName, docName, docName];
  await client.addDataToSign(names, docBase64, [], options.isPdf === true);

  await client.registerQRSinging();

  const qr: QrInfo = {
    qrCodeDataUrl: client.getQR(),
    eGovMobileLink: client.getEGovMobileLaunchLink(),
    eGovBusinessLink: client.getEGovBusinessLaunchLink(),
    expiresAt: client.expireAt ? new Date(client.expireAt) : null,
  };

  options.onQrReady?.(qr);

  // Now poll. Long-running until the user signs (or the QR expires, or they cancel).
  const cmsList = await client.getSignatures(
    () => options.onDataSent?.(),
    (err: Error) => options.onPollError?.(err),
  );

  if (!cmsList || cmsList.length === 0) {
    throw new Error('SIGEX returned no signatures');
  }

  const signatureBase64 = cmsList[0]!;
  const signature = base64ToUint8Array(signatureBase64);

  return {
    signature,
    signatureBase64,
    signedAt: new Date(),
  };
}

/**
 * Best-effort: detect a mobile/touch device. Use this to choose between rendering a QR
 * (desktop) and redirecting to the eGov Mobile deeplink (phone/tablet).
 */
export function isLikelyMobile(): boolean {
  if (typeof window === 'undefined' || typeof navigator === 'undefined') return false;
  // navigator.userAgentData is the modern path; userAgent is the fallback.
  const uaData = (navigator as { userAgentData?: { mobile?: boolean } }).userAgentData;
  if (uaData?.mobile !== undefined) return uaData.mobile;
  if (typeof navigator.userAgent === 'string') {
    if (/Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent)) return true;
  }
  // Coarse pointer + small viewport is a strong signal too.
  if (typeof window.matchMedia === 'function') {
    return window.matchMedia('(pointer: coarse) and (max-width: 900px)').matches;
  }
  return false;
}
