import { QRSigningClientCMS } from 'sigex-qr-signing-client';
import type { QrSignOptions, QrSignResult, QrInfo, QrLogoOptions } from './types';
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

  // SIGEX's getQR() returns the bare base64 string without a data-URL prefix; wrap it
  // so the result can be used directly as `<img src={qr.qrCodeDataUrl}>`.
  const rawQr = client.getQR();
  const sigexQrDataUrl = rawQr.startsWith('data:') ? rawQr : `data:image/png;base64,${rawQr}`;

  // If the caller wants their own logo in the centre, repaint the QR with the overlay.
  // We swallow overlay failures (logo URL unreachable, canvas tainted, etc.) and fall back
  // to the original SIGEX QR — the signing flow itself must not break over branding.
  let qrCodeDataUrl = sigexQrDataUrl;
  if (options.logo) {
    try {
      qrCodeDataUrl = await overlayQrLogo(sigexQrDataUrl, options.logo);
    } catch (err) {
      options.onPollError?.(err as Error);
    }
  }

  const qr: QrInfo = {
    qrCodeDataUrl,
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
 * Repaint a QR PNG with a custom logo in the centre. Returns a new PNG data URL.
 *
 * Works by drawing the QR onto a canvas, masking out the centre with a coloured box, then
 * drawing the logo on top. The QR payload bytes are unchanged — Reed-Solomon error
 * correction in the QR absorbs the visual occlusion, so eGov Mobile still scans it.
 *
 * Exposed so callers can use the same overlay outside the signing flow (e.g. for a static
 * preview, or for QRs not produced by this library). Throws if the logo URL can't be
 * loaded or the canvas is tainted (cross-origin without CORS).
 *
 * Browser-only: needs `document.createElement('canvas')` and the DOM `Image` constructor.
 */
export async function overlayQrLogo(
  qrPngDataUrl: string,
  logo: QrLogoOptions,
): Promise<string> {
  if (typeof document === 'undefined' || typeof Image === 'undefined') {
    throw new Error('overlayQrLogo requires a browser environment (uses <canvas> and Image).');
  }

  const crossOrigin = logo.crossOrigin === undefined ? 'anonymous' : logo.crossOrigin;

  const [qrImg, logoImg] = await Promise.all([
    loadImage(qrPngDataUrl, crossOrigin),
    typeof logo.src === 'string' ? loadImage(logo.src, crossOrigin) : Promise.resolve(logo.src),
  ]);

  const canvas = document.createElement('canvas');
  canvas.width = qrImg.naturalWidth || qrImg.width;
  canvas.height = qrImg.naturalHeight || qrImg.height;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('Could not get 2D canvas context for QR overlay.');

  ctx.drawImage(qrImg, 0, 0, canvas.width, canvas.height);

  const sizeFraction = clamp(logo.size ?? 0.22, 0.05, 0.4);
  const padding = Math.max(0, logo.padding ?? 6);
  const background = logo.background ?? '#ffffff';
  const borderRadius = Math.max(0, logo.borderRadius ?? 0);

  const logoSide = Math.round(Math.min(canvas.width, canvas.height) * sizeFraction);
  const boxSide = logoSide + padding * 2;
  const boxX = Math.round((canvas.width - boxSide) / 2);
  const boxY = Math.round((canvas.height - boxSide) / 2);

  if (background !== 'transparent') {
    ctx.fillStyle = background;
    if (borderRadius > 0) {
      drawRoundedRectPath(ctx, boxX, boxY, boxSide, boxSide, borderRadius);
      ctx.fill();
    } else {
      ctx.fillRect(boxX, boxY, boxSide, boxSide);
    }
  }

  // Preserve aspect ratio if the logo isn't square — fit inside the logoSide×logoSide box.
  const logoW = logoImg.naturalWidth || logoImg.width;
  const logoH = logoImg.naturalHeight || logoImg.height;
  const scale = logoW > 0 && logoH > 0 ? Math.min(logoSide / logoW, logoSide / logoH) : 1;
  const drawW = Math.round(logoW * scale);
  const drawH = Math.round(logoH * scale);
  const drawX = Math.round((canvas.width - drawW) / 2);
  const drawY = Math.round((canvas.height - drawH) / 2);
  ctx.drawImage(logoImg, drawX, drawY, drawW, drawH);

  return canvas.toDataURL('image/png');
}

function loadImage(src: string, crossOrigin: 'anonymous' | 'use-credentials' | null): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    if (crossOrigin !== null) img.crossOrigin = crossOrigin;
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error(`Failed to load image: ${src.slice(0, 80)}…`));
    img.src = src;
  });
}

function drawRoundedRectPath(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  r: number,
): void {
  const rr = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.lineTo(x + w - rr, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + rr);
  ctx.lineTo(x + w, y + h - rr);
  ctx.quadraticCurveTo(x + w, y + h, x + w - rr, y + h);
  ctx.lineTo(x + rr, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - rr);
  ctx.lineTo(x, y + rr);
  ctx.quadraticCurveTo(x, y, x + rr, y);
  ctx.closePath();
}

function clamp(n: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, n));
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
