// Headless-browser smoke test for the new QR logo-overlay feature.
// Generates a real QR (high error-correction), overlays a coloured logo,
// then re-decodes the resulting PNG to prove the QR still scans.

import { chromium } from 'playwright';
import QRCode from 'qrcode';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const BUNDLE = path.join(ROOT, 'dist/egov-helper.min.js');

if (!fs.existsSync(BUNDLE)) {
  console.error(`bundle not found at ${BUNDLE} — run \`npm run build\` first`);
  process.exit(2);
}

const PAYLOAD = 'https://sigex.kz/api/qrSigning?id=test-7f3a-fixture';
let passed = 0;
let failed = 0;
const ok = (m) => { console.log(`  ok   ${m}`); passed++; };
const fail = (m, d) => { console.log(`  FAIL ${m}${d ? `\n       ${d}` : ''}`); failed++; };

console.log('== QR logo-overlay test ==\n');
console.log(`1. launching headless chromium`);

const browser = await chromium.launch();
const page = await browser.newPage();

// Surface page-side console errors / unhandled rejections back to the runner.
page.on('console', (msg) => {
  if (msg.type() === 'error') console.error('  [page error]', msg.text());
});
page.on('pageerror', (err) => console.error('  [pageerror]', err.message));

// Generate a real high-EC QR in Node — `qrcode` ships a Node API but no prebuilt
// browser bundle, so we do this here and hand the data URL to the page.
const qrDataUrlFromNode = await QRCode.toDataURL(PAYLOAD, {
  errorCorrectionLevel: 'H',
  margin: 2,
  width: 320,
});

const jsqrSrc = fs.readFileSync(path.join(ROOT, 'node_modules/jsqr/dist/jsQR.js'), 'utf8');

const html = `<!doctype html><meta charset="utf-8"><body>
  <script>${jsqrSrc}</script>
  <script>${fs.readFileSync(BUNDLE, 'utf8')}</script>
</body>`;

await page.setContent(html, { waitUntil: 'load' });
ok('page + bundles loaded');

// Sanity: the IIFE exposed our helper.
const hasFn = await page.evaluate(() => typeof window.EgovHelper?.overlayQrLogo === 'function');
if (hasFn) ok('window.EgovHelper.overlayQrLogo is exported');
else { fail('overlayQrLogo not exported from bundle'); await browser.close(); process.exit(1); }

console.log('\n2. generate a real high-EC QR, overlay a logo, re-decode');

const result = await page.evaluate(async ({ PAYLOAD, qrDataUrl }) => {
  // 1. (QR generated in Node — passed in as qrDataUrl.)

  // 2. Build a synthetic logo data-URL (blue square with a white "<").
  const logoCanvas = document.createElement('canvas');
  logoCanvas.width = 128;
  logoCanvas.height = 128;
  const lctx = logoCanvas.getContext('2d');
  lctx.fillStyle = '#2b7fff';
  lctx.fillRect(0, 0, 128, 128);
  lctx.fillStyle = '#ffffff';
  lctx.font = 'bold 96px sans-serif';
  lctx.textAlign = 'center';
  lctx.textBaseline = 'middle';
  lctx.fillText('<', 64, 70);
  const logoDataUrl = logoCanvas.toDataURL('image/png');

  // 3. Overlay.
  const overlaidDataUrl = await window.EgovHelper.overlayQrLogo(qrDataUrl, {
    src: logoDataUrl,
    size: 0.22,
    background: '#ffffff',
    padding: 6,
    borderRadius: 8,
  });

  // 4. Inspect: read centre pixel + a corner pixel to confirm overlay actually painted.
  const overlaidImg = await new Promise((res, rej) => {
    const i = new Image();
    i.onload = () => res(i); i.onerror = rej;
    i.src = overlaidDataUrl;
  });
  const insp = document.createElement('canvas');
  insp.width = overlaidImg.width;
  insp.height = overlaidImg.height;
  const ictx = insp.getContext('2d');
  ictx.drawImage(overlaidImg, 0, 0);

  const cx = Math.floor(overlaidImg.width / 2);
  const cy = Math.floor(overlaidImg.height / 2);
  // Dead-centre hits the white "<" glyph on the logo — sample 8px off-centre
  // (still well inside the logo but in the blue field).
  const center = Array.from(ictx.getImageData(cx + 18, cy, 1, 1).data); // expect ~blue
  const corner = Array.from(ictx.getImageData(20, 20, 1, 1).data);       // QR finder area

  // 5. Re-decode the overlaid QR with jsQR to prove the payload survives.
  const full = ictx.getImageData(0, 0, overlaidImg.width, overlaidImg.height);
  const decoded = window.jsQR(full.data, full.width, full.height);

  return {
    qrDataUrl,
    overlaidDataUrl,
    logoDataUrl,
    width: overlaidImg.width,
    height: overlaidImg.height,
    isPng: overlaidDataUrl.startsWith('data:image/png;base64,'),
    center,
    corner,
    decodedPayload: decoded?.data ?? null,
  };
}, { PAYLOAD, qrDataUrl: qrDataUrlFromNode });

if (result.isPng) ok('overlay returns a PNG data URL');
else fail('overlay should return data:image/png;base64,…', `got prefix: ${result.overlaidDataUrl.slice(0, 32)}`);

if (result.width > 0 && result.height > 0) ok(`output has dimensions ${result.width}×${result.height}`);
else fail('output has zero dimensions');

// Center pixel: should be the blue logo (R<100, G<160, B>200) — definitely NOT a clean black/white QR pixel.
const [cR, cG, cB] = result.center;
const looksBlue = cB > 180 && cR < 120;
if (looksBlue) ok(`centre pixel is blue (rgb ${cR},${cG},${cB}) — logo was painted`);
else fail(`centre pixel not blue (rgb ${cR},${cG},${cB}) — logo overlay did not apply`);

// Corner: should still be a QR finder pattern (black or white, not blue).
const [coR, coG, coB] = result.corner;
const looksMonochrome = Math.abs(coR - coG) < 20 && Math.abs(coG - coB) < 20;
if (looksMonochrome) ok(`corner pixel preserved as QR (rgb ${coR},${coG},${coB})`);
else fail(`corner pixel changed (rgb ${coR},${coG},${coB}) — overlay leaked outside the centre`);

// THE critical assertion: the QR still decodes to the same payload.
if (result.decodedPayload === PAYLOAD) ok(`overlaid QR still decodes to "${PAYLOAD}"`);
else fail('overlaid QR no longer decodes', `expected: "${PAYLOAD}"\n       got: ${JSON.stringify(result.decodedPayload)}`);

// Drop the before/after PNGs so you can eyeball them.
const outDir = path.join(ROOT, 'tmp');
fs.mkdirSync(outDir, { recursive: true });
const writeDataUrl = (name, dataUrl) => {
  const b64 = dataUrl.split(',')[1];
  fs.writeFileSync(path.join(outDir, name), Buffer.from(b64, 'base64'));
};
writeDataUrl('qr-original.png', result.qrDataUrl);
writeDataUrl('qr-with-logo.png', result.overlaidDataUrl);
writeDataUrl('logo.png', result.logoDataUrl);
console.log(`\n   wrote tmp/qr-original.png, tmp/qr-with-logo.png, tmp/logo.png — open them to compare visually`);

await browser.close();
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
