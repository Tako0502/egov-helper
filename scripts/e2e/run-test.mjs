// Automated end-to-end test for the QR-sign + backend-store flow.
//
// Boots the same stack as run-demo.mjs (mock-sigex, mock-kalkan, app-backend
// plus a tiny static server for the demo page), then drives the page in headless
// Chromium and asserts the contract was stored correctly.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { startStack, shutdown } from './stack.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const BUNDLE = path.join(ROOT, 'dist/egov-helper.min.js');
const DEMO   = path.join(__dirname, 'demo.html');

if (!fs.existsSync(BUNDLE)) {
  console.error(`Bundle not found at ${BUNDLE}\nRun \`npm run build\` first.`);
  process.exit(2);
}

let passed = 0, failed = 0;
const ok   = (m) => { console.log(`  ok   ${m}`); passed++; };
const fail = (m, d) => { console.log(`  FAIL ${m}${d ? `\n       ${d}` : ''}`); failed++; };

console.log('== e2e QR-sign test ==\n');
console.log('1. starting services');
const services = await startStack({ verbose: false });
ok(`all 3 mock services are healthy`);

console.log('\n2. serving demo.html');
const staticServer = http.createServer((req, res) => {
  const url = (req.url ?? '/').split('?')[0];
  const filePath = url === '/lib/egov-helper.min.js' ? BUNDLE : DEMO;
  fs.readFile(filePath, (err, buf) => {
    if (err) { res.writeHead(404); res.end(); return; }
    const ct = filePath.endsWith('.js') ? 'application/javascript' : 'text/html; charset=utf-8';
    res.writeHead(200, { 'Content-Type': ct });
    res.end(buf);
  });
});
await new Promise((r) => staticServer.listen(5173, '127.0.0.1', r));
ok('static server up on :5173');

const browser = await chromium.launch();
const page = await browser.newPage();
page.on('pageerror', (e) => console.error('  [pageerror]', e.message));
page.on('console', (m) => { if (m.type() === 'error') console.error('  [console.error]', m.text()); });

try {
  console.log('\n3. driving the page');
  await page.goto('http://localhost:5173/demo.html', { waitUntil: 'load' });
  ok('demo page loaded');

  // Upload a synthetic document via the file input.
  const docContent = `e2e test contract — timestamp ${Date.now()}\nBIN: 123456789012\n`;
  await page.setInputFiles('#file', {
    name: 'contract.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from(docContent, 'utf8'),
  });
  ok('file picked');

  await page.click('#sign');
  ok('sign button clicked');

  // Wait for the QR's src to be set (more reliable than waiting on visibility —
  // mock SIGEX auto-signs after 2.5s, which clears the QR's visibility quickly).
  await page.waitForFunction(
    () => document.getElementById('qr').src.startsWith('data:image/png;base64,'),
    { timeout: 5000 },
  );
  const qrSrc = await page.$eval('#qr', (el) => el.src);
  if (qrSrc.startsWith('data:image/png;base64,') && qrSrc.length > 1000) {
    ok(`QR is rendered (${qrSrc.length} chars in data URL)`);
  } else {
    fail('QR src looks wrong', `prefix=${qrSrc.slice(0, 40)} len=${qrSrc.length}`);
  }

  // Inspect the QR centre pixels to confirm the Atasuai logo overlay was applied.
  const centrePixel = await page.evaluate(async () => {
    const img = document.getElementById('qr');
    await new Promise((res) => { if (img.complete) res(); else img.onload = res; });
    const c = document.createElement('canvas');
    c.width = img.naturalWidth; c.height = img.naturalHeight;
    const ctx = c.getContext('2d');
    ctx.drawImage(img, 0, 0);
    const cx = Math.floor(img.naturalWidth / 2);
    const cy = Math.floor(img.naturalHeight / 2);
    // 18px off-centre to skip the white "<" glyph and land on the blue field.
    return Array.from(ctx.getImageData(cx + 18, cy, 1, 1).data);
  });
  const [r, g, b] = centrePixel;
  if (b > 180 && r < 120) ok(`logo is painted (centre pixel rgb ${r},${g},${b})`);
  else fail('logo overlay not visible at QR centre', `rgb ${r},${g},${b}`);

  // Wait for the "done" state — mock SIGEX auto-signs after 2.5s, then backend round-trip.
  await page.waitForFunction(
    () => ['done', 'error'].includes(document.getElementById('stage').dataset.stage),
    { timeout: 15000 },
  );
  const stage = await page.$eval('#stage', (el) => el.dataset.stage);
  if (stage === 'done') ok('flow reached "done" stage');
  else {
    const err = await page.$eval('#error', (el) => el.textContent);
    fail('flow failed', err);
  }

  // Confirm the backend received + stored the contract.
  const contractId = await page.$eval('#result', (el) => el.dataset.contractId);
  if (contractId) ok(`backend returned contract id: ${contractId}`);
  else fail('no contract id returned');

  if (contractId) {
    const stored = await fetch(`http://localhost:4000/api/contracts/${contractId}`).then((r) => r.json());

    if (stored.documentName === 'contract.txt') ok('stored documentName matches upload');
    else fail('documentName mismatch', JSON.stringify(stored));

    if (stored.signerInfo?.iin === '901231400123') ok(`signerInfo.iin extracted from CMS cert`);
    else fail('signerInfo.iin missing', JSON.stringify(stored.signerInfo));

    if (stored.signerInfo?.bin === '123456789012') ok(`signerInfo.bin extracted from CMS cert`);
    else fail('signerInfo.bin missing', JSON.stringify(stored.signerInfo));

    if (stored.documentDigestMatches === true) ok('documentDigestMatches: signature is for THIS doc');
    else fail('documentDigestMatches false', JSON.stringify(stored));

    if (stored.chainValid === true) ok('chainValid: cert chain accepted by mock Kalkan');
    else fail('chainValid false');
  }
} catch (e) {
  fail(`unhandled error: ${e.message}`, e.stack);
} finally {
  await browser.close();
  staticServer.close();
  shutdown(services);
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
