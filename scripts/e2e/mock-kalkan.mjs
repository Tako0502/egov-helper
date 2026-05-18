// Mock Kalkan signer for the e2e demo.
//
// Only implements POST /cms/verify, which is the only Kalkan endpoint the demo
// app-backend calls. Returns the same shape as the real Java service:
//   { valid, signerInfo: {iin,bin,commonName,...}, documentDigestMatches, chainValid }
//
// Reuses the library's own inspectSignature() so we don't reimplement CMS parsing
// — and so the mock catches the same issues the real backend would catch.

import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const { inspectSignature } = await import(path.join(ROOT, 'dist/index.js'));

const PORT = readPort(7676);

http
  .createServer(async (req, res) => {
    if (req.method === 'OPTIONS') return cors(res, 204);
    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    if (url.pathname === '/health' && req.method === 'GET') {
      return json(res, 200, { ok: true, mock: 'kalkan' });
    }
    if (url.pathname === '/cms/verify' && req.method === 'POST') {
      return verify(req, res);
    }
    return json(res, 404, { error: `No route for ${req.method} ${url.pathname}` });
  })
  .listen(PORT, '0.0.0.0', () => {
    console.log(`[mock-kalkan]  listening on http://localhost:${PORT}`);
    console.log(`[mock-kalkan]  endpoints: POST /cms/verify, GET /health`);
  });

async function verify(req, res) {
  const body = await readBody(req);
  let parsed;
  try { parsed = JSON.parse(body); } catch {
    return json(res, 400, { error: 'invalid JSON' });
  }
  const { cmsBase64, documentBase64 } = parsed;
  if (typeof cmsBase64 !== 'string') {
    return json(res, 400, { error: 'cmsBase64 required' });
  }

  try {
    const docBytes = typeof documentBase64 === 'string' && documentBase64.length > 0
      ? Buffer.from(documentBase64, 'base64')
      : undefined;
    const insp = await inspectSignature(cmsBase64, docBytes ? { document: docBytes } : {});
    const signer = insp.signers?.[0];
    if (!signer) return json(res, 422, { error: 'CMS has no signers' });

    // Demo simplification: trust any cert that comes through. Real Kalkan walks the
    // NUC RK trust chain here — that's the whole point of using Kalkan over node-forge.
    // (We also can't gate on signer.signatureValid because forge's CMS DER ordering
    //  doesn't round-trip through our canonical re-encoder — see scripts/mock-backend.mjs.)
    const chainValid = true;
    const documentDigestMatches = insp.documentDigestMatches;
    const valid = chainValid && documentDigestMatches !== false;

    return json(res, 200, {
      valid,
      chainValid,
      documentDigestMatches,
      signerInfo: signer.certInfo,
    });
  } catch (e) {
    return json(res, 422, { error: `Could not parse CMS: ${e.message}` });
  }
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...corsHeaders() });
  res.end(JSON.stringify(body));
}
function cors(res, status = 204) { res.writeHead(status, corsHeaders()); res.end(); }
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}
async function readBody(req) {
  let buf = '';
  for await (const chunk of req) buf += chunk;
  return buf;
}
function readPort(fallback) {
  const i = process.argv.indexOf('--port');
  if (i !== -1 && process.argv[i + 1]) return Number(process.argv[i + 1]);
  return Number(process.env.PORT ?? fallback);
}
