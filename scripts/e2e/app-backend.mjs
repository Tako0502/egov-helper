// Your app's backend — what you'd actually deploy.
//
// POST /api/contracts/store  { documentBase64, documentName, signatureBase64, signedAt }
//   → forwards to Kalkan signer's /cms/verify
//   → if valid, stores in an in-memory Map
//   → returns { id, valid, signerInfo, documentDigestMatches }
//
// GET  /api/contracts/:id  → returns stored contract metadata
// GET  /api/contracts      → lists all stored ids

import http from 'node:http';
import crypto from 'node:crypto';

const PORT        = readPort(4000);
const KALKAN_URL  = process.env.KALKAN_URL  ?? 'http://localhost:7676';

const contracts = new Map();   // id → { documentName, signerInfo, signedAt, storedAt, docSha256 }

http
  .createServer(async (req, res) => {
    if (req.method === 'OPTIONS') return cors(res, 204);
    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    const p = url.pathname;

    try {
      if (p === '/health' && req.method === 'GET') {
        return json(res, 200, { ok: true, kalkan: KALKAN_URL, contractCount: contracts.size });
      }

      if (p === '/api/contracts' && req.method === 'GET') {
        const items = [...contracts.entries()].map(([id, c]) => ({ id, ...summarise(c) }));
        return json(res, 200, { items });
      }

      const m = p.match(/^\/api\/contracts\/([\w-]+)$/);
      if (m && req.method === 'GET') {
        const c = contracts.get(m[1]);
        if (!c) return json(res, 404, { error: 'not found' });
        return json(res, 200, { id: m[1], ...summarise(c) });
      }

      if (p === '/api/contracts/store' && req.method === 'POST') {
        return storeContract(req, res);
      }

      return json(res, 404, { error: `No route for ${req.method} ${p}` });
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  })
  .listen(PORT, '0.0.0.0', () => {
    console.log(`[app-backend]  listening on http://localhost:${PORT}`);
    console.log(`[app-backend]  forwards verification to ${KALKAN_URL}/cms/verify`);
  });

async function storeContract(req, res) {
  const body = await readBody(req);
  let parsed;
  try { parsed = JSON.parse(body); } catch {
    return json(res, 400, { error: 'invalid JSON' });
  }
  const { documentBase64, documentName, signatureBase64, signedAt } = parsed;
  if (typeof documentBase64 !== 'string' || typeof signatureBase64 !== 'string') {
    return json(res, 400, { error: 'documentBase64 and signatureBase64 required' });
  }

  // 1. Verify via Kalkan.
  let verifyRes;
  try {
    verifyRes = await fetch(`${KALKAN_URL}/cms/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cmsBase64: signatureBase64, documentBase64 }),
    });
  } catch (e) {
    return json(res, 502, { error: `Could not reach Kalkan at ${KALKAN_URL}: ${e.message}` });
  }
  const verdict = await verifyRes.json();
  if (!verifyRes.ok || !verdict.valid) {
    return json(res, 422, { error: 'signature rejected', verdict });
  }

  // 2. Store.
  const id = crypto.randomBytes(6).toString('hex');
  const docBytes = Buffer.from(documentBase64, 'base64');
  const docSha256 = crypto.createHash('sha256').update(docBytes).digest('hex');
  contracts.set(id, {
    documentName: documentName ?? 'document',
    documentBytes: docBytes.length,
    docSha256,
    signerInfo: verdict.signerInfo,
    documentDigestMatches: verdict.documentDigestMatches,
    chainValid: verdict.chainValid,
    signedAt: signedAt ?? null,
    storedAt: new Date().toISOString(),
  });

  console.log(
    `[app-backend]  stored contract id=${id} doc="${parsed.documentName}" `
    + `signer=${verdict.signerInfo?.commonName} (IIN=${verdict.signerInfo?.iin})`,
  );

  return json(res, 200, {
    id,
    valid: true,
    documentDigestMatches: verdict.documentDigestMatches,
    chainValid: verdict.chainValid,
    signerInfo: verdict.signerInfo,
  });
}

function summarise(c) {
  return {
    documentName: c.documentName,
    documentBytes: c.documentBytes,
    docSha256: c.docSha256,
    signerInfo: c.signerInfo,
    documentDigestMatches: c.documentDigestMatches,
    chainValid: c.chainValid,
    signedAt: c.signedAt,
    storedAt: c.storedAt,
  };
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
