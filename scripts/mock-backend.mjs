// Tiny mock signing backend — implements the wire protocol that the JS lib's
// `transport: 'backend'` expects. Useful for:
//   1. Validating that the protocol works end-to-end without setting up Kalkan + Java.
//   2. Local dev when the Java signer is overkill.
//   3. CORS-enabled localhost target for the Vue tester app.
//
// It signs RSA .p12 files with the same code our browser path uses (which means
// GOST keys will still hit the "GOST not supported" error — exactly what the Java
// service is for). This is for protocol-level testing, not GOST coverage.
//
// Run:
//   npm run build
//   node scripts/mock-backend.mjs                 # listens on 0.0.0.0:7575
//   node scripts/mock-backend.mjs --port 9000     # override port

import http from 'node:http';
import { signDocument } from '../dist/index.js';

const port = readPort();
const ALLOWED_ORIGIN = process.env.MOCK_BACKEND_ORIGIN ?? '*';

http
  .createServer(async (req, res) => {
    // CORS preflight so the Vue tester can hit us from localhost:5174
    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders());
      res.end();
      return;
    }

    if (req.url === '/health' && req.method === 'GET') {
      writeJson(res, 200, { ok: true, mock: true });
      return;
    }

    if (req.method !== 'POST') {
      writeJson(res, 405, { error: 'Method Not Allowed — POST only' });
      return;
    }

    let body = '';
    try {
      for await (const chunk of req) body += chunk;
    } catch (e) {
      writeJson(res, 400, { error: `Could not read request body: ${e.message}` });
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(body);
    } catch {
      writeJson(res, 400, { error: 'Request body is not valid JSON' });
      return;
    }

    const { p12Base64, password, documentBase64, detached, hashAlgorithm } = parsed;
    if (typeof p12Base64 !== 'string' || typeof password !== 'string' || typeof documentBase64 !== 'string') {
      writeJson(res, 400, { error: 'Missing one of: p12Base64, password, documentBase64' });
      return;
    }

    const p12 = Buffer.from(p12Base64, 'base64');
    const doc = Buffer.from(documentBase64, 'base64');

    try {
      const result = await signDocument(new Uint8Array(p12), password, new Uint8Array(doc), {
        detached: detached !== false,
        hashAlgorithm: hashAlgorithm && hashAlgorithm !== 'auto' ? hashAlgorithm : 'SHA-256',
        transport: 'browser', // explicitly: this mock can only do RSA
      });

      writeJson(res, 200, {
        signatureBase64: result.signatureBase64,
        signedAtIso: result.signedAt.toISOString(),
        detached: result.detached,
        certInfo: serializeCertInfo(result.certInfo),
      });
    } catch (e) {
      // GOST errors get a 422; everything else 400.
      const msg = e.message ?? String(e);
      const status = /GOST/i.test(msg) ? 422 : 400;
      writeJson(res, status, { error: msg });
    }
  })
  .listen(port, '0.0.0.0', () => {
    console.log(`mock signing backend listening on http://localhost:${port}`);
    console.log(`POST any JSON {p12Base64, password, documentBase64, detached, hashAlgorithm}`);
    console.log(`CORS Origin allow: ${ALLOWED_ORIGIN}`);
  });

function writeJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...corsHeaders() });
  res.end(JSON.stringify(body));
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function serializeCertInfo(c) {
  return {
    bin: c.bin,
    iin: c.iin,
    commonName: c.commonName,
    surname: c.surname,
    givenName: c.givenName,
    organization: c.organization,
    email: c.email,
    keyUsage: c.keyUsage,
    validFromIso: c.validFrom.toISOString(),
    validToIso: c.validTo.toISOString(),
    serialNumberHex: c.serialNumberHex,
    certificatePem: c.certificatePem,
  };
}

function readPort() {
  const i = process.argv.indexOf('--port');
  if (i !== -1 && process.argv[i + 1]) return Number(process.argv[i + 1]);
  return Number(process.env.PORT ?? 7575);
}
