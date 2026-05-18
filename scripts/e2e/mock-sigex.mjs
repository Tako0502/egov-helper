// Mock SIGEX hub for the e2e demo.
//
// Implements the wire protocol used by `sigex-qr-signing-client`:
//   POST /api/egovQr                       → register session, return QR + URLs
//   POST /api/egovQr/:sid/data             → receive documents
//   GET  /api/egovQr/:sid/sign             → return CMS signatures (long-poll-ish)
//
// Auto-signs whatever the browser uploads using a synthetic RSA test cert
// after AUTO_SIGN_DELAY_MS, so no real phone or eGov Mobile is involved.

import http from 'node:http';
import crypto from 'node:crypto';
import forge from 'node-forge';
import QRCode from 'qrcode';

const PORT = readPort(8080);
const AUTO_SIGN_DELAY_MS = Number(process.env.SIGEX_AUTO_SIGN_MS ?? 2500);

// Synthetic signer — same KZ subject shape as a real NUC RK cert (BIN + IIN).
const TEST_IIN = '901231400123';
const TEST_BIN = '123456789012';
const TEST_CN  = 'TEST USER (MOCK SIGEX)';
const { cert: SIGNER_CERT, key: SIGNER_KEY } = makeSigner();

const sessions = new Map();   // sid → { docs, signaturePromise, expireAt }

http
  .createServer(async (req, res) => {
    if (req.method === 'OPTIONS') return cors(res, 204);
    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    const p = url.pathname;

    try {
      if (p === '/health' && req.method === 'GET') {
        return json(res, 200, { ok: true, mock: 'sigex' });
      }

      if (p === '/api/egovQr' && req.method === 'POST') {
        return registerSession(req, res);
      }

      const m = p.match(/^\/api\/egovQr\/([\w-]+)\/(data|sign)$/);
      if (m) {
        const [, sid, kind] = m;
        const session = sessions.get(sid);
        if (!session) return json(res, 404, { message: `Unknown session ${sid}` });
        if (kind === 'data' && req.method === 'POST') return receiveDocs(req, res, session);
        if (kind === 'sign' && req.method === 'GET')  return returnSignatures(req, res, session);
      }

      return json(res, 404, { message: `No route for ${req.method} ${p}` });
    } catch (e) {
      return json(res, 500, { message: e.message });
    }
  })
  .listen(PORT, '0.0.0.0', () => {
    console.log(`[mock-sigex]   listening on http://localhost:${PORT}`);
    console.log(`[mock-sigex]   auto-signs uploaded docs after ${AUTO_SIGN_DELAY_MS}ms`);
    console.log(`[mock-sigex]   signer subject: CN=${TEST_CN}, IIN=${TEST_IIN}, BIN=${TEST_BIN}`);
  });

// ────────────────────────────────────────────────────────────────────────

async function registerSession(req, res) {
  await readBody(req);  // body is just { description } — we don't need it
  const sid = crypto.randomBytes(8).toString('hex');
  const base = `http://localhost:${PORT}/api/egovQr/${sid}`;
  const launchLink = `egovmobile://sign?qr=${base}`;

  // Real QR PNG encoding the launch URL — what a phone camera would resolve.
  const qrPngDataUrl = await QRCode.toDataURL(launchLink, {
    errorCorrectionLevel: 'H',
    margin: 2,
    width: 320,
  });
  // SIGEX returns the bare base64 string (no data URL prefix). Match that.
  const qrCode = qrPngDataUrl.replace(/^data:image\/png;base64,/, '');

  sessions.set(sid, {
    docs: null,
    signaturePromise: null,
    expireAt: Date.now() + 5 * 60_000,
  });

  return json(res, 200, {
    qrCode,
    dataURL: `${base}/data`,
    signURL: `${base}/sign`,
    eGovMobileLaunchLink: launchLink,
    eGovBusinessLaunchLink: launchLink.replace('egovmobile://', 'egovbusiness://'),
  });
}

async function receiveDocs(req, res, session) {
  const body = await readBody(req);
  let parsed;
  try { parsed = JSON.parse(body); } catch {
    return json(res, 400, { message: 'invalid JSON' });
  }
  if (!Array.isArray(parsed?.documentsToSign) || parsed.documentsToSign.length === 0) {
    return json(res, 400, { message: 'documentsToSign empty' });
  }
  session.docs = parsed.documentsToSign;
  session.signMethod = parsed.signMethod ?? 'CMS_SIGN_ONLY';

  // Kick off "phone is signing…" in the background. The browser will poll signURL
  // until this resolves.
  session.signaturePromise = new Promise((resolve) => {
    setTimeout(() => {
      const detached = session.signMethod !== 'CMS_WITH_DATA';
      const signed = session.docs.map((d) => ({
        ...d,
        document: {
          ...d.document,
          file: {
            ...d.document.file,
            data: signDocBase64ToCmsBase64(d.document.file.data, { detached }),
          },
        },
      }));
      resolve(signed);
    }, AUTO_SIGN_DELAY_MS);
  });

  console.log(`[mock-sigex]   received ${session.docs.length} doc(s), auto-signing in ${AUTO_SIGN_DELAY_MS}ms`);
  return json(res, 200, { status: 'OK' });
}

async function returnSignatures(req, res, session) {
  if (!session.signaturePromise) {
    return json(res, 425, { message: 'data not yet uploaded' });
  }
  const signed = await session.signaturePromise;
  console.log(`[mock-sigex]   delivering ${signed.length} signature(s)`);
  return json(res, 200, { status: 'OK', documentsToSign: signed });
}

// ────────────────────────────────────────────────────────────────────────
// CMS signing with node-forge — same approach as scripts/mock-backend.mjs.

function signDocBase64ToCmsBase64(docB64, { detached }) {
  const docBytes = Buffer.from(docB64, 'base64');
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(docBytes.toString('binary'), 'raw');
  p7.addCertificate(SIGNER_CERT);
  p7.addSigner({
    key: SIGNER_KEY,
    certificate: SIGNER_CERT,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() },
    ],
  });
  p7.sign({ detached });
  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return Buffer.from(der, 'binary').toString('base64');
}

function makeSigner() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 86_400_000);
  cert.validity.notAfter  = new Date(Date.now() + 365 * 86_400_000);
  const subject = [
    { name: 'commonName',             value: TEST_CN },
    { type: '2.5.4.5',                value: `IIN${TEST_IIN}` },
    { name: 'organizationalUnitName', value: `BIN${TEST_BIN}` },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'extKeyUsage', clientAuth: true, emailProtection: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert, key: keys.privateKey };
}

// ────────────────────────────────────────────────────────────────────────

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...corsHeaders() });
  res.end(JSON.stringify(body));
}
function cors(res, status = 204) {
  res.writeHead(status, corsHeaders());
  res.end();
}
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
