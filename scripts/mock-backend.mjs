// Self-contained mock signing backend. Implements the same wire protocol as the
// Java/Kalkan service in packages/java/egov-helper-signer/, but using node-forge
// internally — so it covers ONLY RSA keys (Kalkan handles GOST + RSA).
//
// Useful for:
//   1. Testing the wire protocol in CI without spinning up Kalkan (which is licensed).
//   2. Local dev when you don't need GOST coverage.
//   3. A target the tester UI can hit without Docker.
//
// For real GOST keys, use packages/java/egov-helper-signer/.
//
// Run:
//   npm run build
//   node scripts/mock-backend.mjs                 # listens on 0.0.0.0:7575
//   node scripts/mock-backend.mjs --port 9000     # override port

import http from 'node:http';
import forge from 'node-forge';

const port = readPort();
const ALLOWED_ORIGIN = process.env.MOCK_BACKEND_ORIGIN ?? '*';

http
  .createServer(async (req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders());
      res.end();
      return;
    }

    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    const path = url.pathname;

    if (path === '/health' && req.method === 'GET') {
      writeJson(res, 200, { ok: true, mock: true, kalkan: '(mock — RSA only)' });
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

    const { p12Base64, password } = parsed;
    if (typeof p12Base64 !== 'string' || typeof password !== 'string') {
      writeJson(res, 400, { error: 'Missing p12Base64 or password' });
      return;
    }

    try {
      const { certificate, privateKey, certInfo } = parseP12(Buffer.from(p12Base64, 'base64'), password);

      if (path === '/info') {
        writeJson(res, 200, certInfo);
        return;
      }

      // /sign (or /, for back-compat)
      const { documentBase64, detached: detachedRaw, hashAlgorithm } = parsed;
      if (typeof documentBase64 !== 'string') {
        writeJson(res, 400, { error: 'Missing documentBase64 for signing request' });
        return;
      }
      const doc = Buffer.from(documentBase64, 'base64');
      const detached = detachedRaw !== false;
      const hashAlg = hashAlgorithm && hashAlgorithm !== 'auto' ? hashAlgorithm : 'SHA-256';

      const cms = signCmsWithForge(certificate, privateKey, doc, { detached, hashAlg });

      writeJson(res, 200, {
        signatureBase64: cms.toString('base64'),
        signedAtIso: new Date().toISOString(),
        detached,
        certInfo,
      });
    } catch (e) {
      const msg = e.message ?? String(e);
      const status = /password|wrong/i.test(msg) ? 400 : /GOST/i.test(msg) ? 422 : 400;
      writeJson(res, status, { error: msg });
    }
  })
  .listen(port, '0.0.0.0', () => {
    console.log(`mock signing backend listening on http://localhost:${port}`);
    console.log(`endpoints: POST /sign, POST /info, GET /health`);
    console.log(`CORS Origin allow: ${ALLOWED_ORIGIN}`);
  });

// ────────────────────────────────────────────────────────────────────────
// Forge-based parse + CMS sign (RSA only — this is the mock!)

function parseP12(p12Buffer, password) {
  let p12Asn1;
  try {
    p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
  } catch (e) {
    throw new Error(`Invalid PKCS#12: ${e.message}`);
  }

  let p12;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);
  } catch (e) {
    if (/mac|password|decrypt/i.test(e.message)) throw new Error('Wrong password or corrupted PKCS#12 file');
    throw new Error(`Could not open PKCS#12: ${e.message}`);
  }

  let certificate = null;
  let privateKey = null;
  let sawCertBag = false, sawKeyBag = false;
  for (const safeContent of p12.safeContents) {
    for (const bag of safeContent.safeBags) {
      if (bag.type === forge.pki.oids.certBag) {
        sawCertBag = true;
        if (bag.cert) certificate = bag.cert;
      } else if (
        bag.type === forge.pki.oids.pkcs8ShroudedKeyBag ||
        bag.type === forge.pki.oids.keyBag
      ) {
        sawKeyBag = true;
        if (bag.key) privateKey = bag.key;
      }
    }
  }

  if ((sawCertBag && !certificate) || (sawKeyBag && !privateKey)) {
    throw new Error('GOST keys are not supported by the mock backend — use the Kalkan-Java service for those');
  }
  if (!certificate || !privateKey) throw new Error('PKCS#12 missing cert or key');

  return { certificate, privateKey, certInfo: certInfoFromForge(certificate) };
}

function certInfoFromForge(cert) {
  const subj = {};
  for (const a of cert.subject.attributes) {
    if (typeof a.value !== 'string') continue;
    if (a.shortName) subj[a.shortName] = a.value;
    if (a.type) subj[a.type] = a.value;
  }
  const serial = subj.SERIALNUMBER ?? subj['2.5.4.5'] ?? '';
  const ou = subj.OU ?? subj['2.5.4.11'] ?? '';
  const matchKz = (v, prefix) => {
    const m = v?.match(new RegExp(`${prefix}[\\s:=]*?(\\d{12})`, 'i'));
    return m ? m[1] : null;
  };
  const iin = matchKz(serial, 'IIN') ?? matchKz(ou, 'IIN');
  const bin = matchKz(serial, 'BIN') ?? matchKz(ou, 'BIN');
  return {
    bin,
    iin,
    commonName: subj.CN ?? null,
    surname: subj.SN ?? null,
    givenName: subj.GN ?? null,
    organization: subj.O ?? null,
    email: subj.E ?? subj.emailAddress ?? null,
    keyUsage: 'UNKNOWN',
    validFromIso: cert.validity.notBefore.toISOString(),
    validToIso: cert.validity.notAfter.toISOString(),
    serialNumberHex: cert.serialNumber,
    certificatePem: forge.pki.certificateToPem(cert),
  };
}

function signCmsWithForge(certificate, privateKey, doc, { detached, hashAlg }) {
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(doc.toString('binary'), 'raw');
  p7.addCertificate(certificate);
  p7.addSigner({
    key: privateKey,
    certificate,
    digestAlgorithm: oidForHash(hashAlg),
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() },
    ],
  });
  p7.sign({ detached });
  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return Buffer.from(der, 'binary');
}

function oidForHash(h) {
  return ({
    'SHA-256': forge.pki.oids.sha256,
    'SHA-384': forge.pki.oids.sha384,
    'SHA-512': forge.pki.oids.sha512,
  })[h] ?? forge.pki.oids.sha256;
}

function writeJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...corsHeaders() });
  res.end(JSON.stringify(body));
}
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS, GET',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}
function readPort() {
  const i = process.argv.indexOf('--port');
  if (i !== -1 && process.argv[i + 1]) return Number(process.argv[i + 1]);
  return Number(process.env.PORT ?? 7575);
}
