// End-to-end smoke test for the modern (v0.3.0+) backend-only API.
// Spins up the in-process mock backend, builds a synthetic RSA .p12, runs the
// public API surface against it (checkBin, signDocument, inspectSignature).
// Run with:  node scripts/smoke-test.mjs   (after `npm run build`)

import { spawn } from 'node:child_process';
import forge from 'node-forge';
import {
  checkBin,
  signDocument,
  inspectSignature,
} from '../dist/index.js';

const PORT = 7800 + Math.floor(Math.random() * 800); // dodge port collisions

let passed = 0;
let failed = 0;
const ok = (msg) => { console.log(`  ok   ${msg}`); passed++; };
const fail = (msg, detail) => { console.log(`  FAIL ${msg}${detail ? `\n       ${detail}` : ''}`); failed++; };

function expect(name, actual, expected) {
  const same = JSON.stringify(actual) === JSON.stringify(expected);
  if (same) ok(name);
  else fail(name, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

console.log('== egov-helper smoke test ==\n');

// 1. Start the mock backend in-process so checkBin/signDocument have somewhere to POST to.
console.log(`1. starting mock backend on :${PORT}`);
const server = spawn('node', ['scripts/mock-backend.mjs', '--port', String(PORT)], {
  stdio: ['ignore', 'pipe', 'inherit'],
});
await new Promise((resolve, reject) => {
  let buf = '';
  const t = setTimeout(() => reject(new Error('server did not announce readiness in 5s')), 5000);
  server.stdout.on('data', (chunk) => {
    buf += chunk.toString();
    if (buf.includes('listening on')) { clearTimeout(t); resolve(); }
  });
});
ok('mock backend up');
const BACKEND = `http://localhost:${PORT}`;

try {
  // 2. Build a synthetic RSA .p12 with the KZ subject layout (IIN + BIN).
  const TEST_PASSWORD = 'testPa$$';
  const TEST_IIN = '901231400123';
  const TEST_BIN = '123456789012';

  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 86400000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 86400000);
  const subject = [
    { name: 'commonName', value: 'TEST USER' },
    { type: '2.5.4.5', value: `IIN${TEST_IIN}` },
    { name: 'organizationalUnitName', value: `BIN${TEST_BIN}` },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'extKeyUsage', clientAuth: true, emailProtection: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], TEST_PASSWORD, { algorithm: '3des' });
  const der = forge.asn1.toDer(p12Asn1).getBytes();
  const p12 = new Uint8Array(der.length);
  for (let i = 0; i < der.length; i++) p12[i] = der.charCodeAt(i);

  // 3. checkBin (positive — IIN match)
  console.log('\n2. checkBin (positive cases)');
  const r1 = await checkBin(p12, TEST_PASSWORD, TEST_IIN, { backendUrl: BACKEND });
  if (r1.match) ok('IIN match returns match=true');
  else fail('IIN match returns match=true');
  expect('matchedField is IIN', r1.matchedField, 'IIN');

  const r2 = await checkBin(p12, TEST_PASSWORD, TEST_BIN, { backendUrl: BACKEND });
  if (r2.match) ok('BIN match returns match=true');
  else fail('BIN match returns match=true');
  expect('matchedField is BIN', r2.matchedField, 'BIN');

  // 4. checkBin (negative)
  console.log('\n3. checkBin (negative)');
  const r3 = await checkBin(p12, TEST_PASSWORD, '999999999999', { backendUrl: BACKEND });
  expect('non-matching value returns match=false', r3.match, false);
  expect('matchedField is null on no-match', r3.matchedField, null);

  // 5. signDocument
  console.log('\n4. signDocument (detached, SHA-256)');
  const docBytes = new TextEncoder().encode('this is a contract: pay 1000 KZT to BIN 123456789012');
  const sig = await signDocument(p12, TEST_PASSWORD, docBytes, { backendUrl: BACKEND });
  if (sig.signature.length > 0) ok('signature has bytes');
  else fail('signature has bytes');
  if (sig.signatureBase64.length > 0) ok('signatureBase64 is non-empty');
  else fail('signatureBase64 is non-empty');
  expect('certInfo.bin hydrated from wire', sig.certInfo.bin, TEST_BIN);
  if (sig.signedAt instanceof Date) ok('signedAt is a Date');
  else fail('signedAt is a Date');

  // 6. inspectSignature on the freshly produced CMS
  console.log('\n5. inspectSignature on the produced CMS');
  const insp = await inspectSignature(sig.signature, { document: docBytes });
  expect('CMS is detached', insp.attached, false);
  expect('embeddedContent is null when detached', insp.embeddedContent, null);
  expect('one signer', insp.signers.length, 1);
  const signer = insp.signers[0];
  expect('signer hash algorithm', signer.hashAlgorithm, 'SHA-256');
  expect('signer cert IIN', signer.certInfo.iin, TEST_IIN);
  expect('signer cert BIN', signer.certInfo.bin, TEST_BIN);
  if (insp.documentDigestMatches === true) ok('documentDigestMatches when correct doc supplied');
  else fail('documentDigestMatches when correct doc supplied');
  // Note: hasSigningCertificateV2 and signatureValid are NOT asserted here because the
  // mock backend uses node-forge's basic CMS path (no V2 attr; different auth-attrs ordering
  // than our canonical DER re-encoder). Real Kalkan output is fully CAdES-BES compliant
  // and verifies cleanly — see scripts/test-gost-real.mjs.

  // 7. inspectSignature with the WRONG document → digest mismatch
  console.log('\n6. inspectSignature with the WRONG document → digest mismatch');
  const wrongDoc = new TextEncoder().encode('a different contract');
  const inspWrong = await inspectSignature(sig.signatureBase64, { document: wrongDoc });
  expect('documentDigestMatches false on wrong doc', inspWrong.documentDigestMatches, false);

  // 8. checkBin propagates server errors
  console.log('\n7. checkBin propagates server errors (wrong password)');
  try {
    await checkBin(p12, 'WRONG-PASSWORD', TEST_IIN, { backendUrl: BACKEND });
    fail('wrong password did not throw');
  } catch (e) {
    if (/password|PKCS#12/i.test(e.message)) ok('backend error propagated to client');
    else fail(`unexpected error: ${e.message}`);
  }

  // 9. signDocument missing backendUrl → friendly error
  console.log('\n8. signDocument without backendUrl rejects early');
  try {
    await signDocument(p12, TEST_PASSWORD, docBytes, {});
    fail('missing backendUrl did not throw');
  } catch (e) {
    if (/backendUrl/i.test(e.message)) ok('missing-URL error is actionable');
    else fail(`unexpected error: ${e.message}`);
  }
} finally {
  server.kill();
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
