// End-to-end test of the `transport: 'backend'` path. Spins the mock backend up
// in-process, signs a synthetic RSA .p12 through the backend route, and verifies
// the resulting CMS round-trips through inspectSignature.
//
// Run: node scripts/test-backend-transport.mjs

import { spawn } from 'node:child_process';
import forge from 'node-forge';
import { signDocument, inspectSignature } from '../dist/index.js';

const PORT = 7575 + Math.floor(Math.random() * 1000); // dodge collisions

let passed = 0, failed = 0;
const ok = (msg) => { console.log(`  ok   ${msg}`); passed++; };
const fail = (msg, detail) => { console.log(`  FAIL ${msg}${detail ? `\n       ${detail}` : ''}`); failed++; };

console.log('== backend transport e2e ==\n');

console.log(`1. starting mock backend on :${PORT}`);
const server = spawn('node', ['scripts/mock-backend.mjs', '--port', String(PORT)], {
  stdio: ['ignore', 'pipe', 'inherit'],
});

// Wait for the server's startup log line
await new Promise((resolve, reject) => {
  let buf = '';
  const t = setTimeout(() => reject(new Error('server did not announce readiness in 5s')), 5000);
  server.stdout.on('data', (chunk) => {
    buf += chunk.toString();
    if (buf.includes('listening on')) {
      clearTimeout(t);
      resolve();
    }
  });
});
ok('mock backend up');

try {
  // Build a synthetic RSA .p12 (same trick as smoke-test.mjs).
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '02';
  cert.validity.notBefore = new Date(Date.now() - 86400000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 86400000);
  const subject = [
    { name: 'commonName', value: 'BACKEND-E2E USER' },
    { type: '2.5.4.5', value: 'IIN901231400123' },
    { name: 'organizationalUnitName', value: 'BIN555666777888' },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'extKeyUsage', clientAuth: true, emailProtection: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], 'p4ss', { algorithm: '3des' });
  const der = forge.asn1.toDer(p12Asn1).getBytes();
  const p12Bytes = new Uint8Array(der.length);
  for (let i = 0; i < der.length; i++) p12Bytes[i] = der.charCodeAt(i);

  const docBytes = new TextEncoder().encode('this contract was signed via the backend transport');

  console.log('\n2. signDocument with transport=\'backend\'');
  const r = await signDocument(p12Bytes, 'p4ss', docBytes, {
    transport: 'backend',
    backendSignUrl: `http://localhost:${PORT}/`,
  });
  ok(`returned ${r.signature.length} byte CMS`);
  if (r.certInfo.bin !== '555666777888') fail(`certInfo.bin wrong: ${r.certInfo.bin}`);
  else ok('certInfo.bin hydrated correctly from wire');
  if (!(r.signedAt instanceof Date)) fail('signedAt not a Date object');
  else ok('signedAt is a Date instance');

  console.log('\n3. inspectSignature on the result');
  const insp = await inspectSignature(r.signature, { document: docBytes });
  if (insp.signers[0]?.signatureValid) ok('signature value verifies');
  else fail('signature does NOT verify');
  if (insp.documentDigestMatches === true) ok('document digest matches');
  else fail(`documentDigestMatches = ${insp.documentDigestMatches}`);

  console.log('\n4. transport=\'auto\' with RSA — should sign in-browser, NOT call backend');
  // We point at a guaranteed-unreachable URL. If the auto-flow incorrectly routes to backend,
  // it'll throw a fetch error. RSA path should never reach fetch.
  const r2 = await signDocument(p12Bytes, 'p4ss', docBytes, {
    transport: 'auto',
    backendSignUrl: 'http://127.0.0.1:1/this-should-not-be-called',
  });
  ok(`auto+RSA returned ${r2.signature.length} byte CMS without hitting backend`);

  console.log('\n5. transport=\'backend\' propagates server errors');
  try {
    await signDocument(p12Bytes, 'WRONG-PASSWORD', docBytes, {
      transport: 'backend',
      backendSignUrl: `http://localhost:${PORT}/`,
    });
    fail('wrong password did not throw');
  } catch (e) {
    if (/password|PKCS#12/i.test(e.message)) ok('backend error propagated to client');
    else fail(`unexpected error: ${e.message}`);
  }
} finally {
  server.kill();
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
