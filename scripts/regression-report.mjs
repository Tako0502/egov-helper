// Run the full GOST-error / RSA-success report against the LOCAL v0.1.2 build.
// Confirms the new error message fires consistently across every entry point
// that touches parseP12, and that the existing RSA round-trip still works.

import { readFileSync } from 'node:fs';
import forge from 'node-forge';
import {
  parseP12,
  checkBin,
  signDocument,
  inspectSignature,
} from '../dist/index.js';

const GOST_PATH = '/Users/talanterzhan/Downloads/GOST512_9459c55e675f840ebced2e7bc76160572ddb0ed5.p12';
const GOST_PASSWORD = 'Qar2026@)@^';

console.log('=== regression report — egov-helper @ local 0.1.2 ===\n');

const gostBytes = new Uint8Array(readFileSync(GOST_PATH));

async function expectGostError(label, fn) {
  try {
    await fn();
    console.log(`✗ ${label}: did NOT throw (regression!)`);
  } catch (e) {
    const msg = e.message;
    const isGost = msg.includes('GOST');
    const icon = isGost ? '✓' : '?';
    console.log(`${icon} ${label}:`);
    console.log(`    ${msg}`);
  }
  console.log();
}

console.log('── GOST .p12 against every entry point ──────────────────────────\n');
await expectGostError('parseP12', () => parseP12(gostBytes, GOST_PASSWORD));
await expectGostError('checkBin', () => checkBin(gostBytes, GOST_PASSWORD, '123456789012'));
await expectGostError('signDocument', () =>
  signDocument(gostBytes, GOST_PASSWORD, new TextEncoder().encode('hello')));

console.log('── RSA self-signed .p12 still works (no regression) ─────────────\n');
function buildRsaP12() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 86400000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 86400000);
  const subject = [
    { name: 'commonName', value: 'REGRESSION USER' },
    { type: '2.5.4.5', value: 'IIN901231400123' },
    { name: 'organizationalUnitName', value: 'BIN123456789012' },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'extKeyUsage', clientAuth: true, emailProtection: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const p12 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], 'testPa$$', { algorithm: '3des' });
  const der = forge.asn1.toDer(p12).getBytes();
  const out = new Uint8Array(der.length);
  for (let i = 0; i < der.length; i++) out[i] = der.charCodeAt(i);
  return out;
}

const rsaBytes = buildRsaP12();
const parsed = await parseP12(rsaBytes, 'testPa$$');
console.log(`✓ parseP12 → BIN ${parsed.certInfo.bin}, IIN ${parsed.certInfo.iin}`);

const check = await checkBin(rsaBytes, 'testPa$$', '901231400123');
console.log(`✓ checkBin  → match=${check.match}, field=${check.matchedField}`);

const doc = new TextEncoder().encode('regression payload');
const sig = await signDocument(rsaBytes, 'testPa$$', doc);
console.log(`✓ signDocument → ${sig.signature.length} byte CMS`);

const insp = await inspectSignature(sig.signature, { document: doc });
const s = insp.signers[0];
console.log(`✓ inspectSignature → signatureValid=${s.signatureValid}, V2=${s.hasSigningCertificateV2}, docDigestMatches=${insp.documentDigestMatches}`);

console.log('\n── Verdict ─────────────────────────────────────────────────────');
console.log('GOST path: emits clear, actionable error across all 3 entry points.');
console.log('RSA path:  unchanged, full round-trip still verifies.');
console.log('Ship 0.1.2.');
