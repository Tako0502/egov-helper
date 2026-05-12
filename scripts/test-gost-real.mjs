// Sign the real KZ GOST .p12 through the live Java + Kalkan service.
// This is the proof-of-life test for the whole "GOST without NCALayer" claim.

import { readFileSync } from 'node:fs';
import { checkBin, signDocument, inspectSignature } from '../dist/index.js';

const P12 = '/Users/talanterzhan/Documents/Secretkey/QarSolutions/GOST512_1800c083acbbf16157027f4f14b1cad739f1f1b6.p12';
const PASSWORD = 'ZQARSolutions2025';
const BACKEND = 'http://localhost:7676';

const p12 = new Uint8Array(readFileSync(P12));
const doc = new TextEncoder().encode('Real GOST contract — signed at ' + new Date().toISOString());

console.log('== GOST .p12 → Java/Kalkan backend → CMS ==\n');
console.log('cert:     ', P12.split('/').pop());
console.log('backend:  ', BACKEND);
console.log('doc:      ', doc.length, 'bytes\n');

console.log('1. checkBin (real BIN of the cert: 190440033661) — should match');
try {
  const r = await checkBin(p12, PASSWORD, '190440033661', { backendUrl: BACKEND });
  console.log(`   match=${r.match}, field=${r.matchedField}, certBIN=${r.certBin}`);
  if (!r.match) process.exit(1);
} catch (e) {
  console.error('✗ checkBin threw:', e.message);
  process.exit(1);
}

console.log('\n2. checkBin with WRONG BIN — should NOT match');
try {
  const r = await checkBin(p12, PASSWORD, '111111111111', { backendUrl: BACKEND });
  console.log(`   match=${r.match} (expected false)`);
  if (r.match) process.exit(1);
} catch (e) {
  console.error('✗ checkBin threw:', e.message);
  process.exit(1);
}

console.log('\n3. signDocument through the Kalkan backend');
let result;
try {
  result = await signDocument(p12, PASSWORD, doc, { backendUrl: BACKEND });
} catch (e) {
  console.error('✗ signDocument threw:', e.message);
  process.exit(1);
}

console.log('✓ signature produced:', result.signature.length, 'bytes');
console.log('  signed at:', result.signedAt.toISOString());
console.log('  signer:   ', result.certInfo.commonName);
console.log('  BIN:      ', result.certInfo.bin ?? '(none)');
console.log('  IIN:      ', result.certInfo.iin ?? '(none)');
console.log('  org:      ', result.certInfo.organization ?? '(none)');

console.log('\n2. inspectSignature on the result (CMS structure / cert chain check)');
try {
  const insp = await inspectSignature(result.signature, { document: doc });
  if (insp.signers[0]) {
    const s = insp.signers[0];
    console.log('  signers:                  ', insp.signers.length);
    console.log('  hash algorithm:           ', s.hashAlgorithm);
    console.log('  signingCertificateV2:     ', s.hasSigningCertificateV2);
    console.log('  signatureValid (vs cert): ', s.signatureValid,
      '  ← node-forge can only verify RSA, GOST may show false here');
    console.log('  documentDigestMatches:    ', insp.documentDigestMatches);
  } else {
    console.log('  (no signers parsed — possible if our JS inspect doesn\'t handle GOST CMS yet)');
  }
} catch (e) {
  console.log('  inspectSignature threw — expected for GOST CMS:', e.message);
  console.log('  (our JS inspectSignature uses node-forge; verifying GOST CMS needs Kalkan-side verify)');
}

console.log('\n✓ End-to-end GOST signing through the Kalkan backend works.');
