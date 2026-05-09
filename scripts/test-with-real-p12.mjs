// Validate egov-helper against a REAL NUC RK certificate from your egov.kz key bundle.
//
// Usage:
//   node scripts/test-with-real-p12.mjs <path-to-your-p12> <password> <expected-bin-or-iin>
//
// Example:
//   node scripts/test-with-real-p12.mjs ~/Downloads/AUTH_RSA256_xxxx.p12 'MyPassword' 123456789012
//
// What it checks:
//   1. The .p12 parses, BIN/IIN/CN are extracted correctly.
//   2. checkBin() recognises the BIN/IIN you supplied.
//   3. signDocument() produces a CMS that inspectSignature() can decode and verify.
//   4. The document-digest match works.
//   5. The .NET cross-validator can verify the same signature.
//
// The .p12, password, and any signed output stay on YOUR machine.
// Nothing is sent over the network.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  parseP12,
  checkBin,
  signDocument,
  inspectSignature,
} from '../dist/index.js';

const [, , p12Path, password, typedBin] = process.argv;

if (!p12Path || password === undefined || !typedBin) {
  console.error('Usage: node scripts/test-with-real-p12.mjs <p12-path> <password> <expected-bin-or-iin>');
  process.exit(2);
}

const p12Bytes = new Uint8Array(readFileSync(resolve(p12Path)));
const repoRoot = process.cwd();
const tmp = join(repoRoot, 'tmp');
mkdirSync(tmp, { recursive: true });

console.log('== egov-helper · real .p12 validation ==');
console.log(`file:       ${p12Path}`);
console.log(`expected:   ${typedBin}\n`);

let passed = 0, failed = 0;
const ok = (msg) => { console.log(`  ok   ${msg}`); passed++; };
const fail = (msg, detail) => { console.log(`  FAIL ${msg}${detail ? `\n       ${detail}` : ''}`); failed++; };

console.log('1. parseP12');
let parsedCertInfo;
try {
  const parsed = await parseP12(p12Bytes, password);
  parsedCertInfo = parsed.certInfo;
  console.log(`     CN:         ${parsedCertInfo.commonName ?? '(none)'}`);
  console.log(`     BIN:        ${parsedCertInfo.bin ?? '(none)'}`);
  console.log(`     IIN:        ${parsedCertInfo.iin ?? '(none)'}`);
  console.log(`     org:        ${parsedCertInfo.organization ?? '(none)'}`);
  console.log(`     valid:      ${parsedCertInfo.validFrom.toISOString()} → ${parsedCertInfo.validTo.toISOString()}`);
  console.log(`     keyUsage:   ${parsedCertInfo.keyUsage}`);
  ok('parsed without error');
  if (!parsedCertInfo.bin && !parsedCertInfo.iin) {
    fail('no BIN or IIN extracted — cert subject layout might be unusual', JSON.stringify(parsedCertInfo, null, 2));
  }
} catch (e) {
  fail('parseP12 threw', e.message);
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(1);
}

console.log('\n2. checkBin');
try {
  const r = await checkBin(p12Bytes, password, typedBin);
  if (r.match) ok(`matched ${r.matchedField}`);
  else fail(`no match — cert BIN=${r.certBin}, IIN=${r.certIin}`);
} catch (e) {
  fail('checkBin threw', e.message);
}

console.log('\n3. signDocument + inspectSignature round-trip');
const docBytes = new TextEncoder().encode(`Test contract signed at ${new Date().toISOString()}`);
let sig;
try {
  sig = await signDocument(p12Bytes, password, docBytes);
  ok(`produced ${sig.signature.length}-byte CMS`);
} catch (e) {
  fail('signDocument threw', e.message);
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(1);
}

try {
  const insp = await inspectSignature(sig.signature, { document: docBytes });
  if (insp.signers.length !== 1) fail(`expected 1 signer, got ${insp.signers.length}`);
  else {
    const s = insp.signers[0];
    if (s.signatureValid) ok('signer signature value verifies against embedded cert');
    else fail('signature does NOT verify');
    if (s.hasSigningCertificateV2) ok('signingCertificateV2 (CAdES-BES) present');
    else fail('signingCertificateV2 missing');
    if (insp.documentDigestMatches === true) ok('document digest matches');
    else fail(`document digest does not match (${insp.documentDigestMatches})`);
    if (s.certInfo.bin === parsedCertInfo?.bin) ok('inspected BIN matches parsed BIN');
  }
} catch (e) {
  fail('inspectSignature threw', e.message);
}

console.log('\n4. Writing artifacts to ./tmp/ for the .NET cross-validator');
writeFileSync(join(tmp, 'doc.bin'), docBytes);
writeFileSync(join(tmp, 'sig-detached.cms'), sig.signature);
const sigAtt = await signDocument(p12Bytes, password, docBytes, { detached: false });
writeFileSync(join(tmp, 'sig-attached.cms'), sigAtt.signature);
writeFileSync(join(tmp, 'expected.json'), JSON.stringify({
  iin: parsedCertInfo.iin,
  bin: parsedCertInfo.bin,
  commonName: parsedCertInfo.commonName,
  hashAlgorithm: 'SHA-256',
  signedAt: sig.signedAt.toISOString(),
}, null, 2));
ok('wrote tmp/doc.bin, tmp/sig-detached.cms, tmp/sig-attached.cms, tmp/expected.json');

console.log('\nNext step: cross-validate with .NET');
console.log('   dotnet run --project packages/dotnet/EgovHelper.Net.Tests');
console.log('\nIf both this script and the .NET tests pass, your sign/inspect round-trip works');
console.log('against your real key. Chain validation against NUC RK roots is exercised separately;');
console.log('see EgovTrustRoots in the .NET package.\n');

console.log(`${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
