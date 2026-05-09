// End-to-end smoke test: generate a self-signed RSA cert, bundle into a .p12,
// run signDocument() + inspectSignature() against it, and verify the round-trip.
//
// Run with:  node scripts/smoke-test.mjs   (after `npm run build`)

import forge from 'node-forge';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  parseP12,
  checkBin,
  signDocument,
  inspectSignature,
} from '../dist/index.js';

// Output directory for cross-language validation: the C# test program reads from here.
const TMP = join(process.cwd(), 'tmp');
mkdirSync(TMP, { recursive: true });

let passed = 0;
let failed = 0;

function expect(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) {
    console.log(`  ok   ${name}`);
    passed++;
  } else {
    console.log(`  FAIL ${name}\n       expected: ${JSON.stringify(expected)}\n       actual:   ${JSON.stringify(actual)}`);
    failed++;
  }
}

function expectTrue(name, actual) {
  if (actual === true) {
    console.log(`  ok   ${name}`);
    passed++;
  } else {
    console.log(`  FAIL ${name}\n       expected: true\n       actual:   ${JSON.stringify(actual)}`);
    failed++;
  }
}

function buildTestP12(opts) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 86400000);
  cert.validity.notAfter = new Date(Date.now() + 365 * 86400000);

  const subject = [
    { name: 'commonName', value: opts.commonName },
    // OID 2.5.4.5 = serialNumber attribute. node-forge doesn't expose 'SERIALNUMBER'
    // as a shortName, so use the OID directly.
    { type: '2.5.4.5', value: `IIN${opts.iin}` },
  ];
  if (opts.bin) subject.push({ name: 'organizationalUnitName', value: `BIN${opts.bin}` });
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'extKeyUsage', clientAuth: true, emailProtection: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [cert], opts.password, {
    algorithm: '3des',
  });
  const der = forge.asn1.toDer(p12Asn1).getBytes();
  const bytes = new Uint8Array(der.length);
  for (let i = 0; i < der.length; i++) bytes[i] = der.charCodeAt(i);
  return bytes;
}

console.log('== egov-helper smoke test ==\n');

// Build a fake "AUTH_RSA"-style cert
const TEST_PASSWORD = 'testPa$$';
const TEST_IIN = '901231400123';
const TEST_BIN = '123456789012';
const p12 = buildTestP12({
  password: TEST_PASSWORD,
  commonName: 'TEST USER',
  iin: TEST_IIN,
  bin: TEST_BIN,
});

console.log('1. parseP12');
const parsed = await parseP12(p12, TEST_PASSWORD);
expect('cert IIN extracted', parsed.certInfo.iin, TEST_IIN);
expect('cert BIN extracted', parsed.certInfo.bin, TEST_BIN);
expect('cert CN extracted', parsed.certInfo.commonName, 'TEST USER');

console.log('\n2. checkBin (positive cases)');
const r1 = await checkBin(p12, TEST_PASSWORD, TEST_IIN);
expectTrue('IIN match returns match=true', r1.match);
expect('matchedField is IIN', r1.matchedField, 'IIN');

const r2 = await checkBin(p12, TEST_PASSWORD, TEST_BIN);
expectTrue('BIN match returns match=true', r2.match);
expect('matchedField is BIN', r2.matchedField, 'BIN');

console.log('\n3. checkBin (negative)');
const r3 = await checkBin(p12, TEST_PASSWORD, '999999999999');
expect('non-matching value returns match=false', r3.match, false);
expect('matchedField is null on no-match', r3.matchedField, null);

console.log('\n4. signDocument (detached, SHA-256)');
const docBytes = new TextEncoder().encode('this is a contract: pay 1000 KZT to BIN 123456789012');
const sig = await signDocument(p12, TEST_PASSWORD, docBytes);
expectTrue('signature has bytes', sig.signature.length > 0);
expectTrue('signatureBase64 is non-empty', sig.signatureBase64.length > 0);
expect('detached flag', sig.detached, true);

console.log('\n5. inspectSignature on the freshly produced CMS');
const insp = await inspectSignature(sig.signature, { document: docBytes });
expect('CMS is detached', insp.attached, false);
expect('embeddedContent is null when detached', insp.embeddedContent, null);
expect('one signer', insp.signers.length, 1);
const signer = insp.signers[0];
expect('signer hash algorithm', signer.hashAlgorithm, 'SHA-256');
expect('signer cert IIN', signer.certInfo.iin, TEST_IIN);
expect('signer cert BIN', signer.certInfo.bin, TEST_BIN);
expectTrue('signingCertificateV2 (CAdES-BES) attribute present', signer.hasSigningCertificateV2);
expectTrue('signer signature value verifies', signer.signatureValid);
expect('hasTimestamp false (not yet timestamped)', insp.hasTimestamp, false);
expectTrue('documentDigestMatches when correct doc supplied', insp.documentDigestMatches);

console.log('\n6. inspectSignature with the WRONG document → digest mismatch');
const wrongDoc = new TextEncoder().encode('a different contract');
const inspWrong = await inspectSignature(sig.signatureBase64, { document: wrongDoc });
expect('documentDigestMatches false on wrong doc', inspWrong.documentDigestMatches, false);
expectTrue('signature still verifies (signed attrs intact)', inspWrong.signers[0].signatureValid);

console.log('\n7. signDocument (attached)');
const sigAtt = await signDocument(p12, TEST_PASSWORD, docBytes, { detached: false });
const inspAtt = await inspectSignature(sigAtt.signature);
expect('attached flag round-trips', inspAtt.attached, true);
expectTrue('embeddedContent present in attached', inspAtt.embeddedContent !== null && inspAtt.embeddedContent.length === docBytes.length);

console.log('\n8. inspectSignature accepts base64 string input');
const inspB64 = await inspectSignature(sig.signatureBase64);
expectTrue('base64 input parses to one signer', inspB64.signers.length === 1);

console.log('\n9. Writing artifacts to ./tmp/ for the C# cross-validation test');
writeFileSync(join(TMP, 'doc.bin'), docBytes);
writeFileSync(join(TMP, 'sig-detached.cms'), sig.signature);
writeFileSync(join(TMP, 'sig-attached.cms'), sigAtt.signature);
writeFileSync(
  join(TMP, 'expected.json'),
  JSON.stringify(
    {
      iin: TEST_IIN,
      bin: TEST_BIN,
      commonName: 'TEST USER',
      hashAlgorithm: 'SHA-256',
      signedAt: sig.signedAt.toISOString(),
    },
    null,
    2,
  ),
);
console.log('  ok   wrote tmp/doc.bin, tmp/sig-detached.cms, tmp/sig-attached.cms, tmp/expected.json');
console.log('       run: dotnet run --project packages/dotnet/EgovHelper.Net.Tests');

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
