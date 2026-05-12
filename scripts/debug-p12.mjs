// Dump the internal structure of a .p12 file. Use this when the library says
// "No certificate found" against a key that you know is valid — the output
// shows exactly which encryption algorithms and bag types are present so we
// can patch the parser.
//
// Usage:
//   node scripts/debug-p12.mjs <path-to.p12> <password>
//
// The .p12 and password stay on your machine — this script does not phone home.

import forge from 'node-forge';
import { readFileSync } from 'node:fs';

const [, , p12Path, password] = process.argv;
if (!p12Path || password === undefined) {
  console.error('Usage: node scripts/debug-p12.mjs <p12-path> <password>');
  process.exit(2);
}

const bytes = readFileSync(p12Path);
const binary = bytes.toString('binary');
const asn1 = forge.asn1;

// Decode the outer PFX manually so we can see every ContentInfo type and
// every encryption algorithm before forge transparently decrypts things.
let outer;
try {
  outer = asn1.fromDer(binary);
} catch (e) {
  console.error('Outer ASN.1 parse failed:', e.message);
  process.exit(1);
}

console.log('=== Outer PFX ===');
console.log('version:', (outer.value?.[0]?.value ?? '').charCodeAt?.(0) ?? '?');
console.log('authSafe content type:', oidOf(outer.value?.[1]?.value?.[0]));

// authSafe is a ContentInfo wrapping an OCTET STRING which itself is the
// DER of a SEQUENCE OF ContentInfo (the AuthenticatedSafe).
const authSafeContent = outer.value?.[1]?.value?.[1]?.value?.[0];
const authSafeBytes = typeof authSafeContent?.value === 'string'
  ? authSafeContent.value
  : null;

if (!authSafeBytes) {
  console.error('Could not locate AuthenticatedSafe inner bytes — file may be unusual.');
  process.exit(1);
}

let authSafe;
try {
  authSafe = asn1.fromDer(authSafeBytes);
} catch (e) {
  console.error('AuthenticatedSafe ASN.1 parse failed:', e.message);
  process.exit(1);
}

console.log(`\n=== AuthenticatedSafe (${authSafe.value.length} ContentInfo(s)) ===`);
for (let i = 0; i < authSafe.value.length; i++) {
  const ci = authSafe.value[i];
  const ctOid = oidOf(ci.value?.[0]);
  console.log(`\n  [${i}] contentType = ${ctOid}  (${nameForOid(ctOid)})`);

  if (ctOid === '1.2.840.113549.1.7.1') {
    // Data — unencrypted
    const inner = ci.value?.[1]?.value?.[0];
    const safeBytes = typeof inner?.value === 'string' ? inner.value : null;
    if (safeBytes) describeSafeContents(safeBytes, '      ');
  } else if (ctOid === '1.2.840.113549.1.7.6') {
    // EncryptedData
    const ed = ci.value?.[1]?.value?.[0];
    // EncryptedData ::= SEQUENCE { version, EncryptedContentInfo }
    // EncryptedContentInfo ::= SEQUENCE { contentType, algorithm, [0] encryptedContent }
    const eci = ed?.value?.[1];
    const algSeq = eci?.value?.[1];
    const algOid = oidOf(algSeq?.value?.[0]);
    console.log(`      EncryptedContentInfo algorithm = ${algOid}  (${nameForOid(algOid)})`);
    if (algOid === '1.2.840.113549.1.5.13') {
      // PBES2
      const pbes2Params = algSeq?.value?.[1];
      const kdfAlg = pbes2Params?.value?.[0];
      const encAlg = pbes2Params?.value?.[1];
      const kdfOid = oidOf(kdfAlg?.value?.[0]);
      const encOid = oidOf(encAlg?.value?.[0]);
      console.log(`        KDF = ${kdfOid}  (${nameForOid(kdfOid)})`);
      console.log(`        ENC = ${encOid}  (${nameForOid(encOid)})`);
      if (kdfOid === '1.2.840.113549.1.5.12') {
        // PBKDF2 params
        const kdfParams = kdfAlg?.value?.[1];
        const prfAlg = kdfParams?.value?.[3];
        if (prfAlg) {
          const prfOid = oidOf(prfAlg?.value?.[0]);
          console.log(`        PRF = ${prfOid}  (${nameForOid(prfOid)})`);
        } else {
          console.log('        PRF = (default: hmacWithSHA1)');
        }
      }
    }

    // Try to decrypt with forge's pkcs7.messageFromAsn1 / direct decrypt
    try {
      const decryptedBytes = tryDecryptForge(ci, password);
      if (decryptedBytes) {
        console.log('      ✓ forge decryption succeeded — inner bags:');
        describeSafeContents(decryptedBytes, '        ');
      } else {
        console.log('      ✗ forge cannot decrypt this content (likely the smoking gun)');
      }
    } catch (e) {
      console.log('      ✗ forge decryption threw:', e.message);
    }
  } else {
    console.log('      (unhandled content type — dump skipped)');
  }
}

// Finally, run the high-level forge parser and see what it finds.
console.log('\n=== forge.pkcs12.pkcs12FromAsn1() result ===');
let p12;
try {
  p12 = forge.pkcs12.pkcs12FromAsn1(asn1.fromDer(binary), false, password);
} catch (e) {
  console.log('  threw:', e.message);
  process.exit(0);
}
console.log(`  safeContents.length = ${p12.safeContents.length}`);
let totalCerts = 0, totalKeys = 0, totalOther = 0;
for (let i = 0; i < p12.safeContents.length; i++) {
  const sc = p12.safeContents[i];
  console.log(`  [${i}] safeBags = ${sc.safeBags.length}`);
  for (const bag of sc.safeBags) {
    const t = bag.type;
    if (t === forge.pki.oids.certBag) totalCerts++;
    else if (t === forge.pki.oids.pkcs8ShroudedKeyBag || t === forge.pki.oids.keyBag) totalKeys++;
    else totalOther++;
    console.log(`        bag.type = ${t}  (${nameForOid(t)}) — has cert: ${!!bag.cert}, has key: ${!!bag.key}`);
  }
}
console.log(`\nTotals: ${totalCerts} cert bag(s), ${totalKeys} key bag(s), ${totalOther} other.`);
if (totalCerts === 0) {
  console.log('\n→ This is the bug. The cert bag isn\'t reaching us through forge.pkcs12FromAsn1.');
  console.log('  The EncryptedContentInfo algorithm above tells us what to support.');
}

// ─────────────────────────────────────────────────────────────────────────

function oidOf(node) {
  if (!node || typeof node.value !== 'string') return '(?)';
  try { return asn1.derToOid(node.value); } catch { return '(parse-fail)'; }
}

function describeSafeContents(bytes, prefix) {
  let scAsn1;
  try { scAsn1 = asn1.fromDer(bytes); }
  catch (e) { console.log(`${prefix}(safeContents asn1 parse failed: ${e.message})`); return; }
  if (!Array.isArray(scAsn1.value)) return;
  console.log(`${prefix}SafeContents has ${scAsn1.value.length} SafeBag(s):`);
  for (let i = 0; i < scAsn1.value.length; i++) {
    const bag = scAsn1.value[i];
    const bagOid = oidOf(bag?.value?.[0]);
    console.log(`${prefix}  [${i}] bagId = ${bagOid}  (${nameForOid(bagOid)})`);
  }
}

function tryDecryptForge(contentInfo, pass) {
  try {
    // Reach into forge's private helper if available, else replicate via PBES decrypt.
    const ed = contentInfo.value?.[1]?.value?.[0];
    const eci = ed?.value?.[1];
    const algSeq = eci?.value?.[1];
    const encBytes = eci?.value?.[2]?.value;
    if (typeof encBytes !== 'string') return null;
    const decrypted = forge.pkcs12.pkcs12FromAsn1 // ensure forge is loaded
      ? forge.pkcs5
        ? null
        : null
      : null;
    // Use the documented forge approach: pkcs7.decrypt path requires a full
    // message — for safeContents we use the lower-level _pbe routines.
    // forge.pki.pbe.getCipher is the right primitive but it's internal.
    const cipherFn = forge.pki.pbe?.getCipher
      ? forge.pki.pbe.getCipher
      : null;
    if (!cipherFn) return null;
    const cipher = cipherFn(forge.asn1.toDer(algSeq).getBytes(), pass);
    cipher.update(forge.util.createBuffer(encBytes));
    if (!cipher.finish()) return null;
    return cipher.output.getBytes();
  } catch {
    return null;
  }
}

function nameForOid(oid) {
  return {
    '1.2.840.113549.1.7.1': 'data',
    '1.2.840.113549.1.7.6': 'encryptedData',
    '1.2.840.113549.1.7.2': 'signedData',
    '1.2.840.113549.1.12.10.1.1': 'keyBag',
    '1.2.840.113549.1.12.10.1.2': 'pkcs8ShroudedKeyBag',
    '1.2.840.113549.1.12.10.1.3': 'certBag',
    '1.2.840.113549.1.12.10.1.4': 'crlBag',
    '1.2.840.113549.1.12.10.1.5': 'secretBag',
    '1.2.840.113549.1.12.10.1.6': 'safeContentsBag',
    '1.2.840.113549.1.12.1.1': 'pbeWithSHAAnd128BitRC4',
    '1.2.840.113549.1.12.1.2': 'pbeWithSHAAnd40BitRC4',
    '1.2.840.113549.1.12.1.3': 'pbeWithSHAAnd3-KeyTripleDES-CBC',
    '1.2.840.113549.1.12.1.4': 'pbeWithSHAAnd2-KeyTripleDES-CBC',
    '1.2.840.113549.1.12.1.5': 'pbeWithSHAAnd128BitRC2-CBC',
    '1.2.840.113549.1.12.1.6': 'pbeWithSHAAnd40BitRC2-CBC',
    '1.2.840.113549.1.5.13': 'PBES2',
    '1.2.840.113549.1.5.12': 'PBKDF2',
    '1.2.840.113549.2.7': 'hmacWithSHA1',
    '1.2.840.113549.2.8': 'hmacWithSHA224',
    '1.2.840.113549.2.9': 'hmacWithSHA256',
    '1.2.840.113549.2.10': 'hmacWithSHA384',
    '1.2.840.113549.2.11': 'hmacWithSHA512',
    '2.16.840.1.101.3.4.1.2': 'aes128-CBC',
    '2.16.840.1.101.3.4.1.22': 'aes192-CBC',
    '2.16.840.1.101.3.4.1.42': 'aes256-CBC',
    '1.2.840.113549.1.1.1': 'rsaEncryption',
  }[oid] ?? '?';
}
