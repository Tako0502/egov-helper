/**
 * CLI for @smoker_winston/egov-helper. Shebang added by tsup banner during build.
 *
 * Three commands:
 *   egov-helper sign     --p12 <file> --pwd <pwd> --doc <file> --backend <url> [--out <file>] [--attached]
 *   egov-helper info     --p12 <file> --pwd <pwd> --backend <url>
 *   egov-helper inspect  --sig <base64|file> [--doc <file>]
 *
 * The CLI is published with the package, so consumers can run it with `npx`:
 *   npx @smoker_winston/egov-helper sign --p12 cert.p12 --pwd ... --doc contract.pdf --backend http://localhost:7676
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { signDocument, checkBin, inspectSignature } from '../index.js';
import type { CertInfo } from '../types.js';

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const args: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a?.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      args[key] = true;
    } else {
      args[key] = next;
      i++;
    }
  }
  return args;
}

function usage(): never {
  process.stderr.write(`egov-helper — CLI

Commands:
  sign     Sign a document via the Kalkan backend
  info     Show cert info from a .p12 (BIN/IIN/CN/validity)
  inspect  Decode a CMS signature blob (no backend needed)

Usage:
  egov-helper sign    --p12 <file> --pwd <pwd> --doc <file> --backend <url> [--out <file>] [--attached] [--hash SHA-256|SHA-384|SHA-512]
  egov-helper info    --p12 <file> --pwd <pwd> --backend <url>
  egov-helper inspect --sig <base64|file>  [--doc <file>]

Examples:
  egov-helper sign    --p12 cert.p12 --pwd s3cret --doc contract.pdf --backend http://localhost:7676 --out contract.cms
  egov-helper info    --p12 cert.p12 --pwd s3cret --backend http://localhost:7676
  egov-helper inspect --sig contract.cms --doc contract.pdf
`);
  process.exit(2);
}

function readMaybeFileOrBase64(value: string): Uint8Array {
  const path = resolve(value);
  if (existsSync(path)) {
    return new Uint8Array(readFileSync(path));
  }
  // Try base64 string
  const clean = value.replace(/\s+/g, '');
  return new Uint8Array(Buffer.from(clean, 'base64'));
}

async function cmdSign(args: Record<string, string | boolean>): Promise<void> {
  if (typeof args.p12 !== 'string' || typeof args.pwd !== 'string' || typeof args.doc !== 'string' || typeof args.backend !== 'string') {
    usage();
  }
  const p12 = new Uint8Array(readFileSync(args.p12 as string));
  const doc = new Uint8Array(readFileSync(args.doc as string));
  const detached = args.attached !== true;
  const hashRaw = typeof args.hash === 'string' ? args.hash : 'SHA-256';
  const hash = ['SHA-256', 'SHA-384', 'SHA-512'].includes(hashRaw)
    ? (hashRaw as 'SHA-256' | 'SHA-384' | 'SHA-512')
    : 'SHA-256';

  const result = await signDocument(p12, args.pwd as string, doc, {
    backendUrl: args.backend as string,
    detached,
    hashAlgorithm: hash,
  });

  process.stderr.write(`✓ ${result.signature.length}-byte CMS  ·  signer: ${result.certInfo.commonName ?? '(none)'}  ·  ${result.certInfo.bin ? 'BIN ' + result.certInfo.bin : 'IIN ' + result.certInfo.iin}\n`);

  if (typeof args.out === 'string') {
    writeFileSync(args.out, result.signature);
    process.stderr.write(`  wrote ${args.out}\n`);
  } else {
    process.stdout.write(result.signatureBase64);
    process.stdout.write('\n');
  }
}

async function cmdInfo(args: Record<string, string | boolean>): Promise<void> {
  if (typeof args.p12 !== 'string' || typeof args.pwd !== 'string' || typeof args.backend !== 'string') {
    usage();
  }
  const p12 = new Uint8Array(readFileSync(args.p12 as string));
  // checkBin needs a 12-digit value but we don't care about the comparison here — use a dummy
  // value and just print the cert info.
  const r = await checkBin(p12, args.pwd as string, '000000000000', { backendUrl: args.backend as string });
  printCertInfo(r.certInfo);
}

async function cmdInspect(args: Record<string, string | boolean>): Promise<void> {
  if (typeof args.sig !== 'string') usage();
  const sig = readMaybeFileOrBase64(args.sig as string);
  const opts: { document?: Uint8Array } = {};
  if (typeof args.doc === 'string') {
    opts.document = new Uint8Array(readFileSync(args.doc as string));
  }
  const result = await inspectSignature(sig, opts);

  process.stdout.write(`signers:                   ${result.signers.length}\n`);
  process.stdout.write(`attached:                  ${result.attached}\n`);
  process.stdout.write(`has timestamp:             ${result.hasTimestamp}\n`);
  if (result.documentDigestMatches !== null) {
    process.stdout.write(`document digest matches:   ${result.documentDigestMatches}\n`);
  }
  result.signers.forEach((s, i) => {
    process.stdout.write(`\nsigner ${i + 1}:\n`);
    process.stdout.write(`  hash:                    ${s.hashAlgorithm}\n`);
    process.stdout.write(`  signed at:               ${s.signedAt?.toISOString() ?? '(none)'}\n`);
    process.stdout.write(`  CAdES-BES (V2 attr):     ${s.hasSigningCertificateV2}\n`);
    process.stdout.write(`  signature verifies:      ${s.signatureValid}\n`);
    printCertInfo(s.certInfo, '  ');
  });
}

function printCertInfo(c: CertInfo, prefix = ''): void {
  const lines: Array<[string, string | null]> = [
    ['common name', c.commonName],
    ['BIN', c.bin],
    ['IIN', c.iin],
    ['organization', c.organization],
    ['email', c.email],
    ['key usage', c.keyUsage],
    ['valid from', c.validFrom.toISOString()],
    ['valid to', c.validTo.toISOString()],
    ['serial', c.serialNumberHex],
  ];
  for (const [k, v] of lines) {
    if (v) process.stdout.write(`${prefix}${k.padEnd(24)} ${v}\n`);
  }
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const args = parseArgs(argv.slice(1));
  try {
    switch (cmd) {
      case 'sign':    await cmdSign(args);    break;
      case 'info':    await cmdInfo(args);    break;
      case 'inspect': await cmdInspect(args); break;
      case '-h':
      case '--help':
      case 'help':
      case undefined: usage();
      default:
        process.stderr.write(`Unknown command: ${cmd}\n\n`);
        usage();
    }
  } catch (e) {
    process.stderr.write(`✗ ${(e as Error).message}\n`);
    process.exit(1);
  }
}

main();
