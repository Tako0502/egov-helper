/**
 * @smoker_winston/egov-helper
 *
 * Browser-side helper for Kazakhstan e-Gov digital signatures, without NCALayer.
 *
 *   1. checkBin(p12, password, typedBin)
 *      → does the BIN/IIN the user typed match the one inside their certificate?
 *
 *   2. signDocument(p12, password, contentBytes, options?)
 *      → produce a CAdES-BES (CMS / PKCS#7 SignedData) blob with signingCertificateV2 (RFC 5035)
 *
 *   3. inspectSignature(base64OrBytes, options?)
 *      → decode a CMS signature blob and return everything inside it (signer cert, signed time,
 *        hash algorithm, signature validity, timestamp presence, …)
 *
 *   4. addTimestamp(signature, { tsaUrl })
 *      → upgrade a CAdES-BES signature to CAdES-T by round-tripping through an RFC 3161 TSA
 *        and embedding the resulting TimeStampToken as an unsigned attribute. (Run on backend
 *        unless your TSA sets CORS.)
 *
 * The private key from a .p12 file never leaves the JS runtime that calls these functions.
 *
 * GOST R 34.10 keys are not supported (the library targets RSA only). When a GOST key is
 * detected, parseP12() throws with a clear message pointing to RSA reissuance or NCALayer.
 */

export { checkBin } from './bin';
export { signDocument } from './sign';
export { inspectSignature } from './inspect';
export { addTimestamp } from './timestamp';
export { parseP12, extractCertInfo } from './parse';

export type {
  P12Input,
  CertInfo,
  CheckBinResult,
  CheckBinOptions,
  BackendOptions,
  SignOptions,
  SignResult,
  SignerInspection,
  SignatureInspection,
  InspectOptions,
  TimestampOptions,
} from './types';
