import type { P12Input, CheckBinResult } from './types';
import { parseP12 } from './parse';

/**
 * Verify that a typed BIN (or IIN) matches what's actually inside the user's .p12 certificate.
 *
 * Why this matters: in KZ flows, users often type the BIN of the company they want to sign
 * on behalf of into a form, but the certificate they upload may belong to someone else
 * (wrong file picked, employee using their personal IIN cert instead of the company BIN cert,
 * etc.). This function gives a definitive yes/no.
 *
 * @param p12       The .p12 / .pfx file (File from <input>, or raw bytes)
 * @param password  The password the user entered for the .p12
 * @param typedValue  The 12-digit value the user typed in your form. Non-digits are stripped.
 *                    The function checks against BOTH the cert's BIN and IIN, so callers don't
 *                    need to know upfront which type the user typed.
 */
export async function checkBin(
  p12: P12Input,
  password: string,
  typedValue: string,
): Promise<CheckBinResult> {
  const normalized = (typedValue ?? '').replace(/\D/g, '');
  if (normalized.length !== 12) {
    throw new Error(
      `Typed BIN/IIN must be exactly 12 digits (got ${normalized.length} digit(s) after stripping non-numeric characters)`,
    );
  }

  const { certInfo } = await parseP12(p12, password);

  let match = false;
  let matchedField: 'BIN' | 'IIN' | null = null;

  if (certInfo.bin && certInfo.bin === normalized) {
    match = true;
    matchedField = 'BIN';
  } else if (certInfo.iin && certInfo.iin === normalized) {
    match = true;
    matchedField = 'IIN';
  }

  return {
    match,
    certBin: certInfo.bin,
    certIin: certInfo.iin,
    matchedField,
    certInfo,
  };
}
