/**
 * Accepted forms for a PKCS#12 (.p12 / .pfx) file.
 * - File: from a browser <input type="file">
 * - ArrayBuffer / Uint8Array: from fetch(), Blob.arrayBuffer(), Node fs.readFile, etc.
 */
export type P12Input = File | ArrayBuffer | Uint8Array;

/**
 * What was extracted from the certificate inside a NUC RK .p12 file.
 *
 * KZ certificates put the BIN/IIN in either:
 *   - subject SERIALNUMBER (OID 2.5.4.5), e.g. "IIN123456789012"
 *   - subject OU (OID 2.5.4.11), e.g. "BIN123456789012"
 *
 * Natural-person certs (AUTH_RSA / RSA personal) carry an IIN.
 * Legal-entity certs (organization certs) carry a BIN (and usually also an IIN of the responsible person).
 */
export interface CertInfo {
  /** 12-digit BIN of the legal entity, or null if not present */
  bin: string | null;
  /** 12-digit IIN of the natural person, or null if not present */
  iin: string | null;
  /** Common Name (CN) — usually the owner's full name in cyrillic */
  commonName: string | null;
  /** Surname (SN / OID 2.5.4.4) */
  surname: string | null;
  /** Given name (GN / OID 2.5.4.42) */
  givenName: string | null;
  /** Organization (O) — present on legal-entity certs */
  organization: string | null;
  /** Email address embedded in the subject, if any */
  email: string | null;
  /** Best-effort detection: "AUTH" (authentication-only) or "SIGN" (document-signing) cert */
  keyUsage: 'AUTH' | 'SIGN' | 'UNKNOWN';
  /** Certificate validity start */
  validFrom: Date;
  /** Certificate validity end */
  validTo: Date;
  /** Certificate serial number (the cert's own serial, not the BIN/IIN) as a hex string */
  serialNumberHex: string;
  /** PEM-encoded certificate, useful for sending to a backend for verification */
  certificatePem: string;
}

export interface CheckBinResult {
  /** True if the typed value matches either the certificate's BIN or IIN */
  match: boolean;
  /** BIN extracted from the certificate, or null */
  certBin: string | null;
  /** IIN extracted from the certificate, or null */
  certIin: string | null;
  /** Which field the typed value matched against, or null if no match */
  matchedField: 'BIN' | 'IIN' | null;
  /** Full info about the certificate so callers can show owner name, organization, expiry, etc. */
  certInfo: CertInfo;
}

/**
 * Common options every backend-routed call needs.
 *
 * The library always routes `.p12` operations through your Kalkan-backed Java service
 * (the one in `packages/java/egov-helper-signer/`). Set `backendUrl` to the base URL of
 * that service — the library appends `/sign` for signing and `/info` for cert lookups.
 */
export interface BackendOptions {
  /**
   * Base URL of the Kalkan-backed signing service.
   * Examples:
   *   - 'http://localhost:7676'              (local dev)
   *   - 'https://api.example.kz/egov'        (production behind a TLS terminator)
   *
   * The library POSTs to `${backendUrl}/sign` and `${backendUrl}/info`.
   */
  backendUrl: string;
  /**
   * Extra fetch options (custom headers, AbortSignal, credentials mode, etc.) passed
   * through to the backend POST.
   */
  fetchInit?: RequestInit;
}

export interface SignOptions extends BackendOptions {
  /**
   * If true (default), produces a detached signature: the document content is NOT embedded
   * in the signature. The verifier must be given both the original document and the signature.
   *
   * If false, produces an attached signature: the document content is embedded inside the
   * CMS structure. The verifier needs only the signature blob.
   */
  detached?: boolean;
  /**
   * Hash algorithm. Default: SHA-256. For GOST keys the backend ignores this and uses the
   * algorithm mandated by the key's curve (Stribog-256 / Stribog-512).
   */
  hashAlgorithm?: 'SHA-256' | 'SHA-384' | 'SHA-512';
}

export interface CheckBinOptions extends BackendOptions {}

/**
 * Options for `checkBinViaQr` — the no-.p12 BIN-check flow. Combines the SIGEX QR-signing
 * pieces (`onQrReady`, `description`, etc.) with the `backendUrl` of your Kalkan signer
 * (used to extract the cert from the resulting CMS).
 */
export interface CheckBinViaQrOptions extends BackendOptions {
  /** Override what eGov Mobile shows the user. Default: 'BIN verification'. */
  description?: string;
  /** SIGEX hub. Default: 'https://sigex.kz'. */
  sigexHub?: string;
  /** Called as soon as the QR + deeplinks are ready — render the QR or redirect. */
  onQrReady?: (qr: QrInfo) => void;
  /** Called once eGov Mobile has fetched the signing data from SIGEX. */
  onDataSent?: () => void;
  /** Called for each transient polling error (for debugging only). */
  onPollError?: (err: Error) => void;
  /** Replace the SIGEX logo in the center of the QR with your own. See `QrLogoOptions`. */
  logo?: QrLogoOptions;
}

/**
 * Overlay a custom logo on top of the SIGEX-rendered QR code. We paint your image over
 * the center of the QR (covering SIGEX's logo). QR error correction (Reed-Solomon) makes
 * this safe — the payload is unchanged, eGov Mobile still scans it.
 *
 * Keep `size` ≤ 0.25 to stay within the recoverable-area budget of the SIGEX QR.
 */
export interface QrLogoOptions {
  /**
   * The logo to draw. Either a URL/data-URL string, or a preloaded `HTMLImageElement`.
   * If you already have the logo loaded (e.g. an imported asset), passing the element
   * avoids a re-fetch.
   */
  src: string | HTMLImageElement;
  /**
   * Logo size as a fraction of the QR width. Default: `0.22` (matches SIGEX's own logo size).
   * Anything above ~0.3 starts to corrupt the QR — keep it small.
   */
  size?: number;
  /**
   * Background colour drawn behind the logo, to mask SIGEX's logo underneath.
   * Default: `'#ffffff'`. Set to `'transparent'` to skip the mask (your logo must then
   * fully cover SIGEX's, or the result will look messy).
   */
  background?: string;
  /** Padding (in px) between the background box and the logo image. Default: `6`. */
  padding?: number;
  /** Corner radius (in px) of the background box. Default: `0` (square). */
  borderRadius?: number;
  /**
   * `crossOrigin` to set on the `Image` element used to load `src` when it's a string URL.
   * Default: `'anonymous'`. Set to `null` to skip — but then the canvas may become tainted
   * and `toDataURL()` will throw.
   */
  crossOrigin?: 'anonymous' | 'use-credentials' | null;
}

/**
 * Info about the QR/deeplink rendered by signDocumentViaQr(). Pass this to your UI:
 * desktop renders the QR; mobile redirects to the deeplink.
 */
export interface QrInfo {
  /** Base64 PNG data URL, usable directly as `<img src={...}>`. */
  qrCodeDataUrl: string;
  /** Deeplink that opens eGov Mobile to start signing. Use `window.location.href = link` on phones. */
  eGovMobileLink: string;
  /** Deeplink for the eGov Business app (alternative). */
  eGovBusinessLink: string;
  /** When SIGEX will time out the request, or null if not reported by the hub. */
  expiresAt: Date | null;
}

export interface QrSignOptions {
  /** SIGEX hub base URL. Default: `https://sigex.kz`. */
  sigexHub?: string;
  /** Description shown to the user inside eGov Mobile. Default: a generic one. */
  description?: string;
  /** Document name (shown in the eGov Mobile signing dialog). Default: `'document'`. */
  documentName?: string;
  /**
   * Localised document names as [ru, kk, en]. Overrides `documentName` if provided.
   * If you only know the document name in one language, pass the same string three times.
   */
  documentNames?: string[];
  /** If true, embed the document inside the CMS. Default: false (detached). */
  attached?: boolean;
  /**
   * If true, eGov Mobile shows a PDF preview before the user signs. Only set true if
   * the document is actually a PDF — otherwise the preview will be junk.
   */
  isPdf?: boolean;
  /** Called as soon as the QR + deeplinks are ready. Render the QR or redirect. */
  onQrReady?: (qr: QrInfo) => void;
  /** Called when SIGEX confirms eGov Mobile has fetched the data (between scan and sign). */
  onDataSent?: () => void;
  /** Called for each transient polling error (debugging). */
  onPollError?: (err: Error) => void;
  /** Replace the SIGEX logo in the center of the QR with your own. See `QrLogoOptions`. */
  logo?: QrLogoOptions;
}

export interface QrSignResult {
  /** CMS / PKCS#7 SignedData bytes. */
  signature: Uint8Array;
  /** Same bytes, base64-encoded. */
  signatureBase64: string;
  /** Time the signature was received (best-effort — SIGEX doesn't report the exact sign time). */
  signedAt: Date;
}

export interface SignResult {
  /** CMS / PKCS#7 SignedData (DER-encoded). This is what KalkanCrypt verifies. */
  signature: Uint8Array;
  /** Same bytes, base64-encoded — ready to send over JSON/HTTP */
  signatureBase64: string;
  /** Local timestamp included as a signed attribute (signingTime) */
  signedAt: Date;
  /** Whether the signature is detached (true) or attached (false) */
  detached: boolean;
  /** Info about the certificate that was used to sign */
  certInfo: CertInfo;
}

/**
 * Per-signer fields extracted by inspectSignature().
 * (CMS allows multiple signers; in NUC RK practice there's almost always just one.)
 */
export interface SignerInspection {
  /** Decoded info from the signer's certificate */
  certInfo: CertInfo;
  /** Time from the signingTime authenticated attribute, if present */
  signedAt: Date | null;
  /** Hash of the original document, base64. Compare against your own SHA-X(doc) to confirm. */
  messageDigestBase64: string | null;
  /** Hash algorithm declared in the SignerInfo, e.g. "SHA-256" */
  hashAlgorithm: string;
  /** True if the CAdES-BES "signingCertificateV2" (ESS, RFC 5035) attribute is present */
  hasSigningCertificateV2: boolean;
  /**
   * Whether the signer's RSA signature value verifies against the embedded certificate's
   * public key. This proves the signed attributes were not tampered with by anyone who
   * doesn't hold the private key. It does NOT prove:
   *   - the certificate is trusted (chain validation against NUC roots — do that on your backend)
   *   - the messageDigest in signedAttrs matches your original document
   *     (call inspectSignature with { document } to also verify that)
   */
  signatureValid: boolean;
}

export interface SignatureInspection {
  /** True if the document content is embedded in the CMS (attached); false if detached */
  attached: boolean;
  /** If attached, the embedded document bytes; otherwise null */
  embeddedContent: Uint8Array | null;
  /** Per-signer information (usually one entry) */
  signers: SignerInspection[];
  /** True if the CMS contains a TimeStampToken in unsigned attributes (CAdES-T) */
  hasTimestamp: boolean;
  /** The TSA-claimed time, if a timestamp is present and parseable */
  timestampAt: Date | null;
  /** True if you provided `options.document` and its SHA-X matches the signed messageDigest */
  documentDigestMatches: boolean | null;
}

export interface InspectOptions {
  /**
   * Optional original document bytes (only useful for detached signatures).
   * If provided, inspectSignature also verifies that SHA-X(document) equals the messageDigest
   * in the signed attributes — i.e. proof that this signature is for THIS document.
   */
  document?: ArrayBuffer | Uint8Array | string;
}

export interface TimestampOptions {
  /**
   * URL of an RFC 3161 Time Stamping Authority. KZ TSA is at https://tsp.pki.gov.kz/tsp.
   * Public TSAs do not send CORS headers, so this typically must be called from a Node
   * backend or via a server-side proxy you control.
   */
  tsaUrl: string;
  /** Hash algorithm for the TSP request. Default: SHA-256. */
  hashAlgorithm?: 'SHA-256' | 'SHA-384' | 'SHA-512';
  /** Optional fetch options (headers, signal, etc.) — passed through to fetch() */
  fetchInit?: RequestInit;
}
