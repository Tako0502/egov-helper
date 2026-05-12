// Minimal type declarations for the upstream `sigex-qr-signing-client` (which ships no
// .d.ts). Mirror only the methods we actually call from src/qr.ts.

declare module 'sigex-qr-signing-client' {
  export class QRSigningClientCMS {
    /**
     * @param description Human-readable text shown in eGov Mobile.
     * @param attach Whether to embed the document inside the CMS (true) or sign-only (false, default).
     * @param baseUrl SIGEX hub base URL — default 'https://sigex.kz'.
     */
    constructor(description: string, attach?: boolean, baseUrl?: string);

    /** When SIGEX is going to expire the signing request, ms since epoch. */
    expireAt: number | null;

    /**
     * Queue a document for signing. Call once per document.
     * @param names Display names per language: [ru, kk, en]. At least one required.
     * @param data Document bytes — base64 string (Node) or ArrayBuffer / Blob / File (browser).
     * @param meta Optional metadata array, usually [].
     * @param isPDF If true, eGov Mobile renders the document as a PDF preview before signing.
     */
    addDataToSign(
      names: string[],
      data: string | ArrayBuffer | Blob | File,
      meta?: unknown[],
      isPDF?: boolean,
    ): Promise<void>;

    /** Register the signing request with the SIGEX hub and produce a QR + deeplinks. */
    registerQRSinging(): Promise<void>;

    /** Base64-encoded PNG of the QR code, ready to use as <img src=...>. */
    getQR(): string;

    /** Deeplink that opens eGov Mobile to start signing. */
    getEGovMobileLaunchLink(): string;

    /** Deeplink for eGov Business app (alternative). */
    getEGovBusinessLaunchLink(): string;

    /**
     * Send the queued documents to SIGEX, then poll until eGov Mobile signs them.
     * Returns one base64 CMS per queued document, in the same order.
     */
    getSignatures(
      dataSentCallback?: () => void,
      debugErrorsCallback?: (err: Error) => void,
    ): Promise<string[]>;
  }

  export class QRSigningError extends Error {
    canceledByUser?: boolean;
    details?: string;
  }
}
