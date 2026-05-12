import { useState, type ChangeEvent } from 'react';
import {
  checkBin,
  signDocument,
  type CheckBinResult,
  type SignResult,
} from '@smoker_winston/egov-helper';

const DEFAULT_BACKEND = 'http://localhost:7676';

export function App() {
  const [backend, setBackend] = useState(DEFAULT_BACKEND);
  return (
    <main>
      <h1>egov-helper · React example</h1>
      <p className="sub">
        Drop-in React 18 + Vite + TypeScript demo. Backed by your local Kalkan signer service.
      </p>

      <BackendInput backend={backend} setBackend={setBackend} />
      <CheckBinPanel backend={backend} />
      <SignPanel backend={backend} />
    </main>
  );
}

function BackendInput({ backend, setBackend }: { backend: string; setBackend: (v: string) => void }) {
  return (
    <section>
      <h2>Backend URL</h2>
      <p className="sub">Base URL of your Kalkan-Java service. The lib appends /sign and /info.</p>
      <input type="text" value={backend} onChange={(e) => setBackend(e.target.value)} />
    </section>
  );
}

function CheckBinPanel({ backend }: { backend: string }) {
  const [p12, setP12] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [typed, setTyped] = useState('');
  const [result, setResult] = useState<CheckBinResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onCheck() {
    setErr(null);
    setResult(null);
    if (!p12) {
      setErr('Pick a .p12 first');
      return;
    }
    setBusy(true);
    try {
      const r = await checkBin(p12, password, typed, { backendUrl: backend });
      setResult(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2>1. checkBin</h2>
      <label>Certificate (.p12)</label>
      <input
        type="file"
        accept=".p12,.pfx"
        onChange={(e: ChangeEvent<HTMLInputElement>) => setP12(e.target.files?.[0] ?? null)}
      />
      <label>Password</label>
      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <label>BIN or IIN typed by user</label>
      <input type="text" value={typed} onChange={(e) => setTyped(e.target.value)} placeholder="123456789012" />
      <button disabled={!p12 || !password || !typed || busy} onClick={onCheck}>
        {busy ? 'Checking…' : 'Check'}
      </button>
      {err && <p className="err">Error: {err}</p>}
      {result && (
        <>
          <p className={result.match ? 'ok' : 'bad'}>
            {result.match ? `✓ MATCH (cert ${result.matchedField})` : '✗ NO MATCH'}
          </p>
          <div className="kv">
            <div className="k">Owner</div><div>{result.certInfo.commonName ?? '(none)'}</div>
            <div className="k">Org</div><div>{result.certInfo.organization ?? '—'}</div>
            <div className="k">Cert BIN</div><div>{result.certBin ?? '—'}</div>
            <div className="k">Cert IIN</div><div>{result.certIin ?? '—'}</div>
            <div className="k">Valid until</div><div>{result.certInfo.validTo.toISOString()}</div>
          </div>
        </>
      )}
    </section>
  );
}

function SignPanel({ backend }: { backend: string }) {
  const [p12, setP12] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [doc, setDoc] = useState<File | null>(null);
  const [result, setResult] = useState<SignResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSign() {
    setErr(null);
    setResult(null);
    if (!p12 || !doc) {
      setErr('Pick both a .p12 and a document');
      return;
    }
    setBusy(true);
    try {
      const docBytes = new Uint8Array(await doc.arrayBuffer());
      const r = await signDocument(p12, password, docBytes, { backendUrl: backend });
      setResult(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2>2. signDocument</h2>
      <label>Certificate (.p12)</label>
      <input type="file" accept=".p12,.pfx" onChange={(e) => setP12(e.target.files?.[0] ?? null)} />
      <label>Password</label>
      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <label>Document</label>
      <input type="file" onChange={(e) => setDoc(e.target.files?.[0] ?? null)} />
      <button disabled={!p12 || !password || !doc || busy} onClick={onSign}>
        {busy ? 'Signing…' : 'Sign'}
      </button>
      {err && <p className="err">Error: {err}</p>}
      {result && (
        <>
          <p className="ok">✓ Produced {result.signature.length}-byte CAdES-BES CMS</p>
          <div className="kv">
            <div className="k">Signed at</div><div>{result.signedAt.toISOString()}</div>
            <div className="k">Signer</div><div>{result.certInfo.commonName ?? '—'}</div>
            <div className="k">BIN</div><div>{result.certInfo.bin ?? '—'}</div>
          </div>
          <label>Base64 signature</label>
          <pre>{result.signatureBase64.slice(0, 200)}…</pre>
        </>
      )}
    </section>
  );
}
