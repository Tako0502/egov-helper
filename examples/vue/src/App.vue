<script setup lang="ts">
import { ref } from 'vue';
import {
  checkBin,
  signDocument,
  inspectSignature,
  type CheckBinResult,
  type SignResult,
  type SignatureInspection,
} from '@atasuai/egov-helper';

// ── Form 1: BIN check ─────────────────────────────────────────────────────
const binFile = ref<File | null>(null);
const binPassword = ref('');
const binTyped = ref('');
const binResult = ref<CheckBinResult | null>(null);
const binError = ref<string | null>(null);

async function runCheckBin() {
  binError.value = null;
  binResult.value = null;
  if (!binFile.value) {
    binError.value = 'Pick a .p12 file first';
    return;
  }
  try {
    binResult.value = await checkBin(binFile.value, binPassword.value, binTyped.value);
  } catch (e) {
    binError.value = (e as Error).message;
  }
}

// ── Form 2: sign document ─────────────────────────────────────────────────
const signFile = ref<File | null>(null);
const signPassword = ref('');
const signDoc = ref<File | null>(null);
const signResult = ref<SignResult | null>(null);
const signError = ref<string | null>(null);

async function runSign() {
  signError.value = null;
  signResult.value = null;
  if (!signFile.value || !signDoc.value) {
    signError.value = 'Pick both a .p12 and a document to sign';
    return;
  }
  try {
    const docBytes = new Uint8Array(await signDoc.value.arrayBuffer());
    const r = await signDocument(signFile.value, signPassword.value, docBytes);
    signResult.value = r;
    inspectInput.value = r.signatureBase64; // auto-fill the inspect form
  } catch (e) {
    signError.value = (e as Error).message;
  }
}

// ── Form 3: inspect a signature ───────────────────────────────────────────
const inspectInput = ref('');
const inspectDoc = ref<File | null>(null);
const inspectResult = ref<SignatureInspection | null>(null);
const inspectError = ref<string | null>(null);

async function runInspect() {
  inspectError.value = null;
  inspectResult.value = null;
  if (!inspectInput.value.trim()) {
    inspectError.value = 'Paste a base64 or hex signature first';
    return;
  }
  try {
    const opts: { document?: Uint8Array } = {};
    if (inspectDoc.value) {
      opts.document = new Uint8Array(await inspectDoc.value.arrayBuffer());
    }
    inspectResult.value = await inspectSignature(inspectInput.value.trim(), opts);
  } catch (e) {
    inspectError.value = (e as Error).message;
  }
}

function onFile(setter: (f: File | null) => void) {
  return (e: Event) => {
    const target = e.target as HTMLInputElement;
    setter(target.files?.[0] ?? null);
  };
}

function pretty(v: unknown): string {
  return JSON.stringify(
    v,
    (_k, val) => {
      if (val instanceof Uint8Array) return `<${val.length} bytes>`;
      if (val instanceof Date) return val.toISOString();
      return val;
    },
    2,
  );
}
</script>

<template>
  <main>
    <h1>egov-helper · Vue 3 example</h1>
    <p class="sub">
      Three features in one page. Nothing is uploaded — the .p12 stays in your browser.
    </p>

    <section>
      <h2>1. Check BIN / IIN match</h2>
      <label>Certificate (.p12 / .pfx)</label>
      <input type="file" accept=".p12,.pfx" @change="onFile(f => (binFile = f))" />
      <label>Password</label>
      <input type="password" v-model="binPassword" autocomplete="off" />
      <label>BIN or IIN to verify (12 digits)</label>
      <input type="text" v-model="binTyped" inputmode="numeric" maxlength="12" />
      <button @click="runCheckBin">Check</button>
      <p v-if="binError" class="err">Error: {{ binError }}</p>
      <p v-if="binResult" :class="binResult.match ? 'ok' : 'bad'">
        {{ binResult.match ? `MATCH (${binResult.matchedField})` : 'NO MATCH' }}
      </p>
      <pre v-if="binResult">{{ pretty(binResult) }}</pre>
    </section>

    <section>
      <h2>2. Sign a document (CAdES-BES)</h2>
      <label>Certificate (.p12 / .pfx)</label>
      <input type="file" accept=".p12,.pfx" @change="onFile(f => (signFile = f))" />
      <label>Password</label>
      <input type="password" v-model="signPassword" autocomplete="off" />
      <label>Document to sign</label>
      <input type="file" @change="onFile(f => (signDoc = f))" />
      <button @click="runSign">Sign (detached, SHA-256)</button>
      <p v-if="signError" class="err">Error: {{ signError }}</p>
      <pre v-if="signResult">{{ pretty({
        ...signResult,
        signature: `<${signResult.signature.length} bytes>`,
        signatureBase64: signResult.signatureBase64.slice(0, 80) + '… (full value sent to inspect form)',
      }) }}</pre>
    </section>

    <section>
      <h2>3. Inspect a signature (decode CMS)</h2>
      <label>Signature (base64 or hex)</label>
      <textarea v-model="inspectInput" placeholder="MIIH... (base64 CMS)"></textarea>
      <label>Optional: original document (for detached)</label>
      <input type="file" @change="onFile(f => (inspectDoc = f))" />
      <button @click="runInspect">Inspect</button>
      <p v-if="inspectError" class="err">Error: {{ inspectError }}</p>
      <template v-if="inspectResult">
        <p v-for="s in inspectResult.signers" :key="s.certInfo.serialNumberHex">
          Signed by <b>{{ s.certInfo.commonName ?? '(no CN)' }}</b>
          <span v-if="s.certInfo.bin"> · BIN {{ s.certInfo.bin }}</span>
          <span v-if="s.certInfo.iin"> · IIN {{ s.certInfo.iin }}</span>
          · {{ s.signedAt?.toISOString() ?? '(no signedAt)' }}
          · <span :class="s.signatureValid ? 'ok' : 'bad'">
              signature {{ s.signatureValid ? 'verifies' : 'INVALID' }}
            </span>
          · CAdES-BES: {{ s.hasSigningCertificateV2 ? 'yes' : 'no' }}
          · timestamp: {{ inspectResult.hasTimestamp ? 'yes' : 'no' }}
          <span v-if="inspectResult.documentDigestMatches !== null">
            · doc digest: <span :class="inspectResult.documentDigestMatches ? 'ok' : 'bad'">
              {{ inspectResult.documentDigestMatches ? 'matches' : 'MISMATCH' }}
            </span>
          </span>
        </p>
        <pre>{{ pretty(inspectResult) }}</pre>
      </template>
    </section>
  </main>
</template>

<style>
:root { color-scheme: light dark; }
body { margin: 0; }
main {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  max-width: 760px;
  margin: 32px auto;
  padding: 0 16px;
  line-height: 1.5;
}
h1 { margin: 0 0 4px; }
.sub { color: #777; }
section {
  border: 1px solid #ccc;
  border-radius: 8px;
  padding: 16px 20px;
  margin: 16px 0;
}
h2 { margin-top: 0; }
label { display: block; margin: 8px 0 4px; font-size: 14px; }
input[type=text], input[type=password], input[type=file], textarea {
  width: 100%;
  padding: 8px;
  font-size: 14px;
  box-sizing: border-box;
  font-family: inherit;
}
textarea { min-height: 90px; resize: vertical; }
button {
  margin-top: 12px;
  padding: 8px 16px;
  font-size: 14px;
  cursor: pointer;
}
pre {
  background: #f4f4f4;
  padding: 12px;
  border-radius: 6px;
  overflow-x: auto;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}
.ok { color: #2a7a2a; font-weight: bold; }
.bad { color: #a52a2a; font-weight: bold; }
.err { color: #a52a2a; }
@media (prefers-color-scheme: dark) {
  section { border-color: #444; }
  pre { background: #222; }
}
</style>
