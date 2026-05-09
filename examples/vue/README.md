# Vue 3 example

Minimal Vite + Vue 3 + TypeScript app demonstrating all three features of `@tako0502/egov-helper`.

## Run it

From the **repo root** (build the library first so the local file-link resolves):

```bash
npm install            # at the repo root
npm run build
```

Then in this folder:

```bash
cd examples/vue
npm install
npm run dev
```

Open <http://localhost:5174>.

## What it shows

A single `App.vue` using `<script setup lang="ts">` and the Composition API:

- File inputs with v-model bound via `@change` (so `File` objects flow through reactive refs)
- Direct calls to `checkBin`, `signDocument`, `inspectSignature`
- Sign → auto-fills the Inspect form so you can decode the same blob round-trip
- Renders `SignatureInspection` results inline with type-safe template

The library is wired in with a local file dependency (`"@tako0502/egov-helper": "file:../.."`) so any change you make to the library and `npm run build` is picked up automatically by Vite.
