# React example

Vite + React 18 + TypeScript demo using `@smoker_winston/egov-helper`. Mirrors the Vue example but in React idioms. Single `App.tsx` with two components: `CheckBinPanel` and `SignPanel`.

## Run it

From the repo root, build the library first:

```bash
npm install
npm run build
```

Then in this folder:

```bash
cd examples/react
npm install
npm run dev
```

Open <http://localhost:5175>. The backend URL defaults to `http://localhost:7676` — make sure the Java signer is up (`docker compose up` at the repo root).

## What it shows

Plain React with `useState`. The library is the same `@smoker_winston/egov-helper` package as everywhere else — type-safe imports, async calls, the same `{ backendUrl }` option as the Vue / Razor / mobile flows.

Copy any of these panels into your real React app. The only React-specific code is the input plumbing; the library calls are framework-agnostic.
