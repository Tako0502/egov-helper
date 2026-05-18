// Shared boot logic for the e2e demo + automated test.
//
// startStack() spawns mock-sigex, mock-kalkan, and app-backend, waits until
// each /health endpoint responds, and returns the child handles.

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const STACK = [
  { name: 'mock-sigex',  script: 'mock-sigex.mjs',  port: 8080 },
  { name: 'mock-kalkan', script: 'mock-kalkan.mjs', port: 7676 },
  { name: 'app-backend', script: 'app-backend.mjs', port: 4000 },
];

export async function startStack({ verbose = false } = {}) {
  const children = [];
  for (const svc of STACK) {
    const child = spawn(process.execPath, [path.join(__dirname, svc.script)], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env },
    });
    if (verbose) {
      child.stdout.on('data', (b) => process.stdout.write(b));
      child.stderr.on('data', (b) => process.stderr.write(b));
    } else {
      // Silent except for unexpected exit info.
      child.stdout.on('data', () => {});
      child.stderr.on('data', (b) => process.stderr.write(`[${svc.name}] ${b}`));
    }
    child.on('exit', (code, sig) => {
      if (code !== 0 && code !== null) {
        console.error(`[${svc.name}] exited unexpectedly (code=${code}, sig=${sig})`);
      }
    });
    children.push({ ...svc, child });
  }

  // Wait for each /health to come up.
  for (const svc of children) {
    await waitForHealth(`http://localhost:${svc.port}/health`, svc.name);
  }
  return children;
}

export function shutdown(children) {
  for (const c of children) {
    try { c.child.kill(); } catch { /* ignore */ }
  }
}

async function waitForHealth(url, name, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${name} did not become healthy at ${url} within ${timeoutMs}ms`);
}
