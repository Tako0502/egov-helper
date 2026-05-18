// Boots the full e2e stack for interactive use:
//   :8080  mock SIGEX
//   :7676  mock Kalkan
//   :4000  your app's backend
//   :5173  static server hosting demo.html + the IIFE bundle
//
// Opens the demo in your default browser. Ctrl-C kills everything.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startStack, shutdown } from './stack.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');

const BUNDLE = path.join(ROOT, 'dist/egov-helper.min.js');
const DEMO   = path.join(__dirname, 'demo.html');

if (!fs.existsSync(BUNDLE)) {
  console.error(`Bundle not found at ${BUNDLE}\nRun \`npm run build\` first.`);
  process.exit(2);
}

const services = await startStack({ verbose: true });

// Tiny static file server for the demo HTML + the IIFE bundle.
const staticServer = http.createServer((req, res) => {
  const url = (req.url ?? '/').split('?')[0];
  let filePath;
  if (url === '/' || url === '/demo.html') filePath = DEMO;
  else if (url === '/lib/egov-helper.min.js') filePath = BUNDLE;
  else { res.writeHead(404); res.end('Not found'); return; }

  fs.readFile(filePath, (err, buf) => {
    if (err) { res.writeHead(500); res.end(err.message); return; }
    const ct = filePath.endsWith('.js') ? 'application/javascript' : 'text/html; charset=utf-8';
    res.writeHead(200, { 'Content-Type': ct, 'Cache-Control': 'no-store' });
    res.end(buf);
  });
});
await new Promise((r) => staticServer.listen(5173, '0.0.0.0', r));
console.log(`[static]       listening on http://localhost:5173`);

const url = 'http://localhost:5173/demo.html';
console.log('\n──────────────────────────────────────────────────────────────');
console.log(`  Open ${url}`);
console.log('──────────────────────────────────────────────────────────────\n');

if (!process.env.NO_OPEN) {
  // macOS open / Linux xdg-open / Windows start
  const opener = process.platform === 'darwin' ? 'open'
    : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  try { spawn(opener, args, { stdio: 'ignore', detached: true }).unref(); } catch { /* ignore */ }
}

process.on('SIGINT',  () => stop(0));
process.on('SIGTERM', () => stop(0));

function stop(code) {
  console.log('\n[run-demo]    shutting down…');
  staticServer.close();
  shutdown(services);
  process.exit(code);
}
