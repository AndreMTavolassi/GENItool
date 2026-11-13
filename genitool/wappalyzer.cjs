/* Wappalyzer adapter. The engine and signatures are an optional dependency.
 * This adapter performs no network requests and never executes page scripts.
 * The Python client supplies one TLS-verified HTTP snapshot over stdin.
 */
'use strict';

const fs = require('fs');
const path = require('path');

function loadEngine() {
  const directory = process.env.GENITOOL_WAPPALYZER_DIR || path.dirname(require.resolve('wappalyzer/package.json'));
  const metadata = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
  if (metadata.name !== 'wappalyzer' || metadata.version !== '6.10.66') {
    throw new Error('Unsupported engine version');
  }
  const engine = require(path.join(path.resolve(directory), 'wappalyzer.js'));
  let technologies = {};
  for (const filename of fs.readdirSync(path.join(directory, 'technologies')).filter((name) => name.endsWith('.json')).sort()) {
    Object.assign(technologies, JSON.parse(fs.readFileSync(path.join(directory, 'technologies', filename), 'utf8')));
  }
  engine.setTechnologies(technologies);
  engine.setCategories(JSON.parse(fs.readFileSync(path.join(directory, 'categories.json'), 'utf8')));
  return engine;
}

try {
  const engine = loadEngine();
  if (process.argv.includes('--check')) {
    process.stdout.write('Wappalyzer 6.10.66 static engine ready\n');
    process.exit(0);
  }
  const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (typeof payload.url !== 'string' || typeof payload.html !== 'string') throw new Error('Invalid snapshot');
  const headers = {};
  for (const [name, value] of Object.entries(payload.headers || {})) {
    headers[name.toLowerCase()] = Array.isArray(value) ? value : [String(value)];
  }
  const detected = engine.resolve(engine.analyze({
    url: payload.url, html: payload.html, headers,
    meta: payload.meta || {}, scriptSrc: payload.scriptSrc || [],
  }));
  process.stdout.write(JSON.stringify({technologies: detected.map((item) => ({
    name: item.name,
    version: item.version || '',
    confidence: item.confidence,
    cpe: item.cpe || '',
  }))}) + '\n');
} catch (_) {
  // Do not echo input, page content, credentials, or arbitrary library errors.
  process.stderr.write('Wappalyzer engine unavailable or snapshot invalid.\n');
  process.exit(1);
}
