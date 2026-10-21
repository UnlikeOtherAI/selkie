// Explicit headless comparison of the base and repaired browser session restoration.
/* global localStorage, sessionStorage, document */
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
const { chromium } = await import(pathToFileURL(process.env.PLAYWRIGHT_MODULE).href);
const logo = await readFile('assets/icon-1024.png');
const key = 'e2e-test-secret-that-is-long-enough';
const exp = Math.floor(Date.now() / 1000) + 3600;
const claims = { sub: 'fixture-product-reference', jti: 'fixture-original-session', is_super: true,
  iss: 'selkie', aud: ['admin'], iat: exp - 3600, exp };
function sign(value) {
  const encoded = [Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
    Buffer.from(JSON.stringify(value)).toString('base64url')].join('.');
  return `${encoded}.${createHmac('sha256', key).update(encoded).digest('base64url')}`;
}
const legacy = sign({ ...claims, email: 'old@example.com', display_name: 'Old Copy' });
const clean = sign(claims);
const profile = { sub: claims.sub, session_id: claims.jti, is_super: true,
  email: 'agent.smith@example.com', display_name: 'Agent Smith', picture: '' };
const browser = await chromium.launch({ headless: true, channel: 'chrome' });
try {
  for (const [stage, port] of [['before', 5207], ['after', 5206]]) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(token => {
      if (!sessionStorage.getItem('fixture-initialized')) {
        localStorage.setItem('selkie_jwt', token); sessionStorage.setItem('fixture-initialized', 'true');
      }
    }, legacy);
    await page.route('**/*', async route => {
      const request = route.request(), path = new URL(request.url()).pathname;
      if (path === '/assets/icon-1024.png') return route.fulfill({ contentType: 'image/png', body: logo });
      const authenticated = request.headers().authorization?.startsWith('Bearer ');
      if (path === '/auth/session') return route.fulfill({ status: authenticated ? 200 : 401, json: profile });
      if (path === '/api/v1/auth/session') return route.fulfill({ json: { token: clean } });
      if (path === '/api/v1/auth/profile') return route.fulfill({ status: authenticated ? 200 : 401, json: profile });
      if (path === '/auth/dev-status') return route.fulfill({ json: { enabled: true } });
      if (path.startsWith('/api/')) return route.fulfill({ status: authenticated ? 200 : 401, json: { devices: [] } });
      return route.continue();
    });
    await page.goto(`http://127.0.0.1:${port}/admin/devices`);
    if (stage === 'before') await page.waitForURL('**/login');
    else {
      await page.locator('#user-email').filter({ hasText: 'Agent Smith' }).waitFor();
      const persisted = await page.evaluate(() => localStorage.getItem('selkie_jwt'));
      assert.equal(persisted, clean);
      assert.equal(page.url().endsWith('/admin/devices'), true);
    }
    await page.evaluate(() => document.fonts.ready);
    assert.deepEqual(errors, []);
    await mkdir(`docs/evidence/pr-14-ui/${stage}`, { recursive: true });
    await page.screenshot({ path: `docs/evidence/pr-14-ui/${stage}/legacy-session-1280.png`, fullPage: true });
    console.log(stage, new URL(page.url()).pathname);
    await page.close();
  }
} finally { await browser.close(); }
