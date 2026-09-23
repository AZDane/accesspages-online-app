// Offline browser regression for a long first-certificate wait and saved enrollment.
const {chromium, webkit} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

async function main() {
  const app = path.resolve(process.env.APP_RUNTIME || path.join(__dirname, '../accesspages_online_test/rootfs/opt/accesspages-test'));
  const python = `import json,sys,tempfile
from pathlib import Path
from unittest.mock import patch
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'guest_gateway'),sys.argv[2]]
import runtime
from test_certificate_setup import pending_runtime
with tempfile.TemporaryDirectory() as d:
 r=Path(d);i=pending_runtime(r)
 with patch.object(runtime,'ROOT',r):
  assert i.prepare() is False
  print(json.dumps(i.public_status()))
`;
  const pending = JSON.parse(process.env.ENROLLMENT_STATUS_FIXTURE
    ? fs.readFileSync(process.env.ENROLLMENT_STATUS_FIXTURE, 'utf8')
    : execFileSync('python3', ['-B', '-c', python, app, __dirname], {encoding: 'utf8'}));
  const isWebKit = process.env.UI_BROWSER === 'webkit';
  const mobile = process.env.UI_MOBILE === '1';
  const browser = await (isWebKit ? webkit : chromium).launch({headless: true, ...(!isWebKit ? {channel: 'chrome'} : {})});
  let checks = 0;
  const check = (value, expected, description) => { assert.deepEqual(value, expected, description); checks++; };
  try {
    for (const savedEnrollment of [false, true]) {
      const context = await browser.newContext({serviceWorkers: 'block', viewport: mobile ? {width: 390, height: 844} : {width: 1280, height: 900}});
      const page = await context.newPage();
      await page.clock.install();
      await page.clock.pauseAt(new Date());
      let enrolled = savedEnrollment, ready = false, unavailable = false, reject = !savedEnrollment;
      let posts = 0, polls = 0, unexpected = 0, loaded = 0;
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await context.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url());
        assert.equal(url.origin, 'https://ha.example.test');
        if (url.pathname === '/') {
          loaded++;
          const body = ready ? '<h1>Admin ready</h1>' : fs.readFileSync(path.join(app, savedEnrollment ? 'waiting.html' : 'setup.html'), 'utf8').replaceAll('SETUP_CSRF', 'synthetic-csrf').replaceAll('SERVICE_ADDRESS', 'nhp.example.test:62206');
          return route.fulfill({contentType: 'text/html', body});
        }
        if (url.pathname === '/setup/enroll') {
          posts++;
          check(request.method(), 'POST', 'Enrollment still uses POST');
          check(request.headers()['x-access-pages-csrf'], 'synthetic-csrf', 'Enrollment retains CSRF binding');
          check(JSON.parse(request.postData()), {enrollment_token: 'synthetic-one-use-credential'}, 'Credential is only in the enrollment body');
          if (reject) return route.fulfill({status: 400, contentType: 'application/json', body: '{}'});
          enrolled = true;
          return route.fulfill({contentType: 'application/json', body: '{}'});
        }
        if (url.pathname === '/setup/status') {
          polls++;
          if (unavailable) return route.abort();
          return route.fulfill({contentType: 'application/json', body: JSON.stringify({...pending, enrolled, ready, admin_ready: ready})});
        }
        unexpected++;
        return route.abort();
      });
      await page.goto('https://ha.example.test/');
      if (!savedEnrollment) {
        await page.locator('#token').fill('synthetic-one-use-credential');
        await page.getByRole('button', {name: 'Connect', exact: true}).click();
        await page.locator('#status').filter({hasText: 'Could not enroll'}).waitFor();
        check(await page.locator('form').isVisible(), true, 'Rejected enrollment restores input');
        reject = false;
        await page.locator('#token').fill('synthetic-one-use-credential');
        await page.getByRole('button', {name: 'Connect', exact: true}).click();
        await page.locator('#progress-status').filter({hasText: 'Enrolled.'}).waitFor();
      }
      const status = page.locator(savedEnrollment ? '#status' : '#progress-status');
      await page.clock.runFor(125000);
      await status.filter({hasText: 'couple of minutes'}).waitFor();
      check(await status.textContent(), pending.message, 'Actual runtime status explains a long certificate wait');
      check(await status.getAttribute('role'), 'status', 'Progress remains accessible');
      check(await page.locator('form:visible').count(), 0, 'No repeat enrollment while certificate is pending');
      check(loaded, 1, 'Pending certificate does not navigate or imply completion');
      check(polls >= 35, true, 'Status polling continues beyond the observed 105-second wait');
      check(posts, savedEnrollment ? 0 : 2, 'Saved enrollment and long waits do not resubmit a credential');
      check(await page.locator('html').evaluate(el => el.scrollWidth <= el.clientWidth + 1), true, 'Progress fits viewport');
      check((await page.locator('body').innerText()).includes('synthetic-one-use-credential'), false, 'Credential is not rendered in progress');
      unavailable = true;
      await page.clock.runFor(6000);
      check(loaded, 1, 'A transient status outage cannot mark setup complete');
      check(await page.locator('form:visible').count(), 0, 'Status outage cannot request a second credential');
      unavailable = false;
      await page.clock.runFor(3000);
      await status.filter({hasText: 'couple of minutes'}).waitFor();
      ready = true;
      await page.clock.runFor(3000);
      await page.getByRole('heading', {name: 'Admin ready'}).waitFor();
      check(loaded, 2, 'Successful readiness advances automatically');
      check(unexpected, 0, 'Only existing local enrollment/status endpoints used');
      check(errors, [], 'No browser errors');
      await context.close();
    }
    console.log(JSON.stringify({passed: true, checks, browser: isWebKit ? 'webkit' : 'chromium', mobile, simulated_wait_seconds: 125}));
  } finally {
    await browser.close();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
