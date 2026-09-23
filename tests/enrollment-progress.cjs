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
  pending=i.public_status()
  i.message='Waiting for customer certificate issuance. Retrying automatically.'
  retrying=i.public_status()
  i.message='Paste the enrollment API token to connect this Home Assistant.'
  print(json.dumps({'pending':pending,'retrying':retrying,'reconnecting':i.public_status()}))
`;
  const fixtures = JSON.parse(process.env.ENROLLMENT_STATUS_FIXTURE
    ? fs.readFileSync(process.env.ENROLLMENT_STATUS_FIXTURE, 'utf8')
    : execFileSync('python3', ['-B', '-c', python, app, __dirname], {encoding: 'utf8'}));
  const pending = fixtures.pending;
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
      let reported = savedEnrollment ? fixtures.reconnecting : pending;
      let releaseEnrollment;
      const enrollmentAccepted = new Promise(resolve => { releaseEnrollment = resolve; });
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
          await enrollmentAccepted;
          enrolled = true;
          return route.fulfill({contentType: 'application/json', body: '{}'});
        }
        if (url.pathname === '/setup/status') {
          polls++;
          if (unavailable === 'network') return route.abort();
          if (unavailable === 'http') return route.fulfill({status: 503, contentType: 'application/json', body: '{}'});
          return route.fulfill({contentType: 'application/json', body: JSON.stringify({...reported, enrolled, ready, admin_ready: ready})});
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
        check(await page.locator('#enrollment-instructions').isVisible(), true, 'Rejected enrollment retains relevant setup instructions');
        check(await page.locator('#enrollment-complete').isVisible(), false, 'Rejected enrollment never claims success');
        reject = false;
        await page.locator('#token').fill('synthetic-one-use-credential');
        await page.getByRole('button', {name: 'Connect', exact: true}).click();
        await page.locator('#progress-status').filter({hasText: 'Connecting to Access Pages'}).waitFor();
        check(await page.locator('#enrollment-complete').isVisible(), false, 'Pending enrollment does not claim acceptance');
        releaseEnrollment();
        await page.locator('#progress-status').filter({hasText: 'Setting up your secure connection'}).waitFor();
      }
      const status = page.locator(savedEnrollment ? '#status' : '#progress-status');
      const userView = async () => {
        const text = await page.locator('body').innerText();
        check(/enrollment API token|NHP|62206|customer TLS|certificate/i.test(text), false, 'Enrolled view hides token, server, and certificate internals');
        check(text.includes('Enrollment complete'), true, 'Only confirmed enrollment is marked complete');
        check(text.includes('couple of minutes') && text.includes('continue automatically'), true, 'Setup duration and automatic continuation are visible');
        check(await page.title(), 'Connecting Access Pages', 'Document title reflects connection setup');
      };
      await userView();
      if (savedEnrollment) {
        await page.clock.runFor(3000);
        await status.filter({hasText: 'Your enrollment is saved'}).waitFor();
        await userView();
      }
      reported = pending;
      await page.clock.runFor(125000);
      await status.filter({hasText: 'Setting up your secure connection'}).waitFor();
      check(await status.textContent(), pending.message, 'Current connection setup status is shown during a long wait');
      await userView();
      check(await status.getAttribute('role'), 'status', 'Progress remains accessible');
      check(await page.locator('form:visible').count(), 0, 'No repeat enrollment while certificate is pending');
      check(loaded, 1, 'Pending certificate does not navigate or imply completion');
      check(polls >= 35, true, 'Status polling continues beyond the observed 105-second wait');
      check(posts, savedEnrollment ? 0 : 2, 'Saved enrollment and long waits do not resubmit a credential');
      check(await page.locator('html').evaluate(el => el.scrollWidth <= el.clientWidth + 1), true, 'Progress fits viewport');
      check((await page.locator('body').innerText()).includes('synthetic-one-use-credential'), false, 'Credential is not rendered in progress');
      for (const outage of ['network', 'http']) {
        unavailable = outage;
        await page.clock.runFor(6000);
        await status.filter({hasText: 'Unable to check progress'}).waitFor();
        check(loaded, 1, 'A transient status outage cannot mark setup complete');
        check(await page.locator('form:visible').count(), 0, 'Status outage cannot request a second credential');
        await userView();
      }
      unavailable = false;
      reported = fixtures.retrying;
      await page.clock.runFor(3000);
      await status.filter({hasText: 'contact support'}).waitFor();
      await userView();
      check(loaded, 1, 'Runtime retries retain the connection progress view');
      reported = pending;
      await page.clock.runFor(3000);
      await status.filter({hasText: 'Setting up your secure connection'}).waitFor();
      if (process.env.UI_EVIDENCE_DIR) {
        fs.mkdirSync(process.env.UI_EVIDENCE_DIR, {recursive: true});
        await page.screenshot({path: path.join(process.env.UI_EVIDENCE_DIR, `${isWebKit ? 'webkit' : 'chromium'}-${mobile ? 'mobile' : 'desktop'}-${savedEnrollment ? 'saved' : 'new'}.png`), fullPage: true});
      }
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
