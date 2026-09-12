/* Uses a naturally expiring operator invitation. No service policy changes. */
const {chromium} = require('playwright');
const dns = require('node:dns').promises;
const net = require('node:net');
const crypto = require('node:crypto');
const landing = 'https://access.beta.accesspages.app';
const report = {started: new Date().toISOString(), tests: []};
let stage = 'input validation', browser, probe, printed = false;
function output() { if (!printed) {printed = true; report.finished = new Date().toISOString(); console.log('EXPIRY_CHECK_RESULT ' + JSON.stringify(report));} }
function check(name, passed) {report.tests.push({name, passed: Boolean(passed)}); if (!passed) throw new Error('Check failed');}
const deadline = setTimeout(() => {report.passed = false; report.failure = {stage, type: 'TestDeadlineExceeded'}; output(); process.exit(1);}, 360000);
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

(async () => {
  const item = JSON.parse(process.env.ACCESSPAGES_EXPIRY_INPUT || 'null');
  delete process.env.ACCESSPAGES_EXPIRY_INPUT;
  const destination = new URL(item.expected_origin);
  if (destination.protocol !== 'https:' || destination.port !== '20003' || destination.origin !== item.expected_origin ||
      !/^[a-f0-9]{48}\.[a-f0-9]{48}\.sites\.beta\.accesspages\.app$/.test(destination.hostname) ||
      item.resource !== 'page-ha-green-demo-2' || !/^gw_[A-Za-z0-9_-]{43}$/.test(item.expected_gateway_id) ||
      !Number.isInteger(item.expires)) throw new Error('Invalid scoped input');
  for (const link of [item.access_url, item.renewal_url]) {
    const url = new URL(link), hash = new URLSearchParams(url.hash.slice(1));
    if (url.origin !== landing || url.pathname !== '/' || url.search || hash.get('resource') !== item.resource || !/^[A-Za-z0-9_-]{43}$/.test(hash.get('access') || '')) throw new Error('Invalid link');
    for (const value of [link, hash.get('access')]) console.log('::add-mask::' + value);
  }
  for (const value of [item.expected_origin, destination.hostname, item.expected_gateway_id]) console.log('::add-mask::' + value);
  const remaining = item.expires - Date.now() / 1000;
  check('Natural expiry window is between 15 seconds and four minutes', remaining > 15 && remaining < 240);
  const address = (await dns.resolve4(destination.hostname))[0];
  browser = await chromium.launch({channel: 'chrome', headless: true, chromiumSandbox: true});
  const allowed = new Set([landing, 'https://relay.beta.accesspages.app:8443', item.expected_origin]);
  async function context() {
    const value = await browser.newContext();
    await value.route('**/*', route => allowed.has(new URL(route.request().url()).origin) ? route.continue() : route.abort());
    return value;
  }
  async function read(page) {
    return page.evaluate(async resource => {
      try {const response = await fetch('/api/access/' + resource, {signal: AbortSignal.timeout(7000)}); return {status: response.status};}
      catch (error) {return {status: null, type: error.name};}
    }, item.resource);
  }
  async function admit(url) {
    const profile = await context(), page = await profile.newPage();
    const result = {profile, page};
    page.on('request', request => {
      const target = new URL(request.url());
      if (target.origin === item.expected_origin && target.pathname === '/handoff') {
        const token = new URLSearchParams(request.postData() || '').get('nhp_token');
        if (token) {console.log('::add-mask::' + token); result.claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());}
      }
    });
    await page.goto(url, {waitUntil: 'domcontentloaded', timeout: 30000});
    await page.waitForURL(value => value.origin === item.expected_origin && value.pathname === '/access/' + item.resource, {timeout: 40000});
    check('Signed handoff binds the expected Gateway and resource', result.claims?.gateway_id === item.expected_gateway_id && result.claims?.resource === item.resource);
    return result;
  }
  stage = 'short remaining lifetime admission';
  const original = await admit(item.access_url);
  check('Session deadline is capped by invitation expiry', original.claims.session_exp === item.expires);
  check('Page is usable before expiry', (await read(original.page)).status === 200);
  const cookieName = '__Host-nhp_guest_' + crypto.createHash('sha256').update(item.resource).digest('hex').slice(0, 24);
  const oldCookie = (await original.profile.cookies()).find(cookie => cookie.name === cookieName);
  check('Authenticated session cookie exists before expiry', Boolean(oldCookie));
  console.log('::add-mask::' + oldCookie.value);
  stage = 'natural expiry wait';
  report.session_expires = item.expires;
  await pause(Math.max(0, (item.expires + 2) * 1000 - Date.now()));
  const expiredRead = await read(original.page);
  report.expired_read = expiredRead;
  check('Expired original session returns no protected content', expiredRead.status === 401 || expiredRead.status === null && ['TimeoutError', 'AbortError', 'TypeError'].includes(expiredRead.type));
  await pause(Math.max(0, (item.expires + 8) * 1000 - Date.now()));
  stage = 'network expiry';
  const reachable = await new Promise(resolve => {
    // Retain the probe socket through renewal to avoid immediately reusing a
    // NAT source port belonging to the deliberately dropped connection.
    probe = net.createConnection({host: address, port: Number(destination.port)});
    const timer = setTimeout(() => resolve(false), 3000);
    probe.once('connect', () => {clearTimeout(timer); resolve(true);});
    probe.once('error', () => {clearTimeout(timer); resolve(false);});
  });
  check('Guest TCP endpoint is unreachable after admission expiry', !reachable);
  stage = 'fresh admission after expiry';
  const renewed = await admit(item.renewal_url);
  check('Fresh invitation restores authorized page access', (await read(renewed.page)).status === 200);
  const stale = await context();
  const forcedCookie = {...oldCookie}; delete forcedCookie.expires;
  await stale.addCookies([forcedCookie]);
  const stalePage = await stale.newPage();
  const rejected = await stalePage.goto(item.expected_origin + '/api/access/' + item.resource, {waitUntil: 'domcontentloaded', timeout: 20000});
  check('Server rejects expired cookie after network access is restored', rejected.status() === 401);
  check('Renewed session still works after expired-cookie rejection', (await read(renewed.page)).status === 200);
  report.passed = true;
})().catch(error => {
  report.passed = false; report.failure = {stage, type: error.name, codes: [...new Set(error.message?.match(/net::ERR_[A-Z_]+|ETIMEDOUT|ECONN[A-Z]+/g) || [])]}; process.exitCode = 1;
}).finally(async () => {
  output(); if (probe) probe.destroy();
  if (browser) await Promise.race([browser.close().catch(() => {}), pause(5000)]);
  clearTimeout(deadline); process.exit(process.exitCode || 0);
});
