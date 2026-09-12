/* Manual, bounded checks against the two operator-supplied beta AccessLinks.
 * Inputs come only from a temporary Actions secret. No credentials, cookies,
 * destination inventory, traces or screenshots are written to public results.
 */
const {chromium} = require('playwright');
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const net = require('node:net');

const landing = 'https://access.beta.accesspages.app';
const report = {started: new Date().toISOString(), tests: [], transport: {relay_responses: 0, handoff_responses: []}};
let stage = 'input validation', browser;
function check(name, passed) {
  report.tests.push({name, passed: Boolean(passed)});
  if (!passed) throw new Error('Check failed');
}
function mask(value) { console.log('::add-mask::' + value); }
function tcpReachable(address, port) {
  return new Promise(resolve => {
    const connection = net.createConnection({host: address, port});
    const finish = value => { connection.destroy(); resolve(value); };
    connection.setTimeout(3000, () => finish(false));
    connection.once('connect', () => finish(true));
    connection.once('error', () => finish(false));
  });
}
function cookieName(resource) {
  return '__Host-nhp_guest_' + crypto.createHash('sha256').update(resource).digest('hex').slice(0, 24);
}

(async () => {
  const inputs = JSON.parse(process.env.ACCESSPAGES_GUEST_TEST_INPUTS || 'null');
  delete process.env.ACCESSPAGES_GUEST_TEST_INPUTS;
  if (!Array.isArray(inputs) || inputs.length !== 2) throw new Error('Missing input');
  for (const item of inputs) {
    const access = new URL(item.access_url), destination = new URL(item.expected_origin);
    const fragment = new URLSearchParams(access.hash.slice(1));
    if (!['demo-ha-1', 'demo-ha-2'].includes(item.label) || access.origin !== landing ||
        access.pathname !== '/' || access.search ||
        !/^[A-Za-z0-9_-]{43}$/.test(fragment.get('access') || '') ||
        !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(item.resource) || fragment.get('resource') !== item.resource ||
        !/^gw_[A-Za-z0-9_-]{43}$/.test(item.expected_gateway_id) ||
        destination.protocol !== 'https:' || destination.username || destination.password ||
        !/^[a-f0-9]{48}\.[a-f0-9]{48}\.sites\.beta\.accesspages\.app$/.test(destination.hostname) ||
        !['20002', '20003'].includes(destination.port) || destination.origin !== item.expected_origin) {
      throw new Error('Invalid scoped input');
    }
    for (const value of [item.access_url, fragment.get('access'), item.expected_origin,
                          destination.hostname, item.expected_gateway_id]) mask(value);
    item.address = (await dns.resolve4(destination.hostname))[0];
    item.port = Number(destination.port);
  }
  check('Two different installations supplied', new Set(inputs.map(i => i.expected_origin)).size === 2 && new Set(inputs.map(i => i.label)).size === 2);
  stage = 'unadmitted network baseline';
  for (const item of inputs) check(item.label + ': guest port unreachable before admission', !await tcpReachable(item.address, item.port));

  stage = 'browser startup';
  browser = await chromium.launch({headless: true, chromiumSandbox: true});
  const allowedOrigins = new Set([landing, 'https://relay.beta.accesspages.app:8443', ...inputs.map(i => i.expected_origin)]);
  async function context() {
    const value = await browser.newContext();
    await value.route('**/*', route => allowedOrigins.has(new URL(route.request().url()).origin) ? route.continue() : route.abort());
    value.on('response', response => {
      const url = new URL(response.url());
      if (url.hostname === 'relay.beta.accesspages.app') report.transport.relay_responses++;
      if (url.pathname === '/handoff') report.transport.handoff_responses.push(response.status());
    });
    return value;
  }
  const guests = [];
  for (let index = 0; index < inputs.length; index++) {
    const item = inputs[index]; stage = item.label + ': native admission and handoff';
    const profile = await context(), page = await profile.newPage();
    const guest = {item, profile, page, handoff: null, claims: null};
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.origin === item.expected_origin && url.pathname === '/handoff') {
        guest.handoff = new URLSearchParams(request.postData() || '').get('nhp_token');
        if (guest.handoff) {
          mask(guest.handoff);
          try { guest.claims = JSON.parse(Buffer.from(guest.handoff.split('.')[1], 'base64url').toString()); } catch {}
        }
      }
    });
    await page.goto(item.access_url, {waitUntil: 'domcontentloaded', timeout: 30000});
    await page.waitForURL(url => url.origin === item.expected_origin && url.pathname === '/access/' + item.resource, {timeout: 60000});
    check(item.label + ': signed handoff binds the expected Gateway and resource', guest.claims?.gateway_id === item.expected_gateway_id && guest.claims?.resource === item.resource);
    check(item.label + ': final address contains no credential', !new URL(page.url()).search && !new URL(page.url()).hash);
    const response = await profile.request.get(item.expected_origin + '/api/access/' + item.resource);
    check(item.label + ': authorized page data is available', response.status() === 200);
    const body = await response.json();
    check(item.label + ': correct page resources arrived', body.id === item.resource && Array.isArray(body.resources) && body.resources.length > 0);
    guest.cookie = (await profile.cookies()).find(cookie => cookie.name === cookieName(item.resource));
    check(item.label + ': secure host-only session cookie', guest.cookie && guest.cookie.secure && guest.cookie.httpOnly && guest.cookie.path === '/' && !guest.cookie.domain.startsWith('.'));
    if (guest.cookie) mask(guest.cookie.value);
    guests.push(guest);
    if (index === 0) check('Admission to Demo 1 leaves Demo 2 network port blocked', !await tcpReachable(inputs[1].address, inputs[1].port));
  }
  stage = 'session and installation isolation';
  const stranger = await context();
  for (let index = 0; index < guests.length; index++) {
    const own = guests[index], other = guests[1 - index];
    const target = own.item.expected_origin + '/api/access/' + own.item.resource;
    check(own.item.label + ': same-source visitor without a session is denied', (await stranger.request.get(target)).status() === 401);
    check(own.item.label + ': other installation session is denied', (await other.profile.request.get(target)).status() === 401);
    const copied = await context();
    await copied.addCookies([{...other.cookie, domain: new URL(own.item.expected_origin).hostname, name: cookieName(own.item.resource)}]);
    check(own.item.label + ': transplanted session cookie is denied', (await copied.request.get(target)).status() === 401);
    await copied.close();
    check(own.item.label + ': guest endpoint hides Admin', (await own.profile.request.get(own.item.expected_origin + '/api/admin/pages')).status() === 404);
    const replay = await own.profile.request.post(own.item.expected_origin + '/handoff', {headers: {Origin: landing}, form: {nhp_token: own.handoff}, maxRedirects: 0});
    check(own.item.label + ': handoff replay is rejected', replay.status() === 401);
  }
  await stranger.close();
  stage = 'one-use invitation replay';
  for (const own of guests) {
    const again = await context(), page = await again.newPage();
    await page.goto(own.item.access_url, {waitUntil: 'domcontentloaded'});
    await page.waitForFunction(() => document.querySelector('#status')?.textContent === 'Access Link invalid', null, {timeout: 30000});
    check(own.item.label + ': consumed invitation cannot be redeemed again', new URL(page.url()).origin === landing);
    check(own.item.label + ': original authorized session still works', (await own.profile.request.get(own.item.expected_origin + '/api/access/' + own.item.resource)).status() === 200);
    await again.close();
  }
  check('Real Browser NHP Relay traffic was observed', report.transport.relay_responses > 0);
  report.passed = true;
})().catch(error => {
  report.passed = false;
  report.failure = {stage, type: error.name};
  process.exitCode = 1;
}).finally(async () => {
  if (browser) await browser.close().catch(() => {});
  report.finished = new Date().toISOString();
  console.log('GUEST_CHECK_RESULT ' + JSON.stringify(report));
});
