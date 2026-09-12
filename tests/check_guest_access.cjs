/* Manual, bounded checks against the two operator-supplied beta AccessLinks.
 * Inputs come only from a temporary Actions secret. No credentials, cookies,
 * destination inventory, traces or screenshots are written to public results.
 */
const {chromium} = require('playwright');
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const net = require('node:net');
const tls = require('node:tls');

const landing = 'https://access.beta.accesspages.app';
const report = {started: new Date().toISOString(), tests: [], transport: {relay_responses: 0, handoff_responses: [], page_data_responses: [], request_failures: []}};
const preAdmissionProbes = process.env.ACCESSPAGES_PRE_ADMISSION_PROBES !== 'false';
const holdSeconds = Number(process.env.ACCESSPAGES_HOLD_SECONDS || 0);
report.replica = Number(process.env.ACCESSPAGES_TEST_REPLICA || 1);
report.pre_admission_probes = preAdmissionProbes;
let stage = 'input validation', browser;
let destinations = [];
let reported = false;
function finishReport() {
  if (reported) return;
  reported = true;
  report.finished = new Date().toISOString();
  console.log('GUEST_CHECK_RESULT ' + JSON.stringify(report));
}
const deadline = setTimeout(() => {
  report.passed = false;
  report.failure = {stage, type: 'TestDeadlineExceeded'};
  finishReport();
  process.exit(1);
}, 180000);
function check(name, passed) {
  report.tests.push({name, passed: Boolean(passed)});
  console.log('GUEST_CHECK_PROGRESS ' + JSON.stringify({name, passed: Boolean(passed)}));
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
function tlsHealth(item) {
  return new Promise(resolve => {
    const result = {installation: item.label, tcp_connected: false, tls_verified: false};
    let complete = false, header = '';
    const connection = tls.connect({host: item.address, port: item.port,
      servername: new URL(item.expected_origin).hostname, rejectUnauthorized: true});
    const finish = () => {
      if (complete) return;
      complete = true; clearTimeout(timer); connection.destroy(); resolve(result);
    };
    const timer = setTimeout(() => {result.timed_out = true; finish();}, 10000);
    connection.once('connect', () => {result.tcp_connected = true;});
    connection.once('secureConnect', () => {
      result.tls_verified = connection.authorized;
      connection.write('GET /health HTTP/1.1\r\nHost: ' + new URL(item.expected_origin).host + '\r\nConnection: close\r\n\r\n');
    });
    connection.on('data', data => {
      header += data.toString('utf8').slice(0, 64);
      const match = header.match(/^HTTP\/1\.[01] (\d{3}) /);
      if (match) {result.http_status = Number(match[1]); finish();}
      else if (header.length > 128) finish();
    });
    connection.once('error', error => {result.error_code = /^[A-Z_0-9]+$/.test(error.code || '') ? error.code : 'CONNECTION_ERROR'; finish();});
    connection.once('end', finish);
  });
}
async function readPage(page, resource) {
  return page.evaluate(async resource => {
    const response = await fetch('/api/access/' + resource, {signal: AbortSignal.timeout(15000)});
    return {status: response.status, body: await response.json()};
  }, resource);
}
// Keep admission and all HTTP checks on Chrome's network stack. Playwright's
// APIRequestContext uses a separate Node HTTP client, outside browser routing.
async function navigateStatus(profile, url) {
  const page = await profile.newPage();
  try {
    const response = await page.goto(url, {waitUntil: 'domcontentloaded', timeout: 20000});
    return response.status();
  } finally { await page.close(); }
}

(async () => {
  if (!Number.isInteger(holdSeconds) || holdSeconds < 0 || holdSeconds > 120 || ![1, 2, 3].includes(report.replica)) throw new Error('Invalid test scope');
  const inputs = JSON.parse(process.env.ACCESSPAGES_GUEST_TEST_INPUTS || 'null');
  delete process.env.ACCESSPAGES_GUEST_TEST_INPUTS;
  if (!Array.isArray(inputs) || inputs.length !== 2) throw new Error('Missing input');
  for (const item of inputs) {
    const access = new URL(item.access_url), destination = new URL(item.expected_origin);
    const credential = access.hash.slice(1);
    if (!['demo-ha-1', 'demo-ha-2'].includes(item.label) || access.origin !== landing ||
        access.pathname !== '/' || access.search ||
        !/^[A-Za-z0-9_-]{43}$/.test(credential) ||
        !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(item.resource) ||
        !/^gw_[A-Za-z0-9_-]{43}$/.test(item.expected_gateway_id) ||
        (item.one_time !== undefined && typeof item.one_time !== 'boolean') ||
        (item.check_invalid_routing !== undefined && typeof item.check_invalid_routing !== 'boolean') ||
        destination.protocol !== 'https:' || destination.username || destination.password ||
        !/^[a-f0-9]{48}\.[a-f0-9]{48}\.sites\.beta\.accesspages\.app$/.test(destination.hostname) ||
        !['20002', '20003'].includes(destination.port) || destination.origin !== item.expected_origin) {
      throw new Error('Invalid scoped input');
    }
    for (const value of [item.access_url, credential, item.expected_origin,
                          destination.hostname, item.expected_gateway_id]) mask(value);
    if (item.expired_access_url !== undefined) {
      const expired = new URL(item.expired_access_url);
      const expiredCredential = expired.hash.slice(1);
      if (expired.origin !== landing || expired.pathname !== '/' || expired.search ||
          !/^[A-Za-z0-9_-]{43}$/.test(expiredCredential) ||
          !Number.isInteger(item.expired_at) || item.expired_at >= Math.floor(Date.now() / 1000)) {
        throw new Error('Invalid expired invitation input');
      }
      mask(item.expired_access_url); mask(expiredCredential);
    }
    item.address = (await dns.resolve4(destination.hostname))[0];
    item.port = Number(destination.port);
  }
  check('Two different installations supplied', new Set(inputs.map(i => i.expected_origin)).size === 2 && new Set(inputs.map(i => i.label)).size === 2);
  destinations = inputs;
  stage = 'unadmitted network baseline';
  for (const item of inputs) {
    if (preAdmissionProbes) check(item.label + ': guest port unreachable before admission', !await tcpReachable(item.address, item.port));
    else report.tests.push({name: item.label + ': guest-runner network baseline', skipped: 'Disabled; separate observer evidence is required for network denial'});
  }

  stage = 'browser startup';
  // The runner's packaged Chrome has Ubuntu's supported sandbox profile.
  browser = await chromium.launch({channel: 'chrome', headless: true, chromiumSandbox: true});
  report.browser_version = browser.version();
  const allowedOrigins = new Set([landing, 'https://relay.beta.accesspages.app:8443', ...inputs.map(i => i.expected_origin)]);
  async function context() {
    const value = await browser.newContext();
    await value.route('**/*', route => allowedOrigins.has(new URL(route.request().url()).origin) ? route.continue() : route.abort());
    value.on('response', response => {
      const url = new URL(response.url());
      if (url.hostname === 'relay.beta.accesspages.app') report.transport.relay_responses++;
      if (url.pathname === '/handoff') report.transport.handoff_responses.push(response.status());
      const item = inputs.find(item => url.origin === item.expected_origin);
      if (item && url.pathname === '/api/access/' + item.resource && report.transport.page_data_responses.length < 80) {
        report.transport.page_data_responses.push({installation: item.label, status: response.status()});
      }
    });
    value.on('requestfailed', request => {
      const url = new URL(request.url()), item = inputs.find(item => url.origin === item.expected_origin);
      const code = request.failure()?.errorText?.match(/^net::ERR_[A-Z_]+$/)?.[0];
      if (item && code && report.transport.request_failures.length < 20) {
        report.transport.request_failures.push({installation: item.label, code,
          route: url.pathname.startsWith('/api/access/') ? 'page-data' : url.pathname === '/handoff' ? 'handoff' : 'page-or-asset'});
      }
    });
    return value;
  }
  async function rejectedInvitation(url, name) {
    stage = name;
    const profile = await context(), page = await profile.newPage();
    let handoffAttempted = false;
    page.on('request', request => {
      if (new URL(request.url()).pathname === '/handoff') handoffAttempted = true;
    });
    await page.goto(url, {waitUntil: 'domcontentloaded', timeout: 30000});
    await page.waitForFunction(() => document.querySelector('#status')?.textContent === 'Access Link invalid', null, {timeout: 30000});
    check(name, new URL(page.url()).origin === landing && !handoffAttempted);
    await profile.close();
  }
  for (const item of inputs) {
    if (item.check_invalid_routing) {
      const other = inputs.find(value => value !== item);
      const variants = [
        ['ResourceID injection into an opaque AccessLink is rejected', url => {url.hash += '&resource=' + other.resource;}],
        ['Old named-parameter link format is rejected', url => {url.hash = 'access=' + url.hash.slice(1);} ],
        ['AccessLink with an altered credential is rejected', url => {
          const credential = url.hash.slice(1);
          url.hash = (credential[0] === 'A' ? 'B' : 'A') + credential.slice(1);
        }],
      ];
      for (const [name, modify] of variants) {
        const url = new URL(item.access_url);
        modify(url);
        mask(url.href); mask(url.hash.slice(1));
        await rejectedInvitation(url.href, item.label + ': ' + name);
      }
    }
    if (item.expired_access_url) {
      await rejectedInvitation(item.expired_access_url, item.label + ': expired unused invitation is rejected');
    }
  }
  const guests = [];
  for (let index = 0; index < inputs.length; index++) {
    const item = inputs[index]; stage = item.label + ': native admission and handoff';
    const profile = await context(), page = await profile.newPage();
    const guest = {item, profile, page, handoff: null, claims: null};
    page.on('request', request => {
      const url = new URL(request.url());
      if (url.origin === item.expected_origin && url.pathname === '/handoff') {
        item.handoff_attempted = true;
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
    guest.cookie = (await profile.cookies()).find(cookie => cookie.name === cookieName(item.resource));
    check(item.label + ': secure host-only session cookie', guest.cookie && guest.cookie.secure && guest.cookie.httpOnly && guest.cookie.path === '/' && !guest.cookie.domain.startsWith('.'));
    if (guest.cookie) mask(guest.cookie.value);
    stage = item.label + ': browser page data';
    const response = await readPage(page, item.resource);
    check(item.label + ': authorized page data is available', response.status === 200);
    check(item.label + ': correct page resources arrived', response.body.id === item.resource && Array.isArray(response.body.resources) && response.body.resources.length > 0);
    guests.push(guest);
    if (index === 0 && preAdmissionProbes) check('Admission to Demo 1 leaves Demo 2 network port blocked', !await tcpReachable(inputs[1].address, inputs[1].port));
  }
  stage = 'session and installation isolation';
  const stranger = await context();
  for (let index = 0; index < guests.length; index++) {
    const own = guests[index], other = guests[1 - index];
    const target = own.item.expected_origin + '/api/access/' + own.item.resource;
    stage = own.item.label + ': session and installation isolation';
    check(own.item.label + ': same-source visitor without a session is denied', await navigateStatus(stranger, target) === 401);
    check(own.item.label + ': other installation session is denied', await navigateStatus(other.profile, target) === 401);
    const copied = await context();
    await copied.addCookies([{...other.cookie, domain: new URL(own.item.expected_origin).hostname, name: cookieName(own.item.resource)}]);
    check(own.item.label + ': transplanted session cookie is denied', await navigateStatus(copied, target) === 401);
    await copied.close();
    check(own.item.label + ': guest endpoint hides Admin', await navigateStatus(own.profile, own.item.expected_origin + '/api/admin/pages') === 404);
    const replayPage = await own.profile.newPage();
    stage = own.item.label + ': unexpired handoff replay';
    await replayPage.goto(landing, {waitUntil: 'domcontentloaded'});
    check(own.item.label + ': replay uses an unexpired signed handoff', own.claims.exp > Math.floor(Date.now() / 1000) + 5);
    const replayResponse = replayPage.waitForResponse(response => response.url() === own.item.expected_origin + '/handoff', {timeout: 20000});
    await replayPage.evaluate(({origin, token}) => {
      const form = document.createElement('form'); form.method = 'POST'; form.action = origin + '/handoff';
      const input = document.createElement('input'); input.type = 'hidden'; input.name = 'nhp_token'; input.value = token;
      form.appendChild(input); document.body.appendChild(form); form.submit();
    }, {origin: own.item.expected_origin, token: own.handoff});
    const replay = await replayResponse;
    check(own.item.label + ': handoff replay is rejected', replay.status() === 401);
    // Chrome may stall closing a tab during the rejected POST navigation.
    // Keep these two tabs until the bounded browser cleanup after all checks.
  }
  await stranger.close();
  stage = 'one-use invitation replay';
  for (const own of guests) {
    if (own.item.one_time === false) {
      report.tests.push({name: own.item.label + ': one-use invitation replay', skipped: 'Operator supplied a reusable test invitation'});
      check(own.item.label + ': original authorized session still works', (await readPage(own.page, own.item.resource)).status === 200);
      continue;
    }
    const again = await context(), page = await again.newPage();
    await page.goto(own.item.access_url, {waitUntil: 'domcontentloaded'});
    await page.waitForFunction(() => document.querySelector('#status')?.textContent === 'Access Link invalid', null, {timeout: 30000});
    check(own.item.label + ': consumed invitation cannot be redeemed again', new URL(page.url()).origin === landing);
    check(own.item.label + ': original authorized session still works', (await readPage(own.page, own.item.resource)).status === 200);
    await again.close();
  }
  check('Real Browser NHP Relay traffic was observed', report.transport.relay_responses > 0);
  if (holdSeconds) {
    stage = 'authorized sessions during independent observation';
    report.active_observation = {started: new Date().toISOString(), successful_polls: 0, hold_seconds: holdSeconds};
    const end = Date.now() + holdSeconds * 1000;
    do {
      for (const own of guests) {
        const response = await readPage(own.page, own.item.resource);
        if (response.status !== 200 || response.body.id !== own.item.resource) throw new Error('Authorized session lost');
        report.active_observation.successful_polls++;
      }
      await new Promise(resolve => setTimeout(resolve, 5000));
    } while (Date.now() < end);
    report.active_observation.finished = new Date().toISOString();
    check('Both authorized sessions remained usable during observation', true);
  }
  report.passed = true;
})().catch(async error => {
  report.passed = false;
  report.failure = {stage, type: error.name, codes: [...new Set(error.message?.match(/net::ERR_[A-Z_]+|ECONN[A-Z]+|ETIMEDOUT|ENOTFOUND|EAI_AGAIN/g) || [])]};
  process.exitCode = 1;
  report.connection_diagnostics = await Promise.all(destinations.filter(item => item.handoff_attempted).map(tlsHealth));
}).finally(async () => {
  finishReport();
  if (browser) await Promise.race([browser.close().catch(() => {}), new Promise(resolve => setTimeout(resolve, 5000))]);
  clearTimeout(deadline);
  process.exit(process.exitCode || 0);
});
