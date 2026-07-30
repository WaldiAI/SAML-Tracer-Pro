import zlib from 'node:zlib';

let failures = 0;
const check = (name, condition, extra = '') => {
  if (condition) console.log('  ok   ' + name);
  else {
    failures++;
    console.log('  FAIL ' + name + (extra ? ' → ' + extra : ''));
  }
};

const on = {};
const event = (name) => ({ addListener: (fn) => (on[name] = fn) });
let connectHandler = null;
const badge = {};
let storageListener = null;

globalThis.chrome = {
  runtime: {
    getURL: (path = '') => 'chrome-extension://abc/' + path,
    onConnect: { addListener: (fn) => (connectHandler = fn) },
    onInstalled: { addListener: () => {} }
  },
  webRequest: {
    onBeforeRequest: event('beforeRequest'),
    onSendHeaders: event('sendHeaders'),
    onHeadersReceived: event('headersReceived'),
    onBeforeRedirect: event('beforeRedirect'),
    onCompleted: event('completed'),
    onErrorOccurred: event('error')
  },
  storage: {
    session: { get: async () => ({}), set: async () => {}, remove: async () => {} },
    local: { get: async (defaults) => ({ ...defaults }), set: async () => {}, remove: async () => {} },
    onChanged: { addListener: (fn) => (storageListener = fn) }
  },
  action: {
    setBadgeText: async ({ text }) => {
      badge.text = text;
    },
    setBadgeBackgroundColor: async () => {},
    onClicked: { addListener: () => {} }
  },
  windows: {
    create: async () => ({ id: 1 }),
    update: async () => {},
    onRemoved: { addListener: () => {} }
  }
};

await import('../background.js');
await new Promise((r) => setTimeout(r, 30));

console.log('\nListener registration');
for (const name of ['beforeRequest', 'sendHeaders', 'headersReceived', 'beforeRedirect', 'completed', 'error']) {
  check(`${name} listener registered`, typeof on[name] === 'function');
}

// connect a fake panel
const received = [];
const port = {
  name: 'tracer',
  onDisconnect: { addListener: () => {} },
  onMessage: { addListener: (fn) => (port._handler = fn) },
  postMessage: (m) => received.push(m)
};
connectHandler(port);
check('init sent on connect', received[0] && received[0].type === 'init', JSON.stringify(received[0] || {}).slice(0, 80));

const REQUEST_XML =
  '<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="req-1"/>';
const deflated = zlib.deflateRawSync(Buffer.from(REQUEST_XML, 'utf8')).toString('base64');

console.log('\nCapture is off until asked');
{
  const before = received.filter((m) => m.type === 'add').length;
  on.beforeRequest({ requestId: '800', url: 'https://example.com/quiet', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
  check('nothing captured before start', received.filter((m) => m.type === 'add').length === before);
  check('init reports capturing false', received[0].capturing === false, String(received[0].capturing));
  port._handler({ type: 'setCapturing', value: true });
  check('start broadcasts status', received.some((m) => m.type === 'capturing' && m.value === true && m.reason === 'started'));
}

console.log('\nRedirect-binding AuthnRequest');
on.beforeRequest({
  requestId: '900',
  url:
    'https://integrator-1238320.okta.com/app/sso/saml?SAMLRequest=' +
    encodeURIComponent(deflated) +
    '&RelayState=state-1&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=abc',
  method: 'GET',
  type: 'main_frame',
  tabId: 5,
  frameId: 0,
  timeStamp: Date.now(),
  initiator: 'https://sp.samltest.kmmr.jp'
});
const added = received.filter((m) => m.type === 'add').map((m) => m.entry);
check('entry added', added.length === 1);
check('saml detected', added[0].saml && added[0].saml.kind === 'SAMLRequest');
check('binding is Redirect', added[0].saml.binding === 'Redirect');
check('raw parameter url-decoded', added[0].saml.raw === deflated);
check('relay state captured', added[0].saml.relayState === 'state-1');
check('sigalg captured', /rsa-sha256$/.test(added[0].saml.sigAlg));
check('entry id includes hop', added[0].id === '900.0');
check('badge counts saml messages', badge.text === '1', String(badge.text));

const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url');
const payload = Buffer.from(JSON.stringify({ sub: 'x' })).toString('base64url');
const token = `${header}.${payload}.sig`;

on.sendHeaders({
  requestId: '900',
  url: 'https://integrator-1238320.okta.com/app/sso/saml',
  requestHeaders: [
    { name: 'Authorization', value: 'Bearer ' + token },
    { name: 'Cookie', value: 'sid=1' }
  ]
});
on.headersReceived({ requestId: '900', url: 'x', statusCode: 302, statusLine: 'HTTP/1.1 302 Found', responseHeaders: [{ name: 'Location', value: 'https://next' }] });
on.beforeRedirect({ requestId: '900', url: 'x', statusCode: 302, statusLine: 'HTTP/1.1 302 Found', responseHeaders: [], redirectUrl: 'https://next/step', timeStamp: Date.now() });
await new Promise((r) => setTimeout(r, 220));

const patches = received.filter((m) => m.type === 'patch').flatMap((m) => m.items);
const merged = Object.assign({}, ...patches.filter((p) => p.id === '900.0').map((p) => p.patch));
console.log('\nHeaders and redirect');
check('request headers patched', Array.isArray(merged.requestHeaders) && merged.requestHeaders.length === 2);
check('jwt spotted in Authorization header', merged.jwts && merged.jwts.includes(token), JSON.stringify(merged.jwts));
check('status patched', merged.status === 302);
check('redirect target patched', merged.redirectUrl === 'https://next/step');

console.log('\nRedirect hop gets its own entry');
on.beforeRequest({
  requestId: '900',
  url: 'https://next/step',
  method: 'GET',
  type: 'main_frame',
  tabId: 5,
  frameId: 0,
  timeStamp: Date.now()
});
const hop = received.filter((m) => m.type === 'add').map((m) => m.entry).at(-1);
check('second hop is a separate entry', hop.id === '900.1', hop.id);
check('hop counter increments', hop.hop === 1);

console.log('\nPOST-binding SAMLResponse');
const RESPONSE_XML = '<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"/>';
const responseB64 = Buffer.from(RESPONSE_XML, 'utf8').toString('base64');
on.beforeRequest({
  requestId: '901',
  url: 'https://sp.samltest.kmmr.jp/acs/',
  method: 'POST',
  type: 'main_frame',
  tabId: 5,
  frameId: 0,
  timeStamp: Date.now(),
  requestBody: { formData: { SAMLResponse: [responseB64], RelayState: ['rs'] } }
});
const post = received.filter((m) => m.type === 'add').map((m) => m.entry).at(-1);
check('post saml detected', post.saml.kind === 'SAMLResponse' && post.saml.binding === 'POST');
check('raw body text rebuilt', post.postText.startsWith('SAMLResponse='));
check('form data kept', Array.isArray(post.formData.SAMLResponse));

console.log('\nRaw (non-formData) body');
const rawBody = Buffer.from('SAMLResponse=' + encodeURIComponent(responseB64), 'utf8');
on.beforeRequest({
  requestId: '902',
  url: 'https://sp.samltest.kmmr.jp/acs/',
  method: 'POST',
  type: 'xmlhttprequest',
  tabId: 5,
  frameId: 0,
  timeStamp: Date.now(),
  requestBody: { raw: [{ bytes: rawBody.buffer.slice(rawBody.byteOffset, rawBody.byteOffset + rawBody.byteLength) }] }
});
const raw = received.filter((m) => m.type === 'add').map((m) => m.entry).at(-1);
check('raw body decoded to text', raw.postText.startsWith('SAMLResponse='));
check('saml found in raw body', raw.saml && raw.saml.kind === 'SAMLResponse');
check('raw value url-decoded back to base64', raw.saml.raw === responseB64);

console.log('\nErrors and 5xx');
on.completed({ requestId: '901', url: 'x', statusCode: 500, statusLine: 'HTTP/1.1 500 Internal Server Error', responseHeaders: [], timeStamp: Date.now(), fromCache: false, ip: '1.2.3.4' });
on.beforeRequest({ requestId: '903', url: 'https://www.eauditor.eu/IAM-lp/', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
on.error({ requestId: '903', url: 'https://www.eauditor.eu/IAM-lp/', error: 'net::ERR_BLOCKED_BY_RESPONSE', timeStamp: Date.now() });
await new Promise((r) => setTimeout(r, 220));
const all = received.filter((m) => m.type === 'patch').flatMap((m) => m.items);
const p901 = Object.assign({}, ...all.filter((p) => p.id === '901.0').map((p) => p.patch));
const p903 = Object.assign({}, ...all.filter((p) => p.id === '903.0').map((p) => p.patch));
check('500 recorded', p901.status === 500);
check('remote ip recorded', p901.ip === '1.2.3.4');
check('network error recorded', p903.error === 'net::ERR_BLOCKED_BY_RESPONSE');

console.log('\nOwn pages are skipped');
const before = received.filter((m) => m.type === 'add').length;
on.beforeRequest({ requestId: '904', url: 'chrome-extension://abc/panel/panel.html', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
on.beforeRequest({ requestId: '905', url: 'chrome://settings', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
check('extension and chrome:// urls ignored', received.filter((m) => m.type === 'add').length === before);

console.log('\nPause and clear');
port._handler({ type: 'setCapturing', value: false });
const countBefore = received.filter((m) => m.type === 'add').length;
on.beforeRequest({ requestId: '906', url: 'https://example.com/', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
check('paused capture drops events', received.filter((m) => m.type === 'add').length === countBefore);
port._handler({ type: 'setCapturing', value: true });
port._handler({ type: 'clear' });
check('cleared broadcast', received.some((m) => m.type === 'cleared'));
check('badge shows REC while listening with an empty capture', badge.text === 'REC', String(badge.text));
port._handler({ type: 'ping' });
check('heartbeat answered', received.some((m) => m.type === 'pong'));


console.log('\nCapture scope (data minimisation)');
{
  check('storage.onChanged listener registered', typeof storageListener === 'function');

  storageListener({ settings: { newValue: { captureDomains: ['*.okta.com', 'sp.samltest.kmmr.jp'] } } }, 'local');
  const before = received.filter((m) => m.type === 'add').length;
  on.beforeRequest({ requestId: '910', url: 'https://mbank.pl/account', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
  check('off-scope request never stored', received.filter((m) => m.type === 'add').length === before);

  on.beforeRequest({ requestId: '911', url: 'https://integrator-1238320.okta.com/app/sso/saml', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
  check('in-scope request still captured', received.filter((m) => m.type === 'add').length === before + 1);

  on.sendHeaders({ requestId: '910', url: 'https://mbank.pl/account', requestHeaders: [{ name: 'Cookie', value: 'session=secret' }] });
  await new Promise((r) => setTimeout(r, 200));
  const leaked = received.some((m) => JSON.stringify(m).includes('session=secret'));
  check('no headers leak in for a skipped request', !leaked);

  storageListener({ settings: { newValue: { captureDomains: [] } } }, 'local');
  const openAgain = received.filter((m) => m.type === 'add').length;
  on.beforeRequest({ requestId: '912', url: 'https://mbank.pl/account', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
  check('empty list means capture everything', received.filter((m) => m.type === 'add').length === openAgain + 1);
}

console.log('\nIdle capture toggle');
{
  storageListener({ settings: { newValue: { captureDomains: [], captureWhenClosed: false } } }, 'local');
  const before = received.filter((m) => m.type === 'add').length;
  on.beforeRequest({ requestId: '913', url: 'https://example.com/a', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
  check('with a panel connected it still captures', received.filter((m) => m.type === 'add').length === before + 1);
}


console.log('\nAuto-stop when the flow goes quiet');
{
  // 1 second of quiet is enough for the test
  storageListener({ settings: { newValue: { captureDomains: [], autoStop: true, autoStopIdleSeconds: 1, autoStopMaxSeconds: 300 } } }, 'local');
  port._handler({ type: 'setCapturing', value: true });

  const responseB64 = Buffer.from('<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r9"/>', 'utf8').toString('base64');
  on.beforeRequest({
    requestId: '920',
    url: 'https://sp.samltest.kmmr.jp/acs/',
    method: 'POST',
    type: 'main_frame',
    tabId: 5,
    frameId: 0,
    timeStamp: Date.now(),
    requestBody: { formData: { SAMLResponse: [responseB64] } }
  });

  await new Promise((r) => setTimeout(r, 700));
  check('still capturing while the navigation is in flight', received.filter((m) => m.type === 'capturing').at(-1).value === true);

  on.completed({ requestId: '920', url: 'https://sp.samltest.kmmr.jp/acs/', statusCode: 500, statusLine: 'HTTP/1.1 500', responseHeaders: [], timeStamp: Date.now() });
  await new Promise((r) => setTimeout(r, 1700));

  const last = received.filter((m) => m.type === 'capturing').at(-1);
  check('capture stopped by itself', last.value === false);
  check('reason is the quiet flow', last.reason === 'flow-complete', last.reason);
  check('run counters reported', last.session.samlCount === 1, JSON.stringify(last.session));

  const before = received.filter((m) => m.type === 'add').length;
  on.beforeRequest({ requestId: '921', url: 'https://example.com/after', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
  check('nothing captured after the auto-stop', received.filter((m) => m.type === 'add').length === before);
}

console.log('\nPost-assertion traffic is not cut off too early');
{
  storageListener({ settings: { newValue: { captureDomains: [], autoStop: true, autoStopIdleSeconds: 2, autoStopMaxSeconds: 300 } } }, 'local');
  port._handler({ type: 'setCapturing', value: true });
  const responseB64 = Buffer.from('<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r10"/>', 'utf8').toString('base64');
  on.beforeRequest({
    requestId: '930',
    url: 'https://sp.samltest.kmmr.jp/acs/',
    method: 'POST',
    type: 'main_frame',
    tabId: 5,
    frameId: 0,
    timeStamp: Date.now(),
    requestBody: { formData: { SAMLResponse: [responseB64] } }
  });
  on.completed({ requestId: '930', url: 'https://sp.samltest.kmmr.jp/acs/', statusCode: 302, statusLine: 'HTTP/1.1 302', responseHeaders: [], timeStamp: Date.now() });
  await new Promise((r) => setTimeout(r, 400));

  const before = received.filter((m) => m.type === 'add').length;
  on.beforeRequest({ requestId: '931', url: 'https://sp.samltest.kmmr.jp/app/home', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
  check('the redirect after the assertion is still captured', received.filter((m) => m.type === 'add').length === before + 1);
  on.completed({ requestId: '931', url: 'https://sp.samltest.kmmr.jp/app/home', statusCode: 200, statusLine: 'HTTP/1.1 200', responseHeaders: [], timeStamp: Date.now() });
  port._handler({ type: 'setCapturing', value: false });
}

console.log('\nHard time limit for a login that never completes');
{
  storageListener({ settings: { newValue: { captureDomains: [], autoStop: true, autoStopIdleSeconds: 60, autoStopMaxSeconds: 1 } } }, 'local');
  port._handler({ type: 'setCapturing', value: true });
  await new Promise((r) => setTimeout(r, 1500));
  const last = received.filter((m) => m.type === 'capturing').at(-1);
  check('stopped without ever seeing a response', last.value === false);
  check('reason is the time limit', last.reason === 'time-limit', last.reason);
}

console.log('\nAlways-on mode still available');
{
  storageListener({ settings: { newValue: { captureDomains: [], captureMode: 'always' } } }, 'local');
  await new Promise((r) => setTimeout(r, 50));
  const before = received.filter((m) => m.type === 'add').length;
  on.beforeRequest({ requestId: '940', url: 'https://example.com/always', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() });
  check('always-on captures without a start', received.filter((m) => m.type === 'add').length === before + 1);
  storageListener({ settings: { newValue: { captureDomains: [], captureMode: 'manual' } } }, 'local');
  await new Promise((r) => setTimeout(r, 50));
  check('switching back to manual stops capture', received.filter((m) => m.type === 'capturing').at(-1).value === false);
}


console.log('\nA hung navigation must not block the stop');
{
  storageListener({ settings: { newValue: { captureDomains: [], autoStop: true, autoStopIdleSeconds: 1, autoStopMaxSeconds: 300 } } }, 'local');
  port._handler({ type: 'setCapturing', value: true });
  // a main_frame request that never completes, timestamped well in the past
  on.beforeRequest({ requestId: '950', url: 'https://slow.example/hang', method: 'GET', type: 'main_frame', tabId: 5, frameId: 0, timeStamp: Date.now() - 60000 });
  const responseB64 = Buffer.from('<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r11"/>', 'utf8').toString('base64');
  on.beforeRequest({
    requestId: '951',
    url: 'https://sp.samltest.kmmr.jp/acs/',
    method: 'POST',
    type: 'xmlhttprequest',
    tabId: 5,
    frameId: 0,
    timeStamp: Date.now(),
    requestBody: { formData: { SAMLResponse: [responseB64] } }
  });
  await new Promise((r) => setTimeout(r, 1800));
  const last = received.filter((m) => m.type === 'capturing').at(-1);
  check('stale navigation ignored, capture stopped', last.value === false && last.reason === 'flow-complete', JSON.stringify({ v: last.value, r: last.reason }));
}


console.log('\nWS-Federation through the capture pipeline');
{
  storageListener({ settings: { newValue: { captureDomains: [], autoStop: false } } }, 'local');
  port._handler({ type: 'setCapturing', value: true });

  on.beforeRequest({
    requestId: '960',
    url: 'https://adfs.corp.example/adfs/ls/?wa=wsignin1.0&wtrealm=https%3A%2F%2Fsp.corp.example%2F&wctx=rm%3D0',
    method: 'GET',
    type: 'main_frame',
    tabId: 5,
    frameId: 0,
    timeStamp: Date.now()
  });
  const signin = received.filter((m) => m.type === 'add').map((m) => m.entry).at(-1);
  check('WS-Fed sign-in captured as a federation message', signin.saml && signin.saml.protocol === 'ws-fed', JSON.stringify(signin.saml));
  check('realm kept for the panel', signin.saml.extras.wtrealm === 'https://sp.corp.example/');

  on.beforeRequest({
    requestId: '961',
    url: 'https://sp.corp.example/signin-wsfed',
    method: 'POST',
    type: 'main_frame',
    tabId: 5,
    frameId: 0,
    timeStamp: Date.now(),
    requestBody: { formData: { wa: ['wsignin1.0'], wresult: ['<t:RequestSecurityTokenResponse xmlns:t="x"/>'], wctx: ['rm=0'] } }
  });
  const token = received.filter((m) => m.type === 'add').map((m) => m.entry).at(-1);
  check('WS-Fed token captured', token.saml.kind === 'WS-Fed token');
  check('token xml kept verbatim', token.saml.raw.startsWith('<t:RequestSecurityTokenResponse'));
  check('badge counts it like any federation message', badge.text !== '', String(badge.text));
  port._handler({ type: 'setCapturing', value: false });
}

console.log(failures ? `\n${failures} check(s) failed` : '\nAll background checks passed');
process.exit(failures ? 1 : 0);
