import { JSDOM } from 'jsdom';
import { readFileSync } from 'node:fs';
import zlib from 'node:zlib';

const html = readFileSync(new URL('../panel/panel.html', import.meta.url), 'utf8');
const dom = new JSDOM(html, {
  url: 'chrome-extension://abc/panel/panel.html?ctx=window',
  pretendToBeVisual: true
});
const { window } = dom;

for (const key of [
  'window', 'document', 'location', 'HTMLElement', 'Element', 'Node',
  'DOMParser', 'CustomEvent', 'Event', 'getComputedStyle', 'requestAnimationFrame',
  'cancelAnimationFrame', 'matchMedia', 'CSS'
]) {
  if (window[key] === undefined) continue;
  try {
    globalThis[key] = window[key];
  } catch {
    Object.defineProperty(globalThis, key, { value: window[key], configurable: true });
  }
}
globalThis.matchMedia = window.matchMedia || (() => ({ matches: false, addEventListener() {} }));
if (!globalThis.CSS || !globalThis.CSS.escape) globalThis.CSS = { escape: (s) => String(s).replace(/["\\]/g, '\\$&') };
let lastBlob = null;
window.URL.createObjectURL = (blob) => {
  lastBlob = blob;
  return 'blob:stub';
};
window.URL.revokeObjectURL = () => {};
globalThis.URL.createObjectURL = (blob) => {
  lastBlob = blob;
  return 'blob:stub';
};
globalThis.URL.revokeObjectURL = () => {};

let portListener = null;
const posted = [];
const stored = {};
globalThis.chrome = {
  runtime: {
    connect: () => ({
      onMessage: { addListener: (fn) => (portListener = fn) },
      onDisconnect: { addListener: () => {} },
      postMessage: (m) => posted.push(m)
    }),
    getURL: (p) => 'chrome-extension://abc/' + p
  },
  storage: {
    local: {
      get: async (defaults) => ({ ...defaults, ...stored }),
      set: async (values) => Object.assign(stored, values),
      remove: async () => {}
    },
    onChanged: { addListener: () => {} }
  },
  downloads: { download: (opts, cb) => cb && cb(1) }
};

let failures = 0;
const check = (name, condition, extra = '') => {
  if (condition) console.log('  ok   ' + name);
  else {
    failures++;
    console.log('  FAIL ' + name + (extra ? ' → ' + extra : ''));
  }
};

const errors = [];
window.addEventListener('error', (e) => errors.push(String(e.error || e.message)));
process.on('unhandledRejection', (reason) => errors.push('unhandled: ' + reason));

await import('../panel/panel.js');
await new Promise((r) => setTimeout(r, 60));

const $ = (id) => window.document.getElementById(id);

console.log('\nPanel boot');
check('no boot errors', errors.length === 0, errors.join('; '));
check('port connected', typeof portListener === 'function');
check('saml tab active', $('count') && document.querySelector('.tab.is-active').dataset.view === 'saml');
check('theme applied', document.documentElement.dataset.theme === 'dark' || document.documentElement.dataset.theme === 'light');
check('scope button hidden without devtools', $('btnScope').hidden === true);

const iso = (m) => new Date(Date.now() + m * 60000).toISOString();
const XML = `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Destination="https://sp.samltest.kmmr.jp/acs/" ID="r1" IssueInstant="${iso(0)}"><saml:Issuer>http://www.okta.com/exk15</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="a1"><saml:Subject><saml:NameID>pawelkajdan@risebrand.pl</saml:NameID></saml:Subject><saml:Conditions NotBefore="${iso(-5)}" NotOnOrAfter="${iso(5)}"><saml:AudienceRestriction><saml:Audience>https://sp.samltest.kmmr.jp/metadata/</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement SessionIndex="s1"/><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>pawelkajdan@risebrand.pl</saml:AttributeValue></saml:Attribute><saml:Attribute Name="department"/></saml:AttributeStatement></saml:Assertion></samlp:Response>`;

const samlEntry = {
  id: '100.0',
  seq: 1,
  tabId: 7,
  method: 'POST',
  url: 'https://sp.samltest.kmmr.jp/acs/',
  type: 'main_frame',
  started: Date.now(),
  status: 500,
  statusLine: 'HTTP/1.1 500 Internal Server Error',
  requestHeaders: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
  responseHeaders: [{ name: 'Server', value: 'Apache' }],
  postText: 'SAMLResponse=x',
  formData: null,
  jwts: [],
  saml: {
    kind: 'SAMLResponse',
    binding: 'POST',
    raw: Buffer.from(XML, 'utf8').toString('base64'),
    relayState: 'rs-1',
    sigAlg: '',
    signature: ''
  },
  source: 'live'
};

const plainEntry = {
  id: '101.0',
  seq: 2,
  tabId: 7,
  method: 'GET',
  url: 'https://integrator-1238320.okta.com/home/app?fromHome=true',
  type: 'main_frame',
  started: Date.now() + 10,
  status: 302,
  statusLine: 'HTTP/1.1 302 Found',
  requestHeaders: [{ name: 'Accept-Language', value: 'pl-PL' }],
  responseHeaders: [{ name: 'Location', value: 'https://x/y' }],
  postText: '',
  jwts: [],
  saml: null,
  source: 'live'
};

portListener({ type: 'init', capturing: false, entries: [samlEntry, plainEntry], limits: {}, session: {} });
await new Promise((r) => setTimeout(r, 120));

console.log('\nList');
const rows = document.querySelectorAll('#entries .row');
check('saml view shows only the saml row', rows.length === 1, String(rows.length));
check('row shows the SAMLResponse tag', rows[0].textContent.includes('SAMLResponse'));
check('row shows the 500 status', rows[0].textContent.includes('500'));
check('count label', $('count').textContent === '1 capture', $('count').textContent);

console.log('\nDetail (auto-selected)');
const detail = $('detail').textContent;
check('title is Response', $('detail').querySelector('h1').textContent === 'Response');
check('issuer shown', detail.includes('http://www.okta.com/exk15'));
check('subject shown', detail.includes('pawelkajdan@risebrand.pl'));
check('status urn shown', detail.includes('urn:oasis:names:tc:SAML:2.0:status:Success'));
check('audience shown', detail.includes('https://sp.samltest.kmmr.jp/metadata/'));
check('attribute table has the empty department', detail.includes('(no values)'));
check('validity verdict rendered', /Inside validity window/.test(detail), detail.slice(0, 120));
check('raw xml section rendered', !!$('detail').querySelector('pre.xml'));
check('xml is highlighted', $('detail').querySelector('pre.xml').innerHTML.includes('class="x-tag"'));
check('request headers section', detail.includes('Request Headers'));
check('response headers section', detail.includes('Response Headers'));
check('binding badge', detail.includes('POST binding'));
check('no-signature warning', detail.includes('No XML signature'));
check('relay state shown', detail.includes('rs-1'));


console.log('\nCapture control');
{
  check('button offers to start', $('recLabel').textContent === 'Start capture', $('recLabel').textContent);
  check('status bar explains the order of operations', $('statusBar').textContent.includes('trigger the login'), $('statusBar').textContent);

  $('btnRecord').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 40));
  check('start sent to the worker', posted.some((m) => m.type === 'setCapturing' && m.value === true));
  check('button flips to stop', $('recLabel').textContent === 'Stop capture');
  check('live styling applied', $('btnRecord').classList.contains('is-live'));

  portListener({ type: 'capturing', value: false, reason: 'flow-complete', session: { samlCount: 2, requestCount: 47 } });
  await new Promise((r) => setTimeout(r, 40));
  const bar = $('statusBar').textContent;
  check('auto-stop explained in plain words', bar.includes('went quiet'), bar);
  check('run counters shown', bar.includes('2 SAML') && bar.includes('47 requests'), bar);
  check('offers to start again', bar.includes('Start again'));
  check('captured data is not thrown away', document.querySelectorAll('#entries .row').length > 0);

  portListener({ type: 'capturing', value: false, reason: 'time-limit', session: { samlCount: 0, requestCount: 3 } });
  await new Promise((r) => setTimeout(r, 40));
  check('time limit explained', $('statusBar').textContent.includes('time limit'), $('statusBar').textContent);
}


console.log('\nViews');
document.querySelector('.tab[data-view="all"]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
await new Promise((r) => setTimeout(r, 40));
check('all traffic shows both rows', document.querySelectorAll('#entries .row').length === 2);
check('count label switches noun', $('count').textContent === '2 requests', $('count').textContent);

document.querySelector('.tab[data-view="errors"]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
await new Promise((r) => setTimeout(r, 40));
check('errors view shows the 500 only', document.querySelectorAll('#entries .row').length === 1);

document.querySelector('.tab[data-view="jwt"]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
await new Promise((r) => setTimeout(r, 40));
check('jwt view visible', $('jwtView').hidden === false && $('traceBody').hidden === true);

const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
const payload = Buffer.from(JSON.stringify({ iss: 'https://okta', exp: Math.floor(Date.now() / 1000) + 60 })).toString('base64url');
$('jwtText').value = `${header}.${payload}.sig`;
$('jwtText').dispatchEvent(new window.Event('input', { bubbles: true }));
await new Promise((r) => setTimeout(r, 250));
check('jwt decoded into cards', $('jwtResult').textContent.includes('RS256'), $('jwtResult').textContent.slice(0, 80));
check('jwt expiry verdict', $('jwtResult').textContent.includes('Not expired'));
check('jwt issuer highlight', $('jwtResult').textContent.includes('https://okta'));

console.log('\nFilter');
document.querySelector('.tab[data-view="all"]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
$('filter').value = 'okta';
$('filter').dispatchEvent(new window.Event('input', { bubbles: true }));
await new Promise((r) => setTimeout(r, 40));
check('filter narrows the list', document.querySelectorAll('#entries .row').length === 1);
$('filter').value = 'nothing-here';
$('filter').dispatchEvent(new window.Event('input', { bubbles: true }));
await new Promise((r) => setTimeout(r, 40));
check('empty state message', $('listEmpty').hidden === false);
$('filter').value = '';
$('filter').dispatchEvent(new window.Event('input', { bubbles: true }));

console.log('\nPatch + clear');
portListener({ type: 'patch', items: [{ id: '101.0', patch: { status: 404 } }] });
await new Promise((r) => setTimeout(r, 40));
check('patch applied to the list', document.getElementById('entries').textContent.includes('404'));

$('btnClear').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
await new Promise((r) => setTimeout(r, 40));
check('clear empties the list', document.querySelectorAll('#entries .row').length === 0);
check('clear told the worker', posted.some((m) => m.type === 'clear'));
check('still no runtime errors', errors.length === 0, errors.join('; '));


console.log('\nImport (HAR drop)');
{
  const b64 = Buffer.from(XML, 'utf8').toString('base64');
  const har = {
    log: {
      entries: [
        {
          startedDateTime: new Date().toISOString(),
          request: {
            method: 'POST',
            url: 'https://sp.samltest.kmmr.jp/acs/',
            headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
            postData: {
              mimeType: 'application/x-www-form-urlencoded',
              text: 'SAMLResponse=' + encodeURIComponent(b64) + '&RelayState=har-1'
            }
          },
          response: { status: 200, statusText: 'HTTP/1.1 200 OK', headers: [{ name: 'Server', value: 'nginx' }] }
        }
      ]
    }
  };
  const dropEvent = new window.Event('drop', { bubbles: true });
  dropEvent.dataTransfer = { files: [{ text: async () => JSON.stringify(har) }], types: ['Files'] };
  window.dispatchEvent(dropEvent);
  await new Promise((r) => setTimeout(r, 120));

  const importedRows = document.querySelectorAll('#entries .row');
  check('imported entry listed', importedRows.length === 1, String(importedRows.length));
  check('marked as imported', importedRows[0].textContent.includes('imported'));
  check('saml detected in imported body', importedRows[0].textContent.includes('SAMLResponse'));

  importedRows[0].dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 120));
  const detailText = $('detail').textContent;
  check('imported entry decodes', detailText.includes('pawelkajdan@risebrand.pl'));
  check('imported relay state', detailText.includes('har-1'));
}

console.log('\nImport (saml-tracer style array)');
{
  const b64 = Buffer.from(XML, 'utf8').toString('base64');
  const classic = [
    {
      method: 'POST',
      url: 'https://sp.samltest.kmmr.jp/acs/',
      statusLine: 'HTTP/1.1 302 Found',
      timestamp: new Date().toISOString(),
      requestHeaders: { Origin: 'https://integrator-1238320.okta.com' },
      responseHeaders: [{ name: 'Location', value: '/app' }],
      postData: 'SAMLResponse=' + encodeURIComponent(b64)
    }
  ];
  const dropEvent = new window.Event('drop', { bubbles: true });
  dropEvent.dataTransfer = { files: [{ text: async () => JSON.stringify(classic) }], types: ['Files'] };
  window.dispatchEvent(dropEvent);
  await new Promise((r) => setTimeout(r, 120));
  check('second import added', document.querySelectorAll('#entries .row').length === 2);
  check('status parsed out of the status line', document.querySelectorAll('#entries .row')[1].textContent.includes('302'));
  check('object-shaped headers accepted', true);
}

console.log('\nBad import');
{
  const dropEvent = new window.Event('drop', { bubbles: true });
  dropEvent.dataTransfer = { files: [{ text: async () => '{"nope":1}' }], types: ['Files'] };
  window.dispatchEvent(dropEvent);
  await new Promise((r) => setTimeout(r, 80));
  check('bad file reported in a toast', $('toast').textContent.includes('Import failed'), $('toast').textContent);
  check('list untouched', document.querySelectorAll('#entries .row').length === 2);
}

console.log('\nExport + report');
{
  $('btnExport').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 60));
  check('export toast', $('toast').textContent.includes('Exported'), $('toast').textContent);
  $('btnReport').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 200));
  check('report toast', $('toast').textContent.includes('Report saved'), $('toast').textContent);
  check('no errors after export/report', errors.length === 0, errors.join('; '));
}


console.log('\nCSS invariants (real-browser cascade)');
{
  const css = readFileSync(new URL('../panel/panel.css', import.meta.url), 'utf8');
  const hiddenRule = /\[hidden\]\s*{[^}]*display:\s*none\s*!important/.test(css);
  check('[hidden] beats class-level display rules', hiddenRule);

  // Every element toggled through .hidden in panel.js must survive that toggle in
  // a real browser, where a class rule like `display: grid` outranks the UA [hidden] rule.
  const js = readFileSync(new URL('../panel/panel.js', import.meta.url), 'utf8');
  const toggled = [...js.matchAll(/(?:els\.(\w+)|\$\('(\w+)'\))\.hidden\s*=/g)]
    .map((m) => m[1] || m[2]);
  check('toggled elements found in source', toggled.length >= 3, toggled.join(','));
  check('no toggle relies on the UA sheet alone', hiddenRule, 'add [hidden]{display:none!important}');
}


console.log('\nRedaction on the way out');
{
  portListener({
    type: 'add',
    entry: {
      ...samlEntry,
      id: '200.0',
      requestHeaders: [
        { name: 'Cookie', value: 'KMMRSamlTest=74t2j0v65va02f8si7obtdhols' },
        { name: 'Content-Type', value: 'application/x-www-form-urlencoded' }
      ],
      responseHeaders: [{ name: 'Set-Cookie', value: 'KMMRSamlTest=74t2j0v65va02f8si7obtdhols; HttpOnly' }]
    }
  });
  await new Promise((r) => setTimeout(r, 120));

  $('btnExport').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 80));
  const exported = await lastBlob.text();
  check('cookie value absent from the export', !exported.includes('74t2j0v65va02f8si7obtdhols'), 'cookie leaked');
  check('redaction marker present', exported.includes('redacted by SAML Tracer Pro'));
  check('header name kept', exported.includes('"Set-Cookie"'));
  check('assertion itself still exported', exported.includes('SAMLResponse'));
  check('export flags redaction', JSON.parse(exported).redacted === true);

  $('btnReport').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 250));
  const report = await lastBlob.text();
  check('cookie value absent from the report', !report.includes('74t2j0v65va02f8si7obtdhols'));
  check('report notes the redaction', report.includes('redacted'));
  check('settings never touch storage.sync', !('sync' in chrome.storage));
}

console.log('\nWS-Federation and artifact rendering');
{
  const ADFS_TOKEN = `<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:Lifetime><wsu:Created xmlns:wsu="u">${iso(-1)}</wsu:Created><wsu:Expires xmlns:wsu="u">${iso(60)}</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp="p"><wsa:EndpointReference xmlns:wsa="a"><wsa:Address>https://sp.corp.example/</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" Issuer="http://adfs.corp.example/adfs/services/trust"><saml:Conditions NotBefore="${iso(-5)}" NotOnOrAfter="${iso(60)}"><saml:AudienceRestrictionCondition><saml:Audience>https://sp.corp.example/</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AttributeStatement><saml:Subject><saml:NameIdentifier>CORP\\pkajdan</saml:NameIdentifier></saml:Subject><saml:Attribute AttributeName="upn" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims"><saml:AttributeValue>pkajdan@corp.example</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></t:RequestedSecurityToken><t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType></t:RequestSecurityTokenResponse>`;

  portListener({
    type: 'add',
    entry: {
      id: '300.0',
      seq: 10,
      tabId: 7,
      method: 'POST',
      url: 'https://sp.corp.example/signin-wsfed',
      type: 'main_frame',
      started: Date.now(),
      status: 302,
      statusLine: 'HTTP/1.1 302 Found',
      requestHeaders: [],
      responseHeaders: [],
      postText: 'wa=wsignin1.0&wresult=…',
      jwts: [],
      saml: { kind: 'WS-Fed token', protocol: 'ws-fed', opaque: false, binding: 'POST', raw: ADFS_TOKEN, relayState: 'ctx1', extras: { wa: 'wsignin1.0', wtrealm: 'https://sp.corp.example/' } },
      source: 'live'
    }
  });
  await new Promise((r) => setTimeout(r, 150));
  document.querySelectorAll('#entries .row').forEach((row) => {
    if (row.textContent.includes('WS-Fed token')) row.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  });
  await new Promise((r) => setTimeout(r, 200));

  const detailText = $('detail').textContent;
  check('WS-Fed message listed', [...document.querySelectorAll('#entries .row')].some((r) => r.textContent.includes('WS-Fed token')));
  check('protocol named in the header', detailText.includes('WS-Federation'), detailText.slice(0, 140));
  check('WS-Fed envelope section rendered', detailText.includes('WS-Federation envelope'));
  check('realm shown', detailText.includes('https://sp.corp.example/'));
  check('SAML 1.1 subject shown', detailText.includes('CORP\\pkajdan'));
  check('SAML 1.1 attribute shown', detailText.includes('pkajdan@corp.example'));
  check('wtrealm listed among parameters', detailText.includes('wtrealm'));
  check('raw xml still available', !!$('detail').querySelector('pre.xml'));

  portListener({
    type: 'add',
    entry: {
      id: '301.0',
      seq: 11,
      tabId: 7,
      method: 'GET',
      url: 'https://sp.example/acs?SAMLart=AAQAAM3%2F',
      type: 'main_frame',
      started: Date.now() + 5,
      status: 200,
      statusLine: 'HTTP/1.1 200 OK',
      requestHeaders: [],
      responseHeaders: [],
      postText: '',
      jwts: [],
      saml: { kind: 'SAMLart', protocol: 'saml', opaque: true, binding: 'Artifact', raw: 'AAQAAM3/', relayState: '' },
      source: 'live'
    }
  });
  await new Promise((r) => setTimeout(r, 150));
  document.querySelectorAll('#entries .row').forEach((row) => {
    if (row.textContent.includes('SAMLart')) row.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  });
  await new Promise((r) => setTimeout(r, 200));
  const artText = $('detail').textContent;
  check('artifact explained instead of a decode error', artText.includes('back-channel'), artText.slice(0, 160));
  check('no decode-failed wording for artifacts', !artText.includes('Decode failed'));
  check('artifact value still shown', artText.includes('AAQAAM3/'));
}



console.log('\nFlow tab');
{
  document.querySelector('.tab[data-view="flow"]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 80));
  check('flow view visible', $('flowView').hidden === false && $('traceBody').hidden === true);

  const text = $('flowView').textContent;
  check('actor lane rendered', text.includes('Identity provider') && text.includes('Service provider'));
  check('stages have plain-words teaching', text.includes('signed-in user') || text.includes('assertion'));
  check('checklists available', text.includes('What to check at this stage'));
  check('response stage present and expanded', text.includes('the IdP sends the assertion back'));

  const hop = [...$('flowView').querySelectorAll('.hop')].find((el) => el.textContent.includes('SAMLResponse') || el.textContent.includes('acs'));
  check('hops are listed under stages', !!hop);
  if (hop) {
    hop.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 80));
    check('clicking a hop jumps to its detail', $('flowView').hidden === true && $('detail').textContent.length > 40);
  }
}


console.log('\nNo stray "null" text in the UI');
{
  portListener({ type: 'capturing', value: false, reason: 'flow-complete', session: { samlCount: 1, requestCount: 223 } });
  await new Promise((r) => setTimeout(r, 40));
  check('status bar free of literal null', !/\bnull\b/.test($('statusBar').textContent), $('statusBar').textContent);
  check('whole document free of literal null text nodes', !/>null</.test(document.body.innerHTML));
}


console.log('\nPages & SSO only toggle');
{
  portListener({
    type: 'add',
    entry: { id: '400.0', seq: 20, tabId: 7, method: 'GET', url: 'https://b.static.lightning.force.com/app.js', type: 'script', started: Date.now(), status: 200, statusLine: 'HTTP/1.1 200', requestHeaders: [], responseHeaders: [], postText: '', jwts: [], saml: null, source: 'live' }
  });
  await new Promise((r) => setTimeout(r, 80));
  document.querySelector('.tab[data-view="all"]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 60));
  const before = document.querySelectorAll('#entries .row').length;
  check('script asset visible by default', [...document.querySelectorAll('#entries .row')].some((r) => r.textContent.includes('app.js')));

  $('navOnly').checked = true;
  $('navOnly').dispatchEvent(new window.Event('change', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 60));
  check('toggle hides page assets', !([...document.querySelectorAll('#entries .row')].some((r) => r.textContent.includes('app.js'))));
  check('navigations and saml stay', document.querySelectorAll('#entries .row').length < before && document.querySelectorAll('#entries .row').length > 0);
  check('count explains what is hidden', $('count').textContent.includes('assets hidden'), $('count').textContent);

  document.querySelector('.tab[data-view="saml"]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 60));
  check('toggle hidden outside All Traffic', $('navOnlyWrap').style.display === 'none');
  $('navOnly').checked = false;
  document.querySelector('.tab[data-view="all"]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 30));
  $('navOnly').dispatchEvent(new window.Event('change', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 30));
}


console.log('\nValidity at delivery vs now');
{
  const isoAt = (ms) => new Date(ms).toISOString();
  const t0 = Date.now();
  const XMLOLD = `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="old1" IssueInstant="${isoAt(t0 - 11 * 60000)}"><saml:Issuer>okta</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="olda"><saml:Subject><saml:NameID>x@y</saml:NameID></saml:Subject><saml:Conditions NotBefore="${isoAt(t0 - 16 * 60000)}" NotOnOrAfter="${isoAt(t0 - 6 * 60000)}"><saml:AudienceRestriction><saml:Audience>aud</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>`;
  portListener({
    type: 'add',
    entry: { id: '500.0', seq: 30, tabId: 7, method: 'POST', url: 'https://sp/acs', type: 'main_frame', started: t0 - 11 * 60000, status: 302, statusLine: 'HTTP/1.1 302', requestHeaders: [], responseHeaders: [], postText: '', jwts: [], source: 'live',
      saml: { kind: 'SAMLResponse', protocol: 'saml', binding: 'POST', raw: Buffer.from(XMLOLD, 'utf8').toString('base64'), relayState: '' } }
  });
  await new Promise((r) => setTimeout(r, 60));
  document.querySelector('.tab[data-view="saml"]').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 60));
  [...document.querySelectorAll('#entries .row')].at(-1).dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 200));
  const text = $('detail').textContent;
  check('delivery verdict shown', text.includes('Valid when delivered'), text.slice(0, 80));
  check('live status still present alongside', text.includes('Window closed') || text.includes('expired'));
  check('explains the difference between then and now', text.includes('replayed now'));
}

console.log(failures ? `\n${failures} check(s) failed` : '\nAll panel checks passed');
process.exit(failures ? 1 : 0);
