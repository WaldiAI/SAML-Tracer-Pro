/**
 * Panel controller. Runs both as a DevTools panel (?ctx=devtools) and as a
 * standalone window (?ctx=window). Holds the authoritative copy of the capture
 * for as long as it is open, so a service-worker restart is invisible here.
 */

import * as SAML from '../lib/saml.js';
import { decodeJwt, humanDuration } from '../lib/jwt.js';
import { buildHtmlReport } from '../lib/report.js';
import { buildFlow, stageInfo, orderedStagesIn } from '../lib/flow.js';
import {
  hostOf,
  shortUrl,
  redactHeaders,
  clockTime,
  fullTime,
  isoToLocal,
  statusClass,
  isErrorEntry,
  hostMatches,
  samlFromUrl,
  samlFromForm,
  parseUrlEncoded,
  headerValue
} from '../lib/util.js';

const CTX = new URLSearchParams(location.search).get('ctx') === 'devtools' ? 'devtools' : 'window';
const inspectedTabId =
  CTX === 'devtools' && typeof chrome !== 'undefined' && chrome.devtools
    ? chrome.devtools.inspectedWindow.tabId
    : null;

const DEFAULTS = {
  highlightDomains: [],
  captureDomains: [],
  captureMode: 'manual',
  autoStop: true,
  autoStopIdleSeconds: 15,
  autoStopMaxSeconds: 300,
  captureWhenClosed: true,
  redactSensitive: true,
  navOnly: false,
  pins: [],
  theme: 'auto',
  maxEntries: 1500,
  wrapXml: true,
  autoSelect: true,
  scopeThisTab: CTX === 'devtools'
};

const state = {
  entries: [],
  byId: new Map(),
  decoded: new Map(),
  view: 'saml',
  filter: '',
  selectedId: null,
  stickToLatest: true,
  capturing: false,
  runReason: '',
  run: { samlCount: 0, requestCount: 0, startedAt: 0 },
  settings: { ...DEFAULTS },
  importSeq: -1,
  renderToken: 0,
  tickers: []
};

const $ = (id) => document.getElementById(id);
const els = {
  count: $('count'),
  entries: $('entries'),
  listEmpty: $('listEmpty'),
  listPane: $('listPane'),
  splitter: $('splitter'),
  detail: $('detail'),
  filter: $('filter'),
  traceBody: $('traceBody'),
  flowView: $('flowView'),
  jwtView: $('jwtView'),
  jwtText: $('jwtText'),
  jwtResult: $('jwtResult'),
  jwtFound: $('jwtFound'),
  jwtFoundNote: $('jwtFoundNote'),
  dropOverlay: $('dropOverlay'),
  toast: $('toast'),
  settings: $('settings'),
  fileInput: $('fileInput'),
  btnRecord: $('btnRecord'),
  recLabel: $('recLabel'),
  statusBar: $('statusBar'),
  btnScope: $('btnScope')
};

/* ------------------------------------------------------------------- markup */

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2).toLowerCase(), value);
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(3)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return node;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
function icon(name) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', '#' + name);
  svg.append(use);
  return svg;
}

function toast(message) {
  els.toast.textContent = message;
  els.toast.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => {
    els.toast.hidden = true;
  }, 2200);
}

async function copyText(text, label = 'Copied') {
  const value = String(text ?? '');
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const area = h('textarea', { style: 'position:fixed;opacity:0' });
    area.value = value;
    document.body.append(area);
    area.select();
    document.execCommand('copy');
    area.remove();
  }
  toast(label);
}

function copyButton(text, label = 'Copy') {
  return h(
    'button',
    { class: 'btn-mini', title: label, onclick: () => copyText(text) },
    icon('i-copy')
  );
}

function pinButton(pinKey) {
  const pinned = state.settings.pins.some((p) => p.toLowerCase() === pinKey.toLowerCase());
  return h(
    'button',
    {
      class: 'btn-mini' + (pinned ? ' is-pinned' : ''),
      title: pinned ? `Unpin ${pinKey}` : `Pin ${pinKey} to the info bar`,
      onclick: () => togglePin(pinKey)
    },
    icon('i-pin')
  );
}

/* ------------------------------------------------------------------ settings */

// Local, never sync: highlighted domains and pinned field names describe the
// systems being debugged, so they must not travel through a Google account.
const storage = (chrome.storage && chrome.storage.local) || null;

async function loadSettings() {
  if (!storage) return;
  try {
    const saved = await storage.get({ settings: null });
    if (saved.settings) {
      state.settings = { ...DEFAULTS, ...saved.settings };
    } else if (chrome.storage.sync) {
      // one-off migration away from synced settings, then wipe the synced copy
      const legacy = await chrome.storage.sync.get({ settings: null });
      if (legacy.settings) {
        state.settings = { ...DEFAULTS, ...legacy.settings };
        await storage.set({ settings: state.settings });
        await chrome.storage.sync.remove('settings');
      }
    }
  } catch {
    /* keep defaults */
  }
  applyTheme();
}

async function saveSettings() {
  if (!storage) return;
  try {
    await storage.set({ settings: state.settings });
  } catch {
    toast('Settings could not be saved.');
  }
}

function applyTheme() {
  let theme = state.settings.theme;
  if (theme === 'auto') {
    const devtoolsTheme = chrome.devtools && chrome.devtools.panels && chrome.devtools.panels.themeName;
    if (devtoolsTheme) theme = devtoolsTheme === 'dark' ? 'dark' : 'light';
    else theme = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  document.documentElement.dataset.theme = theme;
}

function togglePin(pinKey) {
  const pins = state.settings.pins;
  const index = pins.findIndex((p) => p.toLowerCase() === pinKey.toLowerCase());
  if (index >= 0) pins.splice(index, 1);
  else pins.push(pinKey);
  saveSettings();
  renderDetail();
}

function isHighlighted(url) {
  const host = hostOf(url);
  return state.settings.highlightDomains.some((pattern) => hostMatches(pattern, host));
}

/* ------------------------------------------------------------ service worker */

let port = null;

function connect() {
  port = chrome.runtime.connect({ name: 'tracer' });
  port.onMessage.addListener(onPortMessage);
  port.onDisconnect.addListener(() => {
    port = null;
    setTimeout(connect, 600);
  });
}

setInterval(() => {
  try {
    if (port) port.postMessage({ type: 'ping' });
  } catch {
    /* reconnect handles it */
  }
}, 20000);

function onPortMessage(message) {
  switch (message.type) {
    case 'init':
      state.capturing = message.capturing;
      if (message.session) state.run = { ...state.run, ...message.session };
      if (message.session && message.session.reason) state.runReason = message.session.reason;
      for (const entry of message.entries) mergeEntry(entry);
      sortEntries();
      renderCaptureUi();
      if (!state.selectedId && state.settings.autoSelect) {
        const latestSaml = [...state.entries].reverse().find((entry) => entry.saml);
        if (latestSaml) {
          state.selectedId = latestSaml.id;
          scheduleDetail();
        }
      }
      scheduleList();
      break;
    case 'add':
      mergeEntry(message.entry);
      maybeAutoSelect(message.entry);
      if (state.view === 'flow') scheduleFlow();
      if (state.capturing) {
        state.run.requestCount++;
        if (message.entry.saml) state.run.samlCount++;
        renderCaptureUi();
      }
      scheduleList();
      break;
    case 'patch':
      for (const item of message.items) {
        const entry = state.byId.get(item.id);
        if (!entry) continue;
        Object.assign(entry, item.patch);
        if (entry.id === state.selectedId) scheduleDetail();
      }
      scheduleList();
      break;
    case 'cleared':
      state.entries = state.entries.filter((e) => e.source === 'import');
      rebuildIndex();
      state.selectedId = null;
      state.decoded.clear();
      renderList();
      renderDetail();
      break;
    case 'capturing':
      state.capturing = message.value;
      state.runReason = message.reason || '';
      if (message.session) state.run = { ...state.run, ...message.session };
      renderCaptureUi();
      break;
  }
}

function mergeEntry(entry) {
  const existing = state.byId.get(entry.id);
  if (existing) {
    Object.assign(existing, entry);
    return existing;
  }
  state.byId.set(entry.id, entry);
  state.entries.push(entry);
  if (state.entries.length > state.settings.maxEntries) {
    const removed = state.entries.splice(0, state.entries.length - state.settings.maxEntries);
    for (const item of removed) {
      state.byId.delete(item.id);
      state.decoded.delete(item.id);
    }
  }
  return entry;
}

function rebuildIndex() {
  state.byId = new Map(state.entries.map((e) => [e.id, e]));
}

function sortEntries() {
  state.entries.sort((a, b) => (a.started || 0) - (b.started || 0) || (a.seq || 0) - (b.seq || 0));
}

function maybeAutoSelect(entry) {
  if (!state.settings.autoSelect || !entry.saml) return;
  if (state.view !== 'saml' && state.view !== 'all') return;
  if (state.selectedId && !state.stickToLatest) return;
  state.selectedId = entry.id;
  scheduleDetail();
}

/* ---------------------------------------------------------------- list view */

function isPageOrSso(entry) {
  return entry.saml || entry.type === 'main_frame' || entry.type === 'sub_frame';
}

function passesFilter(entry) {
  if (state.view === 'saml' && !entry.saml) return false;
  if (state.view === 'errors' && !isErrorEntry(entry)) return false;
  if (state.view === 'all' && state.settings.navOnly && !isPageOrSso(entry)) return false;
  if (
    state.settings.scopeThisTab &&
    inspectedTabId != null &&
    entry.source !== 'import' &&
    entry.tabId !== inspectedTabId
  ) {
    return false;
  }
  const query = state.filter.trim().toLowerCase();
  if (!query) return true;
  const haystack = [
    entry.url,
    entry.method,
    entry.status || '',
    entry.error || '',
    entry.type || '',
    entry.saml ? entry.saml.kind : ''
  ]
    .join(' ')
    .toLowerCase();
  return query.split(/\s+/).every((part) => haystack.includes(part));
}

function visibleEntries() {
  return state.entries.filter(passesFilter);
}

let listTimer = null;
function scheduleList() {
  if (listTimer) return;
  listTimer = requestAnimationFrame(() => {
    listTimer = null;
    renderList();
  });
}

function renderList() {
  const list = visibleEntries();
  const container = els.entries;
  const atBottom = container.scrollTop + container.clientHeight >= container.scrollHeight - 30;

  const fragment = document.createDocumentFragment();
  for (const entry of list.slice(-800)) fragment.append(rowFor(entry));
  container.replaceChildren(fragment);

  els.listEmpty.hidden = list.length > 0;
  if (list.length === 0) {
    els.listEmpty.textContent = state.filter
      ? 'No requests match this filter.'
      : state.view === 'saml'
        ? 'No SAML messages yet. Start a login and the SSO hops show up here.'
        : state.view === 'errors'
          ? 'No 4xx, 5xx or network errors captured.'
          : 'Nothing captured yet.';
  }

  const noun = state.view === 'saml' ? 'capture' : state.view === 'errors' ? 'error' : 'request';
  const hidden = state.view === 'all' && state.settings.navOnly ? state.entries.length - list.length : 0;
  els.count.textContent =
    `${list.length} ${noun}${list.length === 1 ? '' : 's'}` + (hidden > 0 ? ` (+${hidden} assets hidden)` : '');
  $('navOnlyWrap').style.display = state.view === 'all' ? '' : 'none';
  $('navOnly').checked = !!state.settings.navOnly;
  if (atBottom) container.scrollTop = container.scrollHeight;
}

function rowFor(entry) {
  const selected = entry.id === state.selectedId;
  const methodClass = entry.method === 'POST' ? 'm-post' : entry.method === 'GET' ? '' : 'm-other';
  const statusText = entry.error ? 'ERR' : entry.status ? String(entry.status) : '…';

  const top = h(
    'div',
    { class: 'row-top' },
    h('span', { class: 'method ' + methodClass, text: entry.method || '?' }),
    h('span', { class: 'pill ' + statusClass(entry), text: statusText }),
    entry.saml
      ? h('span', {
          class: 'tag' + (entry.saml.kind === 'SAMLRequest' ? ' tag-req' : ''),
          text: entry.saml.kind
        })
      : null,
    entry.source === 'import' ? h('span', { class: 'tag tag-imported', text: 'imported' }) : null,
    h('span', { class: 'row-time', text: clockTime(entry.started) })
  );

  const urlLine = h('div', { class: 'row-url' });
  if (isHighlighted(entry.url)) {
    urlLine.append(h('span', { class: 'row-star', title: 'Highlighted domain' }, icon('i-star')), ' ');
  }
  urlLine.append(entry.url);

  return h(
    'li',
    {
      class:
        'row' +
        (selected ? ' is-selected' : '') +
        (entry.saml ? ' is-saml' : '') +
        (isErrorEntry(entry) ? ' has-error' : ''),
      'data-id': entry.id,
      onclick: () => selectEntry(entry.id, true)
    },
    top,
    urlLine
  );
}

function selectEntry(id, manual) {
  state.selectedId = id;
  if (manual) {
    const list = visibleEntries();
    state.stickToLatest = list.length > 0 && list[list.length - 1].id === id;
  }
  renderList();
  renderDetail();
}

function moveSelection(delta) {
  const list = visibleEntries();
  if (!list.length) return;
  const index = list.findIndex((e) => e.id === state.selectedId);
  const next = list[Math.min(Math.max((index < 0 ? 0 : index) + delta, 0), list.length - 1)];
  if (next) {
    selectEntry(next.id, true);
    const node = els.entries.querySelector(`[data-id="${CSS.escape(next.id)}"]`);
    if (node) node.scrollIntoView({ block: 'nearest' });
  }
}

/* ------------------------------------------------------------------- decode */

async function ensureDecoded(entry) {
  if (!entry || !entry.saml) return null;
  if (state.decoded.has(entry.id)) return state.decoded.get(entry.id);
  if (!entry.saml.raw || entry.saml.opaque) {
    let note;
    if (entry.saml.truncated) {
      note = 'The encoded message was dropped to stay inside the storage quota.';
    } else if (entry.saml.kind === 'SAMLart') {
      note =
        'Artifact binding: the SP fetches the assertion back-channel over SOAP, so the browser never carries it. The artifact below is only a reference.';
    } else if (entry.saml.protocol === 'ws-fed') {
      note = 'WS-Federation request — the parameters below are the whole message, no token is present yet.';
    } else {
      note = 'This message carries no encoded payload.';
    }
    const record = { note };
    state.decoded.set(entry.id, record);
    return record;
  }
  let record;
  try {
    const { xml, encoding, bytes } = await SAML.decodeSamlMessage(entry.saml.raw);
    record = { xml, encoding, bytes, pretty: SAML.formatXml(xml), model: SAML.parseSaml(xml) };
  } catch (error) {
    record = { error: error.message };
  }
  state.decoded.set(entry.id, record);
  return record;
}

/* ------------------------------------------------------------- detail view */

let detailTimer = null;
let flowTimer = null;
function scheduleFlow() {
  if (flowTimer) return;
  flowTimer = setTimeout(() => {
    flowTimer = null;
    if (state.view === 'flow') renderFlow();
  }, 300);
}

function scheduleDetail() {
  if (detailTimer) return;
  detailTimer = requestAnimationFrame(() => {
    detailTimer = null;
    renderDetail();
  });
}

async function renderDetail() {
  const token = ++state.renderToken;
  state.tickers = [];
  const entry = state.byId.get(state.selectedId);
  if (!entry) {
    els.detail.replaceChildren(h('div', { class: 'placeholder', text: 'Select a request on the left.' }));
    return;
  }
  const decoded = entry.saml ? await ensureDecoded(entry) : null;
  if (token !== state.renderToken) return;

  const nodes = [];
  nodes.push(detailHead(entry, decoded));
  const bar = infoBar(entry, decoded);
  if (bar) nodes.push(bar);

  if (entry.saml) nodes.push(...samlSections(entry, decoded));
  else nodes.push(...genericSections(entry));

  nodes.push(headersSection('Request Headers', entry.requestHeaders));
  nodes.push(headersSection('Response Headers', entry.responseHeaders));

  if (entry.saml && decoded && decoded.xml) nodes.push(rawXmlSection(entry, decoded));

  els.detail.replaceChildren(...nodes.filter(Boolean));
  els.detail.scrollTop = 0;
}

function detailHead(entry, decoded) {
  const title = entry.saml
    ? entry.saml.kind === 'SAMLResponse'
      ? 'Response'
      : entry.saml.kind === 'SAMLRequest'
        ? 'Request'
        : entry.saml.kind
    : `${entry.method} ${hostOf(entry.url)}`;

  const decodedModel = decoded && decoded.model;

  const sub = [
    entry.saml ? `${protocolLabel(entry, decodedModel)} · ${entry.saml.binding} binding` : entry.type,
    entry.status ? `HTTP ${entry.status}` : entry.error || '',
    fullTime(entry.started)
  ]
    .filter(Boolean)
    .join(' · ');

  return h(
    'div',
    { class: 'detail-head' },
    h('h1', { text: title }),
    h('span', { class: 'sub', text: sub }),
    h(
      'div',
      { class: 'head-actions' },
      h('button', { class: 'btn', onclick: () => copyText(entryAsText(entry, decoded), 'Entry copied as text') }, 'Copy'),
      entry.saml && decoded && decoded.xml
        ? h(
            'button',
            {
              class: 'btn',
              onclick: () => downloadBlob(new Blob([decoded.pretty], { type: 'application/xml' }), `${entry.saml.kind}-${stamp()}.xml`)
            },
            'Save XML'
          )
        : null
    )
  );
}

function kvList(rows) {
  const dl = h('dl', { class: 'kv' });
  for (const row of rows) {
    if (!row) continue;
    const [label, value, options = {}] = row;
    const isEmpty = value === '' || value === null || value === undefined;
    if (isEmpty && !options.always) continue;
    dl.append(h('dt', { text: label }));
    const dd = h('dd');
    if (isEmpty) dd.append(h('span', { class: 'empty', text: '(empty)' }));
    else if (value.nodeType) dd.append(value);
    else dd.textContent = String(value);
    dl.append(dd);
    const copySource = options.copyText ?? (value && value.nodeType ? null : value);
    dl.append(
      h(
        'div',
        { class: 'act' },
        options.pin ? pinButton(options.pin) : null,
        copySource ? copyButton(copySource) : null
      )
    );
  }
  return dl;
}

function section(title, count, ...children) {
  const heading = h('h2', {}, title);
  if (count !== null && count !== undefined) heading.append(h('span', { class: 'n', text: ` (${count})` }));
  return h('section', { class: 'section' }, heading, ...children);
}

function samlSections(entry, decoded) {
  const out = [];
  if (decoded && decoded.note && !decoded.model) {
    out.push(
      h('div', { class: 'badges' }, h('span', { class: 'badge b-info', text: protocolLabel(entry) })),
      section('Nothing to decode', null, h('p', { class: 'hint', text: decoded.note })),
      parametersSection(entry)
    );
    return out;
  }
  if (!decoded || decoded.error || !decoded.model || !decoded.model.ok) {
    out.push(
      section(
        'Decode failed',
        null,
        h('pre', { class: 'mono-block', text: (decoded && (decoded.error || decoded.model?.error)) || 'Unknown error' }),
        h('p', { class: 'hint', text: 'The raw parameter is still available under Parameters below.' })
      )
    );
    out.push(parametersSection(entry));
    return out;
  }

  const model = decoded.model;
  const a0 = model.assertions[0];

  out.push(badgesRow(entry, decoded, model, a0));

  out.push(
    kvList([
      ['URL', entry.url, { pin: 'url' }],
      ['Issuer', model.issuer, { pin: 'saml:issuer', always: true }],
      ['Destination', model.destination, { pin: 'saml:destination' }],
      ['Subject', model.summary.subject, { pin: 'saml:subject', always: model.isResponse }],
      [
        'NameID Format',
        a0 && a0.subject.format ? shortUrn(a0.subject.format) : '',
        { copyText: a0 ? a0.subject.format : '' }
      ],
      ['Status', model.status ? model.status.code : '', { pin: 'saml:status' }],
      ['Status message', model.status ? model.status.message : ''],
      ['Sub-status', model.status ? model.status.subCode : ''],
      ['Issued', model.issueInstant ? `${model.issueInstant} · ${isoToLocal(model.issueInstant)}` : '', { copyText: model.issueInstant }],
      ['InResponseTo', model.inResponseTo, { pin: 'saml:inresponseto' }],
      ['Message ID', model.id],
      ['Encoding', decoded.encoding + (decoded.bytes ? ` · ${formatBytes(decoded.bytes)} XML` : '')],
      ['RelayState', entry.saml.relayState, { pin: 'saml:relaystate' }]
    ])
  );

  if (model.wsfed) {
    out.push(
      section(
        'WS-Federation envelope',
        null,
        kvList([
          ['AppliesTo (realm)', model.wsfed.appliesTo, { pin: 'saml:destination' }],
          ['Token type', shortUrn(model.wsfed.tokenType), { copyText: model.wsfed.tokenType }],
          ['Created', model.wsfed.created ? `${model.wsfed.created} · ${isoToLocal(model.wsfed.created)}` : '', { copyText: model.wsfed.created }],
          ['Expires', model.wsfed.expires ? `${model.wsfed.expires} · ${isoToLocal(model.wsfed.expires)}` : '', { copyText: model.wsfed.expires }],
          ['Key type', shortUrn(model.wsfed.keyType)],
          ['wctx', entry.saml.relayState]
        ])
      )
    );
  }

  if (model.request) {
    out.push(
      section(
        'AuthnRequest',
        null,
        kvList([
          ['ACS URL', model.request.acsUrl],
          ['Protocol binding', shortUrn(model.request.protocolBinding)],
          ['NameID policy', shortUrn(model.request.nameIdFormat)],
          ['ForceAuthn', model.request.forceAuthn],
          ['IsPassive', model.request.isPassive],
          ['Provider name', model.request.providerName],
          ['Requested context', model.request.requestedContext.map(shortUrn).join(', ')],
          ['Comparison', model.request.comparison],
          ['Scoping IdPs', model.request.scopingIdps.join(', ')]
        ])
      )
    );
  }

  if (model.logout) {
    out.push(
      section(
        'LogoutRequest',
        null,
        kvList([
          ['NameID', model.logout.nameId],
          ['SessionIndex', model.logout.sessionIndex],
          ['Reason', model.logout.reason],
          ['NotOnOrAfter', model.logout.notOnOrAfter]
        ])
      )
    );
  }

  if (a0) {
    const attributes = a0.attributes;
    out.push(
      section(
        'Attributes',
        attributes.length,
        attributes.length
          ? attributesTable(attributes)
          : h('p', { class: 'hint', text: 'The assertion carries no attribute statement.' })
      )
    );

    out.push(
      section(
        'Conditions',
        null,
        validityMeter(a0, entry),
        kvList([
          ['NotBefore', a0.conditions.notBefore ? `${a0.conditions.notBefore} · ${isoToLocal(a0.conditions.notBefore)}` : '', { pin: 'saml:notbefore', copyText: a0.conditions.notBefore }],
          ['NotOnOrAfter', a0.conditions.notOnOrAfter ? `${a0.conditions.notOnOrAfter} · ${isoToLocal(a0.conditions.notOnOrAfter)}` : '', { pin: 'saml:notonorafter', copyText: a0.conditions.notOnOrAfter }],
          ['Audience', a0.conditions.audiences.join(', '), { pin: 'saml:audience', always: true }],
          ['One-time use', a0.conditions.oneTimeUse ? 'yes' : ''],
          ['Recipient', a0.subject.recipient],
          ['Subject expires', a0.subject.notOnOrAfter],
          ['Subject confirmation', shortUrn(a0.subject.confirmationMethod)],
          ['Client address', a0.subject.address || a0.authn.ipAddress]
        ])
      )
    );

    out.push(
      section(
        'Authentication',
        null,
        kvList([
          ['AuthnInstant', a0.authn.instant ? `${a0.authn.instant} · ${isoToLocal(a0.authn.instant)}` : '', { copyText: a0.authn.instant }],
          ['SessionIndex', a0.authn.sessionIndex, { pin: 'saml:sessionindex' }],
          ['Session expires', a0.authn.sessionNotOnOrAfter],
          ['AuthnContext', shortUrn(a0.authn.contextClassRef), { copyText: a0.authn.contextClassRef, pin: 'saml:authncontext' }],
          ['Authenticating authority', a0.authn.authenticatingAuthority],
          ['Assertion ID', a0.id],
          ['Assertion issuer', a0.issuer]
        ])
      )
    );
  }

  if (model.assertions.length > 1) {
    out.push(
      section(
        'Additional assertions',
        model.assertions.length - 1,
        ...model.assertions.slice(1).map((assertion, index) =>
          h(
            'div',
            {},
            h('h3', { text: `Assertion ${index + 2}` }),
            kvList([
              ['Subject', assertion.subject.nameId],
              ['NotOnOrAfter', assertion.conditions.notOnOrAfter],
              ['Audience', assertion.conditions.audiences.join(', ')]
            ]),
            attributesTable(assertion.attributes)
          )
        )
      )
    );
  }

  out.push(signatureSection(model, a0));
  out.push(parametersSection(entry));
  return out.filter(Boolean);
}

function protocolLabel(entry, model) {
  if (model && model.protocolLabel) return model.protocolLabel;
  if (entry.saml && entry.saml.protocol === 'ws-fed') return 'WS-Federation';
  return 'SAML';
}

function badgesRow(entry, decoded, model, a0) {
  const badges = [];
  const add = (text, kind, code) =>
    badges.push(h('span', { class: 'badge' + (kind ? ' b-' + kind : '') }, text, code ? h('code', { text: code }) : null));

  add(protocolLabel(entry, model), 'info');

  if (model.status) {
    add(model.status.isSuccess ? 'Status Success' : `Status ${model.status.short}`, model.status.isSuccess ? 'ok' : 'err');
  }
  if (model.signed) add('Response signed', 'info', shortUrn(model.signatureAlg));
  if (a0 && a0.signed) add('Assertion signed', 'info', shortUrn(a0.signatureAlg));
  if (!model.signed && (!a0 || !a0.signed)) add('No XML signature', 'warn');
  if (model.encryptedAssertions) add(`Encrypted assertion ×${model.encryptedAssertions}`, 'warn');
  if (model.encryptedIds) add('Encrypted NameID', 'warn');
  if (a0 && a0.encryptedAttributes) add(`Encrypted attributes ×${a0.encryptedAttributes}`, 'warn');
  add(`${entry.saml.binding} binding`);
  if (entry.saml.signature) add('Query signature present', 'info', shortUrn(entry.saml.sigAlg));
  if (entry.saml.truncated) add('Parameter truncated', 'warn');

  return h('div', { class: 'badges' }, ...badges);
}

function attributesTable(attributes) {
  const table = h('table', { class: 'tbl attrs' });
  table.append(
    h('colgroup', {}, h('col', { class: 'c1' }), h('col', { class: 'c2' }), h('col'), h('col', { class: 'col-act' })),
    h('thead', {}, h('tr', {}, h('th', { text: 'Friendly' }), h('th', { text: 'Name' }), h('th', { text: 'Value' }), h('th', {})))
  );
  const body = h('tbody');
  for (const attribute of attributes) {
    const values = attribute.values.length
      ? h('div', {}, ...attribute.values.map((v) => h('div', { text: v })))
      : h('span', { class: 'none', text: '(no values)' });
    body.append(
      h(
        'tr',
        {},
        h('td', {}, h('span', { class: 'chip', text: attribute.friendlyName || '—' })),
        h('td', {}, h('span', { class: 'urn', text: attribute.name || '—' })),
        h('td', {}, values),
        h(
          'td',
          {},
          pinButton(`saml:attr:${attribute.friendlyName || attribute.name}`),
          attribute.values.length ? copyButton(attribute.values.join(', ')) : null
        )
      )
    );
  }
  table.append(body);
  return table;
}

function signatureSection(model, a0) {
  const certificates = [
    ...model.certificates.map((c) => ['Response', c]),
    ...(a0 ? a0.certificates.map((c) => ['Assertion', c]) : [])
  ];
  if (!certificates.length && !model.signatureAlg) return null;

  const node = section(
    'Signature',
    null,
    kvList([
      ['Signature algorithm', shortUrn(model.signatureAlg) || (a0 ? shortUrn(a0.signatureAlg) : ''), { copyText: model.signatureAlg || (a0 && a0.signatureAlg) }],
      ['Digest algorithm', shortUrn(model.digestAlg) || (a0 ? shortUrn(a0.digestAlg) : '')]
    ])
  );

  for (const [scope, cert] of certificates) {
    const row = h('dl', { class: 'kv' });
    const dd = h('dd', { text: 'computing fingerprint…' });
    row.append(h('dt', { text: `${scope} certificate` }), dd, h('div', { class: 'act' }, copyButton(pemFor(cert))));
    node.append(row);
    SAML.certFingerprint(cert).then((fingerprint) => {
      dd.textContent = fingerprint ? `SHA-256 ${fingerprint}` : 'fingerprint unavailable';
    });
  }
  node.append(
    h('p', { class: 'hint', text: 'Signatures are not verified here — compare the fingerprint with the certificate configured in your IdP.' })
  );
  return node;
}

function pemFor(base64) {
  const body = base64.replace(/\s+/g, '').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`;
}

const WSFED_LABELS = {
  wa: 'wa (action)',
  wtrealm: 'wtrealm (SP realm)',
  wctx: 'wctx (context)',
  wreply: 'wreply (reply URL)',
  whr: 'whr (home realm)',
  wct: 'wct (created)',
  wp: 'wp (policy)',
  wfresh: 'wfresh (max age)',
  wauth: 'wauth (auth type)'
};

function parametersSection(entry) {
  const saml = entry.saml;
  const rows = [];
  if (saml.raw) rows.push([saml.kind, truncated(saml.raw, 140), { copyText: saml.raw }]);
  if (saml.protocol === 'ws-fed') {
    for (const [key, value] of Object.entries(saml.extras || {})) {
      rows.push([WSFED_LABELS[key] || key, value, { pin: `query:${key}` }]);
    }
  } else {
    rows.push(
      ['RelayState', saml.relayState, { pin: 'saml:relaystate' }],
      ['SigAlg', saml.sigAlg],
      ['Signature', truncated(saml.signature, 80), { copyText: saml.signature }]
    );
  }
  return section(`Parameters (${saml.binding} binding)`, null, kvList(rows));
}

function validityMeter(assertion, entry) {
  const from = Date.parse(assertion.conditions.notBefore || '');
  const to = Date.parse(assertion.conditions.notOnOrAfter || '');
  if (Number.isNaN(from) && Number.isNaN(to)) return null;

  const wrap = h('div', { class: 'meter' });

  // The diagnostic question first: was it valid when the SP received it?
  const delivered = entry && entry.started;
  if (delivered) {
    const okAtDelivery =
      (Number.isNaN(from) || delivered >= from) && (Number.isNaN(to) || delivered < to);
    wrap.append(
      h(
        'div',
        { class: 'meter-head' },
        h('span', {
          class: 'meter-verdict ' + (okAtDelivery ? 'is-valid' : 'is-expired'),
          text: okAtDelivery ? 'Valid when delivered' : 'NOT valid when delivered'
        }),
        h('span', {
          text: okAtDelivery
            ? `the SP received it at ${clockTime(delivered)}, inside the window — the live status below only tells you whether it could still be replayed now`
            : `the SP received it at ${clockTime(delivered)}, outside the window — this alone makes the SP reject it (clock skew or a stale form re-submit)`
        })
      )
    );
  }

  const verdict = h('span', { class: 'meter-verdict' });
  const detail = h('span', {});
  wrap.append(h('div', { class: 'meter-head' }, verdict, detail));

  const track = h('div', { class: 'meter-track' });
  const fill = h('div', { class: 'meter-fill' });
  const now = h('div', { class: 'meter-now' });
  track.append(fill, now);
  wrap.append(track);
  wrap.append(
    h(
      'div',
      { class: 'meter-ends' },
      h('span', { text: Number.isNaN(from) ? 'no NotBefore' : isoToLocal(assertion.conditions.notBefore) }),
      h('span', { text: Number.isNaN(to) ? 'no NotOnOrAfter' : isoToLocal(assertion.conditions.notOnOrAfter) })
    )
  );

  const start = Number.isNaN(from) ? to - 5 * 60 * 1000 : from;
  const end = Number.isNaN(to) ? from + 5 * 60 * 1000 : to;
  const span = Math.max(end - start, 1);

  const tick = () => {
    const current = Date.now();
    const ratio = Math.min(Math.max((current - start) / span, 0), 1);
    fill.style.right = `${(1 - ratio) * 100}%`;
    now.style.left = `${ratio * 100}%`;
    if (current < start) {
      verdict.textContent = 'Not valid yet';
      verdict.className = 'meter-verdict is-early';
      detail.textContent = `starts in ${humanDuration(start - current)} — check clock skew between IdP and SP`;
      now.classList.add('is-out');
    } else if (current > end) {
      verdict.textContent = 'Window closed';
      verdict.className = 'meter-verdict is-expired';
      detail.textContent = `expired ${humanDuration(current - end)} ago`;
      now.classList.add('is-out');
    } else {
      verdict.textContent = 'Inside validity window';
      verdict.className = 'meter-verdict is-valid';
      detail.textContent = `${humanDuration(end - current)} left of ${humanDuration(span)}`;
      now.classList.remove('is-out');
    }
  };
  tick();
  state.tickers.push(tick);
  return wrap;
}

setInterval(() => {
  for (const tick of state.tickers) {
    try {
      tick();
    } catch {
      /* node detached */
    }
  }
}, 1000);

function genericSections(entry) {
  const out = [];
  const duration = entry.completed && entry.started ? Math.round(entry.completed - entry.started) : null;
  out.push(
    kvList([
      ['URL', entry.url, { pin: 'url' }],
      ['Method', entry.method],
      ['Status', entry.statusLine || (entry.status ? String(entry.status) : ''), { always: true }],
      ['Error', entry.error],
      ['Resource type', entry.type],
      ['Started', fullTime(entry.started)],
      ['Duration', duration !== null ? `${duration} ms` : ''],
      ['Remote IP', entry.ip],
      ['From cache', entry.fromCache ? 'yes' : ''],
      ['Redirects to', entry.redirectUrl],
      ['Initiator', entry.initiator],
      ['Tab', entry.tabId >= 0 ? `#${entry.tabId}` : 'no tab']
    ])
  );

  if (entry.postText) {
    const formatted = entry.formData
      ? Object.entries(entry.formData)
          .map(([key, values]) => `${key} = ${values.join('\n' + ' '.repeat(key.length + 3))}`)
          .join('\n')
      : entry.postText;
    out.push(
      section(
        'Request body',
        null,
        h('pre', { class: 'mono-block', text: formatted }),
        h('div', { style: 'margin-top:6px' }, copyButton(entry.postText))
      )
    );
  }

  if (entry.jwts && entry.jwts.length) {
    out.push(
      section(
        'Tokens found',
        entry.jwts.length,
        ...entry.jwts.map((token) =>
          h(
            'div',
            { style: 'margin-bottom:6px' },
            h('button', { class: 'btn', onclick: () => openJwt(token) }, 'Decode in JWT tab'),
            ' ',
            h('span', { class: 'urn', text: truncated(token, 90) })
          )
        )
      )
    );
  }
  return out;
}

function headersSection(title, headers) {
  if (!headers || !headers.length) return null;
  const table = h('table', { class: 'tbl headers' });
  table.append(h('colgroup', {}, h('col', { class: 'c1' }), h('col'), h('col', { class: 'col-act' })));
  const body = h('tbody');
  for (const header of headers) {
    body.append(
      h(
        'tr',
        {},
        h('td', {}, h('span', { class: 'chip', text: header.name })),
        h('td', { text: header.value ?? '' }),
        h('td', {}, pinButton(header.name), copyButton(header.value ?? ''))
      )
    );
  }
  table.append(body);
  return section(title, headers.length, table);
}

function rawXmlSection(entry, decoded) {
  const details = h('details', { class: 'raw', open: decoded.pretty.length < 20000 ? true : null });
  const pre = h('pre', { class: 'xml' + (state.settings.wrapXml ? ' wrap' : '') });
  pre.innerHTML = SAML.highlightXml(decoded.pretty);

  const summary = h(
    'summary',
    {},
    'Raw XML',
    h('span', { class: 'grow' }),
    h('span', { class: 'urn', text: `${decoded.pretty.split('\n').length} lines · ${formatBytes(decoded.bytes || decoded.xml.length)}` }),
    h(
      'button',
      {
        class: 'btn-mini',
        title: 'Toggle line wrapping',
        onclick: (event) => {
          event.preventDefault();
          event.stopPropagation();
          state.settings.wrapXml = !state.settings.wrapXml;
          pre.classList.toggle('wrap', state.settings.wrapXml);
          saveSettings();
        }
      },
      'wrap'
    ),
    h(
      'button',
      {
        class: 'btn-mini',
        title: 'Copy XML',
        onclick: (event) => {
          event.preventDefault();
          event.stopPropagation();
          copyText(decoded.pretty, 'XML copied');
        }
      },
      icon('i-copy')
    )
  );
  details.append(summary, pre);
  return h('section', { class: 'section' }, details);
}

function infoBar(entry, decoded) {
  const pins = state.settings.pins;
  if (!pins.length) return null;
  const bar = h('div', { class: 'infobar' });
  const parts = [];
  for (const pin of pins) {
    const resolved = resolvePin(pin, entry, decoded);
    if (!resolved) continue;
    parts.push(`${resolved.label}: ${resolved.value}`);
    bar.append(
      h(
        'div',
        { class: 'ib' },
        h('span', { class: 'ib-label', text: resolved.label }),
        h('span', {
          class: 'ib-value' + (resolved.value ? '' : ' is-missing'),
          text: resolved.value || 'not in this entry'
        })
      )
    );
  }
  if (!bar.children.length) return null;
  bar.append(h('div', { class: 'ib-copy' }, copyButton(parts.join('\n'), 'Copy info bar')));
  return bar;
}

function resolvePin(pin, entry, decoded) {
  const key = String(pin).trim();
  if (!key) return null;
  const model = decoded && decoded.model && decoded.model.ok ? decoded.model : null;
  const a0 = model && model.assertions[0];

  if (/^saml:attr:/i.test(key)) {
    const wanted = key.slice(10).toLowerCase();
    const attributes = (a0 && a0.attributes) || [];
    const hit = attributes.find(
      (a) => (a.friendlyName || '').toLowerCase() === wanted || (a.name || '').toLowerCase() === wanted
    );
    return { label: key.slice(10), value: hit ? hit.values.join(', ') : '' };
  }
  if (/^saml:/i.test(key)) {
    const field = key.slice(5).toLowerCase();
    const map = {
      issuer: model && model.issuer,
      destination: model && model.destination,
      subject: model && model.summary.subject,
      status: model && model.status && model.status.code,
      id: model && model.id,
      inresponseto: model && model.inResponseTo,
      issued: model && model.issueInstant,
      notbefore: a0 && a0.conditions.notBefore,
      notonorafter: a0 && a0.conditions.notOnOrAfter,
      audience: a0 && a0.conditions.audiences.join(', '),
      sessionindex: a0 && a0.authn.sessionIndex,
      authncontext: a0 && a0.authn.contextClassRef,
      nameidformat: a0 && a0.subject.format,
      relaystate: entry.saml && entry.saml.relayState,
      binding: entry.saml && entry.saml.binding
    };
    return { label: key.slice(5), value: map[field] || '' };
  }
  const pathMatch = key.match(/^path\[(-?\d+)\]$/i);
  if (pathMatch) {
    let segments = [];
    try {
      segments = new URL(entry.url).pathname.split('/').filter(Boolean);
    } catch {
      /* ignore */
    }
    const index = Number(pathMatch[1]);
    const value = index < 0 ? segments[segments.length + index] : segments[index];
    return { label: `path[${pathMatch[1]}]`, value: value || '' };
  }
  const queryMatch = key.match(/^query:(.+)$/i);
  if (queryMatch) {
    let value = '';
    try {
      value = new URL(entry.url).searchParams.get(queryMatch[1]) || '';
    } catch {
      /* ignore */
    }
    return { label: queryMatch[1], value };
  }
  if (/^url$/i.test(key)) return { label: 'URL', value: entry.url };
  if (/^host$/i.test(key)) return { label: 'Host', value: hostOf(entry.url) };
  if (/^status$/i.test(key)) return { label: 'Status', value: entry.statusLine || String(entry.status || '') };
  return {
    label: key,
    value: headerValue(entry.responseHeaders, key) || headerValue(entry.requestHeaders, key)
  };
}

/* ------------------------------------------------------------- redaction */

/**
 * Copy of an entry safe to put in a file, a ticket or the clipboard: the SAML
 * assertion is the point of the export, session cookies and bearer tokens are not.
 */
function forSharing(entry) {
  if (!state.settings.redactSensitive) return entry;
  return {
    ...entry,
    requestHeaders: redactHeaders(entry.requestHeaders),
    responseHeaders: redactHeaders(entry.responseHeaders)
  };
}

/* -------------------------------------------------------------- copy as text */

function entryAsText(rawEntry, decoded) {
  const entry = forSharing(rawEntry);
  const lines = [];
  lines.push(`${entry.method} ${entry.url}`);
  lines.push(`Status: ${entry.statusLine || entry.status || entry.error || '—'}`);
  lines.push(`Time:   ${fullTime(entry.started)}`);
  if (entry.saml) lines.push(`SAML:   ${entry.saml.kind} over ${entry.saml.binding} binding`);

  const model = decoded && decoded.model && decoded.model.ok ? decoded.model : null;
  if (model) {
    const a0 = model.assertions[0];
    lines.push('', '--- SAML summary ---');
    lines.push(`Issuer:       ${model.issuer}`);
    lines.push(`Destination:  ${model.destination}`);
    if (model.status) lines.push(`Status:       ${model.status.code}${model.status.message ? ' — ' + model.status.message : ''}`);
    lines.push(`Issued:       ${model.issueInstant}`);
    if (model.inResponseTo) lines.push(`InResponseTo: ${model.inResponseTo}`);
    if (a0) {
      lines.push(`Subject:      ${a0.subject.nameId}`);
      lines.push(`Conditions:   ${a0.conditions.notBefore} → ${a0.conditions.notOnOrAfter}`);
      lines.push(`Audience:     ${a0.conditions.audiences.join(', ')}`);
      if (a0.authn.sessionIndex) lines.push(`SessionIndex: ${a0.authn.sessionIndex}`);
      if (a0.attributes.length) {
        lines.push('', '--- Attributes ---');
        const width = Math.max(...a0.attributes.map((a) => (a.friendlyName || '').length), 8);
        for (const attribute of a0.attributes) {
          lines.push(
            `${(attribute.friendlyName || '—').padEnd(width)}  ${attribute.values.join(', ') || '(no values)'}  [${attribute.name}]`
          );
        }
      }
    }
  } else if (decoded && decoded.error) {
    lines.push('', `Decode failed: ${decoded.error}`);
  }

  const headerBlock = (title, headers) => {
    if (!headers || !headers.length) return;
    lines.push('', `--- ${title} ---`);
    for (const header of headers) lines.push(`${header.name}: ${header.value}`);
  };
  headerBlock('Request headers', entry.requestHeaders);
  headerBlock('Response headers', entry.responseHeaders);

  if (decoded && decoded.pretty) {
    lines.push('', '--- XML ---', decoded.pretty);
  }
  return lines.join('\n');
}

/* ------------------------------------------------------- export / import */

function stamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  if (chrome.downloads && chrome.downloads.download) {
    chrome.downloads.download({ url, filename }, () => setTimeout(() => URL.revokeObjectURL(url), 30000));
    return;
  }
  const anchor = h('a', { href: url, download: filename });
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

function exportJson() {
  const list = visibleEntries();
  const payload = {
    format: 'saml-tracer-pro',
    version: 1,
    exportedAt: new Date().toISOString(),
    view: state.view,
    redacted: state.settings.redactSensitive,
    entries: list.map(forSharing).map((entry) => ({
      // native fields
      ...entry,
      // aliases so other tracers and HAR-ish readers find their way
      postData: entry.postText || '',
      timestamp: new Date(entry.started).toISOString()
    }))
  };
  downloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }), `saml-capture-${stamp()}.json`);
  toast(`Exported ${list.length} entries`);
}

function normalizeHeaders(input) {
  if (!input) return null;
  if (Array.isArray(input)) {
    return input
      .map((header) => ({ name: header.name ?? header.key ?? '', value: header.value ?? '' }))
      .filter((header) => header.name);
  }
  if (typeof input === 'object') {
    return Object.entries(input).map(([name, value]) => ({ name, value: String(value) }));
  }
  return null;
}

function importedEntry(item, index) {
  const request = item.request || {};
  const response = item.response || {};
  const url = item.url || request.url || '';
  const method = item.method || request.method || 'GET';
  const statusLine = item.statusLine || response.statusText || '';
  let status = Number(item.status ?? item.statusCode ?? response.status ?? 0) || 0;
  if (!status && statusLine) {
    const match = statusLine.match(/\b(\d{3})\b/);
    if (match) status = Number(match[1]);
  }
  const postText =
    item.postText ||
    (typeof item.postData === 'string' ? item.postData : '') ||
    (request.postData && (request.postData.text || '')) ||
    item.body ||
    '';
  const started =
    Date.parse(item.timestamp || item.startedDateTime || item.date || '') ||
    (typeof item.started === 'number' ? item.started : Date.now());

  let formData = item.formData || null;
  if (!formData && postText && /^[\w.%+\-[\]]+=/.test(postText)) formData = parseUrlEncoded(postText);
  if (!formData && request.postData && Array.isArray(request.postData.params)) {
    formData = {};
    for (const param of request.postData.params) {
      (formData[param.name] = formData[param.name] || []).push(param.value ?? '');
    }
  }

  const saml = item.saml || samlFromUrl(url) || samlFromForm(formData);

  return {
    id: `imp${state.importSeq--}.${index}`,
    seq: -1,
    tabId: -1,
    source: 'import',
    url,
    method,
    type: item.type || request.resourceType || 'other',
    status,
    statusLine,
    started,
    completed: item.completed || 0,
    requestHeaders: normalizeHeaders(item.requestHeaders || request.headers),
    responseHeaders: normalizeHeaders(item.responseHeaders || response.headers),
    postText,
    formData,
    saml,
    jwts: item.jwts || [],
    error: item.error || '',
    initiator: item.initiator || '',
    redirectUrl: item.redirectUrl || ''
  };
}

function importPayload(raw) {
  let list = null;
  if (Array.isArray(raw)) list = raw;
  else if (raw && Array.isArray(raw.entries)) list = raw.entries;
  else if (raw && Array.isArray(raw.requests)) list = raw.requests;
  else if (raw && raw.log && Array.isArray(raw.log.entries)) list = raw.log.entries;
  if (!list) throw new Error('No entries array found. Expected a saml-tracer JSON export or a HAR file.');

  let added = 0;
  list.forEach((item, index) => {
    const entry = importedEntry(item, index);
    if (!entry.url) return;
    mergeEntry(entry);
    added++;
  });
  sortEntries();
  renderList();
  toast(`Imported ${added} entries`);
}

async function importFile(file) {
  try {
    const text = await file.text();
    importPayload(JSON.parse(text));
  } catch (error) {
    toast('Import failed: ' + error.message);
  }
}

async function makeReport() {
  const list = visibleEntries();
  if (!list.length) {
    toast('Nothing to report — the current view is empty.');
    return;
  }
  await Promise.all(list.filter((entry) => entry.saml).map(ensureDecoded));
  const html = buildHtmlReport({
    entries: list.map(forSharing),
    decodedById: state.decoded,
    title: 'SAML capture report',
    note: [state.filter ? `filter: ${state.filter}` : '', state.settings.redactSensitive ? 'cookie and authorization headers redacted' : '']
      .filter(Boolean)
      .join(' · ')
  });
  downloadBlob(new Blob([html], { type: 'text/html' }), `saml-report-${stamp()}.html`);
  toast('Report saved');
}

/* ---------------------------------------------------------------- jwt view */

function openJwt(token) {
  setView('jwt');
  els.jwtText.value = token;
  renderJwt();
}

function renderJwt() {
  const raw = els.jwtText.value.trim();
  if (!raw) {
    els.jwtResult.replaceChildren();
    return;
  }
  const result = decodeJwt(raw);
  if (!result.ok) {
    els.jwtResult.replaceChildren(h('div', { class: 'jwt-error', text: result.error }));
    return;
  }

  const warnings = [];
  if (result.unsecured) warnings.push(['This token has no signature (alg none or empty signature part).', 'b-err']);
  if (result.expired === true) warnings.push(['Expired — exp is in the past.', 'b-err']);
  if (result.expired === false) warnings.push(['Not expired.', 'b-ok']);
  if (result.expired === null) warnings.push(['No exp claim, so this token never expires on its own.', 'b-warn']);
  if (!result.payloadIsJson) warnings.push(['The payload is not JSON — it may be a nested or opaque token.', 'b-warn']);

  const badges = h('div', { class: 'badges' }, ...warnings.map(([text, cls]) => h('span', { class: 'badge ' + cls, text })));

  const highlights = kvList(result.highlights.map((item) => [item.label, item.value]));

  const cards = h(
    'div',
    { class: 'jwt-grid' },
    h('div', { class: 'jwt-card' }, h('h3', { text: 'Header' }), h('pre', { text: JSON.stringify(result.header, null, 2) })),
    h('div', { class: 'jwt-card' }, h('h3', { text: 'Payload' }), h('pre', { text: result.payloadText })),
    h(
      'div',
      { class: 'jwt-card' },
      h('h3', { text: 'Signature (not verified)' }),
      h('pre', { text: result.signature || '(none)' })
    )
  );

  els.jwtResult.replaceChildren(
    badges,
    section('Highlights', null, highlights),
    cards,
    h(
      'div',
      { style: 'margin-top:12px;display:flex;gap:8px' },
      h('button', { class: 'btn', onclick: () => copyText(JSON.stringify(result.payload, null, 2), 'Payload copied') }, 'Copy payload'),
      h('button', { class: 'btn', onclick: () => copyText(JSON.stringify(result.header, null, 2), 'Header copied') }, 'Copy header')
    )
  );
}

function renderFoundTokens() {
  const tokens = new Map();
  for (const entry of state.entries) {
    for (const token of entry.jwts || []) {
      if (!tokens.has(token)) tokens.set(token, entry);
    }
  }
  els.jwtFound.replaceChildren();
  const list = [...tokens.entries()].slice(-12);
  els.jwtFoundNote.textContent = list.length
    ? 'Tokens seen in this capture:'
    : 'No tokens spotted in captured requests yet.';
  for (const [token, entry] of list) {
    els.jwtFound.append(
      h(
        'button',
        {
          class: 'jwt-chip',
          title: entry.url,
          onclick: () => {
            els.jwtText.value = token;
            renderJwt();
          }
        },
        `${hostOf(entry.url) || 'token'} · ${token.slice(0, 12)}…`
      )
    );
  }
}

/* --------------------------------------------------------------- flow view */

function renderFlow() {
  const scoped = state.entries.filter((entry) => {
    if (
      state.settings.scopeThisTab &&
      inspectedTabId != null &&
      entry.source !== 'import' &&
      entry.tabId !== inspectedTabId
    ) {
      return false;
    }
    return true;
  });

  const { steps, findings, hosts } = buildFlow(scoped);
  const container = els.flowView;

  if (!steps.length) {
    container.replaceChildren(
      h(
        'div',
        { class: 'flow-empty' },
        h('h2', { text: 'How a SAML login works' }),
        h('p', {
          text:
            'Start a capture, trigger a login, and this tab will replay it stage by stage: the app noticing you have no session, the AuthnRequest it sends, what happens at the identity provider, the assertion coming back, and the app turning it into a session.'
        }),
        h('p', {
          text: 'Each stage comes with a plain-words explanation and the checklist an IAM admin runs when that stage misbehaves — so the timeline below doubles as a walkthrough of the protocol itself.'
        })
      )
    );
    return;
  }

  const nodes = [];

  // actor lane: browser → IdP → SP
  const lane = h('div', { class: 'flow-lane' });
  const laneNode = (role, hostsSet, cls) =>
    h(
      'div',
      { class: 'lane-node ' + cls },
      h('span', { class: 'ln-role', text: role }),
      h('span', { class: 'ln-host', text: hostsSet && hostsSet.size ? [...hostsSet].join(', ') : '—' })
    );
  lane.append(
    laneNode('Browser', null, 'is-browser'),
    h('span', { class: 'lane-arrow', text: '⇄' }),
    laneNode('Identity provider', hosts.idp, 'is-idp'),
    h('span', { class: 'lane-arrow', text: '⇄' }),
    laneNode('Service provider', hosts.sp, 'is-sp')
  );
  nodes.push(lane);

  if (findings.length) {
    nodes.push(
      h(
        'div',
        { class: 'flow-findings' },
        ...findings.map((f) => h('div', { class: 'finding f-' + f.severity, text: f.text }))
      )
    );
  }

  // timeline grouped by stage, in flow order
  for (const stageId of orderedStagesIn(steps)) {
    const info = stageInfo(stageId);
    const stageSteps = steps.filter((s) => s.stage === stageId);
    const hasSaml = stageSteps.some((s) => s.entry.saml);
    const hasError = stageSteps.some((s) => isErrorEntry(s.entry));

    const details = h('details', {
      class: 'stage' + (hasSaml ? ' s-saml' : '') + (hasError ? ' s-err' : ''),
      open: hasSaml || hasError ? true : null
    });

    details.append(
      h(
        'summary',
        { class: 'stage-head' },
        h('span', { class: 'stage-dot' }),
        h('span', { class: 'stage-title', text: info.label }),
        info.who ? h('span', { class: 'stage-who', text: info.who }) : null,
        h('span', { class: 'stage-n', text: `${stageSteps.length} hop${stageSteps.length === 1 ? '' : 's'}` })
      )
    );

    const body = h('div', { class: 'stage-body' });
    body.append(h('p', { class: 'stage-teach', text: info.teach }));
    if (info.checks && info.checks.length) {
      const checks = h('details', { class: 'stage-checks' });
      checks.append(
        h('summary', { text: 'What to check at this stage' }),
        h('ul', {}, ...info.checks.map((c) => h('li', { text: c })))
      );
      body.append(checks);
    }

    for (const step of stageSteps) {
      const entry = step.entry;
      body.append(
        h(
          'div',
          {
            class: 'hop',
            title: entry.url,
            onclick: () => {
              setView(entry.saml ? 'saml' : 'all');
              selectEntry(entry.id, true);
            }
          },
          h('span', { class: 'pill ' + statusClass(entry), text: entry.error ? 'ERR' : String(entry.status || '…') }),
          h('span', { class: 'method ' + (entry.method === 'POST' ? 'm-post' : ''), text: entry.method }),
          entry.saml ? h('span', { class: 'tag' + (/Request|sign-in/.test(entry.saml.kind) ? ' tag-req' : ''), text: entry.saml.kind }) : null,
          h('span', { class: 'hop-arrow', text: '→' }),
          h('span', { class: 'hop-url', text: shortUrl(entry.url, 110) }),
          h('span', { class: 'row-time', text: clockTime(entry.started) })
        )
      );
    }

    details.append(body);
    nodes.push(details);
  }

  container.replaceChildren(...nodes);
}

/* ------------------------------------------------------------------- views */

function setView(view) {
  state.view = view;
  for (const tab of document.querySelectorAll('.tab')) {
    tab.classList.toggle('is-active', tab.dataset.view === view);
  }
  const jwt = view === 'jwt';
  const flow = view === 'flow';
  els.jwtView.hidden = !jwt;
  els.flowView.hidden = !flow;
  els.traceBody.hidden = jwt || flow;
  if (jwt) {
    renderFoundTokens();
    renderJwt();
    els.jwtText.focus();
  } else if (flow) {
    renderFlow();
  } else {
    renderList();
    renderDetail();
  }
}

const STOP_REASONS = {
  'flow-complete': 'the SAML conversation went quiet',
  'time-limit': 'the time limit was reached',
  'stopped-by-hand': 'you stopped it',
  'mode-changed': 'the capture mode changed'
};

function renderCaptureUi() {
  const live = state.capturing;
  const always = state.settings.captureMode === 'always';

  els.btnRecord.classList.toggle('is-live', live);
  els.recLabel.textContent = live ? 'Stop capture' : 'Start capture';
  els.btnRecord.title = live
    ? 'Stop capturing (Ctrl/Cmd+Enter)'
    : 'Start capturing, then trigger the login (Ctrl/Cmd+Enter)';

  const bar = els.statusBar;
  bar.classList.toggle('is-live', live);
  bar.classList.toggle('is-done', !live && state.runReason === 'flow-complete');

  const counts = `${state.run.samlCount || 0} SAML · ${state.run.requestCount || 0} requests`;
  let text;
  let action = null;

  if (live && always) {
    text = 'Capturing continuously (always-on mode).';
  } else if (live) {
    const idle = state.settings.autoStop ? ` Stops on its own ${state.settings.autoStopIdleSeconds}s after the flow goes quiet.` : '';
    text = state.run.samlCount
      ? `Capturing — SAML seen.${idle}`
      : `Capturing — trigger the login now.${idle}`;
  } else if (state.runReason) {
    const why = STOP_REASONS[state.runReason] || state.runReason;
    text = `Capture stopped because ${why}. The capture below stays until you clear it.`;
    action = 'Start again';
  } else {
    text = 'Not capturing. Start first, then trigger the login — the AuthnRequest is the first thing worth seeing.';
    action = 'Start capture';
  }

  bar.replaceChildren(
    ...[
      h('span', { class: 'sb-text' }, text, state.run.requestCount ? h('span', { class: 'sb-count' }, ` ${counts}`) : null),
      action ? h('button', { class: 'btn', onclick: () => setCapturing(true) }, action) : null,
      live && !always ? h('button', { class: 'btn', onclick: () => setCapturing(false) }, 'Stop') : null
    ].filter(Boolean)
  );
}

function setCapturing(value) {
  state.capturing = value;
  if (value) {
    state.runReason = '';
    state.run = { samlCount: 0, requestCount: 0, startedAt: Date.now() };
  }
  renderCaptureUi();
  if (port) port.postMessage({ type: 'setCapturing', value });
}

function renderScopeButton() {
  if (inspectedTabId == null) {
    els.btnScope.hidden = true;
    return;
  }
  els.btnScope.classList.toggle('is-on', state.settings.scopeThisTab);
  els.btnScope.title = state.settings.scopeThisTab
    ? 'Showing this tab only — click for all tabs'
    : 'Showing all tabs — click for this tab only';
}

/* ------------------------------------------------------------------ wiring */

function openSettings() {
  $('setDomains').value = state.settings.highlightDomains.join('\n');
  $('setCapture').value = state.settings.captureDomains.join('\n');
  $('setPins').value = state.settings.pins.join('\n');
  $('setIdle').checked = state.settings.captureWhenClosed;
  $('setRedact').checked = state.settings.redactSensitive;
  $('setMode').value = state.settings.captureMode;
  $('setAutoStop').checked = state.settings.autoStop;
  $('setIdleSecs').value = String(state.settings.autoStopIdleSeconds);
  $('setMaxSecs').value = String(state.settings.autoStopMaxSeconds);
  $('setTheme').value = state.settings.theme;
  $('setMax').value = String(state.settings.maxEntries);
  $('setWrap').checked = state.settings.wrapXml;
  $('setAutoSelect').checked = state.settings.autoSelect;
  els.settings.showModal();
}

els.settings.addEventListener('close', () => {
  if (els.settings.returnValue !== 'save') return;
  const lines = (value) =>
    value
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
  state.settings.highlightDomains = lines($('setDomains').value);
  state.settings.captureDomains = lines($('setCapture').value);
  state.settings.pins = lines($('setPins').value);
  state.settings.captureWhenClosed = $('setIdle').checked;
  state.settings.redactSensitive = $('setRedact').checked;
  state.settings.captureMode = $('setMode').value === 'always' ? 'always' : 'manual';
  state.settings.autoStop = $('setAutoStop').checked;
  state.settings.autoStopIdleSeconds = Number($('setIdleSecs').value) || 15;
  state.settings.autoStopMaxSeconds = Number($('setMaxSecs').value);
  state.settings.theme = $('setTheme').value;
  state.settings.maxEntries = Number($('setMax').value) || DEFAULTS.maxEntries;
  state.settings.wrapXml = $('setWrap').checked;
  state.settings.autoSelect = $('setAutoSelect').checked;
  saveSettings();
  applyTheme();
  renderCaptureUi();
  renderList();
  renderDetail();
  toast('Settings saved');
});

for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => setView(tab.dataset.view));
}

els.filter.addEventListener('input', () => {
  state.filter = els.filter.value;
  renderList();
});

$('navOnly').addEventListener('change', () => {
  state.settings.navOnly = $('navOnly').checked;
  saveSettings();
  renderList();
});

els.btnRecord.addEventListener('click', () => setCapturing(!state.capturing));

els.btnScope.addEventListener('click', () => {
  state.settings.scopeThisTab = !state.settings.scopeThisTab;
  saveSettings();
  renderScopeButton();
  renderList();
});

$('btnClear').addEventListener('click', () => {
  if (port) port.postMessage({ type: 'clear' });
  state.entries = [];
  state.byId.clear();
  state.decoded.clear();
  state.selectedId = null;
  state.stickToLatest = true;
  renderList();
  renderDetail();
  if (state.view === 'flow') renderFlow();
});

$('btnExport').addEventListener('click', exportJson);
$('btnReport').addEventListener('click', makeReport);
$('btnSettings').addEventListener('click', openSettings);
$('btnImport').addEventListener('click', () => els.fileInput.click());

els.fileInput.addEventListener('change', () => {
  const file = els.fileInput.files && els.fileInput.files[0];
  if (file) importFile(file);
  els.fileInput.value = '';
});

let dragDepth = 0;
window.addEventListener('dragenter', (event) => {
  if (![...(event.dataTransfer?.types || [])].includes('Files')) return;
  dragDepth++;
  els.dropOverlay.hidden = false;
});
window.addEventListener('dragover', (event) => event.preventDefault());
window.addEventListener('dragleave', () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) els.dropOverlay.hidden = true;
});
window.addEventListener('drop', (event) => {
  event.preventDefault();
  dragDepth = 0;
  els.dropOverlay.hidden = true;
  const file = event.dataTransfer?.files?.[0];
  if (file) importFile(file);
});

$('jwtPaste').addEventListener('click', async () => {
  try {
    els.jwtText.value = await navigator.clipboard.readText();
    renderJwt();
  } catch {
    toast('Clipboard read was blocked — paste with Ctrl/Cmd+V instead.');
    els.jwtText.focus();
  }
});

$('jwtClear').addEventListener('click', () => {
  els.jwtText.value = '';
  renderJwt();
  els.jwtText.focus();
});

let jwtTimer = null;
els.jwtText.addEventListener('input', () => {
  clearTimeout(jwtTimer);
  jwtTimer = setTimeout(renderJwt, 150);
});

document.addEventListener('keydown', (event) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName);
  if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
    event.preventDefault();
    setCapturing(!state.capturing);
    return;
  }
  if ((event.metaKey || event.ctrlKey) && event.key === 'f') {
    event.preventDefault();
    els.filter.focus();
    els.filter.select();
    return;
  }
  if (typing) return;
  if (event.key === 'ArrowDown' || event.key === 'j') {
    event.preventDefault();
    moveSelection(1);
  } else if (event.key === 'ArrowUp' || event.key === 'k') {
    event.preventDefault();
    moveSelection(-1);
  } else if (event.key === '/') {
    event.preventDefault();
    els.filter.focus();
  } else if (['1', '2', '3', '4', '5'].includes(event.key)) {
    setView(['saml', 'all', 'errors', 'flow', 'jwt'][Number(event.key) - 1]);
  }
});

// splitter
(() => {
  let dragging = false;
  els.splitter.addEventListener('mousedown', (event) => {
    dragging = true;
    event.preventDefault();
    document.body.style.cursor = 'col-resize';
  });
  window.addEventListener('mousemove', (event) => {
    if (!dragging) return;
    const width = Math.min(Math.max(event.clientX, 200), window.innerWidth - 360);
    els.listPane.style.width = width + 'px';
  });
  window.addEventListener('mouseup', () => {
    dragging = false;
    document.body.style.cursor = '';
  });
})();

matchMedia('(prefers-color-scheme: light)').addEventListener('change', applyTheme);

/* ------------------------------------------------------------------- helpers */

function truncated(value, max) {
  const text = String(value || '');
  return text.length > max ? text.slice(0, max) + '…' : text;
}

function shortUrn(urn) {
  if (!urn) return '';
  const tail = String(urn).split(/[/#]/).pop();
  return tail && tail.length > 2 ? tail : String(urn).split(':').pop();
}

function formatBytes(bytes) {
  if (!bytes) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

/* --------------------------------------------------------------------- boot */

(async function boot() {
  await loadSettings();
  renderScopeButton();
  renderCaptureUi();
  setView('saml');
  connect();
})();
