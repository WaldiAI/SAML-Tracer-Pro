/**
 * Service worker: watches webRequest, builds one entry per request hop,
 * flags SAML messages, and streams everything to open tracer panels.
 *
 * The panel keeps its own copy of the capture, so a service-worker restart
 * never loses what an open panel is already showing. chrome.storage.session
 * holds a trimmed backup for panels that open after a restart.
 */

import { messageFromUrl, messageFromForm, parseUrlEncoded, hostOf, hostMatches } from './lib/util.js';
import { JWT_RE } from './lib/jwt.js';

const MAX_ENTRIES = 1200;
const MAX_RAW = 1_500_000;
const PERSIST_LIMIT = 150;
const OWN_ORIGIN = chrome.runtime.getURL('');

const entries = new Map(); // entry id -> entry
let order = []; // entry ids, oldest first
const active = new Map(); // requestId -> { key, hop }
let seq = 0;
let capturing = false; // armed, not listening: capture starts when asked
let samlCount = 0;
const ports = new Set();
const pendingNavigations = new Map(); // in-flight main_frame requestId -> started ms
const NAV_STALE_MS = 20000; // a navigation that never finishes must not block the auto-stop

/**
 * One debugging run. A run ends when the SAML conversation goes quiet
 * (no new message for autoStopIdleSeconds, nothing navigating) or when the
 * hard time limit is reached — a failed login never produces a SAMLResponse,
 * so "stop after the response" alone would listen forever.
 */
const session = { startedAt: 0, deadline: 0, lastSamlAt: 0, responseSeen: false, samlCount: 0, requestCount: 0, reason: '' };
let stopTimer = null;

/**
 * Data-minimisation settings, mirrored from chrome.storage.local (never sync —
 * the config stays on this machine). captureDomains empty means "everything".
 */
const limits = {
  captureDomains: [],
  captureWhenClosed: true,
  captureMode: 'manual', // 'manual' = start/stop on request, 'always' = legacy always-on
  autoStop: true,
  autoStopIdleSeconds: 15,
  autoStopMaxSeconds: 300
};

loadLimits();

async function loadLimits() {
  try {
    const { settings } = await chrome.storage.local.get({ settings: null });
    if (settings) applyLimits(settings);
  } catch {
    /* defaults stand */
  }
}

function applyLimits(settings) {
  const previousMode = limits.captureMode;
  limits.captureDomains = Array.isArray(settings.captureDomains) ? settings.captureDomains : [];
  limits.captureWhenClosed = settings.captureWhenClosed !== false;
  limits.captureMode = settings.captureMode === 'always' ? 'always' : 'manual';
  limits.autoStop = settings.autoStop !== false;
  limits.autoStopIdleSeconds = Number(settings.autoStopIdleSeconds) || 15;
  limits.autoStopMaxSeconds = Number(settings.autoStopMaxSeconds) || 300;

  if (limits.captureMode === 'always' && !capturing) startCapture();
  else if (limits.captureMode === 'manual' && previousMode === 'always' && capturing) stopCapture('mode-changed');
}

/* ------------------------------------------------------------ capture runs */

function startCapture() {
  capturing = true;
  const now = Date.now();
  session.startedAt = now;
  session.deadline =
    limits.captureMode === 'always' || !limits.autoStop || !limits.autoStopMaxSeconds
      ? 0
      : now + limits.autoStopMaxSeconds * 1000;
  session.lastSamlAt = 0;
  session.responseSeen = false;
  session.samlCount = 0;
  session.requestCount = 0;
  session.reason = '';
  pendingNavigations.clear();
  armStopTimer();
  broadcastStatus('started');
  schedulePersist();
}

function stopCapture(reason) {
  capturing = false;
  session.reason = reason;
  clearTimeout(stopTimer);
  stopTimer = null;
  pendingNavigations.clear();
  broadcastStatus(reason);
  schedulePersist();
}

function armStopTimer() {
  clearTimeout(stopTimer);
  if (!capturing || limits.captureMode === 'always' || !limits.autoStop) return;
  const now = Date.now();
  const waits = [];
  if (session.deadline) waits.push(session.deadline - now);
  if (session.responseSeen && session.lastSamlAt) {
    waits.push(session.lastSamlAt + limits.autoStopIdleSeconds * 1000 - now);
  }
  const wait = waits.length ? Math.max(Math.min(...waits), 250) : 0;
  if (wait) stopTimer = setTimeout(maybeAutoStop, wait + 250);
}

/** Navigations still worth waiting for: recent ones only. */
function busyNavigations(now) {
  for (const [id, started] of pendingNavigations) {
    if (now - started > NAV_STALE_MS) pendingNavigations.delete(id);
  }
  return pendingNavigations.size;
}

function maybeAutoStop() {
  if (!capturing || limits.captureMode === 'always' || !limits.autoStop) return;
  const now = Date.now();
  if (session.deadline && now >= session.deadline) {
    stopCapture('time-limit');
    return;
  }
  const quietFor = session.lastSamlAt ? now - session.lastSamlAt : 0;
  const quietEnough = session.responseSeen && quietFor >= limits.autoStopIdleSeconds * 1000;
  if (quietEnough && busyNavigations(now) === 0) {
    stopCapture('flow-complete');
    return;
  }
  armStopTimer();
}

function broadcastStatus(reason) {
  broadcast({ type: 'capturing', value: capturing, reason, session: { ...session } });
  updateBadge();
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.settings) applyLimits(changes.settings.newValue || {});
});

function inCaptureScope(url) {
  if (!limits.captureDomains.length) return true;
  const host = hostOf(url);
  return limits.captureDomains.some((pattern) => hostMatches(pattern, host));
}

/* ------------------------------------------------------------- persistence */

restore();

async function restore() {
  try {
    const saved = await chrome.storage.session.get(['capture', 'capturing', 'session']);
    if (saved.session) Object.assign(session, saved.session);
    if (typeof saved.capturing === 'boolean') capturing = saved.capturing;
    // a worker restart must not silently resurrect an expired run
    if (capturing && session.deadline && Date.now() >= session.deadline) capturing = false;
    if (capturing) armStopTimer();
    if (Array.isArray(saved.capture)) {
      for (const entry of saved.capture) {
        if (entries.has(entry.id)) continue;
        entries.set(entry.id, entry);
        order.unshift(entry.id);
        if (entry.saml) samlCount++;
      }
      order.sort((a, b) => (entries.get(a).seq || 0) - (entries.get(b).seq || 0));
      seq = order.reduce((max, id) => Math.max(max, entries.get(id).seq || 0), 0);
      updateBadge();
    }
  } catch {
    /* session storage unavailable — in-memory only */
  }
}

let persistTimer = null;
function schedulePersist() {
  if (persistTimer) return;
  persistTimer = setTimeout(persist, 2000);
}

async function persist() {
  persistTimer = null;
  try {
    const keep = [];
    for (let i = order.length - 1; i >= 0 && keep.length < PERSIST_LIMIT; i--) {
      const entry = entries.get(order[i]);
      if (!entry) continue;
      if (entry.saml || entry.error || (entry.status || 0) >= 400 || keep.length < 60) {
        keep.push(slim(entry));
      }
    }
    await chrome.storage.session.set({ capture: keep.reverse(), capturing, session });
  } catch {
    /* over quota or storage gone: the panel copy still has everything */
  }
}

function slim(entry) {
  let copy = { ...entry };
  if (!copy.saml && copy.postText && copy.postText.length > 8000) {
    copy.postText = copy.postText.slice(0, 8000) + '…';
  }
  if (copy.saml && copy.saml.raw && copy.saml.raw.length > 800_000) {
    copy = { ...copy, saml: { ...copy.saml, raw: '', truncated: true } };
  }
  return copy;
}

/* ------------------------------------------------------------- panel ports */

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'tracer') return;
  ports.add(port);
  port.onDisconnect.addListener(() => ports.delete(port));
  port.onMessage.addListener((msg) => handlePortMessage(msg, port));
  port.postMessage({
    type: 'init',
    entries: order.map((id) => entries.get(id)).filter(Boolean),
    capturing,
    limits: { ...limits },
    session: { ...session }
  });
});

function handlePortMessage(msg, port) {
  switch (msg && msg.type) {
    case 'ping':
      port.postMessage({ type: 'pong' });
      break;
    case 'clear':
      entries.clear();
      order = [];
      active.clear();
      samlCount = 0;
      session.samlCount = 0;
      session.requestCount = 0;
      updateBadge();
      broadcast({ type: 'cleared' });
      chrome.storage.session.remove('capture').catch(() => {});
      break;
    case 'setCapturing':
      if (msg.value) startCapture();
      else stopCapture('stopped-by-hand');
      break;
    case 'getAll':
      port.postMessage({
    type: 'init',
    entries: order.map((id) => entries.get(id)).filter(Boolean),
    capturing,
    limits: { ...limits },
    session: { ...session }
  });
      break;
  }
}

function broadcast(message) {
  for (const port of ports) {
    try {
      port.postMessage(message);
    } catch {
      ports.delete(port);
    }
  }
}

let patchTimer = null;
const pendingPatches = new Map();

function sendAdd(entry) {
  broadcast({ type: 'add', entry });
}

function sendPatch(id, patch) {
  const merged = pendingPatches.get(id) || {};
  pendingPatches.set(id, Object.assign(merged, patch));
  if (patchTimer) return;
  patchTimer = setTimeout(() => {
    patchTimer = null;
    const items = [...pendingPatches].map(([entryId, entryPatch]) => ({ id: entryId, patch: entryPatch }));
    pendingPatches.clear();
    if (items.length) broadcast({ type: 'patch', items });
  }, 150);
}

/* ------------------------------------------------------------ request store */

function addEntry(entry) {
  entries.set(entry.id, entry);
  order.push(entry.id);
  session.requestCount++;
  if (entry.saml) {
    samlCount++;
    session.samlCount++;
    session.lastSamlAt = Date.now();
    if (/Response$/.test(entry.saml.kind)) session.responseSeen = true;
    armStopTimer();
    updateBadge();
  }
  while (order.length > MAX_ENTRIES) {
    entries.delete(order.shift());
  }
  sendAdd(entry);
  schedulePersist();
}

function patch(requestId, values) {
  const state = active.get(requestId);
  if (!state) return;
  const entry = entries.get(state.key);
  if (!entry) return;
  Object.assign(entry, values);
  sendPatch(entry.id, values);
  schedulePersist();
}

function updateBadge() {
  const text = capturing ? (samlCount ? String(samlCount) : 'REC') : samlCount ? String(samlCount) : '';
  chrome.action.setBadgeText({ text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ color: capturing ? '#c0392b' : '#3b6fd4' }).catch(() => {});
}

/* --------------------------------------------------------------- body decode */

const decoder = new TextDecoder('utf-8', { fatal: false });

function rawToText(raw) {
  try {
    let total = 0;
    for (const part of raw) if (part.bytes) total += part.bytes.byteLength;
    if (!total) return '';
    const buffer = new Uint8Array(Math.min(total, MAX_RAW));
    let offset = 0;
    for (const part of raw) {
      if (!part.bytes) continue;
      const chunk = new Uint8Array(part.bytes);
      const room = buffer.length - offset;
      if (room <= 0) break;
      buffer.set(chunk.subarray(0, room), offset);
      offset += Math.min(chunk.length, room);
    }
    return decoder.decode(buffer.subarray(0, offset));
  } catch {
    return '';
  }
}

function formDataToText(formData) {
  const parts = [];
  for (const [key, values] of Object.entries(formData)) {
    for (const value of values) {
      parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
    }
  }
  return parts.join('&');
}

function capRaw(saml) {
  if (saml && saml.raw && saml.raw.length > MAX_RAW) {
    return { ...saml, raw: saml.raw.slice(0, MAX_RAW), truncated: true };
  }
  return saml;
}

function findJwts(text) {
  if (!text) return [];
  const found = new Set();
  for (const match of String(text).matchAll(JWT_RE)) found.add(match[0]);
  return [...found].slice(0, 8);
}

/* ---------------------------------------------------------------- listeners */

const FILTER = { urls: ['<all_urls>'] };

function ignored(details) {
  const url = details.url || '';
  if (url.startsWith(OWN_ORIGIN) || url.startsWith('chrome://') || url.startsWith('devtools://')) return true;
  if (!limits.captureWhenClosed && ports.size === 0) return true;
  if (!inCaptureScope(url)) return true;
  return false;
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    maybeAutoStop();
    if (!capturing || ignored(details)) return;
    if (details.type === 'main_frame') pendingNavigations.set(details.requestId, details.timeStamp || Date.now());
    const previous = active.get(details.requestId);
    const hop = previous ? previous.hop + 1 : 0;
    const key = `${details.requestId}.${hop}`;
    active.set(details.requestId, { key, hop });

    const entry = {
      id: key,
      requestId: details.requestId,
      hop,
      seq: ++seq,
      tabId: details.tabId,
      frameId: details.frameId,
      type: details.type,
      method: details.method,
      url: details.url,
      initiator: details.initiator || '',
      started: details.timeStamp,
      status: 0,
      statusLine: '',
      requestHeaders: null,
      responseHeaders: null,
      postText: '',
      formData: null,
      saml: null,
      jwts: [],
      redirectUrl: '',
      error: '',
      completed: 0,
      source: 'live'
    };

    const body = details.requestBody;
    if (body) {
      if (body.formData) {
        entry.formData = body.formData;
        entry.postText = formDataToText(body.formData);
      } else if (body.raw) {
        entry.postText = rawToText(body.raw);
        if (/^[\w.%+\-[\]]+=/.test(entry.postText)) entry.formData = parseUrlEncoded(entry.postText);
      } else if (body.error) {
        entry.postText = `[request body unavailable: ${body.error}]`;
      }
    }

    entry.saml = capRaw(messageFromUrl(details.url) || messageFromForm(entry.formData));
    if (entry.saml) entry.saml.paramSource = entry.saml.binding === 'POST' ? 'body' : 'query';
    entry.jwts = findJwts(entry.postText).concat(findJwts(details.url));

    addEntry(entry);
  },
  FILTER,
  ['requestBody']
);

chrome.webRequest.onSendHeaders.addListener(
  (details) => {
    // no capturing guard: a request that was already recorded gets to finish,
    // otherwise patch() is a no-op for anything we never stored
    const headers = details.requestHeaders || [];
    const state = active.get(details.requestId);
    const entry = state && entries.get(state.key);
    const extra = entry ? findJwts(headers.map((h) => h.value).join(' ')) : [];
    patch(details.requestId, {
      requestHeaders: headers,
      jwts: entry ? [...new Set([...(entry.jwts || []), ...extra])].slice(0, 8) : extra
    });
  },
  FILTER,
  ['requestHeaders', 'extraHeaders']
);

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    // no capturing guard: a request that was already recorded gets to finish,
    // otherwise patch() is a no-op for anything we never stored
    patch(details.requestId, {
      status: details.statusCode,
      statusLine: details.statusLine || '',
      responseHeaders: details.responseHeaders || []
    });
  },
  FILTER,
  ['responseHeaders', 'extraHeaders']
);

chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    // no capturing guard: a request that was already recorded gets to finish,
    // otherwise patch() is a no-op for anything we never stored
    patch(details.requestId, {
      status: details.statusCode,
      statusLine: details.statusLine || '',
      responseHeaders: details.responseHeaders || [],
      redirectUrl: details.redirectUrl || '',
      completed: details.timeStamp
    });
  },
  FILTER,
  ['responseHeaders', 'extraHeaders']
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    patch(details.requestId, {
      status: details.statusCode,
      statusLine: details.statusLine || '',
      responseHeaders: details.responseHeaders || [],
      fromCache: !!details.fromCache,
      ip: details.ip || '',
      completed: details.timeStamp
    });
    active.delete(details.requestId);
    pendingNavigations.delete(details.requestId);
    maybeAutoStop();
  },
  FILTER,
  ['responseHeaders', 'extraHeaders']
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    patch(details.requestId, { error: details.error || 'net::ERR_FAILED', completed: details.timeStamp });
    active.delete(details.requestId);
    pendingNavigations.delete(details.requestId);
    maybeAutoStop();
  },
  FILTER
);

/* ------------------------------------------------------------ tracer window */

let tracerWindowId = null;

chrome.action.onClicked.addListener(async () => {
  if (tracerWindowId != null) {
    try {
      await chrome.windows.update(tracerWindowId, { focused: true });
      return;
    } catch {
      tracerWindowId = null;
    }
  }
  const win = await chrome.windows.create({
    url: chrome.runtime.getURL('panel/panel.html?ctx=window'),
    type: 'popup',
    width: 1320,
    height: 920
  });
  tracerWindowId = win.id;
});

chrome.windows.onRemoved.addListener((id) => {
  if (id === tracerWindowId) tracerWindowId = null;
});

chrome.runtime.onInstalled.addListener(() => {
  updateBadge();
});
