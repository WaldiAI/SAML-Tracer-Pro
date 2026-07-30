/** Small helpers shared by the service worker, the panel and the report builder. */

export const SAML_PARAMS = ['SAMLRequest', 'SAMLResponse', 'SAMLart'];

export function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

export function shortUrl(url, max = 120) {
  const s = String(url || '');
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

/** Wildcard host match: "*.okta.com" or "okta.com" or "*test*". Case-insensitive. */
export function hostMatches(pattern, host) {
  const p = String(pattern || '').trim().toLowerCase();
  const h = String(host || '').toLowerCase();
  if (!p || !h) return false;
  if (!p.includes('*')) return h === p || h.endsWith('.' + p);
  const re = new RegExp('^' + p.split('*').map(escapeRe).join('.*') + '$');
  return re.test(h);
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function clockTime(ms) {
  const d = new Date(ms);
  return d.toLocaleTimeString(undefined, { hour12: false });
}

export function fullTime(ms) {
  return new Date(ms).toLocaleString(undefined, { hour12: false });
}

/** ISO 8601 (SAML timestamps) → local time plus a relative hint. */
export function isoToLocal(iso) {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return new Date(t).toLocaleString(undefined, { hour12: false });
}

export function statusClass(entry) {
  if (entry.error) return 'st-err';
  const s = entry.status || 0;
  if (!s) return 'st-none';
  if (s >= 500) return 'st-err';
  if (s >= 400) return 'st-warnerr';
  if (s >= 300) return 'st-redir';
  return 'st-ok';
}

export function isErrorEntry(entry) {
  return !!entry.error || (entry.status || 0) >= 400;
}

const WSFED_ACTIONS = {
  'wsignin1.0': 'WS-Fed sign-in',
  'wsignout1.0': 'WS-Fed sign-out',
  'wsignoutcleanup1.0': 'WS-Fed sign-out cleanup',
  'wattr1.0': 'WS-Fed attribute request',
  'wpseudo1.0': 'WS-Fed pseudonym request'
};

const WSFED_KEYS = ['wa', 'wtrealm', 'wctx', 'wreply', 'whr', 'wct', 'wp', 'wfresh', 'wauth'];

function wsFedExtras(get) {
  const extras = {};
  for (const key of WSFED_KEYS) {
    const value = get(key);
    if (value) extras[key] = value;
  }
  return extras;
}

/** Find SAML parameters in a URL query string. */
export function samlFromUrl(url) {
  try {
    const u = new URL(url);
    for (const key of SAML_PARAMS) {
      const value = u.searchParams.get(key);
      if (value) {
        return {
          kind: key,
          protocol: 'saml',
          opaque: key === 'SAMLart',
          binding: key === 'SAMLart' ? 'Artifact' : 'Redirect',
          raw: value,
          relayState: u.searchParams.get('RelayState') || '',
          sigAlg: u.searchParams.get('SigAlg') || '',
          signature: u.searchParams.get('Signature') || ''
        };
      }
    }
  } catch {
    /* not a parseable URL */
  }
  return null;
}

/** Find SAML parameters in an application/x-www-form-urlencoded body. */
export function samlFromForm(params) {
  if (!params) return null;
  const get = (key) => {
    const v = params[key];
    if (v == null) return '';
    return Array.isArray(v) ? v[0] : v;
  };
  for (const key of SAML_PARAMS) {
    const value = get(key);
    if (value) {
      return {
        kind: key,
        protocol: 'saml',
        opaque: key === 'SAMLart',
        binding: key === 'SAMLart' ? 'Artifact' : 'POST',
        raw: value,
        relayState: get('RelayState'),
        sigAlg: get('SigAlg'),
        signature: get('Signature')
      };
    }
  }
  return null;
}

/**
 * Any federation message we can recognise in a URL: SAML 2.0 / 1.1 bindings
 * first, then WS-Federation (ADFS and anything else speaking wsignin1.0).
 */
export function messageFromUrl(url) {
  const saml = samlFromUrl(url);
  if (saml) return saml;
  try {
    const u = new URL(url);
    const get = (key) => u.searchParams.get(key) || '';
    return wsFedMessage(get, 'Redirect');
  } catch {
    return null;
  }
}

/** Same, for an application/x-www-form-urlencoded body. */
export function messageFromForm(params) {
  const saml = samlFromForm(params);
  if (saml) return saml;
  if (!params) return null;
  const get = (key) => {
    const v = params[key];
    if (v == null) return '';
    return Array.isArray(v) ? v[0] : v;
  };
  return wsFedMessage(get, 'POST');
}

function wsFedMessage(get, binding) {
  const wresult = get('wresult');
  const wa = get('wa');
  if (!wresult && !WSFED_ACTIONS[wa]) return null;
  return {
    kind: wresult ? 'WS-Fed token' : WSFED_ACTIONS[wa],
    protocol: 'ws-fed',
    opaque: !wresult,
    binding,
    raw: wresult,
    relayState: get('wctx'),
    sigAlg: '',
    signature: '',
    extras: wsFedExtras(get)
  };
}

export function parseUrlEncoded(text) {
  const out = {};
  for (const [k, v] of new URLSearchParams(text || '')) {
    (out[k] = out[k] || []).push(v);
  }
  return out;
}

export function headerValue(headers, name) {
  if (!headers) return '';
  const lower = String(name).toLowerCase();
  const hit = headers.find((h) => (h.name || '').toLowerCase() === lower);
  return hit ? hit.value || '' : '';
}

/** Headers that carry credentials of their own and have no business in a shared file. */
export const SENSITIVE_HEADERS =
  /^(cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-csrf-token|x-xsrf-token|dpop)$/i;

export const REDACTED = '[redacted by SAML Tracer Pro]';

export function redactHeaders(headers) {
  if (!headers) return headers;
  return headers.map((header) =>
    SENSITIVE_HEADERS.test(header.name || '') ? { name: header.name, value: REDACTED } : header
  );
}
