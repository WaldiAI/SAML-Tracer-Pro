/**
 * SAML decoding, parsing and XML formatting.
 * Pure functions, no Chrome APIs — usable from the panel, a report builder or a test runner.
 */

/* ------------------------------------------------------------------ base64 */

export function base64ToBytes(input) {
  const clean = String(input).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = clean + '='.repeat((4 - (clean.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function bytesToBase64(bytes) {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

async function inflate(bytes, format) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const utf8 = new TextDecoder('utf-8', { fatal: false });
const looksLikeXml = (s) => /^\s*(<\?xml|<)/.test(s);

/**
 * Decode a SAMLRequest / SAMLResponse parameter value.
 * Handles POST binding (plain base64) and Redirect binding (base64 + raw deflate).
 * @returns {Promise<{xml:string, encoding:string, bytes:number}>}
 */
export async function decodeSamlMessage(param) {
  const text = String(param ?? '');
  // WS-Federation puts the token in wresult as plain XML, no base64 in sight
  if (looksLikeXml(text)) return { xml: text, encoding: 'plain XML', bytes: text.length };
  const bytes = base64ToBytes(text);
  const asText = utf8.decode(bytes);
  if (looksLikeXml(asText)) {
    return { xml: asText, encoding: 'base64', bytes: bytes.length };
  }
  for (const format of ['deflate-raw', 'deflate', 'gzip']) {
    try {
      const out = await inflate(bytes, format);
      const text = utf8.decode(out);
      if (looksLikeXml(text)) {
        const label = format === 'deflate-raw' ? 'base64 + deflate (raw)' : `base64 + ${format}`;
        return { xml: text, encoding: label, bytes: out.length };
      }
    } catch {
      /* try next */
    }
  }
  throw new Error('Not a decodable SAML message: after base64 (and inflate) the payload is not XML.');
}

/* ------------------------------------------------------------------- parse */

const kids = (node, name) => Array.from(node.getElementsByTagNameNS('*', name));
const kid = (node, name) => node.getElementsByTagNameNS('*', name)[0] || null;
const txt = (node) => (node ? (node.textContent || '').trim() : '');
const attr = (node, name) => (node && node.hasAttribute(name) ? node.getAttribute(name) : '');

/** Direct children of `node` with the given local name. */
function directKids(node, name) {
  return Array.from(node.children || []).filter((c) => c.localName === name);
}

const CLAIM_LABELS = {
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'email',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': 'firstName',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': 'lastName',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'name',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier': 'nameIdentifier',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': 'upn',
  'http://schemas.microsoft.com/ws/2008/06/identity/claims/role': 'role',
  'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups': 'groups',
  'http://schemas.xmlsoap.org/claims/Group': 'group',
  'urn:oid:0.9.2342.19200300.100.1.3': 'mail',
  'urn:oid:2.5.4.4': 'sn',
  'urn:oid:2.5.4.42': 'givenName',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'eduPersonPrincipalName',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': 'eduPersonAffiliation'
};

/** Best-effort friendly label for an attribute Name when FriendlyName is absent. */
export function deriveFriendlyName(name) {
  if (!name) return '';
  if (CLAIM_LABELS[name]) return CLAIM_LABELS[name];
  const tail = name.split(/[/#]/).pop() || name;
  return tail.split(':').pop() || name;
}

function parseAttribute(el) {
  const values = kids(el, 'AttributeValue').map((v) => {
    const nested = kid(v, 'NameID');
    const value = txt(nested || v);
    const nil = v.getAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'nil');
    return nil === 'true' ? '' : value;
  }).filter((v) => v !== '');
  const name = attr(el, 'Name') || attr(el, 'AttributeName');
  const namespace = attr(el, 'AttributeNamespace');
  return {
    name: name && namespace && !name.includes(':') && !name.includes('/') ? `${namespace}/${name}` : name,
    friendlyName: attr(el, 'FriendlyName') || deriveFriendlyName(name),
    nameFormat: attr(el, 'NameFormat') || namespace,
    values
  };
}

function parseAssertion(el, doc) {
  const subject = kid(el, 'Subject');
  // SAML 1.1 spells several of these differently (NameIdentifier, AuthenticationStatement…)
  const nameId = subject ? kid(subject, 'NameID') || kid(subject, 'NameIdentifier') : null;
  const scd = subject ? kid(subject, 'SubjectConfirmationData') : null;
  const sc = subject ? kid(subject, 'SubjectConfirmation') : null;
  const conditions = kid(el, 'Conditions');
  const authn = kid(el, 'AuthnStatement') || kid(el, 'AuthenticationStatement');
  const signature = directKids(el, 'Signature')[0] || null;

  return {
    id: attr(el, 'ID'),
    issueInstant: attr(el, 'IssueInstant'),
    issuer: txt(directKids(el, 'Issuer')[0]) || attr(el, 'Issuer'),
    signed: !!signature,
    signatureAlg: signature ? attr(kid(signature, 'SignatureMethod'), 'Algorithm') : '',
    digestAlg: signature ? attr(kid(signature, 'DigestMethod'), 'Algorithm') : '',
    certificates: signature ? kids(signature, 'X509Certificate').map(txt) : [],
    subject: {
      nameId: txt(nameId),
      format: attr(nameId, 'Format'),
      spNameQualifier: attr(nameId, 'SPNameQualifier'),
      confirmationMethod: attr(sc, 'Method') || txt(subject ? kid(subject, 'ConfirmationMethod') : null),
      recipient: attr(scd, 'Recipient'),
      notOnOrAfter: attr(scd, 'NotOnOrAfter'),
      inResponseTo: attr(scd, 'InResponseTo'),
      address: attr(scd, 'Address')
    },
    conditions: {
      notBefore: attr(conditions, 'NotBefore'),
      notOnOrAfter: attr(conditions, 'NotOnOrAfter'),
      audiences: conditions ? kids(conditions, 'Audience').map(txt) : [],
      oneTimeUse: conditions ? !!kid(conditions, 'OneTimeUse') : false
    },
    authn: {
      instant: attr(authn, 'AuthnInstant') || attr(authn, 'AuthenticationInstant'),
      sessionIndex: attr(authn, 'SessionIndex'),
      sessionNotOnOrAfter: attr(authn, 'SessionNotOnOrAfter'),
      contextClassRef:
        txt(authn ? kid(authn, 'AuthnContextClassRef') : null) || attr(authn, 'AuthenticationMethod'),
      authenticatingAuthority: txt(authn ? kid(authn, 'AuthenticatingAuthority') : null),
      ipAddress: authn ? attr(kid(authn, 'SubjectLocality'), 'Address') : ''
    },
    attributes: kids(el, 'Attribute').map(parseAttribute),
    encryptedAttributes: kids(el, 'EncryptedAttribute').length
  };
}

/**
 * Parse decoded SAML XML into a display model.
 * Namespace-agnostic: works with ns2:, saml2:, saml: or no prefix at all.
 */
export function parseSaml(xml) {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const err = doc.getElementsByTagName('parsererror')[0];
  const root = doc.documentElement;
  if (err || !root) {
    return { ok: false, error: (err && err.textContent.trim()) || 'XML could not be parsed.' };
  }

  const kind = root.localName;
  const ns = root.namespaceURI || '';
  const wsFed = /^RequestSecurityTokenResponse(Collection)?$/.test(kind);
  const major = attr(root, 'MajorVersion');
  const family = wsFed
    ? 'ws-fed'
    : major === '1' || /SAML:1\.[01]/.test(ns) || kids(root, 'AuthenticationStatement').length
      ? 'saml1'
      : 'saml2';
  const rootSignature = directKids(root, 'Signature')[0] || null;
  const statusEl = kid(root, 'Status');
  const statusCode = statusEl ? kid(statusEl, 'StatusCode') : null;
  const subStatus = statusCode ? kid(statusCode, 'StatusCode') : null;
  const code = attr(statusCode, 'Value');

  const encryptedAssertions = kids(root, 'EncryptedAssertion').length;
  const assertions = kids(root, 'Assertion').map((a) => parseAssertion(a, doc));

  const model = {
    ok: true,
    kind,
    isResponse: /Response$/.test(kind),
    family,
    protocolLabel: family === 'ws-fed' ? 'WS-Federation' : family === 'saml1' ? 'SAML 1.1' : 'SAML 2.0',
    id: attr(root, 'ID') || attr(root, 'ResponseID') || attr(root, 'RequestID'),
    version: attr(root, 'Version') || (major ? `${major}.${attr(root, 'MinorVersion') || '0'}` : ''),
    issueInstant: attr(root, 'IssueInstant'),
    destination: attr(root, 'Destination'),
    inResponseTo: attr(root, 'InResponseTo'),
    consent: attr(root, 'Consent'),
    issuer:
      txt(directKids(root, 'Issuer')[0]) ||
      attr(root, 'Issuer') ||
      (assertions[0] && assertions[0].issuer) ||
      '',
    signed: !!rootSignature,
    signatureAlg: rootSignature ? attr(kid(rootSignature, 'SignatureMethod'), 'Algorithm') : '',
    digestAlg: rootSignature ? attr(kid(rootSignature, 'DigestMethod'), 'Algorithm') : '',
    certificates: rootSignature ? kids(rootSignature, 'X509Certificate').map(txt) : [],
    status: statusEl
      ? {
          code,
          short: code ? code.split(':').pop() : '',
          subCode: attr(subStatus, 'Value'),
          message: txt(kid(statusEl, 'StatusMessage')),
          detail: txt(kid(statusEl, 'StatusDetail')),
          // SAML 2.0 sends a URN, SAML 1.1 a QName like "samlp:Success"
          isSuccess: /(^|:)Success$/.test(code || '')
        }
      : null,
    encryptedAssertions,
    encryptedIds: kids(root, 'EncryptedID').length,
    assertions
  };

  if (wsFed) {
    // ADFS and friends wrap the assertion in a WS-Trust token response
    model.wsfed = {
      tokenType: txt(kid(root, 'TokenType')),
      appliesTo: txt(kid(root, 'Address')),
      created: txt(kid(root, 'Created')),
      expires: txt(kid(root, 'Expires')),
      keyType: txt(kid(root, 'KeyType')),
      requestType: txt(kid(root, 'RequestType'))
    };
  }

  if (kind === 'AuthnRequest') {
    const policy = kid(root, 'NameIDPolicy');
    const rac = kid(root, 'RequestedAuthnContext');
    model.request = {
      acsUrl: attr(root, 'AssertionConsumerServiceURL'),
      acsIndex: attr(root, 'AssertionConsumerServiceIndex'),
      protocolBinding: attr(root, 'ProtocolBinding'),
      forceAuthn: attr(root, 'ForceAuthn'),
      isPassive: attr(root, 'IsPassive'),
      providerName: attr(root, 'ProviderName'),
      nameIdFormat: attr(policy, 'Format'),
      allowCreate: attr(policy, 'AllowCreate'),
      spNameQualifier: attr(policy, 'SPNameQualifier'),
      comparison: attr(rac, 'Comparison'),
      requestedContext: rac ? kids(rac, 'AuthnContextClassRef').map(txt) : [],
      scopingIdps: kids(root, 'IDPEntry').map((e) => attr(e, 'ProviderID'))
    };
  }

  if (kind === 'LogoutRequest') {
    model.logout = {
      nameId: txt(kid(root, 'NameID')),
      sessionIndex: txt(kid(root, 'SessionIndex')),
      reason: attr(root, 'Reason'),
      notOnOrAfter: attr(root, 'NotOnOrAfter')
    };
  }

  // Flattened view used by the summary block and the HTML report.
  const a0 = assertions[0];
  model.summary = {
    issuer: model.issuer,
    destination:
      model.destination ||
      (model.request && model.request.acsUrl) ||
      (model.wsfed && model.wsfed.appliesTo) ||
      '',
    subject: a0 ? a0.subject.nameId : model.logout ? model.logout.nameId : '',
    status: model.status ? model.status.code : '',
    issued: model.issueInstant,
    notBefore: a0 ? a0.conditions.notBefore : '',
    notOnOrAfter: a0 ? a0.conditions.notOnOrAfter : '',
    audiences: a0 ? a0.conditions.audiences : [],
    attributes: a0 ? a0.attributes : []
  };

  return model;
}

/** SHA-256 fingerprint of a base64 DER certificate, as colon-separated hex. */
export async function certFingerprint(b64) {
  try {
    const der = base64ToBytes(b64);
    const digest = await crypto.subtle.digest('SHA-256', der);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(':')
      .toUpperCase();
  } catch {
    return '';
  }
}

/* ------------------------------------------------------- pretty print + hl */

const INDENT = '  ';

/** Re-indent XML that arrived as a single line. */
export function formatXml(xml) {
  const collapsed = String(xml).replace(/\r\n?/g, '\n').replace(/>\s+</g, '><').trim();
  const tokens = collapsed.match(/<!--[\s\S]*?-->|<[?!][^>]*>|<[^>]*>|[^<]+/g) || [];
  const lines = [];
  let depth = 0;

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const pad = INDENT.repeat(Math.max(depth, 0));

    if (token.startsWith('<?') || token.startsWith('<!')) {
      lines.push(pad + token);
      continue;
    }
    if (token.startsWith('</')) {
      depth--;
      lines.push(INDENT.repeat(Math.max(depth, 0)) + token);
      continue;
    }
    if (token.startsWith('<')) {
      const selfClosing = /\/\s*>$/.test(token);
      const next = tokens[i + 1];
      const after = tokens[i + 2];
      // <tag>text</tag> stays on one line
      if (!selfClosing && next && !next.startsWith('<') && after && after.startsWith('</')) {
        lines.push(pad + token + next.trim() + after);
        i += 2;
        continue;
      }
      lines.push(pad + token);
      if (!selfClosing) depth++;
      continue;
    }
    const text = token.trim();
    if (text) lines.push(pad + text);
  }
  return lines.join('\n');
}

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function tagToHtml(token) {
  const open = token.startsWith('</') ? '</' : '<';
  let body = token.slice(open.length, -1);
  let close = '>';
  if (/\/\s*$/.test(body)) {
    body = body.replace(/\/\s*$/, '');
    close = '/>';
  }
  const name = (body.match(/^[^\s]*/) || [''])[0];
  const rest = body.slice(name.length);

  let attrs = '';
  const re = /([\w:.-]+)(\s*=\s*)("[^"]*"|'[^']*')/g;
  let last = 0;
  let m;
  while ((m = re.exec(rest))) {
    attrs += escapeHtml(rest.slice(last, m.index));
    attrs += `<span class="x-att">${escapeHtml(m[1])}</span>${escapeHtml(m[2])}`;
    attrs += `<span class="x-val">${escapeHtml(m[3])}</span>`;
    last = m.index + m[0].length;
  }
  attrs += escapeHtml(rest.slice(last));

  return (
    `<span class="x-pun">${escapeHtml(open)}</span>` +
    `<span class="x-tag">${escapeHtml(name)}</span>` +
    attrs +
    `<span class="x-pun">${escapeHtml(close)}</span>`
  );
}

/** Syntax-highlight already formatted XML. Everything is escaped on the way out. */
export function highlightXml(pretty) {
  const tokens = String(pretty).match(/<!--[\s\S]*?-->|<[?!][^>]*>|<[^>]*>|[^<]+/g) || [];
  let out = '';
  for (const token of tokens) {
    if (token.startsWith('<!--')) out += `<span class="x-com">${escapeHtml(token)}</span>`;
    else if (/^<[?!]/.test(token)) out += `<span class="x-decl">${escapeHtml(token)}</span>`;
    else if (token.startsWith('<')) out += tagToHtml(token);
    else out += `<span class="x-txt">${escapeHtml(token)}</span>`;
  }
  return out;
}
