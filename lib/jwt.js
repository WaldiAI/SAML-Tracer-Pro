/**
 * JWT / JWS decoding. Decodes only — signatures are never verified,
 * so nothing here should be used to make trust decisions.
 */

import { base64ToBytes } from './saml.js';

const utf8 = new TextDecoder('utf-8', { fatal: false });

const CLAIM_NOTES = {
  iss: 'Issuer',
  sub: 'Subject',
  aud: 'Audience',
  exp: 'Expires at',
  nbf: 'Not before',
  iat: 'Issued at',
  jti: 'JWT ID',
  azp: 'Authorized party',
  scp: 'Scopes',
  scope: 'Scopes',
  cid: 'Client ID',
  client_id: 'Client ID',
  uid: 'User ID',
  ver: 'Version',
  nonce: 'Nonce',
  at_hash: 'Access token hash',
  auth_time: 'Authentication time',
  amr: 'Authentication methods',
  idp: 'Identity provider',
  groups: 'Groups',
  email: 'Email',
  preferred_username: 'Preferred username'
};

export const JWT_RE = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{0,}/g;

function decodePart(part) {
  const bytes = base64ToBytes(part);
  const text = utf8.decode(bytes);
  try {
    return { json: JSON.parse(text), text };
  } catch {
    return { json: null, text };
  }
}

/**
 * @param {string} token raw compact-serialization token
 * @returns {{ok:boolean, error?:string, header?:object, payload?:object,
 *            headerText?:string, payloadText?:string, signature?:string,
 *            highlights?:Array, expired?:boolean|null, parts?:number}}
 */
export function decodeJwt(token) {
  const raw = String(token).trim().replace(/^Bearer\s+/i, '').replace(/\s+/g, '');
  if (!raw) return { ok: false, error: 'Paste a token to decode it.' };

  const parts = raw.split('.');
  if (parts.length < 2) {
    return { ok: false, error: 'A JWT needs at least two dot-separated parts (header.payload).' };
  }
  if (parts.length === 5) {
    return {
      ok: false,
      error: 'This looks like an encrypted token (JWE, five parts). Decoding needs the recipient key.'
    };
  }

  let header;
  let payload;
  try {
    header = decodePart(parts[0]);
    payload = decodePart(parts[1]);
  } catch (e) {
    return { ok: false, error: 'Base64url decoding failed: ' + e.message };
  }
  if (!header.json) return { ok: false, error: 'The header is not valid JSON after base64url decoding.' };

  const claims = payload.json || {};
  const now = Math.floor(Date.now() / 1000);
  const expired = typeof claims.exp === 'number' ? claims.exp < now : null;

  const highlights = [];
  const push = (label, value, extra) => {
    if (value !== undefined && value !== null && value !== '') highlights.push({ label, value, extra });
  };
  push('Algorithm', header.json.alg);
  push('Type', header.json.typ);
  push('Key ID', header.json.kid);
  push('Issuer', claims.iss);
  push('Audience', Array.isArray(claims.aud) ? claims.aud.join(', ') : claims.aud);
  push('Subject', claims.sub);
  push('Client', claims.cid || claims.client_id || claims.azp);
  push('Scopes', Array.isArray(claims.scp) ? claims.scp.join(' ') : claims.scope);
  if (typeof claims.iat === 'number') push('Issued at', epochToText(claims.iat));
  if (typeof claims.nbf === 'number') push('Not before', epochToText(claims.nbf));
  if (typeof claims.exp === 'number') {
    push('Expires at', epochToText(claims.exp), expired ? 'expired' : 'valid');
  }
  if (typeof claims.exp === 'number' && typeof claims.iat === 'number') {
    push('Lifetime', humanDuration((claims.exp - claims.iat) * 1000));
  }

  return {
    ok: true,
    parts: parts.length,
    header: header.json,
    payload: claims,
    headerText: header.text,
    payloadText: payload.json ? JSON.stringify(payload.json, null, 2) : payload.text,
    payloadIsJson: !!payload.json,
    signature: parts[2] || '',
    unsecured: header.json.alg === 'none' || !parts[2],
    expired,
    highlights,
    claimNotes: CLAIM_NOTES
  };
}

export function epochToText(seconds) {
  const d = new Date(seconds * 1000);
  const delta = d.getTime() - Date.now();
  const rel = delta >= 0 ? `in ${humanDuration(delta)}` : `${humanDuration(-delta)} ago`;
  return `${d.toLocaleString()} (${rel})`;
}

export function humanDuration(ms) {
  const s = Math.round(Math.abs(ms) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}
