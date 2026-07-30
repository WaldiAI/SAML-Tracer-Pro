/** Builds a single self-contained HTML file from a capture. Safe to attach to a ticket. */

import { escapeHtml, formatXml, highlightXml } from './saml.js';
import { clockTime, fullTime, isoToLocal, statusClass, isErrorEntry, hostOf } from './util.js';

const CSS = `
:root{--bg:#0f1319;--card:#161c26;--line:#232c39;--text:#e6ebf4;--dim:#95a2b7;--faint:#6c7889;
--ok:#46c39a;--redir:#ddb05a;--warn:#ffa657;--err:#ff6b6b;--gold:#f2b53b;--saml:#86a9f5;--violet:#b98ce0;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--ui:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:13px/1.55 var(--ui);padding:26px 22px 60px}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:20px;margin:0 0 4px}
.meta{color:var(--faint);font:11.5px var(--mono);margin-bottom:18px}
.stats{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:22px}
.stat{border:1px solid var(--line);border-radius:8px;padding:7px 12px;background:var(--card)}
.stat b{display:block;font:600 16px var(--mono)}
.stat span{color:var(--faint);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
h2{font-size:15px;margin:26px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.card{border:1px solid var(--line);border-radius:9px;background:var(--card);padding:14px 16px;margin-bottom:14px}
.card h3{margin:0 0 8px;font-size:13.5px}
.card h3 .kind{color:var(--saml)}
.card h3 .t{color:var(--faint);font:11px var(--mono);font-weight:400;margin-left:6px}
.badges{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 12px}
.badge{border:1px solid var(--line);border-radius:999px;padding:2px 9px;font-size:11px;color:var(--dim)}
.badge.ok{color:var(--ok)}.badge.err{color:var(--err)}.badge.warn{color:var(--warn)}.badge.info{color:var(--saml)}
dl.kv{display:grid;grid-template-columns:170px 1fr;gap:1px 12px;margin:0 0 12px}
dl.kv dt{color:var(--faint);font-size:11.5px;padding:2px 0}
dl.kv dd{margin:0;padding:2px 0;font:12px var(--mono);overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;table-layout:fixed;margin-bottom:12px}
th{text-align:left;font:600 10px var(--ui);letter-spacing:.09em;text-transform:uppercase;color:var(--faint);
padding:0 10px 6px 0;border-bottom:1px solid var(--line)}
td{padding:6px 10px 6px 0;border-bottom:1px solid #1c2430;font:12px var(--mono);vertical-align:top;overflow-wrap:anywhere}
td .none{color:var(--faint);font-style:italic}
.chip{background:#1d2532;border-radius:4px;padding:1px 6px;font:11.5px var(--mono)}
details{border:1px solid var(--line);border-radius:8px;margin-bottom:12px;background:#121820}
summary{padding:7px 10px;cursor:pointer;font-weight:600;font-size:12.5px}
pre.xml{margin:0;padding:10px 12px;border-top:1px solid #1c2430;font:11.5px/1.5 var(--mono);
white-space:pre-wrap;overflow-wrap:anywhere;tab-size:2}
.x-tag{color:var(--saml)}.x-att{color:var(--gold)}.x-val{color:var(--ok)}.x-pun{color:var(--faint)}
.x-txt{color:var(--text)}.x-decl,.x-com{color:var(--faint)}
.st-ok{color:var(--ok)}.st-redir{color:var(--redir)}.st-warnerr{color:var(--warn)}.st-err{color:var(--err)}.st-none{color:var(--faint)}
tr.saml td:nth-child(4){color:var(--saml)}
footer{margin-top:30px;color:var(--faint);font-size:11px}
@media print{body{background:#fff;color:#111}.card,.stat,details{background:#fff;border-color:#ccc}
pre.xml,td,th{color:#111}.x-tag{color:#1a4b9c}.x-att{color:#7a5200}.x-val{color:#155e45}}
`;

const cell = (value) =>
  value ? escapeHtml(value) : '<span class="none">(empty)</span>';

function kv(rows) {
  const body = rows
    .filter(([, value]) => value !== '' && value != null)
    .map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${cell(String(value))}</dd>`)
    .join('');
  return body ? `<dl class="kv">${body}</dl>` : '';
}

function attributesTable(attributes) {
  if (!attributes || !attributes.length) return '';
  const rows = attributes
    .map(
      (a) => `<tr><td><span class="chip">${escapeHtml(a.friendlyName || '')}</span></td>
<td>${escapeHtml(a.name || '')}</td>
<td>${a.values.length ? a.values.map(escapeHtml).join('<br>') : '<span class="none">(no values)</span>'}</td></tr>`
    )
    .join('');
  return `<table><colgroup><col style="width:22%"><col style="width:34%"><col></colgroup>
<thead><tr><th>Friendly</th><th>Name</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function headersTable(title, headers) {
  if (!headers || !headers.length) return '';
  const rows = headers
    .map((h) => `<tr><td><span class="chip">${escapeHtml(h.name)}</span></td><td>${cell(h.value)}</td></tr>`)
    .join('');
  return `<details><summary>${escapeHtml(title)} (${headers.length})</summary>
<table style="margin:0"><colgroup><col style="width:220px"><col></colgroup><tbody>${rows}</tbody></table></details>`;
}

function samlCard(entry, decoded) {
  const model = decoded && decoded.model;
  const kind = (entry.saml && entry.saml.kind) || 'SAML';
  const binding = (entry.saml && entry.saml.binding) || '';
  const a0 = model && model.assertions && model.assertions[0];

  const badges = [];
  if (model && model.status) {
    badges.push(
      `<span class="badge ${model.status.isSuccess ? 'ok' : 'err'}">${escapeHtml(model.status.short || model.status.code)}</span>`
    );
  }
  if (model && model.signed) badges.push('<span class="badge info">Response signed</span>');
  if (a0 && a0.signed) badges.push('<span class="badge info">Assertion signed</span>');
  if (model && model.encryptedAssertions) badges.push('<span class="badge warn">Encrypted assertion</span>');
  if (binding) badges.push(`<span class="badge">${escapeHtml(binding)} binding</span>`);
  if (decoded && decoded.encoding) badges.push(`<span class="badge">${escapeHtml(decoded.encoding)}</span>`);

  const summaryRows = [
    ['URL', entry.url],
    ['Issuer', model ? model.issuer : ''],
    ['Destination', model ? model.destination : ''],
    ['Subject', model ? model.summary.subject : ''],
    ['Status', model && model.status ? model.status.code : ''],
    ['Issued', model ? `${model.issueInstant} ${model.issueInstant ? '· ' + isoToLocal(model.issueInstant) : ''}` : ''],
    ['InResponseTo', model ? model.inResponseTo : ''],
    ['Message ID', model ? model.id : ''],
    ['NotBefore', a0 ? a0.conditions.notBefore : ''],
    ['NotOnOrAfter', a0 ? a0.conditions.notOnOrAfter : ''],
    ['Audience', a0 ? a0.conditions.audiences.join(', ') : ''],
    ['SessionIndex', a0 ? a0.authn.sessionIndex : ''],
    ['AuthnContext', a0 ? a0.authn.contextClassRef : ''],
    ['RelayState', entry.saml ? entry.saml.relayState : '']
  ];

  const xml = decoded && decoded.xml ? formatXml(decoded.xml) : '';
  const rawBlock = xml
    ? `<details><summary>Raw XML (${xml.split('\n').length} lines)</summary><pre class="xml">${highlightXml(xml)}</pre></details>`
    : `<p class="none">XML could not be decoded${decoded && decoded.error ? ': ' + escapeHtml(decoded.error) : '.'}</p>`;

  return `<div class="card">
<h3><span class="kind">${escapeHtml(kind)}</span> <span class="t">${escapeHtml(clockTime(entry.started))} · ${escapeHtml(entry.method)} ${escapeHtml(hostOf(entry.url))}</span></h3>
<div class="badges">${badges.join('')}</div>
${kv(summaryRows)}
${a0 ? attributesTable(a0.attributes) : ''}
${rawBlock}
${headersTable('Request headers', entry.requestHeaders)}
${headersTable('Response headers', entry.responseHeaders)}
</div>`;
}

function trafficRows(entries) {
  return entries
    .map(
      (e) => `<tr class="${e.saml ? 'saml' : ''}">
<td>${escapeHtml(clockTime(e.started))}</td>
<td>${escapeHtml(e.method || '')}</td>
<td class="${statusClass(e)}">${escapeHtml(e.error ? e.error : String(e.status || '—'))}</td>
<td>${e.saml ? escapeHtml(e.saml.kind) : ''}</td>
<td>${escapeHtml(e.url)}</td></tr>`
    )
    .join('');
}

/**
 * @param {{entries:Array, decodedById:Map, title?:string, note?:string}} input
 * @returns {string} complete HTML document
 */
export function buildHtmlReport({ entries, decodedById, title, note }) {
  const samlEntries = entries.filter((e) => e.saml);
  const errorEntries = entries.filter(isErrorEntry);
  const generated = fullTime(Date.now());
  const hosts = [...new Set(entries.map((e) => hostOf(e.url)).filter(Boolean))];

  const cards = samlEntries.map((e) => samlCard(e, decodedById.get(e.id))).join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title || 'SAML capture report')}</title>
<style>${CSS}</style></head>
<body><div class="wrap">
<h1>${escapeHtml(title || 'SAML capture report')}</h1>
<p class="meta">Generated ${escapeHtml(generated)} · SAML Tracer Pro${note ? ' · ' + escapeHtml(note) : ''}</p>
<div class="stats">
<div class="stat"><b>${entries.length}</b><span>requests</span></div>
<div class="stat"><b>${samlEntries.length}</b><span>SAML messages</span></div>
<div class="stat"><b>${errorEntries.length}</b><span>errors</span></div>
<div class="stat"><b>${hosts.length}</b><span>hosts</span></div>
</div>

<h2>SAML messages</h2>
${cards || '<p class="none">No SAML messages in this capture.</p>'}

${
  errorEntries.length
    ? `<h2>Errors</h2><table><colgroup><col style="width:80px"><col style="width:60px"><col style="width:120px"><col style="width:120px"><col></colgroup>
<thead><tr><th>Time</th><th>Method</th><th>Status</th><th>SAML</th><th>URL</th></tr></thead>
<tbody>${trafficRows(errorEntries)}</tbody></table>`
    : ''
}

<h2>All traffic</h2>
<table><colgroup><col style="width:80px"><col style="width:60px"><col style="width:80px"><col style="width:120px"><col></colgroup>
<thead><tr><th>Time</th><th>Method</th><th>Status</th><th>SAML</th><th>URL</th></tr></thead>
<tbody>${trafficRows(entries)}</tbody></table>

<footer>Signatures are not verified in this report. Tokens and assertions in it are credentials — treat the file as sensitive.</footer>
</div></body></html>`;
}
