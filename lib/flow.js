/**
 * Turns a flat capture into a story: which SSO stage each hop belongs to,
 * what happened there, and what to check when it goes wrong.
 *
 * Pure functions over entry objects — no Chrome APIs, testable in Node.
 */

import { hostOf, isErrorEntry } from './util.js';

/**
 * Stage definitions. `teach` is the plain-words explanation shown to someone
 * seeing SAML for the first time; `checks` is what an IAM admin verifies here.
 */
export const STAGES = {
  'sp-start': {
    label: 'Start at the service provider',
    who: 'SP',
    teach:
      'You asked the application for a page that needs a signed-in user. The app has no session for you yet, so instead of the page it decides to send you to its identity provider.',
    checks: ['Is this the app you expected?', 'Does the app redirect at all, or return its own login form?']
  },
  'authn-request': {
    label: 'AuthnRequest — the SP asks the IdP to authenticate you',
    who: 'SP → IdP',
    teach:
      'The application builds a small signed-or-plain XML message: "please authenticate this browser and send the result to my ACS URL". It travels inside the redirect URL (Redirect binding) or in a hidden form (POST binding). RelayState remembers where you wanted to go.',
    checks: [
      'Issuer = SP Entity ID as configured at the IdP',
      'AssertionConsumerServiceURL matches the ACS the IdP knows',
      'NameIDPolicy format is one the IdP can produce'
    ]
  },
  'wsfed-signin': {
    label: 'WS-Fed sign-in — the SP sends you to the IdP',
    who: 'SP → IdP',
    teach:
      'WS-Federation version of the same idea: the app redirects you to the IdP with wa=wsignin1.0. wtrealm identifies the app, wctx remembers where you were heading.',
    checks: ['wtrealm matches the relying-party identifier at the IdP', 'wreply is an allowed return URL']
  },
  'idp-auth': {
    label: 'Authentication at the identity provider',
    who: 'IdP',
    teach:
      'Now you are on the IdP\'s own pages: login form, password, MFA, policy checks. The SP sees none of this — it only ever gets the final result. If you already had an IdP session, this stage can be a single invisible hop.',
    checks: [
      'Does the IdP show a login page or reuse an existing session?',
      'MFA prompts and policy errors happen here, not at the SP',
      'A loop returning here again and again usually means the SP rejects the response and retries'
    ]
  },
  'saml-response': {
    label: 'SAMLResponse — the IdP sends the assertion back',
    who: 'IdP → SP',
    teach:
      'The IdP answers with a signed XML document: who you are (Subject), which app may consume it (Audience), how long it is valid (Conditions), and your attributes. Your browser carries it in an auto-submitting form to the SP\'s ACS URL — the two servers never talk directly in this binding.',
    checks: [
      'Status is Success (anything else: read StatusMessage and the sub-status)',
      'Audience = SP Entity ID, Destination = ACS URL',
      'NotBefore/NotOnOrAfter window covers "now" — clock skew shows up here',
      'InResponseTo matches the AuthnRequest ID (missing = IdP-initiated flow)',
      'The attributes the SP needs are present and non-empty'
    ]
  },
  'wsfed-token': {
    label: 'WS-Fed token — the IdP posts the token back',
    who: 'IdP → SP',
    teach:
      'The WS-Federation counterpart of the SAMLResponse: a RequestSecurityTokenResponse envelope with a (usually SAML 1.1) assertion inside, posted to the app as the wresult form field.',
    checks: ['AppliesTo matches the relying-party identifier', 'Lifetime (Created/Expires) covers "now"']
  },
  'artifact': {
    label: 'Artifact — a reference instead of the assertion',
    who: 'IdP ↔ SP',
    teach:
      'Only a short reference travels through your browser. The SP exchanges it for the real assertion over a direct back-channel (SOAP) call, which this tool cannot see.',
    checks: ['If the flow fails here, the back-channel between SP and IdP is the place to look — server logs, not the browser']
  },
  'acs-consume': {
    label: 'The SP consumes the assertion',
    who: 'SP',
    teach:
      'The application validates the signature, the audience, the time window and the InResponseTo, then creates its own session — usually visible as a Set-Cookie followed by a redirect to the page you originally wanted.',
    checks: [
      'HTTP status of the ACS request: 302 with Set-Cookie is the happy path, 4xx/5xx means validation failed',
      'A redirect back to the IdP instead of into the app = the SP rejected the response'
    ]
  },
  'sp-reject': {
    label: 'The SP rejected the assertion',
    who: 'SP',
    teach:
      'The assertion was delivered, but instead of a session the application sent the browser to its SSO error page. The HTTP statuses can all be 200 here — the failure lives in the page, not in the transport. The reason is on the SP side: read the error page and the SP\'s SSO logs.',
    checks: [
      'Is the user provisioned at the SP? An unknown Subject/NameID is the most common cause',
      'Does the NameID format and value match what the SP expects (email vs username vs federation ID)?',
      'Audience = SP Entity ID, certificate fingerprint matches the one configured at the SP',
      'SP-side SSO logs usually name the exact reason (e.g. Salesforce: SAML Validation in Setup)'
    ]
  },
  'app-session': {
    label: 'Signed in — back at the application',
    who: 'SP',
    teach:
      'The SP session cookie is set and the browser lands on the target page. From now on requests carry the app\'s own cookie; SAML is out of the picture until the session expires.',
    checks: ['The final page loads with 200', 'No further bounces to the IdP']
  },
  'logout': {
    label: 'Logout',
    who: 'SP ↔ IdP',
    teach:
      'Single logout mirrors the login: LogoutRequest and LogoutResponse messages (or wsignout1.0) end the sessions on both sides.',
    checks: ['Both the SP and the IdP session actually end — half-done logout is a common gap']
  }
};

const STAGE_ORDER = [
  'sp-start',
  'authn-request',
  'wsfed-signin',
  'idp-auth',
  'saml-response',
  'wsfed-token',
  'artifact',
  'acs-consume',
  'sp-reject',
  'app-session',
  'logout'
];

/**
 * SSO failure pages served with a happy HTTP status. The transport succeeded,
 * the login did not — URL shape is the only browser-visible signal.
 */
const ERROR_PAGE_RE =
  /saml.?error|sso.?error|SAMLValidationPage|login\/error|error\/sso|\/loginerror|errorcode=|saml2?\/status|federation.?error|access_denied/i;

export function looksLikeSsoErrorPage(url) {
  return ERROR_PAGE_RE.test(String(url || ''));
}

function isNavigation(entry) {
  return entry.type === 'main_frame' || entry.type === 'sub_frame' || entry.saml;
}

function stageForSaml(entry) {
  const kind = entry.saml.kind || '';
  if (/Logout/i.test(kind) || kind === 'WS-Fed sign-out' || kind === 'WS-Fed sign-out cleanup') return 'logout';
  if (kind === 'SAMLart') return 'artifact';
  if (entry.saml.protocol === 'ws-fed') return entry.saml.raw ? 'wsfed-token' : 'wsfed-signin';
  if (/Response$/.test(kind)) return 'saml-response';
  return 'authn-request';
}

/**
 * Build the flow model from captured entries.
 * @returns {{steps: Array, findings: Array, hosts: {sp:Set, idp:Set}}}
 */
export function buildFlow(entries) {
  const navs = entries.filter(isNavigation).sort((a, b) => (a.started || 0) - (b.started || 0));

  // find the anchor messages first
  const samlIdx = navs.map((e, i) => (e.saml ? i : -1)).filter((i) => i >= 0);
  const firstRequestIdx = samlIdx.find((i) => ['authn-request', 'wsfed-signin'].includes(stageForSaml(navs[i])));
  const responseIdxs = samlIdx.filter((i) => ['saml-response', 'wsfed-token', 'artifact'].includes(stageForSaml(navs[i])));
  const lastResponseIdx = responseIdxs.length ? responseIdxs[responseIdxs.length - 1] : undefined;

  const idpHosts = new Set();
  const spHosts = new Set();
  for (const i of samlIdx) {
    const entry = navs[i];
    const host = hostOf(entry.url);
    const stage = stageForSaml(entry);
    // a request goes TO the IdP; a response goes TO the SP…
    if (stage === 'authn-request' || stage === 'wsfed-signin') idpHosts.add(host);
    if (stage === 'saml-response' || stage === 'wsfed-token') {
      spHosts.add(host);
      // …and the response is POSTed FROM an IdP page, which is the only IdP
      // signal an IdP-initiated flow has (no AuthnRequest ever exists there)
      const from = hostOf(entry.initiator || '');
      if (from && from !== host) idpHosts.add(from);
    }
  }
  // fallback: pages served before the response by hosts with sso/saml paths
  if (!idpHosts.size && lastResponseIdx !== undefined) {
    for (let i = 0; i < lastResponseIdx; i++) {
      if (/\/(sso|saml|adfs|idp)\//i.test(navs[i].url)) idpHosts.add(hostOf(navs[i].url));
    }
  }

  const steps = navs.map((entry, i) => {
    let stage;
    if (entry.saml) {
      stage = stageForSaml(entry);
    } else {
      const host = hostOf(entry.url);
      if (firstRequestIdx !== undefined && i < firstRequestIdx) stage = 'sp-start';
      else if (lastResponseIdx !== undefined && i > lastResponseIdx) {
        if (looksLikeSsoErrorPage(entry.url)) stage = 'sp-reject';
        else stage = spHosts.has(host) || !idpHosts.has(host) ? 'app-session' : 'idp-auth';
      } else if (idpHosts.has(host)) stage = 'idp-auth';
      else if (firstRequestIdx !== undefined && lastResponseIdx !== undefined && i > firstRequestIdx && i < lastResponseIdx)
        stage = 'idp-auth';
      else if (firstRequestIdx === undefined && lastResponseIdx !== undefined && i < lastResponseIdx)
        stage = 'idp-auth'; // IdP-initiated: everything before the response is the IdP side
      else stage = spHosts.has(host) ? 'app-session' : 'sp-start';
    }
    return { entry, stage, index: i };
  });

  // The lane should reflect what the timeline concluded, not only message
  // metadata — initiator is not always populated by the browser.
  for (const step of steps) {
    const host = hostOf(step.entry.url);
    if (!host) continue;
    if (step.stage === 'idp-auth') idpHosts.add(host);
    if (step.stage === 'sp-reject' || step.stage === 'acs-consume') spHosts.add(host);
  }

  return { steps, findings: analyze(steps, navs), hosts: { sp: spHosts, idp: idpHosts } };
}

/** Cross-step diagnostics: things a single entry cannot tell you on its own. */
function analyze(steps, navs) {
  const findings = [];
  const add = (severity, text) => findings.push({ severity, text });

  const requests = steps.filter((s) => s.stage === 'authn-request' || s.stage === 'wsfed-signin');
  const responses = steps.filter((s) => ['saml-response', 'wsfed-token'].includes(s.stage));
  const artifacts = steps.filter((s) => s.stage === 'artifact');

  if (!steps.length) return findings;

  if (!requests.length && responses.length) {
    add('info', 'No AuthnRequest was captured before the response — this looks like an IdP-initiated flow (or capture started after the request went out).');
  }
  if (requests.length && !responses.length && !artifacts.length) {
    add('warn', 'An authentication request went out but no response came back. The flow stalled at the identity provider — a failed login, an unfinished MFA prompt, or capture stopped too early.');
  }
  if (responses.length > 1) {
    add('warn', `${responses.length} responses in one capture. More than one usually means the SP rejected the first response and retried — compare their statuses and timestamps.`);
  }
  if (requests.length > 2) {
    add('err', `${requests.length} authentication requests — a redirect loop between SP and IdP. The SP keeps rejecting what the IdP sends (audience, signature or clock mismatch are the usual causes).`);
  }

  // per-response checks against the surrounding traffic
  for (const step of responses) {
    const entry = step.entry;
    if (isErrorEntry(entry)) {
      add('err', `The response was delivered to ${hostOf(entry.url)} but the SP answered ${entry.error || 'HTTP ' + entry.status} — the assertion reached the app and the app refused it. Open this entry: Status, Conditions and Audience are the first things to compare.`);
    }
  }

  // did anything after the last response error out — by status or by landing on an error page?
  const lastResponse = responses[responses.length - 1];
  if (lastResponse) {
    const after = steps.filter((s) => s.index > lastResponse.index);
    const rejected = after.find((s) => s.stage === 'sp-reject');
    const errAfter = after.find((s) => isErrorEntry(s.entry));
    if (rejected) {
      add(
        'err',
        `The SP accepted the POST but then sent the browser to its SSO error page (${hostOf(rejected.entry.url)}${pathHint(rejected.entry.url)}). The login FAILED even though every HTTP status looks fine. Most common cause: the user is not provisioned at the SP, or the NameID does not match any account there. The SP's own SSO logs name the exact reason.`
      );
    } else if (errAfter && !isErrorEntry(lastResponse.entry)) {
      add('warn', `The assertion was accepted but a later request failed (${hostOf(errAfter.entry.url)} → ${errAfter.entry.error || 'HTTP ' + errAfter.entry.status}). The SSO part worked; the problem is on the application side.`);
    }
    if (!rejected && !errAfter && after.length) {
      add('ok', 'The response was delivered and the traffic after it stayed clean — this flow completed.');
    }
  }

  if (artifacts.length) {
    add('info', 'Artifact binding in use: the assertion itself travels over a back-channel this tool cannot see. Browser-side, you can only verify that the artifact was delivered.');
  }

  return findings;
}

function pathHint(url) {
  try {
    const path = new URL(url).pathname;
    return path && path !== '/' ? ' — ' + path : '';
  } catch {
    return '';
  }
}

export function stageInfo(stageId) {
  return STAGES[stageId] || { label: stageId, who: '', teach: '', checks: [] };
}

export function orderedStagesIn(steps) {
  const present = new Set(steps.map((s) => s.stage));
  return STAGE_ORDER.filter((id) => present.has(id));
}
