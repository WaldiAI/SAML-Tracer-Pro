# SAML Tracer Pro

A Chrome extension (Manifest V3) for debugging SSO: it captures traffic, decodes `SAMLRequest` / `SAMLResponse` on the fly, shows attributes under friendly names, and provides an all-requests view, an errors view, and a JWT decoder. Everything runs locally — the extension sends nothing anywhere.

Detection works **at the protocol level, not the vendor level** — nothing in the code is hardwired to a specific IdP. See the [IAM vendor compatibility](#iam-vendor-compatibility) section for details.

## Installation (developer mode)

1. Unpack the archive, e.g. into `~/saml-tracer-pro`.
2. Open `chrome://extensions`.
3. Enable **Developer mode** (top-right corner).
4. **Load unpacked** → point at the directory containing `manifest.json`.
5. Pin the icon to the toolbar.

Updating after editing files: click **Reload** on the extension tile (for changes in `panel/`, closing and reopening the tracer window is enough).

## Two ways to use it

| Mode | How to open | When |
| --- | --- | --- |
| Separate window | click the toolbar icon | the login bounces you across domains and you want the tracer next to the browser window |
| DevTools panel | F12 → **SAML** tab | you're debugging alongside Network / Console |

## Recording lifecycle

By default the extension **does not listen**. A single debugging session looks like this:

1. **Start capture** (button in the toolbar or `Ctrl/Cmd+Enter`) — only now is anything captured.
2. Kick off the login. Order matters: start **before** you click, otherwise you lose the `AuthnRequest`, i.e. the beginning of the flow.
3. The extension stops on its own once the SAML conversation **goes quiet** — by default 15 s with no new SAML message and no navigation in flight.
4. Captured data stays in the panel until you click `Clear`. The status bar tells you why recording ended and offers "Start again".

Why quiet time rather than "stop once `SAMLResponse` arrives": right after the assertion is when the actual failure often happens — the SP establishes a session and redirects, loops back to the IdP, or returns a 500. Stopping the second the assertion arrives would cut off the most interesting part. The quiet window keeps that tail in the recording while still ending the session within seconds.

Additional safeguards:

- **Hard time limit** (default 5 min). If the login dies on the IdP side, the `SAMLResponse` never arrives and the quiet condition would never trigger by itself.
- **A stuck navigation doesn't block the stop** — a `main_frame` request that doesn't finish within 20 s stops being taken into account.
- **The toolbar icon shows `REC`** in red while listening is active. You can't accidentally leave recording on without a trace.

In settings you can switch back to **Always on** mode (listening from browser startup, even with the panel closed) — then you open the panel after the fact and see the latest messages from the `chrome.storage.session` buffer. That mode is more convenient but collects considerably more data.

## Tabs

- **SAML** — SAML messages only. Header: URL, Issuer, Destination, Subject, Status, Issued, Encoding. Then: badges (response / assertion signature, encryption, binding), a validity bar, the attribute table (Friendly / Name / Value), Conditions, Authentication, Signature with the certificate fingerprint, Parameters, request and response headers, and finally a collapsible **Raw XML** with syntax highlighting.
- **All Traffic** — every request with method, status, type, timing, redirect, POST body and headers. Each redirect hop is its own row.
- **Errors** — only 4xx, 5xx and network errors (`net::ERR_*`).
- **Flow** — the captured login replayed stage by stage as a timeline: start in the app → `AuthnRequest` → authentication at the IdP → assertion → consumption at the ACS → application session (WS-Fed and logout analogously). Each stage has a plain-language description (what's happening, who is talking to whom) and an expandable "What to check at this stage" list. Above the timeline: a Browser ⇄ IdP ⇄ SP actor bar with the recognized hosts, plus **automatic diagnoses** — flow stalled at the IdP, assertion rejected by the SP (with the status code), redirect loop, IdP-initiated flow, artifact binding, and also **the SP rejecting the assertion despite clean HTTP statuses** — many applications (e.g. Salesforce) respond to failed validation with a 302 redirect to their own error page served with a 200; Flow recognizes such pages by their path (`SamlError`, `SAMLValidationPage`, `sso-error`, `errorcode=`...), marks the stage "The SP rejected the assertion" and suggests the most common cause: the user not provisioned on the SP side, or a NameID matching no account. Clicking any hop jumps to its details. The tab doubles as a SAML tutorial for someone seeing the protocol for the first time — when empty it shows a description of what the login will look like.
- **JWT** — paste a token (or click a token picked up from an `Authorization` header in the traffic): header, payload, signature, and a Highlights panel with iss / aud / exp and whether the token has expired.

The filter above the list searches by URL, method and status — multiple words act as AND (`post 500 acs`).

Shortcuts: `Ctrl/Cmd+Enter` start/stop recording, `1`–`5` tabs, `↑`/`↓` or `j`/`k` row selection, `/` or `Ctrl/Cmd+F` filter.

## What the original doesn't have

- **Assertion validity bar** — `NotBefore` → `NotOnOrAfter` with a "now" marker, a countdown to expiry, and a clock-skew hint when the assertion isn't valid yet. This is the most common cause of "login works for me, fails for the customer".
- **HAR import** — besides saml-tracer's JSON format it also loads HAR from DevTools and loose request arrays. The importer is tolerant: it maps `request`/`response`, headers as an array or an object, `postData` as text or `params`, and detects SAML in the URL and in the POST body on its own.
- **Certificate fingerprint** — SHA-256 of the certificate from `<ds:X509Certificate>` plus copying it as PEM. You compare it with the certificate in the Okta app without leaving the panel.
- **JWT detection in traffic** — tokens from headers and request bodies are collected and available with one click in the JWT tab.
- **Pinned fields bar** with extended syntax (`path[n]`, `query:name`, `saml:attr:email`).
- **Copy as text** — the whole entry (summary + attributes + headers + XML) ready to paste into a ticket.
- Works in a separate window, not just in DevTools.

## Settings (gear icon)

- **Highlighted domains** — one host per line, wildcards allowed (`*.okta.com`, `sp.samltest.*`). Matching rows get a gold star. Entering a bare domain (`okta.com`) covers subdomains too.
- **Pinned fields** — fields shown in the bar above each entry:
  - a header name, e.g. `Set-Cookie` (looked up in the response first, then the request),
  - `saml:issuer`, `saml:destination`, `saml:subject`, `saml:status`, `saml:audience`, `saml:notbefore`, `saml:notonorafter`, `saml:sessionindex`, `saml:inresponseto`, `saml:relaystate`, `saml:binding`, `saml:nameidformat`,
  - `saml:attr:email` — a specific attribute by friendly or full name,
  - `path[2]` / `path[-1]` — a URL path segment (extracting a tenant or application ID),
  - `query:RelayState`, `url`, `host`, `status`.
  The pin button next to every header, attribute and summary field adds an entry here automatically.
- **Capture** — `Only when I start it` (default) or `Always on`.
- **Stop after quiet** — length of the quiet window that ends a session (5–60 s).
- **Hard time limit** — upper bound for a single recording session (1 min – unlimited).
- **Stop capturing by itself once the SAML flow goes quiet** — turning this off leaves recording running until a manual stop (the hard limit still applies).
- **Capture only these domains** — an allowlist of hosts that get captured at all (wildcards allowed). Empty = all traffic. Listing your IdP and SP here is the strongest form of minimization: traffic outside the list never even reaches memory.
- **Remove Cookie and Authorization headers…** — on by default. JSON export, the HTML report and "Copy" replace the values of the `Cookie`, `Set-Cookie`, `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `X-CSRF-Token` and `DPoP` headers with `[redacted by SAML Tracer Pro]`. Header names stay, so you can see what was there. In the panel you see the full values — redaction only applies to what leaves the tool.
- **In always-on mode, keep capturing while no tracer window is open** — applies to Always on mode only.
- **Theme** — dark, light, or follow the browser (in DevTools it follows the DevTools theme).
- **Keep at most** — limit on stored requests.

## IAM vendor compatibility

Detection is based on parameter names from the SAML 2.0 bindings (`SAMLRequest`, `SAMLResponse`, `SAMLart`) and WS-Federation (`wa=wsignin1.0`, `wresult`), and the parser is **namespace-prefix agnostic** — `saml2:`, `saml:`, `ns2:`, `t:` or no prefix at all are treated identically. No vendor name appears in the code beyond examples in comments.

| Protocol / vendor | Status | Notes |
| --- | --- | --- |
| SAML 2.0 — Okta, Entra ID (Azure AD), Ping, Keycloak, Shibboleth, Auth0, OneLogin, JumpCloud, Google Workspace, Salesforce as IdP | full support | both bindings (POST and Redirect), `AuthnRequest`, `Response`, `LogoutRequest`/`LogoutResponse` |
| SAML 1.1 (older ADFS, legacy SSO) | full support | `NameIdentifier`, `AuthenticationStatement`, `AudienceRestrictionCondition`, `AttributeName` + `AttributeNamespace`, status as a QName (`samlp:Success`) |
| WS-Federation — ADFS and derivatives | full support | `wsignin1.0` / `wsignout1.0` with the `wtrealm`, `wctx`, `wreply`, `whr` parameters; the `wresult` token as plain XML (no base64), a "WS-Federation envelope" section with `AppliesTo`, `TokenType` and lifetime |
| Artifact binding (`SAMLart`) | detected, not decoded | the SP fetches the assertion over a back channel (SOAP), the browser never sees it — the panel says so outright instead of showing a decoding error |
| Encrypted assertions (`EncryptedAssertion`) | detected, not decrypted | decryption requires the SP's private key; the panel shows an "Encrypted assertion" badge |
| OIDC / OAuth 2.0 — Entra ID, Auth0, Keycloak, Okta | partial | requests and responses visible in **All Traffic**, `Bearer` tokens and `id_token`s from headers and bodies are picked up into the JWT tab. There is no dedicated OIDC flow view. Mind a browser limitation: the URL fragment (`#id_token=…` in the implicit flow) is never sent to the server, so it doesn't appear in `webRequest` |
| WS-Trust (SOAP), CAS, Kerberos/SPNEGO | none | different protocols, no parser |

Attribute names are translated into readable labels for the `schemas.xmlsoap.org` (ADFS, Entra ID), `schemas.microsoft.com` and `urn:oid:` (Shibboleth / eduPerson) schemas. If the IdP sends a `FriendlyName`, it takes precedence; otherwise the label is derived from the name.

The tests cover real response shapes from Entra ID (no namespace prefixes), ADFS over WS-Fed with a SAML 1.1 assertion in a WS-Trust envelope, Shibboleth (`urn:oid` + `FriendlyName`), a Ping/Keycloak error with a nested `StatusCode`, and legacy SAML 1.1.

## Diagnostics — what to look at

| Symptom | Where to check |
| --- | --- |
| SP returns 400/500 on `/acs` | Errors tab, then the same entry in SAML — Status and Conditions |
| "Audience mismatch" | Conditions → Audience vs Audience URI / SP Entity ID (in ADFS: `AppliesTo` in the WS-Fed envelope) |
| "Assertion not yet valid" | validity bar — if the "now" marker sits before the window starts, the SP and IdP clocks have drifted apart |
| SP doesn't see groups/attributes | Attributes table — an attribute without values shows `(no values)`, meaning the mapping on the IdP side returned nothing |
| "InResponseTo mismatch" | `InResponseTo` in the response vs `ID` in the `AuthnRequest` (the previous hop in All Traffic) |
| Signature rejected | badges (what is signed: response, assertion, both) + the certificate fingerprint in the Signature section |
| ADFS: "token not valid" | WS-Federation envelope section — `AppliesTo` vs the RP identifier, `Created`/`Expires` vs the SP clock |
| Redirect loop | All Traffic — each 302 hop separately, with the `Location` header |

## Export and report

- **Export JSON** (down-arrow icon) — saves the currently visible entries (so the filter and active tab matter). Every entry carries both native fields and the `postData` / `timestamp` aliases, so the file is readable by other tools too.
- **Import** (up arrow, or drag a file into the window) — JSON from this extension, saml-tracer JSON, HAR.
- **HTML report** (document icon) — a single self-contained file: statistics, SAML message cards with attributes and XML, the error list, and a table of all traffic. Suitable for sending to support and for printing.

## Security and personal data

### What leaves the machine

Nothing. The extension makes not a single network call: no `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, no telemetry, no external scripts, fonts, CDNs or images. All code (the SAML parser, the JWT decoder, the report generator) is local and the fonts are system fonts. Manifest V3 additionally blocks remote code execution. You can verify it with one command in the extension directory:

```bash
grep -rnE "fetch\(|XMLHttpRequest|WebSocket|sendBeacon|https?://" --include=*.js --include=*.html --include=*.css . | grep -v tests/
```

The only data that leaves the tool are files **you** save yourself (Export JSON, the HTML report, Save XML) and whatever you copy to the clipboard.

### Where data lives and for how long

| Data | Location | Lifetime |
| --- | --- | --- |
| Captured requests, encoded `SAMLResponse`, headers (including `Cookie`) | RAM of the service worker and the open panel | until `Clear`, an extension reload, or closing the browser; collected only during an active recording session |
| Buffer of the last ~150 entries | `chrome.storage.session` — **memory**, not disk | until the browser closes; Chrome doesn't persist this area to disk |
| Decoded XML and the parsed model | panel RAM | until the panel closes |
| Settings (highlights, pins, allowlist, theme) | `chrome.storage.local` | until the extension is uninstalled |
| Pasted JWT | a text field in the panel | until the field is cleared / the panel closes |

**`storage.local`, not `storage.sync`** — deliberately. IdP and SP hostnames and pinned fields describe customer systems, so they have no business being in a Google account or on sync servers. If you used version 1.0.x, on the first run of 1.1.0 the settings are migrated to `storage.local` and the `sync` copy is deleted.

The extension **keeps no log on disk**, doesn't save assertions automatically, and doesn't send them to itself between sessions.

### Permissions and what they're for

| Permission | Purpose |
| --- | --- |
| `webRequest` + `<all_urls>` | inspecting request metadata and POST bodies — without this there is no tracer |
| `storage` | settings (`local`) and the session buffer (`session`) |
| `downloads` | saving the export, the report and XML |
| `clipboardRead` / `clipboardWrite` | the "Copy" and "Paste from clipboard" buttons in the JWT decoder |
| `tabs` | opening the tracer window |

No `scripting` and no content scripts — the extension injects nothing into pages and doesn't read the DOM of visited sites.

### A data-minimization-friendly configuration (GDPR Art. 5(1)(c))

By default, listening covers all traffic, including traffic unrelated to SSO — convenient, but too broad from a minimization standpoint. Recommended settings for day-to-day work:

1. **Capture: Only when I start it** (default) + auto-stop on quiet. A recording lasts as long as the flow — a dozen seconds instead of a whole day. There's nothing to delete, because nothing was collected.
2. **Capture only these domains** → enter only the IdP and SP hosts, e.g. `*.okta.com` and `sp.samltest.kmmr.jp`. Everything outside the list is never captured at all — your bank, mail and intranet never reach the tool's memory. The two mechanisms work independently: the first limits **time**, the second **scope**.
3. **Remove Cookie and Authorization headers…** → leave it on, unless the ticket specifically requires session cookies.
4. `Clear` (trash icon) once you're done analyzing — recorded data lives in the panel until cleared.
5. Use a test account for testing, not a real user's account — the assertion contains a first name, last name, e-mail address and groups, i.e. personal data.

### Working with assertions — things to keep in mind

- A SAML assertion and a JWT are **credentials**, not just data. A valid assertion pasted into a ticket can be replayed against the SP within its validity window (Okta's default is 5 minutes) — so attach the report only after the window has expired, or use a test account.
- The export, the report and copied text contain full attributes (e-mail, groups, department) — treat the files as personal data: handing them to external support is a data disclosure, so a data-processing agreement / legal basis applies, and the file should be deleted once the case is closed.
- The extension **does not verify signatures** — it shows the algorithm and the certificate fingerprint. It is not proof of signature validity nor a cryptographic audit tool.
- Exported files are not encrypted. If they are to leave your machine, zip them with a password or hand them over via an encrypted channel.
- An extension loaded as "unpacked" does not update itself, and anyone with access to your Chrome profile sees the same data in the panel — the usual workstation-locking rules apply.

## Limitations

- Chrome does not expose **response bodies** to extensions in `webRequest`, so you can see request bodies (that's where the `SAMLResponse` lives with the POST binding) but not the response HTML. For SAML that's enough; for inspecting response bodies there's still the Network tab.
- Traffic of `chrome://` pages, the Chrome Web Store and other extensions is invisible to extensions — a browser limitation.
- The URL fragment (the part after `#`) is never sent to the server, so tokens from the OIDC implicit flow don't reach `webRequest`. Paste them manually in the JWT tab.
- After a service worker restart the buffer covers the last ~150 entries (in memory, not on disk); the full history lives in the open panel.
- Very large assertions (>1.5 MB of encoded parameter) are truncated — the entry then gets a "Parameter truncated" badge.

## Structure

```
manifest.json          permissions, service worker, devtools_page, action
background.js          webRequest listening, entry building, SAML detection, port to the panel
devtools/              registration of the "SAML" tab in DevTools
panel/panel.html       layout: four tabs, list, details panel, JWT decoder
panel/panel.css        color and typography tokens, both themes
panel/panel.js         state, list and details rendering, import/export, report, JWT
lib/saml.js            base64 + inflate, SAML parser, XML formatting and highlighting
lib/jwt.js             JWT decoder
lib/util.js            host matching, SAML parameter detection, time
lib/report.js          self-contained HTML report generator
tests/                 Node tests (jsdom) — SAML/JWT logic, panel, service worker
```

## Tests

```bash
npm install jsdom
node tests/run.mjs         # decoding, parser, XML formatting, JWT, report
node tests/panel.mjs       # the panel in jsdom: list, details, filter, HAR import, export
node tests/background.mjs  # the webRequest pipeline: hops, SAML, errors, pause, clear
```

The tests run the extension's real code against Chrome API stubs, so they catch bugs before you even reload the extension.
