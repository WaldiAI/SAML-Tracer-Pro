import { JSDOM } from 'jsdom';
import zlib from 'node:zlib';
import { writeFileSync } from 'node:fs';

const dom = new JSDOM('<!doctype html><html><body></body></html>');
globalThis.DOMParser = dom.window.DOMParser;
globalThis.document = dom.window.document;

const SAML = await import('../lib/saml.js');
const { decodeJwt } = await import('../lib/jwt.js');
const { buildHtmlReport } = await import('../lib/report.js');
const U = await import('../lib/util.js');

let failures = 0;
function check(name, condition, extra = '') {
  if (condition) console.log('  ok   ' + name);
  else {
    failures++;
    console.log('  FAIL ' + name + (extra ? ' → ' + extra : ''));
  }
}

const now = new Date();
const iso = (offsetMinutes) => new Date(now.getTime() + offsetMinutes * 60000).toISOString().replace(/\.\d+Z$/, '.307Z');

const RESPONSE_XML = `<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.samltest.kmmr.jp/acs/" ID="id123" InResponseTo="id-req-9" IssueInstant="${iso(-1)}" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exk15qwrsodrnNyTI698</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference></ds:SignedInfo><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBkTCB+wIJAKD3&lt;fake&gt;</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-assert-1" IssueInstant="${iso(-1)}" Version="2.0"><saml2:Issuer>http://www.okta.com/exk15qwrsodrnNyTI698</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo></ds:Signature><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">pawelkajdan@risebrand.pl</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="id-req-9" NotOnOrAfter="${iso(5)}" Recipient="https://sp.samltest.kmmr.jp/acs/"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="${iso(-5)}" NotOnOrAfter="${iso(5)}"><saml2:AudienceRestriction><saml2:Audience>https://sp.samltest.kmmr.jp/metadata/</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="${iso(-1)}" SessionIndex="id-session-7"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement><saml2:Attribute Name="firstName"><saml2:AttributeValue>Paweł</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="lastName"><saml2:AttributeValue>Kajdan</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="email"><saml2:AttributeValue>pawelkajdan@risebrand.pl</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="department"/><saml2:Attribute Name="dupa"><saml2:AttributeValue>nanana</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml2:AttributeValue>pawelkajdan@risebrand.pl</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>`;

const REQUEST_XML = `<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="https://sp.samltest.kmmr.jp/acs/" Destination="https://integrator-1238320.okta.com/app/x/sso/saml" ForceAuthn="false" ID="id-req-9" IssueInstant="${iso(-2)}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer>https://sp.samltest.kmmr.jp/metadata/</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></samlp:AuthnRequest>`;

const b64 = (buf) => Buffer.from(buf).toString('base64');

console.log('\n1. POST binding (plain base64)');
{
  const decoded = await SAML.decodeSamlMessage(b64(Buffer.from(RESPONSE_XML, 'utf8')));
  check('encoding reported as base64', decoded.encoding === 'base64', decoded.encoding);
  check('xml round trips', decoded.xml.includes('saml2p:Response'));

  const model = SAML.parseSaml(decoded.xml);
  check('parsed ok', model.ok === true, JSON.stringify(model).slice(0, 200));
  check('kind Response', model.kind === 'Response', model.kind);
  check('issuer', model.issuer === 'http://www.okta.com/exk15qwrsodrnNyTI698', model.issuer);
  check('destination', model.destination === 'https://sp.samltest.kmmr.jp/acs/', model.destination);
  check('status success', model.status && model.status.isSuccess === true);
  check('status short', model.status.short === 'Success', model.status.short);
  check('inResponseTo', model.inResponseTo === 'id-req-9');
  check('response signed', model.signed === true);
  check('response sig alg', /rsa-sha256$/.test(model.signatureAlg), model.signatureAlg);
  check('response digest alg', /sha256$/.test(model.digestAlg), model.digestAlg);
  check('one certificate at response level', model.certificates.length === 1, String(model.certificates.length));
  check('one assertion', model.assertions.length === 1);

  const a = model.assertions[0];
  check('assertion signed', a.signed === true);
  check('subject nameId', a.subject.nameId === 'pawelkajdan@risebrand.pl', a.subject.nameId);
  check('nameId format', /emailAddress$/.test(a.subject.format));
  check('recipient', a.subject.recipient === 'https://sp.samltest.kmmr.jp/acs/');
  check('conditions notBefore present', !!a.conditions.notBefore);
  check('audience', a.conditions.audiences[0] === 'https://sp.samltest.kmmr.jp/metadata/', String(a.conditions.audiences));
  check('sessionIndex', a.authn.sessionIndex === 'id-session-7');
  check('authn context', /PasswordProtectedTransport$/.test(a.authn.contextClassRef));
  check('6 attributes', a.attributes.length === 6, String(a.attributes.length));
  check('firstName value', a.attributes[0].values[0] === 'Paweł', a.attributes[0].values[0]);
  check('empty department has no values', a.attributes[3].values.length === 0);
  check('friendly name derived from claim urn', a.attributes[5].friendlyName === 'email', a.attributes[5].friendlyName);
  check('summary subject', model.summary.subject === 'pawelkajdan@risebrand.pl');
  check('assertion issuer picked up', a.issuer === 'http://www.okta.com/exk15qwrsodrnNyTI698');
}

console.log('\n2. Redirect binding (deflate-raw + base64)');
{
  const deflated = zlib.deflateRawSync(Buffer.from(REQUEST_XML, 'utf8'));
  const decoded = await SAML.decodeSamlMessage(b64(deflated));
  check('encoding reports deflate', /deflate/.test(decoded.encoding), decoded.encoding);
  const model = SAML.parseSaml(decoded.xml);
  check('kind AuthnRequest', model.kind === 'AuthnRequest', model.kind);
  check('acs url', model.request.acsUrl === 'https://sp.samltest.kmmr.jp/acs/');
  check('protocol binding', /HTTP-POST$/.test(model.request.protocolBinding));
  check('nameid policy', /emailAddress$/.test(model.request.nameIdFormat));
  check('issuer is the SP', model.request && model.issuer === 'https://sp.samltest.kmmr.jp/metadata/', model.issuer);
  check('no status on a request', model.status === null);
}

console.log('\n3. zlib-wrapped deflate and URL-encoded whitespace');
{
  const zlibbed = zlib.deflateSync(Buffer.from(REQUEST_XML, 'utf8'));
  const decoded = await SAML.decodeSamlMessage(b64(zlibbed));
  check('zlib deflate handled', decoded.xml.includes('AuthnRequest'), decoded.encoding);
  const withWhitespace = b64(Buffer.from(RESPONSE_XML, 'utf8')).replace(/(.{40})/g, '$1\n  ');
  const decoded2 = await SAML.decodeSamlMessage(withWhitespace);
  check('whitespace in base64 tolerated', decoded2.xml.includes('Response'));
  const urlSafe = b64(Buffer.from(REQUEST_XML, 'utf8')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const decoded3 = await SAML.decodeSamlMessage(urlSafe);
  check('base64url tolerated', decoded3.xml.includes('AuthnRequest'));
}

console.log('\n4. Bad input');
{
  let threw = false;
  try {
    await SAML.decodeSamlMessage(b64(Buffer.from('not xml at all, just text')));
  } catch {
    threw = true;
  }
  check('non-xml payload rejected', threw);
  const broken = SAML.parseSaml('<a><b></a>');
  check('malformed xml reported', broken.ok === false, JSON.stringify(broken));
}

console.log('\n5. Formatting and escaping');
{
  const pretty = SAML.formatXml(RESPONSE_XML);
  const lines = pretty.split('\n');
  check('multi-line output', lines.length > 20, String(lines.length));
  check('indentation applied', lines.some((l) => /^ {2}<saml2:Issuer/.test(l)), lines.slice(0, 4).join(' | '));
  check('text kept inline with its tag', lines.some((l) => /<saml2:Audience>https:\/\/sp\.samltest\.kmmr\.jp\/metadata\/<\/saml2:Audience>/.test(l)));

  const evil = '<r a="&quot;><img src=x onerror=alert(1)>"><script>alert(2)</script><t>&lt;b&gt;</t></r>';
  const html = SAML.highlightXml(SAML.formatXml(evil));
  check('no raw <img in highlighted output', !/<img/i.test(html));
  check('no raw <script in highlighted output', !/<script/i.test(html));
  check('spans emitted', /class="x-tag"/.test(html));
  const tagCount = (html.match(/<span/g) || []).length;
  check('reasonable span count', tagCount > 4, String(tagCount));
}

console.log('\n6. Attribute helpers');
{
  check('urn:oid friendly', SAML.deriveFriendlyName('urn:oid:0.9.2342.19200300.100.1.3') === 'mail');
  check('ms claim friendly', SAML.deriveFriendlyName('http://schemas.microsoft.com/ws/2008/06/identity/claims/role') === 'role');
  check('plain name kept', SAML.deriveFriendlyName('dupa') === 'dupa');
}

console.log('\n7. JWT decoder');
{
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'abc', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      iss: 'https://integrator-1238320.okta.com',
      aud: 'api://default',
      sub: 'pawelkajdan@risebrand.pl',
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) + 3540,
      scp: ['openid', 'profile']
    })
  ).toString('base64url');
  const token = `${header}.${payload}.c2lnbmF0dXJl`;

  const result = decodeJwt(token);
  check('decoded ok', result.ok === true, result.error);
  check('alg surfaced', result.header.alg === 'RS256');
  check('not expired', result.expired === false);
  check('highlights include issuer', result.highlights.some((x) => x.label === 'Issuer'));
  check('lifetime computed', result.highlights.some((x) => x.label === 'Lifetime'));
  check('signature captured', result.signature === 'c2lnbmF0dXJl');
  check('Bearer prefix stripped', decodeJwt('Bearer ' + token).ok === true);

  const expiredPayload = Buffer.from(JSON.stringify({ exp: 1000 })).toString('base64url');
  check('expired detected', decodeJwt(`${header}.${expiredPayload}.x`).expired === true);
  check('jwe rejected', decodeJwt('a.b.c.d.e').ok === false);
  check('garbage rejected', decodeJwt('hello').ok === false);
  check('unsecured flagged', decodeJwt(`${header}.${payload}.`).unsecured === true);

  const found = ('authorization: Bearer ' + token + ' and another ' + token).match(
    (await import('../lib/jwt.js')).JWT_RE
  );
  check('JWT_RE finds tokens in header text', found && found.length === 2, String(found && found.length));
}

console.log('\n8. Util');
{
  check('wildcard subdomain', U.hostMatches('*.okta.com', 'integrator-1238320.okta.com'));
  check('bare domain matches subdomain', U.hostMatches('okta.com', 'integrator-1238320.okta.com'));
  check('no false positive', !U.hostMatches('okta.com', 'notokta.company.com'));
  check('mid-wildcard', U.hostMatches('*samltest*', 'sp.samltest.kmmr.jp'));
  const fromUrl = U.samlFromUrl('https://idp.example/sso?SAMLRequest=abc%3D&RelayState=xyz&SigAlg=rsa');
  check('saml from query', fromUrl && fromUrl.kind === 'SAMLRequest' && fromUrl.raw === 'abc=' && fromUrl.relayState === 'xyz');
  const fromForm = U.samlFromForm({ SAMLResponse: ['zzz'], RelayState: ['r'] });
  check('saml from form', fromForm.kind === 'SAMLResponse' && fromForm.binding === 'POST');
  check('no saml found', U.samlFromForm({ user: ['a'] }) === null);
  check('urlencoded parse', U.parseUrlEncoded('a=1&a=2&b=x%20y').a.length === 2);
  check('header lookup case-insensitive', U.headerValue([{ name: 'Set-Cookie', value: 'v' }], 'set-cookie') === 'v');
  check('error entry by status', U.isErrorEntry({ status: 500 }) === true);
  check('error entry by net error', U.isErrorEntry({ status: 0, error: 'net::ERR' }) === true);
  check('ok entry', U.isErrorEntry({ status: 302 }) === false);
}

console.log('\n8b. Header redaction');
{
  const headers = [
    { name: 'Cookie', value: 'sid=secret' },
    { name: 'Authorization', value: 'Bearer abc' },
    { name: 'Set-Cookie', value: 'sid=secret; HttpOnly' },
    { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
    { name: 'X-Api-Key', value: 'k' }
  ];
  const out = U.redactHeaders(headers);
  check('cookie redacted', out[0].value === U.REDACTED);
  check('authorization redacted', out[1].value === U.REDACTED);
  check('set-cookie redacted', out[2].value === U.REDACTED);
  check('harmless header untouched', out[3].value === 'application/x-www-form-urlencoded');
  check('api key redacted', out[4].value === U.REDACTED);
  check('names kept so the reader knows what was there', out[0].name === 'Cookie');
  check('null-safe', U.redactHeaders(null) === null);
}

console.log('\n9. HTML report');
{
  const decoded = await SAML.decodeSamlMessage(b64(Buffer.from(RESPONSE_XML, 'utf8')));
  const entry = {
    id: 'e1',
    url: 'https://sp.samltest.kmmr.jp/acs/',
    method: 'POST',
    status: 500,
    statusLine: 'HTTP/1.1 500 Internal Server Error',
    started: Date.now(),
    type: 'main_frame',
    requestHeaders: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
    responseHeaders: [{ name: 'Server', value: 'Apache' }],
    saml: { kind: 'SAMLResponse', binding: 'POST', raw: 'x', relayState: '' }
  };
  const decodedById = new Map([['e1', { ...decoded, pretty: SAML.formatXml(decoded.xml), model: SAML.parseSaml(decoded.xml) }]]);
  const html = buildHtmlReport({ entries: [entry], decodedById, title: 'Test report' });
  writeFileSync(new URL('./report-sample.html', import.meta.url), html);
  check('doctype present', html.startsWith('<!doctype html>'));
  check('attributes rendered', html.includes('nanana'));
  check('subject rendered', html.includes('pawelkajdan@risebrand.pl'));
  check('status class applied', html.includes('st-err'));
  check('xml block present', html.includes('class="xml"'));
  const doc = new JSDOM(html).window.document;
  check('parses as html', !!doc.querySelector('h1'));
  check('tables built', doc.querySelectorAll('table').length >= 2, String(doc.querySelectorAll('table').length));
  check('no unescaped fake cert markup', !html.includes('<fake>'));
}


console.log('\n10. Inni dostawcy IdP — Entra ID / ADFS / Shibboleth / Ping / SAML 1.1');
{
  // --- Microsoft Entra ID (Azure AD): default namespace, no prefixes
  const ENTRA = `<?xml version="1.0" encoding="UTF-8"?><Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="_e1" Version="2.0" IssueInstant="${iso(-1)}" Destination="https://sp.example.com/saml/acs" InResponseTo="_req1"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://sts.windows.net/72f988bf-1111-2222-3333-444455556666/</Issuer><Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status><Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" IssueInstant="${iso(-1)}" Version="2.0"><Issuer>https://sts.windows.net/72f988bf-1111-2222-3333-444455556666/</Issuer><Subject><NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">jvGT9k2mFQ</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="_req1" NotOnOrAfter="${iso(60)}" Recipient="https://sp.example.com/saml/acs"/></SubjectConfirmation></Subject><Conditions NotBefore="${iso(-5)}" NotOnOrAfter="${iso(60)}"><AudienceRestriction><Audience>spn:11112222-3333-4444-5555-666677778888</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><AttributeValue>pawel@corp.example</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"><AttributeValue>IAM-Admins</AttributeValue><AttributeValue>All-Staff</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="${iso(-1)}" SessionIndex="_a1"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion></Response>`;
  const entra = SAML.parseSaml(ENTRA);
  check('Entra: parses without namespace prefixes', entra.ok === true);
  check('Entra: family saml2', entra.family === 'saml2', entra.family);
  check('Entra: issuer', /sts\.windows\.net/.test(entra.issuer), entra.issuer);
  check('Entra: success', entra.status.isSuccess === true);
  check('Entra: persistent nameid', entra.assertions[0].subject.nameId === 'jvGT9k2mFQ');
  check('Entra: audience', /^spn:/.test(entra.assertions[0].conditions.audiences[0]));
  check('Entra: claim urn mapped to a friendly label', entra.assertions[0].attributes[0].friendlyName === 'email');
  check('Entra: multi-valued group claim', entra.assertions[0].attributes[1].values.length === 2);

  // --- ADFS over WS-Federation, carrying a SAML 1.1 assertion
  const ADFS = `<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">${iso(-1)}</wsu:Created><wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">${iso(60)}</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>https://sp.corp.example/</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="_adfs1" Issuer="http://adfs.corp.example/adfs/services/trust" IssueInstant="${iso(-1)}"><saml:Conditions NotBefore="${iso(-5)}" NotOnOrAfter="${iso(60)}"><saml:AudienceRestrictionCondition><saml:Audience>https://sp.corp.example/</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AttributeStatement><saml:Subject><saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">CORP\\pkajdan</saml:NameIdentifier><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject><saml:Attribute AttributeName="upn" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims"><saml:AttributeValue>pkajdan@corp.example</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName="Group" AttributeNamespace="http://schemas.xmlsoap.org/claims"><saml:AttributeValue>Domain Admins</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthenticationStatement AuthenticationMethod="urn:federation:authentication:windows" AuthenticationInstant="${iso(-1)}"><saml:Subject><saml:NameIdentifier>CORP\\pkajdan</saml:NameIdentifier></saml:Subject></saml:AuthenticationStatement></saml:Assertion></t:RequestedSecurityToken><t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>`;
  const adfs = SAML.parseSaml(ADFS);
  check('ADFS: WS-Fed envelope recognised', adfs.family === 'ws-fed', adfs.family);
  check('ADFS: label', adfs.protocolLabel === 'WS-Federation');
  check('ADFS: AppliesTo realm', adfs.wsfed.appliesTo === 'https://sp.corp.example/', adfs.wsfed.appliesTo);
  check('ADFS: token type', /SAML:1\.0:assertion$/.test(adfs.wsfed.tokenType));
  check('ADFS: lifetime read', !!adfs.wsfed.created && !!adfs.wsfed.expires);
  check('ADFS: assertion found inside the envelope', adfs.assertions.length === 1);
  check('ADFS: issuer from the assertion attribute', adfs.issuer === 'http://adfs.corp.example/adfs/services/trust', adfs.issuer);
  check('ADFS: NameIdentifier used as subject', adfs.assertions[0].subject.nameId === 'CORP\\pkajdan', adfs.assertions[0].subject.nameId);
  check('ADFS: ConfirmationMethod element read', /cm:bearer$/.test(adfs.assertions[0].subject.confirmationMethod));
  check('ADFS: AudienceRestrictionCondition read', adfs.assertions[0].conditions.audiences[0] === 'https://sp.corp.example/');
  check('ADFS: AuthenticationStatement instant', !!adfs.assertions[0].authn.instant);
  check('ADFS: AuthenticationMethod as context', /authentication:windows$/.test(adfs.assertions[0].authn.contextClassRef));
  check('ADFS: SAML 1.1 attribute name composed', adfs.assertions[0].attributes[0].name.endsWith('/upn'), adfs.assertions[0].attributes[0].name);
  check('ADFS: friendly label from AttributeName', adfs.assertions[0].attributes[0].friendlyName === 'upn');
  check('ADFS: second attribute value', adfs.assertions[0].attributes[1].values[0] === 'Domain Admins');
  check('ADFS: summary destination falls back to the realm', adfs.summary.destination === 'https://sp.corp.example/');

  // --- Shibboleth: urn:oid attributes with FriendlyName
  const SHIB = `<?xml version="1.0"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_s1" Version="2.0" IssueInstant="${iso(0)}"><saml2:Issuer>https://idp.uni.example/idp/shibboleth</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion ID="_sa1"><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_abc</saml2:NameID></saml2:Subject><saml2:AttributeStatement><saml2:Attribute FriendlyName="eduPersonPrincipalName" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml2:AttributeValue>pkajdan@uni.example</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="urn:oid:2.5.4.4"><saml2:AttributeValue>Kajdan</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>`;
  const shib = SAML.parseSaml(SHIB);
  check('Shibboleth: FriendlyName respected', shib.assertions[0].attributes[0].friendlyName === 'eduPersonPrincipalName');
  check('Shibboleth: bare urn:oid mapped', shib.assertions[0].attributes[1].friendlyName === 'sn', shib.assertions[0].attributes[1].friendlyName);
  check('Shibboleth: transient nameid', shib.assertions[0].subject.format.endsWith('transient'));

  // --- Ping / Keycloak style failure with a nested status code
  const FAIL = `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_f1" Version="2.0" IssueInstant="${iso(0)}"><saml:Issuer>https://sso.pingone.example/idp</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"/></samlp:StatusCode><samlp:StatusMessage>NameIDPolicy format not supported</samlp:StatusMessage></samlp:Status></samlp:Response>`;
  const fail = SAML.parseSaml(FAIL);
  check('Ping: failure not marked success', fail.status.isSuccess === false);
  check('Ping: top status short', fail.status.short === 'Responder', fail.status.short);
  check('Ping: nested sub-status', /InvalidNameIDPolicy$/.test(fail.status.subCode), fail.status.subCode);
  check('Ping: status message', fail.status.message === 'NameIDPolicy format not supported');
  check('Ping: no assertion is fine', fail.assertions.length === 0);

  // --- legacy SAML 1.1 Response with a QName status
  const SAML1 = `<?xml version="1.0"?><Response xmlns="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" ResponseID="_r1" IssueInstant="${iso(0)}"><Status><StatusCode Value="samlp:Success"/></Status><Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="_l1" Issuer="https://legacy.idp.example"><AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="${iso(0)}"><Subject><NameIdentifier>legacy@example</NameIdentifier></Subject></AuthenticationStatement></Assertion></Response>`;
  const saml1 = SAML.parseSaml(SAML1);
  check('SAML 1.1: family detected', saml1.family === 'saml1', saml1.family);
  check('SAML 1.1: label', saml1.protocolLabel === 'SAML 1.1');
  check('SAML 1.1: QName status counts as success', saml1.status.isSuccess === true);
  check('SAML 1.1: version reconstructed', saml1.version === '1.1', saml1.version);
  check('SAML 1.1: ResponseID used as id', saml1.id === '_r1');
  check('SAML 1.1: subject via NameIdentifier', saml1.assertions[0].subject.nameId === 'legacy@example');
}

console.log('\n11. Wykrywanie wiadomości niezależne od dostawcy');
{
  // WS-Fed sign-in request (ADFS): no token yet, parameters are the message
  const signin = U.messageFromUrl(
    'https://adfs.corp.example/adfs/ls/?wa=wsignin1.0&wtrealm=https%3A%2F%2Fsp.corp.example%2F&wctx=rm%3D0&wreply=https%3A%2F%2Fsp.corp.example%2Fsignin&whr=urn%3Afederation%3AMicrosoftOnline'
  );
  check('WS-Fed sign-in detected', signin && signin.protocol === 'ws-fed', JSON.stringify(signin));
  check('WS-Fed action named in plain words', signin.kind === 'WS-Fed sign-in');
  check('WS-Fed request has no payload to decode', signin.opaque === true && signin.raw === '');
  check('WS-Fed realm captured', signin.extras.wtrealm === 'https://sp.corp.example/');
  check('WS-Fed home realm captured', signin.extras.whr === 'urn:federation:MicrosoftOnline');
  check('WS-Fed wctx becomes relay state', signin.relayState === 'rm=0');

  const signout = U.messageFromUrl('https://adfs.corp.example/adfs/ls/?wa=wsignout1.0');
  check('WS-Fed sign-out detected', signout.kind === 'WS-Fed sign-out');

  // WS-Fed token posted back to the SP as raw XML
  const token = U.messageFromForm({ wa: ['wsignin1.0'], wresult: ['<t:RequestSecurityTokenResponse xmlns:t="x"/>'], wctx: ['ctx1'] });
  check('WS-Fed token detected in a POST body', token.kind === 'WS-Fed token' && token.binding === 'POST');
  check('WS-Fed token is decodable', token.opaque === false);

  const plain = await SAML.decodeSamlMessage('<t:RequestSecurityTokenResponse xmlns:t="x"/>');
  check('plain XML payload accepted', plain.encoding === 'plain XML', plain.encoding);

  // artifact binding: reference only
  const art = U.messageFromUrl('https://sp.example/acs?SAMLart=AAQAAM3%2F');
  check('artifact detected', art.kind === 'SAMLart' && art.binding === 'Artifact');
  check('artifact marked as opaque', art.opaque === true);

  // SAML still wins when both are somehow present
  const both = U.messageFromForm({ SAMLResponse: ['abc'], wa: ['wsignin1.0'] });
  check('SAML takes precedence over WS-Fed', both.kind === 'SAMLResponse' && both.protocol === 'saml');
  check('plain traffic still returns nothing', U.messageFromUrl('https://example.com/page?x=1') === null);
}


console.log('\n12. Flow engine');
{
  const F = await import('../lib/flow.js');
  const t0 = Date.now();
  const mk = (i, over) => ({
    id: 'f' + i, started: t0 + i * 100, method: 'GET', type: 'main_frame', status: 302, url: '', saml: null, ...over
  });

  // classic SP-initiated flow with a failing ACS
  const entries = [
    mk(0, { url: 'https://app.example.com/dashboard', status: 302 }),
    mk(1, { url: 'https://idp.okta.example/app/sso/saml?SAMLRequest=x', saml: { kind: 'SAMLRequest', protocol: 'saml', binding: 'Redirect', raw: 'x' } }),
    mk(2, { url: 'https://idp.okta.example/login', status: 200 }),
    mk(3, { url: 'https://idp.okta.example/login', method: 'POST', status: 302 }),
    mk(4, { url: 'https://app.example.com/saml/acs', method: 'POST', status: 500, saml: { kind: 'SAMLResponse', protocol: 'saml', binding: 'POST', raw: 'y' } }),
    mk(5, { url: 'https://cdn.example.com/app.js', type: 'script', status: 200 })
  ];
  const flow = F.buildFlow(entries);

  check('script hop excluded from the story', flow.steps.length === 5, String(flow.steps.length));
  check('start classified as sp-start', flow.steps[0].stage === 'sp-start');
  check('request classified', flow.steps[1].stage === 'authn-request');
  check('idp pages classified by host', flow.steps[2].stage === 'idp-auth' && flow.steps[3].stage === 'idp-auth');
  check('response classified', flow.steps[4].stage === 'saml-response');
  check('idp host derived from the request target', flow.hosts.idp.has('idp.okta.example'));
  check('sp host derived from the response target', flow.hosts.sp.has('app.example.com'));

  const errFinding = flow.findings.find((f) => f.severity === 'err');
  check('rejected assertion produces an error finding', !!errFinding);
  check('finding names the SP and the status', /app\.example\.com/.test(errFinding.text) && /500/.test(errFinding.text), errFinding.text);

  // happy path
  const ok = F.buildFlow([
    entries[0], entries[1], entries[2],
    mk(4, { url: 'https://app.example.com/saml/acs', method: 'POST', status: 302, saml: { kind: 'SAMLResponse', protocol: 'saml', binding: 'POST', raw: 'y' } }),
    mk(6, { url: 'https://app.example.com/dashboard', status: 200 })
  ]);
  check('post-assertion hop lands in app-session', ok.steps[4].stage === 'app-session', ok.steps[4].stage);
  check('clean flow produces an ok finding', ok.findings.some((f) => f.severity === 'ok'));

  // stalled at the IdP
  const stalled = F.buildFlow([entries[0], entries[1], entries[2]]);
  check('missing response flagged as a stall', stalled.findings.some((f) => f.severity === 'warn' && /stalled/.test(f.text)));

  // IdP-initiated
  const idpInit = F.buildFlow([
    mk(0, { url: 'https://idp.okta.example/home', status: 200 }),
    mk(1, { url: 'https://app.example.com/saml/acs', method: 'POST', status: 302, saml: { kind: 'SAMLResponse', protocol: 'saml', binding: 'POST', raw: 'y' } })
  ]);
  check('idp-initiated recognised', idpInit.findings.some((f) => /IdP-initiated/.test(f.text)));
  check('pre-response hops treated as idp side', idpInit.steps[0].stage === 'idp-auth', idpInit.steps[0].stage);

  // redirect loop
  const loopReq = (i) => mk(i, { url: 'https://idp.okta.example/sso?SAMLRequest=x', saml: { kind: 'SAMLRequest', protocol: 'saml', binding: 'Redirect', raw: 'x' } });
  const loopResp = (i) => mk(i, { url: 'https://app.example.com/acs', method: 'POST', status: 302, saml: { kind: 'SAMLResponse', protocol: 'saml', binding: 'POST', raw: 'y' } });
  const loop = F.buildFlow([loopReq(0), loopResp(1), loopReq(2), loopResp(3), loopReq(4), loopResp(5)]);
  check('loop detected', loop.findings.some((f) => f.severity === 'err' && /loop/.test(f.text)));

  // WS-Fed and logout stages
  const wsfed = F.buildFlow([
    mk(0, { url: 'https://adfs.corp/adfs/ls/?wa=wsignin1.0', saml: { kind: 'WS-Fed sign-in', protocol: 'ws-fed', binding: 'Redirect', raw: '', opaque: true } }),
    mk(1, { url: 'https://sp.corp/signin', method: 'POST', status: 302, saml: { kind: 'WS-Fed token', protocol: 'ws-fed', binding: 'POST', raw: '<x/>' } }),
    mk(2, { url: 'https://adfs.corp/adfs/ls/?wa=wsignout1.0', saml: { kind: 'WS-Fed sign-out', protocol: 'ws-fed', binding: 'Redirect', raw: '', opaque: true } })
  ]);
  check('ws-fed sign-in staged', wsfed.steps[0].stage === 'wsfed-signin');
  check('ws-fed token staged', wsfed.steps[1].stage === 'wsfed-token');
  check('ws-fed sign-out staged as logout', wsfed.steps[2].stage === 'logout');

  // every referenced stage exists and teaches something
  for (const step of [...flow.steps, ...wsfed.steps]) {
    const info = F.stageInfo(step.stage);
    if (!info.teach || !info.label) { check('stage ' + step.stage + ' has teaching copy', false); break; }
  }
  check('all stages carry teaching copy', true);
  check('stage order is flow order', JSON.stringify(F.orderedStagesIn(flow.steps)) === JSON.stringify(['sp-start', 'authn-request', 'idp-auth', 'saml-response']), JSON.stringify(F.orderedStagesIn(flow.steps)));
  check('empty capture yields empty model', F.buildFlow([]).steps.length === 0);
}


console.log('\n13. Odrzucenie przez SP — scenariusz z zrzutu (Salesforce, user not provisioned)');
{
  const F = await import('../lib/flow.js');
  const t0 = Date.now();
  const mk = (i, over) => ({
    id: 's' + i, started: t0 + i * 100, method: 'GET', type: 'main_frame', status: 200, url: '', saml: null, initiator: '', ...over
  });

  // IdP-initiated from Okta tile; Salesforce rejects with 302→200 error pages
  const capture = [
    mk(0, { url: 'https://integrator-1238320.okta.com/home/salesforce/0oa15/46?fromHome=true', status: 302 }),
    mk(1, { url: 'https://integrator-1238320.okta.com/app/salesforce/0oa15/mc?fromHome=true', status: 302 }),
    mk(2, { url: 'https://integrator-1238320.okta.com/app/salesforce/exk15/sso/saml?fromHome=true', status: 200 }),
    mk(3, {
      url: 'https://orgfarm-99134af371-dev-ed.develop.my.salesforce.com/',
      method: 'POST', status: 302,
      initiator: 'https://integrator-1238320.okta.com',
      saml: { kind: 'SAMLResponse', protocol: 'saml', binding: 'POST', raw: 'x' }
    }),
    mk(4, { url: 'https://orgfarm-99134af371-dev-ed.develop.my.salesforce.com/_nc_external/identity/saml/SamlError', status: 200 }),
    mk(5, { url: 'https://orgfarm-99134af371-dev-ed.develop.my.salesforce-setup.com/setup/secur/SAMLValidationPage.apexp?appLay=1', status: 200 }),
    mk(6, { url: 'https://login.salesforce.com/login/sessionserver212.html', status: 200 })
  ];
  const flow = F.buildFlow(capture);

  check('IdP recognised from the response initiator', flow.hosts.idp.has('integrator-1238320.okta.com'), [...flow.hosts.idp].join(','));
  check('SP still recognised', flow.hosts.sp.has('orgfarm-99134af371-dev-ed.develop.my.salesforce.com'));
  check('SamlError page staged as rejection', flow.steps.find((s) => /SamlError/.test(s.entry.url)).stage === 'sp-reject');
  check('SAMLValidationPage staged as rejection', flow.steps.find((s) => /SAMLValidationPage/.test(s.entry.url)).stage === 'sp-reject');

  const err = flow.findings.find((f) => f.severity === 'err');
  check('rejection finding raised despite clean HTTP statuses', !!err);
  check('finding says the login FAILED', err && /FAILED/.test(err.text), err && err.text);
  check('finding names the most common cause', err && /not provisioned/.test(err.text));
  check('finding points at the error page path', err && /SamlError/.test(err.text));
  check('no false "flow completed"', !flow.findings.some((f) => f.severity === 'ok'));
  check('idp pages before the response classified as idp-auth', flow.steps[0].stage === 'idp-auth');

  const info = F.stageInfo('sp-reject');
  check('rejection stage teaches provisioning first', /provisioned/.test(info.checks[0]));

  // control: a genuinely clean flow still reports completion
  const clean = F.buildFlow([
    capture[0], capture[2], capture[3],
    mk(4, { url: 'https://orgfarm-99134af371-dev-ed.develop.my.salesforce.com/home/home.jsp', status: 200 })
  ]);
  check('clean flow still gets the ok finding', clean.findings.some((f) => f.severity === 'ok'));
  check('clean landing page is app-session, not rejection', clean.steps[3].stage === 'app-session');

  // error-page matcher hygiene
  check('generic saml error paths match', F.looksLikeSsoErrorPage('https://sp/x/sso-error?code=12'));
  check('plain pages do not match', !F.looksLikeSsoErrorPage('https://sp/dashboard/samples'));
  check('errorcode query matches', F.looksLikeSsoErrorPage('https://sp/login?ErrorCode=INVALID_SUBJECT'));
}


console.log('\n14. Pasek aktorow bez pola initiator');
{
  const F = await import('../lib/flow.js');
  const t0 = Date.now();
  const mk = (i, over) => ({ id: 'n'+i, started: t0+i*100, method: 'GET', type: 'main_frame', status: 200, url: '', saml: null, initiator: '', ...over });
  const flow = F.buildFlow([
    mk(0, { url: 'https://integrator-1238320.okta.com/home/salesforce/x/46', status: 302 }),
    mk(1, { url: 'https://integrator-1238320.okta.com/app/salesforce/x/sso/saml', status: 200 }),
    mk(2, { url: 'https://org.my.salesforce.com/', method: 'POST', status: 302, saml: { kind: 'SAMLResponse', protocol: 'saml', binding: 'POST', raw: 'x' } }),
    mk(3, { url: 'https://org.my.salesforce.com/secur/frontdoor.jsp?sid=abc', status: 200 })
  ]);
  check('IdP lane filled without initiator', flow.hosts.idp.has('integrator-1238320.okta.com'), [...flow.hosts.idp].join(','));
  check('SP lane intact', flow.hosts.sp.has('org.my.salesforce.com'));
  check('flow still completes', flow.findings.some((f) => f.severity === 'ok'));
}

console.log(failures ? `\n${failures} check(s) failed` : '\nAll checks passed');
process.exit(failures ? 1 : 0);
