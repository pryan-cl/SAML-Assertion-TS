/* Generates synthetic SAML responses that exercise each branch of the SAML tab.
   Nothing here is a real credential: the "certificate" is a byte blob shaped so
   the tool's UTCTime scanner finds a validity window, and the signature is not a
   real signature. The tool never verifies XML signatures (by design, it says so),
   so these render exactly like the real thing. */
const fs = require('fs');
const path = require('path');

/* Writes next to this script unless a directory is given. */
const OUT = process.argv[2] || __dirname;

const TENANT = '00000000-1111-2222-3333-444444444444';
const NOW = new Date();
const iso = d => new Date(d).toISOString();
const plus = (mins) => iso(NOW.getTime() + mins * 60000);

/* A DER-ish blob carrying a UTCTime validity pair the tool can find. */
function fakeCert(fromYYMMDD, toYYMMDD) {
  const t = s => Array.from(s, c => c.charCodeAt(0));
  const body = [
    0x30, 0x82, 0x02, 0x5a, 0x30, 0x82, 0x01, 0xc3, 0xa0, 0x03, 0x02, 0x01, 0x02,
    ...Array.from({ length: 40 }, (_, i) => (i * 7 + 11) & 0xff),
    0x30, 0x1E, 0x17, 0x0D, ...t(fromYYMMDD + '000000Z'), 0x17, 0x0D, ...t(toYYMMDD + '000000Z'),
    ...Array.from({ length: 120 }, (_, i) => (i * 13 + 29) & 0xff),
  ];
  return Buffer.from(body).toString('base64');
}

const CERT_OK = fakeCert('250101', '280101');   // valid, well in date
const CERT_SOON = fakeCert('250101', '260901');  // expires ~20 days after NOW
const CERT_DEAD = fakeCert('230101', '260101');  // expired

const claims = (extra = '') => `
      <saml:AttributeStatement>
        <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
          <saml:AttributeValue>jdoe@contoso.com</saml:AttributeValue></saml:Attribute>
        <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname">
          <saml:AttributeValue>Jane</saml:AttributeValue></saml:Attribute>
        <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname">
          <saml:AttributeValue>Doe</saml:AttributeValue></saml:Attribute>
        <saml:Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier">
          <saml:AttributeValue>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</saml:AttributeValue></saml:Attribute>
        <saml:Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid">
          <saml:AttributeValue>${TENANT}</saml:AttributeValue></saml:Attribute>${extra}
      </saml:AttributeStatement>`;

function sig(cert, alg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256') {
  return `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo><ds:SignatureMethod Algorithm="${alg}"/></ds:SignedInfo>
      <ds:SignatureValue>bm90LWEtcmVhbC1zaWduYXR1cmU=</ds:SignatureValue>
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>${cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </ds:Signature>`;
}

function response(o = {}) {
  const nb = o.notBefore ?? plus(-5), noa = o.notOnOrAfter ?? plus(60);
  const assertion = o.noAssertion ? '' : `
    <saml:Assertion ID="_a1" IssueInstant="${plus(-1)}" Version="2.0">
      <saml:Issuer>https://sts.windows.net/${TENANT}/</saml:Issuer>
      ${o.unsigned ? '' : sig(o.cert ?? CERT_OK, o.sigAlg)}
      <saml:Subject>
        <saml:NameID Format="${o.nameIdFormat ?? 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'}">${o.nameId ?? 'jdoe@contoso.com'}</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
          <saml:SubjectConfirmationData NotOnOrAfter="${noa}" Recipient="https://sp.example.org/acs"/>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:Conditions NotBefore="${nb}" NotOnOrAfter="${noa}">
        ${o.noAudience ? '' : `<saml:AudienceRestriction><saml:Audience>${o.audience ?? 'https://sp.example.org/saml'}</saml:Audience></saml:AudienceRestriction>`}
      </saml:Conditions>
      <saml:AuthnStatement AuthnInstant="${plus(-1)}">
        <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
      </saml:AuthnStatement>${o.noClaims ? '' : claims(o.extraClaims)}
    </saml:Assertion>`;

  return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="${plus(-1)}" Destination="https://sp.example.org/acs"${o.idpInitiated ? '' : ' InResponseTo="_req1"'}>
  <saml:Issuer>https://sts.windows.net/${TENANT}/</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="${o.statusCode ?? 'urn:oasis:names:tc:SAML:2.0:status:Success'}"/>${o.statusMessage ? `<samlp:StatusMessage>${o.statusMessage}</samlp:StatusMessage>` : ''}</samlp:Status>${assertion}${o.encrypted ? '\n  <saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">redacted</xenc:EncryptedData></saml:EncryptedAssertion>' : ''}
</samlp:Response>`;
}

const b64 = s => Buffer.from(s, 'utf8').toString('base64');

const samples = [
  ['01-healthy', 'Everything correct. All five segments green or blue. Window is deliberately wide so this stays valid for a fortnight.', b64(response({ window: 60*24*14 }))],
  ['02-expired-window', 'Assertion window closed 30 minutes ago. exp should be red.',
    b64(response({ notBefore: plus(-90), notOnOrAfter: plus(-30) }))],
  ['03-not-yet-valid', 'Window opens in 30 minutes, the classic clock-skew case. exp red.',
    b64(response({ notBefore: plus(30), notOnOrAfter: plus(90) }))],
  ['04-status-failure', 'AADSTS50105 in the status message, no assertion issued. sts red.',
    b64(response({ statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Responder', noAssertion: true,
      statusMessage: 'AADSTS50105: The signed in user is not assigned to a role for the application.' }))],
  ['05-unsigned', 'No signature anywhere. sig red.', b64(response({ unsigned: true }))],
  ['06-no-audience', 'Conditions carry no AudienceRestriction. aud red.', b64(response({ noAudience: true }))],
  ['07-sha1-signature', 'Signature algorithm downgraded to SHA-1. Should warn.',
    b64(response({ sigAlg: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' }))],
  ['08-cert-expiring', 'Signing certificate expires in about 20 days. Should warn.',
    b64(response({ cert: CERT_SOON }))],
  ['09-cert-expired', 'Signing certificate already expired. Should fail the cert row.',
    b64(response({ cert: CERT_DEAD }))],
  ['10-idp-initiated', 'No InResponseTo. Should warn that SP-initiated-only SPs reject this.',
    b64(response({ idpInitiated: true }))],
  ['11-encrypted', 'EncryptedAssertion with no readable assertion. Should say so, not crash.',
    b64(response({ noAssertion: true, encrypted: true }))],
  ['12-no-claims', 'Assertion with no AttributeStatement. clm should warn.', b64(response({ noClaims: true }))],
  ['13-email-nameid', 'NameID format emailAddress, the configuration most SPs want.',
    b64(response({ nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' }))],
  ['14-truncated', 'Deliberately corrupt: the base64 is cut in half. Should refuse cleanly.',
    b64(response()).slice(0, 400)],
  ['15-raw-xml', 'Raw XML rather than base64, which the decoder should detect.', response()],
];

const out = [
  '# Federation Bench, SAML tab test samples',
  '',
  'Synthetic. No real credentials and no real signature.',
  'Every identifier is invented: the tenant, object and group GUIDs are',
  'placeholders and come from no directory.',
  '',
  'Paste each value into the **SAML message** tab and press **Inspect assertion**.',
  `Generated against a clock of ${iso(NOW)}, so the time-based cases read correctly`,
  'only if your clock is near that. Regenerate if they look wrong.',
  '',
];
for (const [name, expect, value] of samples) {
  out.push(`## ${name}`, '', expect, '', '```', value, '```', '');
}
const dest = path.join(OUT, 'saml-test-samples.md');
fs.writeFileSync(dest, out.join('\n'));
fs.writeFileSync(path.join(OUT, 'saml-samples-loader.js'), 'window.__samples=' + JSON.stringify(samples) + ';');
console.log(`wrote ${samples.length} samples to ${dest}`);
