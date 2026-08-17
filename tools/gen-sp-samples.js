/* Generates synthetic service provider metadata, one document per branch of the
   SP metadata tab. Nothing here is real: the certificates are byte blobs shaped
   so the tool's UTCTime scanner finds a validity window, and no key material is
   involved. The tab never verifies a signature, so these render exactly as a
   genuine document would.

   The identifiers deliberately match the ones in gen-saml-samples.js, so that
   loading SAML sample 01 and then SP sample 01 produces an all-green
   cross-check. Cases 02 to 04 are the same document with one near-miss
   introduced, which is the comparison the tab exists to make. */
const fs = require('fs');
const path = require('path');

/* Writes next to this script unless a directory is given. */
const OUT = process.argv[2] || __dirname;

const ENTITY = 'https://sp.example.org/saml';   // the assertion <Audience>
const ACS = 'https://sp.example.org/acs';       // the assertion Destination
const NOW = new Date();
const day = n => new Date(NOW.getTime() + n * 86400000).toISOString();

/* Same shape as the SAML generator's, so the two agree on what a certificate
   looks like to the UTCTime scanner. */
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
const CERT_OK = fakeCert('250101', '280101');
const CERT_DEAD = fakeCert('230101', '260101');

const key = (cert, use) =>
  `<md:KeyDescriptor${use ? ` use="${use}"` : ''}><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
  `<ds:X509Data><ds:X509Certificate>${cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`;

const POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
const EMAIL = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
const UNSPEC = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

function sp(o = {}) {
  const acs = o.acsList || [{ loc: o.acs ?? ACS, binding: POST, index: 0, def: true }];
  const formats = o.nameIds ?? [EMAIL];
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${o.entityId ?? ENTITY}"${
    o.validUntil ? ` validUntil="${o.validUntil}"` : ''}>
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"${
    o.wantSigned != null ? ` WantAssertionsSigned="${o.wantSigned}"` : ''}${
    o.reqSigned != null ? ` AuthnRequestsSigned="${o.reqSigned}"` : ''}>
    ${o.keys || ''}
    ${formats.map(f => `<md:NameIDFormat>${f}</md:NameIDFormat>`).join('\n    ')}
    ${acs.map(a => `<md:AssertionConsumerService Binding="${a.binding}" Location="${a.loc}" index="${a.index}"${
      a.def ? ' isDefault="true"' : ''}/>`).join('\n    ')}
    ${o.slo ? `<md:SingleLogoutService Binding="${POST}" Location="${o.slo}"/>` : ''}
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">Example Service Provider</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">Example Service Provider</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">https://sp.example.org/</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="technical">
    <md:EmailAddress>federation@sp.example.org</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`;
}

/* An identity provider document, which is what someone hands over when they
   export the wrong half from Entra. */
function idp() {
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sts.windows.net/00000000-1111-2222-3333-444444444444/">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    ${key(CERT_OK, 'signing')}
    <md:NameIDFormat>${UNSPEC}</md:NameIDFormat>
    <md:SingleSignOnService Binding="${POST}" Location="https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/saml2"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;
}

const samples = [
  /* Declares both formats on purpose. The SAML samples send unspecified, so a
     document accepting only emailAddress warns on the NameID row and this
     stops being the all-green case it is supposed to be. */
  ['01-healthy', 'Matches the SAML samples exactly. Load SAML sample 01 first and every cross-check row should be green.',
    sp({ nameIds: [EMAIL, UNSPEC] })],
  ['02-entity-trailing-slash', 'Entity ID carries a trailing slash the assertion does not. Cross-check should say "differs only by a trailing slash", not "no match".',
    sp({ entityId: ENTITY + '/' })],
  ['03-acs-case-mismatch', 'ACS path differs only in letter case. Reply URL matching is case sensitive, so this is a real failure.',
    sp({ acs: 'https://sp.example.org/ACS' })],
  ['04-acs-scheme-mismatch', 'ACS is http where the assertion says https. Usually the SP sits behind a terminating proxy.',
    sp({ acs: 'http://sp.example.org/acs' })],
  ['05-no-acs', 'SPSSODescriptor with no AssertionConsumerService. acs segment should be red.',
    sp({ acsList: [] })],
  ['06-idp-metadata', 'Identity provider metadata, the wrong half. Should say so plainly rather than reporting an SP with no endpoints.', idp()],
  ['07-expired-validuntil', 'validUntil passed a fortnight ago. Should fail, and say re-fetching stale metadata fixes nothing.',
    sp({ validUntil: day(-14) })],
  ['08-expiring-validuntil', 'validUntil inside the fortnight. Should warn.', sp({ validUntil: day(7) })],
  ['09-encryption-key', 'Publishes an encryption key. With no live tenant loaded this is information; with an unencrypting tenant it should read as an offer, not a fault.',
    sp({ keys: key(CERT_OK, 'encryption') })],
  ['10-key-without-use', 'KeyDescriptor with no use attribute, which the schema says means both purposes. Should not be labelled signing-only.',
    sp({ keys: key(CERT_OK) })],
  ['11-expired-certificate', 'Published certificate expired at the start of the year. crt segment should be red.',
    sp({ keys: key(CERT_DEAD, 'signing') })],
  ['12-multiple-acs', 'Three endpoints with the default flagged second. The default is the one compared against Entra.',
    sp({ acsList: [
      { loc: 'https://sp.example.org/acs/legacy', binding: POST, index: 0 },
      { loc: ACS, binding: POST, index: 1, def: true },
      { loc: 'https://sp.example.org/acs/alt', binding: POST, index: 2 },
    ] })],
  ['13-no-post-binding', 'Only a Redirect binding. Entra posts responses, so this needs a different integration rather than a reconfigured one.',
    sp({ acsList: [{ loc: ACS, binding: REDIRECT, index: 0, def: true }] })],
  ['14-wants-unsigned', 'WantAssertionsSigned="false". Legal, and worth raising with the provider.',
    sp({ wantSigned: false })],
  ['15-urn-entity-id', 'A URN entity ID rather than a URL. Must not be described as a host or path difference.',
    sp({ entityId: 'urn:example:sp:production' })],
  ['16-entities-descriptor', 'An aggregate whose first entry carries no role. The parser should skip to the entity that has one.',
    `<?xml version="1.0" encoding="UTF-8"?>\n<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">\n  <md:EntityDescriptor entityID="https://placeholder.example.org/"/>\n${
      sp().replace(/^<\?xml[^>]*\?>\n/, '')}\n</md:EntitiesDescriptor>`],
  ['17-nameid-unspecified-only', 'Declares only unspecified. An assertion using emailAddress should raise a caveat, not a verdict.',
    sp({ nameIds: [UNSPEC] })],
  ['18-with-logout', 'Carries a SingleLogoutService, which Entra does not populate from metadata.',
    sp({ slo: 'https://sp.example.org/logout' })],
  ['19-truncated', 'Cut off mid-document. Should refuse cleanly and name the likely cause.', sp().slice(0, 300)],
  ['20-not-xml', 'Base64 rather than XML, the paste-the-wrong-thing case. Should say it is not base64 it wants.',
    Buffer.from(sp(), 'utf8').toString('base64')],
];

const out = [
  '# Federation Bench, SP metadata tab test samples',
  '',
  'Synthetic. No real service provider, no real key, no real certificate.',
  'Every identifier is invented and resolves to nothing.',
  '',
  'Paste each document into the **SP metadata** tab and press **Inspect metadata**.',
  '',
  'The entity ID and ACS URL match the ones in `gen-saml-samples.js`, so the',
  'intended order is: inspect SAML sample `01-healthy` first, then SP sample',
  '`01-healthy`, and read the **Cross-check** card. Samples 02 to 04 are that same',
  'document with one near miss introduced, which is the comparison this tab exists',
  'to make and the one nobody can do by eye.',
  '',
  `Generated at ${NOW.toISOString()}. The validUntil cases (07, 08) are relative to`,
  'that, so regenerate if they stop reading as described.',
  '',
];
for (const [name, expect, value] of samples) {
  out.push(`## ${name}`, '', expect, '', '```xml', value, '```', '');
}
fs.writeFileSync(path.join(OUT, 'sp-test-samples.md'), out.join('\n'));
fs.writeFileSync(path.join(OUT, 'sp-samples-loader.js'), 'window.__sp=' + JSON.stringify(samples) + ';');
console.log(`wrote ${samples.length} SP metadata samples to ${OUT}`);
