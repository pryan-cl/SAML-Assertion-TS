/* Generates synthetic OIDC tokens, one per branch of the OIDC token tab.
   No real signature and no real key: inspectJwt never verifies one, and the
   separate Verify button is the only thing that touches JWKS. Nothing here is
   a credential. */
const fs = require('fs');
const path = require('path');

/* Writes next to this script unless a directory is given. */
const OUT = process.argv[2] || __dirname;

const TENANT = '00000000-1111-2222-3333-444444444444';
const CLIENT = '11111111-2222-3333-4444-555555555555';
const OID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const NOW = Date.now();
const secs = mins => Math.floor((NOW + mins * 60000) / 1000);

const b64u = o => Buffer.from(JSON.stringify(o), 'utf8').toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const jwt = (head, body) => `${b64u(head)}.${b64u(body)}.bm90LWEtcmVhbC1zaWduYXR1cmU`;

const HEAD = { typ: 'JWT', alg: 'RS256', kid: 'JDLzZm6nHm3ilKPxUqQoO0oM' };
const BODY = {
  aud: CLIENT,
  iss: `https://login.microsoftonline.com/${TENANT}/v2.0`,
  iat: secs(-5), nbf: secs(-5), exp: secs(60),
  oid: OID,
  sub: 'AAAAAAAAAAAAAAAAAAAAAJ1p1_5kQ7bJ2rQ0Rr9nEXA',
  preferred_username: 'jdoe@contoso.com',
  email: 'jdoe@contoso.com',
  name: 'Jane Doe',
  ver: '2.0',
  tid: TENANT,
};
const t = (h = {}, b = {}, drop = []) => {
  const body = { ...BODY, ...b };
  drop.forEach(k => delete body[k]);
  return jwt({ ...HEAD, ...h }, body);
};

const samples = [
  ['01-healthy-id-token', 'A normal v2 id_token. alg iss exp sub green, aud blue, grp not applicable.', t()],
  ['02-alg-none', 'Unsigned token. alg red, and it should say to discard it.', t({ alg: 'none' })],
  ['03-graph-audience', 'A Graph access token handed over by mistake. aud red.',
    t({}, { aud: '00000003-0000-0000-c000-000000000000' })],
  ['04-expired', 'exp is in the past. exp red.', t({}, { nbf: secs(-120), exp: secs(-60) })],
  ['05-not-yet-valid', 'nbf is in the future, the clock-skew case. exp red.',
    t({}, { nbf: secs(30), exp: secs(90) })],
  ['06-no-audience', 'aud claim removed entirely. aud red.', t({}, {}, ['aud'])],
  ['07-group-overage', 'hasgroups instead of a group list. grp amber, and it should explain the overage.',
    t({}, { hasgroups: true }, ['groups'])],
  ['08-groups-guids', 'A real group list of object IDs. grp green.',
    t({}, { groups: ['11111111-2222-3333-4444-555555555555', '66666666-7777-8888-9999-aaaaaaaaaaaa'] })],
  ['09-v1-issuer', 'v1 endpoint issuer. Should report v1.0 rather than v2.0.',
    t({}, { iss: `https://sts.windows.net/${TENANT}/`, ver: '1.0', upn: 'jdoe@contoso.com' })],
  ['10-header-nonce', 'A nonce in the header marks a Microsoft-resource access token. Should warn.',
    t({ nonce: 'abc123' })],
  ['11-sub-only', 'oid removed, only the pairwise sub remains. Should warn that sub is per-application.',
    t({}, {}, ['oid'])],
  ['12-no-email', 'email claim absent, the case that breaks SPs provisioning on email.', t({}, {}, ['email'])],
  ['13-access-token-scopes', 'An access token with scp and appid rather than id_token claims.',
    t({}, { aud: 'api://some-resource', scp: 'User.Read Files.Read', appid: CLIENT })],
  ['14-app-roles', 'roles claim present, the app-role authorisation case.',
    t({}, { roles: ['District.Admin', 'Reports.Read'] })],
  ['15-hs256', 'A symmetric algorithm, which Entra never issues. alg amber.', t({ alg: 'HS256' })],
  ['16-two-segments', 'Malformed: only two segments. Should refuse cleanly.', 'header.body'],
  ['17-bearer-prefix', 'A Bearer prefix pasted along with the token. Should be tolerated.', 'Bearer ' + t()],
];

const out = [
  '# Federation Bench, OIDC tab test samples',
  '',
  'Synthetic. No real signature and no real key.',
  'Every identifier is invented: the tenant, object and group GUIDs are',
  'placeholders and come from no directory.',
  'Paste each value into the **OIDC token** tab and press **Inspect token**.',
  '',
  'The **Verify signature** button will fail on all of these, which is correct:',
  'the signature is not real. Use a genuine token to exercise that path.',
  '',
  `Generated at ${new Date(NOW).toISOString()}. The time-based cases (04, 05) are`,
  'relative to that, so regenerate if they stop reading as described.',
  '',
];
for (const [name, expect, value] of samples) {
  out.push(`## ${name}`, '', expect, '', '```', value, '```', '');
}
fs.writeFileSync(path.join(OUT, 'oidc-test-samples.md'), out.join('\n'));
fs.writeFileSync(path.join(OUT, 'oidc-samples-loader.js'), 'window.__jwt=' + JSON.stringify(samples) + ';');
console.log(`wrote ${samples.length} OIDC samples`);
