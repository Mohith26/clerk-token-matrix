// Mints Clerk-shaped JWTs with a local RSA key and runs each one through
// @clerk/backend's verifyToken() and authenticateRequest() (Bearer header path).
// Everything is offline: jwtKey makes verification networkless.
import { generateKeyPairSync, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { verifyToken, createClerkClient } from '@clerk/backend';

const version = JSON.parse(readFileSync(new URL('./node_modules/@clerk/backend/package.json', import.meta.url))).version;

// Fail loudly if anything tries to reach the network.
let networkCalls = 0;
globalThis.fetch = async (url) => {
  networkCalls++;
  throw new Error(`network blocked: ${url}`);
};

const KID = 'ins_local_test';
const FAPI = 'example-app-00.clerk.accounts.dev';
const ISS = `https://${FAPI}`;
const ORIGIN = 'http://localhost:3000';
const CAT = {
  session: 'cl_B7d4PD111AAA',
  template: 'cl_B7d4PD222AAA',
  m2m: 'cl_B7d4PD333AAA',
};

const main = generateKeyPairSync('rsa', { modulusLength: 2048 });
const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwtKey = main.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const publishableKey = 'pk_test_' + Buffer.from(`${FAPI}$`).toString('base64');

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

function sign({ header = {}, payload = {}, key = main.privateKey, alg = 'RS256' } = {}) {
  const h = { alg, typ: 'JWT', kid: KID, ...header };
  for (const k of Object.keys(h)) if (h[k] === undefined) delete h[k];
  const now = Math.floor(Date.now() / 1000);
  const p = {
    azp: ORIGIN,
    exp: now + 60,
    iat: now - 5,
    nbf: now - 10,
    iss: ISS,
    sid: 'sess_local',
    sub: 'user_local',
    v: 2,
    ...payload,
  };
  for (const k of Object.keys(p)) if (p[k] === undefined) delete p[k];
  const input = `${b64(h)}.${b64(p)}`;
  if (alg === 'none') return `${input}.`;
  const s = createSign('RSA-SHA256');
  s.update(input);
  return `${input}.${s.sign(key).toString('base64url')}`;
}

const now = () => Math.floor(Date.now() / 1000);

const cases = [
  ['session token, cat=session', sign({ header: { cat: CAT.session } })],
  ['session token, no cat (pre-rollout)', sign()],
  ['JWT template, cat=template', sign({ header: { cat: CAT.template } })],
  ['M2M JWT, cat=m2m', sign({ header: { cat: CAT.m2m } })],
  ['unknown cat value', sign({ header: { cat: 'cl_somethingelse' } })],
  ['azp from another origin', sign({ payload: { azp: 'https://evil.example' } })],
  ['azp missing', sign({ payload: { azp: undefined } })],
  ['iss from another instance', sign({ payload: { iss: 'https://other-app-11.clerk.accounts.dev' } })],
  ['expired 3s ago (inside 5s skew)', sign({ payload: { exp: now() - 3 } })],
  ['expired 30s ago', sign({ payload: { exp: now() - 30 } })],
  ['nbf 30s in the future', sign({ payload: { nbf: now() + 30 } })],
  ['iat 30s in the future', sign({ payload: { iat: now() + 30 } })],
  ['sub missing', sign({ payload: { sub: undefined } })],
  ['signed with a different key', sign({ key: other.privateKey })],
  ['alg=none', sign({ alg: 'none' })],
  ['typ=at+jwt', sign({ header: { typ: 'at+jwt' } })],
];

const opts = { jwtKey, authorizedParties: [ORIGIN], issuer: ISS };
const clerk = createClerkClient({
  publishableKey,
  // authenticateRequest() insists on a secret key even when jwtKey makes it networkless.
  // This one is fake; fetch is stubbed above so it is never sent anywhere.
  secretKey: 'sk_test_not_a_real_key',
  jwtKey,
  telemetry: { disabled: true },
});

function short(err) {
  return err ? (err.reason || err.code || err.name) + ': ' + String(err.message).split('\n')[0].slice(0, 90) : '';
}

const rows = [];
for (const [name, token] of cases) {
  // The package-level verifyToken() throws on failure (the internal one returns { errors }).
  let v;
  try {
    v = { data: await verifyToken(token, opts) };
  } catch (e) {
    v = { errors: [e] };
  }
  const vOut = v.errors ? 'reject' : 'accept';
  let aOut, aWhy;
  try {
    const req = new Request(`${ORIGIN}/api/me`, { headers: { authorization: `Bearer ${token}` } });
    const state = await clerk.authenticateRequest(req, { authorizedParties: [ORIGIN], issuer: ISS, jwtKey });
    aOut = state.isSignedIn ? 'signed-in' : state.status;
    aWhy = state.reason || '';
  } catch (e) {
    aOut = 'threw';
    aWhy = String(e.message).slice(0, 90);
  }
  rows.push({ case: name, verifyToken: vOut, verifyTokenReason: short(v.errors?.[0]), authenticateRequest: aOut, authReason: aWhy });
}

console.log(`@clerk/backend ${version}, node ${process.version}, network calls attempted: ${networkCalls}\n`);
console.log('| case | verifyToken | authenticateRequest (Bearer) |');
console.log('|---|---|---|');
for (const r of rows) {
  const v = r.verifyToken + (r.verifyTokenReason ? ` (${r.verifyTokenReason})` : '');
  const a = r.authenticateRequest + (r.authReason ? ` (${r.authReason})` : '');
  console.log(`| ${r.case} | ${v} | ${a} |`);
}
