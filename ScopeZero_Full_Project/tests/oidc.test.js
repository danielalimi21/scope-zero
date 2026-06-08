import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { AuthService } from "../src/auth.js";

// Real RS256 verification against a mock JWKS — no network. Proves the OIDC path
// (issuer/audience/exp checks + RSASSA-PKCS1-v1_5 signature verify) works end to
// end with a key served as a JWK, the way an enterprise IdP would.

const ISSUER = "https://login.example.com/";
const AUDIENCE = "api://scopezero";
const KID = "test-key-1";

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function makeJwt(payload, privateKey, kid = KID) {
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid }));
  const body = b64url(JSON.stringify(payload));
  const signature = crypto
    .sign("RSA-SHA256", Buffer.from(`${header}.${body}`), privateKey)
    .toString("base64url");
  return `${header}.${body}.${signature}`;
}

function authWithJwks(jwks) {
  const auth = new AuthService({
    secret: "hmac-secret",
    requireAuth: true,
    oidcIssuer: ISSUER,
    oidcAudience: AUDIENCE,
    jwksUrl: "https://login.example.com/jwks.json"
  });
  auth.jwksCache = jwks;             // pre-seed so getJwks() never fetches
  auth.jwksCacheUntil = Date.now() + 60_000;
  return auth;
}

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: KID, use: "sig", alg: "RS256" };
const jwks = { keys: [jwk] };
const exp = Math.floor(Date.now() / 1000) + 3600;

test("a valid RS256 OIDC token verifies against the JWKS", async () => {
  const auth = authWithJwks(jwks);
  const token = makeJwt({ iss: ISSUER, aud: AUDIENCE, sub: "user@contoso.example", tenant_id: "tenant_contoso", roles: ["security_operator"], exp }, privateKey);
  const principal = await auth.authenticate({ headers: { authorization: `Bearer ${token}` } });
  assert.equal(principal.auth_type, "oidc");
  assert.equal(principal.subject, "user@contoso.example");
});

test("a token whose signature doesn't match the JWKS key is rejected", async () => {
  const auth = authWithJwks(jwks);
  const otherKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  const token = makeJwt({ iss: ISSUER, aud: AUDIENCE, sub: "attacker", exp }, otherKey);
  await assert.rejects(() => auth.authenticate({ headers: { authorization: `Bearer ${token}` } }), /invalid_token|signature/i);
});

test("a wrong issuer is rejected", async () => {
  const auth = authWithJwks(jwks);
  const token = makeJwt({ iss: "https://evil.example/", aud: AUDIENCE, sub: "x", exp }, privateKey);
  await assert.rejects(() => auth.authenticate({ headers: { authorization: `Bearer ${token}` } }), /issuer/i);
});

test("a wrong audience is rejected", async () => {
  const auth = authWithJwks(jwks);
  const token = makeJwt({ iss: ISSUER, aud: "api://someone-else", sub: "x", exp }, privateKey);
  await assert.rejects(() => auth.authenticate({ headers: { authorization: `Bearer ${token}` } }), /audience/i);
});

test("an expired OIDC token is rejected", async () => {
  const auth = authWithJwks(jwks);
  const token = makeJwt({ iss: ISSUER, aud: AUDIENCE, sub: "x", exp: Math.floor(Date.now() / 1000) - 10 }, privateKey);
  await assert.rejects(() => auth.authenticate({ headers: { authorization: `Bearer ${token}` } }), /expired/i);
});
