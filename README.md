# clerk-token-matrix

I wanted to see exactly which tokens `@clerk/backend` accepts, without needing a Clerk instance. This script makes its own RSA key, mints Clerk-shaped JWTs with it (good ones and deliberately broken ones), and runs each through both `verifyToken()` and `authenticateRequest()` with a Bearer header. Passing `jwtKey` makes verification networkless, and `fetch` is stubbed to throw, so the run is fully offline.

```
npm install
npm start
```

Both calls get the same options: `jwtKey`, `authorizedParties: ['http://localhost:3000']`, and `issuer` set to the fake instance's URL. `authenticateRequest()` refuses to run without a secret key even when `jwtKey` is set, so I pass a fake one; it is never sent anywhere.

## Results (@clerk/backend 3.26.5, Node 26.3, 0 network calls)

| token | verifyToken() | authenticateRequest() |
|---|---|---|
| session token, `cat` = session | accept | signed-in |
| session token, no `cat` (pre-rollout) | accept | signed-in |
| JWT template, `cat` = template | **accept** | signed-out: token-type-mismatch |
| M2M JWT, `cat` = m2m | reject: token-invalid | signed-out: token-type-mismatch |
| unknown `cat` value | **accept** | signed-out: token-type-mismatch |
| `azp` from another origin | reject: token-invalid-authorized-parties | signed-out: token-invalid-authorized-parties |
| `azp` missing | reject: token-invalid-authorized-parties | signed-out: token-invalid-authorized-parties |
| `iss` from another instance | reject: token-invalid-issuer | signed-out: token-invalid-issuer |
| expired 3s ago (inside the 5s default skew) | accept | signed-in |
| expired 30s ago | reject: token-expired | signed-out: session-token-expired-refresh-non-eligible-no-refresh-cookie |
| `nbf` 30s in the future | reject: token-not-active-yet | signed-out: session-token-nbf |
| `iat` 30s in the future | reject: token-iat-in-the-future | signed-out: session-token-iat-in-the-future |
| `sub` missing | reject: token-verification-failed | signed-out: token-verification-failed |
| signed with a different key | reject: token-invalid-signature | signed-out: token-invalid-signature |
| `alg` = none | reject: token-invalid-algorithm | signed-out: token-invalid-algorithm |
| `typ` = at+jwt | reject: token-invalid | signed-out: token-type-mismatch |

## What I noticed

The two entry points agree on every claim check. They differ on the `cat` header that tags which kind of token a JWT is:

- `authenticateRequest()` treats anything that is not the session-token category as the wrong token type ([request.ts](https://github.com/clerk/javascript/blob/bae8b9081e74/packages/backend/src/tokens/request.ts#L428)).
- Standalone `verifyToken()` only rejects the M2M category ([verify.ts](https://github.com/clerk/javascript/blob/bae8b9081e74/packages/backend/src/tokens/verify.ts#L125)), so a JWT-template token or a token with a `cat` it does not recognize verifies fine if the signature and claims check out.

This is known and deliberate: the comment above that check in `request.ts` says template tokens "pass verifyToken()" and are rejected one layer up because they carry no `sid` and outlive revocation of the session that minted them. The practical takeaway is for apps that call `verifyToken()` directly to guard a route that should only take session tokens: there, a template token (or one with a `cat` the SDK does not know) still verifies, so the app has to check `cat` or `sid` itself.

## Limits

These are synthetic tokens shaped like the examples in the `verifyToken()` docs, signed with my own key. They show how the SDK's checks behave, not what Clerk's servers actually issue. I only tested the Bearer header path of `authenticateRequest()`, not cookies or the handshake flow.
