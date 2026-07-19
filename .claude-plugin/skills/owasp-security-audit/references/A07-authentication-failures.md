# A07: Authentication Failures

**Reference:** OWASP Top 10 (2025), category A07
**Main associated CWEs:** CWE-255, CWE-259, CWE-287, CWE-295, CWE-306, CWE-307, CWE-308, CWE-330, CWE-340, CWE-345, CWE-346, CWE-347, CWE-384, CWE-521, CWE-522, CWE-601, CWE-613, CWE-620, CWE-640
**Finding format:** `OWASP-A07-NNN`

This file is loaded by the `owasp-security-audit` orchestrator skill when analyzing category A07. It provides detection patterns, standard fixes, and the severity grid specific to authentication failures.

---

## Definition

Authentication failures encompass the full set of weaknesses that allow an attacker to trick a system into recognizing an invalid user as legitimate. The scope covers identity verification (who is presenting themselves?) and the resulting session management (how is that identity maintained over time?).

**Central position in the security chain:** authentication is the first line of defense between an anonymous visitor and protected data. Once bypassed, access controls (A01) become inoperative: the attacker acts under a legitimate identity.

Guiding principle: **deny by default** on all entry points, server-side managed sessions with systematic regeneration and invalidation, and intentionally opaque errors so as not to help an attacker.

---

## Attack Surface: Exploitability Prerequisites

Before declaring an A07 finding, verify that **the authentication mechanism is exposed and attackable**. Typical vectors:

- Login, password reset, or registration endpoints accessible without rate limiting
- JWT or session tokens transmitted over insecure channels or stored in an accessible way
- Account recovery mechanisms exploitable for user enumeration
- Default credentials or hardcoded secrets in production code

**Cases where the finding should be downgraded or dismissed:**

- `jwt.decode()` used **only for logging or auditing purposes**, not for making authorization decisions (verification is performed elsewhere via `jwt.verify()`)
- Absence of MFA on an **internal** service account with restricted network access
- "Weak" password policy in **test fixtures** or database seed scripts
- Session without expiration on an **admin** endpoint with strong network access control (VPN, IP allowlist)
- Hardcoded credentials in **test files** or documentation examples (`.env.example`)

---

## Detection Methodology

### 1. Map authentication touchpoints

Identify all endpoints that verify or establish an identity:

- Login forms, authentication API endpoints.
- Account recovery mechanisms (password reset, magic link).
- OAuth/OIDC endpoints (callback, token exchange).
- Alternative paths: admin routes, internal APIs, webhooks, legacy routes.

### 2. Check session management

- Source and validation of identity tokens/cookies.
- Lifecycle: regeneration upon authentication, invalidation upon logout and on expiration.
- Cookie security attributes.

### 3. Evaluate protections against automated abuse

- Rate limiting, account lockout, logging.
- Distinction between brute-force / credential stuffing / password spraying in the protections in place.

### 4. Cross-reference with A01

An A07 finding (authentication bypassed) combined with an A01 finding (insufficient access control once authenticated) multiplies the impact. Report both categories if relevant.

---

## Subtypes and Detection Patterns

> The examples mainly use PHP/Laravel and JavaScript/Node.js. **Adapt each pattern to the language and framework of the audited project.**

---

### A07.1: Default Credentials in Production

**CWE-259**: Use of Hard-coded Password | **CWE-255**: Credentials Management Errors

**Pattern:** predefined accounts with known credentials (`admin/admin`, `root/root`, `test/test`) ship with the application and are never changed before going into production. These credentials are often publicly documented.

**Detection - look for:**

- Seeders or migrations creating admin accounts with plaintext or trivial passwords.
- Configuration files containing default credentials not conditioned on the environment.
- Test or demo accounts present in the codebase with no removal mechanism for production.
- Absence of a "first login" mechanism forcing a password change on first connection.
- Third-party management interfaces (databases, monitoring, CI/CD) with default credentials left unchanged.

**Standard fix:**

- Remove all default credentials before going into production.
- Implement a mandatory "first login" flow for privileged accounts: access is blocked until a unique, strong password has been configured.
- Condition development seeders on `APP_ENV !== 'production'`.

**Typical severity:** 🔴 Critical (immediate admin access with no effort).

---

### A07.2: Missing Protection Against Automated Attacks

**CWE-307**: Improper Restriction of Excessive Authentication Attempts | **CWE-306**: Missing Authentication for Critical Function

**Pattern:** the authentication endpoint does not limit the number of attempts, enabling brute-force attacks (passwords tested against a single account), credential stuffing (email/password pairs from leaks tested en masse), and password spraying (a common password tested against every account).

**Detection - look for:**

- Login endpoint with no rate limiting or account lockout.
- Lockout based solely on IP address (bypassable with a botnet or rotating proxy) rather than on the account.
- Absence of logging of failed attempts.
- Absence of progressive delay between attempts.

**Vulnerable code:**

```php
// Bad: no protection at all, brute-force possible indefinitely
public function login(Request $request)
{
    $user = User::where('email', $request->email)->first();
    if ($user && Hash::check($request->password, $user->password)) {
        Auth::login($user);
        return response()->json(['ok' => true]);
    }
    return response()->json(['error' => 'Invalid credentials'], 401);
}
```

**Fix: account-based lockout with exponential backoff:**

```php
// Good: account-based lockout, exponential backoff, logging
public function login(Request $request)
{
    $request->validate(['email' => 'required|email', 'password' => 'required']);
    $user = User::where('email', $request->email)->first();

    // Lockout tied to the account, not the IP
    if ($user && $user->failed_attempts >= 5) {
        if (now()->timestamp < $user->locked_until) {
            Log::warning('login.locked', ['email' => $request->email]);
            return response()->json(['error' => 'Invalid user ID or password.'], 401);
        }
    }

    $passwordOk = $user && Hash::check($request->password, $user->password);

    if (!$user || !$passwordOk) {
        if ($user) {
            $attempts = ($user->failed_attempts ?? 0) + 1;
            $lockSeconds = min(pow(2, $attempts), 900); // cap at 15 min
            $user->update([
                'failed_attempts' => $attempts,
                'locked_until' => now()->timestamp + $lockSeconds
            ]);
        }
        Log::info('login.failed', ['email' => $request->email]);
        // Same message whether or not the account exists
        return response()->json(['error' => 'Invalid user ID or password.'], 401);
    }

    $user->update(['failed_attempts' => 0, 'locked_until' => 0]);
    $request->session()->regenerate(); // anti-session-fixation
    Auth::login($user);
    return response()->json(['ok' => true]);
}
```

**Note:** this same endpoint is often the target of business logic abuse (A06.2). If rate limiting is absent, report both categories.

**Typical severity:** 🔴 Critical (credential stuffing against an unprotected endpoint).

---

### A07.3: Account Enumeration

**CWE-204**: Observable Response Discrepancy | **CWE-208**: Observable Timing Discrepancy

**Pattern:** the application reveals to an attacker whether an account exists through differentiated error messages ("Unknown user" vs. "Incorrect password") or through distinct response times (short-circuiting before the hash is computed if the user does not exist).

**Detection - look for:**

```javascript
// Bad: distinct error messages, enumeration possible
if (!user) return res.status(404).json({ error: "Unknown user" });
if (!validPassword)
  return res.status(401).json({ error: "Incorrect password" });
```

```javascript
// Bad: short-circuit before the hash, timing difference reveals account absence
if (!user) return res.status(401).json({ error: "Invalid credentials" });
// PROBLEM: if user is null, the hash is not computed -> faster response
const valid = await bcrypt.compare(password, user.passwordHash);
```

**Fix: single message AND hash always computed:**

```javascript
// Good: identical message + hash computed even if the user does not exist
const DUMMY_HASH = "$2b$10$..."; // pre-computed valid hash of a dummy password
const user = await db.findUserByEmail(email);
const hashToCheck = user ? user.passwordHash : DUMMY_HASH;

// The hash is always computed, even if user is null -> identical timing
const valid = await bcrypt.compare(password, hashToCheck);

if (!user || !valid) {
  return res.status(401).json({ error: "Invalid user ID or password." });
}
```

**Other enumeration points to check:**

- "Forgot password" endpoint: different message depending on whether the account exists.
- Registration endpoint: different message if the email is already taken.
- For both cases, the correct response is "if an account exists with this email, a link has been sent to it."

**Typical severity:** 🟢 Low to 🟡 Medium (facilitates the reconnaissance phase but is not exploitable on its own).

---

### A07.4: Inadequate Password Storage

**CWE-256**: Plaintext Storage | **CWE-916**: Use of Password Hash With Insufficient Computational Effort

**Pattern:** passwords stored in plaintext, reversibly encrypted, or hashed with a fast algorithm (MD5, SHA-1, SHA-256) with or without a salt. This subtype overlaps with A04.3; report it in both categories.

**Detection - look for:**

- `md5()`, `sha1()`, `sha256()`, `hash('sha256', ...)`, `crypto.createHash('sha256')` functions applied to passwords.
- Dependencies lacking a dedicated password hashing library (`argon2`, `bcrypt`, `bcryptjs`, `phpass`).
- A "send me my password" feature, implying reversible storage (🔴 Critical).
- A `password` column of type `VARCHAR(32)` or `VARCHAR(40)`: the typical size of an MD5 or SHA-1 hash.

**Typical severity:** 🔴 Critical. See A04.3 for detailed fixes.

---

### A07.5: Faulty Session Management

**CWE-384**: Session Fixation | **CWE-613**: Insufficient Session Expiration | **CWE-522**: Insufficiently Protected Credentials

**Pattern:** the session is poorly managed after authentication: identifier not regenerated, not invalidated, exposed in the URL, or persisting indefinitely.

**Detection - look for:**

**Session fixation:**

```javascript
// Bad: session not regenerated after authentication
app.post("/login", async (req, res) => {
  const user = await authenticate(req.body);
  req.session.userId = user.id; // An attacker who knows the pre-auth session ID
  // can now impersonate the user
});

// Good: mandatory regeneration after authentication
app.post("/login", async (req, res) => {
  const user = await authenticate(req.body);
  req.session.regenerate((err) => {
    // New session ID generated
    req.session.userId = user.id;
    res.json({ ok: true });
  });
});
```

**Missing invalidation on logout:**

```javascript
// Bad: logout that does not destroy the server-side session
app.post("/logout", (req, res) => {
  res.clearCookie("session"); // The cookie is removed client-side
  // but the session remains valid server-side
  res.json({ ok: true });
});

// Good: complete session destruction
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("session");
    res.json({ ok: true });
  });
});
```

**Session identifier in the URL:**

```
// Bad: session ID in the URL, appears in logs, the Referer header, browser history
GET /dashboard?sessionId=abc123
```

**Other points to check:**

- Sessions with no expiration or excessive expiration (> 8h on sensitive data).
- Absence of re-authentication for sensitive actions (password change, email change, payment).
- In an SSO context: propagation of logout to all linked applications.

**Cookie attributes to check:** `Secure`, `HttpOnly`, `SameSite` (see A02.5 for details).

**Typical severity:** 🟠 High (session fixation, missing invalidation) to 🔴 Critical (session ID in the URL on a sensitive application).

---

### A07.6: Authentication Bypass via Alternative Path

**CWE-287**: Improper Authentication | **CWE-306**: Missing Authentication for Critical Function

**Pattern:** the application protects a main interface while leaving an alternative path (API route, legacy endpoint, internal interface) accessible without authentication control.

**Detection - look for:**

```php
// Bad: API route within the admin perimeter with no protection
Route::prefix('admin')->group(function () {
    Route::get('/ui', [AdminUiController::class, 'index'])->middleware('auth');
    Route::get('/api/data', [AdminApiController::class, 'data']); // no middleware
});
```

- Routes in an `admin`, `internal`, or `management` group with no middleware applied to the entire group.
- API endpoints corresponding to features protected in the UI but directly accessible.
- Debug or monitoring routes (`/metrics`, `/health/details`, `/debug`) with no access control.
- Legacy or deprecated endpoints not referenced in documentation but still active.

**Fix: deny by default at the group level:**

```php
// Good: the guard applies to the entire group, no omission possible
Route::prefix('admin')
    ->middleware(['admin.guard'])
    ->group(function () {
        Route::get('/ui', [AdminUiController::class, 'index']);
        Route::get('/api/data', [AdminApiController::class, 'data']);
    });
```

**Relation to A01:** this subtype is close to A01.2 (Forced Browsing). The distinction: A07.6 concerns a bypass of the authentication mechanism itself (getting through without authenticating), A01.2 concerns a bypass of authorization control (being authenticated but accessing an unauthorized resource).

**Typical severity:** 🟠 High to 🔴 Critical (depending on what the route exposes).

---

### A07.7: Missing or Poorly Designed MFA

**CWE-308**: Use of Single-factor Authentication | **CWE-640**: Weak Password Recovery Mechanism

**Pattern:** multi-factor authentication is absent on sensitive accounts, or present but with a weak fallback that negates its protection.

**Detection - look for:**

- Absence of MFA on admin accounts or sensitive actions (password change, wire transfer, email change).
- MFA fallback via SMS only (vulnerable to SIM swapping) with no more robust option.
- Fallback via secret questions (see A06.3).
- MFA bypassable via a controllable query parameter or cookie.
- MFA not required for sensitive post-authentication actions (missing re-authentication).
- TOTP code accepted without expiration check or accepted multiple times (replay possible).

**Hierarchy of MFA factors by strength:**

| Factor                                     | Phishing resistance | Note                              |
| ------------------------------------------ | ------------------- | --------------------------------- |
| WebAuthn (FIDO2): biometrics, hardware key | ✅ Strong           | Recommended standard              |
| TOTP app (Authenticator)                   | ⚠️ Partial          | Phishable in real time            |
| SMS OTP                                    | ❌ Weak             | SIM swapping, SS7                 |
| Email OTP                                  | ❌ Weak             | Depends on email account security |
| Secret questions                           | ❌ Very weak        | See A06.3                         |

**Typical severity:** 🟠 High (MFA absent on a standard account) to 🔴 Critical (MFA absent on an admin or financial account, bypassable fallback).

---

### A07.8: Incorrect JWT Validation

**CWE-345**: Insufficient Verification of Data Authenticity | **CWE-347**: Improper Verification of Cryptographic Signature

**Pattern:** a JWT is partially validated (signature checked but functional claims ignored) or not validated at all. This subtype overlaps with A04.6; report it in both categories.

**Detection - look for:**

```javascript
// Bad: jwt.decode() with no signature verification
const payload = jwt.decode(token); // decodes without validating

// Bad: functional claims ignored
const payload = jwt.verify(token, secret); // signature OK but exp/iss/aud not checked
```

**Claims to validate systematically:**

| Claim              | Role              | Risk if ignored                             |
| ------------------ | ----------------- | ------------------------------------------- |
| `exp`              | Expiration date   | Expired token accepted indefinitely         |
| `iss` (issuer)     | Issuing authority | Token from another service accepted         |
| `aud` (audience)   | Target service    | Token intended for another context accepted |
| `nbf` (not before) | Future validity   | Token not yet valid is accepted             |

**Fix:**

```javascript
// Good: full validation, signature + functional claims
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ["HS256"], // allowlist, 'none' excluded
  issuer: "my-app",
  audience: "my-app-clients",
  // exp is checked automatically by jwt.verify()
});
```

**Typical severity:** 🔴 Critical (unsigned token accepted, expired token or token from another service accepted).

---

### A07.9: Insufficient Password Policy

**CWE-521**: Weak Password Requirements | **CWE-620**: Unverified Password Change

**Pattern:** the password policy is too permissive (insufficient minimum length, restricted character set) or poorly oriented (artificial complexity rather than length).

**Detection - look for:**

- Minimum length below 8 characters.
- Restriction on special characters (prevents long passphrases).
- Maximum length too low (< 64 characters), blocking password managers.
- No rejection of known compromised passwords.
- Password change with no verification of the current password.
- No re-authentication before sensitive actions.

**Current recommendations (NIST SP 800-63B):**

| Context     | Minimum length |
| ----------- | -------------- |
| With MFA    | 8 characters   |
| Without MFA | 15 characters  |

- Allow all characters (uppercase, lowercase, digits, symbols, spaces, emoji).
- Maximum length >= 64 characters.
- Do not impose mandatory periodic rotation (encourages predictable passwords).
- Impose rotation only in case of suspected compromise.

**Typical severity:** 🟡 Medium (insufficient policy alone) to 🟠 High (combined with absence of MFA and brute-force protection).

---

### A07.10: Acceptance of Compromised Passwords

**CWE-521**: Weak Password Requirements

**Pattern:** the application accepts passwords found in public data breach databases. Attackers prioritize these lists in their credential stuffing attacks.

**Detection - look for:**

- No password check at registration and password change against a compromised password database.
- Frameworks with this check built in but not enabled: `NotCompromisedPassword` (Symfony), `Password::uncompromised()` (Laravel).

**Standard fix:**

```php
// Good: Laravel, check via the HaveIBeenPwned API (k-anonymity, the password itself is never sent)
use Illuminate\Validation\Rules\Password;

$request->validate([
    'password' => ['required', Password::min(15)->uncompromised()]
]);
```

```php
// Good: Symfony
use Symfony\Component\Validator\Constraints as Assert;

#[Assert\NotCompromisedPassword]
private string $password;
```

**Technical note:** the HaveIBeenPwned API uses a k-anonymity model (only the SHA-1 prefix is sent, never the password itself): no sensitive data is transmitted.

**Typical severity:** 🟡 Medium to 🟠 High (depending on the combination with other protections).

---

### A07.11: OAuth 2.0 / OIDC Vulnerabilities

**CWE-346**: Origin Validation Error | **CWE-601**: URL Redirection to Untrusted Site | **CWE-345**: Insufficient Verification of Data Authenticity

**Pattern:** OAuth 2.0 and OIDC are complex protocols with many implementation points. The most frequent errors involve the absence of the `state` parameter (OAuth CSRF), the absence of PKCE (authorization code interception), lax validation of redirect URIs (open redirect), and failure to validate `id_token` claims.

**Detection - look for:**

**1. Absence of the `state` parameter (OAuth CSRF):**

```javascript
// Bad: OAuth flow initiated with no state, CSRF possible
const authUrl =
  `https://provider.com/oauth/authorize?` +
  `client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code`;
// An attacker can force a victim to link their account to the attacker's account

// Good: random state generated via CSPRNG, stored in session, verified at the callback
const state = crypto.randomBytes(32).toString("hex");
req.session.oauthState = state;
const authUrl =
  `https://provider.com/oauth/authorize?` +
  `client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&state=${state}`;

// At the callback:
if (req.query.state !== req.session.oauthState) {
  return res.status(403).send("CSRF protection: state mismatch");
}
```

**2. Absence of PKCE for public apps (SPA, mobile, Electron):**

```javascript
// Bad: Authorization Code flow with no PKCE, code interceptable in logs, Referer, etc.
const authUrl = buildAuthUrl({
  clientId,
  redirectUri,
  scope,
  responseType: "code",
});

// Good: PKCE (code_challenge / code_verifier), mandatory for any app without a confidential backend
const codeVerifier = crypto.randomBytes(32).toString("base64url");
const codeChallenge = crypto
  .createHash("sha256")
  .update(codeVerifier)
  .digest("base64url");

req.session.codeVerifier = codeVerifier; // stored server-side or in encrypted localStorage

const authUrl = buildAuthUrl({
  clientId,
  redirectUri,
  scope,
  responseType: "code",
  code_challenge: codeChallenge,
  code_challenge_method: "S256",
});

// When exchanging the code:
const tokens = await exchangeCode(code, { code_verifier: codeVerifier });
```

**3. Overly permissive redirect URI (open redirect):**

```javascript
// Bad: prefix-based validation, vulnerable to arbitrary subdomains
const isValid = redirectUri.startsWith("https://app.example.com");
// Accepts: https://app.example.com.evil.com

// Bad: lax regex
const isValid = /https:\/\/app\.example\.com/.test(redirectUri);
// Accepts: https://app.example.com.attacker.com

// Good: exact comparison against an allowlist
const ALLOWED_REDIRECT_URIS = [
  "https://app.example.com/oauth/callback",
  "https://app.example.com/admin/callback",
  "http://localhost:3000/oauth/callback", // dev only, restrict in prod
];
if (!ALLOWED_REDIRECT_URIS.includes(redirectUri)) {
  return res.status(400).send("Invalid redirect_uri");
}
```

**4. Client secret exposed on the frontend:**

```javascript
// Bad: code exchange performed client-side, client_secret visible in DevTools
const tokens = await fetch("https://provider.com/oauth/token", {
  method: "POST",
  body: new URLSearchParams({
    client_secret: "SUPER_SECRET", // visible in the browser
    code,
    grant_type: "authorization_code",
  }),
});
// -> use PKCE + BFF (Backend for Frontend) for public apps
```

**5. Unvalidated OIDC claims (`id_token`):**

```javascript
// Bad: id_token decoded with no signature or claims verification
const payload = jwt.decode(idToken); // no validation
const userId = payload.sub; // can be forged

// Good: full verification of the OIDC id_token
const { createRemoteJWKSet, jwtVerify } = require("jose");

const JWKS = createRemoteJWKSet(
  new URL("https://provider.com/.well-known/jwks.json"),
);

const { payload } = await jwtVerify(idToken, JWKS, {
  issuer: "https://provider.com", // iss mandatory
  audience: CLIENT_ID, // aud mandatory
  // exp checked automatically
});

// Check the nonce if used (prevent replay)
if (payload.nonce !== req.session.oauthNonce) {
  throw new Error("Nonce mismatch");
}
```

**6. Absence of `nonce` (OIDC token replay):**

```javascript
// Bad: OIDC flow with no nonce, token can be replayed in another session
const authUrl = buildAuthUrl({
  clientId,
  redirectUri,
  scope: "openid profile",
});

// Good: random nonce generated, hashed into the id_token, verified at the callback
const nonce = crypto.randomBytes(32).toString("hex");
req.session.oauthNonce = nonce;
const authUrl = buildAuthUrl({
  clientId,
  redirectUri,
  scope: "openid profile",
  nonce,
});
```

**Other points to check:**

- **Long-lived refresh tokens** with no rotation: a stolen refresh token grants indefinite access.
- **Overly broad scope**: requesting `openid email profile` when only `openid` is needed.
- **Reusable state**: the state must be invalidated after use to prevent replay.
- **Implicit flow**: deprecated (RFC 9700), the access token in the URL is exposed in logs. Migrate to Authorization Code + PKCE.
- **Missing verification of `acr` or `amr`** in contexts requiring MFA.

**OAuth 2.0 / OIDC compliance checklist:**

| Control                                            | Mandatory for                                |
| -------------------------------------------------- | -------------------------------------------- |
| CSPRNG `state` + verification at the callback      | Every OAuth flow                             |
| PKCE (`S256`)                                      | Public apps (SPA, mobile, desktop)           |
| `redirect_uri` on an exact allowlist               | Both the authorization server and the client |
| Code exchange performed server-side only           | Apps with a backend                          |
| `id_token` verified (`iss`, `aud`, `exp`, `nonce`) | Every OIDC flow                              |
| Refresh token rotation                             | Flows with offline access                    |
| Implicit flow disabled                             | Every new deployment                         |

**Typical severity:** 🔴 Critical (open redirect leading to account takeover via OAuth CSRF, client secret exposed on the frontend) to 🟠 High (PKCE absent on a public app, id_token not verified) to 🟡 Medium (overly broad scope, nonce absent with no confirmed replay).

---

## Cross-Cutting Remediation Rules

1. **Single error message**: "Invalid user ID or password." in every authentication failure case, regardless of the reason.
2. **Hash computed systematically**: even if the user does not exist, compute a dummy hash to neutralize timing attacks.
3. **Account-based lockout** (not IP-based) with exponential backoff and logging.
4. **Session regeneration** after every successful authentication.
5. **Complete server-side invalidation** of the session on logout and after inactivity.
6. **Deny by default on route groups**: the auth middleware applies to the group, not to each individual route.
7. **Phishing-resistant MFA** (WebAuthn / FIDO2) for sensitive accounts. No fallback via secret questions.
8. **Full JWT validation**: signature + `exp`, `iss`, `aud`. Algorithm enforced server-side. `none` explicitly excluded.
9. **Length >= 15 characters without MFA, >= 8 with MFA**, all characters allowed, max length >= 64.
10. **Verification of compromised passwords** at registration and on password change.
11. **Re-authentication for sensitive actions**: email change, password change, payment method change.
12. **Removal of default credentials** and mandatory first-login for privileged accounts.
13. **OAuth: CSPRNG `state` + verification at the callback**, invalidated after use. PKCE (`S256`) mandatory for every public app.
14. **OAuth: `redirect_uri` on an exact allowlist**: strict comparison, never by prefix or regex.
15. **OIDC: `id_token` verified**: signature (JWKS), `iss`, `aud`, `exp`, `nonce`. Never `jwt.decode()` alone.
16. **OAuth: implicit flow disabled**: migrate to Authorization Code + PKCE (RFC 9700).

---

## Severity Classification Guide

| Finding criteria                                                                                                                                                                                                                                                                                                                                | Severity         |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| Default credentials active in production, login endpoint with no brute-force protection whatsoever on a public app, auth bypass on an admin route, JWT accepted with no signature verification, session ID in the URL on sensitive data, bypassable MFA, OAuth open redirect leading to account takeover, client_secret exposed on the frontend | 🔴 Critical      |
| MFA absent on admin accounts, session not invalidated on logout, session fixation possible, lockout based solely on IP, MFA fallback via SMS only, PKCE absent on a public app, OIDC id_token not verified                                                                                                                                      | 🟠 High          |
| Account enumeration, no re-authentication for sensitive actions, insufficient password policy combined with absence of MFA, sessions with no reasonable expiration, OAuth state absent, implicit flow still in use, overly broad OAuth scope                                                                                                    | 🟡 Medium        |
| Account enumeration alone (with no other vector), slightly insufficient length policy with active MFA, OIDC nonce absent with no confirmed replay                                                                                                                                                                                               | 🟢 Low           |
| No verification of compromised passwords with an otherwise correct policy, session rotation absent on a non-sensitive app, refresh token rotation absent with a short lifetime                                                                                                                                                                  | ℹ️ Informational |

---

## Common False Positives: A07

| Detected pattern                                 | Reason for the false positive                                                                                     | How to verify                                                                           |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `jwt.decode(token)` with no `jwt.verify()`       | May be used to read claims for logging or auditing purposes, with verification performed upstream in a middleware | Look for `jwt.verify()` in the authentication middleware or route guard                 |
| No brute-force protection visible in the handler | May be implemented at the level of a global middleware, a WAF, or a reverse proxy                                 | Look for `rateLimit`, `slowDown`, `helmet`, or check the Nginx/Cloudflare configuration |
| Simple password (`password123`) in the code      | Likely in test fixtures or seed scripts, not in production                                                        | Check the file path: `*.test.*`, `seeds/`, `fixtures/`, `factories/`                    |
| No MFA mentioned                                 | MFA may be handled by an external SSO (Okta, Auth0, Keycloak) not visible in the code                             | Check whether an external identity provider is configured                               |
| Session with no expiration configured            | May have a default expiration provided by the framework                                                           | Check the framework documentation or the session store configuration                    |
| Token in the URL                                 | May be a short-lived, single-use token (magic link, OAuth callback)                                               | Check the token's lifetime and whether it is single-use                                 |

---

## Finding Template for the Report

````
**[OWASP-A07-NNN]** - [Short title]

- **Severity:** [level + icon]
- **Confidence:** 🔵 High / 🟣 Medium / ⚪ Low `[MANUAL VERIFICATION REQUIRED if Low]`
- **Remediation effort:** Low (<1h) / Medium (1-4h) / High (>4h) / Architectural
- **Justification:** [1 sentence, specify the impact on the authentication chain]
- **Subtype:** A07.X - [subtype name]
- **Location:** [file:line / endpoint / configuration]
- **Description:** [mechanism of the failure and how it is exploitable]
- **Potential impact:** [identity theft, account takeover, unauthorized access]
- **Evidence / Vulnerable example:**
  ```[language]
  // audited excerpt
````

- **Recommendation:** [concrete action]
- **Remediation example:**
  ```[language]
  // fixed version
  ```
- **References:** [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) | [OWASP A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

```

> Note: Authentication Failures corresponds to A07 in the OWASP Top 10 2021. In this orchestrator's 2025 reference, it remains A07.

---

## Limits of Static Analysis for A07

- **Effective rate limiting**: detecting the absence of a rate-limiting middleware is possible statically, but verifying that rate limiting actually works in production requires dynamic testing (bypass via IP rotation, X-Forwarded-For headers).
- **Timing behavior**: enumeration via timing (A07.3) is only detectable through dynamic tests measuring response times.
- **Active default credentials**: the presence of vulnerable seeders is detectable statically, but confirming that the accounts are active in production requires database access or a connection test.
- **Effective session invalidation**: verifying that `session.destroy()` is called is possible, but confirming that the token is actually invalidated server-side requires a dynamic test.
- **MFA configured and active**: the MFA configuration may be present in the code but disabled via a feature flag or an environment variable that is not provided.
- **Cloud / SSO policies**: the propagation of logout in an SSO context depends on the identity providers' configuration, which is not visible from the application code alone.

Mention these limitations in the "Limitations" section of the report and propose the relevant dynamic checks with explicit validation.
```
