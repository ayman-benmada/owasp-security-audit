# A04 - Cryptographic Failures

**Reference framework:** OWASP Top 10 (2025), category A04
**Main associated CWEs:** CWE-261, CWE-310, CWE-319, CWE-320, CWE-326, CWE-327, CWE-328, CWE-330, CWE-331, CWE-338, CWE-347, CWE-522, CWE-523, CWE-757, CWE-798
**Finding format:** `OWASP-A04-NNN`

This file is loaded by the `owasp-security-audit` orchestrator skill when analyzing category A04. It provides detection patterns, standard fixes, and the severity grid specific to cryptographic failures.

---

## Definition

Cryptographic failures encompass all vulnerabilities related to the improper use or absence of cryptographic mechanisms: lack of encryption for sensitive data, obsolete or compromised algorithms, poor key management, exposure of secrets, incorrect implementation of protocols, or generation of insecure random values.

This category is particularly insidious: a cryptographic failure can remain silent for a long time, leaving sensitive data accessible without triggering any alert.

**Emerging threat to flag systematically:** the _harvest now, decrypt later_ strategy consists of intercepting and storing encrypted data (RSA, ECC) today, in the hope of decrypting it once quantum computing capabilities allow it. Systems handling data with a long sensitivity lifespan (medical, financial, government data) should incorporate a migration path toward post-quantum cryptography (NIST FIPS 203/204/205, published in August 2024) with a target horizon of 2030.

Guiding principle: **never implement cryptography yourself**. Use proven primitives, exposed by maintained libraries, with the parameters recommended by current standards.

---

## Attack Surface: Exploitability Prerequisites

Before declaring an A04 finding, verify that **the cryptographic weakness is exploitable within the real threat context**. Typical vectors:

- Sensitive data transmitted in cleartext over an accessible network (HTTP, unsecured WebSocket)
- Keys or secrets stored in source code or an accessible repository
- Tokens generated with a weak PRNG that are predictable by an attacker
- Password hashing algorithms that can be cracked through brute force

**Cases where the finding should be downgraded or dismissed:**

- MD5/SHA1 used for non-security checksums (HTTP ETag, file deduplication), not for security-relevant integrity
- `Math.random()` used to generate IDs for non-sensitive resources (not auth tokens or reset keys)
- TLS disabled on a closed private network (intra-service Kubernetes traffic with no external exposure), verify the network architecture
- Weak algorithm used only for legacy compatibility with an external third-party system (not under the team's control)
- "Weak" encryption applied to non-sensitive data (technical logs, aggregated metrics)

---

## Detection Methodology

A04 covers application code, network protocol configuration, and secrets management all at once. First identify the surfaces that can be analyzed.

### 1. Identify the surfaces present

- **Password storage**: hashing functions used, presence of a salt, configurable cost factor.
- **Encryption of sensitive data**: symmetric/asymmetric algorithms, encryption modes, IV/nonce management.
- **Transport**: TLS configuration, presence of HSTS, HTTP to HTTPS redirects, mixed content.
- **Tokens and sessions**: generation of random values, JWT validation, accepted algorithms.
- **Key management**: hardcoded secrets, environment variables, vaults, rotation.
- **Internal HTTP clients**: certificate validation configuration.

If a surface is not provided (e.g., the reverse proxy's TLS configuration is absent), report it in "Limitations."

### 2. Distinguish absence of cryptography from bad cryptography

The two are distinct findings:

- **Absence**: sensitive data transmitted or stored in cleartext, direct impact on confidentiality.
- **Bad implementation**: encryption present but breakable or bypassable, impact potentially delayed but just as critical.

### 3. Assess the sensitivity of the data involved

Severity largely depends on what is exposed. Health data, financial data, passwords, private keys: maximum severity. Non-sensitive metadata: reduced severity. Calibrate accordingly.

---

## Subtypes and Detection Patterns

> The examples primarily use Node.js and PHP. **Adapt each pattern to the language and framework of the audited project.**

---

### A04.1 - Cleartext Transmission of Sensitive Data

**CWE-319** - Cleartext Transmission of Sensitive Information | **CWE-523** - Unprotected Transport of Credentials

**Pattern:** sensitive data travels without encryption or with encryption that can be bypassed (mixed content, HTTP redirect without HSTS, internal connections in cleartext).

**Detection: look for**

- `http://` URLs in application code for calls to services handling sensitive data.
- Absence of the `Strict-Transport-Security` header in the server or reverse proxy configuration.
- HTTP to HTTPS redirect configured but without HSTS: the first request can travel in cleartext and be intercepted before the redirect takes effect.
- Mixed content: an HTTPS page loading resources (scripts, images, API calls) over HTTP.
- Inter-service communications (microservices, databases, cache) in cleartext over an exposed internal network.

**Critical point about HSTS:** a 301 redirect from HTTP to HTTPS does not protect a user's first visit, nor any visit before the browser has recorded the policy. HSTS must be enabled with a sufficiently long `max-age`.

```nginx
# ✅ Recommended Nginx configuration
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

**Typical severity:** 🟠 High (traffic exposed on an unsecured network) to 🔴 Critical (credentials or medical/financial data in cleartext).

---

### A04.2 - Obsolete or Compromised Cryptographic Algorithms

**CWE-327** - Use of a Broken or Risky Cryptographic Algorithm | **CWE-326** - Inadequate Encryption Strength

**Pattern:** use of algorithms whose cryptographic strength is insufficient with respect to current standards.

**Detection: look for**

**Hashing:**

- `MD5` or `SHA-1` used for digital signatures, integrity verification of sensitive data, or certificates. These algorithms are vulnerable to collisions: two different inputs can produce the same hash, allowing a legitimate file to be substituted with a malicious one.
- Calls to `md5()`, `sha1()`, `crypto.createHash('md5')`, `crypto.createHash('sha1')`.

**Symmetric encryption:**

- `DES`, `3DES`: insufficient key size (56 bits and effectively 112 bits).
- `RC4`: biased pseudo-random stream, partially predictable, prohibited in TLS since RFC 7465.
- AES used in `ECB` mode: does not conceal relationships between blocks, patterns in the data remain visible.

**Asymmetric encryption:**

- RSA with a key size smaller than 2048 bits.
- Elliptic curves that are not recommended or of insufficient size.

**TLS:**

- TLS 1.0 / TLS 1.1 versions accepted (deprecated, RFC 8996).
- Cipher suites including RC4, DES, EXPORT, or NULL.

**Quick algorithm reference:**

| Use case              | Avoid                     | Use                                        |
| --------------------- | ------------------------- | ------------------------------------------ |
| General hashing       | MD5, SHA-1                | SHA-256, SHA-3                             |
| Password hashing      | MD5, SHA-\*, bcrypt alone | Argon2id, bcrypt (with cost >= 10), scrypt |
| Symmetric encryption  | DES, 3DES, RC4, AES-ECB   | AES-256-GCM, ChaCha20-Poly1305             |
| Asymmetric encryption | RSA < 2048 bits           | RSA >= 2048 bits, ECDSA P-256+             |
| TLS                   | 1.0, 1.1                  | TLS 1.2 (minimum), TLS 1.3 (recommended)   |

**Typical severity:** 🟠 High to 🔴 Critical (depending on usage: MD5 for a profile picture is ℹ️, MD5 for a contract signature is 🔴).

---

### A04.3 - Inadequate Password Hashing

**CWE-328** - Use of Weak Hash | **CWE-261** - Weak Cryptography for Passwords | **CWE-522** - Insufficiently Protected Credentials

**Pattern:** passwords are stored using a fast hash function (MD5, SHA-\*, even SHA-256) or without a salt, exposing the system to massive brute-force attacks and rainbow tables.

**Understanding the risk:**

- **Fast hashing**: a modern GPU can test billions of SHA-256 hashes per second. An 8-character password is cracked within minutes.
- **No salt**: two users with the same password produce the same hash, so rainbow tables (precomputed lookup databases) are immediately exploitable.
- **Salt alone**: makes rainbow tables ineffective, but does not slow down brute force if the function is fast.

The correct solution is an **adaptive function** combining a salt with a configurable computational cost:

**Detection: look for**

- Calls to `md5()`, `sha256()`, `hash('sha256', ...)`, `crypto.createHash('sha256')` applied to passwords.
- Passwords stored in the database without a `password_hash` / `password_digest` column using a dedicated function.
- Password-hashing libraries absent from dependencies (`argon2`, `bcrypt`, `bcryptjs`).

**Vulnerable code:**

```javascript
// ❌ Node.js - SHA-256 without a salt, fast and crackable
const hash = crypto.createHash("sha256").update(password).digest("hex");
await db.saveUser({ email, password: hash });
```

**Fix:**

```javascript
// ✅ Node.js - Argon2id, adaptive, with built-in salt
const argon2 = require("argon2");
const hash = await argon2.hash(password, { type: argon2.argon2id });
await db.saveUser({ email, password: hash });

// Verification
const valid = await argon2.verify(storedHash, password);
```

**Equivalents:** `password_hash($password, PASSWORD_ARGON2ID)` (PHP), `werkzeug.security.generate_password_hash` with `method='scrypt'` (Python/Flask), `BCrypt.hashpw()` (Java).

**Typical severity:** 🔴 Critical (fast hashing without a salt on production data) to 🟠 High (bcrypt with too low a cost factor, or a hardcoded static salt).

---

### A04.4 - Generation of Non-Cryptographic Random Values (Weak PRNG)

**CWE-330** - Use of Insufficiently Random Values | **CWE-338** - Use of Cryptographically Weak PRNG

**Pattern:** security-relevant values (password reset tokens, session identifiers, CSRF tokens, IVs, nonces, keys) are generated using a non-cryptographic PRNG whose internal state can be partially or fully reconstructed from observed outputs.

**Detection: look for**

| Language | Avoid                                 | Use                                                |
| -------- | ------------------------------------- | -------------------------------------------------- |
| Node.js  | `Math.random()`                       | `crypto.randomBytes()`, `crypto.randomUUID()`      |
| PHP      | `rand()`, `mt_rand()`, `uniqid()`     | `random_bytes()`, `random_int()`                   |
| Python   | `random.random()`, `random.randint()` | `secrets.token_bytes()`, `secrets.token_urlsafe()` |
| Java     | `java.util.Random`                    | `java.security.SecureRandom`                       |

**Vulnerable code:**

```javascript
// ❌ Math.random() for a password reset token
const resetToken = Math.random().toString(36).slice(2);
```

**Fix:**

```javascript
// ✅ crypto.randomBytes() - sufficient cryptographic entropy (128 bits minimum)
const resetToken = crypto.randomBytes(32).toString("hex"); // 256 bits
```

**Special cases to watch for:**

- PHP's `uniqid()`: based on the microsecond timestamp, partially predictable.
- Seed derived from a timestamp (`new Random(System.currentTimeMillis())` in Java): very low entropy.
- UUID v1: includes the timestamp and MAC address, not suitable for security use. Prefer UUID v4 generated by a CSPRNG.

**Typical severity:** 🟠 High to 🔴 Critical (depending on usage: a password reset token or session key using a weak PRNG is 🔴).

---

### A04.5 - Hardcoded Keys and Secrets

**CWE-798** - Use of Hard-coded Credentials | **CWE-321** - Use of Hard-coded Cryptographic Key

**Pattern:** encryption keys, JWT secrets, API tokens, or database passwords present directly in the source code or in versioned files. Once committed to Git, these secrets are **permanently compromised**: the history is not erased by a simple deletion commit.

**Detection: look for**

- Strings resembling keys in the code: `const JWT_SECRET = "..."`, `SECRET_KEY = "..."`, `ENCRYPTION_KEY = "..."`.
- Versioned `.env` files containing real values.
- `Dockerfile` with `ENV SECRET=...` or `ARG API_KEY=...` (`ARG` values appear in the layer history).
- Secrets passed as command-line arguments (visible in system logs).

**Mandatory masking rule:** if a real secret is detected, **never reproduce it** in the report. Replace it with `[SECRET MASKED]` and flag its presence as a separate finding with a recommendation for immediate rotation.

**Standard fix:**

```javascript
// ❌
const jwtSecret = "my_hardcoded_secret_in_the_code";

// ✅
const jwtSecret = process.env.JWT_SECRET; // injected at runtime via a vault or CI secrets
if (!jwtSecret) throw new Error("JWT_SECRET is not defined");
```

**Note:** this subtype overlaps with A02.2 (Security Misconfiguration, hardcoded secrets). Report it under both categories if relevant, referencing the cross-linked finding.

**Typical severity:** 🔴 Critical.

---

### A04.6 - Disabled TLS or Signature Validation

**CWE-295** - Improper Certificate Validation | **CWE-347** - Improper Verification of Cryptographic Signature | **CWE-757** - Selection of Less-Secure Algorithm During Negotiation

**Pattern:** verification of a peer's authenticity (TLS certificate) or of a token's authenticity (JWT signature) is disabled or can be bypassed, nullifying the cryptographic guarantees of the channel or mechanism.

**Detection: look for**

**TLS validation disabled:**

```javascript
// ❌ Node.js - disables server certificate verification
const https = require("https");
const agent = new https.Agent({ rejectUnauthorized: false });
```

```php
// ❌ PHP - disables TLS verification in cURL
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
```

```python
# ❌ Python requests - disables verification
requests.get(url, verify=False)
```

**Incorrect JWT validation:**

```javascript
// ❌ "none" algorithm accepted - token without a valid signature
const payload = jwt.verify(token, secret); // if the library accepts alg:none by default

// ❌ Algorithm determined by the token's header (attacker-controlled)
const { alg } = jwt.decode(token, { complete: true }).header;
const payload = jwt.verify(token, secret, { algorithms: [alg] }); // alg injected by the attacker
```

**JWT fix:**

```javascript
// ✅ Algorithm enforced server-side, "none" explicitly excluded
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ["HS256"], // strict allowlist, never 'none'
  issuer: "my-app",
  audience: "my-app-clients",
});
```

**Other patterns to look for:**

- Self-signed certificates accepted in production without certificate pinning.
- Absence of `exp` claim (expiration) verification in manual JWT validation.
- HMAC signature verified using an RSA public key (algorithm confusion), an HS256/RS256 downgrade attack.

**Typical severity:** 🔴 Critical (TLS disabled in production, JWT with no signature verification, "none" algorithm accepted).

---

### A04.7 - Poor Cryptographic Key Management

**CWE-320** - Key Management Errors | **CWE-310** - Cryptographic Issues

**Pattern:** cryptographic keys are not rotated, are stored with insufficient protection, or the architecture does not allow rotation without massive re-encryption of data.

**Detection: look for**

- Absence of a documented or implemented key rotation policy.
- Keys stored in the database or on the filesystem alongside the data they protect (same level of protection, meaning a database compromise also exposes the keys).
- Single-key architecture: one key encrypts all the data, leading to total compromise if that key leaks.
- Absence of a KMS (Key Management Service) or HSM for systems handling sensitive data.
- Reused or static IV (initialization vector) in GCM or CTR mode: reusing an IV with the same key in AES-GCM compromises both the confidentiality and integrity of the encryption.

**Recommended architecture (DEK/KEK):**

```
Sensitive data
    ↓ encrypted by
DEK (Data Encryption Key) - key per record or per resource
    ↓ encrypted by
KEK (Key Encryption Key) - stored in a KMS/HSM, never exposed directly to the application
```

This model makes it possible to:

- Rotate keys without re-encrypting all the data (only the DEKs are re-encrypted with the new KEK).
- Isolate compromise: an exposed DEK only compromises a single resource, not the whole system.

**Typical severity:** 🟠 High (absence of rotation, static IV) to 🔴 Critical (a single key encrypting all data stored alongside that data, IV reused in GCM).

---

### A04.8 - Lack of Crypto-Agility and Post-Quantum Risk

**CWE-327** - Use of a Broken or Risky Cryptographic Algorithm

**Pattern:** the application uses asymmetric algorithms (RSA, ECC) to protect data with a long sensitivity lifespan, without a migration path toward post-quantum cryptography. The _harvest now, decrypt later_ strategy makes this risk active as of today.

**Detection: look for**

- Use of RSA or ECC to encrypt or sign data whose sensitivity extends beyond 2030.
- Absence of a mechanism allowing cryptographic algorithms to be replaced without an application redesign (the algorithm hardcoded rather than configurable).
- No mention of a post-quantum migration path in the security documentation of a critical system.

**Note on severity:** this subtype is generally ℹ️ Informational to 🟢 Low for most applications. It becomes 🟡 Medium to 🟠 High for systems handling medical, financial, or government data, or any system whose data sensitivity lifespan exceeds 5 years. Mention it systematically as a point of attention in the report, even when the severity is low.

**Reference standards:** NIST FIPS 203 (ML-KEM / Kyber), FIPS 204 (ML-DSA / Dilithium), FIPS 205 (SLH-DSA / SPHINCS+), published in August 2024.

**Typical severity:** ℹ️ Informational to 🟡 Medium depending on the sensitivity and lifespan of the data.

---

## Cross-Cutting Remediation Rules

1. **TLS everywhere, HSTS enabled**: all communications over HTTPS, `Strict-Transport-Security` with `includeSubDomains` and `preload`, `max-age` >= 1 year.
2. **Argon2id for passwords**: with the parameters recommended by the OWASP Password Storage Cheat Sheet. bcrypt acceptable (cost >= 10). Never MD5/SHA-\* alone.
3. **CSPRNG for any security-relevant value**: `crypto.randomBytes()` (Node.js), `random_bytes()` (PHP), `secrets` (Python), `SecureRandom` (Java). Never `Math.random()`, `rand()`, `mt_rand()`.
4. **Secrets via a vault**: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault. Environment variables injected at runtime. Nothing in the code, nothing in Git, nothing in Docker images.
5. **Never disable TLS validation**: not even temporarily, not even in staging. Use self-signed certificates with a trusted internal CA if necessary.
6. **JWT: algorithm enforced server-side**: strict allowlist, `none` explicitly excluded, never trust the token's `alg` field.
7. **DEK/KEK architecture**: separate data keys from key-protecting keys, store KEKs in a KMS or HSM.
8. **Unique IV per encryption operation**: generated via a CSPRNG for each encryption, never reused with the same key (critical in GCM/CTR mode).
9. **Never implement cryptography yourself**: use maintained libraries (libsodium, Web Crypto API, OpenSSL via an official binding).
10. **Crypto-agility**: configure algorithms rather than hardcoding them, to allow migration without a redesign.

---

## Severity Classification Guide

| Finding criteria                                                                                                                                                                                                                                           | Severity         |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| Passwords in cleartext or hashed with MD5/SHA-\* without a salt, JWT secret hardcoded in production, TLS disabled on an HTTP client, JWT with no signature verification or with `none` accepted, IV reused in AES-GCM, weak PRNG for a reset/session token | 🔴 Critical      |
| Obsolete algorithm (DES, RC4, 3DES) on sensitive data, bcrypt with insufficient cost, single key without rotation encrypting all data, absence of HSTS on an app handling credentials, weak PRNG for a short-lived value                                   | 🟠 High          |
| MD5/SHA-1 for non-critical integrity verification, TLS 1.1 still accepted, absence of documented key rotation, architecture without DEK/KEK on moderately sensitive data                                                                                   | 🟡 Medium        |
| SHA-256 used where Argon2id would be preferable but without compromised production data, absence of crypto-agility on a non-critical system                                                                                                                | 🟢 Low           |
| Absence of a post-quantum migration path on a non-critical system, RSA 2048 where 4096 would be preferable, correct algorithm but not the recommended first choice                                                                                         | ℹ️ Informational |

---

## Common False Positives - A04

| Detected pattern                                | Reason for false positive                                                                  | How to verify                                                                                               |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `MD5(...)` in the code                          | MD5 can be used for non-security checksums (ETag, cache key, deduplication)                | Check what the value is used for: security-relevant integrity or authentication, or something else?         |
| `Math.random()`                                 | Can be used for non-sensitive resource IDs or UX/UI purposes                               | Check whether the value is used to generate an auth token, a reset link, or a security-relevant value       |
| `SHA1`                                          | Weak for signatures, acceptable for non-security uses                                      | Check the usage context: token signature vs. content hash                                                   |
| `rejectUnauthorized: false`                     | May be present only in test or local development code                                      | Check whether this code is gated on `NODE_ENV === 'development'` or present in the production configuration |
| API key in a config variable                    | May be a value injected by the environment, not hardcoded                                  | Check whether it is `process.env.API_KEY` (injected) or a hardcoded literal value                           |
| `bcrypt` hashing algorithm with `saltRounds: 8` | May look weak but remains acceptable; OWASP recommends >= 10, not a critical vulnerability | Note as Informational if fewer than 10 rounds                                                               |

---

## Finding Template for the Report

````
**[OWASP-A04-NNN]** - [Short title]

- **Severity:** [level + icon]
- **Confidence:** 🔵 High / 🟣 Medium / ⚪ Low `[MANUAL VERIFICATION REQUIRED if Low]`
- **Remediation effort:** Low (<1h) / Medium (1-4h) / High (>4h) / Architectural
- **Justification:** [1 sentence, specify the sensitivity of the data involved]
- **Subtype:** A04.X - [subtype name]
- **Location:** [file:line / function / endpoint]
- **Description:** [explanation of the failing cryptographic mechanism]
- **Potential impact:** [what an attacker can obtain, decrypted data, stolen session, etc.]
- **Evidence / Vulnerable example:**
  ```[language]
  // audited excerpt - secrets replaced with [SECRET MASKED]
````

- **Recommendation:** [concrete action with the recommended algorithm/library]
- **Remediation example:**
  ```[language]
  // fixed version
  ```
- **References:** [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) | [OWASP A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) (if applicable)

```

> Note: Cryptographic Failures corresponds to A02 in the OWASP Top 10 2021. In this orchestrator's 2025 reference framework, it is A04.

---

## Limitations of Static Analysis for A04

- **Effective TLS configuration**: code-level directives (`rejectUnauthorized: false`) are statically detectable, but the server's actual TLS configuration (accepted versions, cipher suites) requires an active scan (testssl.sh, Qualys SSL Labs).
- **Real entropy of generated values**: detecting `Math.random()` is straightforward; assessing whether a generated value has sufficient entropy in practice requires dynamic analysis.
- **Effective key rotation**: a DEK/KEK architecture may be described in the code but never applied operationally, which is not verifiable statically.
- **Sensitive data stored in cleartext**: requires access to the database or storage artifacts to confirm the actual format of the stored data.
- **Post-quantum risk**: a contextual assessment depending on the data's lifespan, not determinable from the code alone.

Mention these limitations in the "Limitations" section of the report and propose the relevant dynamic verifications with explicit validation.
```
