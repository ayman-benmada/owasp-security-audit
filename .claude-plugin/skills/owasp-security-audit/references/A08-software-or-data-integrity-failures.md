# A08 - Software and Data Integrity Failures

**Reference standard:** OWASP Top 10 (2025), category A08
**Main associated CWEs:** CWE-345, CWE-346, CWE-349, CWE-354, CWE-494, CWE-502, CWE-506, CWE-565, CWE-601, CWE-829, CWE-830
**Finding format:** `OWASP-A08-NNN`

This file is loaded by the `owasp-security-audit` orchestrator skill when analyzing category A08. It provides detection patterns, standard fixes, and the severity grid specific to software and data integrity failures.

---

## Definition

A08 covers situations where an application, a CI/CD pipeline, or an update mechanism treats code, configurations, or data as trustworthy **without having verified their integrity or provenance**.

The danger lies in its silent nature: an attacker who injects malicious code into a dependency, a build pipeline, or a serialized data stream compromises the system without triggering any alert, the injected code is then treated as legitimate by every downstream component.

**Overlap with A03:** A03 (Supply Chain) covers exposure to vulnerable dependencies and CI/CD pipeline security from an organizational standpoint. A08 focuses on the **technical mechanisms of integrity verification**: immutable references, cryptographic signatures, secure deserialization. Both categories can produce overlapping findings on the same scope.

Guiding principle: **never trust a mutable reference or unsigned data**. Anything that gets executed or reconstructed must be tied to an immutable cryptographic identifier that is verified before use.

---

## Attack surface, exploitability prerequisites

Before declaring an A08 finding, verify that **the attacker can influence the deserialized data or the build pipeline**. Typical vectors:

- Serialized data coming from an HTTP input (cookie, body, header) deserialized without validation
- CI/CD pipeline using mutable dependencies or images without integrity verification
- Webhooks or callbacks whose payload is deserialized without signature verification
- Data stored in a database or cache that can be modified by an attacker with partial access

**Cases where the finding should be downgraded or dismissed:**

- `pickle.loads()` or `unserialize()` on data **generated and stored by the same system** with no possible external interference
- Deserialization of data coming from a **trusted internal source** (another microservice with mTLS, internal database)
- CI/CD pipeline using actions without a SHA hash but coming from the **official organization** with active branch protection
- Signed data verified further down the flow, the verification does not necessarily have to happen at the point of deserialization

---

## Detection methodology

### 1. Identify unverified code or data entry points

- **CI/CD pipeline**: actions, base images, scripts downloaded on the fly.
- **Application dependencies**: floating versions, unofficial sources, missing or unvalidated lockfile.
- **Deserialized data**: cookies, request bodies, inter-service messages, any flow where a native serialization format is used on externally sourced data.
- **Update mechanisms**: application auto-update, plugin downloads, loading of remote configurations.

### 2. Check for the presence of integrity mechanisms

For each identified entry point:

- Is there an immutable cryptographic identifier (commit SHA, image digest, file hash)?
- Is the signature or hash verified **before** any execution or deserialization?
- Is the source restricted to an explicitly authorized set of origins?

### 3. Distinguish A08 from A03

- **A03**: "this dependency is vulnerable" or "the pipeline lacks security processes."
- **A08**: "this reference is mutable and can be replaced without detection" or "this data is deserialized without integrity or signature verification."

---

## Subtypes and detection patterns

---

### A08.1 - Mutable references in CI/CD pipelines

**CWE-494** - Download of Code Without Integrity Check | **CWE-829** - Inclusion of Functionality from Untrusted Control Sphere

**Pattern:** CI/CD actions, base images, or scripts are referenced by floating tags (`main`, `master`, `latest`, `v4`) or downloaded without hash verification. A tag is a mutable pointer, the maintainer (or an attacker who has compromised their account) can move it to point to a malicious commit without any diff appearing in the pipeline.

**Detection, look in workflow files:**

```yaml
# ❌ Floating tag - 'main' can point to any commit
- uses: actions/checkout@main

# ❌ Semantic version - 'v4' is a movable tag
- uses: actions/checkout@v4

# ❌ Third-party action on a floating branch
- uses: some-org/some-action@master

# ❌ Script downloaded and executed directly - unverified content
- run: curl https://example.com/script.sh | bash

# ❌ Docker image with a floating tag
- run: docker pull myapp:latest
```

**Fix, immutable references:**

```yaml
# ✅ Full commit SHA (40 characters) - immutable by definition
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1

# ✅ Third-party action audited and pinned to a SHA
- uses: some-org/some-action@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 # v2.3.1

# ✅ Script downloaded, verified, then executed
- name: Download and verify script
  run: |
    curl -fsSL -o script.sh https://example.com/script.sh
    echo "abc123def456...  script.sh" | sha256sum -c -
    bash script.sh

# ✅ Docker image pinned to a digest
- run: docker pull myapp@sha256:abc123...
```

**Three principles of a hardened pipeline:**

1. **Immutability**: commit SHA for Git, digest for Docker images, hash for files.
2. **Least privilege**: `permissions: contents: read` by default, expanded only as needed.
3. **Isolation and ephemerality**: each build runs in a fresh, disposable environment that is destroyed after use.

**Minimal permissions in GitHub Actions:**

```yaml
# ✅ Permissions explicitly restricted to the minimum necessary
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read # read-only - no write, no publishing
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
```

**Typical severity:** High to Critical (a compromised pipeline has privileged access to secrets, registries, and production environments).

---

### A08.2 - Dependencies from untrusted sources or floating versions

**CWE-494** - Download of Code Without Integrity Check | **CWE-830** - Inclusion of Web Functionality from an Untrusted Source

**Pattern:** dependencies are declared with floating versions (`^`, `~`, `*`, `latest`) or downloaded from unofficial sources. An imperceptible version change in the lockfile can introduce malicious code without any modification of the source code being visible.

**Detection, look for:**

```json
// ❌ Floating versions - non-deterministic resolution
{
  "dependencies": {
    "lodash": "^4.17.0", // accepts any 4.x.x version >= 4.17.0
    "internal-utils": "*" // accepts any version
  }
}
```

- Absence of a lockfile (`package-lock.json`, `composer.lock`, `Pipfile.lock`, `go.sum`).
- Use of `npm install` instead of `npm ci` in CI (does not guarantee reproducibility).
- Packages downloaded from direct URLs rather than from the official registry.
- `lockfile-lint` absent from the pipeline (does not validate that download URLs use HTTPS and come only from the official registry).

**Vulnerable vs. fixed code:**

```json
// ✅ Pinned versions
{
  "dependencies": {
    "lodash": "4.17.21",
    "internal-utils": "1.2.3"
  },
  "scripts": {
    // lockfile-lint validates HTTPS + official source before any install
    "preinstall": "npx --yes lockfile-lint --path package-lock.json --validate-https --allowed-hosts npm"
  }
}
```

```bash
# ❌ Install without any guarantee of reproducibility
npm install

# ✅ Reproducible install from the lockfile + vulnerability audit
npm ci
npm audit --audit-level=high
```

**Dependency confusion:** an attack in which an attacker publishes a package on a public registry that has the same name as an internal package. If the resolver checks the public registry first, it installs the malicious package. Detect this by verifying that internal packages are configured to resolve only from the internal registry (`.npmrc` with `@scope:registry=https://internal-registry/`).

**Typical severity:** Medium (floating versions alone) to High (missing lockfile + audit on an exposed app) to Critical (confirmed dependency confusion or unofficial source).

---

### A08.3 - Insecure deserialization

**CWE-502** - Deserialization of Untrusted Data | **CWE-565** - Reliance on Cookies without Validation and Integrity Checking

**Pattern:** user-controlled data is passed to a native deserialization function (`unserialize()` in PHP, `pickle.loads()` in Python, `ObjectInputStream` in Java, `BinaryFormatter` in .NET). These functions instantiate real objects and automatically trigger special methods (magic methods), without any explicit action from the developer. An attacker who controls the serialized string also controls which classes are instantiated and which methods run.

**Exploitation mechanism (PHP):**

```php
// An apparently harmless utility class, legitimately used elsewhere in the application
class FileCache {
    public $cacheFile;
    public $content;

    // __destruct() runs AUTOMATICALLY at the end of the script, with no explicit call
    public function __destruct() {
        file_put_contents($this->cacheFile, $this->content);
    }
}

// ❌ Deserialization of a client-controlled cookie
$session = unserialize($_COOKIE['session']);
// Attacker payload:
// O:9:"FileCache":2:{s:9:"cacheFile";s:24:"/var/www/html/shell.php";s:7:"content";s:29:"<?php system($_GET['c']); ?>";}
// -> PHP instantiates FileCache, sets the properties, then __destruct() writes a web shell
```

**What makes this risk distinctive:** exploitation requires no flaw in either `FileCache` or `unserialize()`. It is the use of `unserialize()` on external data that is inherently dangerous, it turns data into executable logic. Tools such as **phpggc** (PHP) and **ysoserial** (Java) contain pre-built gadget chains for popular frameworks (Symfony, Laravel, Spring, Apache Commons).

**Detection, look for:**

```php
// ❌ PHP - unserialize on external data
unserialize($_COOKIE['...'])
unserialize($_POST['...'])
unserialize($_GET['...'])
unserialize(base64_decode($input)) // common obfuscation attempt
```

```python
# ❌ Python - pickle on external data
import pickle
obj = pickle.loads(request.data)
obj = pickle.loads(base64.b64decode(cookie_value))
```

```java
// ❌ Java - ObjectInputStream on unverified data
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();
```

```csharp
// ❌ .NET - BinaryFormatter (deprecated since .NET 5, forbidden in .NET 7+)
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);
```

**Main fix, replace with a pure data format:**

```php
// ✅ PHP - JSON cannot instantiate any arbitrary class
$session = json_decode($_COOKIE['session'], true);
if ($session === null && json_last_error() !== JSON_ERROR_NONE) {
    throw new InvalidArgumentException('Invalid session');
}
```

```python
# ✅ Python - json triggers no code execution
import json
data = json.loads(request.data)
```

**If native deserialization is strictly necessary, three combined measures:**

```php
// ✅ PHP - combined measures (signature + restricted classes)

// 1. Sign the data BEFORE sending it to the client
$payload = serialize($sessionData);
$signature = hash_hmac('sha256', $payload, $_ENV['SESSION_SECRET']);
$cookie = base64_encode($payload) . '.' . $signature;

// 2. Verify the signature BEFORE any deserialization
[$encodedPayload, $receivedSig] = explode('.', $cookie, 2);
$payload = base64_decode($encodedPayload);
$expectedSig = hash_hmac('sha256', $payload, $_ENV['SESSION_SECRET']);

if (!hash_equals($expectedSig, $receivedSig)) {
    throw new SecurityException('Invalid signature - data rejected');
}

// 3. Restrict the allowed classes (last-resort filter)
$session = unserialize($payload, ['allowed_classes' => ['UserSession', 'UserPreferences']]);
```

**Note on `allowed_classes`:** restricting the allowed classes is defense in depth, not a sufficient protection on its own, gadget chains sometimes exist even among the allowed classes. The HMAC signature remains the primary safeguard.

**Serialization formats by risk level:**

| Format                              | Code execution risk | Recommendation                   |
| ----------------------------------- | ------------------- | -------------------------------- |
| PHP `serialize()` / `unserialize()` | High                | Replace with JSON                |
| Python `pickle`                     | High                | Replace with JSON                |
| Java `ObjectInputStream`            | High                | Replace with JSON/Protobuf       |
| .NET `BinaryFormatter`              | High                | Forbidden since .NET 7           |
| JSON                                | None                | Recommended format               |
| Protobuf / MessagePack              | Low                 | Acceptable with validated schema |
| YAML (with constructors)            | Moderate            | Disable custom constructors      |

**Typical severity:** Critical (RCE via gadget chain, web shell written, arbitrary file read).

---

### A08.4 - Unverified signed or encrypted data

**CWE-345** - Insufficient Verification of Data Authenticity | **CWE-346** - Origin Validation Error

**Pattern:** data presented as authentic (tokens, signed cookies, webhooks) is accepted without verification of its cryptographic integrity, or with incorrect verification.

**Detection, look for:**

- **JWT**: `jwt.decode()` without `jwt.verify()`, `none` algorithm accepted, `alg` field read from the token itself (see A04.6 and A07.8 for details).
- **Signed cookies**: signature checked with a non-constant-time comparison (vulnerable to timing attacks) instead of `hash_equals()` / `hmac.compare_digest()`.
- **Webhooks**: webhook payload (GitHub, Stripe, Shopify) accepted without verifying the HMAC signature provided in the headers.
- **Downloads**: files or configurations downloaded from CDNs without verifying the hash announced by the provider.

**Vulnerable code, webhook without verification:**

```javascript
// ❌ Webhook payload accepted without signature verification
app.post("/webhook/github", (req, res) => {
  const event = req.body; // anyone can send a fake event
  processEvent(event);
  res.sendStatus(200);
});
```

**Fix, HMAC verification before processing:**

```javascript
// ✅ Signature verified before any processing
const crypto = require("crypto");

app.post(
  "/webhook/github",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const signature = req.headers["x-hub-signature-256"];
    const expected =
      "sha256=" +
      crypto
        .createHmac("sha256", process.env.WEBHOOK_SECRET)
        .update(req.body) // raw, unparsed body
        .digest("hex");

    // Constant-time comparison - resistant to timing attacks
    if (
      !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
    ) {
      return res.status(401).send("Invalid signature");
    }

    const event = JSON.parse(req.body);
    processEvent(event);
    res.sendStatus(200);
  },
);
```

**Typical severity:** High to Critical depending on the action triggered by the webhook or the data accepted.

---

## Cross-cutting remediation rules

1. **Immutable references in pipelines**, full commit SHA (40 hex characters) for Git actions, `sha256:...` digest for Docker images. Never floating tags (`latest`, `main`, `v4`).
2. **Hash verification before execution**, any script downloaded on the fly must be written to a local file, have its SHA-256 hash checked against a known value, and only then executed if the verification passes.
3. **Least privilege in pipelines**, `permissions: contents: read` by default, explicitly expanded as needed per job.
4. **Lockfile + `npm ci`**, exactly pinned versions, lockfile validated before install (`lockfile-lint`), `npm ci` in CI.
5. **Deserialization: JSON first**, replace `unserialize()`, `pickle.loads()`, `ObjectInputStream` with JSON or Protobuf on any externally sourced data flow.
6. **HMAC signature before deserialization**, if native serialization is unavoidable: sign before sending, verify with `hash_equals()` before deserializing, then restrict `allowed_classes`.
7. **Webhook verification**, validate the HMAC signature of every webhook before any processing, on the raw, unparsed body.
8. **Constant-time comparison**, always use `hash_equals()` (PHP), `hmac.compare_digest()` (Python), `crypto.timingSafeEqual()` (Node.js) for signature comparisons.
9. **Internal registry for packages**, a proxy validating sources, protection against dependency confusion (`@scope:registry=https://internal-registry/`).
10. **Audit of artifact contents**, regularly verify that published Docker images and packages do not contain unexpected files (see A02.11).

---

## Severity classification aid

| Finding criteria                                                                                                                                                                                                                                                           | Severity      |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Native deserialization on external data without signature (potential RCE), pipeline with a floating tag on an action that has write access to secrets or the registry, confirmed dependency confusion, webhook without signature verification triggering sensitive actions | Critical      |
| Pipeline with floating tags without critical access, `curl \| bash` script without verification, JWT accepted without signature verification (see A07.8), missing lockfile on an exposed app                                                                               | High          |
| Floating versions without a lockfile on non-critical dependencies, absence of `lockfile-lint` in CI, webhook without verification on a low-impact action                                                                                                                   | Medium        |
| `npm install` instead of `npm ci` in CI (lockfile present), absence of a vulnerability audit in CI (scanning present elsewhere in the pipeline)                                                                                                                            | Low           |
| Absence of an internal registry (with no other gap), missing pipeline security documentation                                                                                                                                                                               | Informational |

**Amplification rule:** findings A08.1 (pipeline) and A08.2 (dependencies) are amplified by the effective privileges of the pipeline. A job with `contents: write` or access to the production registry turns a High finding into a Critical one.

---

## Common false positives, A08

| Detected pattern                               | Reason for the false positive                                                      | How to verify                                                                                        |
| ---------------------------------------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `pickle.loads(data)`                           | May deserialize internal data generated by the same system                         | Check the origin of `data`, does it come from an HTTP input, an uploaded file, or an internal cache? |
| `unserialize($_POST['data'])`                  | Clearly dangerous, but check whether validation/signature precedes the call        | Look for an HMAC or signature check right before the call                                            |
| Docker image `FROM ubuntu:latest` without hash | `latest` may point to a maintained version, lower risk than for third-party images | Assess whether the image is official and regularly updated                                           |
| Dependency without a fixed version in CI/CD    | May have a lock file or an artifact caching mechanism                              | Check the lock file and CI/CD caching policies                                                       |
| JWT without visible signature verification     | Verification may happen in a middleware or a global interceptor                    | Look for `jwt.verify()`, `verifyToken()`, or an auth middleware in the processing chain              |

---

## Finding template for the report

````
**[OWASP-A08-NNN]** - [Short title]

- **Severity:** [level + icon]
- **Confidence:** High / Medium / Low `[MANUAL VERIFICATION REQUIRED if Low]`
- **Remediation effort:** Low (<1h) / Medium (1-4h) / High (>4h) / Architectural
- **Justification:** [1 sentence, specify the effective privileges of the compromised entry point]
- **Subtype:** A08.X - [subtype name]
- **Location:** [file:line / workflow / CI step / endpoint]
- **Description:** [injection or integrity-bypass mechanism]
- **Potential impact:** [RCE, artifact tampering, secret exfiltration, etc.]
- **Evidence / Vulnerable example:**
  ```[language/yaml]
  // audited excerpt
````

- **Recommendation:** [immutable reference, signature, alternative format]
- **Remediation example:**
  ```[language/yaml]
  // fixed version
  ```
- **References:** [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) | [OWASP A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) | [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

```

> Note: Software and Data Integrity Failures corresponds to A08 in the OWASP Top 10 2021. In this orchestrator's 2025 reference standard, it is also A08.

---

## Limits of static analysis for A08

- **Deserialization gadget chains**: detecting `unserialize()` on external data is possible statically. Confirming exploitability requires identifying the classes available in the execution context and analyzing their magic methods, an analysis that benefits from dedicated tools (phpggc, ysoserial).
- **Effective floating tags**: a tag such as `v4` may or may not point to a secure commit at the time of the audit, confirming this requires querying the GitHub/GitLab API to resolve the current SHA.
- **Dependency confusion**: requires knowing the names of internal packages and verifying their absence from public registries, this cannot be determined from the code alone.
- **Webhook signatures**: signature verification in the code may be correct but bypassed by a middleware that parses the body before the signature is checked (e.g., `express.json()` before `express.raw()`), this requires an analysis of the middleware chain.
- **Actual artifact contents**: what is actually bundled into a Docker image or a published npm package can only be confirmed by inspecting the built artifact, not solely the Dockerfile or the package.json.

Mention these limitations in the "Limitations" section of the report and propose the relevant dynamic verifications with explicit validation.
```
