# A02 - Security Misconfiguration

**Reference framework:** OWASP Top 10 (2025), category A02
**Main associated CWEs:** CWE-16, CWE-260, CWE-315, CWE-520, CWE-611, CWE-614, CWE-732, CWE-756, CWE-798, CWE-942, CWE-1004
**Finding format:** `OWASP-A02-NNN`

This file is loaded by the `owasp-security-audit` orchestrator skill when analyzing category A02. It provides detection patterns, standard fixes, and the severity grid specific to security misconfigurations.

---

## Definition

Security misconfiguration covers any situation where a system, application, infrastructure component, or cloud service is set up incorrectly or insufficiently secured, creating exploitable attack surfaces. It generally results from operational errors: a parameter left at its default value, a debug option not disabled, an overly permissive cloud permission, a missing security header.

A02 covers **all layers** of an architecture: OS, web server, application framework, database, cloud services, HTTP headers, session management, XML parsers, CI/CD pipelines, and build artifacts.

Guiding principle: security through configuration must not depend on human vigilance, but on **reproducible, automated, and continuously verified hardening processes**.

---

## Attack surface, prerequisites for exploitability

Before declaring an A02 finding, verify that **the misconfiguration is exposed or exploitable in the deployment context**. Typical vectors:

- Publicly accessible configuration files (`.env`, `config.php`, `settings.py`)
- HTTP response headers revealing server information
- Verbose error pages returned to clients
- Admin or monitoring endpoints accessible without authentication
- Environment variables injected into the frontend (JS bundle)

**Cases where the finding should be downgraded or discarded:**

- The `.env` file is in `.gitignore` and not accessible via HTTP; do not flag it as Critical if only the source code is being analyzed
- `APP_DEBUG=true` in a `.env.example` or documentation file; this is not an active configuration
- Missing security headers on public static routes without sensitive data
- Directory listing enabled on a static directory that is intentionally public

---

## Detection methodology

A02 is the most cross-cutting category in the OWASP Top 10; a superficial audit produces many false positives and many false negatives. Follow this order.

### 1. Identify the layers present

Before auditing, list what is analyzable within the provided scope:

- **Application code**: framework (Express, Symfony, Laravel, Django, Spring, etc.), error handling, cookie configuration.
- **Web server / reverse proxy configuration**: Nginx, Apache, Caddy, Traefik, IIS, including the `add_header`, `autoindex`, `root`, `location` directives.
- **Cloud configuration**: IAM policies, S3 ACLs, security groups, managed service settings.
- **CI/CD pipeline**: `Dockerfile`, `.dockerignore`, `.npmignore`, build scripts, bundler configuration (Webpack, Vite).
- **Application configuration files**: `.env`, `config/*.yml`, `application.properties`, `settings.py`.
- **Structured format parsers**: XML, SVG, DOCX/XLSX/PPTX (which are XML), formats using an XML parser internally.

If a layer is not provided, note it in the "Limitations" section of the report rather than inventing findings.

### 2. Go through the sub-types

For each sub-type, apply the patterns. A single layer can accumulate several findings (e.g., an Nginx server with `autoindex on` AND no security headers AND exposed source maps).

### 3. Check for discrepancies between environments

A configuration may be correct in staging but not in production (or vice versa). If both are provided, compare them. Otherwise, report this as a limitation.

### 4. Distinguish "bad practice" from "exploitable vulnerability"

A02 contains many findings that are **defense-in-depth gaps** (e.g., a missing security header). Calibrate severity accordingly: a single missing header is rarely Critical, but combined with another flaw (XSS for CSP, XXE for a parser, etc.) it becomes an amplifier.

---

## Sub-types and detection patterns

> The examples below mix Node.js, Nginx, and PHP because A02 is intrinsically multi-layered. **Transpose each pattern to the stack of the audited project**; an Nginx configuration pattern also applies to Apache or Caddy with the equivalent directives.

---

### A02.1 - Debug mode active in production

**CWE-489** - Active Debug Code

**Pattern:** code, endpoint, or debug parameter left active in production. Includes test accounts, `/debug` routes, verbose logging exposing sensitive data, debug bars (Symfony Profiler, Django Debug Toolbar, Laravel Debugbar).

**Detection, look for:**

- Environment variables: `APP_DEBUG=true`, `DEBUG=True`, `NODE_ENV=development`, `RAILS_ENV=development` in a configuration intended for production.
- Routes or middlewares conditioned by a debug flag but deployed as-is.
- Presence of debug bars or profilers in production HTTP responses.
- Test endpoints (`/test`, `/_internal`, `/healthz` exposing too much information) accessible in production.

**Standard fix:** explicit deactivation via an environment variable (`NODE_ENV=production`, `APP_ENV=production`) **and** automated verification in the CI/CD pipeline before deployment.

**Typical severity:** High to Critical depending on what the debug mode exposes (stack traces, variables, SQL access).

---

### A02.2 - Hard-coded secrets

**CWE-798** - Use of Hard-coded Credentials | **CWE-260** - Password in Configuration File

**Pattern:** passwords, API keys, encryption keys, authentication tokens, private certificates present in the source code, in versioned configuration files, or in Docker images.

**Detection, look for:**

- Strings resembling secrets: `sk_live_`, `AKIA...`, `ghp_...`, `xoxb-`, JWTs (`eyJ...`), private keys (`-----BEGIN ... PRIVATE KEY-----`).
- Direct assignments: `const apiKey = "..."`, `password = "..."`, `database_url = "postgres://user:pass@..."`.
- `.env`, `application.properties`, `config.yml` files with real values rather than references to a vault.
- `Dockerfile` with `ENV API_KEY=...` or `ARG SECRET=...` (`ARG` values appear in the image history).

**Mandatory masking rule:** if a real secret is detected, **never reproduce it** in the report. Replace it with `[MASKED SECRET]` and report its presence as a separate finding.

**Standard fix:** storage in a vault (HashiCorp Vault, AWS Secrets Manager, GitHub/GitLab Secrets for CI), injection at runtime via environment variables, secret scanner in the pipeline (gitleaks, trufflehog, GitHub secret scanning). Any secret exposed in Git must be considered **permanently compromised**; immediate rotation is mandatory.

**Typical severity:** Critical (exposed production secret) to High (staging secret or limited scope).

---

### A02.3 - Verbose error messages exposing the technology stack

**CWE-209** - Generation of Error Message Containing Sensitive Information | **CWE-756** - Missing Custom Error Page

**Pattern:** the application returns stack traces, SQL queries, absolute paths, component versions, or framework error messages to the end user. The risk is not the error itself but the **level of detail** disclosed.

**Detection, look for:**

- Global error handlers that serialize `err.stack`, `err.message`, or return the native error object as-is.
- Default framework error pages displayed in production (Whoops for Laravel, the yellow screen for Symfony, the Django debug screen).
- SQL errors returned as-is (`syntax error at or near "WHERE" in query SELECT * FROM users WHERE...`).
- Headers exposing the version (`X-Powered-By: Express`, `Server: Apache/2.4.41 (Ubuntu)`).

**Vulnerable code:**

```javascript
app.use((err, req, res, next) => {
  res.status(500).json({
    message: err.message, // ⚠️ may contain paths, variable names
    stack: err.stack, // ⚠️ reveals the internal structure of the code
  });
});
```

**Fix:**

```javascript
app.use((err, req, res, next) => {
  logger.error({ err, requestId: req.id }, "Unhandled error"); // ✅ internal log
  res.status(500).json({ error: "Internal server error" }); // ✅ generic response
});
```

**Recommended validation:** deliberately test error cases (malformed request, nonexistent URL, invalid type) and verify that the response remains generic.

**Typical severity:** Medium (information disclosure facilitating reconnaissance) to High if SQL or a sensitive path is exposed.

---

### A02.4 - Directory listing enabled

**CWE-548** - Exposure of Information Through Directory Listing

**Pattern:** the web server allows browsing directories without an index file, exposing backup files (`.bak`, `.old`, `.zip`), configurations, source code, or forgotten private keys.

**Detection, look for:**

```nginx
# ❌ VULNERABLE CONFIGURATION (Nginx)
server {
    root /var/www/html/public;
    location / {
        autoindex on;  # ⚠️ lists directory contents
    }
}
```

- Nginx: `autoindex on;` in a `server` or `location` block.
- Apache: `Options +Indexes` or the absence of `Options -Indexes`.
- IIS: `Directory Browsing` enabled.
- Frameworks serving static files with implicit listing.

**Standard fix:** remove `autoindex on;` (or `Options -Indexes` for Apache), ensure every exposed directory contains an index file or returns a 403/404.

**Typical severity:** Medium to High depending on what is listed.

---

### A02.5 - Misconfigured session cookies

**CWE-614** - Sensitive Cookie Without Secure Attribute | **CWE-1004** - Sensitive Cookie Without HttpOnly Flag | **CWE-1275** - Sensitive Cookie with Improper SameSite Attribute

**Pattern:** a cookie carrying a session identifier or sensitive data does not carry the appropriate protection attributes.

**Detection, look for:**

- Absence of `Secure`: cookie sent over HTTP (interception on unsecured networks, MITM).
- Absence of `HttpOnly`: cookie accessible via JavaScript (theft amplified by XSS).
- `SameSite=None` without justification or without an associated `Secure` attribute: CSRF facilitated.
- Application configuration that does not pass any of these attributes (`res.cookie('session', token)` without options).

**Vulnerable / fixed code (Express):**

```javascript
// ❌
res.cookie("session", token);

// ✅
res.cookie("session", token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax", // 'strict' if UX allows it, 'none' only if truly necessary (and always with secure)
  maxAge: 1000 * 60 * 60,
});
```

**Note on SameSite:** `Strict` blocks all cross-site sending (possible UX impact on inbound navigation). `Lax` is a good compromise. `None` should remain the exception and requires `Secure`.

**Typical severity:** Medium (a single missing attribute) to High (aggravating combination).

---

### A02.6 - Missing or misconfigured HTTP security headers

**CWE-693** - Protection Mechanism Failure

**Pattern:** absence or lax configuration of standard security headers. A defense-in-depth layer, rarely exploitable on its own, but amplifies any other flaw (XSS, clickjacking, SSL stripping).

**Detection, check the presence and configuration of:**

| Header                      | Role                     | Recommended configuration                                         |
| --------------------------- | ------------------------ | ----------------------------------------------------------------- |
| `Strict-Transport-Security` | Forces HTTPS             | `max-age=63072000; includeSubDomains; preload`                    |
| `Content-Security-Policy`   | Restricts sources        | `default-src 'self'; ...` (without `unsafe-inline`/`unsafe-eval`) |
| `X-Frame-Options`           | Anti-clickjacking        | `DENY` or `SAMEORIGIN` (or via CSP `frame-ancestors`)             |
| `X-Content-Type-Options`    | Anti-MIME-sniffing       | `nosniff`                                                         |
| `Referrer-Policy`           | Limits leaks via Referer | `strict-origin-when-cross-origin`                                 |

**Recommended Nginx configuration:**

```nginx
server {
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';" always;
}
```

**Critical point on CSP:** a policy that is present but permissive (`unsafe-inline`, `unsafe-eval`, broad wildcards) does not provide protection. Favor nonces or hashes for inline scripts. Test via `Content-Security-Policy-Report-Only` before applying it strictly.

**Typical severity:** Low (a single isolated missing header) to Medium (permissive CSP on an exposed app) to High if combined with a discovered XSS.

---

### A02.7 - XXE (XML External Entity)

**CWE-611** - Improper Restriction of XML External Entity Reference | **CWE-776** - Improper Restriction of Recursive Entity References ("Billion Laughs")

**Pattern:** an XML parser accepts the resolution of external entities or DTDs, allowing an attacker to read local files, perform internal requests (SSRF), or cause a denial of service through exponential expansion.

**Typical payload (file read):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<stockCheck>
  <productId>&xxe;</productId>
</stockCheck>
```

**"Billion Laughs" payload (DoS):**

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>
```

**Detection, look for:**

- Use of XML parsers: `libxml`, `lxml`, `DocumentBuilder`, `XMLReader`, `SAXParser`, `simplexml_load_*`, etc., **without explicit configuration disabling DTDs/external entities**.
- Endpoints accepting XML input (SOAP, RSS, sitemaps, DOCX/XLSX/PPTX exports, **SVG uploads**).
- Conversions or processing of SVG images (resizing, thumbnail generation, validation): this is XML, and therefore an XXE vector.
- PDF or report generation from XML templates.

**Often underestimated risk:** XML is used indirectly in document generation (PDF, reports), Office formats (DOCX/XLSX/PPTX), and especially **SVG**, which is treated as an image but is actually a full XML document. A malicious SVG file uploaded can trigger an XXE during a simple server-side resize.

**Standard fix (PHP):**

```php
libxml_set_external_entity_loader(null);
```

**Standard fix (Node.js, avoid XML parsing when possible, otherwise configure explicitly):** use libraries that do not execute external entities by default, and disable `resolveExternals` / `loadDTD`. Refer to the [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) for the configuration specific to each language.

**Typical severity:** Critical (file reading, SSRF, DoS).

---

### A02.8 - Overly permissive cloud permissions

**CWE-732** - Incorrect Permission Assignment for Critical Resource | **CWE-942** - Permissive Cross-domain Policy with Untrusted Domains

**Pattern:** a cloud resource configured with permissions broader than necessary: public S3 bucket, IAM policy with wildcards, security group open on `0.0.0.0/0`, publicly accessible database.

**Detection, look for:**

- IAM policies with `"Action": "*"` or `"Resource": "*"` without justification.
- S3 buckets with `"Effect": "Allow"`, `"Principal": "*"`, or `BlockPublicAccess` disabled.
- Inconsistencies between ACLs and bucket policy (the most permissive rule generally wins), hence the recommendation to **use only policies** and abandon ACLs.
- Security groups / firewalls exposing administration ports (22, 3389, 5432, 27017) to `0.0.0.0/0`.
- Long-lived access keys rather than temporary roles.

**Standard fix:**

- Principle of least privilege: actions and resources explicitly listed.
- Enable "Block Public Access" at the AWS account level (a safety net even if an individual bucket is misconfigured).
- Prefer policies (IAM + bucket) over ACLs to avoid inconsistencies.
- Regular audit via dedicated tools (AWS Access Analyzer, Prowler, CloudSploit).

**Typical severity:** Critical (public bucket containing user data, `*:*` policy) to High (exposed admin port without direct data access).

---

### A02.9 - Default components not removed

**CWE-1188** - Insecure Default Initialization | **CWE-756** - Missing Custom Error Page

**Pattern:** example pages, default accounts, admin interfaces, or documentation shipped with a server or framework, left in place in production.

**Detection, look for:**

- Tomcat manager (`/manager/html`), phpMyAdmin at its default path, H2 console, unsecured Spring Boot Actuator on `/actuator/**`.
- Unmodified default accounts: `admin/admin`, `root/root`, `postgres/postgres`.
- Apache's "It works!" page, the default Nginx page, framework example pages.
- Auto-generated documentation (Swagger UI, GraphQL Playground, /docs) publicly accessible in production.

**Standard fix:** explicitly uninstall or disable, restrict necessary admin interfaces by IP, change all default credentials.

**Typical severity:** Medium (information disclosure) to Critical (exploitable default admin account).

---

### A02.10 - Absence of a reproducible hardening process

**CWE-1053** - Missing Documentation for Design

**Pattern:** the secure configuration exists but depends on human vigilance; there is no pipeline that validates it, no IaC, no regular audit. Risk of **drift over time**: a debug mode temporarily enabled and forgotten, a manually edited configuration file, a new framework version introducing an option left at its default.

**Detection, look for:**

- Absence of configuration validation in the CI/CD pipeline (no step checking `NODE_ENV`, no Docker image scan, no configuration linter).
- Configuration only present in documentation, not in code (Terraform, Ansible, Helm).
- Configuration discrepancies between dev / staging / production beyond secrets and URLs.
- No secret scanner in the pipeline.

**Standard fix:** Infrastructure-as-Code, automatic validation in CI (linters, scanners), recurring audit, environments as close as possible to one another (only secrets and URLs should differ).

**Typical severity:** Informational to Low; this is an organizational weakness that amplifies the risk of other A02 findings.

---

### A02.11 - Exposed build artifacts and sensitive files

**CWE-540** - Inclusion of Sensitive Information in Source Code | **CWE-538** - Insertion of Sensitive Information into Externally-Accessible File

**Pattern:** files that should not reach production (source maps, test files, hidden files, dev dependencies) end up in the delivered artifacts.

**Detection, look for:**

- Source maps (`*.map`) accessible from a CDN or public bundle in production, allowing the original code to be reconstructed.
- Exposed hidden files: `.env`, `.git/`, `.htaccess`, `.DS_Store` accessible via HTTP.
- Absence of `.dockerignore` / `.npmignore` or incomplete rules: Docker images contain test directories, internal documentation, CI credentials.
- `Dockerfile` with `COPY . .` without a strict `.dockerignore`.
- Poorly defined webroot (Nginx `root /var/www/app/` instead of `root /var/www/app/public/`), giving access to the entire application codebase.

**Nginx fix, block hidden files:**

```nginx
location ~ /\. { deny all; }
```

**Build fix:**

- Strict `.dockerignore` (at minimum: `.git`, `.env*`, `node_modules`, `*.test.*`, `coverage/`, `docs/`).
- Disable source map generation in production via the bundler configuration.
- Verify the actual contents of the artifact (`docker image inspect`, `npm pack --dry-run`) before deployment.

**Typical severity:** High (exposed source maps, accessible `.env`) to Critical (accessible `.git/` allowing the repo to be cloned).

---

## Cross-cutting remediation rules

These principles guide recommendations regardless of the sub-type:

1. **Automated and reproducible hardening**: configuration security is validated by the pipeline, not by human memory.
2. **Minimal attack surface**: every module, port, account, or endpoint that is not strictly necessary is disabled.
3. **Debug explicitly disabled in production**: standard environment variable (`NODE_ENV=production`, `APP_ENV=production`), validated in CI.
4. **Secrets via dedicated tools**: vault (Vault, Secrets Manager) or CI platform secrets; never in code, never in a Docker image. Any leaked secret requires immediate rotation.
5. **Generic errors client-side, detailed logs server-side**: the end user sees `Internal server error`, the engineering team sees the stack trace in a centralized logging system.
6. **XML parsers hardened by default**: DTDs and external entities disabled as soon as XML from an external origin is processed (including SVG, DOCX, XLSX).
7. **Hardened cookies**: `Secure`, `HttpOnly`, `SameSite` on every sensitive cookie.
8. **Security headers at the reverse proxy level**: not in each individual app, to guarantee universal application.
9. **Cloud: strict least privilege**: no wildcards without justification, "Block Public Access" enabled, ACLs abandoned in favor of policies.
10. **Audit of the actual content of artifacts**: `docker image inspect`, `npm pack --dry-run`, regular scan of the exposed webroot.

---

## Severity classification guide

| Finding criteria                                                                                                                                                                            | Severity         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| Exposed production secret, active debug mode in production, public cloud bucket with sensitive data, exploitable XXE, accessible `.git/` or `.env`                                          | 🔴 Critical      |
| Exposed SQL stack trace, public source maps, directory listing exposing sensitive files, session cookie without `HttpOnly` AND without `Secure`, default component with default credentials | 🟠 High          |
| Directory listing with no sensitive file visible, major security header missing (HSTS, CSP), permissive CSP, error message revealing a component's version                                  | 🟡 Medium        |
| Minor missing header (Referrer-Policy, X-Content-Type-Options), `X-Powered-By` header exposed alone                                                                                         | 🟢 Low           |
| Absence of IaC, slightly divergent environments, lack of recurring audit, with no observed drift                                                                                            | ℹ️ Informational |

**Amplification rule:** an isolated A02 finding may be Low, but combined with another flaw (XSS + absence of CSP, XXE + SVG parser) it becomes an amplifier. Mention this explicitly in the severity justification.

---

## Common false positives - A02

| Detected pattern                      | Reason for the false positive                                                           | How to verify                                                                                               |
| ------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `APP_DEBUG=true` in the source code   | May be in `.env.example` or a dev file, not the production configuration                | Check whether it is in `.env.production`, `docker-compose.prod.yml`, or the CI/CD environment               |
| Secrets visible in the code           | May be a placeholder value in an example file                                           | Check whether the value looks like a real secret (high entropy) or an example (`your_key_here`, `changeme`) |
| Missing security headers              | May be injected by a reverse proxy (Nginx, Cloudflare, AWS ALB) not visible in the code | Check the Nginx/Apache/CDN configuration or test under real conditions                                      |
| Overly broad file permissions         | May be intentional for public files                                                     | Check whether the file contains sensitive data                                                              |
| `CORS: *`                             | Acceptable if the API is strictly public and unauthenticated                            | Check whether authenticated endpoints use the same CORS policy                                              |
| Cookie without `HttpOnly` or `Secure` | May be intentional for functional cookies read by client-side JS                        | Check whether the cookie contains session or authentication data                                            |

---

## Finding template for the report

````
**[OWASP-A02-NNN]** - [Short title]

- **Severity:** [level + icon]
- **Confidence:** 🔵 High / 🟣 Medium / ⚪ Low `[MANUAL VERIFICATION REQUIRED if Low]`
- **Remediation effort:** Low (<1h) / Medium (1-4h) / High (>4h) / Architectural
- **Justification:** [1 sentence, mention whether the finding amplifies another known flaw]
- **Sub-type:** A02.X - [sub-type name]
- **Location:** [file:line / endpoint / cloud resource / server configuration]
- **Description:** [explanation of the mechanism]
- **Potential impact:** [what an attacker can do or facilitate]
- **Evidence / Vulnerable example:**
  ```[language/format]
  // audited excerpt, secrets replaced with [MASKED SECRET]
````

- **Recommendation:** [concrete action]
- **Remediation example:**
  ```[language/format]
  // fixed version
  ```
- **References:** [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) | [OWASP A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) (if applicable)

```

> Note: OWASP renumbered Security Misconfiguration as A05 in the 2021 Top 10. In the 2025 framework used by this orchestrator, it is A02; the official OWASP URL remains that of the historical A05 sheet, which is the same category.

---

## Limitations of static analysis for A02

A02 is the category most dependent on the runtime context. Some flaws can only be detected dynamically:

- **HTTP headers**: only a test against the deployed application confirms their presence and effective value. A purely static audit of the Nginx configuration may miss an upstream reverse proxy that overwrites them.
- **Cloud permissions**: requires access to the cloud provider's console / API, not just the Terraform code (which may be out of sync with reality).
- **Exposed default components**: requires scanning the deployed application to enumerate paths.
- **Source maps in production**: requires an HTTP request to the production CDN/server.
- **Configuration drift over time**: by definition not detectable at a single point in time, detectable only through recurring audits.

Mention these limitations in the "Limitations" section of the report when relevant, and suggest dynamic checks the user can run (with explicit validation, in accordance with the orchestrator's protocol).
```
