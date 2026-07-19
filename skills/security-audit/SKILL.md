---
name: security-audit
description: >
  Performs a complete application security analysis based on the OWASP Top 10 (2025).
  Use this skill whenever the user mentions: security audit, OWASP analysis,
  security code review, application vulnerabilities, application pentest, security review,
  security flaw, API security, code verification, hardening, or asks to
  verify the security of code, an architecture, or a configuration.
  Also trigger for terms such as: SQL injection, XSS, CSRF, weak authentication,
  secrets in code, sensitive data exposure, access control, SSRF.
  This skill orchestrates 10 specialized sub-skills and produces a structured, actionable report.
---

# OWASP Security Audit - Main Skill

This skill orchestrates the application security analysis according to the **OWASP Top 10 (2025)**.
It coordinates 10 specialized sub-skills and produces a structured vulnerability report.

---

## Step 1 - Context Gathering

Before any analysis, identify the context available. If the user has provided only limited information, ask **at most 4 targeted questions** before starting, do not block the analysis if the context is sufficient. The report level and language can be combined into a single question.

**Information to collect:**

- Nature of the target: source code / architecture / configuration / functional description
- Language(s) and framework(s) used
- Desired scope: complete analysis (A01 to A10) or specific category/categories
- Desired report level: executive (summary) / technical (detailed) / exhaustive (with complete remediation)
- **Report language**: ask for the desired language (default: **English**). Options: English, French, Spanish. Store the choice and apply it to the entire report (Step 5), including the Docker validation block (Step 2).

> If the context is partial, perform the analysis on what is visible and flag the limitations in the "Limitations" section.

---

## Step 1.5 - Technical Stack Detection

Identify the stack before analyzing in order to **prioritize the most relevant patterns** and avoid false positives caused by incorrect context.

### Signals to detect

```bash
# Identify the main language(s)
find . -type f \( -name "*.php" -o -name "*.py" -o -name "*.java" -o -name "*.go" -o -name "*.ts" -o -name "*.js" -o -name "*.rb" \) | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -10

# Node.js / TypeScript
grep -rn "mongoose\|prisma\|sequelize\|typeorm\|redis" --include="*.{js,ts}" -l 2>/dev/null
grep -rn "graphql\|apollo\|nexus\|pothos" --include="*.{js,ts}" -l 2>/dev/null
grep -rn "openai\|anthropic\|langchain\|mistral\|ollama" --include="*.{js,ts}" -l 2>/dev/null
grep -rn "fetch\|axios\|got\|node-fetch" --include="*.{js,ts}" -l 2>/dev/null

# PHP / Laravel / Symfony
grep -rn "Illuminate\|Symfony\|Laravel\|Doctrine\|PDO\|mysqli" --include="*.php" -l 2>/dev/null
grep -rn "unserialize\|eval\s*(\|system\s*(\|exec\s*(" --include="*.php" -l 2>/dev/null

# Python / Django / Flask / FastAPI
grep -rn "django\|flask\|fastapi\|sqlalchemy\|pymysql\|psycopg" --include="*.py" -l 2>/dev/null
grep -rn "pickle\|subprocess\|os\.system\|eval\s*(" --include="*.py" -l 2>/dev/null

# Java / Spring
grep -rn "springframework\|hibernate\|jpa\|jdbc" --include="*.java" -l 2>/dev/null
grep -rn "ObjectInputStream\|Runtime\.exec\|ProcessBuilder" --include="*.java" -l 2>/dev/null

# Go
grep -rn "database/sql\|gorm\|gin\|echo\|fiber" --include="*.go" -l 2>/dev/null
grep -rn "exec\.Command\|os/exec" --include="*.go" -l 2>/dev/null

# Frontend JS frameworks - React / Vue / Angular / Next.js / Nuxt
grep -E '"(react|vue|@angular/core|next|nuxt|@nuxtjs)' package.json 2>/dev/null | head -10

# Next.js - detect the presence of server code
ls pages/api 2>/dev/null && echo "NEXTJS_PAGES_API_ROUTES"
ls app/api 2>/dev/null && echo "NEXTJS_APP_API_ROUTES"
grep -rln "getServerSideProps\|getStaticProps\|'use server'\|server-only" --include="*.{js,jsx,ts,tsx}" 2>/dev/null | head -10
grep -rn "NEXT_PUBLIC_" .env* 2>/dev/null | grep -iE "secret|key|token|password|api" | head -10

# Nuxt.js - detect server routes
ls server/api server/routes 2>/dev/null | head -5
grep -rln "defineEventHandler\|useServerApi\|serverApi" --include="*.{js,ts}" 2>/dev/null | head -5

# Angular - is SSR enabled?
grep -E '"@angular/ssr|@nguniversal' package.json 2>/dev/null

# Secrets exposed client-side (all frameworks)
grep -rn "REACT_APP_\|VUE_APP_\|VITE_\|NEXT_PUBLIC_" .env* 2>/dev/null | grep -iE "secret|key|token|password|api" | head -10
grep -rln "localStorage\.setItem\|sessionStorage\.setItem" --include="*.{js,jsx,ts,tsx}" 2>/dev/null | head -5
```

### Role of JS frameworks: SSR vs CSR

Before analyzing a project using React, Vue, Angular, Next.js, or Nuxt, **determine the execution mode**: it radically changes the attack surface.

| Mode                                                   | Characteristics                                                                                                                                         | What this implies for the audit                                                                                                                                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Pure CSR** (React SPA, Vue SPA, Angular without SSR) | All the code runs in the browser. No server code in the frontend.                                                                                       | Analyze only: DOM XSS (A05.7-9), secrets in the bundle, auth in `localStorage`, cross-origin API calls. Server-side vulnerabilities (SQL injection, SSRF, etc.) do **not** apply to frontend code. |
| **SSR / Hybrid** (Next.js, Nuxt.js, Angular Universal) | Server code and client code coexist. API routes, Server Components, `getServerSideProps`, Server Actions, and `defineEventHandler` run **server-side**. | Analyze **as backend code**: injection (A05.1-13), SSRF (A05.10), access control (A01), server-side secrets. In addition to the CSR client-side risks.                                             |

#### Signals for identifying the role

```
Presence of pages/api/ or app/api/          → Next.js with API routes (genuine server code)
Presence of 'use server' or server-only     → Next.js Server Actions / Server Components
getServerSideProps in the pages             → Server-side rendering with possible access to the DB/env
server/api/ or defineEventHandler           → Nuxt.js with server routes
@angular/ssr in package.json                → Angular Universal (SSR)
Absence of all of the above + React/Vue     → Pure SPA (CSR only)
```

#### Impact on the analysis: what not to do

- **Do not apply injection/SSRF patterns** to React/Vue/Angular code that is **purely CSR**: these vectors do not exist on the browser side
- **Do not ignore Next.js API routes** on the grounds that "it's just React": they are genuine server endpoints to be analyzed like Express
- **Check the `NEXT_PUBLIC_*`, `REACT_APP_*`, `VITE_*` variables**: anything carrying this prefix is **bundled into the client** and potentially accessible to the user

---

### Stack -> priority patterns matrix

| Detected stack                       | Role          | Patterns to prioritize                                                                                                                                                             |
| ------------------------------------ | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Node.js + MongoDB / Mongoose         | Server        | NoSQL injection (A05.11), deserialization (A08.3)                                                                                                                                  |
| PHP + MySQL / MariaDB                | Server        | SQL injection (A05.1-3), `unserialize()` (A08.3)                                                                                                                                   |
| GraphQL (Apollo, Nexus, etc.)        | Server        | GraphQL auth bypass (A01.11), introspection/DoS (A05.12)                                                                                                                           |
| Integrated LLM / AI                  | Server        | Prompt injection (A05.13), tool access (A01)                                                                                                                                       |
| AWS / GCP / Azure                    | Infra         | SSRF -> metadata endpoint (A05.10), cloud permissions (A02.8)                                                                                                                      |
| JWT / OAuth 2.0 / OIDC               | Auth          | JWT validation (A04.6, A07.8), OAuth (A07.11)                                                                                                                                      |
| Configurable webhooks                | Server        | SSRF (A05.10), HMAC signature (A08.4)                                                                                                                                              |
| File upload                          | Server        | Unrestricted upload (A06.6), SSRF via SVG (A05.10)                                                                                                                                 |
| React / Vue / Angular **(pure SPA)** | Client        | DOM XSS (A05.7-9), secrets in bundle (`REACT_APP_`, `VITE_`), JWT in `localStorage` (A07)                                                                                          |
| **Next.js** with API routes / SSR    | Client+Server | Injection in API routes and Server Actions (A05.1-13), SSRF (A05.10), exposed `NEXT_PUBLIC_` secrets (A02.2), Server Components accessing the DB without access verification (A01) |
| **Nuxt.js** (server routes enabled)  | Client+Server | Injection in `defineEventHandler` (A05), SSRF (A05.10), server middleware (A01)                                                                                                    |
| **Angular Universal** (SSR)          | Client+Server | Injection in server-side rendering (A05), server-side XSS via template (A05.8), `TransferState` exposing server data (A02)                                                         |

> If the context is insufficient to identify the stack, note it in "Limitations" and analyze using generic patterns.

---

## Quick Triage - Critical Patterns to Check First

Before the category-by-category analysis, check these high-impact patterns:

| Pattern                             | Category      | Signal in the code                                                       |
| ----------------------------------- | ------------- | ------------------------------------------------------------------------ |
| SQL injection via concatenation     | A05.1         | `"SELECT ... " + var` or `` `SELECT ... ${var}` ``                       |
| Hardcoded secrets                   | A02.2 / A04.5 | `api_key\|secret\|password\s*=\s*["'][^"']+`                             |
| IDOR without ownership verification | A01.1         | `findById(req.params.id)` without a `userId` check                       |
| JWT decoded without verification    | A04.6 / A07.8 | `jwt.decode(` (instead of `jwt.verify(`)                                 |
| SSRF                                | A05.10        | `fetch(req.\|axios.get(req.\|file_get_contents($url)`                    |
| `unserialize()` on external data    | A08.3         | `unserialize($_COOKIE\|$_GET\|$_POST`                                    |
| Debug mode in production            | A02.1         | `APP_DEBUG=true\|NODE_ENV=development` in prod config                    |
| TLS disabled                        | A04.6         | `rejectUnauthorized: false\|verify=False\|CURLOPT_SSL_VERIFYPEER, false` |
| Native Python/Java deserialization  | A08.3         | `pickle.loads(\|ObjectInputStream\|BinaryFormatter`                      |
| Mass assignment                     | A01.5         | `Object.assign(user, req.body)\|fill($request->all())`                   |

> These patterns cover 80% of Critical findings. Identify them first, then analyze the remaining categories.

---

## Step 2 - Detection of the Execution Environment

Before running any verification command, identify the execution context to determine where dynamic tests should be carried out.

### Automatic Detection

Run the following checks to determine the environment:

```bash
# Check whether we are already inside a container
ls /.dockerenv 2>/dev/null && echo "IN_CONTAINER" || cat /proc/1/cgroup 2>/dev/null | grep -qi docker && echo "IN_CONTAINER" || echo "HOST"

# If on the host machine, list active containers
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null
```

### Decision Tree

```
Detected environment?
├── Host machine with Docker available
│   └── → Offer to run the tests inside the targeted container
│         (e.g.: docker exec <container> <command>)
├── Already inside a Docker container
│   └── → Run the tests locally inside the current container
└── Host machine without Docker (native application)
    └── → Run the tests directly on the host machine
```

### Mandatory Validation Rules Before Any Execution

> **Never execute a command without:**
>
> 1. Announcing the command and its purpose
> 2. Specifying the context (host / `docker exec <container_name>`)
> 3. **Requesting explicit validation from the user**
> 4. In case of failure, analyzing the error before reporting it as a finding

**Validation request format to use systematically:**

```
I would like to execute the following command to verify [objective]:
→ Context : [host machine / docker exec <container_name>]
→ Command : `<command>`
→ Reason  : [what this allows to verify, the OWASP category concerned]

Do you confirm execution? (yes / no / modify)
```

---

## Step 3 - Loading the Sub-skills

Each OWASP category has a dedicated sub-skill in `references/`. **Read the corresponding file before analyzing each category.**

| #   | OWASP Category                         | Reference File                                             |
| --- | -------------------------------------- | ---------------------------------------------------------- |
| A01 | Broken Access Control                  | `references/A01-broken-access-control.md`                  |
| A02 | Security Misconfiguration              | `references/A02-security-misconfiguration.md`              |
| A03 | Software Supply Chain Failures         | `references/A03-software-supply-chain-failures.md`         |
| A04 | Cryptographic Failures                 | `references/A04-cryptographic-failures.md`                 |
| A05 | Injection                              | `references/A05-injection.md`                              |
| A06 | Insecure Design                        | `references/A06-insecure-design.md`                        |
| A07 | Authentication Failures                | `references/A07-authentication-failures.md`                |
| A08 | Software or Data Integrity Failures    | `references/A08-software-or-data-integrity-failures.md`    |
| A09 | Security Logging and Alerting Failures | `references/A09-security-logging-and-alerting-failures.md` |
| A10 | Mishandling of Exceptional Conditions  | `references/A10-mishandling-of-exceptional-conditions.md`  |

**Recommended reading order:**

- **Complete analysis** → read all sub-skills sequentially (A01 to A10)
- **Targeted analysis** → read only the relevant sub-skill(s)
- **Quick triage** → read A01, A02, A03 as a priority (the most frequently exploited categories)

### Analysis Orchestration

Announce progress at the start of each category:

> `🔍 [X/10] Analyzing A0X - Category name...`

**Modest-sized codebase (< 50 source files)** → sequential analysis: read the sub-skill, analyze the category, document the findings, then move on to the next one.

**Large codebase (> 50 source files)** → dispatch one sub-agent per OWASP category via the Agent tool:

- Each sub-agent receives: the reference file (`references/A0X-*.md`) + the scope + the quick triage results
- Each sub-agent returns its findings in the OWASP-A0X-NNN format
- Aggregate and deduplicate the findings before producing the report (Step 5)

---

## Step 4 - Analysis by Category

For each OWASP category analyzed:

1. Read the corresponding sub-skill (`references/A0X-*.md`)
2. Apply the detection patterns defined in the sub-skill
3. If a dynamic check is relevant, follow the Step 2 protocol (environment detection + validation)
4. Classify each finding according to the severity grid below
5. Document it according to the report format (Step 5)

### Severity Grid

| Level         | Icon | Criteria                                                                 |
| ------------- | ---- | ------------------------------------------------------------------------ |
| Critical      | 🔴   | Trivial exploitation, direct impact (RCE, database dump, auth bypass)    |
| High          | 🟠   | Likely exploitation, significant impact (unauthorized access, data leak) |
| Medium        | 🟡   | Conditional exploitation, moderate impact (partial privilege escalation) |
| Low           | 🟢   | Difficult exploitation or limited impact (minor information disclosure)  |
| Informational | ℹ️   | Best practice not followed, no direct exploitation vector                |

### Confidence Levels

Assign a confidence level to each finding to distinguish certainties from suspicions:

| Confidence | Icon | Meaning                                                                                 |
| ---------- | ---- | --------------------------------------------------------------------------------------- |
| High       | 🔵   | Vulnerability confirmed statically or dynamically, direct exploitability demonstrated   |
| Medium     | 🟣   | Suspicious pattern identified, exploitability likely but depends on the calling context |
| Low        | ⚪   | Anomaly detected, exploitation uncertain, mark as `[MANUAL VERIFICATION REQUIRED]`      |

### Remediation Effort

Estimate the cost of the fix to help prioritize by ROI:

| Effort        | Meaning                                                               |
| ------------- | --------------------------------------------------------------------- |
| Low           | < 1h: configuration change, adding a parameter, update                |
| Medium        | 1-4h: localized refactoring, adding validation, algorithm replacement |
| High          | > 4h: multi-file refactoring, business flow modification              |
| Architectural | Structural redesign required (weeks): involves design decisions       |

---

## Step 5 - Output Report Format

Produce the following structured report after the analysis. Adapt the verbosity to the requested level.

> **Report language:** write the entire report (titles, descriptions, recommendations, narrative examples) in the language selected in Step 1. If no language was specified, use **English** by default. Technical identifiers (OWASP category names, CWE IDs, function names, commands) remain in English regardless of the language chosen.

---

````
### 📋 OWASP SECURITY AUDIT REPORT

**Date:** [DD/MM/YYYY]
**Scope analyzed:** [short description, e.g.: "Node.js REST API - auth.js and user.controller.js files"]
**Framework reference:** OWASP Top 10 - 2025
**Analysis level:** [Complete / Targeted / Partial (limited context)]

---

#### Executive Summary

[3 to 5 sentences: overall security level, major risks identified, remediation priority.
E.g.: "The analyzed code presents critical vulnerabilities in access control and SQL injection.
Two critical findings require immediate correction before any production deployment.
The overall security level is insufficient for public exposure."]

**Overall risk score:** 🔴 Critical / 🟠 High / 🟡 Moderate / 🟢 Low

---

#### Vulnerability Summary Table

| Severity      | Count |
|---------------|--------|
| 🔴 Critical   | X      |
| 🟠 High       | X      |
| 🟡 Medium     | X      |
| 🟢 Low        | X      |
| ℹ️ Informational | X      |
| **Total**     | **X**  |

---

#### Vulnerability Details by OWASP Category

[Repeat the following block for each category A01 to A10]

---

### [A0X] - [Category Name]

**Status:**
- ✅ Compliant - no vulnerability identified
- ⚠️ Vulnerable - medium or low severity findings
- ❌ Critical - high or critical severity findings
- 🔍 Not assessable - insufficient context (explain why)

#### Findings

[If no vulnerability detected:]
> No vulnerability identified in this category within the analyzed scope.

[For each vulnerability found, use the following block:]

**[OWASP-A0X-NNN]** - [Short, explicit title]

- **Severity:** 🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low / ℹ️ Informational
- **Confidence:** 🔵 High / 🟣 Medium / ⚪ Low `[MANUAL VERIFICATION REQUIRED if Low]`
- **Remediation effort:** Low (<1h) / Medium (1-4h) / High (>4h) / Architectural
- **Severity justification:** [Explain in 1 sentence why this level applies, e.g.: "Critical because exploitable without authentication and allows access to the entire database."]
- **Attack surface:** [Specify whether this code is reachable from an untrusted input, e.g.: "Public endpoint POST /api/users, `id` parameter directly injected"]
- **Location:** [file:line / endpoint / component / function, e.g.: `auth.js:47, validateToken() function`]
- **Description:** [Clear explanation of the vulnerability and its mechanism]
- **Potential impact:** [What an attacker can concretely do, e.g.: "Authentication bypass, access to all user accounts"]
- **Proof / Vulnerable example:**
  ```[language]
  // Vulnerable code or configuration (mask any real secret → [SECRET MASKED])
````

- **Recommendation:** [Concrete, prioritized, and realistic action]
- **Remediation example:**
  ```[language]
  // Corrected code or secured configuration
  ```
- **References:** [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) | [OWASP - Name](https://owasp.org/...) | CVE-XXXX-XXXXX if applicable

---

#### ⚡ Quick Wins - Fast, High-Impact Gains

[List only Critical or High findings with Low or Medium effort, these are the priority fixes by ROI]

| ID            | Title           | Severity | Effort | Timeline  |
| ------------- | --------------- | -------- | ------ | --------- |
| OWASP-A0X-NNN | [Finding title] | 🔴/🟠    | Low    | Immediate |
| OWASP-A0X-NNN | [Finding title] | 🔴/🟠    | Medium | < 1 week  |

> If there are no Quick Wins: nothing to list, all high-impact fixes require high or architectural effort.

---

#### Prioritized Remediation Plan

[List ordered by urgency, list only actions with findings]

| Priority | Action               | Category | Effort        | Recommended Timeline              |
| -------- | -------------------- | -------- | ------------- | --------------------------------- |
| 1        | 🔴 [Critical action] | A0X      | Low           | Immediate (block deployment)      |
| 2        | 🔴 [Critical action] | A0X      | Architectural | Immediate, redesign plan required |
| 3        | 🟠 [High action]     | A0X      | Medium        | < 1 week                          |
| 4        | 🟡 [Medium action]   | A0X      | High          | < 1 month                         |
| 5        | 🟢 [Low action]      | A0X      | Low           | Next iteration                    |

---

#### Audit Coverage Table

| OWASP Category                                    | Analyzed | Findings count |
| ------------------------------------------------- | -------- | -------------- |
| A01:2025 - Broken Access Control                  | ✅ / ⏭️  | X              |
| A02:2025 - Security Misconfiguration              | ✅ / ⏭️  | X              |
| A03:2025 - Software Supply Chain Failures         | ✅ / ⏭️  | X              |
| A04:2025 - Cryptographic Failures                 | ✅ / ⏭️  | X              |
| A05:2025 - Injection                              | ✅ / ⏭️  | X              |
| A06:2025 - Insecure Design                        | ✅ / ⏭️  | X              |
| A07:2025 - Authentication Failures                | ✅ / ⏭️  | X              |
| A08:2025 - Software or Data Integrity Failures    | ✅ / ⏭️  | X              |
| A09:2025 - Security Logging and Alerting Failures | ✅ / ⏭️  | X              |
| A10:2025 - Mishandling of Exceptional Conditions  | ✅ / ⏭️  | X              |

Legend: ✅ Analyzed | ⏭️ Not analyzed (out of scope or insufficient context)

---

#### Limitations and Excluded Scope

[Explicitly mention what could not be assessed, for example:]

- Infrastructure and server configuration not provided → A05 partially assessed
- Dependency files (package.json, pom.xml, etc.) missing → A06 not assessable
- Dynamic tests (DAST) not possible in this context → some stored XSS vectors not statically detectable
- [Other context-specific limitations]

```

---

## Mandatory Behavior Rules

- **The code examples in the sub-skills are illustrative**: the PHP, Nginx, JavaScript, Node.js, etc. snippets serve only to illustrate the *vulnerability pattern*, they do not define the scope of the analysis. Systematically transpose each pattern to the language and framework actually used in the audited project
- **Never invent vulnerabilities**: if the context is insufficient, mark it "Not assessable" with an explanation
- **Always justify the severity**: each level must be justified in one sentence
- **Stay factual and actionable**: each finding must have a concrete and realistic recommendation
- **Mask detected secrets**: never reproduce a token, password, API key, or certificate in plaintext, replace them with `[SECRET MASKED]` and report their presence as a finding
- **Adapt the depth to the context**: a 20-line excerpt is not the same as a complete codebase, calibrate the analysis accordingly
- **No false positives**: distinguish a bad practice (ℹ️ Informational) from an exploitable vulnerability (🟡 to 🔴)
- **Consistent numbering**: finding IDs follow the format `OWASP-A0X-NNN` (e.g.: `OWASP-A03-001`), the NNN numbering restarts at 001 for each category
- **CWE references**: associate the most precise CWE possible with each finding
- **Check the attack surface**: before declaring a finding, confirm that the vulnerable code is reachable from an untrusted input (HTTP parameter, cookie, upload, webhook, etc.). A dangerous pattern in unexposed internal code drops by at least one severity level
- **Deduplicate cross-category findings**: if the same flaw is detectable in several OWASP categories (e.g.: hardcoded secret → A02 + A04), report it in the most relevant category and add a `→ See also [A0X]` mention in the other categories concerned
- **`[MANUAL VERIFICATION REQUIRED]` tag**: if the vulnerability is likely but not certain (partially visible code, runtime-dependent behavior, external dependency), keep the finding with ⚪ Low confidence and this tag rather than silently removing it
- **Exclude test/dev code from the production scope**: a finding in a `*.test.*`, `*.spec.*`, `__tests__/`, `fixtures/` file, or one conditioned on `NODE_ENV=test`, must be noted as ℹ️ Informational or excluded, explicitly state this in "Limitations"
```
