# OWASP Security Audit

A **Claude Code** plugin that performs a complete application security audit based on the **OWASP Top 10 (2025)**. It orchestrates 10 category reference guides (one per OWASP category) and produces a structured, actionable vulnerability report prioritized by severity and remediation effort.

This plugin doesn't just apply a generic checklist: it detects the technical stack of the audited project, adapts its detection patterns to the language/framework actually in use, distinguishes server-side code from client-side code (SSR vs CSR), and never runs a dynamic verification command without the user's explicit approval.

## When this plugin triggers

The main skill activates automatically as soon as the conversation mentions: security audit, OWASP analysis, security code review, application vulnerabilities, application pentest, API security, hardening, or terms such as SQL injection, XSS, CSRF, weak authentication, secrets in code, sensitive data exposure, SSRF, access control.

It can also be invoked explicitly (see [Usage](#usage)).

## How it works

The audit runs through 5 steps:

### 1. Context gathering

The skill asks **at most 4 targeted questions** if the provided context is insufficient (nature of the target, language/framework, scope: A01 through A10 or specific categories, desired report level plus output language), without ever blocking the analysis if the context already provided is sufficient.

### 2. Technical stack detection

Before any analysis, the skill identifies the language(s), framework(s), ORM, presence of GraphQL, an integrated LLM, etc. via targeted searches (`grep`/`find`), in order to prioritize relevant patterns and avoid false positives.

Particular attention is paid to JS frameworks (React, Vue, Angular, Next.js, Nuxt.js): the skill determines whether the code runs as **pure CSR** (SPA, only DOM XSS flaws and client-side secrets apply) or **SSR/hybrid** (Next.js API routes, Server Actions, Nuxt `defineEventHandler`, Angular Universal; the code must then be audited like standard backend code: injection, SSRF, access control).

A stack-to-priority-patterns matrix then guides the analysis (e.g. Node.js+Mongo → NoSQL injection, PHP+MySQL → SQL injection, JWT/OAuth → token validation, file upload → SSRF via SVG, etc.).

### 3. Quick triage

Before the category-by-category analysis, 10 high-impact patterns are checked first (SQL injection via concatenation, hardcoded secrets, IDOR, JWT decoded without verification, SSRF, unsafe deserialization, debug mode in production, disabled TLS, mass assignment...). These patterns are high-yield starting points for typical critical findings.

### 4. Execution environment detection

Before any **runtime** check (`npm`, `node`, `pip`, `php`, etc.), the skill resolves an **Execution Context**:

- Classifies commands as **static** (host workspace), **runtime** (chosen context only), or **infra** (Docker/Podman/nerdctl CLI on the host)
- Detects whether it is already in a container, whether the project is dockerized (`Dockerfile`, Compose, `.devcontainer`), and which container CLI is available
- If containers are stopped: **asks** whether to start them or to run checks on the host
- Selects the app service automatically when possible, or asks when several candidates exist
- On host fallback for a dockerized project: compares host vs declared image versions, warns on mismatch, and records it in the **audit report** Limitations section (when that situation applies)
- **Never** runs a runtime command without announcing it, specifying context (`exec_prefix`, working directory), and getting explicit user validation

The resolved Execution Context is passed to every category sub-agent on large codebases so parallel analysis cannot bypass it.

### 5. Analysis by category

Each OWASP category has a dedicated reference guide (see table below), loaded on demand. For small codebases (< 50 files), the analysis is sequential; beyond that, one sub-agent is dispatched per OWASP category in parallel, and the results are then aggregated and deduplicated.

Each finding is classified according to:

- **Severity**: 🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low / ℹ️ Informational
- **Confidence**: 🔵 High / 🟣 Medium / ⚪ Low (`[MANUAL VERIFICATION REQUIRED]`)
- **Remediation effort**: Low (< 1h) / Medium (1-4h) / High (> 4h) / Architectural

## Categories covered (OWASP Top 10 - 2025)

| #   | Category                               | Reference                                                  |
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

Each reference file documents: the category definition, attack-surface prerequisites (real exploitability), detection methodologies, category-specific sub-patterns, associated CWEs, and the finding naming format (`OWASP-A0X-NNN`).

## Report produced

The final report includes:

- An **executive summary** with an overall risk score
- A **summary table** of vulnerabilities by severity
- The **detail per category** (A01 to A10), with for each finding: justified severity, confidence level, remediation effort, attack surface, precise location, description, potential impact, vulnerable code example (secrets always masked), recommendation, remediation example, and CWE/OWASP references
- A **Quick Wins** section: critical/high findings with low effort, to fix first
- A **prioritized remediation plan**
- A **coverage table** (categories analyzed vs out of scope)
- An explicit **Limitations** section covering what could not be assessed

The report can be produced in **English (default), French, or Spanish**, at three levels of detail: executive, technical, or exhaustive.

## Guaranteed behavior rules

- No vulnerability is ever invented: insufficient context → category marked "Not assessable"
- Every severity level is justified in one sentence
- Detected secrets are always masked (`[SECRET MASKED]`)
- A dangerous pattern not reachable from an untrusted input is downgraded by at least one severity level
- Findings duplicated across categories (e.g. hardcoded secret → A02 + A04) are attached to the most relevant category with a cross-reference
- Test code (`*.test.*`, `*.spec.*`, `__tests__/`, `fixtures/`) is excluded from the production scope or flagged as Informational

## Installation

This repository is both a plugin and its own Claude Code marketplace.

```
/plugin marketplace add ayman-benmada/owasp-security-audit
/plugin install owasp-security-audit@owasp-security-audit-marketplace
```

## Usage

Once the plugin is enabled, Claude can invoke the skill automatically as soon as a security audit request is detected in the conversation, or it can be invoked explicitly:

```
/owasp-security-audit:security-audit
```

Example request:

> Run a complete security audit of this Node.js/Express repository, technical level, report in English.

## Repository structure

```
.claude-plugin/
├── plugin.json                                # Plugin manifest
└── marketplace.json                           # Marketplace catalog
skills/
└── security-audit/
    ├── SKILL.md                               # Main orchestrator (5 steps)
    └── references/
        ├── A01-broken-access-control.md
        ├── A02-security-misconfiguration.md
        ├── A03-software-supply-chain-failures.md
        ├── A04-cryptographic-failures.md
        ├── A05-injection.md
        ├── A06-insecure-design.md
        ├── A07-authentication-failures.md
        ├── A08-software-or-data-integrity-failures.md
        ├── A09-security-logging-and-alerting-failures.md
        └── A10-mishandling-of-exceptional-conditions.md
```

## Development

To test a local change without going through the marketplace:

```bash
git clone git@github.com:ayman-benmada/owasp-security-audit.git
claude --plugin-dir ./owasp-security-audit
```

## Limitations

- Analysis is primarily **static**: optional runtime checks are proposed only with the user's explicit approval (never automated DAST)
- The depth of the analysis depends on the context provided (code excerpt vs. full codebase); any limitation is stated in the report's "Limitations" section
- Does not replace a tooled penetration test (automated SAST/DAST, fuzzing) or a review by a certified pentester on a high-stakes scope

## Author

Ayman BENMADA
