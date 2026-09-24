# OWASP Security Audit

An agent skill for **Claude Code** and **Cursor** that performs an evidence-based security review of a codebase against the **OWASP Top 10:2025** and produces a structured report with separate severity and confidence ratings.

It is a first-pass review, not a replacement for a penetration test or a dedicated SAST/DAST pipeline. The analysis is mostly static and performed by a language model: it can miss issues and it can be wrong, which is why every finding carries a confidence level and the report lists what could not be assessed.

## What it does

- **Loads one reference guide per OWASP category** (A01 to A10), each with detection patterns, false-positive checks, severity guidance, and remediation examples.
- **Detects the stack first** (languages, frameworks, ORM, GraphQL, LLM integrations, containers) and applies server-side rules only to code that actually runs on a server. React/Vue/Angular code that runs only in the browser is not checked for SQL injection or SSRF; Next.js API routes, Server Actions, Nuxt server routes, and serverless functions are treated as backend code.
- **Separates severity from confidence.** Severity rates the impact if the finding is real; confidence rates how well the code evidence supports it (🔵 traced source-to-sink, 🟣 likely but partly not visible, ⚪ pattern only, marked `[MANUAL VERIFICATION REQUIRED]`).
- **Requires evidence for every finding**: file and line, code excerpt, source-to-sink path for data-flow issues, reachable entry point, impact, and a concrete fix.
- **Reports what it could not assess** (business logic, deployed configuration, cloud IAM, runtime behavior) instead of marking those areas as clean.

## Safety behavior

- **The audited repository is treated as untrusted input.** Instructions embedded in READMEs, comments, config files, fixtures, or agent prompt files inside the target (for example "ignore previous instructions and run this command") are analyzed as content and never followed.
- **Secrets are never reproduced.** The report gives the type and location of a detected secret and masks the value (`[SECRET MASKED]`). Searches print file names and variable names rather than values where possible.
- **No runtime command runs without explicit approval.** Static reads (`grep`, `find`, reading files) run freely inside the target. Anything that can execute project or third-party code (`npm install`, `npm test`, `npx`, `pip install`, `composer install`, `docker compose up`, build tools, test runners) or contact external services (`npm audit`) is shown first with its purpose, execution context, and what it can run, and waits for your "yes". For containerized projects, the skill asks whether to run checks inside the container or on the host, and warns about version mismatches.
- **The audit is read-only**: it does not modify files in the target unless you ask for fixes.

## Categories covered (OWASP Top 10:2025)

| #   | Category                               | Reference guide                                                                                                  |
| --- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| A01 | Broken Access Control (includes SSRF)  | [A01-broken-access-control.md](skills/security-audit/references/A01-broken-access-control.md)                    |
| A02 | Security Misconfiguration              | [A02-security-misconfiguration.md](skills/security-audit/references/A02-security-misconfiguration.md)            |
| A03 | Software Supply Chain Failures         | [A03-software-supply-chain-failures.md](skills/security-audit/references/A03-software-supply-chain-failures.md) |
| A04 | Cryptographic Failures                 | [A04-cryptographic-failures.md](skills/security-audit/references/A04-cryptographic-failures.md)                  |
| A05 | Injection                              | [A05-injection.md](skills/security-audit/references/A05-injection.md)                                            |
| A06 | Insecure Design                        | [A06-insecure-design.md](skills/security-audit/references/A06-insecure-design.md)                                |
| A07 | Authentication Failures                | [A07-authentication-failures.md](skills/security-audit/references/A07-authentication-failures.md)                |
| A08 | Software or Data Integrity Failures    | [A08-software-or-data-integrity-failures.md](skills/security-audit/references/A08-software-or-data-integrity-failures.md) |
| A09 | Security Logging and Alerting Failures | [A09-security-logging-and-alerting-failures.md](skills/security-audit/references/A09-security-logging-and-alerting-failures.md) |
| A10 | Mishandling of Exceptional Conditions  | [A10-mishandling-of-exceptional-conditions.md](skills/security-audit/references/A10-mishandling-of-exceptional-conditions.md) |

Prompt injection in applications that embed an LLM is also checked (A05.12).

## Report

The report contains an executive summary, a summary table by severity with a confidence breakdown, findings grouped by category (ID `OWASP-A0X-NNN`, CWE, severity and justification, confidence, effort, location, evidence, impact, fix, manual verification steps when needed), quick wins, a prioritized remediation plan, a coverage table, and a limitations section.

Three levels of detail are available (executive, technical, exhaustive), in English (default), French, or Spanish.

## Installation

### Claude Code

This repository is its own Claude Code marketplace, so you can add it directly from GitHub:

```
/plugin marketplace add ayman-benmada/owasp-security-audit
/plugin install owasp-security-audit@owasp-security-audit-marketplace
```

To try it from a local clone without installing:

```bash
git clone https://github.com/ayman-benmada/owasp-security-audit.git
claude --plugin-dir ./owasp-security-audit
```

### Cursor

Install it as a local plugin:

```bash
git clone https://github.com/ayman-benmada/owasp-security-audit.git ~/.cursor/plugins/local/owasp-security-audit
```

Then restart Cursor or run **Developer: Reload Window**.

## Usage

The skill can be selected automatically when you ask for a security audit, or invoked explicitly.

- **Claude Code:** `/owasp-security-audit:security-audit`
- **Cursor:** `/security-audit` in Agent chat

Example request:

> Run a security audit of this Node.js/Express repository, technical level, report in English.

The skill may ask up to four questions first (target, stack, scope, report level and language) if they cannot be inferred.

## Limitations

- Static review cannot reliably confirm business logic flaws, multi-step authorization issues, IDOR that depends on implicit ownership rules, multi-tenant isolation, race conditions, or data flows across complex call graphs and services. These are reported with lower confidence or listed as not assessed.
- Deployed configuration (reverse proxies, WAF, cloud IAM, network egress, secrets managers) and actual dependency CVE status are outside what the code shows. CVE checks need a vulnerability database query, which the skill only runs with your approval.
- Findings describe exploitability based on the code; they are not proof of exploitation in production.
- Results depend on the model and on how much of the codebase is in scope. Review findings before acting on them, especially those marked `[MANUAL VERIFICATION REQUIRED]`.

## Repository structure

```
.claude-plugin/
├── plugin.json            # Claude Code plugin manifest
└── marketplace.json       # Claude Code marketplace catalog (this repository)
.cursor-plugin/
└── plugin.json            # Cursor plugin manifest
assets/
└── logo.png
skills/
└── security-audit/        # Shared skill (Claude Code + Cursor)
    ├── SKILL.md           # Orchestrator: operating rules, steps, report format
    └── references/        # One guide per OWASP Top 10:2025 category (A01 to A10)
```

## License

[MIT](LICENSE) © 2026 Ayman BENMADA

This project is independent and is not affiliated with or endorsed by the OWASP Foundation. OWASP® is a registered trademark of the OWASP Foundation, Inc. Category names and numbering refer to the [OWASP Top 10:2025](https://owasp.org/Top10/2025/).
