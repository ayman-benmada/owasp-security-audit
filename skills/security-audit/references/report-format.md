# Security audit report format

Use this reference after the review. Adapt detail to the user's requested audience and language; retain every required evidence field in technical findings.

## Header and summary

State date, exact scope, OWASP Top 10:2025, static or approved-runtime methods, and execution context. Summarize the main risks and the areas that could not be assessed. Count findings by severity and confidence separately. An overall risk rating must not imply that unassessed categories are clean.

## Findings

Group findings by category. Use IDs `OWASP-A0X-NNN`, restarting at 001 in each category. Each finding contains:

- Short title and specific, verified CWE when available.
- Severity (Critical, High, Medium, Low, or Informational) and one-sentence impact/exploitability justification.
- Confidence (High, Medium, or Low) and what was verified or remains unknown. Mark Low-confidence leads `[MANUAL VERIFICATION REQUIRED]`.
- Exact `file:line`, endpoint, or configuration key; a minimal excerpt with secrets replaced by `[SECRET MASKED]`.
- Attacker-controlled entry point, reachable path to the sink or exposed configuration, and why visible controls do not block it.
- Concrete impact, a fix transposed to the actual stack, and manual verification steps when the evidence is incomplete.
- Direct links to the owning OWASP 2025 category and the specific MITRE CWE. Cite relevant OWASP Cheat Sheets for remediation.

Do not invent a code excerpt or an exploit path to fill the template. A finding can omit a field only when the input is architecture rather than code, with that limit explained.

## Coverage and plan

For each requested category, say `assessed`, `partially assessed`, or `not assessable` and why. `Assessed` means the provided scope was reviewed, never a guarantee of absence. List quick wins only when they correspond to evidence-backed High or Critical findings with low or moderate remediation effort. Prioritize other fixes by concrete risk and dependencies. Finish with limitations such as missing deployed configuration, business rules, vulnerability data, or runtime confirmation.
