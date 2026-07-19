# A09 - Security Logging and Monitoring Failures

**Reference:** OWASP Top 10 (2025), category A09
**Main associated CWEs:** CWE-117, CWE-223, CWE-532, CWE-778
**Finding format:** `OWASP-A09-NNN`

This file is loaded by the `owasp-security-audit` orchestrator skill when analyzing category A09. It provides the detection patterns, standard fixes, and severity grid specific to security logging and monitoring failures.

---

## Definition

A09 groups together weaknesses related to log collection, event monitoring, and alert generation. The main risk is an **inability to detect, analyze, and respond to a compromise**: in the absence of actionable logs, an intrusion can persist for long periods without being identified.

**Paradox of the category:** the logs themselves constitute an attack surface. Poorly protected, they can expose sensitive data, be altered or forged, serve as an attack vector (log injection leading to XSS in dashboards, unexpected behavior in ingestion pipelines), or allow an attacker to erase their tracks.

Guiding principle: **log relevant security events, without ever exposing sensitive data, in a centralized system separate from the application, with alerts on high-signal events.**

---

## Attack surface: exploitability prerequisites

Before declaring an A09 finding, verify that **the absence of logging or weak monitoring has a real impact on incident detection**. Typical vectors:

- Critical security events (authentications, privilege escalations, access to sensitive data) not tracked
- Logs containing sensitive data exported to insecure third-party systems
- User input included unescaped in logs (log injection)
- Missing alerts on repeated attack attempts (brute force, scanning)

**Cases where the finding should be downgraded or dismissed:**

- The absence of logging concerns **non-sensitive** actions with no security impact (reading public data, static calls)
- The sensitive logs are in a **development environment** configured separately from production
- Log centralization is handled by an **external collection agent** (Datadog, CloudWatch, Elastic) not visible in the application code
- The log injection concerns debug messages **never exported to production**

---

## Detection methodology

### 1. Identify what is logged, and what is not

Review high-security-stakes endpoints and features and check:

- Are authentication attempts (successful **and** failed) tracked?
- Are authorization failures logged?
- Are exceptions caught and logged server-side?
- Do sensitive actions (transfers, role changes, data deletions) have an audit trail?

### 2. Check what is logged, and how

- Is user input interpolated raw into log messages (log injection risk)?
- Does sensitive data (passwords, tokens, sensitive personal data) appear in the logs?
- Does the log format allow for reliable analysis (structured JSON with context, no concatenation)?

### 3. Assess the logging architecture

- Are the logs only local (deletable by an attacker who has compromised the server)?
- Is there a separate centralized system (SIEM, Loki, Graylog, ELK)?
- Are there alert rules for OWASP CRITICAL events?

### 4. Inherent limitations of static analysis for A09

A09 is inherently difficult to assess statically: the absence of logging leaves no trace in the code. Actively look for code paths where no logging is present, and note cases where context is insufficient to draw a conclusion.

---

## Subtypes and detection patterns

---

### A09.1 - Insufficient logging of authentication and authorization events

**CWE-223** - Omission of Security-relevant Information | **CWE-778** - Insufficient Logging

**Pattern:** the application only logs successful logins, or only failures, never both. Authorization failures (attempts to access an unauthorized resource) are not tracked. Without this data, detecting brute force, credential stuffing, or a privilege escalation attempt becomes impossible.

**Detection, look for:**

- Login endpoints without a call to `Log::info()` / `logger.info()` / `console.log()` on failed attempts.
- Authorization middlewares (guards, policies, voters) that reject a request with a 403 without logging the event.
- Password reset, email change, or role change handlers without an audit trail.
- Absence of relevant context fields in existing logs: source IP address, user agent, user identifier, hashed session identifier (never the raw token).

**Events that should always be logged:**

| Event                                | Recommended level |
| ------------------------------------ | ----------------- |
| Successful login attempt             | INFO              |
| Failed login attempt                 | INFO / WARNING    |
| Account lockout                      | WARNING           |
| Authorization failure (403)          | WARNING           |
| Password change                      | INFO              |
| Email or role change                 | INFO / WARNING    |
| Deletion or export of sensitive data | WARNING           |
| Logout                               | INFO              |

**Vulnerable code:**

```php
// No logging of failures - brute force is invisible
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

**Fix: logging both outcomes with context:**

```php
// Successful and failed logins tracked, with relevant context
public function login(Request $request)
{
    $user = User::where('email', $request->email)->first();
    $passwordOk = $user && Hash::check($request->password, $user->password);

    if (!$user || !$passwordOk) {
        Log::info('authn_login_failure', [
            'email'      => $request->email,
            'source_ip'  => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);
        return response()->json(['error' => 'Invalid user ID or password.'], 401);
    }

    Log::info('authn_login_success', [
        'user_id'    => $user->id,
        'source_ip'  => $request->ip(),
        'user_agent' => $request->userAgent(),
    ]);
    // ... authentication
}
```

**Typical severity:** 🟡 Medium to 🟠 High (depending on the application's sensitivity and the absence of other detection mechanisms).

---

### A09.2 - Insertion of sensitive data into logs

**CWE-532** - Insertion of Sensitive Information into Log File

**Pattern:** the application logs full HTTP requests, payloads, tokens, passwords, or serialized user objects without filtering. Log files become a target for an attacker looking to extract credentials or personal data.

**Detection, look for:**

- Logging of `$request->all()`, `req.body`, `request.data`, which may contain passwords, tokens, or personal data.
- JWT tokens, session identifiers, API keys in the logs.
- Banking data, social security numbers, health data in the logs.
- Stack traces containing file paths or internal variables returned to the client (see A02.3): these are fine in server logs but must never reach the client.

**Data that should never be logged in clear text:**

| Category       | Examples                            | Alternative                       |
| -------------- | ----------------------------------- | --------------------------------- |
| Credentials    | Passwords, PIN codes                | Never log                         |
| Session tokens | JWT, session ID                     | Log the SHA-256 hash of the token |
| Secrets        | API keys, encryption keys           | Never log                         |
| Banking data   | Card numbers, IBAN                  | Mask (`**** **** **** 1234`)      |
| Health data    | Diagnoses, treatments               | Exclude or pseudonymize           |
| Personal data  | Email, phone (depending on context) | Assess according to data policy   |

**Vulnerable code:**

```javascript
// Logging the full body - may contain a password
app.post("/login", (req, res) => {
  logger.info("Login attempt", { body: req.body }); // password: "s3cr3t" in the logs
  // ...
});
```

**Fix: explicit selection of fields to log:**

```javascript
// Only non-sensitive fields are logged
app.post("/login", (req, res) => {
  logger.info("authn_login_attempt", {
    email: req.body.email, // OK - non-secret identifier
    source_ip: req.ip,
    user_agent: req.get("user-agent"),
    // password: never in the logs
  });
  // ...
});
```

**Special case of session identifiers:** they can be logged provided they are hashed, which allows correlating events from the same session without exposing the original token.

```javascript
// Hash the session token for correlation without exposure
const crypto = require("crypto");
const sessionHash = crypto
  .createHash("sha256")
  .update(sessionToken)
  .digest("hex")
  .slice(0, 16);
logger.info("session_event", { session_hash: sessionHash });
```

**Typical severity:** 🟠 High (credentials or tokens in the logs) to 🔴 Critical (health or banking data exposed in accessible logs).

---

### A09.3 - Log injection

**CWE-117** - Improper Output Neutralization for Logs

**Pattern:** user input is interpolated raw into a log message. An attacker can insert line-break characters (`\r`, `\n`) to fabricate false log entries, for example a fake successful login under an administrator's identity. If the logs are displayed in a web dashboard without HTML encoding, this can also trigger an XSS.

**Detection, look for:**

```php
// Direct interpolation in the message - log injection possible
Log::info("Login attempt: {$username}");
// Payload: "admin\n[2024-01-01 00:00:00] INFO: authn_login_success {\"user_id\":1}"
// -> False log line injected into the file
```

```javascript
// Concatenation in the message - same risk
logger.info("Login attempt: " + req.body.username);
```

**Fix: data in structured context, static message:**

```php
// Laravel/Monolog - the context is serialized as JSON (control characters escaped)
Log::info('authn_login_attempt', [
    'username'   => $this->safeLogValue($request->input('username', '')),
    'source_ip'  => $request->ip(),
    'user_agent' => $request->userAgent(),
]);

// Defense in depth: encoding of control characters
private function safeLogValue(?string $v): string
{
    // Escapes rather than removes - preserves forensic information
    $cleaned = preg_replace('/[\x00-\x1F\x7F]/u', '', $v ?? '');
    return mb_substr($cleaned, 0, 256); // limits the size
}
```

```javascript
// Node.js - structured object, never concatenation in the message
logger.info("authn_login_attempt", {
  username: sanitizeLogValue(req.body.username),
  source_ip: req.ip,
});

function sanitizeLogValue(value) {
  if (typeof value !== "string") return String(value);
  // Escapes control characters (preserves the info, avoids injection)
  return value
    .replace(
      /[\x00-\x1F\x7F]/g,
      (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`,
    )
    .slice(0, 256);
}
```

**Important note:** prefer **escaping** rather than **removing** suspicious characters. Removal erases information potentially useful for forensic analysis (an injection attempt is itself a signal worth preserving).

**Typical severity:** 🟡 Medium (log forgery) to 🟠 High (if the logs feed a web dashboard without encoding, leading to XSS, or if the forgery could mislead an investigation).

---

### A09.4 - Uncaught exceptions

**CWE-390** - Detection of Error Condition Without Action | **CWE-778** - Insufficient Logging

**Pattern:** uncaught exceptions leave the application blind to exploits that trigger internal errors. Without a `try/catch` with logging, the system does not know a problem occurred and cannot record it.

**Detection, look for:**

- Critical functions (transfers, payments, permission changes) without a `try/catch` block.
- Global error handlers that log the error but return the stack trace to the client (see A02.3).
- Global error handlers that do not call any logger.
- Unresolved promises without `.catch()` in JavaScript (silent errors).

**Vulnerable code:**

```javascript
// No error handling - silent exception
app.post("/transfer", async (req, res) => {
  const result = await processTransfer(req.body); // may throw an exception
  res.json({ ok: true, result });
  // If processTransfer() throws: the process crashes or returns a 500 without logging
});
```

**Fix: catch with server-side logging, generic response to the client:**

```php
// Laravel - complete pattern: server log + generic client response
public function transfer(Request $request)
{
    $txId = (string) Str::uuid();
    $data = $request->validate([/* ... */]);

    try {
        DB::transaction(function () use ($data) {
            Account::where('id', $data['from_account'])->decrement('balance', $data['amount']);
            Account::where('id', $data['to_account'])->increment('balance', $data['amount']);
        });

        Log::info('transfer_success', [
            'tx_id'  => $txId,
            'from'   => $data['from_account'],
            'to'     => $data['to_account'],
            'amount' => $data['amount'],
            'userid' => $request->user()->id,
        ]);

        return response()->json(['ok' => true, 'tx_id' => $txId]);

    } catch (\Throwable $e) {
        Log::error('transfer_failure', [
            'tx_id'  => $txId,
            'from'   => $data['from_account'],
            'to'     => $data['to_account'],
            'amount' => $data['amount'],
            'userid' => $request->user()->id,
            'error'  => $e->getMessage(),
            'trace'  => $e->getTraceAsString(), // stack trace in server logs only
        ]);

        return response()->json([
            'error' => 'Transaction failed', // generic message - no stack trace to the client
            'tx_id' => $txId,               // allows the user to reference the incident
        ], 500);
    }
}
```

**Typical severity:** 🟡 Medium (uncaught exceptions on non-critical operations) to 🟠 High (financial or security operations without error capture).

---

### A09.5 - Lack of log centralization and integrity

**CWE-778** - Insufficient Logging

**Pattern:** logs are kept only on the application machine. In the event of a compromise, an attacker can alter or delete them, negating any capacity for investigation and incident response.

**Detection, look for:**

- Logging configuration pointing only to local files (`storage/logs/`, `/var/log/app/`) without forwarding to an external system.
- Absence of SIEM, Loki, Graylog, ELK, or equivalent configuration in the provided configuration files.
- Database account used for writing logs having `UPDATE` or `DELETE` rights on the log table (an attacker who has compromised the application can erase their tracks).
- Absence of a secure log rotation and archiving mechanism.

**Recommended architecture:**

- Secure transmission to a separate, dedicated system (SIEM, centralized logging stack).
- Read-only support as early as possible for archived logs.
- Dedicated account for writing logs to the database: `INSERT` rights only, no `UPDATE` or `DELETE`.
- All access to logs tracked, and even subject to prior approval depending on sensitivity.

**Typical severity:** 🟡 Medium to 🟠 High (depending on the application's sensitivity and the absence of other post-compromise detection mechanisms).

---

### A09.6 - Lack of alerting and thresholds on critical events

**CWE-778** - Insufficient Logging

**Pattern:** logs accumulate without correlation rules or alert thresholds. An intrusion can unfold over weeks without triggering a notification, because nobody reads the logs.

**Detection, look for:**

- Absence of alert configuration in the provided monitoring tools.
- Logs produced but no documented ingestion or correlation pipeline.
- OWASP CRITICAL events not covered by alert rules.

**OWASP events classified as CRITICAL: must trigger an immediate alert:**

| OWASP Event                  | Description                                        | Signal                                 |
| ---------------------------- | -------------------------------------------------- | -------------------------------------- |
| `authn_token_reuse`          | Reuse of a revoked token                           | Replay of a compromised session or JWT |
| `authz_fail`                 | Attempt to access an unauthorized resource         | Privilege escalation, IDOR             |
| `authn_impossible_travel`    | Login from two geographically incompatible regions | Compromised account or suspicious VPN  |
| `session_use_after_expire`   | Use of an expired session                          | Token not invalidated or replay        |
| `malicious_direct_reference` | IDOR detected                                      | Access to another user's resource      |
| `malicious_extraneous`       | Unexpected field in the request                    | Mass assignment or fuzzing attempt     |

**Typical severity:** 🟡 Medium (absence of alerting on a low-exposure app) to 🟠 High (absence of alerting on a publicly exposed app with sensitive data).

---

## Cross-cutting remediation rules

1. **Log both outcomes**: successful AND failed authentication attempts, always with context (IP, user agent, identifier).
2. **Never sensitive data in clear text**: no password, token, key, or health/banking data in the logs. Hash session identifiers for correlation.
3. **Static message, data in structured context**: `Log::info('event_name', ['key' => $value])` rather than `Log::info("event: {$value}")`. The JSON context automatically escapes control characters.
4. **Escape rather than remove**: suspicious characters retain their forensic value in encoded form.
5. **Limit the size of logged values**: prevent an attacker from filling up the disk by sending excessively long values.
6. **Systematic try/catch on critical operations**: with server-side error logging and a generic response to the client.
7. **Centralize logs on a separate system**: separate from the application, read-only after writing, access tracked.
8. **Dedicated account for database logs**: `INSERT` rights only, no `UPDATE` or `DELETE`.
9. **Alerts on OWASP CRITICAL events**: `authn_token_reuse`, `authz_fail`, `authn_impossible_travel`, `session_use_after_expire`, `malicious_direct_reference`, `malicious_extraneous`.
10. **Never return the stack trace to the client**: keep it in server logs only, with a `tx_id` in the response to allow correlation.

---

## Severity classification help

| Finding criteria                                                                                                                                                                                   | Severity         |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| Credentials, tokens, or health/banking data in clear text in accessible logs; log injection allowing XSS in an administration dashboard                                                            | 🔴 Critical      |
| Total absence of logging on an app exposed with sensitive data; logs only local on a critical app without SIEM; sensitive personal data in the logs                                                | 🟠 High          |
| Partial logging (successes without failures or vice versa); absence of alerting on OWASP CRITICAL events; uncaught exceptions on financial operations; log injection without an impacted dashboard | 🟡 Medium        |
| Absence of alerting on a non-critical app; local logs on a low-sensitivity app; unstructured log format (plain text rather than JSON)                                                              | 🟢 Low           |
| Absence of a dedicated INSERT-only account for database logs (with no other gap); non-automated log rotation                                                                                       | ℹ️ Informational |

---

## Frequent false positives - A09

| Detected pattern                            | Reason for the false positive                                                          | How to verify                                                                                                    |
| ------------------------------------------- | -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `console.log(user)` or `logger.debug(data)` | May be conditioned on `NODE_ENV === 'development'` and absent in production            | Check whether the log is under a level condition (`debug` vs `info/warn/error`) or an environment condition      |
| Absence of logging on an action             | May not be a security event: not all actions need to be logged                         | Assess whether the action is listed in the OWASP checklist of critical events                                    |
| Sensitive data in the logs                  | May be masked by a logger serializer (e.g. `redact` in pino, Monolog filtering)        | Check the logger configuration for redaction rules                                                               |
| No alert visible in the code                | Alerts may be configured in a SIEM, an external monitoring system, or CloudWatch rules | Check whether an external monitoring tool is integrated                                                          |
| Exception swallowed without logging         | May be intentional for non-security business errors (e.g. duplicate attempt)           | Assess whether the exception has a security impact: business validation errors do not all require a security log |

---

## Finding template for the report

````
**[OWASP-A09-NNN]** - [Short title]

- **Severity:** [level + icon]
- **Confidence:** 🔵 High / 🟣 Medium / ⚪ Low `[MANUAL VERIFICATION REQUIRED if Low]`
- **Remediation effort:** Low (<1h) / Medium (1-4h) / High (>4h) / Architectural
- **Justification:** [1 sentence, specifying the impact on detection or investigation capability]
- **Subtype:** A09.X - [subtype name]
- **Location:** [file:line / endpoint / logging configuration]
- **Description:** [explanation of the failure and its operational impact]
- **Potential impact:** [inability to detect an intrusion, exposure of sensitive data, log forgery]
- **Evidence / Vulnerable example:**
  ```[language]
  // audited excerpt
````

- **Recommendation:** [concrete action]
- **Remediation example:**
  ```[language]
  // fixed version
  ```
- **References:** [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) | [OWASP A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

```

> Note: Security Logging and Monitoring Failures corresponds to A09 in the OWASP Top 10 2021. In this orchestrator's 2025 reference framework, it is also A09.

---

## Limitations of static analysis for A09

A09 is the most difficult category to assess statically: the absence of logging leaves no trace in the code.

- **Event coverage**: detecting the presence of logger calls is possible, but confirming that all critical paths are covered requires an exhaustive analysis of code flows, including error paths.
- **Effective centralization**: a logger's configuration may point to a local file in the code, but be overridden by an environment variable or a deployment configuration that is not provided.
- **Alerting**: alert rules live in the SIEM or the monitoring tool, rarely in the application code, and are not assessable from the code alone.
- **Actual log content**: what actually appears in the logs in production depends on middlewares, serializers, and log level configurations (`LOG_LEVEL=error` may filter out relevant `info` events), and is not verifiable statically.
- **Exploitable log injection**: detecting raw interpolation is possible. Confirming that the log injection is exploitable (dashboard without HTML encoding) requires knowing the tool that consumes the logs.

Systematically mention these limitations in the "Limitations" section of the report for A09: this is the category where "Not assessable (insufficient context)" is most frequently legitimate.
```
