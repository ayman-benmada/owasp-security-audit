# A10 - Mishandling of Exceptional Conditions

**Reference framework:** OWASP Top 10 (2025) - category A10
**Main associated CWEs:** CWE-248, CWE-280, CWE-390, CWE-391, CWE-392, CWE-393, CWE-394, CWE-395, CWE-396, CWE-397, CWE-460, CWE-544, CWE-584, CWE-600, CWE-636, CWE-754, CWE-755
**Finding format:** `OWASP-A10-NNN`

This file is loaded by the `owasp-security-audit` orchestrator skill when analyzing category A10. It provides the detection patterns, standard fixes, and severity grid specific to the mishandling of exceptional conditions.

---

## Definition

A10 covers situations where a system fails to properly prevent, detect, or handle an exceptional condition. The program then shifts into an inconsistent or unpredictable state: it keeps running without any guarantee of internal consistency.

**Common causes:**

- Missing or incomplete input validation
- Error handling performed too high up the call stack rather than at the source
- Unexpected runtime conditions (memory exhaustion, insufficient permissions, network outage)
- Inconsistent or overly generic `catch` blocks
- Exceptions simply ignored

**Relationship to other categories:** A10 partially overlaps with A02.3 (verbose error messages exposing the stack), A06.7 (race conditions), and A09.4 (uncaught exceptions). What distinguishes A10: the flaw lies in the **error-handling mechanism itself** - the `try/catch` is present but poorly structured, or absent where it should exist.

Guiding principle: **fail fast, fail closed**. Immediately halt execution as soon as an uncertain state is detected, deny the action by default whenever a security control errors out, and always release resources whether or not an exception occurs.

---

## Attack surface - Exploitability prerequisites

Before declaring an A10 finding, verify that **the mishandling of the exception is exploitable or exposes sensitive information**. Typical vectors:

- Detailed error messages (stack trace, SQL query, absolute path) returned to the HTTP client
- Unhandled exceptions causing "fail open" behavior (access granted by default on error)
- Multi-step transactions without rollback allowing exploitable inconsistent states
- Resources (DB connections, files, sockets) not released on exception, causing progressive DoS

**Cases where the finding should be downgraded or dismissed:**

- `catch (e) {}` on **non-security business errors** with no impact on access control (e.g., format validation error)
- Stack trace logged **server-side only**, never returned to the client
- Error exposed only in a **development environment** (`NODE_ENV !== 'production'`)
- "Fail open" on a non-security feature (e.g., a recommendation feature fails silently)

---

## Detection methodology

### 1. Identify high-stakes error paths

Focus on:

- Security controls (authentication, authorization, validation) - a `catch` that carries on as if nothing happened is a critical **fail open**.
- Multi-step operations (transfers, cascading creations) - an exception between two steps can leave the state partially applied.
- Resource allocations (files, connections, handles) - an exception can leave the resource open indefinitely.
- Functions whose return value can be `null`, `undefined`, `-1`, or an error.

### 2. Walk through `try/catch` blocks

For each `try/catch` block found, ask:

- Does the `catch` contain a `return true` or a silent continuation on a security control? -> **Fail open**.
- Is the `catch` generic (`Exception $e`, `catch (Error e)`, `except Exception`) with no differentiated handling? -> Error masking.
- Is the stack trace or exception message returned to the client? -> Information leak (see A02.3).
- Is there a `finally` block to release resources? -> If not, look for resource leaks.

### 3. Look for missing error handling

- Functions that can return `null`/`undefined` used without a check.
- `switch` with no `default`.
- Multi-step operations without a transaction or without rollback.
- Default server error pages left uncustomized.

---

## Subtypes and detection patterns

> The examples mainly use PHP/Laravel and JavaScript. **Adapt each pattern to the language and framework of the audited project.**

---

### A10.1 - Sensitive information leak via error messages

**CWE-209** - Generation of Error Message Containing Sensitive Information | **CWE-755** - Improper Handling of Exceptional Conditions

**Pattern:** an uncaught (or poorly caught) exception propagates up to the user, exposing the stack trace, the framework's name and version, the installation path, or the SQL query. This subtype overlaps with A02.3 - report under both categories if relevant.

**Detection - look for:**

```php
// ❌ Exception message returned directly to the client
catch (\Exception $e) {
    return response()->json(['error' => $e->getMessage()], 500);
    // getMessage() can return: "SQLSTATE[42000]: ...SELECT * FROM users WHERE id = ..."
}
```

```javascript
// ❌ Stack trace in the HTTP response
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});
```

**Fix - generic message client-side, detail in logs:**

```php
// ✅ Expected business exception → clean 404 with no technical detail
catch (\Illuminate\Database\Eloquent\ModelNotFoundException $e) {
    return response()->json(['title' => 'User not found', 'status' => 404], 404);
}

// ✅ Unexpected exception → full log server-side, generic response client-side
catch (\Throwable $e) {
    Log::error('unexpected_error', ['error' => $e->getMessage(), 'trace' => $e->getTraceAsString()]);
    return response()->json(['error' => 'Internal server error'], 500);
}
```

**Typical severity:** 🟡 Medium (technical stack trace) to 🟠 High (SQL query with exposed table/column names, framework version exploitable to target known CVEs).

---

### A10.2 - Failing open: security bypassed on exception

**CWE-280** - Improper Handling of Insufficient Permissions or Privileges | **CWE-636** - Not Failing Securely

**Pattern:** a security control (authentication, authorization, validation) throws an exception, and the `catch` block continues execution as if the control had succeeded. Result: an auth service outage or a network error grants access to everyone.

**Detection - look for:**

```javascript
// ❌ Failing open: exception in the access control → access granted
function userCanAccess(userId, resourceId) {
  try {
    const role = getRoleFromAuthService(userId);
    return checkPermission(role, resourceId);
  } catch (e) {
    return true; // ⚠️ if the service is down, everyone gets through
  }
}
```

```php
// ❌ PHP variant - silent catch that lets execution continue
function isAdmin($userId): bool {
    try {
        return AuthService::getRole($userId) === 'admin';
    } catch (\Exception $e) {
        // Exception swallowed: the function implicitly returns false
        // but the calling code may not check the return value
    }
}
```

**Pattern to actively look for:** any `catch` block inside an access-check, authentication, or validation function that returns `true`, a truthy value, or returns nothing (implicit continuation).

**Fix - fail closed systematically:**

```php
// ✅ Fail closed: any exception in a security control → deny + log
function userCanAccess(int $userId, int $resourceId): bool {
    try {
        $role = getRoleFromAuthService($userId);
        return checkPermission($role, $resourceId);
    } catch (AuthServiceUnavailableException $e) {
        logger()->warning('Auth service unavailable, denying access', ['user' => $userId]);
        return false;
    } catch (\Throwable $e) {
        logger()->error('Unexpected error in access check', ['exception' => $e->getMessage()]);
        return false;
    }
}
```

**Typical severity:** 🔴 Critical (authentication or authorization bypass possible via a network error or a service outage).

---

### A10.3 - Missing rollback in a multi-step transaction

**CWE-460** - Improper Cleanup on Thrown Exception | **CWE-755** - Improper Handling of Exceptional Conditions

**Pattern:** an operation involving several dependent actions (debiting one account and crediting another, creating a record and sending a notification) is not wrapped in a transaction. An exception between two steps leaves the system in a partially applied state.

**Detection - look for:**

```php
// ❌ Debit applied even if the credit fails
public function transfer(Request $request): JsonResponse
{
    $from = Account::findOrFail($request->from_id);
    $to   = Account::findOrFail($request->to_id);

    $from->decrement('balance', $request->amount); // applied
    $to->increment('balance', $request->amount);   // can fail → inconsistent state
}
```

- Several sequential database operations without `DB::transaction()` or an equivalent.
- Transaction present but exception caught inside without re-throwing → the automatic rollback never triggers.
- External resources (API calls, message queues) modified before the DB transaction is confirmed.

**Fix - full atomicity with locking:**

```php
// ✅ Transaction + locking + business check performed after the lock
public function transfer(Request $request): JsonResponse
{
    $validated = $request->validate([
        'from_id' => ['required', 'integer', 'exists:accounts,id'],
        'to_id'   => ['required', 'integer', 'exists:accounts,id', 'different:from_id'],
        'amount'  => ['required', 'numeric', 'min:0.01'],
    ]);

    DB::transaction(function () use ($validated) {
        // Locking in a deterministic order (avoids cross deadlocks)
        $ids      = collect([$validated['from_id'], $validated['to_id']])->sort()->values();
        $accounts = Account::whereIn('id', $ids)->lockForUpdate()->get()->keyBy('id');

        $from = $accounts[$validated['from_id']];
        $to   = $accounts[$validated['to_id']];

        // Business check AFTER the lock: balance guaranteed up to date
        if ($from->balance < $validated['amount']) {
            throw new InsufficientFundsException(); // triggers the automatic rollback
        }

        $from->decrement('balance', $validated['amount']);
        $to->increment('balance', $validated['amount']);
    });

    return response()->json(['status' => 'ok']);
}
```

**Typical severity:** 🔴 Critical (financial inconsistency, double debit/credit) to 🟠 High (inconsistent application state with no direct financial impact).

---

### A10.4 - Generic catch masking critical errors

**CWE-390** - Detection of Error Condition Without Action | **CWE-391** - Unchecked Error Condition

**Pattern:** overly generic exceptions are caught without differentiated handling, masking significant malfunctions: logic errors, constraint violations, `OutOfMemoryError`, configuration errors. The system appears to be functioning normally while actually in a degraded state.

**Detection - look for:**

```php
// ❌ Generic catch: OutOfMemoryError, PDOException, LogicException, all swallowed
catch (\Exception $e) {
    // total silence: no log, no alert, no error returned
}
```

```javascript
// ❌ Empty catch or with insufficient console.log in production
try {
  await sensitiveOperation();
} catch (e) {
  console.log(e); // lost in production without log aggregation
}
```

```python
# ❌ Generic except on a critical operation
try:
    process_payment(data)
except Exception:
    pass  # silent exception
```

**Fix - differentiated exceptions, none swallowed silently:**

```php
// ✅ Differentiated handling based on the exception type
try {
    processPayment($data);
} catch (InsufficientFundsException $e) {
    // Expected business exception: functional response
    return response()->json(['error' => 'Insufficient funds'], 422);
} catch (PaymentGatewayException $e) {
    // External technical exception: log + generic response
    Log::error('payment_gateway_error', ['message' => $e->getMessage()]);
    return response()->json(['error' => 'Payment service unavailable'], 503);
} catch (\Throwable $e) {
    // Everything else: full log + alert + generic response
    Log::critical('unexpected_payment_error', ['trace' => $e->getTraceAsString()]);
    return response()->json(['error' => 'Internal error'], 500);
}
```

**Typical severity:** 🟡 Medium (malfunction masked with no immediate security impact) to 🟠 High (critical error swallowed within a financial or security flow).

---

### A10.5 - Resources not released after an exception (resource leak)

**CWE-584** - Return Inside Finally Block | **CWE-755** - Improper Handling of Exceptional Conditions

**Pattern:** a resource (file, database connection, network handle, stream) is opened and not released if an exception occurs before the `fclose()`/`close()`/`disconnect()` call. Repeated across many requests, this progressively exhausts the server's available descriptors, causing a denial of service.

**Detection - look for:**

```php
// ❌ fclose() never reached if an exception is thrown inside the loop
$handle = fopen($path, 'r');
while (($row = fgetcsv($handle)) !== false) {
    User::create(['name' => $row[0], 'email' => $row[1]]); // can throw
}
fclose($handle); // never reached in case of exception
```

```javascript
// ❌ stream not closed on error
const stream = fs.createReadStream(filePath);
stream.on("data", (chunk) => processChunk(chunk)); // can throw
// no error handling → stream left open
```

**Fix - `finally` guarantees release in all cases:**

```php
// ✅ finally executed whether an exception is thrown or not
$handle = fopen($path, 'r');
try {
    while (($row = fgetcsv($handle)) !== false) {
        User::create(['name' => $row[0], 'email' => $row[1]]);
    }
} finally {
    fclose($handle); // always executed
}
```

```javascript
// ✅ Node.js: explicit handling of the 'error' event
const stream = fs.createReadStream(filePath);
stream.on("error", (err) => {
  logger.error("stream_error", { error: err.message });
  stream.destroy();
});
stream.on("data", (chunk) => processChunk(chunk));
```

**Multi-language equivalents:** `try-with-resources` (Java), `using` (C#/Python), `defer` (Go): these constructs guarantee the release automatically.

**Typical severity:** 🟡 Medium (localized resource leak) to 🟠 High (leak on a frequently called endpoint that can lead to a DoS).

---

### A10.6 - Switch with no `default` or a missing `break`

**CWE-478** - Missing Default Case in Switch Statement | **CWE-484** - Omitted Break Statement in Switch

**Pattern:** a `switch` with no `default` case silently lets unexpected values through: the function returns `undefined`/`null` and the subsequent computation crashes or produces an incorrect result. A missing `break` causes an unintended fall-through, combining two behaviors and corrupting the state.

**Detection - look for:**

```javascript
// ❌ No default: unexpected value returns undefined
function applyDiscount(tier, price) {
  switch (tier) {
    case "gold":
      return price * 0.7;
    case "silver":
      return price * 0.85;
    // 'bronze' or any unknown value → undefined → NaN in the following calculation
  }
}
```

```javascript
// ❌ break forgotten: fall-through to the next case
switch (action) {
  case "read":
    allowRead();
  // break forgotten → falls through to 'write'
  case "write":
    allowWrite();
    break;
}
```

**Fix - mandatory `default`, explicit failure on unknown value:**

```javascript
// ✅ Default that throws an explicit error rather than returning silently
function applyDiscount(tier, price) {
  switch (tier) {
    case "gold":
      return price * 0.7;
    case "silver":
      return price * 0.85;
    case "bronze":
      return price * 0.95;
    default:
      throw new Error(`Unknown discount tier: ${tier}`);
  }
}
```

**Note:** in the context of access control or routing of sensitive business logic, a `switch` with no `default` can be a bypass vector if an attacker can control the value (e.g., an injected role or action).

**Typical severity:** 🟢 Low to 🟡 Medium (depending on whether the unhandled value can be controlled by an attacker or affects security logic).

---

### A10.7 - Unchecked return value

**CWE-252** - Unchecked Return Value | **CWE-754** - Improper Check for Unusual or Exceptional Conditions

**Pattern:** the result of a function that may return `null`, `undefined`, `-1`, or an error value is used directly without a check. This causes an immediate crash or a silently incorrect state. An attacker can deliberately trigger this condition to cause a repeated denial of service.

**Detection - look for:**

```javascript
// ❌ Array.find() can return undefined
function getEmail(userId) {
  const user = users.find((u) => u.id === userId);
  return user.email.toLowerCase(); // TypeError if user is undefined
}
```

```php
// ❌ firstOrFail() would be correct but first() can return null
$user = User::where('email', $email)->first();
$name = $user->name; // Fatal error if $user is null
```

```python
# ❌ dict.get() returns None if the key is absent
config = load_config()
timeout = config.get('timeout')
time.sleep(timeout)  # TypeError: 'NoneType' cannot be interpreted as integer
```

**Fix - explicit check or dedicated business exception:**

```javascript
// ✅ Explicit check with a business exception
function getEmail(userId) {
  const user = users.find((u) => u.id === userId);
  if (!user) throw new UserNotFoundError(userId);
  return (user.email ?? "").toLowerCase();
}
```

```php
// ✅ firstOrFail() throws ModelNotFoundException if absent: handle the exception
$user = User::where('email', $email)->firstOrFail();
```

**Typical severity:** 🟢 Low to 🟡 Medium (localized crash) to 🟠 High (if the unchecked value is in a security flow or exploitable for a targeted DoS).

---

### A10.8 - Default server error pages exposed

**CWE-209** - Generation of Error Message Containing Sensitive Information

**Pattern:** the default error pages of the web server (Nginx, Apache, IIS) expose the server's name and version, making it easier to identify applicable CVEs. This subtype overlaps with A02.3 - report under both categories.

**Detection - look for:**

```nginx
# ❌ No error_page directive, server_tokens active by default
server {
    listen 80;
    server_name example.com;
    # server_tokens is "on" by default → "Server: nginx/1.24.0" in every response
    # Default Nginx error pages → version shown in the footer
}
```

**Fix:**

```nginx
# ✅ Version hidden + generic error pages under control
server {
    listen 80;
    server_name example.com;

    server_tokens off; # hides the version in headers and error pages

    error_page 400 401 403 404 /errors/4xx.html;
    error_page 500 502 503 504 /errors/5xx.html;

    location = /errors/4xx.html { internal; root /var/www/static; }
    location = /errors/5xx.html { internal; root /var/www/static; }
}
```

**Typical severity:** 🟢 Low to 🟡 Medium (information disclosure facilitating reconnaissance, see A02.3 for calibration).

---

## Cross-cutting remediation rules

1. **Fail closed by default** - any security control that throws an exception must return `false`/access denied, never continue or return `true`.
2. **Differentiated exceptions** - catch exceptions at the most precise level possible, never an empty `catch (Exception e) {}` on critical code.
3. **Never swallow an exception silently** - any empty `catch` or one with `// ignore` is suspect; log at minimum, alert if the context is sensitive.
4. **Stack trace only in server logs** - never in the HTTP response to the client; provide a `tx_id` for correlation.
5. **`finally` for resources** - every `open()`/`fopen()`/`connect()` must have a `finally` (or its equivalent `try-with-resources`, `using`, `defer`) guaranteeing release.
6. **Atomic transactions** - any multi-step dependent operation wrapped in a transaction with automatic rollback on exception.
7. **Return value checks** - any function returning `null`/`undefined`/`-1` must be followed by an explicit check or a call to the "or fail" variant (e.g., `firstOrFail()`).
8. **`default` in every `switch`** - throwing an explicit exception on an unknown value, especially for values that can originate externally.
9. **Strict and early validation** - reduce exceptional conditions by filtering out invalid input before it propagates into the business logic (Zod, framework validation rules, type guards).
10. **`server_tokens off` and custom error pages** - never expose the server version in HTTP responses.

---

## Severity classification guide

| Finding criteria                                                                                                                                                                           | Severity         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------- |
| Failing open on an authentication or authorization control, missing rollback on a multi-step financial operation, exception caught and security state kept as valid                        | 🔴 Critical      |
| SQL stack trace or internal path leak, resource leak on a frequently called endpoint (potential DoS), generic catch swallowing errors in a payment or security flow                        | 🟠 High          |
| Generic catch with no log on non-critical code, unchecked return value in an exploitable context, server error pages exposing the version                                                  | 🟡 Medium        |
| Switch with no default on a value not controllable by the user, resource leak on a rarely used endpoint, stack trace in server log (correct) but log level too low (info instead of error) | 🟢 Low           |
| `server_tokens` active with no other exploitation vector, missing `default` in a purely internal switch                                                                                    | ℹ️ Informational |

**Context rule:** the severity of A10 depends heavily on the context of the exception. An empty `catch` on a cosmetic update is ℹ️. The same pattern on an authorization check is 🔴. Always assess which logic is protected by the failing `try/catch`.

---

## Common false positives - A10

| Detected pattern                         | Reason for the false positive                                                                  | How to verify                                                                                             |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Empty `catch (e) { }` or with log only   | May be intentional for non-security business errors                                            | Assess whether the exception has a security impact: access control, data integrity, availability          |
| Stack trace in server logs               | Acceptable as long as it is never transmitted to the HTTP client                               | Verify that the HTTP response returns a generic message, not the exception detail                         |
| No explicit rollback                     | ORM/framework may handle transactions automatically                                            | Check whether `@Transactional`, `transaction.rollback()`, or a transaction middleware wraps the operation |
| `return null` or `return false` on error | May be intentional if the calling code correctly handles the null value                        | Check whether the calling code verifies the return value before acting                                    |
| Generic error with no detail             | May look like insufficient logging but it is good practice not to expose details to the client | Verify separately whether the error is properly logged server-side (A09)                                  |
| `switch` with no `default`               | Acceptable if all possible values are covered by the explicit `case` statements                | Check whether the incoming type is an exhaustive enum or whether unanticipated values are possible        |

---

## Finding template for the report

````
**[OWASP-A10-NNN]** - [Short title]

- **Severity:** [level + icon]
- **Confidence:** 🔵 High / 🟣 Medium / ⚪ Low `[MANUAL VERIFICATION REQUIRED if Low]`
- **Remediation effort:** Low (<1h) / Medium (1-4h) / High (>4h) / Architectural
- **Justification:** [1 sentence, specify which logic is affected by the mishandled exception]
- **Subtype:** A10.X - [subtype name]
- **Location:** [file:line / function / endpoint]
- **Description:** [explanation of the failing mechanism and the resulting inconsistent state]
- **Potential impact:** [security bypass, inconsistent state, DoS, information leak]
- **Evidence / Vulnerable example:**
  ```[language]
  // audited excerpt with the try/catch block or the missing error handling
````

- **Recommendation:** [fail closed, finally, transaction, return value check, etc.]
- **Remediation example:**
  ```[language]
  // fixed version
  ```
- **References:** [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) | [OWASP A10:2021 - Insufficient Logging and Monitoring](https://owasp.org/Top10/) | [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

```

> Note: Mishandling of Exceptional Conditions is a category from the 2025 framework. In the OWASP Top 10 2021, it does not exist as such; its themes are distributed across A05 (Security Misconfiguration) and other categories.

---

## Limits of static analysis for A10

- **Failing open**: detecting a `return true` inside a `catch` is possible statically. Confirming that it is indeed a security control (and not a legitimate return value) requires understanding the function's semantics.
- **Implicit transactions**: some ORMs automatically wrap operations in transactions (configurable behavior), so the explicit absence of `DB::transaction()` does not necessarily mean there is no protection.
- **Resource leaks**: file descriptor and connection leaks are hard to confirm statically without profiling; the analysis identifies risky patterns, not the actual leak.
- **Intentional fall-through**: some `switch` statements with no `break` are intentional (accumulation pattern). Do not report them as a finding without having verified the intent.
- **Return values**: a function returning `null` can be used safely if the caller handles that case; trace the full flow before concluding.

Mention these limitations in the report's "Limitations" section when relevant.
```
