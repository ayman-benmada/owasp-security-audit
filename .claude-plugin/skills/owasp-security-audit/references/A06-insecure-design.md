# A06: Insecure Design

**Reference:** OWASP Top 10 (2025), category A06
**Main associated CWEs:** CWE-73, CWE-183, CWE-209, CWE-233, CWE-256, CWE-434, CWE-444, CWE-451, CWE-602, CWE-657, CWE-770, CWE-799, CWE-841, CWE-1021
**Finding format:** `OWASP-A06-NNN`

This file is loaded by the orchestrator skill `owasp-security-audit` when analyzing category A06. It provides detection patterns, typical fixes, and the severity grid specific to design flaws.

---

## Definition

Insecure Design encompasses vulnerabilities that originate not from coding errors, but from insufficient or unsuitable design of security mechanisms.

**Fundamental distinction:**

- An **implementation flaw** (SQL injection, XSS, weak hashing) can be fixed with a targeted patch.
- A **design flaw** cannot be compensated for by a perfect implementation. If a control was never considered in the architecture, no superficial fix can close that gap.

These flaws often escape automated tools because the code **complies with the technical specifications while betraying the business intent**.

Guiding principle: security must be a fundamental property built in from the design stage, not a layer added on later. The question to ask for every feature is: **"How could someone abuse this?"**

---

## Attack Surface: Exploitability Prerequisites

Before reporting an A06 finding, verify that **the design flaw is exploitable in the actual deployment context**. Typical vectors:

- Features accessible without proper authentication or authorization
- Business flows that can be manipulated by replaying or skipping steps (e.g., payment -> confirmation without server-side validation)
- Endpoints without rate limiting exposed to the internet
- Account recovery logic exploitable for enumeration or account takeover

**Cases where the finding should be downgraded or dismissed:**

- The absence of rate limiting concerns an **internal** API not directly exposed to the internet
- The design flaw concerns an **admin-only** feature with strong authentication
- The potentially exploitable business logic requires authenticated access with an elevated role
- The attack scenario involves very specific preconditions that make exploitation unlikely in this context

---

## Detection Methodology

A06 is the category most difficult to detect through static analysis. Findings come from reading the business logic, not from syntactic patterns.

### 1. Identify High-Stakes Features

Focus on flows where exploitation would have a significant business or security impact:

- Financial operations or operations involving a limited resource (inventory, credit, seats, tickets).
- Authentication and account recovery mechanisms.
- Multi-tenant or multi-user access to shared data.
- File upload endpoints.
- Flows with potentially concurrent shared state (coupons, single-use tokens, quotas).

### 2. Model Functional Abuse

For each identified feature, ask:

- Can a user trigger this flow more times than intended?
- Can a bot automate this flow at a rate incompatible with human behavior?
- Can two simultaneous requests produce an inconsistent state?
- Is the sensitive data processed here protected by design, or only by convention?
- Is the separation between tenants / users enforced structurally, or only through an application-level filter?

### 3. Assess the Depth of Protection

An A06 finding is more severe the more the protection relies on a single layer that is easy to bypass. Look for:

- Client-side-only protections (JavaScript, hidden HTML attributes).
- Application-level filters without enforcement at the database level.
- Read-time validation without a guarantee of write-time atomicity.
- Business rules missing from the code (TODO comments, unhandled cases).

### 4. Distinguishing A06 from Other Categories

A06 can appear to overlap with other categories (A01 for access, A04 for cryptography, A05 for injection). The difference: a finding is A06 when **no correct implementation of the feature as designed can fix the problem**, it is the design itself that must change.

---

## Subtypes and Detection Patterns

> The examples primarily use Node.js and PHP/Laravel. **Adapt each pattern to the language and framework of the project being audited.**

---

### A06.1: Business Logic Exploitable Through Functional Abuse

**CWE-841**: Improper Enforcement of Behavioral Workflow | **CWE-799**: Improper Control of Interaction Frequency

**Pattern:** the business rules are followed to the letter but were not designed to withstand malicious or automated use. The attacker uses the features exactly as intended, but in an unintended way.

**Detection, look for:**

- No per-user or per-account limit on finite resources (seats, inventory, quotas, credits).
- No time-based or rate limit on repeatable actions.
- Deposits or financial commitments marked as "required" but not enforced before confirmation.
- No validation of account age or authenticity for sensitive actions.
- No distinction between a temporary reservation (an expirable pre-booking) and a final confirmation.

**Vulnerable code:**

```javascript
// ❌ The only rule is "deposit required if > 15 seats", not enforced, with no cumulative limit
async function reserveSeats(req, res) {
  const { showtimeId, seatCount } = req.body;
  const requiresDeposit = seatCount > 15;

  // Nothing prevents reserving 500 seats without paying
  const reservation = await db.reservations.create({
    showtimeId,
    seatCount,
    depositRequired: requiresDeposit,
    depositPaid: false,
  });
  return res.json({ success: true, reservation });
}
```

**Fix: business rules reflecting the threat model:**

```javascript
// ✅ Each rule is enforced, not just declared
async function reserveSeats(req, res) {
  const { showtimeId, seatCount } = req.body;
  const userId = req.user.id;

  // Absolute limit per reservation
  if (seatCount > 50) {
    return res.status(400).json({ error: "Reservation too large" });
  }

  // For groups: expirable pre-reservation, payment required before confirmation
  if (seatCount > 15) {
    const pending = await db.reservations.createPending({
      showtimeId,
      seatCount,
      userId,
      expiresAt: Date.now() + 15 * 60 * 1000,
    });
    return res.json({ paymentUrl: getPaymentUrl(pending.id) });
  }

  const reservation = await db.reservations.create({
    showtimeId,
    seatCount,
    userId,
  });
  return res.json({ success: true, reservation });
}
```

**Typical severity:** 🟠 High to 🔴 Critical (depending on the economic or operational impact of the abuse).

---

### A06.2: Lack of Bot Protection in Sensitive Flows

**CWE-799**: Improper Control of Interaction Frequency | **CWE-770**: Allocation of Resources Without Limits or Throttling

**Pattern:** a commercial or critical flow (purchase, registration, password reset) includes no behavioral barrier. Bots can automate this flow at a rate incompatible with human behavior, causing resource hoarding, scalping, credential stuffing, or account creation fraud.

**Detection, look for:**

- No rate limiting on authentication, purchase, account creation, or password reset endpoints.
- No minimum delay between the release of a high-demand product and purchase authorization.
- No strict per-account limit on high-demand products.
- No verification of account age or authenticity for sensitive actions.
- API endpoints with no distinction between a human browser and a programmatic client.

**Vulnerable code:**

```javascript
// ❌ No behavioral barrier, purchase can be automated at will
async function checkout(req, res) {
  const { productId, quantity } = req.body;
  const product = await Product.findById(productId);
  const order = await Order.create({
    userId: req.user.id,
    productId,
    quantity,
    total: product.price * quantity,
  });
  return res.json({ orderId: order.id });
}
```

**Fix: anti-bot rules built into the design:**

```javascript
// ✅ Behavioral barriers at multiple levels
async function checkout(req, res) {
  const { productId, quantity } = req.body;
  const userId = req.user.id;
  const product = await Product.findById(productId);

  // Minimum delay after release for sensitive products
  if (product.isHighDemand && Date.now() - product.releasedAt < 5000) {
    return enqueueForLottery(userId, productId, quantity, res);
  }

  // Strict limit per verified account
  if (product.isHighDemand) {
    const prev = await Order.countByUserAndProduct(userId, productId, "30d");
    if (prev + quantity > 1) {
      return res
        .status(429)
        .json({ error: "Limite d'un exemplaire par client" });
    }
  }

  // Verify account age
  const account = await Account.findById(userId);
  if (product.isHighDemand && account.ageInDays < 30) {
    return res
      .status(403)
      .json({ error: "Account too recent for this purchase" });
  }

  // Behavioral score, additional challenge, not a hard block
  const riskScore = await calculateBehavioralRiskScore(req);
  if (riskScore > 0.85) {
    return res.status(202).json({ challenge: "verification_required" });
  }

  const order = await Order.create({
    userId,
    productId,
    quantity,
    total: product.price * quantity,
  });
  return res.json({ orderId: order.id });
}
```

**Typical severity:** 🟠 High (business impact, resource hoarding) to 🔴 Critical (credential stuffing on an auth endpoint without rate limiting).

---

### A06.3: Unreliable Account Recovery Mechanisms

**CWE-640**: Weak Password Recovery Mechanism for Forgotten Password

**Pattern:** the access recovery mechanism relies on insufficient proof of identity: secret questions, a password hint, or a reset link without an expiration. This information can be known, guessed, or brute-forced by third parties.

**Detection, look for:**

- Security questions used as the sole recovery factor (`mother's maiden name`, `first pet`, `birth city`, information that is often public on social media).
- Reset links without expiration or that are reusable.
- Reset tokens generated with a weak PRNG (see A04.4) or predictable (based on timestamp, email, or ID).
- Reset sent to an email address that was not verified at registration.
- No invalidation of active sessions after a password change.

**Principle:** no implementation, however careful, can fix a recovery mechanism that is conceptually weak. Secret questions should be removed, not improved.

**Typical fix:**

- A single-use link, expiring within a short window (15-30 min), generated via a CSPRNG (see A04.4).
- Sent only to the email address verified at registration.
- Invalidation of all active sessions after a reset.
- Optionally: validation via a registered device or second factor.

**Typical severity:** 🟠 High to 🔴 Critical (depending on the sensitivity of the protected accounts).

---

### A06.4: Lack of Tenant Separation (Multi-Tenancy)

**CWE-657**: Violation of Secure Design Principles | **CWE-233**: Improper Handling of Parameters

**Pattern:** in a SaaS application, the separation between tenants relies solely on a `tenant_id` filter in the application code. The slightest developer oversight exposes one customer's data to another. A robust design makes this leak **structurally impossible**.

**Detection, look for:**

- SQL queries without a `tenant_id` filter in controllers or repositories that should have one.
- No PostgreSQL Row-Level Security (RLS) or equivalent at the database level.
- Cache keys not prefixed with `tenant_id` (risk of cross-tenant cache pollution).
- Shared message queues without per-tenant isolation.
- A `tenant_id` extracted from the request body or query string rather than from the verified authentication token.

**Vulnerable code:**

```javascript
// ❌ Application-level filter only, a single developer oversight is enough
async function getInvoices(req, res) {
  const tenantId = req.user.tenantId;
  const invoices = await db.query(
    "SELECT * FROM invoices WHERE tenant_id = ?",
    [tenantId],
  );
  return res.json(invoices);
  // If another route forgets this filter -> cross-tenant leak
}
```

**Fix: defense-in-depth isolation at every layer:**

```javascript
// ✅ Level 1: PostgreSQL Row-Level Security
// CREATE POLICY tenant_isolation ON invoices
//   USING (tenant_id = current_setting('app.tenant_id')::uuid);
// Even if a SQL query forgets the filter, the database refuses to return the rows

// ✅ Level 2: middleware injecting the tenantId into the DB session
async function tenantMiddleware(req, res, next) {
  if (!req.user?.tenantId) return res.status(401).end();
  await db.query("SET LOCAL app.tenant_id = $1", [req.user.tenantId]);
  next();
}

// ✅ Level 3: repository requiring a tenantId at construction
class InvoiceRepository {
  constructor(tenantId) {
    if (!tenantId) throw new Error("TenantId requis");
    this.tenantId = tenantId;
  }
  async findById(id) {
    // Double protection: RLS (DB) + explicit filter (app)
    const result = await db.query(
      "SELECT * FROM invoices WHERE id = $1 AND tenant_id = $2",
      [id, this.tenantId],
    );
    if (!result.rows[0]) throw new NotFoundError();
    return result.rows[0];
  }
}

// ✅ Level 4: cache keys and queues prefixed with tenantId
const cacheKey = `tenant:${tenantId}:invoice:${id}`;
const queueName = `tenant:${tenantId}:invoice-processing`;
```

**Typical severity:** 🔴 Critical (a cross-tenant leak in a SaaS product exposes the data of customers who have no relationship with each other).

---

### A06.5: Unprotected Storage of Credentials by Design

**CWE-256**: Plaintext Storage of a Password | **CWE-257**: Storing Passwords in a Recoverable Format

**Pattern:** the architecture for storing credentials (passwords, API tokens, secrets) was not designed to be secure. This is not an implementation oversight but an incorrect architectural decision, for example designing a "recover my password" feature (which implies reversible storage), or failing to define a hashing standard from the design phase onward.

**Detection, look for:**

- A "show my password" or "we will send you your password" feature -> implies plaintext or (reversibly) encrypted storage.
- No hashing standard defined in the architecture (each developer chooses their own algorithm).
- API tokens or integration secrets stored in plaintext in the database with no rotation capability.
- No secrets vault in an architecture that needs one.

**Note:** this subtype partially overlaps with A04.3 (unsuitable hashing) and A04.5 (hardcoded secrets). The A06 distinction: the weakness comes from an **architectural decision** (e.g., "we store passwords so we can retrieve them") rather than an implementation error (e.g., "we used MD5 instead of Argon2").

**Typical fix:** define the storage standard from the architecture phase onward: Argon2id for passwords, non-reversible hashing, a vault for secrets. Remove any feature that implies reversible storage of passwords.

**Typical severity:** 🔴 Critical.

---

### A06.6: Unrestricted File Upload by Design

**CWE-434**: Unrestricted Upload of File with Dangerous Type | **CWE-73**: External Control of File Name or Path

**Pattern:** an upload endpoint is designed without explicitly defining accepted types, maximum sizes, storage location, and access mode. Validation relies on elements controlled by the attacker (client-side extension, declared MIME type).

**Detection, look for:**

```php
// ❌ Error 1: insufficient validation
$request->validate(['file' => 'required|file']);

// ❌ Error 2: MIME type declared by the client (can be forged)
$mimeType = $file->getClientMimeType(); // the attacker controls this value

// ❌ Error 3: original client filename (path traversal possible)
$originalName = $file->getClientOriginalName(); // may contain "../../../etc/passwd"

// ❌ Error 4: stored in the public folder (executable via URL)
$file->move(public_path('uploads'), $originalName);

// ❌ Error 5: returns the direct URL to the file
return response()->json(['url' => asset('uploads/' . $originalName)]);
```

**Exploitation scenario:** the attacker sends `shell.php` renamed to `photo.jpg` with `Content-Type: image/jpeg`. `getClientMimeType()` returns `image/jpeg`, so the filter passes. The file is stored at `public/uploads/shell.php` and executed via `GET /uploads/shell.php?cmd=id`.

**Fix: secure design of the upload:**

```php
// ✅ Rule 1: validation by magic bytes (not by client Content-Type)
$request->validate([
    'file' => ['required', 'file', 'max:10240', 'mimes:jpeg,png,pdf']
    // 'mimes' checks the file's actual magic bytes, not the declared Content-Type
]);

// ✅ Rule 2: double-check of the actual MIME type
if (!in_array($file->getMimeType(), ['image/jpeg', 'image/png', 'application/pdf'], true)) {
    return response()->json(['error' => 'Unauthorized type'], 400);
}

// ✅ Rule 3: randomly generated name, original name ignored
$safeName = Str::random(32) . '.' . $file->extension();

// ✅ Rule 4: stored outside the public directory (not accessible via a direct URL)
$file->storeAs('uploads', $safeName, disk: 'private');

// ✅ Rule 5: access via a dedicated endpoint that checks permissions
return response()->json(['id' => $safeName]); // never the real path
```

**Cross-cutting rule:** an uploaded file must never be served from a path directly accessible via URL without explicit access control. The access mode (`attachment` vs `inline`) must also be defined by the application, never left to the browser.

**Typical severity:** 🔴 Critical (RCE via a web shell if the PHP file is executable, reading of sensitive files via path traversal).

---

### A06.7: Concurrency Issues in Critical Workflows (TOCTOU)

**CWE-362**: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition) | **CWE-367**: Time-of-check Time-of-use (TOCTOU) Race Condition

**Pattern:** a feature is designed assuming a flow will only ever be triggered once at a time. Without an atomicity mechanism, two simultaneous requests can check a condition at the same moment (both see "coupon not used"), then both apply the action (both grant the credit).

**Detection, look for:**

- A "read then write" pattern without a transaction or lock: separate `find()` + `update()` calls on single-use resources.
- Single-use or limited resources without atomicity control: coupons, reset tokens, credits, product inventory.
- Financial operations (withdrawal, transfer) without locking or a conditional UPDATE.
- No transaction encompassing the checks and the modifications.

**Vulnerable code:**

```javascript
// ❌ Check then action without atomicity
async function redeemCoupon(userId, couponCode) {
  const coupon = await Coupon.findByCode(couponCode);

  // Between this line and the update, other concurrent requests can slip through
  if (coupon && !coupon.used) {
    await User.addCredit(userId, coupon.amount);
    await Coupon.markAsUsed(coupon.id); // too late if two requests arrive here
    return { success: true };
  }
  return { success: false };
}
```

**Fix: atomicity via a conditional UPDATE within a transaction:**

```javascript
// ✅ Atomicity is guaranteed by the database
async function redeemCoupon(userId, couponCode) {
  return db.transaction(async (tx) => {
    // Conditional UPDATE: only the first request will succeed
    // RETURNING avoids a separate SELECT
    const result = await tx.query(
      `
      UPDATE coupons
      SET used = true, used_by = $1, used_at = NOW()
      WHERE code = $2 AND used = false AND expires_at > NOW()
      RETURNING amount
    `,
      [userId, couponCode],
    );

    if (result.rows.length === 0) {
      throw new Error("Invalid or already used coupon");
    }

    // The credit is only added if the UPDATE succeeded, within the same transaction
    await tx.query("UPDATE users SET credit = credit + $1 WHERE id = $2", [
      result.rows[0].amount,
      userId,
    ]);

    return { success: true, amount: result.rows[0].amount };
  });
}
```

**Other atomicity mechanisms depending on context:**

- `SELECT ... FOR UPDATE` (pessimistic locking) when a conditional UPDATE is not sufficient.
- Distributed application-level locks (Redis `SET NX`, Redlock) for cross-service workflows.
- Idempotency keys on sensitive endpoints to reject duplicate requests.

**Typical severity:** 🔴 Critical (double spending, credit fraud, quota bypass) to 🟠 High (inconsistent state without direct financial impact).

---

## Cross-Cutting Remediation Rules

1. **Model abuse at design time**: for every feature, ask who can abuse it, how, at what rate, and with what resources. Do not wait for the pentest.
2. **Make business rules impossible to bypass**: enforce them at a level that cannot be forgotten (database, middleware) rather than in every controller.
3. **Separate temporary reservation from final confirmation**: any limited resource should only be locked by a payment or an irreversible action, not by a mere declaration of intent.
4. **Defense-in-depth multi-tenant isolation**: RLS, context-injection middleware, repositories with a mandatory tenant, prefixed cache keys. Never a single filtering layer.
5. **Upload: magic bytes, random name, private storage**: validate the actual type, ignore the client-provided name, store outside the webroot, serve via an endpoint with access control.
6. **Atomicity for single-use resources**: conditional UPDATE + transaction for coupons, tokens, inventory, and financial operations. Eliminate the unlocked "read then write" pattern.
7. **Secret questions: remove, do not improve**: replace with a single-use, time-limited CSPRNG-generated link.
8. **Rate limiting on all sensitive endpoints**: authentication, password reset, account creation, checkout. With progressive escalation (slowdown -> challenge -> block).
9. **Archive security architecture decisions**: document design choices (secrets storage method, hashing standard, isolation policy) to prevent them from being inadvertently revisited.

---

## Severity Classification Guide

| Finding criteria                                                                                                                                                                             | Severity         |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| RCE via unrestricted upload, cross-tenant leak, double spending/fraud via a race condition, a bypassable recovery mechanism leading to account takeover                                      | 🔴 Critical      |
| Business logic abuse with significant economic impact, no rate limiting on an auth endpoint (credential stuffing), no anti-bot protection on limited high-demand resources                   | 🟠 High          |
| Race condition without direct financial impact, tenant separation that is application-level only (without RLS), a weak recovery mechanism that cannot be bypassed without social engineering | 🟡 Medium        |
| Rate limiting missing on a non-sensitive endpoint, missing per-user limits with no proven risk of abuse                                                                                      | 🟢 Low           |
| Good design practice not followed, with no identifiable exploitation vector                                                                                                                  | ℹ️ Informational |

**A06 severity rule:** always assess the concrete business impact, not just the technical risk. A business logic abuse can be 🟠 or 🔴 depending on whether it causes a financial loss, a service degradation, or a mere consequence-free anomaly.

---

## Common False Positives: A06

| Detected pattern                         | Reason for false positive                                                  | How to verify                                                                              |
| ---------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| No rate limiting                         | May be implemented at the reverse proxy/WAF level, not visible in the code | Check the Nginx, Cloudflare, AWS API Gateway config, or global middleware                  |
| File upload without type restriction     | May be intentional in an admin context with trusted users                  | Check whether the endpoint is accessible without authentication or with limited privileges |
| No server-side validation on a flow step | Validation may be in a middleware or an upstream service call              | Check the full call chain, not just the final handler                                      |
| Sensitive data stored in plaintext       | May be encrypted at the database level (at-rest encryption)                | Check the database configuration and column-level encryption options                       |
| No CAPTCHA                               | May be present on the frontend or via an external WAF service              | Check whether an anti-bot service is configured at a higher level                          |

---

## Finding Template for the Report

````
**[OWASP-A06-NNN]**: [Short title]

- **Severity:** [level + icon]
- **Confidence:** 🔵 High / 🟣 Medium / ⚪ Low `[MANUAL VERIFICATION REQUIRED if Low]`
- **Remediation effort:** Low (<1h) / Medium (1-4h) / High (>4h) / Architectural
- **Justification:** [1 sentence, specify the concrete business or operational impact]
- **Subtype:** A06.X: [subtype name]
- **Location:** [file:line / endpoint / architectural component]
- **Description:** [explanation of the design flaw and the abuse mechanism]
- **Potential impact:** [what an attacker can accomplish and at what scale]
- **Evidence / Vulnerable example:**
  ```[language]
  // excerpt of the code or description of the vulnerable architecture
````

- **Recommendation:** [required design change, specify if a patch alone is insufficient]
- **Remediation example:**
  ```[language]
  // fixed version or alternative architecture
  ```
- **References:** [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) | [OWASP A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/) | [OWASP Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)

```

> Note: Insecure Design corresponds to A04 in the OWASP Top 10 2021. In this orchestrator's 2025 reference, it is A06.

---

## Limitations of Static Analysis for A06

A06 is the category least detectable through static analysis and most dependent on business context:

- **Business logic**: an auditor without knowledge of the business domain may fail to identify that a rule is missing. A06.1 and A06.2 findings require understanding the intent of the feature, not just its implementation.
- **Race conditions**: detecting the "read then write" pattern is possible statically, but confirming exploitability requires load or concurrency testing.
- **Multi-tenant isolation**: checking for the presence of application-level filters is possible, but confirming the presence of RLS or other database-level mechanisms requires access to the schemas and to the server configuration.
- **Upload**: validation via magic bytes vs. declared MIME type can only be confirmed by reading the libraries used and their actual configuration.
- **Behavior under load**: business logic abuses (A06.1, A06.2) often only reveal themselves under load or during business-oriented penetration testing, not from reading the code alone.

Systematically mention these limitations in the "Limitations" section of the report for A06, and recommend business-logic-oriented penetration testing to complement the static analysis.
```
