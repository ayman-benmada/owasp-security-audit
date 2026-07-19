# A01 - Broken Access Control

**Reference framework:** OWASP Top 10 (2025), category A01
**Main associated CWEs:** CWE-284, CWE-285, CWE-639, CWE-22, CWE-352, CWE-862, CWE-863, CWE-732, CWE-285
**Finding format:** `OWASP-A01-NNN`

This file is loaded by the `owasp-security-audit` orchestrator skill when analyzing category A01. It provides detection patterns, standard fixes, and the severity grid specific to access control.

---

## Definition

Access control ensures that each user can only perform actions they are explicitly authorized to perform. It must be enforced **consistently across all entry points** (web, API, internal jobs, webhooks). A flaw appears as soon as a discrepancy exists between the intended mechanism and an alternative, unprotected access path.

Guiding principle: **deny by default**. Every request is denied unless explicitly authorized, and the authorization decision is always made server-side.

---

## Detection methodology

Before looking for flaws, map the terrain. This step avoids both false positives (flagging a legitimate public route like `/login`) and false negatives (forgetting that a route is mounted via a parent router).

### 1. Inventory of access surfaces

For each exposed endpoint, answer these questions:

- **Is auth required?** Which middleware/filter/guard enforces it? (`requireAuth`, `IsGranted`, `auth` middleware, `@PreAuthorize`, etc.)
- **What is the source of identity?** Where does the current user come from? Acceptable answers: a JWT verified server-side, a server session, an introspected OAuth token. **Warning sign**: a raw header like `X-User-Id`, a `userId` field in the body, an unsigned cookie.
- **Is the resource designated by a client-supplied ID?** If the endpoint manipulates a resource identified by `req.params.id`, `$_GET['id']`, `@PathVariable`, etc., it is an IDOR candidate.
- **Is it a sensitive action?** Role modification, deletion, access to another user's data, file reading: these should trigger an explicit authorization check.

### 2. Go through the sub-types below

For each sub-type, apply the detection patterns. The same piece of code can trigger multiple findings (e.g., an admin route with no auth AND no CSRF protection): report them separately.

### 3. Verify cross-channel consistency

A feature that is protected in the web controller but accessible without verification via an API route, a GraphQL endpoint, or an internal job remains vulnerable. Always cross-check the access paths to a given resource.

---

---

## Attack surface, exploitability prerequisites

Before declaring an A01 finding, verify that **the code is reachable from an untrusted input**. Typical input vectors for this category:

- URL parameters controllable by the user (`req.params`, `$_GET`, `path variables`)
- HTTP request body (`req.body`, `$_POST`, JSON payload)
- Manipulable HTTP headers (`Authorization`, `X-User-Id`, `X-Forwarded-For`)
- Cookies or JWT tokens supplied by the client
- Client-supplied GraphQL / gRPC parameters

**Cases where the finding should be downgraded or dismissed:**

- The vulnerable code is only called from an internal service with no external HTTP exposure
- An upstream middleware/guard (auth, ownership check) already protects the access; verify its presence in the routing
- The restriction is applied at a proxy or gateway level not visible in the analyzed code

---

## Sub-types and detection patterns

> The examples below are in Node.js/Express because they illustrate the patterns most readably. **Systematically transpose to the language and framework of the audited project** (Symfony Voters, Laravel Policies, Spring `@PreAuthorize`, Django permissions, etc.).

---

### A01.1 - IDOR (Insecure Direct Object Reference)

**CWE-639** - Authorization Bypass Through User-Controlled Key

**Vulnerability pattern:** a resource is retrieved by an identifier supplied by the user, without verifying that this user is authorized to access it. The identifier can be in the URL, a hidden field, a cookie, or the body.

**Detection, look for:**

- An endpoint that reads `req.params.id`, `req.query.id`, `request.GET['id']`, `@PathVariable Long id`, etc.
- Followed by a `findById` / `SELECT * FROM ... WHERE id = ?` / `Repository.find(id)`
- **Without** a clause restricting to the current user (e.g., `WHERE id = ? AND user_id = ?`) **nor** a post-fetch ownership check.

**Vulnerable code:**

```javascript
app.get("/api/orders/:orderId", requireAuth, async (req, res) => {
  const order = await db.findOrderById(req.params.orderId);
  if (!order) return res.status(404).json({ error: "Not found" });
  return res.json(order); // ⚠️ no ownership check
});
```

**Fix:**

```javascript
app.get("/api/orders/:orderId", requireAuth, async (req, res) => {
  const order = await db.findOrderById(req.params.orderId);
  if (!order) return res.status(404).json({ error: "Not found" });
  if (order.userId !== req.user.id) {
    return res.status(403).json({ error: "Forbidden" });
  }
  return res.json(order);
});
```

**Typical severity:** High to Critical (depending on the sensitivity of the exposed resource).

---

### A01.2 - Forced Browsing (direct access to unprotected routes)

**CWE-862** - Missing Authorization

**Pattern:** a sensitive route (admin, debug, export) is accessible without a permission check, simply by knowing its URL.

**Detection, look for:**

- Routes containing `/admin`, `/internal`, `/debug`, `/export`, `/backup` with no auth middleware or role check.
- Management pages (user creation/deletion, configuration) accessible without an equivalent of `requireRole('admin')`.
- Routes inherited from a parent router: verify that `app.use('/admin', adminRouter)` actually applies the admin middleware.

**Typical severity:** High (admin route) to Critical (full data export).

---

### A01.3 - Client-side-only access control

**CWE-602** - Client-Side Enforcement of Server-Side Security

**Pattern:** the authorization decision is made in the browser (hiding buttons, JS checks) with no server-side counterpart.

**Detection, look for:**

- An API endpoint that does not check the caller's role/permission even though the UI only exposes it to certain roles.
- Server-side code that trusts a field sent by the client (`req.body.role`, `req.body.isAdmin`, `req.body.userId` when the user is acting on themselves).

**Vulnerable code:**

```javascript
app.post("/api/users/:id/role", requireAuth, async (req, res) => {
  await db.updateUserRole(req.params.id, req.body.role); // ⚠️ anyone can self-promote
  res.json({ success: true });
});
```

**Fix:**

```javascript
app.post("/api/users/:id/role", requireAuth, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }
  const allowedRoles = ["user", "moderator", "admin"];
  if (!allowedRoles.includes(req.body.role)) {
    return res.status(400).json({ error: "Invalid role" });
  }
  await db.updateUserRole(req.params.id, req.body.role);
  res.json({ success: true });
});
```

**Typical severity:** Critical if privilege escalation, High otherwise.

---

### A01.4 - HTTP methods not protected uniformly

**CWE-650** - Trusting HTTP Permission Methods on the Server Side

**Pattern:** `GET` is protected but `DELETE` or `PUT` on the same URL is not.

**Detection, look for:**

- Multiple handlers (`app.get`, `app.delete`, `app.put`) on the same URL with different middlewares.
- Frameworks using per-method decorators: verify that each method has its own authorization annotation.
- Routes defined via `app.all(...)` or a method wildcard with no check in the handler.

**Typical severity:** High to Critical.

---

### A01.5 - Vertical privilege escalation

**CWE-269** - Improper Privilege Management

**Pattern:** a user obtains rights higher than those they were granted, generally because sensitive information (role, permissions) is modifiable client-side.

**Detection, look for:**

- Registration or profile update endpoints that accept a `role`, `isAdmin`, `permissions` field in the body with no filtering (mass assignment).
- JWTs whose `role` or `permissions` claims are derived from unvalidated user data.
- Use of `Object.assign(user, req.body)` or equivalent (unfiltered `@RequestBody User user`, `User.objects.create(**request.data)` in Django): a **mass assignment** pattern.

**Typical severity:** Critical.

---

### A01.6 - CORS misconfiguration

**CWE-942** - Permissive Cross-domain Policy with Untrusted Domains

**Pattern:** the CORS configuration allows untrusted origins, letting a malicious site running in an authenticated victim's browser read API responses on their behalf.

**Detection, look for:**

- `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` (a combination rejected by recent browsers, but can signal a dangerous intent).
- Loose suffix or regex validation (`origin.endsWith('advisor.com')` accepts `definitelynotadvisor.com`).
- Blind reflection of the origin: `res.setHeader('Access-Control-Allow-Origin', req.headers.origin)` with no allowlist.
- Missing `Vary: Origin` when the value is dynamic, which can enable cache poisoning.

**Vulnerable code:**

```javascript
app.use(
  cors({
    origin: (origin, cb) => cb(null, true), // ⚠️ accepts everything
    credentials: true,
  }),
);
```

**Fix:**

```javascript
const ALLOWED_ORIGINS = [
  "https://app.example.com",
  "https://admin.example.com",
];
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
  }),
);
// + ensure that `Vary: Origin` is present (cors does this by default when origin is dynamic)
```

**Important note:** CORS is not an authentication mechanism, it only protects against cross-origin requests initiated by a browser. `curl`, Postman, and mobile apps ignore it. True protection remains server-side auth/authorization.

**Typical severity:** High (if the API is sensitive and uses credentials), Medium otherwise.

---

### A01.7 - CSRF (Cross-Site Request Forgery)

**CWE-352** - Cross-Site Request Forgery

**Pattern:** a sensitive action can be triggered by a request originating from another site, with no verification that the user intentionally initiated it.

**Detection, look for:**

- Mutation endpoints (POST/PUT/DELETE) that rely on a session cookie **without**:
  - A verified CSRF token, **OR**
  - A `SameSite=Lax` or `SameSite=Strict` cookie, **OR**
  - Verification of a custom header (which forces a CORS preflight).
- Frameworks with native CSRF protection disabled (`csrf_exempt` in Django, `@CsrfToken(false)`, global middleware disabled).

**Note:** stateless APIs using a JWT in the `Authorization` header are not vulnerable to classic CSRF (the browser does not automatically send the header). However, if the JWT is stored in a cookie, the risk returns.

**Typical severity:** High for sensitive actions, Medium for actions with limited impact.

---

### A01.8 - Path Traversal

**CWE-22** - Improper Limitation of a Pathname to a Restricted Directory

**Pattern:** a file path is built from user input without validation, allowing an attacker to escape the authorized directory via `../`, alternative encodings (`%2e%2e%2f`, `..%2f`), or absolute paths.

**Detection, look for:**

- Path concatenation or joining (`path.join`, `os.path.join`, `File()`, `Paths.get()`) with unvalidated user input.
- File read/write functions (`fs.readFile`, `sendFile`, `file_get_contents`, `open()`) applied to a path derived from the client.
- Absence of a post-resolution check that the final path stays within the authorized directory.

**Vulnerable code:**

```javascript
app.get("/files", (req, res) => {
  const filePath = path.join("/var/app/uploads", req.query.name);
  res.sendFile(filePath); // ⚠️ ?name=../../etc/passwd works
});
```

**Fix (resolution + containment check):**

```javascript
const UPLOAD_DIR = path.resolve("/var/app/uploads");
app.get("/files", (req, res) => {
  const requested = path.resolve(UPLOAD_DIR, req.query.name);
  if (!requested.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(403).json({ error: "Forbidden" });
  }
  res.sendFile(requested);
});
```

**Even more robust approach: allowlist.** If the accessible files are known, map a validated identifier to a predefined path rather than deriving the path from user input.

**Typical severity:** Critical (reading `/etc/passwd`, configuration files, private keys).

---

### A01.9 - Token / metadata manipulation (JWT, cookies)

**CWE-345** - Insufficient Verification of Data Authenticity

**Pattern:** an attacker modifies or replays authentication elements to bypass controls. Typical cases: unverified JWT signature, accepted `none` algorithm, weak secret, modifiable sensitive claims.

**Detection, look for:**

- JWT decoding without verification (`jwt.decode(token)` instead of `jwt.verify(token, secret)`).
- Acceptance of the `none` algorithm (verify that the `algorithms` list is explicitly passed to `jwt.verify`).
- Weak or hardcoded HMAC secrets in the code (also a signal for A02, Cryptographic Failures).
- No verification of expiration (`exp`), issuer (`iss`), or audience (`aud`) when relevant.
- Long-lived JWTs (>1h for an access token) with no revocation mechanism.
- Session cookies without `HttpOnly`, `Secure`, or `SameSite`.

**Vulnerable code:**

```javascript
const payload = jwt.decode(req.headers.authorization.split(" ")[1]); // ⚠️ no verification
req.user = payload;
```

**Fix:**

```javascript
const token = req.headers.authorization.split(" ")[1];
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ["HS256"], // ✅ 'none' not possible
  issuer: "my-app",
  audience: "my-app-clients",
});
req.user = payload;
```

**Typical severity:** Critical.

---

### A01.10 - New features with no default control

**CWE-1188** - Insecure Default Initialization of Resource

**Pattern:** a recently added route or feature does not follow the authentication pattern used by the rest of the application. Often introduced during rapid development or an incomplete copy-paste.

**Detection, look for:**

- Routes defined without the project's standard auth middleware while other routes in the same file have it.
- Debug/test endpoints left in production (`/debug`, `/_test`, `/__internal`).
- Missing `deny by default` configuration: a router that registers routes with no root middleware.

**Typical severity:** depends on what the route exposes; often High because these routes tend to be overlooked in regular audits.

---

### A01.11 - GraphQL: missing authorization on fields and mutations

**CWE-285** - Improper Authorization

> **Applicable only to applications using GraphQL.** Signal: `graphql`, `apollo-server`, `@nestjs/graphql`, `nexus`, `pothos` dependencies in `package.json`.

**Pattern:** GraphQL exposes by default every field declared in the schema. Without explicit authorization checks in each resolver, sensitive data becomes accessible to any authenticated caller (or even an unauthenticated one). Protection in the user interface does not protect the GraphQL endpoint, any client can craft the appropriate query.

**Detection, look for:**

```javascript
// ❌ Sensitive fields accessible without verification in the schema
const typeDefs = gql`
  type User {
    id: ID!
    name: String!
    email: String!
    adminNotes: String # ⚠️ accessible to any authenticated user
    passwordHash: String # ⚠️ should never appear in the schema
    ssn: String # ⚠️ sensitive personal data exposed
  }
`;

// ❌ Resolver with no user context check
const resolvers = {
  Mutation: {
    deleteUser: async (_, { id }) => {
      // Accessible to any caller, no role check
      return User.findByIdAndDelete(id);
    },
    updateUserRole: async (_, { id, role }) => {
      // Mass assignment via GraphQL, privilege escalation possible
      return User.findByIdAndUpdate(id, { role });
    },
  },
  Query: {
    users: async () => User.find(), // ⚠️ access to all users with no tenant filter
  },
};
```

**Fix, per-field authorization with graphql-shield:**

```javascript
// ✅ graphql-shield: centralized, composable authorization rules
const { shield, and, or, rule, allow, deny } = require("graphql-shield");

const isAuthenticated = rule({ cache: "contextual" })(
  async (parent, args, ctx) => ctx.user !== null,
);

const isAdmin = rule({ cache: "contextual" })(
  async (parent, args, ctx) => ctx.user?.role === "admin",
);

const isOwner = rule({ cache: "strict" })(
  async (parent, args, ctx) => parent.id === ctx.user?.id,
);

const permissions = shield({
  Query: {
    users: isAdmin,
    user: isAuthenticated, // ownership is checked in the resolver
  },
  User: {
    email: or(isOwner, isAdmin), // accessible only by the owner or an admin
    adminNotes: isAdmin, // admin only
    passwordHash: deny, // never exposed
    ssn: deny, // never exposed
  },
  Mutation: {
    deleteUser: isAdmin,
    updateUserRole: isAdmin,
    updateProfile: isAuthenticated, // ownership check in the resolver
  },
});

// Integration into Apollo Server v4
const server = new ApolloServer({
  schema: applyMiddleware(schema, permissions),
});
```

**Alternative fix, inline verification in each resolver:**

```javascript
// ✅ If graphql-shield is not used, systematic check in each resolver
Mutation: {
  deleteUser: async (_, { id }, { user }) => {
    if (!user) throw new AuthenticationError('Not authenticated');
    if (user.role !== 'admin') throw new ForbiddenError('Admins only');
    return User.findByIdAndDelete(id);
  },
  updateProfile: async (_, { id, data }, { user }) => {
    if (!user) throw new AuthenticationError('Not authenticated');
    if (user.id !== id && user.role !== 'admin') throw new ForbiddenError('Access denied');
    // Filter allowed fields (avoid GraphQL mass assignment)
    const { name, bio } = data; // never `role`, `isAdmin`, etc.
    return User.findByIdAndUpdate(id, { name, bio });
  }
}
```

**Additional points to check:**

- **Mass assignment via mutation**: an `updateUser` mutation accepting fields such as `role`, `isAdmin`, `permissions` as arguments.
- **BOLA (Broken Object Level Authorization)**: a resolver returning an object by ID with no ownership check (the GraphQL equivalent of IDOR).
- **Unbounded batching**: batched queries allowing bulk extraction of other users' data via arbitrary IDs.
- **Introspection in production**: exposes the full schema to an attacker, letting them map unprotected mutations (see A05.12).

**Typical severity:** Critical (admin mutation with no auth, mass assignment escalating to admin) to High (access to other users' data via BOLA, sensitive fields in the schema).

---

## Cross-cutting remediation rules

These rules are not findings in themselves but should guide recommendations.

1. **Deny by default**: every request denied unless explicitly authorized.
2. **Single Policy Enforcement Point**: every request passes through a control point (middleware, gateway) before reaching business logic.
3. **Centralize authorization logic**: Voters (Symfony), Policies (Laravel), permission classes (Django/DRF), `@PreAuthorize` (Spring). Avoid duplicating rules across multiple controllers.
4. **Permissions rather than roles alone**: prefer `user.can('DELETE_ACCOUNT')` over `user.role === 'ADMIN'`. Roles group permissions together, but the decision should be based on the precise permission.
5. **Object-level authorization**: check access to the resource _instance_, not just its type. Being able to read invoices is not the same as being able to read _this_ invoice.
6. **Never trust the client**: any data from the body/query/header can be forged. The source of truth remains the server (verified JWT, session, database lookup).
7. **Sessions and tokens**: invalidation on logout, short lifetimes for access tokens, refresh tokens stored and revocable.
8. **Strict CORS**: explicit allowlist, no loose regex, `Vary: Origin` when the value is dynamic.
9. **Path traversal**: resolution + containment check, or an allowlist mapping identifiers to predefined paths.

---

## Severity classification aid

When an A01 finding is identified, use this grid to calibrate:

| Finding criteria                                                                                                                   | Severity         |
| ---------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| Exploitable with no authentication + access to sensitive data or takeover (escalation to admin, arbitrary reading of system files) | 🔴 Critical      |
| Exploitable by any authenticated user, exposes other users' data (IDOR on a sensitive resource, CSRF on a critical action)         | 🟠 High          |
| Conditional exploitation (CSRF on a moderate action, permissive CORS on a low-sensitivity API, partial escalation)                 | 🟡 Medium        |
| Risky pattern but with no direct exploitable vector (suboptimal configuration, defense-in-depth only)                              | 🟢 Low           |
| Best practice not followed with no exploitation risk (e.g., roles used where permissions would be preferable)                      | ℹ️ Informational |

---

---

## Common false positives - A01

| Detected pattern                                                   | Reason for false positive                                                  | How to verify                                                                                    |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `findById(req.params.id)` with no visible `userId` check           | The ownership check may be in a global middleware or a route guard         | Verify the middleware chain in the router; look for `isOwner`, `canAccess`, `authorize` upstream |
| CORS `Access-Control-Allow-Origin: *`                              | Acceptable on public routes that do not serve sensitive data               | Check whether the route exposes user data or mutating operations                                 |
| Role-based access with no explicit check in the handler            | The control may be centralized in a decorator or a policy object           | Look for `@Roles()`, `@Guard()`, `can()`, `gate()`, `policy()` in the context                    |
| `isAdmin` read from the JWT with no re-verification against the DB | Acceptable if the JWT has a short lifetime and a revocation mechanism      | Check the token's `exp` and the existence of a revocation list                                   |
| Multi-tenant: no visible `tenantId` filter                         | The filter may be injected globally via a tenant-aware ORM or a middleware | Look for `setTenantId`, `withTenant`, `TenantScope` in the ORM configuration                     |

---

## Finding template for the report

Reproduce this format in the report produced by the orchestrator. Adapt the language of the code excerpts to that of the audited project.

````
**[OWASP-A01-NNN]** - [Short title]

- **Severity:** [level + icon]
- **Confidence:** 🔵 High / 🟣 Medium / ⚪ Low `[MANUAL VERIFICATION REQUIRED if Low]`
- **Remediation effort:** Low (<1h) / Medium (1-4h) / High (>4h) / Architectural
- **Justification:** [1 sentence]
- **Sub-type:** A01.X - [sub-type name]
- **Location:** [file:line / endpoint]
- **Description:** [explanation of the mechanism]
- **Potential impact:** [what an attacker can do]
- **Evidence / Vulnerable example:**
  ```[language]
  // excerpt from the audited code
````

- **Recommendation:** [concrete action]
- **Remediation example:**
  ```[language]
  // fixed version
  ```
- **References:** [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) | [OWASP A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

```

---

## Limitations of static analysis for A01

Some access control flaws are only detectable dynamically or with functional knowledge:

- Access to another tenant's resource that is not marked in the code by an obvious field (implicit tenant_id, schema-based multi-tenancy).
- Business logic granting access via a chain of relationships (user → team → project → resource): static auditing can flag the absence of a check but cannot confirm its functional insufficiency.
- Race conditions on authorization checks (TOCTOU).

Mention these limitations in the "Limitations" section of the report when relevant.
```
