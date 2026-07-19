# A03: Software Supply Chain Failures

**Reference:** OWASP Top 10 (2025), category A03
**Main associated CWEs:** CWE-494, CWE-506, CWE-829, CWE-830, CWE-937, CWE-1104
**Finding format:** `OWASP-A03-NNN`

This file is loaded by the `owasp-security-audit` orchestrator skill when analyzing category A03. It provides the detection patterns, standard fixes, and the severity grid specific to software supply chain failures.

---

## Definition

The software supply chain refers to the set of actors, tools, and processes involved in producing and distributing software: third-party dependencies, package managers, code repositories, CI/CD pipelines, container images, IDE extensions, and development environments.

The risks rest on two structural factors:

- **Implicit trust**: installing a dependency amounts to trusting the package, its maintainers, the registry hosting it, and the entirety of its transitive dependencies, often without thorough verification.
- **Shared execution scope**: third-party components run with the same privileges as the application. A compromised component does not need to exploit a vulnerability: it already has direct access to the execution environment.

Guiding principle: **verify rather than trust**. Every link in the chain (dependency, artifact, pipeline, tool) must be auditable, pinned, and signed.

---

## Attack Surface: Exploitability Prerequisites

Before declaring an A03 finding, verify that **the vulnerable dependency is actually used in the execution path**. Typical vectors:

- Direct dependencies with a known CVE imported into production code
- Transitive dependencies with a vulnerability that is exploitable via the API being used
- Packages installed from unofficial sources or with a similar name (typosquatting)
- CI/CD using actions/images without a fixed integrity hash

**Cases where the finding should be downgraded or dismissed:**

- The CVE concerns a feature of the dependency that is not used in this project
- The vulnerable dependency is only present in `devDependencies` and is not included in the production bundle
- A lock file (`package-lock.json`, `yarn.lock`, `composer.lock`) is present and fixes the version: the risk is limited to the locked version
- The vulnerability requires specific network access or a configuration that is absent from this project

---

## Detection Methodology

A03 covers very different surfaces: application dependencies, the CI/CD pipeline, development tools. First identify what is analyzable within the scope provided.

### 1. Identify the surfaces present

- **Dependency files**: `package.json`, `package-lock.json`, `composer.json`, `composer.lock`, `requirements.txt`, `Pipfile.lock`, `pom.xml`, `go.mod`, `Gemfile.lock`.
- **CI/CD pipeline**: `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, build scripts.
- **Container configuration**: `Dockerfile`, `.dockerignore`, registry configuration.
- **Build tools**: Webpack/Vite configuration, `postinstall` scripts, npm hooks.
- **SBOM and signatures**: presence/absence of `sbom.json`, cosign/sigstore configuration.

If a surface is not provided, note it in the "Limitations" section of the report.

### 2. Go through the sub-types

For each sub-type, apply the patterns. A single surface can concentrate several findings (e.g., a `package.json` with floating versions plus known vulnerable dependencies plus a suspicious `postinstall`).

### 3. Distinguish structural risk from active vulnerability

A03 contains many findings that are **organizational weaknesses** (no lockfile, no SBOM) without a directly associated CVE. Calibrate severity accordingly: structural risk is rarely Critical on its own, but it strongly amplifies the impact of a supply chain compromise.

---

## Sub-types and Detection Patterns

> The examples below use the Node.js/npm ecosystem since it is the main context of the audited project. **Transpose each pattern to the actual ecosystem in use**: the Composer (PHP), pip (Python), Maven/Gradle (Java), Go modules, and Bundler (Ruby) equivalents are noted where relevant.

---

### A03.1: Known Vulnerable Components

**CWE-937**: OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities | **CWE-1104**: Use of Unmaintained Third Party Components

**Pattern:** the application integrates third-party components with known, unpatched CVEs. This can result from a lack of vigilance or from a deliberate decision (compatibility constraints).

**Detection, look for:**

- Versions explicitly pinned in dependency files that correspond to versions known to be vulnerable (cross-reference with public databases: NVD, GitHub Advisory, Snyk).
- Dependencies with a significant version gap compared to the latest stable release: a signal of stagnation.
- Packages with no update for 2+ years that have open security issues.
- Unaddressed `npm audit` / `composer audit` results (present in the code but with no remediation process).

**Special case, transitive dependencies:** the vulnerability may not be in a direct dependency but in a dependency of a dependency. Without an analysis of the complete graph (lockfile + SBOM), these exposures remain invisible.

**Note on accepted decisions:** a vulnerable version intentionally kept for compatibility reasons must be documented (accepted risk, remediation plan, compensating measures). Its absence is itself a finding.

**Standard fix:** `npm audit fix`, update to the patched version, or replacement with a maintained alternative. If the update is blocking, formally document the accepted risk along with a review date.

**Typical severity:** 🔴 Critical (critical CVE remotely exploitable without authentication) to 🟡 Medium (local or low-impact CVE).

---

### A03.2: Lack of Visibility into Transitive Dependencies

**CWE-829**: Inclusion of Functionality from Untrusted Control Sphere

**Pattern:** only direct dependencies are audited. The actual graph, often 10x larger, remains opaque. Deep vulnerabilities in the dependency tree go unnoticed.

**Detection, look for:**

- Absence of a lockfile (`package-lock.json`, `composer.lock`, `Pipfile.lock`, `go.sum`): without a lockfile, the transitive tree is not fixed.
- No SBOM generated during the build.
- Pipeline using `npm install` instead of `npm ci` (does not guarantee reproducibility of the dependency tree).
- No software composition analysis tool (Grype, Dependabot, Snyk) configured.

**Typical severity:** 🟡 Medium to 🟠 High (depending on the depth and potential criticality of the unaudited dependencies).

---

### A03.3: Unpinned Versions (Floating Dependencies)

**CWE-494**: Download of Code Without Integrity Check

**Pattern:** dependencies are declared with flexible version operators (`^`, `~`, `latest`, `*`), allowing a different version, potentially malicious or vulnerable, to be installed on every build without any visible change to the source code.

**Vulnerable code:**

```json
// ❌ package.json - floating versions
{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "latest"
  }
}
```

**Fix:**

```json
// ✅ package.json - pinned versions
{
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21"
  }
}
```

**Important point:** pinning versions in `package.json` is not enough. Reproducibility relies on the lockfile, which captures the complete tree along with checksums. In CI, it is essential to use `npm ci` (which fails if `package-lock.json` is missing or inconsistent) rather than `npm install`.

```bash
# ❌ Vulnerable CI
npm install

# ✅ Reproducible CI
npm ci
```

**Equivalents:** `composer install --no-dev` (PHP), `pip install -r requirements.txt` with `pip-compile` (Python), `go mod download` with a verified `go.sum` (Go).

**Typical severity:** 🟡 Medium (structural risk) to 🟠 High if `latest` is used on a high-impact dependency.

---

### A03.4: Absence of an SBOM (Software Bill of Materials)

**CWE-494**: Download of Code Without Integrity Check

**Pattern:** no exhaustive inventory of components is generated and maintained. In the event of a compromise, it is impossible to quickly determine which systems are affected.

**Detection, look for:**

- Absence of an `sbom.json` or `sbom.xml` file among the artifacts or in the pipeline.
- No SBOM generation step in the CI/CD.
- No cosign or sigstore attestation associated with the Docker images.

**Recommended workflow (npm + Docker):**

```bash
# 1. Resolve dependencies
npm ci

# 2. Build the image
docker build -t myapp:1.2.3 .

# 3. Generate the SBOM on the final image (not on the source folder)
syft packages myapp:1.2.3 -o cyclonedx-json > sbom.json

# 4. Sign the image and attach the SBOM
cosign sign --yes myapp:1.2.3
cosign attest --predicate sbom.json --type cyclonedx myapp:1.2.3

# 5. Verify the signature at deployment (with identity restriction)
cosign verify myapp:1.2.3 \
  --certificate-identity-regexp "https://github.com/myorg/myrepo/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

**Critical point about verification:** `cosign verify` without `--certificate-identity-regexp` is insufficient: it only verifies that a valid signature exists, not that it originates from this pipeline. Anyone could sign the image with their own credentials.

**Typical severity:** 🟢 Low (absence alone) to 🟠 High if combined with the absence of vulnerability scanning and signing.

---

### A03.5: Absence of Vulnerability Scanning in CI and After Deployment

**CWE-937**: Using Components with Known Vulnerabilities

**Pattern:** no automated tool blocks the build over known vulnerabilities, and no system monitors new CVEs after deployment. A vulnerability published against a dependency of an application deployed 6 months ago will not trigger any alert.

**Detection, look for:**

- Absence of an `npm audit`, `composer audit`, Grype, or Snyk step in the CI pipeline.
- Absence of Dependabot, Renovate, or Dependency-Track configured.
- A build that passes despite high-severity `npm audit` findings.

**Recommended combination:**

```yaml
# GitHub Actions - block in CI with Grype
- name: Scan vulnerabilities
  uses: anchore/scan-action@v3
  with:
    sbom: sbom.json
    fail-build: true
    severity-cutoff: high
```

```bash
# Or via the command line
grype sbom:./sbom.json --fail-on high

# Send the SBOM to Dependency-Track for continuous monitoring
curl -X PUT https://dtrack.interne.exemple.com/api/v1/bom \
  -H "X-Api-Key: $DT_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"project\": \"uuid\", \"bom\": \"$(base64 -w 0 sbom.json)\"}"
```

**Complementary logic:** Grype blocks in CI on CVEs known at build time. Dependency-Track alerts on CVEs published after deployment. Both use the same `sbom.json`.

**Typical severity:** 🟡 Medium (no CI scanning) to 🟠 High (no post-deployment monitoring on a publicly exposed app).

---

### A03.6: Insufficiently Secured CI/CD Pipeline

**CWE-829**: Inclusion of Functionality from Untrusted Control Sphere | **CWE-732**: Incorrect Permission Assignment for Critical Resource

**Pattern:** the pipeline has privileged access (secrets, registries, production environments) but is secured with less rigor than the application itself. A compromised pipeline can modify artifacts, exfiltrate secrets, or deploy malicious code while bypassing every application-level control.

**Detection, look for, in workflow files:**

**Overly broad permissions on the CI token:**

```yaml
# ❌ Default permissions - GITHUB_TOKEN with broad rights
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      # A malicious postinstall script can exploit GITHUB_TOKEN
      # to push code into the repository

# ✅ Explicit minimal permissions
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
```

**Third-party actions referenced by tag rather than by hash:**

```yaml
# ❌ Mutable tag - may point to a different commit tomorrow
- uses: actions/checkout@v4

# ✅ Immutable hash - guarantees the exact version used
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

**Secrets not separated according to their sensitivity:**

- Repository secrets accessible to all workflows without validation: should be reserved for non-critical uses.
- Production secrets: should be environment secrets with approval and restrictions.

**Absence of separation of duties:**

- Direct push to the main branch without a mandatory PR or review.
- Absence of "required reviewers" on sensitive environments.
- The same person can introduce code and deploy it to production with no control.

**Typical severity:** 🟠 High to 🔴 Critical (depending on the pipeline's effective access to production environments).

---

### A03.7: Compromise via Typosquatting

**CWE-506**: Embedded Malicious Code | **CWE-830**: Inclusion of Web Functionality from an Untrusted Source

**Pattern:** an attacker publishes a package whose name imitates a legitimate library (e.g., `lodahs` instead of `lodash`, `expres` instead of `express`). A typo when declaring a dependency silently installs the malicious package.

**Detection, look for:**

- Package names close to popular libraries but with a slight variation (transposed letter, similar-looking character, unusual suffix).
- Packages with very few downloads that claim to be common utilities.
- Packages with no associated GitHub repository, no identifiable maintainer, or published very recently.
- `preinstall` / `postinstall` scripts in the installed package's `package.json`: an arbitrary code execution vector during installation.

**Standard fix:**

- Carefully verify package names before declaring any dependency.
- Use an internal proxy registry that only allows approved packages.
- Regularly audit dependencies' `postinstall` scripts: `npm audit` and `npm install --ignore-scripts` (when compatible) reduce the automatic execution surface.

**Typical severity:** 🔴 Critical (arbitrary code execution upon installation).

---

### A03.8: Unmaintained or Abandoned Components

**CWE-1104**: Use of Unmaintained Third Party Components

**Pattern:** abandoned or unmaintained dependencies expose the application to unpatched vulnerabilities. Aggravating case: inactive maintainer accounts can be compromised and used to publish malicious versions of a historically legitimate component.

**Detection, look for:**

- Packages with no commits for 2+ years in a repository that is still referenced.
- Packages with open security issues and no response from the maintainers.
- Packages with an abnormal recent publication history (unexpected major version, unknown maintainer): a signal of account takeover.
- `package.json` with dependencies pointing to unofficial forks or Git archives.

**Typical severity:** 🟡 Medium (no active CVE) to 🟠 High (critical architectural component, with no alternative and no replacement plan).

---

### A03.9: Uncontrolled IDE Extensions and Development Tools

**CWE-829**: Inclusion of Functionality from Untrusted Control Sphere

**Pattern:** IDE extensions often carry broad permissions on the host system (access to source code, SSH tokens, configuration files) and rarely receive the same level of scrutiny as application dependencies. A compromised extension can inject code, intercept secrets, or exfiltrate data.

**Detection, look for:**

- Absence of an approved-extensions policy within the organization (allowlist).
- Extensions installed from unofficial marketplaces or from unknown maintainers.
- Extensions with broad permissions and no apparent justification.
- No process for updating extensions or tracking their associated vulnerabilities.

**Standard fix:** define and maintain an allowlist of validated extensions, restrict installation to official sources, include IDE extensions within the security audit scope, and apply security updates.

**Typical severity:** 🟡 Medium to 🟠 High (depending on the extension's permissions and the sensitivity of the development environment).

---

## Cross-cutting Remediation Rules

1. **Pin + lockfile + `npm ci`**: fixed versions in the manifest, the complete tree captured in the lockfile, `npm ci` in CI to guarantee reproducibility.
2. **SBOM generated on the final artifact**: after dependency resolution and after the Docker build, not on the source folder.
3. **Sign and verify with identity restriction**: `cosign verify` with `--certificate-identity-regexp` to guarantee that the signature originates from this specific pipeline.
4. **Grype in CI + Dependency-Track continuously**: block on known CVEs at build time, alert on new CVEs after deployment. Both rely on the same SBOM.
5. **Minimal permissions in the pipeline**: `permissions: contents: read` by default, extended only as strictly needed. Third-party actions pinned by hash.
6. **Segmented secrets**: repository secrets for non-critical uses, environment secrets with approval for production.
7. **Separation of duties**: protected main branch (mandatory PR plus review), "required reviewers" on sensitive environments.
8. **Internal proxy registry**: centralized control point over approved packages, caching of validated versions.
9. **IDE extension allowlist**: the same level of rigor as for application dependencies.
10. **Audit of postinstall scripts**: an arbitrary code execution vector at package installation time.

---

## Severity Classification Aid

| Finding criteria                                                                                                                                                                          | Severity         |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| Critical, remotely exploitable CVE on a production dependency; confirmed typosquatting; pipeline with unsecured production access; maintainer account takeover                            | 🔴 Critical      |
| High CVE on an exposed dependency; pipeline lacking minimal permissions with access to secrets; total absence of CI scanning on a publicly exposed app; missing SBOM with no verification | 🟠 High          |
| Floating versions on critical dependencies; unaudited transitive dependencies; unmaintained component with no alternative; IDE extensions with no policy                                  | 🟡 Medium        |
| Absence of an SBOM alone (with no other gap); lockfile present but `npm install` used in CI; missing post-deployment monitoring on a non-critical app                                     | 🟢 Low           |
| Absence of IaC for the pipeline; no proxy registry (with no other gap); missing documentation of an accepted risk                                                                         | ℹ️ Informational |

---

## Common False Positives: A03

| Detected pattern                                     | Reason for false positive                                                 | How to verify                                                                                    |
| ---------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Floating version `^1.2.0` in `package.json`          | A present lock file fixes the actual installed version                    | Check `package-lock.json` or `yarn.lock` for the effective resolved version                      |
| Dependency with a listed CVE                         | The CVE may not affect the usage made of it in this project               | Read the CVE details; check whether the vulnerable feature is used (`grep` for the affected API) |
| Dependency in `devDependencies` with a vulnerability | Not included in production if the build is correctly configured           | Verify that the bundler excludes devDependencies from the production build                       |
| Docker image without a fixed tag                     | `latest` may point to a recent and secure version                         | Check the build date and whether the image is managed by a trusted team                          |
| GitHub Action without a SHA hash                     | Acceptable if the action is official and under the organization's control | Check whether it is an official `actions/` action or a third-party action                        |

---

## Finding Template for the Report

````
**[OWASP-A03-NNN]** - [Short title]

- **Severity:** [level + icon]
- **Confidence:** 🔵 High / 🟣 Medium / ⚪ Low `[MANUAL VERIFICATION REQUIRED if Low]`
- **Remediation effort:** Low (<1h) / Medium (1-4h) / High (>4h) / Architectural
- **Justification:** [1 sentence]
- **Sub-type:** A03.X - [sub-type name]
- **Location:** [file / CI step / Docker image / extension]
- **Description:** [explanation of the mechanism]
- **Potential impact:** [what an attacker can do]
- **Evidence / Vulnerable example:**
  ```[language/format]
  // audited excerpt
````

- **Recommendation:** [concrete action]
- **Remediation example:**
  ```[language/format]
  // fixed version
  ```
- **References:** [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) | [OWASP A03:2025 - Software Supply Chain Failures](https://owasp.org/Top10/)

```

---

## Limitations of Static Analysis for A03

A03 is particularly dependent on the state of the runtime and of external systems:

- **CVEs on dependencies**: requires an active scan (`npm audit`, Grype) against up-to-date databases; a static analysis of `package.json` without querying a vulnerability database cannot conclusively determine the presence of a CVE.
- **Typosquatting**: visually detectable from suspicious names, but a thorough verification requires querying the npm registry (download count, creation date, maintainer).
- **Maintainer compromise**: not statically detectable; requires continuous monitoring (Dependency-Track, GitHub Advisory alerts).
- **Actual content of artifacts**: a `Dockerfile` without a `.dockerignore` is a signal, but only `docker image inspect` on the built image confirms what is actually embedded.
- **Effective pipeline permissions**: workflow files declare the requested permissions, but the secrets actually accessible depend on the organization's GitHub/GitLab configuration.

Mention these limitations in the "Limitations" section of the report and propose the relevant dynamic verification commands (with explicit validation, in accordance with the orchestrator's protocol).
```
