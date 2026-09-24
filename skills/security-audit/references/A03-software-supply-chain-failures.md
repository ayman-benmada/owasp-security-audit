# A03: Software Supply Chain Failures

**Examples are illustrative; transpose each pattern to the detected stack and verify that the relevant code runs in the claimed execution context.**

**Reference:** OWASP Top 10 (2025), category A03
**Key CWEs:** CWE-1104, CWE-1329, CWE-1357, CWE-1395
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
- The vulnerable dependency is only present in `devDependencies` and is not included in the production bundle (this lowers runtime exposure only: dev dependencies still execute on developer machines and in CI, so a malicious package remains a risk there)
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
- **SBOM and signatures**: presence or absence of an artifact inventory and signature verification policy.

If a surface is not provided, note it in the "Limitations" section of the report.

### 2. Go through the sub-types

For each sub-type, apply the patterns. A single surface can concentrate several findings (e.g., a `package.json` with floating versions plus known vulnerable dependencies plus a suspicious `postinstall`).

### 3. Distinguish structural risk from active vulnerability

A03 contains many findings that are **organizational weaknesses** (no lockfile, no SBOM) without a directly associated CVE. Calibrate severity accordingly: structural risk is rarely Critical on its own, but it strongly amplifies the impact of a supply chain compromise.

---

## Sub-types and Detection Patterns

> The examples below use the Node.js/npm ecosystem for readability. **Transpose each pattern to the actual ecosystem in use**: the Composer (PHP), pip (Python), Maven/Gradle (Java), Go modules, and Bundler (Ruby) equivalents are noted where relevant.

---

### A03.1: Known Vulnerable Components

**CWE-1395**: Dependency on Vulnerable Third-Party Component | **CWE-1104**: Use of Unmaintained Third Party Components

**Pattern:** the application integrates third-party components with known, unpatched CVEs. This can result from a lack of vigilance or from a deliberate decision (compatibility constraints).

**Detection, look for:**

- Versions explicitly pinned in dependency files that correspond to versions known to be vulnerable (cross-reference with public databases: NVD, GitHub Advisory, Snyk).
- Dependencies with a significant version gap compared to the latest stable release: a signal of stagnation.
- Packages with no update for 2+ years that have open security issues.
- Unaddressed `npm audit` / `composer audit` results (present in the code but with no remediation process).

**Special case, transitive dependencies:** the vulnerability may not be in a direct dependency but in a dependency of a dependency. Without an analysis of the complete graph (lockfile + SBOM), these exposures remain invisible.

**Note on accepted decisions:** a vulnerable version intentionally kept for compatibility reasons must be documented (accepted risk, remediation plan, compensating measures). Its absence is itself a finding.

**Standard fix:** update to the patched version (for example with `npm audit fix`, run by the project team, not by the auditor), or replace with a maintained alternative. If the update is blocking, formally document the accepted risk along with a review date.

**Typical severity:** 🔴 Critical (critical CVE remotely exploitable without authentication) to 🟡 Medium (local or low-impact CVE).

---

### A03.2: Lack of Visibility into Transitive Dependencies

**CWE-1357**: Reliance on Insufficiently Trustworthy Component

**Pattern:** only direct dependencies are audited. The actual graph, often 10x larger, remains opaque. Deep vulnerabilities in the dependency tree go unnoticed.

**Detection, look for:**

- Absence of a lockfile (`package-lock.json`, `composer.lock`, `Pipfile.lock`, `go.sum`): without a lockfile, the transitive tree is not fixed.
- No SBOM generated during the build.
- Pipeline using `npm install` instead of `npm ci` (does not guarantee reproducibility of the dependency tree).
- No dependency-vulnerability monitoring visible in the provided build and deployment scope.

**Typical severity:** Informational or Low without a demonstrated vulnerable dependency or exploitable build path. Record missing visibility as a limitation when pipeline and inventory information are unavailable.

---

### A03.3: Unpinned Versions (Floating Dependencies)

**CWE-1357**: Reliance on Insufficiently Trustworthy Component

**Pattern:** dependencies are declared with flexible version operators (`^`, `~`, `latest`, `*`), allowing a different version, potentially malicious or vulnerable, to be installed on every build without any visible change to the source code.

**Vulnerable code:**

```jsonc
// ❌ package.json - floating versions
{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "latest"
  }
}
```

**Fix:**

```jsonc
// ✅ package.json - pinned versions
{
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21"
  }
}
```

**Important point:** pinning versions in `package.json` is not enough. A lockfile records the resolved dependency tree; check the actual package manager and lockfile format for integrity metadata. For npm projects with a lockfile, `npm ci` fails if the lockfile is missing or inconsistent with the manifest and avoids updating it. This improves reproducibility, but does not prove that every artifact or install script is safe.

```bash
# ❌ Vulnerable CI
npm install

# ✅ Reproducible CI
npm ci
```

**Equivalents:** `composer install --no-dev` (PHP), `pip install -r requirements.txt` with `pip-compile` (Python), `go mod download` with a verified `go.sum` (Go).

**Typical severity:** Low to Medium when the effective build is unpinned. A present, enforced lockfile can eliminate the asserted floating-version path.

---

### A03.4: Absence of an SBOM (Software Bill of Materials)

**CWE-1357**: Reliance on Insufficiently Trustworthy Component

**Pattern:** no exhaustive inventory of components is generated and maintained. In the event of a compromise, it is impossible to quickly determine which systems are affected.

**Detection, look for:**

- Absence of an `sbom.json` or `sbom.xml` file among the artifacts or in the pipeline.
- No SBOM generation step in the CI/CD.
- No artifact identity or integrity verification visible in the deployment path.

**Recommended workflow:** generate an inventory from the final artifact, associate it with the artifact identity, and verify both before deployment. Choose tooling only after checking the project's actual CI platform and the tool's current official documentation. Any build, scanner, signing, or network command requires the user approval described in the main skill.

**Typical severity:** Informational to Low for absence alone. Raise severity only for a distinct, evidence-backed integrity or vulnerability-management failure.

---

### A03.5: Absence of Vulnerability Scanning in CI and After Deployment

**CWE-1395**: Dependency on Vulnerable Third-Party Component

**Pattern:** no automated tool blocks the build over known vulnerabilities, and no system monitors new CVEs after deployment. A vulnerability published against a dependency of an application deployed 6 months ago will not trigger any alert.

**Detection, look for:**

- No dependency vulnerability check visible in the complete CI pipeline.
- No monitoring for new advisories against deployed dependency versions visible in the provided scope.
- A build that passes despite high-severity `npm audit` findings.

**Recommended combination:** check known vulnerabilities at build time and monitor deployed versions for newly published advisories. Verify that a scanner is absent from the whole pipeline before calling it a gap. Do not query an external database without the user's approval.

**Typical severity:** Informational to Medium depending on a documented vulnerability-management requirement and the visibility of external monitoring. Absence of a scanner call in one repository is not proof that no scanning exists.

---

### A03.6: Insufficiently Secured CI/CD Pipeline

**CWE-1357**: Reliance on Insufficiently Trustworthy Component

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

**CWE-1357**: Reliance on Insufficiently Trustworthy Component

**Pattern:** an attacker publishes a package whose name imitates a legitimate library (e.g., `lodahs` instead of `lodash`, `expres` instead of `express`). A typo when declaring a dependency silently installs the malicious package.

**Detection, look for:**

- Package names close to popular libraries but with a slight variation (transposed letter, similar-looking character, unusual suffix).
- Packages with very few downloads that claim to be common utilities.
- Packages with no associated GitHub repository, no identifiable maintainer, or published very recently.
- `preinstall` / `postinstall` scripts in the installed package's `package.json`: an arbitrary code execution vector during installation.

**Standard fix:**

- Carefully verify package names before declaring any dependency.
- Use an internal proxy registry that only allows approved packages.
- Regularly review dependencies' install scripts; use install-time script restrictions where compatible. Note that `npm audit` only reports known advisories, it does not inspect install scripts.

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

**CWE-1357**: Reliance on Insufficiently Trustworthy Component

**Pattern:** IDE extensions often carry broad permissions on the host system (access to source code, SSH tokens, configuration files) and rarely receive the same level of scrutiny as application dependencies. A compromised extension can inject code, intercept secrets, or exfiltrate data.

**Detection, look for:**

- Absence of an approved-extensions policy within the organization (allowlist).
- Extensions installed from unofficial marketplaces or from unknown maintainers.
- Extensions with broad permissions and no apparent justification.
- No process for updating extensions or tracking their associated vulnerabilities.

**Standard fix:** define and maintain an allowlist of validated extensions, restrict installation to official sources, include IDE extensions within the security audit scope, and apply security updates.

**Typical severity:** Informational unless a specific extension, distribution path, privilege, and exposure are evidenced.

---

## Cross-cutting Remediation Rules

1. **Pin + lockfile + frozen install**: use the package manager's documented frozen install mode for the actual project; for npm projects, `npm ci` uses the existing lockfile without updating it.
2. **SBOM generated on the final artifact**: after dependency resolution and after the Docker build, not on the source folder.
3. **Sign and verify with identity restriction**: verify the signature and the identity of the expected build pipeline before deployment, using tooling documented for the actual platform.
4. **Scan and monitor**: check known CVEs at build time and monitor deployed component versions for newly published advisories.
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
| Verified remotely exploitable vulnerability in a reachable production dependency with severe impact, or confirmed code substitution in a privileged build | 🔴 Critical |
| Verified applicable high-impact vulnerability in a reachable component; attacker-controlled pipeline step with access to sensitive assets | 🟠 High |
| Confirmed reachable vulnerable component with limited impact, or a concrete supply chain weakness with a demonstrated substitution path and limited privileges | 🟡 Medium |
| Absence of an SBOM alone; lockfile present but `npm install` used in CI; missing post-deployment monitoring without a demonstrated exposure | Investigate; do not assign severity yet |
| Absence of IaC, a proxy registry, or documentation with no demonstrated exposure | Informational observation only |

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

## Finding template for the report

Use the finding block defined in `references/report-format.md`. Category-specific fields:

- **Sub-type:** A03.X - [sub-type name]
- **Severity justification:** [1 sentence; specify whether the affected component or pipeline step actually reaches production or has access to secrets]
- **References:** [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) | [OWASP A03:2025 - Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/) | [OWASP Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)

---

## Limitations of Static Analysis for A03

A03 is particularly dependent on the state of the runtime and of external systems:

- **CVEs on dependencies**: requires an active check against up-to-date databases; a static analysis of `package.json` without querying a vulnerability database cannot conclusively determine the presence of a CVE.
- **Typosquatting**: visually detectable from suspicious names, but a thorough verification requires querying the npm registry (download count, creation date, maintainer).
- **Maintainer compromise**: not statically detectable; requires monitoring and provenance review beyond the provided source files.
- **Actual content of artifacts**: a `Dockerfile` without a `.dockerignore` is a signal, but only `docker image inspect` on the built image confirms what is actually embedded.
- **Effective pipeline permissions**: workflow files declare the requested permissions, but the secrets actually accessible depend on the organization's GitHub/GitLab configuration.

Mention these limitations in the "Limitations" section of the report and propose the relevant dynamic verification commands (with explicit validation, in accordance with the orchestrator's protocol).
