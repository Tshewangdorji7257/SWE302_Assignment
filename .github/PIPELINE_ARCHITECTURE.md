# Security Analysis Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GITHUB REPOSITORY                                    │
│                     SWE302_Assignment (main branch)                          │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │
                               │ Push / PR / Schedule
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       GITHUB ACTIONS WORKFLOW                                │
│                    security-analysis.yml                                     │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │
                ┌──────────────┼──────────────┬──────────────┐
                │              │              │              │
                ▼              ▼              ▼              ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  JOB 1:      │  │  JOB 2:      │  │  JOB 3:      │  │  JOB 4:      │
    │  Snyk Scan   │  │  SonarCloud  │  │  SonarCloud  │  │  OWASP ZAP   │
    │  (SAST)      │  │  Backend     │  │  Frontend    │  │  (DAST)      │
    └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
           │                 │                 │                 │
           │                 │                 │                 │
           ▼                 ▼                 ▼                 ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │                                                                   │
    │  SCAN BACKEND       SCAN FRONTEND        START APPS              │
    │  Dependencies       Dependencies         Backend: :8080          │
    │  • go.mod           • package.json       Frontend: :4100         │
    │                                                                   │
    │  CHECK FOR          ANALYZE CODE         RUN ZAP SCANS           │
    │  • CVEs             • Bugs               • Baseline (passive)    │
    │  • Licenses         • Vulnerabilities    • Full scan (active)    │
    │  • Outdated pkgs    • Code smells        • API testing           │
    │                     • Tech debt                                  │
    │                     • Coverage                                   │
    └──────────────────────────────────────────────────────────────────┘
           │                 │                 │                 │
           │                 │                 │                 │
           ▼                 ▼                 ▼                 ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  Upload to   │  │  Upload to   │  │  Upload to   │  │  Generate    │
    │  GitHub      │  │  SonarCloud  │  │  SonarCloud  │  │  Reports     │
    │  Security    │  │  Dashboard   │  │  Dashboard   │  │  • HTML      │
    │              │  │              │  │              │  │  • JSON      │
    └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
           │                 │                 │                 │
           └─────────────────┴─────────────────┴─────────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  JOB 5:              │
                    │  Security Summary    │
                    │                      │
                    │  • Combine results   │
                    │  • Generate report   │
                    │  • Post PR comment   │
                    │  • Upload artifacts  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  DELIVERABLES        │
                    │                      │
                    │  ✓ GitHub Alerts     │
                    │  ✓ SonarCloud Report │
                    │  ✓ Snyk Dashboard    │
                    │  ✓ ZAP Scan Reports  │
                    │  ✓ Security Summary  │
                    └──────────────────────┘
```

## Pipeline Flow

### 1. **Trigger Events**
- **Push:** Commits to `main` or `develop` branches
- **Pull Request:** PRs targeting `main` or `develop`
- **Schedule:** Weekly scan every Monday at 9 AM UTC
- **Manual:** Can be triggered from Actions tab

### 2. **Job Execution Order**

```
Parallel Execution (Jobs 1-3):
┌────────────────────────────────────────────┐
│ Snyk Scan      (2-3 mins)                  │
│ SonarCloud BE  (3-5 mins)                  │
│ SonarCloud FE  (3-5 mins)                  │
└────────────────────────────────────────────┘
                    ↓
Sequential Execution:
┌────────────────────────────────────────────┐
│ OWASP ZAP      (10-15 mins)                │
│   depends on: Snyk + SonarCloud            │
└────────────────────────────────────────────┘
                    ↓
┌────────────────────────────────────────────┐
│ Security Summary (1 min)                   │
│   depends on: All previous jobs            │
└────────────────────────────────────────────┘
```

**Total Execution Time:** ~15-20 minutes

### 3. **Security Checks**

#### Snyk (Dependency Scanning)
```
Input:  go.mod, package.json
Checks: 
  - Known CVEs
  - License compliance
  - Outdated packages
Output: SARIF → GitHub Security tab
```

#### SonarCloud (Static Analysis)
```
Input:  Source code (.go, .js, .jsx)
Checks:
  - Code quality (A-F grade)
  - Security vulnerabilities
  - Code smells
  - Test coverage
  - Technical debt
Output: Dashboard → sonarcloud.io
```

#### OWASP ZAP (Dynamic Testing)
```
Input:  Running applications
Checks:
  - Missing security headers
  - XSS vulnerabilities
  - SQL injection
  - CSRF vulnerabilities
  - API security issues
Output: HTML/JSON reports → Artifacts
```

### 4. **Results & Notifications**

#### GitHub Security Tab
- All Snyk findings
- Code scanning alerts
- Dependency alerts

#### SonarCloud Dashboard
- Quality gate status
- New/fixed issues
- Coverage trends
- Code metrics

#### Pull Request Comments
- Automated comment with summary
- Pass/fail status for each tool
- Links to detailed reports

#### Artifacts (Downloadable)
- `zap-reports/` - OWASP ZAP scan results
- `security-summary.md` - Combined report

## Security Gates

### ❌ Build Fails If:
- Critical SQL injection found
- Critical XSS vulnerability found
- High severity dependency vulnerability
- Quality gate failed in SonarCloud

### ⚠️ Build Warns If:
- Medium severity vulnerabilities
- Missing security headers
- Low test coverage (<80%)
- Code smells detected

### ✅ Build Passes If:
- All critical issues resolved
- No high severity vulnerabilities
- Quality gate passed
- Test coverage acceptable

## Integration Points

### GitHub
```
Repository Settings:
├── Secrets (SNYK_TOKEN, SONAR_TOKEN)
├── Actions (Workflows)
├── Security (Alerts)
└── Branches (Protection rules)
```

### External Services
```
Snyk:        app.snyk.io
  └── Projects: Backend, Frontend

SonarCloud:  sonarcloud.io
  └── Projects: realworld-backend, realworld-frontend

Docker Hub:  hub.docker.com
  └── Image: zaproxy/zap-stable
```

## Data Flow

```
Source Code → GitHub Push
    ↓
GitHub Actions Triggered
    ↓
┌─────────────────────────────────────┐
│ Checkout code                       │
│ Setup environments (Go, Node)       │
│ Install dependencies                │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│ Run Security Scans (parallel)       │
│   • Snyk → GitHub API               │
│   • SonarCloud → SonarCloud API     │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│ Start Applications                  │
│   • Backend on :8080                │
│   • Frontend on :4100               │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│ Run OWASP ZAP Scan                  │
│   • Baseline scan (passive)         │
│   • Full scan (active attacks)      │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│ Generate Reports                    │
│   • Combine all results             │
│   • Upload artifacts                │
│   • Post PR comment                 │
└─────────────────────────────────────┘
    ↓
Results Available:
  • GitHub Security tab
  • SonarCloud dashboard
  • Snyk dashboard
  • Downloadable reports
```

## Monitoring & Maintenance

### Weekly Tasks
- [ ] Review security alerts in GitHub
- [ ] Check SonarCloud quality trends
- [ ] Update dependencies with Snyk fixes
- [ ] Review ZAP scan reports

### Monthly Tasks
- [ ] Review and update ZAP rules
- [ ] Update SonarCloud quality profiles
- [ ] Review false positives
- [ ] Update documentation

### Quarterly Tasks
- [ ] Security audit of entire codebase
- [ ] Review and update security policies
- [ ] Update workflow configurations
- [ ] Professional penetration testing

## Metrics & KPIs

Track these metrics over time:

### Vulnerability Metrics
- Total vulnerabilities found
- Critical/High/Medium/Low breakdown
- Mean time to remediate
- Vulnerability density (per 1000 LOC)

### Code Quality Metrics
- SonarCloud quality gate status
- Technical debt ratio
- Code coverage percentage
- Duplications percentage

### Process Metrics
- Pipeline success rate
- Average execution time
- False positive rate
- Developer remediation rate

---

**Architecture Version:** 1.0  
**Last Updated:** December 2, 2025
