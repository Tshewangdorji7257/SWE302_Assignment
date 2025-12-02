# GitHub Actions Security Pipeline Setup

This document explains the automated security analysis pipeline configured for this repository.

## Overview

The security pipeline automatically runs three security tools:
1. **Snyk** - Dependency vulnerability scanning
2. **SonarCloud** - Static code analysis (SAST)
3. **OWASP ZAP** - Dynamic application security testing (DAST)

## Required Secrets

You need to configure the following secrets in your GitHub repository settings:

### 1. Snyk Token
- **Secret Name:** `SNYK_TOKEN`
- **How to get it:**
  1. Go to https://app.snyk.io/account
  2. Copy your API token
  3. Add to GitHub: Settings → Secrets and variables → Actions → New repository secret

### 2. SonarCloud Token
- **Secret Name:** `SONAR_TOKEN`
- **How to get it:**
  1. Go to https://sonarcloud.io/account/security
  2. Generate a new token
  3. Add to GitHub: Settings → Secrets and variables → Actions → New repository secret

### 3. SonarCloud Organization
- **Secret Name:** `SONAR_ORGANIZATION`
- **Value:** Your SonarCloud organization key (found in SonarCloud dashboard)

### 4. Snyk Organization ID (Optional)
- **Secret Name:** `SNYK_ORG_ID`
- **Value:** Your Snyk organization ID (found in Snyk dashboard)

## SonarCloud Setup

### Step 1: Create SonarCloud Account
1. Go to https://sonarcloud.io/
2. Sign in with your GitHub account
3. Import your repository

### Step 2: Configure Projects
The pipeline creates two SonarCloud projects:
- **Backend:** `realworld-backend`
- **Frontend:** `realworld-frontend`

### Step 3: Update Configuration Files
Edit these files and replace `your-sonarcloud-org` with your actual organization key:
- `golang-gin-realworld-example-app/sonar-project.properties`
- `react-redux-realworld-example-app/sonar-project.properties`

## Workflow Triggers

The security pipeline runs automatically on:
- **Push** to `main` or `develop` branches
- **Pull requests** to `main` or `develop` branches
- **Schedule** - Every Monday at 9 AM UTC
- **Manual trigger** - Can be run manually from Actions tab

## Workflow Jobs

### Job 1: Snyk Dependency Scan
- Scans backend (Go) dependencies
- Scans frontend (npm) dependencies
- Fails on HIGH or CRITICAL vulnerabilities
- Uploads results to GitHub Security tab

### Job 2: SonarCloud Backend Analysis
- Analyzes Go code for bugs, vulnerabilities, code smells
- Runs test coverage
- Uploads coverage reports to SonarCloud
- View results at: https://sonarcloud.io/project/overview?id=realworld-backend

### Job 3: SonarCloud Frontend Analysis
- Analyzes React/JavaScript code
- Runs test coverage
- Checks code quality metrics
- View results at: https://sonarcloud.io/project/overview?id=realworld-frontend

### Job 4: OWASP ZAP Dynamic Scan
- Starts backend and frontend applications
- Runs baseline scan (passive)
- Runs full scan (active attacks)
- Generates HTML/JSON/Markdown reports

### Job 5: Security Summary
- Combines all scan results
- Generates summary report
- Posts comment on pull requests
- Uploads artifacts

## Viewing Results

### GitHub Actions
1. Go to **Actions** tab in your repository
2. Click on the latest workflow run
3. View logs for each job

### Security Tab
1. Go to **Security** tab in your repository
2. Click **Code scanning alerts**
3. View Snyk and other security findings

### SonarCloud Dashboard
1. Go to https://sonarcloud.io/
2. Select your organization
3. View backend and frontend projects
4. Review bugs, vulnerabilities, code smells

### Snyk Dashboard
1. Go to https://app.snyk.io/
2. View your projects
3. Review dependency vulnerabilities
4. Monitor fix status

## Workflow Configuration

The main workflow file is located at:
```
.github/workflows/security-analysis.yml
```

### Customization Options

**Change scan frequency:**
```yaml
schedule:
  - cron: '0 9 * * 1'  # Every Monday at 9 AM
  # Change to: '0 0 * * *' for daily scans
```

**Change severity threshold:**
```yaml
args: --severity-threshold=high
# Options: low, medium, high, critical
```

**Exclude files from SonarCloud:**
Edit `sonar-project.properties`:
```properties
sonar.exclusions=**/vendor/**,**/test/**,**/mock/**
```

## ZAP Scan Configuration

ZAP scanning rules are configured in:
```
.zap/rules.tsv
```

Rules are categorized as:
- **FAIL** - Critical vulnerabilities that fail the build
- **WARN** - Important issues that generate warnings
- **INFO** - Informational findings
- **IGNORE** - False positives or accepted risks

## Troubleshooting

### "SNYK_TOKEN not found"
- Verify secret is added in GitHub Settings → Secrets and variables → Actions
- Check secret name is exactly `SNYK_TOKEN` (case-sensitive)

### "SONAR_TOKEN not found"
- Generate new token from SonarCloud
- Add to GitHub repository secrets
- Make sure the token has admin permissions

### SonarCloud analysis fails
- Check organization key is correct in `sonar-project.properties`
- Verify project keys are unique in SonarCloud
- Check SonarCloud organization settings

### ZAP scan times out
- Increase sleep time in workflow (currently 10s for backend, 30s for frontend)
- Check if applications start successfully in logs
- Consider using Docker compose for reliable startup

### Build fails on tests
- Backend: Ensure CGO is enabled (`CGO_ENABLED=1`)
- Frontend: Check all npm dependencies are installed
- Review test logs in Actions tab

## Manual Execution

### Run Snyk locally:
```bash
# Backend
cd golang-gin-realworld-example-app
snyk test --severity-threshold=high

# Frontend
cd react-redux-realworld-example-app
npm install
snyk test --severity-threshold=high
```

### Run SonarCloud locally:
```bash
# Install SonarScanner
# Download from: https://docs.sonarcloud.io/advanced-setup/ci-based-analysis/sonarscanner-cli/

# Backend
cd golang-gin-realworld-example-app
sonar-scanner \
  -Dsonar.token=$SONAR_TOKEN \
  -Dsonar.organization=your-org

# Frontend
cd react-redux-realworld-example-app
sonar-scanner \
  -Dsonar.token=$SONAR_TOKEN \
  -Dsonar.organization=your-org
```

### Run ZAP locally:
```bash
# Pull ZAP Docker image
docker pull zaproxy/zap-stable

# Run baseline scan
docker run -v $(pwd):/zap/wrk/:rw -t zaproxy/zap-stable \
  zap-baseline.py -t http://localhost:4100 -r report.html
```

## CI/CD Integration

### Status Badges
Add to your README.md:
```markdown
![Security Analysis](https://github.com/Tshewangdorji7257/SWE302_Assignment/workflows/Security%20Analysis%20Pipeline/badge.svg)
```

### Branch Protection
Recommended settings:
1. Go to Settings → Branches → Branch protection rules
2. Add rule for `main` branch
3. Enable:
   - Require status checks to pass before merging
   - Require branches to be up to date before merging
   - Select: `snyk-scan`, `sonarcloud-backend`, `sonarcloud-frontend`

## Artifacts

Each workflow run generates artifacts:
- **snyk-reports** - Vulnerability reports
- **zap-reports** - ZAP scan results (HTML, JSON, Markdown)
- **security-summary** - Combined summary report

Download artifacts from Actions tab → Select workflow run → Artifacts section

## Cost Considerations

### Free Tier Limits
- **GitHub Actions:** 2,000 minutes/month (free for public repos)
- **Snyk:** Unlimited tests for open source
- **SonarCloud:** Free for public repositories
- **OWASP ZAP:** Free and open source

### Optimization
- Run full scans weekly, quick scans on PRs
- Use caching for dependencies
- Run ZAP scans only on `main` branch

## Security Best Practices

1. **Never commit secrets** to the repository
2. **Use secrets** for all API tokens
3. **Review security findings** before merging PRs
4. **Keep dependencies updated** (use Dependabot)
5. **Monitor security alerts** regularly
6. **Fix critical issues** immediately
7. **Document exceptions** for false positives

## Support and Documentation

- **GitHub Actions:** https://docs.github.com/en/actions
- **Snyk:** https://docs.snyk.io/
- **SonarCloud:** https://docs.sonarcloud.io/
- **OWASP ZAP:** https://www.zaproxy.org/docs/

## Next Steps

1. ✅ Add all required secrets to GitHub
2. ✅ Update SonarCloud organization in config files
3. ✅ Push changes to trigger first workflow run
4. ✅ Review results in GitHub Actions tab
5. ✅ Check SonarCloud and Snyk dashboards
6. ✅ Fix any critical issues found
7. ✅ Set up branch protection rules
8. ✅ Add status badges to README

## Questions?

If you encounter issues:
1. Check workflow logs in Actions tab
2. Review this documentation
3. Check tool-specific documentation
4. Open an issue in the repository

---

**Last Updated:** December 2, 2025
