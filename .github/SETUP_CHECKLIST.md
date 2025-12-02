# GitHub Actions Security Pipeline - Quick Setup Checklist

## ✅ Pre-requisites
- [ ] GitHub repository created
- [ ] Code pushed to repository
- [ ] GitHub Actions enabled

## 🔐 Step 1: Add GitHub Secrets

Go to: **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

### Required Secrets:
- [ ] **SNYK_TOKEN**
  - Get from: https://app.snyk.io/account
  - Copy your API token
  
- [ ] **SONAR_TOKEN**
  - Get from: https://sonarcloud.io/account/security
  - Generate new token
  
- [ ] **SONAR_ORGANIZATION**
  - Your SonarCloud organization key
  - Find in SonarCloud dashboard URL: `sonarcloud.io/organizations/YOUR-ORG-KEY`

### Optional Secrets:
- [ ] **SNYK_ORG_ID** - Your Snyk organization ID (for dashboard links)

## 🏗️ Step 2: Update Configuration Files

### Backend Configuration:
- [ ] Edit `golang-gin-realworld-example-app/sonar-project.properties`
  - Replace `your-sonarcloud-org` with your actual organization key

### Frontend Configuration:
- [ ] Edit `react-redux-realworld-example-app/sonar-project.properties`
  - Replace `your-sonarcloud-org` with your actual organization key

## 🚀 Step 3: Push to GitHub

```bash
git add .
git commit -m "Add GitHub Actions security pipeline"
git push origin main
```

## 🎯 Step 4: Verify Workflow Execution

- [ ] Go to **Actions** tab in GitHub
- [ ] Check if "Security Analysis Pipeline" workflow is running
- [ ] Wait for all jobs to complete (5-10 minutes)
- [ ] Review logs for any errors

## 📊 Step 5: Check Results

### GitHub Security Tab:
- [ ] Go to **Security** → **Code scanning alerts**
- [ ] Verify Snyk findings appear

### SonarCloud Dashboard:
- [ ] Login to https://sonarcloud.io
- [ ] Find `realworld-backend` project
- [ ] Find `realworld-frontend` project
- [ ] Review quality gates

### Snyk Dashboard:
- [ ] Login to https://app.snyk.io
- [ ] Verify backend project appears
- [ ] Verify frontend project appears
- [ ] Check vulnerability count

## 🛡️ Step 6: Review Security Findings

- [ ] Check **Critical** vulnerabilities (fix immediately)
- [ ] Check **High** vulnerabilities (fix within 1 week)
- [ ] Review **Medium** vulnerabilities
- [ ] Document any false positives

## 🔧 Step 7: Configure Branch Protection (Recommended)

Go to: **Settings** → **Branches** → **Add branch protection rule**

For `main` branch:
- [ ] Require status checks to pass before merging
- [ ] Select checks:
  - `snyk-scan`
  - `sonarcloud-backend`
  - `sonarcloud-frontend`
- [ ] Require branches to be up to date before merging

## 📝 Step 8: Add Status Badge to README

Add to your `README.md`:
```markdown
![Security Analysis](https://github.com/Tshewangdorji7257/SWE302_Assignment/workflows/Security%20Analysis%20Pipeline/badge.svg)
```

## 🎉 You're Done!

Your automated security pipeline is now active and will run:
- ✅ On every push to main/develop
- ✅ On every pull request
- ✅ Every Monday at 9 AM (weekly scan)
- ✅ Manually when needed

## 🆘 Troubleshooting

### Workflow not running?
- Check if Actions are enabled in repository settings
- Verify `.github/workflows/security-analysis.yml` exists
- Check if you have permissions to run Actions

### "Secret not found" error?
- Verify secret names are EXACT (case-sensitive)
- Re-check secret values (no extra spaces)
- Try regenerating tokens

### SonarCloud fails?
- Verify organization key is correct
- Check project key is unique
- Ensure token has admin permissions

### Need help?
- Read: `.github/SECURITY_PIPELINE_SETUP.md`
- Check workflow logs in Actions tab
- Review tool documentation

---

**Quick Reference URLs:**
- Snyk Account: https://app.snyk.io/account
- SonarCloud Security: https://sonarcloud.io/account/security
- GitHub Actions: https://github.com/Tshewangdorji7257/SWE302_Assignment/actions
- Security Alerts: https://github.com/Tshewangdorji7257/SWE302_Assignment/security

**Last Updated:** December 2, 2025
