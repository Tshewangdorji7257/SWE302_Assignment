# 🎯 QUICK START: GitHub Actions Security Pipeline

## ✨ What You Have Now

```
✅ Complete GitHub Actions workflow
✅ SonarCloud configuration (Backend + Frontend)
✅ OWASP ZAP security rules
✅ Comprehensive documentation
```

## 🚀 3 Steps to Activate

### Step 1️⃣: Add GitHub Secrets (2 minutes)

**Go to:** https://github.com/Tshewangdorji7257/SWE302_Assignment/settings/secrets/actions

**Click:** "New repository secret" and add each:

| Secret Name ⭐ | Get From 🔗 | Example Value |
|---------------|-------------|---------------|
| `SNYK_TOKEN` | https://app.snyk.io/account | `abc123...` |
| `SONAR_TOKEN` | https://sonarcloud.io/account/security | `xyz789...` |
| `SONAR_ORGANIZATION` | SonarCloud dashboard URL | `your-org-name` |

**💡 You said you already have tokens! Just verify they're named exactly as above.**

---

### Step 2️⃣: Update SonarCloud Org (1 minute)

**Find your org key:**
```
1. Go to: https://sonarcloud.io/
2. Look at URL: sonarcloud.io/organizations/YOUR-ORG-KEY-HERE
3. Copy the org key
```

**Update 2 files:**

**File 1:** `golang-gin-realworld-example-app/sonar-project.properties`
```properties
# Line 2: Change this line
sonar.organization=your-sonarcloud-org

# To your actual org (example):
sonar.organization=tshewangdorji7257
```

**File 2:** `react-redux-realworld-example-app/sonar-project.properties`
```properties
# Line 2: Same change
sonar.organization=your-actual-org-key
```

---

### Step 3️⃣: Push & Watch Magic Happen (30 seconds)

```bash
# Add everything
git add .

# Commit
git commit -m "🔒 Add GitHub Actions security pipeline"

# Push (this triggers the workflow!)
git push origin main
```

**Then watch:**
1. Go to: https://github.com/Tshewangdorji7257/SWE302_Assignment/actions
2. See "Security Analysis Pipeline" running
3. Wait 15-20 minutes for results ☕

---

## 📊 After It Runs (Results)

### GitHub Security Tab 🛡️
```
https://github.com/Tshewangdorji7257/SWE302_Assignment/security
→ View all Snyk vulnerabilities
→ See code scanning alerts
```

### SonarCloud Dashboard 📈
```
https://sonarcloud.io/organizations/YOUR-ORG-KEY
→ realworld-backend (Go code analysis)
→ realworld-frontend (React analysis)
```

### Snyk Dashboard 🔍
```
https://app.snyk.io/
→ Backend project (Go dependencies)
→ Frontend project (npm dependencies)
```

### Download ZAP Reports 📥
```
GitHub → Actions → Latest run → Artifacts
→ zap-reports.zip (HTML/JSON/Markdown)
→ security-summary.md
```

---

## 🎯 What Gets Scanned

```
┌─────────────────────────────────────────────┐
│ EVERY PUSH / PR AUTOMATICALLY RUNS:         │
├─────────────────────────────────────────────┤
│ ✅ Snyk          → Dependencies             │
│ ✅ SonarCloud    → Code Quality             │
│ ✅ OWASP ZAP     → Live App Testing         │
│ ✅ Summary       → Combined Report          │
└─────────────────────────────────────────────┘

⏰ ALSO RUNS: Every Monday at 9 AM (weekly scan)
```

---

## 🔥 Pro Tips

### Add Status Badge to README
```markdown
![Security](https://github.com/Tshewangdorji7257/SWE302_Assignment/workflows/Security%20Analysis%20Pipeline/badge.svg)
```

### Manual Trigger
```bash
# From command line
gh workflow run security-analysis.yml

# Or click "Run workflow" button in Actions tab
```

### Branch Protection (Recommended)
```
Settings → Branches → Add rule for "main"
→ ✅ Require status checks: snyk-scan, sonarcloud-backend, sonarcloud-frontend
```

---

## 🆘 Common Issues

| Problem | Solution |
|---------|----------|
| ❌ "SNYK_TOKEN not found" | Check secret name is exactly `SNYK_TOKEN` (case-sensitive) |
| ❌ "SONAR_TOKEN not found" | Regenerate token at sonarcloud.io/account/security |
| ❌ SonarCloud project error | Update organization key in sonar-project.properties |
| ❌ Workflow doesn't start | Check: Settings → Actions → Allow all actions |
| ❌ ZAP scan fails | Check logs - might need longer sleep time |

---

## 📚 Full Documentation

Need more details? Check these files:

| File | Purpose |
|------|---------|
| `README_GITHUB_ACTIONS.md` | **👈 START HERE** - Complete overview |
| `.github/SETUP_CHECKLIST.md` | Step-by-step checklist |
| `.github/SECURITY_PIPELINE_SETUP.md` | Detailed setup guide |
| `.github/PIPELINE_ARCHITECTURE.md` | How it works (technical) |

---

## ✅ Success Checklist

After pushing, verify:

- [ ] Actions tab shows workflow running
- [ ] All 5 jobs complete successfully
- [ ] SonarCloud shows 2 projects
- [ ] GitHub Security tab has alerts
- [ ] Can download ZAP reports from artifacts
- [ ] (If PR) Comment appears automatically

---

## 🎉 That's It!

**Total setup time:** ~3 minutes  
**Total scan time:** ~15-20 minutes  
**Result:** Fully automated security pipeline! 🚀

---

**Questions?** 
- Check `.github/SECURITY_PIPELINE_SETUP.md`
- Review workflow logs in Actions tab
- Open an issue in the repo

**Created:** December 2, 2025  
**Status:** ✅ Ready to deploy
