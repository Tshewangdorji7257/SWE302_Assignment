# Snyk Security Remediation Plan

## Document Information
**Date Created:** November 30, 2025  
**Organization:** tshewangdorji7257  
**Applications:**
- Backend: golang-gin-realworld-example-app
- Frontend: react-redux-realworld-example-app

---

## Executive Summary

### Total Vulnerabilities
| Application | Critical | High | Medium | Low | Total |
|-------------|----------|------|--------|-----|-------|
| Backend (Go) | 0 | 2 | 0 | 0 | 2 |
| Frontend (React) | 1 | 0 | 5 | 0 | 6 |
| **TOTAL** | **1** | **2** | **5** | **0** | **8** |

### Risk Classification
- **Immediate Risk:** 3 issues (1 Critical, 2 High)
- **Medium Risk:** 5 issues (all Medium)
- **Low Risk:** 0 issues

---

## Phase 1: Critical Issues (Must Fix Immediately)

### Priority 1.1: Frontend - Predictable Boundary Generation (CRITICAL)

**Issue:** form-data uses Math.random() for boundary generation  
**Severity:** Critical (CVSS 9.4)  
**CVE:** CVE-2025-7783  
**Affected:** react-redux-realworld-example-app

#### Risk Assessment
- **Exploit Maturity:** Proof of Concept Available
- **EPSS Score:** 0.00062 (Low exploitation probability but high impact)
- **Impact:** HTTP parameter pollution, potential data breach
- **Affected Functionality:** All HTTP file uploads and form submissions

#### Remediation Steps

**Step 1: Upgrade SuperAgent**
```bash
cd react-redux-realworld-example-app
npm install superagent@^10.2.2
```

**Step 2: Verify Package Updates**
```bash
npm list form-data
# Should show form-data@4.0.5 or higher
```

**Step 3: Update package-lock.json**
```bash
npm install  # Regenerates package-lock.json
```

**Step 4: Test Critical Paths**
- Test user registration with file uploads
- Test article creation with images
- Test all API calls that use SuperAgent
- Verify authentication still works

**Step 5: Verify Fix**
```bash
snyk test
# Verify CVE-2025-7783 no longer appears
```

#### Breaking Changes Assessment
**Likelihood:** HIGH (Major version upgrade from 3.x to 10.x)

**Known Breaking Changes:**
1. **Callback API removed** - Must use promises or async/await
2. **Error handling changed** - Different error object structure
3. **Plugin system updated** - Custom plugins may need updates
4. **TLS/SSL defaults changed** - More secure but may affect some APIs

**Code Review Required In:**
- `src/agent.js` - Main API client
- All components making HTTP requests
- Error handling middleware

#### Estimated Time
- **Development:** 4 hours
- **Testing:** 4 hours
- **Code Review:** 2 hours
- **Total:** 10 hours

#### Rollback Plan
```bash
# If issues occur, rollback to previous version
npm install superagent@3.8.3
npm install
```
**Note:** This is temporary only; must find alternative fix.

---

## Phase 2: High Priority Issues (Fix Within 1 Week)

### Priority 2.1: Backend - JWT Authentication Bypass (HIGH)

**Issue:** github.com/dgrijalva/jwt-go vulnerable to audience bypass  
**Severity:** High (CVSS 7.5)  
**CVE:** CVE-2020-26160  
**Affected:** golang-gin-realworld-example-app

#### Risk Assessment
- **Exploit Maturity:** Not Publicly Available
- **EPSS Score:** 0.00066 (Very low exploitation probability)
- **Impact:** Authentication bypass, unauthorized access
- **Affected Functionality:** All authenticated endpoints

#### Remediation Steps

**Step 1: Choose Migration Path**

**Option A: Upgrade to jwt-go v4 (Quickest)**
```bash
cd golang-gin-realworld-example-app
go get github.com/dgrijalva/jwt-go@v4.0.0-preview1
go mod tidy
```

**Option B: Migrate to golang-jwt/jwt (RECOMMENDED)**
```bash
# Remove old package
go mod edit -droprequire github.com/dgrijalva/jwt-go

# Add new maintained package
go get github.com/golang-jwt/jwt/v5@latest
go mod tidy
```

**Step 2: Update Import Statements**

For Option B (recommended), update all files:
```go
// OLD
import "github.com/dgrijalva/jwt-go"

// NEW
import "github.com/golang-jwt/jwt/v5"
```

Files to update:
- `users/models.go`
- `users/middlewares.go`
- Any other files using JWT

**Step 3: Update JWT Code**

**Breaking Changes in v5:**
```go
// OLD v3 syntax
token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{...})

// NEW v5 syntax (mostly compatible)
token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{...})
// Type assertions may need updating
```

**Step 4: Test Authentication Flow**
- User registration
- User login
- Token validation
- Protected routes
- Token expiration
- Invalid token handling

**Step 5: Verify Fix**
```bash
snyk test
# Verify CVE-2020-26160 no longer appears
```

#### Code Locations
- `users/models.go` - Token generation
- `users/middlewares.go` - Token validation
- `common/` - Shared authentication utilities

#### Estimated Time
- **Option A:** 2 hours (upgrade only)
- **Option B:** 6 hours (migration + testing)
- **Testing:** 3 hours
- **Total Option A:** 5 hours
- **Total Option B:** 9 hours (RECOMMENDED)

#### Testing Checklist
- [ ] User can register
- [ ] User can login
- [ ] User can access protected routes
- [ ] Invalid tokens are rejected
- [ ] Expired tokens are rejected
- [ ] Audience validation works correctly
- [ ] All existing tests pass

---

### Priority 2.2: Backend - SQLite Heap Buffer Overflow (HIGH)

**Issue:** github.com/mattn/go-sqlite3 buffer overflow  
**Severity:** High (CVSS 7.3)  
**CVE:** None specified  
**Affected:** golang-gin-realworld-example-app (transitive via GORM)

#### Risk Assessment
- **Exploit Maturity:** Proof of Concept Exists
- **Impact:** Code execution, data corruption, DoS
- **Affected Functionality:** All database operations
- **Dependency Type:** Transitive (via GORM)

#### Remediation Steps

**Step 1: Update go-sqlite3**
```bash
cd golang-gin-realworld-example-app
go get github.com/mattn/go-sqlite3@v1.14.18
go mod tidy
```

**Step 2: Verify GORM Compatibility**
```bash
# Check GORM version
go list -m github.com/jinzhu/gorm

# May need to update GORM if conflicts occur
go get github.com/jinzhu/gorm@latest
```

**Step 3: Consider GORM v2 Migration (RECOMMENDED)**

GORM v1 is no longer maintained. Consider upgrading:
```bash
# Remove GORM v1
go mod edit -droprequire github.com/jinzhu/gorm

# Add GORM v2
go get -u gorm.io/gorm
go get -u gorm.io/driver/sqlite
```

**Breaking Changes in GORM v2:**
- Different import paths
- Updated query syntax
- New error handling
- Different associations API

**Step 4: Test Database Operations**
- Create operations (users, articles)
- Read operations (queries, finds)
- Update operations
- Delete operations
- Complex queries
- Transactions
- Associations (has-many, belongs-to)

**Step 5: Verify Fix**
```bash
snyk test --all-projects
```

#### Estimated Time
- **Quick Fix (Update only):** 2 hours
- **GORM v2 Migration:** 16 hours
- **Testing:** 6 hours
- **Total Quick Fix:** 8 hours
- **Total Migration:** 22 hours

#### Decision Matrix
| Approach | Time | Risk | Long-term Benefit |
|----------|------|------|-------------------|
| Update go-sqlite3 only | 8h | Low | Low (v1 EOL) |
| Migrate to GORM v2 | 22h | Medium | High (Active support) |

**Recommendation:** Quick fix now, plan GORM v2 migration for next sprint.

---

## Phase 3: Medium Priority Issues (Fix Within 2-4 Weeks)

### Priority 3.1-3.5: Frontend - marked ReDoS Vulnerabilities (MEDIUM)

**Issue:** Multiple ReDoS vulnerabilities in marked markdown parser  
**Severity:** Medium (CVSS 5.3-5.9)  
**CVEs:** CVE-2022-21681, CVE-2022-21680  
**Affected:** react-redux-realworld-example-app

#### Risk Assessment
- **Count:** 5 separate vulnerabilities
- **Exploit Maturity:** 2 PoCs available
- **Impact:** Denial of Service (CPU exhaustion)
- **Affected Functionality:** Markdown rendering (articles, comments)

#### Consolidated Remediation

**Step 1: Upgrade Marked Package**
```bash
cd react-redux-realworld-example-app
npm install marked@^4.0.10
```

**Step 2: Check for Breaking Changes**

**Major Breaking Changes from 0.3.19 to 4.0.10:**
1. **Renderer API changed** - Custom renderers need updates
2. **Options object changed** - Some options deprecated
3. **Sanitize option removed** - Must use DOMPurify instead
4. **Pedantic mode removed**
5. **Mangle removed**

**Step 3: Update Code Using Marked**

Search for marked usage:
```bash
grep -r "marked" src/
```

Likely locations:
- Article rendering components
- Comment rendering components
- Preview components

**Old syntax:**
```javascript
import marked from 'marked';
marked.setOptions({ sanitize: true });
const html = marked(markdown);
```

**New syntax:**
```javascript
import { marked } from 'marked';
import DOMPurify from 'dompurify';

const dirty = marked.parse(markdown);
const html = DOMPurify.sanitize(dirty);
```

**Step 4: Add DOMPurify for XSS Protection**
```bash
npm install dompurify
npm install --save-dev @types/dompurify  # If using TypeScript
```

**Step 5: Test Markdown Rendering**
- Test article creation with complex markdown
- Test comment rendering
- Test edge cases (long text, nested lists, code blocks)
- Test with malicious markdown patterns
- Verify XSS protection still works

**Step 6: Verify Fix**
```bash
snyk test
# All 5 marked vulnerabilities should be resolved
```

#### ReDoS Attack Vectors (For Testing)
```javascript
// Test Case 1: inline.text ReDoS
marked.parse('a'.repeat(5000) + '@');

// Test Case 2: inline.reflinkSearch ReDoS
marked.parse(`[x]: x\n\n\\[\\](\\[\\](\\[\\](`);

// Test Case 3: block.def ReDoS  
marked.parse(`[x]:${' '.repeat(1500)}x ${' '.repeat(1500)} x`);
```

**All should complete in < 100ms after fix.**

#### Estimated Time
- **Upgrade:** 2 hours
- **Code Updates:** 6 hours
- **Testing:** 4 hours
- **Total:** 12 hours

#### Workaround (If Upgrade Blocked)
Implement input validation:
```javascript
// Limit markdown length
const MAX_MARKDOWN_LENGTH = 50000;
if (markdown.length > MAX_MARKDOWN_LENGTH) {
  throw new Error('Markdown too long');
}

// Set timeout for marked parsing
const parseWithTimeout = (md, timeout = 1000) => {
  return Promise.race([
    Promise.resolve(marked.parse(md)),
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Timeout')), timeout)
    )
  ]);
};
```

---

## Implementation Timeline

### Week 1: Critical Issues
| Day | Task | Owner | Hours |
|-----|------|-------|-------|
| Mon | Fix form-data (Frontend) | Frontend Dev | 6 |
| Mon-Tue | Test SuperAgent upgrade | QA | 4 |
| Wed | Fix JWT issue (Backend) | Backend Dev | 6 |
| Thu | Test authentication flows | QA | 3 |
| Fri | Review & deploy to staging | DevOps | 2 |

**Subtotal:** 21 hours

### Week 2: High Priority
| Day | Task | Owner | Hours |
|-----|------|-------|-------|
| Mon | Fix SQLite issue (Backend) | Backend Dev | 4 |
| Tue | Test database operations | QA | 4 |
| Wed | Code review | Lead Dev | 2 |
| Thu-Fri | Deploy to production | DevOps | 4 |

**Subtotal:** 14 hours

### Week 3-4: Medium Priority
| Day | Task | Owner | Hours |
|-----|------|-------|-------|
| Week 3 | Fix marked ReDoS (Frontend) | Frontend Dev | 8 |
| Week 3 | Test markdown rendering | QA | 4 |
| Week 4 | Final review & deployment | All | 4 |

**Subtotal:** 16 hours

**Total Effort:** 51 hours

---

## Dependency Update Strategy

### Package Version Pinning Strategy

**Current Approach (Too Permissive):**
```json
{
  "dependencies": {
    "marked": "^0.3.19",     // Bad: Allows 0.x updates
    "superagent": "^3.8.3"   // Bad: Allows 3.x updates
  }
}
```

**Recommended Approach:**
```json
{
  "dependencies": {
    "marked": "~4.0.10",     // Good: Only patch updates (4.0.x)
    "superagent": "~10.2.2"  // Good: Only patch updates (10.2.x)
  }
}
```

**For Backend (Go):**
```go
// go.mod
require (
    github.com/golang-jwt/jwt/v5 v5.2.0  // Pin major version
    github.com/mattn/go-sqlite3 v1.14.18  // Pin minor version
)
```

### Automated Update Tools

**Setup Dependabot (GitHub):**
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/react-redux-realworld-example-app"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    
  - package-ecosystem: "gomod"
    directory: "/golang-gin-realworld-example-app"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
```

**Setup Snyk GitHub Integration:**
1. Install Snyk GitHub App
2. Enable automatic PR generation
3. Configure auto-fix for minor/patch updates

---

## Testing Plan

### Backend Testing Checklist

#### Authentication Tests
- [ ] User registration with valid data
- [ ] User login with valid credentials
- [ ] JWT token generation
- [ ] JWT token validation
- [ ] Protected endpoint access with valid token
- [ ] Protected endpoint rejection with invalid token
- [ ] Token expiration handling
- [ ] Audience claim validation

#### Database Tests
- [ ] Create user
- [ ] Create article
- [ ] Read operations
- [ ] Update operations
- [ ] Delete operations
- [ ] Complex queries
- [ ] Transactions
- [ ] Foreign key constraints

### Frontend Testing Checklist

#### HTTP Client Tests
- [ ] API GET requests
- [ ] API POST requests with JSON
- [ ] API POST requests with form data
- [ ] File upload functionality
- [ ] Error handling
- [ ] Authentication headers
- [ ] CORS handling

#### Markdown Rendering Tests
- [ ] Simple markdown (headings, paragraphs)
- [ ] Complex markdown (lists, code blocks)
- [ ] Edge cases (very long text)
- [ ] XSS attack prevention
- [ ] Performance (no ReDoS)
- [ ] Article preview
- [ ] Comment rendering

### Integration Tests
- [ ] End-to-end user registration
- [ ] End-to-end article creation
- [ ] End-to-end comment posting
- [ ] End-to-end authentication flow

### Performance Tests
- [ ] Markdown rendering performance
- [ ] API response times
- [ ] Database query performance
- [ ] Load testing

---

## Rollback Procedures

### Frontend Rollback

**If SuperAgent upgrade fails:**
```bash
cd react-redux-realworld-example-app
git revert <commit-hash>
npm install
npm test
npm run build
# Deploy previous version
```

**If marked upgrade fails:**
```bash
# Temporary workaround: Input validation
npm install marked@0.3.19
# Implement length limits and timeouts
```

### Backend Rollback

**If JWT migration fails:**
```bash
cd golang-gin-realworld-example-app
git revert <commit-hash>
go mod tidy
go test ./...
go build
# Deploy previous version
```

**If SQLite upgrade fails:**
```bash
go get github.com/mattn/go-sqlite3@v1.14.15
go mod tidy
go test ./...
```

### Emergency Contact
- **Lead Developer:** [Name]
- **DevOps Lead:** [Name]
- **Security Team:** security@company.com
- **Snyk Support:** support@snyk.io

---

## Post-Remediation Verification

### Verification Steps

**Step 1: Run Snyk Scans**
```bash
# Backend
cd golang-gin-realworld-example-app
snyk test
snyk monitor

# Frontend
cd react-redux-realworld-example-app
snyk test
snyk code test
snyk monitor
```

**Step 2: Generate Reports**
```bash
# Backend
snyk test --json > snyk-backend-report-after.json

# Frontend
snyk test --json > snyk-frontend-report-after.json
```

**Step 3: Compare Before/After**
Create comparison document showing:
- Vulnerabilities fixed
- Remaining vulnerabilities (if any)
- New vulnerabilities introduced (if any)

**Step 4: Update Documentation**
- Update README.md with new dependency versions
- Update SECURITY.md if it exists
- Document any breaking changes

**Step 5: Stakeholder Communication**
Send report to:
- Development team
- Security team
- Management
- DevOps team

---

## Long-Term Improvements

### 1. Automated Security Scanning
- [ ] Integrate Snyk into CI/CD pipeline
- [ ] Add pre-commit hooks for local scanning
- [ ] Set up Snyk PR checks
- [ ] Configure automated fix PRs

### 2. Dependency Management Policy
- [ ] Document approved package sources
- [ ] Define update schedule (weekly/monthly)
- [ ] Establish breaking change review process
- [ ] Create dependency approval workflow

### 3. Security Training
- [ ] Developer security training
- [ ] Secure coding practices
- [ ] Dependency security awareness
- [ ] Incident response procedures

### 4. Monitoring & Alerting
- [ ] Real-time vulnerability alerts
- [ ] Dependency license monitoring
- [ ] Security dashboard
- [ ] Monthly security reports

### 5. Code Quality
- [ ] Implement SAST in CI/CD
- [ ] Add DAST testing
- [ ] Set up code coverage requirements
- [ ] Implement security code reviews

---

## Success Criteria

### Measurable Goals

**By End of Week 1:**
- ✓ Critical vulnerability (form-data) fixed
- ✓ Frontend deployed to production
- ✓ No new critical vulnerabilities introduced

**By End of Week 2:**
- ✓ Both high vulnerabilities (JWT, SQLite) fixed
- ✓ Backend deployed to production  
- ✓ All critical and high issues resolved

**By End of Week 4:**
- ✓ All marked ReDoS vulnerabilities fixed
- ✓ Complete frontend deployed
- ✓ Zero critical or high vulnerabilities
- ✓ Security dashboard showing green status

### Key Performance Indicators (KPIs)
- **Vulnerability Count:** 0 critical, 0 high
- **Mean Time To Remediate (MTTR):** < 7 days for critical
- **Test Coverage:** No regression in existing tests
- **Performance:** No degradation in response times
- **Availability:** 99.9% uptime maintained

---

## Budget Estimate

### Labor Costs

| Role | Hours | Rate | Cost |
|------|-------|------|------|
| Backend Developer | 20 | $100/hr | $2,000 |
| Frontend Developer | 20 | $100/hr | $2,000 |
| QA Engineer | 15 | $80/hr | $1,200 |
| DevOps Engineer | 10 | $120/hr | $1,200 |
| Security Reviewer | 5 | $150/hr | $750 |
| **Total** | **70** | | **$7,150** |

### Tool Costs
- Snyk Pro: $0 (current free tier sufficient)
- CI/CD updates: $0 (using existing infrastructure)

**Total Project Cost: $7,150**

---

## Risk Register

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Breaking changes in SuperAgent | High | High | Extensive testing, gradual rollout |
| JWT migration issues | High | Medium | Keep old package as fallback |
| GORM compatibility issues | Medium | Low | Test in staging first |
| marked rendering changes | Medium | Medium | Visual regression testing |
| Production downtime | High | Low | Deploy during maintenance window |
| Data corruption | Critical | Very Low | Full backups before changes |

---

## Sign-Off

### Approvals Required

- [ ] **Security Team Lead:** _________________ Date: _______
- [ ] **Development Manager:** _________________ Date: _______
- [ ] **DevOps Lead:** _________________ Date: _______
- [ ] **QA Manager:** _________________ Date: _______
- [ ] **Product Owner:** _________________ Date: _______

### Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-30 | GitHub Copilot | Initial remediation plan |

---

## Appendix A: Quick Reference Commands

### Frontend Commands
```bash
# Upgrade packages
npm install superagent@^10.2.2 marked@^4.0.10 dompurify

# Run tests
npm test

# Run Snyk scan
snyk test
snyk code test

# Build for production
npm run build
```

### Backend Commands
```bash
# Upgrade packages
go get github.com/golang-jwt/jwt/v5@latest
go get github.com/mattn/go-sqlite3@v1.14.18
go mod tidy

# Run tests
go test ./...

# Run Snyk scan
snyk test

# Build
go build
```

---

## Appendix B: Contact Information

**Snyk Dashboard:**
- Organization: tshewangdorji7257
- Backend Project: https://app.snyk.io/org/tshewangdorji7257/project/b55e9d3f-f22c-4b12-b596-5c95d7bd29bf/
- Frontend Project: https://app.snyk.io/org/tshewangdorji7257/project/a5069746-183c-4773-9f67-79c591014ac8/

**Snyk Support:**
- Email: support@snyk.io
- Docs: https://docs.snyk.io
- Community: https://community.snyk.io
