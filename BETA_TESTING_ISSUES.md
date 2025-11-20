# Beta Testing Issues - November 20, 2025

## ✅ FIXED (Just Deployed)

### 1. CORS Unhandled Error Crash 🔴
**Timestamp:** 16:22:30
**Issue:** CORS middleware threw unhandled error, crashing requests
**Fix:** Changed `cb(new Error())` to `cb(null, false)` - now denies gracefully
**Commit:** c8751f3

### 2. PII/Security Exposure in Logs 🔴
**Issue:** Production logs showing:
- User emails (PII violation)
- Company IDs (sensitive)
- Full cookie headers (security tokens exposed)
- Cookie secret status

**Fix:** Wrapped debug logging in `NODE_ENV !== 'production'` check
**Commit:** c8751f3

---

## 🔴 CRITICAL - Fix Next

### 3. Cookie Persistence Failures
**Issue:** Multiple users showing no cookies despite being authenticated

**Evidence from logs:**
```
hasGHLLocation: false
signedCookieKeys: []
regularCookieKeys: []
rawCookieHeader: 'none'
```

**Affected:**
- Safari users (146.75.237.84) - multiple occurrences
- Chrome users intermittently

**Root Causes:**
1. **SameSite=None requires HTTPS** - Check if all requests are HTTPS
2. **Safari ITP (Intelligent Tracking Prevention)** - Blocks 3rd party cookies
3. **Partitioned cookies** - We use `Partitioned` attribute but Safari may not support
4. **Cookie domain mismatch** - importer.savvysales.ai vs importer.api.savvysales.ai

**Action Items:**
- [ ] Verify all cookie-setting responses include Secure flag
- [ ] Test in Safari with different ITP settings
- [ ] Consider localStorage fallback for Safari users
- [ ] Check cookie domain configuration matches actual domain

---

### 4. Bulk Installation Race Condition 🟡
**Timestamp:** 16:01:42 - 16:02:58

**Issue:** Bulk install for company `6OrUnDCM3AzwpQVuQ4Lm`:
- 16:01:42: Returns **0 locations**
- 16:02:58: Same company returns **5 locations**
- User tried to access location in between → got 404

**Impact:** Poor UX - users get "app not installed" error, have to wait/retry

**Root Cause:** GHL API takes time to propagate bulk installations across all locations

**Solutions:**
1. **Polling approach:** Poll GHL API for X seconds after bulk install
2. **Webhook:** Use GHL webhooks to notify when install completes
3. **Better error message:** Tell user "Installation in progress, please wait 30 seconds"

---

### 5. Token Refresh Too Close to Expiry 🟡
**Timestamp:** 16:22:07

```
🔔 Token expiring in 174s for ORAR6TYKTK091V2KxxCL, refreshing...
```

**Issue:** Refreshing with only 2.9 minutes remaining

**Risk:** If refresh fails/delays, user gets kicked out

**Current threshold:** 5 minutes before expiry
**Recommended:** 10 minutes before expiry (or earlier)

**Fix:**
```javascript
// In tokenService.js
const REFRESH_BUFFER_MS = 10 * 60 * 1000; // Change from 5 to 10 minutes
```

---

## 🟢 LOW PRIORITY

### 6. OAuth Without State Parameter (Informational)
**Timestamps:** 16:01:42, 16:02:57, 16:11:57

**Status:** ⚠️ **Not a bug** - GHL Marketplace installs don't provide state parameter

**Context:** State parameter is for CSRF protection, but GHL's marketplace OAuth flow doesn't include it. We correctly handle both cases.

**Action:** Change log level from WARN to INFO

---

### 7. LocationId Undefined in Bulk OAuth 🟢
**Timestamps:** 16:01:42, 16:02:57

```
OAuth token exchange successful for locationId: undefined
```

**Status:** Expected behavior for bulk/agency installations

**Impact:** None - bulk installs don't have a specific location, we handle this correctly

**Action:** Improve log message:
```javascript
console.log(`OAuth token exchange successful (bulk installation - no specific locationId)`);
```

---

### 8. Excessive Agency Branding API Calls 🟢
**Pattern:** 3-4 calls to `/api/agency-branding` per page load

**Impact:** Minor - extra API calls, but cached

**Optimization:** Implement client-side caching with longer TTL

---

## 📊 User Behavior Insights

### Active Beta Testers:
1. **info@devli.com** (146.75.237.84) - Safari, frequent 401s (cookie issues)
2. **info@piratfundraising.it** (95.249.56.24) - Chrome, successful imports
3. **sonshine.david@gmail.com** (179.1.148.226) - Your testing, Chrome, working well
4. **Edge user** (184.103.41.209) - Single location install, successful

### Success Metrics:
- **23 total installations** in database
- **5-location bulk install** completed successfully
- Multiple successful CSV imports
- Token refresh working correctly

### Pain Points:
1. Cookie persistence (especially Safari)
2. First-time bulk install delay
3. Re-authentication frequency (token refresh timing)

---

## 🎯 Recommended Action Plan

### Immediate (This Week):
1. ✅ Fix CORS crash (DONE)
2. ✅ Remove PII from logs (DONE)
3. **Investigate Safari cookie issues** - highest user impact
4. **Improve token refresh threshold** - 5→10 minutes
5. **Better UX for bulk install delays** - loading state + messaging

### Medium Priority (Next Week):
6. Add client-side caching for agency branding
7. Implement retry logic for bulk installation checks
8. Add monitoring/alerting for 401 spikes

### Low Priority (Nice to Have):
9. Improve log messages for bulk installs
10. Add request ID tracking for debugging
11. Implement security monitoring dashboard

---

## 🔍 Monitoring Recommendations

### Add Alerts For:
- **401 error rate > 10%** in 5-minute window
- **CORS rejections > 5/hour**
- **Token refresh failures**
- **Bulk install with 0 locations returned**

### Add Metrics For:
- Cookie persistence rate by browser
- Time-to-first-successful-API-call after auth
- Token lifetime before refresh
- Bulk installation propagation time

---

## 📝 Notes

**OAuth State Parameter:** Not a security issue for our use case. GHL marketplace installs are initiated from within GHL's trusted environment, so CSRF risk is minimal. Direct OAuth flow (via /oauth/install) does use state parameter correctly.

**Cookie Issues:** This is likely the #1 blocker for user adoption. Safari's ITP is aggressive about blocking 3rd-party cookies. Consider:
- Session storage + sync via postMessage
- Backend session with session ID in URL
- Token-based auth instead of cookies

**Token Refresh:** Current implementation is solid, just needs earlier threshold to provide buffer for network delays.
