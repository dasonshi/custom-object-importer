# 🧪 Security Testing Sequence
**Date:** November 19, 2025
**Purpose:** Verify all security fixes are working correctly in production

---

## Pre-Testing Setup

```bash
# Set your base URL
export API_URL="https://importer.api.savvysales.ai"
export VALID_LOCATION_ID="your-authenticated-location-id"
export OTHER_LOCATION_ID="another-location-id-you-dont-own"

# Optional: Install httpie for prettier output
# brew install httpie
```

---

## Test Suite 1: Authentication & Authorization ✅

### Test 1.1: Debug Endpoints Disabled in Production
**Expected:** All debug endpoints return 404

```bash
# Should return 404
curl -s "$API_URL/api/debug/sdk-methods" | jq

# Should return 404
curl -s "$API_URL/api/debug/cookies" | jq

# Should return 404
curl -s "$API_URL/api/debug/install/$VALID_LOCATION_ID" | jq
```

**✅ PASS Criteria:** All return `{"error":"Debug endpoints disabled in production"}`

---

### Test 1.2: IDOR Protection - validateTenant Middleware
**Expected:** Cannot access other locations' data via query parameters

```bash
# First, get authenticated cookie by logging into your app normally
# Then try to access another location's data

# Test objects endpoint
curl -s "$API_URL/api/objects?locationId=$OTHER_LOCATION_ID" \
  -H "Cookie: ghl_location=s%3A$VALID_LOCATION_ID.SIGNATURE" | jq

# Test custom values endpoint
curl -s "$API_URL/api/custom-values?locationId=$OTHER_LOCATION_ID" \
  -H "Cookie: ghl_location=s%3A$VALID_LOCATION_ID.SIGNATURE" | jq

# Test associations endpoint
curl -s "$API_URL/api/associations?locationId=$OTHER_LOCATION_ID" \
  -H "Cookie: ghl_location=s%3A$VALID_LOCATION_ID.SIGNATURE" | jq
```

**✅ PASS Criteria:** All return `{"error":"Access denied","message":"Cannot access data for this location"}`

---

### Test 1.3: Removed /decrypt-user-data Endpoint
**Expected:** Endpoint no longer exists

```bash
# Should return 404
curl -s -X POST "$API_URL/api/decrypt-user-data" \
  -H "Content-Type: application/json" \
  -d '{"encryptedData":"test"}' | jq
```

**✅ PASS Criteria:** Returns 404 or "Cannot POST /api/decrypt-user-data"

---

### Test 1.4: App-Context Requires Authentication
**Expected:** Empty requests rejected, no fallback to random locations

```bash
# Attempt auth bypass with empty encrypted data
curl -s -X POST "$API_URL/api/app-context" \
  -H "Content-Type: application/json" \
  -d '{"encryptedData":""}' | jq

# Attempt without any data
curl -s -X POST "$API_URL/api/app-context" \
  -H "Content-Type: application/json" \
  -d '{}' | jq
```

**✅ PASS Criteria:** Returns `401` with `{"error":"authentication_required"}`

---

## Test Suite 2: Rate Limiting 🚦

### Test 2.1: General API Rate Limit (50 requests / 15min)
**Expected:** Blocked after 50 requests in 15 minutes

```bash
# Rapid fire 51 requests
for i in {1..51}; do
  echo "Request $i:"
  curl -s -w "\nHTTP Status: %{http_code}\n" "$API_URL/health" | tail -1
  sleep 0.1
done
```

**✅ PASS Criteria:**
- Requests 1-50: Return `200`
- Request 51: Returns `429` with `{"error":"Rate limit exceeded"}`

---

### Test 2.2: Feedback Rate Limit (3 requests / hour)
**Expected:** Blocked after 3 submissions per hour

```bash
# Submit 4 feedback requests rapidly
for i in {1..4}; do
  echo "Feedback submission $i:"
  curl -s -X POST "$API_URL/api/feedback/submit" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "Test User",
      "email": "test@example.com",
      "component": "testing",
      "message": "Security test submission #'$i'"
    }' | jq -r '.error // "Success"'
done
```

**✅ PASS Criteria:**
- Submissions 1-3: Return success (or validation errors if webhook not configured)
- Submission 4: Returns `{"error":"Too many feedback submissions"}`

---

### Test 2.3: OAuth Rate Limit (10 requests / 15min)
**Expected:** OAuth endpoints rate limited

```bash
# Test OAuth install endpoint
for i in {1..11}; do
  echo "OAuth request $i:"
  curl -s -I "$API_URL/oauth/install" | grep "HTTP/1.1"
  sleep 0.1
done
```

**✅ PASS Criteria:** Request 11 returns `429`

---

## Test Suite 3: Security Headers 🛡️

### Test 3.1: Helmet Headers Present
**Expected:** Security headers added by helmet.js

```bash
# Check security headers
curl -I "$API_URL/health"
```

**✅ PASS Criteria:** Response includes:
```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-DNS-Prefetch-Control: off
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
```

---

### Test 3.2: CSP Allows GHL Embedding
**Expected:** Content-Security-Policy allows iframe embedding

```bash
# Check CSP header
curl -I "$API_URL/api/objects" | grep -i "content-security"
```

**✅ PASS Criteria:** Contains `frame-ancestors 'self' https://app.gohighlevel.com https://*.gohighlevel.com`

---

## Test Suite 4: Webhook Security 🔐

### Test 4.1: Uninstall Webhook Requires Signature
**Expected:** Webhook rejects requests without valid signature

```bash
# Attempt uninstall without signature
curl -s -X POST "$API_URL/oauth/uninstall" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "UNINSTALL",
    "locationId": "'$VALID_LOCATION_ID'",
    "companyId": "test"
  }' | jq
```

**✅ PASS Criteria:** Returns `401` with `{"error":"Unauthorized","message":"Invalid webhook signature"}`

---

### Test 4.2: Uninstall Webhook Accepts Valid Signature
**Expected:** Webhook processes requests with valid HMAC signature

```bash
# This requires generating a valid HMAC signature
# In production, GHL will send this automatically
# Manual test: Use a script to generate HMAC-SHA256 signature

# Python example:
python3 << 'EOF'
import hmac
import hashlib
import json
import os

payload = {
    "type": "UNINSTALL",
    "locationId": os.environ.get("VALID_LOCATION_ID"),
    "companyId": "test"
}

secret = os.environ.get("GHL_CLIENT_SECRET", "")
signature = hmac.new(
    secret.encode(),
    json.dumps(payload).encode(),
    hashlib.sha256
).hexdigest()

print(f"X-Webhook-Signature: {signature}")
print(f"Payload: {json.dumps(payload)}")
EOF
```

**✅ PASS Criteria:** With valid signature, returns `200` with `{"success":true}`

---

## Test Suite 5: Logging & Info Disclosure 📝

### Test 5.1: No Token Logging in Production
**Expected:** Tokens not logged to console in production

```bash
# Check production logs (on Render dashboard)
# Look for recent OAuth callbacks

# Search logs for:
grep -i "token" logs.txt
grep -i "access_token" logs.txt
grep -i "refresh_token" logs.txt
```

**✅ PASS Criteria:**
- Logs show: "OAuth token exchange successful for locationId: XXX"
- Logs do NOT show: actual token values or partial token strings
- Token metadata (keys, scopes) not logged in production

---

## Test Suite 6: CSV Import Security 📊

### Test 6.1: CSV Extra Columns Handled Gracefully
**Expected:** Import succeeds even with extra columns

```bash
# Create test CSV with extra columns
cat > /tmp/test_extra_columns.csv << 'EOF'
name,email,extra_col1,extra_col2,extra_col3
Test User,test@example.com,ignored,ignored,ignored
EOF

# Upload to your authenticated session
curl -X POST "$API_URL/api/objects/YOUR_OBJECT/records/import?locationId=$VALID_LOCATION_ID" \
  -H "Cookie: ghl_location=s%3A$VALID_LOCATION_ID.SIGNATURE" \
  -F "records=@/tmp/test_extra_columns.csv"
```

**✅ PASS Criteria:** Import succeeds, `__parsed_extra` field filtered out

---

## Test Suite 7: Production Readiness ✅

### Test 7.1: OAuth Flow Works
**Expected:** Complete OAuth flow succeeds

1. Navigate to: `$API_URL/oauth/install`
2. Complete OAuth on GHL marketplace
3. Verify redirect to `/launch`
4. Check cookie is set: `ghl_location`

**✅ PASS Criteria:** Cookie set, app loads successfully

---

### Test 7.2: Token Refresh Works Automatically
**Expected:** Expired tokens refresh without user intervention

```bash
# This is tested automatically over time
# Check logs for token refresh messages:

# Should see in logs:
# "🔔 Token expiring in XXs for LOCATION_ID, refreshing..."
# "✅ Token refreshed and saved successfully for LOCATION_ID"
```

**✅ PASS Criteria:** No forced re-authentication, smooth token refresh

---

### Test 7.3: Valid Authenticated Requests Work
**Expected:** Normal operations unaffected by security changes

```bash
# Test authenticated endpoints work correctly
curl -s "$API_URL/api/objects?locationId=$VALID_LOCATION_ID" \
  -H "Cookie: ghl_location=s%3A$VALID_LOCATION_ID.SIGNATURE" | jq

curl -s "$API_URL/api/custom-values?locationId=$VALID_LOCATION_ID" \
  -H "Cookie: ghl_location=s%3A$VALID_LOCATION_ID.SIGNATURE" | jq

curl -s "$API_URL/health" | jq
```

**✅ PASS Criteria:** All return `200` with valid data

---

## Quick Automated Test Script

```bash
#!/bin/bash
# save as: security_test.sh
# chmod +x security_test.sh

API_URL="https://importer.api.savvysales.ai"

echo "🧪 Security Testing Suite"
echo "========================="

# Test 1: Debug endpoints disabled
echo ""
echo "Test 1: Debug endpoints (should be 404)..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/debug/sdk-methods")
if [ "$STATUS" == "404" ]; then
  echo "✅ PASS: Debug endpoints disabled"
else
  echo "❌ FAIL: Debug endpoints returned $STATUS"
fi

# Test 2: decrypt-user-data removed
echo ""
echo "Test 2: decrypt-user-data endpoint (should be 404)..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/decrypt-user-data" \
  -H "Content-Type: application/json" -d '{"encryptedData":"test"}')
if [ "$STATUS" == "404" ]; then
  echo "✅ PASS: decrypt-user-data removed"
else
  echo "❌ FAIL: decrypt-user-data returned $STATUS"
fi

# Test 3: App-context requires auth
echo ""
echo "Test 3: app-context auth bypass (should be 401)..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL/api/app-context" \
  -H "Content-Type: application/json" -d '{"encryptedData":""}')
if [ "$STATUS" == "401" ]; then
  echo "✅ PASS: Auth bypass prevented"
else
  echo "❌ FAIL: app-context returned $STATUS"
fi

# Test 4: Security headers
echo ""
echo "Test 4: Security headers (helmet.js)..."
HEADERS=$(curl -s -I "$API_URL/health" | grep -i "x-content-type-options")
if [[ "$HEADERS" == *"nosniff"* ]]; then
  echo "✅ PASS: Security headers present"
else
  echo "❌ FAIL: Security headers missing"
fi

# Test 5: Health endpoint works
echo ""
echo "Test 5: Health check (should be 200)..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/health")
if [ "$STATUS" == "200" ]; then
  echo "✅ PASS: Health check working"
else
  echo "❌ FAIL: Health check returned $STATUS"
fi

echo ""
echo "========================="
echo "🏁 Testing Complete"
```

---

## Test Results Template

```
# Security Testing Results
Date: ___________
Tester: ___________
Environment: Production / Staging

## Results

| Test | Expected | Actual | Status |
|------|----------|--------|--------|
| 1.1 Debug endpoints disabled | 404 | ___ | ☐ PASS ☐ FAIL |
| 1.2 IDOR protection | 403 | ___ | ☐ PASS ☐ FAIL |
| 1.3 decrypt-user-data removed | 404 | ___ | ☐ PASS ☐ FAIL |
| 1.4 App-context auth required | 401 | ___ | ☐ PASS ☐ FAIL |
| 2.1 General rate limit | 429 at 51 | ___ | ☐ PASS ☐ FAIL |
| 2.2 Feedback rate limit | 429 at 4 | ___ | ☐ PASS ☐ FAIL |
| 2.3 OAuth rate limit | 429 at 11 | ___ | ☐ PASS ☐ FAIL |
| 3.1 Helmet headers | Present | ___ | ☐ PASS ☐ FAIL |
| 3.2 CSP for GHL | frame-ancestors | ___ | ☐ PASS ☐ FAIL |
| 4.1 Webhook auth | 401 | ___ | ☐ PASS ☐ FAIL |
| 5.1 No token logging | Clean logs | ___ | ☐ PASS ☐ FAIL |
| 7.1 OAuth flow | Success | ___ | ☐ PASS ☐ FAIL |
| 7.3 Valid requests | 200 | ___ | ☐ PASS ☐ FAIL |

## Overall: ☐ ALL TESTS PASSED ☐ SOME FAILURES

## Notes:
_______________________________________________
_______________________________________________
```

---

## Priority Testing Order

**Critical (Test First):**
1. Test 1.4 - App-context auth bypass prevention
2. Test 1.2 - IDOR protection
3. Test 7.1 - OAuth flow works
4. Test 7.3 - Valid requests work

**Important (Test Next):**
5. Test 1.1 - Debug endpoints disabled
6. Test 1.3 - decrypt-user-data removed
7. Test 2.1 - Rate limiting
8. Test 3.1 - Security headers

**Nice to Have:**
9. Test 4.1 - Webhook signature
10. Test 5.1 - Token logging
11. Test 6.1 - CSV handling

---

## Emergency Rollback

If critical tests fail:

```bash
# Rollback to previous commit
cd /Users/davidsonshine/Desktop/Custom\ Object\ Importer/custom-object-importer
git log --oneline -5  # Find previous stable commit
git revert HEAD  # Or git reset --hard <commit-hash>
git push --force-with-lease origin master

# Redeploy on Render (auto-deploys on push)
```

---

**Last Updated:** November 19, 2025
**Next Review:** After deployment to production
