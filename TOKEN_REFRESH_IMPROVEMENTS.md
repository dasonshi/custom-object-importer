# Token Refresh Improvements - October 2025

## Overview
Comprehensive improvements to the OAuth token refresh mechanism to significantly reduce the frequency of forced re-authentication.

## Problems Identified
1. **Aggressive Token Deletion**: System immediately deleted tokens on first refresh failure
2. **No Retry Logic**: Single network failure could force re-authentication
3. **Short Refresh Buffer**: Only 30 seconds before expiry, leaving little room for error
4. **Poor Error Differentiation**: Treated all errors as permanent failures
5. **No Token Rotation**: No fallback mechanism for refresh token issues
6. **Limited Debugging Info**: Insufficient logging for troubleshooting

## Implemented Solutions

### 1. Retry Logic with Exponential Backoff
- **Max Attempts**: 3 attempts before giving up
- **Backoff Strategy**: 1s → 2s → 4s (max 30s)
- **Retryable Errors**:
  - Network failures (no response)
  - Rate limiting (429)
  - Server errors (5xx)
  - Temporary auth issues

### 2. Extended Refresh Buffer
- **Old**: 30 seconds before expiry
- **New**: 5 minutes before expiry
- **Benefit**: More time to handle network issues or server delays

### 3. Token Rotation with Grace Period
- **Implementation**: Store previous refresh token for 1 hour after rotation
- **Fallback**: If new token fails, try previous token within grace period
- **Benefit**: Handles edge cases where new token isn't properly saved

### 4. Intelligent Error Handling
- **Permanent Failures** (delete installation):
  - `invalid_grant`: Token revoked or expired
  - `invalid_client`: Invalid credentials
- **Temporary Failures** (retry):
  - Network errors
  - Rate limits
  - Server errors
  - Temporary auth issues

### 5. Enhanced Logging
- Detailed error information with status codes
- Retry attempt tracking
- Time until expiry logging
- Clear emojis for quick visual scanning

## Configuration Constants

```javascript
TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000;        // 5 minutes
MAX_RETRY_ATTEMPTS = 3;                         // 3 attempts
INITIAL_RETRY_DELAY_MS = 1000;                  // 1 second
MAX_RETRY_DELAY_MS = 30000;                     // 30 seconds
TOKEN_ROTATION_GRACE_PERIOD_MS = 60 * 60 * 1000; // 1 hour
```

## Files Modified
1. `/src/services/tokenService.js` - Location token refresh logic
2. `/src/routes/appContext.js` - Agency token refresh logic

## Expected Impact

### Before Improvements
- Any network hiccup → forced re-auth
- Token refresh failures → immediate deletion
- Users re-authenticating multiple times per day

### After Improvements
- Network issues → automatic retry with backoff
- Token issues → fallback to previous token
- Re-authentication only for truly expired/revoked tokens
- Expected re-auth frequency: Once per year (refresh token expiry)

## Deployment Steps
1. Pull latest changes from master branch
2. Restart Node.js server
3. Monitor logs for token refresh patterns

## Monitoring Recommendations
- Track frequency of retry attempts
- Monitor permanent vs temporary failures
- Alert on high rates of `invalid_grant` errors
- Track average time between re-authentications

## Future Enhancements (Optional)
1. Implement refresh token pre-emptive renewal (before 1-year mark)
2. Add metrics/alerting for token health
3. Implement circuit breaker pattern for API failures
4. Consider storing multiple historical refresh tokens

## Log Examples

### Successful Refresh with Retry:
```
🔔 Token expiring in 298s for location123, refreshing...
🔄 Token refresh attempt 1/3 for location123
❌ Token refresh attempt 1 failed: {status: 503, retryable: true}
⏳ Retrying in 1000ms...
🔄 Token refresh attempt 2/3 for location123
✅ Token refresh successful on attempt 2 for location123
✅ Token refreshed and saved successfully for location123
```

### Fallback to Previous Token:
```
🔔 Token expiring in 250s for location456, refreshing...
❌ All token refresh attempts failed: invalid_grant
🔄 Attempting to use previous refresh token within grace period...
✅ Successfully refreshed using previous token for location456
```

### Permanent Failure:
```
🔔 Token expiring in 180s for location789, refreshing...
❌ Permanent token failure (invalid_grant) - will not retry
🗑️ Clearing permanently invalid installation for location789
```

## Notes
- GoHighLevel access tokens expire after ~24 hours (normal)
- GoHighLevel refresh tokens are single-use and expire after 1 year if unused
- The 24-hour access token lifecycle is standard and expected
- These improvements focus on handling the refresh process more gracefully