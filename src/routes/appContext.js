// src/routes/appContext.js
import { Router } from 'express';
import CryptoJS from 'crypto-js';
import express from 'express';
import axios from 'axios';
import { setAuthCookie, installs } from '../middleware/auth.js';
import { API_BASE, withAccessToken } from '../services/tokenService.js';

const router = Router();

// Token refresh configuration (matching tokenService.js)
const TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000; // 5 minutes before expiry
const MAX_RETRY_ATTEMPTS = 3;
const INITIAL_RETRY_DELAY_MS = 1000; // 1 second
const MAX_RETRY_DELAY_MS = 30000; // 30 seconds
const TOKEN_ROTATION_GRACE_PERIOD_MS = 60 * 60 * 1000; // 1 hour grace period

// Helper function to delay execution
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Helper function to check if error is retryable
const isRetryableError = (error) => {
  const status = error?.response?.status;
  const errorCode = error?.response?.data?.error;
  const errorMessage = error?.response?.data?.message || error?.message || '';

  // Network errors are retryable
  if (!error.response) {
    console.log('🔄 Network error detected - will retry');
    return true;
  }

  // Rate limit errors are retryable
  if (status === 429) {
    console.log('⏳ Rate limited - will retry after delay');
    return true;
  }

  // Temporary server errors are retryable
  if (status >= 500 && status < 600) {
    console.log('🔧 Server error detected - will retry');
    return true;
  }

  // Some 401 errors might be temporary
  if (status === 401 && errorMessage.toLowerCase().includes('temporarily')) {
    console.log('⏱️ Temporary auth issue - will retry');
    return true;
  }

  // invalid_grant is NOT retryable
  if (errorCode === 'invalid_grant') {
    console.log('❌ Permanent token failure (invalid_grant) - will not retry');
    return false;
  }

  // invalid_client is NOT retryable
  if (errorCode === 'invalid_client') {
    console.log('❌ Invalid client credentials - will not retry');
    return false;
  }

  return false;
};

// Function to refresh agency token with retry logic
async function refreshAgencyTokenWithRetry(pendingAgency, user, attempt = 1) {
  try {
    console.log(`🔄 Agency token refresh attempt ${attempt}/${MAX_RETRY_ATTEMPTS} for company ${user.companyId}`);

    const refreshBody = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: pendingAgency.agency_refresh_token,
      client_id: process.env.GHL_CLIENT_ID,
      client_secret: process.env.GHL_CLIENT_SECRET
    });

    const refreshResponse = await axios.post(`${API_BASE}/oauth/token`, refreshBody, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 30000 // 30 second timeout
    });

    console.log(`✅ Agency token refresh successful on attempt ${attempt}`);
    return refreshResponse.data;

  } catch (error) {
    const isRetryable = isRetryableError(error);

    console.error(`❌ Agency token refresh attempt ${attempt} failed:`, {
      companyId: user.companyId,
      status: error?.response?.status,
      error: error?.response?.data?.error,
      message: error?.response?.data?.message || error.message,
      retryable: isRetryable
    });

    // If not retryable or max attempts reached, throw the error
    if (!isRetryable || attempt >= MAX_RETRY_ATTEMPTS) {
      throw error;
    }

    // Calculate exponential backoff delay
    const retryDelay = Math.min(
      INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt - 1),
      MAX_RETRY_DELAY_MS
    );

    console.log(`⏳ Retrying agency token refresh in ${retryDelay}ms...`);
    await delay(retryDelay);

    // Retry with incremented attempt count
    return refreshAgencyTokenWithRetry(pendingAgency, user, attempt + 1);
  }
}

// Helper function to refresh agency tokens if expired
async function ensureValidAgencyToken(pendingAgency, user) {
  // Check if token is expired or about to expire (5 minutes buffer)
  const tokenExpiryTime = pendingAgency.agency_expires_at ?? 0;
  const timeUntilExpiry = tokenExpiryTime - Date.now();

  if (timeUntilExpiry >= TOKEN_REFRESH_BUFFER_MS) {
    // Token is still valid
    return pendingAgency.agency_access_token;
  }

  // Token is expired or about to expire, refresh it
  console.log(`🔔 Agency token expiring in ${Math.floor(timeUntilExpiry / 1000)}s for company ${user.companyId}, refreshing...`);

  try {
    const refreshed = await refreshAgencyTokenWithRetry(pendingAgency, user);

    // Update the agency installation with new tokens (including token rotation)
    const updatedAgencyData = {
      ...pendingAgency,
      agency_access_token: refreshed.access_token,
      agency_refresh_token: refreshed.refresh_token || pendingAgency.agency_refresh_token,
      agency_expires_at: Date.now() + ((refreshed.expires_in ?? 3600) * 1000) - 60_000,
      // Store old tokens for grace period (token rotation)
      previous_agency_refresh_token: pendingAgency.agency_refresh_token,
      previous_agency_refresh_token_expires: Date.now() + TOKEN_ROTATION_GRACE_PERIOD_MS
    };

    await installs.saveAgencyInstall(user.companyId, updatedAgencyData);
    console.log(`✅ Agency token refreshed and saved successfully for company ${user.companyId}`);

    return refreshed.access_token;

  } catch (refreshError) {
    console.error('❌ All agency token refresh attempts failed:', refreshError?.response?.data || refreshError.message);

    // Check if we have a previous refresh token within grace period
    if (pendingAgency.previous_agency_refresh_token &&
        pendingAgency.previous_agency_refresh_token_expires &&
        Date.now() < pendingAgency.previous_agency_refresh_token_expires) {

      console.log('🔄 Attempting to use previous agency refresh token within grace period...');

      try {
        // Try with the previous refresh token
        const tempAgency = { ...pendingAgency, agency_refresh_token: pendingAgency.previous_agency_refresh_token };
        const refreshed = await refreshAgencyTokenWithRetry(tempAgency, user, 1);

        const updatedAgencyData = {
          ...pendingAgency,
          agency_access_token: refreshed.access_token,
          agency_refresh_token: refreshed.refresh_token || pendingAgency.previous_agency_refresh_token,
          agency_expires_at: Date.now() + ((refreshed.expires_in ?? 3600) * 1000) - 60_000
        };

        await installs.saveAgencyInstall(user.companyId, updatedAgencyData);
        console.log(`✅ Successfully refreshed agency token using previous token for company ${user.companyId}`);

        return refreshed.access_token;

      } catch (fallbackError) {
        console.error('❌ Previous agency refresh token also failed:', fallbackError?.response?.data || fallbackError.message);
      }
    }

    // Only delete for permanent failures
    if (refreshError?.response?.data?.error === 'invalid_grant' ||
        refreshError?.response?.data?.error === 'invalid_client') {
      console.log(`🗑️ Clearing permanently invalid agency installation for company ${user.companyId}`);
      await installs.deleteAgencyInstall(user.companyId);
      throw new Error('Agency authentication expired - please reconnect');
    }

    // For other errors, throw but don't delete
    throw new Error(`Failed to refresh agency access token: ${refreshError?.response?.data?.message || refreshError.message}`);
  }
}

// SECURITY: Removed /decrypt-user-data endpoint - it was unused and allowed
// unauthenticated decryption of user data, which is a security risk.
// Decryption is now only done internally within /app-context endpoint.

// App context endpoint
router.post('/app-context', express.json(), async (req, res) => {
  console.log('🚀 APP-CONTEXT ENDPOINT HIT - Request received');
  try {
    const { encryptedData, locationId } = req.body;
    const queryLocationId = req.query.locationId;
    const targetLocationId = locationId || queryLocationId;
    // 1) Validate payload - allow empty encryptedData for cases where we don't have encrypted context
    if (typeof encryptedData !== 'string') {
      return res.status(422).json({
        error: 'invalid_payload',
        message: 'Encrypted user data must be a string (can be empty)'
      });
    }

    console.log('🔍 Processing app-context request with encryptedData:', encryptedData ? 'provided' : 'empty');
    console.log('🎯 Target locationId:', targetLocationId || 'not provided');

    // Fast path: if location already has tokens, proceed normally
    if (targetLocationId && await installs.has(targetLocationId)) {
      console.log('✅ Location already has tokens, proceeding with normal flow');
      // Continue with normal flow below...
    }

    // 2) Decrypt user (if encryptedData is provided)
    let user = null;
    if (encryptedData && encryptedData.trim().length > 0) {
      try {
        const decrypted = CryptoJS.AES.decrypt(
          encryptedData,
          process.env.GHL_APP_SHARED_SECRET
        ).toString(CryptoJS.enc.Utf8);
        user = JSON.parse(decrypted);
      } catch (e) {
        console.error('User decrypt failed:', e.message);
        return res.status(422).json({
          error: 'decrypt_failed',
          message: 'Unable to decrypt user payload (check Shared Secret and ciphertext source)'
        });
      }
    }

    // Get cookie location early for use in checks below
    const cookieLocation = req.signedCookies?.ghl_location || req.cookies?.ghl_location || null;

    // SECURITY: If no encrypted user data and no cookie, require OAuth
    // We cannot safely "guess" which location to authenticate
    if (!user && !cookieLocation && !targetLocationId) {
      console.log('⚠️ No authentication context provided - redirecting to OAuth');
      return res.status(401).json({
        error: 'authentication_required',
        message: 'Please complete OAuth setup to access this app',
        redirectUrl: '/oauth/install'
      });
    }

    // Slow path: check for agency bulk installation to consume
    const locationToCheck = targetLocationId || user?.activeLocation;

    if (locationToCheck && !await installs.has(locationToCheck) && user?.companyId) {
      console.log('🔍 Checking for agency bulk installation to consume for location:', locationToCheck);

      const pendingAgency = await installs.getAgencyInstallByCompanyId(user.companyId);

      if (pendingAgency && pendingAgency.locations?.some(l => l.id === locationToCheck)) {
        console.log('🎯 Found matching agency installation for location:', locationToCheck);

        // Exchange agency tokens for location-specific tokens
        console.log('🔄 Exchanging agency tokens for location-specific tokens');

        try {
          // Ensure agency token is valid and refresh if needed
          const validAgencyToken = await ensureValidAgencyToken(pendingAgency, user);

          const locationTokenResponse = await axios.post(`${API_BASE}/oauth/locationToken`, {
            locationId: locationToCheck,
            companyId: user.companyId
          }, {
            headers: {
              Authorization: `Bearer ${validAgencyToken}`,
              'Content-Type': 'application/json',
              Version: '2021-07-28'
            }
          });

          const { access_token, refresh_token, expires_in } = locationTokenResponse.data;

          // Store the location-specific tokens
          const tokenData = {
            access_token,
            refresh_token,
            expires_at: Date.now() + (expires_in * 1000),
            isBulkInstallation: true,
            userType: pendingAgency.userType,
            companyId: user.companyId
          };

          console.log('💾 Storing location-specific token data:', {
            hasAccessToken: !!tokenData.access_token,
            hasRefreshToken: !!tokenData.refresh_token,
            expiresAt: new Date(tokenData.expires_at).toISOString(),
            userType: tokenData.userType,
            isBulkInstallation: tokenData.isBulkInstallation,
            accessTokenPrefix: tokenData.access_token?.substring(0, 20) + '...'
          });

          await installs.set(locationToCheck, tokenData);

        } catch (tokenExchangeError) {
          console.error('❌ Failed to exchange agency tokens for location tokens:', tokenExchangeError?.response?.data || tokenExchangeError.message);
          return res.status(422).json({
            error: 'token_exchange_failed',
            message: `Failed to exchange agency tokens for location ${locationToCheck}`,
            redirectUrl: '/oauth/install'
          });
        }

        console.log('✅ Agency installation consumed for location:', locationToCheck);

        // Optional: Clean up the agency installation if all locations have been consumed
        // For now, we'll leave it for future locations
      } else if (locationToCheck) {
        console.log('❌ No agency installation found for location:', locationToCheck);
        return res.status(422).json({
          error: 'app_not_installed',
          message: `App not installed for location ${locationToCheck}`,
          redirectUrl: '/oauth/install'
        });
      }
    }
    // Optional: log AFTER user exists
    console.log('AppContext user:', user ? {
      companyId: user.companyId,
      activeLocation: user.activeLocation,
      type: user.type,
      email: user.email
    } : 'No encrypted user data provided');
    console.log('Request cookies debug:', {
      hasGHLLocation: !!req.signedCookies?.ghl_location,
      signedCookieKeys: Object.keys(req.signedCookies || {}),
      regularCookieKeys: Object.keys(req.cookies || {}),
      rawCookieHeader: req.headers.cookie || 'none',
      cookieSecret: process.env.APP_SECRET ? 'configured' : 'missing',
      headers: {
        userAgent: req.headers['user-agent'] ? req.headers['user-agent'].substring(0, 50) + '...' : 'none',
        referer: req.headers.referer || 'none'
      }
    });

// 3) Enforce cookie vs activeLocation (only if user data is available)
if (user?.activeLocation && cookieLocation && cookieLocation !== user.activeLocation) {
  // Check if we have an installation for the new location
  if (await installs.has(user.activeLocation)) {
    // Update cookie to new location
setAuthCookie(res, user.activeLocation);

    console.log(`Location switched: ${cookieLocation} → ${user.activeLocation}`);
  } else {
    // New location doesn't have the app installed
    return res.status(422).json({
      error: 'app_not_installed',
      message: `App not installed for location ${user.activeLocation}`,
      redirectUrl: '/oauth/install'
    });
  }
}
    // If no cookie but we have an install for activeLocation, set it
    if (user?.activeLocation && !cookieLocation && await installs.has(user.activeLocation)) {
setAuthCookie(res, user.activeLocation);
}
    // 4) Location details (UI friendly) - determine location from user or cookie
    let location = null;
    const currentLocationId = user?.activeLocation || cookieLocation;

    if (currentLocationId && await installs.has(currentLocationId)) {
      try {
// Use withAccessToken to automatically handle token refresh
const accessToken = await withAccessToken(currentLocationId);
const { data: loc } = await axios.get(
  `${API_BASE}/locations/${encodeURIComponent(currentLocationId)}`,
  {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Version: '2021-07-28',
      Accept: 'application/json'
    },
    timeout: 30000,
  }
);
          location = {
          id: currentLocationId,
          name: loc.name || null,
          companyName: loc.companyName || null,
          logoUrl: loc.logoUrl || null,
          website: loc.website || null
        };
      } catch (e) {
        console.warn('Location fetch failed:', e?.response?.status, e?.response?.data || e.message);

        // If JWT is invalid, clear the installation
        if (e?.response?.status === 401 && e?.response?.data?.message === 'Invalid JWT') {
          console.log(`Clearing invalid installation for ${currentLocationId}`);
          await installs.delete(currentLocationId);
        }
      }
    }
res.json({ user, location });
  } catch (error) {
    console.error('Failed to get app context:', error.message);
    res.status(400).json({ error: 'app_context_failed', message: error.message });
  }
});

// Switch location
router.post('/switch-location', express.json(), async (req, res) => {
  try {
    const { locationId, encryptedData } = req.body;

    if (!locationId) {
      return res.status(400).json({ error: 'Location ID required' });
    }

    // SECURITY: encryptedData is REQUIRED to prove user has access
    if (!encryptedData) {
      return res.status(401).json({
        error: 'authentication_required',
        message: 'Encrypted user context required to switch locations'
      });
    }

    // Verify the new location has the app installed
    if (!await installs.has(locationId)) {
      return res.status(422).json({
        error: 'app_not_installed',
        message: `App not installed for location ${locationId}`,
        redirectUrl: '/oauth/install'
      });
    }

    // Decrypt and validate user context
    try {
      const decrypted = CryptoJS.AES.decrypt(
        encryptedData,
        process.env.GHL_APP_SHARED_SECRET
      ).toString(CryptoJS.enc.Utf8);
      const user = JSON.parse(decrypted);

      // Ensure the user has access to this location
      if (user.activeLocation !== locationId) {
        return res.status(403).json({
          error: 'access_denied',
          message: 'User does not have access to this location'
        });
      }
    } catch (e) {
      console.error('User context validation failed:', e.message);
      return res.status(401).json({
        error: 'invalid_authentication',
        message: 'Invalid or expired user context'
      });
    }

    // Set the new location cookie
    setAuthCookie(res, locationId);

    res.json({
      success: true,
      locationId,
      message: 'Location switched successfully'
    });

  } catch (error) {
    console.error('Location switch failed:', error.message);
    res.status(500).json({ error: 'Location switch failed' });
  }
});

// Dev routes
router.get('/dev/mock-encrypted', (req, res) => {
  if (process.env.NODE_ENV === 'production') return res.status(404).end();

  // pick a real locationId you've already installed the app on
  const { companyId = 'AGENCY_123', locationId = process.env.DEV_LOCATION_ID } = req.query;

  const payload = {
    userId: 'DEVUSER',
    companyId,
    role: 'admin',
    type: locationId ? 'location' : 'agency',
    ...(locationId ? { activeLocation: locationId } : {}),
    userName: 'Dev User',
    email: 'dev@example.com'
  };

  const ciphertext = CryptoJS.AES.encrypt(
    JSON.stringify(payload),
    process.env.GHL_APP_SHARED_SECRET
  ).toString();

  res.json({ encryptedData: ciphertext });
});

router.post('/dev/set-location/:locationId', async (req, res) => {
  if (process.env.NODE_ENV === 'production') return res.status(404).end();

  const { locationId } = req.params;
  if (!locationId || !(await installs.has(locationId))) {
    return res.status(400).json({ error: 'unknown_location_or_not_installed' });
  }

  // normal signed cookie
  res.cookie('ghl_location', locationId, {
    domain: process.env.COOKIE_DOMAIN || undefined,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none',
    signed: true,
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  // CHIPS/partitioned duplicate for cross-site iframes
  const d = process.env.COOKIE_DOMAIN ? `Domain=${process.env.COOKIE_DOMAIN}; ` : '';
  res.append('Set-Cookie',
    `ghl_location=${encodeURIComponent(locationId)}; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=604800`
  );

  res.json({ ok: true, locationId });
});

// Debug endpoint to check cookies
router.get('/debug-cookies', (req, res) => {
  if (process.env.NODE_ENV === 'production') return res.status(404).end();

  res.json({
    signedCookies: req.signedCookies || {},
    regularCookies: req.cookies || {},
    rawCookieHeader: req.headers.cookie || 'none',
    cookieSecret: process.env.APP_SECRET ? 'configured' : 'missing'
  });
});

export default router;