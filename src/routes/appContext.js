// src/routes/appContext.js
import { Router } from 'express';
import CryptoJS from 'crypto-js';
import express from 'express';
import axios from 'axios';
import { setAuthCookie, installs } from '../middleware/auth.js';
import { API_BASE } from '../services/tokenService.js';

const router = Router();

// User context decryption
router.post('/decrypt-user-data', express.json(), async (req, res) => {
  try {
    const { encryptedData } = req.body;
    
    if (!encryptedData) {
      return res.status(400).json({ error: 'Encrypted data required' });
    }

    // Use CryptoJS directly (no const declaration needed)
    const decrypted = CryptoJS.AES.decrypt(encryptedData, process.env.GHL_APP_SHARED_SECRET)
      .toString(CryptoJS.enc.Utf8);
    
    const userData = JSON.parse(decrypted);
    
    res.json(userData);
  } catch (error) {
    console.error('Failed to decrypt user data:', error);
    res.status(400).json({ error: 'Failed to decrypt user data' });
  }
});

// App context endpoint
router.post('/app-context', express.json(), async (req, res) => {
  try {
    const { encryptedData } = req.body;
    // 1) Validate payload - allow empty encryptedData for cases where we don't have encrypted context
    if (typeof encryptedData !== 'string') {
      return res.status(422).json({
        error: 'invalid_payload',
        message: 'Encrypted user data must be a string (can be empty)'
      });
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
    // Optional: log AFTER user exists
    console.log('AppContext user:', user ? {
      companyId: user.companyId,
      activeLocation: user.activeLocation,
      type: user.type,
      email: user.email
    } : 'No encrypted user data provided');
    console.log('Request cookies debug:', {
      hasPendingTokens: !!req.signedCookies?.ghl_pending_tokens,
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

// Get cookie location once for reuse
const cookieLocation = req.signedCookies?.ghl_location || req.cookies?.ghl_location || null;

// Try to access pending tokens from both signed and unsigned cookies for debugging
const pendingTokens = req.signedCookies?.ghl_pending_tokens || req.cookies?.ghl_pending_tokens || null;
if (pendingTokens) {
  console.log('Found pending tokens in cookies:', {
    source: req.signedCookies?.ghl_pending_tokens ? 'signed' : 'unsigned',
    length: pendingTokens.length
  });
}

// (NEW) 2.5) If FE provides an activeLocation and we have pending tokens from OAuth, finish the install now
if (user?.activeLocation && pendingTokens) {
  try {
    console.log(`Found pending tokens for user with activeLocation: ${user.activeLocation}`);
    const bytes = CryptoJS.AES.decrypt(
      pendingTokens,
      process.env.APP_SECRET || 'dev-secret-change-me-in-production'
    );
    const str = bytes.toString(CryptoJS.enc.Utf8);
    const pending = JSON.parse(str || '{}');
    console.log('Pending tokens structure:', pending ? 'Valid' : 'Invalid');

    if (pending?.access_token && pending?.refresh_token && pending?.expires_at) {
      console.log(`Consuming pending tokens and saving to location: ${user.activeLocation}`);
      await installs.set(user.activeLocation, {
        access_token: pending.access_token,
        refresh_token: pending.refresh_token,
        expires_at: pending.expires_at
      });

      // Clear the pending cookie and set normal auth cookie
      res.clearCookie('ghl_pending_tokens', {
        domain: process.env.COOKIE_DOMAIN || undefined,
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'none',
        signed: true
      });
      console.log('Pending tokens cookie cleared after consumption');
      setAuthCookie(res, user.activeLocation);
      console.log(`✅ Pending tokens consumed successfully for ${user.activeLocation}`);
    } else {
      console.warn('Pending tokens missing required fields:', {
        hasAccessToken: !!pending?.access_token,
        hasRefreshToken: !!pending?.refresh_token,
        hasExpiresAt: !!pending?.expires_at
      });
    }
  } catch (e) {
    console.warn('Failed to consume pending tokens:', e?.message || e);
  }
}

// (NEW) 2.6) If we have pending tokens but no user activeLocation, check query params or cookie for locationId
if (!user?.activeLocation && pendingTokens) {
  console.log('Have pending tokens but no user activeLocation, checking query params and cookies...');

  // Try to get locationId from query parameter or cookie
  let fallbackLocationId = req.query.locationId || req.body.locationId || cookieLocation;

  // If no fallbackLocationId provided, try to detect it from HighLevel API using the access token
  if (!fallbackLocationId) {
    try {
      console.log('No fallbackLocationId found, attempting to detect from HighLevel API...');
      const bytes = CryptoJS.AES.decrypt(
        pendingTokens,
        process.env.APP_SECRET || 'dev-secret-change-me-in-production'
      );
      const str = bytes.toString(CryptoJS.enc.Utf8);
      const pending = JSON.parse(str || '{}');

      if (pending?.access_token) {
        // Try to get user info from HighLevel API to determine locationId
        try {
          // Try the HighLevel /me endpoint to get current user's location context
          const response = await axios.get(`${API_BASE}/me`, {
            headers: {
              Authorization: `Bearer ${pending.access_token}`,
              Version: '2021-07-28',
              Accept: 'application/json'
            },
            timeout: 10000,
          });

          console.log('HighLevel /me API response:', {
            status: response.status,
            hasData: !!response.data,
            dataKeys: response.data ? Object.keys(response.data) : []
          });

          // Try to extract locationId from the /me response
          // This might be in response.data.locationId or response.data.currentLocationId
          const detectedLocationId = response.data?.locationId ||
                                     response.data?.currentLocationId ||
                                     response.data?.location?.id ||
                                     (response.data?.locations && response.data.locations[0]?.id);

          if (detectedLocationId) {
            fallbackLocationId = detectedLocationId;
            console.log(`✅ Detected locationId from HighLevel /me API: ${fallbackLocationId}`);
          }
        } catch (apiError) {
          console.log('HighLevel API call failed:', apiError?.response?.status, apiError?.response?.data || apiError.message);
        }
      }

      console.log('Pending token payload:', {
        hasAccessToken: !!pending?.access_token,
        hasRefreshToken: !!pending?.refresh_token,
        hasExpiresAt: !!pending?.expires_at,
        detectedLocationId: fallbackLocationId || 'none'
      });
    } catch (e) {
      console.warn('Failed to inspect pending tokens:', e?.message || e);
    }
  }

  if (fallbackLocationId) {
    console.log(`Using fallback locationId: ${fallbackLocationId} for pending token consumption`);

    try {
      const bytes = CryptoJS.AES.decrypt(
        pendingTokens,
        process.env.APP_SECRET || 'dev-secret-change-me-in-production'
      );
      const str = bytes.toString(CryptoJS.enc.Utf8);
      const pending = JSON.parse(str || '{}');

      if (pending?.access_token && pending?.refresh_token && pending?.expires_at) {
        console.log(`Consuming pending tokens for fallback locationId: ${fallbackLocationId}`);
        await installs.set(fallbackLocationId, {
          access_token: pending.access_token,
          refresh_token: pending.refresh_token,
          expires_at: pending.expires_at
        });

        // Clear the pending cookie and set normal auth cookie
        res.clearCookie('ghl_pending_tokens', {
          domain: process.env.COOKIE_DOMAIN || undefined,
          path: '/',
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'none',
          signed: true
        });
        setAuthCookie(res, fallbackLocationId);
        console.log(`✅ Pending tokens consumed successfully for fallback ${fallbackLocationId}`);
      }
    } catch (e) {
      console.warn('Failed to consume pending tokens with fallback locationId:', e?.message || e);
    }
  }
}

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
    const locationId = user?.activeLocation || cookieLocation;

    if (locationId && await installs.has(locationId)) {
      try {
const install = await installs.get(locationId);
if (!install?.access_token) throw new Error('No tokens for this location');
const { data: loc } = await axios.get(
  `${API_BASE}/locations/${encodeURIComponent(locationId)}`,
  {
    headers: {
      Authorization: `Bearer ${install.access_token}`,
      Version: '2021-07-28',
      Accept: 'application/json'
    },
    timeout: 30000,
  }
);
          location = {
          id: locationId,
          name: loc.name || null,
          companyName: loc.companyName || null,
          logoUrl: loc.logoUrl || null,
          website: loc.website || null
        };
      } catch (e) {
        console.warn('Location fetch failed:', e?.response?.status, e?.response?.data || e.message);

        // If JWT is invalid, clear the installation
        if (e?.response?.status === 401 && e?.response?.data?.message === 'Invalid JWT') {
          console.log(`Clearing invalid installation for ${locationId}`);
          await installs.delete(locationId);
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
    
    // Verify the new location has the app installed
    if (!await installs.has(locationId)) {
      return res.status(422).json({
        error: 'app_not_installed',
        message: `App not installed for location ${locationId}`,
        redirectUrl: '/oauth/install'
      });
    }
    
    // Decrypt and validate user context if provided
    if (encryptedData) {
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
        return res.status(400).json({ error: 'Invalid user context' });
      }
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