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
    // 1) Validate payload
    if (typeof encryptedData !== 'string' || encryptedData.trim().length === 0) {
      return res.status(422).json({
        error: 'invalid_payload',
        message: 'Encrypted user data is required and must be a non-empty string'
      });
    }
    // 2) Decrypt user
    let user;
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
    // Optional: log AFTER user exists
    console.log('AppContext user:', {
      companyId: user.companyId,
      activeLocation: user.activeLocation,
      type: user.type,
      email: user.email
    });
    console.log('Request cookies check:', {
      hasPendingTokens: !!req.signedCookies?.ghl_pending_tokens,
      hasGHLLocation: !!req.signedCookies?.ghl_location,
      cookieKeys: Object.keys(req.signedCookies || {})
    });
// (NEW) 2.5) If FE provides an activeLocation and we have pending tokens from OAuth, finish the install now
if (user.activeLocation && req.signedCookies?.ghl_pending_tokens) {
  try {
    console.log(`Found pending tokens for user with activeLocation: ${user.activeLocation}`);
    const bytes = CryptoJS.AES.decrypt(
      req.signedCookies.ghl_pending_tokens,
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
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'none',
        signed: true
      });
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
// 3) Enforce cookie vs activeLocation
    const cookieLocation = req.signedCookies?.ghl_location || req.cookies?.ghl_location || null;
if (user.activeLocation && cookieLocation && cookieLocation !== user.activeLocation) {
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
    if (user.activeLocation && !cookieLocation && await installs.has(user.activeLocation)) {
setAuthCookie(res, user.activeLocation);
}
    // 4) Location details (UI friendly)
    let location = null;
    if (user.activeLocation && await installs.has(user.activeLocation)) {
      try {
const install = await installs.get(user.activeLocation);
if (!install?.access_token) throw new Error('No tokens for this location');
const { data: loc } = await axios.get(
  `${API_BASE}/locations/${encodeURIComponent(user.activeLocation)}`,
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
          id: user.activeLocation,
          name: loc.name || null,
          companyName: loc.companyName || null,
          logoUrl: loc.logoUrl || null,
          website: loc.website || null
        };
      } catch (e) {
        console.warn('Location fetch failed:', e?.response?.status, e?.response?.data || e.message);

        // If JWT is invalid, clear the installation
        if (e?.response?.status === 401 && e?.response?.data?.message === 'Invalid JWT') {
          console.log(`Clearing invalid installation for ${user.activeLocation}`);
          await installs.delete(user.activeLocation);
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

export default router;