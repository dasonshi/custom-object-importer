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
  // Copy the handler from server.js
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
// (NEW) 2.5) If FE provides an activeLocation and we have pending tokens from OAuth, finish the install now
if (user.activeLocation && req.signedCookies?.ghl_pending_tokens) {
  try {
    const bytes = CryptoJS.AES.decrypt(
      req.signedCookies.ghl_pending_tokens,
      process.env.APP_SECRET || 'dev-secret-change-me-in-production'
    );
    const str = bytes.toString(CryptoJS.enc.Utf8);
    const pending = JSON.parse(str || '{}');
    if (pending?.access_token && pending?.refresh_token && pending?.expires_at) {
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
  // Copy the handler from server.js
});

// Dev routes
router.get('/dev/mock-encrypted', (req, res) => {
  // Copy the handler
});

router.post('/dev/set-location/:locationId', async (req, res) => {
  // Copy the handler
});

export default router;