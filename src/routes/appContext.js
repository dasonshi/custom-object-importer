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

    // Special case: Handle marketplace installs without encrypted user data
    // This happens when HighLevel doesn't provide encrypted context for marketplace apps
    if (!user && (!targetLocationId && !cookieLocation)) {
      console.log('🏪 Marketplace install without encrypted user data - searching for recent agency installations');

      // Try to find the most recent agency installation and consume it
      // This is a fallback for marketplace installs that don't provide user context
      try {
        // We'll need to modify the database to get recent agency installations
        // For now, let's assume we have a way to get all agency installations

        // Get the first available location from any recent agency installation
        // This is a temporary solution - ideally we'd have better context
        const allInstalls = await installs.list();
        console.log('📋 Current installations:', allInstalls.length);

        if (allInstalls.length === 0) {
          console.log('❌ No existing installations found for marketplace install fallback');
          return res.status(422).json({
            error: 'no_installations',
            message: 'No app installations found. Please install the app first.',
            redirectUrl: '/oauth/install'
          });
        }

        // Use the most recently updated installation
        const recentInstall = allInstalls.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))[0];
        const fallbackLocationId = recentInstall.locationId;

        console.log('🎯 Using fallback location from recent install:', fallbackLocationId);
        setAuthCookie(res, fallbackLocationId);

        // Return minimal context for the fallback location
        return res.json({
          user: null,
          location: {
            id: fallbackLocationId,
            name: 'Loading...',
            fallback: true
          }
        });

      } catch (error) {
        console.error('❌ Failed to handle marketplace install fallback:', error.message);
        return res.status(422).json({
          error: 'fallback_failed',
          message: 'Failed to set up marketplace install. Please try reinstalling.',
          redirectUrl: '/oauth/install'
        });
      }
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
          const locationTokenResponse = await axios.post(`${API_BASE}/oauth/locationToken`, {
            locationId: locationToCheck,
            companyId: user.companyId
          }, {
            headers: {
              Authorization: `Bearer ${pendingAgency.agency_access_token}`,
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

    // Get cookie location for existing auth flows
    const cookieLocation = req.signedCookies?.ghl_location || req.cookies?.ghl_location || null;

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
const install = await installs.get(currentLocationId);
if (!install?.access_token) throw new Error('No tokens for this location');
const { data: loc } = await axios.get(
  `${API_BASE}/locations/${encodeURIComponent(currentLocationId)}`,
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