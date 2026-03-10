// src/routes/auth.js
import { Router } from 'express';
import { clearAuthCookie, installs, requireAuth } from '../middleware/auth.js';

const router = Router();

// Helper to detect Safari browser
function isSafari(userAgent) {
  return userAgent &&
         userAgent.includes('Safari') &&
         !userAgent.includes('Chrome') &&
         !userAgent.includes('Chromium');
}

// Auth status endpoint - also includes browser compatibility info
router.get('/status', async (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const isSafariBrowser = isSafari(userAgent);
  const locationId = req.signedCookies?.ghl_location || req.cookies?.ghl_location;
  const queryLocationId = req.query.locationId;

  // Add Safari warning header
  if (isSafariBrowser) {
    res.set('X-Safari-Cookie-Warning', 'true');
  }

  // Build browser info for frontend
  const browserInfo = {
    isSafari: isSafariBrowser,
    cookieSupport: !!locationId,
    ...(isSafariBrowser && !locationId && {
      warning: 'Safari may be blocking cookies. For the best experience, use Chrome, Firefox, or Edge.',
      troubleshooting: {
        primaryFix: 'Open this app in Chrome, Firefox, or Microsoft Edge',
        alternativeFix: 'In Safari Settings → Privacy → uncheck "Prevent cross-site tracking"'
      }
    })
  };

  if (!locationId) {
    return res.json({
      authenticated: false,
      message: 'Not authenticated',
      browser: browserInfo
    });
  }

  const hasInstall = await installs.has(locationId);
  if (!hasInstall) {
    return res.json({
      authenticated: false,
      message: 'Not authenticated',
      browser: browserInfo
    });
  }

  const install = await installs.get(locationId);
  const isExpired = Date.now() > (install.expires_at ?? 0) - 30_000;

  res.json({
    authenticated: true,
    locationId,
    tokenStatus: isExpired ? 'needs_refresh' : 'valid',
    expiresIn: Math.max(0, Math.floor(((install.expires_at ?? 0) - Date.now()) / 1000)),
    browser: browserInfo
  });
});

// Logout endpoint
router.post('/logout', (req, res) => {
  clearAuthCookie(res);
  res.json({ message: 'Logged out successfully' });
});

// Disconnect and clear installation
router.post('/disconnect', requireAuth, async (req, res) => {
  const locationId = req.locationId;

  try {
    // Delete the location-specific installation only
    // Agency install is preserved so other locations under the same agency still work
    // True uninstalls are handled by the GHL uninstall webhook in server.js
    await installs.delete(locationId);

    // Clear the auth cookie
    clearAuthCookie(res);

    console.log(`✅ Disconnected location ${locationId}`);

    res.json({
      message: 'Disconnected successfully',
      redirectUrl: '/oauth/install'
    });
  } catch (e) {
    console.error('Disconnect error:', e.message);
    res.status(500).json({ error: 'Failed to disconnect' });
  }
});

export default router;