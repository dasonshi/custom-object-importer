// src/routes/auth.js
import { Router } from 'express';
import { clearAuthCookie, installs, requireAuth } from '../middleware/auth.js';

const router = Router();

// Auth status endpoint
router.get('/status', async (req, res) => {
  const locationId = req.signedCookies?.ghl_location;
  
  if (!locationId) {
    return res.json({
      authenticated: false,
      message: 'Not authenticated'
    });
  }

  const hasInstall = await installs.has(locationId);
  if (!hasInstall) {
    return res.json({
      authenticated: false,
      message: 'Not authenticated'
    });
  }

  const install = await installs.get(locationId);
  const isExpired = Date.now() > (install.expires_at ?? 0) - 30_000;
  
  res.json({
    authenticated: true,
    locationId,
    tokenStatus: isExpired ? 'needs_refresh' : 'valid',
    expiresIn: Math.max(0, Math.floor(((install.expires_at ?? 0) - Date.now()) / 1000))
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
    await installs.delete(locationId);
    clearAuthCookie(res);
    
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