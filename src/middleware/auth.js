// src/middleware/auth.js
import { InstallsDB } from '../../database.js';
import { generateEncryptionKey } from '../utils/crypto.js';

// Initialize the database connection
const ENC_KEY = generateEncryptionKey(process.env.APP_SECRET);
const installs = new InstallsDB(ENC_KEY);

// Cookie helper functions
export function setAuthCookie(res, locationId) {
  res.cookie('ghl_location', locationId, {
    domain: process.env.COOKIE_DOMAIN || undefined,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none',
    signed: true,
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  
  const d = process.env.COOKIE_DOMAIN ? `Domain=${process.env.COOKIE_DOMAIN}; ` : '';
  res.append(
    'Set-Cookie',
    `ghl_location=${encodeURIComponent(locationId)}; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=604800`
  );
}

export function clearAuthCookie(res) {
  res.clearCookie('ghl_location', {
    domain: process.env.COOKIE_DOMAIN || undefined,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none'
  });
  
  const d = process.env.COOKIE_DOMAIN ? `Domain=${process.env.COOKIE_DOMAIN}; ` : '';
  res.append(
    'Set-Cookie',
    `ghl_location=; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=0`
  );
}

// Authentication middleware
export async function requireAuth(req, res, next) {
  let locationId = req.signedCookies?.ghl_location || req.cookies?.ghl_location || null;

  // allow explicit override via ?locationId= or X-Location-Id
  const override = (req.query.locationId || req.get('x-location-id') || '').trim();
  if (override && override !== locationId) {
    if (await installs.has(override)) {
      // set signed cookie
      setAuthCookie(res, override);
      locationId = override;
    } else {
      // Clear old cookies and return auth required instead of forbidden
      clearAuthCookie(res);
      return res.status(401).json({ error: 'Authentication required', message: 'Please complete OAuth setup first' });
    }
  }

  if (!locationId) {
    return res.status(401).json({ error: 'Authentication required', message: 'Please complete OAuth setup first' });
  }

  const hasInstall = await installs.has(locationId);
  if (!hasInstall) {
    clearAuthCookie(res);
    return res.status(401).json({ error: 'Installation not found', message: 'Please re-authenticate' });
  }

  req.locationId = locationId;
  next();
}

export function validateTenant(req, res, next) {
  const paramLocation = req.params.locationId || req.query.locationId;
  
  if (paramLocation && paramLocation !== req.locationId) {
    return res.status(403).json({ 
      error: 'Access denied',
      message: 'Cannot access data for this location'
    });
  }
  
  next();
}

export function handleLocationOverride(req, res, next) {
  const requestedLocationId = req.query.locationId || req.params.locationId;
  
  if (requestedLocationId && requestedLocationId !== req.locationId) {
    console.log(`Location override: ${req.locationId} -> ${requestedLocationId}`);
    req.locationId = requestedLocationId;
  }
  
  next();
}

// Export the installs database for use in other files
export { installs };