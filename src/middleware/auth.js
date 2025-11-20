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
    path: '/',
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
    path: '/',
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

// Helper to detect Safari browser
function isSafari(userAgent) {
  return userAgent &&
         userAgent.includes('Safari') &&
         !userAgent.includes('Chrome') &&
         !userAgent.includes('Chromium');
}

// Authentication middleware
export async function requireAuth(req, res, next) {
  // SECURITY: Only trust the signed cookie for authentication
  // Query parameters and headers are NOT trusted for auth
  const locationId = req.signedCookies?.ghl_location || null;

  if (!locationId) {
    const userAgent = req.headers['user-agent'] || '';
    const isSafariBrowser = isSafari(userAgent);

    // Provide Safari-specific messaging for cookie issues
    if (isSafariBrowser) {
      return res.status(401).json({
        error: 'safari_cookie_blocked',
        message: 'Safari is blocking authentication cookies. Please try Chrome, Firefox, or Edge for the best experience.',
        userAgent: userAgent,
        troubleshooting: {
          recommendation: 'Use Chrome, Firefox, or Edge browser',
          safariIssue: 'Safari\'s privacy settings block cross-site cookies required for this app',
          learnMore: 'https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/'
        }
      });
    }

    return res.status(401).json({
      error: 'Authentication required',
      message: 'Please complete OAuth setup first'
    });
  }

  const hasInstall = await installs.has(locationId);
  if (!hasInstall) {
    clearAuthCookie(res);
    return res.status(401).json({
      error: 'Installation not found',
      message: 'Please re-authenticate'
    });
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

// DEPRECATED - DO NOT USE
// This function was a security vulnerability that allowed bypassing authentication
// Use validateTenant instead to ensure query params match authenticated location
export function handleLocationOverride(req, res, next) {
  // No-op for backwards compatibility during migration
  // All routes should use validateTenant instead
  next();
}

// Export the installs database for use in other files
export { installs };