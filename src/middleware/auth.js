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
  const userAgent = req.headers['user-agent'] || '';
  const isSafariBrowser = isSafari(userAgent);

  // Always add Safari warning header so frontend can show proactive warning
  if (isSafariBrowser) {
    res.set('X-Safari-Cookie-Warning', 'true');
  }

  // Check signed cookie first, fall back to unsigned cookie (for Safari/partitioned cookies)
  // Query parameters and headers are NOT trusted for auth
  const locationId = req.signedCookies?.ghl_location || req.cookies?.ghl_location || null;
  const queryLocationId = req.query.locationId;

  if (!locationId) {
    // Log details for debugging intermittent Safari issues
    console.warn('🔐 Auth failed - no cookie found', {
      path: req.path,
      isSafari: isSafariBrowser,
      queryLocationId: queryLocationId || 'none',
      hasCookies: Object.keys(req.cookies || {}).length > 0,
      hasSignedCookies: Object.keys(req.signedCookies || {}).length > 0
    });

    // Provide Safari-specific messaging for cookie issues
    if (isSafariBrowser) {
      return res.status(401).json({
        error: 'safari_cookie_blocked',
        message: 'Safari is blocking authentication cookies. Please use Chrome, Firefox, or Edge instead.',
        isSafari: true,
        troubleshooting: {
          primaryFix: 'Open this app in Chrome, Firefox, or Microsoft Edge',
          alternativeFix: 'In Safari Settings → Privacy → uncheck "Prevent cross-site tracking"',
          explanation: 'Safari blocks third-party cookies in iframes by default. This is a browser privacy feature that affects all GHL Marketplace apps.',
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
    console.warn('🔐 Auth failed - installation not found', {
      locationId,
      isSafari: isSafariBrowser
    });
    clearAuthCookie(res);
    return res.status(401).json({
      error: 'Installation not found',
      message: 'Please re-authenticate',
      ...(isSafariBrowser && {
        safariNote: 'If you just installed the app, Safari may have blocked the authentication. Try using Chrome or Firefox.'
      })
    });
  }

  req.locationId = locationId;
  req.isSafari = isSafariBrowser;
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