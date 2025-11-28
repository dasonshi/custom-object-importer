// server.js
import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import axios from 'axios';
import fs from 'fs/promises';
import Papa from 'papaparse';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { InstallsDB } from './database.js';
import CryptoJS from 'crypto-js';
import { parseCSV, cleanupTempFiles } from './src/utils/csvParser.js';
import { normalizeDataType, parseOptions, asBool } from './src/utils/dataTransformers.js';
import { generateEncryptionKey, createSecureState, verifySecureState, validateEncryptionSetup, validateWebhookSignature } from './src/utils/crypto.js';
import { handleAPIError } from './src/utils/apiHelpers.js';
import { setAuthCookie, clearAuthCookie, requireAuth, validateTenant, installs } from './src/middleware/auth.js';
import { withAccessToken, callGHLAPI, API_BASE } from './src/services/tokenService.js';
import authRoutes from './src/routes/auth.js';
import templateRoutes from './src/routes/templates.js';
import debugRoutes from './src/routes/debug.js';
import objectRoutes from './src/routes/objects.js';
import agencyRoutes from './src/routes/agency.js';
import customValuesRoutes from './src/routes/customValues.js';
import associationsRoutes from './src/routes/associations.js';
import importRoutes from './src/routes/imports/index.js';
import appContextRoutes from './src/routes/appContext.js';
import feedbackRoutes from './src/routes/feedback.js';


// Replace the HighLevel lines with this temporary debug version:
import { createRequire } from 'module';
// Generate encryption key for OAuth state
const ENC_KEY = generateEncryptionKey(process.env.APP_SECRET);
const require = createRequire(import.meta.url);
const HighLevelPackage = require('@gohighlevel/api-client');
const HighLevel = HighLevelPackage.default || HighLevelPackage.HighLevel || HighLevelPackage;
global.ghl = new HighLevel({
  clientId: process.env.GHL_CLIENT_ID,
  clientSecret: process.env.GHL_CLIENT_SECRET
});

if (typeof global.ghl.setAccessToken !== 'function') {
  global.ghl.setAccessToken = function (token) { this._accessToken = token; };
}
// Polyfill: some SDK builds don’t expose setAccessToken. Prevent runtime crashes.
if (typeof global.ghlsetAccessToken !== 'function') {
  global.ghlsetAccessToken = function (token/*, locationId */) {
    // no-op: callers expect this to exist; routes using axios attach the header directly
    this._accessToken = token;
  };
}



const app = express();

// trust Cloudflare/Render proxy so req.secure is true and secure cookies work
app.set('trust proxy', 1); // trust CF + Render chain
app.disable('x-powered-by');

// ===== OAuth Install (Marketplace chooselocation endpoint, fixed scopes) =====
app.get('/oauth/install', (req, res) => {
  const state = createSecureState(ENC_KEY);

  const scopes = [
    'objects/schema.readonly',
    'objects/schema.write',
    'objects/record.readonly',
    'objects/record.write',
    'locations/customFields.readonly',
    'locations/customFields.write',
    'locations/customValues.readonly',
    'locations/customValues.write',
    'locations.readonly',
    'marketplace-installer-details.readonly',
    'associations.readonly',
    'associations/relation.readonly',
    'associations/relation.write'

  ].join(' ');

  const url = `https://marketplace.leadconnectorhq.com/oauth/chooselocation` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(process.env.GHL_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(process.env.GHL_REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&state=${state}`;

  res.redirect(url);
});


const upload = multer({
  dest: '/tmp',
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB max per file
    files: 5 // Max 5 files per request
  }
});
const REQUIRED_ENV = ['GHL_CLIENT_ID', 'GHL_CLIENT_SECRET', 'GHL_REDIRECT_URI'];
REQUIRED_ENV.forEach(v => {
  if (!process.env[v]) { 
    console.error(`❌ Missing required environment variable: ${v}`); 
    process.exit(1); 
  }
});


// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Cookie parser with your APP_SECRET
app.use(cookieParser(process.env.APP_SECRET || 'dev-secret-change-me-in-production'));

// Security headers with helmet
app.use(helmet({
  contentSecurityPolicy: false, // We set CSP manually below for GHL iframe embedding
  crossOriginEmbedderPolicy: false, // Allow embedding in GHL
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  }
}));

const COOKIE_CLEAR_OPTS = {
  domain: process.env.COOKIE_DOMAIN || undefined, // e.g., importer.savvysales.ai
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'none'
};

// CORS configuration
const allowedList = (process.env.CORS_ORIGINS || 'http://localhost:3000,http://localhost:8080')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// allow Lovable (new) preview domains and old sandbox domains
const allowedRegexes = [
  // old-style sandboxes, e.g. https://<uuid>.sandbox.lovable.dev
  /^https:\/\/[a-f0-9-]+\.sandbox\.lovable\.dev$/i,
  // new preview domains (handles preview--*, id-preview--*, nested, etc.)
  /^https:\/\/([a-z0-9-]+\.)*lovable\.app$/i,
  // Lovable project domains
  /^https:\/\/([a-z0-9-]+\.)*lovableproject\.com$/i,
];

function isAllowedOrigin(origin) {
  if (allowedList.includes(origin)) return true;
  return allowedRegexes.some(rx => rx.test(origin));
}

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // Postman/mobile/no CORS
    if (isAllowedOrigin(origin)) return cb(null, true);
    console.warn(`CORS blocked origin: ${origin}`);
    // Don't throw error - just deny the request gracefully
    cb(null, false);
  },
  credentials: true, // allow cookies
}));
// Allow embedding inside HighLevel
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "frame-ancestors 'self' https://app.gohighlevel.com https://*.gohighlevel.com"
  );
  next();
});

// Rate limiting
app.use('/oauth', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'OPTIONS',
  message: { error: 'Too many OAuth requests, please try again later' }
}));

app.use('/import', rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'OPTIONS',
  message: { error: 'Too many import requests, please slow down' }
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50, // Reduced from 200 to prevent enumeration attacks
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'OPTIONS' || req.path === '/health',
  message: { error: 'Rate limit exceeded, please try again later' }
}));
// Mount auth routes
app.use('/api/auth', authRoutes);
app.use('/templates', templateRoutes);
app.use('/api/debug', debugRoutes);
app.use('/api/objects', objectRoutes);
app.use('/api', agencyRoutes);
app.use('/api/custom-values', customValuesRoutes);
app.use('/api/associations', associationsRoutes);
app.use('/api/feedback', feedbackRoutes);
app.use('/import', importRoutes);
app.use('/api', appContextRoutes);
app.use('/api', importRoutes);

// ===== Health Check Route =====
app.get('/health', async (req, res) => {
  const healthData = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    version: process.env.npm_package_version || '1.0.0',
    services: {
      ghl_api: 'unknown', // Could ping GHL API here
      database: 'connected'
    },
    memory: {
      used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
      total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + ' MB'
    },
    activeInstalls: await installs.size()
  };
  
  res.status(200).json(healthData);
});

app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code) {
    return res.status(400).send('Authorization code is required');
  }
  
// State parameter handling:
  // - GHL Marketplace installs do NOT include state parameter
  // - Direct OAuth installs (from our /oauth/install endpoint) include state
  // - If state is provided, it MUST be valid (CSRF protection)
  // - If state is missing, allow it (marketplace install)
  if (state && typeof state === 'string' && state.length > 0) {
    try {
      verifySecureState(state, ENC_KEY);
      console.log('✅ OAuth state validated successfully');
    } catch (e) {
      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
      console.error('🚨 OAuth state validation failed:', {
        timestamp: new Date().toISOString(),
        error: e.message,
        clientIp,
        userAgent: req.headers['user-agent'],
        referer: req.headers['referer']
      });
      return res.redirect('/launch?error=invalid_state');
    }
  } else {
    console.log('ℹ️ OAuth callback without state (likely GHL Marketplace install) - proceeding');
  }

  try {
    const codePrefix = String(code).substring(0, 8);
    console.log(`OAuth callback - code: ${codePrefix}..., client_id: ${process.env.GHL_CLIENT_ID}, redirect_uri: ${process.env.GHL_REDIRECT_URI}`);

    const tokenResp = await global.ghl.oauth.getAccessToken({
      client_id: process.env.GHL_CLIENT_ID,
      client_secret: process.env.GHL_CLIENT_SECRET,
      code: String(code),
      grant_type: 'authorization_code',
      redirect_uri: process.env.GHL_REDIRECT_URI,
    });

    // SECURITY: Only log token metadata in development, never log actual tokens
    if (process.env.NODE_ENV !== 'production') {
      console.log('Token response received:', tokenResp ? 'Success' : 'No response');
      console.log('LocationId from response:', tokenResp?.locationId || 'Not found');
      console.log('IsBulkInstallation:', tokenResp?.isBulkInstallation || false);
      console.log('UserType:', tokenResp?.userType || 'unknown');
      console.log('CompanyId:', tokenResp?.companyId || 'Not found');
    } else {
      console.log('OAuth token exchange successful for locationId:', tokenResp?.locationId);
    }
    const { access_token, refresh_token, expires_in, locationId, isBulkInstallation, userType, companyId } = tokenResp || {};

if (!locationId) {
  // Handle bulk installation vs pending token scenarios
  if (isBulkInstallation && userType === 'Company' && companyId) {
    console.log('🏢 Bulk installation detected - fetching installed locations');
    console.log('API call parameters:', {
      companyId,
      appId: '68ae6ca8bb70273ca2ca7e24',
      clientId: process.env.GHL_CLIENT_ID
    });

    try {
      // Get locations where app is installed using the agency token
      const locationsResponse = await axios.get(`${API_BASE}/oauth/installedLocations`, {
        headers: {
          Authorization: `Bearer ${access_token}`,
          Version: '2021-07-28',
          Accept: 'application/json'
        },
        params: {
          companyId,
          appId: '68ae6ca8bb70273ca2ca7e24', // Marketplace App ID (temporarily hardcoded)
          isInstalled: true
        },
        timeout: 10000,
      });

      console.log('📍 Installed locations response:', {
        status: locationsResponse.status,
        locationCount: locationsResponse.data?.locations?.length || 0,
        locations: locationsResponse.data?.locations?.map(loc => ({ id: loc._id, name: loc.name, isInstalled: loc.isInstalled })) || []
      });

      // Debug: Check what isInstalled values we're getting
      const allLocations = locationsResponse.data?.locations || [];
      console.log('🔍 Location isInstalled values:', allLocations.map(loc => ({
        id: loc._id,
        name: loc.name,
        isInstalled: loc.isInstalled,
        hasIsInstalledProp: loc.hasOwnProperty('isInstalled')
      })));

      const installedLocations = allLocations.filter(loc => loc.isInstalled) || [];

      console.log('✅ Filtered installed locations:', installedLocations.length, 'out of', allLocations.length, 'total locations');

      if (installedLocations.length > 0) {
        // For each location, we need to get location-specific tokens
        // Agency tokens can't access location-specific APIs due to authClass restrictions
        console.log('🔄 Getting location-specific tokens for', installedLocations.length, 'locations');

        for (const location of installedLocations) {
          try {
            console.log(`🎯 Getting location token for: ${location.name} (${location._id})`);

            // Use HighLevel's API to get location-specific tokens
            const locationTokenResponse = await axios.post(`${API_BASE}/oauth/locationToken`, {
              locationId: location._id,
              companyId: companyId
            }, {
              headers: {
                Authorization: `Bearer ${access_token}`,
                Version: '2021-07-28',
                Accept: 'application/json'
              },
              timeout: 10000,
            });

            console.log('📍 Location token response:', {
              status: locationTokenResponse.status,
              hasAccessToken: !!locationTokenResponse.data?.access_token,
              hasRefreshToken: !!locationTokenResponse.data?.refresh_token
            });

            if (locationTokenResponse.data?.access_token) {
              // Store the location-specific token
              await installs.set(location._id, {
                access_token: locationTokenResponse.data.access_token,
                refresh_token: locationTokenResponse.data.refresh_token,
                expires_at: Date.now() + ((locationTokenResponse.data.expires_in ?? 3600) * 1000) - 60_000,
                isBulkInstallation: true,
                userType: 'Location', // This should be Location type, not Company
                companyId
              });

              console.log(`✅ Location token stored for: ${location.name}`);
            } else {
              console.log(`❌ No location token received for: ${location.name}`);
            }

          } catch (error) {
            console.error(`❌ Failed to get location token for ${location.name}:`, error?.response?.status, error?.response?.data || error.message);

            // Fallback: store agency token but mark it properly
            console.log(`🔄 Falling back to agency token for: ${location.name}`);
            await installs.set(location._id, {
              access_token: access_token,
              refresh_token: refresh_token,
              expires_at: Date.now() + ((expires_in ?? 3600) * 1000) - 60_000,
              isBulkInstallation: true,
              userType: 'Company', // Agency token
              companyId,
              isAgencyToken: true // Flag to indicate this needs special handling
            });
          }
        }

        console.log('💾 Bulk installation processed for', installedLocations.length, 'locations');
      }

      // Always save agency tokens for on-demand location token exchange
      // This handles the case where GHL returns 0 installed locations at install time
      // (timing issue or API quirk) - the app-context endpoint can exchange later
      console.log('💾 Saving agency tokens for company:', companyId);
      await installs.saveAgencyInstall(companyId, {
        agency_access_token: access_token,
        agency_refresh_token: refresh_token,
        agency_expires_at: Date.now() + ((expires_in ?? 3600) * 1000) - 60_000,
        userType: 'Company',
        companyId,
        locations: allLocations.map(loc => ({ id: loc._id, name: loc.name }))
      });
      console.log('✅ Agency tokens saved for on-demand consumption');

      return res.redirect('/launch');

    } catch (error) {
      console.error('❌ Failed to fetch installed locations:', error?.response?.status, error?.response?.data || error.message);
      return res.redirect('/launch?error=api_failed');
    }
  }

  // For non-bulk installations, this should not happen in marketplace installs
  console.log('⚠️ Non-bulk installation without locationId - this should not happen in marketplace installs');
  return res.redirect('/launch?error=no_location_id');
}

// Normal case: we have locationId, save and set cookies
await installs.set(locationId, {
  access_token,
  refresh_token,
  expires_at: Date.now() + ((expires_in ?? 3600) * 1000) - 60_000
});
setAuthCookie(res, locationId);

// Add a CHIPS/Partitioned cookie so Chrome will send it cross-site from Lovable
{
  const d = process.env.COOKIE_DOMAIN ? `Domain=${process.env.COOKIE_DOMAIN}; ` : '';
  res.append(
    'Set-Cookie',
    `ghl_location=${encodeURIComponent(locationId)}; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=604800`
  );
}

// Redirect to /launch page which sends postMessage and closes the popup
return res.redirect('/launch');
    
  } catch (e) {
    console.error('OAuth callback error:', e?.response?.status, e?.response?.data || e.message);
    res.status(400).json({
      error: 'OAuth exchange failed',
      details: e?.response?.data?.error_description || e.message
    });
  }
});

// Uninstall webhook handler
app.post('/oauth/uninstall', express.json(), async (req, res) => {
  try {
    // SECURITY: Validate webhook signature to prevent unauthorized uninstall requests
    const signature = req.headers['x-webhook-signature'] || req.headers['x-ghl-signature'];

    if (!validateWebhookSignature(req.body, signature, process.env.GHL_CLIENT_SECRET)) {
      console.error('❌ Invalid webhook signature - rejecting uninstall request');
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid webhook signature'
      });
    }

    const { type, appId, locationId, companyId } = req.body;

    console.log(`✅ Uninstall webhook received with valid signature:`, { type, appId, locationId, companyId });

    if (type === 'UNINSTALL') {
      if (locationId) {
        await installs.delete(locationId);
        console.log(`✅ Removed location installation: ${locationId}`);
      } else if (companyId) {
        // For agency-level uninstalls, we'd need to remove all locations for this company
        // This would require tracking company->location mapping, which we don't currently do
        console.log(`⚠️ Agency-level uninstall for company ${companyId} - manual cleanup may be needed`);
      }
    }

    res.json({ success: true, message: 'Uninstall processed' });
  } catch (e) {
    console.error('Uninstall webhook error:', e.message);
    res.status(500).json({ error: 'Failed to process uninstall' });
  }
});

// Fields import route moved to src/routes/imports/index.js
// Get object schema by key (proxied to GHL)
// FE calls: GET /api/objects/:objectKey/schema?fetchProperties=true[&locationId=...]

// Records import route moved to src/routes/imports/index.js
// 4) Import Association TYPES (schema-level)
app.post('/api/associations/types/import', requireAuth, upload.single('associations'), async (req, res) => {
  const locationId = req.locationId;
const headers = { Authorization: `Bearer ${await withAccessToken(locationId)}` };
  if (!req.file) return res.status(400).json({ error: 'Associations CSV file is required' });

  try {
    const rows = await parseCSV(req.file.path);

    const created = [];
    const skipped = [];
    const errors  = [];

    const ensureKey = (k) => {
      if (!k) return k;
      // only prefix custom objects (contacts etc. should be left as-is)
      return /^custom_objects\./.test(k) ? k : (['contact','opportunity','business'].includes(k) ? k : `custom_objects.${k}`);
    };

    for (const row of rows) {
      try {
        const key = String(row.association_key || row.key || '').trim();
        const firstObjectKey  = ensureKey(String(row.first_object_key || '').trim());
        const firstObjectLabel = String(row.first_object_label || row.first_label || '').trim();
        const secondObjectKey = ensureKey(String(row.second_object_key || '').trim());
        const secondObjectLabel = String(row.second_object_label || row.second_label || '').trim();

        if (!key || !firstObjectKey || !firstObjectLabel || !secondObjectKey || !secondObjectLabel) {
          throw new Error('Missing required fields (key, first_object_key/label, second_object_key/label)');
        }

        const payload = {
          locationId,
          key,
          firstObjectLabel,
          firstObjectKey,
          secondObjectLabel,
          secondObjectKey
        };

        // Create association TYPE
        const r = await axios.post(`${API_BASE}/associations/`, payload, { headers });

        created.push({
          id: r.data?.id || r.data?.data?.id,
          key,
          firstObjectKey,
          secondObjectKey
        });
      } catch (e) {
        // If API returns “already exists”/duplicate, treat as skip
        const msg = e?.response?.data || e.message;
        if (/(exist|duplicate)/i.test(String(msg))) {
          skipped.push({ row, reason: 'already exists' });
        } else {
          errors.push({ row, error: msg });
          console.error('Association type create error:', msg);
        }
      }
    }

await cleanupTempFiles([req.file.path]);    res.json({ success: errors.length === 0, created, skipped, errors });

  } catch (e) {
  handleAPIError(res, e, 'Association types import');
  }
});
// 5) Import Custom Values
app.post('/api/custom-values/import', requireAuth, upload.single('customValues'), async (req, res) => {
  const locationId = req.locationId;
const headers = { Authorization: `Bearer ${await withAccessToken(locationId)}` };
  
  if (!req.file) {
    return res.status(400).json({ error: 'Custom values CSV file is required' });
  }

  try {
    const customValues = await parseCSV(req.file.path);
    
    const created = [];
    const updated = [];
    const errors = [];

    for (const row of customValues) {
      try {
        const payload = {
          name: String(row.name || '').trim(),
          value: String(row.value || '').trim()
        };

        if (!payload.name || !payload.value) {
          throw new Error('Both name and value are required');
        }

        let result;
        const customValueId = row.id ? String(row.id).trim() : null;

        if (customValueId) {
          // Update existing custom value
          result = await axios.put(
            `${API_BASE}/locations/${locationId}/customValues/${customValueId}`,
            payload,
            { headers }
          );
          updated.push({ 
            id: customValueId, 
            name: payload.name,
            value: payload.value
          });
        } else {
          // Create new custom value
          result = await axios.post(
            `${API_BASE}/locations/${locationId}/customValues`,
            payload,
            { headers }
          );
          created.push({ 
            id: result.data?.id || result.data?.data?.id,
            name: payload.name,
            value: payload.value
          });
        }
      } catch (e) {
        errors.push({ 
          name: row.name || 'unnamed', 
          error: e?.response?.data || e.message 
        });
        console.error(`Failed to process custom value ${row.name}:`, e?.response?.data || e.message);
      }
    }

await cleanupTempFiles([req.file.path]);
    res.json({
      success: errors.length === 0,
      message: `Processed ${customValues.length} custom values`,
      created,
      updated,
      errors,
      summary: {
        total: customValues.length,
        created: created.length,
        updated: updated.length,
        failed: errors.length
      }
    });

  } catch (e) {
 handleAPIError(res, e, 'Custom values import');
  }
});
// 6. Import Relations (record-to-record links within associations)
app.post('/api/associations/relations/import', requireAuth, upload.single('relations'), async (req, res) => {
  const locationId = req.locationId;
  const token = await withAccessToken(locationId);
  const headers = { 
    Authorization: `Bearer ${token}`,
    Version: '2021-07-28'
  };

  if (!req.file) {
    return res.status(400).json({ error: 'Relations CSV file is required' });
  }

  try {
    const relations = await parseCSV(req.file.path);
    const created = [];
    const errors = [];
    const skipped = [];

    for (const row of relations) {
      try {
        // Required fields
        const associationId = String(row.association_id || '').trim();
        const firstRecordId = String(row.first_record_id || '').trim();
        const secondRecordId = String(row.second_record_id || '').trim();

        if (!associationId || !firstRecordId || !secondRecordId) {
          throw new Error('Missing required fields (association_id, first_record_id, second_record_id)');
        }

        // Optional: validate that the association exists first
        try {
          await axios.get(
            `${API_BASE}/associations/${associationId}`,
            { 
              headers,
              params: { locationId }
            }
          );
        } catch (e) {
          if (e?.response?.status === 404) {
            throw new Error(`Association ${associationId} not found`);
          }
        }

        // Create the relation
        const payload = {
          locationId: locationId,
          associationId: associationId,
          firstRecordId: firstRecordId,
          secondRecordId: secondRecordId
        };

        const result = await axios.post(
          `${API_BASE}/associations/relations`,
          payload,
          { headers }
        );

        created.push({
          id: result.data?.id || result.data?.data?.id,
          associationId,
          firstRecordId,
          secondRecordId,
          description: `${firstRecordId} ↔ ${secondRecordId}`
        });

      } catch (e) {
        const msg = e?.response?.data?.message || e?.response?.data || e.message;
        
        // Check if relation already exists
        if (/(exist|duplicate)/i.test(String(msg))) {
          skipped.push({ 
            associationId: row.association_id,
            firstRecordId: row.first_record_id,
            secondRecordId: row.second_record_id,
            reason: 'Relation already exists'
          });
        } else {
          errors.push({ 
            row,
            error: msg
          });
          console.error('Relation create error:', msg);
        }
      }
    }

    await cleanupTempFiles([req.file.path]);

    res.json({
      success: errors.length === 0,
      message: `Processed ${relations.length} relations`,
      created,
      skipped,
      errors,
      summary: {
        total: relations.length,
        created: created.length,
        skipped: skipped.length,
        failed: errors.length
      }
    });

  } catch (e) {
    handleAPIError(res, e, 'Relations import');
  }
});
// ===== Error Handling =====
// Basic entry points
app.get('/', (req, res) => {
  // Simple bounce to your in-app page
  return res.redirect('/launch');
});

app.get('/launch', (req, res) => {
  const error = req.query.error;

  // Handle error cases
  if (error === 'missing_state' || error === 'invalid_state') {
    const errorTitle = error === 'missing_state'
      ? 'Security Check Failed'
      : 'Session Expired';
    const errorMessage = error === 'missing_state'
      ? 'The authentication request was missing required security information. This may indicate a security issue.'
      : 'Your authentication session has expired. Please try again.';

    return res.status(403).send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>${errorTitle}</title>
    <style>
      body {
        font-family: system-ui, -apple-system, sans-serif;
        padding: 40px;
        text-align: center;
        background: #f5f5f5;
      }
      .container {
        max-width: 500px;
        margin: 100px auto;
        background: white;
        padding: 40px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      h1 {
        color: #ef4444;
        font-size: 24px;
        margin-bottom: 16px;
      }
      p {
        color: #666;
        margin-bottom: 20px;
        line-height: 1.5;
      }
      .retry-btn {
        display: inline-block;
        padding: 12px 24px;
        background: #3b82f6;
        color: white;
        text-decoration: none;
        border-radius: 6px;
        font-weight: 500;
        transition: background 0.2s;
      }
      .retry-btn:hover {
        background: #2563eb;
      }
      .error-code {
        font-size: 12px;
        color: #999;
        margin-top: 20px;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>⚠️ ${errorTitle}</h1>
      <p>${errorMessage}</p>
      <a href="/oauth/install" class="retry-btn">Try Again</a>
      <p class="error-code">Error: ${error}</p>
    </div>
    <script>
      // Notify parent window of error
      (function() {
        const errorType = '${error}';
        if (window.opener) {
          try {
            window.opener.postMessage({ type: 'oauth_error', error: errorType }, '*');
          } catch (e) {
            console.error('Could not message parent:', e);
          }
        }
        if (window.parent && window.parent !== window) {
          try {
            window.parent.postMessage({ type: 'oauth_error', error: errorType }, '*');
          } catch (e) {
            console.error('Could not message parent frame:', e);
          }
        }
      })();
    </script>
  </body>
</html>`);
  }

  // Handle other error cases
  if (error === 'no_location_id') {
    return res.status(400).send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Installation Error</title>
    <style>
      body {
        font-family: system-ui, -apple-system, sans-serif;
        padding: 40px;
        text-align: center;
        background: #f5f5f5;
      }
      .container {
        max-width: 500px;
        margin: 100px auto;
        background: white;
        padding: 40px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      h1 {
        color: #ef4444;
        font-size: 24px;
        margin-bottom: 16px;
      }
      p {
        color: #666;
        margin-bottom: 20px;
        line-height: 1.5;
      }
      .retry-btn {
        display: inline-block;
        padding: 12px 24px;
        background: #3b82f6;
        color: white;
        text-decoration: none;
        border-radius: 6px;
        font-weight: 500;
        transition: background 0.2s;
      }
      .retry-btn:hover {
        background: #2563eb;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>⚠️ Installation Error</h1>
      <p>Unable to complete the installation. Please ensure you selected a location and try again.</p>
      <a href="/oauth/install" class="retry-btn">Try Again</a>
    </div>
  </body>
</html>`);
  }

  // Success case - original behavior
  res.status(200).send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Connected</title>
    <style>
      body {
        font-family: system-ui, -apple-system, sans-serif;
        padding: 40px;
        text-align: center;
        background: #f5f5f5;
      }
      .container {
        max-width: 400px;
        margin: 100px auto;
        background: white;
        padding: 40px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      h1 {
        color: #22c55e;
        font-size: 24px;
        margin-bottom: 16px;
      }
      p {
        color: #666;
        margin-bottom: 20px;
      }
      .spinner {
        border: 3px solid #f3f3f3;
        border-top: 3px solid #22c55e;
        border-radius: 50%;
        width: 40px;
        height: 40px;
        animation: spin 1s linear infinite;
        margin: 20px auto;
      }
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>✓ Connected Successfully</h1>
      <div class="spinner"></div>
      <p>Closing window...</p>
    </div>
    <script>
      // Immediately try to notify parent and close
      (function() {
        // Notify parent window (if opened as popup)
        if (window.opener) {
          try {
            window.opener.postMessage({ type: 'oauth_success' }, '*');
          } catch (e) {
            console.error('Could not message parent:', e);
          }
        }

        // Also try parent frame (if in iframe)
        if (window.parent && window.parent !== window) {
          try {
            window.parent.postMessage({ type: 'oauth_success' }, '*');
          } catch (e) {
            console.error('Could not message parent frame:', e);
          }
        }

        // Auto close after brief delay to ensure message is sent
        setTimeout(() => {
          try {
            window.close();
          } catch (e) {
            // If close fails, show a message
            document.querySelector('.container').innerHTML =
              '<h1>✓ Connected Successfully</h1>' +
              '<p>You can now close this window and return to the app.</p>';
          }
        }, 500); // Half second delay to ensure message delivery
      })();
    </script>
  </body>
</html>`);
});

// ===== Server Startup =====
validateEncryptionSetup();

const PORT = process.env.PORT || 8080;

app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  
  try {
    const installCount = await installs.size();
    console.log(`📊 Database connected with ${installCount} installations`);
  } catch (error) {
    console.error('❌ Database connection error:', error.message);
  }
});
// Multer error handling (file upload errors)
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        error: 'File too large',
        message: 'File size cannot exceed 100MB'
      });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        error: 'Too many files',
        message: 'Maximum 5 files allowed per request'
      });
    }
    return res.status(400).json({
      error: 'File upload error',
      message: err.message
    });
  }
  next(err);
});

// General error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});





// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await installs.disconnect();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  await installs.disconnect();
  process.exit(0);
});