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
import { InstallsDB } from './database.js';


const app = express();
// trust Cloudflare/Render proxy so req.secure is true and secure cookies work
app.set('trust proxy', 1); // trust CF + Render chain
app.disable('x-powered-by');

// ===== OAuth: Install (Marketplace chooselocation endpoint, fixed scopes) =====
app.get('/oauth/install', (req, res) => {
  const state = createSecureState();

  const scopes = [
    'objects/schema.readonly',
    'objects/schema.write',
    'objects/record.readonly',
    'objects/record.write',
    'locations/customFields.readonly',
    'locations/customFields.write'
  ].join(' ');

  const url = `https://marketplace.gohighlevel.com/oauth/chooselocation` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(process.env.GHL_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(process.env.GHL_REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&state=${state}`;

  res.redirect(url);
});

console.log('Environment check:', { 
  CLIENT_ID: process.env.GHL_CLIENT_ID, 
  REDIRECT_URI: process.env.GHL_REDIRECT_URI,
  HAS_SECRET: !!process.env.GHL_CLIENT_SECRET 
});
const upload = multer({ dest: '/tmp' });
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
    cb(new Error('CORS policy violation'));
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
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'OPTIONS' || req.path === '/health',
  message: { error: 'Rate limit exceeded, please try again later' }
}));

const API_BASE = 'https://services.leadconnectorhq.com';
// Generate encryption key from APP_SECRET
const ENC_KEY = crypto.createHash('sha256')
  .update(String(process.env.APP_SECRET || 'dev-secret-change-me-in-production'))
  .digest();

function encryptToken(token) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(token, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decryptToken(encryptedToken) {
  const buffer = Buffer.from(encryptedToken, 'base64');
  const iv = buffer.subarray(0, 12);
  const tag = buffer.subarray(12, 28);
  const encrypted = buffer.subarray(28);
  
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

function validateEncryptionSetup() {
  if (process.env.NODE_ENV === 'production') {
    if (!process.env.APP_SECRET || process.env.APP_SECRET === 'dev-secret-change-me-in-production') {
      console.error('❌ APP_SECRET must be set to a secure random value in production!');
      process.exit(1);
    }
    if (process.env.APP_SECRET.length < 32) {
      console.error('❌ APP_SECRET should be at least 32 characters long for security');
      process.exit(1);
    }
  }
}

// Store tokens safely (use database in production)
const installs = new InstallsDB(ENC_KEY);

function authHeader(token) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
    'Content-Type': 'application/json',
    Version: '2021-07-28'
  };
}
function createSecureState() {
  const payload = {
    timestamp: Date.now(),
    nonce: crypto.randomBytes(16).toString('hex')
  };
  
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', ENC_KEY).update(data).digest('base64url');
  
  return `${data}.${signature}`;
}

function verifySecureState(state) {
  if (!state || typeof state !== 'string') {
    throw new Error('Missing or invalid state parameter');
  }
  
  const parts = state.split('.');
  if (parts.length !== 2) {
    throw new Error('Invalid state format');
  }
  
  const [data, signature] = parts;
  
  // Verify signature
  const expectedSignature = crypto.createHmac('sha256', ENC_KEY).update(data).digest('base64url');
  if (signature !== expectedSignature) {
    throw new Error('Invalid state signature');
  }
  
  // Parse and validate payload
  let payload;
  try {
    payload = JSON.parse(Buffer.from(data, 'base64url').toString());
  } catch (e) {
    throw new Error('Invalid state payload');
  }
  
  // Check expiration (10 minutes)
  const age = Date.now() - payload.timestamp;
  const MAX_AGE = 10 * 60 * 1000; // 10 minutes
  
  if (age > MAX_AGE) {
    throw new Error('State parameter expired');
  }
  
  if (age < 0) {
    throw new Error('State parameter from future');
  }
  
  return payload;
}
// Authentication middleware functions
// Authentication middleware functions
async function requireAuth(req, res, next) {
const locationId = req.signedCookies?.ghl_location || req.cookies?.ghl_location;

  if (!locationId) {
    return res.status(401).json({
      error: 'Authentication required',
      message: 'Please complete OAuth setup first'
    });
  }

  // Verify this location still has valid tokens
  const hasInstall = await installs.has(locationId);
  if (!hasInstall) {
    // Clear invalid cookies (signed + partitioned)
    res.clearCookie('ghl_location', COOKIE_CLEAR_OPTS);
    {
      const d = process.env.COOKIE_DOMAIN ? `Domain=${process.env.COOKIE_DOMAIN}; ` : '';
      res.append(
        'Set-Cookie',
        `ghl_location=; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=0`
      );
    }
    return res.status(401).json({
      error: 'Installation not found',
      message: 'Please re-authenticate'
    });
  }

  req.locationId = locationId;
  next();
}
function validateTenant(req, res, next) {
  const paramLocation = req.params.locationId || req.query.locationId;
  
  if (paramLocation && paramLocation !== req.locationId) {
    return res.status(403).json({ 
      error: 'Access denied',
      message: 'Cannot access data for this location'
    });
  }
  
  next();
}
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
// Auth status endpoint
app.get('/api/auth/status', async (req, res) => {
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
app.post('/api/auth/logout', (req, res) => {
res.clearCookie('ghl_location', COOKIE_CLEAR_OPTS);
  res.json({ message: 'Logged out successfully' });
});
// Disconnect and clear installation
app.post('/api/auth/disconnect', requireAuth, async (req, res) => {
  const locationId = req.locationId;
  
  try {
    // Remove installation from database
    await installs.delete(locationId);
    
    // Clear cookies
    res.clearCookie('ghl_location', COOKIE_CLEAR_OPTS);
    {
      const d = process.env.COOKIE_DOMAIN ? `Domain=${process.env.COOKIE_DOMAIN}; ` : '';
      res.append(
        'Set-Cookie',
        `ghl_location=; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=0`
      );
    }
    
    res.json({ 
      message: 'Disconnected successfully',
      redirectUrl: '/oauth/install' // Frontend can redirect here for reauth
    });
  } catch (e) {
    console.error('Disconnect error:', e.message);
    res.status(500).json({ error: 'Failed to disconnect' });
  }
});

app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;
  
  if (!code) {
    return res.status(400).send('Authorization code is required');
  }
  
// Marketplace sometimes omits `state`; verify if present, otherwise proceed
if (typeof state === 'string' && state.length > 0) {
  try {
    verifySecureState(state);
  } catch (e) {
    console.error('OAuth state validation failed:', e.message);
    return res.status(400).send(`Invalid or expired state: ${e.message}`);
  }
} else {
  console.warn('OAuth callback arrived without state (likely Marketplace install). Proceeding.');
}

  try {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: String(code),
      client_id: process.env.GHL_CLIENT_ID,
      client_secret: process.env.GHL_CLIENT_SECRET,
      redirect_uri: process.env.GHL_REDIRECT_URI
    });

    const tokenResp = await axios.post(
      `${API_BASE}/oauth/token`,
      body.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token, refresh_token, expires_in, locationId } = tokenResp.data;

    await installs.set(locationId, {
      access_token,
      refresh_token,
      expires_at: Date.now() + ((expires_in ?? 3600) * 1000) - 60_000
    });

    // Set secure authentication cookie
res.cookie('ghl_location', locationId, {
  domain: process.env.COOKIE_DOMAIN || undefined, // e.g., importer.savvysales.ai
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',  // required when SameSite=None
  sameSite: 'none',                                // needed if GHL loads you in an iframe
  signed: true,
  maxAge: 7 * 24 * 60 * 60 * 1000
});

// 👇 add this immediately after to support cross-site (Lovable) requests in Chrome
{
  const d = process.env.COOKIE_DOMAIN ? `Domain=${process.env.COOKIE_DOMAIN}; ` : '';
  res.append(
    'Set-Cookie',
    `ghl_location=${encodeURIComponent(locationId)}; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=604800`
  );
}

// Add a CHIPS/Partitioned cookie so Chrome will send it cross-site from Lovable
{
  const d = process.env.COOKIE_DOMAIN ? `Domain=${process.env.COOKIE_DOMAIN}; ` : '';
  res.append(
    'Set-Cookie',
    `ghl_location=${encodeURIComponent(locationId)}; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=604800`
  );
}


    res.send(`<!doctype html><html><body style="font-family:system-ui;padding:24px">
      <h1>✅ Connected Successfully</h1>
      <p>Authenticated for location <code>${locationId}</code>.</p>
      <p><a href="/api/auth/status">Check Auth Status</a> | 
         <a href="/api/objects">View Objects</a></p>
      <script>
        // Auto-close if opened in popup
        if (window.opener) {
          window.opener.postMessage({ type: 'oauth_success', locationId: '${locationId}' }, '*');
          window.close();
        }
      </script>
    </body></html>`);
    
  } catch (e) {
    console.error('OAuth callback error:', e?.response?.status, e?.response?.data || e.message);
    res.status(400).json({
      error: 'OAuth exchange failed',
      details: e?.response?.data?.error_description || e.message
    });
  }
});

// ===== Helper Functions =====
async function withAccessToken(locationId) {
  let row = await installs.get(locationId);
  if (!row) throw new Error(`No installation found for locationId: ${locationId}`);

  // Refresh if expiring within 30s
  if (Date.now() > (row.expires_at ?? 0) - 30_000) {
    try {
      const body = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: row.refresh_token,
        client_id: process.env.GHL_CLIENT_ID,
        client_secret: process.env.GHL_CLIENT_SECRET
      });

      const r = await axios.post(
        `${API_BASE}/oauth/token`,
        body.toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      row = {
        access_token: r.data.access_token,
        refresh_token: r.data.refresh_token || row.refresh_token,
        expires_at: Date.now() + ((r.data.expires_in ?? 3600) * 1000) - 60_000
      };
      
      await installs.set(locationId, row);
    } catch (e) {
      console.error('Token refresh failed:', e?.response?.status, e?.response?.data || e.message);
      throw new Error('Failed to refresh access token');
    }
  }

  return row.access_token;
}

async function parseCSV(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const result = Papa.parse(content, {
      header: true,           // Use first row as headers
      skipEmptyLines: true,   // Skip empty rows
      trim: true,            // Trim whitespace
      dynamicTyping: false,  // keep IDs/keys as strings
      transformHeader: (header) => String(header || '').trim().toLowerCase().replace(/\s+/g, '_'),
      transform: (v) => (typeof v === 'string' ? v.trim() : v),
      complete: (results) => {
        if (results.errors.length > 0) {
          console.warn(`CSV parsing warnings for ${filePath}:`, results.errors);
        }
      }
    });
    
    if (result.errors.length > 0) {
      const criticalErrors = result.errors.filter(err => err.type === 'Delimiter');
      if (criticalErrors.length > 0) {
        throw new Error(`Critical CSV parsing errors: ${criticalErrors.map(e => e.message).join(', ')}`);
      }
    }
    
    return result.data;
  } catch (error) {
    console.error(`Failed to parse CSV file ${filePath}:`, error.message);
    throw new Error(`CSV parsing failed: ${error.message}`);
  }
}

// ===== Import Route =====
app.post('/import/:locationId', requireAuth, validateTenant, upload.fields([
  { name: 'objects', maxCount: 1 },
  { name: 'fields', maxCount: 1 },
  { name: 'records', maxCount: 1 }
]), async (req, res) => {
const locationId = req.locationId; // Use authenticated location

  let objPath, fldPath, recPath;
  try {
    const token = await withAccessToken(locationId);
    const headers = { ...authHeader(token) };

    // Step 1: Ensure schemas/objects exist
    objPath = req.files?.objects?.[0]?.path;
    const objects = objPath ? await parseCSV(objPath) : [];
    const schemaIdByKey = {};

    console.log('Attempting to list schemas with:', {
      url: `${API_BASE}/objects/`,
      params: { locationId }
    });

let existing = [];
try {
  const listSchemas = await axios.get(
    `${API_BASE}/objects/`,
    { headers, params: { locationId } }
  );
  existing = Array.isArray(listSchemas.data?.objects)
    ? listSchemas.data.objects
    : Array.isArray(listSchemas.data?.data)
      ? listSchemas.data.data
      : Array.isArray(listSchemas.data) ? listSchemas.data : [];
} catch (e) {
  if (e?.response?.status === 404) {
    // No objects exist yet for this location — treat as empty and continue
    existing = [];
  } else {
    console.error('List objects failed:', e?.response?.status, e?.response?.data || e.message);
    throw e;
  }
}

for (const sch of existing) {
  if (sch?.key && sch?.id) schemaIdByKey[sch.key] = sch.id;
}

    // Create missing schemas
    for (const row of objects) {
      const key = row.object_key;
      if (!key) {
        console.warn('Skipping object row without object_key:', row);
        continue;
      }
      if (schemaIdByKey[key]) continue;

try {
  const objectKey = String(row.object_key).trim();              // e.g., "test_products"
  const singular   = String(row.name || row.display_label || objectKey).trim();  // e.g., "Products"
  const plural     = String(row.plural || `${singular}s`).trim();                // e.g., "Products"

  // Fully-qualified keys to satisfy validator examples:
  const fqObjectKey = objectKey.startsWith('custom_objects.')
    ? objectKey
    : `custom_objects.${objectKey}`;

  const primaryKey = String(row.primary_display_field || 'name').trim();
  const fqPrimaryKey = primaryKey.startsWith(`custom_objects.${objectKey}.`)
    ? primaryKey
    : `custom_objects.${objectKey}.${primaryKey}`;

  const payload = {
    // REQUIRED
    labels: {
      singular,  // "Pet"
      plural     // "Pets"
    },
    // REQUIRED (doc’s example shows fully-qualified with prefix)
    key: fqObjectKey,                   // "custom_objects.test_products"
    description: row.description || '',
    // REQUIRED: must contain key + name + dataType
    primaryDisplayPropertyDetails: {
      key: fqPrimaryKey,                // "custom_objects.test_products.name"
      name: String(row.primary_display_label || 'Name'),
      dataType: 'TEXT'                  // or 'NUMERICAL' if you need that
    },
    // REQUIRED: per doc, in the BODY (not as query param) for POST /objects/
    locationId
  };

  const create = await axios.post(
    `${API_BASE}/objects/`,
    payload,
    { headers } // keep Version/Authorization headers from authHeader(token)
  );

  const createdId =
    create.data?.id || create.data?.data?.id || create.data?.object?.id;
  if (!createdId) throw new Error('No object id returned');

  schemaIdByKey[objectKey] = createdId;
} catch (e) {
  console.error(`Failed to create schema ${row.object_key}:`, e?.response?.data || e.message);
  throw e;
}
    }

    // Step 2: Ensure fields exist
    fldPath = req.files?.fields?.[0]?.path;
    const fields = fldPath ? await parseCSV(fldPath) : [];
    const fieldCacheBySchema = {};

    // Initialize caches (we’re creating fresh; skip listing to avoid extra calls)
    for (const [, schemaId] of Object.entries(schemaIdByKey)) {
      fieldCacheBySchema[schemaId] = {};
    }

    // Create missing fields
    for (const row of fields) {
      const schemaId = schemaIdByKey[row.object_key];
      if (!schemaId) {
        console.warn(`Unknown object_key in field: ${row.object_key}`);
        continue;
      }

      const key = row.field_key;
      if (!key) {
        console.warn('Skipping field row without field_key:', row);
        continue;
      }

      const exists = fieldCacheBySchema[schemaId]?.[key];
      if (exists) continue;

      try {
        const payload = {
          key,
          label: row.name || row.display_label || key,
          type: row.type || 'text',
          required: String(row.required).toLowerCase() === 'true',
          helpText: row.help_text || undefined,
          defaultValue: row.default_value || undefined,
          unique: String(row.unique).toLowerCase() === 'true' || undefined
        };

        if (row.type === 'select' || row.type === 'multiselect') {
          try { payload.options = JSON.parse(row.options); }
          catch { payload.options = (row.options || '').split('|').map(s => s.trim()).filter(Boolean); }
        }

        const createField = await axios.post(
          `${API_BASE}/objects/properties`,
          { objectId: schemaId, ...payload },
          { headers, params: { locationId } }
        );

        if (!fieldCacheBySchema[schemaId]) fieldCacheBySchema[schemaId] = {};
        fieldCacheBySchema[schemaId][key] =
          createField.data?.id || createField.data?.data?.id || createField.data?.property?.id;
      } catch (e) {
        console.error(`Failed to create field ${key}:`, e?.response?.data || e.message);
        throw e;
      }
    }

    // Step 3: Import records (if provided)
    recPath = req.files?.records?.[0]?.path;
    let recordsProcessed = 0;

    if (recPath) {
      const records = await parseCSV(recPath);
      for (const row of records) {
        const schemaId = schemaIdByKey[row.object_key];
        if (!schemaId) {
          console.warn(`Unknown object_key in records: ${row.object_key}`);
          continue;
        }

        const externalId = row.external_id;
        const attributes = {};

        for (const [k, v] of Object.entries(row)) {
          if (k === 'object_key' || k === 'external_id') continue;
          attributes[k] = v === '' ? null : v;
        }

        try {
          await axios.post(
            `${API_BASE}/objects/records`,
            { objectId: schemaId, externalId, attributes },
            { headers, params: { locationId } }
          );
          recordsProcessed++;
        } catch (e) {
          console.error(`Failed to create record extId=${externalId}:`, e?.response?.data || e.message);
          // continue
        }
      }
    }

    // Clean up temp files
    try {
      if (objPath) await fs.unlink(objPath);
      if (fldPath) await fs.unlink(fldPath);
      if (recPath) await fs.unlink(recPath);
    } catch (e) {
      console.warn('Failed to clean up temp files:', e.message);
    }

    res.json({
      ok: true,
      message: 'Import complete',
      stats: {
        schemasProcessed: objects.length,
        fieldsProcessed: fields.length,
        recordsProcessed
      }
    });

  } catch (e) {
    console.error('Import error:', e?.response?.data || e.message);
    res.status(400).json({
      ok: false,
      error: e?.response?.data?.message || e.message,
      details: e?.response?.data || ''
    });
  }
});
app.get('/api/debug/cookies', (req, res) => {
  res.json({
    origin: req.get('origin') || null,
    hasSigned: Boolean(req.signedCookies?.ghl_location),
    hasUnsigned: Boolean(req.cookies?.ghl_location),
    valuePreview: (req.signedCookies?.ghl_location || req.cookies?.ghl_location || '').slice(0, 8),
  });
});

// ===== Error Handling =====
// Basic entry points
app.get('/', (req, res) => {
  // Simple bounce to your in-app page
  return res.redirect('/launch');
});

app.get('/launch', (req, res) => {
  res
    .status(200)
    .send('Custom Object Importer is live. Use /oauth/install to connect, then /api/auth/status to verify.');
});

// ===== Debug Route: List custom object schemas =====
// ===== Debug Route: List objects =====
app.get('/api/objects', requireAuth, async (req, res) => {
  const locationId = req.locationId; // Use authenticated location
  try {
    const token = await withAccessToken(locationId);
    const r = await axios.get(
      `${API_BASE}/objects/`,
      { headers: authHeader(token), params: { locationId } }
    );
    
    // Filter to only custom objects (exclude standard objects like contact, opportunity, business)
    const allObjects = Array.isArray(r.data?.objects) ? r.data.objects : 
                      Array.isArray(r.data?.data) ? r.data.data : 
                      Array.isArray(r.data) ? r.data : [];
    
    const customObjects = allObjects.filter(obj => 
      obj.key && obj.key.startsWith('custom_objects.') && 
      !['contact', 'opportunity', 'business'].includes(obj.key.replace('custom_objects.', ''))
    );
    
    res.json({
      ...r.data,
      objects: customObjects,
      data: customObjects // support both response formats
    });
  } catch (e) {
    console.error('objects lookup error:', e?.response?.status, e?.response?.data || e.message);
    res.status(500).json({ error: 'Lookup failed', details: e?.response?.data || e.message });
  }
});
// Get custom fields for a specific object key
app.get('/api/objects/:objectKey/fields', requireAuth, async (req, res) => {
  const locationId = req.locationId;
  let { objectKey } = req.params;
  
  try {
    const token = await withAccessToken(locationId);
    
    // Always ensure we have the correct format by removing any existing prefix and adding it back
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const apiObjectKey = `custom_objects.${cleanKey}`;
    
    console.log(`Fields request: original="${objectKey}" -> cleaned="${cleanKey}" -> api="${apiObjectKey}"`);
    
    const response = await axios.get(
      `${API_BASE}/custom-fields/object-key/${apiObjectKey}`,
      { headers: authHeader(token), params: { locationId } }
    );
    res.json(response.data);
  } catch (e) {
    console.error(`Failed to fetch fields for object ${objectKey}:`, e?.response?.data || e.message);
    res.status(500).json({ error: 'Failed to fetch fields', details: e?.response?.data || e.message });
  }
});
// Get custom fields for a specific object key
// Generate dynamic records template for a specific object
// Generate dynamic records template for a specific object
app.get('/api/objects/:objectKey/template', requireAuth, async (req, res) => {
  const locationId = req.locationId;
  let { objectKey } = req.params;
  
  try {
    const token = await withAccessToken(locationId);
    
    // Get the object's custom fields
const cleanKey = objectKey.replace(/^custom_objects\./, '');
const apiObjectKey = `custom_objects.${cleanKey}`;

console.log(`Template request: original="${objectKey}" -> cleaned="${cleanKey}" -> api="${apiObjectKey}"`);

const fieldsResponse = await axios.get(
  `${API_BASE}/custom-fields/object-key/${apiObjectKey}`,
  { headers: authHeader(token), params: { locationId } }
);

console.log('Full template API response:', JSON.stringify(fieldsResponse.data, null, 2));    
// Extract field keys - the fields are directly in customFields array
const fields = fieldsResponse.data?.fields || [];
console.log('fieldsResponse.data keys:', Object.keys(fieldsResponse.data || {}));
console.log('fieldsResponse.data.fields type:', typeof fieldsResponse.data?.fields);
console.log('fieldsResponse.data.fields length:', fieldsResponse.data?.fields?.length);
console.log('Template API Response fields:', fields);

const fieldKeys = fields.map(field => {
  console.log('Processing field:', field);
  // Extract just the field name from the full fieldKey
  if (field.fieldKey) {
    const parts = field.fieldKey.split('.');
    const extracted = parts[parts.length - 1];
    console.log('Extracted from fieldKey:', field.fieldKey, '->', extracted);
    return extracted;
  }
  // Fallback to sanitized name
  const fallback = field.name?.toLowerCase().replace(/[^a-z0-9]/g, '_');
  console.log('Using fallback name:', field.name, '->', fallback);
  return fallback || field.id;
}).filter(Boolean);
    
    console.log('Final fieldKeys:', fieldKeys);
    
    // Generate CSV with headers and empty row
    const headers = ['object_key', 'external_id', ...fieldKeys];
    const emptyRow = [cleanKey, '', ...fieldKeys.map(() => '')];
    
    const csvContent = [
      headers.join(','),
      emptyRow.join(',')
    ].join('\n');
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${cleanKey}_records_template.csv"`);
    res.send(csvContent);
    
  } catch (e) {
    console.error(`Failed to generate template for ${objectKey}:`, e?.response?.data || e.message);
    res.status(500).json({ error: 'Failed to generate template' });
  }
});// Serve CSV templates
app.get('/templates/:type', (req, res) => {
  const { type } = req.params;
  
  if (!['objects', 'fields', 'records'].includes(type)) {
    return res.status(404).json({ error: 'Template not found' });
  }
  
  const templatePath = `./templates/${type}.csv`;
  res.download(templatePath, `${type}_template.csv`, (err) => {
    if (err) {
      console.error(`Template download error for ${type}:`, err.message);
      res.status(404).json({ error: 'Template file not found' });
    }
  });
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