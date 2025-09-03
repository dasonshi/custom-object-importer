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
import CryptoJS from 'crypto-js';




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
    'locations/customFields.write',
    'locations/customValues.readonly',
    'locations/customValues.write',
    'locations.readonly',

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
  let locationId = req.signedCookies?.ghl_location || req.cookies?.ghl_location || null;

  // Allow explicit override (query or header)
  const override = (req.query.locationId || req.get('x-location-id') || '').trim();
  if (override && override !== locationId) {
    if (await installs.has(override)) {
      // Set signed cookie
      res.cookie('ghl_location', override, {
        domain: process.env.COOKIE_DOMAIN || undefined,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'none',
        signed: true,
        maxAge: 7 * 24 * 60 * 60 * 1000
      });
      // Partitioned duplicate for cross-site iframes
      const d = process.env.COOKIE_DOMAIN ? `Domain=${process.env.COOKIE_DOMAIN}; ` : '';
      res.append(
        'Set-Cookie',
        `ghl_location=${encodeURIComponent(override)}; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=604800`
      );
      locationId = override;
    } else {
      return res.status(403).json({ error: 'invalid_location', message: 'Unknown or uninstalled locationId override' });
    }
  }

  if (!locationId) {
    return res.status(401).json({
      error: 'Authentication required',
      message: 'Please complete OAuth setup first'
    });
  }

const hasInstall = await installs.has(locationId);
  if (!hasInstall) 
    {
    res.clearCookie('ghl_location', COOKIE_CLEAR_OPTS);
    {
      const d = process.env.COOKIE_DOMAIN ? `Domain=${process.env.COOKIE_DOMAIN}; ` : '';
      res.append(
        'Set-Cookie',
        `ghl_location=; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=0`
      );
    }
    return res.status(401).json({ error: 'Installation not found', message: 'Please re-authenticate' });
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
// Add this RIGHT AFTER the validateTenant function
function handleLocationOverride(req, res, next) {
  const requestedLocationId = req.query.locationId || req.params.locationId;
  
  if (requestedLocationId && requestedLocationId !== req.locationId) {
    console.log(`Location override: ${req.locationId} -> ${requestedLocationId}`);
    req.locationId = requestedLocationId;
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
function normalizeDataType(input) {
  const t = String(input || 'TEXT').toLowerCase();
  const map = {
    text: 'TEXT',
    textarea: 'LARGE_TEXT', large_text: 'LARGE_TEXT',
    number: 'NUMERICAL', numerical: 'NUMERICAL',
    phone: 'PHONE',
    email: 'EMAIL',
    date: 'DATE',
    money: 'MONETORY', monetary: 'MONETORY', currency: 'MONETORY',
    checkbox: 'CHECKBOX',
    select: 'SINGLE_OPTIONS', single: 'SINGLE_OPTIONS', single_options: 'SINGLE_OPTIONS',
    multiselect: 'MULTIPLE_OPTIONS', multiple: 'MULTIPLE_OPTIONS', multiple_options: 'MULTIPLE_OPTIONS',
    textbox_list: 'TEXTBOX_LIST',
    file: 'FILE_UPLOAD', file_upload: 'FILE_UPLOAD',
    radio: 'RADIO'
  };
  return map[t] || String(input).toUpperCase();
}

function parseOptions(raw) {
  if (!raw) return undefined;
  try {
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) {
      return arr.map(o => (typeof o === 'string' ? { key: o.toLowerCase().replace(/\s+/g,'_'), label: o } : o));
    }
  } catch {}
  return String(raw).split('|').map(s => s.trim()).filter(Boolean)
    .map(label => ({ key: label.toLowerCase().replace(/\s+/g,'_'), label }));
}

function asBool(v, fallback=false) {
  if (v === undefined || v === null || v === '') return fallback;
  return String(v).toLowerCase() === 'true';
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

const fieldPayload = {
  locationId: locationId,
  name: payload.label,
  description: payload.helpText || row.description || "",
  placeholder: row.placeholder || "",
  showInForms: row.show_in_forms !== undefined ? String(row.show_in_forms).toLowerCase() === 'true' : true,
  dataType: (payload.type || 'TEXT').toUpperCase(),
  fieldKey: `custom_objects.${objectKey}.${payload.key}`,
  objectKey: `custom_objects.${objectKey}`
};

// Add optional attributes if provided
if (row.accepted_formats) {
  fieldPayload.acceptedFormats = row.accepted_formats;
}

if (row.max_file_limit) {
  fieldPayload.maxFileLimit = parseInt(row.max_file_limit) || 1;
}

if (row.allow_custom_option !== undefined) {
  fieldPayload.allowCustomOption = String(row.allow_custom_option).toLowerCase() === 'true';
}

if (row.parent_id) {
  fieldPayload.parentId = row.parent_id;
}

if (payload.options) {
  fieldPayload.options = Array.isArray(payload.options) 
    ? payload.options.map(opt => {
        if (typeof opt === 'string') {
          return { key: opt.toLowerCase(), label: opt };
        }
        // Handle objects with key, label, and optional url
        return {
          key: opt.key || opt.label?.toLowerCase() || opt,
          label: opt.label || opt.key || opt,
          ...(opt.url && { url: opt.url })
        };
      })
    : payload.options;
}
if (payload.options) {
  fieldPayload.options = Array.isArray(payload.options) 
    ? payload.options.map(opt => typeof opt === 'string' ? { key: opt.toLowerCase(), label: opt } : opt)
    : payload.options;
}

const createField = await axios.post(
  `${API_BASE}/custom-fields/`,
  fieldPayload,
  { headers }
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
app.get('/api/debug/install/:locationId', async (req, res) => {
  const { locationId } = req.params;
  const has = await installs.has(locationId);
  let tokenOk = false, companyOk = false, locationOk = false, logs = [];

  if (has) {
    try {
      const token = await withAccessToken(locationId);
      tokenOk = Boolean(token);
      const r1 = await axios.get(`${API_BASE}/locations/${locationId}`, { headers: authHeader(token) });
      locationOk = !!r1.data?.id || !!r1.data?.name;
      const r2 = await axios.get(`${API_BASE}/marketplace/app/${process.env.GHL_CLIENT_ID}/installations`, { headers: authHeader(token) });
      companyOk = Boolean(r2.data?.company?.name || r2.data?.name);
    } catch (e) {
      logs.push(e?.response?.data || e.message);
    }
  }

  res.json({ hasInstall: has, tokenOk, locationOk, companyOk, logs });
});

// ===== Separate Import Routes =====

// 1. Import Objects/Schemas Only
app.post('/api/objects/import', requireAuth, upload.single('objects'), async (req, res) => {
  const locationId = req.locationId;
  
  if (!req.file) {
    return res.status(400).json({ error: 'Objects CSV file is required' });
  }
  
  try {
    const token = await withAccessToken(locationId);
    const headers = { ...authHeader(token) };
    const objects = await parseCSV(req.file.path);
    const schemaIdByKey = {};
    
    // Get existing schemas
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
      if (e?.response?.status !== 404) throw e;
      existing = [];
    }

    for (const sch of existing) {
      if (sch?.key && sch?.id) schemaIdByKey[sch.key] = sch.id;
    }

    // Create missing schemas
    const created = [];
    for (const row of objects) {
      const objectKey = String(row.object_key).trim();
      if (!objectKey) {
        console.warn('Skipping object row without object_key:', row);
        continue;
      }
      
      if (schemaIdByKey[objectKey]) {
        console.log(`Schema ${objectKey} already exists, skipping`);
        continue;
      }

      const singular = String(row.name || row.display_label || objectKey).trim();
      const plural = String(row.plural || `${singular}s`).trim();
      const fqObjectKey = objectKey.startsWith('custom_objects.')
        ? objectKey
        : `custom_objects.${objectKey}`;

      const primaryKey = String(row.primary_display_field || 'name').trim();
      const fqPrimaryKey = primaryKey.startsWith(`custom_objects.${objectKey}.`)
        ? primaryKey
        : `custom_objects.${objectKey}.${primaryKey}`;

      const payload = {
        labels: { singular, plural },
        key: fqObjectKey,
        description: row.description || '',
        primaryDisplayPropertyDetails: {
          key: fqPrimaryKey,
          name: String(row.primary_display_label || 'Name'),
          dataType: 'TEXT'
        },
        locationId
      };

      const createResp = await axios.post(`${API_BASE}/objects/`, payload, { headers });
      const createdId = createResp.data?.id || createResp.data?.data?.id || createResp.data?.object?.id;
      
      if (createdId) {
        schemaIdByKey[objectKey] = createdId;
        created.push({ objectKey, id: createdId, name: singular });
      }
    }

    await fs.unlink(req.file.path).catch(() => {});

    res.json({
      success: true,
      message: `Processed ${objects.length} objects, created ${created.length} new schemas`,
      created,
      existing: Object.keys(schemaIdByKey).filter(key => !created.find(c => c.objectKey === key))
    });

  } catch (e) {
    console.error('Objects import error:', e?.response?.data || e.message);
    res.status(400).json({
      error: 'Objects import failed',
      details: e?.response?.data || e.message
    });
  }
});

// 2. Import Fields for a Specific Object
app.post('/api/objects/:objectKey/fields/import', requireAuth, upload.single('fields'), async (req, res) => {
  const locationId = req.locationId;
  const { objectKey } = req.params;
  
  if (!req.file) {
    return res.status(400).json({ error: 'Fields CSV file is required' });
  }

  try {
    const token = await withAccessToken(locationId);
    const headers = { ...authHeader(token) };
    
    // Get the schema ID for this object
    const listSchemas = await axios.get(
      `${API_BASE}/objects/`,
      { headers, params: { locationId } }
    );
    const objects = Array.isArray(listSchemas.data?.objects) ? listSchemas.data.objects : [];
    const schema = objects.find(obj => obj.key === objectKey || obj.key === `custom_objects.${objectKey}`);
    
    if (!schema) {
      return res.status(404).json({ error: `Object ${objectKey} not found` });
    }

    const fields = await parseCSV(req.file.path);
    const created = [];
    const errors = [];

    for (const row of fields) {
      const fieldKey = row.field_key;
      if (!fieldKey) {
        console.warn('Skipping field row without field_key:', row);
        continue;
      }

      try {
        const payload = {
          key: fieldKey,
          label: row.name || row.display_label || fieldKey,
          type: row.type || 'text',
          required: String(row.required).toLowerCase() === 'true',
          helpText: row.help_text || undefined,
          defaultValue: row.default_value || undefined,
          unique: String(row.unique).toLowerCase() === 'true' || undefined
        };

        if (row.type === 'select' || row.type === 'multiselect') {
          try { 
            payload.options = JSON.parse(row.options); 
          } catch { 
            payload.options = (row.options || '').split('|').map(s => s.trim()).filter(Boolean); 
          }
        }

const fieldPayload = {
  locationId: locationId,
  name: payload.label,
  description: payload.helpText || row.description || "",
  placeholder: row.placeholder || "",
  showInForms: row.show_in_forms !== undefined ? String(row.show_in_forms).toLowerCase() === 'true' : true,
  dataType: (payload.type || 'TEXT').toUpperCase(),
  fieldKey: `custom_objects.${objectKey}.${payload.key}`,
  objectKey: `custom_objects.${objectKey}`
};

// Add optional attributes if provided
if (row.accepted_formats) {
  fieldPayload.acceptedFormats = row.accepted_formats;
}

if (row.max_file_limit) {
  fieldPayload.maxFileLimit = parseInt(row.max_file_limit) || 1;
}

if (row.allow_custom_option !== undefined) {
  fieldPayload.allowCustomOption = String(row.allow_custom_option).toLowerCase() === 'true';
}

if (row.parent_id) {
  fieldPayload.parentId = row.parent_id;
}

if (payload.options) {
  fieldPayload.options = Array.isArray(payload.options) 
    ? payload.options.map(opt => {
        if (typeof opt === 'string') {
          return { key: opt.toLowerCase(), label: opt };
        }
        // Handle objects with key, label, and optional url
        return {
          key: opt.key || opt.label?.toLowerCase() || opt,
          label: opt.label || opt.key || opt,
          ...(opt.url && { url: opt.url })
        };
      })
    : payload.options;
}
const createField = await axios.post(
  `${API_BASE}/custom-fields/`,
  fieldPayload,
  { headers }
);
        created.push({ 
          fieldKey, 
          id: createField.data?.id || createField.data?.data?.id,
          label: payload.label 
        });
      } catch (e) {
        errors.push({ fieldKey, error: e?.response?.data || e.message });
        console.error(`Failed to create field ${fieldKey}:`, e?.response?.data || e.message);
      }
    }

    await fs.unlink(req.file.path).catch(() => {});

    res.json({
      success: true,
      message: `Processed ${fields.length} fields for ${objectKey}`,
      objectKey,
      objectId: schema.id,
      created,
      errors
    });

  } catch (e) {
    console.error('Fields import error:', e?.response?.data || e.message);
    res.status(400).json({
      error: 'Fields import failed',
      details: e?.response?.data || e.message
    });
  }
});

// 3. Import Records for a Specific Object
app.post('/api/objects/:objectKey/records/import', requireAuth, upload.single('records'), async (req, res) => {
  const locationId = req.locationId;
  const { objectKey } = req.params;
  
  if (!req.file) {
    return res.status(400).json({ error: 'Records CSV file is required' });
  }

  try {
    const token = await withAccessToken(locationId);
    const headers = { ...authHeader(token) };
    
    // Get the full object key for API calls
    const fullObjectKey = objectKey.startsWith('custom_objects.') 
      ? objectKey 
      : `custom_objects.${objectKey}`;

    const records = await parseCSV(req.file.path);
    const created = [];
    const errors = [];

    for (const row of records) {
      try {
        const properties = {};

const recordId = row.id;

for (const [k, v] of Object.entries(row)) {
  if (['object_key', 'id', 'external_id', 'owner', 'followers'].includes(k)) continue;          if (v === '' || v === null || v === undefined) continue;
          
          // Handle different field types per GHL documentation
          if (k.includes('money') || k.includes('currency')) {
            properties[k] = {
              currency: "default",
              value: parseFloat(v) || 0
            };
          } else if (k.includes('_multi') || k.includes('_checkbox')) {
            properties[k] = v.split(',').map(s => s.trim());
          } else if (k.includes('_files')) {
            properties[k] = [{ url: v }];
          } else {
            properties[k] = v;
          }
        }

// Build request body for CREATE (POST)
const createRequestBody = {
  locationId: locationId,
  properties: properties
};

if (row.owner) {
  createRequestBody.owner = row.owner.split(',').map(s => s.trim());
}
if (row.followers) {
  createRequestBody.followers = row.followers.split(',').map(s => s.trim());
}

// Build request body for UPDATE (PUT) - only properties
const updateRequestBody = {
  properties: properties
};

let recordResult;
let action = 'created';

if (recordId) {
  try {
// First verify the record exists using the exact endpoint format
await axios.get(
  `${API_BASE}/objects/${fullObjectKey}/records/${recordId}`,
  { 
    headers,
    params: { locationId }
  }
);

// Record exists, update it (PUT only wants properties, locationId in query)
recordResult = await axios.put(
  `${API_BASE}/objects/${fullObjectKey}/records/${recordId}`,
  updateRequestBody,
  { 
    headers,
    params: { locationId }
  }
);
    action = 'updated';
  } catch (getError) {
    if (getError?.response?.status === 404) {
      console.log(`Record ID ${recordId} not found, creating new record instead`);
      // Record doesn't exist, create new one
recordResult = await axios.post(
  `${API_BASE}/objects/${fullObjectKey}/records`,
  createRequestBody,
  { headers }
);
      action = 'created (id not found)';
    } else {
      throw getError; // Re-throw other errors
    }
  }
} else {  
  // Create new record
recordResult = await axios.post(
  `${API_BASE}/objects/${fullObjectKey}/records`,
  createRequestBody,
  { headers }
);
}
created.push({ 
  externalId: row.external_id, 
  id: recordResult.data?.id || recordResult.data?.data?.id || recordId,
  properties: Object.keys(properties),
  action: action
});      
} catch (e) {
        errors.push({ 
          externalId: row.external_id, 
          error: e?.response?.data || e.message 
        });
        console.error(`Failed to create record extId=${row.external_id}:`, e?.response?.data || e.message);
      }
    }

    await fs.unlink(req.file.path).catch(() => {});

    res.json({
      success: true,
      message: `Processed ${records.length} records for ${objectKey}`,
      objectKey,
      created,
      errors,
      summary: {
        total: records.length,
        successful: created.length,
        failed: errors.length
      }
    });

  } catch (e) {
    console.error('Records import error:', e?.response?.data || e.message);
    res.status(400).json({
      error: 'Records import failed',
      details: e?.response?.data || e.message
    });
  }
});
// 4) Import Association TYPES (schema-level)
app.post('/api/associations/types/import', requireAuth, upload.single('associations'), async (req, res) => {
  const locationId = req.locationId;
  if (!req.file) return res.status(400).json({ error: 'Associations CSV file is required' });

  try {
    const token = await withAccessToken(locationId);
    const headers = { ...authHeader(token) };
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

    await fs.unlink(req.file.path).catch(() => {});
    res.json({ success: errors.length === 0, created, skipped, errors });

  } catch (e) {
    console.error('Association types import error:', e?.response?.data || e.message);
    res.status(400).json({ error: 'Associations type import failed', details: e?.response?.data || e.message });
  }
});
// 5) Import Custom Values
app.post('/api/custom-values/import', requireAuth, upload.single('customValues'), async (req, res) => {
  const locationId = req.locationId;
  
  if (!req.file) {
    return res.status(400).json({ error: 'Custom values CSV file is required' });
  }

  try {
    const token = await withAccessToken(locationId);
    const headers = { ...authHeader(token) };
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

    await fs.unlink(req.file.path).catch(() => {});

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
    console.error('Custom values import error:', e?.response?.data || e.message);
    res.status(400).json({
      error: 'Custom values import failed',
      details: e?.response?.data || e.message
    });
  }
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
app.get('/api/objects', requireAuth, handleLocationOverride, async (req, res) => {
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
app.get('/api/objects/:objectKey/fields', requireAuth, handleLocationOverride, async (req, res) => {
  const locationId = req.locationId;
  let { objectKey } = req.params;
  
  try {
    const token = await withAccessToken(locationId);
    const headers = { ...authHeader(token) };
    
    // Always ensure we have the correct format by removing any existing prefix and adding it back
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const apiObjectKey = `custom_objects.${cleanKey}`;
    
    console.log(`Fields request: original="${objectKey}" -> cleaned="${cleanKey}" -> api="${apiObjectKey}"`);
    
    const response = await axios.get(
      `${API_BASE}/custom-fields/object-key/${apiObjectKey}`,
      { headers: authHeader(token), params: { locationId } }
    );
    
    const fields = response.data?.fields || [];
    
    // Get unique parent IDs that exist
    const parentIds = [...new Set(fields.map(f => f.parentId).filter(Boolean))];
    
    // Fetch folder details for each parent ID
    const folders = {};
    for (const parentId of parentIds) {
      try {
        const folderResponse = await axios.get(
          `${API_BASE}/custom-fields/${parentId}`,
          { headers }
        );
        folders[parentId] = {
          id: parentId,
          name: folderResponse.data?.name || folderResponse.data?.data?.name || `Folder ${parentId}`,
          ...folderResponse.data
        };
      } catch (e) {
        console.error(`Failed to fetch folder ${parentId}:`, e?.response?.data || e.message);
        folders[parentId] = { id: parentId, name: `Unknown Folder ${parentId}` };
      }
    }
    
    // Enhance fields with folder information
    const enhancedFields = fields.map(field => ({
      ...field,
      folder: field.parentId ? folders[field.parentId] : null
    }));
    
    res.json({
      ...response.data,
      fields: enhancedFields,
      folders: Object.values(folders)
    });
  } catch (e) {
    console.error(`Failed to fetch fields for object ${objectKey}:`, e?.response?.data || e.message);
    res.status(500).json({ error: 'Failed to fetch fields', details: e?.response?.data || e.message });
  }
});
// Get custom values for location
app.get('/api/custom-values', requireAuth, handleLocationOverride, async (req, res) => {
  console.log('=== CUSTOM VALUES REQUEST ===');
  console.log('Query locationId:', req.query.locationId);
  console.log('Final locationId being used:', req.locationId);
  console.log('==============================');

  const locationId = req.locationId;
  
  try {
    const token = await withAccessToken(locationId);
    const response = await axios.get(
      `${API_BASE}/locations/${locationId}/customValues`,
      { headers: authHeader(token) }
    );
    
    res.json(response.data);
  } catch (e) {
    console.error('Custom values fetch error:', e?.response?.data || e.message);
    res.status(500).json({ 
      error: 'Failed to fetch custom values', 
      details: e?.response?.data || e.message 
    });
  }
});
// Get custom fields for a specific object key
// Generate dynamic records template for a specific object
// =======================
// Consolidated CSV Templates
// =======================

// Objects template: /templates/objects  → objects-template.csv
app.get('/templates/objects', (req, res) => {
  const headers = [
    'object_key',              // e.g., products
    'name',                    // singular label
    'plural',                  // plural label
    'description',             // optional
    'primary_display_field',   // e.g., name
    'primary_display_label'    // e.g., Name
  ];
  const emptyRow = new Array(headers.length).fill('');
  const csv = [headers.join(','), emptyRow.join(',')].join('\n');

  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="objects-template.csv"');
  res.send(csv);
});

// Fields template: /templates/fields  → fields-template.csv (full header incl. optionals)
// Fields template: /templates/fields  → fields-template.csv (accurate to /custom-fields)
app.get('/templates/fields', (req, res) => {
  const headers = [
    'object_key',           // e.g., products
    'field_key',            // e.g., color
    'name',                 // e.g., Color
    'data_type',            // TEXT | LARGE_TEXT | NUMERICAL | PHONE | MONETORY | CHECKBOX | SINGLE_OPTIONS | MULTIPLE_OPTIONS | DATE | TEXTBOX_LIST | FILE_UPLOAD | RADIO | EMAIL
    'description',          // optional
    'placeholder',          // optional
    'show_in_forms',        // true/false
    'options',              // for *_OPTIONS/RADIO/CHECKBOX/TEXTBOX_LIST: "Red|Blue" OR JSON
    'accepted_formats',     // for FILE_UPLOAD: ".pdf,.jpg,.png"
    'max_file_limit',       // for FILE_UPLOAD: 1,2,...
    'allow_custom_option',  // for RADIO: true/false
    'parent_id'             // optional folder id
  ];

  // single illustrative row (safe defaults)
  const example = [
    'products',
    'color',
    'Color',
    'SINGLE_OPTIONS',
    '',
    '',
    'true',
    'Red|Blue|Green',
    '',
    '',
    '',
    ''
  ];

  const csv = [headers.join(','), example.join(',')].join('\n');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="fields-template.csv"');
  res.send(csv);
});
// Custom values template: /templates/custom-values → custom-values-template.csv
app.get('/templates/custom-values', (req, res) => {
  const headers = [
    'id',           // optional - for updates (leave empty for new records)
    'name',         // required - custom field name
    'value'         // required - custom field value
  ];
  
  const example = ['', 'Custom Field Name', 'Value'];
  const csv = [headers.join(','), example.join(',')].join('\n');
  
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="custom-values-template.csv"');
  res.send(csv);
});

// Records template (dynamic): /templates/records/:objectKey  → <objectKey>-template.csv
// NOTE: requires auth because we introspect fields via GHL API
app.get('/templates/records/:objectKey', requireAuth, async (req, res) => {
  const locationId = req.locationId;
  let { objectKey } = req.params;

  try {
    const token = await withAccessToken(locationId);
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const apiObjectKey = `custom_objects.${cleanKey}`;

    console.log(`Template request: original="${objectKey}" -> cleaned="${cleanKey}" -> api="${apiObjectKey}"`);

    const fieldsResponse = await axios.get(
      `${API_BASE}/custom-fields/object-key/${apiObjectKey}`,
      { headers: authHeader(token), params: { locationId } }
    );

    // Depending on API shape: fields under data.fields OR fields
    const fields = Array.isArray(fieldsResponse.data?.fields)
      ? fieldsResponse.data.fields
      : Array.isArray(fieldsResponse.data?.data?.fields)
      ? fieldsResponse.data.data.fields
      : [];

    const fieldKeys = fields
      .map((field) => {
        // Prefer extracting from fieldKey (custom_objects.<obj>.<name>)
        if (field.fieldKey) {
          const parts = String(field.fieldKey).split('.');
          return parts[parts.length - 1];
        }
        // fallback to normalized name
        const fallback = String(field.name || '')
          .toLowerCase()
          .replace(/[^a-z0-9]/g, '_');
        return fallback || field.id;
      })
      .filter(Boolean);

    // Include both id and external_id so users can choose update strategy later
    const headers = ['object_key', 'id', 'external_id', 'owner', 'followers', ...fieldKeys];
    const emptyRow = [cleanKey, '', '', '', '', ...fieldKeys.map(() => '')];

    const csvContent = [headers.join(','), emptyRow.join(',')].join('\n');

    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${cleanKey}-template.csv"`
    );
    res.send(csvContent);
  } catch (e) {
    console.error(`Failed to generate template for ${objectKey}:`, e?.response?.data || e.message);
    res.status(500).json({ error: 'Failed to generate records template' });
  }
});

// -----------------------
// Backward-compat redirects (keep old links working)
// -----------------------
app.get('/api/objects/:objectKey/template', (req, res) => {
  return res.redirect(302, `/templates/records/${encodeURIComponent(req.params.objectKey)}`);
});
app.get('/api/objects/fields/template', (req, res) => {
  return res.redirect(302, '/templates/fields');
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
// Fixed debug route to test all scopes
app.get('/api/debug/token-scopes/:locationId', async (req, res) => {
  const { locationId } = req.params;
  
  try {
    const hasInstall = await installs.has(locationId);
    if (!hasInstall) {
      return res.status(404).json({ error: 'Installation not found', locationId });
    }

    const token = await withAccessToken(locationId);
    const headers = { ...authHeader(token) };

    const scopeTests = {
      'objects/schema.readonly': false,
      'objects/schema.write': false, 
      'objects/record.readonly': false,
      'objects/record.write': false,
      'locations/customFields.readonly': false,
      'locations/customFields.write': false,
      'locations/customValues.readonly': false,
      'locations/customValues.write': false
    };

    // Test objects schema read
    try {
      await axios.get(`${API_BASE}/objects/`, { headers, params: { locationId } });
      scopeTests['objects/schema.readonly'] = true;
    } catch (e) { console.log('Objects schema read failed:', e?.response?.status); }

    // Test custom fields read  
    try {
      await axios.get(`${API_BASE}/custom-fields/`, { headers, params: { locationId } });
      scopeTests['locations/customFields.readonly'] = true;
    } catch (e) { console.log('Custom fields read failed:', e?.response?.status); }

    // Test custom values read
    try {
      await axios.get(`${API_BASE}/locations/${locationId}/customValues`, { headers });
      scopeTests['locations/customValues.readonly'] = true;
    } catch (e) { console.log('Custom values read failed:', e?.response?.status, e?.response?.data?.message); }

    // Test records read (need an existing object key)
    try {
      const objectsResp = await axios.get(`${API_BASE}/objects/`, { headers, params: { locationId } });
      const objects = objectsResp.data?.objects || [];
      if (objects.length > 0) {
        const firstObjectKey = objects[0].key;
        await axios.get(`${API_BASE}/objects/${firstObjectKey}/records`, { headers, params: { locationId } });
        scopeTests['objects/record.readonly'] = true;
      }
    } catch (e) { console.log('Records read failed:', e?.response?.status); }

    const install = await installs.get(locationId);
    
    res.json({
      locationId,
      tokenExpiresAt: new Date(install.expires_at),
      scopeTests,
      tokenPreview: token.substring(0, 30) + '...',
      installUrl: req.get('origin') + '/oauth/install'
    });

  } catch (e) {

    res.status(500).json({
      error: 'Token scope debug failed',
      locationId,
      details: e?.response?.data || e.message
    });
  }
});

// User context decryption (for personalization)
app.post('/api/decrypt-user-data', express.json(), async (req, res) => {
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


// Combined endpoint for efficiency (optional)
app.post('/api/app-context', express.json(), async (req, res) => {
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

    // 3) Enforce cookie vs activeLocation
    const cookieLocation = req.signedCookies?.ghl_location || req.cookies?.ghl_location || null;
if (user.activeLocation && cookieLocation && cookieLocation !== user.activeLocation) {
  // Check if we have an installation for the new location
  if (await installs.has(user.activeLocation)) {
    // Update cookie to new location
    res.cookie('ghl_location', user.activeLocation, {
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
      `ghl_location=${encodeURIComponent(user.activeLocation)}; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=604800`
    );
    
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
      res.cookie('ghl_location', user.activeLocation, {
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
        `ghl_location=${encodeURIComponent(user.activeLocation)}; Path=/; ${d}HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=604800`
      );
    }

    // 4) Location details (UI friendly)
    let location = null;
    if (user.activeLocation && await installs.has(user.activeLocation)) {
      try {
        const token = await withAccessToken(user.activeLocation);
        const r = await axios.get(`${API_BASE}/locations/${user.activeLocation}`, {
          headers: authHeader(token)
        });
        const loc = r.data || {};
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

app.get('/dev/mock-encrypted', (req, res) => {
  if (process.env.NODE_ENV === 'production') return res.status(404).end();

  // pick a real locationId you’ve already installed the app on
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
// --- DEV ONLY: manually set the location cookie if we have an install ---
app.post('/dev/set-location/:locationId', async (req, res) => {
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
app.post('/api/switch-location', express.json(), async (req, res) => {
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