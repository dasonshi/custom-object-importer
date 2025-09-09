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
import { parseCSV, cleanupTempFiles } from './src/utils/csvParser.js';
import { normalizeDataType, parseOptions, asBool } from './src/utils/dataTransformers.js';
import { generateEncryptionKey, createSecureState, verifySecureState, validateEncryptionSetup } from './src/utils/crypto.js';
import { handleAPIError } from './src/utils/apiHelpers.js';
import { setAuthCookie, clearAuthCookie, requireAuth, validateTenant, handleLocationOverride, installs } from './src/middleware/auth.js';
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

// ===== OAuth: Install (Marketplace chooselocation endpoint, fixed scopes) =====
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

  const url = `https://marketplace.gohighlevel.com/oauth/chooselocation` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(process.env.GHL_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(process.env.GHL_REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&state=${state}`;

  res.redirect(url);
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
// Mount auth routes
app.use('/api/auth', authRoutes);
app.use('/templates', templateRoutes);

// Debug routes only in development
if (process.env.NODE_ENV !== 'production') {
  app.use('/api/debug', debugRoutes);
}
app.use('/api/objects', objectRoutes);
app.use('/api/agency', agencyRoutes);
app.use('/api/custom-values', customValuesRoutes);
app.use('/api/associations', associationsRoutes);

app.use('/import', importRoutes);
app.use('/api', importRoutes);  // For the /api/objects/import style routes
app.use('/api', appContextRoutes);

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
  
// Marketplace sometimes omits `state`; verify if present, otherwise proceed
if (typeof state === 'string' && state.length > 0) {
  try {
    verifySecureState(state,ENC_KEY);
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

const tokenResp = await global.ghl.oauth.getAccessToken({
  client_id: process.env.GHL_CLIENT_ID,
  client_secret: process.env.GHL_CLIENT_SECRET,
  code: String(code),
  grant_type: 'authorization_code',
  redirect_uri: process.env.GHL_REDIRECT_URI,
});

const { access_token, refresh_token, expires_in, locationId } = tokenResp || {};

if (!locationId) {
  // No location yet? Stash tokens temporarily and let FE finish via /api/app-context
  const payload = JSON.stringify({
    access_token,
    refresh_token,
    expires_at: Date.now() + ((expires_in ?? 3600) * 1000) - 60_000,
  });

  const encrypted = CryptoJS.AES.encrypt(payload, process.env.APP_SECRET || 'dev-secret-change-me-in-production').toString();

  res.cookie('ghl_pending_tokens', encrypted, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none',
    signed: true,
    maxAge: 5 * 60 * 1000 // 5 minutes
  });

  return res.redirect('/launch');
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

return res.redirect('/launch');
    
  } catch (e) {
    console.error('OAuth callback error:', e?.response?.status, e?.response?.data || e.message);
    res.status(400).json({
      error: 'OAuth exchange failed',
      details: e?.response?.data?.error_description || e.message
    });
  }
});

// 2. Import Fields for a Specific Object (simplified CSV format)
app.post('/api/objects/:objectKey/fields/import', requireAuth, upload.single('fields'), async (req, res) => {
  const locationId = req.locationId;
  const { objectKey } = req.params;
  
  if (!req.file) {
    return res.status(400).json({ error: 'Fields CSV file is required' });
  }

  try {
    // Clean the object key
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const apiObjectKey = `custom_objects.${cleanKey}`;
    
    // Verify the object exists
    const token = await withAccessToken(locationId);
    const listSchemas = await axios.get(`${API_BASE}/objects/`, {
      headers: { 
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28'
      },
      params: { locationId }
    });

    const objects = Array.isArray(listSchemas.data?.objects) ? listSchemas.data.objects : [];
    const schema = objects.find(obj => obj.key === objectKey || obj.key === apiObjectKey);
    
    if (!schema) {
      return res.status(404).json({ error: `Object ${objectKey} not found` });
    }

const fields = await parseCSV(req.file.path);
    const created = [];
    const errors = [];
    const skipped = [];
    
    // Ensure we have a folder for the fields
    let defaultFolderId = null;
    
    try {
      const existingResp = await axios.get(
        `${API_BASE}/custom-fields/object-key/${encodeURIComponent(apiObjectKey)}`,
        {
          headers: { 
            Authorization: `Bearer ${token}`,
            Version: '2021-07-28'
          },
          params: { locationId }
        }
      );
      
      // The API returns folders separately
      const folders = existingResp.data?.folders || [];
      
      if (folders.length > 0) {
        defaultFolderId = folders[0].id;
        console.log(`Using existing folder "${folders[0].name}" (${defaultFolderId})`);
      }
    } catch (e) {
      if (e?.response?.status === 404) {
        console.log('No fields exist yet for this object');
      }
    }
    
    // If no folder exists, create one
    if (!defaultFolderId) {
const folderPayload = {
        locationId: locationId,
        name: 'General',
        dataType: 'GROUP',
        fieldKey: `${apiObjectKey}.general_folder`,
        objectKey: apiObjectKey
      };

      try {
        const folderResp = await axios.post(`${API_BASE}/custom-fields/`, folderPayload, {
          headers: { 
            Authorization: `Bearer ${token}`,
            Version: '2021-07-28'
          }
        });
        
        defaultFolderId = folderResp.data?.id || folderResp.data?.data?.id;
        console.log(`Created new folder "General" (${defaultFolderId})`);
      } catch (e) {
        console.error('Failed to create default folder:', e?.response?.data || e.message);
      }
    }
    
    // Check for existing folders/fields to see the structure
    try {
      const existingFieldsResp = await axios.get(
        `${API_BASE}/custom-fields/object-key/${encodeURIComponent(apiObjectKey)}`,
        {
          headers: { 
            Authorization: `Bearer ${token}`,
            Version: '2021-07-28'
          },
          params: { locationId }
        }
      );
      
      const existingFields = existingFieldsResp.data?.fields || [];
      const folders = existingFields.filter(f => f.dataType === 'GROUP');
      
      console.log(`Existing folders for ${apiObjectKey}:`, folders);
      
      // If no folders exist, we might need to create one
      if (folders.length === 0) {
        console.log('No folders found. Creating default folder...');
        
        const folderPayload = {
          locationId: locationId,
          name: 'General',
          dataType: 'GROUP',
          fieldKey: `${apiObjectKey}.general_folder`,
          objectKey: apiObjectKey
        };
        
        const folderResp = await axios.post(`${API_BASE}/custom-fields/`, folderPayload, {
          headers: { 
            Authorization: `Bearer ${token}`,
            Version: '2021-07-28'
          }
        });
        
        const defaultFolderId = folderResp.data?.id || folderResp.data?.data?.id;
        console.log('Created default folder with ID:', defaultFolderId);
        
        // Use this folder ID for all fields
        req.defaultFolderId = defaultFolderId;
      } else {
        // Use the first existing folder
        req.defaultFolderId = folders[0].id;
        console.log('Using existing folder:', folders[0].name, 'ID:', req.defaultFolderId);
      }
    } catch (e) {
      console.error('Error checking/creating folder:', e?.response?.data || e.message);
    }
    
    for (const row of fields) {
      // Generate field key from name
      const fieldName = row.name;
      if (!fieldName) {
        console.warn('Skipping field row without name:', row);
        skipped.push({ row, reason: 'Missing field name' });
        continue;
      }

      // Generate a clean field key from the name
      const fieldKey = fieldName.toLowerCase()
        .replace(/[^a-z0-9\s_-]/g, '') // Remove special chars
        .replace(/\s+/g, '_')           // Replace spaces with underscores
        .replace(/_+/g, '_')            // Remove duplicate underscores
        .replace(/^_|_$/g, '');         // Trim underscores

      try {
        // Parse options if provided
        let options = null;
        if (row.options) {
          try { 
            options = JSON.parse(row.options);
            if (!Array.isArray(options)) {
              options = String(row.options).split('|').map(s => s.trim()).filter(Boolean);
            }
          } catch { 
            options = String(row.options).split('|').map(s => s.trim()).filter(Boolean);
          }
        }

        // Normalize data type
        const dataType = normalizeDataType(row.data_type || 'TEXT');

        const fieldPayload = {
          locationId: locationId,
          name: fieldName,
          description: row.description || "",
          placeholder: row.placeholder || "",
          showInForms: row.show_in_forms !== undefined ? 
            String(row.show_in_forms).toLowerCase() === 'true' : true,
          dataType: dataType,
          fieldKey: `${apiObjectKey}.${fieldKey}`,
          objectKey: apiObjectKey
        };

// For custom objects, parentId (folder) is required
        const providedFolderId = row.existing_folder_id || row.folder_id || row.parent_id || '';
        
        if (providedFolderId && providedFolderId.trim() !== '') {
          fieldPayload.parentId = providedFolderId.trim();
        } else if (defaultFolderId) {
          fieldPayload.parentId = defaultFolderId;
        }
        // Note: If somehow we have no folder at all, the API will error


        // If folderId is empty/null/undefined, we don't add parentId at all        
        // Add options for relevant field types
        if (options && ['SINGLE_OPTIONS', 'MULTIPLE_OPTIONS', 'RADIO', 'CHECKBOX', 'TEXTBOX_LIST'].includes(dataType)) {
          fieldPayload.options = options.map(opt => {
            if (typeof opt === 'string') {
              return { 
                key: opt.toLowerCase().replace(/[^a-z0-9]/g, '_'), 
                label: opt 
              };
            }
            return {
              key: opt.key || opt.label?.toLowerCase().replace(/[^a-z0-9]/g, '_') || opt,
              label: opt.label || opt.key || opt,
              ...(opt.url && { url: opt.url })
            };
          });
        }

// Add file upload specific attributes
        if (dataType === 'FILE_UPLOAD') {
          if (row.accepted_formats && row.accepted_formats.trim() !== '') {
            // Clean up formats - ensure they start with a dot
            const formats = row.accepted_formats.split(',')
              .map(f => f.trim())
              .filter(f => f !== '') // Remove empty strings
              .map(f => f.startsWith('.') ? f : `.${f}`);
            
            // acceptedFormats should be an array, not a string
            if (formats.length > 0) {
              fieldPayload.acceptedFormats = formats;
            }
          }
                              if (row.max_file_limit) {
            fieldPayload.maxFileLimit = parseInt(row.max_file_limit) || 1;
          }
        }

        // Add radio specific attribute
        if (dataType === 'RADIO' && row.allow_custom_option !== undefined) {
          fieldPayload.allowCustomOption = String(row.allow_custom_option).toLowerCase() === 'true';
        }

// Debug: log the exact payload being sent
        console.log(`Creating field ${fieldName}, payload:`, JSON.stringify(fieldPayload, null, 2));
        
        const createField = await axios.post(`${API_BASE}/custom-fields/`, fieldPayload, {          headers: { 
            Authorization: `Bearer ${token}`,
            Version: '2021-07-28'
          }
        });
        
        created.push({ 
          fieldKey, 
          id: createField.data?.id || createField.data?.data?.id || createField.data?.field?.id,
          label: fieldName 
        });
      } catch (e) {
        const errorMessage = e?.response?.data?.message || e?.response?.data || e.message;
        
        // Check if field already exists
        if (e?.response?.status === 400 && errorMessage?.includes('already exists')) {
          skipped.push({ 
            fieldName, 
            reason: 'Field already exists' 
          });
          console.log(`Field ${fieldName} already exists, skipping`);
        } else {
          errors.push({ 
            fieldName, 
            error: errorMessage
          });
          console.error(`Failed to create field ${fieldName}:`, errorMessage);
        }
      }
    }

    await cleanupTempFiles([req.file.path]);
    
    res.json({
      success: errors.length === 0,
      message: `Processed ${fields.length} fields for ${cleanKey}`,
      objectKey: cleanKey,
      objectId: schema.id,
      created,
      skipped,
      errors,
      summary: {
        total: fields.length,
        created: created.length,
        skipped: skipped.length,
        failed: errors.length
      }
    });

  } catch (e) {
    handleAPIError(res, e, 'Fields import');
  }
});
// Get object schema by key (proxied to GHL)
// FE calls: GET /api/objects/:objectKey/schema?fetchProperties=true[&locationId=...]

// 3. Import Records for a Specific Object
// 3. Import Records for a Specific Object
app.post('/api/objects/:objectKey/records/import', requireAuth, upload.single('records'), async (req, res) => {
  const locationId = req.locationId;
  const { objectKey } = req.params;
  const token = await withAccessToken(locationId);
  const headers = { 
    Authorization: `Bearer ${token}`,
    Version: '2021-07-28'
  };

  if (!req.file) {
    return res.status(400).json({ error: 'Records CSV file is required' });
  }

  try {
    // Get the full object key for API calls
    const fullObjectKey = objectKey.startsWith('custom_objects.') 
      ? objectKey 
      : `custom_objects.${objectKey}`;

    // FIRST: Fetch field definitions to know their types
    const fieldsResponse = await axios.get(
      `${API_BASE}/custom-fields/object-key/${encodeURIComponent(fullObjectKey)}`,
      {
        headers,
        params: { locationId }
      }
    );

    const fields = fieldsResponse.data?.fields || [];
    const fieldTypeMap = {};

    // Build a map of field keys to their data types
    fields.forEach(field => {
      if (field.fieldKey) {
        const parts = field.fieldKey.split('.');
        const fieldKey = parts[parts.length - 1];
        fieldTypeMap[fieldKey] = field.dataType;
      }
    });

    const records = await parseCSV(req.file.path);
    const created = [];
    const errors = [];

    for (const row of records) {
      try {
        const properties = {};
        const recordId = row.id;

        for (const [k, v] of Object.entries(row)) {
          // Skip system fields and empty values
          if (['object_key', 'id', 'external_id', 'owner', 'followers', 'association_id', 'related_record_id', 'association_type'].includes(k)) continue;
          if (v === '' || v === null || v === undefined) continue;
          
          // Use the actual field type from schema
          const fieldType = fieldTypeMap[k];
          
if (fieldType === 'MONETORY') {
  properties[k] = {
    currency: "default",
    value: parseFloat(v) || 0
  };
} else if (fieldType === 'MULTIPLE_OPTIONS' || fieldType === 'CHECKBOX') {
  properties[k] = v.split(',').map(s => s.trim());
} else if (fieldType === 'FILE_UPLOAD') {
  properties[k] = [{ url: v }];
} else if (fieldType === 'NUMERICAL') {
  properties[k] = parseFloat(v) || 0;
} else if (fieldType === 'DATE') {
  properties[k] = v; // Keep as string, GHL expects ISO format
} else if (fieldType === 'PHONE') {
  // Clean up phone numbers - remove quotes and extra characters
  let phone = String(v).trim();
  // Remove surrounding quotes if present
  phone = phone.replace(/^["']|["']$/g, '');
  // Ensure it starts with + for international format
  if (phone && !phone.startsWith('+')) {
    phone = '+' + phone;
  }
  properties[k] = phone;
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
            // First verify the record exists
            await axios.get(
              `${API_BASE}/objects/${fullObjectKey}/records/${recordId}`,
              { 
                headers,
                params: { locationId }
              }
            );

            // Record exists, update it
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
              throw getError;
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

        const createdRecordId = recordResult.data?.id || recordResult.data?.data?.id || recordId;

        created.push({ 
          externalId: row.external_id || 'N/A', 
          id: createdRecordId,
          properties: Object.keys(properties),
          action: action
        });

      } catch (e) {
        errors.push({ 
          externalId: row.external_id, 
          error: e?.response?.data || e.message 
        });
        console.error(`Failed to process record:`, e?.response?.data || e.message);
      }
    }

    await cleanupTempFiles([req.file.path]);
    
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
    handleAPIError(res, e, 'Records import');
  }
});
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
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
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

const { default: axios } = await import('axios');
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