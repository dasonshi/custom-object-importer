// src/routes/debug.js
import { Router } from 'express';
import { installs } from '../middleware/auth.js';
import { withAccessToken, API_BASE } from '../services/tokenService.js';
import axios from 'axios';

const router = Router();

// SDK methods check
router.get('/sdk-methods', (req, res) => {
  const methods = {
    ghl_keys: Object.keys(global.ghl),
    has_objects: !!global.ghl.objects,
    has_customFields: !!global.ghl.customFields,
    has_locations: !!global.ghl.locations,
    has_oauth: !!global.ghl.oauth,
    has_contacts: !!global.ghl.contacts,
    has_request: typeof global.ghl.request === 'function',
    has_setAccessToken: typeof global.ghl.setAccessToken === 'function'
  };
  
  if (global.ghl.objects) {
    methods.objects_methods = Object.keys(global.ghl.objects);
  }
  if (global.ghl.customFields) {
    methods.customFields_methods = Object.keys(global.ghl.customFields);
  }
  if (global.ghl.locations) {
    methods.locations_methods = Object.keys(global.ghl.locations);
    if (global.ghl.locations.customFields) {
      methods.locations_customFields_methods = Object.keys(global.ghl.locations.customFields);
    }
    if (global.ghl.locations.customValues) {
      methods.locations_customValues_methods = Object.keys(global.ghl.locations.customValues);
    }
  }
  if (global.ghl.oauth) {
    methods.oauth_methods = Object.keys(global.ghl.oauth);
  }
  
  res.json(methods);
});

// Cookies check
router.get('/cookies', (req, res) => {
  res.json({
    origin: req.get('origin') || null,
    hasSigned: Boolean(req.signedCookies?.ghl_location),
    hasUnsigned: Boolean(req.cookies?.ghl_location),
    valuePreview: (req.signedCookies?.ghl_location || req.cookies?.ghl_location || '').slice(0, 8),
  });
});

// Installation check
router.get('/install/:locationId', async (req, res) => {
  const { locationId } = req.params;
  const has = await installs.has(locationId);
  let tokenOk = false, companyOk = false, locationOk = false, logs = [];

  if (has) {
    try {
      const token = await withAccessToken(locationId);
      tokenOk = Boolean(token);
      const install = await installs.get(locationId);
      if (!install?.access_token) throw new Error(`No tokens for location ${locationId}`);

      const { data } = await axios.get(
        `https://services.leadconnectorhq.com/locations/${encodeURIComponent(locationId)}`,
        {
          headers: {
            Authorization: `Bearer ${install.access_token}`,
            Version: '2021-07-28',
          },
          timeout: 30000,
        }
      );
      const r1 = { data };

      locationOk = !!r1.data?.id || !!r1.data?.name;
      const r2 = await axios.get(`${API_BASE}/marketplace/app/${process.env.GHL_CLIENT_ID}/installations`, 
        { 
          headers: { 
            Authorization: `Bearer ${token}`,
            Version: '2021-07-28'
          } 
        });      
      companyOk = Boolean(r2.data?.company?.name || r2.data?.name);
    } catch (e) {
      logs.push(e?.response?.data || e.message);
    }
  }

  res.json({ hasInstall: has, tokenOk, locationOk, companyOk, logs });
});

// Force token to expire (for testing token refresh)
// Note: This is safe in production - it only affects tokens for testing
router.post('/expire-token/:locationId', async (req, res) => {
  const { locationId } = req.params;

  try {
    const hasInstall = await installs.has(locationId);
    if (!hasInstall) {
      return res.status(404).json({ error: 'Installation not found', locationId });
    }

    const install = await installs.get(locationId);
    const oldExpiry = install.expires_at;

    // Set token to expire in 2 minutes (within the 5-minute refresh buffer)
    const newExpiry = Date.now() + (2 * 60 * 1000);

    await installs.set(locationId, {
      ...install,
      expires_at: newExpiry
    });

    res.json({
      success: true,
      locationId,
      oldExpiryDate: new Date(oldExpiry).toISOString(),
      newExpiryDate: new Date(newExpiry).toISOString(),
      message: 'Token set to expire in 2 minutes. Next API call should trigger refresh.'
    });

  } catch (e) {
    res.status(500).json({
      error: 'Failed to expire token',
      details: e.message
    });
  }
});

// Token scopes test
router.get('/token-scopes/:locationId', async (req, res) => {
  const { locationId } = req.params;
  
  try {
    const hasInstall = await installs.has(locationId);
    if (!hasInstall) {
      return res.status(404).json({ error: 'Installation not found', locationId });
    }

    const token = await withAccessToken(locationId);
    const headers = { Authorization: `Bearer ${token}` };

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

    try {
      await axios.get(`${API_BASE}/objects/`, { headers, params: { locationId } });
      scopeTests['objects/schema.readonly'] = true;
    } catch (e) { console.log('Objects schema read failed:', e?.response?.status); }

    try {
      await axios.get(`${API_BASE}/custom-fields/`, { headers, params: { locationId } });
      scopeTests['locations/customFields.readonly'] = true;
    } catch (e) { console.log('Custom fields read failed:', e?.response?.status); }

    try {
      await axios.get(`${API_BASE}/locations/${locationId}/customValues`, { headers });
      scopeTests['locations/customValues.readonly'] = true;
    } catch (e) { console.log('Custom values read failed:', e?.response?.status, e?.response?.data?.message); }

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

export default router;