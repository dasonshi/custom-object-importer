// src/routes/objects.js
import { Router } from 'express';
import axios from 'axios';
import { requireAuth, handleLocationOverride } from '../middleware/auth.js';
import { withAccessToken, API_BASE } from '../services/tokenService.js';
import { installs } from '../middleware/auth.js';

const router = Router();

// List all custom objects
router.get('/', requireAuth, handleLocationOverride, async (req, res) => {
  const locationId = req.locationId;
  try {
    const token = await withAccessToken(locationId);
    const r = await axios.get(`${API_BASE}/objects/`, {
      headers: { 
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28'
      },
      params: { locationId }
    });

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
      data: customObjects
    });
  } catch (e) {
    console.error('objects lookup error:', e?.response?.status, e?.response?.data || e.message);
    res.status(500).json({ error: 'Lookup failed', details: e?.response?.data || e.message });
  }
});

// Get single object schema
router.get('/:objectKey/schema', requireAuth, async (req, res) => {
  try {
    const locationId = req.locationId;
    const { objectKey } = req.params;

    const cleanKey = String(objectKey).replace(/^custom_objects\./, '');
    const apiObjectKey = `custom_objects.${cleanKey}`;

    const params = { locationId };
    if (String(req.query.fetchProperties).toLowerCase() === 'true') {
      params.fetchProperties = 'true';
    }

    const token = await withAccessToken(locationId);
    const r = await axios.get(`${API_BASE}/objects/${apiObjectKey}`, {
      headers: { 
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28'
      },
      params
    });
    res.json(r.data);
  } catch (e) {
    console.error('schema fetch failed:', e?.response?.status, e?.response?.data || e.message);
    res.status(e?.response?.status || 500).json(e?.response?.data || { error: 'schema_fetch_failed' });
  }
});

// Get fields for object
router.get('/:objectKey/fields', requireAuth, handleLocationOverride, async (req, res) => {
  const locationId = req.locationId;
  let { objectKey } = req.params;
  
  try {
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const apiObjectKey = `custom_objects.${cleanKey}`;
    
    const token = await withAccessToken(locationId);
    const response = await axios.get(`${API_BASE}/custom-fields/object-key/${encodeURIComponent(apiObjectKey)}`, {
      headers: { 
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28'
      },
      params: { locationId }
    });

    const fields = response.data?.fields || [];
    const parentIds = [...new Set(fields.map(f => f.parentId).filter(Boolean))];
    
    const folders = {};
    for (const parentId of parentIds) {
      try {
        const folderToken = await withAccessToken(locationId);
        const folderResponse = await axios.get(
          `${API_BASE}/custom-fields/${parentId}`,
          { 
            headers: {
              Authorization: `Bearer ${folderToken}`,
              Version: '2021-07-28'
            }
          }
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

// Get associations for object
router.get('/:objectKey/associations', requireAuth, handleLocationOverride, async (req, res) => {
  const locationId = req.locationId;
  const { objectKey } = req.params;
  
  try {
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const apiObjectKey = `custom_objects.${cleanKey}`;
    
    const token = await withAccessToken(locationId);
    
    const response = await axios.get(
      `${API_BASE}/associations/objectKey/${encodeURIComponent(apiObjectKey)}`,
      {
        headers: { 
          Authorization: `Bearer ${token}`,
          Version: '2021-07-28'
        },
        params: { locationId }
      }
    );
    
    const associations = Array.isArray(response.data) 
      ? response.data 
      : response.data?.associations || [];
    
    res.json({
      objectKey: cleanKey,
      associations: associations.map(assoc => ({
        id: assoc.id,
        key: assoc.key,
        firstObjectKey: assoc.firstObjectKey,
        firstObjectLabel: assoc.firstObjectLabel,
        secondObjectKey: assoc.secondObjectKey,
        secondObjectLabel: assoc.secondObjectLabel,
        relationTo: assoc.firstObjectKey === apiObjectKey || assoc.firstObjectKey === objectKey
          ? assoc.secondObjectKey
          : assoc.firstObjectKey,
        description: `${assoc.firstObjectLabel} → ${assoc.secondObjectLabel}`,
        isFirst: assoc.firstObjectKey === apiObjectKey || assoc.firstObjectKey === objectKey,
        associationType: assoc.associationType
      }))
    });
  } catch (e) {
    if (e?.response?.status === 404) {
      const cleanKey = objectKey.replace(/^custom_objects\./, '');
      res.json({ objectKey: cleanKey, associations: [] });
    } else {
      console.error('Fetch associations error:', e?.response?.data || e.message);
      res.status(500).json({ error: 'Fetch object associations', details: e?.response?.data || e.message });
    }
  }
});

export default router;