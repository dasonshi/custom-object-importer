// src/routes/imports/index.js
import { Router } from 'express';
import multer from 'multer';
import { requireAuth, validateTenant } from '../../middleware/auth.js';
import { parseCSV, cleanupTempFiles } from '../../utils/csvParser.js';
import { normalizeDataType } from '../../utils/dataTransformers.js';
import { handleAPIError } from '../../utils/apiHelpers.js';
import { withAccessToken, API_BASE } from '../../services/tokenService.js';
import axios from 'axios';

const router = Router();
const upload = multer({ dest: '/tmp' });

// Main import route (original multi-file import)
router.post('/:locationId', requireAuth, validateTenant, upload.fields([
  { name: 'objects', maxCount: 1 },
  { name: 'fields', maxCount: 1 },
  { name: 'records', maxCount: 1 }
]), async (req, res) => {
  const locationId = req.locationId;
  let objPath, fldPath, recPath;
  
  try {
    objPath = req.files?.objects?.[0]?.path;
    const objects = objPath ? await parseCSV(objPath) : [];
    const schemaIdByKey = {};

    let existing = [];
    try {
      const token = await withAccessToken(locationId);
      const listSchemas = await axios.get(`${API_BASE}/objects/`, {
        headers: { 
          Authorization: `Bearer ${token}`,
          Version: '2021-07-28'
        },
        params: { locationId }
      });
      existing = Array.isArray(listSchemas.data?.objects)
        ? listSchemas.data.objects
        : Array.isArray(listSchemas.data?.data)
          ? listSchemas.data.data
          : Array.isArray(listSchemas.data) ? listSchemas.data : [];
    } catch (e) {
      if (e?.response?.status === 404) {
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
        const objectKey = String(row.object_key).trim();
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
          labels: {
            singular,
            plural
          },
          key: fqObjectKey,
          description: row.description || '',
          primaryDisplayPropertyDetails: {
            key: fqPrimaryKey,
            name: String(row.primary_display_label || 'Name'),
            dataType: 'TEXT'
          },
          locationId
        };

        const token = await withAccessToken(locationId);
        const create = await axios.post(`${API_BASE}/objects/`, payload, {
          headers: { 
            Authorization: `Bearer ${token}`,
            Version: '2021-07-28'
          }
        });
        const createdId = create.data?.id || create.data?.data?.id || create.data?.object?.id;
        if (!createdId) throw new Error('No object id returned');

        schemaIdByKey[objectKey] = createdId;
      } catch (e) {
        console.error(`Failed to create schema ${row.object_key}:`, e?.response?.data || e.message);
        throw e;
      }
    }

    // Process fields if provided
    fldPath = req.files?.fields?.[0]?.path;
    const fields = fldPath ? await parseCSV(fldPath) : [];
    const fieldCacheBySchema = {};

    for (const [, schemaId] of Object.entries(schemaIdByKey)) {
      fieldCacheBySchema[schemaId] = {};
    }

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
          fieldKey: `custom_objects.${row.object_key}.${payload.key}`,
          objectKey: `custom_objects.${row.object_key}`
        };

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
                return {
                  key: opt.key || opt.label?.toLowerCase() || opt,
                  label: opt.label || opt.key || opt,
                  ...(opt.url && { url: opt.url })
                };
              })
            : payload.options;
        }

        const token = await withAccessToken(locationId);
        const createField = await axios.post(`${API_BASE}/custom-fields/`, fieldPayload, {
          headers: { 
            Authorization: `Bearer ${token}`,
            Version: '2021-07-28'
          }
        });
        if (!fieldCacheBySchema[schemaId]) fieldCacheBySchema[schemaId] = {};
        fieldCacheBySchema[schemaId][key] = createField.data?.id || createField.data?.data?.id || createField.data?.property?.id;
      } catch (e) {
        console.error(`Failed to create field ${key}:`, e?.response?.data || e.message);
        throw e;
      }
    }

    // Process records if provided
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
        recordsProcessed++;
      }
    }

    await cleanupTempFiles([objPath, fldPath, recPath]);

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

// Import just objects
router.post('/objects/import', requireAuth, upload.single('objects'), async (req, res) => {
  // Copy your existing /api/objects/import route handler here
  // This is lines 967-1075 from your server.js
  const locationId = req.locationId;
  
  if (!req.file) {
    return res.status(400).json({ error: 'Objects CSV file is required' });
  }
  
  try {
    const objects = await parseCSV(req.file.path);
    const schemaIdByKey = {};
    
    let existing = [];
    try {
      const token = await withAccessToken(locationId);
      const listSchemas = await axios.get(`${API_BASE}/objects/`, {
        headers: { 
          Authorization: `Bearer ${token}`,
          Version: '2021-07-28'
        },
        params: { locationId }
      });
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

    const created = [];
    for (const row of objects) {
      const objectKey = row.object_key ? 
        String(row.object_key).trim() : 
        String(row.name || '').trim().toLowerCase().replace(/\s+/g, '_');
      
      if (!objectKey || !row.name) {
        console.warn('Skipping object row without name:', row);
        continue;
      }
      
      if (schemaIdByKey[objectKey]) {
        console.log(`Schema ${objectKey} already exists, skipping`);
        continue;
      }

      const singular = String(row.name).trim();
      const plural = String(row.plural || `${singular}s`).trim();
      const fqObjectKey = `custom_objects.${objectKey}`;

      const primaryFieldName = String(row.primary_field_name || 'Name').trim();
      const primaryKey = primaryFieldName.toLowerCase().replace(/\s+/g, '_');
      const fqPrimaryKey = `custom_objects.${objectKey}.${primaryKey}`;

      const payload = {
        labels: { singular, plural },
        key: fqObjectKey,
        description: row.description || '',
        primaryDisplayPropertyDetails: {
          key: fqPrimaryKey,
          name: primaryFieldName,
          dataType: row.primary_field_type || 'TEXT'
        },
        locationId
      };

      const token = await withAccessToken(locationId);
      const createResp = await axios.post(`${API_BASE}/objects/`, payload, {
        headers: { 
          Authorization: `Bearer ${token}`,
          Version: '2021-07-28'
        }
      });
      const createdId = createResp.data?.id || createResp.data?.data?.id || createResp.data?.object?.id;
      
      if (createdId) {
        schemaIdByKey[objectKey] = createdId;
        created.push({ objectKey, id: createdId, name: singular });
      }
    }

    await cleanupTempFiles([req.file.path]);

    res.json({
      success: true,
      message: `Processed ${objects.length} objects, created ${created.length} new schemas`,
      created,
      existing: Object.keys(schemaIdByKey).filter(key => !created.find(c => c.objectKey === key))
    });

  } catch (e) {
    handleAPIError(res, e, 'Objects import');
  }
});

// ... continuing in src/routes/imports/index.js after the objects import route

// Import fields for a specific object
router.post('/objects/:objectKey/fields/import', requireAuth, upload.single('fields'), async (req, res) => {
  // Copy lines 290-547 from your server.js here
  // This is the entire fields import handler
});

// Import records for a specific object  
router.post('/objects/:objectKey/records/import', requireAuth, upload.single('records'), async (req, res) => {
  // Copy lines 552-683 from your server.js here
  // This is the entire records import handler
});

// Import association types
router.post('/associations/types/import', requireAuth, upload.single('associations'), async (req, res) => {
  // Copy lines 685-738 from your server.js here
});

// Import custom values
router.post('/custom-values/import', requireAuth, upload.single('customValues'), async (req, res) => {
  // Copy lines 740-802 from your server.js here
});

// Import relations
router.post('/associations/relations/import', requireAuth, upload.single('relations'), async (req, res) => {
  // Copy lines 804-881 from your server.js here  
});

export default router;