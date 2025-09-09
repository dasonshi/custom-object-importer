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

        console.log(`Creating field ${fieldName}, payload:`, JSON.stringify(fieldPayload, null, 2));
        
        const createField = await axios.post(`${API_BASE}/custom-fields/`, fieldPayload, {
          headers: { 
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

// Import records for a specific object  
router.post('/objects/:objectKey/records/import', requireAuth, upload.single('records'), async (req, res) => {
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

// Import association types
router.post('/associations/types/import', requireAuth, upload.single('associations'), async (req, res) => {
  const locationId = req.locationId;
  const headers = { Authorization: `Bearer ${await withAccessToken(locationId)}` };
  
  if (!req.file) return res.status(400).json({ error: 'Associations CSV file is required' });

  try {
    const rows = await parseCSV(req.file.path);

    const created = [];
    const skipped = [];
    const errors = [];

    const ensureKey = (k) => {
      if (!k) return k;
      // only prefix custom objects (contacts etc. should be left as-is)
      return /^custom_objects\./.test(k) ? k : (['contact','opportunity','business'].includes(k) ? k : `custom_objects.${k}`);
    };

    for (const row of rows) {
      try {
        const key = String(row.association_key || row.key || '').trim();
        const firstObjectKey = ensureKey(String(row.first_object_key || '').trim());
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
        // If API returns "already exists"/duplicate, treat as skip
        const msg = e?.response?.data || e.message;
        if (/(exist|duplicate)/i.test(String(msg))) {
          skipped.push({ row, reason: 'already exists' });
        } else {
          errors.push({ row, error: msg });
          console.error('Association type create error:', msg);
        }
      }
    }

    await cleanupTempFiles([req.file.path]);
    res.json({ success: errors.length === 0, created, skipped, errors });

  } catch (e) {
    handleAPIError(res, e, 'Association types import');
  }
});

// Import custom values
router.post('/custom-values/import', requireAuth, upload.single('customValues'), async (req, res) => {
  const locationId = req.locationId;
  const headers = { 
    Authorization: `Bearer ${await withAccessToken(locationId)}`,
    Version: '2021-07-28'
  };
  
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

// Import relations
router.post('/associations/relations/import', requireAuth, upload.single('relations'), async (req, res) => {
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
        
        // Support both old format (first_record_id, second_record_id) and new dynamic format
        let firstRecordId = '';
        let secondRecordId = '';
        
        // Try old format first
        if (row.first_record_id && row.second_record_id) {
          firstRecordId = String(row.first_record_id).trim();
          secondRecordId = String(row.second_record_id).trim();
        } else {
          // Try to find dynamic column names ending with '_record_id'
          const recordIdColumns = Object.keys(row).filter(key => 
            key.endsWith('_record_id') && key !== 'association_id'
          );
          
          if (recordIdColumns.length >= 2) {
            // Sort to ensure consistent order (alphabetical)
            recordIdColumns.sort();
            firstRecordId = String(row[recordIdColumns[0]] || '').trim();
            secondRecordId = String(row[recordIdColumns[1]] || '').trim();
          }
        }

        if (!associationId || !firstRecordId || !secondRecordId) {
          const availableColumns = Object.keys(row).join(', ');
          throw new Error(`Missing required fields. Expected: association_id and two record ID columns. Found columns: ${availableColumns}`);
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

export default router;