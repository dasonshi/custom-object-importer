// src/routes/imports/index.js
import { Router } from 'express';
import multer from 'multer';
import pLimit from 'p-limit';
import { requireAuth, validateTenant } from '../../middleware/auth.js';
import { parseCSV, cleanupTempFiles } from '../../utils/csvParser.js';
import { normalizeDataType } from '../../utils/dataTransformers.js';
import { handleAPIError } from '../../utils/apiHelpers.js';
import { withAccessToken, API_BASE } from '../../services/tokenService.js';
import axios from 'axios';
import {
  isStandardObject,
  validateFieldName,
  getFieldCreateEndpoint,
  formatFieldPayload,
  normalizeFieldResponse,
  delay,
  retryWithBackoff
} from '../../utils/objectHelpers.js';
import { AdaptiveRateController } from '../../utils/adaptiveRateController.js';

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
          catch {
            // Auto-detect delimiter: use | if present, otherwise use comma
            const optStr = row.options || '';
            const delimiter = optStr.includes('|') ? '|' : ',';
            payload.options = optStr.split(delimiter).map(s => s.trim()).filter(Boolean);
          }
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
    const skipped = [];
    const errors = [];

    for (let rowIndex = 0; rowIndex < objects.length; rowIndex++) {
      const row = objects[rowIndex];
      try {
        const objectKey = row.object_key ?
          String(row.object_key).trim() :
          String(row.name || '').trim().toLowerCase().replace(/\s+/g, '_');

        if (!objectKey || !row.name) {
          skipped.push({
            recordIndex: rowIndex,
            name: row.name || `Row ${rowIndex + 1}`,
            reason: 'Missing object name'
          });
          console.warn('Skipping object row without name:', row);
          continue;
        }

        if (schemaIdByKey[objectKey]) {
          skipped.push({
            recordIndex: rowIndex,
            name: row.name,
            reason: 'Object already exists'
          });
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
      } catch (e) {
        const apiError = e?.response?.data;
        errors.push({
          recordIndex: rowIndex,
          name: row.name || `Row ${rowIndex + 1}`,
          error: apiError?.message || e.message,
          errorCode: apiError?.error || 'Error',
          statusCode: apiError?.statusCode || e?.response?.status
        });
        console.error(`Failed to create object ${row.name} (row ${rowIndex + 1}):`, apiError || e.message);
      }
    }

    await cleanupTempFiles([req.file.path]);

    res.json({
      success: errors.length === 0,
      message: `Processed ${objects.length} objects, created ${created.length} new schemas`,
      created,
      skipped,
      errors,
      summary: {
        total: objects.length,
        created: created.length,
        skipped: skipped.length,
        failed: errors.length
      }
    });

  } catch (e) {
    handleAPIError(res, e, 'Objects import');
  }
});

// ... continuing in src/routes/imports/index.js after the objects import route

// Import fields for a specific object (both standard and custom)
router.post('/objects/:objectKey/fields/import', requireAuth, upload.single('fields'), async (req, res) => {
  const locationId = req.locationId;
  const { objectKey } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'Fields CSV file is required' });
  }

  try {
    // Clean the object key and detect type
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const isStandard = isStandardObject(cleanKey);
    const apiObjectKey = isStandard ? cleanKey : `custom_objects.${cleanKey}`;

    // Verify the object exists (skip for standard objects as they always exist)
    const token = await withAccessToken(locationId);
    let schema = null;

    if (isStandard) {
      // Standard objects always exist, create a mock schema
      schema = {
        id: `standard_${cleanKey}`,
        key: cleanKey,
        labels: {
          singular: cleanKey.charAt(0).toUpperCase() + cleanKey.slice(1),
          plural: cleanKey.charAt(0).toUpperCase() + cleanKey.slice(1) + 's'
        }
      };
    } else {
      // Verify custom object exists
      const listSchemas = await axios.get(`${API_BASE}/objects/`, {
        headers: {
          Authorization: `Bearer ${token}`,
          Version: '2021-07-28'
        },
        params: { locationId }
      });

      const objects = Array.isArray(listSchemas.data?.objects) ? listSchemas.data.objects : [];
      schema = objects.find(obj => obj.key === objectKey || obj.key === apiObjectKey);

      if (!schema) {
        return res.status(404).json({ error: `Object ${objectKey} not found` });
      }
    }

    const fields = await parseCSV(req.file.path);
    const created = [];
    const errors = [];
    const skipped = [];

    // Ensure we have a folder for custom object fields (skip for standard objects)
    let defaultFolderId = null;

    if (!isStandard) {
      // Only create/fetch folders for custom objects
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
    }
    
    // Process each field
    for (let rowIndex = 0; rowIndex < fields.length; rowIndex++) {
      const row = fields[rowIndex];
      const fieldName = row.name;
      if (!fieldName) {
        console.warn('Skipping field row without name:', row);
        skipped.push({ row, reason: 'Missing field name' });
        continue;
      }

      try {
        // Validate field name for standard objects
        if (isStandard) {
          try {
            validateFieldName(fieldName, cleanKey);
          } catch (e) {
            skipped.push({
              fieldName,
              reason: e.message
            });
            console.log(`Skipping reserved field name: ${fieldName}`);
            continue;
          }
        }

        // Parse options if provided
        let options = null;
        if (row.options) {
          try {
            options = JSON.parse(row.options);
            if (!Array.isArray(options)) {
              // Auto-detect delimiter: use | if present, otherwise use comma
              const optStr = String(row.options);
              const delimiter = optStr.includes('|') ? '|' : ',';
              options = optStr.split(delimiter).map(s => s.trim()).filter(Boolean);
            }
          } catch {
            // Auto-detect delimiter: use | if present, otherwise use comma
            const optStr = String(row.options);
            const delimiter = optStr.includes('|') ? '|' : ',';
            options = optStr.split(delimiter).map(s => s.trim()).filter(Boolean);
          }
        }

        // Prepare field data
        const fieldData = {
          name: fieldName,
          dataType: normalizeDataType(row.data_type || 'TEXT'),
          description: row.description || "",
          placeholder: row.placeholder || "",
          show_in_forms: row.show_in_forms,
          position: row.position,
          options: options,
          acceptedFormat: row.accepted_formats,
          isMultipleFile: row.is_multiple_file,
          maxNumberOfFiles: row.max_number_of_files || row.max_file_limit,
          textBoxListOptions: row.textbox_list_options
        };

        // Determine folder ID - use CSV value if provided for custom objects, otherwise default
        const folderId = !isStandard
          ? (row.existing_folder_id || row.folder_id || row.parent_id || defaultFolderId)
          : null;

        // Format payload based on object type
        const fieldPayload = formatFieldPayload(cleanKey, fieldData, locationId, folderId);

        // Get the correct endpoint
        const endpoint = getFieldCreateEndpoint(cleanKey, locationId);

        console.log(`Creating ${isStandard ? 'standard' : 'custom'} field ${fieldName} for ${cleanKey}`);
        console.log('Endpoint:', endpoint);
        console.log('Payload:', JSON.stringify(fieldPayload, null, 2));

        // Create the field
        const createField = await axios.post(endpoint, fieldPayload, {
          headers: {
            Authorization: `Bearer ${token}`,
            Version: '2021-07-28'
          }
        });

        // Add rate limiting delay to prevent API throttling
        await delay(200);

        // Normalize response and track success
        const field = normalizeFieldResponse(createField.data, isStandard);
        created.push({
          fieldKey: field.fieldKey || fieldName,
          id: field.id,
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
          const apiError = e?.response?.data;
          errors.push({
            recordIndex: rowIndex,
            fieldName,
            name: fieldName,
            error: apiError?.message || errorMessage,
            errorCode: apiError?.error || 'Error',
            statusCode: apiError?.statusCode || e?.response?.status
          });
          console.error(`Failed to create field ${fieldName} (row ${rowIndex + 1}):`, errorMessage);
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

    // Use adaptive rate controller based on file size
    const controller = new AdaptiveRateController(records.length);
    console.log(`[RecordsImport] Starting import of ${records.length} records for ${fullObjectKey}`);

    // Helper function to process a single record
    const processRecord = async (row, rowIndex) => {
      try {
        const properties = {};
        const recordId = row.id;
        for (const [k, v] of Object.entries(row)) {
          // Skip system fields, CSV parser metadata, and empty values
          if (['object_key', 'id', 'external_id', 'owner', 'followers', 'association_id', 'related_record_id', 'association_type', '__parsed_extra'].includes(k)) continue;
          if (v === '' || v === null || v === undefined) continue;

          // Use the actual field type from schema
          const fieldType = fieldTypeMap[k];

          if (fieldType === 'MONETORY') {
            properties[k] = {
              currency: "default",
              value: parseFloat(v) || 0
            };
          } else if (fieldType === 'MULTIPLE_OPTIONS' || fieldType === 'CHECKBOX' || fieldType === 'TEXTBOX_LIST') {
            properties[k] = String(v).split(',').map(s => s.trim());
          } else if (fieldType === 'FILE_UPLOAD') {
            properties[k] = [{ url: v }];
          } else if (fieldType === 'NUMERICAL') {
            properties[k] = parseFloat(v) || 0;
          } else if (fieldType === 'DATE') {
            properties[k] = v; // Keep as string, GHL expects ISO format
          } else if (fieldType === 'PHONE') {
            // Smart phone number formatting with warning tracking
            const { formatPhoneNumber } = await import('../../utils/phoneFormatter.js');
            let phone = String(v).trim().replace(/^["']|["']$/g, '');
            const phoneResult = formatPhoneNumber(phone);
            properties[k] = phoneResult.formatted;
            if (phoneResult.warning) {
              if (!row._phoneWarnings) row._phoneWarnings = [];
              row._phoneWarnings.push({ field: k, warning: phoneResult.warning });
            }
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
          createRequestBody.owner = String(row.owner).split(',').map(s => s.trim());
        }
        if (row.followers) {
          createRequestBody.followers = String(row.followers).split(',').map(s => s.trim());
        }
        // Build request body for UPDATE (PUT) - only properties
        const updateRequestBody = {
          properties: properties
        };
        let recordResult;
        let action = 'created';
        if (recordId) {
          try {
            // First verify the record exists (with retry for rate limits)
            await retryWithBackoff(() => axios.get(
              `${API_BASE}/objects/${fullObjectKey}/records/${recordId}`,
              { headers }
            ));
            // Record exists, update it (with retry for rate limits)
            recordResult = await retryWithBackoff(() => axios.put(
              `${API_BASE}/objects/${fullObjectKey}/records/${recordId}`,
              updateRequestBody,
              { headers }
            ));
            action = 'updated';
          } catch (getError) {
            if (getError?.response?.status === 404) {
              console.log(`Record ID ${recordId} not found, creating new record instead`);
              // Record doesn't exist, create new one (with retry for rate limits)
              recordResult = await retryWithBackoff(() => axios.post(
                `${API_BASE}/objects/${fullObjectKey}/records`,
                createRequestBody,
                { headers }
              ));
              action = 'created (id not found)';
            } else {
              throw getError;
            }
          }
        } else {
          // Create new record (with retry for rate limits)
          recordResult = await retryWithBackoff(() => axios.post(
            `${API_BASE}/objects/${fullObjectKey}/records`,
            createRequestBody,
            { headers }
          ));
        }

        const createdRecordId = recordResult.data?.id || recordResult.data?.data?.id || recordId;

        // Record success and apply adaptive delay
        controller.recordSuccess();
        await controller.applyDelay();

        return {
          success: true,
          data: {
            externalId: row.external_id || 'N/A',
            id: createdRecordId,
            properties: Object.keys(properties),
            action: action,
            phoneWarnings: row._phoneWarnings || null
          }
        };

      } catch (e) {
        const apiError = e?.response?.data;
        const statusCode = apiError?.statusCode || e?.response?.status;

        // Report 429s to controller for adaptive rate limiting
        if (statusCode === 429) {
          controller.record429();
        }

        console.error(`Failed to process record (row ${rowIndex + 1}):`, apiError || e.message);
        return {
          success: false,
          error: {
            recordIndex: rowIndex,
            externalId: row.external_id,
            name: row.external_id || Object.values(row).find(v => v && typeof v === 'string')?.substring(0, 50),
            error: apiError?.message || e.message,
            errorCode: apiError?.error || 'Error',
            statusCode: statusCode
          }
        };
      }
    };

    // Process records in batches with adaptive rate limiting
    const allResults = [];
    const batchSize = controller.getBatchSize();
    const totalBatches = Math.ceil(records.length / batchSize);

    for (let batchNum = 0; batchNum < totalBatches; batchNum++) {
      const batchStart = batchNum * batchSize;
      const batchEnd = Math.min(batchStart + batchSize, records.length);
      const batch = records.slice(batchStart, batchEnd);

      console.log(`[RecordsImport] Processing batch ${batchNum + 1}/${totalBatches} (records ${batchStart + 1}-${batchEnd})`);

      // Wait for circuit breaker if tripped
      await controller.waitIfCircuitBroken();

      // Process batch with current concurrency setting
      const limit = pLimit(controller.getConcurrency());
      const batchResults = await Promise.all(
        batch.map((row, idx) => limit(async () => {
          // Wait for circuit breaker before each request
          await controller.waitIfCircuitBroken();
          return processRecord(row, batchStart + idx);
        }))
      );

      allResults.push(...batchResults);

      // Pause between batches (except for last batch)
      if (batchNum < totalBatches - 1) {
        await controller.applyBatchPause();
      }
    }

    // Separate successes and failures
    const created = allResults.filter(r => r.success).map(r => r.data);
    const errors = allResults.filter(r => !r.success).map(r => r.error);

    // Collect all phone formatting warnings
    const phoneWarnings = created
      .filter(r => r.phoneWarnings && r.phoneWarnings.length > 0)
      .map(r => ({
        recordId: r.id,
        externalId: r.externalId,
        warnings: r.phoneWarnings
      }));

    const stats = controller.getStats();
    console.log(`[RecordsImport] Complete. Stats:`, stats);
    if (phoneWarnings.length > 0) {
      console.log(`[RecordsImport] Phone numbers auto-formatted: ${phoneWarnings.length} records`);
    }

    await cleanupTempFiles([req.file.path]);

    res.json({
      success: true,
      message: `Processed ${records.length} records for ${objectKey}`,
      objectKey,
      created,
      errors,
      phoneWarnings,
      summary: {
        total: records.length,
        successful: created.length,
        failed: errors.length,
        phoneAutoFormatted: phoneWarnings.length
      },
      rateStats: stats
    });

  } catch (e) {
    handleAPIError(res, e, 'Records import');
  }
});

// Bulk delete records
router.post('/objects/:objectKey/records/delete', requireAuth, validateTenant, upload.single('records'), async (req, res) => {
  const locationId = req.locationId;
  const { objectKey } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'Records CSV file with IDs is required' });
  }

  try {
    const token = await withAccessToken(locationId);
    const headers = {
      Authorization: `Bearer ${token}`,
      Version: '2021-07-28'
    };

    // Ensure proper object key format
    const fullObjectKey = objectKey.startsWith('custom_objects.')
      ? objectKey
      : `custom_objects.${objectKey}`;

    const records = await parseCSV(req.file.path);

    if (records.length === 0) {
      await cleanupTempFiles([req.file.path]);
      return res.status(400).json({ error: 'CSV file is empty or has no valid records' });
    }

    // Find the ID column - look for common variations
    const firstRow = records[0];
    const idColumnCandidates = ['id', 'record_id', 'recordid', 'record id', '_id'];
    let idColumn = null;

    for (const candidate of idColumnCandidates) {
      if (firstRow.hasOwnProperty(candidate)) {
        idColumn = candidate;
        break;
      }
    }

    // If no standard ID column found, check if there's only one column
    const columns = Object.keys(firstRow);
    if (!idColumn && columns.length === 1) {
      idColumn = columns[0];
    }

    if (!idColumn) {
      await cleanupTempFiles([req.file.path]);
      return res.status(400).json({
        error: 'Could not find ID column in CSV',
        message: 'CSV must have a column named "id", "record_id", or similar. Found columns: ' + columns.join(', ')
      });
    }

    console.log(`[RecordsDelete] Starting deletion of ${records.length} records from ${fullObjectKey} using column "${idColumn}"`);

    // Use adaptive rate controller
    const controller = new AdaptiveRateController(records.length);
    const batchSize = controller.getBatchSize();
    const totalBatches = Math.ceil(records.length / batchSize);

    // Process delete for a single record
    const processDelete = async (row, rowIndex) => {
      const recordId = String(row[idColumn] || '').trim();

      if (!recordId) {
        return {
          success: false,
          error: {
            recordIndex: rowIndex + 2, // +2 for header row and 0-indexing
            id: null,
            error: 'Missing or empty record ID',
            errorCode: 'MISSING_ID'
          }
        };
      }

      try {
        await retryWithBackoff(() => axios.delete(
          `${API_BASE}/objects/${fullObjectKey}/records/${recordId}`,
          { headers }
        ));

        controller.recordSuccess();
        await controller.applyDelay();

        return {
          success: true,
          data: {
            id: recordId,
            action: 'deleted',
            rowIndex: rowIndex + 2
          }
        };
      } catch (e) {
        const status = e?.response?.status;
        const apiError = e?.response?.data;

        if (status === 429) {
          controller.record429();
        }

        // Treat 404 as "not found" rather than error
        if (status === 404) {
          return {
            success: false,
            notFound: true,
            data: {
              id: recordId,
              rowIndex: rowIndex + 2,
              reason: 'Record not found'
            }
          };
        }

        return {
          success: false,
          error: {
            recordIndex: rowIndex + 2,
            id: recordId,
            error: apiError?.message || e.message,
            errorCode: apiError?.error || 'DELETE_FAILED',
            statusCode: status
          }
        };
      }
    };

    // Process in batches
    const allResults = [];

    for (let batchNum = 0; batchNum < totalBatches; batchNum++) {
      const batchStart = batchNum * batchSize;
      const batch = records.slice(batchStart, batchStart + batchSize);

      console.log(`[RecordsDelete] Processing batch ${batchNum + 1}/${totalBatches} (${batch.length} records)`);

      const limit = pLimit(controller.getConcurrency());
      const batchResults = await Promise.all(
        batch.map((row, idx) => limit(async () => {
          await controller.waitIfCircuitBroken();
          return processDelete(row, batchStart + idx);
        }))
      );

      allResults.push(...batchResults);

      // Pause between batches (except for last batch)
      if (batchNum < totalBatches - 1) {
        await controller.applyBatchPause();
      }
    }

    // Separate results
    const deleted = allResults.filter(r => r.success).map(r => r.data);
    const notFound = allResults.filter(r => r.notFound).map(r => r.data);
    const errors = allResults.filter(r => !r.success && !r.notFound).map(r => r.error);

    const stats = controller.getStats();
    console.log(`[RecordsDelete] Complete. Deleted: ${deleted.length}, Not Found: ${notFound.length}, Errors: ${errors.length}`);

    await cleanupTempFiles([req.file.path]);

    res.json({
      success: errors.length === 0,
      message: `Deleted ${deleted.length} records from ${objectKey}`,
      objectKey: fullObjectKey,
      deleted,
      notFound,
      errors,
      summary: {
        total: records.length,
        deleted: deleted.length,
        notFound: notFound.length,
        failed: errors.length
      },
      rateStats: stats
    });

  } catch (e) {
    await cleanupTempFiles([req.file?.path].filter(Boolean));
    handleAPIError(res, e, 'Records delete');
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

    for (let rowIndex = 0; rowIndex < rows.length; rowIndex++) {
      const row = rows[rowIndex];
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
        const apiError = e?.response?.data;
        const msg = apiError?.message || apiError || e.message;
        if (/(exist|duplicate)/i.test(String(msg))) {
          skipped.push({ row, reason: 'already exists' });
        } else {
          errors.push({
            recordIndex: rowIndex,
            name: row.association_key || row.key || `Row ${rowIndex + 1}`,
            error: typeof msg === 'string' ? msg : JSON.stringify(msg),
            errorCode: apiError?.error || 'Error',
            statusCode: apiError?.statusCode || e?.response?.status
          });
          console.error(`Association type create error (row ${rowIndex + 1}):`, msg);
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

    for (let rowIndex = 0; rowIndex < customValues.length; rowIndex++) {
      const row = customValues[rowIndex];
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
        const apiError = e?.response?.data;
        errors.push({
          recordIndex: rowIndex,
          name: row.name || 'unnamed',
          error: apiError?.message || (typeof apiError === 'string' ? apiError : e.message),
          errorCode: apiError?.error || 'Error',
          statusCode: apiError?.statusCode || e?.response?.status
        });
        console.error(`Failed to process custom value ${row.name} (row ${rowIndex + 1}):`, apiError || e.message);
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

    // Get association ID from form field (new method) or fall back to CSV column (legacy)
    const formAssociationId = req.body?.associationId?.trim();

    // Helper to get association details
    const getAssociationDetails = async (associationId) => {
      // Handle hardcoded Contact-Business native association
      if (associationId === 'contact-business-native') {
        return {
          id: 'contact-business-native',
          key: 'contact-business',
          firstObjectKey: 'contact',
          firstObjectLabel: 'Contact',
          secondObjectKey: 'business',
          secondObjectLabel: 'Business',
          isNative: true
        };
      }

      try {
        const response = await axios.get(
          `${API_BASE}/associations/${associationId}`,
          { headers, params: { locationId } }
        );
        return response.data;
      } catch (e) {
        if (e?.response?.status === 404) {
          throw new Error(`Association ${associationId} not found`);
        }
        throw e;
      }
    };

    // Helper to check if association is Contact-Business
    const isContactBusinessAssociation = (association) => {
      const first = association.firstObjectKey?.toLowerCase();
      const second = association.secondObjectKey?.toLowerCase();
      return (first === 'contact' && second === 'business') ||
             (first === 'business' && second === 'contact');
    };

    // Get association details ONCE if provided via form field
    let association = null;
    if (formAssociationId) {
      association = await getAssociationDetails(formAssociationId);
      console.log(`[Relations Import] Using form association: ${formAssociationId} (${association.firstObjectKey} → ${association.secondObjectKey})`);
    }

    // First pass: separate Contact-Business links from regular relations
    const contactBusinessLinks = {}; // businessId -> [{contactId, rowIndex}]
    const regularRelations = []; // [{row, rowIndex, association}]

    for (let rowIndex = 0; rowIndex < relations.length; rowIndex++) {
      const row = relations[rowIndex];
      try {
        // Use form association if provided, else read from CSV row (legacy)
        let rowAssociation = association;
        let associationId = formAssociationId;

        if (!rowAssociation) {
          // Legacy: read from CSV column
          associationId = String(row.association_id || '').trim();
          if (!associationId) {
            throw new Error('Missing association_id. Please select an association before uploading.');
          }
          rowAssociation = await getAssociationDetails(associationId);
        }

        // Parse record IDs (support dynamic column names like contact_record_id, business_record_id)
        let firstRecordId = '';
        let secondRecordId = '';

        // Try explicit columns first
        if (row.first_record_id && row.second_record_id) {
          firstRecordId = String(row.first_record_id).trim();
          secondRecordId = String(row.second_record_id).trim();
        } else {
          // Find columns ending in _record_id (e.g., contact_record_id, business_record_id)
          const recordIdColumns = Object.keys(row).filter(key =>
            key.endsWith('_record_id') && key !== 'association_id'
          );
          if (recordIdColumns.length >= 2) {
            recordIdColumns.sort();
            firstRecordId = String(row[recordIdColumns[0]] || '').trim();
            secondRecordId = String(row[recordIdColumns[1]] || '').trim();
          }
        }

        if (!firstRecordId || !secondRecordId) {
          const availableColumns = Object.keys(row).join(', ');
          throw new Error(`Missing record IDs. Expected two columns ending in _record_id. Found: ${availableColumns}`);
        }

        if (isContactBusinessAssociation(rowAssociation)) {
          // Determine which ID is contact and which is business
          const contactId = rowAssociation.firstObjectKey?.toLowerCase() === 'contact'
            ? firstRecordId : secondRecordId;
          const businessId = rowAssociation.firstObjectKey?.toLowerCase() === 'business'
            ? firstRecordId : secondRecordId;

          if (!contactBusinessLinks[businessId]) {
            contactBusinessLinks[businessId] = [];
          }
          contactBusinessLinks[businessId].push({ contactId, rowIndex });
        } else {
          regularRelations.push({ row, rowIndex, associationId, firstRecordId, secondRecordId });
        }

      } catch (e) {
        const msg = e?.response?.data?.message || e?.response?.data || e.message;
        errors.push({
          recordIndex: rowIndex,
          name: `Row ${rowIndex + 1}`,
          error: typeof msg === 'string' ? msg : JSON.stringify(msg),
          errorCode: 'ValidationError'
        });
      }
    }

    // Process Contact-Business links in batches (max 50 per API call)
    console.log(`[Relations Import] Processing ${Object.keys(contactBusinessLinks).length} businesses with contact links`);
    for (const [businessId, contacts] of Object.entries(contactBusinessLinks)) {
      const contactIds = contacts.map(c => c.contactId);

      // Batch in groups of 50
      for (let i = 0; i < contactIds.length; i += 50) {
        const batch = contactIds.slice(i, i + 50);
        try {
          await axios.post(
            `${API_BASE}/contacts/bulk/business`,
            { locationId, ids: batch, businessId },
            { headers }
          );

          // Mark all contacts in this batch as created
          batch.forEach(contactId => {
            created.push({
              type: 'contact-business',
              contactId,
              businessId,
              description: `Contact ${contactId} → Business ${businessId}`
            });
          });

          await delay(200); // Rate limiting
        } catch (e) {
          console.error(`[Relations Import] Contact-Business API error:`, JSON.stringify({
            status: e?.response?.status,
            data: e?.response?.data,
            businessId,
            contactIds: batch
          }, null, 2));

          const msg = e?.response?.data?.message || e?.response?.data || e.message;

          // Check if already linked
          if (/(exist|already)/i.test(String(msg))) {
            batch.forEach(contactId => {
              skipped.push({ contactId, businessId, reason: 'Already linked' });
            });
          } else {
            // Find the row indices for error reporting
            const rowIndices = contacts
              .filter(c => batch.includes(c.contactId))
              .map(c => c.rowIndex);
            errors.push({
              recordIndex: rowIndices[0],
              name: `Business ${businessId} (${batch.length} contacts)`,
              error: typeof msg === 'string' ? msg : JSON.stringify(msg),
              errorCode: e?.response?.data?.error || 'Error',
              statusCode: e?.response?.status
            });
          }
        }
      }
    }

    // Process regular Custom Object relations
    console.log(`[Relations Import] Processing ${regularRelations.length} regular relations`);
    for (const { row, rowIndex, associationId, firstRecordId, secondRecordId } of regularRelations) {
      try {
        const payload = {
          locationId,
          associationId,
          firstRecordId,
          secondRecordId
        };

        const result = await axios.post(
          `${API_BASE}/associations/relations`,
          payload,
          { headers }
        );

        created.push({
          id: result.data?.id || result.data?.data?.id,
          type: 'custom-object',
          associationId,
          firstRecordId,
          secondRecordId,
          description: `${firstRecordId} ↔ ${secondRecordId}`
        });

        await delay(200); // Rate limiting

      } catch (e) {
        const msg = e?.response?.data?.message || e?.response?.data || e.message;

        if (/(exist|duplicate)/i.test(String(msg))) {
          skipped.push({
            associationId,
            firstRecordId,
            secondRecordId,
            reason: 'Relation already exists'
          });
        } else {
          errors.push({
            recordIndex: rowIndex,
            name: `${firstRecordId} ↔ ${secondRecordId}`,
            error: typeof msg === 'string' ? msg : JSON.stringify(msg),
            errorCode: e?.response?.data?.error || 'Error',
            statusCode: e?.response?.status
          });
          console.error(`Relation create error (row ${rowIndex + 1}):`, msg);
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
        failed: errors.length,
        contactBusinessLinks: Object.keys(contactBusinessLinks).length > 0
          ? Object.values(contactBusinessLinks).reduce((sum, arr) => sum + arr.length, 0)
          : 0
      }
    });

  } catch (e) {
    handleAPIError(res, e, 'Relations import');
  }
});

export default router;