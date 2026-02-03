// src/routes/objects.js
import { Router } from 'express';
import axios from 'axios';
import { requireAuth, validateTenant } from '../middleware/auth.js';
import { withAccessToken, API_BASE } from '../services/tokenService.js';
import { installs } from '../middleware/auth.js';
import Papa from 'papaparse';
import { handleAPIError } from '../utils/apiHelpers.js';
import { isStandardObject, getFieldFetchEndpoint } from '../utils/objectHelpers.js';
const router = Router();

/**
 * Safely normalize dataType to a string.
 * Handles cases where GHL API returns dataType as an object {id, label} instead of a string.
 */
function normalizeDataType(dataType) {
  if (typeof dataType === 'string') return dataType;
  if (dataType && typeof dataType === 'object') {
    if (typeof dataType.id === 'string') return dataType.id;
    if (typeof dataType.label === 'string') return dataType.label;
  }
  return 'TEXT';
}

// List all objects (both standard and custom)
router.get('/', requireAuth, validateTenant, async (req, res) => {
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

    // Filter to only get custom objects
    const customObjects = allObjects.filter(obj =>
      obj.key && obj.key.startsWith('custom_objects.')
    );

    // Extract standard objects from GHL response (they include custom labels!)
    const ghlContactObj = allObjects.find(obj => obj.key === 'contact');
    const ghlOpportunityObj = allObjects.find(obj => obj.key === 'opportunity');
    const ghlBusinessObj = allObjects.find(obj => obj.key === 'business');

    // Build standard objects - use GHL labels if available, fallback to defaults
    const standardObjects = [
      {
        id: ghlContactObj?.id || 'standard_contact',
        key: 'contact',
        labels: ghlContactObj?.labels || { singular: 'Contact', plural: 'Contacts' },
        isStandard: true,
        icon: 'user',
        description: 'Standard CRM contact object'
      },
      {
        id: ghlOpportunityObj?.id || 'standard_opportunity',
        key: 'opportunity',
        labels: ghlOpportunityObj?.labels || { singular: 'Opportunity', plural: 'Opportunities' },
        isStandard: true,
        icon: 'dollar-sign',
        description: 'Standard CRM opportunity/deal object'
      },
      {
        id: ghlBusinessObj?.id || 'standard_business',
        key: 'business',
        labels: ghlBusinessObj?.labels || { singular: 'Business', plural: 'Businesses' },
        isStandard: true,
        icon: 'building',
        description: 'Standard CRM business/company object'
      }
    ];

    // Mark custom objects as non-standard
    const enhancedCustomObjects = customObjects.map(obj => ({
      ...obj,
      isStandard: false
    }));

    // Combine standard and custom objects
    const allAvailableObjects = [...standardObjects, ...enhancedCustomObjects];

    res.json({
      ...r.data,
      objects: allAvailableObjects,
      data: allAvailableObjects
    });
  } catch (e) {
    console.error('objects lookup error:', e?.response?.status, e?.response?.data || e.message);

    // If JWT is invalid, clear the installation
    if (e?.response?.status === 401 && e?.response?.data?.message === 'Invalid JWT') {
      console.log(`Clearing invalid installation for ${locationId}`);
      await installs.delete(locationId);
    }

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

// Get fields for object (both standard and custom)
router.get('/:objectKey/fields', requireAuth, validateTenant, async (req, res) => {
  const locationId = req.locationId;
  let { objectKey } = req.params;

  try {
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const isStandard = isStandardObject(cleanKey);
    const token = await withAccessToken(locationId);

    let response;
    let fields = [];
    let folders = {};

    if (isStandard) {
      // Fetch standard object fields using appropriate endpoint
      const endpoint = getFieldFetchEndpoint(cleanKey, locationId);
      response = await axios.get(endpoint.url, {
        headers: {
          Authorization: `Bearer ${token}`,
          Version: '2021-07-28'
        },
        params: endpoint.params
      });

      if (endpoint.responseType === 'customObject') {
        // Business uses the same response format as custom objects
        fields = (response.data?.fields || []).map(field => ({
          id: field.id,
          name: field.name,
          fieldKey: field.fieldKey,
          dataType: normalizeDataType(field.dataType),
          placeholder: field.placeholder,
          description: field.description,
          picklistOptions: field.options,
          isStandard: true
        }));
        folders = response.data?.folders || [];
      } else {
        // Contact/Opportunity use customFields response format
        const customFields = response.data?.customFields || [];
        fields = customFields.filter(field =>
          field.model === cleanKey
        ).map(field => ({
          id: field.id,
          name: field.name,
          fieldKey: field.fieldKey,
          dataType: normalizeDataType(field.dataType),
          placeholder: field.placeholder,
          position: field.position,
          model: field.model,
          picklistOptions: field.picklistOptions,
          isStandard: true
        }));
        folders = {};
      }
    } else {
      // Custom object - use existing logic
      const apiObjectKey = `custom_objects.${cleanKey}`;
      response = await axios.get(`${API_BASE}/custom-fields/object-key/${encodeURIComponent(apiObjectKey)}`, {
        headers: {
          Authorization: `Bearer ${token}`,
          Version: '2021-07-28'
        },
        params: { locationId }
      });

      fields = response.data?.fields || [];
      const parentIds = [...new Set(fields.map(f => f.parentId).filter(Boolean))];

      // Fetch folder information for custom objects
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

      // Enhance fields with folder information and normalize dataType
      fields = fields.map(field => ({
        ...field,
        dataType: normalizeDataType(field.dataType),
        folder: field.parentId ? folders[field.parentId] : null
      }));
    }

    res.json({
      objectKey: cleanKey,
      fields: fields,
      folders: Object.values(folders),
      isStandardObject: isStandard
    });
  } catch (e) {
    console.error(`Failed to fetch fields for object ${objectKey}:`, e?.response?.data || e.message);

    // If GHL returns 400 Bad Request for business fields (known API limitation),
    // return empty fields instead of erroring out
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    if (e?.response?.status === 400 && cleanKey === 'business') {
      console.log('GHL API does not support business custom fields for this location, returning empty fields');
      return res.json({
        objectKey: cleanKey,
        fields: [],
        folders: [],
        isStandardObject: true,
        note: 'Business custom fields are not available via API for this location'
      });
    }

    res.status(500).json({ error: 'Failed to fetch fields', details: e?.response?.data || e.message });
  }
});

// Get associations for object
router.get('/:objectKey/associations', requireAuth, validateTenant, async (req, res) => {
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
// Export all records for an object as CSV
router.get('/:objectKey/records/export', requireAuth, validateTenant, async (req, res) => {
  const locationId = req.locationId;
  const { objectKey } = req.params;
  
  try {
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const apiObjectKey = `custom_objects.${cleanKey}`;
    
    // First, fetch the field definitions to know the structure
    const token = await withAccessToken(locationId);
    const fieldsResponse = await axios.get(
      `${API_BASE}/custom-fields/object-key/${encodeURIComponent(apiObjectKey)}`,
      {
        headers: { 
          Authorization: `Bearer ${token}`,
          Version: '2021-07-28'
        },
        params: { locationId }
      }
    );
    
    const fields = fieldsResponse.data?.fields || [];
    const fieldMap = {};
    
    // Build a map of field keys to their labels and types
    fields.forEach(field => {
      if (field.fieldKey) {
        const parts = field.fieldKey.split('.');
        const fieldKey = parts[parts.length - 1];
        fieldMap[fieldKey] = {
          label: field.name || fieldKey,
          dataType: field.dataType
        };
      }
    });
    
    // Fetch all records with pagination
    let allRecords = [];
    let page = 1;
    let hasMore = true;
    const pageLimit = 100; // Max per request
    
    while (hasMore) {
      const searchBody = {
        locationId: locationId,
        page: page,
        pageLimit: pageLimit,
        query: '',
        searchAfter: []
      };
      
      const response = await axios.post(
        `${API_BASE}/objects/${encodeURIComponent(apiObjectKey)}/records/search`,
        searchBody,
        {
          headers: { 
            Authorization: `Bearer ${token}`,
            Version: '2021-07-28',
            'Content-Type': 'application/json'
          }
        }
      );
      
      const records = response.data?.records || [];
      allRecords = [...allRecords, ...records];
      
      // Check if we've fetched everything
      hasMore = records.length === pageLimit && allRecords.length < (response.data?.total || 0);
      page++;
      
      // Safety limit to prevent infinite loops
      if (page > 100) {
        console.warn(`Safety limit reached for ${objectKey} export, stopping at ${allRecords.length} records`);
        hasMore = false;
      }
    }
    
    // Handle empty results
    if (allRecords.length === 0) {
      // Still return an empty CSV with headers
      const headers = ['id', 'created_at', 'updated_at'];
      const csv = Papa.unparse({
        fields: headers,
        data: []
      });
      
      const timestamp = new Date().toISOString().split('T')[0];
      const filename = `${cleanKey}-export-${timestamp}.csv`;
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Cache-Control', 'no-cache');
      
      return res.send(csv);
    }
    
    // Get all unique field keys from all records
    const allFieldKeys = new Set();
    allRecords.forEach(record => {
      if (record.properties) {
        Object.keys(record.properties).forEach(key => allFieldKeys.add(key));
      }
    });
    
    // Build CSV headers - include system fields and custom fields
    const systemHeaders = ['id', 'created_at', 'updated_at', 'created_by', 'updated_by'];
    const customHeaders = Array.from(allFieldKeys).sort();
    const headers = [...systemHeaders, ...customHeaders];
    
    // Build CSV rows
    const rows = allRecords.map(record => {
      const row = [];
      
      // System fields
      row.push(record.id || '');
      row.push(record.createdAt || '');
      row.push(record.updatedAt || '');
      row.push(record.createdBy?.sourceId || '');
      row.push(record.lastUpdatedBy?.sourceId || '');
      
      // Custom fields
      customHeaders.forEach(fieldKey => {
        const value = record.properties?.[fieldKey];
        
        // Handle different data types
        if (value === null || value === undefined) {
          row.push('');
        } else if (typeof value === 'object') {
          // Handle special field types
          if (value.currency && value.value !== undefined) {
            // MONETORY field
            row.push(value.value.toString());
          } else if (Array.isArray(value)) {
            // Handle arrays (MULTIPLE_OPTIONS, FILE_UPLOAD, etc.)
            if (value.length > 0 && value[0].url) {
              // FILE_UPLOAD - extract URLs
              row.push(value.map(f => f.url).join('|'));
            } else {
              // Regular array
              row.push(value.join('|'));
            }
          } else {
            // Other objects - stringify
            row.push(JSON.stringify(value));
          }
        } else {
          // Simple values
          row.push(String(value));
        }
      });
      
      return row;
    });
    
    // Convert to CSV format using Papaparse
    const csv = Papa.unparse({
      fields: headers.map(h => {
        // Use field labels where available
        if (fieldMap[h]) {
          return fieldMap[h].label;
        }
        // Make system headers more readable
        return h.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
      }),
      data: rows
    });
    
    // Set response headers for file download
    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `${cleanKey}-export-${timestamp}.csv`;
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Cache-Control', 'no-cache');
    
    // Send the CSV
    res.send(csv);
    
  } catch (e) {
    console.error(`Failed to export records for ${objectKey}:`, e?.response?.data || e.message);
    handleAPIError(res, e, 'Export records');
  }
});

// Search/Get records for a specific object (for viewing, not export)
router.post('/:objectKey/records/search', requireAuth, validateTenant, async (req, res) => {
  const locationId = req.locationId;
  const { objectKey } = req.params;
  
  try {
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const apiObjectKey = `custom_objects.${cleanKey}`;
    
    const requestBody = {
      locationId: locationId,
      page: req.body.page || 1,
      pageLimit: req.body.pageLimit || 20,
      query: req.body.query || '',
      searchAfter: req.body.searchAfter || []
    };
    
    const token = await withAccessToken(locationId);
    const response = await axios.post(
      `${API_BASE}/objects/${encodeURIComponent(apiObjectKey)}/records/search`,
      requestBody,
      {
        headers: { 
          Authorization: `Bearer ${token}`,
          Version: '2021-07-28',
          'Content-Type': 'application/json'
        }
      }
    );
    
    res.json({
      objectKey: cleanKey,
      ...response.data
    });
    
  } catch (e) {
    if (e?.response?.status === 404) {
      res.json({
        objectKey: objectKey.replace(/^custom_objects\./, ''),
        records: [],
        total: 0
      });
    } else {
      console.error(`Failed to search records for ${objectKey}:`, e?.response?.data || e.message);
      handleAPIError(res, e, 'Search object records');
    }
  }
});

// Convenience GET endpoint for simple record queries
router.get('/:objectKey/records', requireAuth, validateTenant, async (req, res) => {
  const locationId = req.locationId;
  const { objectKey } = req.params;
  
  try {
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const apiObjectKey = `custom_objects.${cleanKey}`;
    
    const requestBody = {
      locationId: locationId,
      page: parseInt(req.query.page) || 1,
      pageLimit: parseInt(req.query.limit) || parseInt(req.query.pageLimit) || 20,
      query: req.query.query || req.query.search || '',
      searchAfter: req.query.searchAfter ? 
        (Array.isArray(req.query.searchAfter) ? req.query.searchAfter : [req.query.searchAfter]) : []
    };
    
    const token = await withAccessToken(locationId);
    const response = await axios.post(
      `${API_BASE}/objects/${encodeURIComponent(apiObjectKey)}/records/search`,
      requestBody,
      {
        headers: { 
          Authorization: `Bearer ${token}`,
          Version: '2021-07-28',
          'Content-Type': 'application/json'
        }
      }
    );
    
    res.json({
      objectKey: cleanKey,
      ...response.data
    });
    
  } catch (e) {
    if (e?.response?.status === 404) {
      res.json({
        objectKey: objectKey.replace(/^custom_objects\./, ''),
        records: [],
        total: 0
      });
    } else {
      console.error(`Failed to fetch records for ${objectKey}:`, e?.response?.data || e.message);
      handleAPIError(res, e, 'Fetch object records');
    }
  }
});
export default router;