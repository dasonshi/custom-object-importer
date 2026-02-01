import { API_BASE } from '../services/tokenService.js';

// Define standard objects supported by the app
const STANDARD_OBJECTS = Object.freeze(['contact', 'opportunity']);

// Define reserved field names that can't be used for custom fields
const RESERVED_FIELD_NAMES = Object.freeze({
  contact: [
    'firstName', 'lastName', 'email', 'phone', 'address1', 'address2',
    'city', 'state', 'country', 'postalCode', 'companyName', 'website',
    'timezone', 'dnd', 'dndAll', 'inboundDndAll', 'tags', 'source',
    'customField', 'dateOfBirth', 'ssn'
  ],
  opportunity: [
    'name', 'pipelineId', 'pipelineStageId', 'status', 'monetaryValue',
    'assignedTo', 'contactId', 'locationId', 'source', 'wonValue',
    'lostValue', 'leadValue', 'stageName', 'createdBy', 'updatedBy'
  ]
});

/**
 * Check if an object key represents a standard object (contact/opportunity)
 * @param {string} objectKey - The object key to check
 * @returns {boolean} True if standard object, false otherwise
 */
export function isStandardObject(objectKey) {
  // Remove any prefix if it exists
  const cleanKey = objectKey.replace('custom_objects.', '');
  return STANDARD_OBJECTS.includes(cleanKey);
}

/**
 * Validate that a field name is not reserved for a standard object
 * @param {string} name - The field name to validate
 * @param {string} objectType - The object type (contact/opportunity)
 * @throws {Error} If the field name is reserved
 */
export function validateFieldName(name, objectType) {
  const normalizedName = name.toLowerCase().replace(/[^a-z0-9]/g, '');
  const reservedNames = RESERVED_FIELD_NAMES[objectType];

  if (reservedNames) {
    const reserved = reservedNames.some(reserved =>
      reserved.toLowerCase() === normalizedName
    );

    if (reserved) {
      throw new Error(`"${name}" is a reserved field name for ${objectType}`);
    }
  }
}

/**
 * Get the correct API endpoint for creating fields based on object type
 * @param {string} objectKey - The object key
 * @param {string} locationId - The location ID
 * @returns {string} The API endpoint URL
 */
export function getFieldCreateEndpoint(objectKey, locationId) {
  const cleanKey = objectKey.replace('custom_objects.', '');

  if (isStandardObject(cleanKey)) {
    return `${API_BASE}/locations/${locationId}/customFields`;
  }
  return `${API_BASE}/custom-fields/`;
}

/**
 * Format field payload based on whether it's for a standard or custom object
 * @param {string} objectKey - The object key
 * @param {Object} fieldData - The field data from CSV
 * @param {string} locationId - The location ID
 * @param {string} folderId - The folder ID (only for custom objects)
 * @returns {Object} Formatted payload for API
 */
export function formatFieldPayload(objectKey, fieldData, locationId, folderId = null) {
  const cleanKey = objectKey.replace('custom_objects.', '');

  if (isStandardObject(cleanKey)) {
    // Standard object payload format
    const payload = {
      name: fieldData.name,
      dataType: fieldData.dataType || fieldData.data_type,
      model: cleanKey, // 'contact' or 'opportunity'
      placeholder: fieldData.placeholder || '',
      position: parseInt(fieldData.position) || 0
    };

    // Add options for dropdown/multi-select/checkbox/textbox_list fields
    // Standard objects use 'options' as array of strings (not picklistOptions)
    if (fieldData.options && ['SINGLE_OPTIONS', 'MULTIPLE_OPTIONS', 'RADIO', 'CHECKBOX', 'TEXTBOX_LIST'].includes(payload.dataType)) {
      // Ensure options is a string before splitting
      const optionsStr = typeof fieldData.options === 'string' ? fieldData.options : String(fieldData.options);
      payload.options = optionsStr.split('|').map(opt => opt.trim()).filter(opt => opt);
    }

    // Add file upload options if applicable
    if (payload.dataType === 'FILE_UPLOAD') {
      // Support both old field names and new API field names
      const acceptedFormats = fieldData.acceptedFormats || fieldData.acceptedFormat || fieldData.accepted_formats;
      const maxFileLimit = fieldData.maxFileLimit || fieldData.maxNumberOfFiles || fieldData.max_file_limit;

      if (acceptedFormats) {
        payload.acceptedFormats = acceptedFormats;
      }
      if (maxFileLimit) {
        payload.maxFileLimit = parseInt(maxFileLimit);
      }
    }

    return payload;
  } else {
    // Custom object payload format (existing)
    const fieldKey = fieldData.fieldKey || fieldData.name.toLowerCase()
      .replace(/[^a-z0-9_]/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_|_$/g, '');

    const payload = {
      locationId: locationId,
      name: fieldData.name,
      dataType: fieldData.dataType || fieldData.data_type,
      fieldKey: `custom_objects.${cleanKey}.${fieldKey}`,
      objectKey: `custom_objects.${cleanKey}`,
      parentId: folderId, // Required for custom objects
      description: fieldData.description || '',
      placeholder: fieldData.placeholder || '',
      showInForms: fieldData.show_in_forms !== 'false'
    };

    // Add options for dropdown/multi-select/checkbox/textbox_list fields
    if (fieldData.options && ['SINGLE_OPTIONS', 'MULTIPLE_OPTIONS', 'RADIO', 'CHECKBOX', 'TEXTBOX_LIST'].includes(payload.dataType)) {
      // Ensure options is a string before splitting
      const optionsStr = typeof fieldData.options === 'string' ? fieldData.options : String(fieldData.options);
      // GHL API expects options with key and label
      payload.options = optionsStr.split('|').map((opt, idx) => {
        const label = opt.trim();
        return {
          key: label.toLowerCase().replace(/[^a-z0-9]/g, '_'),
          label
        };
      }).filter(opt => opt.label);
    }

    // Add file upload options if applicable
    if (payload.dataType === 'FILE_UPLOAD') {
      // Support both old field names and new API field names
      const acceptedFormats = fieldData.acceptedFormats || fieldData.acceptedFormat || fieldData.accepted_formats;
      const maxFileLimit = fieldData.maxFileLimit || fieldData.maxNumberOfFiles || fieldData.max_file_limit;

      if (acceptedFormats) {
        payload.acceptedFormats = acceptedFormats;
      }
      if (maxFileLimit) {
        payload.maxFileLimit = parseInt(maxFileLimit);
      }
    }

    return payload;
  }
}

/**
 * Normalize field response from different API endpoints
 * @param {Object} response - The API response
 * @param {boolean} isStandard - Whether this is a standard object
 * @returns {Object} Normalized field object
 */
export function normalizeFieldResponse(response, isStandard) {
  if (isStandard) {
    // Standard object response has 'customField' wrapper
    const field = response.customField || response;
    return {
      id: field.id,
      fieldKey: field.fieldKey,
      name: field.name,
      dataType: field.dataType,
      placeholder: field.placeholder,
      model: field.model
    };
  } else {
    // Custom object response is direct
    return {
      id: response.id,
      fieldKey: response.fieldKey,
      name: response.name,
      dataType: response.dataType,
      description: response.description,
      objectKey: response.objectKey
    };
  }
}

/**
 * Get field fetch endpoint based on object type
 * @param {string} objectKey - The object key
 * @param {string} locationId - The location ID
 * @returns {Object} Endpoint and params for fetching fields
 */
export function getFieldFetchEndpoint(objectKey, locationId) {
  const cleanKey = objectKey.replace('custom_objects.', '');

  if (isStandardObject(cleanKey)) {
    return {
      url: `${API_BASE}/locations/${locationId}/customFields`,
      params: { model: cleanKey }
    };
  } else {
    return {
      url: `${API_BASE}/custom-fields/object-key/${encodeURIComponent(`custom_objects.${cleanKey}`)}`,
      params: { locationId }
    };
  }
}

/**
 * Utility to add delay for rate limiting
 * @param {number} ms - Milliseconds to delay
 * @returns {Promise} Promise that resolves after delay
 */
export function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry a function with exponential backoff on 429 rate limit errors
 * @param {Function} fn - Async function to retry
 * @param {number} maxRetries - Maximum number of retries (default: 3)
 * @param {number} baseDelay - Base delay in ms before first retry (default: 1000)
 * @returns {Promise} Result of the function
 */
export async function retryWithBackoff(fn, maxRetries = 3, baseDelay = 1000) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      const status = error?.response?.status;
      if (status === 429 && attempt < maxRetries) {
        const delayMs = baseDelay * Math.pow(2, attempt);
        console.log(`Rate limited (429), retrying in ${delayMs}ms (attempt ${attempt + 1}/${maxRetries})`);
        await delay(delayMs);
      } else {
        throw error;
      }
    }
  }
}