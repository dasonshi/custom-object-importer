// src/routes/templates.js
import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { withAccessToken, API_BASE } from '../services/tokenService.js';
import axios from 'axios';

const router = Router();

// Objects template
router.get('/objects', (req, res) => {
  const headers = ['name', 'plural', 'description', 'primary_field_name', 'primary_field_type'];
  const example = ['Product', 'Products', 'Physical products for sale', 'Product Name', 'TEXT'];
  const csv = [headers.join(','), example.join(',')].join('\n');

  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="objects-template.csv"');
  res.send(csv);
});

// Fields template
router.get('/fields/:objectKey', (req, res) => {
  const { objectKey } = req.params;
  const cleanKey = objectKey.replace(/^custom_objects\./, '');
  
  const headers = ['name', 'data_type', 'description', 'placeholder', 'show_in_forms', 'options', 'accepted_formats', 'max_file_limit', 'allow_custom_option', 'existing_folder_id'];
  
  const examples = [
    ['Product Name', 'TEXT', 'Enter the product name', 'e.g., Widget Pro 2000', 'true', '', '', '', '',''],
    ['Price', 'MONETORY', 'Product price in USD', '99.99', 'true', '', '', '', '',''],
    ['Category', 'SINGLE_OPTIONS', 'Product category', '', 'true', 'Electronics|Clothing|Home & Garden|Sports', '', '', '',''],
    ['Tags', 'MULTIPLE_OPTIONS', 'Select all that apply', '', 'true', 'New|Featured|Sale|Limited Edition', '', '', '',''],
    ['Description', 'LARGE_TEXT', 'Detailed product description', 'Enter product details...', 'true', '', '', '', '',''],
    ['SKU', 'TEXT', 'Stock keeping unit', 'ABC-123', 'true', '', '', '', '',''],
    ['In Stock', 'CHECKBOX', 'Is this product currently in stock?', '', 'true', 'Yes|No', '', '', '',''],
    ['Launch Date', 'DATE', 'Product launch date', '', 'false', '', '', '', '',''],
    ['Product Image', 'FILE_UPLOAD', 'Upload product images', '', 'true', '', '.jpg,.png', '5', '',''],
    ['Contact Email', 'EMAIL', 'Supplier contact email', 'supplier@example.com', 'false', '', '', '', '',''],
    ['Support Phone', 'PHONE', 'Customer support number', '(555) 123-4567', 'false', '', '', '', '','']
  ];

  const csvContent = [
    headers.join(','),
    ...examples.map(row => row.map(cell => 
      cell.includes(',') ? `"${cell}"` : cell
    ).join(','))
  ].join('\n');

  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${cleanKey}-fields-template.csv"`);
  res.send(csvContent);
});

// Custom values template (static - for create mode)
router.get('/custom-values', (req, res) => {
  const headers = ['name', 'value'];
  const example = ['Custom Field Name', 'Value'];
  const csv = [headers.join(','), example.join(',')].join('\n');
  
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="custom-values-template.csv"');
  res.send(csv);
});

// Dynamic custom values template (for update mode with existing values)
router.get('/custom-values/update', requireAuth, async (req, res) => {
  const locationId = req.locationId;
  
  try {
    // Fetch all existing custom values for this location
    const token = await withAccessToken(locationId);
    const response = await axios.get(`${API_BASE}/locations/${locationId}/customValues`, {
      headers: { 
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28'
      }
    });
    
    const customValues = response.data?.customValues || [];
    
    // CSV headers
    const headers = ['id', 'name', 'value'];
    
    // If no custom values exist, provide empty template with headers only
    if (customValues.length === 0) {
      const csv = [headers.join(','), ',New Custom Value,New Value'].join('\n');
      
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="custom-values-update-template.csv"');
      return res.send(csv);
    }
    
    // Build CSV rows from existing custom values
    const rows = customValues.map(cv => [
      cv.id || '',
      cv.name || '',
      cv.value || ''
    ]);
    
    // Create CSV content
    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => {
        // Escape commas and quotes in CSV
        const stringValue = String(cell || '');
        if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
          return `"${stringValue.replace(/"/g, '""')}"`;
        }
        return stringValue;
      }).join(','))
    ].join('\n');
    
    // Generate filename with timestamp
    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `custom-values-update-${timestamp}.csv`;
    
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);
    
  } catch (e) {
    console.error('Failed to generate custom values update template:', e?.response?.data || e.message);
    
    // Fallback to basic template on error
    const headers = ['id', 'name', 'value'];
    const fallback = [headers.join(','), ',Custom Value Name,Custom Value'].join('\n');
    
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="custom-values-template.csv"');
    res.send(fallback);
  }
});

// Relations template (generic - backward compatibility)
router.get('/relations', (req, res) => {
  const headers = ['association_id', 'first_record_id', 'second_record_id'];
  const examples = [
    ['assoc_123abc', 'rec_456def', 'rec_789ghi'],
    ['assoc_123abc', 'rec_111aaa', 'rec_222bbb'],
    ['assoc_xyz789', 'rec_333ccc', 'rec_444ddd']
  ];
  
  const csvContent = [
    headers.join(','),
    ...examples.map(row => row.join(','))
  ].join('\n');

  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="relations-template.csv"');
  res.send(csvContent);
});

// Dynamic relations template for specific association
router.get('/relations/:associationId', requireAuth, async (req, res) => {
  const locationId = req.locationId;
  const { associationId } = req.params;
  
  try {
    // Fetch ALL associations and find the specific one by ID
    const token = await withAccessToken(locationId);
    const associationsResponse = await axios.get(
      `${API_BASE}/associations/`,
      {
        headers: { 
          Authorization: `Bearer ${token}`,
          Version: '2021-07-28'
        },
        params: { locationId }
      }
    );
    
    // Find the specific association by ID
    const associations = Array.isArray(associationsResponse.data) 
      ? associationsResponse.data 
      : associationsResponse.data?.associations || [];
      
    const association = associations.find(assoc => assoc.id === associationId);
    
    if (!association) {
      throw new Error(`Association with ID ${associationId} not found`);
    }
    
    // Get clean object keys for column names  
    const firstObjectKey = association.firstObjectKey || 'first_object';
    const secondObjectKey = association.secondObjectKey || 'second_object';
    
    // Clean object keys for safe column names (replace dots and special chars with underscores)
    const cleanFirstKey = firstObjectKey.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    const cleanSecondKey = secondObjectKey.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    
    // Create dynamic headers using actual object keys
    const headers = [
      'association_id',
      `${cleanFirstKey}_record_id`,
      `${cleanSecondKey}_record_id`
    ];
    
    // Create example rows with object key context
    const examples = [
      [associationId, `${cleanFirstKey}_rec_123`, `${cleanSecondKey}_rec_456`],
      [associationId, `${cleanFirstKey}_rec_789`, `${cleanSecondKey}_rec_abc`],
      [associationId, `${cleanFirstKey}_rec_def`, `${cleanSecondKey}_rec_ghi`]
    ];
    
    const csvContent = [
      headers.join(','),
      ...examples.map(row => row.join(','))
    ].join('\n');
    
    // Generate descriptive filename using object keys
    const filename = `${cleanFirstKey}-${cleanSecondKey}-relations-template.csv`;
    
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);
    
  } catch (e) {
    console.error(`Failed to generate relations template for ${associationId}:`, e?.response?.data || e.message);
    
    // Fallback to generic template if association fetch fails
    const headers = ['association_id', 'first_record_id', 'second_record_id'];
    const examples = [
      [associationId, 'record_123', 'record_456'],
      [associationId, 'record_789', 'record_abc']
    ];
    
    const csvContent = [
      headers.join(','),
      ...examples.map(row => row.join(','))
    ].join('\n');
    
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="relations-template.csv"');
    res.send(csvContent);
  }
});

// Error route for fields without object key
router.get('/fields', (req, res) => {
  res.status(400).json({ 
    error: 'Object key required', 
    message: 'Please use /templates/fields/:objectKey to get a fields template for a specific object' 
  });
});

// Dynamic records template
router.get('/records/:objectKey', requireAuth, async (req, res) => {
  const locationId = req.locationId;
  let { objectKey } = req.params;

  try {
    const cleanKey = objectKey.replace(/^custom_objects\./, '');
    const apiObjectKey = `custom_objects.${cleanKey}`;
    const isUpdateMode = req.query.mode === 'update';

    const token = await withAccessToken(locationId);
    const fieldsResponse = await axios.get(`${API_BASE}/custom-fields/object-key/${encodeURIComponent(apiObjectKey)}`, {
      headers: { 
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28'
      },
      params: { locationId }
    });

    const fields = Array.isArray(fieldsResponse.data?.fields)
      ? fieldsResponse.data.fields
      : Array.isArray(fieldsResponse.data?.data?.fields)
      ? fieldsResponse.data.data.fields
      : [];

    const fieldInfo = fields
      .map((field) => {
        let key = '';
        if (field.fieldKey) {
          const parts = String(field.fieldKey).split('.');
          key = parts[parts.length - 1];
        } else {
          key = String(field.name || '')
            .toLowerCase()
            .replace(/[^a-z0-9]/g, '_') || field.id;
        }
        
        return {
          key,
          dataType: field.dataType || field.type || 'TEXT',
          name: field.name,
          options: field.options
        };
      })
      .filter(f => f.key);
    
    const fieldKeys = fieldInfo.map(f => f.key);
    
    function getSampleData(field) {
      switch (field.dataType) {
        case 'TEXT': return `Sample ${field.name}`;
        case 'LARGE_TEXT': return `This is a sample description for ${field.name}`;
        case 'NUMERICAL': return '123';
        case 'PHONE': return '(555) 123-4567';
        case 'EMAIL': return 'example@email.com';
        case 'DATE': return new Date().toISOString().split('T')[0];
        case 'MONETORY': return '99.99';
        case 'CHECKBOX': return field.options?.length > 0 ? field.options[0].label : 'Yes';
        case 'SINGLE_OPTIONS':
        case 'RADIO': return field.options?.length > 0 ? field.options[0].label : 'Option 1';
        case 'MULTIPLE_OPTIONS': return field.options?.length > 1 
          ? `${field.options[0].label}|${field.options[1].label}`
          : 'Option 1|Option 2';
        case 'TEXTBOX_LIST': return 'Item 1|Item 2|Item 3';
        case 'FILE_UPLOAD': return 'https://example.com/file.pdf';
        default: return `Sample ${field.name}`;
      }
    }
    
    const headers = isUpdateMode ? ['id', ...fieldKeys] : fieldKeys;
    const sampleRow = isUpdateMode 
      ? ['record_id_here', ...fieldInfo.map(f => getSampleData(f))]
      : fieldInfo.map(f => getSampleData(f));

    const csvContent = [
      headers.join(','), 
      sampleRow.map(cell => 
        cell.includes(',') || cell.includes('|') ? `"${cell}"` : cell
      ).join(',')
    ].join('\n');

    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${cleanKey}-${isUpdateMode ? 'update' : 'create'}-template.csv"`
    );
    res.send(csvContent);
  } catch (e) {
    console.error(`Failed to generate template for ${objectKey}:`, e?.response?.data || e.message);
    res.status(500).json({ error: 'Failed to generate records template' });
  }
});

export default router;