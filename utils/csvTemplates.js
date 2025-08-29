// utils/csvTemplates.js
import Papa from 'papaparse';

export const CSV_TEMPLATES = {
  objects: {
    headers: ['object_key', 'display_label', 'description', 'primary_display_field', 'icon'],
    example: [
      {
        object_key: 'customers',
        display_label: 'Customers',
        description: 'Customer database with contact info',
        primary_display_field: 'name',
        icon: 'user'
      },
      {
        object_key: 'products',
        display_label: 'Products',
        description: 'Product catalog with pricing',
        primary_display_field: 'title',
        icon: 'package'
      }
    ]
  },
  
  fields: {
    headers: ['object_key', 'field_key', 'display_label', 'type', 'required', 'help_text', 'default_value', 'unique', 'options'],
    example: [
      {
        object_key: 'customers',
        field_key: 'name',
        display_label: 'Full Name',
        type: 'text',
        required: 'true',
        help_text: 'Customer full name',
        default_value: '',
        unique: 'false',
        options: ''
      },
      {
        object_key: 'customers',
        field_key: 'email',
        display_label: 'Email Address',
        type: 'email',
        required: 'true',
        help_text: 'Primary email contact',
        default_value: '',
        unique: 'true',
        options: ''
      },
      {
        object_key: 'customers',
        field_key: 'status',
        display_label: 'Status',
        type: 'select',
        required: 'false',
        help_text: 'Customer status',
        default_value: 'active',
        unique: 'false',
        options: 'active|inactive|prospect|churned'
      },
      {
        object_key: 'products',
        field_key: 'title',
        display_label: 'Product Title',
        type: 'text',
        required: 'true',
        help_text: 'Product name',
        default_value: '',
        unique: 'false',
        options: ''
      },
      {
        object_key: 'products',
        field_key: 'price',
        display_label: 'Price',
        type: 'number',
        required: 'true',
        help_text: 'Product price in USD',
        default_value: '0',
        unique: 'false',
        options: ''
      }
    ]
  },
  
  records: {
    headers: ['object_key', 'external_id', 'name', 'email', 'status'],
    example: [
      {
        object_key: 'customers',
        external_id: 'cust_001',
        name: 'John Doe',
        email: 'john.doe@example.com',
        status: 'active'
      },
      {
        object_key: 'customers',
        external_id: 'cust_002',
        name: 'Jane Smith',
        email: 'jane.smith@example.com',
        status: 'prospect'
      }
    ]
  }
};

export const FIELD_TYPES = [
  'text',
  'textarea',
  'number',
  'email',
  'phone',
  'url',
  'date',
  'datetime',
  'boolean',
  'select',
  'multiselect',
  'currency',
  'percentage'
];

export function generateCSVContent(templateType) {
  const template = CSV_TEMPLATES[templateType];
  if (!template) {
    throw new Error(`Unknown template type: ${templateType}`);
  }
  
  return Papa.unparse(template.example);
}

export function generateEmptyCSVTemplate(templateType) {
  const template = CSV_TEMPLATES[templateType];
  if (!template) {
    throw new Error(`Unknown template type: ${templateType}`);
  }
  
  // Create empty row with headers
  const emptyRow = {};
  template.headers.forEach(header => {
    emptyRow[header] = '';
  });
  
  return Papa.unparse([emptyRow]);
}

export function validateCSVStructure(csvData, templateType) {
  const template = CSV_TEMPLATES[templateType];
  const errors = [];
  const warnings = [];
  
  if (!csvData || csvData.length === 0) {
    errors.push('CSV is empty');
    return { valid: false, errors, warnings };
  }
  
  const headers = Object.keys(csvData[0]);
  const requiredHeaders = template.headers;
  
  // Check for required headers
  const missingHeaders = requiredHeaders.filter(h => !headers.includes(h));
  if (missingHeaders.length > 0) {
    errors.push(`Missing required headers: ${missingHeaders.join(', ')}`);
  }
  
  // Check for unknown headers (warnings only)
  const unknownHeaders = headers.filter(h => !requiredHeaders.includes(h));
  if (unknownHeaders.length > 0) {
    warnings.push(`Unknown headers (will be ignored): ${unknownHeaders.join(', ')}`);
  }
  
  // Validate data types and required fields
  csvData.forEach((row, index) => {
    if (templateType === 'objects') {
      if (!row.object_key) {
        errors.push(`Row ${index + 1}: object_key is required`);
      }
    } else if (templateType === 'fields') {
      if (!row.object_key) {
        errors.push(`Row ${index + 1}: object_key is required`);
      }
      if (!row.field_key) {
        errors.push(`Row ${index + 1}: field_key is required`);
      }
      if (row.type && !FIELD_TYPES.includes(row.type)) {
        warnings.push(`Row ${index + 1}: unknown field type '${row.type}'. Valid types: ${FIELD_TYPES.join(', ')}`);
      }
      if ((row.type === 'select' || row.type === 'multiselect') && !row.options) {
        warnings.push(`Row ${index + 1}: select/multiselect fields should have options defined`);
      }
    } else if (templateType === 'records') {
      if (!row.object_key) {
        errors.push(`Row ${index + 1}: object_key is required`);
      }
      if (!row.external_id) {
        warnings.push(`Row ${index + 1}: external_id recommended for record updates`);
      }
    }
  });
  
  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}