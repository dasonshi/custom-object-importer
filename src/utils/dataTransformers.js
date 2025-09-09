// src/utils/dataTransformers.js

export function normalizeDataType(input) {
  const t = String(input || 'TEXT').toLowerCase();
  const map = {
    text: 'TEXT',
    textarea: 'LARGE_TEXT', large_text: 'LARGE_TEXT',
    number: 'NUMERICAL', numerical: 'NUMERICAL',
    phone: 'PHONE',
    email: 'EMAIL',
    date: 'DATE',
    money: 'MONETORY', monetary: 'MONETORY', currency: 'MONETORY',
    checkbox: 'CHECKBOX',
    select: 'SINGLE_OPTIONS', single: 'SINGLE_OPTIONS', single_options: 'SINGLE_OPTIONS',
    multiselect: 'MULTIPLE_OPTIONS', multiple: 'MULTIPLE_OPTIONS', multiple_options: 'MULTIPLE_OPTIONS',
    textbox_list: 'TEXTBOX_LIST',
    file: 'FILE_UPLOAD', file_upload: 'FILE_UPLOAD',
    radio: 'RADIO'
  };
  return map[t] || String(input).toUpperCase();
}

export function parseOptions(raw) {
  if (!raw) return undefined;
  try {
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) {
      return arr.map(o => (typeof o === 'string' ? { key: o.toLowerCase().replace(/\s+/g,'_'), label: o } : o));
    }
  } catch {}
  return String(raw).split('|').map(s => s.trim()).filter(Boolean)
    .map(label => ({ key: label.toLowerCase().replace(/\s+/g,'_'), label }));
}

export function asBool(v, fallback=false) {
  if (v === undefined || v === null || v === '') return fallback;
  return String(v).toLowerCase() === 'true';
}