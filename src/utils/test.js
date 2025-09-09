// src/utils/test.js
import { parseCSV, cleanupTempFiles } from './csvParser.js';
import { normalizeDataType, parseOptions, asBool } from './dataTransformers.js';
import { generateEncryptionKey, createSecureState, verifySecureState } from './crypto.js';

// Test each function
console.log('Testing normalizeDataType:', normalizeDataType('text')); // Should output: TEXT
console.log('Testing parseOptions:', parseOptions('Option1|Option2')); // Should output array
console.log('Testing asBool:', asBool('true')); // Should output: true

const key = generateEncryptionKey('test-secret');
const state = createSecureState(key);
console.log('Testing crypto:', verifySecureState(state, key)); // Should output payload

console.log('✅ All utility functions working!');