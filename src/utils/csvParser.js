// src/utils/csvParser.js
import fs from 'fs/promises';
import Papa from 'papaparse';

export async function parseCSV(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const result = Papa.parse(content, {
      header: true,
      skipEmptyLines: true,
      trim: true,
      dynamicTyping: false,
      transformHeader: (header) => String(header || '').trim().toLowerCase().replace(/\s+/g, '_'),
      transform: (v) => (typeof v === 'string' ? v.trim() : v),
      complete: (results) => {
        if (results.errors.length > 0) {
          console.warn(`CSV parsing warnings for ${filePath}:`, results.errors);
        }
      }
    });
    
    if (result.errors.length > 0) {
      const criticalErrors = result.errors.filter(err => err.type === 'Delimiter');
      if (criticalErrors.length > 0) {
        throw new Error(`Critical CSV parsing errors: ${criticalErrors.map(e => e.message).join(', ')}`);
      }
    }
    
    return result.data;
  } catch (error) {
    console.error(`Failed to parse CSV file ${filePath}:`, error.message);
    throw new Error(`CSV parsing failed: ${error.message}`);
  }
}

export async function cleanupTempFiles(filePaths) {
  for (const path of filePaths.filter(Boolean)) {
    try {
      await fs.unlink(path);
    } catch (e) {
      console.warn(`Failed to clean up temp file ${path}:`, e.message);
    }
  }
}