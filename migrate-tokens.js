// migrate-tokens.js - Migrate from file-based to database storage
import fs from 'fs/promises';
import crypto from 'crypto';
import path from 'path';
import { InstallsDB } from './database.js';
import 'dotenv/config';

// Same encryption setup as your server
const ENC_KEY = crypto.createHash('sha256')
  .update(String(process.env.APP_SECRET || 'dev-secret-change-me-in-production'))
  .digest();

const TOKENS_FILE = process.env.TOKENS_FILE || path.resolve(process.cwd(), '.tokens.json');

function decryptToken(encryptedToken) {
  const buffer = Buffer.from(encryptedToken, 'base64');
  const iv = buffer.subarray(0, 12);
  const tag = buffer.subarray(12, 28);
  const encrypted = buffer.subarray(28);
  
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

async function migrateTokens() {
  const db = new InstallsDB(ENC_KEY);
  
  try {
    console.log('🔄 Starting token migration from file to database...');
    
    // Check if .tokens.json exists
    let tokensData;
    try {
      const raw = await fs.readFile(TOKENS_FILE, 'utf8');
      tokensData = JSON.parse(raw);
    } catch (e) {
      if (e.code === 'ENOENT') {
        console.log('ℹ️  No .tokens.json file found. Nothing to migrate.');
        return;
      }
      throw e;
    }
    
    console.log(`📄 Found ${Object.keys(tokensData).length} installations to migrate`);
    
    let migrated = 0;
    let errors = 0;
    
    // Migrate each installation
    for (const [locationId, tokenData] of Object.entries(tokensData)) {
      try {
        console.log(`🔄 Migrating installation for location: ${locationId}`);
        
        // Check if tokens are encrypted (base64 with = padding) or plain text
        let accessToken, refreshToken;
        
        if (typeof tokenData.access_token === 'string' && tokenData.access_token.includes('=')) {
          // Encrypted tokens - decrypt them
          accessToken = decryptToken(tokenData.access_token);
          refreshToken = decryptToken(tokenData.refresh_token);
        } else {
          // Plain text tokens (from legacy format)
          accessToken = tokenData.access_token;
          refreshToken = tokenData.refresh_token;
        }
        
        // Store in database (will re-encrypt)
        await db.set(locationId, {
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_at: tokenData.expires_at
        });
        
        console.log(`✅ Successfully migrated installation: ${locationId}`);
        migrated++;
        
      } catch (error) {
        console.error(`❌ Error migrating installation ${locationId}:`, error.message);
        errors++;
      }
    }
    
    console.log('\n📊 Migration Summary:');
    console.log(`✅ Successfully migrated: ${migrated}`);
    console.log(`❌ Errors: ${errors}`);
    console.log(`📄 Total installations: ${Object.keys(tokensData).length}`);
    
    if (migrated > 0) {
      // Create backup of original file
      const backupName = `.tokens.json.backup.${Date.now()}`;
      await fs.copyFile(TOKENS_FILE, backupName);
      console.log(`\n💾 Original tokens backed up to: ${backupName}`);
      console.log('⚠️  You can safely delete the original .tokens.json file after verifying the migration');
    }
    
    // Verify migration
    console.log('\n🔍 Verifying migration...');
    const dbCount = await db.size();
    console.log(`📊 Database now contains ${dbCount} installations`);
    
    // Test one installation
    if (dbCount > 0) {
      const installations = await db.list();
      const testLocationId = installations[0].locationId;
      const testInstall = await db.get(testLocationId);
      
      if (testInstall && testInstall.access_token) {
        console.log('✅ Database read/decrypt test passed');
      } else {
        console.error('❌ Database read/decrypt test failed');
      }
    }
    
  } catch (error) {
    console.error('💥 Migration failed:', error);
    process.exit(1);
  } finally {
    await db.disconnect();
  }
}

// Run migration
if (process.argv[1].endsWith('migrate-tokens.js')) {
  migrateTokens().then(() => {
    console.log('\n🎉 Migration completed successfully!');
    process.exit(0);
  }).catch((error) => {
    console.error('💥 Migration failed:', error);
    process.exit(1);
  });
}