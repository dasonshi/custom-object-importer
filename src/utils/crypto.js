// src/utils/crypto.js
import crypto from 'crypto';

// Generate encryption key from APP_SECRET
export function generateEncryptionKey(appSecret) {
  return crypto.createHash('sha256')
    .update(String(appSecret || 'dev-secret-change-me-in-production'))
    .digest();
}

export function createSecureState(encKey) {
  const payload = {
    timestamp: Date.now(),
    nonce: crypto.randomBytes(16).toString('hex')
  };
  
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', encKey).update(data).digest('base64url');
  
  return `${data}.${signature}`;
}

export function verifySecureState(state, encKey) {
  if (!state || typeof state !== 'string') {
    throw new Error('Missing or invalid state parameter');
  }
  
  const parts = state.split('.');
  if (parts.length !== 2) {
    throw new Error('Invalid state format');
  }
  
  const [data, signature] = parts;
  
  // Verify signature
  const expectedSignature = crypto.createHmac('sha256', encKey).update(data).digest('base64url');
  if (signature !== expectedSignature) {
    throw new Error('Invalid state signature');
  }
  
  // Parse and validate payload
  let payload;
  try {
    payload = JSON.parse(Buffer.from(data, 'base64url').toString());
  } catch (e) {
    throw new Error('Invalid state payload');
  }
  
  // Check expiration (10 minutes)
  const age = Date.now() - payload.timestamp;
  const MAX_AGE = 10 * 60 * 1000; // 10 minutes
  
  if (age > MAX_AGE) {
    throw new Error('State parameter expired');
  }
  
  if (age < 0) {
    throw new Error('State parameter from future');
  }
  
  return payload;
}

export function validateEncryptionSetup() {
  if (process.env.NODE_ENV === 'production') {
    if (!process.env.APP_SECRET || process.env.APP_SECRET === 'dev-secret-change-me-in-production') {
      console.error('⚠ APP_SECRET must be set to a secure random value in production!');
      process.exit(1);
    }
    if (process.env.APP_SECRET.length < 32) {
      console.error('⚠ APP_SECRET should be at least 32 characters long for security');
      process.exit(1);
    }
  }
}

// Validate GHL webhook signature
export function validateWebhookSignature(payload, signature, secret) {
  if (!signature) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(JSON.stringify(payload))
    .digest('hex');

  // Use timing-safe comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}