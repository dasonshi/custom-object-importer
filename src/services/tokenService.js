// src/services/tokenService.js
import axios from 'axios';
import { installs } from '../middleware/auth.js';

const API_BASE = 'https://services.leadconnectorhq.com';

// Token refresh configuration
const TOKEN_REFRESH_BUFFER_MS = 5 * 60 * 1000; // 5 minutes before expiry
const MAX_RETRY_ATTEMPTS = 3;
const INITIAL_RETRY_DELAY_MS = 1000; // 1 second
const MAX_RETRY_DELAY_MS = 30000; // 30 seconds
const TOKEN_ROTATION_GRACE_PERIOD_MS = 60 * 60 * 1000; // 1 hour grace period for old tokens

// Helper function to delay execution
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Helper function to check if error is retryable
const isRetryableError = (error) => {
  const status = error?.response?.status;
  const errorCode = error?.response?.data?.error;
  const errorMessage = error?.response?.data?.message || error?.message || '';

  // Network errors are retryable
  if (!error.response) {
    console.log('🔄 Network error detected - will retry');
    return true;
  }

  // Rate limit errors are retryable
  if (status === 429) {
    console.log('⏳ Rate limited - will retry after delay');
    return true;
  }

  // Temporary server errors are retryable
  if (status >= 500 && status < 600) {
    console.log('🔧 Server error detected - will retry');
    return true;
  }

  // Some 401 errors might be temporary
  if (status === 401 && errorMessage.toLowerCase().includes('temporarily')) {
    console.log('⏱️ Temporary auth issue - will retry');
    return true;
  }

  // invalid_grant is NOT retryable - token is permanently invalid
  if (errorCode === 'invalid_grant') {
    console.log('❌ Permanent token failure (invalid_grant) - will not retry');
    return false;
  }

  // invalid_client is NOT retryable - credentials are wrong
  if (errorCode === 'invalid_client') {
    console.log('❌ Invalid client credentials - will not retry');
    return false;
  }

  // Default to not retrying for unknown errors
  return false;
};

// Function to refresh token with retry logic
async function refreshTokenWithRetry(locationId, install, attempt = 1) {
  try {
    console.log(`🔄 Token refresh attempt ${attempt}/${MAX_RETRY_ATTEMPTS} for ${locationId}`);

    const refreshBody = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: install.refresh_token,
      client_id: process.env.GHL_CLIENT_ID,
      client_secret: process.env.GHL_CLIENT_SECRET
    });

    const refreshResponse = await axios.post(`${API_BASE}/oauth/token`, refreshBody, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 30000 // 30 second timeout
    });

    console.log(`✅ Token refresh successful on attempt ${attempt} for ${locationId}`);
    return refreshResponse.data;

  } catch (error) {
    const isRetryable = isRetryableError(error);

    console.error(`❌ Token refresh attempt ${attempt} failed for ${locationId}:`, {
      status: error?.response?.status,
      error: error?.response?.data?.error,
      message: error?.response?.data?.message || error.message,
      retryable: isRetryable
    });

    // If not retryable or max attempts reached, throw the error
    if (!isRetryable || attempt >= MAX_RETRY_ATTEMPTS) {
      throw error;
    }

    // Calculate exponential backoff delay
    const retryDelay = Math.min(
      INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt - 1),
      MAX_RETRY_DELAY_MS
    );

    console.log(`⏳ Retrying in ${retryDelay}ms...`);
    await delay(retryDelay);

    // Retry with incremented attempt count
    return refreshTokenWithRetry(locationId, install, attempt + 1);
  }
}

export async function withAccessToken(locationId) {
  const install = await installs.get(locationId);
  if (!install) throw new Error(`No installation found for locationId: ${locationId}`);

  // Set the access token for this request (if ghl SDK is being used)
  if (global.ghl && typeof global.ghl.setAccessToken === 'function') {
    global.ghl.setAccessToken(install.access_token, locationId);
  }

  // Check if token needs refresh (5 minutes before expiry)
  const tokenExpiryTime = install.expires_at ?? 0;
  const timeUntilExpiry = tokenExpiryTime - Date.now();

  if (timeUntilExpiry < TOKEN_REFRESH_BUFFER_MS) {
    console.log(`🔔 Token expiring in ${Math.floor(timeUntilExpiry / 1000)}s for ${locationId}, refreshing...`);

    try {
      // Attempt refresh with retry logic
      const refreshed = await refreshTokenWithRetry(locationId, install);

      const updatedInstall = {
        access_token: refreshed.access_token,
        refresh_token: refreshed.refresh_token || install.refresh_token,
        expires_at: Date.now() + ((refreshed.expires_in ?? 3600) * 1000) - 60_000,
        // Store old tokens for grace period (token rotation)
        previous_refresh_token: install.refresh_token,
        previous_refresh_token_expires: Date.now() + TOKEN_ROTATION_GRACE_PERIOD_MS
      };

      // If install has other properties (like userType, companyId), preserve them
      if (install.userType) updatedInstall.userType = install.userType;
      if (install.companyId) updatedInstall.companyId = install.companyId;
      if (install.isBulkInstallation) updatedInstall.isBulkInstallation = install.isBulkInstallation;

      await installs.set(locationId, updatedInstall);
      console.log(`✅ Token refreshed and saved successfully for ${locationId}`);

      if (global.ghl && typeof global.ghl.setAccessToken === 'function') {
        global.ghl.setAccessToken(refreshed.access_token, locationId);
      }

      return refreshed.access_token;

    } catch (refreshError) {
      console.error(`❌ All token refresh attempts failed for ${locationId}:`, refreshError?.response?.data || refreshError.message);

      // Check if we have a previous refresh token within grace period
      if (install.previous_refresh_token &&
          install.previous_refresh_token_expires &&
          Date.now() < install.previous_refresh_token_expires) {

        console.log('🔄 Attempting to use previous refresh token within grace period...');

        try {
          // Try with the previous refresh token
          const tempInstall = { ...install, refresh_token: install.previous_refresh_token };
          const refreshed = await refreshTokenWithRetry(locationId, tempInstall, 1);

          const updatedInstall = {
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token || install.previous_refresh_token,
            expires_at: Date.now() + ((refreshed.expires_in ?? 3600) * 1000) - 60_000
          };

          // Preserve other properties
          if (install.userType) updatedInstall.userType = install.userType;
          if (install.companyId) updatedInstall.companyId = install.companyId;
          if (install.isBulkInstallation) updatedInstall.isBulkInstallation = install.isBulkInstallation;

          await installs.set(locationId, updatedInstall);
          console.log(`✅ Successfully refreshed using previous token for ${locationId}`);

          if (global.ghl && typeof global.ghl.setAccessToken === 'function') {
            global.ghl.setAccessToken(refreshed.access_token, locationId);
          }

          return refreshed.access_token;

        } catch (fallbackError) {
          console.error('❌ Previous refresh token also failed:', fallbackError?.response?.data || fallbackError.message);
        }
      }

      // Only clear installation for permanent failures
      if (refreshError?.response?.data?.error === 'invalid_grant' ||
          refreshError?.response?.data?.error === 'invalid_client') {
        console.log(`🗑️ Clearing permanently invalid installation for ${locationId}`);
        await installs.delete(locationId);
        throw new Error('Authentication expired - please reconnect your account');
      }

      // For other errors, throw but don't delete the installation
      throw new Error(`Failed to refresh access token: ${refreshError?.response?.data?.message || refreshError.message}`);
    }
  }

  return install.access_token;
}

// Helper function that was using withAccessToken
export async function callGHLAPI(locationId, apiFunction) {
  await withAccessToken(locationId);
  return await apiFunction();
}

export { API_BASE };