// src/services/tokenService.js
import axios from 'axios';
import { installs } from '../middleware/auth.js';

const API_BASE = 'https://services.leadconnectorhq.com';

export async function withAccessToken(locationId) {
  const install = await installs.get(locationId);
  if (!install) throw new Error(`No installation found for locationId: ${locationId}`);
  
  // Set the access token for this request (if ghl SDK is being used)
  if (global.ghl && typeof global.ghl.setAccessToken === 'function') {
    global.ghl.setAccessToken(install.access_token, locationId);
  }
  
  // Check if token needs refresh
  if (Date.now() > (install.expires_at ?? 0) - 30_000) {
    console.log(`Token expired for ${locationId}, attempting refresh...`);
    try {
      const refreshBody = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: install.refresh_token,
        client_id: process.env.GHL_CLIENT_ID,
        client_secret: process.env.GHL_CLIENT_SECRET
      });
      
      const refreshResponse = await axios.post(`${API_BASE}/oauth/token`, refreshBody, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      
      const refreshed = refreshResponse.data;
        
      const updatedInstall = {
        access_token: refreshed.access_token,
        refresh_token: refreshed.refresh_token || install.refresh_token,
        expires_at: Date.now() + ((refreshed.expires_in ?? 3600) * 1000) - 60_000
      };
      
      await installs.set(locationId, updatedInstall);
      console.log(`Token refreshed successfully for ${locationId}`);
      
      if (global.ghl && typeof global.ghl.setAccessToken === 'function') {
        global.ghl.setAccessToken(refreshed.access_token, locationId);
      }
      
      return refreshed.access_token;
    } catch (e) {
      console.error(`Token refresh failed for ${locationId}:`, e?.response?.data || e.message);

      // If refresh fails with invalid_grant, the installation is likely stale
      // Clear it so the user can reinstall
      if (e?.response?.data?.error === 'invalid_grant') {
        console.log(`Clearing stale installation for ${locationId}`);
        await installs.delete(locationId);
      }

      throw new Error('Failed to refresh access token');
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