// src/routes/customValues.js
import { Router } from 'express';
import axios from 'axios';
import { requireAuth, handleLocationOverride } from '../middleware/auth.js';
import { withAccessToken, API_BASE } from '../services/tokenService.js';

const router = Router();

router.get('/', requireAuth, handleLocationOverride, async (req, res) => {
  const locationId = req.locationId;
  
  try {
    const token = await withAccessToken(locationId);
    const response = await axios.get(`${API_BASE}/locations/${locationId}/customValues`, {
      headers: { 
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28'
      }
    });
    res.json(response.data);
  } catch (e) {
    console.error('Custom values fetch error:', e?.response?.data || e.message);
    res.status(500).json({ 
      error: 'Failed to fetch custom values', 
      details: e?.response?.data || e.message 
    });
  }
});

// Get custom values folders - attempts to use custom fields API for folder structure
router.get('/folders', requireAuth, handleLocationOverride, async (req, res) => {
  const locationId = req.locationId;
  
  try {
    const token = await withAccessToken(locationId);
    
    // Try to get folders from custom fields API for locations
    // This might not exist for custom values, but attempting based on user request
    const response = await axios.get(`${API_BASE}/custom-fields/object-key/locations`, {
      headers: { 
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28'
      },
      params: { locationId }
    });
    
    // Extract just the folders
    const folders = response.data?.folders || [];
    res.json({ folders });
    
  } catch (e) {
    console.error('Custom values folders fetch error:', e?.response?.data || e.message);
    
    // If the API doesn't support folders for custom values, return empty array
    if (e?.response?.status === 404 || e?.response?.status === 400) {
      res.json({ 
        folders: [],
        message: 'Custom values folders not supported or not found'
      });
    } else {
      res.status(500).json({ 
        error: 'Failed to fetch custom values folders', 
        details: e?.response?.data || e.message 
      });
    }
  }
});

export default router;