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

export default router;