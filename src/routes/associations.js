// src/routes/associations.js
import { Router } from 'express';
import axios from 'axios';
import { requireAuth, handleLocationOverride } from '../middleware/auth.js';
import { withAccessToken, API_BASE } from '../services/tokenService.js';
import { handleAPIError } from '../utils/apiHelpers.js';

const router = Router();

router.get('/', requireAuth, handleLocationOverride, async (req, res) => {
  const locationId = req.locationId;
  
  try {
    const token = await withAccessToken(locationId);
    const response = await axios.get(`${API_BASE}/associations`, {
      headers: { 
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28'
      },
      params: { locationId }
    });
    
    const associations = response.data?.associations || response.data || [];
    
    res.json({
      associations: associations.map(assoc => ({
        id: assoc.id,
        key: assoc.key,
        firstObjectKey: assoc.firstObjectKey,
        firstObjectLabel: assoc.firstObjectLabel,
        secondObjectKey: assoc.secondObjectKey,
        secondObjectLabel: assoc.secondObjectLabel,
        description: `${assoc.firstObjectLabel} → ${assoc.secondObjectLabel}`
      }))
    });
  } catch (e) {
    if (e?.response?.status === 404) {
      res.json({ associations: [] });
    } else {
      handleAPIError(res, e, 'Fetch associations');
    }
  }
});

export default router;