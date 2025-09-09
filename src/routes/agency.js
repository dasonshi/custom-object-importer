// src/routes/agency.js
import { Router } from 'express';
import axios from 'axios';
import { requireAuth } from '../middleware/auth.js';
import { installs } from '../middleware/auth.js';
import { API_BASE } from '../services/tokenService.js';

const router = Router();

router.get('/agency-branding', requireAuth, async (req, res) => {
  const locationId = req.locationId;
  
  try {
    const install = await installs.get(locationId);
    const locationResponse = await axios.get(
      `${API_BASE}/locations/${locationId}`,
      {
        headers: {
          'Authorization': `Bearer ${install.access_token}`,
          'Version': '2021-07-28',
          'Accept': 'application/json'
        },
      }
    );

    const location = locationResponse.data.location || locationResponse.data;
    
    const branding = {
      companyName: location.companyName || location.name || 'HighLevel',
      logoUrl: location.logo || location.logoUrl || null,
      website: location.website || null,
      locationName: location.name || null,
      email: location.email || null,
      phone: location.phone || null,
      address: location.address || null,
      city: location.city || null,
      state: location.state || null,
      country: location.country || null,
      postalCode: location.postalCode || null,
      timezone: location.timezone || null,
      primaryColor: '#6366f1',
      secondaryColor: '#f3f4f6'
    };

    res.json(branding);

  } catch (e) {
    console.error('Agency branding fetch error:', e?.response?.data || e.message);
    res.json({
      companyName: 'HighLevel',
      logoUrl: null,
      website: null,
      primaryColor: '#6366f1',
      secondaryColor: '#f3f4f6',
      locationName: null,
      timezone: null,
      country: null
    });
  }
});

export default router;