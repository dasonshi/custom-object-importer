// src/routes/associations.js
import { Router } from 'express';
import axios from 'axios';
import { requireAuth, validateTenant } from '../middleware/auth.js';
import { withAccessToken, API_BASE } from '../services/tokenService.js';
import { handleAPIError } from '../utils/apiHelpers.js';

const router = Router();

// Hardcoded Contact-Business association (native GHL relationship)
// GHL Associations API only returns Custom Objects associations (USER_DEFINED),
// not native relationships like Contact-Business
const CONTACT_BUSINESS_ASSOCIATION = {
  id: 'contact-business-native',
  key: 'contact-business',
  firstObjectKey: 'contact',
  firstObjectLabel: 'Contact',
  secondObjectKey: 'business',
  secondObjectLabel: 'Business',
  description: 'Contact → Business (Native)',
  isNative: true
};

router.get('/', requireAuth, validateTenant, async (req, res) => {
  const locationId = req.locationId;

  try {
    const token = await withAccessToken(locationId);
    const response = await axios.get(`${API_BASE}/associations`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28'
      },
      params: { locationId, skip: 0, limit: 100 }
    });

    console.log('[Associations] GHL response:', JSON.stringify(response.data, null, 2));
    const associations = response.data?.associations || response.data || [];
    console.log(`[Associations] Found ${associations.length} custom associations`);

    res.json({
      associations: [
        CONTACT_BUSINESS_ASSOCIATION,  // Always include Contact-Business first
        ...associations.map(assoc => ({
          id: assoc.id,
          key: assoc.key,
          firstObjectKey: assoc.firstObjectKey,
          firstObjectLabel: assoc.firstObjectLabel,
          secondObjectKey: assoc.secondObjectKey,
          secondObjectLabel: assoc.secondObjectLabel,
          description: `${assoc.firstObjectLabel} → ${assoc.secondObjectLabel}`
        }))
      ]
    });
  } catch (e) {
    if (e?.response?.status === 404) {
      // Even on error, return the Contact-Business option
      res.json({ associations: [CONTACT_BUSINESS_ASSOCIATION] });
    } else {
      handleAPIError(res, e, 'Fetch associations');
    }
  }
});

export default router;