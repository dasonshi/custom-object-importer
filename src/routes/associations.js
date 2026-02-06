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
    const response = await axios.get(`${API_BASE}/associations/`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Version: '2021-07-28'
      },
      params: { locationId, skip: 0, limit: 100 }
    });

    const associations = response.data?.associations || response.data || [];

    // Helper to get clean object name from key (e.g., "custom_objects.car" -> "Car")
    const getObjectName = (key) => {
      if (!key) return 'Unknown';
      const cleanKey = key.replace(/^custom_objects\./, '');
      return cleanKey.charAt(0).toUpperCase() + cleanKey.slice(1);
    };

    // Log raw response to understand structure
    console.log('Raw GHL associations response:', JSON.stringify(associations.slice(0, 3), null, 2));

    res.json({
      associations: [
        CONTACT_BUSINESS_ASSOCIATION,  // Always include Contact-Business first
        ...associations.map(assoc => {
          // Use GHL's labels if available, otherwise derive from object keys
          const firstName = assoc.firstObjectLabel || getObjectName(assoc.firstObjectKey);
          const secondName = assoc.secondObjectLabel || getObjectName(assoc.secondObjectKey);
          // For description, show both the label AND the object type if they differ
          const firstObjName = getObjectName(assoc.firstObjectKey);
          const secondObjName = getObjectName(assoc.secondObjectKey);
          const description = (firstName !== firstObjName || secondName !== secondObjName)
            ? `${firstName} (${firstObjName}) → ${secondName} (${secondObjName})`
            : `${firstName} → ${secondName}`;

          return {
            id: assoc.id,
            key: assoc.key,
            firstObjectKey: assoc.firstObjectKey,
            firstObjectLabel: firstName,
            secondObjectKey: assoc.secondObjectKey,
            secondObjectLabel: secondName,
            description
          };
        })
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