// src/routes/associations.js
import { Router } from 'express';
import axios from 'axios';
import { requireAuth, validateTenant } from '../middleware/auth.js';
import { withAccessToken, API_BASE } from '../services/tokenService.js';
import { handleAPIError } from '../utils/apiHelpers.js';

const router = Router();

// Helper to get clean object name from key (e.g., "custom_objects.car" -> "Car")
const getObjectName = (key) => {
  if (!key) return 'Unknown';
  const cleanKey = key.replace(/^custom_objects\./, '');
  // Handle special cases
  if (cleanKey === 'contact') return 'Contact';
  if (cleanKey === 'business') return 'Business';
  if (cleanKey === 'opportunity') return 'Opportunity';
  // Capitalize first letter for custom objects
  return cleanKey.charAt(0).toUpperCase() + cleanKey.slice(1);
};

// Helper to format association key into readable name
const formatAssociationKey = (key) => {
  if (!key) return '';
  // Convert snake_case or SCREAMING_SNAKE to Title Case
  return key
    .toLowerCase()
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
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

    res.json({
      associations: associations.map(assoc => {
        const firstObjName = getObjectName(assoc.firstObjectKey);
        const secondObjName = getObjectName(assoc.secondObjectKey);

        // Build description based on association type
        let description;
        if (assoc.associationType === 'SYSTEM_DEFINED') {
          // For system associations, just show clean object names
          description = `${firstObjName} → ${secondObjName}`;
        } else {
          // For user-defined, include the relationship name if meaningful
          const relationName = formatAssociationKey(assoc.key);
          description = relationName
            ? `${relationName}: ${firstObjName} → ${secondObjName}`
            : `${firstObjName} → ${secondObjName}`;
        }

        return {
          id: assoc.id,
          key: assoc.key,
          firstObjectKey: assoc.firstObjectKey,
          firstObjectLabel: firstObjName,
          secondObjectKey: assoc.secondObjectKey,
          secondObjectLabel: secondObjName,
          associationType: assoc.associationType,
          description
        };
      })
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