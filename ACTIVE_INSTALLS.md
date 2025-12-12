# Active Installs - Custom Object Importer

**Last Updated:** 2025-12-12

## Summary

| Metric | Count |
|--------|-------|
| Total Installs | 10 |
| Real Users (non-dev) | 9 |
| Active (last 7 days) | 6 |
| New This Week | 2 |

---

## User Directory

### 4NXbu5OPwVzBZJXx74EA
| Field | Value |
|-------|-------|
| First Seen | Dec 12, 2025 |
| Last Activity | Dec 12, 2025 |
| Request Count | 51 |
| Browser | Windows Chrome 142 |
| IP | 70.57.25.16 |
| Status | **Needs Follow-up** |

**Objects Used:**
- `custom_objects.weven_imports`
- `custom_objects.vendors`

**Issue History:**
- **Dec 12 @ 4:34 AM EST:** CSV parsing errors (`TooManyFields`) on `weven_imports` - rows had 17-18 columns when header had 16. Caused by unescaped commas in field values.
- **Dec 12 @ 4:38 AM EST:** 1,623 records failed with `Invalid key in properties first_name` on `weven_imports` - user's CSV has a `first_name` column but that field doesn't exist on the object.
- **Dec 12 @ 4:40 AM EST:** User emailed: "Seems to always get hung up at 90%. When I check the object I see imported data but not all of it."
- **Dec 12 @ 2:11 PM EST:** New import attempt on `vendors` object with new errors:
  - **Invalid picklist values:** `services_provided` field - user providing values not in allowed picklist (allowed: `accent_lighting_rental`, `audio_visual_equipment`, `dj`, `baked_goods_and_desserts`, `bartending`, `bar_trailer_or_beverage_cart`, `beverage_delivery`...)
  - **Invalid phone format:** `vendor_phone` field - phone `+9192081579` rejected (missing digits, needs full international format like `+15247XXXXXX`)

**Root Causes:**
1. Malformed CSV with unescaped commas causing rows to be skipped
2. CSV contains columns that don't exist on the target object (`first_name`)
3. Picklist values in CSV don't match allowed values defined on the field
4. Phone numbers not in valid international format

**Resolution Needed:**
1. Open CSV in Excel/Google Sheets and re-export (fixes comma escaping)
2. Match CSV columns to object fields (or add missing fields)
3. Use exact picklist values from the object definition
4. Format phone numbers as full international (e.g., `+15551234567`)

**Frontend Enhancement Needed:** Surface these GHL API validation errors clearly to user after import

---

### 77eh6Yb7UDb3RkDTFQbS
| Field | Value |
|-------|-------|
| First Seen | Dec 11, 2025 |
| Last Activity | Dec 11, 2025 |
| Request Count | 66 |
| Status | New user - monitoring |

**Notes:** New install, moderate activity on first day. No issues reported.

---

### f5gtkYApXptSz4A6sHUR
| Field | Value |
|-------|-------|
| First Seen | Dec 9, 2025 |
| Last Activity | Dec 11, 2025 |
| Request Count | 203 |
| Status | Active - healthy |

**Notes:** High engagement user. 203 requests over 3 days indicates active usage. No issues reported.

---

### YcTMZv0tRv2yF4Jsyc3m
| Field | Value |
|-------|-------|
| First Seen | Dec 8, 2025 |
| Last Activity | Dec 10, 2025 |
| Request Count | 24 |
| Status | Active - light usage |

**Notes:** Light but consistent usage over 3 days.

---

### r3iSJSDlWKdBeTbxzq15
| Field | Value |
|-------|-------|
| First Seen | Dec 8, 2025 |
| Last Activity | Dec 8, 2025 |
| Request Count | 19 |
| Status | Inactive - one-day user |

**Notes:** Only active on install day. May have been evaluating the app.

---

### j6Lo4zmR1bLqAZKa4qA4
| Field | Value |
|-------|-------|
| First Seen | Dec 3, 2025 |
| Last Activity | Dec 9, 2025 |
| Request Count | 32 |
| Status | Active - light usage |

**Notes:** Spread out usage over a week. Returning user.

---

### 8M1NSZzckY7M2KH4YD54
| Field | Value |
|-------|-------|
| First Seen | Nov 26, 2025 |
| Last Activity | Nov 26, 2025 |
| Request Count | 12 |
| Status | Churned - one-day user |

**Notes:** Only active on install day. Likely evaluated and didn't continue.

---

### 2VuOfM265RvlOoxkQkpI
| Field | Value |
|-------|-------|
| First Seen | Nov 24, 2025 |
| Last Activity | Dec 8, 2025 |
| Request Count | 34 |
| Status | Active - light usage |

**Notes:** Long-term user (2+ weeks) with light but continued usage.

---

### QjrnkYkApsr3Pw9D6Xkl
| Field | Value |
|-------|-------|
| First Seen | Nov 22, 2025 |
| Last Activity | Nov 27, 2025 |
| Request Count | 168 |
| Status | Churned - was active |

**Notes:** High engagement (168 requests) but inactive since Nov 27. Was one of the earliest real users.

---

### gdzneuvA9mUJoRroCv4O (Dev Account)
| Field | Value |
|-------|-------|
| First Seen | Nov 21, 2025 |
| Last Activity | Dec 12, 2025 |
| Request Count | 511 |
| Status | Dev/Test Account |

**Notes:** Primary development and testing account. High request count is from testing.

---

## Known Issues & Fixes

### Windows 401 Auth Errors
- **Affected:** Multiple Windows users with Chrome 119 (outdated browser)
- **Cause:** Third-party cookies blocked in iframe, postMessage not receiving locationId
- **Fix Deployed:** Dec 11 - Enhanced postMessage handling + alternative locationId extraction
- **Status:** Monitoring - recent Windows users showing success

### CSV Parsing Errors (TooManyFields)
- **Affected:** Location `4NXbu5OPwVzBZJXx74EA`
- **Cause:** CSV fields containing commas not wrapped in quotes
- **Fix Deployed:** Dec 11 - Frontend validation to detect and block malformed CSVs before upload
- **Status:** User may have cached old frontend - need to verify fix is working

### Invalid Field Errors
- **Affected:** Location `4NXbu5OPwVzBZJXx74EA`
- **Cause:** CSV contains columns that don't exist on target object
- **Fix:** User education - need to match CSV columns to object fields
- **Potential Enhancement:** Pre-validate CSV columns against object schema before import

### Data Validation Errors (Picklist, Phone, etc.)
- **Affected:** Location `4NXbu5OPwVzBZJXx74EA`
- **Cause:** GHL API rejects records with invalid values:
  - Picklist fields: Value not in allowed options
  - Phone fields: Invalid international format
  - Other field type validations
- **Current Behavior:** Errors logged server-side, but user only sees partial import success
- **Fix Needed:** Surface per-record errors on frontend after import completes
- **Status:** Enhancement pending

---

## Refresh Instructions

To update this file with latest Axiom data:

```bash
axiom query "['custom-object-importer'] | where message contains 'locationId=' | where application == 'http-request' | limit 5000" --format=json > /tmp/axiom_locations.json
```

Then analyze the JSON to extract:
- New location IDs
- Request counts
- First/last activity dates
- Any error patterns
