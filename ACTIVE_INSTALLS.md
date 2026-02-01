# Active Installs - Custom Object Importer

**Last Updated:** 2026-01-08

## Summary

| Metric | Count |
|--------|-------|
| Total Installs | 17 |
| Real Users (non-dev) | 16 |
| Active (last 7 days) | 2 |
| New This Week | 1 |

### Activity Summary (Jan 8, 2026)
- **NEW INSTALL! 🎉** First install since Dec 26
  - OAuth completed at 2:29 PM UTC (9:29 AM EST) from IP 207.231.41.241
  - User hasn't opened the app yet - no locationId identified
- **Returning users (2 active today):**
  - `YcTMZv0tRv2yF4Jsyc3m` - came back after 1 month! 19 requests, healthy (major retention win!)
  - `ORAR6TYKTK091V2KxxCL` - 11 requests, consistent usage
- **DB Total:** 37+ installations

---

## User Directory

### NEW INSTALL - Jan 8, 2026 (Location ID Unknown)
| Field | Value |
|-------|-------|
| Install Date | Jan 8, 2026 @ 2:29 PM UTC (9:29 AM EST) |
| IP | 207.231.41.241 |
| Status | OAuth completed - awaiting first use |

**Notes:** OAuth callback successful (302 redirect). User has not yet opened the app, so locationId is not yet identified. Will update this entry once they use the app.

---

### 8MdvxtWC7PwpAQrKrkFk (Dec 26)
| Field | Value |
|-------|-------|
| First Seen | Dec 26, 2025 |
| Last Activity | Jan 2, 2026 |
| Request Count | 35 |
| IP | 184.103.62.124 |
| Status | Active - healthy |

**Notes:** Came back on Jan 2 - retention! No errors.

---

### ORAR6TYKTK091V2KxxCL (Dec 22)
| Field | Value |
|-------|-------|
| First Seen | Dec 22, 2025 |
| Last Activity | Jan 8, 2026 |
| Request Count | 180 |
| Browser | Mac Safari 26.1, Mac Chrome 143 |
| IP | 72.76.72.159 (Dec), 146.75.245.78 (Jan 5 Safari) |
| Status | **Active - consistent user, retention win!** |

**Objects Used:** `custom_objects.properties`

**History:**
- Dec 22: 4 successful imports
- Dec 23: 2 more successful imports
- Jan 5: Came back! 22 requests, using both Safari and Chrome
- Jan 8: 11 requests (3:47 PM UTC) - consistent usage

**Note:** Initial 401s were just GET requests before POST `/api/app-context` established auth - working as designed.

---

### ygw6rrilEUeLsuDssdJz (Dec 21)
| Field | Value |
|-------|-------|
| First Seen | Dec 21, 2025 |
| Last Activity | Dec 21, 2025 |
| Request Count | 583 |
| Browser | **Windows HighLevel Desktop App** |
| IP | 92.238.16.106 |
| Status | Active - has 404 errors |

**Notes:** Using HighLevel desktop app on Windows.
**Issue:** Hitting 404 on `/api/objects/custom_objects.orders/records/update` - trying to use an update endpoint that doesn't exist.

---

### O7pOtfkCX8Xjon59hb52 (Dec 18)
| Field | Value |
|-------|-------|
| First Seen | Dec 18, 2025 |
| Last Activity | Dec 30, 2025 |
| Request Count | 905 |
| Browser | Mac Chrome 142 |
| IP | 97.212.56.14 |
| Status | **Active - healthy** |

**Objects Used:** `custom_objects.listings`
**History:**
- Dec 18: Had CSV parsing errors ("Too many fields")
- Dec 19: Fixed CSV, now importing successfully
- Dec 30: Still active, no new issues

---

### 41ySOzBJAkE36l3Iz7C8 (NEW - Dec 16!)
| Field | Value |
|-------|-------|
| First Seen | Dec 16, 2025 |
| Last Activity | Dec 18, 2025 |
| Request Count | 148 |
| Browser | **HighLevel Desktop App** (Electron) |
| IP | 47.162.51.72 |
| Status | Active - healthy |

**Notes:** Using HighLevel desktop app instead of browser. No errors.

---

### nG8OlMhCho0vPY7msUnA (Dec 16)
| Field | Value |
|-------|-------|
| First Seen | Dec 16, 2025 |
| Last Activity | Dec 26, 2025 |
| Request Count | 1008 |
| Browser | Mac Chrome 143 |
| IP | 71.248.179.225 |
| Status | Active - healthy |

**Notes:** Very active user. 1000+ requests over 10 days. No issues reported. Power user!

---

### 4NXbu5OPwVzBZJXx74EA (Dec 12)
| Field | Value |
|-------|-------|
| First Seen | Dec 12, 2025 |
| Last Activity | Dec 31, 2025 |
| Request Count | 418 |
| Browser | Windows Chrome 142 |
| IP | 70.57.25.16 |
| Status | **Active - still has issues** |

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

### f5gtkYApXptSz4A6sHUR (Dec 9)
| Field | Value |
|-------|-------|
| First Seen | Dec 9, 2025 |
| Last Activity | Dec 29, 2025 |
| Request Count | 2122 |
| Status | Active - had 400 error |

**Notes:** Highest engagement user. 2100+ requests over 20 days. Power user!
**Issue:** Dec 22 - 400 error on `/api/objects/opportunity/records/export` (bad request on export)

---

### YcTMZv0tRv2yF4Jsyc3m (Dec 8)
| Field | Value |
|-------|-------|
| First Seen | Dec 8, 2025 |
| Last Activity | Jan 8, 2026 |
| Request Count | 43 |
| Status | **Active - retention win!** |

**History:**
- Dec 8-10: 24 requests over 3 days
- Inactive for 1 month
- Jan 8: Came back! 19 requests (8:30-8:35 AM UTC)

**Notes:** Major retention win - returned after 1 month absence. Healthy usage pattern.

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

### j6Lo4zmR1bLqAZKa4qA4 (Dec 3)
| Field | Value |
|-------|-------|
| First Seen | Dec 3, 2025 |
| Last Activity | Jan 2, 2026 |
| Request Count | 46 |
| Status | Active - returning user |

**Notes:** Long-term user - active across Dec and Jan. Healthy.

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
| Last Activity | Dec 16, 2025 |
| Request Count | 661 |
| Status | Dev/Test Account |

**Notes:** Primary development and testing account. High request count is from testing.

---

## Known Issues & Fixes

### GHL Reconnect API Removed (FIXED - Jan 6, 2026)
- **Discovered:** Jan 5, 2026 during investigation of abandoned install attempt
- **Affected:** Any user with expired/invalid auth trying to use the app
- **Incident:** Location `Kd5ikeLjdIFPL4TbXiGX` (companyId `T8ipYCEUa9Sy3v4eJsx4`) tried to use app on Jan 5 @ 7:50 PM EST
  - Got 422 error when app tried to recover auth
  - Started OAuth reinstall flow but abandoned
- **Root Cause:** GHL silently removed the `/oauth/reconnect` API endpoint
  - Returns: `{"message": "API endpoint has been removed", "statusCode": 400}`
  - GHL's [official docs](https://help.gohighlevel.com/support/solutions/articles/155000003717) still recommend using this endpoint (outdated)
  - Tested and confirmed dead on Jan 6, 2026
- **Impact:** App would try the dead endpoint (10 second timeout) before showing error to user, causing confusion and abandonment
- **Fix Deployed:** Jan 6, 2026 - Removed dead Reconnect API fallback code (79 lines)
  - Now immediately returns 422 with `redirectUrl: '/oauth/install'` when auth recovery fails
  - Faster, cleaner UX - no waiting for dead API call
- **Status:** ✅ Fixed in `src/routes/appContext.js:350-359`

### 404 on /records/update Endpoint (NEW)
- **Affected:** `ygw6rrilEUeLsuDssdJz`, `4NXbu5OPwVzBZJXx74EA`
- **Pattern:** Users hitting `/api/objects/custom_objects.X/records/update`
- **Cause:** This endpoint doesn't exist - there's no bulk update feature
- **User Expectation:** Users expect to be able to update existing records, not just import new ones
- **Status:** Feature request? Or UI is misleading users to think update is available
- **Fix:** Either implement update endpoint or clarify in UI that only import (create) is supported

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
