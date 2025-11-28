# Complete User Documentation
**Generated:** November 25, 2025 19:35 UTC
**Data Sources:** 
- Render logs: Nov 19 08:50 to Nov 21 23:55 UTC (~63 hours, 6,470 log lines)
- Axiom logs: Last 7 days with real-time streaming (302 events)

---

## Executive Summary

**Total Unique Users: 6**

| # | Location ID | Status | Activity Level | First Active | Most Recent Active | Issues |
|---|-------------|--------|----------------|--------------|-------------------|--------|
| 1 | `gdzneuvA9mUJoRroCv4O` | ✅ Active (3d ago) | HIGH | 2025-11-19 22:27 UTC | 2025-11-21 23:55 UTC | None |
| 2 | `QjrnkYkApsr3Pw9D6Xkl` | ✅ Active (1d ago) | VERY HIGH | 2025-11-22 20:12 UTC | 2025-11-24 08:28 UTC | None |
| 3 | `2VuOfM265RvlOoxkQkpI` | ✅ Active (today) | MODERATE | 2025-11-19 15:54 UTC | 2025-11-24 21:03 UTC | Agency install failed |
| 4 | `ORAR6TYKTK091V2KxxCL` | ✅ Active (today) | MODERATE | 2025-11-19 16:26 UTC | 2025-11-24 20:31 UTC | Safari cookies |
| 5 | `8MdvxtWC7PwpAQrKrkFk` | ⚠️ Inactive (4d) | LOW | 2025-11-20 16:11 UTC | 2025-11-21 21:29 UTC | None |
| 6 | `YwiHnfdr74kXJGsVlc6c` | ❌ Inactive (6d) | MINIMAL | 2025-11-19 17:32 UTC | 2025-11-19 17:32 UTC | Abandoned/Test |

---

## Detailed User Information

## User 1: `gdzneuvA9mUJoRroCv4O`

### Overview
- **Status:** ✅ Active (last seen 3 days ago)
- **User Type:** Primary developer/owner
- **Activity Level:** HIGH (93 total events)
- **First Seen:** Nov 19, 2025 22:27:59 UTC
- **Last Seen:** Nov 21, 2025 23:55:00 UTC

### User Information
- **IP Address:** 179.1.148.226
- **Browser:** Chrome 142.0.0.0
- **Operating System:** macOS (Intel Mac OS X 10_15_7)
- **Device Type:** Desktop/Laptop

### Activity Details
- **OAuth Token Exchanges:** 3
- **Auth Cookie Operations:** 3
- **Token Refreshes:** 2 (successful)
- **Agency Installation Uses:** 28 (heavy user of this feature)
- **API Calls:** Accessing multiple endpoints (agency-branding, objects, custom schemas)
- **Custom Objects:** Working with "test", "car", "product" objects

### Issues & Bugs
✅ **No issues detected** - All operations completing successfully

### Notes
- Most active user
- Using agency bulk install feature extensively
- Token refresh working correctly
- Primary testing/development account

---

## User 2: `QjrnkYkApsr3Pw9D6Xkl` 🆕

### Overview
- **Status:** ✅ Active (last seen 1 day ago - Nov 24, 08:28 UTC)
- **User Type:** External marketplace user (NEW!)
- **Activity Level:** VERY HIGH (263 events in 2 days)
- **First Seen:** Nov 22, 2025 20:12:14 UTC
- **Last Seen:** Nov 24, 2025 08:28:52 UTC

### User Information
- **IP Addresses:** 
  - 47.223.208.49 (Primary - Windows)
  - 49.205.145.211 (Secondary - Mac)
- **Browsers:** Chrome 142.0.0.0 on both devices
- **Operating Systems:** 
  - Windows NT 10.0 (x64)
  - macOS
- **Device Type:** Multiple devices (work/home setup)

### Activity Details
- **API Calls:** 263 (very active usage)
- **Custom Objects:** Working with "companies" custom object
- **Endpoints Used:**
  - `/api/agency-branding`
  - `/api/objects`
  - `/api/objects/companies/schema`
  - `/templates/records/custom_objects.properties`
  - `/api/custom-values`
- **Features Used:**
  - Custom object schema fetching
  - Template downloads
  - Custom field values
  - Agency branding

### Issues & Bugs
✅ **No issues detected** - Clean, successful API responses (200 status codes)

### Notes
- **FIRST EXTERNAL MARKETPLACE USER!**
- Highly engaged - 263 API calls in 2 days
- Using multiple devices indicating serious usage
- Actively working with custom objects for companies
- All operations succeeding
- Last active yesterday morning

---

## User 3: `2VuOfM265RvlOoxkQkpI`

### Overview
- **Status:** ✅ Active (ACTIVE TODAY - Nov 24, 21:03 UTC)
- **User Type:** External user
- **Activity Level:** MODERATE (22 events)
- **First Seen:** Nov 19, 2025 15:54:56 UTC
- **Last Seen:** Nov 24, 2025 21:03:34 UTC

### User Information
- **IP Address:** 70.163.254.178
- **Browser:** Chrome 142.0.0.0
- **Operating System:** Windows
- **Device Type:** Desktop/Laptop

### Activity Details
- **Agency Installation Attempts:** 4 (all failed)
- **API Calls:** 9
- **Custom Objects:** Working with "bookings" custom object
- **Endpoints Used:**
  - `/api/agency-branding`
  - `/api/objects`
  - `/api/objects/bookings/schema`

### Issues & Bugs
⚠️ **ISSUE: Agency Installation Not Found**

**Problem:**
- User attempting to use agency bulk install feature
- System logs: "❌ No agency installation found for location"
- Attempted 4 times between Nov 19 15:54-16:25

**Status:** Unresolved - user appears to have given up on this feature but continues using app

**Impact:** User cannot use agency-level bulk install feature, must install individually

**Root Cause:** No AgencyInstall record exists in database for this location
- Either: Agency didn't complete marketplace install properly
- Or: This is a sub-account location trying to use agency install

**Recommended Action:** 
1. Check if this location has a parent agency
2. Verify AgencyInstall table for missing records
3. May need to manually create agency install record

### Notes
- Despite install issue, user continues to access the app
- Recently active (today)
- Using standard features successfully

---

## User 4: `ORAR6TYKTK091V2KxxCL`

### Overview
- **Status:** ✅ Active (ACTIVE TODAY - Nov 24, 20:31 UTC)
- **User Type:** Testing account / Safari user
- **Activity Level:** MODERATE (46 events)
- **First Seen:** Nov 19, 2025 16:26:03 UTC
- **Last Seen:** Nov 24, 2025 20:31:56 UTC

### User Information
- **IP Address:** 146.75.237.85 (from earlier analysis)
- **Browser:** Safari (version unknown)
- **Operating System:** Unknown (likely macOS)
- **Device Type:** Desktop/Laptop

### Activity Details
- **Auth Cookie Operations:** 11 (excessive - indicates problem)
- **Token Refreshes:** 2 (successful)
- **OAuth Events:** 0 (never completed OAuth flow in Render window)
- **Pattern:** Repeated auth cookie setting without successful authentication

### Issues & Bugs
⚠️ **KNOWN ISSUE: Safari ITP Cookie Blocking**

**Problem:**
- Safari's Intelligent Tracking Prevention (ITP) blocking third-party cookies
- Auth cookies being set repeatedly (11 times) but not persisting
- User unable to maintain authenticated session

**Status:** Partially mitigated - Safari warning banner deployed

**Impact:** 
- User cannot stay logged in
- Poor user experience
- May appear as "logged out" frequently

**Timeline:**
- Nov 19-21: Heavy cookie issues (11 cookie sets)
- Nov 24: Still seeing issues (1 event today)

**Solution Implemented:**
- Safari warning banner guides user to Chrome/Firefox
- User appears to still be attempting with Safari

**Recommended Action:**
- Monitor if user switches browsers
- Consider email to user suggesting browser change
- May need more prominent Safari warning

### Notes
- Despite persistent auth issues, user continues attempting to use app
- Shows user interest but frustrated experience
- This is a test account belonging to app owner based on previous analysis

---

## User 5: `8MdvxtWC7PwpAQrKrkFk`

### Overview
- **Status:** ⚠️ Inactive (4 days - last seen Nov 21)
- **User Type:** External user
- **Activity Level:** LOW (6 events)
- **First Seen:** Nov 20, 2025 16:11:57 UTC
- **Last Seen:** Nov 21, 2025 21:29:54 UTC

### User Information
- **IP Address:** Unknown (not in Axiom 7-day window)
- **Browser:** Unknown
- **Operating System:** Unknown

### Activity Details
- **OAuth Token Exchange:** 1 (successful)
- **Auth Cookie Operations:** 1
- **Token Refreshes:** 1 (successful)
- **Duration:** Active for ~29 hours (Nov 20 16:11 to Nov 21 21:29)

### Issues & Bugs
✅ **No issues detected** during active period

### Notes
- Brief usage period
- All authentication operations successful
- Has not returned in 4 days
- May have been evaluating the app
- Possibly uninstalled or lost interest

---

## User 6: `YwiHnfdr74kXJGsVlc6c`

### Overview
- **Status:** ❌ Inactive (6 days - last seen Nov 19)
- **User Type:** Test/Abandoned installation
- **Activity Level:** MINIMAL (2 events)
- **First Seen:** Nov 19, 2025 17:32:50 UTC
- **Last Seen:** Nov 19, 2025 17:32:50 UTC (same second)

### User Information
- **IP Address:** Unknown
- **Browser:** Unknown
- **Operating System:** Unknown

### Activity Details
- **Total Events:** 2 (both in same second)
- **Duration:** < 1 second
- **No successful operations logged**

### Issues & Bugs
⚠️ **Abandoned or Test Installation**

**Analysis:**
- Only 2 log entries, both at exact same timestamp
- No follow-up activity in 6 days
- Never completed any meaningful operations

### Notes
- Likely a test installation that was immediately uninstalled
- Or marketplace preview that user dismissed
- No actual usage detected
- Can be considered inactive/abandoned

---

## Analysis & Insights

### Active Users Summary
- **3 Currently Active** (seen in last 24 hours): QjrnkYkApsr3Pw9D6Xkl, 2VuOfM265RvlOoxkQkpI, ORAR6TYKTK091V2KxxCL
- **1 Recently Active** (last 3 days): gdzneuvA9mUJoRroCv4O
- **2 Inactive** (>3 days): 8MdvxtWC7PwpAQrKrkFk, YwiHnfdr74kXJGsVlc6c

### External vs Internal Users
- **External Marketplace Users:** 2-3 (QjrnkYkApsr3Pw9D6Xkl confirmed, 2VuOfM265RvlOoxkQkpI likely, 8MdvxtWC7PwpAQrKrkFk possibly)
- **Internal/Testing:** 2-3 (gdzneuvA9mUJoRroCv4O confirmed owner, ORAR6TYKTK091V2KxxCL Safari test, YwiHnfdr74kXJGsVlc6c test)

### Issues by Severity

**HIGH Priority:**
- None currently

**MEDIUM Priority:**
1. **Agency Install Missing** (User 3: 2VuOfM265RvlOoxkQkpI)
   - Blocking feature usage
   - May affect other users
   - Database inconsistency

**LOW Priority:**
2. **Safari Cookie Issues** (User 4: ORAR6TYKTK091V2KxxCL)
   - Known browser limitation
   - Mitigation in place (warning banner)
   - Affects test account only

3. **User Churn** (Users 5 & 6)
   - Natural evaluation/trial behavior
   - No technical issues preventing usage

### Usage Patterns
- **Most Active User:** QjrnkYkApsr3Pw9D6Xkl (263 events in 2 days)
- **Most Engaged Feature:** Agency bulk install (User 1: 28 uses)
- **Popular Custom Objects:** companies, bookings, test, car, product
- **Browser Distribution:** Chrome (majority), Safari (1 user with issues)
- **OS Distribution:** macOS (3), Windows (2), Unknown (1)

### Growth Indicators
- **New user acquisition:** 1 confirmed new external user (Nov 22)
- **User retention:** 4 of 6 users still active
- **Feature adoption:** Users actively creating custom objects and using templates

---

## Data Sources & Methodology

### Render Logs
- **Period:** Nov 19 08:50 to Nov 21 23:55 UTC (~63 hours)
- **Volume:** 6,470 log lines across 6 batches
- **Coverage:** Historical usage patterns, detailed authentication flows
- **Limitations:** No data beyond Nov 21, limited to 1000 lines per query

### Axiom Logs
- **Period:** Last 7 days (rolling window)
- **Volume:** 302 location-related events
- **Coverage:** Recent activity, real-time data, includes TODAY's usage
- **Advantages:** 30-day retention, unlimited queries, real-time streaming

### Combined Analysis
- Render provides historical depth and auth flow details
- Axiom provides current status and recent activity
- Cross-reference validates user patterns and identifies issues

---

**Report End**
