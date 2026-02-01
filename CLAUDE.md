# Claude Code Project Context

## Project Architecture

**This is the BACKEND API** - a Node.js/Express server that handles:
- GHL OAuth authentication
- CSV parsing and import processing
- GHL API calls for objects, fields, and records

**The FRONTEND is a separate React app** located at:
- **Local path:** `/Users/davidsonshine/Desktop/Custom Object Importer/ghl-data-forge`
- **GitHub:** `https://github.com/dasonshi/ghl-data-forge`
- **Deployed via:** Lovable (not auto-deployed from git push)
- **Tech stack:** React + TypeScript + Vite + shadcn/ui

**Where users upload CSVs:** Frontend `ImportRecordsTab.tsx` and `AddFieldsTab.tsx` components handle file uploads using PapaParse for client-side CSV parsing, then POST to this backend's `/api/imports/*` endpoints.

---

## Axiom Logging - ALWAYS USE THE HELPER SCRIPT

**IMPORTANT:** Always use `scripts/axiom.sh` for log queries. This ensures correct hostname filtering.

### Primary Commands (use these first)

```bash
# Check for new installs & inactive users (compares against users.csv)
./scripts/axiom.sh check

# Check for app bugs/errors (500s, exceptions, auth failures)
./scripts/axiom.sh bugs
```

### Other Commands

```bash
# Show OAuth callbacks (raw install events)
./scripts/axiom.sh installs [days]

# Activity for specific user
./scripts/axiom.sh activity <locationId>

# Count requests for user
./scripts/axiom.sh count <locationId>

# Raw query (auto-adds host filter)
./scripts/axiom.sh raw "where message contains 'OAuth'"
```

### What Each Command Shows

**`check`** - Compares logs against users.csv:
- NEW INSTALLS: Location IDs in logs but not in users.csv
- INACTIVE USERS: Users in users.csv with no recent activity (excludes churned)
- Summary with counts

**`bugs`** - Shows app errors:
- 500 ERRORS: Server errors (real bugs)
- APP EXCEPTIONS: severity=error logs
- AUTH FAILURES: 401s excluding Safari (Safari cookie issues are expected)
- Note: "Bad Request" errors are GHL API validation errors, not app bugs

---

## User Tracking

User activity is tracked in `users.csv` with columns:
- `location_id` - GHL location ID (unique per user/account)
- `first_seen`, `last_activity` - Date range
- `request_count` - Total API requests
- `is_dev_account` - true if dev/test
- `months_active` - Duration
- `status` - active/churned

**Dev account:** `gdzneuvA9mUJoRroCv4O`

### Workflow: Checking for Changes

```bash
# 1. Run check to see new installs and inactive users
./scripts/axiom.sh check

# 2. Add any new installs to users.csv
# 3. Mark long-inactive users as churned if appropriate
```
