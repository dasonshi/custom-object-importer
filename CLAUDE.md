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

### Axiom API (for monitors/notifiers)

The CLI doesn't support monitors or notifiers. Use the REST API instead.

**Auth credentials** (from `~/.axiom.toml`):
```
Token: xapt-ed795584-adec-4ab9-bb00-ef5b78d2f308
Org ID: savvy-sales-k2ob
```

**Headers required for all API calls:**
```bash
-H "Authorization: Bearer <token>"
-H "X-Axiom-Org-Id: savvy-sales-k2ob"
-H "Content-Type: application/json"
```

**Existing resources:**
- Notifier `oCCzANvP6FvANXUVU7` → david@savvysales.ai
- Monitor `l0IwKumEQRWxeUfTgL` → "New App Install" (emails on OAuth success)

**API examples:**
```bash
# List notifiers
curl -s "https://api.axiom.co/v2/notifiers" \
  -H "Authorization: Bearer xapt-ed795584-adec-4ab9-bb00-ef5b78d2f308" \
  -H "X-Axiom-Org-Id: savvy-sales-k2ob"

# List monitors
curl -s "https://api.axiom.co/v2/monitors" \
  -H "Authorization: Bearer xapt-ed795584-adec-4ab9-bb00-ef5b78d2f308" \
  -H "X-Axiom-Org-Id: savvy-sales-k2ob"

# Create email notifier
curl -s -X POST "https://api.axiom.co/v2/notifiers" \
  -H "Authorization: Bearer xapt-ed795584-adec-4ab9-bb00-ef5b78d2f308" \
  -H "X-Axiom-Org-Id: savvy-sales-k2ob" \
  -H "Content-Type: application/json" \
  -d '{"name": "Alert Name", "properties": {"email": {"emails": ["user@example.com"]}}}'

# Create monitor (MatchEvent type for instant alerts)
curl -s -X POST "https://api.axiom.co/v2/monitors" \
  -H "Authorization: Bearer xapt-ed795584-adec-4ab9-bb00-ef5b78d2f308" \
  -H "X-Axiom-Org-Id: savvy-sales-k2ob" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Monitor Name",
    "type": "MatchEvent",
    "aplQuery": "[\"custom-object-importer\"] | where hostname == \"importer.api.savvysales.ai\" | where <your filter>",
    "notifierIds": ["<notifier-id>"],
    "intervalMinutes": 5,
    "rangeMinutes": 5
  }'
```

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
