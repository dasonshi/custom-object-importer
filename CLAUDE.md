# Claude Code Project Context

## User Tracking

User activity is tracked in `users.csv` with the following columns:
- `location_id` - GHL location ID (unique per user/account)
- `first_seen` - Date of first activity
- `last_activity` - Date of most recent activity
- `request_count` - Total API requests made
- `is_dev_account` - true if this is a dev/test account
- `months_active` - Number of months from first to last activity

**Dev account IDs:** `gdzneuvA9mUJoRroCv4O` (from .env DEV_LOCATION_ID)

### Refreshing user data
Run this to regenerate users.csv from Axiom logs:
```bash
axiom query "['custom-object-importer'] | where message contains 'locationId=' | where application == 'http-request'" --format=json > /tmp/axiom_locations.json

cat /tmp/axiom_locations.json | python3 -c "
import json, sys, re
from collections import defaultdict
from datetime import datetime

DEV_ACCOUNTS = ['gdzneuvA9mUJoRroCv4O']
data = defaultdict(lambda: {'first': None, 'last': None, 'count': 0})

for line in sys.stdin:
    try:
        obj = json.loads(line)
        if obj.get('metadata.method') == 'OPTIONS': continue
        path = obj.get('metadata.path', '')
        match = re.search(r'locationId=([a-zA-Z0-9]+)', path)
        if match:
            loc_id, date = match.group(1), obj.get('_time', '')[:10]
            if not data[loc_id]['first'] or date < data[loc_id]['first']: data[loc_id]['first'] = date
            if not data[loc_id]['last'] or date > data[loc_id]['last']: data[loc_id]['last'] = date
            data[loc_id]['count'] += 1
    except: pass

print('location_id,first_seen,last_activity,request_count,is_dev_account,months_active')
for loc_id, info in sorted(data.items(), key=lambda x: x[1]['first'] or ''):
    is_dev = 'true' if loc_id in DEV_ACCOUNTS else 'false'
    first = datetime.strptime(info['first'], '%Y-%m-%d')
    last = datetime.strptime(info['last'], '%Y-%m-%d')
    months = max(1, (last.year - first.year) * 12 + (last.month - first.month) + 1)
    print(f\"{loc_id},{info['first']},{info['last']},{info['count']},{is_dev},{months}\")
" > users.csv
```

---

## Axiom Logging

This project uses Axiom for log aggregation. The CLI is installed globally.

### Dataset
- **Dataset name:** `custom-object-importer`
- **Contains:** HTTP request logs from `importer.api.savvysales.ai`

### Key Fields
- `metadata.path` - Request path (e.g., `/oauth/callback`, `/api/app-context`)
- `metadata.method` - HTTP method (GET, POST, OPTIONS)
- `metadata.statusCode` - Response status code
- `metadata.clientIP` - Client IP address
- `metadata.userAgent` - User agent string
- `metadata.responseTimeMS` - Response time in milliseconds
- `_time` - Timestamp

### Common Queries

**Check for new installs (OAuth callbacks):**
```bash
axiom query "['custom-object-importer'] | where _time > now() - 3d | where message contains '/oauth/callback'" --format=table
```

**Summarize traffic by path:**
```bash
axiom query "['custom-object-importer'] | where _time >= datetime('2025-12-06') | summarize count() by bin(_time, 1d), ['metadata.path']" --format=table
```

**Check real app usage (filter out bots):**
```bash
axiom query "['custom-object-importer'] | where _time > now() - 3d | where message contains '/api/' | where ['metadata.method'] == 'POST'" --format=table
```

**Get all requests from a specific IP:**
```bash
axiom query "['custom-object-importer'] | where ['metadata.clientIP'] == '179.1.148.226'" --format=table
```

### Notes
- Most logs with `<nil>` path are database connection logs (Render Postgres), not HTTP requests
- Bot traffic often hits paths like `/.env`, `/phpinfo.php`, `/backup.sql` - these are security scanners
- Real user activity typically shows up on `/api/app-context`, `/api/objects`, `/import/*` paths
- OAuth installs come through `/oauth/callback` with a 302 redirect to `/launch`
