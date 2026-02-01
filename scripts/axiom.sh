#!/bin/bash
# Axiom query helper for Custom Object Importer
# Always filters by correct hostnames to avoid mixing with other services

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
USERS_CSV="$PROJECT_DIR/users.csv"

DATASET="custom-object-importer"
HOST_FILTER="hostname == 'importer.api.savvysales.ai' or hostname == 'custom-object-uploader'"

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  check [days]        - Check for new installs & inactive users (default: 7 days)"
    echo "  bugs [hours]        - Check for app errors/bugs (default: 24 hours)"
    echo "  installs [days]     - Show OAuth installs (default: 3 days)"
    echo "  activity <locId>    - Show activity for a specific location ID"
    echo "  count <locId>       - Count requests for a location ID"
    echo "  raw <apl>           - Run raw APL query (auto-adds host filter)"
    echo ""
    exit 1
}

# Check if axiom CLI is available
if ! command -v axiom &> /dev/null; then
    echo "Error: axiom CLI not found. Install from https://axiom.co/docs/reference/cli"
    exit 1
fi

case "$1" in
    check)
        DAYS="${2:-7}"
        echo "=== User Check (last $DAYS days) ==="
        echo ""

        # Get active location IDs from logs
        ACTIVE_IDS=$(axiom query "['$DATASET'] | where _time > now() - ${DAYS}d | where $HOST_FILTER | where message contains 'locationId='" --format=table 2>&1 | grep -o 'locationId=[a-zA-Z0-9]*' | sed 's/locationId=//' | sort -u)

        # Get known IDs from users.csv
        if [ -f "$USERS_CSV" ]; then
            KNOWN_IDS=$(tail -n +2 "$USERS_CSV" | cut -d',' -f1 | sort -u)
        else
            KNOWN_IDS=""
            echo "Warning: users.csv not found at $USERS_CSV"
        fi

        # Find new installs (in logs but not in users.csv)
        echo "NEW INSTALLS (not in users.csv):"
        NEW_COUNT=0
        for id in $ACTIVE_IDS; do
            if ! echo "$KNOWN_IDS" | grep -q "^${id}$"; then
                # Get request count for this ID
                COUNT=$(axiom query "['$DATASET'] | where _time > now() - ${DAYS}d | where $HOST_FILTER | where message contains '$id' | summarize count()" --format=table 2>&1 | grep -oE '[0-9]+' | tail -1)
                echo "  - $id (${COUNT:-0} requests)"
                NEW_COUNT=$((NEW_COUNT + 1))
            fi
        done
        if [ $NEW_COUNT -eq 0 ]; then
            echo "  (none)"
        fi
        echo ""

        # Find inactive users (in users.csv but no activity in logs)
        echo "INACTIVE USERS (no activity in last $DAYS days):"
        INACTIVE_COUNT=0
        for id in $KNOWN_IDS; do
            if [ -n "$id" ] && ! echo "$ACTIVE_IDS" | grep -q "^${id}$"; then
                # Get user info from CSV
                USER_INFO=$(grep "^$id," "$USERS_CSV" | head -1)
                LAST_SEEN=$(echo "$USER_INFO" | cut -d',' -f3)
                STATUS=$(echo "$USER_INFO" | cut -d',' -f7)
                if [ "$STATUS" != "churned" ]; then
                    echo "  - $id (last seen: $LAST_SEEN)"
                    INACTIVE_COUNT=$((INACTIVE_COUNT + 1))
                fi
            fi
        done
        if [ $INACTIVE_COUNT -eq 0 ]; then
            echo "  (none)"
        fi
        echo ""

        # Summary
        ACTIVE_COUNT=$(echo "$ACTIVE_IDS" | grep -c .)
        KNOWN_COUNT=$(echo "$KNOWN_IDS" | grep -c .)
        echo "SUMMARY:"
        echo "  Active in last $DAYS days: $ACTIVE_COUNT"
        echo "  Known in users.csv: $KNOWN_COUNT"
        echo "  New installs: $NEW_COUNT"
        echo "  Inactive (not churned): $INACTIVE_COUNT"
        ;;

    bugs)
        HOURS="${2:-24}"
        echo "=== App Errors (last $HOURS hours) ==="
        echo ""

        # Check for 500 errors
        echo "500 ERRORS:"
        ERRORS_500=$(axiom query "['$DATASET'] | where _time > now() - ${HOURS}h | where $HOST_FILTER | where ['metadata.statusCode'] >= 500 | project _time, ['metadata.path'], ['metadata.statusCode']" --format=table 2>&1)
        if echo "$ERRORS_500" | grep -q "no results"; then
            echo "  (none)"
        else
            echo "$ERRORS_500" | head -20
        fi
        echo ""

        # Check for severity=error logs (app exceptions)
        echo "APP EXCEPTIONS:"
        EXCEPTIONS=$(axiom query "['$DATASET'] | where _time > now() - ${HOURS}h | where $HOST_FILTER | where severity == 'error' | project _time, message" --format=table 2>&1)
        if echo "$EXCEPTIONS" | grep -q "no results"; then
            echo "  (none)"
        else
            echo "$EXCEPTIONS" | head -20
        fi
        echo ""

        # Check for auth failures (excluding Safari which is expected)
        echo "AUTH FAILURES (non-Safari):"
        AUTH_FAILS=$(axiom query "['$DATASET'] | where _time > now() - ${HOURS}h | where $HOST_FILTER | where ['metadata.statusCode'] == 401 | where message !contains 'Safari'" --format=table 2>&1)
        if echo "$AUTH_FAILS" | grep -q "no results"; then
            echo "  (none)"
        else
            echo "$AUTH_FAILS" | grep -v Safari | head -10
        fi
        echo ""

        # Count summary
        echo "SUMMARY:"
        COUNT_500=$(axiom query "['$DATASET'] | where _time > now() - ${HOURS}h | where $HOST_FILTER | where ['metadata.statusCode'] >= 500 | summarize count()" --format=table 2>&1 | grep -oE '[0-9]+' | tail -1)
        COUNT_ERR=$(axiom query "['$DATASET'] | where _time > now() - ${HOURS}h | where $HOST_FILTER | where severity == 'error' | summarize count()" --format=table 2>&1 | grep -oE '[0-9]+' | tail -1)
        COUNT_401=$(axiom query "['$DATASET'] | where _time > now() - ${HOURS}h | where $HOST_FILTER | where ['metadata.statusCode'] == 401 | summarize count()" --format=table 2>&1 | grep -oE '[0-9]+' | tail -1)
        echo "  500 errors: ${COUNT_500:-0}"
        echo "  App exceptions: ${COUNT_ERR:-0}"
        echo "  Auth failures (401): ${COUNT_401:-0}"
        ;;

    installs)
        DAYS="${2:-3}"
        echo "=== OAuth Installs (last $DAYS days) ==="
        axiom query "['$DATASET'] | where _time > now() - ${DAYS}d | where $HOST_FILTER | where message contains '/oauth/callback' and ['metadata.statusCode'] == 302 | project _time, ['metadata.clientIP'], ['metadata.userAgent']" --format=table
        ;;

    activity)
        if [ -z "$2" ]; then
            echo "Error: location ID required"
            echo "Usage: $0 activity <locationId>"
            exit 1
        fi
        DAYS="${3:-7}"
        echo "=== Activity for $2 (last $DAYS days) ==="
        axiom query "['$DATASET'] | where _time > now() - ${DAYS}d | where $HOST_FILTER | where message contains '$2' | project _time, ['metadata.path'], ['metadata.statusCode']" --format=table
        ;;

    count)
        if [ -z "$2" ]; then
            echo "Error: location ID required"
            echo "Usage: $0 count <locationId>"
            exit 1
        fi
        DAYS="${3:-7}"
        axiom query "['$DATASET'] | where _time > now() - ${DAYS}d | where $HOST_FILTER | where message contains '$2' | summarize count()" --format=table
        ;;

    raw)
        if [ -z "$2" ]; then
            echo "Error: APL query required"
            echo "Usage: $0 raw '<apl query>'"
            exit 1
        fi
        QUERY="$2"
        if [[ ! "$QUERY" =~ "hostname" ]]; then
            QUERY="['$DATASET'] | where $HOST_FILTER | $QUERY"
        fi
        axiom query "$QUERY" --format=table
        ;;

    *)
        usage
        ;;
esac
