#!/bin/bash
# NAIL Institute API — cURL Examples
# Replace YOUR_API_KEY with your actual API key.

API_KEY="${NAIL_API_KEY:-YOUR_API_KEY}"
BASE="https://api.nailinstitute.org/v2"
AUTH="Authorization: Bearer $API_KEY"

echo "=== NAIL Institute API — cURL Examples ==="

# 1. Health check (no auth required)
echo -e "\n--- Health Check ---"
curl -s "$BASE/health" | python3 -m json.tool

# 2. List cards (first 5)
echo -e "\n--- List Cards (first 5) ---"
curl -s -H "$AUTH" "$BASE/cards?per_page=5" | python3 -m json.tool

# 3. Search for prompt injection vulnerabilities
echo -e "\n--- Search: prompt injection ---"
curl -s -H "$AUTH" "$BASE/cards?q=prompt+injection&severity=critical" | python3 -m json.tool

# 4. Get a specific card
echo -e "\n--- Get Card: AVE-2024-001 ---"
curl -s -H "$AUTH" "$BASE/cards/AVE-2024-001" | python3 -m json.tool

# 5. Database statistics
echo -e "\n--- Statistics ---"
curl -s -H "$AUTH" "$BASE/stats" | python3 -m json.tool

# 6. List categories
echo -e "\n--- Categories ---"
curl -s -H "$AUTH" "$BASE/categories" | python3 -m json.tool

# 7. Check usage
echo -e "\n--- Usage ---"
curl -s -H "$AUTH" "$BASE/auth/usage" | python3 -m json.tool

# 8. Get changes since a date
echo -e "\n--- Diff since 2026-03-01 ---"
curl -s -H "$AUTH" "$BASE/cards/diff?since=2026-03-01T00:00:00Z" | python3 -m json.tool

echo -e "\n=== Done ==="
