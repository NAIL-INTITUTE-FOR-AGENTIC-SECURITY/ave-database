#!/usr/bin/env python3
"""
NAIL AVE → Splunk HEC Ingestion Script

Fetches AVE cards from the NAIL API and sends them to Splunk via HTTP Event Collector.

Usage:
    python splunk_ingest.py \
        --hec-url https://your-splunk:8088 \
        --hec-token YOUR_TOKEN \
        --nail-api https://api.nailinstitute.org/api/v1

    # Continuous polling (every 5 minutes):
    python splunk_ingest.py \
        --hec-url https://your-splunk:8088 \
        --hec-token YOUR_TOKEN \
        --poll-interval 300
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

DEFAULT_NAIL_API = "https://api.nailinstitute.org/api/v1"
STATE_FILE = Path.home() / ".nail-splunk-state.json"


def load_state() -> dict:
    """Load last ingestion state (for incremental sync)."""
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"last_sync": None, "cards_ingested": 0}


def save_state(state: dict) -> None:
    """Save ingestion state."""
    STATE_FILE.write_text(json.dumps(state, indent=2))


def fetch_ave_cards(api_base: str, since: str | None = None) -> list[dict]:
    """Fetch AVE cards from the NAIL API."""
    url = f"{api_base}/cards"
    params = {}
    if since:
        params["updated_since"] = since

    logger.info(f"Fetching AVE cards from {url}")
    try:
        resp = requests.get(url, params=params, timeout=30)
        resp.raise_for_status()
        cards = resp.json()
        if isinstance(cards, dict) and "cards" in cards:
            cards = cards["cards"]
        logger.info(f"Fetched {len(cards)} card(s)")
        return cards
    except requests.RequestException as e:
        logger.error(f"Failed to fetch AVE cards: {e}")
        return []


def card_to_hec_event(card: dict) -> dict:
    """Transform an AVE card into a Splunk HEC event."""
    # Parse date for Splunk timestamp
    date_str = card.get("date_published", "")
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        epoch = dt.timestamp()
    except (ValueError, TypeError):
        epoch = time.time()

    return {
        "time": epoch,
        "sourcetype": "nail:ave",
        "index": "nail",
        "event": card,
    }


def send_to_hec(
    hec_url: str,
    hec_token: str,
    events: list[dict],
    verify_ssl: bool = True,
) -> bool:
    """Send events to Splunk HTTP Event Collector."""
    endpoint = f"{hec_url.rstrip('/')}/services/collector/event"
    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json",
    }

    # Batch events (Splunk HEC accepts newline-delimited JSON)
    payload = "\n".join(json.dumps(e) for e in events)

    try:
        resp = requests.post(
            endpoint,
            data=payload,
            headers=headers,
            verify=verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        if result.get("code") == 0:
            logger.info(f"Successfully sent {len(events)} event(s) to Splunk HEC")
            return True
        else:
            logger.error(f"HEC error: {result}")
            return False
    except requests.RequestException as e:
        logger.error(f"Failed to send to HEC: {e}")
        return False


def run_ingestion(
    hec_url: str,
    hec_token: str,
    nail_api: str,
    verify_ssl: bool = True,
) -> int:
    """Run a single ingestion cycle. Returns number of events sent."""
    state = load_state()
    since = state.get("last_sync")

    cards = fetch_ave_cards(nail_api, since=since)
    if not cards:
        logger.info("No new cards to ingest")
        return 0

    events = [card_to_hec_event(card) for card in cards]

    if send_to_hec(hec_url, hec_token, events, verify_ssl=verify_ssl):
        state["last_sync"] = datetime.now(timezone.utc).isoformat()
        state["cards_ingested"] = state.get("cards_ingested", 0) + len(events)
        save_state(state)
        return len(events)

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ingest NAIL AVE cards into Splunk via HEC"
    )
    parser.add_argument(
        "--hec-url",
        required=True,
        help="Splunk HEC URL (e.g., https://your-splunk:8088)",
    )
    parser.add_argument(
        "--hec-token",
        required=True,
        help="Splunk HEC token",
    )
    parser.add_argument(
        "--nail-api",
        default=DEFAULT_NAIL_API,
        help=f"NAIL API base URL (default: {DEFAULT_NAIL_API})",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=0,
        help="Continuous polling interval in seconds (0 = single run)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL verification (for dev environments)",
    )
    parser.add_argument(
        "--reset-state",
        action="store_true",
        help="Reset ingestion state (full re-sync)",
    )

    args = parser.parse_args()

    if args.reset_state and STATE_FILE.exists():
        STATE_FILE.unlink()
        logger.info("Ingestion state reset")

    verify = not args.no_verify_ssl

    if args.poll_interval > 0:
        logger.info(f"Starting continuous ingestion (interval: {args.poll_interval}s)")
        while True:
            run_ingestion(args.hec_url, args.hec_token, args.nail_api, verify)
            time.sleep(args.poll_interval)
    else:
        count = run_ingestion(args.hec_url, args.hec_token, args.nail_api, verify)
        logger.info(f"Ingestion complete: {count} event(s) sent")
        sys.exit(0 if count >= 0 else 1)


if __name__ == "__main__":
    main()
