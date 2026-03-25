#!/usr/bin/env python3
"""NAIL Institute API — Python Quick Start

This example demonstrates basic usage of the NAIL API v2.
Replace YOUR_API_KEY with your actual API key.
"""

import os
import httpx

BASE_URL = "https://api.nailinstitute.org/v2"
API_KEY = os.getenv("NAIL_API_KEY", "YOUR_API_KEY")

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
}


def list_cards():
    """List all AVE cards with pagination."""
    resp = httpx.get(f"{BASE_URL}/cards", headers=headers, params={"per_page": 5})
    resp.raise_for_status()
    data = resp.json()
    print(f"Total cards: {data['pagination']['total']}")
    for card in data["cards"]:
        print(f"  {card['ave_id']}: {card['name']} [{card['severity']}]")


def search_cards(query: str):
    """Search cards by keyword."""
    resp = httpx.get(
        f"{BASE_URL}/cards",
        headers=headers,
        params={"q": query, "sort": "severity", "order": "desc"},
    )
    resp.raise_for_status()
    data = resp.json()
    print(f"\nSearch results for '{query}':")
    for card in data["cards"]:
        print(f"  {card['ave_id']}: {card['name']}")


def get_card(ave_id: str):
    """Get detailed card information."""
    resp = httpx.get(f"{BASE_URL}/cards/{ave_id}", headers=headers)
    resp.raise_for_status()
    card = resp.json()
    print(f"\n{card['ave_id']}: {card['name']}")
    print(f"  Category: {card['category']}")
    print(f"  Severity: {card['severity']}")
    print(f"  Summary: {card['summary'][:200]}...")


def get_stats():
    """Get database statistics."""
    resp = httpx.get(f"{BASE_URL}/stats", headers=headers)
    resp.raise_for_status()
    stats = resp.json()
    print(f"\nDatabase Statistics:")
    print(f"  Total cards: {stats['total_cards']}")
    print(f"  Categories: {len(stats['by_category'])}")
    for sev, count in stats["by_severity"].items():
        print(f"  {sev}: {count}")


def check_usage():
    """Check API usage stats."""
    resp = httpx.get(f"{BASE_URL}/auth/usage", headers=headers)
    resp.raise_for_status()
    usage = resp.json()
    print(f"\nAPI Usage:")
    print(f"  Plan: {usage['plan']}")
    print(f"  Used: {usage['requests_used']}/{usage['requests_limit']}")
    print(f"  Remaining: {usage['requests_remaining']}")


if __name__ == "__main__":
    print("=== NAIL Institute API — Python Quick Start ===\n")
    list_cards()
    search_cards("prompt injection")
    get_card("AVE-2024-001")
    get_stats()
    check_usage()
