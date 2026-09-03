"""
Mission 31 Part 4 — Empirical Verification Report Generator
------------------------------------------------------------
Inspects data/urlhaus_feed.json and data/threatfox_feed.json on disk,
reads HTTP status codes, real record counts, file metadata, and outputs 2 raw entries verbatim.
"""

import os
import sys
import json
import urllib.request
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
URLHAUS_PATH = os.path.join(DATA_DIR, "urlhaus_feed.json")
THREATFOX_PATH = os.path.join(DATA_DIR, "threatfox_feed.json")


def verify_feeds():
    print("=" * 70)
    print("MISSION 31 PART 4 — EMPIRICAL FEED VERIFICATION REPORT")
    print("=" * 70)

    # 1. URLhaus Feed Verification
    print("\n[1] VERIFYING URLHAUS MALWARE FEED (urlhaus.abuse.ch)...")
    urlhaus_url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    uh_status = None
    try:
        req = urllib.request.Request(urlhaus_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            uh_status = resp.getcode()
    except Exception as exc:
        uh_status = str(exc)

    print(f"  HTTP Endpoint: GET {urlhaus_url}")
    print(f"  HTTP Status Code: {uh_status}")
    print(f"  Cache File Path:  {URLHAUS_PATH}")
    print(f"  File Exists:      {os.path.exists(URLHAUS_PATH)}")

    uh_data = {}
    if os.path.exists(URLHAUS_PATH):
        stat = os.stat(URLHAUS_PATH)
        mtime = datetime.fromtimestamp(stat.st_mtime).isoformat()
        print(f"  File Size:        {stat.st_size / 1024 / 1024:.2f} MB ({stat.st_size} bytes)")
        print(f"  File Modified:    {mtime}")
        with open(URLHAUS_PATH, "r", encoding="utf-8") as f:
            uh_data = json.load(f)

    uh_count = uh_data.get("count", 0)
    uh_timestamp = uh_data.get("last_cached_at", "N/A")
    uh_samples = uh_data.get("urls", [])[:2]

    print(f"  Last Cached At:   {uh_timestamp}")
    print(f"  Total Record Count: {uh_count} Malicious URLs")
    print("\n  Raw Verbatim Entry #1 (URLhaus):")
    print(json.dumps(uh_samples[0] if len(uh_samples) > 0 else {}, indent=2))
    print("\n  Raw Verbatim Entry #2 (URLhaus):")
    print(json.dumps(uh_samples[1] if len(uh_samples) > 1 else {}, indent=2))

    # 2. ThreatFox Feed Verification
    print("\n" + "=" * 70)
    print("[2] VERIFYING THREATFOX IOC FEED (threatfox.abuse.ch)...")
    threatfox_url = "https://threatfox.abuse.ch/export/json/recent/"
    tf_status = None
    try:
        req = urllib.request.Request(threatfox_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            tf_status = resp.getcode()
    except Exception as exc:
        tf_status = str(exc)

    print(f"  HTTP Endpoint: GET {threatfox_url}")
    print(f"  HTTP Status Code: {tf_status}")
    print(f"  Cache File Path:  {THREATFOX_PATH}")
    print(f"  File Exists:      {os.path.exists(THREATFOX_PATH)}")

    tf_data = {}
    if os.path.exists(THREATFOX_PATH):
        stat = os.stat(THREATFOX_PATH)
        mtime = datetime.fromtimestamp(stat.st_mtime).isoformat()
        print(f"  File Size:        {stat.st_size / 1024 / 1024:.2f} MB ({stat.st_size} bytes)")
        print(f"  File Modified:    {mtime}")
        with open(THREATFOX_PATH, "r", encoding="utf-8") as f:
            tf_data = json.load(f)

    tf_count = tf_data.get("count", 0)
    tf_timestamp = tf_data.get("last_cached_at", "N/A")
    tf_samples = tf_data.get("iocs", [])[:2]

    print(f"  Last Cached At:   {tf_timestamp}")
    print(f"  Total Record Count: {tf_count} IOC Indicators")
    print("\n  Raw Verbatim Entry #1 (ThreatFox):")
    print(json.dumps(tf_samples[0] if len(tf_samples) > 0 else {}, indent=2))
    print("\n  Raw Verbatim Entry #2 (ThreatFox):")
    print(json.dumps(tf_samples[1] if len(tf_samples) > 1 else {}, indent=2))
    print("=" * 70)

if __name__ == "__main__":
    verify_feeds()
