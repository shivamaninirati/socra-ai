#!/usr/bin/env python3
"""
Backfill script to add today's existing HIGH/CRITICAL events to the notifications table.
Uses idempotent deduplication to avoid duplicates. Preserves existing user read states.
"""
import sys
import os
from datetime import datetime, timezone
from typing import Dict, Any

# Add the backend directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from app.storage.storage_manager import storage_manager
from app.storage.sqlite_storage import sqlite_storage

def _compute_fingerprint(event_data: Dict[str, Any]) -> str:
    """Compute stable fingerprint from event identity fields - matches sqlite_storage.py"""
    import hashlib
    import json
    
    host = event_data.get("host", "") or event_data.get("event", {}).get("host", "") or event_data.get("event", {}).get("computer", "")
    event_id = str(event_data.get("event_id", "") or event_data.get("event", {}).get("event_id", ""))
    time = event_data.get("time", "") or event_data.get("event", {}).get("time", "")
    process_name = event_data.get("process_name", "") or event_data.get("event", {}).get("process_name", "")
    
    fingerprint_data = {
        "host": host.strip(),
        "event_id": event_id.strip(),
        "time": time.strip(),
        "process_name": process_name.strip()
    }
    
    return hashlib.sha256(json.dumps(fingerprint_data, sort_keys=True).encode()).hexdigest()

def backfill_todays_notifications():
    """Backfill today's HIGH/CRITICAL events into notifications table"""
    print("[Backfill] Starting notification backfill...")
    
    # Get today's start time in ISO format
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ).isoformat().replace("+00:00", "Z")
    
    # Get all users first
    users = storage_manager.get_all_users()
    if not users:
        print("[Backfill] No users found in database")
        return False
    
    print(f"[Backfill] Found {len(users)} users to process")
    
    # Get all today's events from events table
    with sqlite3.connect(sqlite_storage.db_path, timeout=sqlite_storage.sqlite_timeout) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM events 
            WHERE event_time >= ? 
            AND severity IN ('Critical', 'High', 'critical', 'high', 'CRITICAL', 'HIGH')
            ORDER BY event_time DESC
        """, (today_start,))
        events = cursor.fetchall()
    
    print(f"[Backfill] Found {len(events)} today's HIGH/CRITICAL events to process")
    
    LEGACY_SHARED_USER_ID = "legacy_shared_admin"
    created_count = 0
    skipped_count = 0
    
    for event_row in events:
        event_dict = dict(event_row)
        
        # Normalize severity
        severity = (event_dict.get("severity") or "").strip().capitalize()
        if severity not in {"Critical", "High"}:
            skipped_count += 1
            continue
        
        # Prepare normalized event data matching what _create_alert_notifications sends
        normalized_event = {
            "event": {
                "host": event_dict.get("host"),
                "computer": event_dict.get("computer"),
                "process_name": event_dict.get("process_name"),
                "process_id": event_dict.get("process_id"),
                "event_id": event_dict.get("event_id"),
                "time": event_dict.get("event_time") or event_dict.get("created_at")
            },
            "detection": {
                "severity": severity,
                "detection": event_dict.get("title") or event_dict.get("description"),
                "description": event_dict.get("description"),
                "mitre": event_dict.get("mitre")
            },
            "metadata": {
                "fingerprint": event_dict.get("fingerprint")
            },
            "_id": event_dict.get("id"),
            "id": event_dict.get("id")
        }
        
        # Compute fingerprint if not present
        fingerprint = event_dict.get("fingerprint") or _compute_fingerprint(normalized_event)
        
        # Create notifications for all users
        for user in users:
            user_id = user.get("id")
            if not user_id:
                user_id = LEGACY_SHARED_USER_ID
            
            try:
                result = storage_manager.create_notification(user_id, normalized_event, fingerprint)
                if result:
                    created_count += 1
                else:
                    skipped_count += 1
            except Exception as e:
                print(f"[Backfill] Failed to create notification for user {user_id}: {e}")
                skipped_count += 1
    
    # Flush all writes to database
    storage_manager.history_store.flush(timeout=5.0)
    
    print(f"[Backfill] Complete! Created {created_count} new notifications, skipped {skipped_count} duplicates/invalid")
    return True

if __name__ == "__main__":
    import sqlite3
    success = backfill_todays_notifications()
    sys.exit(0 if success else 1)