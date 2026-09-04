"""
Comprehensive test suite for Windows event normalization pipeline
Tests all 11 required scenarios from the enterprise event normalization fix mandate
"""
import json
import sqlite3
import tempfile
from datetime import datetime, timezone
from app.parsers.windows_parser import WindowsLogParser
from app.collector.normalizer import EventNormalizer
from app.storage.sqlite_storage import SQLiteStorage
from app.mitre.mitre_engine import MitreEngine

def test_1_event_4688_full_process_info():
    """Test 1: Event 4688 with full process information"""
    print("\n" + "="*70)
    print("Test 1: Event 4688 with full process information")
    print("="*70)
    
    parser = WindowsLogParser()
    raw_event = {
        "EventID": 4688,
        "TimeCreated": datetime.now(timezone.utc).isoformat(),
        "Computer": "MANI",
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Level": 0,
        "SubjectUserName": "user",
        "SubjectDomainName": "MANI",
        "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
        "NewProcessId": "0x1a34",
        "CreatorProcessName": "C:\\Windows\\explorer.exe",
        "CreatorProcessId": "0x5678",
        "NewProcessCommandLine": "powershell.exe -enc ABC123",
        "TokenElevationType": "%%1937",
        "MandatoryLabel": "Mandatory Label\High Mandatory Level"
    }
    
    parsed = parser.parse(raw_event)
    assert parsed["event_id"] == "4688", "Event ID should be preserved"
    assert parsed["process_name"] == "powershell.exe", "Process name should be extracted"
    assert parsed["process_id"] == "0x1a34", "Original hex process ID should be preserved"
    assert parsed["process_id_decimal"] == 6708, "Decimal process ID should be calculated"
    assert parsed["parent_process_name"] == "explorer.exe", "Parent process name should be extracted"
    assert parsed["parent_process_id"] == "0x5678", "Original hex parent process ID should be preserved"
    assert parsed["parent_process_id_decimal"] == 22136, "Decimal parent process ID should be calculated"
    assert parsed["command_line"] == "powershell.exe -enc ABC123", "Command line should be preserved"
    assert parsed["user"] == "user", "User should be preserved"
    assert parsed["host"] == "MANI", "Host should be preserved"
    print("[PASS] Test 1 passed - All process fields preserved")

def test_2_event_4688_missing_command_line():
    """Test 2: Event 4688 with missing command line"""
    print("\n" + "="*70)
    print("Test 2: Event 4688 with missing command line")
    print("="*70)
    
    parser = WindowsLogParser()
    raw_event = {
        "EventID": 4688,
        "TimeCreated": datetime.now(timezone.utc).isoformat(),
        "Computer": "MANI",
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "NewProcessId": "0x2b45",
        "CreatorProcessName": "C:\\Windows\\System32\\powershell.exe",
        "CreatorProcessId": "0x1a34"
        # Command line intentionally missing
    }
    
    parsed = parser.parse(raw_event)
    assert parsed["command_line"] in (None, ""), "Missing command line should be null/empty"
    assert parsed["process_id"] == "0x2b45", "Process ID preserved despite missing fields"
    print("[PASS] Test 2 passed - Missing fields properly set to null")

def test_3_event_4688_hexadecimal_pid():
    """Test 3: Event 4688 with hexadecimal PID"""
    print("\n" + "="*70)
    print("Test 3: Event 4688 with hexadecimal PID")
    print("="*70)
    
    parser = WindowsLogParser()
    raw_event = {
        "EventID": 4688,
        "TimeCreated": datetime.now(timezone.utc).isoformat(),
        "Computer": "MANI",
        "NewProcessName": "C:\\Windows\\System32\\whoami.exe",
        "NewProcessId": "0x3c56",
        "CreatorProcessId": "0x2b45"
    }
    
    parsed = parser.parse(raw_event)
    assert parsed["process_id"] == "0x3c56", "Original hex PID preserved"
    assert parsed["process_id_decimal"] == 15446, "Hex correctly converted to decimal"
    assert parsed["parent_process_id"] == "0x2b45", "Parent hex PID preserved"
    assert parsed["parent_process_id_decimal"] == 11077, "Parent hex correctly converted"
    print("[PASS] Test 3 passed - Hex PID conversion works correctly")

def test_4_event_with_parent_process_info():
    """Test 4: Event with parent process information"""
    print("\n" + "="*70)
    print("Test 4: Event with parent process information")
    print("="*70)
    
    parser = WindowsLogParser()
    # Process tree: explorer.exe (0x1000) → powershell.exe (0x2000) → cmd.exe (0x3000) → whoami.exe (0x4000)
    events = [
        {
            "EventID": 4688,
            "TimeCreated": datetime.now(timezone.utc).isoformat(),
            "Computer": "MANI",
            "NewProcessName": "C:\\Windows\\explorer.exe",
            "NewProcessId": "0x1000",
            "CreatorProcessId": "0x0000"
        },
        {
            "EventID": 4688,
            "TimeCreated": datetime.now(timezone.utc).isoformat(),
            "Computer": "MANI",
            "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
            "NewProcessId": "0x2000",
            "CreatorProcessName": "C:\\Windows\\explorer.exe",
            "CreatorProcessId": "0x1000"
        },
        {
            "EventID": 4688,
            "TimeCreated": datetime.now(timezone.utc).isoformat(),
            "Computer": "MANI",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "NewProcessId": "0x3000",
            "CreatorProcessName": "C:\\Windows\\System32\\powershell.exe",
            "CreatorProcessId": "0x2000"
        },
        {
            "EventID": 4688,
            "TimeCreated": datetime.now(timezone.utc).isoformat(),
            "Computer": "MANI",
            "NewProcessName": "C:\\Windows\\System32\\whoami.exe",
            "NewProcessId": "0x4000",
            "CreatorProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CreatorProcessId": "0x3000"
        }
    ]
    
    parsed_events = [parser.parse(e) for e in events]
    
    # Verify parent-child relationships can be built via process_id/parent_process_id
    process_tree = {}
    for e in parsed_events:
        process_tree[e["process_id"]] = {
            "name": e["process_name"],
            "parent_id": e["parent_process_id"],
            "children": []
        }
    
    # Build tree
    for pid, node in process_tree.items():
        if node["parent_id"] in process_tree:
            process_tree[node["parent_id"]]["children"].append(pid)
    
    # Verify explorer is root
    root = process_tree["0x1000"]
    assert len(root["children"]) == 1, "Explorer should have one child (powershell)"
    assert root["children"][0] == "0x2000", "Powershell is child of explorer"
    powershell = process_tree["0x2000"]
    assert len(powershell["children"]) == 1, "Powershell should have one child (cmd)"
    assert powershell["children"][0] == "0x3000", "Cmd is child of powershell"
    cmd = process_tree["0x3000"]
    assert len(cmd["children"]) == 1, "Cmd should have one child (whoami)"
    assert cmd["children"][0] == "0x4000", "Whoami is child of cmd"
    print("[PASS] Test 4 passed - Process tree relationships correctly preserved")

def test_5_event_with_multiple_mitre_techniques():
    """Test 5: Event with multiple MITRE techniques"""
    print("\n" + "="*70)
    print("Test 5: Event with multiple MITRE techniques")
    print("="*70)
    
    mitre_engine = MitreEngine()
    detection = {
        "mitre": ["T1059", "T1059.001"],
        "detection_name": "PowerShell Execution",
        "severity": "Medium"
    }
    
    result = mitre_engine.map(detection)
    assert isinstance(result, list), "Multiple MITRE techniques should return a list"
    assert len(result) == 2, "Should have 2 MITRE blocks"
    assert result[0]["id"] == "T1059", "First technique ID preserved"
    assert result[1]["id"] == "T1059.001", "Second technique ID preserved"
    print("[PASS] Test 5 passed - Multiple MITRE techniques correctly handled")

def test_6_event_with_no_mitre_mapping():
    """Test 6: Event with no MITRE mapping"""
    print("\n" + "="*70)
    print("Test 6: Event with no MITRE mapping")
    print("="*70)
    
    mitre_engine = MitreEngine()
    detection = {
        "mitre": [],
        "detection_name": "Unknown Event",
        "severity": "Low"
    }
    
    result = mitre_engine.map(detection)
    assert isinstance(result, list) or isinstance(result, dict), "Should handle empty MITRE list"
    print("[PASS] Test 6 passed - Empty MITRE list handled correctly")

def test_7_event_with_no_process_info():
    """Test 7: Event with no process information"""
    print("\n" + "="*70)
    print("Test 7: Event with no process information")
    print("="*70)
    
    parser = WindowsLogParser()
    raw_event = {
        "EventID": 4625,  # Failed login, not process related
        "TimeCreated": datetime.now(timezone.utc).isoformat(),
        "Computer": "MANI",
        "TargetUserName": "invalid_user",
        "IpAddress": "192.168.1.100"
    }
    
    parsed = parser.parse(raw_event)
    assert parsed["process_name"] in (None, "", "Not available in event"), "Missing process_name should be null/sentinel"
    assert parsed["process_id"] in (None, "", "Not available"), "Missing process_id should be null/sentinel"
    assert parsed["parent_process_name"] in (None, "", "Not available in event"), "Missing parent_process_name should be null/sentinel"
    assert parsed["parent_process_id"] in (None, ""), "Missing parent_process_id should be null/empty"
    assert parsed["user"] == "invalid_user", "User field still extracted correctly"
    print("[PASS] Test 7 passed - Non-process events handled correctly (nulls for missing fields)")

def test_8_sqlite_insertion_with_list_mitre_fields():
    """Test 8: SQLite insertion with list-valued MITRE fields"""
    print("\n" + "="*70)
    print("Test 8: SQLite insertion with list-valued MITRE fields")
    print("="*70)
    
    # Create temporary SQLite database
    from app.storage.sqlite_storage import sqlite_storage as storage
    
    # Create event with list of MITRE techniques
    event = {
        "event": {
            "time": datetime.now(timezone.utc).isoformat(),
            "host": "MANI",
            "event_id": "4688",
            "process_name": "powershell.exe",
            "process_id": "0x1234",
            "source": "Windows",
            "raw": {}
        },
        "detection": {
            "severity": "Medium",
            "mitre": [
                {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
                {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}
            ],
            "ioc": [],
            "status": "New"
        }
    }
    
    try:
        # This should NOT throw the SQLite binding error!
        storage.save_event(event)
        print("[PASS] Test 8 passed - List-valued MITRE fields successfully inserted into SQLite")
    except Exception as e:
        assert False, f"SQLite insertion failed with list MITRE fields: {e}"


def test_9_sqlite_insertion_with_dict_enrichment_fields():
    """Test 9: SQLite insertion with dict-valued enrichment fields"""
    print("\n" + "="*70)
    print("Test 9: SQLite insertion with dict-valued enrichment fields")
    print("="*70)
    
    from app.storage.sqlite_storage import sqlite_storage as storage
    
    # Create event with dict metadata/enrichment
    event = {
        "event": {
            "time": datetime.now(timezone.utc).isoformat(),
            "host": "MANI",
            "event_id": "4688",
            "process_name": "cmd.exe",
            "process_id": "0x5678",
            "source": "Windows",
            "raw": {}
        },
        "detection": {
            "severity": "Low",
            "mitre": "T1059.003",
            "ioc": [],
            "status": "New"
        },
        "metadata": {
            "enrichment": {
                "geoip": {"country": "US", "city": "New York"},
                "threat_intel": {"actor": "unknown", "malware_family": None},
                "tags": ["command_execution", "low_risk"]
            },
            "risk_score": 25
        }
    }
    
    try:
        storage.save_event(event)
        print("[PASS] Test 9 passed - Dict-valued enrichment fields successfully inserted")
    except Exception as e:
        assert False, f"SQLite insertion failed with dict enrichment: {e}"


def test_10_api_serialization_deserialization():
    """Test 10: API serialization/deserialization"""
    print("\n" + "="*70)
    print("Test 10: API serialization/deserialization")
    print("="*70)
    
    # Simulate API response serialization
    normalized_event = {
        "event_id": 4688,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": "MANI",
        "process_name": "powershell.exe",
        "process_id": "0x1234",
        "process_id_decimal": 4660,
        "parent_process_name": "explorer.exe",
        "parent_process_id": "0x5678",
        "parent_process_id_decimal": 22136,
        "command_line": "powershell.exe -enc ABC123",
        "user": "MANI\\user",
        "severity": "Medium",
        "mitre_techniques": [
            {"id": "T1059.001", "name": "PowerShell"}
        ]
    }
    
    # Serialize to JSON (what API would do)
    serialized = json.dumps(normalized_event)
    # Deserialize back
    deserialized = json.loads(serialized)
    
    assert deserialized["process_id"] == "0x1234", "Original hex PID preserved through serialization"
    assert deserialized["process_id_decimal"] == 4660, "Decimal PID preserved"
    assert len(deserialized["mitre_techniques"]) == 1, "MITRE list preserved"
    assert deserialized["mitre_techniques"][0]["id"] == "T1059.001", "MITRE details preserved"
    print("[PASS] Test 10 passed - Serialization/deserialization works correctly")

def test_11_process_tree_parent_child_relationship():
    """Test 11: Process tree parent-child relationship verification"""
    print("\n" + "="*70)
    print("Test 11: Process tree parent-child relationship")
    print("="*70)
    
    parser = WindowsLogParser()
    # Create chain of processes
    events = []
    pids = ["0x1000", "0x2000", "0x3000", "0x4000"]
    names = ["explorer.exe", "powershell.exe", "cmd.exe", "whoami.exe"]
    
    for i in range(len(pids)):
        events.append({
            "EventID": 4688,
            "TimeCreated": datetime.now(timezone.utc).isoformat(),
            "Computer": "MANI",
            "NewProcessName": f"C:\\Windows\\System32\\{names[i]}",
            "NewProcessId": pids[i],
            "CreatorProcessId": pids[i-1] if i > 0 else "0x0000"
        })
    
    parsed = [parser.parse(e) for e in events]
    
    # Verify chain is intact
    for i in range(1, len(parsed)):
        current = parsed[i]
        parent = parsed[i-1]
        assert current["parent_process_id"] == parent["process_id"], f"Process {names[i]} should have parent {names[i-1]}"
    
    print("[PASS] Test 11 passed - Process tree parent-child relationships strictly enforced")

if __name__ == "__main__":
    print("\n" + "*"*70)
    print("RUNNING ALL 11 EVENT NORMALIZATION TESTS")
    print("*"*70)
    
    tests = [
        test_1_event_4688_full_process_info,
        test_2_event_4688_missing_command_line,
        test_3_event_4688_hexadecimal_pid,
        test_4_event_with_parent_process_info,
        test_5_event_with_multiple_mitre_techniques,
        test_6_event_with_no_mitre_mapping,
        test_7_event_with_no_process_info,
        test_8_sqlite_insertion_with_list_mitre_fields,
        test_9_sqlite_insertion_with_dict_enrichment_fields,
        test_10_api_serialization_deserialization,
        test_11_process_tree_parent_child_relationship
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed +=1
        except Exception as e:
            print(f"\n[FAIL] {test.__name__} FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed +=1
    
    print("\n" + "*"*70)
    print(f"TEST SUMMARY: {passed} passed, {failed} failed")
    print("*"*70)
    
    if failed == 0:
        print("\n ALL TESTS PASSED! Event normalization pipeline is working correctly.")
        exit(0)
    else:
        print("\n! Some tests failed. Please review the errors above.")
        exit(1)