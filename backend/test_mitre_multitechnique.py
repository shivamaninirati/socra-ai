"""
Test script to verify multi-technique MITRE mapping functionality
Tests both single and multiple MITRE IDs to ensure backward compatibility
"""
from app.mitre.mitre_engine import MitreEngine
from app.registry.windows_event_registry import build_mitre_block, resolve_mitre

def test_build_mitre_block():
    print("=" * 70)
    print("Testing build_mitre_block function...")
    print("=" * 70)

    # Test 1: Single MITRE ID (backward compatibility)
    print("\n1. Testing single MITRE ID: T1059.001")
    single_block = build_mitre_block("T1059.001", "PowerShell Execution", "High")
    print(f"   Result type: {type(single_block)}")
    print(f"   Block: {single_block}")
    assert isinstance(single_block, dict), "Single MITRE ID should return a dict"
    assert single_block["id"] == "T1059.001", "Single ID should be preserved"
    print("   ✓ Single MITRE ID test passed")

    # Test 2: Multiple MITRE IDs (new functionality)
    print("\n2. Testing multiple MITRE IDs: ['T1059.001', 'T1059.003']")
    multi_blocks = build_mitre_block(["T1059.001", "T1059.003"], "Command Execution", "Critical")
    print(f"   Result type: {type(multi_blocks)}")
    print(f"   Number of blocks: {len(multi_blocks)}")
    for i, block in enumerate(multi_blocks):
        print(f"   Block {i+1}: {block}")
    assert isinstance(multi_blocks, list), "Multiple MITRE IDs should return a list"
    assert len(multi_blocks) == 2, "Should return 2 blocks for 2 IDs"
    assert multi_blocks[0]["id"] == "T1059.001", "First ID should be preserved"
    assert multi_blocks[1]["id"] == "T1059.003", "Second ID should be preserved"
    print("   ✓ Multiple MITRE IDs test passed")

    # Test 3: Unmapped MITRE ID
    print("\n3. Testing unmapped MITRE ID: 'Unknown'")
    unmapped_block = build_mitre_block("Unknown", "Unknown Event", "Informational")
    print(f"   Result: {unmapped_block}")
    assert unmapped_block["id"] == "Unmapped", "Unknown ID should be 'Unmapped'"
    print("   ✓ Unmapped MITRE ID test passed")

    # Test 4: Multiple IDs including one unknown
    print("\n4. Testing mixed IDs: ['T1070.001', 'Unknown']")
    mixed_blocks = build_mitre_block(["T1070.001", "Unknown"], "Event Log Clearing", "High")
    print(f"   Result type: {type(mixed_blocks)}")
    print(f"   Number of blocks: {len(mixed_blocks)}")
    for i, block in enumerate(mixed_blocks):
        print(f"   Block {i+1}: {block}")
    assert isinstance(mixed_blocks, list), "Mixed IDs should return a list"
    assert len(mixed_blocks) == 2, "Should return 2 blocks for 2 IDs"
    assert mixed_blocks[0]["id"] == "T1070.001", "Valid ID should be preserved"
    assert mixed_blocks[1]["id"] == "Unmapped", "Unknown ID should be 'Unmapped'"
    print("   ✓ Mixed IDs test passed")

def test_mitre_engine_map():
    print("\n" + "=" * 70)
    print("Testing MitreEngine.map() function...")
    print("=" * 70)

    mitre_engine = MitreEngine()

    # Test 1: Detection with single MITRE ID (backward compatibility)
    print("\n1. Testing detection with single MITRE dict:")
    detection_single = {
        "mitre": {"id": "T1059.001"},
        "detection": "PowerShell Execution",
        "severity": "High"
    }
    result_single = mitre_engine.map(detection_single)
    print(f"   Result type: {type(result_single)}")
    print(f"   Result: {result_single}")
    assert isinstance(result_single, list), "Engine should always return a list"
    assert len(result_single) == 1, "Single ID should return 1 block"
    assert result_single[0]["id"] == "T1059.001", "ID should be preserved"
    print("   ✓ Single MITRE dict test passed")

    # Test 2: Detection with multiple MITRE IDs as strings
    print("\n2. Testing detection with list of MITRE IDs:")
    detection_multi_str = {
        "mitre": ["T1059.001", "T1059.003"],
        "detection": "Command Execution",
        "severity": "Critical"
    }
    result_multi_str = mitre_engine.map(detection_multi_str)
    print(f"   Result type: {type(result_multi_str)}")
    print(f"   Number of blocks: {len(result_multi_str)}")
    for i, block in enumerate(result_multi_str):
        print(f"   Block {i+1}: {block}")
    assert isinstance(result_multi_str, list), "Engine should return a list"
    assert len(result_multi_str) == 2, "Should return 2 blocks for 2 IDs"
    print("   ✓ List of MITRE IDs test passed")

    # Test 3: Detection with multiple MITRE dicts
    print("\n3. Testing detection with list of MITRE dicts:")
    detection_multi_dict = {
        "mitre": [
            {"id": "T1059.001", "tactic": "Execution", "technique": "PowerShell"},
            {"id": "T1059.003", "tactic": "Execution", "technique": "Windows Command Shell"}
        ],
        "detection": "Multiple Command Techniques",
        "severity": "Critical"
    }
    result_multi_dict = mitre_engine.map(detection_multi_dict)
    print(f"   Result type: {type(result_multi_dict)}")
    print(f"   Number of blocks: {len(result_multi_dict)}")
    for i, block in enumerate(result_multi_dict):
        print(f"   Block {i+1}: {block}")
    assert isinstance(result_multi_dict, list), "Engine should return a list"
    assert len(result_multi_dict) == 2, "Should return 2 blocks for 2 dicts"
    print("   ✓ List of MITRE dicts test passed")

    # Test 4: Detection with no MITRE data (should map from detection name)
    print("\n4. Testing detection with no MITRE data:")
    detection_none = {
        "detection": "Unknown Detection",
        "severity": "Low"
    }
    result_none = mitre_engine.map(detection_none)
    print(f"   Result type: {type(result_none)}")
    print(f"   Result: {result_none}")
    assert isinstance(result_none, list), "Engine should always return a list"
    assert len(result_none) == 1, "Should return 1 block for no IDs"
    assert result_none[0]["id"] == "Unmapped", "Unknown detection should be unmapped"
    print("   ✓ No MITRE data test passed")

    # Test 5: Detection with empty MITRE string
    print("\n5. Testing detection with empty MITRE string:")
    detection_empty = {
        "mitre": "",
        "detection": "Empty MITRE Event",
        "severity": "Informational"
    }
    result_empty = mitre_engine.map(detection_empty)
    print(f"   Result: {result_empty}")
    assert isinstance(result_empty, list), "Engine should return a list"
    assert result_empty[0]["id"] == "Unmapped", "Empty string should be unmapped"
    print("   ✓ Empty MITRE string test passed")

if __name__ == "__main__":
    print("Running MITRE multi-technique validation tests...")
    test_build_mitre_block()
    test_mitre_engine_map()
    print("\n" + "=" * 70)
    print("✅ ALL TESTS PASSED! Multi-technique MITRE mapping is working correctly.")
    print("=" * 70)