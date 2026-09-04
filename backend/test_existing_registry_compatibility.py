"""
Test to verify existing registry format is compatible with our new multi-technique MITRE mapping
Tests that all existing events with single MITRE dicts still work correctly
"""
from app.registry.windows_event_registry import WINDOWS_EVENT_RULES, build_mitre_block
from app.mitre.mitre_engine import MitreEngine

def test_existing_registry_events():
    print("=" * 70)
    print("Testing existing registry events compatibility...")
    print("=" * 70)

    mitre_engine = MitreEngine()
    success_count = 0
    failure_count = 0

    # Test a sample of existing events from the registry
    sample_event_ids = ["4688", "4625", "4697", "1102", "7045"]  # Mix of different events
    
    for event_id in sample_event_ids:
        rule = WINDOWS_EVENT_RULES.get(event_id)
        if not rule:
            print(f"\n❌ Event ID {event_id} not found in registry")
            failure_count += 1
            continue

        print(f"\nTesting Event ID {event_id}: {rule['name']}")
        print(f"   Original MITRE data: {rule['mitre']}")

        # Create a detection object like what would be passed to the engine
        detection = {
            "mitre": rule["mitre"],  # This is the original dict format
            "detection": rule["detection"],
            "severity": rule["severity"]
        }

        try:
            # Process with our updated MITRE engine
            result = mitre_engine.map(detection)
            print(f"   Processed result type: {type(result)}")
            print(f"   Number of MITRE blocks: {len(result)}")
            print(f"   First block: {result[0]}")

            # Verify the result is correct
            assert isinstance(result, list), "Engine should always return a list"
            assert len(result) >= 1, "Should return at least one block"
            assert result[0]["id"] == rule["mitre"]["id"] or (rule["mitre"]["id"] in ["N/A", "Unknown"] and result[0]["id"] == "Unmapped"), "Original MITRE ID should be preserved"
            
            print(f"   ✓ Event ID {event_id} processed successfully")
            success_count += 1
        except Exception as e:
            print(f"   ❌ Failed to process Event ID {event_id}: {str(e)}")
            failure_count += 1

    print("\n" + "=" * 70)
    print(f"Compatibility test summary: {success_count} passed, {failure_count} failed")
    if failure_count == 0:
        print("✅ All existing registry events are compatible with multi-technique MITRE mapping!")
    else:
        print("❌ Some events failed compatibility checks")
    print("=" * 70)

def test_build_mitre_block_with_existing_format():
    print("\n" + "=" * 70)
    print("Testing build_mitre_block with existing MITRE dict format...")
    print("=" * 70)

    # Simulate what happens when an existing MITRE dict is passed to build_mitre_block
    # This tests backward compatibility
    from app.registry.windows_event_registry import build_mitre_block
    
    # Test with a single MITRE ID string (original usage)
    result1 = build_mitre_block("T1059", "Process Creation", "Medium")
    print(f"Single ID string result: {result1}")
    assert isinstance(result1, dict), "Single ID string should still return a dict"
    
    # Test with what happens when engine passes a list with one ID (new usage)
    result2 = build_mitre_block(["T1059"], "Process Creation", "Medium")
    print(f"Single ID in list result: {result2}")
    assert isinstance(result2, list), "List with one ID should return a list"
    assert len(result2) == 1, "List with one ID should have one block"
    assert result2[0]["id"] == "T1059", "ID should be preserved"
    
    print("\n✅ Backward compatibility verified!")

if __name__ == "__main__":
    test_existing_registry_events()
    test_build_mitre_block_with_existing_format()