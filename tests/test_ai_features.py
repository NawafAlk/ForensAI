"""
Test script for ForensAI AI features.

This script tests:
1. AI service connectivity to Groq
2. File artifact explanation
3. Notes storage and retrieval
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from managers.ai_service import get_ai_service
from managers.notes_manager import get_notes_manager, Note


def test_ai_service():
    """Test AI service connectivity and basic explanation."""
    print("=" * 60)
    print("Testing AI Service")
    print("=" * 60)

    ai_service = get_ai_service()

    # Check if Groq is available
    print("\n1. Checking Groq API connectivity...")
    if ai_service.is_available():
        print("   [OK] Groq API is accessible")
    else:
        print("   [ERROR] Cannot connect to Groq API")
        print("\n   Please ensure:")
        print("   - Your Groq API key is configured in Options > API Keys")
        print("   - Get a free key at https://console.groq.com")
        return False

    # Test file explanation
    print("\n2. Testing file artifact explanation...")
    test_file = {
        'name': 'pagefile.sys',
        'path': 'C:\\pagefile.sys',
        'type': 'file',
        'mime_type': 'application/octet-stream',
        'size': 4294967296,  # 4GB
        'created': '2025-01-15 08:23:14 UTC',
        'modified': '2025-01-20 14:32:45 UTC',
        'accessed': '2025-01-20 14:32:45 UTC',
        'md5': '5d41402abc4b2a76b9719d911017c592',
        'sha256': '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
    }

    print(f"   Analyzing: {test_file['name']}")
    print("   (This may take 10-30 seconds on first run while model loads...)")

    explanation = ai_service.explain_file_artifact(test_file)

    print("\n   AI Explanation:")
    print("   " + "-" * 56)
    for line in explanation.split('\n'):
        print(f"   {line}")
    print("   " + "-" * 56)

    if "error" in explanation.lower() or len(explanation) < 20:
        print("\n   [ERROR] Explanation seems invalid")
        return False

    print("\n   [OK] Explanation generated successfully")
    return True


def test_notes_manager():
    """Test notes storage and retrieval."""
    print("\n" + "=" * 60)
    print("Testing Notes Manager")
    print("=" * 60)

    notes_mgr = get_notes_manager()

    # Test adding a note
    print("\n1. Creating test note...")
    test_note = Note(
        artifact_type='file',
        artifact_id='12345@2048',
        artifact_name='test.exe',
        content='This is a test AI-generated explanation.',
        ai_generated=True,
        edited=False
    )

    note_id = notes_mgr.add_note(test_note)
    print(f"   [OK] Note created with ID: {note_id}")

    # Test retrieving the note
    print("\n2. Retrieving note...")
    retrieved = notes_mgr.get_note_for_artifact('file', '12345@2048')

    if retrieved:
        print(f"   [OK] Note retrieved successfully")
        print(f"      Artifact: {retrieved.artifact_name}")
        print(f"      Content: {retrieved.content[:50]}...")
    else:
        print("   [ERROR] Failed to retrieve note")
        return False

    # Test getting all notes
    print("\n3. Getting all notes...")
    all_notes = notes_mgr.get_all_notes()
    print(f"   [OK] Found {len(all_notes)} note(s) in database")

    # Clean up
    print("\n4. Cleaning up test data...")
    notes_mgr.delete_note(note_id)
    print("   [OK] Test note deleted")

    return True


def main():
    """Run all tests."""
    print("\n")
    print("+" + "=" * 58 + "+")
    print("|" + " " * 12 + "ForensAI AI Features Test Suite" + " " * 14 + "|")
    print("+" + "=" * 58 + "+")

    success = True

    # Test AI service
    if not test_ai_service():
        success = False

    # Test notes manager
    if not test_notes_manager():
        success = False

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)

    if success:
        print("\n[SUCCESS] All tests passed!")
        print("\nYou can now use AI features in ForensAI:")
        print("  1. Load an evidence image")
        print("  2. Select a file")
        print("  3. Go to 'File Metadata' tab")
        print("  4. Click 'Explain This Artifact' button")
    else:
        print("\n[FAILED] Some tests failed")
        print("\nPlease check the errors above and:")
        print("  1. Ensure Groq API key is configured in Options > API Keys")
        print("  2. Get a free key at https://console.groq.com")
        print("  3. Check for any error messages")

    print("\n")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
