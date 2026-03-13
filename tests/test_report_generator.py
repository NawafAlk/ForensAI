"""
ForensAI - Forensic Report Generator Tests
==========================================
Basic tests for the forensic report generator module.
"""

import os
import sys
import tempfile
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.forensic_report_generator import (
    ForensicReportGenerator,
    HashVerifier,
    ChainOfCustodyEntry,
    ArtifactInfo,
    ProcessingStep
)


def test_hash_verifier():
    """Test hash computation functionality."""
    print("Testing HashVerifier...")

    # Create a temporary test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Test content for hash verification\n" * 100)
        temp_file = f.name

    try:
        # Compute hashes
        hashes = HashVerifier.compute_hashes(temp_file, ['md5', 'sha256'])

        # Verify results
        assert 'md5' in hashes, "MD5 hash missing"
        assert 'sha256' in hashes, "SHA256 hash missing"
        assert len(hashes['md5']) == 32, "MD5 hash wrong length"
        assert len(hashes['sha256']) == 64, "SHA256 hash wrong length"

        # Test verification
        match, results = HashVerifier.verify_hashes(temp_file, hashes)
        assert match, "Hash verification should match"
        assert all(results.values()), "All hashes should match"

        print("[PASS] HashVerifier tests passed")
        return True

    finally:
        # Cleanup
        if os.path.exists(temp_file):
            os.unlink(temp_file)


def test_chain_of_custody_entry():
    """Test chain of custody entry creation."""
    print("Testing ChainOfCustodyEntry...")

    entry = ChainOfCustodyEntry(
        action="Test action",
        actor="Test Actor",
        source="/test/source.dd",
        target="/test/target.iso",
        tools="Test Tool v1.0",
        hashes={'md5': 'abc123', 'sha256': 'def456'}
    )

    # Convert to dict
    entry_dict = entry.to_dict()

    # Verify fields
    assert entry_dict['action'] == "Test action"
    assert entry_dict['actor'] == "Test Actor"
    assert entry_dict['source'] == "/test/source.dd"
    assert entry_dict['target'] == "/test/target.iso"
    assert entry_dict['tools'] == "Test Tool v1.0"
    assert 'timestamp_utc' in entry_dict
    assert 'hostname' in entry_dict

    print("[PASS] ChainOfCustodyEntry tests passed")
    return True


def test_artifact_info():
    """Test artifact information structure."""
    print("Testing ArtifactInfo...")

    artifact = ArtifactInfo(
        path="/test/path/file.txt",
        name="file.txt",
        size=1024,
        artifact_type="document"
    )

    artifact.sha256 = "abc123"
    artifact.notable_reasons = ["test_reason"]
    artifact.priority = 50

    # Convert to dict
    artifact_dict = artifact.to_dict()

    # Verify fields
    assert artifact_dict['name'] == "file.txt"
    assert artifact_dict['size_bytes'] == 1024
    assert artifact_dict['type'] == "document"
    assert artifact_dict['sha256'] == "abc123"
    assert len(artifact_dict['notable_reasons']) == 1

    print("[PASS] ArtifactInfo tests passed")
    return True


def test_processing_step():
    """Test processing step tracking."""
    print("Testing ProcessingStep...")

    step = ProcessingStep("Test Step", "test command")

    assert step.step_name == "Test Step"
    assert step.command == "test command"
    assert step.success is True

    # Complete the step
    step.complete(stdout="test output", stderr="", success=True)

    # Convert to dict
    step_dict = step.to_dict()

    assert step_dict['step'] == "Test Step"
    assert step_dict['cmd'] == "test command"
    assert step_dict['success'] is True
    assert 'start' in step_dict
    assert 'end' in step_dict

    print("[PASS] ProcessingStep tests passed")
    return True


def test_report_generator_initialization():
    """Test report generator initialization."""
    print("Testing ForensicReportGenerator initialization...")

    # Create temporary directories
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a dummy master image
        master_image = os.path.join(temp_dir, "test.dd")
        with open(master_image, 'wb') as f:
            f.write(b'X' * 1024 * 1024)  # 1 MB test file

        output_dir = os.path.join(temp_dir, "reports")

        # Initialize generator
        generator = ForensicReportGenerator(
            case_id="TEST-001",
            operator="Test Operator",
            master_image=master_image,
            output_dir=output_dir
        )

        # Verify initialization
        assert generator.case_id == "TEST-001"
        assert generator.operator == "Test Operator"
        assert generator.master_image == os.path.abspath(master_image)
        assert os.path.exists(generator.output_dir)

        print("[PASS] ForensicReportGenerator initialization tests passed")
        return True


def test_report_generation():
    """Test full report generation."""
    print("Testing report generation...")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test master image
        master_image = os.path.join(temp_dir, "test.dd")
        with open(master_image, 'wb') as f:
            f.write(b'Test evidence data\n' * 1000)

        # Create test artifacts directory
        artifacts_dir = os.path.join(temp_dir, "artifacts")
        os.makedirs(artifacts_dir)

        # Create some test artifacts
        for i in range(10):
            artifact_path = os.path.join(artifacts_dir, f"test_file_{i}.txt")
            with open(artifact_path, 'w') as f:
                f.write(f"Test artifact {i}\n" * 10)

        # Create password file (should be flagged as notable)
        password_file = os.path.join(artifacts_dir, "passwords.txt")
        with open(password_file, 'w') as f:
            f.write("test password file\n")

        output_dir = os.path.join(temp_dir, "reports")

        # Initialize generator
        generator = ForensicReportGenerator(
            case_id="TEST-002",
            operator="Test Analyst",
            master_image=master_image,
            output_dir=output_dir,
            parsed_artifacts_dir=artifacts_dir
        )

        # Generate report
        result = generator.generate_report(formats=['html', 'json'])

        # Verify result
        assert result['status'] in ['success', 'partial'], f"Report generation failed: {result['summary']}"
        assert result['case_id'] == "TEST-002"
        assert result['report_html'] is not None, "HTML report not generated"
        assert result['manifest_json'] is not None, "JSON manifest not generated"

        # Verify HTML file exists
        assert os.path.exists(result['report_html']), "HTML report file missing"

        # Verify JSON file exists and is valid
        assert os.path.exists(result['manifest_json']), "JSON manifest file missing"

        with open(result['manifest_json'], 'r') as f:
            manifest = json.load(f)

        # Verify JSON structure
        assert manifest['case_id'] == "TEST-002"
        assert manifest['operator'] == "Test Analyst"
        assert 'artifacts_count' in manifest
        assert manifest['artifacts_count']['files'] == 11  # 10 test files + 1 password file
        assert 'master_image' in manifest
        assert 'chain_of_custody' in manifest
        assert 'processing_steps' in manifest

        # Verify notable artifacts detected
        notable_count = manifest['artifacts_count']['notable']
        assert notable_count >= 1, "Password file should be flagged as notable"

        # Verify chain of custody
        assert len(manifest['chain_of_custody']) >= 1, "Chain of custody should have entries"

        # Verify HTML content
        with open(result['report_html'], 'r', encoding='utf-8') as f:
            html_content = f.read()

        assert "TEST-002" in html_content, "Case ID missing from HTML"
        assert "Test Analyst" in html_content, "Operator missing from HTML"
        assert "Chain of Custody" in html_content, "Chain of Custody section missing"

        print("[PASS] Report generation tests passed")
        print(f"  Generated HTML: {result['report_html']}")
        print(f"  Generated JSON: {result['manifest_json']}")
        print(f"  Artifacts scanned: {manifest['artifacts_count']['files']}")
        print(f"  Notable artifacts: {notable_count}")

        return True


def test_artifact_categorization():
    """Test file type categorization."""
    print("Testing artifact categorization...")

    with tempfile.TemporaryDirectory() as temp_dir:
        master_image = os.path.join(temp_dir, "test.dd")
        with open(master_image, 'wb') as f:
            f.write(b'test')

        artifacts_dir = os.path.join(temp_dir, "artifacts")
        os.makedirs(artifacts_dir)

        # Create files of different types
        test_files = {
            'document.pdf': 'document',
            'image.jpg': 'image',
            'video.mp4': 'video',
            'audio.mp3': 'audio',
            'archive.zip': 'archive',
            'program.exe': 'executable',
            'data.db': 'database',
            'message.eml': 'email',
            'page.html': 'web',
            'script.py': 'code',
            'unknown.xyz': 'unknown'
        }

        for filename in test_files.keys():
            with open(os.path.join(artifacts_dir, filename), 'w') as f:
                f.write("test")

        output_dir = os.path.join(temp_dir, "reports")

        generator = ForensicReportGenerator(
            case_id="TEST-003",
            operator="Test",
            master_image=master_image,
            output_dir=output_dir,
            parsed_artifacts_dir=artifacts_dir
        )

        # Scan artifacts
        generator.scan_artifacts()

        # Verify categorization
        for artifact in generator.artifacts:
            expected_type = test_files.get(artifact.name)
            assert artifact.artifact_type == expected_type, \
                f"Wrong type for {artifact.name}: got {artifact.artifact_type}, expected {expected_type}"

        print("[PASS] Artifact categorization tests passed")
        return True


def run_all_tests():
    """Run all tests."""
    print("="*70)
    print("ForensAI Forensic Report Generator - Test Suite")
    print("="*70)
    print()

    tests = [
        test_hash_verifier,
        test_chain_of_custody_entry,
        test_artifact_info,
        test_processing_step,
        test_report_generator_initialization,
        test_artifact_categorization,
        test_report_generation,  # Run this last as it's most comprehensive
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"[FAIL] {test.__name__} failed")
        except Exception as e:
            failed += 1
            print(f"[FAIL] {test.__name__} failed with exception: {e}")
            import traceback
            traceback.print_exc()

        print()

    print("="*70)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("="*70)

    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
