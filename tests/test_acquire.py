"""
ForensAI - Acquisition Module Tests
Unit tests for physical disk acquisition functionality.
"""

import os
import sys
import unittest
import tempfile
import shutil
import subprocess
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.acquire import (
    is_admin,
    list_physical_disks_windows,
    verify_hash,
    simulate_acquisition,
    write_metadata_json,
    get_windows_error_message,
    get_volume_guid_for_drive,
    try_open_device,
    open_device_with_fallback,
    dry_run_check_device,
    AcquisitionError
)


class TestAdminCheck(unittest.TestCase):
    """Test administrator privilege checking."""

    @patch('platform.system')
    def test_is_admin_non_windows(self, mock_system):
        """Test that is_admin returns False on non-Windows systems."""
        mock_system.return_value = 'Linux'
        self.assertFalse(is_admin())

    @patch('platform.system')
    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    def test_is_admin_windows(self, mock_is_admin, mock_system):
        """Test admin check on Windows."""
        mock_system.return_value = 'Windows'
        mock_is_admin.return_value = 1
        self.assertTrue(is_admin())

        mock_is_admin.return_value = 0
        self.assertFalse(is_admin())


class TestDiskListing(unittest.TestCase):
    """Test disk listing functionality."""

    @patch('platform.system')
    def test_list_disks_non_windows(self, mock_system):
        """Test that list_physical_disks_windows raises error on non-Windows."""
        mock_system.return_value = 'Linux'

        with self.assertRaises(AcquisitionError) as context:
            list_physical_disks_windows()

        self.assertIn('only supported on Windows', str(context.exception))

    @patch('modules.acquire.is_admin')
    @patch('platform.system')
    def test_list_disks_no_admin(self, mock_system, mock_is_admin):
        """Test that list_physical_disks_windows requires admin."""
        mock_system.return_value = 'Windows'
        mock_is_admin.return_value = False

        with self.assertRaises(AcquisitionError) as context:
            list_physical_disks_windows()

        self.assertIn('Administrator privileges required', str(context.exception))

    @patch('subprocess.run')
    @patch('modules.acquire.is_admin')
    @patch('platform.system')
    def test_list_disks_success(self, mock_system, mock_is_admin, mock_run):
        """Test successful disk listing."""
        mock_system.return_value = 'Windows'
        mock_is_admin.return_value = True

        # Mock WMIC output
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Node,DeviceID,InterfaceType,Model,SerialNumber,Size\n"
            "COMPUTER,\\\\.\\PHYSICALDRIVE0,SCSI,Samsung SSD 850,S12345,256060514304\n"
            "COMPUTER,\\\\.\\PHYSICALDRIVE1,USB,USB Flash Drive,U67890,16000000000\n"
        )
        mock_run.return_value = mock_result

        disks = list_physical_disks_windows()

        self.assertEqual(len(disks), 2)
        self.assertEqual(disks[0]['number'], 0)
        self.assertEqual(disks[0]['model'], 'Samsung SSD 850')
        self.assertEqual(disks[1]['number'], 1)
        self.assertEqual(disks[1]['interface'], 'USB')


class TestHashVerification(unittest.TestCase):
    """Test hash computation functionality."""

    def setUp(self):
        """Create a temporary file for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, 'test.dat')

        # Write test data
        with open(self.test_file, 'wb') as f:
            f.write(b'Hello, ForensAI!' * 1000)

    def tearDown(self):
        """Clean up temporary files."""
        shutil.rmtree(self.test_dir)

    def test_verify_hash_md5(self):
        """Test MD5 hash computation."""
        hash_value = verify_hash(self.test_file, 'md5')
        self.assertIsInstance(hash_value, str)
        self.assertEqual(len(hash_value), 32)  # MD5 is 32 hex characters

    def test_verify_hash_sha1(self):
        """Test SHA1 hash computation."""
        hash_value = verify_hash(self.test_file, 'sha1')
        self.assertIsInstance(hash_value, str)
        self.assertEqual(len(hash_value), 40)  # SHA1 is 40 hex characters

    def test_verify_hash_sha256(self):
        """Test SHA256 hash computation."""
        hash_value = verify_hash(self.test_file, 'sha256')
        self.assertIsInstance(hash_value, str)
        self.assertEqual(len(hash_value), 64)  # SHA256 is 64 hex characters

    def test_verify_hash_invalid_type(self):
        """Test that invalid hash type raises error."""
        with self.assertRaises(AcquisitionError) as context:
            verify_hash(self.test_file, 'invalid')

        self.assertIn('Unsupported hash type', str(context.exception))

    def test_verify_hash_nonexistent_file(self):
        """Test that hashing nonexistent file raises error."""
        with self.assertRaises(AcquisitionError):
            verify_hash('/nonexistent/file.dat', 'md5')


class TestSimulateAcquisition(unittest.TestCase):
    """Test acquisition simulation (dry-run mode)."""

    def setUp(self):
        """Create a temporary directory for output."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        shutil.rmtree(self.test_dir)

    def test_simulate_acquisition_basic(self):
        """Test basic simulation."""
        result = simulate_acquisition(
            output_dir=self.test_dir,
            size_mb=1,
            compute_hashes=['md5', 'sha1']
        )

        self.assertTrue(result['success'])
        self.assertTrue(result['simulated'])
        self.assertTrue(os.path.exists(result['output_path']))
        self.assertEqual(result['size_bytes'], 1 * 1024 * 1024)
        self.assertIn('md5', result['hashes'])
        self.assertIn('sha1', result['hashes'])

    def test_simulate_acquisition_with_sha256(self):
        """Test simulation with SHA256."""
        result = simulate_acquisition(
            output_dir=self.test_dir,
            size_mb=2,
            compute_hashes=['md5', 'sha1', 'sha256']
        )

        self.assertTrue(result['success'])
        self.assertIn('sha256', result['hashes'])
        self.assertEqual(len(result['hashes']['sha256']), 64)

    def test_simulate_acquisition_creates_file(self):
        """Test that simulation creates actual file."""
        result = simulate_acquisition(
            output_dir=self.test_dir,
            size_mb=5
        )

        output_path = result['output_path']
        self.assertTrue(os.path.isfile(output_path))

        # Verify file size
        file_size = os.path.getsize(output_path)
        self.assertEqual(file_size, 5 * 1024 * 1024)


class TestMetadataWriting(unittest.TestCase):
    """Test metadata JSON writing."""

    def setUp(self):
        """Create a temporary directory."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        shutil.rmtree(self.test_dir)

    def test_write_metadata_json(self):
        """Test metadata JSON creation."""
        output_path = os.path.join(self.test_dir, 'test.dd')

        metadata = {
            'source': 'PHYSICALDRIVE0',
            'size_bytes': 123456789,
            'md5': 'abc123',
            'operator': 'Test User'
        }

        metadata_path = write_metadata_json(output_path, metadata)

        self.assertTrue(os.path.exists(metadata_path))
        self.assertEqual(metadata_path, output_path + '.metadata.json')

        # Read and verify content
        import json
        with open(metadata_path, 'r') as f:
            written_metadata = json.load(f)

        self.assertEqual(written_metadata['source'], 'PHYSICALDRIVE0')
        self.assertEqual(written_metadata['size_bytes'], 123456789)
        self.assertEqual(written_metadata['tool'], 'ForensAI')
        self.assertIn('tool_version', written_metadata)
        self.assertIn('acquisition_host', written_metadata)


class TestAcquisitionError(unittest.TestCase):
    """Test custom exception."""

    def test_acquisition_error(self):
        """Test AcquisitionError can be raised and caught."""
        with self.assertRaises(AcquisitionError) as context:
            raise AcquisitionError("Test error message")

        self.assertIn("Test error message", str(context.exception))


class TestErrorMessages(unittest.TestCase):
    """Test Windows error message translation."""

    def test_known_error_codes(self):
        """Test that known error codes return proper messages."""
        # Test common error codes
        msg_5 = get_windows_error_message(5)
        self.assertIn("Access is denied", msg_5)
        self.assertIn("Administrator", msg_5)

        msg_161 = get_windows_error_message(161)
        self.assertIn("invalid", msg_161.lower())
        self.assertIn("path", msg_161.lower())

        msg_1314 = get_windows_error_message(1314)
        self.assertIn("privilege", msg_1314.lower())

    def test_unknown_error_code(self):
        """Test that unknown error codes return generic message."""
        msg = get_windows_error_message(99999)
        self.assertIn("99999", msg)


class TestVolumeGUID(unittest.TestCase):
    """Test volume GUID lookup."""

    @patch('subprocess.run')
    def test_get_volume_guid_success(self, mock_run):
        """Test successful volume GUID lookup."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "\\\\?\\Volume{12345678-1234-1234-1234-123456789012}\\"
        mock_run.return_value = mock_result

        guid = get_volume_guid_for_drive("E:")
        self.assertIsNotNone(guid)
        self.assertIn("Volume{", guid)

    @patch('subprocess.run')
    def test_get_volume_guid_failure(self, mock_run):
        """Test volume GUID lookup failure."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        guid = get_volume_guid_for_drive("Z:")
        self.assertIsNone(guid)

    @patch('subprocess.run')
    def test_get_volume_guid_timeout(self, mock_run):
        """Test volume GUID lookup with timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired('mountvol', 10)

        guid = get_volume_guid_for_drive("E:")
        self.assertIsNone(guid)


class TestDeviceOpenFallback(unittest.TestCase):
    """Test device opening with fallback logic."""

    @patch('modules.acquire.try_open_device')
    def test_fallback_first_attempt_succeeds(self, mock_try_open):
        """Test that first attempt succeeding returns immediately."""
        mock_try_open.return_value = 12345  # Mock handle

        handle, path, error = open_device_with_fallback(drive_number=0)

        self.assertIsNotNone(handle)
        self.assertEqual(handle, 12345)
        self.assertIn("PHYSICALDRIVE0", path)
        self.assertEqual(error, "")

    @patch('ctypes.windll.kernel32.GetLastError')
    @patch('modules.acquire.try_open_device')
    def test_fallback_all_attempts_fail(self, mock_try_open, mock_get_error):
        """Test that all attempts failing returns error summary."""
        mock_try_open.return_value = None
        mock_get_error.return_value = 5  # Access denied

        handle, path, error = open_device_with_fallback(drive_number=1)

        self.assertIsNone(handle)
        self.assertEqual(path, "")
        self.assertIn("Failed to open device", error)
        self.assertIn("Suggestions", error)

    @patch('modules.acquire.get_volume_guid_for_drive')
    @patch('modules.acquire.try_open_device')
    def test_fallback_with_drive_letter_and_guid(self, mock_try_open, mock_get_guid):
        """Test fallback trying drive letter and volume GUID."""
        # First attempt fails, second succeeds
        mock_try_open.side_effect = [None, 98765]
        mock_get_guid.return_value = "\\\\?\\Volume{test-guid}\\"

        handle, path, error = open_device_with_fallback(drive_letter="E:")

        self.assertIsNotNone(handle)
        self.assertEqual(handle, 98765)
        # Should have tried both \\.\\E: and the GUID path
        self.assertEqual(mock_try_open.call_count, 2)
        # Verify the GUID path was attempted
        self.assertIn("Volume{test-guid}", path)


class TestAcquireRawWindowsSignature(unittest.TestCase):
    """Test the updated acquire_raw_windows function signature."""

    @patch('modules.acquire.is_admin')
    @patch('platform.system')
    def test_requires_admin(self, mock_system, mock_is_admin):
        """Test that acquisition requires admin privileges."""
        mock_system.return_value = 'Windows'
        mock_is_admin.return_value = False

        with self.assertRaises(AcquisitionError) as context:
            from modules.acquire import acquire_raw_windows
            acquire_raw_windows(
                drive_number=0,
                output_path="C:\\test.dd"
            )

        self.assertIn("Administrator privileges required", str(context.exception))

    @patch('platform.system')
    def test_requires_windows(self, mock_system):
        """Test that acquisition only works on Windows."""
        mock_system.return_value = 'Linux'

        with self.assertRaises(AcquisitionError) as context:
            from modules.acquire import acquire_raw_windows
            acquire_raw_windows(
                drive_number=0,
                output_path="/tmp/test.dd"
            )

        self.assertIn("only supported on Windows", str(context.exception))


class TestDryRunCheckDevice(unittest.TestCase):
    """Test dry-run device checking."""

    @patch('platform.system')
    def test_requires_windows(self, mock_system):
        """Test that dry-run requires Windows."""
        mock_system.return_value = 'Linux'

        with self.assertRaises(AcquisitionError) as context:
            dry_run_check_device(drive_number=0)

        self.assertIn("only supported on Windows", str(context.exception))

    @patch('modules.acquire.is_admin')
    @patch('platform.system')
    def test_requires_admin(self, mock_system, mock_is_admin):
        """Test that dry-run requires admin."""
        mock_system.return_value = 'Windows'
        mock_is_admin.return_value = False

        with self.assertRaises(AcquisitionError) as context:
            dry_run_check_device(drive_number=0)

        self.assertIn("Administrator privileges required", str(context.exception))

    @patch('ctypes.windll.kernel32.CloseHandle')
    @patch('modules.acquire.open_device_with_fallback')
    @patch('modules.acquire.is_admin')
    @patch('platform.system')
    def test_successful_check_device_opens(self, mock_system, mock_is_admin, mock_open, mock_close):
        """Test successful dry-run - device can be opened."""
        mock_system.return_value = 'Windows'
        mock_is_admin.return_value = True
        mock_open.return_value = (12345, "\\\\.\\PHYSICALDRIVE0", "")

        result = dry_run_check_device(drive_number=0)

        self.assertTrue(result['success'])
        self.assertTrue(result['can_acquire'])
        self.assertEqual(result['device_path'], "\\\\.\\PHYSICALDRIVE0")
        # Size may or may not be available depending on mocking, but device opens successfully


class TestMetadataFormat(unittest.TestCase):
    """Test metadata JSON format matches spec."""

    def setUp(self):
        """Create a temporary directory."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        shutil.rmtree(self.test_dir)

    def test_metadata_has_required_fields(self):
        """Test that metadata includes all required fields."""
        output_path = os.path.join(self.test_dir, 'test.dd')

        metadata = {
            'operator': 'Test Operator',
            'device': '\\\\.\\PHYSICALDRIVE1',
            'drive_letter': 'E:',
            'output_file': output_path,
            'bytes_written': 4001366016,
            'hashes': {
                'md5': 'abc123',
                'sha1': 'def456',
                'sha256': 'ghi789'
            },
            'start_time': '2025-01-01T10:00:00',
            'end_time': '2025-01-01T10:30:00',
            'status': 'complete'
        }

        metadata_path = write_metadata_json(output_path, metadata)
        self.assertTrue(os.path.exists(metadata_path))

        # Read and verify
        import json
        with open(metadata_path, 'r') as f:
            written = json.load(f)

        # Check required fields
        self.assertEqual(written['operator'], 'Test Operator')
        self.assertEqual(written['device'], '\\\\.\\PHYSICALDRIVE1')
        self.assertEqual(written['bytes_written'], 4001366016)
        self.assertEqual(written['status'], 'complete')
        self.assertIn('tool', written)
        self.assertIn('tool_version', written)

    def test_metadata_aborted_status(self):
        """Test metadata with aborted status."""
        output_path = os.path.join(self.test_dir, 'test.dd')

        metadata = {
            'operator': 'Test',
            'device': '\\\\.\\PHYSICALDRIVE1',
            'output_file': output_path,
            'bytes_written': 1000000,
            'status': 'aborted',
            'error': 'Interrupted by user (SIGINT)',
            'hashes': {
                'md5': 'partial_hash'
            },
            'start_time': '2025-01-01T10:00:00',
            'end_time': '2025-01-01T10:01:00'
        }

        metadata_path = write_metadata_json(output_path, metadata)

        import json
        with open(metadata_path, 'r') as f:
            written = json.load(f)

        self.assertEqual(written['status'], 'aborted')
        self.assertIn('error', written)
        self.assertEqual(written['bytes_written'], 1000000)


def run_tests():
    """Run all tests and return results."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestAdminCheck))
    suite.addTests(loader.loadTestsFromTestCase(TestDiskListing))
    suite.addTests(loader.loadTestsFromTestCase(TestHashVerification))
    suite.addTests(loader.loadTestsFromTestCase(TestSimulateAcquisition))
    suite.addTests(loader.loadTestsFromTestCase(TestMetadataWriting))
    suite.addTests(loader.loadTestsFromTestCase(TestAcquisitionError))
    suite.addTests(loader.loadTestsFromTestCase(TestErrorMessages))
    suite.addTests(loader.loadTestsFromTestCase(TestVolumeGUID))
    suite.addTests(loader.loadTestsFromTestCase(TestDeviceOpenFallback))
    suite.addTests(loader.loadTestsFromTestCase(TestAcquireRawWindowsSignature))
    suite.addTests(loader.loadTestsFromTestCase(TestDryRunCheckDevice))
    suite.addTests(loader.loadTestsFromTestCase(TestMetadataFormat))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == '__main__':
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
