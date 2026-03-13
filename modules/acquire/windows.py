"""
ForensAI - Windows Disk Acquisition
Windows-specific implementation for disk acquisition using ctypes and WMIC.
"""

import os
import ctypes
import subprocess
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .base import (
    BaseAcquirer, AcquisitionError, DiskInfo, PartitionInfo,
    AcquisitionResult, ProgressCallback, AbortCheck
)
from .common import create_hashers, finalize_hashes, get_logger, ProgressTracker


GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
INVALID_HANDLE_VALUE = -1


def get_windows_error_message(error_code: int) -> str:
    """
    Get a human-readable error message for a Windows error code.

    Args:
        error_code: Windows error code from GetLastError()

    Returns:
        str: Human-readable error message
    """
    error_messages = {
        2: "The system cannot find the file specified (ERROR_FILE_NOT_FOUND)",
        3: "The system cannot find the path specified (ERROR_PATH_NOT_FOUND)",
        5: "Access is denied (ERROR_ACCESS_DENIED) - Ensure you have Administrator privileges",
        32: "The process cannot access the file because it is being used by another process (ERROR_SHARING_VIOLATION)",
        161: "The specified path is invalid (ERROR_BAD_PATHNAME) - Device may not support raw access",
        170: "The requested resource is in use (ERROR_BUSY)",
        1314: "A required privilege is not held by the client (ERROR_PRIVILEGE_NOT_HELD) - Run as Administrator",
    }

    if error_code in error_messages:
        return error_messages[error_code]
    else:
        return f"Windows error code {error_code}"


class WindowsAcquirer(BaseAcquirer):
    """
    Windows-specific disk acquisition implementation.

    Uses Windows API via ctypes for device access and WMIC for device enumeration.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize Windows acquirer.

        Args:
            logger: Optional logger instance
        """
        self.logger = logger or get_logger(__name__)

    def is_admin(self) -> bool:
        """Check if running with administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _get_volume_guid_for_drive(self, drive_letter: str) -> Optional[str]:
        """
        Get the volume GUID path for a given drive letter.

        Args:
            drive_letter: Drive letter (e.g., 'E:', 'F:', etc.)

        Returns:
            Volume GUID path or None if not found
        """
        if not drive_letter.endswith(':'):
            drive_letter = drive_letter + ':'

        try:
            result = subprocess.run(
                ['mountvol', drive_letter + '\\', '/L'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                guid_path = result.stdout.strip()
                if guid_path and 'Volume{' in guid_path:
                    return guid_path
        except Exception:
            pass

        return None

    def _try_open_device(self, device_path: str) -> Optional[int]:
        """
        Attempt to open a device path with proper Windows flags.

        Args:
            device_path: Device path to open

        Returns:
            Valid file handle or None if failed
        """
        self.logger.info(f"Attempting to open: {device_path}")

        flags = FILE_FLAG_SEQUENTIAL_SCAN

        handle = ctypes.windll.kernel32.CreateFileW(
            device_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            flags,
            None
        )

        if handle == INVALID_HANDLE_VALUE or handle == 0xFFFFFFFF:
            error_code = ctypes.windll.kernel32.GetLastError()
            error_msg = get_windows_error_message(error_code)
            self.logger.warning(f"Failed to open {device_path}: {error_msg}")
            return None

        self.logger.info(f"Successfully opened: {device_path}")
        return handle

    def _open_device_with_fallback(
        self,
        drive_number: Optional[int] = None,
        device_path: Optional[str] = None,
        drive_letter: Optional[str] = None
    ) -> Tuple[Optional[int], str, str]:
        """
        Attempt to open a device with fallback logic.

        Args:
            drive_number: Physical drive number
            device_path: Direct device path
            drive_letter: Drive letter

        Returns:
            Tuple of (handle, successful_path, error_message)
        """
        attempts = []
        errors = []

        if device_path:
            attempts.append(device_path)

        if drive_number is not None:
            attempts.append(f"\\\\.\\PHYSICALDRIVE{drive_number}")

        if drive_letter:
            if not drive_letter.endswith(':'):
                drive_letter = drive_letter + ':'
            attempts.append(f"\\\\.\\{drive_letter}")

            guid_path = self._get_volume_guid_for_drive(drive_letter)
            if guid_path:
                guid_path_clean = guid_path.rstrip('\\')
                attempts.append(guid_path_clean)

        for path in attempts:
            handle = self._try_open_device(path)
            if handle is not None:
                return handle, path, ""

            error_code = ctypes.windll.kernel32.GetLastError()
            error_msg = get_windows_error_message(error_code)
            errors.append(f"  {path}: {error_msg}")

        error_summary = "Failed to open device. Attempted paths:\n" + "\n".join(errors)
        error_summary += "\n\nSuggestions:\n"
        error_summary += "  - Ensure you are running as Administrator\n"
        error_summary += "  - For removable drives, try using the drive letter (\\\\.\\E:)\n"
        error_summary += "  - Some devices may not support raw sector access\n"
        error_summary += "  - Close any applications that might have the device open\n"

        return None, "", error_summary

    def list_physical_disks(self) -> List[DiskInfo]:
        """List all physical disks using WMIC."""
        if not self.is_admin():
            raise AcquisitionError("Administrator privileges required to enumerate physical disks")

        disks = []

        try:
            result = subprocess.run(
                ['wmic', 'diskdrive', 'get',
                 'DeviceID,Model,Size,SerialNumber,InterfaceType', '/format:csv'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                raise AcquisitionError(f"WMIC command failed: {result.stderr}")

            lines = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]

            if len(lines) < 2:
                return disks

            headers = [h.strip() for h in lines[0].split(',')]

            for line in lines[1:]:
                if not line:
                    continue

                values = [v.strip() for v in line.split(',')]

                if len(values) != len(headers):
                    continue

                disk_info = dict(zip(headers, values))

                device_id = disk_info.get('DeviceID', '')
                try:
                    drive_num = int(device_id.split('PHYSICALDRIVE')[-1])
                except (ValueError, IndexError):
                    continue

                size_str = disk_info.get('Size', '0')
                try:
                    size = int(size_str) if size_str and size_str != 'NULL' else 0
                except ValueError:
                    size = 0

                disks.append(DiskInfo(
                    device_path=f"\\\\.\\PHYSICALDRIVE{drive_num}",
                    number=drive_num,
                    model=disk_info.get('Model', 'Unknown').strip() or 'Unknown',
                    size=size,
                    serial=disk_info.get('SerialNumber', 'Unknown').strip() or 'Unknown',
                    interface=disk_info.get('InterfaceType', 'Unknown').strip() or 'Unknown'
                ))

            return sorted(disks, key=lambda x: x.number or 0)

        except subprocess.TimeoutExpired:
            raise AcquisitionError("Timeout while enumerating physical disks")
        except Exception as e:
            raise AcquisitionError(f"Failed to enumerate physical disks: {str(e)}")

    def list_partitions(self) -> List[PartitionInfo]:
        """List all logical drives/partitions using WMIC."""
        partitions = []

        try:
            result = subprocess.run(
                ['wmic', 'logicaldisk', 'get',
                 'DeviceID,VolumeName,FileSystem,Size,FreeSpace,DriveType', '/format:csv'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                raise AcquisitionError(f"WMIC command failed: {result.stderr}")

            lines = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]

            if len(lines) < 2:
                return partitions

            headers = [h.strip() for h in lines[0].split(',')]

            drive_type_map = {
                '0': 'Unknown',
                '1': 'No Root Directory',
                '2': 'Removable',
                '3': 'Fixed',
                '4': 'Network',
                '5': 'CD-ROM',
                '6': 'RAM Disk'
            }

            for line in lines[1:]:
                if not line:
                    continue

                values = [v.strip() for v in line.split(',')]

                if len(values) != len(headers):
                    continue

                drive_info = dict(zip(headers, values))

                device_id = drive_info.get('DeviceID', '')
                if not device_id:
                    continue

                size_str = drive_info.get('Size', '0')
                try:
                    size = int(size_str) if size_str and size_str != 'NULL' else 0
                except ValueError:
                    size = 0

                free_str = drive_info.get('FreeSpace', '0')
                try:
                    free_space = int(free_str) if free_str and free_str != 'NULL' else 0
                except ValueError:
                    free_space = 0

                drive_type_num = drive_info.get('DriveType', '0')
                drive_type = drive_type_map.get(drive_type_num, 'Unknown')

                partitions.append(PartitionInfo(
                    device_path=f"\\\\.\\{device_id}",
                    drive_letter=device_id,
                    mount_point=device_id,
                    label=drive_info.get('VolumeName', '').strip() or 'Local Disk',
                    file_system=drive_info.get('FileSystem', 'Unknown').strip() or 'Unknown',
                    size=size,
                    free_space=free_space,
                    partition_type=drive_type
                ))

            return sorted(partitions, key=lambda x: x.drive_letter or '')

        except subprocess.TimeoutExpired:
            raise AcquisitionError("Timeout while enumerating partitions")
        except Exception as e:
            raise AcquisitionError(f"Failed to enumerate partitions: {str(e)}")

    def acquire_raw(
        self,
        device_path: str,
        output_path: str,
        progress_callback: Optional[ProgressCallback] = None,
        abort_check: Optional[AbortCheck] = None,
        compute_hashes: Optional[List[str]] = None,
        buffer_size: int = 4 * 1024 * 1024,
        max_bytes: Optional[int] = None
    ) -> AcquisitionResult:
        """Acquire a device to raw .dd format."""
        if not self.is_admin():
            raise AcquisitionError(
                "Administrator privileges required to acquire physical disks.\n"
                "Please run this program as Administrator."
            )

        hashers = create_hashers(compute_hashes)
        tracker = ProgressTracker()

        acquisition_status = "complete"
        error_message = None
        handle = None
        out_file = None
        actual_device_path = device_path

        try:
            if device_path.isdigit():
                drive_number = int(device_path)
                handle, actual_device_path, error_msg = self._open_device_with_fallback(
                    drive_number=drive_number
                )
            elif device_path.endswith(':') or (len(device_path) == 1 and device_path.isalpha()):
                handle, actual_device_path, error_msg = self._open_device_with_fallback(
                    drive_letter=device_path
                )
            else:
                handle, actual_device_path, error_msg = self._open_device_with_fallback(
                    device_path=device_path
                )

            if handle is None:
                raise AcquisitionError(error_msg)

            self.logger.info(f"Device opened successfully: {actual_device_path}")

            total_size = None
            try:
                file_size = ctypes.c_ulonglong(0)
                success = ctypes.windll.kernel32.GetFileSizeEx(handle, ctypes.byref(file_size))
                if success:
                    total_size = file_size.value
                    tracker.total_size = total_size
                    self.logger.info(f"Device size: {total_size:,} bytes ({total_size / (1024**3):.2f} GB)")
            except Exception as e:
                self.logger.warning(f"Could not get device size: {e}")

            self.logger.info(f"Writing to: {output_path}")
            out_file = open(output_path, 'wb')

            buffer = ctypes.create_string_buffer(buffer_size)
            bytes_read_ct = ctypes.c_ulong()
            bytes_written = 0

            while True:
                if abort_check and abort_check():
                    self.logger.warning("Acquisition aborted by user")
                    acquisition_status = "aborted"
                    error_message = "Aborted by user"
                    break

                if max_bytes is not None and bytes_written >= max_bytes:
                    self.logger.info(f"Reached max_bytes limit: {max_bytes:,}")
                    break

                success = ctypes.windll.kernel32.ReadFile(
                    handle,
                    buffer,
                    buffer_size,
                    ctypes.byref(bytes_read_ct),
                    None
                )

                if not success:
                    error_code = ctypes.windll.kernel32.GetLastError()
                    if error_code in [38, 27]:
                        self.logger.info(f"Reached end of device (error code {error_code})")
                        break
                    else:
                        error_msg = get_windows_error_message(error_code)
                        self.logger.error(f"Read error at offset {bytes_written}: {error_msg}")
                        raise AcquisitionError(f"Read error: {error_msg}")

                if bytes_read_ct.value == 0:
                    self.logger.info("ReadFile returned 0 bytes - end of device reached")
                    break

                chunk = buffer.raw[:bytes_read_ct.value]
                out_file.write(chunk)
                out_file.flush()
                os.fsync(out_file.fileno())

                for hasher in hashers.values():
                    hasher.update(chunk)

                bytes_written += bytes_read_ct.value

                if progress_callback and tracker.should_update_callback():
                    stats = tracker.update(bytes_written)
                    progress_callback(bytes_written, total_size, stats['speed_mbps'])

            out_file.close()
            out_file = None
            ctypes.windll.kernel32.CloseHandle(handle)
            handle = None

            final_stats = tracker.update(bytes_written)
            final_stats = tracker.get_final_stats()

            if progress_callback:
                progress_callback(bytes_written, total_size or bytes_written, final_stats['speed_mbps'])

            self.logger.info(f"Acquisition {acquisition_status}: {bytes_written:,} bytes")

            return AcquisitionResult(
                success=acquisition_status == "complete",
                status=acquisition_status,
                output_path=output_path,
                device_path=actual_device_path,
                bytes_written=bytes_written,
                duration_seconds=final_stats['duration_seconds'],
                speed_mbps=final_stats['speed_mbps'],
                start_time=final_stats['start_time'],
                end_time=final_stats['end_time'],
                hashes=finalize_hashes(hashers) if hashers else {},
                error=error_message
            )

        except KeyboardInterrupt:
            self.logger.warning("Keyboard interrupt - saving partial acquisition")
            if out_file:
                out_file.close()
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)

            final_stats = tracker.get_final_stats()
            return AcquisitionResult(
                success=False,
                status="aborted",
                output_path=output_path,
                device_path=actual_device_path,
                bytes_written=tracker.bytes_processed,
                duration_seconds=final_stats['duration_seconds'],
                speed_mbps=final_stats['speed_mbps'],
                start_time=final_stats['start_time'],
                end_time=final_stats['end_time'],
                hashes=finalize_hashes(hashers) if hashers else {},
                error="Interrupted by user"
            )

        except Exception as e:
            self.logger.error(f"Acquisition failed: {str(e)}")
            if out_file:
                try:
                    out_file.close()
                except:
                    pass
            if handle:
                try:
                    ctypes.windll.kernel32.CloseHandle(handle)
                except:
                    pass

            if isinstance(e, AcquisitionError):
                raise
            raise AcquisitionError(f"Acquisition failed: {str(e)}")

    def dry_run_check(self, device_path: str) -> Dict:
        """Verify device can be opened without acquiring."""
        if not self.is_admin():
            raise AcquisitionError("Administrator privileges required")

        self.logger.info("DRY-RUN MODE: Checking device access...")

        if device_path.isdigit():
            handle, actual_path, error_msg = self._open_device_with_fallback(
                drive_number=int(device_path)
            )
        elif device_path.endswith(':') or (len(device_path) == 1 and device_path.isalpha()):
            handle, actual_path, error_msg = self._open_device_with_fallback(
                drive_letter=device_path
            )
        else:
            handle, actual_path, error_msg = self._open_device_with_fallback(
                device_path=device_path
            )

        if handle is None:
            raise AcquisitionError(error_msg)

        self.logger.info(f"Device opened successfully: {actual_path}")

        total_size = None
        size_available = False
        try:
            file_size = ctypes.c_ulonglong(0)
            success = ctypes.windll.kernel32.GetFileSizeEx(handle, ctypes.byref(file_size))
            if success:
                total_size = file_size.value
                size_available = True
                self.logger.info(f"Device size: {total_size:,} bytes ({total_size / (1024**3):.2f} GB)")
        except Exception as e:
            self.logger.warning(f"Could not get device size: {e}")

        ctypes.windll.kernel32.CloseHandle(handle)
        self.logger.info("Device closed successfully")

        return {
            'success': True,
            'device_path': actual_path,
            'size_bytes': total_size,
            'size_available': size_available,
            'can_acquire': True
        }

    def get_device_size(self, device_path: str) -> Optional[int]:
        """Get device size in bytes."""
        try:
            result = self.dry_run_check(device_path)
            return result.get('size_bytes')
        except:
            return None
