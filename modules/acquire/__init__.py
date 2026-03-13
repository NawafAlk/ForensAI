"""
ForensAI - Cross-Platform Disk Acquisition Module

Provides unified disk acquisition functionality for both Windows and Linux.
Automatically detects the current platform and uses the appropriate implementation.

Usage:
    from modules.acquire import (
        is_admin,
        list_physical_disks,
        list_partitions,
        acquire_raw,
        dry_run_check,
        AcquisitionError,
        DiskInfo,
        PartitionInfo,
        AcquisitionResult
    )

    # Check privileges
    if not is_admin():
        print("Run as administrator/root")

    # List disks
    disks = list_physical_disks()
    for disk in disks:
        print(f"{disk.device_path}: {disk.model} ({disk.size_gb} GB)")

    # Acquire disk
    result = acquire_raw(
        device_path="/dev/sda",  # or "0" on Windows for PHYSICALDRIVE0
        output_path="disk.dd",
        compute_hashes=['md5', 'sha256']
    )
"""

import platform
from typing import List, Optional, Dict

from .base import (
    AcquisitionError,
    DiskInfo,
    PartitionInfo,
    AcquisitionResult,
    BaseAcquirer,
    ProgressCallback,
    AbortCheck
)

from .common import (
    verify_hash,
    write_metadata_json,
    simulate_acquisition,
    format_size,
    ProgressTracker,
    acquire_with_ewfacquire
)

_system = platform.system()

if _system == 'Windows':
    from .windows import WindowsAcquirer
    _AcquirerClass = WindowsAcquirer
elif _system == 'Linux':
    from .linux import LinuxAcquirer
    _AcquirerClass = LinuxAcquirer
else:
    _AcquirerClass = None


def _get_acquirer() -> BaseAcquirer:
    """
    Get the appropriate acquirer for the current platform.

    Returns:
        Platform-specific acquirer instance

    Raises:
        AcquisitionError: If platform is not supported
    """
    if _AcquirerClass is None:
        raise AcquisitionError(
            f"Platform '{_system}' is not supported for disk acquisition.\n"
            "Supported platforms: Windows, Linux"
        )
    return _AcquirerClass()


_acquirer = None


def _ensure_acquirer() -> BaseAcquirer:
    """Ensure acquirer is initialized."""
    global _acquirer
    if _acquirer is None:
        _acquirer = _get_acquirer()
    return _acquirer


def is_admin() -> bool:
    """
    Check if the current process has elevated privileges.

    Returns:
        bool: True if running with admin (Windows) or root (Linux) privileges
    """
    return _ensure_acquirer().is_admin()


def list_physical_disks() -> List[DiskInfo]:
    """
    List all physical disks on the system.

    Returns:
        List[DiskInfo]: List of physical disk information

    Raises:
        AcquisitionError: If enumeration fails or privileges insufficient
    """
    return _ensure_acquirer().list_physical_disks()


def list_partitions() -> List[PartitionInfo]:
    """
    List all partitions/volumes on the system.

    Returns:
        List[PartitionInfo]: List of partition information

    Raises:
        AcquisitionError: If enumeration fails
    """
    return _ensure_acquirer().list_partitions()


def acquire_raw(
    device_path: str,
    output_path: str,
    progress_callback: Optional[ProgressCallback] = None,
    abort_check: Optional[AbortCheck] = None,
    compute_hashes: Optional[List[str]] = None,
    buffer_size: int = 4 * 1024 * 1024,
    max_bytes: Optional[int] = None
) -> AcquisitionResult:
    """
    Acquire a device to raw .dd format.

    Args:
        device_path: Device to acquire
            - Windows: Drive number ("0"), drive letter ("E:"), or path ("\\\\.\\PHYSICALDRIVE0")
            - Linux: Device path ("/dev/sda") or name ("sda")
        output_path: Output file path for the .dd image
        progress_callback: Optional callback(bytes_read, total_bytes, speed_mbps)
        abort_check: Optional function that returns True to abort
        compute_hashes: List of hash types ['md5', 'sha1', 'sha256']
        buffer_size: Read buffer size (default 4MB)
        max_bytes: Optional maximum bytes to read

    Returns:
        AcquisitionResult: Result containing success status, hashes, etc.

    Raises:
        AcquisitionError: If acquisition fails
    """
    return _ensure_acquirer().acquire_raw(
        device_path=device_path,
        output_path=output_path,
        progress_callback=progress_callback,
        abort_check=abort_check,
        compute_hashes=compute_hashes,
        buffer_size=buffer_size,
        max_bytes=max_bytes
    )


def dry_run_check(device_path: str) -> Dict:
    """
    Verify device can be opened without actually acquiring.

    Args:
        device_path: Device path to check

    Returns:
        Dict with device info and access status

    Raises:
        AcquisitionError: If device cannot be accessed
    """
    return _ensure_acquirer().dry_run_check(device_path)


def get_device_size(device_path: str) -> Optional[int]:
    """
    Get the size of a device in bytes.

    Args:
        device_path: Device path

    Returns:
        Size in bytes or None if unknown
    """
    return _ensure_acquirer().get_device_size(device_path)


def get_platform() -> str:
    """
    Get the current platform name.

    Returns:
        Platform name ('Windows', 'Linux', etc.)
    """
    return _system


def is_supported() -> bool:
    """
    Check if the current platform is supported.

    Returns:
        True if platform is supported for disk acquisition
    """
    return _AcquirerClass is not None


def list_physical_disks_windows() -> List[Dict]:
    """
    Legacy function for Windows disk listing.
    Returns list of dicts for backward compatibility.
    """
    if _system != 'Windows':
        raise AcquisitionError("This function is only supported on Windows")

    disks = list_physical_disks()
    return [
        {
            'number': disk.number,
            'model': disk.model,
            'size': disk.size,
            'size_gb': disk.size_gb,
            'serial': disk.serial,
            'interface': disk.interface,
            'device_path': disk.device_path
        }
        for disk in disks
    ]


def list_logical_drives_windows() -> List[Dict]:
    """
    Legacy function for Windows logical drive listing.
    Returns list of dicts for backward compatibility.
    """
    if _system != 'Windows':
        raise AcquisitionError("This function is only supported on Windows")

    partitions = list_partitions()
    return [
        {
            'drive_letter': part.drive_letter,
            'label': part.label,
            'file_system': part.file_system,
            'size': part.size,
            'size_gb': part.size_gb,
            'free_space': part.free_space,
            'free_space_gb': part.free_space_gb,
            'drive_type': part.partition_type,
            'device_path': part.device_path
        }
        for part in partitions
    ]


def acquire_raw_windows(
    drive_number: Optional[int] = None,
    device_path: Optional[str] = None,
    drive_letter: Optional[str] = None,
    output_path: str = None,
    progress_callback=None,
    abort_check=None,
    compute_hashes: List[str] = None,
    buffer_size: int = 4 * 1024 * 1024,
    max_bytes: Optional[int] = None,
    **kwargs
) -> Dict:
    """
    Legacy function for Windows raw acquisition.
    Returns dict for backward compatibility.
    """
    if _system != 'Windows':
        raise AcquisitionError("This function is only supported on Windows")

    if device_path:
        dev = device_path
    elif drive_number is not None:
        dev = str(drive_number)
    elif drive_letter:
        dev = drive_letter
    else:
        raise AcquisitionError("Must specify drive_number, device_path, or drive_letter")

    result = acquire_raw(
        device_path=dev,
        output_path=output_path,
        progress_callback=progress_callback,
        abort_check=abort_check,
        compute_hashes=compute_hashes,
        buffer_size=buffer_size,
        max_bytes=max_bytes
    )

    return result.to_dict()


def dry_run_check_device(
    drive_number: Optional[int] = None,
    device_path: Optional[str] = None,
    drive_letter: Optional[str] = None,
    **kwargs
) -> Dict:
    """
    Legacy function for dry-run device check.
    """
    if drive_number is not None:
        dev = str(drive_number)
    elif device_path:
        dev = device_path
    elif drive_letter:
        dev = drive_letter
    else:
        raise AcquisitionError("Must specify drive_number, device_path, or drive_letter")

    return dry_run_check(dev)


__all__ = [
    'AcquisitionError',

    'DiskInfo',
    'PartitionInfo',
    'AcquisitionResult',

    'is_admin',
    'list_physical_disks',
    'list_partitions',
    'acquire_raw',
    'dry_run_check',
    'get_device_size',
    'get_platform',
    'is_supported',

    'verify_hash',
    'write_metadata_json',
    'simulate_acquisition',
    'format_size',
    'acquire_with_ewfacquire',

    'list_physical_disks_windows',
    'list_logical_drives_windows',
    'acquire_raw_windows',
    'dry_run_check_device',
]
