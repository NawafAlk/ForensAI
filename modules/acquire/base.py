"""
ForensAI - Acquisition Base Classes
Abstract base classes and shared types for cross-platform disk acquisition.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
from datetime import datetime


class AcquisitionError(Exception):
    """Custom exception for acquisition-related errors."""
    pass


@dataclass
class DiskInfo:
    """Information about a physical disk."""
    device_path: str
    model: str = "Unknown"
    size: int = 0
    size_gb: float = 0.0
    serial: str = "Unknown"
    interface: str = "Unknown"
    # Platform-specific identifiers
    number: Optional[int] = None  # Windows: PhysicalDrive number
    name: Optional[str] = None    # Linux: device name (sda, nvme0n1)

    def __post_init__(self):
        if self.size > 0 and self.size_gb == 0.0:
            self.size_gb = round(self.size / (1024**3), 2)


@dataclass
class PartitionInfo:
    """Information about a partition or logical drive."""
    device_path: str
    size: int = 0
    size_gb: float = 0.0
    free_space: int = 0
    free_space_gb: float = 0.0
    file_system: str = "Unknown"
    label: str = ""
    mount_point: Optional[str] = None  # Linux: /mnt/data, Windows: C:
    drive_letter: Optional[str] = None  # Windows only
    partition_type: str = "Unknown"
    bootable: bool = False
    disk_device: Optional[str] = None  # Parent disk device

    def __post_init__(self):
        if self.size > 0 and self.size_gb == 0.0:
            self.size_gb = round(self.size / (1024**3), 2)
        if self.free_space > 0 and self.free_space_gb == 0.0:
            self.free_space_gb = round(self.free_space / (1024**3), 2)


@dataclass
class AcquisitionResult:
    """Result of an acquisition operation."""
    success: bool
    status: str  # "complete", "aborted", "failed"
    output_path: str
    device_path: str
    bytes_written: int = 0
    duration_seconds: float = 0.0
    speed_mbps: float = 0.0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            'success': self.success,
            'status': self.status,
            'output_path': self.output_path,
            'device_path': self.device_path,
            'bytes_written': self.bytes_written,
            'duration_seconds': self.duration_seconds,
            'speed_mbps': self.speed_mbps,
        }
        if self.start_time:
            result['start_time'] = self.start_time
        if self.end_time:
            result['end_time'] = self.end_time
        if self.hashes:
            result['hashes'] = self.hashes
        if self.error:
            result['error'] = self.error
        return result


# Type alias for progress callback
# callback(bytes_read: int, total_bytes: Optional[int], speed_mbps: float)
ProgressCallback = Callable[[int, Optional[int], float], None]

# Type alias for abort check
# Returns True to abort acquisition
AbortCheck = Callable[[], bool]


class BaseAcquirer(ABC):
    """
    Abstract base class for platform-specific disk acquisition.

    Implementations must provide:
    - is_admin() - Check for elevated privileges
    - list_physical_disks() - Enumerate physical disks
    - list_partitions() - Enumerate partitions/volumes
    - acquire_raw() - Perform raw disk acquisition
    - dry_run_check() - Verify device access without acquiring
    """

    @abstractmethod
    def is_admin(self) -> bool:
        """
        Check if the current process has elevated privileges.

        Returns:
            bool: True if running with admin/root privileges
        """
        pass

    @abstractmethod
    def list_physical_disks(self) -> List[DiskInfo]:
        """
        List all physical disks on the system.

        Returns:
            List[DiskInfo]: List of physical disk information

        Raises:
            AcquisitionError: If enumeration fails
        """
        pass

    @abstractmethod
    def list_partitions(self) -> List[PartitionInfo]:
        """
        List all partitions/volumes on the system.

        Returns:
            List[PartitionInfo]: List of partition information

        Raises:
            AcquisitionError: If enumeration fails
        """
        pass

    @abstractmethod
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
        """
        Acquire a device to raw .dd format.

        Args:
            device_path: Device path to acquire
            output_path: Output file path
            progress_callback: Optional progress callback
            abort_check: Optional abort check function
            compute_hashes: List of hash types ['md5', 'sha1', 'sha256']
            buffer_size: Read buffer size (default 4MB)
            max_bytes: Optional maximum bytes to read

        Returns:
            AcquisitionResult: Acquisition result

        Raises:
            AcquisitionError: If acquisition fails
        """
        pass

    @abstractmethod
    def dry_run_check(self, device_path: str) -> Dict:
        """
        Verify device can be opened without actually acquiring.

        Args:
            device_path: Device path to check

        Returns:
            Dict with device info and access status

        Raises:
            AcquisitionError: If device cannot be accessed
        """
        pass

    def get_device_size(self, device_path: str) -> Optional[int]:
        """
        Get the size of a device in bytes.

        Args:
            device_path: Device path

        Returns:
            Size in bytes or None if unknown
        """
        # Default implementation - subclasses can override
        return None
