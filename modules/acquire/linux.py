"""
ForensAI - Linux Disk Acquisition
Linux-specific implementation for disk acquisition using lsblk and standard I/O.
"""

import os
import json
import subprocess
import logging
from typing import Dict, List, Optional

from .base import (
    BaseAcquirer, AcquisitionError, DiskInfo, PartitionInfo,
    AcquisitionResult, ProgressCallback, AbortCheck
)
from .common import create_hashers, finalize_hashes, get_logger, ProgressTracker


class LinuxAcquirer(BaseAcquirer):
    """
    Linux-specific disk acquisition implementation.

    Uses lsblk for device enumeration and standard Python I/O for acquisition.
    Supports SATA, NVMe, USB, and virtual devices.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize Linux acquirer.

        Args:
            logger: Optional logger instance
        """
        self.logger = logger or get_logger(__name__)

    def is_admin(self) -> bool:
        """Check if running with root privileges."""
        return os.geteuid() == 0

    def _run_lsblk(self, args: List[str] = None) -> Dict:
        """
        Run lsblk command and return parsed JSON output.

        Args:
            args: Additional arguments for lsblk

        Returns:
            Parsed JSON output from lsblk

        Raises:
            AcquisitionError: If lsblk fails
        """
        cmd = ['lsblk', '-J']
        if args:
            cmd.extend(args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                raise AcquisitionError(f"lsblk failed: {result.stderr}")

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            raise AcquisitionError("Timeout while running lsblk")
        except json.JSONDecodeError as e:
            raise AcquisitionError(f"Failed to parse lsblk output: {e}")
        except FileNotFoundError:
            raise AcquisitionError("lsblk command not found. Is util-linux installed?")

    def _parse_size(self, size_str: str) -> int:
        """
        Parse size string from lsblk (e.g., '500G', '1T', '256M').

        Args:
            size_str: Size string with optional unit

        Returns:
            Size in bytes
        """
        if not size_str:
            return 0

        size_str = size_str.strip().upper()

        if size_str.isdigit():
            return int(size_str)

        units = {
            'B': 1,
            'K': 1024,
            'M': 1024**2,
            'G': 1024**3,
            'T': 1024**4,
            'P': 1024**5,
        }

        for unit, multiplier in units.items():
            if size_str.endswith(unit):
                try:
                    value = float(size_str[:-1])
                    return int(value * multiplier)
                except ValueError:
                    return 0

        try:
            return int(size_str)
        except ValueError:
            return 0

    def _get_device_path(self, name: str) -> str:
        """
        Convert device name to full path.

        Args:
            name: Device name (e.g., 'sda', 'nvme0n1')

        Returns:
            Full device path (e.g., '/dev/sda')
        """
        if name.startswith('/dev/'):
            return name
        return f'/dev/{name}'

    def list_physical_disks(self) -> List[DiskInfo]:
        """List all physical disks using lsblk."""
        if not self.is_admin():
            raise AcquisitionError(
                "Root privileges required to enumerate physical disks.\n"
                "Please run with sudo."
            )

        disks = []

        try:
            result = subprocess.run(
                ['lsblk', '-dJbo', 'NAME,SIZE,MODEL,SERIAL,TYPE,ROTA,TRAN,VENDOR'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                result = subprocess.run(
                    ['lsblk', '-dJbo', 'NAME,SIZE,TYPE'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

            data = json.loads(result.stdout)
            devices = data.get('blockdevices', [])

            for dev in devices:
                dev_type = dev.get('type', '')

                if dev_type not in ['disk']:
                    continue

                name = dev.get('name', '')
                if not name:
                    continue

                if name.startswith('loop') or name.startswith('ram'):
                    continue

                size = dev.get('size', 0)
                if isinstance(size, str):
                    size = self._parse_size(size)

                tran = dev.get('tran', '').upper()
                if tran:
                    interface = tran
                elif name.startswith('nvme'):
                    interface = 'NVMe'
                elif name.startswith('sd'):
                    interface = 'SATA/USB'
                elif name.startswith('vd'):
                    interface = 'VirtIO'
                elif name.startswith('mmcblk'):
                    interface = 'SD/MMC'
                else:
                    interface = 'Unknown'

                model = dev.get('model', '').strip() if dev.get('model') else 'Unknown'
                serial = dev.get('serial', '').strip() if dev.get('serial') else 'Unknown'
                vendor = dev.get('vendor', '').strip() if dev.get('vendor') else ''

                if vendor and model != 'Unknown':
                    model = f"{vendor} {model}".strip()

                disks.append(DiskInfo(
                    device_path=self._get_device_path(name),
                    name=name,
                    model=model or 'Unknown',
                    size=size,
                    serial=serial or 'Unknown',
                    interface=interface
                ))

            return sorted(disks, key=lambda x: x.name or '')

        except subprocess.TimeoutExpired:
            raise AcquisitionError("Timeout while enumerating physical disks")
        except json.JSONDecodeError as e:
            raise AcquisitionError(f"Failed to parse lsblk output: {e}")
        except Exception as e:
            raise AcquisitionError(f"Failed to enumerate physical disks: {str(e)}")

    def list_partitions(self) -> List[PartitionInfo]:
        """List all partitions using lsblk."""
        partitions = []

        try:
            result = subprocess.run(
                ['lsblk', '-Jbo', 'NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT,PKNAME'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                raise AcquisitionError(f"lsblk failed: {result.stderr}")

            data = json.loads(result.stdout)
            devices = data.get('blockdevices', [])

            def process_device(dev, parent_name=None):
                """Recursively process devices and their children."""
                dev_type = dev.get('type', '')
                name = dev.get('name', '')

                if dev_type == 'part':
                    size = dev.get('size', 0)
                    if isinstance(size, str):
                        size = self._parse_size(size)

                    partitions.append(PartitionInfo(
                        device_path=self._get_device_path(name),
                        size=size,
                        file_system=dev.get('fstype', 'Unknown') or 'Unknown',
                        label=dev.get('label', '') or '',
                        mount_point=dev.get('mountpoint'),
                        partition_type='partition',
                        disk_device=self._get_device_path(parent_name) if parent_name else None
                    ))

                for child in dev.get('children', []):
                    process_device(child, name)

            for dev in devices:
                process_device(dev)

            return sorted(partitions, key=lambda x: x.device_path)

        except subprocess.TimeoutExpired:
            raise AcquisitionError("Timeout while enumerating partitions")
        except json.JSONDecodeError as e:
            raise AcquisitionError(f"Failed to parse lsblk output: {e}")
        except Exception as e:
            raise AcquisitionError(f"Failed to enumerate partitions: {str(e)}")

    def _get_device_size(self, device_path: str) -> Optional[int]:
        """
        Get device size using multiple methods.

        Args:
            device_path: Device path

        Returns:
            Size in bytes or None
        """
        name = os.path.basename(device_path)
        base_name = name.rstrip('0123456789')
        if name != base_name:
            sys_path = f'/sys/class/block/{name}/size'
        else:
            sys_path = f'/sys/block/{name}/size'

        try:
            with open(sys_path, 'r') as f:
                sectors = int(f.read().strip())
                return sectors * 512
        except:
            pass

        try:
            result = subprocess.run(
                ['blockdev', '--getsize64', device_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return int(result.stdout.strip())
        except:
            pass

        try:
            with open(device_path, 'rb') as f:
                f.seek(0, 2)
                return f.tell()
        except:
            pass

        return None

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
        """Acquire a device to raw .dd format using standard Python I/O."""
        if not self.is_admin():
            raise AcquisitionError(
                "Root privileges required to acquire disks.\n"
                "Please run with: sudo python your_script.py"
            )

        if not device_path.startswith('/dev/'):
            device_path = f'/dev/{device_path}'

        if not os.path.exists(device_path):
            raise AcquisitionError(f"Device not found: {device_path}")

        hashers = create_hashers(compute_hashes)
        tracker = ProgressTracker()

        total_size = self._get_device_size(device_path)
        if total_size:
            tracker.total_size = total_size
            self.logger.info(f"Device size: {total_size:,} bytes ({total_size / (1024**3):.2f} GB)")
        else:
            self.logger.warning("Could not determine device size, will stream until EOF")

        acquisition_status = "complete"
        error_message = None
        src_file = None
        dst_file = None
        bytes_written = 0

        try:
            self.logger.info(f"Opening device: {device_path}")
            src_file = open(device_path, 'rb')

            self.logger.info(f"Writing to: {output_path}")
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            dst_file = open(output_path, 'wb')

            while True:
                if abort_check and abort_check():
                    self.logger.warning("Acquisition aborted by user")
                    acquisition_status = "aborted"
                    error_message = "Aborted by user"
                    break

                if max_bytes is not None and bytes_written >= max_bytes:
                    self.logger.info(f"Reached max_bytes limit: {max_bytes:,}")
                    break

                chunk = src_file.read(buffer_size)

                if not chunk:
                    self.logger.info("Reached end of device")
                    break

                dst_file.write(chunk)
                dst_file.flush()
                os.fsync(dst_file.fileno())

                for hasher in hashers.values():
                    hasher.update(chunk)

                bytes_written += len(chunk)

                if progress_callback and tracker.should_update_callback():
                    stats = tracker.update(bytes_written)
                    progress_callback(bytes_written, total_size, stats['speed_mbps'])

            src_file.close()
            src_file = None
            dst_file.close()
            dst_file = None

            tracker.update(bytes_written)
            final_stats = tracker.get_final_stats()

            if progress_callback:
                progress_callback(bytes_written, total_size or bytes_written, final_stats['speed_mbps'])

            self.logger.info(f"Acquisition {acquisition_status}: {bytes_written:,} bytes in {final_stats['duration_seconds']:.2f}s")

            return AcquisitionResult(
                success=acquisition_status == "complete",
                status=acquisition_status,
                output_path=output_path,
                device_path=device_path,
                bytes_written=bytes_written,
                duration_seconds=final_stats['duration_seconds'],
                speed_mbps=final_stats['speed_mbps'],
                start_time=final_stats['start_time'],
                end_time=final_stats['end_time'],
                hashes=finalize_hashes(hashers) if hashers else {},
                error=error_message
            )

        except PermissionError:
            raise AcquisitionError(
                f"Permission denied accessing {device_path}.\n"
                "Make sure you're running as root (sudo)."
            )

        except KeyboardInterrupt:
            self.logger.warning("Keyboard interrupt - saving partial acquisition")
            if src_file:
                src_file.close()
            if dst_file:
                dst_file.close()

            final_stats = tracker.get_final_stats()
            return AcquisitionResult(
                success=False,
                status="aborted",
                output_path=output_path,
                device_path=device_path,
                bytes_written=bytes_written,
                duration_seconds=final_stats['duration_seconds'],
                speed_mbps=final_stats['speed_mbps'],
                start_time=final_stats['start_time'],
                end_time=final_stats['end_time'],
                hashes=finalize_hashes(hashers) if hashers else {},
                error="Interrupted by user"
            )

        except Exception as e:
            self.logger.error(f"Acquisition failed: {str(e)}")
            if src_file:
                try:
                    src_file.close()
                except:
                    pass
            if dst_file:
                try:
                    dst_file.close()
                except:
                    pass

            if isinstance(e, AcquisitionError):
                raise
            raise AcquisitionError(f"Acquisition failed: {str(e)}")

    def dry_run_check(self, device_path: str) -> Dict:
        """Verify device can be opened without acquiring."""
        if not self.is_admin():
            raise AcquisitionError(
                "Root privileges required.\n"
                "Please run with sudo."
            )

        if not device_path.startswith('/dev/'):
            device_path = f'/dev/{device_path}'

        self.logger.info(f"DRY-RUN MODE: Checking device access for {device_path}")

        if not os.path.exists(device_path):
            raise AcquisitionError(f"Device not found: {device_path}")

        try:
            with open(device_path, 'rb') as f:
                f.read(512)
                self.logger.info(f"Device opened successfully: {device_path}")
        except PermissionError:
            raise AcquisitionError(
                f"Permission denied accessing {device_path}.\n"
                "Make sure you're running as root (sudo)."
            )
        except Exception as e:
            raise AcquisitionError(f"Cannot open device: {e}")

        total_size = self._get_device_size(device_path)
        size_available = total_size is not None

        if size_available:
            self.logger.info(f"Device size: {total_size:,} bytes ({total_size / (1024**3):.2f} GB)")
        else:
            self.logger.warning("Could not determine device size")

        return {
            'success': True,
            'device_path': device_path,
            'size_bytes': total_size,
            'size_available': size_available,
            'can_acquire': True
        }

    def get_device_size(self, device_path: str) -> Optional[int]:
        """Get device size in bytes."""
        if not device_path.startswith('/dev/'):
            device_path = f'/dev/{device_path}'
        return self._get_device_size(device_path)
