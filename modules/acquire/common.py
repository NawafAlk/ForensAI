"""
ForensAI - Acquisition Common Utilities
Shared utilities for hash computation, metadata, and progress tracking.
"""

import os
import json
import hashlib
import platform
import time
import logging
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

from .base import AcquisitionError


def get_logger(name: str = __name__) -> logging.Logger:
    """
    Get or create a logger with standard formatting.

    Args:
        name: Logger name

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def create_hashers(hash_types: Optional[List[str]] = None) -> Dict[str, 'hashlib._Hash']:
    """
    Create hash objects for specified types.

    Args:
        hash_types: List of hash types ['md5', 'sha1', 'sha256']

    Returns:
        Dictionary mapping hash type to hasher object
    """
    hashers = {}
    if hash_types:
        for hash_type in hash_types:
            hash_type = hash_type.lower()
            if hash_type == 'md5':
                hashers[hash_type] = hashlib.md5()
            elif hash_type == 'sha1':
                hashers[hash_type] = hashlib.sha1()
            elif hash_type == 'sha256':
                hashers[hash_type] = hashlib.sha256()
    return hashers


def finalize_hashes(hashers: Dict[str, 'hashlib._Hash']) -> Dict[str, str]:
    """
    Get final hex digests from hash objects.

    Args:
        hashers: Dictionary of hash objects

    Returns:
        Dictionary mapping hash type to hex digest
    """
    return {
        hash_type: hasher.hexdigest()
        for hash_type, hasher in hashers.items()
    }


def verify_hash(file_path: str, hash_type: str = 'md5') -> str:
    """
    Calculate hash of a file.

    Args:
        file_path: Path to the file to hash
        hash_type: Type of hash ('md5', 'sha1', 'sha256')

    Returns:
        str: Hexadecimal hash string

    Raises:
        AcquisitionError: If hashing fails
    """
    hash_type = hash_type.lower()

    if hash_type == 'md5':
        hasher = hashlib.md5()
    elif hash_type == 'sha1':
        hasher = hashlib.sha1()
    elif hash_type == 'sha256':
        hasher = hashlib.sha256()
    else:
        raise AcquisitionError(f"Unsupported hash type: {hash_type}")

    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)

        return hasher.hexdigest()

    except Exception as e:
        raise AcquisitionError(f"Failed to calculate {hash_type.upper()} hash: {str(e)}")


def write_metadata_json(
    output_path: str,
    metadata: Dict[str, any]
) -> str:
    """
    Write acquisition metadata to JSON file.

    Args:
        output_path: Base path for the image file (the .dd file)
        metadata: Dictionary containing metadata

    Returns:
        str: Path to the written metadata file
    """
    metadata_path = output_path + '.metadata.json'

    metadata['tool'] = 'ForensAI'
    metadata['tool_version'] = '1.0.0'
    metadata['acquisition_host'] = platform.node()
    metadata['acquisition_os'] = f"{platform.system()} {platform.release()}"

    try:
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        return metadata_path

    except Exception as e:
        raise AcquisitionError(f"Failed to write metadata: {str(e)}")


def format_size(size_bytes: int) -> str:
    """
    Format byte size as human-readable string.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 GB")
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024**2:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024**3:
        return f"{size_bytes / 1024**2:.2f} MB"
    else:
        return f"{size_bytes / 1024**3:.2f} GB"


def simulate_acquisition(
    output_dir: str,
    size_mb: int = 100,
    compute_hashes: Optional[List[str]] = None
) -> Dict[str, any]:
    """
    Simulate an acquisition for testing (dry-run mode).
    Creates a dummy image file with deterministic data.

    Args:
        output_dir: Directory for output files
        size_mb: Size of dummy image in MB
        compute_hashes: List of hash types to compute

    Returns:
        Dict containing simulated acquisition results
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    output_path = os.path.join(output_dir, f"image_{timestamp}.dd")

    hashers = create_hashers(compute_hashes)

    start_time = time.time()

    with open(output_path, 'wb') as f:
        chunk_size = 1024 * 1024
        total_written = 0
        target_size = size_mb * 1024 * 1024

        while total_written < target_size:
            chunk = bytes([(total_written + i) % 256 for i in range(min(chunk_size, target_size - total_written))])
            f.write(chunk)

            for hasher in hashers.values():
                hasher.update(chunk)

            total_written += len(chunk)

    end_time = time.time()
    duration = end_time - start_time

    result = {
        'success': True,
        'output_path': output_path,
        'size_bytes': total_written,
        'duration_seconds': duration,
        'speed_mbps': (total_written / (1024 * 1024)) / duration if duration > 0 else 0,
        'started_at': datetime.fromtimestamp(start_time).isoformat(),
        'finished_at': datetime.fromtimestamp(end_time).isoformat(),
        'simulated': True
    }

    if hashers:
        result['hashes'] = finalize_hashes(hashers)

    return result


def acquire_with_ewfacquire(
    drive_number: int,
    output_path: str,
    progress_callback=None,
    abort_check=None,
    metadata: Dict = None
) -> Dict[str, any]:
    """
    Acquire a physical disk to E01 format using ewfacquire (if available).

    This function works on both Windows and Linux if ewfacquire/libewf is installed.

    Args:
        drive_number: Physical drive number (Windows) or device path (Linux)
        output_path: Output file path (without .E01 extension)
        progress_callback: Optional callback function
        abort_check: Optional abort check function
        metadata: Optional metadata dictionary

    Returns:
        Dict containing acquisition results

    Raises:
        AcquisitionError: If ewfacquire is not available or acquisition fails
    """
    try:
        result = subprocess.run(['ewfacquire', '-V'], capture_output=True, timeout=5)
        if result.returncode != 0:
            raise FileNotFoundError()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        raise AcquisitionError(
            "ewfacquire is not available. Please install libewf-tools or use raw .dd format.\n"
            "Ubuntu/Debian: sudo apt install libewf-tools\n"
            "Windows: Download from https://github.com/libyal/libewf"
        )

    if platform.system() == 'Windows':
        if isinstance(drive_number, int):
            device_path = f"\\\\.\\PHYSICALDRIVE{drive_number}"
        else:
            device_path = str(drive_number)
    else:
        if isinstance(drive_number, int):
            device_path = f"/dev/sd{chr(ord('a') + drive_number)}"
        elif str(drive_number).startswith('/dev/'):
            device_path = str(drive_number)
        else:
            device_path = f"/dev/{drive_number}"

    cmd = [
        'ewfacquire',
        '-t', output_path,
        '-u',
        device_path
    ]

    start_time = time.time()

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in process.stdout:
            if abort_check and abort_check():
                process.terminate()
                raise AcquisitionError("Acquisition aborted by user")

            if progress_callback:
                pass

        process.wait()

        if process.returncode != 0:
            raise AcquisitionError(f"ewfacquire failed with return code {process.returncode}")

        end_time = time.time()
        duration = end_time - start_time

        return {
            'success': True,
            'output_path': output_path + '.E01',
            'duration_seconds': duration,
            'started_at': datetime.fromtimestamp(start_time).isoformat(),
            'finished_at': datetime.fromtimestamp(end_time).isoformat(),
            'format': 'E01'
        }

    except Exception as e:
        if isinstance(e, AcquisitionError):
            raise
        raise AcquisitionError(f"E01 acquisition failed: {str(e)}")


class ProgressTracker:
    """
    Track acquisition progress and calculate statistics.
    """

    def __init__(self, total_size: Optional[int] = None):
        """
        Initialize progress tracker.

        Args:
            total_size: Total expected size in bytes (if known)
        """
        self.total_size = total_size
        self.bytes_processed = 0
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.last_update_bytes = 0

    def update(self, bytes_processed: int) -> Dict[str, float]:
        """
        Update progress and calculate statistics.

        Args:
            bytes_processed: Total bytes processed so far

        Returns:
            Dict with progress statistics
        """
        self.bytes_processed = bytes_processed
        current_time = time.time()

        elapsed = current_time - self.start_time
        speed_mbps = (bytes_processed / (1024 * 1024)) / elapsed if elapsed > 0 else 0

        if self.total_size and self.total_size > 0:
            percent = (bytes_processed / self.total_size) * 100
        else:
            percent = None

        if self.total_size and speed_mbps > 0:
            remaining_bytes = self.total_size - bytes_processed
            eta_seconds = remaining_bytes / (speed_mbps * 1024 * 1024)
        else:
            eta_seconds = None

        return {
            'bytes_processed': bytes_processed,
            'total_size': self.total_size,
            'percent': percent,
            'speed_mbps': speed_mbps,
            'elapsed_seconds': elapsed,
            'eta_seconds': eta_seconds
        }

    def should_update_callback(self, interval: float = 0.25) -> bool:
        """
        Check if enough time has passed to update progress callback.

        Args:
            interval: Minimum seconds between updates

        Returns:
            True if callback should be updated
        """
        current_time = time.time()
        if current_time - self.last_update_time >= interval:
            self.last_update_time = current_time
            return True
        return False

    def get_final_stats(self) -> Dict[str, float]:
        """
        Get final acquisition statistics.

        Returns:
            Dict with final statistics
        """
        end_time = time.time()
        duration = end_time - self.start_time
        speed_mbps = (self.bytes_processed / (1024 * 1024)) / duration if duration > 0 else 0

        return {
            'bytes_written': self.bytes_processed,
            'duration_seconds': duration,
            'speed_mbps': speed_mbps,
            'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
            'end_time': datetime.fromtimestamp(end_time).isoformat()
        }
