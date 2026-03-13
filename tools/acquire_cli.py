#!/usr/bin/env python3
"""
ForensAI - Command Line Acquisition Tool
Provides cross-platform CLI interface for physical disk acquisition.
Supports Windows and Linux.
"""

import sys
import os
import argparse
import json
import platform
from datetime import datetime

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.acquire import (
    list_physical_disks,
    list_partitions,
    acquire_raw,
    simulate_acquisition,
    write_metadata_json,
    dry_run_check,
    is_admin,
    get_platform,
    AcquisitionError
)
import logging

# Detect platform for platform-specific messages
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'


def format_size(bytes_size):
    """Format bytes as human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


def get_privilege_message():
    """Get platform-specific privilege instructions."""
    if IS_WINDOWS:
        return (
            "Please run this script as Administrator:\n"
            "  1. Right-click on Command Prompt or PowerShell\n"
            "  2. Select 'Run as administrator'\n"
            "  3. Run the command again"
        )
    else:
        return (
            "Please run this script with root privileges:\n"
            "  sudo python acquire_cli.py <command>"
        )


def get_verify_command(file_path):
    """Get platform-specific verification command."""
    if IS_WINDOWS:
        return f'certutil -hashfile "{file_path}" MD5'
    else:
        return f'md5sum "{file_path}"'


def list_disks_command():
    """List available physical disks."""
    print("=" * 80)
    print(f"Available Physical Disks ({get_platform()})")
    print("=" * 80)

    if not is_admin():
        print(f"\nERROR: {'Administrator' if IS_WINDOWS else 'Root'} privileges required to list physical disks.")
        print(get_privilege_message() + "\n")
        return 1

    try:
        disks = list_physical_disks()

        if not disks:
            print("\nNo physical disks found.\n")
            return 0

        for disk in disks:
            if IS_WINDOWS:
                print(f"\nPhysical Drive {disk.number}:")
            else:
                print(f"\nDisk {disk.name}:")
            print(f"  Device Path: {disk.device_path}")
            print(f"  Model:       {disk.model}")
            print(f"  Size:        {format_size(disk.size)} ({disk.size:,} bytes)")
            print(f"  Serial:      {disk.serial}")
            print(f"  Interface:   {disk.interface}")

        print("\n" + "=" * 80)
        print(f"Total: {len(disks)} disk(s)")
        print("=" * 80 + "\n")

        return 0

    except AcquisitionError as e:
        print(f"\nERROR: {str(e)}\n")
        return 1


def list_partitions_command():
    """List available partitions/volumes."""
    print("=" * 80)
    print(f"Available {'Logical Drives' if IS_WINDOWS else 'Partitions'} ({get_platform()})")
    print("=" * 80)

    try:
        partitions = list_partitions()

        if not partitions:
            print("\nNo partitions found.\n")
            return 0

        for part in partitions:
            if part.size == 0:
                continue

            if IS_WINDOWS:
                print(f"\nLogical Drive {part.drive_letter}:")
                print(f"  Label:       {part.label}")
            else:
                print(f"\nPartition {os.path.basename(part.device_path)}:")
                if part.label:
                    print(f"  Label:       {part.label}")
                if part.mount_point:
                    print(f"  Mount Point: {part.mount_point}")

            print(f"  Device Path: {part.device_path}")
            print(f"  File System: {part.file_system}")
            print(f"  Size:        {format_size(part.size)} ({part.size:,} bytes)")
            print(f"  Type:        {part.partition_type}")

        valid_parts = [p for p in partitions if p.size > 0]
        print("\n" + "=" * 80)
        print(f"Total: {len(valid_parts)} partition(s)")
        print("=" * 80 + "\n")

        return 0

    except AcquisitionError as e:
        print(f"\nERROR: {str(e)}\n")
        return 1


def acquire_command(args):
    """Execute disk acquisition."""
    print("=" * 80)
    print(f"ForensAI - Physical Disk Acquisition ({get_platform()})")
    print("=" * 80)

    if not is_admin():
        print(f"\nERROR: {'Administrator' if IS_WINDOWS else 'Root'} privileges required for acquisition.")
        print(get_privilege_message() + "\n")
        return 1

    # Parse hash types
    hash_types = []
    if args.md5:
        hash_types.append('md5')
    if args.sha1:
        hash_types.append('sha1')
    if args.sha256:
        hash_types.append('sha256')

    if not hash_types:
        print("\nERROR: Please specify at least one hash type (--md5, --sha1, or --sha256)\n")
        return 1

    # Determine device path
    device_path = None
    device_description = ""
    confirmation_token = ""

    if hasattr(args, 'device') and args.device:
        device_path = args.device
        device_description = device_path
        # Generate confirmation token
        basename = os.path.basename(device_path.replace('\\', '/').rstrip(':'))
        confirmation_token = f"CONFIRM {basename.upper()}"

    elif IS_WINDOWS and hasattr(args, 'drive_letter') and args.drive_letter:
        drive_letter = args.drive_letter
        device_path = drive_letter
        device_description = f"\\\\.\\{drive_letter}:" if not drive_letter.endswith(':') else f"\\\\.\\{drive_letter}"
        letter = drive_letter.replace(':', '').strip()
        confirmation_token = f"CONFIRM DRIVE {letter.upper()}"

    elif hasattr(args, 'drive') and args.drive is not None:
        if IS_WINDOWS:
            device_path = str(args.drive)
            device_description = f"\\\\.\\PHYSICALDRIVE{args.drive}"
            confirmation_token = f"CONFIRM PHYSICALDRIVE{args.drive}"
        else:
            # Linux: assume sdX if integer
            device_path = f"/dev/sd{chr(ord('a') + args.drive)}"
            device_description = device_path
            confirmation_token = f"CONFIRM {os.path.basename(device_path).upper()}"

    else:
        if IS_WINDOWS:
            print("\nERROR: Must specify --drive, --device, or --drive-letter\n")
        else:
            print("\nERROR: Must specify --drive or --device\n")
        return 1

    # Try to get disk information for display
    disk_info = None
    try:
        disks = list_physical_disks()
        if IS_WINDOWS and hasattr(args, 'drive') and args.drive is not None:
            disk_info = next((d for d in disks if d.number == args.drive), None)
        elif IS_LINUX and device_path:
            disk_info = next((d for d in disks if d.device_path == device_path), None)

        if hasattr(args, 'drive') and args.drive is not None and not disk_info:
            print(f"\nWARNING: Device not found in enumeration.")
            print("Available devices:")
            for d in disks:
                print(f"  {d.device_path}: {d.model} ({format_size(d.size)})")
            print("\nProceeding anyway (device may still be accessible)...\n")
    except AcquisitionError as e:
        print(f"\nWARNING: Could not enumerate disks: {str(e)}")
        print("Proceeding anyway...\n")

    # Display acquisition details
    print(f"\nDevice: {device_description}")
    if disk_info:
        print(f"Model:  {disk_info.model}")
        print(f"Size:   {format_size(disk_info.size)} ({disk_info.size:,} bytes)")
        print(f"Serial: {disk_info.serial}")
    print(f"\nOutput: {args.output}")
    print(f"Format: {args.format.upper()}")
    print(f"Hashes: {', '.join([h.upper() for h in hash_types])}")
    print(f"Operator: {args.operator}")

    if args.notes:
        print(f"Notes: {args.notes}")

    print("\n" + "=" * 80)

    # Require confirmation
    print(f"\nWARNING: This will image the entire device!")
    print(f"To proceed, type exactly: {confirmation_token}\n")

    try:
        user_input = input("Confirmation: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n\nAcquisition cancelled.\n")
        return 0

    if user_input != confirmation_token:
        print(f"\nERROR: Confirmation string mismatch.")
        print(f"Expected: {confirmation_token}")
        print(f"Got:      {user_input}")
        print("\nAcquisition cancelled.\n")
        return 1

    # Prepare metadata
    metadata = {
        'operator': args.operator,
        'notes': args.notes or '',
        'source_device': device_description,
    }

    if disk_info:
        metadata.update({
            'source_model': disk_info.model,
            'source_serial': disk_info.serial,
            'source_size_bytes': disk_info.size
        })

    # Setup logger
    logger = logging.getLogger('forensai.acquire')
    logger.setLevel(logging.DEBUG if hasattr(args, 'verbose') and args.verbose else logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Get chunk size
    chunk_size = args.chunk if hasattr(args, 'chunk') and args.chunk else (4 * 1024 * 1024)

    # Progress callback
    last_progress = [0]

    def progress_callback(bytes_read, total_bytes, speed_mbps):
        if total_bytes and total_bytes > 0:
            progress = int((bytes_read / total_bytes) * 100)
            if progress != last_progress[0] or progress == 100:
                print(
                    f"\rProgress: {progress:3d}% "
                    f"({format_size(bytes_read)} / {format_size(total_bytes)}) "
                    f"- Speed: {speed_mbps:.2f} MB/s",
                    end='', flush=True
                )
                last_progress[0] = progress
        else:
            print(
                f"\rProgress: {format_size(bytes_read)} - Speed: {speed_mbps:.2f} MB/s",
                end='', flush=True
            )

    print("\n" + "=" * 80)
    print("Starting acquisition...")
    print("=" * 80 + "\n")

    # Safety notes
    print("SAFETY NOTES:")
    if IS_WINDOWS:
        print("  - Close cloud sync applications (Dropbox, OneDrive, etc.)")
        print("  - Unplug non-target removable disks to avoid mistakes")
    else:
        print("  - Ensure the device is not mounted (umount if necessary)")
        print("  - Unplug non-target removable disks to avoid mistakes")
    print()

    result = None
    exit_code = 0

    try:
        if args.format == 'raw':
            acq_result = acquire_raw(
                device_path=device_path,
                output_path=args.output,
                progress_callback=progress_callback,
                abort_check=None,
                compute_hashes=hash_types,
                buffer_size=chunk_size,
                max_bytes=args.max_bytes if hasattr(args, 'max_bytes') else None
            )
            # Convert to dict for compatibility
            result = acq_result.to_dict()
        elif args.format == 'e01':
            print("\nERROR: E01 format requires ewfacquire to be installed\n")
            return 1
        else:
            print(f"\nERROR: Unknown format: {args.format}\n")
            return 1

        print("\n\n" + "=" * 80)
        if result['status'] == 'complete':
            print("Acquisition Complete!")
        else:
            print(f"Acquisition {result['status'].upper()}")
        print("=" * 80)
        print(f"\nOutput file: {result['output_path']}")
        print(f"Size:        {format_size(result['bytes_written'])} ({result['bytes_written']:,} bytes)")
        print(f"Duration:    {result['duration_seconds']:.2f} seconds")
        print(f"Speed:       {result['speed_mbps']:.2f} MB/s")
        print(f"Status:      {result['status']}")

        if 'hashes' in result:
            print("\nHashes:")
            for hash_type, hash_value in result['hashes'].items():
                print(f"  {hash_type.upper():6s}: {hash_value}")

        # Prepare metadata for JSON
        metadata_for_json = {
            'operator': metadata['operator'],
            'notes': metadata['notes'],
            'device': result.get('device_path', device_description),
            'output_file': result['output_path'],
            'bytes_written': result['bytes_written'],
            'start_time': result.get('start_time'),
            'end_time': result.get('end_time'),
            'status': result['status']
        }

        if 'hashes' in result:
            metadata_for_json['hashes'] = result['hashes']

        if 'error' in result:
            metadata_for_json['error'] = result['error']

        # Write metadata
        metadata_path = write_metadata_json(result['output_path'], metadata_for_json)
        print(f"\nMetadata:    {metadata_path}")

        print("\n" + "=" * 80)
        print("Verification command (MD5):")
        print(f"  {get_verify_command(result['output_path'])}")
        print("=" * 80 + "\n")

        return 0 if result['status'] == 'complete' else 1

    except KeyboardInterrupt:
        print("\n\n" + "=" * 80)
        print("INTERRUPTED - Saving partial acquisition")
        print("=" * 80 + "\n")

        if result:
            metadata_for_json = {
                'operator': metadata['operator'],
                'notes': metadata['notes'],
                'device': result.get('device_path', device_description),
                'output_file': result['output_path'],
                'bytes_written': result['bytes_written'],
                'start_time': result.get('start_time'),
                'end_time': result.get('end_time'),
                'status': result['status'],
                'error': result.get('error', 'Interrupted by user')
            }

            if 'hashes' in result:
                metadata_for_json['hashes'] = result['hashes']

            try:
                metadata_path = write_metadata_json(result['output_path'], metadata_for_json)
                print(f"Partial acquisition saved: {result['output_path']}")
                print(f"Bytes written: {result['bytes_written']:,}")
                print(f"Metadata: {metadata_path}")
            except Exception as e:
                print(f"Warning: Could not write metadata: {e}")

        print("\nPartial file has been preserved for forensic analysis.")
        print("Check metadata.json for details.\n")
        return 2

    except AcquisitionError as e:
        print(f"\n\nERROR: {str(e)}\n")
        return 1
    except Exception as e:
        print(f"\n\nUNEXPECTED ERROR: {str(e)}\n")
        import traceback
        traceback.print_exc()
        return 1


def dry_run_device_check(args):
    """Execute dry-run device check."""
    print("=" * 80)
    print(f"ForensAI - Dry-Run Device Check ({get_platform()})")
    print("=" * 80)

    if not is_admin():
        print(f"\nERROR: {'Administrator' if IS_WINDOWS else 'Root'} privileges required.")
        print(get_privilege_message() + "\n")
        return 1

    # Determine device path
    device_path = None
    device_description = ""

    if hasattr(args, 'device') and args.device:
        device_path = args.device
        device_description = device_path
    elif IS_WINDOWS and hasattr(args, 'drive_letter') and args.drive_letter:
        device_path = args.drive_letter
        device_description = f"\\\\.\\{args.drive_letter}:"
    elif hasattr(args, 'drive') and args.drive is not None:
        if IS_WINDOWS:
            device_path = str(args.drive)
            device_description = f"\\\\.\\PHYSICALDRIVE{args.drive}"
        else:
            device_path = f"/dev/sd{chr(ord('a') + args.drive)}"
            device_description = device_path
    else:
        if IS_WINDOWS:
            print("\nERROR: Must specify --drive, --device, or --drive-letter\n")
        else:
            print("\nERROR: Must specify --drive or --device\n")
        return 1

    print(f"\nDevice: {device_description}\n")

    try:
        result = dry_run_check(device_path)

        print("\n" + "=" * 80)
        print("DRY-RUN RESULT: READY FOR ACQUISITION")
        print("=" * 80)
        print(f"\nDevice: {result['device_path']}")
        if result['size_available']:
            print(f"Size:   {format_size(result['size_bytes'])} ({result['size_bytes']:,} bytes)")
        else:
            print("Size:   Unknown (will stream until EOF)")
        print("\nThis device can be acquired successfully.")
        print("=" * 80 + "\n")

        return 0

    except AcquisitionError as e:
        print(f"\n\nERROR: {str(e)}\n")
        return 1


def dry_run_simulation(args):
    """Execute dry-run simulation."""
    print("=" * 80)
    print("ForensAI - Dry Run Simulation")
    print("=" * 80)

    # Parse hash types
    hash_types = []
    if args.md5:
        hash_types.append('md5')
    if args.sha1:
        hash_types.append('sha1')
    if args.sha256:
        hash_types.append('sha256')

    if not hash_types:
        hash_types = ['md5', 'sha1']

    print(f"\nOutput directory: {args.output}")
    print(f"Simulated size:   {args.size} MB")
    print(f"Hashes:           {', '.join([h.upper() for h in hash_types])}")
    print(f"Operator:         {args.operator}")

    if args.notes:
        print(f"Notes:            {args.notes}")

    print("\n" + "=" * 80)
    print("Starting simulation...")
    print("=" * 80 + "\n")

    try:
        result = simulate_acquisition(
            output_dir=args.output,
            size_mb=args.size,
            compute_hashes=hash_types
        )

        metadata = {
            'operator': args.operator,
            'notes': args.notes or 'Dry-run simulation',
            'source_device': 'SIMULATED',
            'source_model': 'Simulation Device',
            'source_serial': 'SIM-' + datetime.now().strftime("%Y%m%d%H%M%S"),
            'source_size_bytes': result['size_bytes']
        }

        result.update(metadata)

        metadata_path = write_metadata_json(result['output_path'], result)

        log_path = result['output_path'] + '.log'
        with open(log_path, 'w') as log_file:
            log_file.write("ForensAI Acquisition Log (Dry-Run Simulation)\n")
            log_file.write("=" * 80 + "\n\n")
            log_file.write(f"Started:  {result['started_at']}\n")
            log_file.write(f"Finished: {result['finished_at']}\n")
            log_file.write(f"Duration: {result['duration_seconds']:.2f} seconds\n")
            log_file.write(f"Size:     {result['size_bytes']:,} bytes\n")
            log_file.write(f"Speed:    {result['speed_mbps']:.2f} MB/s\n\n")

            if 'hashes' in result:
                log_file.write("Hashes:\n")
                for hash_type, hash_value in result['hashes'].items():
                    log_file.write(f"  {hash_type.upper()}: {hash_value}\n")

            log_file.write("\nThis was a DRY-RUN simulation. No real device was imaged.\n")

        print("=" * 80)
        print("Simulation Complete!")
        print("=" * 80)
        print(f"\nOutput file: {result['output_path']}")
        print(f"Size:        {format_size(result['size_bytes'])} ({result['size_bytes']:,} bytes)")
        print(f"Duration:    {result['duration_seconds']:.2f} seconds")
        print(f"Speed:       {result['speed_mbps']:.2f} MB/s")

        if 'hashes' in result:
            print("\nHashes:")
            for hash_type, hash_value in result['hashes'].items():
                print(f"  {hash_type.upper():6s}: {hash_value}")

        print(f"\nMetadata:    {metadata_path}")
        print(f"Log file:    {log_path}")

        print("\n" + "=" * 80 + "\n")

        return 0

    except Exception as e:
        print(f"\n\nERROR: {str(e)}\n")
        return 1


def main():
    """Main entry point."""
    # Platform-specific examples
    if IS_WINDOWS:
        examples = """
Examples (Windows):

  List available physical disks:
    python acquire_cli.py list

  List available logical drives (volumes/partitions):
    python acquire_cli.py list-logical

  Acquire physical drive by number:
    python acquire_cli.py acquire --drive 1 --output C:\\Evidence\\disk1.dd --md5 --sha1 --operator "John Doe"

  Acquire logical drive by letter:
    python acquire_cli.py acquire --drive-letter E: --output C:\\Evidence\\partition_E.dd --md5 --sha256 --operator "Jane Smith"

  Dry-run check:
    python acquire_cli.py dry-run --drive 1
    python acquire_cli.py dry-run --drive-letter E:

  Simulate acquisition:
    python acquire_cli.py simulate --output C:\\Evidence\\sample --size 100 --operator "Test User"
"""
    else:
        examples = """
Examples (Linux):

  List available physical disks:
    sudo python acquire_cli.py list

  List available partitions:
    sudo python acquire_cli.py list-logical

  Acquire physical drive:
    sudo python acquire_cli.py acquire --device /dev/sdb --output /evidence/disk.dd --md5 --sha1 --operator "John Doe"

  Acquire using drive index (sda=0, sdb=1, etc.):
    sudo python acquire_cli.py acquire --drive 1 --output /evidence/disk1.dd --md5 --sha256 --operator "Jane Smith"

  Dry-run check:
    sudo python acquire_cli.py dry-run --device /dev/sdb
    sudo python acquire_cli.py dry-run --drive 1

  Simulate acquisition:
    python acquire_cli.py simulate --output /tmp/sample --size 100 --operator "Test User"
"""

    parser = argparse.ArgumentParser(
        description=f'ForensAI Physical Disk Acquisition CLI ({get_platform()})',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples + """
IMPORTANT: Real acquisitions require explicit confirmation string.
NOTE: Files are written directly to .dd (no temp file) for crash safety with flush+fsync.
"""
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # List physical disks command
    subparsers.add_parser('list', help='List available physical disks')

    # List partitions command
    subparsers.add_parser('list-logical', help='List available partitions/volumes')

    # Acquire command
    acquire_parser = subparsers.add_parser('acquire', help='Acquire a physical disk')

    # Device selection
    device_group = acquire_parser.add_mutually_exclusive_group(required=True)
    device_group.add_argument('--drive', type=int,
                              help='Drive index (Windows: PHYSICALDRIVE#, Linux: sd[a+#])')
    device_group.add_argument('--device',
                              help='Device path (Windows: "\\\\.\\PhysicalDrive1", Linux: "/dev/sdb")')
    if IS_WINDOWS:
        device_group.add_argument('--drive-letter',
                                  help='Drive letter (Windows only, e.g., "E:" or "E")')

    acquire_parser.add_argument('--output', required=True,
                                help='Output file path')
    acquire_parser.add_argument('--format', choices=['raw', 'e01'], default='raw',
                                help='Output format (default: raw)')
    acquire_parser.add_argument('--md5', action='store_true',
                                help='Compute MD5 hash')
    acquire_parser.add_argument('--sha1', action='store_true',
                                help='Compute SHA1 hash')
    acquire_parser.add_argument('--sha256', action='store_true',
                                help='Compute SHA256 hash')
    acquire_parser.add_argument('--operator', required=True,
                                help='Operator name')
    acquire_parser.add_argument('--notes', default='',
                                help='Case notes')
    acquire_parser.add_argument('--chunk', type=int,
                                help='Chunk size in bytes (default: 4MB)')
    acquire_parser.add_argument('--max-bytes', type=int,
                                help='Maximum bytes to acquire (for sampling)')
    acquire_parser.add_argument('--verbose', action='store_true',
                                help='Enable verbose logging')

    # Dry-run device check
    dry_run_parser = subparsers.add_parser('dry-run', help='Check device access without writing')
    dry_run_device_group = dry_run_parser.add_mutually_exclusive_group(required=True)
    dry_run_device_group.add_argument('--drive', type=int,
                                      help='Drive index')
    dry_run_device_group.add_argument('--device',
                                      help='Device path')
    if IS_WINDOWS:
        dry_run_device_group.add_argument('--drive-letter',
                                          help='Drive letter (Windows only)')
    dry_run_parser.add_argument('--verbose', action='store_true',
                                help='Enable verbose logging')

    # Simulation command
    sim_parser = subparsers.add_parser('simulate', help='Create simulated acquisition files')
    sim_parser.add_argument('--output', required=True,
                            help='Output directory for simulated files')
    sim_parser.add_argument('--size', type=int, default=100,
                            help='Simulated image size in MB (default: 100)')
    sim_parser.add_argument('--md5', action='store_true', default=True,
                            help='Compute MD5 hash (default: True)')
    sim_parser.add_argument('--sha1', action='store_true', default=True,
                            help='Compute SHA1 hash (default: True)')
    sim_parser.add_argument('--sha256', action='store_true',
                            help='Compute SHA256 hash')
    sim_parser.add_argument('--operator', default='Simulation User',
                            help='Operator name (default: Simulation User)')
    sim_parser.add_argument('--notes', default='',
                            help='Case notes')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'list':
        return list_disks_command()
    elif args.command == 'list-logical':
        return list_partitions_command()
    elif args.command == 'acquire':
        return acquire_command(args)
    elif args.command == 'dry-run':
        return dry_run_device_check(args)
    elif args.command == 'simulate':
        return dry_run_simulation(args)
    else:
        print(f"Unknown command: {args.command}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
