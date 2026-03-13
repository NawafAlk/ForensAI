# ForensAI Acquisition Runbook

## Windows Physical Disk Acquisition Guide

This runbook describes how to safely acquire physical disks and removable media on Windows using ForensAI's command-line acquisition tool.

---

## Prerequisites

1. **Windows 10/11** with Administrator privileges
2. **Python 3.7+** installed
3. **ForensAI** repository cloned or installed
4. **IMPORTANT**: Close cloud sync applications (Dropbox, OneDrive, Google Drive, etc.)
5. **IMPORTANT**: Unplug non-target removable disks to avoid mistakes

---

## Step 1: Run as Administrator

The acquisition tool requires Administrator privileges to access raw disk devices.

### PowerShell:
```powershell
# Right-click PowerShell and select "Run as administrator"
cd C:\Users\NAWAF\Dropbox\PC\Desktop\projects\ForensAI
```

### Command Prompt:
```cmd
# Right-click Command Prompt and select "Run as administrator"
cd C:\Users\NAWAF\Dropbox\PC\Desktop\projects\ForensAI
```

---

## Step 2: List Available Devices

Before acquiring, list all available physical disks:

```bash
python tools/acquire_cli.py list
```

**Example Output:**
```
================================================================================
Available Physical Disks
================================================================================

Physical Drive 0:
  Device Path: \\.\PHYSICALDRIVE0
  Model:       Samsung SSD 970 EVO Plus 500GB
  Size:        500.11 GB (500,107,862,016 bytes)
  Serial:      S4P2NF0N123456
  Interface:   SCSI

Physical Drive 1:
  Device Path: \\.\PHYSICALDRIVE1
  Model:       SanDisk Ultra USB 3.0
  Size:        15.20 GB (16,000,000,000 bytes)
  Serial:      4C530001234567890123
  Interface:   USB

================================================================================
Total: 2 disk(s)
================================================================================
```

**Note:** Physical Drive 0 is typically your system disk. Be careful not to image it accidentally.

---

## Step 3: Dry-Run Check (Recommended)

Before performing a real acquisition, verify device access with a dry-run check:

```bash
# Check by drive number
python tools/acquire_cli.py dry-run --drive 1

# Check by drive letter (for removable media)
python tools/acquire_cli.py dry-run --drive-letter E:

# Check with verbose logging
python tools/acquire_cli.py dry-run --drive 1 --verbose
```

**Example Output:**
```
================================================================================
ForensAI - Dry-Run Device Check
================================================================================

Device: \\.\PHYSICALDRIVE1

DRY-RUN MODE: Checking device access...
Attempting to open: \\.\PHYSICALDRIVE1
✓ Device opened successfully: \\.\PHYSICALDRIVE1
✓ Device size: 16,000,000,000 bytes (14.90 GB)
✓ Device closed successfully

================================================================================
DRY-RUN RESULT: READY FOR ACQUISITION
================================================================================

Device: \\.\PHYSICALDRIVE1
Size:   14.90 GB (16,000,000,000 bytes)

This device can be acquired successfully.
================================================================================
```

---

## Step 4: Acquire the Device

### Option A: Acquire by Physical Drive Number

```bash
python tools/acquire_cli.py acquire \
    --drive 1 \
    --output "C:\ForensAI_Evidence\image_physicaldrive1.dd" \
    --md5 --sha256 \
    --operator "NAWAF"
```

**Confirmation Required:** `CONFIRM PHYSICALDRIVE1`

### Option B: Acquire by Drive Letter (for USB/removable media)

```bash
python tools/acquire_cli.py acquire \
    --drive-letter E: \
    --output "C:\ForensAI_Evidence\usb_drive_E.dd" \
    --md5 --sha1 --sha256 \
    --operator "NAWAF" \
    --notes "USB flash drive from suspect laptop"
```

**Confirmation Required:** `CONFIRM DRIVE E`

### Option C: Acquire by Direct Device Path

```bash
python tools/acquire_cli.py acquire \
    --device "\\.\PHYSICALDRIVE1" \
    --output "C:\ForensAI_Evidence\evidence_001.dd" \
    --sha256 \
    --operator "NAWAF"
```

### Option D: Sample Acquisition (First N Bytes Only)

For testing or sampling, you can limit the acquisition:

```bash
python tools/acquire_cli.py acquire \
    --drive 1 \
    --output "C:\ForensAI_Evidence\sample_100MB.dd" \
    --max-bytes 100000000 \
    --md5 --sha256 \
    --operator "NAWAF"
```

---

## Step 5: Verify Output

After acquisition completes, verify the output files:

### Expected Files:
1. **`image_physicaldrive1.dd`** - The raw disk image
2. **`image_physicaldrive1.dd.metadata.json`** - Acquisition metadata with hashes

### Verify Hashes with certutil:

```cmd
# Verify MD5
certutil -hashfile "C:\ForensAI_Evidence\image_physicaldrive1.dd" MD5

# Verify SHA1
certutil -hashfile "C:\ForensAI_Evidence\image_physicaldrive1.dd" SHA1

# Verify SHA256
certutil -hashfile "C:\ForensAI_Evidence\image_physicaldrive1.dd" SHA256
```

**Compare the output** with the hashes in the `.metadata.json` file to ensure integrity.

### Example Metadata File:

```json
{
  "operator": "NAWAF",
  "notes": "USB flash drive from suspect laptop",
  "device": "\\.\PHYSICALDRIVE1",
  "drive_letter": null,
  "output_file": "C:\\ForensAI_Evidence\\image_physicaldrive1.dd",
  "bytes_written": 16000000000,
  "hashes": {
    "md5": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    "sha256": "1234567890abcdef..."
  },
  "start_time": "2025-11-08T10:30:15.123456",
  "end_time": "2025-11-08T10:45:32.789012",
  "status": "complete",
  "tool": "ForensAI",
  "tool_version": "1.1.0",
  "acquisition_host": "FORENSICS-WORKSTATION",
  "acquisition_os": "Windows 11"
}
```

---

## Advanced Options

### Custom Chunk Size

Change the read/write buffer size (default: 4MB):

```bash
python tools/acquire_cli.py acquire \
    --drive 1 \
    --output "image.dd" \
    --chunk 8388608 \
    --md5 --operator "NAWAF"
```

### Use Temporary .part File

By default, the tool writes directly to the `.dd` file with flush+fsync after each chunk for crash safety. If you prefer the old atomic-rename behavior:

```bash
python tools/acquire_cli.py acquire \
    --drive 1 \
    --output "image.dd" \
    --use-temp-part \
    --md5 --operator "NAWAF"
```

### Verbose Logging

Enable detailed logging for troubleshooting:

```bash
python tools/acquire_cli.py acquire \
    --drive 1 \
    --output "image.dd" \
    --verbose \
    --md5 --operator "NAWAF"
```

---

## Handling Interruptions

### Keyboard Interrupt (Ctrl+C)

If you press `Ctrl+C` during acquisition:

1. The tool will **gracefully close files**
2. The **partial .dd file is preserved** (not deleted)
3. A **metadata.json file is written** with:
   - `status`: `"aborted"`
   - `bytes_written`: Number of bytes captured
   - `hashes`: Partial hashes of captured data
   - `error`: `"Interrupted by user (SIGINT)"`

**The partial file is forensically valuable** - it contains everything captured before interruption.

### Example Partial Metadata:

```json
{
  "operator": "NAWAF",
  "device": "\\.\PHYSICALDRIVE1",
  "output_file": "C:\\ForensAI_Evidence\\image.dd",
  "bytes_written": 8529584128,
  "hashes": {
    "md5": "partial_hash_value",
    "sha256": "partial_hash_value"
  },
  "start_time": "2025-11-08T10:30:15.123456",
  "end_time": "2025-11-08T10:38:22.456789",
  "status": "aborted",
  "error": "Interrupted by user (SIGINT)"
}
```

**Exit Codes:**
- `0` = Success (complete)
- `1` = Error
- `2` = Aborted by user (SIGINT)

---

## Troubleshooting

### Error: "Administrator privileges required"

**Solution:** Run the Command Prompt or PowerShell as Administrator.

### Error: "Access is denied (ERROR_ACCESS_DENIED)"

**Causes:**
1. Not running as Administrator
2. Another application has the device open

**Solutions:**
1. Run as Administrator
2. Close applications that might lock the device:
   - Windows Explorer (file browsing on removable media)
   - Dropbox, OneDrive, Google Drive
   - Antivirus software
3. Check for open handles using Sysinternals `handle.exe`:
   ```cmd
   handle.exe \\.\PHYSICALDRIVE1
   ```

### Error: "The specified path is invalid (ERROR_BAD_PATHNAME)"

**Cause:** Some removable devices don't support `\\.\PHYSICALDRIVE` access.

**Solution:** Use `--drive-letter` instead:
```bash
python tools/acquire_cli.py acquire \
    --drive-letter E: \
    --output "image.dd" \
    --md5 --operator "NAWAF"
```

### GetFileSizeEx Failed / Unknown Size

**Behavior:** The tool will stream until EOF (end-of-file).

**This is normal for:**
- Some removable media
- Virtual disk formats
- Card readers

The tool will read until `ReadFile` returns 0 bytes, indicating EOF.

### Device Not Found in List

**For removable media:**
1. Unplug and replug the device
2. Check Device Manager for the drive letter
3. Use `--drive-letter` option instead of `--drive`

---

## Best Practices

1. **Always run `list` first** to identify target device
2. **Always run `dry-run` before acquisition** to verify access
3. **Close cloud sync apps** (Dropbox, OneDrive, etc.)
4. **Verify hashes** with certutil after acquisition
5. **Document everything** in the `--notes` field
6. **Store images on separate forensic media**, not the system drive
7. **Never image your system drive (PhysicalDrive0)** by accident
8. **Keep partial files** - they contain forensically valuable data
9. **Use write-blocking hardware** when possible for physical evidence

---

## Safety Features

### Built-in Safety Mechanisms:

1. **Confirmation Tokens**: Must type exact confirmation before imaging starts
2. **Direct Write with Flush+Fsync**: Writes directly to .dd with crash safety
3. **Partial File Preservation**: Interrupted acquisitions are saved, not deleted
4. **Metadata on Abort**: Full metadata written even for partial captures
5. **On-the-Fly Hashing**: MD5/SHA1/SHA256 computed during acquisition
6. **Progress Logging**: Every 64MB logged for audit trail
7. **Admin Check**: Refuses to run without elevation
8. **Fallback Device Opening**: Tries multiple device paths automatically

---

## Exit Codes Reference

| Code | Meaning |
|------|---------|
| 0    | Success - acquisition completed |
| 1    | Error - check error message |
| 2    | Aborted by user (SIGINT/Ctrl+C) |

---

## Legal and Ethical Considerations

- **Only image devices you have legal authority to access**
- **Obtain proper authorization** before acquisition
- **Document chain of custody** in metadata and notes
- **Follow your organization's forensic procedures**
- **Use write-blocking hardware** for physical evidence when possible

---

## Support

For issues or questions:
- Check verbose logs with `--verbose`
- Review metadata.json for error details
- Report bugs: https://github.com/anthropics/ForensAI/issues

---

**Version:** ForensAI 1.1.0
**Last Updated:** 2025-11-08
