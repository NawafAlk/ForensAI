# ForensAI Forensic Report Generator

## Overview

The ForensAI Forensic Report Generator creates comprehensive, court-admissible forensic evidence reports with proper chain of custody, hash verification, and artifact documentation. It generates professional HTML, JSON, and PDF reports suitable for legal proceedings and forensic case documentation.

## Features

- **Comprehensive Reporting**: Generates professional forensic reports with all required sections
- **Hash Verification**: Automatic MD5 and SHA256 hash computation and verification
- **Chain of Custody**: Detailed chronological tracking of evidence handling
- **Artifact Analysis**: Automated scanning, categorization, and prioritization of evidence artifacts
- **Multiple Formats**: HTML, JSON manifest, and PDF (with fallback handling)
- **Bulk Extractor Integration**: Parses and summarizes bulk_extractor results
- **Notable Findings**: Automatic detection and prioritization of suspicious/important files
- **Tool Versioning**: Tracks all tools and versions used in analysis
- **Processing Steps**: Records all steps with timestamps and command lines
- **Court-Admissible**: Follows forensic best practices for legal evidence documentation

## Installation

### Required Dependencies

Already included in ForensAI:
```bash
pip install jinja2 pytsk3
```

### Optional Dependencies (for PDF generation)

Choose one:

**Option 1: weasyprint (recommended)**
```bash
pip install weasyprint
```

**Option 2: wkhtmltopdf**
- Download from: https://wkhtmltopdf.org/
- Install and ensure `wkhtmltopdf` is in PATH

If neither is installed, the tool will generate HTML and JSON reports only.

## Quick Start

### Command Line Usage

Basic report generation:
```bash
python tools/generate_forensic_report.py \
  --case-id CASE-2025-001 \
  --operator "John Doe" \
  --master-image C:\cases\evidence.dd \
  --output-dir C:\cases\reports
```

Full analysis with all options:
```bash
python tools/generate_forensic_report.py \
  --case-id CASE-2025-001 \
  --operator "Jane Smith" \
  --master-image /path/to/evidence.dd \
  --derived-iso /path/to/evidence.iso \
  --artifacts-dir /path/to/extracted \
  --bulk-extractor-dir /path/to/bulk_extractor \
  --logfile /path/to/acquisition.log \
  --output-dir /path/to/reports \
  --formats html json pdf \
  --verbose
```

### Python API Usage

```python
from modules.forensic_report_generator import ForensicReportGenerator

# Create generator
generator = ForensicReportGenerator(
    case_id="CASE-2025-001",
    operator="John Doe",
    master_image="C:\\cases\\evidence.dd",
    output_dir="C:\\cases\\reports"
)

# Generate report
result = generator.generate_report(formats=['html', 'json', 'pdf'])

# Check result
if result['status'] == 'success':
    print(f"HTML: {result['report_html']}")
    print(f"JSON: {result['manifest_json']}")
    print(f"PDF: {result['report_pdf']}")
else:
    print(f"Failed: {result['summary']}")
```

## Report Sections

The generated report includes these sections:

### 1. Cover Page
- Case ID, report title, description
- Generated timestamp (UTC)
- Operator name and contact
- Evidence summary

### 2. Executive Summary
- High-level overview
- Top findings (bullet points)
- Key statistics

### 3. Chain of Custody / Provenance
- Chronological table of all evidence handling
- Timestamps (UTC)
- Actor, action, tools used
- Hash values at each step

### 4. Acquisition & Verification Details
- Acquisition method and workstation
- Command lines used
- File metadata (size, timestamps)
- MD5 & SHA256 verification

### 5. Tools & Versions
- All tools used with exact versions
- Git commit SHAs
- Platform information

### 6. Processing Steps Performed
- Step-by-step processing log
- Commands executed
- stdout/stderr excerpts
- Timestamps for each step

### 7. Artifacts Summary
- Total files/directories discovered
- Total size scanned
- File type distribution
- Statistics breakdown

### 8. Notable Findings
- Top 20 priority artifacts
- Suspicious executables
- Recent files
- Files with PII
- Flagged/interesting items
- Actionability recommendations

### 9. Timeline (if available)
- Top 50 events
- Timestamp, event type, context
- UTC timezone

### 10. File-level Index
- Complete artifact listing
- Path, type, size, hashes
- Extracted locations
- Sortable/searchable (HTML)

### 11. Carving & Bulk Extraction Results
- Email addresses found
- URLs discovered
- Phone numbers
- Credit card patterns
- EXIF data
- Recovered archives

### 12. Visuals & Screenshots (optional)
- Included images
- Thumbnails
- Full-size images in media directory

### 13. Exports & Attachments
- Output file locations
- MD5/SHA256 for each export

### 14. Recommendations & Next Steps
- Analyst recommendations
- Further triage steps
- Prioritized review list
- Suggested search queries
- Preservation actions

### 15. Appendices
- Full logfile
- JSON manifest
- Limitations and assumptions

## Command Line Options

### Required Arguments

| Argument | Description |
|----------|-------------|
| `--case-id` | Unique case identifier (e.g., CASE-2025-001) |
| `--operator` | Name of analyst/operator generating report |
| `--master-image` | Path to master evidence image (.dd file) |
| `--output-dir` | Directory where reports will be saved |

### Optional Arguments

| Argument | Description |
|----------|-------------|
| `--derived-iso` | Path to derived ISO file (if created) |
| `--artifacts-dir` | Directory containing extracted/parsed artifacts |
| `--bulk-extractor-dir` | Directory containing bulk_extractor output |
| `--checkpoints-dir` | Directory containing checkpoints |
| `--logfile` | Path to processing/acquisition logfile |
| `--formats` | Output formats: html, json, pdf (default: html json) |
| `--include-screenshots` | Include screenshots in report |
| `--json-output` | Output result as JSON only (for automation) |
| `--verbose`, `-v` | Enable verbose logging |

## JSON Manifest Schema

The JSON manifest follows this exact schema:

```json
{
  "case_id": "CASE-2025-001",
  "generated_at_utc": "2025-01-15T14:30:00Z",
  "operator": "John Doe",
  "hostname": "FORENSIC-WS-01",
  "master_image": {
    "path": "C:\\cases\\evidence.dd",
    "size_bytes": 524288000,
    "sha256": "abc123...",
    "md5": "def456..."
  },
  "derived_iso": {
    "path": "C:\\cases\\evidence.iso",
    "size_bytes": 524288000,
    "sha256": "xyz789...",
    "md5": "uvw012..."
  },
  "artifacts_count": {
    "total": 5432,
    "files": 5432,
    "directories": 234,
    "carved": 45,
    "notable": 78
  },
  "artifacts_index": [
    {
      "path": "Users/Documents/passwords.txt",
      "extracted_path": "C:\\cases\\extracted\\passwords.txt",
      "name": "passwords.txt",
      "type": "document",
      "mime_type": "text/plain",
      "size_bytes": 2048,
      "sha256": "hash...",
      "md5": "hash...",
      "inode": "12345",
      "created_utc": "2024-12-01T10:30:00Z",
      "modified_utc": "2025-01-05T14:22:00Z",
      "notable_reasons": ["filename_keyword:password", "recent_modification:10d"],
      "priority": 70
    }
  ],
  "bulk_extractor_summary": {
    "email": 45,
    "url": 234,
    "telephone": 12,
    "ccn": 0,
    "exif": 89,
    "zip": 23
  },
  "processing_steps": [
    {
      "step": "Verify Master Image",
      "cmd": "hash verification: C:\\cases\\evidence.dd",
      "start": "2025-01-15T14:30:00Z",
      "end": "2025-01-15T14:32:00Z",
      "success": true,
      "stdout_snippet": "Hashes computed...",
      "stderr_snippet": "",
      "error": null
    }
  ],
  "chain_of_custody": [
    {
      "timestamp_utc": "2025-01-15T14:30:00Z",
      "actor": "John Doe",
      "hostname": "FORENSIC-WS-01",
      "action": "Master image hash verification",
      "source": "C:\\cases\\evidence.dd",
      "target": null,
      "tools": "Python hashlib (md5, sha256)",
      "hashes": {
        "md5": "...",
        "sha256": "..."
      }
    }
  ],
  "tool_versions": {
    "python": "3.11.0",
    "platform": "Windows-10-...",
    "forensai_commit": "b83736a",
    "pytsk3": "20210801",
    "bulk_extractor": "not found"
  },
  "files_produced": {
    "html_report": "C:\\cases\\reports\\CASE-2025-001_evidence_report_20250115_143000.html",
    "pdf_report": "C:\\cases\\reports\\CASE-2025-001_evidence_report_20250115_143000.pdf",
    "manifest_json": "C:\\cases\\reports\\CASE-2025-001_evidence_manifest_20250115_143000.json"
  },
  "warnings": [],
  "notes": "Additional case notes here"
}
```

## API Reference

### ForensicReportGenerator Class

#### Constructor

```python
ForensicReportGenerator(
    case_id: str,
    operator: str,
    master_image: str,
    output_dir: str,
    derived_iso: str = None,
    parsed_artifacts_dir: str = None,
    bulk_extractor_dir: str = None,
    checkpoints_dir: str = None,
    logfile: str = None
)
```

**Parameters:**
- `case_id`: Unique case identifier
- `operator`: Name of operator generating report
- `master_image`: Path to master evidence image (.dd)
- `output_dir`: Directory where reports will be saved
- `derived_iso`: Path to derived ISO (optional)
- `parsed_artifacts_dir`: Directory containing parsed artifacts (optional)
- `bulk_extractor_dir`: Directory containing bulk_extractor output (optional)
- `checkpoints_dir`: Directory containing checkpoints (optional)
- `logfile`: Path to processing log file (optional)

#### Methods

##### generate_report()

```python
generate_report(
    formats: List[str] = None,
    include_screenshots: bool = False
) -> Dict[str, Any]
```

Generate complete forensic evidence report.

**Parameters:**
- `formats`: List of formats to generate ['pdf', 'html', 'json'] (default: ['html', 'json'])
- `include_screenshots`: Whether to include screenshots (default: False)

**Returns:**
Dictionary with:
- `status`: 'success', 'partial', or 'failed'
- `case_id`: Case identifier
- `report_pdf`: Path to PDF report (or None)
- `report_html`: Path to HTML report (or None)
- `manifest_json`: Path to JSON manifest (or None)
- `logfile`: Path to copied logfile (or None)
- `summary`: Human-readable summary
- `warnings`: List of warnings (if any)

##### add_chain_of_custody_entry()

```python
add_chain_of_custody_entry(
    action: str,
    source: str = None,
    target: str = None,
    tools: str = None,
    hashes: Dict[str, str] = None
)
```

Add a custom chain of custody entry.

**Parameters:**
- `action`: Description of action performed
- `source`: Source file/device path
- `target`: Target file/device path
- `tools`: Tools and versions used
- `hashes`: Dictionary of hash values

##### verify_master_image()

```python
verify_master_image() -> bool
```

Verify master image exists and compute hashes. Returns True if successful.

##### scan_artifacts()

```python
scan_artifacts()
```

Scan parsed artifacts directory and collect artifact information.

## Artifact Categorization

Files are automatically categorized into types:

| Type | Extensions |
|------|-----------|
| document | .doc, .docx, .pdf, .txt, .rtf, .odt, .xls, .xlsx, .ppt, .pptx |
| image | .jpg, .jpeg, .png, .gif, .bmp, .tif, .tiff, .ico |
| video | .mp4, .avi, .mov, .wmv, .flv, .mkv |
| audio | .mp3, .wav, .flac, .aac, .ogg, .m4a |
| archive | .zip, .rar, .7z, .tar, .gz, .bz2 |
| executable | .exe, .dll, .so, .dylib, .msi, .bat, .sh, .ps1 |
| database | .db, .sqlite, .mdb, .accdb |
| email | .eml, .msg, .pst, .ost |
| web | .html, .htm, .css, .js, .json, .xml |
| code | .py, .java, .c, .cpp, .h, .cs, .php, .rb, .go |

## Notable Artifact Detection

Artifacts are automatically flagged as notable if they match these criteria:

| Criteria | Priority Boost | Reason |
|----------|---------------|---------|
| Suspicious keywords (password, credential, secret, etc.) | +50 | filename_keyword:* |
| Executable file | +30 | executable |
| Recently modified (< 30 days) | +20 | recent_modification:*d |
| Large file (> 100 MB) | +10 | large_file |
| Interesting type (database, email, archive) | +15 | type:* |

Artifacts with higher priority appear first in the Notable Findings section.

## Integration with ForensAI Modules

### With Acquisition Module

```python
from modules.acquire import acquire_disk
from modules.forensic_report_generator import ForensicReportGenerator

# Perform acquisition
result = acquire_disk(
    device_path="\\\\.\\PhysicalDrive1",
    output_path="C:\\cases\\evidence.dd"
)

# Generate report after acquisition
generator = ForensicReportGenerator(
    case_id="CASE-2025-001",
    operator="Analyst",
    master_image="C:\\cases\\evidence.dd",
    output_dir="C:\\cases\\reports",
    logfile="C:\\cases\\acquisition.log"
)

report_result = generator.generate_report()
```

### With Verification Module

```python
from modules.verification import verify_hashes
from modules.forensic_report_generator import ForensicReportGenerator

# Verify hashes
expected_hashes = {
    'sha256': 'abc123...',
    'md5': 'def456...'
}

match, results = verify_hashes("evidence.dd", expected_hashes)

# Add to chain of custody
generator = ForensicReportGenerator(...)
generator.add_chain_of_custody_entry(
    action=f"Hash verification: {'PASS' if match else 'FAIL'}",
    source="evidence.dd",
    tools="ForensAI verification module",
    hashes=results
)
```

## Forensic Best Practices

### Hash Verification
- Master image hashes are computed at the start of report generation
- Hashes are recorded in chain of custody
- Re-verification ensures evidence integrity

### Chain of Custody
- Every action is timestamped (UTC)
- Actor and hostname recorded for each entry
- Tools and versions documented
- Hash values captured at key steps

### Evidence Integrity
- **NEVER modifies the master image** (read-only operations only)
- All processing uses copies or derived files
- Original evidence remains untouched

### Documentation
- All commands executed are recorded
- stdout/stderr captured for each step
- Tool versions tracked for reproducibility
- Warnings and errors documented

## Troubleshooting

### PDF Generation Fails

**Problem:** PDF is not generated, only HTML and JSON.

**Solution:**
1. Install weasyprint: `pip install weasyprint`
2. OR download wkhtmltopdf from https://wkhtmltopdf.org/
3. Verify installation: `weasyprint --version` or `wkhtmltopdf --version`

The tool will automatically fall back to HTML if PDF generation fails.

### Master Image Not Found

**Problem:** Error "Master image not found"

**Solution:**
1. Verify the path exists and is correct
2. Use absolute paths, not relative paths
3. On Windows, use raw strings: `r"C:\path\to\image.dd"`
4. Check file permissions

### No Artifacts Found

**Problem:** Report shows 0 artifacts

**Solution:**
1. Verify `--artifacts-dir` points to the correct directory
2. Ensure directory contains extracted files
3. Check directory permissions
4. Run with `--verbose` to see detailed scanning output

### Slow Report Generation

**Problem:** Report generation takes a very long time

**Solution:**
1. Hash computation is CPU-intensive for large images (expected)
2. For 500GB image, expect 5-10 minutes for hash computation
3. Artifact scanning time depends on number of files
4. Use `--verbose` to monitor progress

## Performance Considerations

- **Hash Computation**: ~100-200 MB/s (depends on CPU and disk)
- **Artifact Scanning**: ~1000 files/second (depends on disk I/O)
- **HTML Generation**: < 1 second (even for large reports)
- **PDF Generation**: 5-30 seconds (depends on report size)

For very large evidence sets (> 1TB), consider:
1. Running on fast SSD storage
2. Using multi-core system for hash computation
3. Pre-computing hashes during acquisition
4. Limiting artifact scanning to specific directories

## Examples

See `examples/generate_report_example.py` for comprehensive examples:

1. Basic report generation
2. Advanced usage with all options
3. Custom chain of custody entries
4. Programmatic artifact analysis
5. Error handling
6. Integration with acquisition

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/forensai/forensai/issues
- Documentation: https://github.com/forensai/forensai/wiki

## License

See LICENSE file in the ForensAI repository.

## Author

ForensAI Development Team

---

**Version:** 1.0
**Last Updated:** 2025-01-15
**Compatible with:** ForensAI v1.0+
