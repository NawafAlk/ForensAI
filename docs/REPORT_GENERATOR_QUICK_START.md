# Forensic Report Generator - Quick Start Guide

## 🚀 Quick Start (30 seconds)

### Minimum Command
```bash
python tools/generate_forensic_report.py \
  --case-id CASE-2025-001 \
  --operator "Your Name" \
  --master-image path/to/evidence.dd \
  --output-dir path/to/reports
```

### Full Command (All Options)
```bash
python tools/generate_forensic_report.py \
  --case-id CASE-2025-001 \
  --operator "Your Name" \
  --master-image path/to/evidence.dd \
  --derived-iso path/to/evidence.iso \
  --artifacts-dir path/to/extracted \
  --bulk-extractor-dir path/to/bulk_extractor \
  --logfile path/to/acquisition.log \
  --output-dir path/to/reports \
  --formats html json pdf \
  --verbose
```

## 📝 Python API (5 lines)

```python
from modules.forensic_report_generator import ForensicReportGenerator

generator = ForensicReportGenerator(
    case_id="CASE-2025-001",
    operator="Your Name",
    master_image="evidence.dd",
    output_dir="reports"
)

result = generator.generate_report()
print(f"Report: {result['report_html']}")
```

## 📦 What You Get

After running the tool, you'll have:

| File | Description |
|------|-------------|
| `CASE-2025-001_evidence_report_*.html` | Professional HTML report (open in browser) |
| `CASE-2025-001_evidence_manifest_*.json` | Complete JSON manifest (machine-readable) |
| `CASE-2025-001_evidence_report_*.pdf` | PDF report (if wkhtmltopdf/weasyprint installed) |

## 🔑 Key Features

- ✅ **Hash Verification**: Automatic MD5 & SHA256 computation
- ✅ **Chain of Custody**: Complete audit trail with timestamps
- ✅ **Artifact Analysis**: Auto-categorization of 11+ file types
- ✅ **Notable Findings**: Auto-detection of suspicious files
- ✅ **Bulk Extractor**: Integrated results parsing
- ✅ **Court-Admissible**: Follows forensic best practices

## 📊 Report Sections (15 sections)

1. Cover Page & Executive Summary
2. Chain of Custody
3. Master Image & Derived ISO Information
4. Tool Versions Used
5. Processing Steps Log
6. Artifacts Summary & Statistics
7. Notable Findings (Top 20)
8. File Type Distribution
9. Timeline (if available)
10. File-Level Index
11. Bulk Extractor Results
12. Recommendations
13. Appendices

## ⚙️ Common Options

| Option | Purpose | Example |
|--------|---------|---------|
| `--case-id` | Unique case identifier | `CASE-2025-001` |
| `--operator` | Your name | `"John Doe"` |
| `--master-image` | Evidence .dd file | `evidence.dd` |
| `--output-dir` | Where to save reports | `./reports` |
| `--formats` | Output formats | `html json pdf` |
| `--verbose` | Show detailed logging | (flag) |

## 🔍 What Gets Flagged as Notable?

Files are automatically prioritized if they:

- ✅ Contain keywords: `password`, `credential`, `secret`, `confidential`, `malware`
- ✅ Are executables (`.exe`, `.dll`, `.so`, `.msi`, `.bat`, `.sh`)
- ✅ Were modified recently (< 30 days)
- ✅ Are large files (> 100 MB)
- ✅ Are interesting types (database, email, archive)

## 📁 File Type Categories

| Category | Extensions |
|----------|-----------|
| **Document** | .doc, .docx, .pdf, .txt, .xls, .xlsx, .ppt, .pptx |
| **Image** | .jpg, .png, .gif, .bmp, .tiff |
| **Video** | .mp4, .avi, .mov, .wmv |
| **Audio** | .mp3, .wav, .flac, .aac |
| **Archive** | .zip, .rar, .7z, .tar, .gz |
| **Executable** | .exe, .dll, .msi, .bat, .sh |
| **Database** | .db, .sqlite, .mdb |
| **Email** | .eml, .msg, .pst, .ost |
| **Web** | .html, .css, .js, .json |
| **Code** | .py, .java, .c, .cpp, .php |

## 🔧 Setup & Dependencies

### Already Installed (included with ForensAI)
```bash
# These are already in requirements.txt
jinja2
pytsk3
```

### Optional (for PDF generation)
```bash
# Choose one:
pip install weasyprint
# OR download: https://wkhtmltopdf.org/
```

## 💡 Pro Tips

### Tip 1: Generate Report After Acquisition
```bash
# After acquiring evidence, immediately generate report
python tools/acquire_cli.py --device /dev/sdb --output evidence.dd
python tools/generate_forensic_report.py --case-id CASE-001 \
  --operator "Analyst" --master-image evidence.dd --output-dir reports
```

### Tip 2: Add Custom Chain of Custody
```python
generator.add_chain_of_custody_entry(
    action="Physical device seized from suspect's office",
    source="Samsung 1TB SSD (Serial: ABC123)",
    tools="Physical custody transfer"
)
```

### Tip 3: Programmatic Artifact Analysis
```python
generator.scan_artifacts()

# Flag specific files
for artifact in generator.artifacts:
    if 'password' in artifact.name.lower():
        artifact.priority += 200
        artifact.notable_reasons.append('contains_credentials')
```

### Tip 4: JSON Output for Automation
```bash
# Use --json-output for scripting/automation
python tools/generate_forensic_report.py \
  --case-id CASE-001 --operator "Bot" \
  --master-image evidence.dd --output-dir reports \
  --json-output > result.json
```

## 🐛 Troubleshooting

### PDF not generated?
Install PDF generator:
```bash
pip install weasyprint
```

### Master image not found?
Use absolute paths:
```bash
# Windows
--master-image "C:\cases\evidence.dd"

# Linux/Mac
--master-image "/mnt/cases/evidence.dd"
```

### Slow hash computation?
This is normal! Large images take time:
- 100 GB = ~5-10 minutes
- 500 GB = ~20-40 minutes
- 1 TB = ~40-80 minutes

Use `--verbose` to monitor progress.

## 📚 More Examples

### Example 1: Basic Case
```bash
python tools/generate_forensic_report.py \
  --case-id CASE-2025-001 \
  --operator "Forensic Analyst" \
  --master-image "C:\cases\evidence.dd" \
  --output-dir "C:\cases\reports"
```

### Example 2: With Artifacts
```bash
python tools/generate_forensic_report.py \
  --case-id CASE-2025-002 \
  --operator "Senior Analyst" \
  --master-image "/data/evidence.dd" \
  --artifacts-dir "/data/extracted" \
  --output-dir "/data/reports" \
  --formats html json pdf
```

### Example 3: Full Analysis Pipeline
```bash
# Step 1: Acquire evidence
python tools/acquire_cli.py --device /dev/sdb --output evidence.dd

# Step 2: Extract artifacts (using your preferred tools)
# ... extraction process ...

# Step 3: Run bulk_extractor
bulk_extractor -o bulk_output evidence.dd

# Step 4: Generate comprehensive report
python tools/generate_forensic_report.py \
  --case-id CASE-2025-003 \
  --operator "Lead Analyst" \
  --master-image evidence.dd \
  --artifacts-dir extracted \
  --bulk-extractor-dir bulk_output \
  --logfile acquisition.log \
  --output-dir final_reports \
  --formats html json pdf \
  --verbose
```

## 📖 Full Documentation

For complete documentation, see:
- **Full Manual**: `docs/FORENSIC_REPORT_GENERATOR.md`
- **Code Examples**: `examples/generate_report_example.py`
- **API Reference**: `docs/FORENSIC_REPORT_GENERATOR.md#api-reference`

## ✅ Test Your Installation

```bash
# Run the test suite
python tests/test_report_generator.py

# Should see: "Test Results: 7 passed, 0 failed"
```

## 🆘 Get Help

```bash
# Show all options
python tools/generate_forensic_report.py --help

# Contact & Issues
# GitHub: https://github.com/forensai/forensai/issues
```

---

**Version**: 1.0
**Author**: ForensAI Team
**License**: See LICENSE file
**Last Updated**: 2025-01-15
