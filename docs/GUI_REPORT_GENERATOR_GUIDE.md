# Using the Forensic Report Generator from ForensAI GUI

## 📱 Accessing the Report Generator

There are **3 ways** to access the forensic report generator from the ForensAI application:

### Method 1: Main Menu (Recommended)
1. Launch ForensAI
2. Click **Tools** menu
3. Select **Generate Forensic Report**

### Method 2: Toolbar Button
1. Look for the **document/report icon** in the main toolbar
2. Click the **"Generate Forensic Report"** button
3. The dialog will open instantly

### Method 3: Keyboard Shortcut (if configured)
- Press the configured hotkey (default: not set)

---

## 🎯 Complete Workflow: From Evidence to Report

### Step 1: Load Evidence Image
```
1. Click "File" → "Add Evidence File"
2. Browse and select your .dd / .raw / .E01 file
3. ForensAI loads the image
```

### Step 2: Perform Analysis (Optional but Recommended)
Before generating the report, you may want to:

- ✅ **Verify Image**: Tools → Verify Image (computes hashes)
- ✅ **Extract Artifacts**: Navigate and extract files of interest
- ✅ **Run File Carving**: Use the file carving feature
- ✅ **Export Extracted Files**: Save carved/extracted files to a directory

### Step 3: Generate Forensic Report
```
1. Click Tools → Generate Forensic Report
   (or click the toolbar button)

2. The report generator dialog opens
```

---

## 🖥️ Using the Report Generator Dialog

### Dialog Layout

The dialog has **4 main sections**:

#### 1️⃣ Required Information (Top Section)

| Field | Description | Auto-Filled? | Example |
|-------|-------------|--------------|---------|
| **Case ID** | Unique case identifier | ✅ Yes (timestamp-based) | CASE-2025-01-15-143052 |
| **Operator Name** | Your name | ✅ Yes (from system username) | John Doe |
| **Master Image** | Path to .dd file | ✅ Yes (if image loaded) | C:\cases\evidence.dd |
| **Output Directory** | Where to save reports | ❌ No | C:\cases\reports |

**🔍 Auto-Detection:**
- If you have an evidence image loaded in ForensAI, the **Master Image** field will be **automatically filled**
- Case ID is auto-generated with current date/time
- Operator name is pulled from your Windows username

#### 2️⃣ Optional Information (Middle Section)

These fields **enhance** your report but are not required:

| Field | Purpose | Browse Button |
|-------|---------|---------------|
| **Derived ISO** | If you created an ISO from the .dd | ✅ Yes |
| **Artifacts Directory** | Folder with extracted/carved files | ✅ Yes |
| **Bulk Extractor** | bulk_extractor output directory | ✅ Yes |
| **Logfile** | Acquisition or processing log | ✅ Yes |

**💡 Pro Tip:** The more optional fields you fill, the more comprehensive your report will be!

#### 3️⃣ Report Options (Lower Section)

**Output Formats** (check at least one):
- ☑️ **HTML Report** - Beautiful, interactive web report (recommended)
- ☑️ **JSON Manifest** - Machine-readable complete data
- ☐ **PDF Report** - Printable PDF (requires wkhtmltopdf or weasyprint)

**Additional Options**:
- ☐ **Include screenshots** - Add UI screenshots to report
- **Case Notes** - Free-text notes about the case (optional)

#### 4️⃣ Progress Area (Bottom Section)

Shows real-time progress during generation:
- Progress messages
- Current step being executed
- Completion status

---

## 📝 Step-by-Step Example: Generate Your First Report

### Scenario: You've acquired a disk image and want to create a report

```
Step 1: Load Evidence
├─ File → Add Evidence File
└─ Select: C:\cases\suspect_laptop.dd

Step 2: Verify Evidence (Optional but Recommended)
├─ Tools → Verify Image
├─ Wait for hash calculation
└─ Note the MD5/SHA256 hashes shown

Step 3: Extract Some Artifacts (Optional)
├─ Navigate the file tree
├─ Right-click interesting files → Export
└─ Save to: C:\cases\extracted\

Step 4: Generate Report
├─ Tools → Generate Forensic Report
└─ Dialog opens with pre-filled fields:
    ├─ Case ID: CASE-2025-01-15-150230
    ├─ Operator: JohnDoe
    ├─ Master Image: C:\cases\suspect_laptop.dd ✅
    └─ Output Directory: [EMPTY - you must fill this]

Step 5: Fill Required Fields
├─ Edit Case ID if needed: CASE-2025-001-LAPTOP
├─ Edit Operator: John Doe (Forensic Analyst)
└─ Output Directory: Browse → C:\cases\reports

Step 6: Add Optional Information (Recommended)
├─ Artifacts Directory: Browse → C:\cases\extracted\
├─ Logfile: Browse → C:\cases\acquisition.log
└─ Skip others if not used

Step 7: Configure Report Options
├─ ✅ HTML Report
├─ ✅ JSON Manifest
├─ ☐ PDF Report (skip if not installed)
├─ Case Notes: "Suspected intellectual property theft case.
│              Focus on document access timeline."

Step 8: Generate!
├─ Click "Generate Report" button
├─ Confirm generation dialog → Yes
└─ Wait for completion (may take 5-30 minutes)

Step 9: View Progress
├─ Progress area shows:
│   ├─ [14:30:45] Starting report generation...
│   ├─ [14:30:46] Verifying master image...
│   ├─ [14:31:52] Scanning artifacts...
│   └─ [14:33:15] Report generation complete!

Step 10: Success!
├─ Success dialog appears
├─ Shows paths to generated files
├─ Click "Open Report Folder" to view
└─ Your reports are ready!
```

---

## 📊 What Happens During Generation?

When you click **"Generate Report"**, ForensAI performs these steps:

### Phase 1: Validation (< 1 second)
- ✅ Checks all required fields are filled
- ✅ Verifies master image file exists
- ✅ Validates paths and permissions

### Phase 2: Hash Computation (2-20 minutes)
- 🔐 Computes MD5 hash of master image
- 🔐 Computes SHA256 hash of master image
- 📝 Records hashes for chain of custody
- ⏱️ **Time depends on image size:**
  - 100 GB = ~5-10 min
  - 500 GB = ~20-40 min
  - 1 TB = ~40-80 min

### Phase 3: Tool Version Collection (< 5 seconds)
- 📌 Records Python version
- 📌 Records ForensAI git commit
- 📌 Records pytsk3 version
- 📌 Checks for bulk_extractor, dd, genisoimage

### Phase 4: Artifact Scanning (1-10 minutes)
- 📁 Scans artifacts directory (if provided)
- 🏷️ Categorizes files by type (document, image, executable, etc.)
- 🚩 Flags notable files (passwords, credentials, recent files, etc.)
- 📊 Computes statistics

### Phase 5: Bulk Extractor Parsing (< 1 minute)
- 📧 Counts extracted emails
- 🌐 Counts URLs
- 📞 Counts phone numbers
- 💳 Counts credit card patterns
- 🖼️ Counts EXIF data entries

### Phase 6: Report Generation (< 30 seconds)
- 📄 Generates HTML report with all sections
- 📋 Creates JSON manifest with complete data
- 📑 Optionally generates PDF (if tools available)
- 💾 Saves all files to output directory

### Phase 7: Completion
- ✅ Shows success dialog
- 📂 Provides "Open Report Folder" button
- 📋 Lists all generated file paths

---

## 🎨 Understanding the Generated Report

### HTML Report Sections

When you open the HTML report in your browser, you'll see:

#### 1. Header
- Case ID
- Generated date/time (UTC)
- Operator name
- Hostname

#### 2. Executive Summary
- Statistics cards (total files, notable artifacts, size, steps)
- Key findings
- Warnings (if any)

#### 3. Master Image Information
- File path
- File size (MB/GB)
- MD5 hash
- SHA256 hash
- Forensic note about evidence preservation

#### 4. Derived ISO Information (if provided)
- Same as master image section

#### 5. Chain of Custody
- Complete chronological table
- Timestamp (UTC), Action, Actor, Tools used
- Audit trail for court admissibility

#### 6. Tools & Versions
- All software versions used
- Git commit SHAs
- Platform information
- Ensures reproducibility

#### 7. Processing Steps
- Every step performed
- Commands executed
- Start/end timestamps
- Success/failure status
- Output snippets

#### 8. Artifacts Summary
- Total files/directories
- File type distribution chart
- Size statistics

#### 9. Notable Findings
- Top 20 priority artifacts
- Suspicious executables
- Files with keywords (password, credential, etc.)
- Recently modified files
- Actionability recommendations

#### 10. Bulk Extractor Results (if provided)
- Email addresses found
- URLs discovered
- Phone numbers
- Credit card patterns
- EXIF data
- Compressed files

#### 11. Recommendations
- Analyst recommendations
- Suggested search queries
- Prioritized review list
- Preservation actions

#### 12. Footer
- Report ID
- ForensAI version
- Platform details

---

## 💡 Pro Tips for Best Results

### Tip 1: Always Verify First
```
Before generating report:
1. Tools → Verify Image
2. Let hash calculation complete
3. THEN generate report

Why? The report will include verified hashes
```

### Tip 2: Use Meaningful Case IDs
```
Instead of: CASE-2025-01-15-143052
Better:     CASE-2025-001-LAPTOP-THEFT
Even Better: CASE-2025-001-SMITH-LAPTOP
```

### Tip 3: Add Detailed Notes
```
Good notes help future analysts:
- Investigation focus
- Key suspects
- Important timeline
- Special circumstances
- Related cases
```

### Tip 4: Organize Your Output
```
Create structured output directories:
C:\cases\CASE-001\
├── evidence\
│   └── suspect_laptop.dd
├── extracted\
│   ├── documents\
│   ├── images\
│   └── executables\
├── logs\
│   └── acquisition.log
└── reports\          ← Set as Output Directory
    ├── CASE-001_evidence_report_*.html
    ├── CASE-001_evidence_manifest_*.json
    └── CASE-001_evidence_report_*.pdf
```

### Tip 5: Generate Reports at Multiple Stages
```
Stage 1: Right after acquisition
├─ Master image only
└─ Quick chain of custody

Stage 2: After initial analysis
├─ Master image + extracted artifacts
└─ Preliminary findings

Stage 3: After complete analysis
├─ Everything included
└─ Final comprehensive report
```

### Tip 6: Include Bulk Extractor Results
```
Before generating report:
1. Run bulk_extractor on your image:
   bulk_extractor -o C:\cases\bulk_output evidence.dd

2. In report dialog:
   Bulk Extractor: C:\cases\bulk_output

3. Report will include email, URL, phone number findings
```

---

## 🔧 Troubleshooting

### Problem: "Master image not found"
**Solution:**
- Use absolute paths: `C:\cases\evidence.dd`
- Check file actually exists
- Ensure you have read permissions

### Problem: PDF not generated
**Solution:**
- PDF generation is optional
- Install: `pip install weasyprint`
- OR download wkhtmltopdf from https://wkhtmltopdf.org/
- HTML and JSON will still be created

### Problem: Report generation is slow
**Solution:**
- This is **normal** for large images
- Hash computation takes the most time:
  - 100 GB = ~5-10 minutes
  - 500 GB = ~20-40 minutes
  - 1 TB = ~40-80 minutes
- Progress is shown in real-time
- You can minimize ForensAI and do other work

### Problem: "Output directory is required"
**Solution:**
- You must select/create an output directory
- Click "Browse..." button
- Select or create folder: `C:\cases\reports`

### Problem: No artifacts found
**Solution:**
- Artifacts Directory is **optional**
- Report will still be generated
- It just won't include extracted file analysis
- To add artifacts: Extract files first, then provide path

### Problem: Dialog won't close after generation
**Solution:**
- Click "Close" button
- Report files are already saved
- You can reopen them anytime from the output directory

---

## 📱 Integration with ForensAI Workflow

### Workflow 1: Quick Evidence Report
```
1. Add Evidence File
2. Tools → Generate Forensic Report
3. Fill Case ID, Operator, Output Dir
4. Generate!
```
**⏱️ Time: 10-30 minutes**
**📋 Result: Basic chain of custody + hashes**

### Workflow 2: Comprehensive Analysis Report
```
1. Add Evidence File
2. Tools → Verify Image (get hashes)
3. Navigate + extract files of interest
4. Run file carving (if needed)
5. Tools → Generate Forensic Report
   ├─ Include extracted artifacts directory
   └─ Add case notes
6. Generate!
```
**⏱️ Time: 1-3 hours (including manual analysis)**
**📋 Result: Complete forensic report with findings**

### Workflow 3: Full Forensic Pipeline
```
1. Tools → Acquire Physical Disk
2. Save as: evidence.dd
3. Tools → Verify Image
4. Extract artifacts to folder
5. Run bulk_extractor externally:
   bulk_extractor -o bulk_output evidence.dd
6. Tools → Generate Forensic Report
   ├─ Master image: evidence.dd
   ├─ Artifacts dir: extracted/
   ├─ Bulk extractor: bulk_output/
   ├─ Logfile: acquisition.log
   └─ Include all options
7. Generate comprehensive report
```
**⏱️ Time: 2-6 hours (full analysis)**
**📋 Result: Court-ready comprehensive forensic report**

---

## 🎓 Training Exercise

Try this hands-on exercise to learn the report generator:

### Exercise: Generate a Test Report

**Materials Needed:**
- A small test evidence image (or create one)
- 10 minutes

**Steps:**
```
1. Create test files:
   - Create folder: C:\test\evidence\
   - Create small test file: test.dd (can be any file renamed)

2. Launch ForensAI

3. Load test evidence:
   - File → Add Evidence File
   - Select your test.dd

4. Generate report:
   - Tools → Generate Forensic Report
   - Case ID: TEST-CASE-001
   - Operator: Your Name
   - Master Image: (already filled)
   - Output Directory: C:\test\reports\
   - Check: HTML Report, JSON Manifest
   - Notes: "This is a test report for training"
   - Click Generate Report

5. Wait for completion (should be fast for small files)

6. Click "Open Report Folder"

7. Open the HTML report in your browser

8. Explore all sections:
   - Executive Summary
   - Chain of Custody
   - Tools & Versions
   - Processing Steps
   - etc.

9. Open the JSON manifest in a text editor
   - Review the structured data
   - See how it matches the HTML report

10. Success! You've generated your first forensic report!
```

---

## 📚 Additional Resources

- **Full Documentation**: `docs/FORENSIC_REPORT_GENERATOR.md`
- **Quick Start**: `docs/REPORT_GENERATOR_QUICK_START.md`
- **Python API**: `docs/FORENSIC_REPORT_GENERATOR.md#api-reference`
- **Code Examples**: `examples/generate_report_example.py`
- **Tests**: `tests/test_report_generator.py`

---

## ✅ Checklist: Before Generating Your Report

Use this checklist to ensure a complete report:

- [ ] Evidence image loaded in ForensAI
- [ ] Image verified (hashes computed)
- [ ] Artifacts extracted (if applicable)
- [ ] bulk_extractor run (if applicable)
- [ ] Case ID chosen (meaningful name)
- [ ] Operator name filled
- [ ] Output directory created
- [ ] Optional paths provided (artifacts, bulk, logs)
- [ ] Output formats selected
- [ ] Case notes written
- [ ] Ready to generate!

---

**Version**: 1.0
**Author**: ForensAI Team
**Last Updated**: 2025-01-15
