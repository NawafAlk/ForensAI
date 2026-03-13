# ForensAI - Algorithm Reference Guide

Comprehensive documentation of every algorithm, technique, and processing logic used in ForensAI.

---

## Table of Contents

1. [Risk Scoring Engine](#1-risk-scoring-engine)
2. [Hybrid Risk Scoring (4-Layer Intelligence)](#2-hybrid-risk-scoring-4-layer-intelligence)
3. [Correlation Engine](#3-correlation-engine)
4. [AI Service (Groq Cloud Integration)](#4-ai-service-groq-cloud-integration)
5. [Audit Logging & Hash Chain Verification](#5-audit-logging--hash-chain-verification)
6. [Confidence & Uncertainty Tracking](#6-confidence--uncertainty-tracking)
7. [Cluster/Block Map & Overwrite Analysis](#7-clusterblock-map--overwrite-analysis)
8. [File Carving Confidence Evaluation](#8-file-carving-confidence-evaluation)
9. [Media & TRIM Detection](#9-media--trim-detection)
10. [VirusTotal Hash Reputation](#10-virustotal-hash-reputation)
11. [PE Digital Signature Verification](#11-pe-digital-signature-verification)
12. [Whitelist Manager (False Positive Protection)](#12-whitelist-manager-false-positive-protection)
13. [Rule Configuration & Versioning](#13-rule-configuration--versioning)
14. [Image Handling & Filesystem Parsing](#14-image-handling--filesystem-parsing)
15. [Image Hash Verification (E01/RAW)](#15-image-hash-verification-e01raw)
16. [E01 to RAW Conversion](#16-e01-to-raw-conversion)
17. [File Search & Recursive Traversal](#17-file-search--recursive-traversal)
18. [Hex Viewer & Binary Search](#18-hex-viewer--binary-search)
19. [Text Viewer & String Extraction](#19-text-viewer--string-extraction)
20. [Message Decoding (Multi-Format)](#20-message-decoding-multi-format)
21. [EXIF Metadata Extraction](#21-exif-metadata-extraction)
22. [Metadata Viewer & istat Integration](#22-metadata-viewer--istat-integration)
23. [Windows Registry Parsing](#23-windows-registry-parsing)
24. [Disk Acquisition (Cross-Platform)](#24-disk-acquisition-cross-platform)
25. [Investigator Notes Manager](#25-investigator-notes-manager)
26. [Forensic Report Generator](#26-forensic-report-generator)

---

## 1. Risk Scoring Engine

**File:** `managers/risk_scorer.py` (class `RiskScorer`)

### Purpose
Rule-based threat assessment that evaluates files against 28 forensic indicator rules, producing a score from 0-100.

### Severity Tiers

| Tier     | Score Range | Action                   |
|----------|------------|--------------------------|
| Critical | 90-100     | Immediate investigation  |
| High     | 70-89      | Priority investigation   |
| Medium   | 40-69      | Review when time permits |
| Low      | 20-39      | Note for context         |
| Info     | 0-19       | Benign                   |

### All 28 Rules

**Execution Location Rules:**

| Rule Code                    | Weight | Trigger Condition                                              |
|------------------------------|--------|----------------------------------------------------------------|
| `executable_in_temp`         | 90 pts | Executable (.exe/.dll/.bat/.ps1/.vbs) found in temp folders    |
| `executable_in_downloads`    | 80 pts | Executable found in Downloads directory                        |
| `executable_in_appdata`      | 75 pts | Executable found in AppData (user-writable persistence path)   |
| `executable_in_user_dir`     | 85 pts | Executable found in non-standard user directory                |
| `system_file_wrong_location` | 95 pts | System files (cmd.exe, powershell.exe, etc.) found outside System32 |

**Filename Pattern Rules:**

| Rule Code              | Weight | Trigger Condition                                      |
|------------------------|--------|--------------------------------------------------------|
| `double_extension`     | 65 pts | File has double extension (e.g., `invoice.pdf.exe`)    |
| `suspicious_extension` | 60 pts | File uses suspicious extensions (.vbs, .js, .pif, .scr, etc.) |
| `masquerading_filename`| 85 pts | Filename impersonates system files (svchost, lsass, etc.) |
| `very_long_filename`   | 40 pts | Filename exceeds 200 characters (obfuscation indicator) |

**Content Analysis Rules:**

| Rule Code               | Weight | Trigger Condition                                      |
|--------------------------|--------|--------------------------------------------------------|
| `extremely_high_entropy` | 85 pts | Shannon entropy > 7.8 (encryption/packing)             |
| `high_entropy`           | 70 pts | Shannon entropy > 7.2                                  |
| `encrypted_archive`      | 60 pts | Archive file (.7z, .rar, .zip) with high entropy       |

**Shannon Entropy Formula:**
```
H(X) = -SUM( p(x) * log2(p(x)) ) for each byte value x in file
```
- Range: 0.0 (all identical bytes) to 8.0 (perfectly random)
- Calculated over first N bytes of file content using byte frequency distribution

**Timestamp Anomaly Rules:**

| Rule Code                    | Weight | Trigger Condition                                      |
|------------------------------|--------|--------------------------------------------------------|
| `timestomp_detected`         | 95 pts | Created time is later than modified time (impossible in normal operation) |
| `deleted_during_investigation`| 90 pts | File deleted within the active investigation period    |
| `recently_deleted`           | 65 pts | File deleted within the last 7 days                    |
| `created_equals_modified`    | 45 pts | Created and modified timestamps are identical (suspicious for executables) |
| `impossible_timestamp`       | 70 pts | Timestamps are in the future or before 1990            |

**Size Anomaly Rules:**

| Rule Code                    | Weight | Trigger Condition                                |
|------------------------------|--------|--------------------------------------------------|
| `unusually_small_executable` | 55 pts | Executable file smaller than 10 KB               |
| `unusually_large_document`   | 50 pts | Document file larger than 100 MB                 |
| `zero_byte_file`             | 30 pts | File is 0 bytes (deletion/wiping artifact)       |

**Location-Based Rules:**

| Rule Code           | Weight | Trigger Condition                                    |
|---------------------|--------|------------------------------------------------------|
| `file_in_startup`   | 75 pts | File found in Startup folders or Run registry keys   |
| `file_in_recycle_bin`| 60 pts | File found in Recycle Bin ($Recycle.Bin)             |
| `archive_in_temp`   | 55 pts | Archive file found in temp directory                 |

**Data Exfiltration Indicators:**

| Rule Code            | Weight | Trigger Condition                                    |
|----------------------|--------|------------------------------------------------------|
| `large_archive_recent`| 65 pts | Archive > 50 MB created within last 7 days (exfiltration staging) |

### Scoring Algorithm (Pseudocode)

```
function score_file(file_data):
    score = 0
    triggered_rules = []

    // Run all 6 check categories
    score += check_executable_risks(file_data)      // Location-based executable checks
    score += check_filename_risks(file_data)         // Pattern-based name analysis
    score += check_content_risks(file_data)          // Entropy and content analysis
    score += check_timestamp_risks(file_data)        // MAC time anomaly detection
    score += check_size_risks(file_data)             // Size-based anomaly detection
    score += check_location_risks(file_data)         // Directory-based risk checks

    // Cap score at 100
    final_score = min(score, 100)

    // Map to severity tier
    severity = map_to_severity(final_score)

    return RiskResult(score, severity, triggered_rules, recommendations)
```

---

## 2. Hybrid Risk Scoring (4-Layer Intelligence)

**File:** `managers/risk_scorer.py` (class `HybridRiskScorer`)

### Purpose
Extends the base risk scorer with four layers of intelligence for more accurate, context-aware threat assessment.

### Layer 1: Rule Engine
Runs the base 28-rule engine described above.

### Layer 2: Case-Type Weight Multipliers
Adjusts rule weights based on the type of investigation:

| Case Type            | Execution | Persistence | Anti-Forensic | Exfiltration |
|----------------------|-----------|-------------|---------------|--------------|
| Malware Investigation| 1.2x      | 1.3x        | 1.0x          | 0.8x         |
| Data Theft           | 0.8x      | 0.7x        | 1.3x          | 1.4x         |
| Intrusion (APT)      | 1.1x      | 1.2x        | 1.2x          | 1.1x         |
| General              | 1.0x      | 1.0x        | 1.0x          | 1.0x         |

### Layer 3: Behavioral Pattern Detection
Detects 8 attack chain patterns by combining multiple rule triggers:

| Pattern                       | Bonus Points | Conditions                                         | MITRE ATT&CK  |
|-------------------------------|-------------|-----------------------------------------------------|----------------|
| Malware Dropper               | +25 pts     | Executable in downloads + high entropy               | T1105          |
| Malware Staging               | +20 pts     | Executable in temp + obfuscation                     | T1059          |
| Persistence Installation      | +30 pts     | File in startup location                             | T1547.001      |
| Masquerade Attack             | +25 pts     | System file in wrong location                        | T1036          |
| Evidence Tampering            | +35 pts     | Timestomp detected                                   | T1070.006      |
| Active Concealment            | +40 pts     | Deletion during investigation                        | T1070.004      |
| Data Staging for Exfiltration | +20 pts     | Large recent archive                                 | T1074          |
| Encrypted Exfiltration Prep   | +25 pts     | Encrypted archive                                    | T1560          |

### Layer 4: AI Contextual Evaluation (Optional)
- Only triggers for medium+ risk scores (>= 50) or when behavioral patterns are detected
- Sends artifact context to Groq AI for analysis
- AI returns: false positive likelihood (0.0-1.0), attack chain stage, score adjustment (-20 to +20)
- Generates actionable recommendations

### Hybrid Scoring Formula
```
base_score = rule_engine_score
adjusted_score = base_score * case_type_multiplier
pattern_bonus = sum(detected_pattern_bonuses)
ai_adjustment = ai_contextual_score_delta  // (-20 to +20)

final_score = min(adjusted_score + pattern_bonus + ai_adjustment, 100)
```

---

## 3. Correlation Engine

**File:** `managers/correlation_engine.py` (class `CorrelationEngine`)

### Purpose
Discovers relationships between artifacts through three dimensions of analysis to identify coordinated attack activity.

### Dimension 1: Temporal Clustering (5-Minute Window)
Groups artifacts that were modified within a 5-minute window of each other.

```
Algorithm:
1. Index each artifact by minute granularity key: YYYYMMDDHHMM
2. For query artifact, check keys in range [artifact_minute - 5, artifact_minute + 5]
3. Return all artifacts found in that window
4. Confidence = HIGH if avg risk score >= 70, MEDIUM if >= 50, else LOW
```

### Dimension 2: Spatial Clustering (Directory-Based)
Groups files that share the same directory path.

```
Algorithm:
1. Normalize artifact path to parent directory
2. Index by normalized directory path
3. Query returns all artifacts in the same directory
4. Hotspot detection: temp, downloads, appdata, startup directories get higher confidence
```

### Dimension 3: Hash Matching
Identifies identical files spread across multiple locations.

```
Algorithm:
1. Index each artifact by MD5, SHA1, and SHA256 hash values
2. Query returns all artifacts sharing the same hash
3. Hash spreading detection: same file in multiple directories indicates propagation
```

### Attack Timeline Reconstruction
Maps correlated artifacts to MITRE ATT&CK kill chain stages:

| Stage            | Mapped Rules                                         |
|------------------|------------------------------------------------------|
| Initial Access   | executable_in_downloads, large_archive_recent        |
| Execution        | executable_in_temp, suspicious_extension             |
| Persistence      | file_in_startup, executable_in_appdata               |
| Defense Evasion  | timestomp_detected, masquerading_filename             |
| Collection       | large_archive_recent, encrypted_archive              |
| Exfiltration     | large_archive_recent, encrypted_archive              |

---

## 4. AI Service (Groq Cloud Integration)

**File:** `managers/ai_service.py` (class `GroqAIService`)

### Purpose
Provides natural language forensic explanations via Groq cloud API using the Llama 3.3 70B model.

### Configuration
- **Model:** Llama 3.3 70B (via Groq API)
- **Temperature:** 0.3 (low randomness for forensic precision)
- **Top-p:** 0.9 (nucleus sampling)
- **API Key:** Stored in `config.ini`, configurable via Options > API Keys

### 5 Specialized Analysis Functions

| Function                        | Max Tokens | Purpose                                              |
|---------------------------------|-----------|-------------------------------------------------------|
| `explain_file_artifact()`       | 600       | Explain file identity, forensic significance, timeline |
| `explain_registry_key()`        | 500       | Explain registry key purpose, persistence mechanisms   |
| `explain_timestamp_pattern()`   | 500       | Detect timestomping, impossible sequences              |
| `explain_risk_score()`          | 800       | Structured: FACTS, INTERPRETATION, ALTERNATIVES, RECOMMENDATIONS |
| `generate_overwriting_story()`  | 600       | Narrative of file destruction, intentionality assessment |

### Confidence Parsing Algorithm
Scans AI response text for linguistic confidence indicators:

| Confidence Level | Indicators                                              | Numeric Value |
|------------------|---------------------------------------------------------|---------------|
| High             | "certainly", "definitely", "confirmed", "verified"      | 0.85          |
| Medium           | "likely", "probably", "appears to be", "suggests"       | 0.65          |
| Low              | "possibly", "maybe", "might", "could be", "speculation" | 0.35          |

Each AI response includes confidence markers: `FACT` (100%), `HIGH CONFIDENCE`, `MEDIUM CONFIDENCE`, `LOW CONFIDENCE`.

---

## 5. Audit Logging & Hash Chain Verification

**File:** `managers/audit_logger.py` (class `AuditLogger`)

### Purpose
Creates immutable, cryptographically chained JSONL audit logs for court-admissible evidence handling.

### Two Log Types

**Rule Firing Log** (`logs/{case_id}_rules.jsonl`):
```json
{
    "timestamp": "ISO-8601",
    "artifact_id": "inode@offset",
    "artifact_name": "filename",
    "artifact_path": "/path/to/file",
    "final_score": 85,
    "severity": "high",
    "rules_fired": ["executable_in_temp", "high_entropy"],
    "total_weight": 160,
    "input_hash": "sha256_of_input_data",
    "log_id": "uuid",
    "previous_hash": "sha256_of_previous_entry"
}
```

**AI Interaction Log** (`logs/{case_id}_ai.jsonl`):
```json
{
    "timestamp": "ISO-8601",
    "model": "llama-3.3-70b-versatile",
    "prompt": "full_prompt_text",
    "response": "ai_response_text",
    "duration_ms": 1234,
    "artifact_id": "inode@offset",
    "interaction_purpose": "file_explanation",
    "temperature": 0.3,
    "top_p": 0.9,
    "confidence": 0.85,
    "uncertainty_factors": [],
    "log_id": "uuid",
    "previous_hash": "sha256_of_previous_entry"
}
```

### Hash Chain Integrity Verification Algorithm
```
function verify_chain(log_file):
    previous_hash = "0" * 64    // Genesis hash (64 zeros)

    for each entry in log_file:
        if entry.previous_hash != previous_hash:
            return CHAIN_BROKEN(entry)

        computed_hash = SHA256(serialize(entry))
        previous_hash = computed_hash

    return CHAIN_VALID
```

- **Thread-safe:** Append-only writes with locking
- **Export formats:** JSON (full trail with verification), CSV (tabular)
- **Tamper detection:** Any modification breaks the hash chain

---

## 6. Confidence & Uncertainty Tracking

**File:** `managers/confidence_tracker.py` (class `ConfidenceTracker`)

### Purpose
Tracks certainty levels for all derived facts, ensuring forensic conclusions include appropriate uncertainty qualifiers.

### Fact Type Classification

| Fact Type  | Base Confidence | Weight | Example                          |
|------------|----------------|--------|----------------------------------|
| DERIVED    | 100%           | 1.0    | Timestamps, file size, path      |
| COMPUTED   | 95%            | 0.9    | Entropy, hashes, fragmentation   |
| INFERRED   | Variable       | 0.5    | AI interpretation, risk analysis |
| EXTERNAL   | Variable       | 0.8    | VirusTotal, NSRL database        |

### Overall Confidence Calculation (Weighted Average)
```
overall_confidence = SUM(fact.confidence * weight[fact.type]) / SUM(weight[fact.type])
```

### Confidence Levels

| Level     | Range   |
|-----------|---------|
| Very High | 90-100% |
| High      | 75-89%  |
| Medium    | 50-74%  |
| Low       | 25-49%  |
| Very Low  | 0-24%   |

### Uncertainty Indicators
Tracked types: `missing_data`, `conflicting_evidence`, `low_confidence`, `incomplete_recovery`, `ai_speculation`, `external_failure`

Each indicator includes: type, severity, description, mitigation strategy, and affected artifacts.

---

## 7. Cluster/Block Map & Overwrite Analysis

**File:** `managers/block_map.py` (classes `ClusterIndex`, `OverwriteAnalysis`)

### Purpose
Cluster-level analysis of deleted files to determine recovery probability, overwrite extent, and fragmentation.

### Overwrite Analysis Algorithm
```
Input:  Deleted file's byte offset, file size
Output: Recovery percentage, overwrite risk, fragmentation score

1. CALCULATE CLUSTER RANGE:
   cluster_size     = 4096 bytes (default NTFS)
   start_cluster    = offset / cluster_size
   num_clusters     = ceil(size / cluster_size)

2. ANALYZE EACH CLUSTER:
   for each cluster in [start_cluster .. start_cluster + num_clusters]:
       if cluster is allocated to another file:
           overwritten_count += 1
           record overwriter (filename, timestamp, cluster_count)
       else:
           recovered_count += 1

3. CALCULATE FRAGMENTATION:
   num_runs = count contiguous state transitions in cluster_states
   if num_runs == 1:
       fragmentation_score = 0.0
   else:
       fragmentation_score = min(100, (num_runs / total_clusters) * 150)

4. CALCULATE RECOVERY PERCENTAGE:
   recovery_pct = (recovered_count / num_clusters) * 100

5. RISK CONTRIBUTION:
   if overwrite_risk > 70%:  risk_points += 30
   elif overwrite_risk > 40%: risk_points += 20
   elif overwrite_risk > 10%: risk_points += 10

   if overwritten_by_count > 2: risk_points += 15  // Multiple wipers
   if fragmentation > 60:      risk_points += 10
```

---

## 8. File Carving Confidence Evaluation

**File:** `managers/carving_confidence.py` (class `CarvingConfidence`)

### Purpose
Evaluates the quality and completeness of carved (recovered) files using a weighted three-component scoring model.

### Scoring Formula
```
overall_score = (0.40 * structural_integrity) + (0.30 * size_match) + (0.30 * parsability)
```

### File-Type Specific Evaluators

**JPEG:**
- Header check: `FF D8 FF` at offset 0 (25 pts)
- Footer check: `FF D9` at end of file (75 pts)
- PIL load verification: attempt `Image.load()` (100 pts if successful)

**PNG:**
- Header check: `89 50 4E 47 0D 0A 1A 0A` at offset 0 (25 pts)
- IEND chunk: `49 45 4E 44 AE 42 60 82` at end (75 pts)
- IHDR dimension sanity: 0 < width < 50000 AND 0 < height < 50000

**PDF:**
- Header check: `%PDF-` at offset 0 (25 pts)
- Trailer check: `%%EOF` near end (50 pts)
- Linearized marker: `/Linearized` present (25 pts)
- `/L` field size match: declared size within 5% of actual (100 pts)
- PyPDF2 page access test (100 pts if readable)

**ZIP:**
- Local file header: `PK\x03\x04` (25 pts)
- End of central directory: `PK\x05\x06` (50 pts)
- Central directory header: `PK\x01\x02` (25 pts)
- `zipfile.testzip()` integrity check (100 pts if passes)

**BMP / WAV:**
- Size field in header matches actual file size (100 pts if match)

**Video (MP4/MOV/WMV):**
- Atom/box sequence analysis (ftyp, moov, mdat, free)
- OpenCV frame readability: `cv2.VideoCapture` test (100 pts if a frame can be read)

### Confidence Tiers

| Tier     | Score  | Color       | Meaning                   |
|----------|--------|-------------|---------------------------|
| Complete | 90-100 | Green       | Full recovery expected     |
| Good     | 70-89  | Light Green | Usable file                |
| Partial  | 50-69  | Yellow      | Some data readable         |
| Damaged  | 30-49  | Orange      | Significant data loss      |
| Fragment | 0-29   | Red         | Minimal/no recovery        |

---

## 9. Media & TRIM Detection

**File:** `managers/media_detector.py` (class `MediaDetector`)

### Purpose
Identifies storage media type and detects TRIM/DEALLOCATE operations that impact file recovery.

### Media Type Detection

| Heuristic           | Classification                              |
|---------------------|---------------------------------------------|
| Size < 2 GB         | Flash / USB drive                            |
| Size 2-128 GB       | SSD (SATA/NVMe)                              |
| Size > 128 GB       | HDD (SATA)                                   |
| EWF metadata keywords | "SSD", "HDD", "NVMe", "SATA", "USB" in metadata |

### TRIM Detection Algorithm
```
1. Sample 10 MB from multiple disk locations (beginning, middle, end)
2. Scan for contiguous zero regions (64 KB+ of 0x00 or 0xFF)
3. Calculate zero_region_ratio = total_zero_bytes / total_sampled_bytes
4. If zero_region_ratio >= 0.7: TRIM = ENABLED
5. Impact: TRIM dramatically reduces file recovery probability on SSDs
```

### EWF Metadata Extraction
Extracts from E01 headers: case number, evidence number, examiner name, acquisition date, acquisition tool, acquisition mode (Physical/Logical/Live), stored hash values (MD5/SHA1).

---

## 10. VirusTotal Hash Reputation

**File:** `managers/virustotal_checker.py` (class `VirusTotalChecker`)

### Purpose
Hash-based malware reputation checking via VirusTotal API. No file upload; only hash lookups.

### Reputation Score Formula
```
detection_rate = positives / total_engines
reputation = (1 - detection_rate) * trusted_vendor_bonus

if any trusted_vendor flagged the file:
    reputation -= 0.15

confidence = min(1.0, total_engines / 70)
```

### Classification Thresholds

| Classification | Condition              |
|----------------|------------------------|
| Malicious      | detection_rate >= 30%  |
| Suspicious     | 5% < detection_rate < 30% |
| Clean          | detection_rate <= 5%   |

### Trusted Vendors
Microsoft, Kaspersky, Symantec, McAfee, ESET, Bitdefender, Avast, AVG, Trend Micro, F-Secure, Sophos, CrowdStrike

### Rate Limiting
- 4 requests/minute (free tier)
- 15-second delay between requests
- JSON cache per hash for session reuse

---

## 11. PE Digital Signature Verification

**File:** `managers/pe_signature_verifier.py` (class `PESignatureVerifier`)

### Purpose
Verifies digital signatures on Windows PE files (.exe, .dll, .sys, .scr) to distinguish legitimate signed software from unsigned/potentially malicious files.

### Verification Algorithm
```
1. Load PE file using pefile library
2. Check for DIRECTORY_ENTRY_SECURITY section
   - If absent: return UNSIGNED
3. Extract signature data from PE security directory
4. Parse file version info (VS_VERSIONINFO / FileInfo / StringTable)
   - Extract CompanyName as signer identity
5. Check signer against trusted publishers list
6. Return verdict:
   - TRUSTED:            Signed + signer in trusted list
   - SIGNED:             Signed but signer not in trusted list
   - UNSIGNED:           No signature section
   - INVALID SIGNATURE:  Signature present but verification failed
```

### Trusted Publishers
Microsoft Corporation, Google LLC, Apple Inc., Adobe Systems, Oracle, Mozilla, NVIDIA, Intel, VMware, Symantec

### Caching
`SignatureCacheManager` stores results in `cache/pe_signatures.json` keyed by file hash to avoid re-verification.

---

## 12. Whitelist Manager (False Positive Protection)

**File:** `managers/whitelist_manager.py` (class `WhitelistManager`)

### Purpose
Reduces false positives by maintaining whitelists of known-good software from multiple sources.

### Whitelist Sources

| Source      | Confidence | Description                              |
|-------------|-----------|------------------------------------------|
| NSRL        | 0.95      | National Software Reference Library      |
| Custom      | 1.0       | Organization-specific known-good files   |
| VirusTotal  | Variable  | Files with clean VT reputation           |
| Signature   | Variable  | Digitally signed by trusted publishers   |

### Hash Lookup Priority
```
1. SHA-256 lookup (highest reliability, confidence * 1.0)
2. SHA-1 lookup   (confidence * 0.95)
3. MD5 lookup     (lowest reliability, confidence * 0.9)
```

### Data Structure
Three in-memory hash dictionaries for O(1) lookup:
- `sha256_lookup: Dict[str, WhitelistEntry]`
- `sha1_lookup: Dict[str, WhitelistEntry]`
- `md5_lookup: Dict[str, WhitelistEntry]`

Persisted as JSON files: `whitelists/{source}_whitelist.json`

### NSRL Import
Supports importing from NSRL RDS CSV format (SHA-1, MD5, CRC32, FileName, FileSize, ProductCode, OpSystemCode). Limited to configurable max entries for performance.

---

## 13. Rule Configuration & Versioning

**File:** `managers/rule_config_manager.py` (class `RuleConfigManager`)

### Purpose
Manages risk scoring rule weights with version control, audit trail, and rollback capability for court defensibility.

### Features
- **Weight adjustment:** Change rule weights with mandatory reason tracking
- **Version control:** Every change creates a new version with timestamp, author, and reason
- **Integrity hashing:** Each version has a SHA-256 hash of sorted rule configuration
- **Rollback:** Revert to any previous rule version
- **"Why NOT flagged" analysis:** Explains why a file scored below a threshold

### Version Hash Calculation
```
1. Sort rules by code alphabetically
2. Serialize as JSON with sorted keys
3. SHA-256 hash, truncated to first 16 hex characters
```

### "Why NOT Flagged" Analysis
```
Input: file_data, threshold_score
Output: WhyNotFlaggedResult

1. Run all 28 rules against file
2. For rules that did NOT fire, record:
   - Rule code
   - Why it didn't fire (condition not met)
   - Potential points if it had fired
3. Calculate: threshold_not_met = threshold - actual_score
4. Generate recommendations for further investigation
```

---

## 14. Image Handling & Filesystem Parsing

**File:** `managers/evidence_utils.py` (class `ImageHandler`)

### Purpose
Core image loading and filesystem access layer. Wraps `pytsk3` and `pyewf` libraries to provide unified access to forensic disk images.

### Supported Formats

| Format   | Extensions                                    | Library  |
|----------|-----------------------------------------------|----------|
| EWF      | .e01, .s01, .l01, .ex01                       | pyewf    |
| RAW      | .raw, .img, .dd, .iso, .ad1, .001, .dmg, .sparse | pytsk3 |

### Image Loading Algorithm
```
1. Determine format from file extension
2. If EWF:
   a. pyewf.glob() to find all segment files
   b. pyewf.handle().open(segments)
   c. Wrap in EWFImgInfo(pytsk3.Img_Info) adapter
3. If RAW:
   a. pytsk3.Img_Info(path) directly
4. Attempt Volume_Info parsing (MBR/GPT partition table)
   - If fails: attempt direct FS_Info (unpartitioned media)
   - If both fail: mark as wiped image
5. Cache FS_Info objects per partition offset
```

### EWFImgInfo Adapter
Custom `pytsk3.Img_Info` subclass that bridges pyewf's read API to pytsk3's expected interface:
- `read(offset, size)` - Seeks to offset in EWF handle, reads size bytes
- `get_size()` - Returns `ewf_handle.get_media_size()`

### Filesystem Type Detection
Maps `pytsk3.TSK_FS_TYPE_*` constants to human-readable names: NTFS, FAT12, FAT16, FAT32, ExFAT, Ext2, Ext3, Ext4, ISO9660, HFS, APFS.

### Windows Version Detection
```
1. Find NTFS partition
2. Extract /Windows/System32/config/SOFTWARE registry hive
3. Write to temp file, parse with python-registry
4. Read Microsoft\Windows NT\CurrentVersion key
5. Extract: ProductName, CurrentVersion, CurrentBuild, RegisteredOwner, ProductId
```

---

## 15. Image Hash Verification (E01/RAW)

**File:** `modules/verification.py` (class `VerificationWidget`)

### Purpose
Verifies forensic image integrity by computing and comparing hash values.

### Algorithm
```
1. Compute hashes by reading image in 4096-byte chunks:
   - MD5  (hashlib.md5)
   - SHA-1 (hashlib.sha1)
   - SHA-256 (hashlib.sha256)

2. For EWF (E01) images additionally:
   a. Extract stored MD5 from EWF header: ewf_handle.get_hash_value("MD5")
   b. Extract stored SHA1 from EWF header: ewf_handle.get_hash_value("SHA1")
   c. Compare computed vs stored: "Match" or "Mismatch"

3. For RAW images:
   - Display computed hashes only (no stored values to compare)

4. Display file size in bytes and MB
```

### Execution
Runs in a background `QThread` (`HashCalculationThread`) to prevent UI freezing during large image processing.

---

## 16. E01 to RAW Conversion

**File:** `modules/converter.py` (class `ConversionWidget`)

### Purpose
Converts EWF (E01) forensic images to raw DD format.

### Conversion Algorithm
```
1. Open E01 with pyewf:
   a. pyewf.glob(input_path) to find segment files
   b. pyewf.handle().open(segments)

2. Stream-copy to output:
   buffer_size = ewf_handle.bytes_per_sector
   while True:
       data = ewf_handle.read(buffer_size)
       if not data: break
       output_file.write(data)

3. Close EWF handle
```

Output format: `.dd` or `.raw` based on user selection.

---

## 17. File Search & Recursive Traversal

**File:** `managers/evidence_utils.py` (class `ImageHandler`) + `modules/list_files.py` (class `FileSearchWidget`)

### Purpose
Lists and searches files within forensic disk images with extension filtering and keyword search.

### Recursive File Traversal Algorithm
```
function recursive_file_search(fs_info, directory, parent_path, files_list, extensions, search_query):
    for each entry in directory:
        skip "." and ".." entries

        if search_query:
            if query starts with ".": match by extension
            else: match by substring in filename (case-insensitive)
        else:
            match by extension list or show all

        if entry is directory:
            recurse into subdirectory via fs_info.open_dir(inode=entry.addr)

        if entry is regular file AND matches query:
            extract metadata (name, path, size, MAC times, inode)
            append to results
```

### Search Modes
1. **Extension filter:** Checkboxes for .txt, .jpg, .jpeg, .png, .pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx
2. **Name search:** Free-text search bar matching filename substrings
3. **Extension search:** Query starting with "." matches file extension exactly

### Size Sorting
Custom `SizeTableWidgetItem` with `__lt__` comparator that compares raw byte values (stored in `Qt.UserRole`) rather than display strings like "1.5 MB".

---

## 18. Hex Viewer & Binary Search

**File:** `modules/hex_tab.py` (classes `HexViewer`, `HexViewerManager`)

### Purpose
Displays raw file content in hexadecimal format with search capabilities.

### Display Format
```
1024 lines per page, 32 bytes per line (16 hex pairs)
Format: 0x{offset:08x}: {hex_byte_pairs} {padding} {ascii_repr}

Example:
0x00000000: 4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  MZ..............
```

### Search Algorithms

**Hex Search** (input: "FF D8 FF"):
```
1. Convert hex string to bytes: bytes.fromhex("FFD8FF")
2. Search entire file content: data.find(query_bytes, position)
3. Return all match offsets, converted to line numbers: offset // 16
```

**String Search** (input: "password"):
```
1. Encode search string to UTF-8 bytes
2. Search file content using bytes.find()
3. Convert match positions to line numbers
```

**Address Jump** (input: "0x00001234"):
```
1. Parse hex address: int("0x00001234", 16)
2. Calculate target line: address // bytes_per_line
3. Calculate target page: line // lines_per_page
4. Jump directly to page
```

### Caching
LRU cache (`functools.lru_cache`, maxsize=None) for formatted page output to avoid redundant hex formatting.

---

## 19. Text Viewer & String Extraction

**File:** `modules/text_tab.py` (class `TextViewerManager`)

### Purpose
Extracts and displays printable strings from binary file content with paginated viewing and search.

### String Extraction Algorithm
```
1. Detect encoding using chardet on first 1024 bytes
2. Decode file content (fallback: ISO-8859-1)
3. Extract printable strings using regex: [ -~]{4,}
   (sequences of 4+ printable ASCII characters, range 0x20-0x7E)
4. Join extracted strings with newlines
```

### Pagination
- **Page size:** 2000 characters per page
- **Navigation:** First, Previous, Next, Last, Go-to-page
- **Total pages:** `ceil(len(text_content) / 2000)`

### Text Search Algorithm
```
1. Find ALL occurrences of search string in full text content
2. Store match positions in array
3. Navigate between matches (wrapping: NEXT/PREVIOUS with modulo)
4. Auto-navigate to page containing current match: page = match_pos // PAGE_SIZE
5. Highlight current match with yellow background using QTextCharFormat
```

---

## 20. Message Decoding (Multi-Format)

**File:** `modules/text_tab.py` (class `CustomTextEdit`)

### Purpose
Decodes selected text from various encoding formats via right-click context menu or automatic tooltip detection.

### Supported Decoders

| Format  | Algorithm                                                  | Example Input            | Example Output |
|---------|------------------------------------------------------------|--------------------------|----------------|
| Base64  | `base64.b64decode(text)` -> UTF-8 decode                  | `SGVsbG8=`               | `Hello`        |
| Hex     | `bytes.fromhex(text)` -> UTF-8 decode                     | `48656c6c6f`             | `Hello`        |
| URL     | `urllib.parse.unquote_plus(text)`                          | `Hello%20World`          | `Hello World`  |
| HTML    | `html.unescape(text)`                                     | `&amp;lt;div&amp;gt;`    | `<div>`        |
| Octal   | `chr(int(octal, 8))` for each space-separated value       | `110 145 154 154 157`    | `Hello`        |
| Binary  | `chr(int(binary, 2))` for each space-separated value      | `01001000 01101001`      | `Hi`           |

### Auto-Detection (Tooltip on Hover)
When text is selected, attempts all decoders in order: Binary, Octal, Base64, Hex, URL, HTML. First successful decode is shown as a tooltip.

---

## 21. EXIF Metadata Extraction

**File:** `modules/exif_tab.py` (classes `ExifViewerManager`, `ExifViewer`)

### Purpose
Extracts and displays EXIF metadata from JPEG images found within forensic disk images.

### Algorithm
```
1. Open image from raw bytes: PIL.Image.open(BytesIO(file_content))
2. Check format is JPEG (only format supporting EXIF)
3. Extract EXIF data: image._getexif()
4. For each EXIF tag:
   a. Look up tag ID in PIL.ExifTags.TAGS dictionary
   b. Filter to string/bytes values only
   c. Build (tag_name, tag_value) pairs
5. Display as styled HTML table
```

### Supported EXIF Fields
Camera make/model, date/time, GPS coordinates, exposure settings, focal length, software, orientation, and all standard EXIF tags defined in the EXIF specification.

---

## 22. Metadata Viewer & istat Integration

**File:** `modules/metadata_tab.py` (class `MetadataViewer`)

### Purpose
Displays comprehensive file metadata including timestamps, hashes, MIME type, and low-level filesystem details from SleuthKit's `istat` tool.

### Metadata Collection Algorithm
```
1. Open file by inode number and partition offset
2. Extract from pytsk3 metadata object:
   - Created time (crtime)
   - Modified time (mtime)
   - Accessed time (atime)
   - Changed time (ctime)
   All formatted as UTC timestamps

3. Compute hashes from file content:
   - MD5:    hashlib.md5(content).hexdigest()
   - SHA-256: hashlib.sha256(content).hexdigest()

4. Detect MIME type using python-magic: magic.from_buffer(content)

5. On Windows: run SleuthKit istat for detailed MFT attributes:
   Command: tools/sleuthkit-4.12.1-win32/bin/istat.exe -o {offset} {image_path} {inode}
   Parse output up to "init_size:" field
```

### AI Artifact Explanation
Sends collected metadata to Groq AI via background thread for forensic significance analysis. Results can be saved as investigator notes.

---

## 23. Windows Registry Parsing

**File:** `modules/registry.py` (class `RegistryExtractor`)

### Purpose
Extracts and browses Windows registry hives from NTFS partitions within forensic disk images.

### Hive Loading Algorithm
```
1. Iterate disk image partitions
2. Find NTFS partitions (fs_type == TSK_FS_TYPE_NTFS)
3. Extract hive file from /Windows/System32/config/{HIVE_NAME}
   Supported hives: SOFTWARE, SYSTEM, SAM, SECURITY, DEFAULT, COMPONENTS
4. Write hive data to temporary file
5. Parse using python-registry: Registry.Registry(temp_file)
6. Recursively build tree:
   - Root key -> Subkeys (recursive) -> Values
   - Each key stores: name, subkey count, value count, last modified timestamp
7. Clean up temporary file
```

### Registry Key Metadata Display
For each selected key: Name, Number of Subkeys, Number of Values, Last Modified timestamp.

### Value Display
Table with columns: Name, Type (REG_SZ, REG_DWORD, etc.), Value data.

### AI Registry Explanation
Right-click any key to generate AI explanation of its forensic significance, with option to save as investigator note.

---

## 24. Disk Acquisition (Cross-Platform)

**File:** `modules/acquire/base.py` (class `BaseAcquirer`), `modules/acquire/windows.py`, `modules/acquire/linux.py`, `tools/acquire_cli.py`

### Purpose
Acquire physical disk images to raw DD format with on-the-fly hash computation.

### Acquisition Algorithm
```
1. Verify elevated privileges (admin/root required)
2. Enumerate physical disks:
   - Windows: WMI Win32_DiskDrive query
   - Linux: /sys/block/ enumeration
3. Open device handle (read-only)
4. Stream-copy with hashing:
   buffer_size = 4 MB (default)
   while bytes_read < total_size:
       chunk = device.read(buffer_size)
       output_file.write(chunk)
       for each hash_algorithm in [md5, sha1, sha256]:
           hasher.update(chunk)
       progress_callback(bytes_read, total_size, speed_mbps)
       if abort_check(): break
5. Finalize hashes
6. Return AcquisitionResult with hashes, duration, speed
```

### Dry-Run Mode
Verifies device access and reads first sector without writing, for testing acquisition setup.

### Output
`AcquisitionResult` dataclass with: success, status, output_path, bytes_written, duration, speed (MB/s), hash values, errors.

---

## 25. Investigator Notes Manager

**File:** `managers/notes_manager.py` (class `NotesManager`)

### Purpose
SQLite-backed storage for investigator annotations and AI-generated explanations, linked to specific artifacts.

### Database Schema
```sql
CREATE TABLE notes (
    note_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_type TEXT NOT NULL,        -- 'file', 'registry', 'carved', 'timeline'
    artifact_id   TEXT NOT NULL,        -- inode@offset, registry path, etc.
    artifact_name TEXT,                 -- Human-readable name
    content       TEXT NOT NULL,        -- Note text
    ai_generated  INTEGER DEFAULT 0,   -- 1 if AI-generated
    edited        INTEGER DEFAULT 0,   -- 1 if AI note was edited
    timestamp     TEXT NOT NULL,        -- ISO-8601
    tags          TEXT,                 -- JSON array of tags
    UNIQUE(artifact_type, artifact_id)
);

CREATE INDEX idx_artifact ON notes(artifact_type, artifact_id);
```

### Operations
- **Add/Update:** Upsert based on (artifact_type, artifact_id) uniqueness
- **Query:** By artifact type, by specific artifact, or all notes
- **Export:** Grouped by artifact type as dictionary for report generation
- **Singleton pattern:** Single `NotesManager` instance shared across application

---

## 26. Forensic Report Generator

**File:** `modules/forensic_report_generator.py`

### Purpose
Generates comprehensive, court-admissible forensic evidence reports with chain of custody, hash verification, and artifact documentation.

### Chain of Custody Tracking
Each `ChainOfCustodyEntry` records:
- Timestamp (UTC)
- Action performed
- Actor (examiner/system)
- Source and target paths
- Tools and versions used
- Hash values at each step
- Hostname
- Additional notes

### Hash Verification (HashVerifier)
```
Buffer size: 8 MB for efficient I/O
Supported algorithms: MD5, SHA-1, SHA-256 (concurrent computation)

1. Open file
2. Read in 8 MB chunks
3. Update all hash objects simultaneously
4. Return dictionary of algorithm -> hex digest
```

### Report Output
Includes: case metadata, chain of custody log, image verification hashes, artifact analysis, risk scoring results, AI explanations, investigator notes, and timeline reconstruction.

---

## Algorithm Summary Table

| #  | Algorithm                     | File                          | Technique                        |
|----|-------------------------------|-------------------------------|----------------------------------|
| 1  | Rule-Based Risk Scoring       | risk_scorer.py                | 28 weighted pattern rules        |
| 2  | Hybrid 4-Layer Intelligence   | risk_scorer.py                | Rules + Patterns + Correlation + AI |
| 3  | Temporal/Spatial Correlation   | correlation_engine.py         | 5-min window + directory clustering |
| 4  | AI Forensic Explanation       | ai_service.py                 | Groq LLM with forensic prompts  |
| 5  | Hash Chain Audit Log          | audit_logger.py               | SHA-256 chained JSONL            |
| 6  | Confidence Tracking           | confidence_tracker.py         | Weighted average by fact type    |
| 7  | Cluster Overwrite Analysis    | block_map.py                  | Contiguous run analysis          |
| 8  | Carving Confidence            | carving_confidence.py         | 3-component weighted evaluation  |
| 9  | TRIM Detection                | media_detector.py             | Zero-run pattern sampling        |
| 10 | VirusTotal Reputation         | virustotal_checker.py         | Detection ratio + vendor trust   |
| 11 | PE Signature Verification     | pe_signature_verifier.py      | pefile + trusted publisher list  |
| 12 | Whitelist Management          | whitelist_manager.py          | Multi-source hash lookup         |
| 13 | Rule Versioning               | rule_config_manager.py        | SHA-256 config hashing + rollback |
| 14 | Image Handling                | evidence_utils.py             | pytsk3/pyewf adapter pattern     |
| 15 | Image Hash Verification       | verification.py               | MD5/SHA1/SHA256 + EWF comparison |
| 16 | E01-to-RAW Conversion         | converter.py                  | Sector-by-sector stream copy     |
| 17 | Recursive File Search         | evidence_utils.py             | DFS traversal with extension filter |
| 18 | Hex Viewer & Search           | hex_tab.py                    | Binary pattern matching + LRU cache |
| 19 | String Extraction             | text_tab.py                   | Regex printable char extraction  |
| 20 | Multi-Format Decoding         | text_tab.py                   | Base64/Hex/URL/HTML/Octal/Binary |
| 21 | EXIF Extraction               | exif_tab.py                   | PIL EXIF tag enumeration         |
| 22 | Metadata + istat              | metadata_tab.py               | pytsk3 meta + SleuthKit CLI      |
| 23 | Registry Parsing              | registry.py                   | python-registry hive traversal   |
| 24 | Disk Acquisition              | acquire/base.py               | Stream copy + concurrent hashing |
| 25 | Notes Management              | notes_manager.py              | SQLite CRUD with artifact linking |
| 26 | Report Generation             | forensic_report_generator.py  | Chain of custody + hash verification |
