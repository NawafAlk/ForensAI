# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ForensAI is a digital forensics analysis platform for examining disk images. It provides AI-powered artifact analysis, risk scoring, and court-admissible evidence handling with Groq cloud AI integration.

## Commands

### Run the Application
```bash
python main.py
```

### Install Dependencies
```bash
# Windows (requires Python 3.11, not 3.12)
pip install -r requirements.txt

# macOS Apple Silicon
./install_macos_silicon.sh

# WSL/Ubuntu
./WSL_Ubuntu_install.sh
```

### Run Tests
```bash
# All tests
pytest

# Single test file
pytest test_ai_features.py
pytest test_intelligence_layer.py
pytest test_must_features.py
pytest test_high_features.py

# Tests in tests/ directory
pytest tests/test_acquire.py
pytest tests/test_report_generator.py
```

### CLI Tools
```bash
# List physical disks (Windows, requires admin)
python tools/acquire_cli.py list

# Acquire disk image
python tools/acquire_cli.py acquire --drive 0 --output C:\Evidence\disk0.dd --md5 --sha1

# Dry-run acquisition test
python tools/acquire_cli.py dry-run --output C:\Evidence\sample --size 100
```

## Architecture

### Layer Structure
```
GUI Layer (modules/)        -> PySide6 widgets, tabs, dialogs
Intelligence Layer (managers/) -> AI service, risk scoring, audit logging
Infrastructure (managers/)  -> Image handling, database, utilities
External Tools (tools/)     -> CLI tools, Arsenal Image Mounter, SleuthKit
```

### Key Entry Points
- `main.py` - Application entry, creates `MainWindow`
- `modules/mainwindow.py` - Main window with menu, toolbar, tab coordination
- `tools/acquire_cli.py` - CLI for disk acquisition

### Core Managers (`managers/`)
- **evidence_utils.py** - `ImageHandler` class wraps pytsk3/pyewf for E01/RAW image access
- **ai_service.py** - `GroqAIService` integrates with Groq cloud API (default: Llama 3.3 70B model)
- **risk_scorer.py** - `RiskScorer` with 28 forensic rules, produces 0-100 scores with severity tiers
- **audit_logger.py** - Immutable JSONL audit trail with SHA-256 hash chain for court defensibility
- **confidence_tracker.py** - Tracks certainty metrics for AI-derived facts
- **notes_manager.py** - SQLite storage for investigator annotations

### Image Format Support
- **EWF (E01, Ex01, s01)** - via `pyewf` + custom `EWFImgInfo` wrapper
- **RAW (dd, img, raw, ad1)** - via `pytsk3.Img_Info`

### Risk Scoring System
Scores 0-100 with severity thresholds:
- Critical: 90-100
- High: 70-89
- Medium: 40-69
- Low: 20-39
- Info: 0-19

Rules cover: executables in suspicious locations, hidden files, timestamp anomalies, naming patterns.

### Data Flow
1. User loads image -> `ImageHandler` parses with pytsk3/pyewf
2. Files listed in `list_files.py` tree view
3. Selection triggers viewers (hex, text, metadata, EXIF)
4. Risk scan iterates files through `RiskScorer`
5. AI explanations via `GroqAIService` -> Groq API
6. All assessments logged to `AuditLogger` for chain-of-custody

## Configuration

- **API Keys** - Stored in `config.ini`, configured via Options > API Keys menu:
  - `groq` - Groq API key for AI analysis (get free at console.groq.com)
  - `virustotal` - VirusTotal API key
  - `veriphone` - Veriphone API key
- **Database** - `tools/new_database_mappings.db` for file type icons and acquisition records
- **Audit Logs** - `logs/{case_id}_rules.jsonl` and `logs/{case_id}_ai.jsonl`

## Platform Notes

- Windows-only features: Physical disk acquisition (requires admin), Arsenal Image Mounter
- Python 3.11 required (3.12 has compatibility issues with pytsk3/libewf)
- Internet connection required for AI features (Groq API)
