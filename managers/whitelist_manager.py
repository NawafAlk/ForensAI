"""
Whitelist Manager - False Positive Protection

Manages whitelists of known-good software to reduce false positives
in forensic analysis. Supports multiple whitelist sources:
- NSRL (National Software Reference Library)
- Custom whitelists (organization-specific)
- VirusTotal reputation
- Digital signature validation

Provides confidence-aware whitelisting with audit trail.
"""

import json
import os
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class WhitelistEntry:
    """Single whitelist entry"""
    hash_sha256: str
    hash_md5: Optional[str] = None
    hash_sha1: Optional[str] = None
    filename: str = ""
    product_name: str = ""
    vendor: str = ""
    version: str = ""
    source: str = "custom"
    added_date: str = ""
    added_by: str = ""
    notes: str = ""
    confidence: float = 1.0

    def matches(self, file_hash: str, hash_type: str = "sha256") -> bool:
        """Check if file hash matches this entry"""
        hash_lower = file_hash.lower()
        if hash_type == "sha256":
            return self.hash_sha256.lower() == hash_lower
        elif hash_type == "md5" and self.hash_md5:
            return self.hash_md5.lower() == hash_lower
        elif hash_type == "sha1" and self.hash_sha1:
            return self.hash_sha1.lower() == hash_lower
        return False


@dataclass
class WhitelistResult:
    """Result of whitelist check"""
    is_whitelisted: bool
    entry: Optional[WhitelistEntry] = None
    confidence: float = 0.0
    reason: str = ""
    matched_by: str = ""


class WhitelistManager:
    """Manages known-good software whitelists"""

    def __init__(self, case_id: str = "default", whitelist_dir: str = "whitelists"):
        """
        Initialize whitelist manager.

        Args:
            case_id: Case identifier
            whitelist_dir: Directory containing whitelist files
        """
        self.case_id = case_id
        self.whitelist_dir = Path(whitelist_dir)
        self.whitelist_dir.mkdir(exist_ok=True)

        self.whitelists: Dict[str, List[WhitelistEntry]] = {
            "nsrl": [],
            "custom": [],
            "virustotal": [],
            "signature": []
        }

        self.sha256_lookup: Dict[str, WhitelistEntry] = {}
        self.md5_lookup: Dict[str, WhitelistEntry] = {}
        self.sha1_lookup: Dict[str, WhitelistEntry] = {}

        self._load_whitelists()

    def _load_whitelists(self):
        """Load whitelist files from disk"""
        for source in ["nsrl", "custom", "virustotal", "signature"]:
            filepath = self.whitelist_dir / f"{source}_whitelist.json"
            if filepath.exists():
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        entries = [WhitelistEntry(**entry) for entry in data.get('entries', [])]
                        self.whitelists[source] = entries

                        for entry in entries:
                            self.sha256_lookup[entry.hash_sha256.lower()] = entry
                            if entry.hash_md5:
                                self.md5_lookup[entry.hash_md5.lower()] = entry
                            if entry.hash_sha1:
                                self.sha1_lookup[entry.hash_sha1.lower()] = entry

                    print(f"[Whitelist] Loaded {len(entries)} entries from {source}")
                except Exception as e:
                    print(f"[Whitelist] Failed to load {source}: {e}")

    def _save_whitelist(self, source: str):
        """Save whitelist to disk"""
        filepath = self.whitelist_dir / f"{source}_whitelist.json"
        try:
            data = {
                "source": source,
                "updated": datetime.utcnow().isoformat(),
                "count": len(self.whitelists[source]),
                "entries": [vars(entry) for entry in self.whitelists[source]]
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[Whitelist] Failed to save {source}: {e}")

    def check_file(self, file_data: Dict) -> WhitelistResult:
        """
        Check if file is whitelisted.

        Args:
            file_data: Dictionary with hash values (sha256, md5, sha1)

        Returns:
            WhitelistResult with match information
        """
        if 'sha256' in file_data and file_data['sha256']:
            sha256 = file_data['sha256'].lower()
            if sha256 in self.sha256_lookup:
                entry = self.sha256_lookup[sha256]
                return WhitelistResult(
                    is_whitelisted=True,
                    entry=entry,
                    confidence=entry.confidence,
                    reason=f"Matched in {entry.source} whitelist",
                    matched_by="sha256"
                )

        if 'md5' in file_data and file_data['md5']:
            md5 = file_data['md5'].lower()
            if md5 in self.md5_lookup:
                entry = self.md5_lookup[md5]
                return WhitelistResult(
                    is_whitelisted=True,
                    entry=entry,
                    confidence=entry.confidence * 0.9,
                    reason=f"Matched in {entry.source} whitelist (MD5)",
                    matched_by="md5"
                )

        if 'sha1' in file_data and file_data['sha1']:
            sha1 = file_data['sha1'].lower()
            if sha1 in self.sha1_lookup:
                entry = self.sha1_lookup[sha1]
                return WhitelistResult(
                    is_whitelisted=True,
                    entry=entry,
                    confidence=entry.confidence * 0.95,
                    reason=f"Matched in {entry.source} whitelist (SHA1)",
                    matched_by="sha1"
                )

        return WhitelistResult(
            is_whitelisted=False,
            confidence=0.0,
            reason="Not found in any whitelist"
        )

    def add_entry(self, source: str, hash_sha256: str, filename: str = "",
                  product_name: str = "", vendor: str = "", version: str = "",
                  hash_md5: str = "", hash_sha1: str = "",
                  added_by: str = "", notes: str = "", confidence: float = 1.0) -> bool:
        """
        Add entry to whitelist.

        Args:
            source: Whitelist source (nsrl, custom, virustotal, signature)
            hash_sha256: SHA256 hash (required)
            filename: Original filename
            product_name: Software product name
            vendor: Vendor/publisher name
            version: Version string
            hash_md5: MD5 hash (optional)
            hash_sha1: SHA1 hash (optional)
            added_by: Who added this entry
            notes: Additional notes
            confidence: Confidence level (0.0-1.0)

        Returns:
            True if added successfully
        """
        if source not in self.whitelists:
            print(f"[Whitelist] Invalid source: {source}")
            return False

        if hash_sha256.lower() in self.sha256_lookup:
            print(f"[Whitelist] Entry already exists: {hash_sha256}")
            return False

        entry = WhitelistEntry(
            hash_sha256=hash_sha256.lower(),
            hash_md5=hash_md5.lower() if hash_md5 else None,
            hash_sha1=hash_sha1.lower() if hash_sha1 else None,
            filename=filename,
            product_name=product_name,
            vendor=vendor,
            version=version,
            source=source,
            added_date=datetime.utcnow().isoformat(),
            added_by=added_by,
            notes=notes,
            confidence=confidence
        )

        self.whitelists[source].append(entry)

        self.sha256_lookup[entry.hash_sha256] = entry
        if entry.hash_md5:
            self.md5_lookup[entry.hash_md5] = entry
        if entry.hash_sha1:
            self.sha1_lookup[entry.hash_sha1] = entry

        self._save_whitelist(source)

        print(f"[Whitelist] Added entry to {source}: {filename or hash_sha256[:16]}")
        return True

    def remove_entry(self, hash_sha256: str) -> bool:
        """
        Remove entry from whitelist.

        Args:
            hash_sha256: SHA256 hash to remove

        Returns:
            True if removed successfully
        """
        hash_lower = hash_sha256.lower()

        if hash_lower not in self.sha256_lookup:
            return False

        entry = self.sha256_lookup[hash_lower]
        source = entry.source

        self.whitelists[source] = [e for e in self.whitelists[source]
                                    if e.hash_sha256 != hash_lower]

        del self.sha256_lookup[hash_lower]
        if entry.hash_md5 and entry.hash_md5 in self.md5_lookup:
            del self.md5_lookup[entry.hash_md5]
        if entry.hash_sha1 and entry.hash_sha1 in self.sha1_lookup:
            del self.sha1_lookup[entry.hash_sha1]

        self._save_whitelist(source)

        print(f"[Whitelist] Removed entry: {hash_sha256[:16]}")
        return True

    def import_nsrl_subset(self, nsrl_file: str, max_entries: int = 10000):
        """
        Import NSRL (National Software Reference Library) subset.

        Args:
            nsrl_file: Path to NSRL CSV file (RDS format)
            max_entries: Maximum entries to import (for testing)

        Note: Full NSRL is very large (~100M hashes). This imports a subset.
        """
        if not os.path.exists(nsrl_file):
            print(f"[Whitelist] NSRL file not found: {nsrl_file}")
            return

        import csv
        count = 0

        try:
            with open(nsrl_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if count >= max_entries:
                        break

                    sha1 = row.get('SHA-1', '').strip()
                    md5 = row.get('MD5', '').strip()
                    filename = row.get('FileName', '').strip()
                    product_code = row.get('ProductCode', '').strip()

                    if sha1 and md5:
                        self.add_entry(
                            source="nsrl",
                            hash_sha256=sha1,
                            hash_sha1=sha1,
                            hash_md5=md5,
                            filename=filename,
                            product_name=f"NSRL Product {product_code}",
                            vendor="NSRL",
                            notes="Imported from NSRL RDS",
                            confidence=0.95
                        )
                        count += 1

            print(f"[Whitelist] Imported {count} entries from NSRL")

        except Exception as e:
            print(f"[Whitelist] Failed to import NSRL: {e}")

    def get_statistics(self) -> Dict[str, int]:
        """Get whitelist statistics"""
        return {
            "nsrl": len(self.whitelists["nsrl"]),
            "custom": len(self.whitelists["custom"]),
            "virustotal": len(self.whitelists["virustotal"]),
            "signature": len(self.whitelists["signature"]),
            "total": len(self.sha256_lookup)
        }

    def export_whitelist(self, source: str, output_path: str) -> bool:
        """Export whitelist to file"""
        if source not in self.whitelists:
            return False

        try:
            data = {
                "source": source,
                "exported": datetime.utcnow().isoformat(),
                "count": len(self.whitelists[source]),
                "entries": [vars(entry) for entry in self.whitelists[source]]
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

            print(f"[Whitelist] Exported {source} to {output_path}")
            return True

        except Exception as e:
            print(f"[Whitelist] Export failed: {e}")
            return False


_whitelist_managers: Dict[str, WhitelistManager] = {}

def get_whitelist_manager(case_id: str = "default") -> WhitelistManager:
    """Get or create whitelist manager for case"""
    if case_id not in _whitelist_managers:
        _whitelist_managers[case_id] = WhitelistManager(case_id)
    return _whitelist_managers[case_id]
