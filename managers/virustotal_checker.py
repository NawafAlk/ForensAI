"""
VirusTotal API Integration

Checks file hashes against VirusTotal for reputation analysis.
Helps identify known malware and reduce false positives for legitimate software.

Features:
- File hash lookup (no file upload - privacy preserved)
- Detection ratio analysis
- Vendor reputation scoring
- Caching to minimize API calls
- Rate limiting support

Requires: VirusTotal API key (free tier: 4 requests/minute)
"""

import requests
import json
import time
import hashlib
from typing import Dict, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import threading


@dataclass
class VTResult:
    """VirusTotal scan result"""
    hash_sha256: str
    detection_ratio: str  # "5/70" format
    positives: int  # Number of engines detecting as malicious
    total: int  # Total engines scanned
    scan_date: str
    permalink: str
    vendors_detected: List[str] = field(default_factory=list)
    is_malicious: bool = False
    is_suspicious: bool = False
    is_clean: bool = False
    reputation_score: float = 0.0  # 0.0 (malicious) to 1.0 (clean)
    confidence: float = 0.0  # Confidence in the result
    error: Optional[str] = None

    def get_verdict(self) -> str:
        """Get human-readable verdict"""
        if self.error:
            return f"Error: {self.error}"
        elif self.is_malicious:
            return f"MALICIOUS ({self.detection_ratio})"
        elif self.is_suspicious:
            return f"SUSPICIOUS ({self.detection_ratio})"
        elif self.is_clean:
            return f"CLEAN ({self.detection_ratio})"
        else:
            return f"UNKNOWN ({self.detection_ratio})"


class VirusTotalChecker:
    """VirusTotal API integration for file reputation checking"""

    # Trusted AV vendors (higher weight in reputation calculation)
    TRUSTED_VENDORS = {
        'Microsoft', 'Kaspersky', 'Symantec', 'McAfee', 'ESET', 'Bitdefender',
        'Avast', 'AVG', 'Trend Micro', 'F-Secure', 'Sophos', 'CrowdStrike'
    }

    def __init__(self, api_key: str = "", cache_dir: str = "cache/virustotal"):
        """
        Initialize VirusTotal checker.

        Args:
            api_key: VirusTotal API key (get from virustotal.com)
            cache_dir: Directory for caching results
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2/file/report"
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Rate limiting (free tier: 4 requests/minute)
        self.rate_limit_delay = 15.0  # seconds between requests
        self.last_request_time = 0.0
        self.request_lock = threading.Lock()

        # Statistics
        self.stats = {
            "cache_hits": 0,
            "api_calls": 0,
            "errors": 0
        }

    def check_hash(self, file_hash: str, hash_type: str = "sha256") -> VTResult:
        """
        Check file hash against VirusTotal.

        Args:
            file_hash: File hash (SHA256, SHA1, or MD5)
            hash_type: Type of hash (sha256, sha1, md5)

        Returns:
            VTResult with scan information
        """
        if not self.api_key:
            return VTResult(
                hash_sha256=file_hash,
                detection_ratio="0/0",
                positives=0,
                total=0,
                scan_date="",
                permalink="",
                error="VirusTotal API key not configured"
            )

        # Check cache first
        cached = self._get_cached_result(file_hash)
        if cached:
            self.stats["cache_hits"] += 1
            return cached

        # Rate limiting
        with self.request_lock:
            time_since_last = time.time() - self.last_request_time
            if time_since_last < self.rate_limit_delay:
                sleep_time = self.rate_limit_delay - time_since_last
                print(f"[VT] Rate limiting: sleeping {sleep_time:.1f}s")
                time.sleep(sleep_time)

            # Make API request
            try:
                params = {
                    'apikey': self.api_key,
                    'resource': file_hash
                }

                response = requests.get(self.base_url, params=params, timeout=30)
                self.last_request_time = time.time()
                self.stats["api_calls"] += 1

                if response.status_code == 200:
                    data = response.json()
                    result = self._parse_response(data, file_hash)
                    self._cache_result(file_hash, result)
                    return result

                elif response.status_code == 204:
                    # Rate limit exceeded
                    self.stats["errors"] += 1
                    return VTResult(
                        hash_sha256=file_hash,
                        detection_ratio="0/0",
                        positives=0,
                        total=0,
                        scan_date="",
                        permalink="",
                        error="Rate limit exceeded. Please wait and try again."
                    )

                elif response.status_code == 403:
                    self.stats["errors"] += 1
                    return VTResult(
                        hash_sha256=file_hash,
                        detection_ratio="0/0",
                        positives=0,
                        total=0,
                        scan_date="",
                        permalink="",
                        error="Invalid API key or access forbidden"
                    )

                else:
                    self.stats["errors"] += 1
                    return VTResult(
                        hash_sha256=file_hash,
                        detection_ratio="0/0",
                        positives=0,
                        total=0,
                        scan_date="",
                        permalink="",
                        error=f"API error: HTTP {response.status_code}"
                    )

            except requests.exceptions.Timeout:
                self.stats["errors"] += 1
                return VTResult(
                    hash_sha256=file_hash,
                    detection_ratio="0/0",
                    positives=0,
                    total=0,
                    scan_date="",
                    permalink="",
                    error="Request timeout"
                )

            except Exception as e:
                self.stats["errors"] += 1
                return VTResult(
                    hash_sha256=file_hash,
                    detection_ratio="0/0",
                    positives=0,
                    total=0,
                    scan_date="",
                    permalink="",
                    error=f"Error: {str(e)}"
                )

    def _parse_response(self, data: Dict, file_hash: str) -> VTResult:
        """Parse VirusTotal API response"""
        response_code = data.get('response_code', 0)

        if response_code == 0:
            # Hash not found in VT database
            return VTResult(
                hash_sha256=file_hash,
                detection_ratio="0/0",
                positives=0,
                total=0,
                scan_date="",
                permalink="",
                error="File not found in VirusTotal database"
            )

        # Extract data
        positives = data.get('positives', 0)
        total = data.get('total', 0)
        scan_date = data.get('scan_date', '')
        permalink = data.get('permalink', '')
        scans = data.get('scans', {})

        # Get vendors that detected as malicious
        vendors_detected = [
            vendor for vendor, result in scans.items()
            if result.get('detected', False)
        ]

        # Calculate reputation score
        reputation_score = self._calculate_reputation(positives, total, vendors_detected)

        # Calculate confidence based on number of engines
        confidence = min(1.0, total / 70.0)  # 70 is typical max engines

        # Determine classification
        detection_rate = positives / total if total > 0 else 0
        is_malicious = detection_rate >= 0.3  # 30% or more detect as malicious
        is_suspicious = 0.05 < detection_rate < 0.3  # 5-30% detection
        is_clean = detection_rate <= 0.05  # 5% or less (likely false positives)

        return VTResult(
            hash_sha256=file_hash,
            detection_ratio=f"{positives}/{total}",
            positives=positives,
            total=total,
            scan_date=scan_date,
            permalink=permalink,
            vendors_detected=vendors_detected,
            is_malicious=is_malicious,
            is_suspicious=is_suspicious,
            is_clean=is_clean,
            reputation_score=reputation_score,
            confidence=confidence
        )

    def _calculate_reputation(self, positives: int, total: int, vendors: List[str]) -> float:
        """
        Calculate reputation score (0.0 = malicious, 1.0 = clean).

        Gives higher weight to trusted vendors.
        """
        if total == 0:
            return 0.5  # Unknown

        # Basic detection rate
        detection_rate = positives / total

        # Check if trusted vendors detected it
        trusted_detections = sum(1 for v in vendors if v in self.TRUSTED_VENDORS)
        trusted_count = sum(1 for v in self.TRUSTED_VENDORS)

        # If multiple trusted vendors flag it, increase malicious score
        if trusted_detections >= 3:
            detection_rate = min(1.0, detection_rate * 1.5)

        # Convert to reputation (invert detection rate)
        reputation = 1.0 - detection_rate

        return max(0.0, min(1.0, reputation))

    def _get_cached_result(self, file_hash: str) -> Optional[VTResult]:
        """Get cached result if available and not expired"""
        cache_file = self.cache_dir / f"{file_hash}.json"

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Check if cache is expired (7 days)
            cached_time = datetime.fromisoformat(data.get('cached_at', ''))
            if datetime.now() - cached_time > timedelta(days=7):
                return None

            # Reconstruct VTResult
            result_data = data.get('result', {})
            return VTResult(**result_data)

        except Exception as e:
            print(f"[VT] Failed to read cache: {e}")
            return None

    def _cache_result(self, file_hash: str, result: VTResult):
        """Cache result to disk"""
        cache_file = self.cache_dir / f"{file_hash}.json"

        try:
            data = {
                'cached_at': datetime.now().isoformat(),
                'hash': file_hash,
                'result': vars(result)
            }

            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"[VT] Failed to write cache: {e}")

    def check_file_data(self, file_data: Dict) -> Optional[VTResult]:
        """
        Check file using available hashes.

        Args:
            file_data: Dictionary with hash fields (sha256, sha1, md5)

        Returns:
            VTResult or None if no hashes available
        """
        # Try SHA256 first (best)
        if 'sha256' in file_data and file_data['sha256']:
            return self.check_hash(file_data['sha256'], 'sha256')

        # Try SHA1
        if 'sha1' in file_data and file_data['sha1']:
            return self.check_hash(file_data['sha1'], 'sha1')

        # Try MD5 (least preferred)
        if 'md5' in file_data and file_data['md5']:
            return self.check_hash(file_data['md5'], 'md5')

        return None

    def get_statistics(self) -> Dict[str, int]:
        """Get usage statistics"""
        return self.stats.copy()


# Singleton pattern
_vt_checkers: Dict[str, VirusTotalChecker] = {}

def get_virustotal_checker(api_key: str = "") -> VirusTotalChecker:
    """Get or create VirusTotal checker"""
    if "default" not in _vt_checkers:
        _vt_checkers["default"] = VirusTotalChecker(api_key)
    return _vt_checkers["default"]
