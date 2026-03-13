"""
ForensAI - Media Type & TRIM Detection
=======================================
Detects storage media characteristics critical for forensic analysis.

Features:
- SSD vs HDD detection
- TRIM/DEALLOCATE evidence detection
- Acquisition metadata extraction
- Media health and reliability assessment
"""

import struct
import pyewf
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class MediaInfo:
    """Complete media information for forensic reporting."""

    media_type: str = "Unknown"
    media_subtype: str = ""

    trim_enabled: bool = False
    trim_evidence_found: bool = False
    trim_confidence: float = 0.0

    total_size_bytes: int = 0
    sector_size: int = 512
    total_sectors: int = 0

    acquisition_tool: str = ""
    acquisition_date: str = ""
    acquisition_mode: str = ""
    acquisition_hash_verified: bool = False
    is_read_only: bool = True

    ewf_case_number: str = ""
    ewf_evidence_number: str = ""
    ewf_examiner_name: str = ""
    ewf_description: str = ""
    ewf_notes: str = ""

    bad_sectors_detected: int = 0
    warning_flags: List[str] = None

    def __post_init__(self):
        if self.warning_flags is None:
            self.warning_flags = []


class MediaDetector:
    """
    Analyzes disk images to determine media type and characteristics.

    Critical for determining recovery probability on SSDs with TRIM.
    """

    TRIM_PATTERN_MIN_SIZE = 64 * 1024
    TRIM_SAMPLE_SIZE = 10 * 1024 * 1024
    TRIM_CONFIDENCE_THRESHOLD = 0.7

    def __init__(self, image_handler):
        """
        Initialize media detector.

        Args:
            image_handler: ImageHandler instance
        """
        self.image_handler = image_handler
        self.media_info: Optional[MediaInfo] = None

    def detect_media_characteristics(self) -> MediaInfo:
        """
        Comprehensive media detection and metadata extraction.

        Returns:
            MediaInfo object with all detected characteristics
        """
        info = MediaInfo()

        info.total_size_bytes = self.image_handler.get_size()
        info.total_sectors = info.total_size_bytes // info.sector_size

        if self.image_handler.get_image_type() == "ewf":
            self._extract_ewf_metadata(info)

        info.media_type, info.media_subtype = self._detect_media_type(info)

        if info.media_type in ['SSD', 'Flash']:
            trim_result = self._detect_trim_patterns()
            info.trim_evidence_found = trim_result['found']
            info.trim_confidence = trim_result['confidence']
            info.trim_enabled = trim_result['confidence'] > self.TRIM_CONFIDENCE_THRESHOLD

        self._generate_warnings(info)

        self.media_info = info
        return info

    def _extract_ewf_metadata(self, info: MediaInfo):
        """
        Extract acquisition metadata from EWF image.

        Args:
            info: MediaInfo object to populate
        """
        try:
            filenames = pyewf.glob(self.image_handler.image_path)
            ewf_handle = pyewf.handle()
            ewf_handle.open(filenames)

            try:
                info.ewf_case_number = ewf_handle.get_header_value("case_number") or ""
            except:
                pass

            try:
                info.ewf_evidence_number = ewf_handle.get_header_value("evidence_number") or ""
            except:
                pass

            try:
                info.ewf_examiner_name = ewf_handle.get_header_value("examiner_name") or ""
            except:
                pass

            try:
                info.ewf_description = ewf_handle.get_header_value("description") or ""
            except:
                pass

            try:
                info.ewf_notes = ewf_handle.get_header_value("notes") or ""
            except:
                pass

            try:
                info.acquisition_date = ewf_handle.get_header_value("acquiry_date") or ""
            except:
                pass

            try:
                info.acquisition_tool = ewf_handle.get_header_value("acquiry_software_version") or ""
            except:
                pass

            try:
                stored_md5 = ewf_handle.get_hash_value("MD5")
                info.acquisition_hash_verified = bool(stored_md5)
            except:
                info.acquisition_hash_verified = False

            info.is_read_only = True
            info.acquisition_mode = "Physical"

            ewf_handle.close()

        except Exception as e:
            print(f"Warning: Failed to extract EWF metadata: {e}")

    def _detect_media_type(self, info: MediaInfo) -> Tuple[str, str]:
        """
        Detect media type based on various indicators.

        Args:
            info: MediaInfo with basic data

        Returns:
            Tuple of (media_type, media_subtype)
        """
        media_type = "Unknown"
        media_subtype = ""

        if info.ewf_description:
            desc_lower = info.ewf_description.lower()

            if 'ssd' in desc_lower or 'solid state' in desc_lower:
                media_type = "SSD"
                if 'nvme' in desc_lower:
                    media_subtype = "NVMe"
                elif 'sata' in desc_lower:
                    media_subtype = "SATA"
            elif 'hdd' in desc_lower or 'hard disk' in desc_lower or 'hard drive' in desc_lower:
                media_type = "HDD"
            elif 'usb' in desc_lower or 'flash drive' in desc_lower:
                media_type = "Flash"
                media_subtype = "USB"
            elif 'cd' in desc_lower or 'dvd' in desc_lower or 'optical' in desc_lower:
                media_type = "Optical"

        size_gb = info.total_size_bytes / (1024**3)

        if media_type == "Unknown":
            if size_gb < 2:
                media_type = "Flash"
                media_subtype = "USB"
            elif size_gb < 128:
                media_type = "SSD"
                media_subtype = "SATA"
            else:
                media_type = "HDD"
                media_subtype = "SATA"

        return media_type, media_subtype

    def _detect_trim_patterns(self) -> Dict:
        """
        Detect evidence of TRIM/DEALLOCATE operations.

        TRIM causes deleted data to be immediately zeroed or set to 0xFF,
        reducing recovery probability dramatically.

        Returns:
            Dict with 'found', 'confidence', and 'details'
        """
        result = {
            'found': False,
            'confidence': 0.0,
            'details': {},
            'patterns_found': []
        }

        try:
            total_size = self.image_handler.get_size()

            sample_locations = [
                int(total_size * 0.1),
                int(total_size * 0.3),
                int(total_size * 0.5),
                int(total_size * 0.7),
                int(total_size * 0.9),
            ]

            trim_indicators = 0
            total_samples = 0

            for offset in sample_locations:
                sample_data = self.image_handler.read(offset, self.TRIM_SAMPLE_SIZE)

                if not sample_data:
                    continue

                total_samples += 1

                if self._has_trim_pattern(sample_data):
                    trim_indicators += 1
                    result['patterns_found'].append(f"Offset {offset}: TRIM pattern detected")

            if total_samples > 0:
                result['confidence'] = trim_indicators / total_samples
                result['found'] = result['confidence'] > 0.3

            result['details'] = {
                'samples_checked': total_samples,
                'trim_patterns': trim_indicators,
                'confidence_pct': result['confidence'] * 100
            }

        except Exception as e:
            print(f"Warning: TRIM detection failed: {e}")
            result['error'] = str(e)

        return result

    def _has_trim_pattern(self, data: bytes) -> bool:
        """
        Check if data contains patterns indicative of TRIM.

        TRIM patterns:
        - Large contiguous blocks of 0x00 (common)
        - Large contiguous blocks of 0xFF (some controllers)
        - Repeating patterns (some controllers fill with patterns)

        Args:
            data: Byte data to analyze

        Returns:
            True if TRIM pattern detected
        """
        if len(data) < self.TRIM_PATTERN_MIN_SIZE:
            return False

        max_zero_run = 0
        current_zero_run = 0

        max_ff_run = 0
        current_ff_run = 0

        for byte in data:
            if byte == 0x00:
                current_zero_run += 1
                max_zero_run = max(max_zero_run, current_zero_run)
            else:
                current_zero_run = 0

            if byte == 0xFF:
                current_ff_run += 1
                max_ff_run = max(max_ff_run, current_ff_run)
            else:
                current_ff_run = 0

        return (max_zero_run >= self.TRIM_PATTERN_MIN_SIZE or
                max_ff_run >= self.TRIM_PATTERN_MIN_SIZE)

    def _generate_warnings(self, info: MediaInfo):
        """
        Generate warning flags based on detected characteristics.

        Args:
            info: MediaInfo to add warnings to
        """
        if info.trim_enabled or info.trim_evidence_found:
            info.warning_flags.append(
                f"CRITICAL: TRIM detected (confidence: {info.trim_confidence*100:.1f}%). "
                "Deleted file recovery probability is LOW."
            )

        if info.media_type == "SSD" and not info.trim_evidence_found:
            info.warning_flags.append(
                "WARNING: SSD detected. If TRIM is enabled in the OS, "
                "deleted data may be unrecoverable."
            )

        if info.acquisition_mode and not info.acquisition_hash_verified:
            info.warning_flags.append(
                "WARNING: Acquisition hash not verified. Image integrity uncertain."
            )

        size_gb = info.total_size_bytes / (1024**3)
        if info.media_type == "Flash" and size_gb < 8:
            info.warning_flags.append(
                "INFO: Small flash drive detected. May have limited forensic value."
            )

    def export_report(self) -> Dict:
        """
        Export complete media detection report.

        Returns:
            Dictionary with all media information
        """
        if not self.media_info:
            self.detect_media_characteristics()

        report = asdict(self.media_info)

        report['summary'] = self._generate_summary()

        return report

    def _generate_summary(self) -> str:
        """Generate human-readable summary."""
        if not self.media_info:
            return "No media information available."

        info = self.media_info
        size_gb = info.total_size_bytes / (1024**3)

        summary = f"Media Type: {info.media_type}"
        if info.media_subtype:
            summary += f" ({info.media_subtype})"

        summary += f"\nCapacity: {size_gb:.2f} GB ({info.total_sectors:,} sectors)"

        if info.trim_enabled:
            summary += f"\nTRIM Status: ENABLED (confidence: {info.trim_confidence*100:.0f}%)"
            summary += "\n⚠ WARNING: Deleted file recovery probability is LOW"
        elif info.media_type == "SSD":
            summary += "\nTRIM Status: Unknown (SSD detected)"

        if info.acquisition_tool:
            summary += f"\nAcquired with: {info.acquisition_tool}"

        if info.acquisition_date:
            summary += f"\nAcquisition Date: {info.acquisition_date}"

        if info.acquisition_mode:
            summary += f"\nAcquisition Mode: {info.acquisition_mode}"

        if info.warning_flags:
            summary += "\n\nWARNINGS:"
            for warning in info.warning_flags:
                summary += f"\n- {warning}"

        return summary


def detect_media(image_handler) -> MediaInfo:
    """
    Convenience function to detect media characteristics.

    Args:
        image_handler: ImageHandler instance

    Returns:
        MediaInfo object
    """
    detector = MediaDetector(image_handler)
    return detector.detect_media_characteristics()
