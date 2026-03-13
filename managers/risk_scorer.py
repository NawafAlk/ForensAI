"""
ForensAI - Risk Scoring Engine
===============================
Rule-based risk assessment for forensic artifacts.

Evaluates files, registry keys, and activities to prioritize investigation
efforts. Uses heuristics and pattern matching to flag suspicious items.
"""

import os
import re
import math
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import numpy as np

try:
    from managers.audit_logger import get_audit_logger, AuditLogger
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False
    AuditLogger = None

try:
    from managers.confidence_tracker import get_confidence_tracker, ConfidenceTracker, FactType
    CONFIDENCE_AVAILABLE = True
except ImportError:
    CONFIDENCE_AVAILABLE = False
    ConfidenceTracker = None
    FactType = None

try:
    from managers.block_map import get_cluster_index, OverwriteAnalysis
    BLOCKMAP_AVAILABLE = True
except ImportError:
    BLOCKMAP_AVAILABLE = False
    OverwriteAnalysis = None


@dataclass
class RiskScore:
    """Risk assessment result for an artifact."""

    score: int
    severity: str
    reasons: List[str]
    details: Dict[str, str]
    recommendations: List[str]
    overwrite_analysis: Optional['OverwriteAnalysis'] = None


class RiskScorer:
    """
    Rule-based risk assessment engine.

    Evaluates artifacts against forensic indicators and assigns risk scores.
    """

    SEVERITY_THRESHOLDS = {
        'critical': 90,
        'high': 70,
        'medium': 40,
        'low': 20,
        'info': 0
    }

    RULE_WEIGHTS = {
        'executable_in_user_dir': 85,
        'executable_in_temp': 90,
        'executable_in_downloads': 80,
        'executable_in_appdata': 75,
        'system_file_wrong_location': 95,
        'hidden_executable': 70,
        'unsigned_executable': 50,

        'double_extension': 65,
        'suspicious_extension': 60,
        'masquerading_filename': 85,
        'very_long_filename': 40,
        'unicode_obfuscation': 55,

        'high_entropy': 70,
        'extremely_high_entropy': 85,
        'encrypted_archive': 60,
        'script_in_document': 80,

        'recently_deleted': 65,
        'deleted_during_investigation': 90,
        'timestomp_detected': 95,
        'impossible_timestamp': 70,
        'created_equals_modified': 45,

        'unusually_small_executable': 55,
        'unusually_large_document': 50,
        'zero_byte_file': 30,

        'file_in_recycle_bin': 60,
        'file_in_system32': 40,
        'file_in_startup': 75,

        'large_archive_recent': 65,
        'archive_in_temp': 55,

        'wiping_tool_artifact': 95,
        'encryption_tool_artifact': 75,
        'timestomp_tool': 90
    }

    SYSTEM_EXECUTABLES = {
        'cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe',
        'mshta.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe',
        'bitsadmin.exe', 'schtasks.exe', 'net.exe', 'netsh.exe'
    }

    SUSPICIOUS_EXTENSIONS = {
        'exe', 'scr', 'pif', 'bat', 'cmd', 'vbs', 'js', 'jse',
        'wsf', 'wsh', 'ps1', 'psm1', 'msi', 'msp', 'com', 'jar'
    }

    DOCUMENT_EXTENSIONS = {
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'txt', 'rtf'
    }

    def __init__(self, investigation_start_time: Optional[datetime] = None,
                 audit_logger: Optional[AuditLogger] = None, case_id: str = "default",
                 confidence_tracker: Optional['ConfidenceTracker'] = None):
        """
        Initialize risk scorer.

        Args:
            investigation_start_time: When investigation began (for recent deletion checks)
            audit_logger: Optional audit logger for provenance tracking
            case_id: Case identifier for audit logging
            confidence_tracker: Optional confidence tracker for uncertainty metrics
        """
        self.investigation_start_time = investigation_start_time or datetime.now()
        self.audit_logger = audit_logger
        self.case_id = case_id
        self.confidence_tracker = confidence_tracker

        self._compiled_patterns = {
            'double_ext_doc': re.compile(r'\.(doc|docx|xls|xlsx|ppt|pptx|pdf|txt|rtf)\.(exe|scr|pif|bat|cmd|vbs|js|jse|wsf|wsh|ps1|psm1|msi|msp|com|jar)$', re.IGNORECASE),
            'suspicious_ext': re.compile(r'\.(vbs|js|jse|wsf|wsh|pif|scr)$', re.IGNORECASE),
            'archive_ext': re.compile(r'\.(7z|rar|zip|aes)$', re.IGNORECASE),
            'exec_ext': re.compile(r'\.(exe|dll|sys|scr|com)$', re.IGNORECASE),
            'system_path': re.compile(r'windows[/\\]system32', re.IGNORECASE),
            'syswow_path': re.compile(r'windows[/\\]syswow64', re.IGNORECASE),
            'temp_path': re.compile(r'[/\\](temp|tmp)[/\\]', re.IGNORECASE),
            'downloads_path': re.compile(r'[/\\]downloads[/\\]', re.IGNORECASE),
            'appdata_path': re.compile(r'[/\\]appdata[/\\]', re.IGNORECASE),
            'users_path': re.compile(r'[/\\]users[/\\]', re.IGNORECASE),
            'recycle_path': re.compile(r'(\$recycle\.bin|recycler)', re.IGNORECASE),
            'startup_path': re.compile(r'(startup|[/\\]run[/\\])', re.IGNORECASE),
            'unicode_suspicious': re.compile(r'[\u200b-\u200f\u202a-\u202e\u2066-\u2069]'),
        }

        self._executor = ThreadPoolExecutor(max_workers=4)

        if self.audit_logger is None and AUDIT_AVAILABLE:
            try:
                self.audit_logger = get_audit_logger(case_id)
            except:
                self.audit_logger = None

        if self.confidence_tracker is None and CONFIDENCE_AVAILABLE:
            try:
                self.confidence_tracker = get_confidence_tracker(case_id)
            except:
                self.confidence_tracker = None

    def score_file(self, file_data: Dict) -> RiskScore:
        """
        Evaluate a file and assign risk score.

        Args:
            file_data: Dictionary containing:
                - name: filename
                - path: full path
                - size: file size in bytes
                - created: creation timestamp
                - modified: modification timestamp
                - accessed: access timestamp
                - is_deleted: whether file is deleted/carved
                - mime_type: MIME type (optional)
                - entropy: file entropy (optional, 0-8)

        Returns:
            RiskScore object
        """
        reasons = []
        details = {}
        recommendations = []
        total_score = 0
        rules_fired_log = []

        filename = file_data.get('name', '').lower()
        filepath = file_data.get('path', '').lower()
        size = file_data.get('size', 0)

        if self.confidence_tracker and CONFIDENCE_AVAILABLE:
            self._track_derived_facts(file_data)

        exec_score, exec_reasons = self._check_executable_risks(file_data)
        total_score += exec_score
        reasons.extend(exec_reasons)

        if total_score >= 90:
            reasons_copy = list(reasons)
            for reason in reasons_copy:
                details[reason] = self._get_reason_description(reason)
            if reasons:
                recommendations = self._get_recommendations(reasons, file_data)
            final_score = min(total_score, 100)
            severity = self._calculate_severity(final_score)
            if self.audit_logger and reasons:
                try:
                    rules_fired_log = [{'code': r, 'weight': self.RULE_WEIGHTS.get(r, 0), 'description': self._get_reason_description(r)} for r in reasons]
                    self.audit_logger.log_rule_firing(
                        artifact_id=str(file_data.get('inode', file_data.get('hash', filename))),
                        artifact_name=file_data.get('name', ''),
                        artifact_path=file_data.get('path', ''),
                        final_score=final_score, severity=severity,
                        rules_fired=rules_fired_log, artifact_data=file_data
                    )
                except Exception:
                    pass
            return RiskScore(score=final_score, severity=severity, reasons=reasons, details=details, recommendations=recommendations)

        name_score, name_reasons = self._check_filename_risks(file_data)
        total_score += name_score
        reasons.extend(name_reasons)

        content_score, content_reasons = self._check_content_risks(file_data)
        total_score += content_score
        reasons.extend(content_reasons)

        time_score, time_reasons = self._check_timestamp_risks(file_data)
        total_score += time_score
        reasons.extend(time_reasons)

        size_score, size_reasons = self._check_size_risks(file_data)
        total_score += size_score
        reasons.extend(size_reasons)

        loc_score, loc_reasons = self._check_location_risks(file_data)
        total_score += loc_score
        reasons.extend(loc_reasons)

        overwrite_analysis = None
        if file_data.get('is_deleted', False) or file_data.get('is_carved', False):
            overwrite_score, overwrite_reasons, overwrite_analysis = self._check_overwrite_risks(file_data)
            total_score += overwrite_score
            reasons.extend(overwrite_reasons)

        for reason in reasons:
            details[reason] = self._get_reason_description(reason)

            rules_fired_log.append({
                'code': reason,
                'weight': self.RULE_WEIGHTS.get(reason, 0),
                'description': self._get_reason_description(reason)
            })

        if reasons:
            recommendations = self._get_recommendations(reasons, file_data)

        final_score = min(total_score, 100)
        severity = self._calculate_severity(final_score)

        if self.audit_logger and rules_fired_log:
            try:
                artifact_id = file_data.get('inode', file_data.get('hash', filename))
                artifact_path = file_data.get('path', '')

                self.audit_logger.log_rule_firing(
                    artifact_id=str(artifact_id),
                    artifact_name=file_data.get('name', ''),
                    artifact_path=artifact_path,
                    final_score=final_score,
                    severity=severity,
                    rules_fired=rules_fired_log,
                    artifact_data=file_data
                )
            except Exception as e:
                print(f"Warning: Audit logging failed: {e}")

        return RiskScore(
            score=final_score,
            severity=severity,
            reasons=reasons,
            details=details,
            recommendations=recommendations,
            overwrite_analysis=overwrite_analysis
        )

    def score_files_batch(self, files: List[Dict]) -> List[RiskScore]:
        """
        Score multiple files in parallel using thread pool.

        Args:
            files: List of file data dictionaries

        Returns:
            List of RiskScore objects
        """
        futures = [self._executor.submit(self.score_file, f) for f in files]
        results = []
        for future in futures:
            try:
                results.append(future.result(timeout=30))
            except Exception as e:
                results.append(RiskScore(
                    score=0, severity='info', reasons=['scoring_error'],
                    details={'scoring_error': str(e)}, recommendations=[]
                ))
        return results

    def _track_derived_facts(self, file_data: Dict):
        """
        Track evidence-derived facts with high confidence.
        These are facts directly extracted from the evidence (not AI inferred).
        """
        if not self.confidence_tracker or not CONFIDENCE_AVAILABLE:
            return

        artifact_id = str(file_data.get('inode', file_data.get('hash', file_data.get('name', ''))))
        artifact_name = file_data.get('name', '')

        try:
            if artifact_name:
                self.confidence_tracker.add_fact(
                    fact_type=FactType.DERIVED,
                    description="File name",
                    value=artifact_name,
                    confidence_score=1.0,
                    source="Filesystem metadata",
                    artifact_id=artifact_id,
                    artifact_name=artifact_name,
                    reasoning="Directly extracted from filesystem"
                )

            if 'size' in file_data:
                self.confidence_tracker.add_fact(
                    fact_type=FactType.DERIVED,
                    description="File size",
                    value=f"{file_data['size']} bytes",
                    confidence_score=1.0,
                    source="Filesystem metadata",
                    artifact_id=artifact_id,
                    artifact_name=artifact_name,
                    reasoning="Directly extracted from filesystem"
                )

            for ts_type in ['created', 'modified', 'accessed', 'changed']:
                if ts_type in file_data and file_data[ts_type]:
                    self.confidence_tracker.add_fact(
                        fact_type=FactType.DERIVED,
                        description=f"Timestamp ({ts_type})",
                        value=str(file_data[ts_type]),
                        confidence_score=1.0,
                        source="Filesystem metadata",
                        artifact_id=artifact_id,
                        artifact_name=artifact_name,
                        reasoning="Directly extracted from filesystem"
                    )

            if 'path' in file_data:
                self.confidence_tracker.add_fact(
                    fact_type=FactType.DERIVED,
                    description="File path",
                    value=file_data['path'],
                    confidence_score=1.0,
                    source="Filesystem metadata",
                    artifact_id=artifact_id,
                    artifact_name=artifact_name,
                    reasoning="Directly extracted from filesystem"
                )

            if 'entropy' in file_data:
                self.confidence_tracker.add_fact(
                    fact_type=FactType.COMPUTED,
                    description="File entropy",
                    value=f"{file_data['entropy']:.2f}",
                    confidence_score=0.95,
                    source="Shannon entropy calculation",
                    artifact_id=artifact_id,
                    artifact_name=artifact_name,
                    reasoning="Mathematically computed from file contents"
                )

            for hash_type in ['md5', 'sha1', 'sha256']:
                if hash_type in file_data and file_data[hash_type]:
                    self.confidence_tracker.add_fact(
                        fact_type=FactType.DERIVED,
                        description=f"{hash_type.upper()} hash",
                        value=file_data[hash_type],
                        confidence_score=1.0,
                        source="Cryptographic hash function",
                        artifact_id=artifact_id,
                        artifact_name=artifact_name,
                        reasoning="Cryptographically computed from file contents"
                    )

            if 'mime_type' in file_data:
                self.confidence_tracker.add_fact(
                    fact_type=FactType.COMPUTED,
                    description="MIME type",
                    value=file_data['mime_type'],
                    confidence_score=0.90,
                    source="File type detection (libmagic)",
                    artifact_id=artifact_id,
                    artifact_name=artifact_name,
                    reasoning="Detected from file signature and content analysis"
                )

            if 'created' not in file_data or 'modified' not in file_data:
                self.confidence_tracker.add_uncertainty(
                    indicator_type="missing_data",
                    severity="medium",
                    description=f"File '{artifact_name}' missing timestamp metadata",
                    mitigation="Timestamps may be unavailable for carved/deleted files",
                    affected_artifacts=[artifact_id]
                )

            if file_data.get('is_deleted', False):
                self.confidence_tracker.add_uncertainty(
                    indicator_type="incomplete_recovery",
                    severity="medium",
                    description=f"File '{artifact_name}' is deleted/carved - may be incomplete",
                    mitigation="Verify file integrity with hash checks and content analysis",
                    affected_artifacts=[artifact_id]
                )

        except Exception as e:
            print(f"Warning: Failed to track derived facts: {e}")

    def _check_executable_risks(self, file_data: Dict) -> Tuple[int, List[str]]:
        """Check executable-related risks."""
        score = 0
        reasons = []

        filename = file_data.get('name', '').lower()
        filepath = file_data.get('path', '').lower()
        ext = os.path.splitext(filename)[1][1:] if '.' in filename else ''

        if ext in ['exe', 'dll', 'sys', 'scr', 'com']:
            if 'users' in filepath and 'downloads' in filepath:
                score += self.RULE_WEIGHTS['executable_in_downloads']
                reasons.append('executable_in_downloads')

            elif 'users' in filepath and ('temp' in filepath or 'tmp' in filepath):
                score += self.RULE_WEIGHTS['executable_in_temp']
                reasons.append('executable_in_temp')

            elif 'users' in filepath and 'appdata' in filepath:
                score += self.RULE_WEIGHTS['executable_in_appdata']
                reasons.append('executable_in_appdata')

            elif 'users' in filepath:
                score += self.RULE_WEIGHTS['executable_in_user_dir']
                reasons.append('executable_in_user_dir')

            base_filename = os.path.basename(filename)
            if base_filename in self.SYSTEM_EXECUTABLES:
                if 'windows\\system32' not in filepath and 'windows\\syswow64' not in filepath:
                    score += self.RULE_WEIGHTS['system_file_wrong_location']
                    reasons.append('system_file_wrong_location')

        return score, reasons

    def _check_filename_risks(self, file_data: Dict) -> Tuple[int, List[str]]:
        """Check filename-related risks."""
        score = 0
        reasons = []

        filename = file_data.get('name', '')
        filename_lower = filename.lower()

        if hasattr(self, '_compiled_patterns') and self._compiled_patterns['double_ext_doc'].search(filename_lower):
            score += self.RULE_WEIGHTS['double_extension']
            reasons.append('double_extension')
        else:
            parts = filename.split('.')
            if len(parts) >= 3:
                second_last_ext = parts[-2].lower()
                last_ext = parts[-1].lower()
                if second_last_ext in self.DOCUMENT_EXTENSIONS and last_ext in self.SUSPICIOUS_EXTENSIONS:
                    score += self.RULE_WEIGHTS['double_extension']
                    reasons.append('double_extension')

        if os.path.basename(filename_lower) in self.SYSTEM_EXECUTABLES:
            filepath = file_data.get('path', '').lower()
            if 'system32' not in filepath:
                score += self.RULE_WEIGHTS['masquerading_filename']
                reasons.append('masquerading_filename')

        if len(filename) > 200:
            score += self.RULE_WEIGHTS['very_long_filename']
            reasons.append('very_long_filename')

        ext = os.path.splitext(filename)[1][1:].lower() if '.' in filename else ''
        if ext in ['vbs', 'js', 'jse', 'wsf', 'wsh', 'pif', 'scr']:
            score += self.RULE_WEIGHTS['suspicious_extension']
            reasons.append('suspicious_extension')

        return score, reasons

    def _check_content_risks(self, file_data: Dict) -> Tuple[int, List[str]]:
        """Check content-based risks."""
        score = 0
        reasons = []

        entropy = file_data.get('entropy')
        if entropy is not None:
            if entropy > 7.8:
                score += self.RULE_WEIGHTS['extremely_high_entropy']
                reasons.append('extremely_high_entropy')
            elif entropy > 7.2:
                score += self.RULE_WEIGHTS['high_entropy']
                reasons.append('high_entropy')

        filename = file_data.get('name', '').lower()
        if any(ext in filename for ext in ['.7z', '.rar', '.zip', '.aes']):
            if entropy and entropy > 7.5:
                score += self.RULE_WEIGHTS['encrypted_archive']
                reasons.append('encrypted_archive')

        return score, reasons

    def _check_timestamp_risks(self, file_data: Dict) -> Tuple[int, List[str]]:
        """Check timestamp-related anomalies."""
        score = 0
        reasons = []

        created = self._parse_timestamp(file_data.get('created'))
        modified = self._parse_timestamp(file_data.get('modified'))
        accessed = self._parse_timestamp(file_data.get('accessed'))

        if file_data.get('is_deleted'):
            if file_data.get('deleted_time'):
                deleted = self._parse_timestamp(file_data['deleted_time'])
                if deleted:
                    days_ago = (datetime.now() - deleted).days
                    if days_ago <= 7:
                        score += self.RULE_WEIGHTS['recently_deleted']
                        reasons.append('recently_deleted')

                    if deleted >= self.investigation_start_time:
                        score += self.RULE_WEIGHTS['deleted_during_investigation']
                        reasons.append('deleted_during_investigation')

        if created and modified:
            if created > modified:
                score += self.RULE_WEIGHTS['timestomp_detected']
                reasons.append('timestomp_detected')

        now = datetime.now()
        for ts in [created, modified, accessed]:
            if ts:
                if ts > now:
                    score += self.RULE_WEIGHTS['impossible_timestamp']
                    reasons.append('impossible_timestamp')
                    break
                if ts.year < 1990:
                    score += self.RULE_WEIGHTS['impossible_timestamp']
                    reasons.append('impossible_timestamp')
                    break

        if created and modified and created == modified:
            ext = os.path.splitext(file_data.get('name', ''))[1][1:].lower()
            if ext in self.SUSPICIOUS_EXTENSIONS:
                score += self.RULE_WEIGHTS['created_equals_modified']
                reasons.append('created_equals_modified')

        return score, reasons

    def _check_size_risks(self, file_data: Dict) -> Tuple[int, List[str]]:
        """Check size-based anomalies."""
        score = 0
        reasons = []

        size = file_data.get('size', 0)
        filename = file_data.get('name', '').lower()
        ext = os.path.splitext(filename)[1][1:] if '.' in filename else ''

        if ext in ['exe', 'dll'] and 0 < size < 10000:
            score += self.RULE_WEIGHTS['unusually_small_executable']
            reasons.append('unusually_small_executable')

        if ext in self.DOCUMENT_EXTENSIONS and size > 100 * 1024 * 1024:
            score += self.RULE_WEIGHTS['unusually_large_document']
            reasons.append('unusually_large_document')

        if size == 0:
            score += self.RULE_WEIGHTS['zero_byte_file']
            reasons.append('zero_byte_file')

        if ext in ['zip', '7z', 'rar', 'tar', 'gz'] and size > 50 * 1024 * 1024:
            modified = self._parse_timestamp(file_data.get('modified'))
            if modified and (datetime.now() - modified).days <= 7:
                score += self.RULE_WEIGHTS['large_archive_recent']
                reasons.append('large_archive_recent')

        return score, reasons

    def _check_location_risks(self, file_data: Dict) -> Tuple[int, List[str]]:
        """Check location-based risks."""
        score = 0
        reasons = []

        filepath = file_data.get('path', '').lower()

        if '$recycle.bin' in filepath or 'recycler' in filepath:
            score += self.RULE_WEIGHTS['file_in_recycle_bin']
            reasons.append('file_in_recycle_bin')

        if 'startup' in filepath or 'run' in filepath:
            score += self.RULE_WEIGHTS['file_in_startup']
            reasons.append('file_in_startup')

        if ('temp' in filepath or 'tmp' in filepath):
            ext = os.path.splitext(file_data.get('name', ''))[1][1:].lower()
            if ext in ['zip', '7z', 'rar']:
                score += self.RULE_WEIGHTS['archive_in_temp']
                reasons.append('archive_in_temp')

        return score, reasons

    def _check_overwrite_risks(self, file_data: Dict) -> Tuple[int, List[str], Optional['OverwriteAnalysis']]:
        """
        Check for overwrite patterns in deleted/carved files.

        Returns:
            Tuple of (score, reasons, overwrite_analysis)
        """
        score = 0
        reasons = []
        overwrite_analysis = None

        if not BLOCKMAP_AVAILABLE:
            return score, reasons, overwrite_analysis

        try:
            image_handler = file_data.get('image_handler')
            if not image_handler:
                return score, reasons, overwrite_analysis

            cluster_index = get_cluster_index(image_handler)

            carved_data = {
                'offset': file_data.get('offset', 0),
                'size': file_data.get('size', 0),
                'file_type': file_data.get('mime_type', 'unknown'),
                'deleted_time': file_data.get('deleted_time', file_data.get('modified'))
            }

            carved_id = str(file_data.get('inode', file_data.get('hash', file_data.get('name', ''))))
            overwrite_analysis = cluster_index.analyze_overwrite(carved_id, carved_data)

            if overwrite_analysis:
                overwrite_contrib = overwrite_analysis.to_risk_contribution()
                score += overwrite_contrib

                if overwrite_analysis.overwrite_risk_pct > 70:
                    reasons.append('heavily_overwritten')
                elif overwrite_analysis.overwrite_risk_pct > 40:
                    reasons.append('partially_overwritten')
                elif overwrite_analysis.overwrite_risk_pct > 10:
                    reasons.append('minor_overwrite')

                if len(overwrite_analysis.overwritten_by) > 2:
                    reasons.append('multiple_overwriters')

                if overwrite_analysis.fragmentation_score > 60:
                    reasons.append('highly_fragmented_deleted')

        except Exception as e:
            print(f"Warning: Overwrite analysis failed: {e}")

        return score, reasons, overwrite_analysis

    def _calculate_severity(self, score: int) -> str:
        """Calculate severity level from score."""
        if score >= self.SEVERITY_THRESHOLDS['critical']:
            return 'critical'
        elif score >= self.SEVERITY_THRESHOLDS['high']:
            return 'high'
        elif score >= self.SEVERITY_THRESHOLDS['medium']:
            return 'medium'
        elif score >= self.SEVERITY_THRESHOLDS['low']:
            return 'low'
        else:
            return 'info'

    def _get_reason_description(self, reason_code: str) -> str:
        """Get human-readable description for a reason code."""
        descriptions = {
            'executable_in_downloads': 'Executable file found in Downloads folder',
            'executable_in_temp': 'Executable file found in temporary directory',
            'executable_in_user_dir': 'Executable file found in user directory (non-standard location)',
            'executable_in_appdata': 'Executable file found in AppData folder',
            'system_file_wrong_location': 'System executable found outside Windows system directories',
            'double_extension': 'File has double extension (possible masquerading)',
            'masquerading_filename': 'Filename matches system file but in wrong location',
            'very_long_filename': 'Filename is unusually long (possible obfuscation)',
            'suspicious_extension': 'File extension commonly used by malware',
            'high_entropy': 'High entropy content suggests encryption or compression',
            'extremely_high_entropy': 'Extremely high entropy - likely encrypted',
            'encrypted_archive': 'Encrypted or password-protected archive',
            'recently_deleted': 'File was recently deleted',
            'deleted_during_investigation': 'File was deleted during investigation period',
            'timestomp_detected': 'Timestamp manipulation detected (created after modified)',
            'impossible_timestamp': 'Timestamp is in future or impossibly old',
            'created_equals_modified': 'Creation and modification times are identical',
            'unusually_small_executable': 'Executable file is unusually small',
            'unusually_large_document': 'Document file is unusually large',
            'zero_byte_file': 'File has zero size',
            'file_in_recycle_bin': 'File found in Recycle Bin',
            'file_in_startup': 'File found in startup location',
            'large_archive_recent': 'Large archive created recently',
            'archive_in_temp': 'Archive file found in temporary directory',
            'heavily_overwritten': 'File heavily overwritten (>70% of clusters reused)',
            'partially_overwritten': 'File partially overwritten (>40% of clusters reused)',
            'minor_overwrite': 'Minor overwrite detected (>10% of clusters affected)',
            'multiple_overwriters': 'Multiple files overwrote this data (deliberate destruction)',
            'highly_fragmented_deleted': 'Deleted file is highly fragmented (unusual pattern)'
        }
        return descriptions.get(reason_code, reason_code)

    def _get_recommendations(self, reasons: List[str], file_data: Dict) -> List[str]:
        """Generate investigation recommendations based on triggered rules."""
        recommendations = []

        if any(r in reasons for r in ['system_file_wrong_location', 'masquerading_filename']):
            recommendations.append('Compare file hash against known-good system file hashes')
            recommendations.append('Examine file metadata and digital signatures')

        if 'double_extension' in reasons:
            recommendations.append('Verify true file type using file signature analysis')

        if any(r in reasons for r in ['high_entropy', 'extremely_high_entropy', 'encrypted_archive']):
            recommendations.append('Attempt to identify encryption method or password')
            recommendations.append('Check for encryption keys in memory dumps or registry')

        if any(r in reasons for r in ['deleted_during_investigation', 'recently_deleted']):
            recommendations.append('Attempt file recovery from unallocated space')
            recommendations.append('Examine deletion timeline for user intent')

        if 'timestomp_detected' in reasons:
            recommendations.append('Check MFT $STANDARD_INFORMATION vs $FILE_NAME timestamps')
            recommendations.append('Look for timestomping tool artifacts')

        if any(r in reasons for r in ['executable_in_downloads', 'executable_in_temp']):
            recommendations.append('Check browser history for download source')
            recommendations.append('Submit hash to VirusTotal or malware databases')

        if 'file_in_startup' in reasons:
            recommendations.append('Document persistence mechanism')
            recommendations.append('Check for related scheduled tasks or registry keys')

        if any(r in reasons for r in ['heavily_overwritten', 'partially_overwritten', 'multiple_overwriters']):
            recommendations.append('Attempt recovery of intact clusters')
            recommendations.append('Investigate timeline of overwriting files')
            recommendations.append('Document evidence destruction attempt')

        if 'highly_fragmented_deleted' in reasons:
            recommendations.append('Analyze fragmentation pattern for deliberate file splitting')

        return recommendations

    @staticmethod
    def calculate_entropy_fast(data: bytes) -> float:
        """Calculate Shannon entropy using numpy vectorization."""
        if not data:
            return 0.0
        byte_array = np.frombuffer(data, dtype=np.uint8)
        _, counts = np.unique(byte_array, return_counts=True)
        probabilities = counts / len(byte_array)
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return float(entropy)

    def set_case_context(self, case_type: str = 'general'):
        """Adjust scoring thresholds based on case context."""
        if case_type == 'malware':
            self.SEVERITY_THRESHOLDS = {'critical': 85, 'high': 65, 'medium': 35, 'low': 15, 'info': 0}
        elif case_type == 'data_theft':
            self.SEVERITY_THRESHOLDS = {'critical': 90, 'high': 70, 'medium': 40, 'low': 20, 'info': 0}
        elif case_type == 'intrusion':
            self.SEVERITY_THRESHOLDS = {'critical': 88, 'high': 68, 'medium': 38, 'low': 18, 'info': 0}
        else:
            self.SEVERITY_THRESHOLDS = {'critical': 90, 'high': 70, 'medium': 40, 'low': 20, 'info': 0}

    @staticmethod
    def _parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
        """Parse timestamp string to datetime object."""
        if not ts_str or ts_str == 'N/A':
            return None

        try:
            for fmt in ['%Y-%m-%d %H:%M:%S UTC', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
                try:
                    return datetime.strptime(ts_str, fmt)
                except ValueError:
                    continue
        except:
            pass

        return None


_risk_scorer = None

def get_risk_scorer() -> RiskScorer:
    """Get singleton risk scorer instance."""
    global _risk_scorer
    if _risk_scorer is None:
        _risk_scorer = RiskScorer()
    return _risk_scorer


@dataclass
class CaseContext:
    """
    Investigation context for adaptive risk scoring.

    Allows the scorer to adjust weights based on:
    - Case type (malware vs. data theft vs. intrusion)
    - Known good/bad files
    - Key investigation timestamps
    """

    CASE_TYPES = {
        'malware': 'Malware infection investigation',
        'data_theft': 'Data exfiltration/insider threat',
        'intrusion': 'Network intrusion/APT',
        'general': 'General forensic examination',
    }

    CATEGORY_MULTIPLIERS = {
        'malware': {
            'execution': 1.2,
            'anti_forensic': 1.0,
            'exfiltration': 0.8,
            'persistence': 1.3,
        },
        'data_theft': {
            'execution': 0.8,
            'anti_forensic': 1.3,
            'exfiltration': 1.4,
            'persistence': 0.7,
        },
        'intrusion': {
            'execution': 1.1,
            'anti_forensic': 1.2,
            'exfiltration': 1.1,
            'persistence': 1.2,
        },
        'general': {
            'execution': 1.0,
            'anti_forensic': 1.0,
            'exfiltration': 1.0,
            'persistence': 1.0,
        }
    }

    case_type: str = 'general'
    case_id: str = ''
    investigation_start: Optional[datetime] = None
    known_good_hashes: Set[str] = field(default_factory=set)
    known_bad_hashes: Set[str] = field(default_factory=set)
    key_timestamps: List[Tuple[datetime, str]] = field(default_factory=list)
    focus_paths: List[str] = field(default_factory=list)

    def get_multiplier(self, category: str) -> float:
        """Get weight multiplier for a rule category."""
        case_multipliers = self.CATEGORY_MULTIPLIERS.get(self.case_type, {})
        return case_multipliers.get(category, 1.0)

    def is_known_good(self, file_hash: str) -> bool:
        """Check if file hash is in known-good whitelist."""
        return file_hash.lower() in self.known_good_hashes if file_hash else False

    def is_known_bad(self, file_hash: str) -> bool:
        """Check if file hash is in known-bad blacklist."""
        return file_hash.lower() in self.known_bad_hashes if file_hash else False

    def add_key_timestamp(self, timestamp: datetime, description: str):
        """Add a significant timestamp (e.g., phishing email received)."""
        self.key_timestamps.append((timestamp, description))
        self.key_timestamps.sort(key=lambda x: x[0])

    def find_matching_timestamps(self, artifact_time: datetime,
                                  window_minutes: int = 30) -> List[Tuple[datetime, str]]:
        """Find key timestamps within window of artifact time."""
        matches = []
        for ts, desc in self.key_timestamps:
            if abs((artifact_time - ts).total_seconds()) <= window_minutes * 60:
                matches.append((ts, desc))
        return matches


@dataclass
class HybridRiskScore:
    """
    Comprehensive risk assessment result from hybrid intelligence system.

    Combines rule-based scoring, behavioral pattern detection,
    correlation analysis, and AI contextual evaluation.
    """

    rule_score: int
    pattern_boost: int
    correlation_boost: int
    ai_adjustment: int
    final_score: int

    severity: str
    confidence: float

    triggered_rules: List[str]
    rule_details: Dict[str, str]
    matched_patterns: List[Dict]
    correlation_insights: Dict

    ai_used: bool
    ai_reasoning: Optional[str]
    false_positive_likelihood: float
    attack_chain_stage: Optional[str]

    recommendations: List[str]

    overwrite_analysis: Optional['OverwriteAnalysis'] = None


BEHAVIORAL_PATTERNS = {
    'malware_dropper': {
        'name': 'Malware Dropper Pattern',
        'description': 'Executable downloaded and placed in staging location',
        'required': ['executable_in_downloads'],
        'supporting': ['high_entropy', 'extremely_high_entropy', 'unsigned_executable',
                       'executable_in_temp', 'suspicious_extension'],
        'min_supporting': 1,
        'score_boost': 25,
        'attack_stage': 'initial_access',
        'mitre_attack': 'T1105',
        'confidence': 'high'
    },
    'malware_staging': {
        'name': 'Malware Staging Pattern',
        'description': 'Executable in temporary location with obfuscation indicators',
        'required': ['executable_in_temp'],
        'supporting': ['high_entropy', 'extremely_high_entropy', 'hidden_executable',
                       'created_equals_modified'],
        'min_supporting': 1,
        'score_boost': 20,
        'attack_stage': 'execution',
        'mitre_attack': 'T1059',
        'confidence': 'high'
    },
    'persistence_install': {
        'name': 'Persistence Installation',
        'description': 'Executable placed in auto-run location',
        'required': ['file_in_startup'],
        'supporting': ['executable_in_appdata', 'hidden_executable',
                       'recently_deleted', 'executable_in_temp'],
        'min_supporting': 0,
        'score_boost': 30,
        'attack_stage': 'persistence',
        'mitre_attack': 'T1547.001',
        'confidence': 'high'
    },
    'masquerade_attack': {
        'name': 'Masquerading Attack',
        'description': 'Executable impersonating legitimate system file',
        'required': ['system_file_wrong_location'],
        'supporting': ['masquerading_filename', 'double_extension', 'hidden_executable'],
        'min_supporting': 0,
        'score_boost': 25,
        'attack_stage': 'defense_evasion',
        'mitre_attack': 'T1036',
        'confidence': 'high'
    },
    'evidence_tampering': {
        'name': 'Evidence Destruction Attempt',
        'description': 'Deliberate evidence manipulation detected',
        'required': ['timestomp_detected'],
        'supporting': ['deleted_during_investigation', 'recently_deleted',
                       'heavily_overwritten', 'wiping_tool_artifact'],
        'min_supporting': 0,
        'score_boost': 35,
        'attack_stage': 'defense_evasion',
        'mitre_attack': 'T1070.006',
        'confidence': 'critical'
    },
    'active_concealment': {
        'name': 'Active Concealment',
        'description': 'Files being hidden or deleted during investigation',
        'required': ['deleted_during_investigation'],
        'supporting': ['heavily_overwritten', 'multiple_overwriters',
                       'timestomp_detected'],
        'min_supporting': 0,
        'score_boost': 40,
        'attack_stage': 'defense_evasion',
        'mitre_attack': 'T1070',
        'confidence': 'critical'
    },
    'data_staging': {
        'name': 'Data Staging for Exfiltration',
        'description': 'Large archives being prepared for potential exfiltration',
        'required': ['large_archive_recent'],
        'supporting': ['encrypted_archive', 'archive_in_temp', 'high_entropy'],
        'min_supporting': 1,
        'score_boost': 20,
        'attack_stage': 'collection',
        'mitre_attack': 'T1074',
        'confidence': 'medium'
    },
    'encrypted_exfil': {
        'name': 'Encrypted Exfiltration Prep',
        'description': 'Encrypted archive suggesting data protection for exfiltration',
        'required': ['encrypted_archive'],
        'supporting': ['large_archive_recent', 'archive_in_temp',
                       'extremely_high_entropy'],
        'min_supporting': 1,
        'score_boost': 25,
        'attack_stage': 'exfiltration',
        'mitre_attack': 'T1560.001',
        'confidence': 'medium'
    }
}

RULE_CATEGORIES = {
    'executable_in_user_dir': 'execution',
    'executable_in_temp': 'execution',
    'executable_in_downloads': 'execution',
    'executable_in_appdata': 'execution',
    'system_file_wrong_location': 'execution',
    'hidden_executable': 'execution',
    'unsigned_executable': 'execution',

    'file_in_startup': 'persistence',

    'timestomp_detected': 'anti_forensic',
    'deleted_during_investigation': 'anti_forensic',
    'recently_deleted': 'anti_forensic',
    'heavily_overwritten': 'anti_forensic',
    'partially_overwritten': 'anti_forensic',
    'multiple_overwriters': 'anti_forensic',
    'wiping_tool_artifact': 'anti_forensic',
    'impossible_timestamp': 'anti_forensic',

    'large_archive_recent': 'exfiltration',
    'encrypted_archive': 'exfiltration',
    'archive_in_temp': 'exfiltration',

    'double_extension': 'other',
    'suspicious_extension': 'other',
    'masquerading_filename': 'other',
    'high_entropy': 'other',
    'extremely_high_entropy': 'other',
}


class HybridRiskScorer:
    """
    Hybrid intelligence risk scoring combining:
    - Rule-based detection (fast, deterministic)
    - Behavioral pattern recognition (attack signature detection)
    - AI contextual evaluation (complex reasoning)
    - Correlation analysis (relationship mapping)

    This scorer builds on top of the base RiskScorer, adding
    intelligence layers for more accurate threat assessment.
    """

    AI_EVALUATION_THRESHOLD = 50

    def __init__(self, case_context: CaseContext = None,
                 use_ai: bool = True, audit_logger: Optional[AuditLogger] = None,
                 case_id: str = "default"):
        """
        Initialize hybrid risk scorer.

        Args:
            case_context: Investigation context for adaptive scoring
            use_ai: Whether to use AI for contextual evaluation
            audit_logger: Optional audit logger
            case_id: Case identifier
        """
        self.case_context = case_context or CaseContext()
        self.use_ai = use_ai
        self.audit_logger = audit_logger
        self.case_id = case_id

        self.rule_scorer = RiskScorer(
            investigation_start_time=self.case_context.investigation_start,
            audit_logger=audit_logger,
            case_id=case_id
        )

        try:
            from managers.correlation_engine import get_correlation_engine
            self.correlation_engine = get_correlation_engine()
        except ImportError:
            self.correlation_engine = None

        self._ai_service = None

    @property
    def ai_service(self):
        """Lazy-load AI service."""
        if self._ai_service is None and self.use_ai:
            try:
                from managers.ai_service import get_ai_service
                self._ai_service = get_ai_service()
            except ImportError:
                self._ai_service = None
        return self._ai_service

    def score_artifact(self, artifact: Dict) -> HybridRiskScore:
        """
        Score artifact using hybrid intelligence approach.

        Flow:
        1. Check known-good/bad lists
        2. Run rule engine (fast, always)
        3. Apply case-type weight multipliers
        4. Detect behavioral patterns
        5. Add to correlation engine
        6. If score > threshold OR patterns detected:
           - Get related artifacts
           - Run AI contextual evaluation (optional)
        7. Return hybrid score with full reasoning
        """

        file_hash = artifact.get('md5') or artifact.get('sha256')
        if file_hash:
            if self.case_context.is_known_good(file_hash):
                return self._create_known_good_result(artifact)
            if self.case_context.is_known_bad(file_hash):
                return self._create_known_bad_result(artifact)

        rule_result = self.rule_scorer.score_file(artifact)

        adjusted_rule_score = self._apply_case_multipliers(
            rule_result.score, rule_result.reasons
        )

        matched_patterns = self._detect_behavioral_patterns(rule_result.reasons)
        pattern_boost = sum(p['score_boost'] for p in matched_patterns)

        correlation_boost = 0
        correlation_insights = {}

        if self.correlation_engine:
            artifact_id = self._get_artifact_id(artifact)

            self.correlation_engine.add_artifact(
                artifact_id, artifact,
                risk_score=adjusted_rule_score + pattern_boost,
                rules=rule_result.reasons
            )

            correlation_insights = self.correlation_engine.get_correlation_summary(artifact_id)

            if correlation_insights.get('total_related', 0) >= 3:
                correlation_boost += 10
            if correlation_insights.get('attack_chain_stage'):
                correlation_boost += 15
            if any(c.get('confidence') == 'high' for c in correlation_insights.get('clusters', [])):
                correlation_boost += 10

        intermediate_score = min(
            adjusted_rule_score + pattern_boost + correlation_boost,
            100
        )

        ai_assessment = None
        ai_adjustment = 0
        ai_used = False

        if self._needs_ai_evaluation(intermediate_score, matched_patterns):
            ai_assessment = self._run_ai_evaluation(
                artifact, intermediate_score, rule_result.reasons,
                matched_patterns, correlation_insights
            )
            if ai_assessment:
                ai_used = True
                ai_adjustment = ai_assessment.get('score_adjustment', 0)

        final_score = min(intermediate_score + ai_adjustment, 100)
        final_score = max(final_score, 0)

        severity = self._calculate_severity(final_score)
        confidence = self._calculate_confidence(
            rule_result, matched_patterns, correlation_insights, ai_assessment
        )

        recommendations = self._build_recommendations(
            rule_result.reasons, matched_patterns,
            correlation_insights, ai_assessment
        )

        attack_stage = None
        if correlation_insights.get('attack_chain_stage'):
            attack_stage = correlation_insights['attack_chain_stage'].get('stage')
        elif matched_patterns:
            attack_stage = matched_patterns[0].get('attack_stage')

        return HybridRiskScore(
            rule_score=rule_result.score,
            pattern_boost=pattern_boost,
            correlation_boost=correlation_boost,
            ai_adjustment=ai_adjustment,
            final_score=final_score,
            severity=severity,
            confidence=confidence,
            triggered_rules=rule_result.reasons,
            rule_details=rule_result.details,
            matched_patterns=matched_patterns,
            correlation_insights=correlation_insights,
            ai_used=ai_used,
            ai_reasoning=ai_assessment.get('reasoning') if ai_assessment else None,
            false_positive_likelihood=ai_assessment.get('false_positive_likelihood', 0.5) if ai_assessment else 0.5,
            attack_chain_stage=attack_stage,
            recommendations=recommendations,
            overwrite_analysis=rule_result.overwrite_analysis
        )

    def _apply_case_multipliers(self, base_score: int, rules: List[str]) -> int:
        """Apply case-type weight multipliers to rule scores."""
        if not rules:
            return base_score

        total_adjustment = 0
        for rule in rules:
            category = RULE_CATEGORIES.get(rule, 'other')
            multiplier = self.case_context.get_multiplier(category)
            base_weight = RiskScorer.RULE_WEIGHTS.get(rule, 0)

            if multiplier != 1.0:
                adjustment = int(base_weight * (multiplier - 1.0))
                total_adjustment += adjustment

        return min(base_score + total_adjustment, 100)

    def _detect_behavioral_patterns(self, triggered_rules: List[str]) -> List[Dict]:
        """Detect behavioral patterns from triggered rules."""
        matched = []

        for pattern_id, pattern in BEHAVIORAL_PATTERNS.items():
            required_match = all(
                rule in triggered_rules
                for rule in pattern['required']
            )

            if not required_match:
                continue

            supporting_count = sum(
                1 for rule in pattern['supporting']
                if rule in triggered_rules
            )

            if supporting_count >= pattern['min_supporting']:
                matched.append({
                    'id': pattern_id,
                    'name': pattern['name'],
                    'description': pattern['description'],
                    'score_boost': pattern['score_boost'],
                    'attack_stage': pattern['attack_stage'],
                    'mitre_attack': pattern['mitre_attack'],
                    'confidence': pattern['confidence'],
                    'matched_required': pattern['required'],
                    'matched_supporting': [
                        r for r in pattern['supporting']
                        if r in triggered_rules
                    ]
                })

        confidence_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        matched.sort(key=lambda x: confidence_order.get(x['confidence'], 4))

        return matched

    def _needs_ai_evaluation(self, score: int, patterns: List[Dict]) -> bool:
        """Determine if artifact needs AI contextual evaluation."""
        if not self.use_ai or not self.ai_service:
            return False

        if patterns:
            return True

        if score >= self.AI_EVALUATION_THRESHOLD:
            return True

        return False

    def _run_ai_evaluation(self, artifact: Dict, current_score: int,
                           rules: List[str], patterns: List[Dict],
                           correlation: Dict) -> Optional[Dict]:
        """Run AI contextual evaluation."""
        if not self.ai_service:
            return None

        try:
            related = correlation.get('related_artifacts', {})

            result = self.ai_service.evaluate_risk_contextually(
                artifact=artifact,
                rule_score=current_score,
                triggered_rules=rules,
                matched_patterns=patterns,
                related_artifacts=related,
                case_context={
                    'type': self.case_context.case_type,
                    'key_timestamps': self.case_context.key_timestamps,
                    'focus_paths': self.case_context.focus_paths
                }
            )

            return result

        except Exception as e:
            print(f"Warning: AI evaluation failed: {e}")
            return None

    def _calculate_severity(self, score: int) -> str:
        """Calculate severity from final score."""
        if score >= 90:
            return 'critical'
        elif score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'info'

    def _calculate_confidence(self, rule_result: RiskScore,
                               patterns: List[Dict],
                               correlation: Dict,
                               ai_assessment: Optional[Dict]) -> float:
        """Calculate overall confidence in the assessment."""
        confidence = 0.5

        if len(rule_result.reasons) >= 3:
            confidence += 0.15
        elif len(rule_result.reasons) >= 2:
            confidence += 0.1

        if patterns:
            pattern_conf = max(
                0.1 if p['confidence'] == 'low' else
                0.15 if p['confidence'] == 'medium' else
                0.2 if p['confidence'] == 'high' else
                0.25
                for p in patterns
            )
            confidence += pattern_conf

        if correlation.get('total_related', 0) >= 3:
            confidence += 0.1
        if correlation.get('attack_chain_stage'):
            confidence += 0.1

        if ai_assessment:
            ai_conf = ai_assessment.get('confidence', 'medium')
            if ai_conf == 'high':
                confidence += 0.1
            elif ai_conf == 'low':
                confidence -= 0.1

        return min(max(confidence, 0.1), 1.0)

    def _build_recommendations(self, rules: List[str], patterns: List[Dict],
                                correlation: Dict,
                                ai_assessment: Optional[Dict]) -> List[str]:
        """Build investigation recommendations."""
        recommendations = []

        if ai_assessment and ai_assessment.get('recommendations'):
            recommendations.extend(ai_assessment['recommendations'][:3])

        for pattern in patterns:
            if pattern['mitre_attack']:
                recommendations.append(
                    f"Research MITRE ATT&CK {pattern['mitre_attack']} for IOC hunting"
                )

        if correlation.get('total_related', 0) >= 2:
            recommendations.append(
                f"Timeline {correlation['total_related']} related artifacts together"
            )

        if correlation.get('attack_chain_stage'):
            stage = correlation['attack_chain_stage']['stage']
            recommendations.append(
                f"Investigate artifacts in {stage} stage of attack chain"
            )

        rule_recs = self.rule_scorer._get_recommendations(rules, {})
        for rec in rule_recs:
            if rec not in recommendations:
                recommendations.append(rec)

        seen = set()
        unique_recs = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recs.append(rec)

        return unique_recs[:8]

    def _get_artifact_id(self, artifact: Dict) -> str:
        """Extract artifact ID from artifact dict."""
        return str(artifact.get('inode', artifact.get('hash', artifact.get('name', ''))))

    def _create_known_good_result(self, artifact: Dict) -> HybridRiskScore:
        """Create result for known-good file."""
        return HybridRiskScore(
            rule_score=0,
            pattern_boost=0,
            correlation_boost=0,
            ai_adjustment=0,
            final_score=0,
            severity='info',
            confidence=0.95,
            triggered_rules=[],
            rule_details={},
            matched_patterns=[],
            correlation_insights={},
            ai_used=False,
            ai_reasoning="File hash matches known-good whitelist",
            false_positive_likelihood=0.95,
            attack_chain_stage=None,
            recommendations=['Verify whitelist is current']
        )

    def _create_known_bad_result(self, artifact: Dict) -> HybridRiskScore:
        """Create result for known-bad file."""
        return HybridRiskScore(
            rule_score=100,
            pattern_boost=0,
            correlation_boost=0,
            ai_adjustment=0,
            final_score=100,
            severity='critical',
            confidence=0.95,
            triggered_rules=['known_bad_hash'],
            rule_details={'known_bad_hash': 'File hash matches known malware database'},
            matched_patterns=[],
            correlation_insights={},
            ai_used=False,
            ai_reasoning="File hash matches known-bad blacklist",
            false_positive_likelihood=0.05,
            attack_chain_stage='execution',
            recommendations=[
                'Quarantine file immediately',
                'Submit to malware sandbox for analysis',
                'Search for related IOCs across system'
            ]
        )


_hybrid_risk_scorer = None


def get_hybrid_risk_scorer(case_context: CaseContext = None,
                           use_ai: bool = True) -> HybridRiskScorer:
    """Get singleton hybrid risk scorer instance."""
    global _hybrid_risk_scorer
    if _hybrid_risk_scorer is None:
        _hybrid_risk_scorer = HybridRiskScorer(
            case_context=case_context,
            use_ai=use_ai
        )
    return _hybrid_risk_scorer
