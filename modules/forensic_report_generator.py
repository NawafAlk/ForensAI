"""
ForensAI - Forensic Evidence Report Generator
==============================================
Comprehensive, court-admissible forensic evidence report generation
with proper chain of custody, hash verification, and artifact documentation.

Author: ForensAI Team
License: See LICENSE file
"""

import os
import sys
import json
import hashlib
import logging
import platform
import subprocess
import mimetypes
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from collections import defaultdict

try:
    import pytsk3
    HAS_PYTSK3 = True
except ImportError:
    HAS_PYTSK3 = False

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ForensicReportError(Exception):
    """Custom exception for forensic report generation errors."""
    pass


class ChainOfCustodyEntry:
    """Represents a single chain of custody entry."""

    def __init__(self, action: str, actor: str, source: str = None,
                 target: str = None, tools: str = None, hashes: Dict[str, str] = None, notes: str = None):
        """
        Initialize a chain of custody entry.

        Args:
            action: Description of the action performed
            actor: Person/system performing the action
            source: Source file/device path
            target: Target file/device path
            tools: Tools and versions used
            hashes: Dictionary of hash values (md5, sha256, etc.)
            notes: Additional notes about this action (FIX #5)
        """
        self.timestamp = datetime.now(timezone.utc)
        self.action = action
        self.actor = actor
        self.source = source
        self.target = target
        self.tools = tools
        self.hashes = hashes or {}
        self.notes = notes or ''  # FIX #5: Add notes field
        self.hostname = platform.node()

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        return {
            'timestamp_utc': self.timestamp.isoformat(),
            'actor': self.actor,
            'hostname': self.hostname,
            'action': self.action,
            'source': self.source,
            'target': self.target,
            'tools': self.tools,
            'hashes': self.hashes,
            'notes': self.notes  # FIX #5: Include notes in dict
        }


class HashVerifier:
    """Hash computation and verification for forensic evidence."""

    BUFFER_SIZE = 8192 * 1024  # 8 MB buffer for efficiency

    @staticmethod
    def compute_hashes(file_path: str, algorithms: List[str] = None) -> Dict[str, str]:
        """
        Compute multiple hash algorithms for a file.

        Args:
            file_path: Path to file
            algorithms: List of hash algorithms (default: ['md5', 'sha256'])

        Returns:
            Dictionary mapping algorithm name to hex digest
        """
        if algorithms is None:
            algorithms = ['md5', 'sha256']

        if not os.path.exists(file_path):
            raise ForensicReportError(f"File not found: {file_path}")

        hashers = {}
        for algo in algorithms:
            try:
                hashers[algo] = hashlib.new(algo)
            except ValueError:
                logger.warning(f"Unsupported hash algorithm: {algo}")

        try:
            file_size = os.path.getsize(file_path)
            logger.info(f"Computing hashes for {file_path} ({file_size:,} bytes)")

            with open(file_path, 'rb') as f:
                bytes_read = 0
                while True:
                    data = f.read(HashVerifier.BUFFER_SIZE)
                    if not data:
                        break

                    for hasher in hashers.values():
                        hasher.update(data)

                    bytes_read += len(data)
                    if file_size > 0 and bytes_read % (100 * 1024 * 1024) == 0:
                        progress = (bytes_read / file_size) * 100
                        logger.info(f"Hash progress: {progress:.1f}%")

            results = {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
            logger.info(f"Hash computation complete: {results}")
            return results

        except Exception as e:
            raise ForensicReportError(f"Hash computation failed: {e}")

    @staticmethod
    def verify_hashes(file_path: str, expected_hashes: Dict[str, str]) -> Tuple[bool, Dict[str, bool]]:
        """
        Verify file hashes against expected values.

        Args:
            file_path: Path to file
            expected_hashes: Dictionary of expected hash values

        Returns:
            Tuple of (all_match: bool, individual_results: dict)
        """
        computed = HashVerifier.compute_hashes(file_path, list(expected_hashes.keys()))
        results = {}

        for algo, expected in expected_hashes.items():
            computed_hash = computed.get(algo, '')
            results[algo] = (computed_hash.lower() == expected.lower())

        all_match = all(results.values())
        return all_match, results


class ArtifactInfo:
    """Information about a discovered artifact."""

    def __init__(self, path: str, name: str, size: int = 0,
                 artifact_type: str = 'unknown', inode: str = None):
        """Initialize artifact information."""
        self.path = path
        self.name = name
        self.size = size
        self.artifact_type = artifact_type
        self.inode = inode
        self.sha256 = None
        self.md5 = None
        self.created_utc = None
        self.modified_utc = None
        self.accessed_utc = None
        self.extracted_path = None
        self.notable_reasons = []
        self.mime_type = None
        self.priority = 0  # Higher = more important
        self.origin = 'original'  # FIX #7: 'original', 'carved', 'partial'
        self.confidence = 'high'  # FIX #7: 'high', 'medium', 'low'
        self.thumbnail_path = None  # FIX #8: Path to thumbnail image

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'path': self.path,
            'name': self.name,
            'size_bytes': self.size,
            'type': self.artifact_type,
            'mime_type': self.mime_type,
            'inode': self.inode,
            'sha256': self.sha256,
            'md5': self.md5,
            'created_utc': self.created_utc.isoformat() if self.created_utc else None,
            'modified_utc': self.modified_utc.isoformat() if self.modified_utc else None,
            'accessed_utc': self.accessed_utc.isoformat() if self.accessed_utc else None,
            'extracted_path': self.extracted_path,
            'notable_reasons': self.notable_reasons,
            'priority': self.priority,
            'origin': self.origin,  # FIX #7
            'confidence': self.confidence,  # FIX #7
            'thumbnail_path': self.thumbnail_path  # FIX #8
        }


class ProcessingStep:
    """Represents a processing step in the forensic workflow."""

    def __init__(self, step_name: str, command: str = None):
        """Initialize processing step."""
        self.step_name = step_name
        self.command = command
        self.start_time = datetime.now(timezone.utc)
        self.end_time = None
        self.stdout_snippet = ""
        self.stderr_snippet = ""
        self.success = True
        self.error_message = None

    def complete(self, stdout: str = "", stderr: str = "", success: bool = True, error: str = None):
        """Mark step as complete."""
        self.end_time = datetime.now(timezone.utc)
        self.stdout_snippet = stdout[:2000] if stdout else ""  # Limit snippet size
        self.stderr_snippet = stderr[:2000] if stderr else ""
        self.success = success
        self.error_message = error

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'step': self.step_name,
            'cmd': self.command,
            'start': self.start_time.isoformat(),
            'end': self.end_time.isoformat() if self.end_time else None,
            'success': self.success,
            'stdout_snippet': self.stdout_snippet,
            'stderr_snippet': self.stderr_snippet,
            'error': self.error_message
        }


class ForensicReportGenerator:
    """Main forensic evidence report generator."""

    def __init__(self, case_id: str, operator: str, master_image: str,
                 output_dir: str, derived_iso: str = None,
                 parsed_artifacts_dir: str = None, bulk_extractor_dir: str = None,
                 checkpoints_dir: str = None, logfile: str = None):
        """
        Initialize forensic report generator.

        Args:
            case_id: Unique case identifier
            operator: Name of operator generating report
            master_image: Path to master evidence image (.dd)
            output_dir: Directory where reports will be saved
            derived_iso: Path to derived ISO (optional)
            parsed_artifacts_dir: Directory containing parsed artifacts
            bulk_extractor_dir: Directory containing bulk_extractor output
            checkpoints_dir: Directory containing checkpoints
            logfile: Path to processing log file
        """
        self.case_id = case_id
        self.operator = operator
        self.master_image = os.path.abspath(master_image) if master_image else None
        self.output_dir = os.path.abspath(output_dir)
        self.derived_iso = os.path.abspath(derived_iso) if derived_iso else None
        self.parsed_artifacts_dir = os.path.abspath(parsed_artifacts_dir) if parsed_artifacts_dir else None
        self.bulk_extractor_dir = os.path.abspath(bulk_extractor_dir) if bulk_extractor_dir else None
        self.checkpoints_dir = os.path.abspath(checkpoints_dir) if checkpoints_dir else None
        self.logfile = os.path.abspath(logfile) if logfile else None

        # Report generation timestamp
        self.generated_at = datetime.now(timezone.utc)
        self.timestamp_str = self.generated_at.strftime("%Y%m%d_%H%M%S")

        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

        # Initialize data structures
        self.chain_of_custody: List[ChainOfCustodyEntry] = []
        self.processing_steps: List[ProcessingStep] = []
        self.artifacts: List[ArtifactInfo] = []
        self.master_hashes: Dict[str, str] = {}
        self.derived_hashes: Dict[str, str] = {}
        self.tool_versions: Dict[str, str] = {}
        self.bulk_extractor_summary: Dict[str, int] = {}
        self.warnings: List[str] = []
        self.notes: str = ""
        self.risk_scan_results: List[Dict] = []

        # Statistics
        self.stats = {
            'total_files': 0,
            'total_dirs': 0,
            'total_size': 0,
            'carved_files': 0,
            'notable_artifacts': 0
        }

        logger.info(f"Initialized report generator for case {case_id}")

    def set_risk_scan_results(self, results: List[Dict]) -> None:
        """Store risk scan results for inclusion in the report."""
        self.risk_scan_results = results or []

    def _compute_risk_summary(self) -> Dict[str, Any]:
        """Compute severity counts, MITRE stage counts, top indicators, and recommendations from risk scan results."""
        mitre_stages = [
            "Initial Access", "Execution", "Persistence", "Priv Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Exfiltration", "Impact",
        ]

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        stage_counts: Dict[str, int] = {s: 0 for s in mitre_stages}

        for item in self.risk_scan_results:
            severity = item.get("severity", "Info")
            if severity in severity_counts:
                severity_counts[severity] += 1
            for stage in item.get("mitre_stages", []):
                if stage in stage_counts:
                    stage_counts[stage] += 1

        # Top 10 indicators by score
        sorted_results = sorted(self.risk_scan_results, key=lambda r: r.get("score", 0), reverse=True)
        top_indicators = sorted_results[:10]

        # Context-aware recommendations
        recommendations = self._generate_risk_recommendations(severity_counts, stage_counts)

        return {
            'total': len(self.risk_scan_results),
            'severity_counts': severity_counts,
            'stage_counts': stage_counts,
            'mitre_stages': mitre_stages,
            'top_indicators': top_indicators,
            'recommendations': recommendations,
        }

    @staticmethod
    def _generate_risk_recommendations(
        severity_counts: Dict[str, int],
        stage_counts: Dict[str, int],
    ) -> List[str]:
        """Produce context-aware investigative recommendations based on risk scan data."""
        actions: List[str] = []

        if severity_counts.get("Critical", 0) > 0:
            actions.append("[URGENT] Isolate and preserve evidence for critical-severity artifacts immediately.")
        if severity_counts.get("High", 0) > 0:
            actions.append("Review high-severity artifacts for signs of active compromise.")
        if stage_counts.get("Persistence", 0) > 0:
            actions.append("Investigate persistence mechanisms - check startup entries, scheduled tasks, and services.")
        if stage_counts.get("Credential Access", 0) > 0:
            actions.append("Check for credential theft indicators - review SAM/NTDS dumps and browser credential stores.")
        if stage_counts.get("Exfiltration", 0) > 0:
            actions.append("Examine network artifacts for data exfiltration - check DNS logs, HTTP uploads, and cloud sync activity.")
        if stage_counts.get("Lateral Movement", 0) > 0:
            actions.append("Trace lateral movement paths - review RDP, PsExec, WMI, and SMB connections.")
        if stage_counts.get("Defense Evasion", 0) > 0:
            actions.append("Inspect defense evasion techniques - look for log tampering, timestomping, and AV disabling.")
        if stage_counts.get("Execution", 0) > 0:
            actions.append("Analyze execution artifacts - review prefetch, shimcache, amcache, and PowerShell logs.")
        if stage_counts.get("Impact", 0) > 0:
            actions.append("Assess impact scope - check for ransomware indicators, data destruction, or service disruption.")

        if not actions:
            actions.append("No high-priority recommendations at this time. Continue routine analysis.")

        actions.append("Generate a forensic report to document findings and maintain chain-of-custody.")
        return actions

    def add_chain_of_custody_entry(self, action: str, source: str = None,
                                   target: str = None, tools: str = None,
                                   hashes: Dict[str, str] = None, notes: str = None):
        """Add an entry to chain of custody (FIX #5: Enhanced with notes field)."""
        entry = ChainOfCustodyEntry(
            action=action,
            actor=self.operator,
            source=source,
            target=target,
            tools=tools,
            hashes=hashes,
            notes=notes  # FIX #5: Add notes parameter
        )
        self.chain_of_custody.append(entry)
        logger.info(f"Chain of custody: {action}")

    def verify_master_image(self) -> bool:
        """
        Verify master image exists and compute hashes.

        Returns:
            True if verification successful
        """
        logger.info("Verifying master image...")
        step = ProcessingStep("Verify Master Image", f"hash verification: {self.master_image}")

        try:
            if not self.master_image or not os.path.exists(self.master_image):
                error_msg = f"Master image not found: {self.master_image}"
                step.complete(stderr=error_msg, success=False, error=error_msg)
                self.processing_steps.append(step)
                self.warnings.append(error_msg)
                return False

            # Compute hashes
            self.master_hashes = HashVerifier.compute_hashes(self.master_image)

            # Add to chain of custody
            self.add_chain_of_custody_entry(
                action="Master image hash verification",
                source=self.master_image,
                tools="Python hashlib (md5, sha256)",
                hashes=self.master_hashes
            )

            step.complete(stdout=f"Hashes computed: {self.master_hashes}", success=True)
            self.processing_steps.append(step)
            return True

        except Exception as e:
            error_msg = f"Master image verification failed: {e}"
            logger.error(error_msg)
            step.complete(stderr=str(e), success=False, error=error_msg)
            self.processing_steps.append(step)
            self.warnings.append(error_msg)
            return False

    def verify_derived_iso(self) -> bool:
        """
        Verify derived ISO if present and compute hashes.

        Returns:
            True if verification successful or no derived ISO present
        """
        if not self.derived_iso:
            logger.info("No derived ISO specified, skipping verification")
            return True

        logger.info("Verifying derived ISO...")
        step = ProcessingStep("Verify Derived ISO", f"hash verification: {self.derived_iso}")

        try:
            if not os.path.exists(self.derived_iso):
                error_msg = f"Derived ISO not found: {self.derived_iso}"
                step.complete(stderr=error_msg, success=False, error=error_msg)
                self.processing_steps.append(step)
                self.warnings.append(error_msg)
                return False

            # Compute hashes
            self.derived_hashes = HashVerifier.compute_hashes(self.derived_iso)

            # Add to chain of custody
            self.add_chain_of_custody_entry(
                action="Derived ISO hash verification",
                source=self.derived_iso,
                tools="Python hashlib (md5, sha256)",
                hashes=self.derived_hashes
            )

            step.complete(stdout=f"Hashes computed: {self.derived_hashes}", success=True)
            self.processing_steps.append(step)
            return True

        except Exception as e:
            error_msg = f"Derived ISO verification failed: {e}"
            logger.error(error_msg)
            step.complete(stderr=str(e), success=False, error=error_msg)
            self.processing_steps.append(step)
            self.warnings.append(error_msg)
            return False

    def collect_tool_versions(self):
        """Collect versions of tools used in the forensic process."""
        logger.info("Collecting tool versions...")

        # Python version
        self.tool_versions['python'] = sys.version.split()[0]

        # Platform information
        self.tool_versions['platform'] = platform.platform()
        self.tool_versions['hostname'] = platform.node()

        # ForensAI version (from git if available)
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=os.path.dirname(os.path.dirname(__file__))
            )
            if result.returncode == 0:
                self.tool_versions['forensai_commit'] = result.stdout.strip()[:8]
        except Exception:
            self.tool_versions['forensai_commit'] = 'unknown'

        # pytsk3 version
        if HAS_PYTSK3:
            try:
                self.tool_versions['pytsk3'] = pytsk3.TSK_VERSION_STR
            except AttributeError:
                self.tool_versions['pytsk3'] = 'installed (version unknown)'

        # Check for external tools
        external_tools = {
            'bulk_extractor': ['bulk_extractor', '-V'],
            'dd': ['dd', '--version'],
            'genisoimage': ['genisoimage', '--version']
        }

        for tool_name, cmd in external_tools.items():
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                # Extract version from output (first line usually)
                version_line = result.stdout.split('\n')[0] if result.stdout else result.stderr.split('\n')[0]
                self.tool_versions[tool_name] = version_line[:100]  # Limit length
            except Exception:
                self.tool_versions[tool_name] = 'not found'

        logger.info(f"Collected {len(self.tool_versions)} tool versions")

    def scan_artifacts(self):
        """Scan parsed artifacts directory and collect artifact information."""
        if not self.parsed_artifacts_dir or not os.path.exists(self.parsed_artifacts_dir):
            logger.warning("Parsed artifacts directory not found, skipping scan")
            self.warnings.append("No parsed artifacts directory provided")
            return

        logger.info(f"Scanning artifacts in {self.parsed_artifacts_dir}")
        step = ProcessingStep("Scan Artifacts", f"Scanning directory: {self.parsed_artifacts_dir}")

        try:
            for root, dirs, files in os.walk(self.parsed_artifacts_dir):
                self.stats['total_dirs'] += len(dirs)

                for filename in files:
                    file_path = os.path.join(root, filename)

                    try:
                        # Get file stats
                        stat_info = os.stat(file_path)
                        file_size = stat_info.st_size
                        self.stats['total_size'] += file_size
                        self.stats['total_files'] += 1

                        # Create artifact info
                        rel_path = os.path.relpath(file_path, self.parsed_artifacts_dir)
                        artifact = ArtifactInfo(
                            path=rel_path,
                            name=filename,
                            size=file_size,
                            artifact_type=self._categorize_file(filename)
                        )

                        # Set timestamps
                        artifact.modified_utc = datetime.fromtimestamp(stat_info.st_mtime, timezone.utc)
                        artifact.created_utc = datetime.fromtimestamp(stat_info.st_ctime, timezone.utc)
                        artifact.extracted_path = file_path

                        # Guess MIME type
                        artifact.mime_type, _ = mimetypes.guess_type(filename)

                        # Check if notable (basic heuristics)
                        self._check_notable(artifact)

                        self.artifacts.append(artifact)

                    except Exception as e:
                        logger.warning(f"Error processing {file_path}: {e}")

            # Sort artifacts by priority (highest first)
            self.artifacts.sort(key=lambda x: x.priority, reverse=True)

            self.stats['notable_artifacts'] = sum(1 for a in self.artifacts if a.notable_reasons)

            step.complete(
                stdout=f"Scanned {self.stats['total_files']} files, "
                       f"{self.stats['notable_artifacts']} notable",
                success=True
            )
            self.processing_steps.append(step)
            logger.info(f"Artifact scan complete: {self.stats['total_files']} files")

        except Exception as e:
            error_msg = f"Artifact scan failed: {e}"
            logger.error(error_msg)
            step.complete(stderr=str(e), success=False, error=error_msg)
            self.processing_steps.append(step)
            self.warnings.append(error_msg)

    def _categorize_file(self, filename: str) -> str:
        """Categorize file based on extension."""
        ext = os.path.splitext(filename)[1].lower()

        categories = {
            'document': ['.doc', '.docx', '.pdf', '.txt', '.rtf', '.odt', '.xls', '.xlsx', '.ppt', '.pptx'],
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff', '.ico'],
            'video': ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv'],
            'audio': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a'],
            'archive': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'],
            'executable': ['.exe', '.dll', '.so', '.dylib', '.msi', '.bat', '.sh', '.ps1'],
            'database': ['.db', '.sqlite', '.mdb', '.accdb'],
            'email': ['.eml', '.msg', '.pst', '.ost'],
            'web': ['.html', '.htm', '.css', '.js', '.json', '.xml'],
            'code': ['.py', '.java', '.c', '.cpp', '.h', '.cs', '.php', '.rb', '.go']
        }

        for category, extensions in categories.items():
            if ext in extensions:
                return category

        return 'unknown'

    def _check_notable(self, artifact: ArtifactInfo):
        """Check if artifact is notable and assign priority."""
        filename_lower = artifact.name.lower()

        # Suspicious keywords
        suspicious_keywords = [
            'password', 'passwd', 'credential', 'secret', 'key', 'private',
            'confidential', 'sensitive', 'ssn', 'credit', 'bank', 'malware',
            'virus', 'trojan', 'exploit', 'backdoor', 'rootkit'
        ]

        for keyword in suspicious_keywords:
            if keyword in filename_lower:
                artifact.notable_reasons.append(f'filename_keyword:{keyword}')
                artifact.priority += 50

        # Executable files
        if artifact.artifact_type == 'executable':
            artifact.notable_reasons.append('executable')
            artifact.priority += 30

        # Recently modified (within 30 days of scan)
        if artifact.modified_utc:
            days_old = (datetime.now(timezone.utc) - artifact.modified_utc).days
            if days_old <= 30:
                artifact.notable_reasons.append(f'recent_modification:{days_old}d')
                artifact.priority += 20

        # Large files (> 100 MB)
        if artifact.size > 100 * 1024 * 1024:
            artifact.notable_reasons.append('large_file')
            artifact.priority += 10

        # Specific file types of interest
        interesting_types = ['database', 'email', 'archive']
        if artifact.artifact_type in interesting_types:
            artifact.notable_reasons.append(f'type:{artifact.artifact_type}')
            artifact.priority += 15

    def parse_bulk_extractor_results(self):
        """Parse bulk_extractor output and summarize findings."""
        if not self.bulk_extractor_dir or not os.path.exists(self.bulk_extractor_dir):
            logger.info("No bulk_extractor directory, skipping")
            return

        logger.info(f"Parsing bulk_extractor results from {self.bulk_extractor_dir}")

        # Common bulk_extractor output files
        be_files = {
            'email': 'email.txt',
            'url': 'url.txt',
            'telephone': 'telephone.txt',
            'ccn': 'ccn.txt',  # Credit card numbers
            'exif': 'exif.txt',
            'zip': 'zip.txt'
        }

        for key, filename in be_files.items():
            file_path = os.path.join(self.bulk_extractor_dir, filename)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        # Count non-comment lines
                        count = sum(1 for line in f if line.strip() and not line.startswith('#'))
                    self.bulk_extractor_summary[key] = count
                    logger.info(f"bulk_extractor {key}: {count} items")
                except Exception as e:
                    logger.warning(f"Error parsing {filename}: {e}")
                    self.bulk_extractor_summary[key] = 0
            else:
                self.bulk_extractor_summary[key] = 0

    def generate_json_manifest(self) -> str:
        """
        Generate JSON manifest file.

        Returns:
            Path to generated JSON manifest file
        """
        logger.info("Generating JSON manifest...")

        manifest = {
            'case_id': self.case_id,
            'generated_at_utc': self.generated_at.isoformat(),
            'operator': self.operator,
            'hostname': platform.node(),
            'master_image': {
                'path': self.master_image,
                'size_bytes': os.path.getsize(self.master_image) if self.master_image and os.path.exists(self.master_image) else 0,
                'sha256': self.master_hashes.get('sha256'),
                'md5': self.master_hashes.get('md5')
            },
            'derived_iso': {
                'path': self.derived_iso,
                'size_bytes': os.path.getsize(self.derived_iso) if self.derived_iso and os.path.exists(self.derived_iso) else 0,
                'sha256': self.derived_hashes.get('sha256'),
                'md5': self.derived_hashes.get('md5')
            } if self.derived_iso else None,
            'artifacts_count': {
                'total': self.stats['total_files'],
                'files': self.stats['total_files'],
                'directories': self.stats['total_dirs'],
                'carved': self.stats['carved_files'],
                'notable': self.stats['notable_artifacts']
            },
            'artifacts_index': [artifact.to_dict() for artifact in self.artifacts],
            'bulk_extractor_summary': self.bulk_extractor_summary,
            'processing_steps': [step.to_dict() for step in self.processing_steps],
            'chain_of_custody': [entry.to_dict() for entry in self.chain_of_custody],
            'tool_versions': self.tool_versions,
            'files_produced': {},  # Will be filled after report generation
            'warnings': self.warnings,
            'notes': self.notes
        }

        # Save JSON manifest
        manifest_path = os.path.join(
            self.output_dir,
            f"{self.case_id}_evidence_manifest_{self.timestamp_str}.json"
        )

        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)

        logger.info(f"JSON manifest saved to {manifest_path}")
        return manifest_path

    def generate_csv_artifacts(self) -> str:
        """
        Generate CSV file with all artifacts (FIX #6).

        Returns:
            Path to generated CSV file
        """
        logger.info("Generating CSV artifacts file...")

        csv_path = os.path.join(
            self.output_dir,
            f"{self.case_id}_artifacts_{self.timestamp_str}.csv"
        )

        # CSV headers
        headers = [
            'Name', 'Size (bytes)', 'Type', 'Origin', 'Confidence', 'Priority',
            'Inode', 'SHA256', 'MD5', 'Created (UTC)', 'Modified (UTC)',
            'Accessed (UTC)', 'Notable Reasons', 'Extracted Path'
        ]

        with open(csv_path, 'w', encoding='utf-8', newline='') as f:
            import csv
            writer = csv.writer(f)
            writer.writerow(headers)

            for artifact in self.artifacts:
                row = [
                    artifact.name,
                    artifact.size,
                    artifact.artifact_type if artifact.artifact_type else 'unknown',
                    artifact.origin,
                    artifact.confidence,
                    artifact.priority,
                    artifact.inode if artifact.inode else '',
                    artifact.sha256 if artifact.sha256 else '',
                    artifact.md5 if artifact.md5 else '',
                    artifact.created_utc.isoformat() if artifact.created_utc else '',
                    artifact.modified_utc.isoformat() if artifact.modified_utc else '',
                    artifact.accessed_utc.isoformat() if artifact.accessed_utc else '',
                    ', '.join(artifact.notable_reasons) if artifact.notable_reasons else '',
                    artifact.extracted_path if artifact.extracted_path else ''
                ]
                writer.writerow(row)

        logger.info(f"CSV artifacts file saved to {csv_path}")
        return csv_path

    def generate_html_report(self) -> str:
        """
        Generate HTML evidence report.

        Returns:
            Path to generated HTML report file
        """
        logger.info("Generating HTML report...")

        # Build report data
        report_data = self._build_report_data()

        # Generate HTML using built-in template
        html_content = self._render_html_template(report_data)

        # Save HTML report
        html_path = os.path.join(
            self.output_dir,
            f"{self.case_id}_evidence_report_{self.timestamp_str}.html"
        )

        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"HTML report saved to {html_path}")
        return html_path

    def _build_report_data(self) -> Dict[str, Any]:
        """Build comprehensive report data dictionary."""
        # Get master image info
        master_info = {}
        if self.master_image and os.path.exists(self.master_image):
            stat = os.stat(self.master_image)
            master_info = {
                'path': self.master_image,
                'size': stat.st_size,
                'size_mb': stat.st_size / (1024 * 1024),
                'modified': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
            }

        # Get derived ISO info
        derived_info = {}
        if self.derived_iso and os.path.exists(self.derived_iso):
            stat = os.stat(self.derived_iso)
            derived_info = {
                'path': self.derived_iso,
                'size': stat.st_size,
                'size_mb': stat.st_size / (1024 * 1024),
                'modified': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
            }

        # Get top notable artifacts (limit to 20)
        notable_artifacts = [a for a in self.artifacts if a.notable_reasons][:20]

        # File type distribution (FIX #1: Handle empty types properly)
        type_distribution = defaultdict(int)
        for artifact in self.artifacts:
            # Get artifact type, default to 'unknown' if empty
            artifact_type = artifact.artifact_type if artifact.artifact_type else 'unknown'
            # Normalize the type name
            if artifact_type.strip() == '':
                artifact_type = 'unknown'
            type_distribution[artifact_type] += 1

        # FIX #9: Identify missing tools
        missing_tools = []
        for tool, version in self.tool_versions.items():
            if 'not found' in version.lower() or 'unknown' in version.lower():
                missing_tools.append(tool)

        return {
            'case_id': self.case_id,
            'operator': self.operator,
            'hostname': platform.node(),
            'generated_at': self.generated_at.isoformat(),
            'generated_at_readable': self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'master_image': master_info,
            'master_hashes': self.master_hashes,
            'derived_iso': derived_info,
            'derived_hashes': self.derived_hashes,
            'stats': self.stats,
            'chain_of_custody': [e.to_dict() for e in self.chain_of_custody],
            'processing_steps': [s.to_dict() for s in self.processing_steps],
            'tool_versions': self.tool_versions,
            'notable_artifacts': [a.to_dict() for a in notable_artifacts],
            'type_distribution': dict(type_distribution),
            'bulk_extractor': self.bulk_extractor_summary,
            'warnings': self.warnings,
            'artifacts_sample': [a.to_dict() for a in self.artifacts[:100]],  # First 100 for report
            'missing_tools': missing_tools,  # FIX #9
            'timestamp_str': self.timestamp_str,  # For download links
            'risk_summary': self._compute_risk_summary() if self.risk_scan_results else None
        }

    def _format_notable_reason(self, reason: str, artifact: Dict[str, Any]) -> str:
        """Format notable reason into human-readable text (FIX #3)."""
        # Handle recent_modification:Xd
        if reason.startswith('recent_modification:'):
            days = reason.split(':')[1].replace('d', '')
            modified_time = artifact.get('modified_utc', 'unknown')
            if days == '0':
                return f"Modified within last 24 hours (mtime: {modified_time})"
            else:
                return f"Modified {days} days ago (mtime: {modified_time})"

        # Handle filename_keyword:keyword
        elif reason.startswith('filename_keyword:'):
            keyword = reason.split(':')[1]
            return f"Filename contains '{keyword}'"

        # Handle type:typename
        elif reason.startswith('type:'):
            file_type = reason.split(':')[1]
            return f"File type: {file_type}"

        # Handle other reasons
        elif reason == 'executable':
            return "Executable file (potential risk)"
        elif reason == 'large_file':
            return "Large file (>100MB)"
        else:
            return reason

    def _render_html_template(self, data: Dict[str, Any]) -> str:
        """Render HTML report from template data."""
        # Since we may not have Jinja2 templates set up, create a basic HTML structure
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Evidence Report - {data['case_id']}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header .subtitle {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .section {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        .section h3 {{
            color: #764ba2;
            margin-top: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th {{
            background-color: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
        }}
        tr:hover {{
            background-color: #f9f9f9;
        }}
        .hash {{
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            background-color: #f4f4f4;
            padding: 5px;
            border-radius: 3px;
            word-break: break-all;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            margin: 2px;
        }}
        .badge-success {{
            background-color: #d4edda;
            color: #155724;
        }}
        .badge-warning {{
            background-color: #fff3cd;
            color: #856404;
        }}
        .badge-danger {{
            background-color: #f8d7da;
            color: #721c24;
        }}
        .badge-info {{
            background-color: #d1ecf1;
            color: #0c5460;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .stat-label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        .warning {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }}
        .info {{
            background-color: #d1ecf1;
            border-left: 4px solid #17a2b8;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }}
        code {{
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        pre {{
            background-color: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            line-height: 1.4;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Forensic Evidence Report</h1>
        <p class="subtitle">Case ID: {data['case_id']}</p>
        <p class="subtitle">Generated: {data['generated_at_readable']}</p>
        <p class="subtitle">Operator: {data['operator']} @ {data['hostname']}</p>
    </div>
"""

        # Executive Summary
        html += """
    <div class="section">
        <h2>1. Executive Summary</h2>
        <p>This report documents the forensic analysis of digital evidence for case <strong>{case_id}</strong>.
        The analysis was conducted on <strong>{generated_at_readable}</strong> by <strong>{operator}</strong>.</p>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Files</div>
                <div class="stat-value">{total_files:,}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Notable Artifacts</div>
                <div class="stat-value">{notable:,}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Size</div>
                <div class="stat-value">{size_gb:.2f} GB</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Processing Steps</div>
                <div class="stat-value">{steps}</div>
            </div>
        </div>
""".format(
            case_id=data['case_id'],
            generated_at_readable=data['generated_at_readable'],
            operator=data['operator'],
            total_files=data['stats']['total_files'],
            notable=data['stats']['notable_artifacts'],
            size_gb=data['stats']['total_size'] / (1024**3),
            steps=len(data['processing_steps'])
        )

        # Warnings section
        if data['warnings']:
            html += """
        <div class="warning">
            <strong>⚠️ Warnings:</strong>
            <ul>
"""
            for warning in data['warnings']:
                html += f"                <li>{warning}</li>\n"
            html += """            </ul>
        </div>
"""

        html += """    </div>
"""

        # Master Image & Verification Information (FIX #4: Enhanced)
        if data['master_image']:
            # Determine verification status
            has_derived = data.get('derived_iso') and data.get('derived_hashes', {}).get('sha256')
            verification_status = "badge-success" if data['master_hashes'].get('sha256') else "badge-warning"
            verification_text = "✓ Verified" if data['master_hashes'].get('sha256') else "⚠ Not Verified"

            html += f"""
    <div class="section">
        <h2>2. Acquisition & Verification Summary</h2>

        <h3>Master Evidence Image</h3>
        <table>
            <tr>
                <th>Property</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>File Path</td>
                <td><code>{data['master_image'].get('path', 'N/A')}</code></td>
            </tr>
            <tr>
                <td>File Size</td>
                <td>{data['master_image'].get('size_mb', 0):,.2f} MB ({data['master_image'].get('size', 0):,} bytes)</td>
            </tr>
            <tr>
                <td>MD5 Hash</td>
                <td><span class="hash">{data['master_hashes'].get('md5', 'N/A')}</span></td>
            </tr>
            <tr>
                <td>SHA256 Hash</td>
                <td><span class="hash">{data['master_hashes'].get('sha256', 'N/A')}</span></td>
            </tr>
            <tr>
                <td>Master Verification Status</td>
                <td><span class="badge {verification_status}">{verification_text}</span></td>
            </tr>
        </table>
"""

            # Add Derived ISO section if present (FIX #4)
            if has_derived:
                derived_sha256 = data['derived_hashes'].get('sha256', 'N/A')
                derived_verified = "badge-success" if derived_sha256 != 'N/A' else "badge-warning"
                derived_verified_text = "✓ Verified" if derived_sha256 != 'N/A' else "⚠ Not Present"

                html += f"""
        <h3 style="margin-top: 25px;">Derived ISO Image</h3>
        <table>
            <tr>
                <th>Property</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>File Path</td>
                <td><code>{data['derived_iso'].get('path', 'N/A')}</code></td>
            </tr>
            <tr>
                <td>File Size</td>
                <td>{data['derived_iso'].get('size_mb', 0):,.2f} MB ({data['derived_iso'].get('size', 0):,} bytes)</td>
            </tr>
            <tr>
                <td>Derived ISO MD5</td>
                <td><span class="hash">{data['derived_hashes'].get('md5', 'N/A')}</span></td>
            </tr>
            <tr>
                <td>Derived ISO SHA256</td>
                <td><span class="hash">{derived_sha256}</span></td>
            </tr>
            <tr>
                <td>Derived Verification Status</td>
                <td><span class="badge {derived_verified}">{derived_verified_text}</span></td>
            </tr>
        </table>
"""
            else:
                html += """
        <h3 style="margin-top: 25px;">Derived ISO Image</h3>
        <div class="warning">
            <strong>⚠️ No Derived ISO:</strong> No derived ISO image was provided for this analysis.
            Only the master evidence image was processed.
        </div>
"""

            html += """
        <div class="info">
            <strong>ℹ️ Forensic Note:</strong> All image hashes have been computed and verified.
            The original evidence files have NOT been modified during this analysis.
            Chain of custody has been maintained throughout the process.
        </div>
    </div>
"""

        # Note: Derived ISO section has been moved to the combined Acquisition & Verification section above

        # Chain of Custody (FIX #5: Now section 3)
        html += """
    <div class="section">
        <h2>3. Chain of Custody</h2>
        <p>Complete chronological record of evidence handling from acquisition to analysis:</p>
        <table>
            <thead>
                <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Action</th>
                    <th>Actor</th>
                    <th>Tools</th>
                    <th>Notes</th>
                </tr>
            </thead>
            <tbody>
"""
        for entry in data['chain_of_custody']:
            timestamp = entry['timestamp_utc'][:19]  # Remove microseconds
            tools = entry.get('tools', 'N/A')
            notes = entry.get('notes', '')
            html += f"""
                <tr>
                    <td>{timestamp}</td>
                    <td>{entry['action']}</td>
                    <td>{entry['actor']}</td>
                    <td>{tools if tools else 'N/A'}</td>
                    <td>{notes if notes else '-'}</td>
                </tr>
"""
        html += """            </tbody>
        </table>
    </div>
"""

        # Tool Versions (FIX #9: Enhanced with missing tools warning)
        html += """
    <div class="section">
        <h2>4. Tools & Versions</h2>
        <p>Software tools used in this forensic analysis:</p>
"""

        # FIX #9: Show missing tools warning prominently
        if data.get('missing_tools'):
            html += f"""
        <div class="warning" style="margin-bottom: 20px;">
            <strong>⚠️ Missing Tools Detected ({len(data['missing_tools'])} tool(s) not found)</strong>
            <p>The following forensic tools were not found on this system. Some analysis features may be limited:</p>
            <ul>
"""
            # Installation instructions for common tools
            install_instructions = {
                'dd': 'Install: <code>apt-get install coreutils</code> (Linux) or included in macOS',
                'dc3dd': 'Install: <code>apt-get install dc3dd</code> (Linux)',
                'genisoimage': 'Install: <code>apt-get install genisoimage</code> (Linux) or <code>brew install cdrtools</code> (macOS)',
                'mkisofs': 'Install: <code>apt-get install mkisofs</code> (Linux) or use genisoimage',
                'bulk_extractor': 'Install: <code>apt-get install bulk-extractor</code> (Linux) or download from digitalcorpora.org',
                'sleuthkit': 'Install: <code>apt-get install sleuthkit</code> (Linux) or <code>brew install sleuthkit</code> (macOS)',
                'volatility': 'Install: <code>pip install volatility3</code> or download from volatilityfoundation.org',
                'foremost': 'Install: <code>apt-get install foremost</code> (Linux)',
                'scalpel': 'Install: <code>apt-get install scalpel</code> (Linux)',
                'photorec': 'Install: <code>apt-get install testdisk</code> (Linux, includes PhotoRec)',
                'wkhtmltopdf': 'Install: <code>apt-get install wkhtmltopdf</code> (Linux) or download from wkhtmltopdf.org',
                'weasyprint': 'Install: <code>pip install weasyprint</code>'
            }

            for tool in data['missing_tools']:
                instruction = install_instructions.get(tool, f'Search online for "{tool} installation instructions"')
                html += f"""
                <li><strong>{tool}</strong>: {instruction}</li>
"""
            html += """
            </ul>
            <p style="margin-top: 10px;"><strong>💡 Note:</strong> Install missing tools to enable full forensic capabilities including ISO creation, advanced carving, and PDF report generation.</p>
        </div>
"""

        html += """
        <table>
            <thead>
                <tr>
                    <th>Tool</th>
                    <th>Version</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
"""
        for tool, version in data['tool_versions'].items():
            # Determine status badge
            if 'not found' in version.lower() or 'unknown' in version.lower():
                status_badge = '<span class="badge badge-danger">Not Found</span>'
            else:
                status_badge = '<span class="badge badge-success">Available</span>'

            html += f"""
                <tr>
                    <td><strong>{tool}</strong></td>
                    <td><code>{version}</code></td>
                    <td>{status_badge}</td>
                </tr>
"""
        html += """            </tbody>
        </table>
    </div>
"""

        # Processing Steps
        html += """
    <div class="section">
        <h2>5. Processing Steps</h2>
        <p>Detailed record of processing steps performed:</p>
"""
        for i, step in enumerate(data['processing_steps'], 1):
            status_badge = "badge-success" if step['success'] else "badge-danger"
            status_text = "✓ Success" if step['success'] else "✗ Failed"

            html += f"""
        <h3>Step {i}: {step['step']}</h3>
        <p><span class="badge {status_badge}">{status_text}</span></p>
        <table>
            <tr><td><strong>Command:</strong></td><td><code>{step.get('cmd', 'N/A')}</code></td></tr>
            <tr><td><strong>Start Time:</strong></td><td>{step.get('start', 'N/A')[:19]}</td></tr>
            <tr><td><strong>End Time:</strong></td><td>{step.get('end', 'N/A')[:19] if step.get('end') else 'In progress'}</td></tr>
        </table>
"""

            if step.get('stdout_snippet'):
                html += f"""
        <p><strong>Output:</strong></p>
        <pre>{step['stdout_snippet'][:500]}</pre>
"""

            if step.get('error'):
                html += f"""
        <div class="warning">
            <strong>Error:</strong> {step['error']}
        </div>
"""

        html += """    </div>
"""

        # Artifacts Summary
        html += f"""
    <div class="section">
        <h2>6. Artifacts Summary</h2>

        <!-- FIX #6: Download links for CSV and JSON -->
        <div class="info" style="margin-bottom: 20px;">
            <strong>📥 Download Full Artifact Data:</strong><br>
            <a href="{self.case_id}_artifacts_{data['timestamp_str']}.csv" download style="color: #667eea; font-weight: bold; text-decoration: none; margin-right: 20px;">
                📊 Download CSV (Excel-compatible)
            </a>
            <a href="{self.case_id}_evidence_manifest_{data['timestamp_str']}.json" download style="color: #667eea; font-weight: bold; text-decoration: none;">
                📄 Download JSON Manifest
            </a>
            <p style="margin-top: 8px; font-size: 0.9em;">
                The CSV file contains all {data['stats']['total_files']:,} artifacts with complete metadata for analysis in spreadsheet tools.
            </p>
        </div>

        <h3>File Type Distribution</h3>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
"""
        total = data['stats']['total_files']
        # FIX #1: Properly display file types (even if empty, show as 'unknown')
        if data['type_distribution']:
            for ftype, count in sorted(data['type_distribution'].items(), key=lambda x: x[1], reverse=True):
                pct = (count / total * 100) if total > 0 else 0
                # Display type or 'unknown' if empty
                display_type = ftype if ftype and ftype.strip() else 'unknown'
                html += f"""
                <tr>
                    <td><span class="badge badge-info">{display_type}</span></td>
                    <td>{count:,}</td>
                    <td>{pct:.1f}%</td>
                </tr>
"""
        else:
            html += """
                <tr>
                    <td colspan="3" style="text-align: center; color: #999;">No file type data available</td>
                </tr>
"""
        html += """            </tbody>
        </table>
    </div>
"""

        # Notable Findings (FIX #2, #3, #7, #8: Enhanced with origin, confidence, thumbnails)
        if data['notable_artifacts']:
            html += """
    <div class="section">
        <h2>7. Notable Findings</h2>
        <p>Top priority artifacts identified during analysis (showing top 20):</p>
        <table>
            <thead>
                <tr>
                    <th>Priority</th>
                    <th>Preview</th>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Origin</th>
                    <th>Confidence</th>
                    <th>Size</th>
                    <th>Reasons</th>
                </tr>
            </thead>
            <tbody>
"""
            for artifact in data['notable_artifacts']:
                size_kb = artifact['size_bytes'] / 1024

                # FIX #3: Format reasons in human-readable format
                formatted_reasons = []
                for reason in artifact['notable_reasons']:
                    formatted_reason = self._format_notable_reason(reason, artifact)
                    formatted_reasons.append(formatted_reason)
                reasons_text = '<br>'.join([f"• {r}" for r in formatted_reasons])

                # FIX #2: Make artifact name clickable if extracted_path exists
                artifact_name = artifact['name']
                if artifact.get('extracted_path') and os.path.exists(artifact['extracted_path']):
                    # Create clickable link to extracted file
                    name_html = f'<a href="file:///{artifact["extracted_path"]}" title="Open extracted file" style="color: #667eea; text-decoration: none;"><code>{artifact_name}</code></a>'
                else:
                    # Just display the name
                    name_html = f'<code>{artifact_name}</code>'

                # Display type or 'unknown' if empty
                artifact_type = artifact.get('type', 'unknown')
                if not artifact_type or artifact_type.strip() == '':
                    artifact_type = 'unknown'

                # FIX #8: Generate preview/thumbnail cell
                preview_html = ""
                if artifact.get('thumbnail_path') and os.path.exists(artifact['thumbnail_path']):
                    # Show thumbnail if available
                    preview_html = f'<img src="{artifact["thumbnail_path"]}" alt="thumbnail" style="max-height: 40px; max-width: 60px; border: 1px solid #ddd; border-radius: 3px;" title="Preview">'
                elif artifact_type in ['image', 'picture', 'photo']:
                    preview_html = '<span style="font-size: 24px;" title="Image file">🖼️</span>'
                elif artifact_type == 'document':
                    preview_html = '<span style="font-size: 24px;" title="Document">📄</span>'
                elif artifact_type == 'executable':
                    preview_html = '<span style="font-size: 24px;" title="Executable">⚙️</span>'
                elif artifact_type == 'archive':
                    preview_html = '<span style="font-size: 24px;" title="Archive">📦</span>'
                elif artifact_type == 'video':
                    preview_html = '<span style="font-size: 24px;" title="Video">🎬</span>'
                else:
                    preview_html = '<span style="font-size: 20px; color: #999;" title="Generic file">📁</span>'

                # FIX #7: Origin and Confidence badges
                origin = artifact.get('origin', 'original')
                confidence = artifact.get('confidence', 'high')

                # Origin badge colors
                origin_badge_class = {
                    'original': 'badge-success',
                    'carved': 'badge-warning',
                    'partial': 'badge-danger'
                }.get(origin, 'badge-info')

                # Confidence badge colors
                confidence_badge_class = {
                    'high': 'badge-success',
                    'medium': 'badge-warning',
                    'low': 'badge-danger'
                }.get(confidence, 'badge-info')

                html += f"""
                <tr>
                    <td><span class="badge badge-warning">{artifact['priority']}</span></td>
                    <td style="text-align: center;">{preview_html}</td>
                    <td>{name_html}</td>
                    <td><span class="badge badge-info">{artifact_type}</span></td>
                    <td><span class="badge {origin_badge_class}">{origin}</span></td>
                    <td><span class="badge {confidence_badge_class}">{confidence}</span></td>
                    <td>{size_kb:,.1f} KB</td>
                    <td style="font-size: 0.9em;">{reasons_text}</td>
                </tr>
"""
            html += """            </tbody>
        </table>

        <div class="info">
            <strong>💡 Tip:</strong> Click on artifact names (if available) to open the extracted file.
            Review these high-priority findings first during your investigation.
        </div>
    </div>
"""

        # Risk Assessment Overview
        risk_summary = data.get('risk_summary')
        if risk_summary:
            sc = risk_summary['severity_counts']
            html += f"""
    <div class="section">
        <h2>8. Risk Assessment Overview</h2>
        <p>Automated risk scoring of <strong>{risk_summary['total']:,}</strong> scanned artifacts:</p>
        <div class="stats-grid">
            <div class="stat-card" style="background: linear-gradient(135deg, #e74c3c, #c0392b);">
                <div class="stat-label">Critical</div>
                <div class="stat-value">{sc['Critical']}</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #e67e22, #d35400);">
                <div class="stat-label">High</div>
                <div class="stat-value">{sc['High']}</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #f1c40f, #f39c12);">
                <div class="stat-label">Medium</div>
                <div class="stat-value">{sc['Medium']}</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #3498db, #2980b9);">
                <div class="stat-label">Low</div>
                <div class="stat-value">{sc['Low']}</div>
            </div>
        </div>
"""
            # Top suspicious indicators table
            if risk_summary['top_indicators']:
                html += """
        <h3>Top Suspicious Indicators</h3>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Artifact</th>
                    <th>Score</th>
                    <th>Severity</th>
                    <th>Top Reason</th>
                </tr>
            </thead>
            <tbody>
"""
                severity_badge_map = {
                    'Critical': 'badge-danger',
                    'High': 'badge-warning',
                    'Medium': 'badge-info',
                    'Low': 'badge-success',
                    'Info': 'badge-info',
                }
                for idx, ind in enumerate(risk_summary['top_indicators'], 1):
                    reasons = ind.get('reasons', [])
                    top_reason = reasons[0] if reasons else ''
                    badge_cls = severity_badge_map.get(ind.get('severity', 'Info'), 'badge-info')
                    html += f"""
                <tr>
                    <td>{idx}</td>
                    <td><code>{ind.get('name', '')}</code></td>
                    <td><strong>{ind.get('score', 0)}</strong></td>
                    <td><span class="badge {badge_cls}">{ind.get('severity', 'Info')}</span></td>
                    <td>{top_reason}</td>
                </tr>
"""
                html += """            </tbody>
        </table>
"""
            html += """    </div>
"""

        # MITRE ATT&CK Mapping
        if risk_summary:
            active_stages = [(s, c) for s, c in risk_summary['stage_counts'].items() if c > 0]
            if active_stages:
                html += """
    <div class="section">
        <h2>9. MITRE ATT&CK Mapping</h2>
        <p>Artifacts mapped to MITRE ATT&CK kill-chain stages (showing stages with hits):</p>
        <table>
            <thead>
                <tr>
                    <th>Stage</th>
                    <th>Artifact Count</th>
                </tr>
            </thead>
            <tbody>
"""
                for stage, count in active_stages:
                    html += f"""
                <tr>
                    <td><strong>{stage}</strong></td>
                    <td>{count}</td>
                </tr>
"""
                html += """            </tbody>
        </table>
    </div>
"""

        # Bulk Extractor Results
        # Section number adjusts based on whether risk sections are present
        be_section = 10 if risk_summary else 8
        if data['bulk_extractor']:
            html += f"""
    <div class="section">
        <h2>{be_section}. Bulk Extractor Results</h2>
        <p>Automated artifact extraction summary:</p>
        <div class="stats-grid">
"""
            be_labels = {
                'email': 'Email Addresses',
                'url': 'URLs',
                'telephone': 'Phone Numbers',
                'ccn': 'Credit Card Numbers',
                'exif': 'EXIF Data',
                'zip': 'Compressed Files'
            }

            for key, label in be_labels.items():
                count = data['bulk_extractor'].get(key, 0)
                html += f"""
            <div class="stat-card">
                <div class="stat-label">{label}</div>
                <div class="stat-value">{count:,}</div>
            </div>
"""
            html += """        </div>
    </div>
"""

        # Recommendations
        rec_section = (11 if risk_summary else 9)
        html += f"""
    <div class="section">
        <h2>{rec_section}. Recommendations &amp; Next Steps</h2>
"""
        # Context-aware recommendations from risk scan data
        if risk_summary and risk_summary.get('recommendations'):
            html += """        <h3>Risk-Based Recommendations:</h3>
        <ul>
"""
            for rec in risk_summary['recommendations']:
                html += f"            <li>{rec}</li>\n"
            html += """        </ul>
"""

        html += f"""        <h3>Analyst Recommendations:</h3>
        <ul>
            <li><strong>Priority Review:</strong> Focus on the {data['stats']['notable_artifacts']} notable artifacts identified in Section 7</li>
            <li><strong>Executable Analysis:</strong> All executable files should be analyzed for malicious behavior</li>
            <li><strong>Recent Activity:</strong> Review recently modified files (last 30 days) for investigation timeline</li>
            <li><strong>Bulk Extractor Findings:</strong> Manually review bulk_extractor results for PII and sensitive data</li>
            <li><strong>Hash Verification:</strong> Periodically re-verify master image hashes to ensure integrity</li>
            <li><strong>Preservation:</strong> Store this report with the evidence package for chain of custody documentation</li>
        </ul>

        <h3>Suggested Search Queries:</h3>
        <ul>
            <li>Search for keywords: "password", "confidential", "secret", "credential"</li>
            <li>Filter by file type: executable, document, archive</li>
            <li>Timeline analysis: Files accessed/modified within suspect timeframe</li>
            <li>Network artifacts: URLs, email addresses, IP addresses from bulk_extractor</li>
        </ul>
    </div>
"""

        # Footer
        html += f"""
    <div class="footer">
        <p><strong>ForensAI Forensic Evidence Report</strong></p>
        <p>Generated on {data['generated_at_readable']} by {data['operator']}</p>
        <p>This report is for official use only and may contain sensitive information.</p>
        <p style="margin-top: 15px; color: #999;">
            Report ID: {data['case_id']}_{self.timestamp_str}<br>
            ForensAI Version: {data['tool_versions'].get('forensai_commit', 'unknown')}<br>
            Platform: {data['tool_versions'].get('platform', 'unknown')}
        </p>
    </div>
</body>
</html>
"""
        return html

    def generate_pdf_report(self, html_path: str) -> Optional[str]:
        """
        Generate PDF report from HTML using external tool.

        Args:
            html_path: Path to HTML report

        Returns:
            Path to PDF report or None if generation failed
        """
        logger.info("Attempting PDF generation...")

        pdf_path = os.path.join(
            self.output_dir,
            f"{self.case_id}_evidence_report_{self.timestamp_str}.pdf"
        )

        # Try wkhtmltopdf first
        tools_to_try = [
            {
                'name': 'wkhtmltopdf',
                'cmd': ['wkhtmltopdf', '--enable-local-file-access', html_path, pdf_path],
                'check': ['wkhtmltopdf', '--version']
            },
            {
                'name': 'weasyprint',
                'cmd': ['weasyprint', html_path, pdf_path],
                'check': ['weasyprint', '--version']
            }
        ]

        for tool in tools_to_try:
            try:
                # Check if tool is available
                check_result = subprocess.run(
                    tool['check'],
                    capture_output=True,
                    timeout=5
                )

                if check_result.returncode == 0:
                    logger.info(f"Using {tool['name']} for PDF generation")

                    # Generate PDF
                    result = subprocess.run(
                        tool['cmd'],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )

                    if result.returncode == 0 and os.path.exists(pdf_path):
                        logger.info(f"PDF report generated successfully: {pdf_path}")
                        return pdf_path
                    else:
                        logger.warning(f"{tool['name']} failed: {result.stderr}")

            except FileNotFoundError:
                logger.debug(f"{tool['name']} not found")
                continue
            except Exception as e:
                logger.warning(f"Error with {tool['name']}: {e}")
                continue

        # If all tools failed, log instructions
        self.warnings.append(
            "PDF generation requires wkhtmltopdf or weasyprint. "
            "Install with: pip install weasyprint OR download wkhtmltopdf from https://wkhtmltopdf.org/"
        )
        logger.warning("PDF generation failed. HTML report is available.")
        return None

    def copy_logfile(self) -> Optional[str]:
        """
        Copy processing logfile to output directory.

        Returns:
            Path to copied logfile or None
        """
        if not self.logfile or not os.path.exists(self.logfile):
            logger.info("No logfile to copy")
            return None

        log_copy_path = os.path.join(
            self.output_dir,
            f"{self.case_id}_processing_log_{self.timestamp_str}.log"
        )

        try:
            import shutil
            shutil.copy2(self.logfile, log_copy_path)
            logger.info(f"Logfile copied to {log_copy_path}")
            return log_copy_path
        except Exception as e:
            logger.warning(f"Failed to copy logfile: {e}")
            return None

    def generate_report(self, formats: List[str] = None,
                       include_screenshots: bool = False) -> Dict[str, Any]:
        """
        Generate complete forensic evidence report.

        Args:
            formats: List of formats to generate ['pdf', 'html', 'json']
            include_screenshots: Whether to include screenshots

        Returns:
            Dictionary with report status and file paths
        """
        if formats is None:
            formats = ['html', 'json']

        logger.info(f"Starting report generation for case {self.case_id}")
        logger.info(f"Output formats: {', '.join(formats)}")

        # FIX #5: Add comprehensive Chain of Custody entries
        # Add acquisition entry (based on image file metadata if available)
        if self.master_image and os.path.exists(self.master_image):
            image_created_time = datetime.fromtimestamp(os.path.getctime(self.master_image), timezone.utc)
            self.add_chain_of_custody_entry(
                action=f"Evidence image acquired: {os.path.basename(self.master_image)}",
                source="Physical device/source media",
                target=self.master_image,
                tools="ForensAI Acquisition Module",
                notes=f"Image file created at {image_created_time.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )

        # Add analysis start entry
        self.add_chain_of_custody_entry(
            action="Forensic analysis initiated",
            source=self.master_image,
            tools=f"ForensAI v{self.tool_versions.get('forensai_commit', 'unknown')}",
            notes=f"Analysis started by {self.operator} on {platform.node()}"
        )

        try:
            # Step 1: Verify master image
            if not self.verify_master_image():
                return {
                    'status': 'failed',
                    'case_id': self.case_id,
                    'report_pdf': None,
                    'report_html': None,
                    'manifest_json': None,
                    'artifacts_csv': None,
                    'logfile': None,
                    'summary': 'Master image verification failed',
                    'warnings': self.warnings
                }

            # Step 2: Verify derived ISO (if present)
            self.verify_derived_iso()

            # Step 3: Collect tool versions
            self.collect_tool_versions()

            # Step 4: Scan artifacts (only if not already loaded from session)
            if len(self.artifacts) == 0:
                # No artifacts loaded yet, scan from directory
                self.scan_artifacts()
            else:
                # Artifacts already loaded (from session data)
                logger.info(f"Using {len(self.artifacts)} artifacts from session data (skipping scan)")

            # Step 5: Parse bulk_extractor results
            self.parse_bulk_extractor_results()

            # Step 6: Generate JSON manifest
            manifest_path = None
            if 'json' in formats:
                manifest_path = self.generate_json_manifest()

            # Step 6.5: Generate CSV artifacts file (FIX #6: Always generate for download links)
            csv_path = self.generate_csv_artifacts()

            # Step 7: Generate HTML report
            html_path = None
            if 'html' in formats or 'pdf' in formats:
                html_path = self.generate_html_report()

            # Step 8: Generate PDF report (if requested)
            pdf_path = None
            if 'pdf' in formats and html_path:
                pdf_path = self.generate_pdf_report(html_path)

            # Step 9: Copy logfile
            log_copy_path = self.copy_logfile()

            # FIX #5: Add report generation CoC entry
            self.add_chain_of_custody_entry(
                action="Forensic report generated",
                tools=f"ForensAI Report Generator, Formats: {', '.join(formats)}",
                notes=f"Generated {len(formats)} report format(s): {', '.join(f.upper() for f in formats)}"
            )

            # FIX #5: Add export/output CoC entry
            if html_path or manifest_path:
                outputs = []
                if html_path:
                    outputs.append(f"HTML: {html_path}")
                if manifest_path:
                    outputs.append(f"JSON: {manifest_path}")
                if pdf_path:
                    outputs.append(f"PDF: {pdf_path}")

                self.add_chain_of_custody_entry(
                    action="Report files exported to output directory",
                    target=self.output_dir,
                    notes=f"Exported files: {'; '.join(outputs)}"
                )

            # Build summary
            summary = (
                f"Report generated successfully. "
                f"Analyzed {self.stats['total_files']:,} files, "
                f"found {self.stats['notable_artifacts']} notable artifacts."
            )

            status = 'success'
            if 'pdf' in formats and not pdf_path:
                status = 'partial'
                summary += " PDF generation failed (HTML and JSON available)."

            result = {
                'status': status,
                'case_id': self.case_id,
                'report_pdf': pdf_path,
                'report_html': html_path,
                'manifest_json': manifest_path,
                'artifacts_csv': csv_path,  # FIX #6: Include CSV path
                'logfile': log_copy_path,
                'summary': summary,
                'warnings': self.warnings
            }

            logger.info(f"Report generation complete: {status}")
            return result

        except Exception as e:
            logger.error(f"Report generation failed: {e}", exc_info=True)
            return {
                'status': 'failed',
                'case_id': self.case_id,
                'report_pdf': None,
                'report_html': None,
                'manifest_json': None,
                'artifacts_csv': None,
                'logfile': None,
                'summary': f'Report generation failed: {str(e)}',
                'warnings': self.warnings + [str(e)]
            }


def main():
    """Main entry point for CLI usage."""
    import argparse

    parser = argparse.ArgumentParser(
        description='ForensAI Forensic Evidence Report Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python forensic_report_generator.py \\
    --case-id CASE-2025-001 \\
    --operator "John Doe" \\
    --master-image /path/to/evidence.dd \\
    --output-dir /path/to/reports \\
    --formats html json pdf

For detailed documentation, see: https://github.com/forensai/forensai
"""
    )

    parser.add_argument('--case-id', required=True, help='Case identifier')
    parser.add_argument('--operator', required=True, help='Operator name')
    parser.add_argument('--master-image', required=True, help='Path to master .dd image')
    parser.add_argument('--output-dir', required=True, help='Output directory for reports')
    parser.add_argument('--derived-iso', help='Path to derived ISO (optional)')
    parser.add_argument('--artifacts-dir', help='Path to parsed artifacts directory')
    parser.add_argument('--bulk-extractor-dir', help='Path to bulk_extractor output')
    parser.add_argument('--checkpoints-dir', help='Path to checkpoints directory')
    parser.add_argument('--logfile', help='Path to processing logfile')
    parser.add_argument('--formats', nargs='+', default=['html', 'json'],
                       choices=['html', 'json', 'pdf'],
                       help='Output formats (default: html json)')
    parser.add_argument('--include-screenshots', action='store_true',
                       help='Include screenshots in report')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')

    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create report generator
    generator = ForensicReportGenerator(
        case_id=args.case_id,
        operator=args.operator,
        master_image=args.master_image,
        output_dir=args.output_dir,
        derived_iso=args.derived_iso,
        parsed_artifacts_dir=args.artifacts_dir,
        bulk_extractor_dir=args.bulk_extractor_dir,
        checkpoints_dir=args.checkpoints_dir,
        logfile=args.logfile
    )

    # Generate report
    result = generator.generate_report(
        formats=args.formats,
        include_screenshots=args.include_screenshots
    )

    # Print result as JSON
    print(json.dumps(result, indent=2))

    # Exit with appropriate code
    sys.exit(0 if result['status'] in ['success', 'partial'] else 1)


if __name__ == '__main__':
    main()
