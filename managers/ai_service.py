"""
ForensAI - Cloud AI Service (Groq)
===================================
Integration with Groq API for fast forensic artifact explanation.

Provides:
- Artifact explanations (files, registry keys, carved data)
- Risk score explanations
- Overwriting story narratives
"""

import json
import requests
import httpx
import asyncio
import time
import configparser
from typing import Dict, Optional, List
from datetime import datetime
from pathlib import Path

# Import audit logger (optional dependency)
try:
    from managers.audit_logger import get_audit_logger, AuditLogger
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False
    AuditLogger = None

# Import confidence tracker (optional dependency)
try:
    from managers.confidence_tracker import get_confidence_tracker, ConfidenceTracker, FactType
    CONFIDENCE_AVAILABLE = True
except ImportError:
    CONFIDENCE_AVAILABLE = False
    ConfidenceTracker = None
    FactType = None


class GroqAIService:
    """Groq API integration for fast forensic analysis."""

    # Available Groq models
    AVAILABLE_MODELS = {
        "llama-3.3-70b-versatile": "Llama 3.3 70B (Best quality)",
        "llama-3.1-8b-instant": "Llama 3.1 8B (Fastest)",
        "mixtral-8x7b-32768": "Mixtral 8x7B (Balanced)",
    }

    # Token limits per analysis type (deeper analysis = more tokens)
    TOKEN_LIMITS = {
        'file_analysis': 600,       # Detailed file analysis
        'registry_analysis': 500,   # Registry key analysis
        'risk_analysis': 800,       # Risk explanation (most detailed)
        'timestamp_analysis': 500,  # Timeline analysis
        'overwrite_analysis': 600,  # Overwrite narrative
    }

    # Domain-specific forensic system prompts
    FORENSIC_SYSTEM_PROMPTS = {
        'file_analysis': """You are a senior digital forensics examiner with expertise in:
- Windows filesystem forensics (NTFS MFT, $UsnJrnl, $I30 indexes)
- Malware analysis and anti-forensic detection
- Timeline reconstruction and temporal analysis
- Chain of custody and court-admissible evidence

When analyzing file artifacts:
1. First, state ONLY what the direct evidence shows (facts from metadata)
2. Then, apply forensic principles to interpret meaning
3. Distinguish between certain conclusions and probabilistic inferences
4. Identify what additional evidence would strengthen or refute hypotheses
5. Provide specific, actionable next steps for the investigator

Your analysis will be used in legal proceedings. Be precise about certainty levels.
Use confidence markers: FACT (100%), HIGH CONFIDENCE, MEDIUM CONFIDENCE, LOW CONFIDENCE.""",

        'registry_analysis': """You are a Windows registry forensics specialist with expertise in:
- Registry persistence mechanisms (Run keys, Services, Scheduled Tasks)
- User activity artifacts (UserAssist, RecentDocs, TypedPaths)
- System configuration and security settings
- Rootkit and kernel-mode malware indicators
- MITRE ATT&CK framework mappings

When analyzing registry keys:
1. Explain what this key controls in Windows
2. Identify forensic significance (what investigator learns from it)
3. Note any indicators of tampering or malicious configuration
4. Reference common attack patterns if applicable (cite MITRE ATT&CK ID)
5. Suggest related registry locations to examine

Your analysis will be used in legal proceedings. Be precise about certainty levels.""",

        'timestamp_analysis': """You are a timeline forensics expert specializing in:
- NTFS timestamp mechanics ($STANDARD_INFO vs $FILE_NAME attributes)
- Timestomping detection and anti-forensic indicators
- Temporal clustering and activity reconstruction
- Distinguishing user actions from automated processes

When analyzing timestamps:
1. Assess timestamp consistency across MFT attributes
2. Identify anomalies suggesting manipulation (zero deltas, impossible sequences)
3. Provide temporal context (what activity pattern this suggests)
4. Rate confidence in timestamp authenticity
5. Suggest corroborating evidence sources (USN Journal, Event Logs, Prefetch)

Mark each assessment with confidence: FACT, HIGH, MEDIUM, or LOW CONFIDENCE.""",

        'risk_analysis': """You are a threat assessment specialist with expertise in:
- Indicator of Compromise (IoC) analysis
- Malware behavior patterns and evasion techniques
- Data exfiltration and concealment methods
- Anti-forensic tool identification

Structure your response EXACTLY as:

**FACTS** (Direct evidence only - cite source)
[What the metadata definitively shows - timestamps, sizes, locations, hashes]

**INTERPRETATION** (State confidence: High/Medium/Low)
[What this evidence likely means, with forensic reasoning]

**ALTERNATIVE HYPOTHESES**
[Other explanations that cannot be ruled out]

**RECOMMENDATIONS**
[Specific next investigative steps, prioritized by value]

Never state speculation as fact. Always identify what evidence would resolve uncertainty.""",

        'overwrite_analysis': """You are a data destruction forensics expert specializing in:
- File deletion and recovery mechanics
- Cluster allocation and overwrite patterns
- Anti-forensic tool identification (wipers, shredders)
- Intentionality assessment from destruction patterns

When analyzing overwrite events:
1. Describe the chronological sequence of events
2. Assess intentionality (deliberate vs. normal system operation)
3. Evaluate recovery prospects based on overwrite percentage
4. Identify patterns suggesting anti-forensic activity
5. Recommend specific recovery or investigation steps

Write in professional, court-ready language suitable for expert testimony."""
    }

    # Chain-of-reasoning framework for deep analysis
    REASONING_FRAMEWORK = """
Apply this forensic reasoning process:

1. OBSERVATION: What does the raw evidence show? (timestamps, sizes, locations, attributes)
2. CONTEXT: What is normal for this type of artifact? What is anomalous here?
3. INFERENCE: What forensic conclusions follow from the observations?
4. CONFIDENCE: How certain are you? (High/Medium/Low) Why?
5. GAPS: What information would you need to increase confidence?
6. ACTION: What should the investigator do next?
"""

    # Confidence calibration instructions
    CONFIDENCE_INSTRUCTION = """
For each assertion, indicate confidence level:
- FACT: Direct from filesystem metadata (100% certain, cite source)
- HIGH CONFIDENCE: Strong forensic inference with multiple supporting indicators
- MEDIUM CONFIDENCE: Reasonable inference, some supporting evidence
- LOW CONFIDENCE: Possible but speculative, requires corroboration
- UNKNOWN: Insufficient evidence to determine

Never state speculation as fact. Always identify what evidence would resolve uncertainty."""

    # Rule significance mappings for risk explanations
    RULE_SIGNIFICANCE = {
        'executable_in_temp': "Malware commonly stages in TEMP to avoid detection and survive reboots",
        'executable_in_downloads': "Recent download suggests external origin - check browser history",
        'executable_in_user_dir': "System executable in user space indicates masquerading or staging",
        'system_file_wrong_location': "Masquerading attack - executable impersonating system file",
        'timestomp_detected': "Timestamp manipulation indicates deliberate evidence tampering",
        'created_equals_modified': "Zero-second delta between creation and modification is suspicious for binaries",
        'high_entropy': "Encrypted/packed content suggests obfuscation or data exfiltration",
        'high_entropy_file': "High entropy indicates encryption, compression, or random data",
        'hidden_file': "Hidden attribute on executable may indicate concealment intent",
        'hidden_executable': "Hidden executable is a strong indicator of malicious intent",
        'deleted_during_investigation': "Destruction of evidence during active case timeline",
        'recently_deleted_sensitive': "Sensitive file deletion may indicate evidence destruction",
        'wiping_tool_artifact': "Anti-forensic tool indicates deliberate destruction attempt",
        'encryption_tool_artifact': "Encryption tool may indicate data concealment or ransomware",
        'suspicious_extension': "Uncommon or deceptive extension may indicate masquerading",
        'double_extension': "Double extension (e.g., .pdf.exe) is a social engineering technique",
        'timestamp_anomaly': "Timestamp inconsistency may indicate manipulation",
        'future_timestamp': "Future timestamp indicates clock manipulation or timestomping",
        'masquerading': "Filename mimics legitimate system file",
        'unsigned_executable': "Missing digital signature - cannot verify publisher authenticity",
        'unknown_hash': "File hash not in known-good databases - requires manual analysis",
        'multiple_overwriters': "Multiple files overwrote this location - suggests heavy activity or wiping",
        'rapid_overwrite': "Quick overwrite after deletion suggests deliberate destruction",
    }

    def __init__(self, api_key: str = None, model: str = "llama-3.3-70b-versatile",
                 audit_logger: Optional[AuditLogger] = None, case_id: str = "default",
                 confidence_tracker: Optional['ConfidenceTracker'] = None):
        """
        Initialize Groq AI service.

        Args:
            api_key: Groq API key (if not provided, reads from config.ini)
            model: Model name (llama-3.3-70b-versatile, llama-3.1-8b-instant, mixtral-8x7b-32768)
            audit_logger: Optional audit logger for provenance tracking
            case_id: Case identifier for audit logging
            confidence_tracker: Optional confidence tracker for uncertainty metrics
        """
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = model
        self.timeout = 30  # Groq is fast, 30s is plenty
        self.audit_logger = audit_logger
        self.case_id = case_id
        self.confidence_tracker = confidence_tracker

        # Async HTTP client with connection pooling
        self._async_client = None

        # Load API key from config if not provided
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = self._load_api_key()

        # Initialize audit logger if enabled and not provided
        if self.audit_logger is None and AUDIT_AVAILABLE:
            try:
                self.audit_logger = get_audit_logger(case_id)
            except:
                self.audit_logger = None

        # Initialize confidence tracker if enabled and not provided
        if self.confidence_tracker is None and CONFIDENCE_AVAILABLE:
            try:
                self.confidence_tracker = get_confidence_tracker(case_id)
            except:
                self.confidence_tracker = None

    def _load_api_key(self) -> str:
        """Load Groq API key from config.ini."""
        try:
            config = configparser.ConfigParser()
            config.read('config.ini')
            return config.get('API_KEYS', 'groq', fallback='')
        except:
            return ''

    def set_api_key(self, api_key: str):
        """Set the Groq API key."""
        self.api_key = api_key

    def is_available(self) -> bool:
        """
        Check if Groq API is accessible.

        Returns:
            True if API key is set and valid, False otherwise
        """
        if not self.api_key:
            return False

        try:
            # Quick test with minimal request
            response = requests.post(
                self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 1
                },
                timeout=10
            )
            return response.status_code in [200, 429]  # 429 = rate limited but valid key
        except:
            return False

    def explain_file_artifact(self, file_data: Dict) -> str:
        """
        Generate deep forensic explanation for a file artifact.

        Args:
            file_data: Dictionary containing:
                - name: filename
                - path: full path (optional)
                - type: file type
                - size: file size in bytes
                - created: creation timestamp
                - modified: modification timestamp
                - accessed: access timestamp
                - changed: metadata change time (optional)
                - md5: MD5 hash (optional)
                - sha256: SHA256 hash (optional)
                - mime_type: MIME type (optional)
                - inode: MFT entry number (optional)
                - entropy: file entropy (optional)
                - is_allocated: allocation status (optional)
                - attributes: file attributes dict (optional)

        Returns:
            Deep forensic explanation string with confidence levels
        """
        # Build basic metadata context
        context = f"""=== FILE ARTIFACT ANALYSIS ===
File: {file_data.get('name', 'unknown')}"""

        if file_data.get('path'):
            context += f"\nFull Path: {file_data['path']}"

        context += f"\nType: {file_data.get('type', 'unknown')}"

        if file_data.get('mime_type'):
            context += f"\nMIME Type: {file_data['mime_type']}"

        if file_data.get('size'):
            size = file_data['size']
            context += f"\nSize: {self._format_size(size)} ({size:,} bytes)"

        # Timestamps with forensic context
        context += "\n\n=== TIMESTAMPS ==="
        if file_data.get('created'):
            context += f"\nCreated (birth): {file_data['created']}"
        if file_data.get('modified'):
            context += f"\nModified (mtime): {file_data['modified']}"
        if file_data.get('accessed'):
            context += f"\nAccessed (atime): {file_data['accessed']}"
        if file_data.get('changed'):
            context += f"\nMetadata Changed (ctime): {file_data['changed']}"

        # Build enriched forensic context
        forensic_context = self._build_forensic_context(file_data)
        if forensic_context:
            context += f"\n\n=== FORENSIC INDICATORS ===\n{forensic_context}"

        # Build prompt with reasoning framework
        prompt = f"""Analyze this file artifact using forensic methodology:

{context}

{self.REASONING_FRAMEWORK}

{self.CONFIDENCE_INSTRUCTION}

Provide a thorough but concise analysis covering:
1. **Identity**: What is this file? What does it do?
2. **Forensic Significance**: Why should an investigator care about this artifact?
3. **Timeline Analysis**: What do the timestamps reveal about file activity?
4. **Risk Assessment**: Any indicators of malicious activity or tampering?
5. **Next Steps**: What should the investigator examine next?

Be precise and cite evidence sources (e.g., "from MFT timestamps", "based on file location")."""

        artifact_id = str(file_data.get('inode', file_data.get('hash', file_data.get('name', ''))))

        return self._query_groq(
            prompt,
            interaction_purpose="explain_file",
            artifact_id=artifact_id,
            artifact_name=file_data.get('name', ''),
            analysis_type="file_analysis"
        )

    def explain_registry_key(self, key_path: str, values: List[Dict] = None,
                             last_modified: str = None, subkey_count: int = None,
                             value_count: int = None) -> str:
        """
        Generate deep forensic explanation for a registry key.

        Args:
            key_path: Full registry key path
            values: List of registry values (name, type, data)
            last_modified: Last write timestamp of the key (optional)
            subkey_count: Number of subkeys (optional)
            value_count: Number of values (optional)

        Returns:
            Deep forensic explanation string with MITRE ATT&CK references
        """
        # Parse key path for forensic context
        key_parts = key_path.split('\\') if key_path else []
        hive = key_parts[0] if key_parts else "Unknown"
        key_name = key_parts[-1] if key_parts else "Unknown"

        context = f"""=== REGISTRY KEY ANALYSIS ===
Full Path: {key_path}
Hive: {hive}
Key Name: {key_name}"""

        if last_modified:
            context += f"\nLast Modified: {last_modified}"
        if subkey_count is not None:
            context += f"\nSubkeys: {subkey_count}"
        if value_count is not None:
            context += f"\nValues: {value_count}"

        # Identify forensically significant key categories
        path_lower = key_path.lower() if key_path else ""
        key_category = []

        if 'run' in path_lower and ('currentversion\\run' in path_lower or 'policies\\explorer\\run' in path_lower):
            key_category.append("PERSISTENCE MECHANISM (auto-run at startup)")
        if 'services' in path_lower and 'currentcontrolset\\services' in path_lower:
            key_category.append("WINDOWS SERVICE (potential persistence)")
        if 'userassist' in path_lower:
            key_category.append("USER ACTIVITY TRACKING (program execution history)")
        if 'recentdocs' in path_lower:
            key_category.append("RECENT DOCUMENTS (file access history)")
        if 'typedpaths' in path_lower or 'typedurls' in path_lower:
            key_category.append("USER INPUT HISTORY (typed paths/URLs)")
        if 'shellbags' in path_lower or 'bagmru' in path_lower:
            key_category.append("FOLDER ACCESS HISTORY (ShellBags)")
        if 'mounteddevices' in path_lower or 'usbstor' in path_lower:
            key_category.append("USB/STORAGE DEVICE HISTORY")
        if 'networkprofile' in path_lower or 'networkservice' in path_lower:
            key_category.append("NETWORK CONNECTION HISTORY")
        if 'appcompatcache' in path_lower or 'shimcache' in path_lower:
            key_category.append("APPLICATION EXECUTION (ShimCache)")

        if key_category:
            context += f"\n\n=== FORENSIC CATEGORY ===\n" + "\n".join(key_category)

        if values:
            context += "\n\n=== VALUES ==="
            for val in values[:8]:  # Show up to 8 values for better context
                val_name = val.get('name', '(Default)')
                val_type = val.get('type', 'Unknown')
                val_data = val.get('data', '')
                # Truncate very long data
                if isinstance(val_data, str) and len(val_data) > 100:
                    val_data = val_data[:100] + "..."
                context += f"\n  {val_name} ({val_type}): {val_data}"

        prompt = f"""Analyze this Windows registry key using forensic methodology:

{context}

Provide analysis covering:

1. **Key Purpose**: What does this registry key control in Windows?

2. **Forensic Significance**: What can an investigator learn from this key?
   - What user/system activity does it reveal?
   - What timeline information can be extracted?

3. **Value Analysis**: What do the specific values indicate?
   - Any suspicious or anomalous values?
   - Evidence of tampering or malicious configuration?

4. **MITRE ATT&CK**: If this key relates to known attack techniques, cite the relevant:
   - Technique ID (e.g., T1547.001 for Run key persistence)
   - Tactic (e.g., Persistence, Defense Evasion)

5. **Related Keys**: What other registry locations should be examined for correlation?

{self.CONFIDENCE_INSTRUCTION}

Be precise about what can be definitively determined vs. what requires further investigation."""

        return self._query_groq(
            prompt,
            interaction_purpose="explain_registry",
            artifact_id=key_path,
            artifact_name=key_name,
            analysis_type="registry_analysis"
        )

    def explain_timestamp_pattern(self, timestamps: Dict, filename: str = None,
                                   file_type: str = None, file_path: str = None) -> str:
        """
        Analyze and explain timestamp patterns with timestomping detection.

        Args:
            timestamps: Dictionary with created, modified, accessed, changed times
            filename: Name of the file (optional, for context)
            file_type: Type of file (optional, for behavioral context)
            file_path: Full path (optional, for location context)

        Returns:
            Deep timeline analysis with manipulation detection
        """
        context = "=== TIMESTAMP ANALYSIS ==="

        if filename:
            context += f"\nFile: {filename}"
        if file_path:
            context += f"\nPath: {file_path}"
        if file_type:
            context += f"\nType: {file_type}"

        context += "\n\n=== NTFS TIMESTAMPS ==="

        # Parse timestamps for anomaly detection
        ts_values = {}
        for key, value in timestamps.items():
            if value:
                context += f"\n{key.capitalize()}: {value}"
                ts_values[key] = value

        # Detect potential anomalies
        anomalies = []

        # Check for created == modified (suspicious for executables)
        if ts_values.get('created') and ts_values.get('modified'):
            if str(ts_values['created']) == str(ts_values['modified']):
                anomalies.append("Created equals Modified (potential timestomping or single-write operation)")

        # Check for modified before created (impossible - indicates tampering)
        if ts_values.get('created') and ts_values.get('modified'):
            try:
                if hasattr(ts_values['created'], 'timestamp') and hasattr(ts_values['modified'], 'timestamp'):
                    if ts_values['modified'].timestamp() < ts_values['created'].timestamp():
                        anomalies.append("CRITICAL: Modified timestamp BEFORE Created (definite tampering)")
            except (TypeError, AttributeError):
                pass

        # Check for future timestamps
        from datetime import datetime
        now = datetime.now()
        for key, value in ts_values.items():
            try:
                if hasattr(value, 'timestamp') and value.timestamp() > now.timestamp():
                    anomalies.append(f"CRITICAL: {key} timestamp is in the FUTURE (clock manipulation or tampering)")
            except (TypeError, AttributeError):
                pass

        if anomalies:
            context += "\n\n=== DETECTED ANOMALIES ===\n" + "\n".join(f"- {a}" for a in anomalies)

        prompt = f"""Analyze these NTFS timestamps for forensic significance:

{context}

Provide analysis covering:

1. **Timeline Reconstruction**: What does this timestamp pattern reveal about file activity?
   - When was the file truly created/modified?
   - What activity does the access pattern suggest?

2. **Authenticity Assessment**: Do these timestamps appear authentic?
   - Are there signs of timestomping ($STANDARD_INFO manipulation)?
   - Does the $FILE_NAME timestamp (if available) contradict $STANDARD_INFO?
   - Rate confidence: HIGH (authentic), MEDIUM (suspicious), LOW (likely tampered)

3. **Pattern Analysis**: What does this pattern indicate?
   - Normal user/system activity?
   - Automated malware behavior?
   - Deliberate anti-forensic manipulation?

4. **Corroboration**: What other evidence sources should be checked?
   - $UsnJrnl (USN Journal) for file operations
   - $MFT $FILE_NAME attribute for original timestamps
   - Prefetch files for execution times
   - Event logs for related activity

{self.CONFIDENCE_INSTRUCTION}

Be explicit about what can be definitively proven vs. what is inference."""

        artifact_id = filename or "timestamp_pattern"

        return self._query_groq(
            prompt,
            interaction_purpose="explain_timestamps",
            artifact_id=artifact_id,
            artifact_name=filename or "Timestamp Pattern",
            analysis_type="timestamp_analysis"
        )

    def generate_overwriting_story(self, carved_file: Dict, overwrite_data: Dict) -> str:
        """
        Generate deep forensic narrative for overwritten/deleted files.

        Args:
            carved_file: Dictionary containing:
                - name: filename
                - size: original size
                - deleted_time: when deleted
                - recovery_percentage: how much recovered
                - file_type: type of file (optional)
                - path: original path (optional)

            overwrite_data: Dictionary containing:
                - overwritten_by: list of (filename, timestamp, size)
                - timeline: chronological events
                - clusters_intact: number of intact clusters (optional)
                - clusters_total: total clusters (optional)
                - fragmentation_score: fragmentation indicator (optional)

        Returns:
            Deep forensic narrative with intentionality assessment
        """
        context = f"""=== DELETED FILE ANALYSIS ===
File: {carved_file.get('name', 'unknown')}
Original Size: {self._format_size(carved_file.get('size', 0))}
Deleted: {carved_file.get('deleted_time', 'unknown')}
Recovery Potential: {carved_file.get('recovery_percentage', 0):.1f}%"""

        if carved_file.get('path'):
            context += f"\nOriginal Path: {carved_file['path']}"
        if carved_file.get('file_type'):
            context += f"\nFile Type: {carved_file['file_type']}"

        # Cluster analysis for intentionality assessment
        clusters_intact = overwrite_data.get('clusters_intact')
        clusters_total = overwrite_data.get('clusters_total')
        if clusters_intact is not None and clusters_total is not None:
            context += f"\n\n=== CLUSTER ANALYSIS ==="
            context += f"\nIntact Clusters: {clusters_intact}/{clusters_total}"
            context += f"\nOverwritten Clusters: {clusters_total - clusters_intact}"
            overwrite_pct = ((clusters_total - clusters_intact) / clusters_total * 100) if clusters_total > 0 else 0
            context += f"\nOverwrite Percentage: {overwrite_pct:.1f}%"

        if overwrite_data.get('fragmentation_score'):
            context += f"\nFragmentation Score: {overwrite_data['fragmentation_score']}"

        if overwrite_data.get('overwritten_by'):
            context += "\n\n=== OVERWRITING FILES ==="
            for i, item in enumerate(overwrite_data['overwritten_by'][:5], 1):
                if isinstance(item, tuple) and len(item) >= 3:
                    filename, timestamp, size = item[0], item[1], item[2]
                    context += f"\n{i}. {filename}"
                    context += f"\n   Written: {timestamp}"
                    context += f"\n   Size: {self._format_size(size)}"
                elif isinstance(item, dict):
                    context += f"\n{i}. {item.get('name', 'unknown')}"
                    if item.get('timestamp'):
                        context += f"\n   Written: {item['timestamp']}"
                    if item.get('size'):
                        context += f"\n   Size: {self._format_size(item['size'])}"

        prompt = f"""Analyze this file destruction event for forensic significance:

{context}

Provide analysis covering:

1. **Chronological Narrative**: What happened to this file?
   - When was it deleted?
   - What overwrote it and when?
   - What is the timeline of events?

2. **Intentionality Assessment** (Critical for court):
   - Does the overwrite pattern suggest DELIBERATE destruction?
   - Or is this NORMAL system operation (temp files, logs, defrag)?
   - Rate confidence: HIGH (deliberate), MEDIUM (suspicious), LOW (likely incidental)

3. **Recovery Assessment**:
   - What percentage of data is potentially recoverable?
   - What forensic value might the intact portions contain?
   - Is the unrecovered portion forensically significant?

4. **Pattern Analysis**:
   - Do the overwriting files have any relationship to the deleted file?
   - Is there evidence of wiping tools (random data, sequential overwrite)?
   - Does timing suggest coordinated deletion activity?

5. **Recommendations**:
   - What recovery techniques should be attempted?
   - What related artifacts should be examined?
   - What timeline events should be correlated?

{self.CONFIDENCE_INSTRUCTION}

Write in professional language suitable for expert testimony in court."""

        carved_id = carved_file.get('id', carved_file.get('name', ''))

        return self._query_groq(
            prompt,
            interaction_purpose="overwrite_story",
            artifact_id=str(carved_id),
            artifact_name=carved_file.get('name', ''),
            analysis_type="overwrite_analysis"
        )

    def explain_risk_score(self, artifact: Dict, score: int, reasons: List[str]) -> str:
        """
        Generate deep forensic explanation for why an artifact received a risk score.

        This is the primary AI analysis method used in the Priority Tab for explaining
        why files were flagged as suspicious. Provides court-ready structured analysis.

        Args:
            artifact: Artifact data dictionary containing:
                - name: filename
                - path: full path
                - size: file size
                - created/modified/accessed: timestamps
                - type: file type
                - overwrite_analysis: cluster analysis data (optional)
                - entropy: file entropy (optional)
                - md5/sha256: hashes (optional)
            score: Risk score (0-100)
            reasons: List of triggered rule codes

        Returns:
            Structured forensic explanation with facts, interpretation,
            alternative hypotheses, and recommendations
        """
        # Build comprehensive artifact context
        context = f"""=== RISK ASSESSMENT ANALYSIS ===
Artifact: {artifact.get('name', 'unknown')}
Path: {artifact.get('path', 'unknown')}
Size: {self._format_size(artifact.get('size', 0))} ({artifact.get('size', 0):,} bytes)
Type: {artifact.get('type', 'unknown')}"""

        # Add risk score with severity context
        risk_context = self._build_risk_context(artifact, score, reasons)
        context += f"\n\n{risk_context}"

        # Add timestamps with forensic context
        context += "\n\n=== TIMESTAMPS ==="
        if artifact.get('created'):
            context += f"\nCreated: {artifact.get('created')}"
        if artifact.get('modified'):
            context += f"\nModified: {artifact.get('modified')}"
        if artifact.get('accessed'):
            context += f"\nAccessed: {artifact.get('accessed')}"
        if artifact.get('changed'):
            context += f"\nMetadata Changed: {artifact.get('changed')}"

        # Add forensic indicators
        forensic_context = self._build_forensic_context(artifact)
        if forensic_context:
            context += f"\n\n=== FORENSIC INDICATORS ===\n{forensic_context}"

        # Add overwrite analysis if available (critical for deleted files)
        if artifact.get('overwrite_analysis'):
            oa = artifact['overwrite_analysis']
            context += f"\n\n=== CLUSTER/OVERWRITE ANALYSIS ==="
            if hasattr(oa, 'overwrite_risk_pct'):
                context += f"\nOverwrite Risk: {oa.overwrite_risk_pct}%"
            if hasattr(oa, 'clusters_intact') and hasattr(oa, 'clusters_total'):
                context += f"\nCluster Status: {oa.clusters_intact}/{oa.clusters_total} intact"
                recovery_pct = (oa.clusters_intact / oa.clusters_total * 100) if oa.clusters_total > 0 else 0
                context += f"\nRecovery Potential: {recovery_pct:.1f}%"
            if hasattr(oa, 'overwritten_by') and oa.overwritten_by:
                context += "\nOverwritten by:"
                import os
                for i, item in enumerate(oa.overwritten_by[:3], 1):
                    if isinstance(item, tuple) and len(item) >= 1:
                        context += f"\n  {i}. {os.path.basename(str(item[0]))}"
                    elif isinstance(item, str):
                        context += f"\n  {i}. {os.path.basename(item)}"

        # Add hash information for threat intel context
        if artifact.get('md5'):
            context += f"\n\nMD5: {artifact['md5']}"
        if artifact.get('sha256'):
            context += f"\nSHA256: {artifact['sha256']}"

        prompt = f"""Analyze this high-risk artifact and explain the risk assessment:

{context}

Structure your response EXACTLY as follows:

**FACTS** (Direct evidence only - cite the source)
- List only what can be definitively determined from the metadata
- Cite sources: "from MFT timestamps", "from file attributes", "from cluster analysis"
- Include: timestamps, size, location, entropy, cluster status

**INTERPRETATION** (State confidence level)
- What does this evidence pattern indicate?
- Is this consistent with malicious activity, user error, or legitimate use?
- Confidence: HIGH (strong evidence) / MEDIUM (probable) / LOW (speculative)

**ALTERNATIVE HYPOTHESES**
- What other explanations cannot be ruled out?
- What evidence would distinguish between hypotheses?

**RECOMMENDATIONS** (Prioritized by forensic value)
- Specific next investigative steps
- What additional artifacts should be examined?
- What external resources should be queried (VirusTotal, NSRL, etc.)?

Be precise, cite evidence sources, and distinguish between facts and inferences.
This analysis may be used in legal proceedings - maintain forensic rigor."""

        artifact_id = str(artifact.get('inode', artifact.get('hash', artifact.get('name', ''))))

        return self._query_groq(
            prompt,
            interaction_purpose="explain_risk",
            artifact_id=artifact_id,
            artifact_name=artifact.get('name', ''),
            analysis_type="risk_analysis"
        )

    def evaluate_risk_contextually(self, artifact: Dict, rule_score: int,
                                    triggered_rules: List[str],
                                    matched_patterns: List[Dict] = None,
                                    related_artifacts: Dict = None,
                                    case_context: Dict = None) -> Dict:
        """
        AI-powered contextual risk evaluation for hybrid scoring.

        Goes beyond static rules to reason about:
        - Is this a likely false positive?
        - Does context make this more or less suspicious?
        - What's the relationship to other artifacts?

        Args:
            artifact: Artifact data dictionary
            rule_score: Initial score from rule engine
            triggered_rules: List of rules that fired
            matched_patterns: Behavioral patterns detected
            related_artifacts: Temporally/spatially related artifacts
            case_context: Investigation context (case type, key timestamps)

        Returns:
            Dictionary with:
                - adjusted_score: int (0-100)
                - score_adjustment: int (delta from rule_score)
                - false_positive_likelihood: float (0.0-1.0)
                - attack_chain_detected: bool
                - attack_chain_stage: str or None
                - confidence: str ('high', 'medium', 'low')
                - reasoning: str
                - recommendations: List[str]
        """
        matched_patterns = matched_patterns or []
        related_artifacts = related_artifacts or {}
        case_context = case_context or {}

        # Build context for AI evaluation
        context = f"""=== CONTEXTUAL RISK EVALUATION ===

Artifact: {artifact.get('name', 'unknown')}
Path: {artifact.get('path', 'unknown')}
Size: {self._format_size(artifact.get('size', 0))}
Type: {artifact.get('type', 'unknown')}

Initial Rule Score: {rule_score}/100
Case Type: {case_context.get('type', 'general')}
"""

        # Add triggered rules
        if triggered_rules:
            context += "\n=== TRIGGERED RULES ===\n"
            for rule in triggered_rules:
                significance = self.RULE_SIGNIFICANCE.get(rule, rule)
                context += f"  - {rule}: {significance}\n"

        # Add matched behavioral patterns
        if matched_patterns:
            context += "\n=== BEHAVIORAL PATTERNS DETECTED ===\n"
            for pattern in matched_patterns:
                context += f"  - {pattern.get('name', 'Unknown')}\n"
                context += f"    Description: {pattern.get('description', '')}\n"
                context += f"    Attack Stage: {pattern.get('attack_stage', 'unknown')}\n"
                context += f"    MITRE ATT&CK: {pattern.get('mitre_attack', 'N/A')}\n"

        # Add related artifacts
        temporal = related_artifacts.get('temporal', [])
        spatial = related_artifacts.get('spatial', [])

        if temporal or spatial:
            context += "\n=== RELATED ARTIFACTS ===\n"

            if temporal:
                context += f"\nTemporal Neighbors ({len(temporal)} files modified within 5 minutes):\n"
                for rel in temporal[:5]:
                    context += f"  - {rel.get('name', 'unknown')} (risk: {rel.get('risk_score', 0)})\n"

            if spatial:
                context += f"\nSpatial Neighbors ({len(spatial)} files in same directory):\n"
                for rel in spatial[:5]:
                    context += f"  - {rel.get('name', 'unknown')} (risk: {rel.get('risk_score', 0)})\n"

        # Add key investigation timestamps
        key_timestamps = case_context.get('key_timestamps', [])
        if key_timestamps:
            context += "\n=== KEY INVESTIGATION TIMESTAMPS ===\n"
            for ts, desc in key_timestamps[:5]:
                context += f"  - {ts}: {desc}\n"

        prompt = f"""{context}

Evaluate this artifact's TRUE risk level considering all available context.

Respond with a JSON object (and ONLY a JSON object) in this exact format:
{{
    "adjusted_score": <0-100>,
    "score_adjustment": <negative or positive integer, how much to change from {rule_score}>,
    "false_positive_likelihood": <0.0-1.0>,
    "attack_chain_detected": <true or false>,
    "attack_chain_stage": "<initial_access|execution|persistence|defense_evasion|collection|exfiltration|null>",
    "confidence": "<high|medium|low>",
    "reasoning": "<1-2 sentence explanation of your assessment>",
    "recommendations": ["<recommendation 1>", "<recommendation 2>", "<recommendation 3>"]
}}

Guidelines for scoring:
- INCREASE score if: patterns form attack chain, multiple related high-risk files, timing matches key events
- DECREASE score if: likely false positive (legitimate software, common system behavior), no supporting context
- MAINTAIN score if: evidence is ambiguous, need more investigation

Be conservative with adjustments. Maximum adjustment: +/-20 points."""

        try:
            response = self._query_groq(
                prompt,
                interaction_purpose="contextual_risk_eval",
                artifact_id=str(artifact.get('inode', artifact.get('name', ''))),
                artifact_name=artifact.get('name', ''),
                analysis_type="risk_analysis"
            )

            # Parse JSON response
            import json
            import re

            # Try to extract JSON from response
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())

                # Validate and normalize
                result['adjusted_score'] = max(0, min(100, int(result.get('adjusted_score', rule_score))))
                result['score_adjustment'] = int(result.get('score_adjustment', 0))
                result['false_positive_likelihood'] = float(result.get('false_positive_likelihood', 0.5))
                result['attack_chain_detected'] = bool(result.get('attack_chain_detected', False))
                result['confidence'] = result.get('confidence', 'medium')
                result['reasoning'] = result.get('reasoning', '')
                result['recommendations'] = result.get('recommendations', [])

                return result

        except Exception as e:
            print(f"Warning: AI contextual evaluation parsing failed: {e}")

        # Return neutral result on failure
        return {
            'adjusted_score': rule_score,
            'score_adjustment': 0,
            'false_positive_likelihood': 0.5,
            'attack_chain_detected': False,
            'attack_chain_stage': None,
            'confidence': 'low',
            'reasoning': 'AI evaluation failed - using rule-based score',
            'recommendations': []
        }

    def _query_groq(self, prompt: str, interaction_purpose: str = "",
                    artifact_id: str = "", artifact_name: str = "",
                    analysis_type: str = "file_analysis") -> str:
        """
        Send query to Groq API with audit logging and domain-specific prompting.

        Args:
            prompt: The prompt to send
            interaction_purpose: Purpose of interaction (for audit log)
            artifact_id: Associated artifact ID
            artifact_name: Associated artifact name
            analysis_type: Type of analysis for selecting system prompt and token limit
                          Options: file_analysis, registry_analysis, risk_analysis,
                                   timestamp_analysis, overwrite_analysis

        Returns:
            AI-generated response
        """
        if not self.api_key:
            return "Error: Groq API key not configured. Go to Options > API Keys to set it up."

        start_time = time.time()
        temperature = 0.3
        top_p = 0.9
        response_text = ""
        error_occurred = False

        # Select domain-specific system prompt and token limit
        system_prompt = self.FORENSIC_SYSTEM_PROMPTS.get(
            analysis_type,
            self.FORENSIC_SYSTEM_PROMPTS['file_analysis']
        )
        max_tokens = self.TOKEN_LIMITS.get(analysis_type, 600)

        try:
            response = requests.post(
                self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": system_prompt
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": temperature,
                    "top_p": top_p,
                    "max_tokens": max_tokens
                },
                timeout=self.timeout
            )

            duration_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                result = response.json()
                response_text = result['choices'][0]['message']['content'].strip()
            elif response.status_code == 401:
                response_text = "Error: Invalid Groq API key. Please check your API key in Options > API Keys."
                error_occurred = True
            elif response.status_code == 429:
                response_text = "Error: Rate limit exceeded. Please wait a moment and try again."
                error_occurred = True
            else:
                response_text = f"Error: Groq API returned status {response.status_code}"
                error_occurred = True

        except requests.exceptions.ConnectionError:
            duration_ms = int((time.time() - start_time) * 1000)
            response_text = "Error: Cannot connect to Groq API. Please check your internet connection."
            error_occurred = True

        except requests.exceptions.Timeout:
            duration_ms = int((time.time() - start_time) * 1000)
            response_text = "Error: Request timed out."
            error_occurred = True

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            response_text = f"Error: {str(e)}"
            error_occurred = True

        # === CONFIDENCE TRACKING ===
        parsed_confidence = 0.0
        if self.confidence_tracker and not error_occurred and CONFIDENCE_AVAILABLE:
            try:
                parsed_confidence = self.confidence_tracker.parse_ai_confidence(response_text)

                fact_description = f"AI {interaction_purpose}: {artifact_name}" if artifact_name else f"AI {interaction_purpose}"
                self.confidence_tracker.add_fact(
                    fact_type=FactType.INFERRED,
                    description=fact_description,
                    value=response_text[:200] + "..." if len(response_text) > 200 else response_text,
                    confidence_score=parsed_confidence,
                    source=f"AI Model: {self.model}",
                    artifact_id=artifact_id,
                    artifact_name=artifact_name,
                    reasoning=f"Parsed from AI response linguistic patterns",
                    evidence=[f"Temperature: {temperature}", f"Model: {self.model}"]
                )

                if parsed_confidence < 0.5:
                    self.confidence_tracker.add_uncertainty(
                        indicator_type="ai_speculation",
                        severity="medium",
                        description=f"AI response has low confidence ({parsed_confidence:.1%}) for {interaction_purpose}",
                        mitigation="Corroborate with additional evidence or manual analysis",
                        affected_artifacts=[artifact_id] if artifact_id else []
                    )
            except Exception as e:
                print(f"Warning: Confidence tracking failed: {e}")

        # === AUDIT LOGGING ===
        if self.audit_logger:
            try:
                self.audit_logger.log_ai_interaction(
                    model=self.model,
                    prompt=prompt,
                    response=response_text,
                    duration_ms=duration_ms,
                    artifact_id=artifact_id,
                    artifact_name=artifact_name,
                    interaction_purpose=interaction_purpose,
                    base_url=self.base_url,
                    temperature=temperature,
                    top_p=top_p,
                    confidence=parsed_confidence if parsed_confidence > 0 else None,
                    uncertainty_factors=["Error occurred"] if error_occurred else (
                        ["Low confidence AI response"] if parsed_confidence < 0.5 else []
                    )
                )
            except Exception as e:
                print(f"Warning: AI interaction audit logging failed: {e}")

        return response_text

    # =========================================================================
    # Async Support
    # =========================================================================

    @property
    def async_client(self):
        """Lazy-initialized async HTTP client with connection pooling."""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
            )
        return self._async_client

    async def close(self):
        """Close the async HTTP client."""
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None

    async def _query_groq_async(self, prompt: str, interaction_purpose: str = "",
                                artifact_id: str = "", artifact_name: str = "",
                                analysis_type: str = "file_analysis") -> str:
        """
        Async version of _query_groq. Send query to Groq API using httpx async client.

        Args:
            prompt: The prompt to send
            interaction_purpose: Purpose of interaction (for audit log)
            artifact_id: Associated artifact ID
            artifact_name: Associated artifact name
            analysis_type: Type of analysis for selecting system prompt and token limit

        Returns:
            AI-generated response
        """
        if not self.api_key:
            return "Error: Groq API key not configured. Go to Options > API Keys to set it up."

        start_time = time.time()
        temperature = 0.3
        top_p = 0.9
        response_text = ""
        error_occurred = False

        # Select domain-specific system prompt and token limit
        system_prompt = self.FORENSIC_SYSTEM_PROMPTS.get(
            analysis_type,
            self.FORENSIC_SYSTEM_PROMPTS['file_analysis']
        )
        max_tokens = self.TOKEN_LIMITS.get(analysis_type, 600)

        try:
            response = await self.async_client.post(
                self.base_url,
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": system_prompt
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": temperature,
                    "top_p": top_p,
                    "max_tokens": max_tokens
                }
            )

            duration_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                result = response.json()
                response_text = result['choices'][0]['message']['content'].strip()
            elif response.status_code == 401:
                response_text = "Error: Invalid Groq API key. Please check your API key in Options > API Keys."
                error_occurred = True
            elif response.status_code == 429:
                response_text = "Error: Rate limit exceeded. Please wait a moment and try again."
                error_occurred = True
            else:
                response_text = f"Error: Groq API returned status {response.status_code}"
                error_occurred = True

        except httpx.ConnectError:
            duration_ms = int((time.time() - start_time) * 1000)
            response_text = "Error: Cannot connect to Groq API. Please check your internet connection."
            error_occurred = True

        except httpx.TimeoutException:
            duration_ms = int((time.time() - start_time) * 1000)
            response_text = "Error: Request timed out."
            error_occurred = True

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            response_text = f"Error: {str(e)}"
            error_occurred = True

        # === CONFIDENCE TRACKING ===
        parsed_confidence = 0.0
        if self.confidence_tracker and not error_occurred and CONFIDENCE_AVAILABLE:
            try:
                parsed_confidence = self.confidence_tracker.parse_ai_confidence(response_text)

                fact_description = f"AI {interaction_purpose}: {artifact_name}" if artifact_name else f"AI {interaction_purpose}"
                self.confidence_tracker.add_fact(
                    fact_type=FactType.INFERRED,
                    description=fact_description,
                    value=response_text[:200] + "..." if len(response_text) > 200 else response_text,
                    confidence_score=parsed_confidence,
                    source=f"AI Model: {self.model}",
                    artifact_id=artifact_id,
                    artifact_name=artifact_name,
                    reasoning=f"Parsed from AI response linguistic patterns",
                    evidence=[f"Temperature: {temperature}", f"Model: {self.model}"]
                )

                if parsed_confidence < 0.5:
                    self.confidence_tracker.add_uncertainty(
                        indicator_type="ai_speculation",
                        severity="medium",
                        description=f"AI response has low confidence ({parsed_confidence:.1%}) for {interaction_purpose}",
                        mitigation="Corroborate with additional evidence or manual analysis",
                        affected_artifacts=[artifact_id] if artifact_id else []
                    )
            except Exception as e:
                print(f"Warning: Confidence tracking failed: {e}")

        # === AUDIT LOGGING ===
        if self.audit_logger:
            try:
                self.audit_logger.log_ai_interaction(
                    model=self.model,
                    prompt=prompt,
                    response=response_text,
                    duration_ms=duration_ms,
                    artifact_id=artifact_id,
                    artifact_name=artifact_name,
                    interaction_purpose=interaction_purpose,
                    base_url=self.base_url,
                    temperature=temperature,
                    top_p=top_p,
                    confidence=parsed_confidence if parsed_confidence > 0 else None,
                    uncertainty_factors=["Error occurred"] if error_occurred else (
                        ["Low confidence AI response"] if parsed_confidence < 0.5 else []
                    )
                )
            except Exception as e:
                print(f"Warning: AI interaction audit logging failed: {e}")

        return response_text

    async def explain_file_artifact_async(self, file_data: Dict) -> str:
        """Async version of explain_file_artifact."""
        # Build basic metadata context
        context = f"""=== FILE ARTIFACT ANALYSIS ===
File: {file_data.get('name', 'unknown')}"""

        if file_data.get('path'):
            context += f"\nFull Path: {file_data['path']}"

        context += f"\nType: {file_data.get('type', 'unknown')}"

        if file_data.get('mime_type'):
            context += f"\nMIME Type: {file_data['mime_type']}"

        if file_data.get('size'):
            size = file_data['size']
            context += f"\nSize: {self._format_size(size)} ({size:,} bytes)"

        context += "\n\n=== TIMESTAMPS ==="
        if file_data.get('created'):
            context += f"\nCreated (birth): {file_data['created']}"
        if file_data.get('modified'):
            context += f"\nModified (mtime): {file_data['modified']}"
        if file_data.get('accessed'):
            context += f"\nAccessed (atime): {file_data['accessed']}"
        if file_data.get('changed'):
            context += f"\nMetadata Changed (ctime): {file_data['changed']}"

        forensic_context = self._build_forensic_context(file_data)
        if forensic_context:
            context += f"\n\n=== FORENSIC INDICATORS ===\n{forensic_context}"

        prompt = f"""Analyze this file artifact using forensic methodology:

{context}

{self.REASONING_FRAMEWORK}

{self.CONFIDENCE_INSTRUCTION}

Provide a thorough but concise analysis covering:
1. **Identity**: What is this file? What does it do?
2. **Forensic Significance**: Why should an investigator care about this artifact?
3. **Timeline Analysis**: What do the timestamps reveal about file activity?
4. **Risk Assessment**: Any indicators of malicious activity or tampering?
5. **Next Steps**: What should the investigator examine next?

Be precise and cite evidence sources (e.g., "from MFT timestamps", "based on file location")."""

        artifact_id = str(file_data.get('inode', file_data.get('hash', file_data.get('name', ''))))

        return await self._query_groq_async(
            prompt,
            interaction_purpose="explain_file",
            artifact_id=artifact_id,
            artifact_name=file_data.get('name', ''),
            analysis_type="file_analysis"
        )

    async def explain_risk_score_async(self, artifact: Dict, score: int, reasons: List[str]) -> str:
        """Async version of explain_risk_score."""
        context = f"""=== RISK ASSESSMENT ANALYSIS ===
Artifact: {artifact.get('name', 'unknown')}
Path: {artifact.get('path', 'unknown')}
Size: {self._format_size(artifact.get('size', 0))} ({artifact.get('size', 0):,} bytes)
Type: {artifact.get('type', 'unknown')}"""

        risk_context = self._build_risk_context(artifact, score, reasons)
        context += f"\n\n{risk_context}"

        context += "\n\n=== TIMESTAMPS ==="
        if artifact.get('created'):
            context += f"\nCreated: {artifact.get('created')}"
        if artifact.get('modified'):
            context += f"\nModified: {artifact.get('modified')}"
        if artifact.get('accessed'):
            context += f"\nAccessed: {artifact.get('accessed')}"
        if artifact.get('changed'):
            context += f"\nMetadata Changed: {artifact.get('changed')}"

        forensic_context = self._build_forensic_context(artifact)
        if forensic_context:
            context += f"\n\n=== FORENSIC INDICATORS ===\n{forensic_context}"

        if artifact.get('overwrite_analysis'):
            oa = artifact['overwrite_analysis']
            context += f"\n\n=== CLUSTER/OVERWRITE ANALYSIS ==="
            if hasattr(oa, 'overwrite_risk_pct'):
                context += f"\nOverwrite Risk: {oa.overwrite_risk_pct}%"
            if hasattr(oa, 'clusters_intact') and hasattr(oa, 'clusters_total'):
                context += f"\nCluster Status: {oa.clusters_intact}/{oa.clusters_total} intact"
                recovery_pct = (oa.clusters_intact / oa.clusters_total * 100) if oa.clusters_total > 0 else 0
                context += f"\nRecovery Potential: {recovery_pct:.1f}%"
            if hasattr(oa, 'overwritten_by') and oa.overwritten_by:
                context += "\nOverwritten by:"
                import os
                for i, item in enumerate(oa.overwritten_by[:3], 1):
                    if isinstance(item, tuple) and len(item) >= 1:
                        context += f"\n  {i}. {os.path.basename(str(item[0]))}"
                    elif isinstance(item, str):
                        context += f"\n  {i}. {os.path.basename(item)}"

        if artifact.get('md5'):
            context += f"\n\nMD5: {artifact['md5']}"
        if artifact.get('sha256'):
            context += f"\nSHA256: {artifact['sha256']}"

        prompt = f"""Analyze this high-risk artifact and explain the risk assessment:

{context}

Structure your response EXACTLY as follows:

**FACTS** (Direct evidence only - cite the source)
- List only what can be definitively determined from the metadata
- Cite sources: "from MFT timestamps", "from file attributes", "from cluster analysis"
- Include: timestamps, size, location, entropy, cluster status

**INTERPRETATION** (State confidence level)
- What does this evidence pattern indicate?
- Is this consistent with malicious activity, user error, or legitimate use?
- Confidence: HIGH (strong evidence) / MEDIUM (probable) / LOW (speculative)

**ALTERNATIVE HYPOTHESES**
- What other explanations cannot be ruled out?
- What evidence would distinguish between hypotheses?

**RECOMMENDATIONS** (Prioritized by forensic value)
- Specific next investigative steps
- What additional artifacts should be examined?
- What external resources should be queried (VirusTotal, NSRL, etc.)?

Be precise, cite evidence sources, and distinguish between facts and inferences.
This analysis may be used in legal proceedings - maintain forensic rigor."""

        artifact_id = str(artifact.get('inode', artifact.get('hash', artifact.get('name', ''))))

        return await self._query_groq_async(
            prompt,
            interaction_purpose="explain_risk",
            artifact_id=artifact_id,
            artifact_name=artifact.get('name', ''),
            analysis_type="risk_analysis"
        )

    async def explain_registry_key_async(self, key_path: str, values: List[Dict] = None,
                                          last_modified: str = None, subkey_count: int = None,
                                          value_count: int = None) -> str:
        """Async version of explain_registry_key."""
        key_parts = key_path.split('\\') if key_path else []
        hive = key_parts[0] if key_parts else "Unknown"
        key_name = key_parts[-1] if key_parts else "Unknown"

        context = f"""=== REGISTRY KEY ANALYSIS ===
Full Path: {key_path}
Hive: {hive}
Key Name: {key_name}"""

        if last_modified:
            context += f"\nLast Modified: {last_modified}"
        if subkey_count is not None:
            context += f"\nSubkeys: {subkey_count}"
        if value_count is not None:
            context += f"\nValues: {value_count}"

        path_lower = key_path.lower() if key_path else ""
        key_category = []

        if 'run' in path_lower and ('currentversion\\run' in path_lower or 'policies\\explorer\\run' in path_lower):
            key_category.append("PERSISTENCE MECHANISM (auto-run at startup)")
        if 'services' in path_lower and 'currentcontrolset\\services' in path_lower:
            key_category.append("WINDOWS SERVICE (potential persistence)")
        if 'userassist' in path_lower:
            key_category.append("USER ACTIVITY TRACKING (program execution history)")
        if 'recentdocs' in path_lower:
            key_category.append("RECENT DOCUMENTS (file access history)")
        if 'typedpaths' in path_lower or 'typedurls' in path_lower:
            key_category.append("USER INPUT HISTORY (typed paths/URLs)")
        if 'shellbags' in path_lower or 'bagmru' in path_lower:
            key_category.append("FOLDER ACCESS HISTORY (ShellBags)")
        if 'mounteddevices' in path_lower or 'usbstor' in path_lower:
            key_category.append("USB/STORAGE DEVICE HISTORY")
        if 'networkprofile' in path_lower or 'networkservice' in path_lower:
            key_category.append("NETWORK CONNECTION HISTORY")
        if 'appcompatcache' in path_lower or 'shimcache' in path_lower:
            key_category.append("APPLICATION EXECUTION (ShimCache)")

        if key_category:
            context += f"\n\n=== FORENSIC CATEGORY ===\n" + "\n".join(key_category)

        if values:
            context += "\n\n=== VALUES ==="
            for val in values[:8]:
                val_name = val.get('name', '(Default)')
                val_type = val.get('type', 'Unknown')
                val_data = val.get('data', '')
                if isinstance(val_data, str) and len(val_data) > 100:
                    val_data = val_data[:100] + "..."
                context += f"\n  {val_name} ({val_type}): {val_data}"

        prompt = f"""Analyze this Windows registry key using forensic methodology:

{context}

Provide analysis covering:

1. **Key Purpose**: What does this registry key control in Windows?

2. **Forensic Significance**: What can an investigator learn from this key?
   - What user/system activity does it reveal?
   - What timeline information can be extracted?

3. **Value Analysis**: What do the specific values indicate?
   - Any suspicious or anomalous values?
   - Evidence of tampering or malicious configuration?

4. **MITRE ATT&CK**: If this key relates to known attack techniques, cite the relevant:
   - Technique ID (e.g., T1547.001 for Run key persistence)
   - Tactic (e.g., Persistence, Defense Evasion)

5. **Related Keys**: What other registry locations should be examined for correlation?

{self.CONFIDENCE_INSTRUCTION}

Be precise about what can be definitively determined vs. what requires further investigation."""

        return await self._query_groq_async(
            prompt,
            interaction_purpose="explain_registry",
            artifact_id=key_path,
            artifact_name=key_name,
            analysis_type="registry_analysis"
        )

    async def explain_timestamp_pattern_async(self, timestamps: Dict, filename: str = None,
                                               file_type: str = None, file_path: str = None) -> str:
        """Async version of explain_timestamp_pattern."""
        context = "=== TIMESTAMP ANALYSIS ==="

        if filename:
            context += f"\nFile: {filename}"
        if file_path:
            context += f"\nPath: {file_path}"
        if file_type:
            context += f"\nType: {file_type}"

        context += "\n\n=== NTFS TIMESTAMPS ==="

        ts_values = {}
        for key, value in timestamps.items():
            if value:
                context += f"\n{key.capitalize()}: {value}"
                ts_values[key] = value

        anomalies = []

        if ts_values.get('created') and ts_values.get('modified'):
            if str(ts_values['created']) == str(ts_values['modified']):
                anomalies.append("Created equals Modified (potential timestomping or single-write operation)")

        if ts_values.get('created') and ts_values.get('modified'):
            try:
                if hasattr(ts_values['created'], 'timestamp') and hasattr(ts_values['modified'], 'timestamp'):
                    if ts_values['modified'].timestamp() < ts_values['created'].timestamp():
                        anomalies.append("CRITICAL: Modified timestamp BEFORE Created (definite tampering)")
            except (TypeError, AttributeError):
                pass

        from datetime import datetime as dt_class
        now = dt_class.now()
        for key, value in ts_values.items():
            try:
                if hasattr(value, 'timestamp') and value.timestamp() > now.timestamp():
                    anomalies.append(f"CRITICAL: {key} timestamp is in the FUTURE (clock manipulation or tampering)")
            except (TypeError, AttributeError):
                pass

        if anomalies:
            context += "\n\n=== DETECTED ANOMALIES ===\n" + "\n".join(f"- {a}" for a in anomalies)

        prompt = f"""Analyze these NTFS timestamps for forensic significance:

{context}

Provide analysis covering:

1. **Timeline Reconstruction**: What does this timestamp pattern reveal about file activity?
   - When was the file truly created/modified?
   - What activity does the access pattern suggest?

2. **Authenticity Assessment**: Do these timestamps appear authentic?
   - Are there signs of timestomping ($STANDARD_INFO manipulation)?
   - Does the $FILE_NAME timestamp (if available) contradict $STANDARD_INFO?
   - Rate confidence: HIGH (authentic), MEDIUM (suspicious), LOW (likely tampered)

3. **Pattern Analysis**: What does this pattern indicate?
   - Normal user/system activity?
   - Automated malware behavior?
   - Deliberate anti-forensic manipulation?

4. **Corroboration**: What other evidence sources should be checked?
   - $UsnJrnl (USN Journal) for file operations
   - $MFT $FILE_NAME attribute for original timestamps
   - Prefetch files for execution times
   - Event logs for related activity

{self.CONFIDENCE_INSTRUCTION}

Be explicit about what can be definitively proven vs. what is inference."""

        artifact_id = filename or "timestamp_pattern"

        return await self._query_groq_async(
            prompt,
            interaction_purpose="explain_timestamps",
            artifact_id=artifact_id,
            artifact_name=filename or "Timestamp Pattern",
            analysis_type="timestamp_analysis"
        )

    async def generate_overwriting_story_async(self, carved_file: Dict, overwrite_data: Dict) -> str:
        """Async version of generate_overwriting_story."""
        context = f"""=== DELETED FILE ANALYSIS ===
File: {carved_file.get('name', 'unknown')}
Original Size: {self._format_size(carved_file.get('size', 0))}
Deleted: {carved_file.get('deleted_time', 'unknown')}
Recovery Potential: {carved_file.get('recovery_percentage', 0):.1f}%"""

        if carved_file.get('path'):
            context += f"\nOriginal Path: {carved_file['path']}"
        if carved_file.get('file_type'):
            context += f"\nFile Type: {carved_file['file_type']}"

        clusters_intact = overwrite_data.get('clusters_intact')
        clusters_total = overwrite_data.get('clusters_total')
        if clusters_intact is not None and clusters_total is not None:
            context += f"\n\n=== CLUSTER ANALYSIS ==="
            context += f"\nIntact Clusters: {clusters_intact}/{clusters_total}"
            context += f"\nOverwritten Clusters: {clusters_total - clusters_intact}"
            overwrite_pct = ((clusters_total - clusters_intact) / clusters_total * 100) if clusters_total > 0 else 0
            context += f"\nOverwrite Percentage: {overwrite_pct:.1f}%"

        if overwrite_data.get('fragmentation_score'):
            context += f"\nFragmentation Score: {overwrite_data['fragmentation_score']}"

        if overwrite_data.get('overwritten_by'):
            context += "\n\n=== OVERWRITING FILES ==="
            for i, item in enumerate(overwrite_data['overwritten_by'][:5], 1):
                if isinstance(item, tuple) and len(item) >= 3:
                    filename, timestamp, size = item[0], item[1], item[2]
                    context += f"\n{i}. {filename}"
                    context += f"\n   Written: {timestamp}"
                    context += f"\n   Size: {self._format_size(size)}"
                elif isinstance(item, dict):
                    context += f"\n{i}. {item.get('name', 'unknown')}"
                    if item.get('timestamp'):
                        context += f"\n   Written: {item['timestamp']}"
                    if item.get('size'):
                        context += f"\n   Size: {self._format_size(item['size'])}"

        prompt = f"""Analyze this file destruction event for forensic significance:

{context}

Provide analysis covering:

1. **Chronological Narrative**: What happened to this file?
   - When was it deleted?
   - What overwrote it and when?
   - What is the timeline of events?

2. **Intentionality Assessment** (Critical for court):
   - Does the overwrite pattern suggest DELIBERATE destruction?
   - Or is this NORMAL system operation (temp files, logs, defrag)?
   - Rate confidence: HIGH (deliberate), MEDIUM (suspicious), LOW (likely incidental)

3. **Recovery Assessment**:
   - What percentage of data is potentially recoverable?
   - What forensic value might the intact portions contain?
   - Is the unrecovered portion forensically significant?

4. **Pattern Analysis**:
   - Do the overwriting files have any relationship to the deleted file?
   - Is there evidence of wiping tools (random data, sequential overwrite)?
   - Does timing suggest coordinated deletion activity?

5. **Recommendations**:
   - What recovery techniques should be attempted?
   - What related artifacts should be examined?
   - What timeline events should be correlated?

{self.CONFIDENCE_INSTRUCTION}

Write in professional language suitable for expert testimony in court."""

        carved_id = carved_file.get('id', carved_file.get('name', ''))

        return await self._query_groq_async(
            prompt,
            interaction_purpose="overwrite_story",
            artifact_id=str(carved_id),
            artifact_name=carved_file.get('name', ''),
            analysis_type="overwrite_analysis"
        )

    async def evaluate_risk_contextually_async(self, artifact: Dict, rule_score: int,
                                                triggered_rules: List[str],
                                                matched_patterns: List[Dict] = None,
                                                related_artifacts: Dict = None,
                                                case_context: Dict = None) -> Dict:
        """Async version of evaluate_risk_contextually."""
        matched_patterns = matched_patterns or []
        related_artifacts = related_artifacts or {}
        case_context = case_context or {}

        context = f"""=== CONTEXTUAL RISK EVALUATION ===

Artifact: {artifact.get('name', 'unknown')}
Path: {artifact.get('path', 'unknown')}
Size: {self._format_size(artifact.get('size', 0))}
Type: {artifact.get('type', 'unknown')}

Initial Rule Score: {rule_score}/100
Case Type: {case_context.get('type', 'general')}
"""

        if triggered_rules:
            context += "\n=== TRIGGERED RULES ===\n"
            for rule in triggered_rules:
                significance = self.RULE_SIGNIFICANCE.get(rule, rule)
                context += f"  - {rule}: {significance}\n"

        if matched_patterns:
            context += "\n=== BEHAVIORAL PATTERNS DETECTED ===\n"
            for pattern in matched_patterns:
                context += f"  - {pattern.get('name', 'Unknown')}\n"
                context += f"    Description: {pattern.get('description', '')}\n"
                context += f"    Attack Stage: {pattern.get('attack_stage', 'unknown')}\n"
                context += f"    MITRE ATT&CK: {pattern.get('mitre_attack', 'N/A')}\n"

        temporal = related_artifacts.get('temporal', [])
        spatial = related_artifacts.get('spatial', [])

        if temporal or spatial:
            context += "\n=== RELATED ARTIFACTS ===\n"

            if temporal:
                context += f"\nTemporal Neighbors ({len(temporal)} files modified within 5 minutes):\n"
                for rel in temporal[:5]:
                    context += f"  - {rel.get('name', 'unknown')} (risk: {rel.get('risk_score', 0)})\n"

            if spatial:
                context += f"\nSpatial Neighbors ({len(spatial)} files in same directory):\n"
                for rel in spatial[:5]:
                    context += f"  - {rel.get('name', 'unknown')} (risk: {rel.get('risk_score', 0)})\n"

        key_timestamps = case_context.get('key_timestamps', [])
        if key_timestamps:
            context += "\n=== KEY INVESTIGATION TIMESTAMPS ===\n"
            for ts, desc in key_timestamps[:5]:
                context += f"  - {ts}: {desc}\n"

        prompt = f"""{context}

Evaluate this artifact's TRUE risk level considering all available context.

Respond with a JSON object (and ONLY a JSON object) in this exact format:
{{
    "adjusted_score": <0-100>,
    "score_adjustment": <negative or positive integer, how much to change from {rule_score}>,
    "false_positive_likelihood": <0.0-1.0>,
    "attack_chain_detected": <true or false>,
    "attack_chain_stage": "<initial_access|execution|persistence|defense_evasion|collection|exfiltration|null>",
    "confidence": "<high|medium|low>",
    "reasoning": "<1-2 sentence explanation of your assessment>",
    "recommendations": ["<recommendation 1>", "<recommendation 2>", "<recommendation 3>"]
}}

Guidelines for scoring:
- INCREASE score if: patterns form attack chain, multiple related high-risk files, timing matches key events
- DECREASE score if: likely false positive (legitimate software, common system behavior), no supporting context
- MAINTAIN score if: evidence is ambiguous, need more investigation

Be conservative with adjustments. Maximum adjustment: +/-20 points."""

        try:
            response = await self._query_groq_async(
                prompt,
                interaction_purpose="contextual_risk_eval",
                artifact_id=str(artifact.get('inode', artifact.get('name', ''))),
                artifact_name=artifact.get('name', ''),
                analysis_type="risk_analysis"
            )

            import re
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())

                result['adjusted_score'] = max(0, min(100, int(result.get('adjusted_score', rule_score))))
                result['score_adjustment'] = int(result.get('score_adjustment', 0))
                result['false_positive_likelihood'] = float(result.get('false_positive_likelihood', 0.5))
                result['attack_chain_detected'] = bool(result.get('attack_chain_detected', False))
                result['confidence'] = result.get('confidence', 'medium')
                result['reasoning'] = result.get('reasoning', '')
                result['recommendations'] = result.get('recommendations', [])

                return result

        except Exception as e:
            print(f"Warning: AI contextual evaluation parsing failed: {e}")

        return {
            'adjusted_score': rule_score,
            'score_adjustment': 0,
            'false_positive_likelihood': 0.5,
            'attack_chain_detected': False,
            'attack_chain_stage': None,
            'confidence': 'low',
            'reasoning': 'AI evaluation failed - using rule-based score',
            'recommendations': []
        }

    # =========================================================================
    # New Sync Methods
    # =========================================================================

    def explain_why_suspicious(self, artifact: Dict, score: int, reasons: List[str]) -> str:
        """Generate structured suspicious artifact explanation."""
        context = f"""=== SUSPICIOUS ARTIFACT ANALYSIS ===
Artifact: {artifact.get('name', 'unknown')}
Path: {artifact.get('path', 'unknown')}
Risk Score: {score}/100
Severity: {'CRITICAL' if score >= 90 else 'HIGH' if score >= 70 else 'MEDIUM' if score >= 40 else 'LOW'}

Triggered Rules: {', '.join(reasons)}
"""
        prompt = f"""{context}

Provide a structured analysis in EXACTLY this format:

**WHY DETECTED**
[1-2 sentences explaining what triggered the detection]

**PATTERN TRIGGERED**
[List the specific forensic patterns/rules that fired and their significance]

**RISK LEVEL**
[Assessment of actual threat level with confidence: HIGH/MEDIUM/LOW]

**NEXT STEPS**
[3-5 specific investigative actions, prioritized]

Be concise and actionable. This is for SOC analyst triage."""

        return self._query_groq(
            prompt,
            interaction_purpose="explain_suspicious",
            artifact_id=str(artifact.get('inode', artifact.get('name', ''))),
            artifact_name=artifact.get('name', ''),
            analysis_type="risk_analysis"
        )

    @staticmethod
    def _format_size(bytes_size: int) -> str:
        """Format byte size to human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} PB"

    def _build_forensic_context(self, file_data: Dict) -> str:
        """
        Build comprehensive forensic context for AI analysis.

        Enriches the basic file data with forensically relevant observations
        that are available but might not be obvious from raw metadata.

        Args:
            file_data: Dictionary containing file metadata

        Returns:
            Formatted string with enriched forensic context
        """
        context_parts = []

        # Allocation status (critical for deleted file analysis)
        if 'is_allocated' in file_data:
            status = "Allocated (live file)" if file_data['is_allocated'] else "Unallocated (deleted/carved)"
            context_parts.append(f"Allocation Status: {status}")

        # Timestamp delta analysis (detect timestomping patterns)
        created = file_data.get('created')
        modified = file_data.get('modified')
        if created and modified:
            try:
                # Handle both datetime objects and strings
                if hasattr(created, 'timestamp') and hasattr(modified, 'timestamp'):
                    delta_seconds = abs(modified.timestamp() - created.timestamp())
                    if delta_seconds < 5:
                        context_parts.append(f"TIMESTAMP ANOMALY: Modified only {delta_seconds:.1f}s after creation (suspicious for executables)")
                    elif delta_seconds < 60:
                        context_parts.append(f"Timestamp Note: Modified {delta_seconds:.0f}s after creation")
            except (TypeError, AttributeError):
                pass  # Skip if timestamps aren't parseable

        # Changed time (ctime) - indicates metadata modification
        if file_data.get('changed'):
            context_parts.append(f"Metadata Changed (ctime): {file_data['changed']}")

        # Inode for timeline correlation
        if file_data.get('inode'):
            context_parts.append(f"Inode/MFT Entry: {file_data['inode']}")

        # Entropy analysis (encryption/packing indicator)
        if 'entropy' in file_data:
            entropy = file_data['entropy']
            if entropy > 7.9:
                context_parts.append(f"Entropy: {entropy:.2f}/8.0 (VERY HIGH - likely encrypted or compressed)")
            elif entropy > 7.5:
                context_parts.append(f"Entropy: {entropy:.2f}/8.0 (HIGH - possibly compressed/packed)")
            elif entropy > 6.0:
                context_parts.append(f"Entropy: {entropy:.2f}/8.0 (moderate - typical binary)")
            else:
                context_parts.append(f"Entropy: {entropy:.2f}/8.0 (low - likely text/structured data)")

        # File attributes (hidden, system, etc.)
        if file_data.get('attributes'):
            attrs = file_data['attributes']
            if isinstance(attrs, dict):
                notable = []
                if attrs.get('hidden'):
                    notable.append("HIDDEN")
                if attrs.get('system'):
                    notable.append("SYSTEM")
                if attrs.get('archive'):
                    notable.append("archive")
                if attrs.get('readonly'):
                    notable.append("readonly")
                if notable:
                    context_parts.append(f"Attributes: {', '.join(notable)}")

        # Hash information for lookup context
        if file_data.get('md5'):
            context_parts.append(f"MD5: {file_data['md5']}")
        if file_data.get('sha256'):
            context_parts.append(f"SHA256: {file_data['sha256']}")

        # Location risk assessment
        path = file_data.get('path', '').lower()
        if path:
            location_notes = []
            if '\\temp\\' in path or '/tmp/' in path:
                location_notes.append("TEMP directory (common malware staging location)")
            if '\\downloads\\' in path:
                location_notes.append("Downloads folder (external origin)")
            if '\\appdata\\local\\' in path or '\\appdata\\roaming\\' in path:
                location_notes.append("AppData (user-writable, persistence common)")
            if '\\system32\\' in path and '\\windows\\system32\\' not in path:
                location_notes.append("SUSPICIOUS: system32 outside Windows directory")
            if '\\recycler\\' in path or '\\$recycle.bin\\' in path:
                location_notes.append("Recycle Bin (deleted file)")
            if location_notes:
                context_parts.append(f"Location Analysis: {'; '.join(location_notes)}")

        return "\n".join(context_parts) if context_parts else ""

    def _build_risk_context(self, artifact: Dict, score: int, reasons: List[str]) -> str:
        """
        Build rich context for risk explanation with rule significance.

        Args:
            artifact: Artifact data dictionary
            score: Risk score (0-100)
            reasons: List of triggered rule codes

        Returns:
            Formatted context string with rule explanations
        """
        context = f"Risk Score: {score}/100"

        # Severity tier
        if score >= 90:
            context += " (CRITICAL)"
        elif score >= 70:
            context += " (HIGH)"
        elif score >= 40:
            context += " (MEDIUM)"
        else:
            context += " (LOW)"

        context += "\n\nTRIGGERED RULES (with forensic significance):\n"

        for reason in reasons:
            significance = self.RULE_SIGNIFICANCE.get(reason, f"Forensically notable: {reason}")
            context += f"  - {reason}: {significance}\n"

        return context


# Backwards compatibility aliases
LocalAIService = GroqAIService

# Singleton instance
_ai_service = None

def get_ai_service() -> GroqAIService:
    """Get singleton AI service instance."""
    global _ai_service
    if _ai_service is None:
        _ai_service = GroqAIService()
    return _ai_service
