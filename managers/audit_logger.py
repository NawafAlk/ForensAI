"""
ForensAI - Audit Logging System
================================
Immutable, exportable audit trail for forensic defensibility.

Logs:
- Rule firings with weights and reasons
- AI interactions (prompt, response, model, timestamp)
- All events with cryptographic integrity verification

Designed for court admissibility and chain-of-custody requirements.
"""

import json
import hashlib
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict, field
import threading


@dataclass
class RuleFiringLog:
    """Log entry for a rule-based risk assessment."""

    timestamp: str
    event_type: str = "rule_firing"
    artifact_id: str = ""  # Inode or unique identifier
    artifact_name: str = ""
    artifact_path: str = ""

    # Scoring details
    final_score: int = 0
    severity: str = ""

    # Rule chain (which rules fired and their weights)
    rules_fired: List[Dict[str, Any]] = field(default_factory=list)  # [{'code': 'xxx', 'weight': 85, 'description': '...'}]
    total_weight: int = 0

    # Input data hash (for verifying artifact hasn't changed)
    input_hash: str = ""

    # Log integrity
    log_id: str = ""
    previous_hash: str = ""


@dataclass
class AIInteractionLog:
    """Log entry for AI/LLM interaction."""

    timestamp: str
    event_type: str = "ai_interaction"

    # AI service details
    model: str = ""
    base_url: str = ""

    # Request
    prompt: str = ""
    prompt_tokens: int = 0  # If available

    # Response
    response: str = ""
    response_tokens: int = 0  # If available
    duration_ms: int = 0

    # Context
    artifact_id: str = ""
    artifact_name: str = ""
    interaction_purpose: str = ""  # "explain_file", "explain_risk", "overwrite_story", etc.

    # Additional metadata
    temperature: float = 0.0
    top_p: float = 0.0

    # Confidence/uncertainty (if available)
    confidence: Optional[float] = None
    uncertainty_factors: List[str] = field(default_factory=list)

    # Log integrity
    log_id: str = ""
    previous_hash: str = ""


class AuditLogger:
    """
    Immutable, append-only audit logger for forensic operations.

    All logs are cryptographically chained and stored in JSON format
    for easy export and verification.
    """

    def __init__(self, case_id: str, log_directory: str = "logs"):
        """
        Initialize audit logger.

        Args:
            case_id: Unique case identifier
            log_directory: Directory to store logs
        """
        self.case_id = case_id
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(parents=True, exist_ok=True)

        # Separate log files for different event types
        self.rule_log_path = self.log_directory / f"{case_id}_rules.jsonl"
        self.ai_log_path = self.log_directory / f"{case_id}_ai.jsonl"
        self.index_path = self.log_directory / f"{case_id}_index.json"

        # Thread safety
        self._lock = threading.Lock()

        # Last hash for chaining (separate per log type)
        self._last_rule_hash = self._get_last_hash(self.rule_log_path)
        self._last_ai_hash = self._get_last_hash(self.ai_log_path)

        # Session metadata
        self.session_start = datetime.utcnow().isoformat() + "Z"
        self._log_index = self._load_or_create_index()

    def log_rule_firing(self, artifact_id: str, artifact_name: str, artifact_path: str,
                       final_score: int, severity: str, rules_fired: List[Dict[str, Any]],
                       artifact_data: Dict = None) -> str:
        """
        Log a rule-based risk assessment event.

        Args:
            artifact_id: Unique identifier (inode, hash, etc.)
            artifact_name: Artifact filename
            artifact_path: Full path
            final_score: Final risk score (0-100)
            severity: Severity level ('critical', 'high', 'medium', 'low', 'info')
            rules_fired: List of dicts with 'code', 'weight', 'description'
            artifact_data: Optional full artifact data for hashing

        Returns:
            log_id: Unique log entry ID
        """
        with self._lock:
            timestamp = datetime.utcnow().isoformat() + "Z"
            log_id = self._generate_log_id("RULE", timestamp, artifact_id)

            # Calculate total weight
            total_weight = sum(r.get('weight', 0) for r in rules_fired)

            # Hash input data for integrity
            input_hash = self._hash_dict(artifact_data) if artifact_data else ""

            # Create log entry
            log_entry = RuleFiringLog(
                timestamp=timestamp,
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                artifact_path=artifact_path,
                final_score=final_score,
                severity=severity,
                rules_fired=rules_fired,
                total_weight=total_weight,
                input_hash=input_hash,
                log_id=log_id,
                previous_hash=self._last_rule_hash
            )

            # Write to log
            self._append_log(self.rule_log_path, log_entry)

            # Update chain
            self._last_rule_hash = self._hash_dict(asdict(log_entry))

            # Update index
            self._update_index("rule_firing", log_id, artifact_name)

            return log_id

    def log_ai_interaction(self, model: str, prompt: str, response: str,
                          duration_ms: int, artifact_id: str = "",
                          artifact_name: str = "", interaction_purpose: str = "",
                          base_url: str = "", temperature: float = 0.0,
                          top_p: float = 0.0, confidence: Optional[float] = None,
                          uncertainty_factors: List[str] = None) -> str:
        """
        Log an AI/LLM interaction.

        Args:
            model: Model name (e.g., 'mistral', 'llama3')
            prompt: Full prompt sent to AI
            response: AI response
            duration_ms: Request duration in milliseconds
            artifact_id: Associated artifact ID (if applicable)
            artifact_name: Associated artifact name
            interaction_purpose: Purpose ('explain_file', 'explain_risk', etc.)
            base_url: API endpoint
            temperature: Temperature parameter
            top_p: Top-p parameter
            confidence: Confidence score (0.0-1.0) if available
            uncertainty_factors: List of uncertainty factors

        Returns:
            log_id: Unique log entry ID
        """
        with self._lock:
            timestamp = datetime.utcnow().isoformat() + "Z"
            log_id = self._generate_log_id("AI", timestamp, artifact_id)

            # Estimate token counts (rough approximation)
            prompt_tokens = len(prompt.split()) * 1.3  # Rough estimate
            response_tokens = len(response.split()) * 1.3

            # Create log entry
            log_entry = AIInteractionLog(
                timestamp=timestamp,
                model=model,
                base_url=base_url,
                prompt=prompt,
                prompt_tokens=int(prompt_tokens),
                response=response,
                response_tokens=int(response_tokens),
                duration_ms=duration_ms,
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                interaction_purpose=interaction_purpose,
                temperature=temperature,
                top_p=top_p,
                confidence=confidence,
                uncertainty_factors=uncertainty_factors or [],
                log_id=log_id,
                previous_hash=self._last_ai_hash
            )

            # Write to log
            self._append_log(self.ai_log_path, log_entry)

            # Update chain
            self._last_ai_hash = self._hash_dict(asdict(log_entry))

            # Update index
            self._update_index("ai_interaction", log_id, artifact_name)

            return log_id

    def export_logs(self, output_format: str = "json", output_path: str = None) -> str:
        """
        Export all logs in specified format.

        Args:
            output_format: 'json' or 'csv'
            output_path: Output file path (auto-generated if None)

        Returns:
            Path to exported file
        """
        if output_path is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = self.log_directory / f"{self.case_id}_audit_{timestamp}.{output_format}"

        if output_format == "json":
            return self._export_json(output_path)
        elif output_format == "csv":
            return self._export_csv(output_path)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify cryptographic integrity of log chains.

        Returns:
            Dict with verification results including final hash
        """
        rule_result = self._verify_chain(self.rule_log_path)
        ai_result = self._verify_chain(self.ai_log_path)

        results = {
            'rule_logs': rule_result,
            'ai_logs': ai_result,
            'timestamp': datetime.utcnow().isoformat() + "Z"
        }

        results['all_valid'] = rule_result['valid'] and ai_result['valid']

        # Get final chain hash for display
        final_hash = self.get_final_chain_hash()
        if final_hash:
            results['final_hash'] = final_hash
            results['final_hash_short'] = final_hash[:12] + "..." + final_hash[-12:]

        return results

    def get_final_chain_hash(self) -> Optional[str]:
        """
        Get the final hash of the audit chain (combined hash of both logs).

        Returns:
            SHA256 hash of the latest state, or None if no logs exist
        """
        rule_hash = self._get_last_hash(self.rule_log_path)
        ai_hash = self._get_last_hash(self.ai_log_path)

        # Combine both hashes
        combined = rule_hash + ai_hash
        if combined == ("0" * 64) * 2:  # Both are genesis hashes
            return None

        return hashlib.sha256(combined.encode()).hexdigest()

    def get_artifact_history(self, artifact_id: str) -> Dict[str, List]:
        """
        Get complete audit history for a specific artifact.

        Args:
            artifact_id: Artifact identifier

        Returns:
            Dict with 'rule_logs' and 'ai_logs' lists
        """
        history = {
            'artifact_id': artifact_id,
            'rule_logs': [],
            'ai_logs': []
        }

        # Read rule logs
        if self.rule_log_path.exists():
            with open(self.rule_log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    entry = json.loads(line)
                    if entry.get('artifact_id') == artifact_id:
                        history['rule_logs'].append(entry)

        # Read AI logs
        if self.ai_log_path.exists():
            with open(self.ai_log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    entry = json.loads(line)
                    if entry.get('artifact_id') == artifact_id:
                        history['ai_logs'].append(entry)

        return history

    # === Private Methods ===

    def _append_log(self, log_path: Path, log_entry):
        """Append log entry to file (JSONL format)."""
        with open(log_path, 'a', encoding='utf-8') as f:
            json.dump(asdict(log_entry), f, ensure_ascii=False)
            f.write('\n')

    def _generate_log_id(self, prefix: str, timestamp: str, artifact_id: str) -> str:
        """Generate unique log ID."""
        unique_str = f"{prefix}_{timestamp}_{artifact_id}_{time.time_ns()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:16]

    def _hash_dict(self, data: Dict) -> str:
        """Create SHA-256 hash of dictionary."""
        json_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(json_str.encode()).hexdigest()

    def _get_last_hash(self, log_path: Path) -> str:
        """Get hash of last entry in log file."""
        if not log_path.exists():
            return "0" * 64  # Genesis hash

        try:
            with open(log_path, 'rb') as f:
                # Read last line
                f.seek(0, 2)  # Go to end
                file_size = f.tell()

                if file_size == 0:
                    return "0" * 64

                # Read backwards to find last complete line
                buffer_size = min(8192, file_size)
                f.seek(-buffer_size, 2)
                lines = f.read().decode('utf-8').splitlines()

                if lines:
                    last_entry = json.loads(lines[-1])
                    return self._hash_dict(last_entry)
        except:
            pass

        return "0" * 64

    def _load_or_create_index(self) -> Dict:
        """Load or create log index for fast lookups."""
        if self.index_path.exists():
            with open(self.index_path, 'r') as f:
                return json.load(f)

        return {
            'case_id': self.case_id,
            'created': self.session_start,
            'events': []
        }

    def _update_index(self, event_type: str, log_id: str, artifact_name: str):
        """Update log index."""
        self._log_index['events'].append({
            'type': event_type,
            'log_id': log_id,
            'artifact': artifact_name,
            'timestamp': datetime.utcnow().isoformat() + "Z"
        })

        # Write index (periodically, not every time for performance)
        if len(self._log_index['events']) % 10 == 0:
            with open(self.index_path, 'w') as f:
                json.dump(self._log_index, f, indent=2)

    def _export_json(self, output_path: Path) -> str:
        """Export logs as single JSON file."""
        export_data = {
            'case_id': self.case_id,
            'export_timestamp': datetime.utcnow().isoformat() + "Z",
            'session_start': self.session_start,
            'rule_logs': [],
            'ai_logs': [],
            'integrity_check': self.verify_integrity()
        }

        # Read all rule logs
        if self.rule_log_path.exists():
            with open(self.rule_log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    export_data['rule_logs'].append(json.loads(line))

        # Read all AI logs
        if self.ai_log_path.exists():
            with open(self.ai_log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    export_data['ai_logs'].append(json.loads(line))

        # Write export
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        return str(output_path)

    def _export_csv(self, output_path: Path) -> str:
        """Export logs as CSV (simplified format)."""
        import csv

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Write header
            writer.writerow(['Timestamp', 'Type', 'Artifact', 'Details', 'Log ID'])

            # Write rule logs
            if self.rule_log_path.exists():
                with open(self.rule_log_path, 'r', encoding='utf-8') as log_f:
                    for line in log_f:
                        entry = json.loads(line)
                        details = f"Score: {entry['final_score']}, Severity: {entry['severity']}, Rules: {len(entry['rules_fired'])}"
                        writer.writerow([
                            entry['timestamp'],
                            'Rule Firing',
                            entry['artifact_name'],
                            details,
                            entry['log_id']
                        ])

            # Write AI logs
            if self.ai_log_path.exists():
                with open(self.ai_log_path, 'r', encoding='utf-8') as log_f:
                    for line in log_f:
                        entry = json.loads(line)
                        details = f"Model: {entry['model']}, Purpose: {entry['interaction_purpose']}, Duration: {entry['duration_ms']}ms"
                        writer.writerow([
                            entry['timestamp'],
                            'AI Interaction',
                            entry['artifact_name'],
                            details,
                            entry['log_id']
                        ])

        return str(output_path)

    def _verify_chain(self, log_path: Path) -> Dict[str, Any]:
        """Verify cryptographic chain integrity."""
        if not log_path.exists():
            return {'valid': True, 'entries': 0, 'message': 'No logs to verify'}

        previous_hash = "0" * 64  # Genesis hash
        entry_count = 0

        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    entry = json.loads(line)
                    entry_count += 1

                    # Verify previous hash
                    if entry.get('previous_hash') != previous_hash:
                        return {
                            'valid': False,
                            'entries': entry_count,
                            'message': f'Chain broken at entry {entry_count}'
                        }

                    # Update for next iteration
                    previous_hash = self._hash_dict(entry)

            return {
                'valid': True,
                'entries': entry_count,
                'message': f'All {entry_count} entries verified'
            }

        except Exception as e:
            return {
                'valid': False,
                'entries': entry_count,
                'message': f'Verification error: {str(e)}'
            }


# === Singleton Management ===

_audit_loggers: Dict[str, AuditLogger] = {}


def get_audit_logger(case_id: str = "default", log_directory: str = "logs") -> AuditLogger:
    """
    Get or create audit logger for a case.

    Args:
        case_id: Case identifier
        log_directory: Log storage directory

    Returns:
        AuditLogger instance
    """
    global _audit_loggers

    if case_id not in _audit_loggers:
        _audit_loggers[case_id] = AuditLogger(case_id, log_directory)

    return _audit_loggers[case_id]
