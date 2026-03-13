"""
Unit tests for ForensAI core manager modules.

Tests cover:
- RiskScorer: rule weights, severity classification, edge cases
- AuditLogger: hash chain integrity, log serialization
- ConfidenceTracker: score calculation, level classification
- CarvingConfidence: file validation confidence scoring
"""

import os
import sys
import json
import tempfile
import shutil
import pytest
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================
# Risk Scorer Tests
# ============================================================

class TestRiskScore:
    """Tests for the RiskScore dataclass."""

    def test_risk_score_creation(self):
        from managers.risk_scorer import RiskScore
        score = RiskScore(
            score=75,
            severity='high',
            reasons=['executable_in_temp'],
            details={'executable_in_temp': 'Executable found in temp directory'},
            recommendations=['Investigate file origin']
        )
        assert score.score == 75
        assert score.severity == 'high'
        assert len(score.reasons) == 1
        assert score.overwrite_analysis is None


class TestRiskScorer:
    """Tests for the RiskScorer engine."""

    def setup_method(self):
        from managers.risk_scorer import RiskScorer
        self.scorer = RiskScorer()

    def test_benign_file_low_score(self):
        """A normal document should score low."""
        artifact = {
            'name': 'report.docx',
            'path': 'C:\\Users\\John\\Documents\\report.docx',
            'size': 50000,
            'created': '2025-01-15 10:00:00',
            'modified': '2025-01-16 14:00:00',
        }
        result = self.scorer.score_file(artifact)
        assert result.score < 40, f"Benign file scored too high: {result.score}"
        assert result.severity in ('info', 'low')

    def test_executable_in_temp_high_score(self):
        """An executable in temp should trigger high risk."""
        artifact = {
            'name': 'payload.exe',
            'path': 'C:\\Users\\John\\AppData\\Local\\Temp\\payload.exe',
            'size': 102400,
            'created': '2025-01-20 14:30:00',
            'modified': '2025-01-20 14:30:00',
        }
        result = self.scorer.score_file(artifact)
        assert result.score >= 70, f"Temp executable scored too low: {result.score}"
        assert 'executable_in_temp' in result.reasons

    def test_double_extension_detection(self):
        """Double extension files should be flagged."""
        artifact = {
            'name': 'invoice.pdf.exe',
            'path': 'C:\\Users\\John\\Downloads\\invoice.pdf.exe',
            'size': 524288,
            'created': '2025-01-20 14:30:00',
            'modified': '2025-01-20 14:30:00',
        }
        result = self.scorer.score_file(artifact)
        assert 'double_extension' in result.reasons

    def test_system_file_wrong_location(self):
        """System files outside Windows\\System32 should be flagged as suspicious."""
        artifact = {
            'name': 'svchost.exe',
            'path': 'C:\\Users\\John\\Documents\\svchost.exe',
            'size': 289792,
            'created': '2025-01-15 08:00:00',
            'modified': '2025-01-15 08:00:00',
        }
        result = self.scorer.score_file(artifact)
        # Should be flagged as executable in user dir at minimum
        assert result.score >= 70, f"System file in wrong location scored too low: {result.score}"
        assert 'executable_in_user_dir' in result.reasons

    def test_score_capped_at_100(self):
        """Score should never exceed 100 even with multiple rules."""
        artifact = {
            'name': 'cmd.exe',
            'path': 'C:\\Users\\John\\AppData\\Local\\Temp\\cmd.exe',
            'size': 289792,
            'created': '2025-01-20 14:30:00',
            'modified': '2020-01-01 00:00:00',  # Timestamp anomaly
            'is_hidden': True,
            'is_deleted': True,
        }
        result = self.scorer.score_file(artifact)
        assert result.score <= 100

    def test_severity_thresholds(self):
        """Verify severity labels match thresholds."""
        from managers.risk_scorer import RiskScorer
        thresholds = RiskScorer.SEVERITY_THRESHOLDS
        assert thresholds['critical'] == 90
        assert thresholds['high'] == 70
        assert thresholds['medium'] == 40
        assert thresholds['low'] == 20
        assert thresholds['info'] == 0

    def test_empty_artifact(self):
        """Scorer should handle minimal artifact data gracefully."""
        artifact = {'name': '', 'path': '', 'size': 0}
        result = self.scorer.score_file(artifact)
        assert result.score >= 0
        assert result.severity in ('critical', 'high', 'medium', 'low', 'info')

    def test_executable_in_appdata_flagged(self):
        """Executables in AppData should be flagged."""
        artifact = {
            'name': 'update.exe',
            'path': 'C:\\Users\\John\\AppData\\update.exe',
            'size': 102400,
            'created': '2025-01-20 14:30:00',
            'modified': '2025-01-20 14:30:00',
        }
        result = self.scorer.score_file(artifact)
        assert 'executable_in_appdata' in result.reasons

    def test_recommendations_generated(self):
        """High-risk files should include investigation recommendations."""
        artifact = {
            'name': 'dropper.exe',
            'path': 'C:\\Users\\John\\Downloads\\dropper.exe',
            'size': 524288,
            'created': '2025-01-20 14:30:00',
            'modified': '2025-01-20 14:30:00',
        }
        result = self.scorer.score_file(artifact)
        assert len(result.recommendations) > 0


# ============================================================
# Audit Logger Tests
# ============================================================

class TestAuditLogger:
    """Tests for the AuditLogger hash chain and serialization."""

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_logger_creation(self):
        from managers.audit_logger import AuditLogger
        logger = AuditLogger(case_id="test_001", log_directory=self.temp_dir)
        assert logger.case_id == "test_001"

    def test_rule_firing_log(self):
        """Rule firing should create a valid log entry."""
        from managers.audit_logger import AuditLogger
        logger = AuditLogger(case_id="test_002", log_directory=self.temp_dir)
        logger.log_rule_firing(
            artifact_id="inode_42",
            artifact_name="suspicious.exe",
            artifact_path="C:\\Temp\\suspicious.exe",
            final_score=85,
            severity="high",
            rules_fired=[
                {'code': 'executable_in_temp', 'weight': 90, 'description': 'Executable in temp'}
            ]
        )
        # Verify log file was created
        log_files = list(Path(self.temp_dir).glob("*rules*.jsonl"))
        assert len(log_files) >= 1

    def test_hash_chain_integrity(self):
        """Sequential log entries should form a valid hash chain."""
        from managers.audit_logger import AuditLogger
        logger = AuditLogger(case_id="test_003", log_directory=self.temp_dir)

        # Log multiple entries
        for i in range(5):
            logger.log_rule_firing(
                artifact_id=f"inode_{i}",
                artifact_name=f"file_{i}.exe",
                artifact_path=f"C:\\Temp\\file_{i}.exe",
                final_score=50 + i * 10,
                severity="medium",
                rules_fired=[{'code': 'test_rule', 'weight': 50, 'description': 'Test'}]
            )

        # Verify chain integrity
        result = logger.verify_integrity()
        assert isinstance(result, dict)
        assert result.get('rules_valid', True), "Hash chain integrity check failed"

    def test_ai_interaction_log(self):
        """AI interaction logging should capture prompt and response."""
        from managers.audit_logger import AuditLogger
        logger = AuditLogger(case_id="test_004", log_directory=self.temp_dir)
        logger.log_ai_interaction(
            model="llama-3.3-70b",
            prompt="Explain this file",
            response="This is a DLL file...",
            duration_ms=500,
            artifact_id="inode_99",
            artifact_name="mystery.dll",
            interaction_purpose="explain_file"
        )
        log_files = list(Path(self.temp_dir).glob("*ai*.jsonl"))
        assert len(log_files) >= 1

    def test_export_json(self):
        """Log export to JSON should produce valid output."""
        from managers.audit_logger import AuditLogger
        logger = AuditLogger(case_id="test_005", log_directory=self.temp_dir)
        logger.log_rule_firing(
            artifact_id="inode_1",
            artifact_name="test.exe",
            artifact_path="C:\\test.exe",
            final_score=75,
            severity="high",
            rules_fired=[{'code': 'test', 'weight': 75, 'description': 'Test'}]
        )
        export_path = os.path.join(self.temp_dir, "export.json")
        result = logger.export_logs(output_format='json', output_path=export_path)
        assert result is not None


# ============================================================
# Confidence Tracker Tests
# ============================================================

class TestConfidenceScore:
    """Tests for the ConfidenceScore dataclass."""

    def test_from_score_very_high(self):
        from managers.confidence_tracker import ConfidenceScore, ConfidenceLevel
        cs = ConfidenceScore.from_score(0.95, "Strong evidence")
        assert cs.level == ConfidenceLevel.VERY_HIGH
        assert cs.score == 0.95

    def test_from_score_high(self):
        from managers.confidence_tracker import ConfidenceScore, ConfidenceLevel
        cs = ConfidenceScore.from_score(0.80, "Good evidence")
        assert cs.level == ConfidenceLevel.HIGH

    def test_from_score_medium(self):
        from managers.confidence_tracker import ConfidenceScore, ConfidenceLevel
        cs = ConfidenceScore.from_score(0.60, "Moderate evidence")
        assert cs.level == ConfidenceLevel.MEDIUM

    def test_from_score_low(self):
        from managers.confidence_tracker import ConfidenceScore, ConfidenceLevel
        cs = ConfidenceScore.from_score(0.30, "Weak evidence")
        assert cs.level == ConfidenceLevel.LOW

    def test_from_score_very_low(self):
        from managers.confidence_tracker import ConfidenceScore, ConfidenceLevel
        cs = ConfidenceScore.from_score(0.10, "Very weak")
        assert cs.level == ConfidenceLevel.VERY_LOW

    def test_to_dict(self):
        from managers.confidence_tracker import ConfidenceScore
        cs = ConfidenceScore.from_score(0.85, "Strong", ["hash match", "signature"])
        d = cs.to_dict()
        assert d['score'] == 0.85
        assert d['level'] == 'high'
        assert len(d['evidence']) == 2

    def test_boundary_values(self):
        """Test exact boundary scores."""
        from managers.confidence_tracker import ConfidenceScore, ConfidenceLevel
        assert ConfidenceScore.from_score(0.90).level == ConfidenceLevel.VERY_HIGH
        assert ConfidenceScore.from_score(0.75).level == ConfidenceLevel.HIGH
        assert ConfidenceScore.from_score(0.50).level == ConfidenceLevel.MEDIUM
        assert ConfidenceScore.from_score(0.25).level == ConfidenceLevel.LOW
        assert ConfidenceScore.from_score(0.0).level == ConfidenceLevel.VERY_LOW


class TestFactType:
    """Tests for the FactType enum."""

    def test_fact_types_exist(self):
        from managers.confidence_tracker import FactType
        assert FactType.DERIVED.value == "derived"
        assert FactType.INFERRED.value == "inferred"
        assert FactType.COMPUTED.value == "computed"
        assert FactType.EXTERNAL.value == "external"


# ============================================================
# Block Map / Overwrite Analysis Tests
# ============================================================

class TestOverwriteAnalysis:
    """Tests for block map overwrite analysis."""

    def test_overwrite_analysis_creation(self):
        from managers.block_map import OverwriteAnalysis
        analysis = OverwriteAnalysis(
            total_clusters=100,
            recovered_clusters=75,
            recovery_percentage=75.0,
            overwritten_by=[('malware.exe', '2025-01-20', 10)],
            unallocated_clusters=15,
            fragmentation_score=30.0,
            contiguous_runs=3,
            largest_run_size=50,
            timeline=[{'time': '2025-01-20', 'event': 'deleted'}],
            summary='File partially recovered'
        )
        assert analysis.recovery_percentage == 75.0
        assert analysis.total_clusters == 100
        assert analysis.clusters_total == 100  # Property alias

    def test_overwrite_analysis_fields(self):
        from managers.block_map import OverwriteAnalysis
        analysis = OverwriteAnalysis(
            total_clusters=200,
            recovered_clusters=200,
            recovery_percentage=100.0,
            overwritten_by=[],
            unallocated_clusters=0,
            fragmentation_score=0.0,
            contiguous_runs=1,
            largest_run_size=200,
            timeline=[],
            summary='Fully recoverable'
        )
        assert analysis.fragmentation_score == 0.0
        assert len(analysis.overwritten_by) == 0


# ============================================================
# Carving Confidence Tests
# ============================================================

class TestCarvingConfidence:
    """Tests for file carving confidence scoring."""

    def test_confidence_tiers(self):
        """Verify confidence tier helper function."""
        from managers.carving_confidence import get_tier
        label, color = get_tier(95)
        assert label == "Complete"
        label, color = get_tier(75)
        assert label == "Good"

    def test_evaluate_method_exists(self):
        """CarvingConfidence should have an evaluate method."""
        from managers.carving_confidence import CarvingConfidence
        cc = CarvingConfidence()
        assert hasattr(cc, 'evaluate')


# ============================================================
# Hybrid Risk Scorer Tests
# ============================================================

class TestHybridRiskScorer:
    """Tests for the HybridRiskScorer behavioral pattern detection."""

    def test_behavioral_patterns_defined(self):
        from managers.risk_scorer import BEHAVIORAL_PATTERNS
        assert 'malware_dropper' in BEHAVIORAL_PATTERNS
        assert 'persistence_install' in BEHAVIORAL_PATTERNS
        assert 'evidence_tampering' in BEHAVIORAL_PATTERNS
        assert 'active_concealment' in BEHAVIORAL_PATTERNS

    def test_rule_categories_defined(self):
        from managers.risk_scorer import RULE_CATEGORIES
        assert RULE_CATEGORIES['executable_in_temp'] == 'execution'
        assert RULE_CATEGORIES['file_in_startup'] == 'persistence'
        assert RULE_CATEGORIES['timestomp_detected'] == 'anti_forensic'
        assert RULE_CATEGORIES['large_archive_recent'] == 'exfiltration'

    def test_case_context_multipliers(self):
        from managers.risk_scorer import CaseContext
        ctx = CaseContext(case_type='insider_threat')
        # Default multiplier should be 1.0
        assert ctx.get_multiplier('unknown_category') == 1.0

    def test_known_good_hash(self):
        from managers.risk_scorer import CaseContext
        ctx = CaseContext()
        ctx.known_good_hashes.add('abc123')
        assert ctx.is_known_good('ABC123')  # Case insensitive
        assert not ctx.is_known_good('def456')

    def test_known_bad_hash(self):
        from managers.risk_scorer import CaseContext
        ctx = CaseContext()
        ctx.known_bad_hashes.add('malware123')
        assert ctx.is_known_bad('MALWARE123')  # Case insensitive
        assert not ctx.is_known_bad('clean456')

    def test_null_hash_handling(self):
        from managers.risk_scorer import CaseContext
        ctx = CaseContext()
        assert not ctx.is_known_good(None)
        assert not ctx.is_known_good('')
        assert not ctx.is_known_bad(None)
        assert not ctx.is_known_bad('')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
