"""
Confidence & Uncertainty Tracking System

Tracks confidence levels and uncertainty indicators for AI-generated insights
and risk assessments to support forensic defensibility.

Features:
- AI confidence scoring (0.0 - 1.0)
- Derived vs Inferred fact tracking
- Uncertainty indicators
- Evidence strength assessment
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Literal
from datetime import datetime
from enum import Enum
import json
import re


class FactType(Enum):
    """Type of forensic fact"""
    DERIVED = "derived"      # Direct from evidence (timestamps, file size, hash)
    INFERRED = "inferred"    # AI interpretation/speculation
    COMPUTED = "computed"    # Calculated from data (entropy, fragmentation)
    EXTERNAL = "external"    # From external sources (VirusTotal, NSRL)


class ConfidenceLevel(Enum):
    """Confidence level categories"""
    VERY_HIGH = "very_high"  # 90-100%
    HIGH = "high"            # 75-89%
    MEDIUM = "medium"        # 50-74%
    LOW = "low"              # 25-49%
    VERY_LOW = "very_low"    # 0-24%


@dataclass
class ConfidenceScore:
    """Confidence score for a specific claim or finding"""
    score: float  # 0.0 - 1.0
    level: ConfidenceLevel
    reasoning: str
    evidence: List[str] = field(default_factory=list)

    @classmethod
    def from_score(cls, score: float, reasoning: str = "", evidence: List[str] = None):
        """Create confidence score from numeric value"""
        if score >= 0.90:
            level = ConfidenceLevel.VERY_HIGH
        elif score >= 0.75:
            level = ConfidenceLevel.HIGH
        elif score >= 0.50:
            level = ConfidenceLevel.MEDIUM
        elif score >= 0.25:
            level = ConfidenceLevel.LOW
        else:
            level = ConfidenceLevel.VERY_LOW

        return cls(
            score=score,
            level=level,
            reasoning=reasoning,
            evidence=evidence or []
        )

    def to_dict(self) -> Dict[str, Any]:
        """Export as dictionary"""
        return {
            "score": self.score,
            "level": self.level.value,
            "reasoning": self.reasoning,
            "evidence": self.evidence
        }


@dataclass
class ForensicFact:
    """A single forensic fact with confidence and provenance"""
    fact_id: str
    fact_type: FactType
    description: str
    value: Any
    confidence: ConfidenceScore
    source: str  # Where this fact came from
    timestamp: datetime
    artifact_id: str = ""
    artifact_name: str = ""
    dependencies: List[str] = field(default_factory=list)  # IDs of facts this depends on

    def to_dict(self) -> Dict[str, Any]:
        """Export as dictionary"""
        return {
            "fact_id": self.fact_id,
            "fact_type": self.fact_type.value,
            "description": self.description,
            "value": str(self.value),
            "confidence": {
                "score": self.confidence.score,
                "level": self.confidence.level.value,
                "reasoning": self.confidence.reasoning,
                "evidence": self.confidence.evidence
            },
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "artifact_id": self.artifact_id,
            "artifact_name": self.artifact_name,
            "dependencies": self.dependencies
        }


@dataclass
class UncertaintyIndicator:
    """Indicator of uncertainty in analysis"""
    indicator_type: Literal["missing_data", "conflicting_evidence", "low_confidence",
                           "incomplete_recovery", "ai_speculation", "external_failure"]
    severity: Literal["critical", "high", "medium", "low"]
    description: str
    mitigation: str  # What can be done about it
    affected_artifacts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.indicator_type,
            "severity": self.severity,
            "description": self.description,
            "mitigation": self.mitigation,
            "affected_artifacts": self.affected_artifacts
        }


class ConfidenceTracker:
    """Tracks confidence and uncertainty across forensic analysis"""

    def __init__(self, case_id: str = "default"):
        self.case_id = case_id
        self.facts: Dict[str, ForensicFact] = {}
        self.uncertainty_indicators: List[UncertaintyIndicator] = []
        self._fact_counter = 0

    def add_fact(self, fact_type: FactType, description: str, value: Any,
                 confidence_score: float, source: str, artifact_id: str = "",
                 artifact_name: str = "", reasoning: str = "",
                 evidence: List[str] = None, dependencies: List[str] = None) -> str:
        """Add a forensic fact with confidence"""
        self._fact_counter += 1
        fact_id = f"FACT_{self.case_id}_{self._fact_counter:06d}"

        confidence = ConfidenceScore.from_score(
            score=confidence_score,
            reasoning=reasoning,
            evidence=evidence or []
        )

        fact = ForensicFact(
            fact_id=fact_id,
            fact_type=fact_type,
            description=description,
            value=value,
            confidence=confidence,
            source=source,
            timestamp=datetime.utcnow(),
            artifact_id=artifact_id,
            artifact_name=artifact_name,
            dependencies=dependencies or []
        )

        self.facts[fact_id] = fact
        return fact_id

    def add_uncertainty(self, indicator_type: str, severity: str,
                       description: str, mitigation: str,
                       affected_artifacts: List[str] = None):
        """Add an uncertainty indicator"""
        indicator = UncertaintyIndicator(
            indicator_type=indicator_type,
            severity=severity,
            description=description,
            mitigation=mitigation,
            affected_artifacts=affected_artifacts or []
        )
        self.uncertainty_indicators.append(indicator)

    def get_artifact_facts(self, artifact_id: str) -> List[ForensicFact]:
        """Get all facts for a specific artifact"""
        return [f for f in self.facts.values() if f.artifact_id == artifact_id]

    def get_facts_by_type(self, fact_type: FactType) -> List[ForensicFact]:
        """Get all facts of a specific type"""
        return [f for f in self.facts.values() if f.fact_type == fact_type]

    def get_low_confidence_facts(self, threshold: float = 0.5) -> List[ForensicFact]:
        """Get facts below confidence threshold"""
        return [f for f in self.facts.values() if f.confidence.score < threshold]

    def get_inferred_facts(self) -> List[ForensicFact]:
        """Get all AI-inferred facts (not derived from evidence)"""
        return self.get_facts_by_type(FactType.INFERRED)

    def get_derived_facts(self) -> List[ForensicFact]:
        """Get all evidence-derived facts"""
        return self.get_facts_by_type(FactType.DERIVED)

    def get_critical_uncertainties(self) -> List[UncertaintyIndicator]:
        """Get critical uncertainty indicators"""
        return [u for u in self.uncertainty_indicators if u.severity == "critical"]

    def get_artifact_uncertainties(self, artifact_id: str) -> List[UncertaintyIndicator]:
        """Get uncertainties affecting a specific artifact"""
        return [u for u in self.uncertainty_indicators
                if artifact_id in u.affected_artifacts]

    def calculate_overall_confidence(self, artifact_id: str) -> ConfidenceScore:
        """Calculate overall confidence for an artifact"""
        facts = self.get_artifact_facts(artifact_id)
        if not facts:
            return ConfidenceScore.from_score(0.0, "No facts available")

        # Weighted average with higher weight for derived facts
        weights = {
            FactType.DERIVED: 1.0,
            FactType.COMPUTED: 0.9,
            FactType.EXTERNAL: 0.8,
            FactType.INFERRED: 0.5
        }

        total_weight = 0.0
        weighted_sum = 0.0

        for fact in facts:
            weight = weights.get(fact.fact_type, 0.5)
            weighted_sum += fact.confidence.score * weight
            total_weight += weight

        avg_confidence = weighted_sum / total_weight if total_weight > 0 else 0.0

        # Count fact types
        derived_count = len([f for f in facts if f.fact_type == FactType.DERIVED])
        inferred_count = len([f for f in facts if f.fact_type == FactType.INFERRED])

        reasoning = f"Based on {len(facts)} facts ({derived_count} derived, {inferred_count} inferred)"

        return ConfidenceScore.from_score(avg_confidence, reasoning)

    def export_confidence_report(self, artifact_id: str = "") -> Dict[str, Any]:
        """Export confidence report for artifact or entire case"""
        if artifact_id:
            facts = self.get_artifact_facts(artifact_id)
            uncertainties = self.get_artifact_uncertainties(artifact_id)
            overall = self.calculate_overall_confidence(artifact_id)
        else:
            facts = list(self.facts.values())
            uncertainties = self.uncertainty_indicators
            overall = None

        # Categorize facts
        derived = [f for f in facts if f.fact_type == FactType.DERIVED]
        inferred = [f for f in facts if f.fact_type == FactType.INFERRED]
        computed = [f for f in facts if f.fact_type == FactType.COMPUTED]
        external = [f for f in facts if f.fact_type == FactType.EXTERNAL]

        low_confidence = [f for f in facts if f.confidence.score < 0.5]

        report = {
            "case_id": self.case_id,
            "artifact_id": artifact_id,
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_facts": len(facts),
                "derived_facts": len(derived),
                "inferred_facts": len(inferred),
                "computed_facts": len(computed),
                "external_facts": len(external),
                "low_confidence_facts": len(low_confidence),
                "uncertainty_indicators": len(uncertainties),
                "critical_uncertainties": len([u for u in uncertainties if u.severity == "critical"])
            },
            "overall_confidence": overall.to_dict() if overall else None,
            "facts": [f.to_dict() for f in facts],
            "uncertainties": [u.to_dict() for u in uncertainties],
            "low_confidence_details": [f.to_dict() for f in low_confidence]
        }

        return report

    def parse_ai_confidence(self, ai_response: str) -> float:
        """
        Parse confidence indicators from AI response text.
        Looks for phrases like "likely", "possibly", "certainly", etc.
        """
        response_lower = ai_response.lower()

        # High confidence indicators
        high_confidence = ["certainly", "definitely", "confirmed", "verified",
                          "clear evidence", "undoubtedly", "absolutely"]

        # Medium confidence indicators
        medium_confidence = ["likely", "probably", "appears to be", "suggests",
                            "indicates", "seems to"]

        # Low confidence indicators
        low_confidence = ["possibly", "maybe", "might", "could be", "uncertain",
                         "unclear", "speculation", "hypothesis"]

        # Count occurrences
        high_count = sum(1 for phrase in high_confidence if phrase in response_lower)
        medium_count = sum(1 for phrase in medium_confidence if phrase in response_lower)
        low_count = sum(1 for phrase in low_confidence if phrase in response_lower)

        # Calculate confidence score
        if high_count > low_count and high_count > 0:
            return 0.85
        elif medium_count > low_count:
            return 0.65
        elif low_count > 0:
            return 0.35
        else:
            # Default medium-high for factual-sounding responses
            return 0.70


# Singleton pattern for easy access
_confidence_trackers: Dict[str, ConfidenceTracker] = {}

def get_confidence_tracker(case_id: str = "default") -> ConfidenceTracker:
    """Get or create confidence tracker for case"""
    if case_id not in _confidence_trackers:
        _confidence_trackers[case_id] = ConfidenceTracker(case_id)
    return _confidence_trackers[case_id]
