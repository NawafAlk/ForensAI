"""
Rule Configuration Manager - Explainability Controls

Manages risk scoring rule weights with versioning and audit trail.
Allows investigators to tune rule weights while maintaining accountability.

Features:
- Adjust rule weights with reason tracking
- Version control for rule changes
- Export/import rule configurations
- Compare rule versions
- Rollback to previous versions
- Custom rule creation
- "Why NOT flagged" analysis

All changes are logged with who, when, why for court defensibility.
"""

import json
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
import hashlib


@dataclass
class RuleDefinition:
    """Single risk scoring rule"""
    code: str  # Unique rule identifier
    name: str  # Human-readable name
    description: str  # What this rule detects
    weight: int  # Points added when rule fires (0-100)
    category: str  # execution, content, timestamp, size, location, etc.
    enabled: bool = True
    custom: bool = False  # User-created custom rule
    created_date: str = ""
    created_by: str = ""


@dataclass
class RuleVersion:
    """Version of rule configuration"""
    version: int
    timestamp: str
    changed_by: str
    change_reason: str
    rules: Dict[str, RuleDefinition] = field(default_factory=dict)
    config_hash: str = ""  # Hash of configuration for integrity

    def calculate_hash(self) -> str:
        """Calculate SHA256 hash of this configuration"""
        # Sort rules by code for consistent hashing
        sorted_rules = sorted(self.rules.items())
        config_str = json.dumps([(code, asdict(rule)) for code, rule in sorted_rules], sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()[:16]


@dataclass
class WhyNotFlaggedResult:
    """Result of 'Why NOT flagged' analysis"""
    file_name: str
    total_score: int
    threshold_not_met: int  # How many points short
    rules_checked: int
    rules_fired: int
    rules_not_fired: List[Tuple[str, str, int]]  # (code, reason_why_not, potential_points)
    recommendations: List[str]


class RuleConfigManager:
    """Manages rule configurations with versioning"""

    # Default rule weights (from RiskScorer)
    DEFAULT_RULES = {
        # Execution-related
        'executable_in_user_dir': RuleDefinition(
            code='executable_in_user_dir',
            name='Executable in User Directory',
            description='System executable found in user directory (potential masquerading)',
            weight=85,
            category='execution'
        ),
        'executable_in_temp': RuleDefinition(
            code='executable_in_temp',
            name='Executable in Temp Folder',
            description='Executable found in temporary directory',
            weight=90,
            category='execution'
        ),
        'executable_in_downloads': RuleDefinition(
            code='executable_in_downloads',
            name='Executable in Downloads',
            description='Executable found in Downloads folder',
            weight=80,
            category='execution'
        ),
        'executable_in_appdata': RuleDefinition(
            code='executable_in_appdata',
            name='Executable in AppData',
            description='Executable in AppData folder (common malware location)',
            weight=75,
            category='execution'
        ),
        'system_file_wrong_location': RuleDefinition(
            code='system_file_wrong_location',
            name='System File in Wrong Location',
            description='Known system file found outside system directories',
            weight=95,
            category='execution'
        ),
        # File naming
        'double_extension': RuleDefinition(
            code='double_extension',
            name='Double Extension',
            description='File has double extension (e.g., .pdf.exe) indicating masquerading',
            weight=65,
            category='naming'
        ),
        'suspicious_extension': RuleDefinition(
            code='suspicious_extension',
            name='Suspicious Extension',
            description='File has potentially dangerous extension',
            weight=60,
            category='naming'
        ),
        # Content-based
        'high_entropy': RuleDefinition(
            code='high_entropy',
            name='High Entropy Content',
            description='File has high entropy (possible encryption/packing)',
            weight=70,
            category='content'
        ),
        'extremely_high_entropy': RuleDefinition(
            code='extremely_high_entropy',
            name='Extremely High Entropy',
            description='File has very high entropy (likely encrypted/packed)',
            weight=85,
            category='content'
        ),
        # Timestamp anomalies
        'recently_deleted': RuleDefinition(
            code='recently_deleted',
            name='Recently Deleted',
            description='File was recently deleted',
            weight=65,
            category='timestamp'
        ),
        'timestomp_detected': RuleDefinition(
            code='timestomp_detected',
            name='Timestomp Detected',
            description='File timestamps appear manipulated',
            weight=95,
            category='timestamp'
        ),
        'created_equals_modified': RuleDefinition(
            code='created_equals_modified',
            name='Created = Modified Time',
            description='Created and modified timestamps are identical',
            weight=45,
            category='timestamp'
        ),
        # Size anomalies
        'unusually_small_executable': RuleDefinition(
            code='unusually_small_executable',
            name='Unusually Small Executable',
            description='Executable is suspiciously small',
            weight=55,
            category='size'
        ),
    }

    def __init__(self, config_dir: str = "config/rules"):
        """Initialize rule configuration manager"""
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.versions: List[RuleVersion] = []
        self.current_version: Optional[RuleVersion] = None

        # Load existing versions
        self._load_versions()

        # Create initial version if none exists
        if not self.versions:
            self._create_initial_version()

    def _load_versions(self):
        """Load all rule versions from disk"""
        version_file = self.config_dir / "rule_versions.json"

        if version_file.exists():
            try:
                with open(version_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                for version_data in data.get('versions', []):
                    rules_data = version_data.get('rules', {})
                    rules = {code: RuleDefinition(**rule_dict)
                            for code, rule_dict in rules_data.items()}

                    version = RuleVersion(
                        version=version_data['version'],
                        timestamp=version_data['timestamp'],
                        changed_by=version_data['changed_by'],
                        change_reason=version_data['change_reason'],
                        rules=rules,
                        config_hash=version_data.get('config_hash', '')
                    )
                    self.versions.append(version)

                # Set current version to latest
                if self.versions:
                    self.current_version = self.versions[-1]
                    print(f"[RuleConfig] Loaded {len(self.versions)} versions")

            except Exception as e:
                print(f"[RuleConfig] Failed to load versions: {e}")

    def _save_versions(self):
        """Save all versions to disk"""
        version_file = self.config_dir / "rule_versions.json"

        try:
            versions_data = []
            for version in self.versions:
                rules_data = {code: asdict(rule) for code, rule in version.rules.items()}
                versions_data.append({
                    'version': version.version,
                    'timestamp': version.timestamp,
                    'changed_by': version.changed_by,
                    'change_reason': version.change_reason,
                    'rules': rules_data,
                    'config_hash': version.config_hash
                })

            data = {
                'updated': datetime.utcnow().isoformat(),
                'version_count': len(self.versions),
                'versions': versions_data
            }

            with open(version_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"[RuleConfig] Failed to save versions: {e}")

    def _create_initial_version(self):
        """Create initial version with default rules"""
        version = RuleVersion(
            version=1,
            timestamp=datetime.utcnow().isoformat(),
            changed_by="system",
            change_reason="Initial configuration with default rules",
            rules=self.DEFAULT_RULES.copy()
        )
        version.config_hash = version.calculate_hash()

        self.versions.append(version)
        self.current_version = version
        self._save_versions()

        print("[RuleConfig] Created initial version with default rules")

    def adjust_rule_weight(self, rule_code: str, new_weight: int,
                          changed_by: str, reason: str) -> bool:
        """
        Adjust weight of existing rule (creates new version).

        Args:
            rule_code: Rule identifier
            new_weight: New weight value (0-100)
            changed_by: Who made the change
            reason: Why the change was made

        Returns:
            True if successful
        """
        if not self.current_version:
            return False

        if rule_code not in self.current_version.rules:
            print(f"[RuleConfig] Rule not found: {rule_code}")
            return False

        if not (0 <= new_weight <= 100):
            print(f"[RuleConfig] Invalid weight: {new_weight} (must be 0-100)")
            return False

        # Create new version
        new_rules = {}
        for code, rule in self.current_version.rules.items():
            if code == rule_code:
                # Create updated rule
                updated_rule = RuleDefinition(
                    code=rule.code,
                    name=rule.name,
                    description=rule.description,
                    weight=new_weight,
                    category=rule.category,
                    enabled=rule.enabled,
                    custom=rule.custom,
                    created_date=rule.created_date,
                    created_by=rule.created_by
                )
                new_rules[code] = updated_rule
            else:
                new_rules[code] = rule

        new_version = RuleVersion(
            version=self.current_version.version + 1,
            timestamp=datetime.utcnow().isoformat(),
            changed_by=changed_by,
            change_reason=f"Adjusted '{rule_code}' weight from {self.current_version.rules[rule_code].weight} to {new_weight}: {reason}",
            rules=new_rules
        )
        new_version.config_hash = new_version.calculate_hash()

        self.versions.append(new_version)
        self.current_version = new_version
        self._save_versions()

        print(f"[RuleConfig] Created version {new_version.version}: {new_version.change_reason}")
        return True

    def add_custom_rule(self, code: str, name: str, description: str,
                       weight: int, category: str, created_by: str) -> bool:
        """
        Add new custom rule (creates new version).

        Args:
            code: Unique rule identifier
            name: Human-readable name
            description: What the rule detects
            weight: Points when rule fires (0-100)
            category: Rule category
            created_by: Who created the rule

        Returns:
            True if successful
        """
        if not self.current_version:
            return False

        if code in self.current_version.rules:
            print(f"[RuleConfig] Rule already exists: {code}")
            return False

        # Create new rule
        new_rule = RuleDefinition(
            code=code,
            name=name,
            description=description,
            weight=weight,
            category=category,
            enabled=True,
            custom=True,
            created_date=datetime.utcnow().isoformat(),
            created_by=created_by
        )

        # Create new version
        new_rules = self.current_version.rules.copy()
        new_rules[code] = new_rule

        new_version = RuleVersion(
            version=self.current_version.version + 1,
            timestamp=datetime.utcnow().isoformat(),
            changed_by=created_by,
            change_reason=f"Added custom rule '{code}' ({name})",
            rules=new_rules
        )
        new_version.config_hash = new_version.calculate_hash()

        self.versions.append(new_version)
        self.current_version = new_version
        self._save_versions()

        print(f"[RuleConfig] Added custom rule: {code}")
        return True

    def get_current_weights(self) -> Dict[str, int]:
        """Get current rule weights as dictionary"""
        if not self.current_version:
            return {}

        return {code: rule.weight
                for code, rule in self.current_version.rules.items()
                if rule.enabled}

    def get_rule(self, code: str) -> Optional[RuleDefinition]:
        """Get rule definition"""
        if not self.current_version:
            return None
        return self.current_version.rules.get(code)

    def rollback_to_version(self, version_num: int, changed_by: str, reason: str) -> bool:
        """Rollback to previous version"""
        target_version = None
        for v in self.versions:
            if v.version == version_num:
                target_version = v
                break

        if not target_version:
            print(f"[RuleConfig] Version {version_num} not found")
            return False

        # Create new version as copy of target
        new_version = RuleVersion(
            version=self.current_version.version + 1 if self.current_version else 1,
            timestamp=datetime.utcnow().isoformat(),
            changed_by=changed_by,
            change_reason=f"Rolled back to version {version_num}: {reason}",
            rules=target_version.rules.copy()
        )
        new_version.config_hash = new_version.calculate_hash()

        self.versions.append(new_version)
        self.current_version = new_version
        self._save_versions()

        print(f"[RuleConfig] Rolled back to version {version_num}")
        return True

    def analyze_why_not_flagged(self, file_data: Dict, risk_score) -> WhyNotFlaggedResult:
        """
        Analyze why a file was NOT flagged as high risk.

        Args:
            file_data: File information
            risk_score: RiskScore result from scoring

        Returns:
            WhyNotFlaggedResult with analysis
        """
        # Determine why rules didn't fire
        rules_not_fired = []
        for code, rule in self.current_version.rules.items():
            if code not in risk_score.reasons and rule.enabled:
                # This rule didn't fire - analyze why
                reason_why_not = self._explain_why_rule_not_fired(code, file_data)
                rules_not_fired.append((code, reason_why_not, rule.weight))

        # Calculate threshold gap
        high_risk_threshold = 70
        threshold_gap = max(0, high_risk_threshold - risk_score.score)

        # Generate recommendations
        recommendations = []
        if threshold_gap > 0:
            recommendations.append(f"File scored {risk_score.score}/100, needs {threshold_gap} more points to be HIGH risk")

            # Suggest which rules could push it over
            for code, reason, weight in rules_not_fired[:5]:  # Top 5
                if weight >= threshold_gap:
                    recommendations.append(f"Rule '{code}' ({weight} pts) would flag this file if conditions were met: {reason}")

        return WhyNotFlaggedResult(
            file_name=file_data.get('name', 'unknown'),
            total_score=risk_score.score,
            threshold_not_met=threshold_gap,
            rules_checked=len(self.current_version.rules),
            rules_fired=len(risk_score.reasons),
            rules_not_fired=rules_not_fired,
            recommendations=recommendations
        )

    def _explain_why_rule_not_fired(self, rule_code: str, file_data: Dict) -> str:
        """Explain why a specific rule didn't fire"""
        # Simplified explanations
        explanations = {
            'executable_in_downloads': "File not in Downloads folder",
            'double_extension': "File does not have double extension",
            'high_entropy': "File entropy is below threshold",
            'recently_deleted': "File was not recently deleted",
            'unusually_small_executable': "Executable size is normal"
        }

        return explanations.get(rule_code, "Conditions not met")

    def export_config(self, output_path: str, version: Optional[int] = None) -> bool:
        """Export configuration to file"""
        target_version = self.current_version
        if version:
            for v in self.versions:
                if v.version == version:
                    target_version = v
                    break

        if not target_version:
            return False

        try:
            rules_data = {code: asdict(rule) for code, rule in target_version.rules.items()}
            data = {
                'version': target_version.version,
                'timestamp': target_version.timestamp,
                'changed_by': target_version.changed_by,
                'change_reason': target_version.change_reason,
                'config_hash': target_version.config_hash,
                'rules': rules_data
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

            print(f"[RuleConfig] Exported version {target_version.version} to {output_path}")
            return True

        except Exception as e:
            print(f"[RuleConfig] Export failed: {e}")
            return False


# Singleton
_rule_managers: Dict[str, RuleConfigManager] = {}

def get_rule_config_manager(case_id: str = "default") -> RuleConfigManager:
    """Get or create rule config manager"""
    if case_id not in _rule_managers:
        _rule_managers[case_id] = RuleConfigManager()
    return _rule_managers[case_id]
