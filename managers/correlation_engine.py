"""
ForensAI - Correlation Engine
==============================
Tracks relationships between forensic artifacts to detect attack chains,
temporal clusters, and spatial patterns that indicate coordinated activity.

This engine enables the hybrid risk scorer to understand context:
- Files modified at the same time suggest coordinated action
- Suspicious files in the same directory suggest staging area
- Similar hashes indicate file copies or variations
"""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from bisect import insort, bisect_left, bisect_right
import os


@dataclass
class CorrelationInsight:
    """Insight discovered through artifact correlation."""

    insight_type: str
    description: str
    confidence: str
    artifact_ids: List[str]
    details: Dict = field(default_factory=dict)


@dataclass
class AttackChainStage:
    """A stage in a detected attack chain."""

    stage: str
    artifacts: List[Dict]
    confidence: str
    mitre_techniques: List[str]
    timestamp_range: Tuple[Optional[datetime], Optional[datetime]]


class IntervalTree:
    """Simple interval tree for O(log n) temporal range queries."""

    def __init__(self):
        self._points = []

    def insert(self, timestamp_minutes: int, artifact_id: str):
        """Insert a timestamp-artifact pair."""
        insort(self._points, (timestamp_minutes, artifact_id))

    def query_range(self, start_minutes: int, end_minutes: int) -> List[str]:
        """Find all artifact IDs within a time range. O(log n + k)."""
        left = bisect_left(self._points, (start_minutes,))
        right = bisect_right(self._points, (end_minutes + 1,))
        return [aid for _, aid in self._points[left:right]]

    def clear(self):
        self._points.clear()


class TrieNode:
    """Node in a path trie for spatial clustering."""

    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.artifact_ids: Set[str] = set()
        self.count: int = 0


class PathTrie:
    """Trie structure for efficient path-based spatial clustering."""

    def __init__(self):
        self.root = TrieNode()

    def insert(self, path: str, artifact_id: str):
        """Insert a path and its artifact ID."""
        parts = path.lower().replace('/', '\\').strip('\\').split('\\')
        node = self.root
        for part in parts:
            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]
            node.count += 1
        node.artifact_ids.add(artifact_id)

    def find_clusters(self, min_size: int = 2) -> List[Dict]:
        """Find directories with multiple artifacts."""
        clusters = []
        self._find_clusters_recursive(self.root, [], min_size, clusters)
        return clusters

    def _find_clusters_recursive(self, node: TrieNode, path_parts: List[str],
                                  min_size: int, clusters: List[Dict]):
        if len(node.artifact_ids) >= min_size:
            clusters.append({
                'path': '\\'.join(path_parts),
                'artifact_ids': list(node.artifact_ids),
                'count': len(node.artifact_ids)
            })
        for part, child in node.children.items():
            self._find_clusters_recursive(child, path_parts + [part], min_size, clusters)

    def get_artifacts_at_path(self, path: str) -> Set[str]:
        """Get all artifacts at a specific path."""
        parts = path.lower().replace('/', '\\').strip('\\').split('\\')
        node = self.root
        for part in parts:
            if part not in node.children:
                return set()
            node = node.children[part]
        return node.artifact_ids

    def clear(self):
        self.root = TrieNode()


class CorrelationEngine:
    """
    Track and analyze relationships between forensic artifacts.

    Provides:
    - Temporal clustering (files modified at same time)
    - Spatial clustering (suspicious files in same location)
    - Hash matching (duplicate/variant detection)
    - Attack chain reconstruction
    """

    TEMPORAL_WINDOW_MINUTES = 5

    MIN_CLUSTER_SIZE = 2

    STAGE_INDICATORS = {
        'initial_access': [
            'executable_in_downloads', 'executable_in_temp',
            'large_archive_recent', 'script_in_document'
        ],
        'execution': [
            'executable_in_temp', 'executable_in_appdata',
            'suspicious_extension', 'unsigned_executable'
        ],
        'persistence': [
            'file_in_startup', 'executable_in_appdata',
            'hidden_executable'
        ],
        'defense_evasion': [
            'timestomp_detected', 'hidden_executable',
            'system_file_wrong_location', 'masquerading_filename',
            'double_extension'
        ],
        'collection': [
            'large_archive_recent', 'encrypted_archive',
            'archive_in_temp'
        ],
        'exfiltration': [
            'large_archive_recent', 'encrypted_archive'
        ]
    }

    def __init__(self):
        """Initialize correlation engine with empty indexes."""
        self.artifacts: Dict[str, Dict] = {}
        self.risk_scores: Dict[str, int] = {}
        self.triggered_rules: Dict[str, List[str]] = {}

        self._temporal_index: Dict[str, Set[str]] = defaultdict(set)
        self._spatial_index: Dict[str, Set[str]] = defaultdict(set)
        self._hash_index: Dict[str, Set[str]] = defaultdict(set)

        self._interval_tree = IntervalTree()
        self._path_trie = PathTrie()

        self._clusters_dirty = True
        self._cached_clusters = []

        self._clusters: List[CorrelationInsight] = []
        self._attack_chain: List[AttackChainStage] = []

    def add_artifact(self, artifact_id: str, artifact: Dict,
                     risk_score: int = 0, rules: List[str] = None):
        """
        Register an artifact for correlation tracking.

        Args:
            artifact_id: Unique identifier for the artifact
            artifact: Artifact data dictionary
            risk_score: Risk score from rule engine
            rules: List of triggered rule codes
        """
        self.artifacts[artifact_id] = artifact
        self.risk_scores[artifact_id] = risk_score
        self.triggered_rules[artifact_id] = rules or []

        self._index_temporal(artifact_id, artifact)

        self._index_spatial(artifact_id, artifact)

        self._index_hash(artifact_id, artifact)

        self._clusters_dirty = True

    def _index_temporal(self, artifact_id: str, artifact: Dict):
        """Index artifact by timestamp for temporal clustering."""
        for ts_field in ['modified', 'created', 'accessed']:
            ts = artifact.get(ts_field)
            if ts:
                minute_key = self._timestamp_to_minute_key(ts)
                if minute_key:
                    self._temporal_index[minute_key].add(artifact_id)
                    try:
                        ts_minutes = int(minute_key[:8]) * 1440 + int(minute_key[8:10]) * 60 + int(minute_key[10:12])
                        self._interval_tree.insert(ts_minutes, artifact_id)
                    except (ValueError, IndexError):
                        pass
                break

    def _index_spatial(self, artifact_id: str, artifact: Dict):
        """Index artifact by directory for spatial clustering."""
        path = artifact.get('path', '')
        if path:
            dir_path = os.path.dirname(path.lower().replace('/', '\\'))
            if dir_path:
                self._spatial_index[dir_path].add(artifact_id)
                self._path_trie.insert(dir_path, artifact_id)

    def _index_hash(self, artifact_id: str, artifact: Dict):
        """Index artifact by hash for duplicate detection."""
        for hash_field in ['md5', 'sha1', 'sha256']:
            hash_val = artifact.get(hash_field)
            if hash_val:
                self._hash_index[hash_val.lower()].add(artifact_id)

    def _timestamp_to_minute_key(self, ts) -> Optional[str]:
        """Convert timestamp to minute-granularity key for indexing."""
        try:
            if isinstance(ts, datetime):
                return ts.strftime('%Y%m%d%H%M')
            elif isinstance(ts, str):
                for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S UTC', '%Y-%m-%d']:
                    try:
                        dt = datetime.strptime(ts.split('.')[0], fmt)
                        return dt.strftime('%Y%m%d%H%M')
                    except ValueError:
                        continue
        except:
            pass
        return None

    def _minute_key_to_datetime(self, key: str) -> Optional[datetime]:
        """Convert minute key back to datetime."""
        try:
            return datetime.strptime(key, '%Y%m%d%H%M')
        except:
            return None

    def find_related(self, artifact_id: str) -> Dict:
        """
        Find all artifacts related to a given artifact.

        Returns:
            Dictionary with temporal, spatial, and hash-matched relatives
        """
        if artifact_id not in self.artifacts:
            return {'temporal': [], 'spatial': [], 'hash_matches': []}

        artifact = self.artifacts[artifact_id]

        return {
            'temporal': self._find_temporal_neighbors(artifact_id, artifact),
            'spatial': self._find_spatial_neighbors(artifact_id, artifact),
            'hash_matches': self._find_hash_duplicates(artifact_id, artifact),
        }

    def _find_temporal_neighbors(self, artifact_id: str, artifact: Dict) -> List[Dict]:
        """Find artifacts modified within the temporal window."""
        neighbors = []

        for ts_field in ['modified', 'created']:
            ts = artifact.get(ts_field)
            if ts:
                center_key = self._timestamp_to_minute_key(ts)
                if center_key:
                    center_dt = self._minute_key_to_datetime(center_key)
                    if center_dt:
                        for delta in range(-self.TEMPORAL_WINDOW_MINUTES,
                                           self.TEMPORAL_WINDOW_MINUTES + 1):
                            check_dt = center_dt + timedelta(minutes=delta)
                            check_key = check_dt.strftime('%Y%m%d%H%M')

                            for other_id in self._temporal_index.get(check_key, set()):
                                if other_id != artifact_id and other_id not in [n['id'] for n in neighbors]:
                                    other = self.artifacts.get(other_id, {})
                                    neighbors.append({
                                        'id': other_id,
                                        'name': other.get('name', 'unknown'),
                                        'path': other.get('path', ''),
                                        'risk_score': self.risk_scores.get(other_id, 0),
                                        'time_delta_minutes': delta
                                    })
                break

        neighbors.sort(key=lambda x: x['risk_score'], reverse=True)
        return neighbors[:10]

    def _find_spatial_neighbors(self, artifact_id: str, artifact: Dict) -> List[Dict]:
        """Find artifacts in the same directory."""
        neighbors = []

        path = artifact.get('path', '')
        if path:
            dir_path = os.path.dirname(path.lower().replace('/', '\\'))
            if dir_path:
                for other_id in self._spatial_index.get(dir_path, set()):
                    if other_id != artifact_id:
                        other = self.artifacts.get(other_id, {})
                        neighbors.append({
                            'id': other_id,
                            'name': other.get('name', 'unknown'),
                            'path': other.get('path', ''),
                            'risk_score': self.risk_scores.get(other_id, 0),
                            'same_directory': True
                        })

        neighbors.sort(key=lambda x: x['risk_score'], reverse=True)
        return neighbors[:10]

    def _find_hash_duplicates(self, artifact_id: str, artifact: Dict) -> List[Dict]:
        """Find artifacts with matching hashes."""
        matches = []

        for hash_field in ['md5', 'sha1', 'sha256']:
            hash_val = artifact.get(hash_field)
            if hash_val:
                hash_lower = hash_val.lower()
                for other_id in self._hash_index.get(hash_lower, set()):
                    if other_id != artifact_id:
                        other = self.artifacts.get(other_id, {})
                        matches.append({
                            'id': other_id,
                            'name': other.get('name', 'unknown'),
                            'path': other.get('path', ''),
                            'hash_type': hash_field,
                            'hash_match': True
                        })

        return matches

    def detect_clusters(self) -> List[CorrelationInsight]:
        """
        Detect suspicious clusters of artifacts.

        Returns:
            List of discovered correlation insights
        """
        clusters = []

        clusters.extend(self._detect_temporal_bursts())

        clusters.extend(self._detect_spatial_hotspots())

        clusters.extend(self._detect_hash_spreading())

        self._clusters = clusters
        return clusters

    def _detect_temporal_bursts(self) -> List[CorrelationInsight]:
        """Detect groups of high-risk files modified at the same time."""
        bursts = []

        for minute_key, artifact_ids in self._temporal_index.items():
            if len(artifact_ids) < self.MIN_CLUSTER_SIZE:
                continue

            high_risk_ids = [
                aid for aid in artifact_ids
                if self.risk_scores.get(aid, 0) >= 40
            ]

            if len(high_risk_ids) >= self.MIN_CLUSTER_SIZE:
                total_risk = sum(self.risk_scores.get(aid, 0) for aid in high_risk_ids)
                avg_risk = total_risk / len(high_risk_ids)

                confidence = 'high' if avg_risk >= 70 else 'medium' if avg_risk >= 50 else 'low'

                bursts.append(CorrelationInsight(
                    insight_type='temporal_cluster',
                    description=f'{len(high_risk_ids)} suspicious files modified within {self.TEMPORAL_WINDOW_MINUTES} minutes',
                    confidence=confidence,
                    artifact_ids=list(high_risk_ids),
                    details={
                        'timestamp': self._minute_key_to_datetime(minute_key),
                        'average_risk': avg_risk,
                        'total_risk': total_risk,
                        'file_count': len(high_risk_ids)
                    }
                ))

        return bursts

    def _detect_spatial_hotspots(self) -> List[CorrelationInsight]:
        """Detect directories with multiple suspicious files."""
        hotspots = []

        for dir_path, artifact_ids in self._spatial_index.items():
            if len(artifact_ids) < self.MIN_CLUSTER_SIZE:
                continue

            suspicious_dirs = ['temp', 'tmp', 'appdata', 'downloads', 'startup', 'run']
            is_suspicious_location = any(sd in dir_path.lower() for sd in suspicious_dirs)

            high_risk_ids = [
                aid for aid in artifact_ids
                if self.risk_scores.get(aid, 0) >= 40
            ]

            if len(high_risk_ids) >= self.MIN_CLUSTER_SIZE or (
                is_suspicious_location and len(high_risk_ids) >= 1
            ):
                total_risk = sum(self.risk_scores.get(aid, 0) for aid in high_risk_ids)
                avg_risk = total_risk / len(high_risk_ids) if high_risk_ids else 0

                confidence = 'high' if is_suspicious_location and avg_risk >= 60 else \
                            'medium' if avg_risk >= 50 else 'low'

                hotspots.append(CorrelationInsight(
                    insight_type='spatial_cluster',
                    description=f'{len(high_risk_ids)} suspicious files in {os.path.basename(dir_path) or dir_path}',
                    confidence=confidence,
                    artifact_ids=list(high_risk_ids),
                    details={
                        'directory': dir_path,
                        'is_suspicious_location': is_suspicious_location,
                        'average_risk': avg_risk,
                        'file_count': len(high_risk_ids)
                    }
                ))

        return hotspots

    def _detect_hash_spreading(self) -> List[CorrelationInsight]:
        """Detect files with same hash in multiple locations."""
        spreading = []

        for hash_val, artifact_ids in self._hash_index.items():
            if len(artifact_ids) < 2:
                continue

            directories = set()
            for aid in artifact_ids:
                artifact = self.artifacts.get(aid, {})
                path = artifact.get('path', '')
                if path:
                    directories.add(os.path.dirname(path.lower()))

            if len(directories) >= 2:
                spreading.append(CorrelationInsight(
                    insight_type='hash_spreading',
                    description=f'Identical file found in {len(directories)} different locations',
                    confidence='medium',
                    artifact_ids=list(artifact_ids),
                    details={
                        'hash': hash_val,
                        'locations': list(directories),
                        'copy_count': len(artifact_ids)
                    }
                ))

        return spreading

    def build_attack_timeline(self) -> List[AttackChainStage]:
        """
        Reconstruct potential attack timeline from artifacts.

        Analyzes triggered rules to map artifacts to attack stages
        and orders them chronologically.

        Returns:
            List of attack chain stages in chronological order
        """
        stages: Dict[str, List[Dict]] = defaultdict(list)

        for artifact_id, rules in self.triggered_rules.items():
            artifact = self.artifacts.get(artifact_id, {})
            risk_score = self.risk_scores.get(artifact_id, 0)

            if risk_score < 40:
                continue

            for stage, indicators in self.STAGE_INDICATORS.items():
                matching_rules = [r for r in rules if r in indicators]
                if matching_rules:
                    stages[stage].append({
                        'artifact_id': artifact_id,
                        'artifact': artifact,
                        'matching_rules': matching_rules,
                        'risk_score': risk_score,
                        'timestamp': artifact.get('modified') or artifact.get('created')
                    })

        timeline = []
        stage_order = [
            'initial_access', 'execution', 'persistence',
            'defense_evasion', 'collection', 'exfiltration'
        ]

        for stage in stage_order:
            if stage in stages and stages[stage]:
                stage_artifacts = sorted(
                    stages[stage],
                    key=lambda x: str(x.get('timestamp', ''))
                )

                timestamps = [a.get('timestamp') for a in stage_artifacts if a.get('timestamp')]
                ts_range = (
                    min(timestamps) if timestamps else None,
                    max(timestamps) if timestamps else None
                )

                mitre_map = {
                    'executable_in_downloads': 'T1105',
                    'executable_in_temp': 'T1059',
                    'file_in_startup': 'T1547.001',
                    'timestomp_detected': 'T1070.006',
                    'hidden_executable': 'T1564.001',
                    'large_archive_recent': 'T1074',
                    'encrypted_archive': 'T1560.001',
                }
                mitre_techniques = set()
                for artifact_data in stage_artifacts:
                    for rule in artifact_data.get('matching_rules', []):
                        if rule in mitre_map:
                            mitre_techniques.add(mitre_map[rule])

                avg_risk = sum(a['risk_score'] for a in stage_artifacts) / len(stage_artifacts)
                confidence = 'high' if avg_risk >= 70 else 'medium' if avg_risk >= 50 else 'low'

                timeline.append(AttackChainStage(
                    stage=stage,
                    artifacts=[a['artifact'] for a in stage_artifacts],
                    confidence=confidence,
                    mitre_techniques=list(mitre_techniques),
                    timestamp_range=ts_range
                ))

        self._attack_chain = timeline
        return timeline

    def get_correlation_summary(self, artifact_id: str) -> Dict:
        """
        Get a complete correlation summary for an artifact.

        Returns:
            Dictionary with related artifacts, clusters, and attack chain position
        """
        related = self.find_related(artifact_id)

        artifact_clusters = [
            c for c in self._clusters
            if artifact_id in c.artifact_ids
        ]

        attack_stage = None
        for stage in self._attack_chain:
            artifact_ids_in_stage = [
                self._get_artifact_id(a) for a in stage.artifacts
            ]
            if artifact_id in artifact_ids_in_stage:
                attack_stage = {
                    'stage': stage.stage,
                    'confidence': stage.confidence,
                    'mitre_techniques': stage.mitre_techniques
                }
                break

        return {
            'related_artifacts': related,
            'clusters': [
                {
                    'type': c.insight_type,
                    'description': c.description,
                    'confidence': c.confidence,
                    'artifact_count': len(c.artifact_ids)
                }
                for c in artifact_clusters
            ],
            'attack_chain_stage': attack_stage,
            'total_related': (
                len(related.get('temporal', [])) +
                len(related.get('spatial', [])) +
                len(related.get('hash_matches', []))
            )
        }

    def _get_artifact_id(self, artifact: Dict) -> str:
        """Extract artifact ID from artifact dict."""
        return str(artifact.get('inode', artifact.get('hash', artifact.get('name', ''))))

    def reconstruct_attack_chain(self) -> Dict:
        """
        Reconstruct attack chain with enhanced temporal ordering.

        Returns:
            Dictionary with attack chain stages, timeline, and confidence assessment
        """
        timeline = self.build_attack_timeline()

        if not timeline:
            return {
                'detected': False,
                'stages': [],
                'total_artifacts': 0,
                'confidence': 'low',
                'timeline_span': None
            }

        stage_confidences = [s.confidence for s in timeline]
        high_count = stage_confidences.count('high')
        total = len(stage_confidences)

        if high_count >= total * 0.6:
            overall_confidence = 'high'
        elif high_count >= total * 0.3:
            overall_confidence = 'medium'
        else:
            overall_confidence = 'low'

        all_timestamps = []
        for stage in timeline:
            if stage.timestamp_range[0]:
                all_timestamps.append(str(stage.timestamp_range[0]))
            if stage.timestamp_range[1]:
                all_timestamps.append(str(stage.timestamp_range[1]))

        timeline_span = None
        if all_timestamps:
            timeline_span = {'start': min(all_timestamps), 'end': max(all_timestamps)}

        stages = []
        for stage in timeline:
            stages.append({
                'stage': stage.stage,
                'artifact_count': len(stage.artifacts),
                'confidence': stage.confidence,
                'mitre_techniques': stage.mitre_techniques,
                'timestamp_range': {
                    'start': str(stage.timestamp_range[0]) if stage.timestamp_range[0] else None,
                    'end': str(stage.timestamp_range[1]) if stage.timestamp_range[1] else None
                },
                'artifacts': [
                    {
                        'name': a.get('name', 'unknown'),
                        'path': a.get('path', ''),
                        'risk_score': self.risk_scores.get(self._get_artifact_id(a), 0)
                    }
                    for a in stage.artifacts[:10]
                ]
            })

        total_artifacts = sum(len(s.artifacts) for s in timeline)

        return {
            'detected': True,
            'stages': stages,
            'stage_count': len(stages),
            'total_artifacts': total_artifacts,
            'confidence': overall_confidence,
            'timeline_span': timeline_span
        }

    def detect_clusters_incremental(self) -> List[CorrelationInsight]:
        """
        Detect clusters incrementally (avoids full recompute if data hasn't changed).
        """
        if not self._clusters_dirty and self._cached_clusters:
            return self._cached_clusters

        clusters = self.detect_clusters()
        self._cached_clusters = clusters
        self._clusters_dirty = False
        return clusters

    def clear(self):
        """Clear all tracked artifacts and indexes."""
        self.artifacts.clear()
        self.risk_scores.clear()
        self.triggered_rules.clear()
        self._temporal_index.clear()
        self._spatial_index.clear()
        self._hash_index.clear()
        self._clusters.clear()
        self._attack_chain.clear()
        self._interval_tree.clear()
        self._path_trie.clear()
        self._clusters_dirty = True
        self._cached_clusters = []


_correlation_engine: Optional[CorrelationEngine] = None


def get_correlation_engine() -> CorrelationEngine:
    """Get singleton correlation engine instance."""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine()
    return _correlation_engine
