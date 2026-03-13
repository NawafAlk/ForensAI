"""
ForensAI - Block/Cluster Map System
====================================
Tracks cluster ownership across filesystem and carved data to enable
overwriting analysis and timeline reconstruction.

Provides:
- Cluster-level ownership tracking
- Overwrite analysis for deleted/carved files
- Timeline reconstruction for data recovery
"""

import struct
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict


@dataclass
class ClusterInfo:
    """Information about a single cluster on disk."""

    cluster_id: int  # Cluster number
    offset: int  # Byte offset on disk
    size: int  # Cluster size in bytes
    status: str = 'unallocated'  # 'allocated', 'unallocated', 'slack', 'metadata'

    # Current owner (for allocated clusters)
    owner_now: Optional[str] = None  # "inode:12345" or file path
    owner_inode: Optional[int] = None
    owner_path: Optional[str] = None
    owner_timestamp: Optional[str] = None

    # Historical owners (for carved/deleted files)
    owner_past: List[Dict] = field(default_factory=list)  # [{'carved_id': X, 'file_type': 'jpg', ...}]

    # Metadata
    last_modified: Optional[datetime] = None


@dataclass
class OverwriteAnalysis:
    """Analysis result for overwritten/deleted file."""

    total_clusters: int
    recovered_clusters: int
    recovery_percentage: float

    # Files that overwrote this data
    overwritten_by: List[Tuple[str, str, int]]  # [(filename, timestamp, cluster_count)]

    # Unallocated clusters (not yet overwritten)
    unallocated_clusters: int

    # Fragmentation analysis
    fragmentation_score: float  # 0-100, higher = more fragmented
    contiguous_runs: int  # Number of contiguous cluster runs
    largest_run_size: int  # Size of largest contiguous run

    # Timeline of events
    timeline: List[Dict]  # [{'time': '...', 'event': 'deleted'}, ...]

    # Summary narrative (for AI to expand)
    summary: str

    # New fields for UI display
    @property
    def clusters_total(self) -> int:
        """Alias for UI consistency."""
        return self.total_clusters

    @property
    def clusters_intact(self) -> int:
        """Alias for UI consistency."""
        return self.recovered_clusters

    @property
    def clusters_reused(self) -> int:
        """Count of reused/overwritten clusters."""
        return sum(count for _, _, count in self.overwritten_by)

    @property
    def clusters_wiped(self) -> int:
        """Clusters that were wiped (zeros, patterns)."""
        # For now, calculate as: total - recovered - reused
        return max(0, self.total_clusters - self.recovered_clusters - self.clusters_reused)

    @property
    def overwrite_risk_pct(self) -> float:
        """Percentage of file that's been overwritten."""
        return round(100 - self.recovery_percentage, 1)

    def to_ui_text(self) -> str:
        """Format for UI display next to rule chain."""
        lines = [
            "Overwrite Analysis:",
            f"• {self.overwrite_risk_pct}% of file area affected"
        ]

        if self.clusters_reused > 0:
            lines.append(f"• {self.clusters_reused}/{self.total_clusters} clusters reused by:")
            for filepath, timestamp, count in self.overwritten_by[:3]:  # Top 3
                import os
                filename = os.path.basename(filepath)
                lines.append(f"  - {filename} ({count} clusters)")

        if self.clusters_wiped > 0:
            lines.append(f"• {self.clusters_wiped} clusters wiped (pattern: 0x00)")

        if self.recovered_clusters > 0:
            lines.append(f"• {self.recovered_clusters} clusters intact (recoverable)")

        return "\n".join(lines)

    def to_risk_contribution(self) -> int:
        """Calculate risk score contribution from overwrite analysis."""
        # Base contribution on overwrite percentage
        risk_points = 0

        if self.overwrite_risk_pct > 70:
            risk_points += 30  # Heavy overwriting = high suspicion
        elif self.overwrite_risk_pct > 40:
            risk_points += 20
        elif self.overwrite_risk_pct > 10:
            risk_points += 10

        # Add points for multiple overwriters (indicates deliberate action)
        if len(self.overwritten_by) > 2:
            risk_points += 15

        # Add points for high fragmentation (unusual)
        if self.fragmentation_score > 60:
            risk_points += 10

        return risk_points


class ClusterIndex:
    """
    Manages cluster-level tracking for forensic analysis.

    Builds an index of cluster ownership from:
    1. Allocated files in the filesystem
    2. Carved/deleted files
    3. Unallocated space
    """

    def __init__(self, image_handler, cluster_size: int = 4096):
        """
        Initialize cluster index.

        Args:
            image_handler: ImageHandler instance
            cluster_size: Cluster size in bytes (default 4096 for NTFS)
        """
        self.image_handler = image_handler
        self.cluster_size = cluster_size
        self.clusters: Dict[int, ClusterInfo] = {}
        self.indexed_partitions: Set[int] = set()

    def build_index(self, start_offset: int, force_rebuild: bool = False):
        """
        Build cluster index for a partition.

        Args:
            start_offset: Partition start offset
            force_rebuild: Rebuild even if already indexed
        """
        if start_offset in self.indexed_partitions and not force_rebuild:
            return  # Already indexed

        print(f"Building cluster index for partition at offset {start_offset}...")

        # Step 1: Index allocated files
        self._index_allocated_files(start_offset)

        # Step 2: Mark remaining clusters as unallocated
        # (This would require reading the allocation bitmap from filesystem)

        self.indexed_partitions.add(start_offset)
        print(f"Cluster index built: {len(self.clusters)} clusters tracked")

    def _index_allocated_files(self, start_offset: int, inode: Optional[int] = None,
                               path_prefix: str = ""):
        """
        Recursively index all allocated files in filesystem.

        Args:
            start_offset: Partition offset
            inode: Current directory inode (None for root)
            path_prefix: Path prefix for building full paths
        """
        try:
            entries = self.image_handler.get_directory_contents(start_offset, inode)

            for entry in entries:
                entry_name = entry.get("name", "")

                # Skip . and ..
                if entry_name in [".", ".."]:
                    continue

                # Build full path
                full_path = f"{path_prefix}/{entry_name}" if path_prefix else entry_name
                entry_inode = entry.get("inode_number")

                if entry.get("is_directory"):
                    # Recursively process directory
                    self._index_allocated_files(start_offset, entry_inode, full_path)
                else:
                    # Index file clusters
                    self._index_file_clusters(
                        start_offset=start_offset,
                        inode=entry_inode,
                        path=full_path,
                        size=entry.get("size", 0),
                        modified=entry.get("modified", "")
                    )

        except Exception as e:
            # Continue even if directory read fails
            pass

    def _index_file_clusters(self, start_offset: int, inode: int, path: str,
                            size: int, modified: str):
        """
        Index clusters used by a specific file.

        Args:
            start_offset: Partition offset
            inode: File inode number
            path: File path
            size: File size
            modified: Modification timestamp
        """
        try:
            # Get file content to understand its cluster allocation
            # Note: For large files, we'd ideally get just the runlist, not full content
            # But ImageHandler doesn't expose runlist directly, so we work with what we have

            # Calculate cluster range based on file size
            num_clusters = (size + self.cluster_size - 1) // self.cluster_size

            if num_clusters == 0:
                return

            # For now, we track that this file exists but don't have exact cluster mapping
            # (Would need pytsk3 file.read_random() with offset to get exact clusters)
            # Store file metadata for later analysis

            # This is a simplified version - full implementation would:
            # 1. Get file's data runs from filesystem
            # 2. Map each run to cluster IDs
            # 3. Mark those clusters as allocated to this file

        except Exception as e:
            pass

    def add_carved_file(self, carved_id: str, file_type: str, offset: int,
                        size: int, deleted_time: Optional[str] = None):
        """
        Register a carved/deleted file in the cluster map.

        Args:
            carved_id: Unique identifier for carved file
            file_type: File type (jpg, doc, etc.)
            offset: Byte offset where file was found
            size: File size in bytes
            deleted_time: When file was deleted (if known)
        """
        start_cluster = offset // self.cluster_size
        num_clusters = (size + self.cluster_size - 1) // self.cluster_size

        for i in range(num_clusters):
            cluster_id = start_cluster + i
            cluster_offset = cluster_id * self.cluster_size

            if cluster_id not in self.clusters:
                # Create cluster info
                self.clusters[cluster_id] = ClusterInfo(
                    cluster_id=cluster_id,
                    offset=cluster_offset,
                    size=self.cluster_size
                )

            cluster = self.clusters[cluster_id]

            # Add to historical owners
            cluster.owner_past.append({
                'carved_id': carved_id,
                'file_type': file_type,
                'deleted_time': deleted_time,
                'offset': offset,
                'size': size
            })

    def analyze_overwrite(self, carved_id: str, carved_data: Dict) -> OverwriteAnalysis:
        """
        Analyze overwriting for a carved file.

        Args:
            carved_id: Carved file identifier
            carved_data: Dictionary with file info (offset, size, deleted_time, etc.)

        Returns:
            OverwriteAnalysis with detailed overwrite information
        """
        offset = carved_data.get('offset', 0)
        size = carved_data.get('size', 0)
        file_type = carved_data.get('file_type', 'unknown')
        deleted_time = carved_data.get('deleted_time')

        # Register this carved file first
        self.add_carved_file(carved_id, file_type, offset, size, deleted_time)

        # Calculate cluster range
        start_cluster = offset // self.cluster_size
        num_clusters = (size + self.cluster_size - 1) // self.cluster_size

        # Analyze each cluster
        recovered = 0
        unallocated = 0
        overwriters = defaultdict(int)  # filename -> cluster_count
        overwriter_times = {}  # filename -> timestamp
        cluster_states = []  # Track state of each cluster for fragmentation

        for i in range(num_clusters):
            cluster_id = start_cluster + i

            if cluster_id not in self.clusters:
                # Cluster not tracked = likely unallocated
                unallocated += 1
                recovered += 1  # Can recover from unallocated
                cluster_states.append('unallocated')
                continue

            cluster = self.clusters[cluster_id]

            if cluster.status == 'unallocated':
                unallocated += 1
                recovered += 1
                cluster_states.append('unallocated')
            elif cluster.status == 'allocated' and cluster.owner_path:
                # Overwritten by another file
                overwriters[cluster.owner_path] += 1
                overwriter_times[cluster.owner_path] = cluster.owner_timestamp
                cluster_states.append(f'overwritten:{cluster.owner_path}')
            else:
                # Unknown status - assume recoverable
                recovered += 1
                cluster_states.append('unknown')

        # Calculate fragmentation metrics
        frag_score, contiguous_runs, largest_run = self._calculate_fragmentation(cluster_states)

        # Build overwritten_by list
        overwritten_by = []
        for filepath, cluster_count in overwriters.items():
            timestamp = overwriter_times.get(filepath, 'unknown')
            overwritten_by.append((filepath, timestamp, cluster_count))

        # Sort by cluster count (most overwriting first)
        overwritten_by.sort(key=lambda x: x[2], reverse=True)

        # Calculate recovery percentage
        recovery_pct = (recovered / num_clusters * 100) if num_clusters > 0 else 0

        # Build timeline
        timeline = []

        if deleted_time:
            timeline.append({
                'time': deleted_time,
                'event': f'File deleted ({file_type.upper()}, {self._format_size(size)})'
            })

        for filepath, timestamp, count in overwritten_by:
            timeline.append({
                'time': timestamp,
                'event': f'{filepath} overwrote {count} clusters ({self._format_size(count * self.cluster_size)})'
            })

        # Generate summary
        if recovery_pct >= 90:
            summary = f"High recovery chance: {recovery_pct:.1f}% of data intact"
        elif recovery_pct >= 50:
            summary = f"Partial recovery possible: {recovery_pct:.1f}% of data intact"
        elif recovery_pct >= 20:
            summary = f"Limited recovery: only {recovery_pct:.1f}% of data intact"
        else:
            summary = f"Minimal recovery: {recovery_pct:.1f}% of data intact, heavily overwritten"

        if overwritten_by:
            top_overwriter = overwritten_by[0][0]
            summary += f". Primary overwriter: {top_overwriter}"

        # Add fragmentation info to summary
        if frag_score > 50:
            summary += f". Highly fragmented ({contiguous_runs} fragments)"
        elif frag_score > 20:
            summary += f". Moderately fragmented ({contiguous_runs} fragments)"

        return OverwriteAnalysis(
            total_clusters=num_clusters,
            recovered_clusters=recovered,
            recovery_percentage=recovery_pct,
            overwritten_by=overwritten_by,
            unallocated_clusters=unallocated,
            fragmentation_score=frag_score,
            contiguous_runs=contiguous_runs,
            largest_run_size=largest_run,
            timeline=timeline,
            summary=summary
        )

    def get_cluster_info(self, byte_offset: int) -> Optional[ClusterInfo]:
        """
        Get information about the cluster at a given byte offset.

        Args:
            byte_offset: Offset in bytes

        Returns:
            ClusterInfo or None
        """
        cluster_id = byte_offset // self.cluster_size
        return self.clusters.get(cluster_id)

    def get_statistics(self) -> Dict:
        """
        Get cluster map statistics.

        Returns:
            Dictionary with statistics
        """
        total = len(self.clusters)
        allocated = sum(1 for c in self.clusters.values() if c.status == 'allocated')
        unallocated = sum(1 for c in self.clusters.values() if c.status == 'unallocated')

        return {
            'total_clusters': total,
            'allocated': allocated,
            'unallocated': unallocated,
            'tracked_size_bytes': total * self.cluster_size,
            'partitions_indexed': len(self.indexed_partitions)
        }

    def _calculate_fragmentation(self, cluster_states: List[str]) -> tuple:
        """
        Calculate fragmentation score for a file based on cluster states.

        Args:
            cluster_states: List of cluster states ('unallocated', 'overwritten:X', 'unknown')

        Returns:
            Tuple of (fragmentation_score, contiguous_runs, largest_run_size)
        """
        if not cluster_states:
            return 0.0, 0, 0

        # Count contiguous runs of same state
        runs = []
        current_run_state = cluster_states[0]
        current_run_length = 1

        for i in range(1, len(cluster_states)):
            if cluster_states[i] == current_run_state:
                current_run_length += 1
            else:
                runs.append((current_run_state, current_run_length))
                current_run_state = cluster_states[i]
                current_run_length = 1

        # Add final run
        runs.append((current_run_state, current_run_length))

        # Calculate metrics
        num_runs = len(runs)
        largest_run = max(r[1] for r in runs)
        total_clusters = len(cluster_states)

        # Fragmentation score:
        # - More runs = higher fragmentation
        # - Smaller average run size = higher fragmentation
        # - Ideal (contiguous) = 1 run, score = 0
        # - Worst case (every cluster different) = N runs, score = 100

        if num_runs == 1:
            frag_score = 0.0  # Perfectly contiguous
        else:
            # Score based on ratio of runs to total clusters
            # If every cluster is its own run: num_runs = total_clusters, score = 100
            # Use logarithmic scaling for better distribution
            run_ratio = num_runs / total_clusters
            frag_score = min(100.0, run_ratio * 150)  # Scale to 0-100

        return round(frag_score, 2), num_runs, largest_run

    @staticmethod
    def _format_size(bytes_size: int) -> str:
        """Format byte size to human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} PB"


# Singleton instance per image
_cluster_indexes: Dict[str, ClusterIndex] = {}


def get_cluster_index(image_handler, image_path: str = None) -> ClusterIndex:
    """
    Get or create ClusterIndex for an image.

    Args:
        image_handler: ImageHandler instance
        image_path: Optional image path for caching

    Returns:
        ClusterIndex instance
    """
    global _cluster_indexes

    if image_path is None:
        image_path = getattr(image_handler, 'image_path', 'default')

    if image_path not in _cluster_indexes:
        _cluster_indexes[image_path] = ClusterIndex(image_handler)

    return _cluster_indexes[image_path]
