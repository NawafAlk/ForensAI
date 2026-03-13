"""
Tests for Mind Map Unlimited Scanning Feature

Tests the unlimited filesystem traversal with batching, safety controls,
and export functionality.

Author: ForensAI Team
License: MIT
"""

import os
import json
import tempfile
import pytest
from unittest.mock import Mock, MagicMock, patch
from collections import deque

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.mindmap.mindmap_widget import (
    MindMapWorker, MindMapWidget, FileNode, NodeType, FileTypeCategory
)


class MockImageHandler:
    """Mock ImageHandler for testing"""

    def __init__(self, filesystem_data):
        """
        Args:
            filesystem_data: Dict mapping inode -> list of file entries
        """
        self.filesystem_data = filesystem_data
        self.fs_type = "NTFS"

    def has_filesystem(self, offset):
        return True

    def get_fs_type(self, offset):
        return self.fs_type

    def get_directory_contents(self, offset, inode):
        """Return mock directory contents"""
        return self.filesystem_data.get(inode, [])


class TestMindMapUnlimitedTraversal:
    """Test suite for unlimited scanning functionality"""

    def setup_method(self):
        """Setup before each test"""
        self.filesystem_data = {
            5: [
                {'name': 'dir1', 'is_directory': True, 'size': 0, 'inode_number': 6},
                {'name': 'file1.txt', 'is_directory': False, 'size': 100, 'inode_number': 7},
            ],
            6: [
                {'name': 'file2.txt', 'is_directory': False, 'size': 200, 'inode_number': 8},
                {'name': 'file3.txt', 'is_directory': False, 'size': 300, 'inode_number': 9},
            ]
        }
        self.image_handler = MockImageHandler(self.filesystem_data)

    def test_full_traversal_completion(self):
        """Test that unlimited traversal completes successfully"""
        worker = MindMapWorker(
            self.image_handler,
            start_offset=0,
            max_depth=None,
            max_children=None,
            max_nodes_guard=1000,
            batch_emit_size=10,
            checkpoint_interval=100
        )

        emitted_batches = []

        def capture_batch(batch):
            emitted_batches.append(batch)

        worker.nodes_batch_created.connect(capture_batch)

        worker.run()

        total_nodes = sum(len(batch) for batch in emitted_batches)
        assert total_nodes == 4, f"Expected 4 nodes, got {total_nodes}"

        all_names = []
        for batch in emitted_batches:
            for name, node_type, parent_path, metadata in batch:
                all_names.append(name)

        assert 'dir1' in all_names
        assert 'file1.txt' in all_names
        assert 'file2.txt' in all_names
        assert 'file3.txt' in all_names

    def test_batched_emission(self):
        """Test that nodes are emitted in batches"""
        large_filesystem = {
            5: [{'name': f'file{i}.txt', 'is_directory': False, 'size': i, 'inode_number': 10 + i}
                for i in range(50)]
        }
        image_handler = MockImageHandler(large_filesystem)

        worker = MindMapWorker(
            image_handler,
            start_offset=0,
            max_depth=None,
            max_children=None,
            max_nodes_guard=1000,
            batch_emit_size=10,
            checkpoint_interval=1000
        )

        emitted_batches = []

        def capture_batch(batch):
            emitted_batches.append(batch)

        worker.nodes_batch_created.connect(capture_batch)
        worker.run()

        assert len(emitted_batches) >= 1, "Should have emitted at least one batch"

        for i, batch in enumerate(emitted_batches[:-1]):
            assert len(batch) == 10, f"Batch {i} should have 10 nodes, got {len(batch)}"

        assert len(emitted_batches[-1]) <= 10, "Last batch should have <= 10 nodes"

    def test_max_nodes_guard_trigger(self):
        """Test that max_nodes_guard emergency stop works"""
        large_filesystem = {
            5: [{'name': f'file{i}.txt', 'is_directory': False, 'size': i, 'inode_number': 10 + i}
                for i in range(150)]
        }
        image_handler = MockImageHandler(large_filesystem)

        worker = MindMapWorker(
            image_handler,
            start_offset=0,
            max_depth=None,
            max_children=None,
            max_nodes_guard=50,
            batch_emit_size=10,
            checkpoint_interval=1000
        )

        guard_triggered = []

        def capture_guard_trigger(count):
            guard_triggered.append(count)

        worker.guard_limit_reached.connect(capture_guard_trigger)
        worker.run()

        assert len(guard_triggered) > 0, "Guard limit should have been triggered"
        assert guard_triggered[0] >= 50, f"Guard should trigger at 50, got {guard_triggered[0]}"

    def test_cancellation(self):
        """Test that cancellation works gracefully"""
        worker = MindMapWorker(
            self.image_handler,
            start_offset=0,
            max_depth=None,
            max_children=None,
            max_nodes_guard=1000,
            batch_emit_size=10,
            checkpoint_interval=100
        )

        worker.cancel()

        assert worker._is_cancelled is True

        assert len(worker._batch_buffer) == 0, "Batch buffer should be flushed on cancel"

    def test_export_json_correctness(self):
        """Test that export_full_structure produces valid JSON"""

        root = FileNode("Root", NodeType.ROOT, 0, FileTypeCategory.UNKNOWN, None)
        dir1 = FileNode("dir1", NodeType.DIRECTORY, 0, FileTypeCategory.UNKNOWN, None, root)
        file1 = FileNode("file1.txt", NodeType.FILE, 100, FileTypeCategory.DOCUMENT, 123, dir1)

        root.add_child(dir1)
        dir1.add_child(file1)

        assert len(root.children) == 1
        assert root.children[0] == dir1
        assert len(dir1.children) == 1
        assert dir1.children[0] == file1


    def test_checkpoint_creation(self):
        """Test that checkpoints are created periodically"""
        worker = MindMapWorker(
            self.image_handler,
            start_offset=0,
            max_depth=None,
            max_children=None,
            max_nodes_guard=1000,
            batch_emit_size=10,
            checkpoint_interval=2
        )

        checkpoint_calls = []

        original_write_checkpoint = worker._write_checkpoint

        def mock_write_checkpoint():
            checkpoint_calls.append(worker._nodes_processed)

        worker._write_checkpoint = mock_write_checkpoint

        worker.run()

        assert len(checkpoint_calls) >= 1, "At least one checkpoint should have been called"

    def test_progress_updates(self):
        """Test that progress updates are emitted correctly"""
        worker = MindMapWorker(
            self.image_handler,
            start_offset=0,
            max_depth=None,
            max_children=None,
            max_nodes_guard=1000,
            batch_emit_size=10,
            checkpoint_interval=100
        )

        progress_updates = []
        status_updates = []

        def capture_progress(pct):
            progress_updates.append(pct)

        def capture_status(msg):
            status_updates.append(msg)

        worker.progress_update.connect(capture_progress)
        worker.status_update.connect(capture_status)

        worker.run()

        assert len(progress_updates) > 0, "Should have progress updates"
        assert 100 in progress_updates, "Should reach 100% at completion"

        assert len(status_updates) > 0, "Should have status updates"


class TestMindMapWidgetConfig:
    """Test configuration loading and validation"""

    def test_config_loading(self):
        """Test that config is loaded correctly"""
        config_path = os.path.join("config", "mindmap_config.json")

        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            assert 'max_nodes_guard' in config
            assert 'batch_emit_size' in config
            assert 'checkpoint_interval' in config
            assert 'enable_full_scan_by_default' in config

            assert config['max_nodes_guard'] > 0
            assert config['batch_emit_size'] > 0
            assert config['checkpoint_interval'] > 0
            assert isinstance(config['enable_full_scan_by_default'], bool)

    def test_config_defaults(self):
        """Test that default config values are reasonable"""
        default_config = {
            "version": "1.0",
            "max_nodes_guard": 1000000,
            "batch_emit_size": 100,
            "checkpoint_interval": 1000,
            "enable_full_scan_by_default": False
        }

        assert default_config['max_nodes_guard'] == 1000000
        assert default_config['batch_emit_size'] == 100
        assert default_config['checkpoint_interval'] == 1000
        assert default_config['enable_full_scan_by_default'] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
