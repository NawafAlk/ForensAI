# Mind Map Unlimited Scanning - Implementation Guide

## Overview

The Mind Map module now supports **unlimited filesystem traversal** with comprehensive safety controls, batched emission, and checkpoint recovery. This allows scanning entire forensic images without artificial depth or file count limits.

---

## What Changed

### Previous Behavior (Removed)
- **Max Depth** spinner: Limited directory traversal depth (default: 5 levels)
- **Max Children** spinner: Limited files per directory (default: 50 files)
- Individual node emission: Each node triggered a separate signal

### New Behavior
- **Enable Full Scan** checkbox: Unlimited traversal (no depth/children limits)
- **Confirmation dialog**: User must explicitly confirm unlimited scans
- **Batched emission**: Nodes emitted in batches of 100 for performance
- **Safety controls**: Emergency stop at configurable `max_nodes_guard`
- **Checkpoints**: Periodic saves every 1,000 nodes for recovery

---

## Safety Controls

### 1. max_nodes_guard (Emergency Stop)

**Purpose:** Prevents runaway scans from consuming all system resources.

**Default:** 1,000,000 nodes

**Configuration:** `config/mindmap_config.json`

```json
{
  "max_nodes_guard": 1000000,
  "max_nodes_guard_description": "Emergency safety limit..."
}
```

**Behavior:**
- When node count reaches this limit, scan stops automatically
- User is shown a warning dialog
- All discovered nodes up to that point are preserved
- Can be increased in config file for larger filesystems

**Example:**
```
⚠️ Emergency stop: max_nodes_guard (1,000,000) reached
Current count: 1,000,234 nodes

This limit prevents runaway scans. You can increase it in:
config/mindmap_config.json
```

---

### 2. Batched Emission

**Purpose:** Improve performance by reducing signal overhead.

**Default:** 100 nodes per batch

**Configuration:** `config/mindmap_config.json`

```json
{
  "batch_emit_size": 100,
  "batch_emit_size_description": "Number of nodes to collect before emitting..."
}
```

**Behavior:**
- Worker collects nodes in memory buffer
- Emits batch when buffer reaches `batch_emit_size`
- Final partial batch emitted at end of scan
- UI processes batches efficiently

**Performance Impact:**
- Previous: 10,000 nodes = 10,000 signal emissions
- New: 10,000 nodes = 100 batch emissions (99% reduction)

---

### 3. Periodic Checkpoints

**Purpose:** Enable recovery from interrupted scans.

**Default:** Every 1,000 nodes

**Configuration:** `config/mindmap_config.json`

```json
{
  "checkpoint_interval": 1000,
  "checkpoint_interval_description": "Write partial tree to temp file..."
}
```

**Behavior:**
- Checkpoint written to `ui/mindmap/checkpoints/` every N nodes
- Contains: node count, timestamp, partition offset
- Last 3 checkpoints kept automatically
- Non-critical: failures don't stop scan

**Checkpoint File Example:**
```json
{
  "nodes_processed": 5000,
  "timestamp": "14:32:18",
  "start_offset": 2048
}
```

**Location:** `ui/mindmap/checkpoints/checkpoint_{offset}_{count}.json`

---

### 4. Confirmation Dialog

**Purpose:** Warn users about unlimited scan implications.

**Trigger:** Checking "Enable Full Scan" checkbox

**Required Actions:**
1. Read warning message
2. Check "I understand and want to proceed with full scan"
3. Click "Enable Full Scan" button (styled red for emphasis)

**Warning Content:**
- Traverses entire filesystem without limits
- May take minutes to hours depending on size
- Uses significant memory and CPU
- Can be cancelled at any time
- Emergency stop at max_nodes_guard limit

---

## Configuration File

### Location
`config/mindmap_config.json`

### Full Configuration
```json
{
  "version": "1.0",
  "description": "Mind Map configuration for unlimited filesystem scanning",
  "max_nodes_guard": 1000000,
  "max_nodes_guard_description": "Emergency safety limit to prevent runaway scans. This is NOT a normal traversal limit - it only stops incorrectly configured or infinite-loop jobs. Default: 1,000,000 nodes.",
  "batch_emit_size": 100,
  "batch_emit_size_description": "Number of nodes to collect before emitting to UI. Larger batches = better performance but less frequent updates. Default: 100.",
  "checkpoint_interval": 1000,
  "checkpoint_interval_description": "Write partial tree to temp file every N nodes for recovery. Default: 1000.",
  "enable_full_scan_by_default": false,
  "enable_full_scan_by_default_description": "If true, full scan is enabled without confirmation. Use only in automated/CLI mode. Default: false (require user confirmation)."
}
```

### Customization Examples

**Large Filesystem (10M+ files):**
```json
{
  "max_nodes_guard": 15000000,
  "batch_emit_size": 200,
  "checkpoint_interval": 5000
}
```

**Small Filesystem (Quick Scans):**
```json
{
  "max_nodes_guard": 100000,
  "batch_emit_size": 50,
  "checkpoint_interval": 500
}
```

**Automated/CLI Mode:**
```json
{
  "enable_full_scan_by_default": true
}
```
⚠️ **Warning:** Only use `enable_full_scan_by_default: true` in automated scripts where user interaction is not possible.

---

## Usage Guide

### UI Usage (MainWindow Integration)

#### 1. Enable Full Scan
1. Open ForensAI application
2. Load forensic image
3. Navigate to "Mind Map" tab
4. In the right panel, check **"Enable Full Scan"**
5. Read confirmation dialog carefully
6. Check "I understand..." checkbox
7. Click "Enable Full Scan" button
8. Click "Generate Mind Map"

#### 2. Monitor Progress
- Progress bar shows percentage estimate
- Status label shows: "Processing: X,XXX nodes found (depth Y)..."
- Updates every 100 nodes

#### 3. Cancel Mid-Scan
- Click "Cancel" button at any time
- All nodes discovered so far are preserved
- Can export partial results

#### 4. Export Full Structure
After scan completes (or during scan):
```python
result = widget.export_full_structure("./exports/full_scan.json")
print(f"Exported {result['node_count']} nodes to {result['output_file']}")
```

---

### Programmatic API Usage

#### Basic Full Scan
```python
from ui.mindmap import MindMapWidget

# Create widget
widget = MindMapWidget()

# Load config (automatic)
# widget._load_config() is called in __init__

# Set image handler
widget.set_image_handler(image_handler, start_offset=0)

# Enable full scan (skip confirmation in automated mode)
widget.max_depth = None
widget.max_children = None
widget.full_scan_confirmed = True

# Start scan
widget._on_generate()

# Wait for completion (connect to worker.finished signal)
```

#### With Progress Monitoring
```python
def on_progress(percentage):
    print(f"Scan progress: {percentage}%")

def on_status(message):
    print(f"Status: {message}")

def on_complete(total_nodes):
    print(f"Scan complete: {total_nodes} nodes")
    result = widget.export_full_structure()
    if result['success']:
        print(f"Exported to: {result['output_file']}")

# Connect signals (after worker is created in _on_generate)
# widget.worker.progress_update.connect(on_progress)
# widget.worker.status_update.connect(on_status)
# widget.worker.finished.connect(on_complete)
```

#### Mid-Scan Export
```python
import time
from PySide6.QtCore import QTimer

# Start scan
widget._on_generate()

# Export every 10 seconds during scan
def periodic_export():
    if widget.worker and widget.worker.isRunning():
        result = widget.export_full_structure("./exports/partial_scan.json")
        if result['success']:
            print(f"Partial export: {result['node_count']} nodes")
        QTimer.singleShot(10000, periodic_export)  # Schedule next export

QTimer.singleShot(10000, periodic_export)  # Start in 10 seconds
```

---

## Recovery from Partial Scans

### Checkpoint Recovery (Automatic)

Checkpoints are written automatically during scans. They contain minimal metadata for debugging and progress tracking.

**To view checkpoint:**
```python
import json

checkpoint_file = "ui/mindmap/checkpoints/checkpoint_0_5000.json"
with open(checkpoint_file, 'r') as f:
    data = json.load(f)
    print(f"Nodes processed: {data['nodes_processed']}")
    print(f"Timestamp: {data['timestamp']}")
```

### Export Recovery (Manual)

If a scan is interrupted, use `export_full_structure()` to save discovered nodes:

```python
# After scan interruption
if widget.root_node:
    result = widget.export_full_structure("./exports/partial_recovery.json")
    if result['success']:
        print(f"Recovered {result['node_count']} nodes")
        print(f"Saved to: {result['output_file']}")
```

The exported JSON includes `scan_complete: false` field to indicate partial scan:
```json
{
  "source": {
    "start_offset": 0,
    "scan_complete": false
  },
  "statistics": {
    "total_nodes": 3245
  }
}
```

---

## Performance Considerations

### Memory Usage

**Per-Node Memory:** ~500 bytes

**Estimation:**
- 10,000 nodes ≈ 5 MB
- 100,000 nodes ≈ 50 MB
- 1,000,000 nodes ≈ 500 MB

**Recommendation:**
- For systems with 8GB+ RAM: Safe up to 1M nodes
- For systems with 16GB+ RAM: Safe up to 5M nodes
- Monitor system resources during large scans

### Scan Duration

**Factors:**
- Filesystem type (NTFS, Ext4, FAT)
- Image format (.dd, .E01)
- Number of files/directories
- Directory structure complexity
- Disk I/O speed

**Typical Performance:**
- Small filesystem (1,000 files): 1-2 seconds
- Medium filesystem (10,000 files): 10-30 seconds
- Large filesystem (100,000 files): 2-5 minutes
- Very large (1,000,000 files): 20-60 minutes

### Optimization Tips

1. **Increase batch size** for very large scans:
   ```json
   "batch_emit_size": 200
   ```

2. **Reduce checkpoint frequency** if I/O is bottleneck:
   ```json
   "checkpoint_interval": 5000
   ```

3. **Close unused applications** to free memory

4. **Use SSD** for image storage if possible

---

## Troubleshooting

### Issue: Scan Takes Too Long

**Solution:**
- Check filesystem size first: `image_handler.get_directory_contents(0, 5)`
- Consider using filters to focus on specific file types
- Increase `batch_emit_size` to 200 or 300
- Cancel and use depth limits for initial exploration

### Issue: Emergency Stop Triggered

**Symptom:** Dialog shows "max_nodes_guard (1,000,000) reached"

**Solution:**
1. Verify filesystem is actually that large (not a loop)
2. If legitimate, increase in config:
   ```json
   "max_nodes_guard": 5000000
   ```
3. Restart scan

### Issue: Out of Memory

**Symptom:** Application crashes or system becomes unresponsive

**Solution:**
- Close other applications
- Reduce max_nodes_guard:
  ```json
  "max_nodes_guard": 500000
  ```
- Use filters to scan only needed file types
- Upgrade system RAM

### Issue: Checkpoints Not Created

**Symptom:** No files in `ui/mindmap/checkpoints/`

**Solution:**
- Check write permissions for `ui/mindmap/` directory
- Ensure checkpoint_interval is not 0
- Check console for error messages
- Create directory manually if needed:
  ```bash
  mkdir -p ui/mindmap/checkpoints
  ```

---

## Testing

Run the test suite:
```bash
cd tests
python -m pytest test_mindmap_unlimited.py -v
```

**Tests Included:**
1. ✓ Full traversal completion
2. ✓ Batched emission (verifies batch size)
3. ✓ max_nodes_guard trigger
4. ✓ Graceful cancellation
5. ✓ Export JSON correctness
6. ✓ Checkpoint creation
7. ✓ Progress updates

---

## Demo

Run the demo application:
```bash
python examples/mindmap_demo.py
```

**Demo Features:**
- Tab 1: Full scan with unlimited traversal
- Tab 2: Export demo with mid-scan exports
- Console output showing progress and statistics
- Auto-export on completion

---

## CLI Usage Example

For automated forensic workflows:

```python
#!/usr/bin/env python3
"""
Automated Mind Map CLI Tool
Scans forensic image and exports full structure
"""

import sys
from PySide6.QtWidgets import QApplication
from ui.mindmap import MindMapWidget
from tools.image_handler import ImageHandler

def main():
    app = QApplication(sys.argv)

    # Load image
    image_path = sys.argv[1] if len(sys.argv) > 1 else "evidence.dd"
    handler = ImageHandler(image_path)

    # Create widget (headless)
    widget = MindMapWidget()
    widget.set_image_handler(handler, start_offset=0)

    # Enable full scan
    widget.max_depth = None
    widget.max_children = None
    widget.full_scan_confirmed = True

    # Handle completion
    def on_complete(total_nodes):
        print(f"Scan complete: {total_nodes} nodes")
        result = widget.export_full_structure(f"./exports/{image_path}_full.json")
        if result['success']:
            print(f"Exported to: {result['output_file']}")
            print(f"Files: {result.get('files', 0)}")
            print(f"Directories: {result.get('directories', 0)}")
        app.quit()

    widget.worker.finished.connect(on_complete)

    # Start
    print(f"Scanning {image_path}...")
    widget._on_generate()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
```

Run:
```bash
python cli_mindmap.py evidence.dd
```

---

## Best Practices

### ✅ DO
- Enable full scan for complete forensic analysis
- Monitor progress during large scans
- Export results periodically for long-running scans
- Configure max_nodes_guard appropriately for filesystem size
- Use checkpoints for recovery planning
- Test with small images first

### ❌ DON'T
- Disable max_nodes_guard (set to 0)
- Set batch_emit_size < 10 (poor performance)
- Run multiple unlimited scans simultaneously
- Ignore memory usage warnings
- Enable full scan by default for interactive use

---

## API Reference

### MindMapWidget.export_full_structure()

```python
def export_full_structure(
    self,
    output_path: str = None,
    include_metadata: bool = True
) -> Dict[str, Any]
```

**Parameters:**
- `output_path` (str, optional): Path to JSON output file. Auto-generated if None.
- `include_metadata` (bool): Include node positions and filter states. Default: True.

**Returns:**
```python
{
    'success': bool,
    'output_file': str,  # Path to exported file
    'node_count': int,   # Total nodes exported
    'total_size': int,   # Total bytes of all files
    'error': str         # Present only if success=False
}
```

**Example:**
```python
result = widget.export_full_structure("./exports/scan.json")
if result['success']:
    print(f"Success: {result['node_count']} nodes")
else:
    print(f"Error: {result['error']}")
```

---

## JSON Export Format

### Structure
```json
{
  "version": "1.0",
  "export_type": "full_structure",
  "timestamp": "14:32:18",
  "source": {
    "image_handler": "ImageHandler",
    "start_offset": 0,
    "scan_complete": true
  },
  "statistics": {
    "total_nodes": 10234,
    "files": 9123,
    "directories": 1111,
    "total_size": 52428800,
    "total_size_human": "50.00 MB"
  },
  "tree": {
    "name": "Root",
    "path": "Root",
    "type": "root",
    "size": 0,
    "child_count": 4,
    "children": [
      {
        "name": "Documents",
        "path": "Root/Documents",
        "type": "directory",
        "size": 0,
        "child_count": 3,
        "children": [...]
      }
    ]
  }
}
```

---

## Release Notes

### Version 2.0 - Unlimited Scanning

**Released:** 2025-11-10

**Major Changes:**
- ✅ Removed Max Depth and Max Children limits
- ✅ Added Enable Full Scan checkbox with confirmation
- ✅ Implemented batched node emission (100/batch)
- ✅ Added max_nodes_guard safety control (1M default)
- ✅ Added periodic checkpointing (every 1000 nodes)
- ✅ Added export_full_structure() API
- ✅ Created comprehensive test suite
- ✅ Updated demo with full scan examples

**Breaking Changes:**
- UI: `depth_spin` and `children_spin` removed
- API: Worker now uses `nodes_batch_created` signal instead of `node_created`
- Config: New `config/mindmap_config.json` file required

**Migration:**
```python
# Old code:
worker.node_created.connect(self._on_node_created)

# New code:
worker.nodes_batch_created.connect(self._on_nodes_batch_created)
```

---

## Support

For issues or questions:
1. Check this documentation
2. Review `examples/mindmap_demo.py`
3. Run test suite: `pytest tests/test_mindmap_unlimited.py`
4. Check `config/mindmap_config.json` settings
5. Review console output for errors

---

**Last Updated:** 2025-11-10
**Version:** 2.0
**Author:** ForensAI Team
