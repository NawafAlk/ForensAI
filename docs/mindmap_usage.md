# Mind Map Module - Usage Guide

## Overview

The Mind Map module provides visual filesystem navigation for ForensAI. It creates an interactive tree visualization of the filesystem structure from forensic disk images.

## Features

- **Interactive Visualization**: Pan, zoom, and navigate filesystem structure
- **Color-Coded Nodes**: Different colors for file types (documents, images, videos, etc.)
- **Background Processing**: Non-blocking filesystem traversal with progress reporting
- **Export Options**: Export to PNG, JSON formats
- **Configurable Limits**: Control depth and child count for performance
- **Thread-Safe**: All operations run safely in background threads

## Quick Start

### Option 1: Using the Widget Directly

```python
from ui.mindmap import MindMapWidget

# Create widget
widget = MindMapWidget()

# Set image handler
widget.set_image_handler(image_handler, start_offset=0)

# Adjust settings if needed
widget.max_depth = 10
widget.max_children = 100

# Show widget
widget.show()

# Generate mind map (or click "Generate Mind Map" button)
widget._on_generate()
```

### Option 2: Using the Programmatic API

```python
from ui.mindmap import create_mindmap_from_image

# Generate with widget display
job = create_mindmap_from_image(
    image_handler,
    start_offset=0,
    options={
        'max_depth': 5,
        'max_children': 50,
        'show_widget': True
    }
)

# Wait for completion
job.wait()

# Check status and get result
if job.status() == 'completed':
    root_node = job.result()
    print(f"Found {len(root_node.children)} top-level items")
```

### Option 3: Headless with Auto-Export

```python
from ui.mindmap import create_mindmap_from_image

# Generate without GUI and export JSON
job = create_mindmap_from_image(
    image_handler,
    start_offset=0,
    outdir="./output",
    options={
        'max_depth': 10,
        'max_children': 100,
        'show_widget': False,
        'auto_export_json': True
    }
)

job.wait()
# Result saved to ./output/mindmap.json
```

## Running the Demo

```bash
cd ForensAI
python examples/mindmap_demo.py
```

The demo creates a mock filesystem and shows:
- Tab 1: Full depth visualization
- Tab 2: Limited depth (3 levels) visualization

## UI Controls

### Toolbar Buttons
- **Generate Mind Map**: Start filesystem traversal
- **Fit to View**: Fit all nodes in viewport
- **Reset View**: Reset zoom to 100%
- **Export...**: Export to PNG/JSON
- **Cancel**: Cancel ongoing traversal

### Mouse Controls
- **Left Click**: Select node
- **Double Click** (on directory): Toggle expansion
- **Middle Button + Drag**: Pan view
- **Ctrl + Mouse Wheel**: Zoom in/out
- **Scroll**: Pan view

### Settings Panel
- **Max Depth**: Limit directory traversal depth (1-20)
- **Max Children**: Limit children per directory (10-500)

## Color Legend

- **Orange (Root)**: Root directory
- **Light Blue**: Directory
- **Blue**: Document (.pdf, .docx, .txt, etc.)
- **Orange**: Image (.jpg, .png, .gif, etc.)
- **Purple**: Video (.mp4, .avi, .mkv, etc.)
- **Green**: Audio (.mp3, .wav, .flac, etc.)
- **Yellow**: Archive (.zip, .rar, .7z, etc.)
- **Red**: Executable (.exe, .dll, etc.)
- **Light Green**: Code (.py, .java, .cpp, etc.)
- **Gray**: Database/Data (.db, .json, .xml, etc.)

## Export Formats

### PNG Export
Exports the current visualization as a high-quality PNG image with anti-aliasing.

### JSON Export
Exports the complete tree structure with metadata:

```json
{
  "name": "root",
  "type": "directory",
  "size": 0,
  "inode": 5,
  "category": null,
  "children": [
    {
      "name": "Documents",
      "type": "directory",
      "size": 0,
      "inode": 10,
      "category": null,
      "children": [...]
    }
  ]
}
```

## Performance Considerations

### Large Filesystems
For large filesystems (>10,000 files), adjust limits:

```python
widget.max_depth = 5       # Limit depth
widget.max_children = 50   # Limit children per directory
```

### Memory Usage
Each node requires ~500 bytes. For 10,000 nodes ≈ 5 MB.

### Cancellation
Always provide a way to cancel long operations:

```python
# User clicks Cancel button
widget._on_cancel()

# Or programmatically
job.cancel()
```

## Integration with ForensAI

### Adding to Main Window

```python
from ui.mindmap import MindMapWidget

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Create mind map tab
        self.mindmap_widget = MindMapWidget()
        self.tabs.addTab(self.mindmap_widget, "Mind Map")

    def on_image_loaded(self, image_handler, partition_offset):
        # Set handler when image is loaded
        self.mindmap_widget.set_image_handler(
            image_handler,
            partition_offset
        )
```

## API Reference

### MindMapWidget

Main widget class for mind map visualization.

**Methods:**
- `set_image_handler(handler, offset)`: Set image handler and partition offset
- `_on_generate()`: Start mind map generation
- `_on_cancel()`: Cancel generation
- `_on_export()`: Show export menu

**Signals:**
- `view.node_selected`: Emitted when node is selected

### create_mindmap_from_image()

Programmatic API for generating mind maps.

**Arguments:**
- `image_handler`: ImageHandler instance
- `start_offset`: Partition offset (default: 0)
- `outdir`: Output directory for exports (optional)
- `options`: Configuration dict with:
  - `max_depth`: Maximum directory depth (default: 5)
  - `max_children`: Maximum children per directory (default: 50)
  - `show_widget`: Show GUI widget (default: False)
  - `auto_export_json`: Auto-export JSON (default: False)

**Returns:**
- `MindMapJob`: Job handle with methods:
  - `status()`: Get status ('running', 'completed', 'error', 'cancelled')
  - `result()`: Get root FileNode if completed
  - `wait(timeout)`: Wait for completion
  - `cancel()`: Cancel the job

## Troubleshooting

### No nodes appear
- Check if `image_handler.has_filesystem(offset)` returns True
- Verify partition offset is correct
- Check console for error messages

### Slow performance
- Reduce `max_depth` to 3-5
- Reduce `max_children` to 25-50
- Use cancellation for very large trees

### Memory issues
- Limit depth and children
- Use JSON export for analysis instead of full visualization
- Process partitions separately

## Examples

See `examples/mindmap_demo.py` for complete working examples.
