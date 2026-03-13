"""
Mind Map Demo - ForensAI

This demo shows how to use the mind map module with:
1. Direct widget usage with UNLIMITED filesystem scanning
2. Programmatic API usage with export functionality
3. Progress monitoring and mid-scan exports

NEW FEATURES DEMONSTRATED:
- Unlimited depth and file count traversal
- Batched node emission (100 nodes/batch)
- Emergency safety controls (max_nodes_guard)
- Full structure export to JSON
- Periodic checkpointing for recovery

The demo uses a mock ImageHandler to simulate filesystem data.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from PySide6.QtWidgets import QApplication, QMainWindow, QTabWidget
from ui.mindmap import MindMapWidget, create_mindmap_from_image


class MockImageHandler:
    """
    Mock image handler that simulates a filesystem.

    Simulates a simple directory structure:
    /
    ├── Documents/
    │   ├── report.pdf
    │   ├── notes.txt
    │   └── presentation.pptx
    ├── Pictures/
    │   ├── photo1.jpg
    │   ├── photo2.png
    │   └── vacation/
    │       ├── beach.jpg
    │       └── sunset.jpg
    ├── Videos/
    │   ├── movie.mp4
    │   └── clip.avi
    └── Music/
        ├── song1.mp3
        └── song2.wav
    """

    def __init__(self):
        self.filesystem = {
            5: [
                ('Documents', True, 0, 10),
                ('Pictures', True, 0, 20),
                ('Videos', True, 0, 30),
                ('Music', True, 0, 40),
            ],
            10: [
                ('report.pdf', False, 524288, 11),
                ('notes.txt', False, 2048, 12),
                ('presentation.pptx', False, 1048576, 13),
            ],
            20: [
                ('photo1.jpg', False, 2097152, 21),
                ('photo2.png', False, 1572864, 22),
                ('vacation', True, 0, 23),
            ],
            23: [
                ('beach.jpg', False, 3145728, 24),
                ('sunset.jpg', False, 2621440, 25),
            ],
            30: [
                ('movie.mp4', False, 52428800, 31),
                ('clip.avi', False, 10485760, 32),
            ],
            40: [
                ('song1.mp3', False, 5242880, 41),
                ('song2.wav', False, 8388608, 42),
            ],
        }

    def has_filesystem(self, start_offset: int) -> bool:
        """Check if partition has filesystem"""
        return True

    def get_directory_contents(self, start_offset: int, parent_inode: int) -> list:
        """
        Get directory contents.

        Returns list of dicts with:
        - name: str
        - is_directory: bool
        - size: int
        - inode_number: int
        """
        entries = self.filesystem.get(parent_inode, [])

        result = []
        for name, is_dir, size, inode in entries:
            result.append({
                'name': name,
                'is_directory': is_dir,
                'size': size,
                'inode_number': inode,
                'created': None,
                'modified': None,
                'accessed': None
            })

        return result


class MindMapDemoWindow(QMainWindow):
    """Main demo window with tabs"""

    def __init__(self):
        super().__init__()

        self.setWindowTitle("ForensAI Mind Map Demo")
        self.setGeometry(100, 100, 1200, 800)

        self.image_handler = MockImageHandler()

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.create_widget_tab()

        self.create_api_tab()

    def create_widget_tab(self):
        """Create tab demonstrating direct widget usage with FULL SCAN"""
        widget = MindMapWidget()
        widget.set_image_handler(self.image_handler, start_offset=0)

        widget.max_depth = None
        widget.max_children = None
        widget.full_scan_confirmed = True

        def on_progress(pct):
            print(f"Progress: {pct}%")

        def on_status(msg):
            print(f"Status: {msg}")


        self.tabs.addTab(widget, "Full Scan Demo (Unlimited)")

        widget._on_generate()

        def export_on_complete(total_nodes):
            print(f"\nScan complete: {total_nodes} nodes")
            result = widget.export_full_structure("./exports/demo_full_structure.json")
            if result['success']:
                print(f"Exported structure to: {result['output_file']}")
                print(f"Total nodes: {result['node_count']}")
                print(f"Total size: {result['total_size']} bytes")


    def create_api_tab(self):
        """Create tab demonstrating programmatic export during scan"""
        widget2 = MindMapWidget()

        widget2.set_image_handler(self.image_handler, start_offset=0)

        widget2.max_depth = None
        widget2.max_children = None
        widget2.full_scan_confirmed = True

        self.tabs.addTab(widget2, "Export Demo")

        widget2._on_generate()


def demo_api_usage():
    """
    Demonstrate programmatic API usage.

    This shows how to use create_mindmap_from_image() without GUI.
    """
    print("Mind Map API Demo")
    print("=" * 50)

    handler = MockImageHandler()

    print("\nOption 1: Generate with widget display")
    job1 = create_mindmap_from_image(
        handler,
        start_offset=0,
        options={
            'max_depth': 5,
            'max_children': 50,
            'show_widget': True
        }
    )

    if job1.wait(timeout=10000):
        print(f"Status: {job1.status()}")
        root = job1.result()
        if root:
            print(f"Root node: {root.name}")
            print(f"Children: {len(root.children)}")

    print("\nOption 2: Generate with JSON export")
    job2 = create_mindmap_from_image(
        handler,
        start_offset=0,
        outdir=".",
        options={
            'max_depth': 10,
            'max_children': 100,
            'show_widget': False,
            'auto_export_json': True
        }
    )

    if job2.wait(timeout=10000):
        print(f"Status: {job2.status()}")
        if job2.status() == 'completed':
            print("Mind map exported to mindmap.json")

    print("\n" + "=" * 50)


def main():
    """Main entry point"""
    print(__doc__)

    app = QApplication(sys.argv)

    window = MindMapDemoWindow()
    window.show()


    sys.exit(app.exec())


if __name__ == '__main__':
    main()
