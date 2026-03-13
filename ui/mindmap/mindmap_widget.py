"""
Mind Map Widget for ForensAI Filesystem Visualization

This module provides a visual mind map representation of filesystem structures
extracted from forensic disk images. It uses a threaded worker for non-blocking
traversal and supports interactive pan/zoom visualization.

Classes:
    FileNode: Visual representation of a file/directory node
    MindMapView: Interactive graphics view with pan/zoom
    MindMapWorker: Background thread for filesystem traversal
    MindMapWidget: Main widget container
    MindMapJob: Job handle for async mind map generation

API:
    create_mindmap_from_image(): Programmatic API for generating mind maps

Author: ForensAI Team
License: MIT
"""

import json
import math
import os
import unicodedata
from collections import deque
from typing import Optional, Dict, List, Tuple, Any
from enum import Enum

from PySide6.QtCore import (
    Qt, QThread, Signal, QPointF, QRectF, QTimer, QSize,
    QPropertyAnimation, QEasingCurve, QParallelAnimationGroup,
    QObject, QEvent
)
from PySide6.QtGui import (
    QColor, QPen, QBrush, QFont, QPainter, QTransform,
    QWheelEvent, QMouseEvent, QKeyEvent, QPainterPath,
    QImage, QLinearGradient, QAction, QPainterPathStroker
)
from PySide6.QtWidgets import (
    QGraphicsEllipseItem, QGraphicsView, QGraphicsScene,
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QProgressBar, QGraphicsTextItem,
    QMenu, QGraphicsLineItem, QSpinBox, QCheckBox,
    QFileDialog, QMessageBox, QGroupBox, QFormLayout,
    QGraphicsItem, QGraphicsPathItem, QApplication, QLineEdit,
    QDialog
)
from PySide6.QtSvgWidgets import QSvgWidget
from PySide6.QtSvg import QSvgGenerator


CLUSTER_THRESHOLD = 25
LOD_THRESHOLD = 200
LOD_ZOOM_THRESHOLD = 0.5
MAX_NODES_GUARD = 10000
BATCH_EMIT_SIZE = 50

DEFAULT_LAYOUT_SPACING = 200
DEFAULT_LEVEL_SPACING = 100

class NodeType(Enum):
    """Node type enumeration"""
    DIRECTORY = "directory"
    FILE = "file"
    ROOT = "root"
    CLUSTER = "cluster"


class FileTypeCategory(Enum):
    """File type categories for color coding"""
    DOCUMENT = "document"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    ARCHIVE = "archive"
    EXECUTABLE = "executable"
    CODE = "code"
    DATA = "data"
    UNKNOWN = "unknown"


FILE_TYPE_COLORS = {
    FileTypeCategory.DOCUMENT: QColor(100, 150, 255),
    FileTypeCategory.IMAGE: QColor(255, 150, 100),
    FileTypeCategory.VIDEO: QColor(200, 100, 255),
    FileTypeCategory.AUDIO: QColor(100, 255, 150),
    FileTypeCategory.ARCHIVE: QColor(255, 200, 100),
    FileTypeCategory.EXECUTABLE: QColor(255, 100, 100),
    FileTypeCategory.CODE: QColor(150, 255, 150),
    FileTypeCategory.DATA: QColor(180, 180, 180),
    FileTypeCategory.UNKNOWN: QColor(200, 200, 200),
}

DIRECTORY_COLOR = QColor(100, 200, 255)
ROOT_COLOR = QColor(255, 180, 50)
CLUSTER_COLOR = QColor(150, 150, 150)

NODE_SIZE_SMALL = 20
NODE_SIZE_MEDIUM = 30
NODE_SIZE_LARGE = 40

NODE_SPACING = 100
LEVEL_SPACING = 150
ANGLE_SPREAD = 360


class ClusterNode(QGraphicsEllipseItem):
    """
    Represents a cluster of collapsed children (+N more nodes).

    Double-click to expand and load actual children.
    """

    expand_requested = Signal()

    def __init__(self, count: int, parent_node: 'FileNode' = None):
        """
        Initialize cluster node.

        Args:
            count: Number of collapsed children
            parent_node: Parent FileNode
        """
        radius = NODE_SIZE_SMALL
        super().__init__(-radius, -radius, radius * 2, radius * 2)

        self.count = count
        self.parent_node = parent_node
        self.node_type = NodeType.CLUSTER
        self.level = parent_node.level + 1 if parent_node else 0
        self.children = []

        self.setBrush(QBrush(CLUSTER_COLOR))
        self.setPen(QPen(CLUSTER_COLOR.darker(120), 2))

        self.label = QGraphicsTextItem(f"+{count} more", self)
        self.label.setDefaultTextColor(Qt.white)
        self.label.setFont(QFont("Arial", 7, QFont.Bold))
        label_rect = self.label.boundingRect()
        self.label.setPos(
            -label_rect.width() / 2,
            radius + 5
        )

        self.setFlags(QGraphicsEllipseItem.ItemIsSelectable)
        self.setAcceptHoverEvents(True)
        self.setToolTip(f"Double-click to expand {count} children")

    def mouseDoubleClickEvent(self, event):
        """Handle double-click to expand"""
        if self.parent_node and hasattr(self.parent_node, 'expand_cluster'):
            self.parent_node.expand_cluster()
        super().mouseDoubleClickEvent(event)

    def hoverEnterEvent(self, event):
        """Highlight on hover"""
        self.setPen(QPen(QColor(255, 200, 0), 3))
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        """Remove highlight"""
        self.setPen(QPen(CLUSTER_COLOR.darker(120), 2))
        super().hoverLeaveEvent(event)


class FileNode(QGraphicsEllipseItem):
    """
    Represents a file or directory node in the mind map.

    Features:
    - Color-coded by type
    - Interactive (click, hover, drag)
    - Displays name and metadata
    - Supports lazy loading for directories
    - Context menu with actions
    """

    copy_path_requested = Signal(str)
    export_requested = Signal(str)
    focus_requested = Signal(object)

    def __init__(
        self,
        name: str,
        node_type: NodeType,
        size: int = 0,
        file_category: FileTypeCategory = FileTypeCategory.UNKNOWN,
        inode: Optional[int] = None,
        parent_node: Optional['FileNode'] = None
    ):
        """
        Initialize a file node.

        Args:
            name: File/directory name
            node_type: Type of node (file/directory/root)
            size: File size in bytes
            file_category: Category for color coding
            inode: Inode number
            parent_node: Parent FileNode
        """
        if node_type == NodeType.ROOT:
            radius = NODE_SIZE_LARGE
        elif node_type == NodeType.DIRECTORY:
            radius = NODE_SIZE_MEDIUM
        else:
            radius = NODE_SIZE_SMALL

        super().__init__(-radius, -radius, radius * 2, radius * 2)

        self.name = name
        self.node_type = node_type
        self.size = size
        self.file_category = file_category
        self.inode = inode
        self.parent_node = parent_node
        self.children: List['FileNode'] = []
        self.is_expanded = True
        self.is_loaded = False
        self.level = 0

        self.cluster_node: Optional['ClusterNode'] = None
        self.collapsed_children: List['FileNode'] = []
        self.pending_child_count = 0

        self._setup_appearance()

        self.label = QGraphicsTextItem(self._get_display_name(), self)
        self.label.setDefaultTextColor(Qt.black)
        self.label.setFont(QFont("Arial", 8))
        self._position_label()

        self.connection_line: Optional[QGraphicsLineItem] = None
        if parent_node:
            self._create_connection_line()

        self.setFlags(
            QGraphicsEllipseItem.ItemIsSelectable |
            QGraphicsEllipseItem.ItemSendsGeometryChanges
        )
        self.setAcceptHoverEvents(True)
        self.setCacheMode(QGraphicsEllipseItem.ItemCoordinateCache)

        self.setToolTip(self._create_tooltip())

        self.detail_level = "full"

        self.is_filtered = False
        self.original_opacity = 1.0

    def set_detail_level(self, level: str):
        """Set rendering detail level for LOD"""
        if level == self.detail_level:
            return

        self.detail_level = level

        if level == "simple":
            if self.label:
                self.label.setVisible(False)
        else:
            if self.label:
                self.label.setVisible(True)

    def set_filtered(self, filtered: bool, hide_mode: bool = False):
        """
        Set filter state for this node.

        Args:
            filtered: True if node doesn't match filter criteria
            hide_mode: If True, hide completely. If False, dim the node.
        """
        self.is_filtered = filtered

        if filtered:
            if hide_mode:
                self.setVisible(False)
                if self.label:
                    self.label.setVisible(False)
                if self.connection_line:
                    self.connection_line.setVisible(False)
            else:
                self.setOpacity(0.2)
                if self.label:
                    self.label.setOpacity(0.2)
        else:
            self.setVisible(True)
            self.setOpacity(self.original_opacity)
            if self.label and self.detail_level == "full":
                self.label.setVisible(True)
                self.label.setOpacity(1.0)
            if self.connection_line:
                self.connection_line.setVisible(True)

    def _setup_appearance(self):
        """Setup visual appearance based on node type"""
        if self.node_type == NodeType.ROOT:
            color = ROOT_COLOR
        elif self.node_type == NodeType.DIRECTORY:
            color = DIRECTORY_COLOR
        else:
            color = FILE_TYPE_COLORS.get(self.file_category, FILE_TYPE_COLORS[FileTypeCategory.UNKNOWN])

        self.setBrush(QBrush(color))
        self.setPen(QPen(color.darker(120), 2))

    def _get_display_name(self) -> str:
        """
        Get display name with Unicode normalization.

        Handles:
        - Unicode NFC normalization
        - RTL text detection
        - Truncation for long names
        """
        normalized_name = unicodedata.normalize('NFC', self.name)

        max_length = 15
        if len(normalized_name) > max_length:
            return normalized_name[:max_length] + "..."
        return normalized_name

    def _is_rtl_text(self, text: str) -> bool:
        """
        Detect if text contains right-to-left characters.

        Returns:
            True if text is predominantly RTL (Arabic, Hebrew, etc.)
        """
        rtl_chars = 0
        total_chars = 0

        for char in text:
            if char.isalpha():
                total_chars += 1
                bidi_type = unicodedata.bidirectional(char)
                if bidi_type in ('R', 'AL', 'RLE', 'RLO'):
                    rtl_chars += 1

        if total_chars == 0:
            return False

        return (rtl_chars / total_chars) > 0.5

    def _position_label(self):
        """
        Position text label below node with RTL support.

        Handles bidirectional text alignment.
        """
        rect = self.rect()
        label_rect = self.label.boundingRect()

        is_rtl = self._is_rtl_text(self.name)

        if is_rtl:
            text_option = self.label.document().defaultTextOption()
            text_option.setTextDirection(Qt.RightToLeft)
            self.label.document().setDefaultTextOption(text_option)

        self.label.setPos(
            rect.center().x() - label_rect.width() / 2,
            rect.bottom() + 5
        )

    def _create_connection_line(self):
        """Create curved B\u00e9zier line connecting to parent node"""
        if not self.parent_node:
            return

        self.connection_line = QGraphicsPathItem()

        alpha = max(50, 255 - (self.level * 25))
        color = QColor(150, 150, 150, alpha)

        self.connection_line.setPen(QPen(color, 1.5))
        self.connection_line.setZValue(-1)

    def update_connection_line(self):
        """Update curved connection line position"""
        if not self.connection_line or not self.parent_node:
            return

        start = self.parent_node.scenePos()
        end = self.scenePos()

        path = QPainterPath()
        path.moveTo(start)

        dx = end.x() - start.x()
        dy = end.y() - start.y()

        ctrl1_x = start.x() + dx * 0.5
        ctrl1_y = start.y()
        ctrl2_x = start.x() + dx * 0.5
        ctrl2_y = end.y()

        path.cubicTo(
            ctrl1_x, ctrl1_y,
            ctrl2_x, ctrl2_y,
            end.x(), end.y()
        )

        self.connection_line.setPath(path)

    def _create_tooltip(self) -> str:
        """Create tooltip with node information"""
        lines = [f"Name: {self.name}"]
        lines.append(f"Type: {self.node_type.value}")
        if self.size > 0:
            lines.append(f"Size: {self._format_size(self.size)}")
        if self.inode is not None:
            lines.append(f"Inode: {self.inode}")
        lines.append(f"Children: {len(self.children)}")
        return "\n".join(lines)

    @staticmethod
    def _format_size(size: int) -> str:
        """Format file size human-readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    def hoverEnterEvent(self, event):
        """Handle mouse hover enter"""
        self.setPen(QPen(QColor(255, 200, 0), 3))
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        """Handle mouse hover leave"""
        color = self.brush().color()
        self.setPen(QPen(color.darker(120), 2))
        super().hoverLeaveEvent(event)

    def mouseDoubleClickEvent(self, event):
        """Handle double-click to toggle collapse/expand"""
        if self.node_type == NodeType.DIRECTORY:
            self.toggle_collapse()
        super().mouseDoubleClickEvent(event)

    def contextMenuEvent(self, event):
        """Show context menu on right-click"""
        menu = QMenu()

        path_parts = []
        node = self
        while node:
            if node.name and node.node_type != NodeType.ROOT:
                path_parts.insert(0, node.name)
            node = node.parent_node
        full_path = "/" + "/".join(path_parts) if path_parts else "/"

        copy_action = QAction("Copy Path", menu)
        copy_action.triggered.connect(lambda: self._copy_to_clipboard(full_path))
        menu.addAction(copy_action)

        if self.node_type == NodeType.FILE:
            export_action = QAction("Export File...", menu)
            export_action.triggered.connect(lambda: self._request_export(full_path))
            menu.addAction(export_action)

        menu.addSeparator()

        focus_action = QAction("Focus on This Node", menu)
        focus_action.triggered.connect(lambda: self._request_focus())
        menu.addAction(focus_action)

        if self.node_type == NodeType.DIRECTORY:
            toggle_text = "Collapse" if self.is_expanded else "Expand"
            toggle_action = QAction(toggle_text, menu)
            toggle_action.triggered.connect(self.toggle_collapse)
            menu.addAction(toggle_action)

        menu.exec_(event.screenPos())

    def _copy_to_clipboard(self, path: str):
        """Copy path to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(path)

    def _request_export(self, path: str):
        """Request file export (emits signal)"""
        pass

    def _request_focus(self):
        """Request focus on this node (emits signal)"""
        if self.scene() and self.scene().views():
            view = self.scene().views()[0]
            view.centerOn(self)
            view.scale(1.5, 1.5)

    def add_child(self, child: 'FileNode'):
        """Add a child node"""
        self.children.append(child)
        child.parent_node = self

    def toggle_collapse(self):
        """Toggle between collapsed and expanded states"""
        if self.is_expanded:
            self.collapse()
        else:
            self.expand()

    def collapse(self, animated: bool = True):
        """
        Collapse this node's children.

        Args:
            animated: If True, use smooth fade-out animation
        """
        if not self.children or not self.is_expanded:
            return

        self.is_expanded = False

        if animated:
            self._animate_collapse()
        else:
            self._collapse_instant()

        self.collapsed_children = self.children.copy()

        if self.cluster_node and self.cluster_node.scene():
            self.cluster_node.scene().removeItem(self.cluster_node)
            if self.cluster_node.label and self.cluster_node.label.scene():
                self.cluster_node.label.scene().removeItem(self.cluster_node.label)
            self.cluster_node = None

    def _collapse_instant(self):
        """Instant collapse without animation"""
        def hide_recursive(node):
            if node.scene():
                node.scene().removeItem(node)
            if node.label and node.label.scene():
                node.label.scene().removeItem(node.label)
            if node.connection_line and node.connection_line.scene():
                node.connection_line.scene().removeItem(node.connection_line)
            for child in node.children:
                hide_recursive(child)

        for child in self.children:
            hide_recursive(child)

    def _animate_collapse(self):
        """Animate collapse with fade-out effect"""
        nodes_to_hide = []

        def collect_recursive(node, delay_ms=0):
            nodes_to_hide.append((node, delay_ms))
            for i, child in enumerate(node.children):
                collect_recursive(child, delay_ms + 30)

        for i, child in enumerate(self.children):
            collect_recursive(child, i * 30)

        anim_group = QParallelAnimationGroup(self)

        for node, delay in nodes_to_hide:
            anim = QPropertyAnimation(node, b"opacity")
            anim.setDuration(200)
            anim.setStartValue(node.opacity())
            anim.setEndValue(0.0)
            anim.setEasingCurve(QEasingCurve.InOutQuad)
            if delay > 0:
                QTimer.singleShot(delay, anim.start)
            anim_group.addAnimation(anim)

        anim_group.finished.connect(lambda: self._collapse_instant())
        anim_group.start()

    def expand(self, animated: bool = True):
        """
        Expand this node to show children.

        Args:
            animated: If True, use smooth fade-in animation
        """
        if self.is_expanded:
            return

        self.is_expanded = True

        def show_recursive(node):
            if not node.scene() and self.scene():
                self.scene().addItem(node)
            if node.label and not node.label.scene() and self.scene():
                self.scene().addItem(node.label)
            if node.connection_line and not node.connection_line.scene() and self.scene():
                self.scene().addItem(node.connection_line)
            if node.is_expanded:
                for child in node.children:
                    show_recursive(child)

        for child in self.collapsed_children:
            show_recursive(child)

        if animated:
            self._animate_expand()

        self.collapsed_children = []

        if self.scene() and hasattr(self.scene(), 'views'):
            views = self.scene().views()
            if views and hasattr(views[0].parent(), '_layout_nodes'):
                views[0].parent()._layout_nodes()

    def _animate_expand(self):
        """Animate expand with fade-in effect"""
        nodes_to_show = []

        def collect_recursive(node, delay_ms=0):
            nodes_to_show.append((node, delay_ms))
            if node.is_expanded:
                for i, child in enumerate(node.children):
                    collect_recursive(child, delay_ms + 30)

        for i, child in enumerate(self.collapsed_children):
            collect_recursive(child, i * 30)

        for node, delay in nodes_to_show:
            node.setOpacity(0.0)

            anim = QPropertyAnimation(node, b"opacity")
            anim.setDuration(250)
            anim.setStartValue(0.0)
            anim.setEndValue(1.0)
            anim.setEasingCurve(QEasingCurve.OutQuad)

            if delay > 0:
                QTimer.singleShot(delay, anim.start)
            else:
                anim.start()

    def expand_cluster(self):
        """Expand cluster node and show actual children"""
        if not self.cluster_node:
            return

        if self.cluster_node.scene():
            self.cluster_node.scene().removeItem(self.cluster_node)
        if self.cluster_node.label and self.cluster_node.label.scene():
            self.cluster_node.label.scene().removeItem(self.cluster_node.label)
        self.cluster_node = None

        self.expand()


class MindMapView(QGraphicsView):
    """
    Interactive graphics view for the mind map.

    Features:
    - Pan with mouse drag
    - Zoom with Ctrl+mouse wheel
    - Fit to view
    - Keyboard navigation
    """

    node_selected = Signal(object)

    def __init__(self, parent=None):
        """Initialize the view"""
        super().__init__(parent)

        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)

        self.setRenderHint(QPainter.Antialiasing)
        self.setRenderHint(QPainter.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        self._isPanning = False
        self._lastPanPoint = QPointF()
        self._zoom_factor = 1.0
        self._min_zoom = 0.1
        self._max_zoom = 5.0

        self.setBackgroundBrush(QBrush(QColor(250, 250, 250)))

    def wheelEvent(self, event: QWheelEvent):
        """Handle mouse wheel for zooming"""
        if event.modifiers() & Qt.ControlModifier:
            zoom_in_factor = 1.15
            zoom_out_factor = 1 / zoom_in_factor

            if event.angleDelta().y() > 0:
                zoom_factor = zoom_in_factor
                self._zoom_factor *= zoom_factor
            else:
                zoom_factor = zoom_out_factor
                self._zoom_factor *= zoom_factor

            if self._zoom_factor < self._min_zoom:
                self._zoom_factor = self._min_zoom
                return
            elif self._zoom_factor > self._max_zoom:
                self._zoom_factor = self._max_zoom
                return

            self.scale(zoom_factor, zoom_factor)

            self._update_lod()
        else:
            super().wheelEvent(event)

    def _update_lod(self):
        """Update Level-of-Detail based on current zoom"""
        total_nodes = len(self.scene.items())
        if total_nodes < LOD_THRESHOLD:
            return

        detail_level = "full" if self._zoom_factor >= LOD_ZOOM_THRESHOLD else "simple"

        for item in self.scene.items():
            if isinstance(item, FileNode):
                item.set_detail_level(detail_level)

    def mousePressEvent(self, event: QMouseEvent):
        """Handle mouse press"""
        if event.button() == Qt.MiddleButton:
            self._isPanning = True
            self._lastPanPoint = event.pos()
            self.setCursor(Qt.ClosedHandCursor)
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent):
        """Handle mouse move"""
        if self._isPanning:
            delta = event.pos() - self._lastPanPoint
            self._lastPanPoint = event.pos()
            self.horizontalScrollBar().setValue(
                self.horizontalScrollBar().value() - delta.x()
            )
            self.verticalScrollBar().setValue(
                self.verticalScrollBar().value() - delta.y()
            )
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent):
        """Handle mouse release"""
        if event.button() == Qt.MiddleButton:
            self._isPanning = False
            self.setCursor(Qt.ArrowCursor)
        else:
            super().mouseReleaseEvent(event)

    def keyPressEvent(self, event: QKeyEvent):
        """Handle keyboard events"""
        super().keyPressEvent(event)

    def fit_in_view(self):
        """Fit all content in view"""
        self.fitInView(self.scene.itemsBoundingRect(), Qt.KeepAspectRatio)
        self._zoom_factor = 1.0

    def reset_view(self):
        """Reset zoom and center view"""
        self.resetTransform()
        self._zoom_factor = 1.0
        self.centerOn(0, 0)

    def clear_scene(self):
        """Clear all items from scene"""
        self.scene.clear()


class MindMapWorker(QThread):
    """
    Background worker for filesystem traversal.

    Performs BFS traversal of the filesystem and emits signals
    for each discovered node. Runs in a separate thread to keep
    the UI responsive.

    Supports unlimited traversal with batched emission and safety controls.

    Signals:
        nodes_batch_created: Emitted for batches of nodes (list of tuples)
        progress_update: Progress percentage (0-100)
        status_update: Status message
        finished: Traversal complete
        error: Error occurred (error_message)
        guard_limit_reached: Emergency stop triggered (current_count)
    """

    nodes_batch_created = Signal(list)
    progress_update = Signal(int)
    status_update = Signal(str)
    finished = Signal(int)
    error = Signal(str)
    guard_limit_reached = Signal(int)

    def __init__(
        self,
        image_handler,
        start_offset: int = 0,
        max_depth: Optional[int] = None,
        max_children: Optional[int] = None,
        max_nodes_guard: int = 1000000,
        batch_emit_size: int = 100,
        checkpoint_interval: int = 1000,
        parent=None
    ):
        """
        Initialize the worker.

        Args:
            image_handler: ImageHandler instance with filesystem access
            start_offset: Partition offset to start from
            max_depth: Maximum directory depth (None = unlimited)
            max_children: Maximum children per directory (None = unlimited)
            max_nodes_guard: Emergency stop limit
            batch_emit_size: Number of nodes per batch emission
            checkpoint_interval: Write checkpoint every N nodes
            parent: Parent QObject
        """
        super().__init__(parent)

        self.image_handler = image_handler
        self.start_offset = start_offset
        self.max_depth = max_depth
        self.max_children = max_children
        self.max_nodes_guard = max_nodes_guard
        self.batch_emit_size = batch_emit_size
        self.checkpoint_interval = checkpoint_interval

        self._is_cancelled = False
        self._nodes_processed = 0
        self._batch_buffer = []
        self._checkpoint_data = []

    def run(self):
        """Execute the traversal"""
        try:
            self.status_update.emit("Starting filesystem traversal...")

            if not self.image_handler.has_filesystem(self.start_offset):
                self.error.emit("No filesystem found at specified offset")
                return

            fs_type = self.image_handler.get_fs_type(self.start_offset)
            self.status_update.emit(f"Detected filesystem: {fs_type}")

            if fs_type in ['NTFS']:
                root_inode = 5
            elif fs_type in ['Ext2', 'Ext3', 'Ext4']:
                root_inode = 2
            elif fs_type in ['FAT12', 'FAT16', 'FAT32', 'ExFAT']:
                root_inode = None
            else:
                root_inode = None

            self._traverse_bfs(root_inode)

            if not self._is_cancelled:
                self.status_update.emit(f"Completed: {self._nodes_processed} nodes processed")
                self.finished.emit(self._nodes_processed)

        except Exception as e:
            self.error.emit(f"Traversal error: {str(e)}")

    def _traverse_bfs(self, root_inode):
        """
        Perform BFS traversal of filesystem with batching and safety controls.

        Args:
            root_inode: Starting inode number (or None for path-based filesystems like FAT)
        """
        queue = deque([(root_inode, 0, "")])
        visited = set()

        if root_inode is None:
            visited = set()

        while queue and not self._is_cancelled:
            if self._nodes_processed >= self.max_nodes_guard:
                self.status_update.emit(
                    f"⚠️ Emergency stop: max_nodes_guard ({self.max_nodes_guard:,}) reached"
                )
                self.guard_limit_reached.emit(self._nodes_processed)
                self._flush_batch()
                break

            inode, depth, parent_path = queue.popleft()

            if self.max_depth is not None and depth > self.max_depth:
                continue

            if root_inode is None:
                visit_key = parent_path if parent_path else "/"
            else:
                visit_key = inode

            if visit_key in visited:
                continue
            visited.add(visit_key)

            try:
                entries = self.image_handler.get_directory_contents(
                    self.start_offset,
                    inode
                )

                if not entries:
                    continue

                if self.max_children is not None and len(entries) > self.max_children:
                    entries = entries[:self.max_children]

                for entry in entries:
                    if self._is_cancelled:
                        break

                    name = entry.get('name', 'unknown')
                    is_dir = entry.get('is_directory', False)
                    size = entry.get('size', 0)
                    entry_inode = entry.get('inode_number')

                    if name in ('.', '..'):
                        continue

                    node_type = NodeType.DIRECTORY.value if is_dir else NodeType.FILE.value

                    metadata = {
                        'size': size,
                        'inode': entry_inode,
                        'depth': depth + 1,
                        'created': entry.get('created'),
                        'modified': entry.get('modified'),
                        'accessed': entry.get('accessed')
                    }

                    self._batch_buffer.append((name, node_type, parent_path, metadata))
                    self._nodes_processed += 1

                    if len(self._batch_buffer) >= self.batch_emit_size:
                        self._flush_batch()

                    if self._nodes_processed % self.checkpoint_interval == 0:
                        self._write_checkpoint()

                    if is_dir:
                        new_path = f"{parent_path}/{name}" if parent_path else name
                        queue.append((entry_inode, depth + 1, new_path))

                    if self._nodes_processed % 100 == 0:
                        if self.max_depth is None:
                            progress_pct = min(95, int((self._nodes_processed / self.max_nodes_guard) * 100))
                        else:
                            progress_pct = min(95, (depth * 100) // self.max_depth)

                        self.progress_update.emit(progress_pct)
                        self.status_update.emit(
                            f"Processing: {self._nodes_processed:,} nodes found (depth {depth})..."
                        )

            except Exception as e:
                print(f"Error processing inode {inode}: {e}")
                continue

        if self._batch_buffer:
            self._flush_batch()

        self.progress_update.emit(100)

    def _flush_batch(self):
        """Emit current batch of nodes"""
        if self._batch_buffer:
            self.nodes_batch_created.emit(self._batch_buffer.copy())
            self._batch_buffer.clear()

    def _write_checkpoint(self):
        """Write checkpoint data for recovery"""
        try:
            checkpoint_dir = os.path.join("ui", "mindmap", "checkpoints")
            os.makedirs(checkpoint_dir, exist_ok=True)

            checkpoint_file = os.path.join(
                checkpoint_dir,
                f"checkpoint_{self.start_offset}_{self._nodes_processed}.json"
            )

            checkpoint_data = {
                "nodes_processed": self._nodes_processed,
                "timestamp": str(QTimer.currentTime()) if hasattr(QTimer, 'currentTime') else "unknown",
                "start_offset": self.start_offset
            }

            with open(checkpoint_file, 'w', encoding='utf-8') as f:
                json.dump(checkpoint_data, f, indent=2)

            checkpoints = sorted([
                f for f in os.listdir(checkpoint_dir)
                if f.startswith(f"checkpoint_{self.start_offset}_")
            ])
            if len(checkpoints) > 3:
                for old_checkpoint in checkpoints[:-3]:
                    os.remove(os.path.join(checkpoint_dir, old_checkpoint))

        except Exception as e:
            print(f"Warning: Failed to write checkpoint: {e}")

    def cancel(self):
        """Cancel the traversal"""
        self._is_cancelled = True
        if self._batch_buffer:
            self._flush_batch()
        self.status_update.emit("Cancelling...")


class FullScanConfirmDialog(QDialog):
    """
    Confirmation dialog for enabling full filesystem scan.

    Warns user about potential performance impact and requires explicit confirmation.
    """

    def __init__(self, max_nodes_guard: int = 1000000, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Confirm Full Scan")
        self.setModal(True)
        self.setMinimumWidth(500)

        layout = QVBoxLayout(self)

        title_layout = QHBoxLayout()
        warning_label = QLabel("⚠️")
        warning_label.setStyleSheet("font-size: 32px;")
        title_layout.addWidget(warning_label)

        title = QLabel("Full Filesystem Scan")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        title_layout.addWidget(title)
        title_layout.addStretch()
        layout.addLayout(title_layout)

        warning_text = QLabel(
            f"<p>You are about to enable <b>unlimited filesystem scanning</b>.</p>"
            f"<p><b>This will:</b></p>"
            f"<ul>"
            f"<li>Traverse the <b>entire filesystem</b> without depth or file count limits</li>"
            f"<li>May take <b>several minutes to hours</b> depending on filesystem size</li>"
            f"<li>Use significant <b>memory and CPU resources</b></li>"
            f"<li>Continue until complete or manually cancelled</li>"
            f"</ul>"
            f"<p><b>Safety Controls:</b></p>"
            f"<ul>"
            f"<li>Emergency stop at {max_nodes_guard:,} nodes (configurable)</li>"
            f"<li>Progress updates every 100 nodes</li>"
            f"<li>Periodic checkpoints for recovery</li>"
            f"<li>Can be cancelled at any time</li>"
            f"</ul>"
            f"<p style='color: orange;'><b>⚠️ For large filesystems (>100,000 files), "
            f"this may take considerable time and resources.</b></p>"
        )
        warning_text.setWordWrap(True)
        layout.addWidget(warning_text)

        self.confirm_checkbox = QCheckBox("I understand and want to proceed with full scan")
        layout.addWidget(self.confirm_checkbox)

        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)

        self.ok_btn = QPushButton("Enable Full Scan")
        self.ok_btn.setEnabled(False)
        self.ok_btn.clicked.connect(self.accept)
        self.ok_btn.setStyleSheet("QPushButton:enabled { background-color: #d9534f; color: white; font-weight: bold; }")
        button_layout.addWidget(self.ok_btn)

        layout.addLayout(button_layout)

        self.confirm_checkbox.stateChanged.connect(
            lambda state: self.ok_btn.setEnabled(state == Qt.Checked)
        )


class MindMapWidget(QWidget):
    """
    Main widget for mind map visualization.

    Features:
    - Toolbar with controls
    - Interactive view
    - Progress display
    - Export functionality
    - Settings panel
    - Legend
    - Unlimited filesystem traversal with safety controls
    """

    full_scan_confirm_required = Signal(int)

    def __init__(self, parent=None):
        """Initialize the mind map widget"""
        super().__init__(parent)

        self.image_handler = None
        self.start_offset = 0
        self.worker: Optional[MindMapWorker] = None
        self.root_node: Optional[FileNode] = None
        self.node_map: Dict[str, FileNode] = {}

        self._load_config()

        self.max_depth = None
        self.max_children = None
        self.full_scan_confirmed = False

        self.layout_spacing = 200
        self.level_spacing = 100
        self.layout_mode = "tree"

        self.active_filters = {
            'Directory': True,
            'Document': True,
            'Image': True,
            'Video': True,
            'Audio': True,
            'Archive': True,
            'Executable': True,
            'Code': True,
        }
        self.search_text = ""
        self.filter_mode = "dim"

        self._init_ui()

    def _init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.view = MindMapView(self)

        self.toolbar = self._create_toolbar()
        layout.addWidget(self.toolbar)

        content_layout = QHBoxLayout()

        content_layout.addWidget(self.view, stretch=1)

        self.side_panel = self._create_side_panel()
        content_layout.addWidget(self.side_panel)

        layout.addLayout(content_layout)

        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximum(100)
        status_layout.addWidget(self.status_label, stretch=1)
        status_layout.addWidget(self.progress_bar)

        layout.addLayout(status_layout)

    def _load_config(self):
        """Load configuration from config file"""
        config_path = os.path.join("config", "mindmap_config.json")
        default_config = {
            "version": "1.0",
            "max_nodes_guard": 1000000,
            "batch_emit_size": 100,
            "checkpoint_interval": 1000,
            "enable_full_scan_by_default": False
        }

        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                for key, value in default_config.items():
                    if key not in self.config:
                        self.config[key] = value
            else:
                self.config = default_config
        except Exception as e:
            print(f"Warning: Failed to load config from {config_path}: {e}")
            self.config = default_config

    def _create_toolbar(self) -> QWidget:
        """Create toolbar with action buttons"""
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(5, 5, 5, 5)

        self.generate_btn = QPushButton("Generate Mind Map")
        self.generate_btn.clicked.connect(self._on_generate)
        toolbar_layout.addWidget(self.generate_btn)

        toolbar_layout.addSpacing(10)

        fit_btn = QPushButton("Fit to View")
        fit_btn.clicked.connect(self.view.fit_in_view)
        toolbar_layout.addWidget(fit_btn)

        reset_btn = QPushButton("Reset View")
        reset_btn.clicked.connect(self.view.reset_view)
        toolbar_layout.addWidget(reset_btn)

        toolbar_layout.addSpacing(10)

        toolbar_layout.addWidget(QLabel("Search:"))
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Filter by name...")
        self.search_box.setMaximumWidth(200)
        self.search_box.textChanged.connect(self._on_search_changed)
        toolbar_layout.addWidget(self.search_box)

        clear_search_btn = QPushButton("Clear")
        clear_search_btn.setMaximumWidth(60)
        clear_search_btn.clicked.connect(lambda: self.search_box.clear())
        toolbar_layout.addWidget(clear_search_btn)

        toolbar_layout.addSpacing(10)

        self.export_btn = QPushButton("Export...")
        self.export_btn.clicked.connect(self._on_export)
        self.export_btn.setEnabled(False)
        toolbar_layout.addWidget(self.export_btn)

        toolbar_layout.addSpacing(10)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self._on_cancel)
        self.cancel_btn.setEnabled(False)
        toolbar_layout.addWidget(self.cancel_btn)

        toolbar_layout.addStretch()

        return toolbar

    def _create_side_panel(self) -> QWidget:
        """Create side panel with legend and settings"""
        panel = QWidget()
        panel.setMaximumWidth(250)
        layout = QVBoxLayout(panel)

        settings_group = QGroupBox("Settings")
        settings_layout = QFormLayout()

        self.full_scan_checkbox = QCheckBox("Enable Full Scan")
        self.full_scan_checkbox.setToolTip("Scan entire filesystem without limits.\nRequires confirmation.")
        self.full_scan_checkbox.setChecked(self.config.get("enable_full_scan_by_default", False))
        self.full_scan_checkbox.stateChanged.connect(self._on_full_scan_toggled)
        settings_layout.addRow("Mode:", self.full_scan_checkbox)

        layout_mode_widget = QWidget()
        layout_mode_layout = QHBoxLayout(layout_mode_widget)
        layout_mode_layout.setContentsMargins(0, 0, 0, 0)

        self.layout_tree_radio = QCheckBox("Tree")
        self.layout_tree_radio.setChecked(True)
        self.layout_tree_radio.toggled.connect(lambda checked: self._on_layout_mode_changed("tree" if checked else "radial"))
        layout_mode_layout.addWidget(self.layout_tree_radio)

        self.layout_radial_radio = QCheckBox("Radial")
        self.layout_radial_radio.toggled.connect(lambda checked: self._on_layout_mode_changed("radial" if checked else "tree"))
        layout_mode_layout.addWidget(self.layout_radial_radio)

        settings_layout.addRow("Layout:", layout_mode_widget)

        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        legend_group = QGroupBox("Filter by Type")
        legend_layout = QVBoxLayout()

        legend_items = [
            ("Directory", DIRECTORY_COLOR),
            ("Document", FILE_TYPE_COLORS[FileTypeCategory.DOCUMENT]),
            ("Image", FILE_TYPE_COLORS[FileTypeCategory.IMAGE]),
            ("Video", FILE_TYPE_COLORS[FileTypeCategory.VIDEO]),
            ("Audio", FILE_TYPE_COLORS[FileTypeCategory.AUDIO]),
            ("Archive", FILE_TYPE_COLORS[FileTypeCategory.ARCHIVE]),
            ("Executable", FILE_TYPE_COLORS[FileTypeCategory.EXECUTABLE]),
            ("Code", FILE_TYPE_COLORS[FileTypeCategory.CODE]),
        ]

        self.legend_checkboxes = {}

        for name, color in legend_items:
            item_layout = QHBoxLayout()

            checkbox = QCheckBox()
            checkbox.setChecked(True)
            checkbox.stateChanged.connect(lambda state, n=name: self._on_filter_changed(n, state))
            self.legend_checkboxes[name] = checkbox

            color_label = QLabel()
            color_label.setFixedSize(20, 20)
            color_label.setStyleSheet(f"background-color: {color.name()}; border: 1px solid black;")

            text_label = QLabel(name)

            item_layout.addWidget(checkbox)
            item_layout.addWidget(color_label)
            item_layout.addWidget(text_label)
            item_layout.addStretch()
            legend_layout.addLayout(item_layout)

        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Mode:"))
        self.filter_mode_dim = QCheckBox("Dim")
        self.filter_mode_dim.setChecked(True)
        self.filter_mode_dim.toggled.connect(lambda checked: self._set_filter_mode("dim" if checked else "hide"))
        mode_layout.addWidget(self.filter_mode_dim)
        mode_layout.addStretch()
        legend_layout.addLayout(mode_layout)

        legend_group.setLayout(legend_layout)
        layout.addWidget(legend_group)

        self.stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout()
        self.stats_label = QLabel("No data")
        self.stats_label.setWordWrap(True)
        stats_layout.addWidget(self.stats_label)
        self.stats_group.setLayout(stats_layout)
        layout.addWidget(self.stats_group)

        layout.addStretch()
        return panel

    def set_image_handler(self, image_handler, start_offset: int = 0):
        """
        Set the image handler for filesystem access.

        Args:
            image_handler: ImageHandler instance
            start_offset: Partition offset
        """
        self.image_handler = image_handler
        self.start_offset = start_offset
        self.generate_btn.setEnabled(True)

    def _on_full_scan_toggled(self, state: int):
        """Handle full scan checkbox toggle"""
        if state == Qt.Checked:
            dialog = FullScanConfirmDialog(
                max_nodes_guard=self.config.get("max_nodes_guard", 1000000),
                parent=self
            )
            if dialog.exec() == QDialog.Accepted:
                self.full_scan_confirmed = True
                self.max_depth = None
                self.max_children = None
            else:
                self.full_scan_checkbox.setChecked(False)
                self.full_scan_confirmed = False
        else:
            self.full_scan_confirmed = False
            self.max_depth = None
            self.max_children = None

    def _on_filter_changed(self, filter_name: str, state: int):
        """Handle filter checkbox state change"""
        self.active_filters[filter_name] = (state == Qt.Checked)
        self._apply_filters()

    def _on_search_changed(self, text: str):
        """Handle search text change"""
        self.search_text = text.lower()
        self._apply_filters()

    def _set_filter_mode(self, mode: str):
        """Set filter mode (dim or hide)"""
        self.filter_mode = mode
        self._apply_filters()

    def _on_layout_mode_changed(self, mode: str):
        """Handle layout mode change"""
        self.layout_mode = mode

        if mode == "tree":
            self.layout_tree_radio.setChecked(True)
            self.layout_radial_radio.setChecked(False)
        else:
            self.layout_tree_radio.setChecked(False)
            self.layout_radial_radio.setChecked(True)

        if self.root_node:
            self._layout_nodes()

    def _apply_filters(self):
        """Apply current filters to all nodes"""
        if not self.root_node:
            return

        self._filter_node_recursive(self.root_node)

    def _filter_node_recursive(self, node: FileNode):
        """
        Recursively apply filters to node and children.

        Args:
            node: FileNode to filter
        """
        if node.node_type == NodeType.DIRECTORY or node.node_type == NodeType.ROOT:
            category_name = "Directory"
        else:
            category_map = {
                FileTypeCategory.DOCUMENT: "Document",
                FileTypeCategory.IMAGE: "Image",
                FileTypeCategory.VIDEO: "Video",
                FileTypeCategory.AUDIO: "Audio",
                FileTypeCategory.ARCHIVE: "Archive",
                FileTypeCategory.EXECUTABLE: "Executable",
                FileTypeCategory.CODE: "Code",
            }
            category_name = category_map.get(node.file_category, "Directory")

        type_visible = self.active_filters.get(category_name, True)
        name_matches = (not self.search_text) or (self.search_text in node.name.lower())

        is_filtered = not (type_visible and name_matches)

        hide_mode = (self.filter_mode == "hide")
        node.set_filtered(is_filtered, hide_mode)

        for child in node.children:
            self._filter_node_recursive(child)

    def _on_generate(self):
        """Generate the mind map"""
        if not self.image_handler:
            QMessageBox.warning(self, "Error", "No image handler set")
            return

        self.view.clear_scene()
        self.node_map.clear()
        self.root_node = None

        self.generate_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.worker = MindMapWorker(
            self.image_handler,
            self.start_offset,
            self.max_depth,
            self.max_children,
            max_nodes_guard=self.config.get("max_nodes_guard", 1000000),
            batch_emit_size=self.config.get("batch_emit_size", 100),
            checkpoint_interval=self.config.get("checkpoint_interval", 1000)
        )
        self.worker.nodes_batch_created.connect(self._on_nodes_batch_created)
        self.worker.progress_update.connect(self._on_progress)
        self.worker.status_update.connect(self._on_status)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.guard_limit_reached.connect(self._on_guard_limit_reached)

        if hasattr(self, '_api_complete_callback'):
            self.worker.finished.connect(self._api_complete_callback)
        if hasattr(self, '_api_error_callback'):
            self.worker.error.connect(self._api_error_callback)

        self.worker.start()

    def _on_cancel(self):
        """Cancel the generation"""
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.cancel_btn.setEnabled(False)

    def _on_nodes_batch_created(self, nodes_batch: list):
        """Handle batch of nodes from worker"""
        if not self.root_node:
            self.root_node = FileNode("Root", NodeType.ROOT, 0, FileTypeCategory.UNKNOWN, None)
            self.view.scene.addItem(self.root_node)
            self.node_map[""] = self.root_node

        for name, node_type, parent_path, metadata in nodes_batch:
            category = self._categorize_file(name)

            ntype = NodeType.DIRECTORY if node_type == NodeType.DIRECTORY.value else NodeType.FILE

            parent_node = self.node_map.get(parent_path, self.root_node)

            node = FileNode(
                name, ntype, metadata.get('size', 0),
                category, metadata.get('inode'), parent_node
            )
            parent_node.add_child(node)
            self.view.scene.addItem(node)

            if node.connection_line:
                self.view.scene.addItem(node.connection_line)

            node_path = f"{parent_path}/{name}" if parent_path else name
            self.node_map[node_path] = node

    def _on_guard_limit_reached(self, node_count: int):
        """Handle max_nodes_guard limit reached"""
        QMessageBox.warning(
            self,
            "Emergency Stop",
            f"The scan has been stopped because it reached the emergency safety limit "
            f"of {self.config.get('max_nodes_guard', 1000000):,} nodes.\n\n"
            f"Current count: {node_count:,} nodes\n\n"
            f"This limit prevents runaway scans. You can increase it in the config file:\n"
            f"config/mindmap_config.json"
        )

    def _layout_nodes(self):
        """Layout nodes based on current layout mode."""
        if not self.root_node:
            return

        if self.layout_mode == "radial":
            self._layout_radial()
        else:
            self._layout_tree()

        self.view.scene.setSceneRect(self.view.scene.itemsBoundingRect())

    def _layout_tree(self):
        """Layout nodes in a hierarchical tree structure."""
        def calculate_positions(node, x, y, level_widths):
            """Recursively calculate node positions."""
            if not hasattr(node, 'level'):
                node.level = 0

            if node.level not in level_widths:
                level_widths[node.level] = []

            node.setPos(x * self.layout_spacing, y * self.level_spacing)
            level_widths[node.level].append(x)

            if node.children:
                child_y = y + 1
                num_children = len(node.children)
                child_x_start = x - (num_children - 1) / 2

                for i, child in enumerate(node.children):
                    child_x = child_x_start + i
                    child.level = node.level + 1
                    calculate_positions(child, child_x, child_y, level_widths)

        level_widths = {}
        calculate_positions(self.root_node, 0, 0, level_widths)

        def update_connections(node):
            """Recursively update connection lines."""
            for child in node.children:
                child.update_connection_line()
                update_connections(child)

        update_connections(self.root_node)

    def _layout_radial(self):
        """
        Layout nodes in a force-directed radial pattern.

        Uses physics simulation to balance node distribution.
        """
        all_nodes = []
        def collect_nodes(node):
            all_nodes.append(node)
            for child in node.children:
                collect_nodes(child)

        collect_nodes(self.root_node)

        self.root_node.setPos(0, 0)
        radius = 150

        node_positions = {self.root_node: QPointF(0, 0)}

        for i, node in enumerate(all_nodes[1:]):
            angle = (2 * math.pi * i) / (len(all_nodes) - 1)
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)
            node_positions[node] = QPointF(x, y)

        iterations = 100
        for iteration in range(iterations):
            forces = {node: QPointF(0, 0) for node in all_nodes}

            repulsion_strength = 5000
            for i, node1 in enumerate(all_nodes):
                for node2 in all_nodes[i+1:]:
                    pos1 = node_positions[node1]
                    pos2 = node_positions[node2]
                    dx = pos2.x() - pos1.x()
                    dy = pos2.y() - pos1.y()
                    dist = math.sqrt(dx*dx + dy*dy) + 1

                    force = repulsion_strength / (dist * dist)
                    fx = (dx / dist) * force
                    fy = (dy / dist) * force

                    forces[node1] -= QPointF(fx, fy)
                    forces[node2] += QPointF(fx, fy)

            attraction_strength = 0.1
            for node in all_nodes:
                if node.parent_node and node.parent_node in node_positions:
                    pos_node = node_positions[node]
                    pos_parent = node_positions[node.parent_node]
                    dx = pos_parent.x() - pos_node.x()
                    dy = pos_parent.y() - pos_node.y()

                    forces[node] += QPointF(dx * attraction_strength, dy * attraction_strength)

            damping = 0.9
            for node in all_nodes:
                if node != self.root_node:
                    new_pos = node_positions[node] + forces[node] * damping
                    node_positions[node] = new_pos

        for node, pos in node_positions.items():
            node.setPos(pos)

        def update_connections(node):
            for child in node.children:
                child.update_connection_line()
                update_connections(child)

        update_connections(self.root_node)

    def _categorize_file(self, name: str) -> FileTypeCategory:
        """Categorize file by extension"""
        ext = os.path.splitext(name)[1].lower()

        categories = {
            FileTypeCategory.DOCUMENT: ['.doc', '.docx', '.pdf', '.txt', '.rtf', '.odt'],
            FileTypeCategory.IMAGE: ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico'],
            FileTypeCategory.VIDEO: ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv'],
            FileTypeCategory.AUDIO: ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma'],
            FileTypeCategory.ARCHIVE: ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'],
            FileTypeCategory.EXECUTABLE: ['.exe', '.dll', '.so', '.app', '.bat', '.sh'],
            FileTypeCategory.CODE: ['.py', '.java', '.cpp', '.c', '.js', '.html', '.css'],
            FileTypeCategory.DATA: ['.db', '.sql', '.json', '.xml', '.csv', '.log'],
        }

        for category, extensions in categories.items():
            if ext in extensions:
                return category

        return FileTypeCategory.UNKNOWN

    def _on_progress(self, value: int):
        """Update progress bar"""
        self.progress_bar.setValue(value)

    def _on_status(self, message: str):
        """Update status label"""
        self.status_label.setText(message)

    def _on_finished(self, node_count: int):
        """Handle completion"""
        self.generate_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.export_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Complete: {node_count} nodes")

        self._layout_nodes()

        self._update_stats(node_count)

        self.view.fit_in_view()

    def _on_error(self, message: str):
        """Handle error"""
        self.generate_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Error: {message}")
        QMessageBox.critical(self, "Error", message)

    def _update_stats(self, node_count: int):
        """Update statistics display"""
        file_counts = {}
        dir_count = 0
        total_size = 0

        for node in self.node_map.values():
            if node.node_type == NodeType.DIRECTORY:
                dir_count += 1
            else:
                category = node.file_category.value
                file_counts[category] = file_counts.get(category, 0) + 1
                total_size += node.size

        stats = [
            f"Total Nodes: {node_count}",
            f"Directories: {dir_count}",
            f"Files: {node_count - dir_count}",
            f"Total Size: {FileNode._format_size(total_size)}",
        ]

        if file_counts:
            stats.append("\nFile Types:")
            for category, count in sorted(file_counts.items()):
                stats.append(f"  {category}: {count}")

        self.stats_label.setText("\n".join(stats))

    def _on_export(self):
        """Export mind map"""
        if not self.root_node:
            return

        menu = QMenu(self)
        menu.addAction("Export as PNG", lambda: self._export_png())
        menu.addAction("Export as SVG", lambda: self._export_svg())
        menu.addAction("Export as JSON", lambda: self._export_json())

        menu.exec_(self.export_btn.mapToGlobal(self.export_btn.rect().bottomLeft()))

    def _export_png(self):
        """Export as PNG image"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export as PNG", "", "PNG Images (*.png)"
        )
        if not file_path:
            return

        rect = self.view.scene.itemsBoundingRect()
        rect.adjust(-50, -50, 50, 50)

        image = QImage(rect.size().toSize(), QImage.Format_ARGB32)
        image.fill(Qt.white)

        painter = QPainter(image)
        painter.setRenderHint(QPainter.Antialiasing)
        self.view.scene.render(painter, QRectF(), rect)
        painter.end()

        if image.save(file_path):
            QMessageBox.information(self, "Success", f"Exported to {file_path}")
        else:
            QMessageBox.warning(self, "Error", "Failed to export PNG")

    def _export_svg(self):
        """Export as SVG vector graphics"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export as SVG", "", "SVG Files (*.svg)"
        )
        if not file_path:
            return

        rect = self.view.scene.itemsBoundingRect()
        rect.adjust(-50, -50, 50, 50)

        generator = QSvgGenerator()
        generator.setFileName(file_path)
        generator.setSize(rect.size().toSize())
        generator.setViewBox(rect)
        generator.setTitle("ForensAI Mind Map")
        generator.setDescription("Filesystem visualization exported from ForensAI")

        painter = QPainter(generator)
        painter.setRenderHint(QPainter.Antialiasing)
        self.view.scene.render(painter, QRectF(), rect)
        painter.end()

        QMessageBox.information(self, "Success", f"Exported to {file_path}")

    def _export_json(self):
        """Export as JSON"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export as JSON", "", "JSON Files (*.json)"
        )
        if not file_path:
            return

        def build_tree(node: FileNode) -> dict:
            tree = {
                'name': node.name,
                'type': node.node_type.value,
                'size': node.size,
                'inode': node.inode,
                'category': node.file_category.value if node.node_type == NodeType.FILE else None,
                'children': []
            }
            for child in node.children:
                tree['children'].append(build_tree(child))
            return tree

        data = build_tree(self.root_node)

        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            QMessageBox.information(self, "Success", f"Exported to {file_path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to export JSON: {e}")

    def export_mindmap(self, out_dir: str, formats: List[str] = None) -> Dict[str, str]:
        """
        Programmatic API to export mind map to multiple formats.

        Args:
            out_dir: Output directory for exports
            formats: List of formats to export ('png', 'svg', 'json')
                    Defaults to all formats

        Returns:
            Dictionary mapping format to output file path

        Example:
            >>> widget.export_mindmap('./exports', ['png', 'json'])
            {'png': './exports/mindmap.png', 'json': './exports/mindmap.json'}
        """
        if formats is None:
            formats = ['png', 'svg', 'json']

        if not self.root_node:
            return {}

        os.makedirs(out_dir, exist_ok=True)

        results = {}

        if 'png' in formats:
            png_path = os.path.join(out_dir, 'mindmap.png')
            try:
                rect = self.view.scene.itemsBoundingRect()
                rect.adjust(-50, -50, 50, 50)
                image = QImage(rect.size().toSize(), QImage.Format_ARGB32)
                image.fill(Qt.white)
                painter = QPainter(image)
                painter.setRenderHint(QPainter.Antialiasing)
                self.view.scene.render(painter, QRectF(), rect)
                painter.end()
                if image.save(png_path):
                    results['png'] = png_path
            except Exception as e:
                print(f"PNG export failed: {e}")

        if 'svg' in formats:
            svg_path = os.path.join(out_dir, 'mindmap.svg')
            try:
                rect = self.view.scene.itemsBoundingRect()
                rect.adjust(-50, -50, 50, 50)
                generator = QSvgGenerator()
                generator.setFileName(svg_path)
                generator.setSize(rect.size().toSize())
                generator.setViewBox(rect)
                generator.setTitle("ForensAI Mind Map")
                generator.setDescription("Filesystem visualization")
                painter = QPainter(generator)
                painter.setRenderHint(QPainter.Antialiasing)
                self.view.scene.render(painter, QRectF(), rect)
                painter.end()
                results['svg'] = svg_path
            except Exception as e:
                print(f"SVG export failed: {e}")

        if 'json' in formats:
            json_path = os.path.join(out_dir, 'mindmap.json')
            try:
                def build_tree(node: FileNode) -> dict:
                    tree = {
                        'name': node.name,
                        'type': node.node_type.value,
                        'size': node.size,
                        'inode': node.inode,
                        'category': node.file_category.value if node.node_type == NodeType.FILE else None,
                        'children': []
                    }
                    for child in node.children:
                        tree['children'].append(build_tree(child))
                    return tree

                data = build_tree(self.root_node)
                with open(json_path, 'w') as f:
                    json.dump(data, f, indent=2)
                results['json'] = json_path
            except Exception as e:
                print(f"JSON export failed: {e}")

        return results

    def export_full_structure(self, output_path: str = None, include_metadata: bool = True) -> Dict[str, Any]:
        """
        Export complete discovered filesystem structure to JSON.

        Supports partial export during scanning (doesn't require scan completion).
        Includes comprehensive metadata, statistics, and file information.

        Args:
            output_path: Path to output JSON file. If None, auto-generates filename
            include_metadata: Whether to include timestamps and extended metadata

        Returns:
            Dictionary with export info including:
            - 'success': bool
            - 'output_file': str (path to exported file)
            - 'node_count': int
            - 'error': str (if failed)

        Example:
            >>> widget.export_full_structure('./exports/full_structure.json')
            {'success': True, 'output_file': './exports/full_structure.json', 'node_count': 5234}
        """
        if not self.root_node:
            return {
                'success': False,
                'error': 'No data to export - root node not created yet'
            }

        if output_path is None:
            timestamp = QTimer.currentTime().toString() if hasattr(QTimer, 'currentTime') else "unknown"
            output_path = os.path.join(
                "ui", "mindmap", "exports",
                f"full_structure_{self.start_offset}_{timestamp}.json"
            )

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        try:
            def build_full_tree(node: FileNode, path: str = "") -> dict:
                """Recursively build tree with full metadata"""
                current_path = f"{path}/{node.name}" if path else node.name

                tree = {
                    'name': node.name,
                    'path': current_path,
                    'type': node.node_type.value,
                    'size': node.size,
                    'size_human': self._format_size(node.size),
                    'inode': node.inode,
                    'is_collapsed': not node.is_expanded if hasattr(node, 'is_expanded') else False,
                    'child_count': len(node.children),
                    'children': []
                }

                if node.node_type == NodeType.FILE:
                    tree['category'] = node.file_category.value
                    tree['extension'] = os.path.splitext(node.name)[1].lower()

                if include_metadata:
                    tree['metadata'] = {
                        'position': {
                            'x': node.pos().x() if hasattr(node, 'pos') else 0,
                            'y': node.pos().y() if hasattr(node, 'pos') else 0
                        },
                        'visible': node.isVisible() if hasattr(node, 'isVisible') else True,
                        'filtered': node.is_filtered if hasattr(node, 'is_filtered') else False
                    }

                for child in node.children:
                    tree['children'].append(build_full_tree(child, current_path))

                return tree

            full_tree = build_full_tree(self.root_node)

            def count_nodes(tree_dict):
                """Count total nodes in tree"""
                count = 1
                for child in tree_dict.get('children', []):
                    count += count_nodes(child)
                return count

            def count_by_type(tree_dict, counts=None):
                """Count nodes by type"""
                if counts is None:
                    counts = {'files': 0, 'directories': 0}

                if tree_dict['type'] == NodeType.FILE.value:
                    counts['files'] += 1
                elif tree_dict['type'] == NodeType.DIRECTORY.value:
                    counts['directories'] += 1

                for child in tree_dict.get('children', []):
                    count_by_type(child, counts)

                return counts

            def calculate_total_size(tree_dict):
                """Calculate total size of all files"""
                total = tree_dict.get('size', 0)
                for child in tree_dict.get('children', []):
                    total += calculate_total_size(child)
                return total

            node_count = count_nodes(full_tree)
            type_counts = count_by_type(full_tree)
            total_size = calculate_total_size(full_tree)

            export_data = {
                'version': '1.0',
                'export_type': 'full_structure',
                'timestamp': str(QTimer.currentTime()) if hasattr(QTimer, 'currentTime') else 'unknown',
                'source': {
                    'image_handler': self.image_handler.__class__.__name__ if self.image_handler else 'Unknown',
                    'start_offset': self.start_offset,
                    'scan_complete': not (self.worker and self.worker.isRunning())
                },
                'statistics': {
                    'total_nodes': node_count,
                    'files': type_counts['files'],
                    'directories': type_counts['directories'],
                    'total_size': total_size,
                    'total_size_human': self._format_size(total_size)
                },
                'tree': full_tree
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            return {
                'success': True,
                'output_file': output_path,
                'node_count': node_count,
                'total_size': total_size
            }

        except Exception as e:
            return {
                'success': False,
                'error': f"Export failed: {str(e)}"
            }

    def _format_size(self, size: int) -> str:
        """Format size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

    def save_layout_state(self, filepath: str = None) -> bool:
        """
        Save current layout state (node positions, zoom, collapsed states).

        Args:
            filepath: Optional custom filepath. If None, uses default location
                     based on image path and partition offset.

        Returns:
            True if saved successfully, False otherwise
        """
        if not self.root_node:
            return False

        if filepath is None:
            if not self.image_handler or not hasattr(self.image_handler, 'image_path'):
                return False
            image_name = os.path.basename(self.image_handler.image_path)
            filename = f"mindmap_layout_{image_name}_{self.start_offset}.json"
            filepath = os.path.join(os.path.dirname(__file__), filename)

        state = {
            "version": "1.0",
            "image_path": getattr(self.image_handler, 'image_path', None),
            "partition_offset": self.start_offset,
            "zoom_level": self.view._zoom_factor,
            "pan_offset": {
                "x": self.view.horizontalScrollBar().value(),
                "y": self.view.verticalScrollBar().value()
            },
            "filter_state": self.active_filters.copy(),
            "search_text": self.search_text,
            "nodes": {}
        }

        def save_node_state(node: FileNode, path: str = ""):
            node_path = f"{path}/{node.name}" if path else node.name
            state["nodes"][node_path] = {
                "position": {"x": node.pos().x(), "y": node.pos().y()},
                "collapsed": not node.is_expanded
            }
            for child in node.children:
                save_node_state(child, node_path)

        if self.root_node:
            save_node_state(self.root_node)

        try:
            with open(filepath, 'w') as f:
                json.dump(state, f, indent=2)
            return True
        except Exception as e:
            print(f"Failed to save layout state: {e}")
            return False

    def load_layout_state(self, filepath: str = None) -> bool:
        """
        Load saved layout state (node positions, zoom, collapsed states).

        Args:
            filepath: Optional custom filepath. If None, looks for default location
                     based on image path and partition offset.

        Returns:
            True if loaded successfully, False otherwise
        """
        if filepath is None:
            if not self.image_handler or not hasattr(self.image_handler, 'image_path'):
                return False
            image_name = os.path.basename(self.image_handler.image_path)
            filename = f"mindmap_layout_{image_name}_{self.start_offset}.json"
            filepath = os.path.join(os.path.dirname(__file__), filename)

        if not os.path.exists(filepath):
            return False

        try:
            with open(filepath, 'r') as f:
                state = json.load(f)

            if "zoom_level" in state:
                zoom_diff = state["zoom_level"] / self.view._zoom_factor
                self.view.scale(zoom_diff, zoom_diff)

            if "pan_offset" in state:
                self.view.horizontalScrollBar().setValue(int(state["pan_offset"]["x"]))
                self.view.verticalScrollBar().setValue(int(state["pan_offset"]["y"]))

            if "filter_state" in state:
                self.active_filters = state["filter_state"]
                for name, checked in self.active_filters.items():
                    if name in self.legend_checkboxes:
                        self.legend_checkboxes[name].setChecked(checked)

            if "search_text" in state:
                self.search_text = state["search_text"]
                if hasattr(self, 'search_box'):
                    self.search_box.setText(self.search_text)

            if "nodes" in state and self.root_node:
                def restore_node_state(node: FileNode, path: str = ""):
                    node_path = f"{path}/{node.name}" if path else node.name
                    if node_path in state["nodes"]:
                        node_state = state["nodes"][node_path]
                        if "position" in node_state:
                            pos = node_state["position"]
                            node.setPos(pos["x"], pos["y"])
                        if "collapsed" in node_state and node_state["collapsed"]:
                            if node.is_expanded:
                                node.collapse(animated=False)
                    for child in node.children:
                        restore_node_state(child, node_path)

                restore_node_state(self.root_node)

            self._apply_filters()

            return True
        except Exception as e:
            print(f"Failed to load layout state: {e}")
            return False


class MindMapJob:
    """
    Handle for an asynchronous mind map generation job.

    Provides status checking and result retrieval.
    """

    def __init__(self, widget: MindMapWidget):
        """
        Initialize job handle.

        Args:
            widget: MindMapWidget instance
        """
        self.widget = widget
        self._is_complete = False
        self._error = None

    def status(self) -> str:
        """
        Get current job status.

        Returns:
            Status string: 'running', 'completed', 'error', or 'cancelled'
        """
        if self._error:
            return 'error'
        elif self._is_complete:
            return 'completed'
        elif self.widget.worker and self.widget.worker.isRunning():
            return 'running'
        else:
            return 'cancelled'

    def result(self) -> Optional[FileNode]:
        """
        Get the result (root node) if completed.

        Returns:
            Root FileNode if completed, None otherwise
        """
        if self._is_complete:
            return self.widget.root_node
        return None

    def wait(self, timeout: int = 30000) -> bool:
        """
        Wait for job to complete.

        Args:
            timeout: Timeout in milliseconds

        Returns:
            True if completed, False if timeout
        """
        if self.widget.worker:
            return self.widget.worker.wait(timeout)
        return False

    def cancel(self):
        """Cancel the job"""
        self.widget._on_cancel()


def create_mindmap_from_image(
    image_handler,
    start_offset: int = 0,
    outdir: Optional[str] = None,
    options: Optional[Dict[str, Any]] = None
) -> MindMapJob:
    """
    Generate mind map from forensic image (programmatic API).

    This function creates a MindMapWidget, configures it, and starts
    the mind map generation process. It returns a job handle that can
    be used to check status and retrieve results.

    Args:
        image_handler: ImageHandler instance with filesystem access
        start_offset: Partition offset to start from (default: 0)
        outdir: Output directory for JSON export (optional)
        options: Optional configuration dict with keys:
            - max_depth: Maximum directory depth (default: 5)
            - max_children: Maximum children per directory (default: 50)
            - show_widget: Whether to show the widget (default: False)
            - auto_export_json: Auto-export JSON to outdir (default: False)

    Returns:
        MindMapJob: Job handle for async operations

    Example:
        >>> handler = ImageHandler("evidence.dd")
        >>> job = create_mindmap_from_image(handler, start_offset=2048)
        >>> job.wait()  # Wait for completion
        >>> if job.status() == 'completed':
        ...     root = job.result()
        ...     print(f"Found {len(root.children)} root items")
    """
    options = options or {}
    max_depth = options.get('max_depth', 5)
    max_children = options.get('max_children', 50)
    show_widget = options.get('show_widget', False)
    auto_export = options.get('auto_export_json', False)

    widget = MindMapWidget()
    widget.max_depth = max_depth
    widget.max_children = max_children
    widget.depth_spin.setValue(max_depth)
    widget.children_spin.setValue(max_children)

    widget.set_image_handler(image_handler, start_offset)

    job = MindMapJob(widget)

    def on_complete(node_count):
        job._is_complete = True
        if auto_export and outdir and widget.root_node:
            json_path = os.path.join(outdir, "mindmap.json")
            def build_tree(node: FileNode) -> dict:
                tree = {
                    'name': node.name,
                    'type': node.node_type.value,
                    'size': node.size,
                    'inode': node.inode,
                    'category': node.file_category.value if node.node_type == NodeType.FILE else None,
                    'children': []
                }
                for child in node.children:
                    tree['children'].append(build_tree(child))
                return tree

            data = build_tree(widget.root_node)
            try:
                with open(json_path, 'w') as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                job._error = str(e)

    def on_error(msg):
        job._error = msg

    widget._api_complete_callback = on_complete
    widget._api_error_callback = on_error

    if show_widget:
        widget.show()

    widget._on_generate()

    return job
