"""
ForensAI - Timeline Tab
========================
Interactive timeline visualization for forensic artifacts.

Displays artifacts on a time-based X axis with activity type on the Y axis,
color-coded by MITRE ATT&CK stage. Supports pan, zoom, filtering, and
integration with the CorrelationEngine's attack chain reconstruction.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGraphicsScene, QGraphicsView,
    QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem,
    QGraphicsRectItem, QToolBar, QComboBox, QLabel, QStatusBar,
    QGraphicsItem, QToolButton, QSizePolicy, QFrame, QGraphicsSimpleTextItem,
)
from PySide6.QtCore import Qt, Signal, QRectF, QPointF, QMarginsF
from PySide6.QtGui import (
    QColor, QPen, QBrush, QFont, QPainter, QWheelEvent, QMouseEvent,
    QAction, QIcon, QTransform,
)


@dataclass
class TimelineEvent:
    """A single forensic event to be plotted on the timeline."""

    timestamp: datetime
    name: str
    event_type: str
    details: str
    risk_score: int
    mitre_stage: str
    color: QColor = field(default_factory=lambda: QColor("#95A5A6"))


MITRE_COLORS: Dict[str, str] = {
    "Initial Access":        "#E74C3C",
    "Execution":             "#E67E22",
    "Persistence":           "#F1C40F",
    "Privilege Escalation":  "#2ECC71",
    "Defense Evasion":       "#1ABC9C",
    "Credential Access":     "#3498DB",
    "Discovery":             "#9B59B6",
    "Lateral Movement":      "#E91E63",
    "Collection":            "#00BCD4",
    "Exfiltration":          "#FF5722",
    "Impact":                "#F44336",
    "Unknown":               "#95A5A6",
}

_STAGE_DISPLAY_NAMES: Dict[str, str] = {
    "initial_access":        "Initial Access",
    "execution":             "Execution",
    "persistence":           "Persistence",
    "privilege_escalation":  "Privilege Escalation",
    "defense_evasion":       "Defense Evasion",
    "credential_access":     "Credential Access",
    "discovery":             "Discovery",
    "lateral_movement":      "Lateral Movement",
    "collection":            "Collection",
    "exfiltration":          "Exfiltration",
    "impact":                "Impact",
}


class EventMarker(QGraphicsEllipseItem):
    """A clickable, hoverable circle representing one timeline event."""

    RADIUS = 8

    def __init__(self, event: TimelineEvent, parent=None):
        diameter = self.RADIUS * 2
        super().__init__(-self.RADIUS, -self.RADIUS, diameter, diameter, parent)
        self.event = event

        color = QColor(event.color)
        self.setBrush(QBrush(color))
        self.setPen(QPen(color.darker(130), 1.5))

        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setCursor(Qt.PointingHandCursor)

        tip_lines = [
            f"<b>{event.name}</b>",
            f"Time: {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Type: {event.event_type}",
            f"MITRE Stage: {event.mitre_stage}",
            f"Risk Score: {event.risk_score}",
        ]
        if event.details:
            detail_text = event.details[:200]
            if len(event.details) > 200:
                detail_text += "..."
            tip_lines.append(f"Details: {detail_text}")
        self.setToolTip("<br>".join(tip_lines))

    def hoverEnterEvent(self, event):
        self.setScale(1.4)
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self.setScale(1.0)
        super().hoverLeaveEvent(event)


class TimelineScene(QGraphicsScene):
    """
    QGraphicsScene that draws the timeline axes and positions event markers.

    X axis = time (left to right)
    Y axis = activity / event type categories (top to bottom)
    """

    event_clicked = Signal(dict)

    MARGIN_LEFT = 160
    MARGIN_RIGHT = 40
    MARGIN_TOP = 40
    MARGIN_BOTTOM = 60
    ROW_HEIGHT = 50
    TICK_HEIGHT = 8
    MIN_PLOT_WIDTH = 600

    def __init__(self, parent=None):
        super().__init__(parent)
        self._events: List[TimelineEvent] = []
        self._markers: List[EventMarker] = []
        self._event_types: List[str] = []
        self._time_min: Optional[datetime] = None
        self._time_max: Optional[datetime] = None
        self._filter_stage: Optional[str] = None

        self._axis_pen = QPen(QColor("#CCCCCC"), 1)
        self._grid_pen = QPen(QColor("#3A3A3A"), 0.5, Qt.DotLine)
        self._label_font = QFont("Segoe UI", 9)
        self._tick_font = QFont("Segoe UI", 8)
        self._title_font = QFont("Segoe UI", 11, QFont.Bold)


    def set_events(self, events: List[TimelineEvent]):
        """Replace the current event list and redraw."""
        self._events = list(events)
        self._rebuild()

    def set_filter_stage(self, stage: Optional[str]):
        """Filter visible events to a single MITRE stage (None = show all)."""
        self._filter_stage = stage
        self._rebuild()

    def get_time_range(self):
        """Return (min_datetime, max_datetime) or (None, None)."""
        return self._time_min, self._time_max


    def _visible_events(self) -> List[TimelineEvent]:
        if self._filter_stage is None:
            return self._events
        return [e for e in self._events if e.mitre_stage == self._filter_stage]

    def _rebuild(self):
        """Clear and redraw everything."""
        self.clear()
        self._markers.clear()

        visible = self._visible_events()
        if not visible:
            text = self.addText("No events to display.", self._title_font)
            text.setDefaultTextColor(QColor("#888888"))
            text.setPos(20, 20)
            self.setSceneRect(QRectF(0, 0, 400, 100))
            return

        type_set: Dict[str, int] = {}
        for ev in visible:
            if ev.event_type not in type_set:
                type_set[ev.event_type] = len(type_set)
        self._event_types = list(type_set.keys())

        timestamps = [e.timestamp for e in visible]
        self._time_min = min(timestamps)
        self._time_max = max(timestamps)

        if self._time_min == self._time_max:
            self._time_min -= timedelta(hours=1)
            self._time_max += timedelta(hours=1)

        num_rows = len(self._event_types)
        plot_width = max(self.MIN_PLOT_WIDTH, len(visible) * 30)
        plot_height = max(num_rows * self.ROW_HEIGHT, 200)

        scene_w = self.MARGIN_LEFT + plot_width + self.MARGIN_RIGHT
        scene_h = self.MARGIN_TOP + plot_height + self.MARGIN_BOTTOM

        bg = self.addRect(
            QRectF(0, 0, scene_w, scene_h),
            QPen(Qt.NoPen),
            QBrush(QColor("#1E1E1E")),
        )
        bg.setZValue(-10)

        self._draw_y_axis(scene_h, plot_height)
        self._draw_x_axis(scene_w, scene_h, plot_width, plot_height)
        self._draw_grid(plot_width, plot_height)

        time_span = (self._time_max - self._time_min).total_seconds()
        if time_span == 0:
            time_span = 1

        for ev in visible:
            t_frac = (ev.timestamp - self._time_min).total_seconds() / time_span
            x = self.MARGIN_LEFT + t_frac * plot_width
            row_idx = type_set[ev.event_type]
            y = self.MARGIN_TOP + row_idx * self.ROW_HEIGHT + self.ROW_HEIGHT / 2

            marker = EventMarker(ev)
            marker.setPos(x, y)
            marker.setZValue(5)
            self.addItem(marker)
            self._markers.append(marker)

        self.setSceneRect(QRectF(0, 0, scene_w, scene_h))

    def _draw_y_axis(self, scene_h: float, plot_height: float):
        """Draw category labels along the Y axis."""
        self.addLine(
            self.MARGIN_LEFT, self.MARGIN_TOP,
            self.MARGIN_LEFT, self.MARGIN_TOP + plot_height,
            self._axis_pen,
        )

        for idx, label_text in enumerate(self._event_types):
            y = self.MARGIN_TOP + idx * self.ROW_HEIGHT + self.ROW_HEIGHT / 2
            self.addLine(
                self.MARGIN_LEFT - 4, y,
                self.MARGIN_LEFT, y,
                self._axis_pen,
            )
            label = self.addSimpleText(label_text, self._label_font)
            label.setBrush(QBrush(QColor("#CCCCCC")))
            label_width = label.boundingRect().width()
            label.setPos(self.MARGIN_LEFT - label_width - 8,
                         y - label.boundingRect().height() / 2)

    def _draw_x_axis(self, scene_w: float, scene_h: float,
                     plot_width: float, plot_height: float):
        """Draw time tick marks along the X axis."""
        y_axis_bottom = self.MARGIN_TOP + plot_height

        self.addLine(
            self.MARGIN_LEFT, y_axis_bottom,
            self.MARGIN_LEFT + plot_width, y_axis_bottom,
            self._axis_pen,
        )

        if self._time_min is None or self._time_max is None:
            return

        num_ticks = min(12, max(4, int(plot_width / 100)))
        time_span = (self._time_max - self._time_min).total_seconds()

        for i in range(num_ticks + 1):
            frac = i / num_ticks
            x = self.MARGIN_LEFT + frac * plot_width
            dt = self._time_min + timedelta(seconds=frac * time_span)

            self.addLine(x, y_axis_bottom, x, y_axis_bottom + self.TICK_HEIGHT,
                         self._axis_pen)

            if time_span > 86400 * 2:
                fmt = "%Y-%m-%d"
            elif time_span > 3600 * 2:
                fmt = "%m-%d %H:%M"
            else:
                fmt = "%H:%M:%S"

            tick_label = self.addSimpleText(dt.strftime(fmt), self._tick_font)
            tick_label.setBrush(QBrush(QColor("#AAAAAA")))
            lw = tick_label.boundingRect().width()
            tick_label.setPos(x - lw / 2,
                              y_axis_bottom + self.TICK_HEIGHT + 2)

    def _draw_grid(self, plot_width: float, plot_height: float):
        """Draw horizontal grid lines for each category row."""
        for idx in range(len(self._event_types)):
            y = self.MARGIN_TOP + idx * self.ROW_HEIGHT + self.ROW_HEIGHT / 2
            line = self.addLine(
                self.MARGIN_LEFT, y,
                self.MARGIN_LEFT + plot_width, y,
                self._grid_pen,
            )
            line.setZValue(-5)


    def handle_marker_click(self, marker: EventMarker):
        """Emit event_clicked with the event data as a dict."""
        ev = marker.event
        self.event_clicked.emit({
            "timestamp": ev.timestamp.isoformat(),
            "name": ev.name,
            "event_type": ev.event_type,
            "details": ev.details,
            "risk_score": ev.risk_score,
            "mitre_stage": ev.mitre_stage,
        })


class _TimelineView(QGraphicsView):
    """QGraphicsView with mouse-wheel zoom and middle-button pan."""

    def __init__(self, scene: TimelineScene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.setRenderHint(QPainter.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        self.setBackgroundBrush(QBrush(QColor("#1E1E1E")))
        self.setFrameShape(QFrame.NoFrame)

        self._zoom_factor = 1.0
        self._min_zoom = 0.1
        self._max_zoom = 10.0

    def wheelEvent(self, event: QWheelEvent):
        """Zoom in / out with the mouse wheel."""
        factor = 1.15
        if event.angleDelta().y() > 0:
            if self._zoom_factor * factor <= self._max_zoom:
                self.scale(factor, factor)
                self._zoom_factor *= factor
        else:
            if self._zoom_factor / factor >= self._min_zoom:
                self.scale(1 / factor, 1 / factor)
                self._zoom_factor /= factor

    def mouseReleaseEvent(self, event: QMouseEvent):
        """Detect clicks on event markers."""
        super().mouseReleaseEvent(event)
        if event.button() == Qt.LeftButton:
            item = self.itemAt(event.pos())
            if isinstance(item, EventMarker):
                scene = self.scene()
                if isinstance(scene, TimelineScene):
                    scene.handle_marker_click(item)

    def zoom_in(self):
        factor = 1.3
        if self._zoom_factor * factor <= self._max_zoom:
            self.scale(factor, factor)
            self._zoom_factor *= factor

    def zoom_out(self):
        factor = 1.3
        if self._zoom_factor / factor >= self._min_zoom:
            self.scale(1 / factor, 1 / factor)
            self._zoom_factor /= factor

    def fit_all(self):
        """Fit the entire scene into the viewport."""
        self.resetTransform()
        self._zoom_factor = 1.0
        scene_rect = self.scene().sceneRect()
        if not scene_rect.isNull():
            self.fitInView(scene_rect.marginsAdded(QMarginsF(20, 20, 20, 20)),
                           Qt.KeepAspectRatio)
            t = self.transform()
            self._zoom_factor = t.m11()


class _MitreLegend(QWidget):
    """Compact horizontal legend showing MITRE stage colors."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(10)

        for stage, hex_color in MITRE_COLORS.items():
            swatch = QLabel()
            swatch.setFixedSize(12, 12)
            swatch.setStyleSheet(
                f"background-color: {hex_color}; border: 1px solid #555; border-radius: 2px;"
            )
            label = QLabel(stage)
            label.setStyleSheet("color: #CCCCCC; font-size: 11px;")
            layout.addWidget(swatch)
            layout.addWidget(label)

        layout.addStretch()


class TimelineTab(QWidget):
    """
    Top-level widget for the forensic timeline visualization.

    Provides:
    - Interactive pan / zoom graphics view
    - Toolbar with zoom controls and MITRE stage filter
    - MITRE ATT&CK color legend
    - Status bar with event count and time range
    - Signal emitted when an event is selected
    """

    event_selected = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self._connect_signals()


    def _build_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(toolbar.iconSize())
        toolbar.setStyleSheet(
            "QToolBar { background: #2D2D2D; border-bottom: 1px solid #444; spacing: 4px; padding: 2px; }"
            "QToolButton { color: #CCC; padding: 4px 8px; border: 1px solid transparent; border-radius: 3px; }"
            "QToolButton:hover { background: #3A3A3A; border-color: #555; }"
        )

        self._action_zoom_in = QAction("Zoom In (+)", self)
        self._action_zoom_in.setShortcut("Ctrl+=")
        toolbar.addAction(self._action_zoom_in)

        self._action_zoom_out = QAction("Zoom Out (-)", self)
        self._action_zoom_out.setShortcut("Ctrl+-")
        toolbar.addAction(self._action_zoom_out)

        self._action_fit = QAction("Fit All", self)
        self._action_fit.setShortcut("Ctrl+0")
        toolbar.addAction(self._action_fit)

        toolbar.addSeparator()

        filter_label = QLabel(" MITRE Stage: ")
        filter_label.setStyleSheet("color: #CCC;")
        toolbar.addWidget(filter_label)

        self._filter_combo = QComboBox()
        self._filter_combo.setMinimumWidth(160)
        self._filter_combo.setStyleSheet(
            "QComboBox { background: #333; color: #CCC; border: 1px solid #555; "
            "border-radius: 3px; padding: 3px 8px; }"
            "QComboBox::drop-down { border: none; }"
            "QComboBox QAbstractItemView { background: #333; color: #CCC; selection-background-color: #555; }"
        )
        self._filter_combo.addItem("All Stages", None)
        for stage in MITRE_COLORS:
            self._filter_combo.addItem(stage, stage)
        toolbar.addWidget(self._filter_combo)

        main_layout.addWidget(toolbar)

        self._scene = TimelineScene(self)
        self._view = _TimelineView(self._scene, self)
        self._view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        main_layout.addWidget(self._view, stretch=1)

        self._legend = _MitreLegend(self)
        self._legend.setStyleSheet("background: #2A2A2A; border-top: 1px solid #444;")
        main_layout.addWidget(self._legend)

        self._status_bar = QStatusBar()
        self._status_bar.setStyleSheet(
            "QStatusBar { background: #252525; color: #999; font-size: 11px; border-top: 1px solid #444; }"
        )
        self._status_label = QLabel("No events loaded.")
        self._status_bar.addPermanentWidget(self._status_label)
        main_layout.addWidget(self._status_bar)

    def _connect_signals(self):
        self._action_zoom_in.triggered.connect(self._view.zoom_in)
        self._action_zoom_out.triggered.connect(self._view.zoom_out)
        self._action_fit.triggered.connect(self._view.fit_all)
        self._filter_combo.currentIndexChanged.connect(self._on_filter_changed)
        self._scene.event_clicked.connect(self._on_event_clicked)


    def load_events(self, events: List[TimelineEvent]):
        """
        Populate the timeline with the given events.

        Args:
            events: List of TimelineEvent dataclass instances.
        """
        for ev in events:
            hex_color = MITRE_COLORS.get(ev.mitre_stage, MITRE_COLORS["Unknown"])
            ev.color = QColor(hex_color)

        self._scene.set_events(events)
        self._update_status()
        self._view.fit_all()

    def load_from_correlation_engine(self, correlation_engine):
        """
        Build timeline events from a CorrelationEngine's attack chain.

        This calls ``build_attack_timeline()`` on the engine and converts
        each ``AttackChainStage`` into ``TimelineEvent`` instances.

        Args:
            correlation_engine: A ``managers.correlation_engine.CorrelationEngine``
                                instance (or any object with the same interface).
        """
        chain = correlation_engine.build_attack_timeline()
        events: List[TimelineEvent] = []

        for stage in chain:
            display_stage = _STAGE_DISPLAY_NAMES.get(stage.stage, stage.stage.replace("_", " ").title())
            hex_color = MITRE_COLORS.get(display_stage, MITRE_COLORS["Unknown"])
            color = QColor(hex_color)

            for artifact in stage.artifacts:
                ts = None
                for ts_field in ("modified", "created", "accessed"):
                    raw = artifact.get(ts_field)
                    if raw:
                        ts = self._parse_timestamp(raw)
                        if ts:
                            break

                if ts is None:
                    if stage.timestamp_range and stage.timestamp_range[0]:
                        ts = self._parse_timestamp(stage.timestamp_range[0])
                    if ts is None:
                        ts = datetime(2000, 1, 1)

                risk_score = correlation_engine.risk_scores.get(
                    correlation_engine._get_artifact_id(artifact), 0
                )

                mitre_label = display_stage
                techniques_str = ", ".join(stage.mitre_techniques) if stage.mitre_techniques else ""
                details_parts = [
                    f"Path: {artifact.get('path', 'N/A')}",
                    f"Confidence: {stage.confidence}",
                ]
                if techniques_str:
                    details_parts.append(f"MITRE Techniques: {techniques_str}")

                events.append(TimelineEvent(
                    timestamp=ts,
                    name=artifact.get("name", "unknown"),
                    event_type=display_stage,
                    details="; ".join(details_parts),
                    risk_score=risk_score,
                    mitre_stage=mitre_label,
                    color=color,
                ))

        self.load_events(events)


    @staticmethod
    def _parse_timestamp(raw) -> Optional[datetime]:
        """Try to parse a timestamp from various types."""
        if isinstance(raw, datetime):
            return raw
        if isinstance(raw, (int, float)):
            try:
                return datetime.fromtimestamp(raw)
            except (OSError, ValueError, OverflowError):
                return None
        if isinstance(raw, str):
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S UTC",
                        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                try:
                    return datetime.strptime(raw.split(".")[0], fmt)
                except ValueError:
                    continue
        return None

    def _on_filter_changed(self, index: int):
        stage = self._filter_combo.itemData(index)
        self._scene.set_filter_stage(stage)
        self._update_status()

    def _on_event_clicked(self, event_dict: dict):
        self.event_selected.emit(event_dict)

    def _update_status(self):
        visible = self._scene._visible_events()
        count = len(visible)
        t_min, t_max = self._scene.get_time_range()

        if count == 0:
            self._status_label.setText("No events to display.")
            return

        range_text = ""
        if t_min and t_max:
            range_text = (
                f"  |  Range: {t_min.strftime('%Y-%m-%d %H:%M:%S')} "
                f"to {t_max.strftime('%Y-%m-%d %H:%M:%S')}"
            )

        total = len(self._scene._events)
        filter_text = ""
        if count != total:
            filter_text = f" (filtered from {total})"

        self._status_label.setText(
            f"Events: {count}{filter_text}{range_text}"
        )
