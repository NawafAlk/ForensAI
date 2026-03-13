"""
Suspicion Dashboard - Default landing tab for ForensAI.

Displays key forensic metrics, MITRE ATT&CK stage visualization,
top suspicious indicators, and recommended investigative actions.
"""

from typing import List, Dict, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QPainter, QColor, QPen
from PySide6.QtWidgets import (
    QWidget,
    QFrame,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QTableWidget,
    QTableWidgetItem,
    QListWidget,
    QListWidgetItem,
    QHeaderView,
    QSizePolicy,
    QScrollArea,
    QSplitter,
)


# ---------------------------------------------------------------------------
# Severity colour constants
# ---------------------------------------------------------------------------
COLOR_CRITICAL = "#FF4444"
COLOR_HIGH = "#FFA500"
COLOR_MEDIUM = "#FFD700"
COLOR_LOW = "#4A90E2"
COLOR_INFO = "#888888"

# ---------------------------------------------------------------------------
# MITRE ATT&CK stage definitions (in kill-chain order)
# ---------------------------------------------------------------------------
MITRE_STAGES = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Priv Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
]


# ========================================================================= #
#  MetricCard                                                                #
# ========================================================================= #
class MetricCard(QFrame):
    """Displays a single numeric metric with a title, large value, and colour accent."""

    def __init__(self, title: str, value: str = "0", color: str = "#4A90E2", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("metricCard")
        self._color = color

        self.setMinimumSize(160, 100)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self._apply_style(color)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        # Title label
        self._title_label = QLabel(title)
        self._title_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self._title_label.setStyleSheet("color: #AAAAAA; font-size: 12px; background: transparent; border: none;")
        layout.addWidget(self._title_label)

        # Value label
        self._value_label = QLabel(value)
        self._value_label.setAlignment(Qt.AlignLeft | Qt.AlignBottom)
        value_font = QFont()
        value_font.setPointSize(26)
        value_font.setBold(True)
        self._value_label.setFont(value_font)
        self._value_label.setStyleSheet(f"color: {color}; background: transparent; border: none;")
        layout.addWidget(self._value_label)

    # ---- public API -------------------------------------------------------
    def set_value(self, value: str) -> None:
        """Update the displayed value."""
        self._value_label.setText(value)

    # ---- internal ---------------------------------------------------------
    def _apply_style(self, color: str) -> None:
        self.setStyleSheet(
            f"""
            QFrame#metricCard {{
                background-color: #1E1E2E;
                border: 1px solid {color}40;
                border-left: 3px solid {color};
                border-radius: 8px;
            }}
            """
        )


# ========================================================================= #
#  AttackStageWidget                                                         #
# ========================================================================= #
class AttackStageWidget(QWidget):
    """Horizontal MITRE ATT&CK kill-chain pipeline with per-stage artifact counts."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("attackStageWidget")
        self._counts: Dict[str, int] = {stage: 0 for stage in MITRE_STAGES}

        self.setMinimumHeight(90)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # Wrap in a scroll area so it remains usable on smaller screens.
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        header = QLabel("MITRE ATT&CK Kill Chain")
        header.setStyleSheet("color: #CCCCCC; font-size: 13px; font-weight: bold; padding: 4px 0;")
        outer.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        container = QWidget()
        self._stage_layout = QHBoxLayout(container)
        self._stage_layout.setContentsMargins(4, 4, 4, 4)
        self._stage_layout.setSpacing(0)

        self._stage_labels: Dict[str, QLabel] = {}
        self._arrow_labels: List[QLabel] = []

        for idx, stage in enumerate(MITRE_STAGES):
            lbl = QLabel(f"{stage}\n0")
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setFixedHeight(56)
            lbl.setMinimumWidth(100)
            lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            self._apply_stage_style(lbl, active=False)
            self._stage_labels[stage] = lbl
            self._stage_layout.addWidget(lbl)

            if idx < len(MITRE_STAGES) - 1:
                arrow = QLabel("\u25B6")
                arrow.setAlignment(Qt.AlignCenter)
                arrow.setFixedWidth(20)
                arrow.setStyleSheet("color: #555555; font-size: 14px; background: transparent;")
                self._arrow_labels.append(arrow)
                self._stage_layout.addWidget(arrow)

        scroll.setWidget(container)
        outer.addWidget(scroll)

    # ---- public API -------------------------------------------------------
    def set_counts(self, counts: Dict[str, int]) -> None:
        """Update artifact counts per stage and refresh visual state."""
        self._counts = counts
        for stage, lbl in self._stage_labels.items():
            count = counts.get(stage, 0)
            lbl.setText(f"{stage}\n{count}")
            self._apply_stage_style(lbl, active=(count > 0))

        # Colour arrows adjacent to active stages
        for idx, arrow in enumerate(self._arrow_labels):
            left_active = counts.get(MITRE_STAGES[idx], 0) > 0
            right_active = counts.get(MITRE_STAGES[idx + 1], 0) > 0
            if left_active or right_active:
                arrow.setStyleSheet("color: #FFA500; font-size: 14px; background: transparent;")
            else:
                arrow.setStyleSheet("color: #555555; font-size: 14px; background: transparent;")

    def clear(self) -> None:
        self.set_counts({stage: 0 for stage in MITRE_STAGES})

    # ---- internal ---------------------------------------------------------
    @staticmethod
    def _apply_stage_style(label: QLabel, active: bool) -> None:
        if active:
            label.setStyleSheet(
                """
                background-color: #2A1F1F;
                color: #FF6B6B;
                border: 1px solid #FF444480;
                border-radius: 6px;
                font-size: 11px;
                font-weight: bold;
                padding: 4px;
                """
            )
        else:
            label.setStyleSheet(
                """
                background-color: #1E1E2E;
                color: #666666;
                border: 1px solid #333333;
                border-radius: 6px;
                font-size: 11px;
                padding: 4px;
                """
            )


# ========================================================================= #
#  SuspicionDashboard                                                        #
# ========================================================================= #
class SuspicionDashboard(QWidget):
    """Main dashboard widget that aggregates metrics, kill-chain view,
    top indicators, and recommended actions."""

    artifact_selected = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("suspicionDashboard")
        self.setStyleSheet(
            """
            QWidget#suspicionDashboard {
                background-color: #14141E;
            }
            """
        )

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(16)

        # --- Title banner ---------------------------------------------------
        banner = QLabel("Suspicion Dashboard")
        banner.setStyleSheet(
            "color: #EEEEEE; font-size: 20px; font-weight: bold; "
            "padding-bottom: 4px; border-bottom: 1px solid #333333;"
        )
        main_layout.addWidget(banner)

        # --- Metric cards row -----------------------------------------------
        metrics_layout = QGridLayout()
        metrics_layout.setSpacing(12)

        self._card_total = MetricCard("Total Scanned", "0", COLOR_LOW)
        self._card_critical = MetricCard("Critical", "0", COLOR_CRITICAL)
        self._card_high = MetricCard("High", "0", COLOR_HIGH)
        self._card_medium = MetricCard("Medium", "0", COLOR_MEDIUM)
        self._card_low = MetricCard("Low", "0", COLOR_INFO)

        metrics_layout.addWidget(self._card_total, 0, 0)
        metrics_layout.addWidget(self._card_critical, 0, 1)
        metrics_layout.addWidget(self._card_high, 0, 2)
        metrics_layout.addWidget(self._card_medium, 0, 3)
        metrics_layout.addWidget(self._card_low, 0, 4)

        main_layout.addLayout(metrics_layout)

        # --- MITRE ATT&CK stage widget -------------------------------------
        self._attack_widget = AttackStageWidget()
        main_layout.addWidget(self._attack_widget)

        # --- Bottom section (table + list) ----------------------------------
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet(
            """
            QSplitter::handle {
                background-color: #333333;
                width: 2px;
            }
            """
        )

        # -- Top 5 Suspicious Indicators table --
        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        indicators_header = QLabel("Top 5 Suspicious Indicators")
        indicators_header.setStyleSheet("color: #CCCCCC; font-size: 13px; font-weight: bold;")
        left_layout.addWidget(indicators_header)

        self._indicators_table = QTableWidget(0, 3)
        self._indicators_table.setHorizontalHeaderLabels(["Artifact", "Score", "Reason"])
        self._indicators_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._indicators_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._indicators_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._indicators_table.verticalHeader().setVisible(False)
        self._indicators_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._indicators_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._indicators_table.setAlternatingRowColors(True)
        self._indicators_table.setStyleSheet(
            """
            QTableWidget {
                background-color: #1A1A2E;
                color: #DDDDDD;
                border: 1px solid #333333;
                border-radius: 6px;
                gridline-color: #2A2A3E;
                font-size: 12px;
            }
            QTableWidget::item {
                padding: 6px;
            }
            QTableWidget::item:selected {
                background-color: #2A2A4E;
            }
            QTableWidget::item:alternate {
                background-color: #1E1E32;
            }
            QHeaderView::section {
                background-color: #14141E;
                color: #AAAAAA;
                border: none;
                border-bottom: 1px solid #333333;
                padding: 6px;
                font-weight: bold;
                font-size: 11px;
            }
            """
        )
        self._indicators_table.cellClicked.connect(self._on_indicator_clicked)
        left_layout.addWidget(self._indicators_table)

        splitter.addWidget(left_container)

        # -- Recommended Actions list --
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)

        actions_header = QLabel("Recommended Actions")
        actions_header.setStyleSheet("color: #CCCCCC; font-size: 13px; font-weight: bold;")
        right_layout.addWidget(actions_header)

        self._actions_list = QListWidget()
        self._actions_list.setStyleSheet(
            """
            QListWidget {
                background-color: #1A1A2E;
                color: #DDDDDD;
                border: 1px solid #333333;
                border-radius: 6px;
                font-size: 12px;
                padding: 4px;
            }
            QListWidget::item {
                padding: 8px 6px;
                border-bottom: 1px solid #2A2A3E;
            }
            QListWidget::item:selected {
                background-color: #2A2A4E;
            }
            """
        )
        right_layout.addWidget(self._actions_list)

        splitter.addWidget(right_container)
        splitter.setSizes([500, 300])

        main_layout.addWidget(splitter, stretch=1)

    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #
    def update_metrics(self, scan_results: List[Dict]) -> None:
        """Populate all dashboard widgets from risk-scoring results.

        Each dict in *scan_results* is expected to have:
            - name (str): artifact / file name
            - score (int): risk score 0-100
            - severity (str): one of Critical, High, Medium, Low, Info
            - reasons (List[str]): human-readable explanations
            - mitre_stages (List[str]): matched MITRE ATT&CK stage names
        """
        total = len(scan_results)
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        stage_counts: Dict[str, int] = {s: 0 for s in MITRE_STAGES}

        for item in scan_results:
            severity = item.get("severity", "Info")
            if severity in counts:
                counts[severity] += 1

            for stage in item.get("mitre_stages", []):
                if stage in stage_counts:
                    stage_counts[stage] += 1

        # -- Metric cards --
        self._card_total.set_value(str(total))
        self._card_critical.set_value(str(counts["Critical"]))
        self._card_high.set_value(str(counts["High"]))
        self._card_medium.set_value(str(counts["Medium"]))
        self._card_low.set_value(str(counts["Low"]))

        # -- MITRE ATT&CK stages --
        self._attack_widget.set_counts(stage_counts)

        # -- Top 5 indicators (by score descending) --
        sorted_results = sorted(scan_results, key=lambda r: r.get("score", 0), reverse=True)
        top5 = sorted_results[:5]

        self._indicators_table.setRowCount(len(top5))
        for row, item in enumerate(top5):
            name_item = QTableWidgetItem(item.get("name", ""))
            score = item.get("score", 0)
            score_item = QTableWidgetItem(str(score))
            score_item.setTextAlignment(Qt.AlignCenter)

            # Colour the score cell by severity
            severity_color = self._severity_color(item.get("severity", "Info"))
            score_item.setForeground(QColor(severity_color))

            reasons = item.get("reasons", [])
            reason_text = reasons[0] if reasons else ""
            reason_item = QTableWidgetItem(reason_text)

            self._indicators_table.setItem(row, 0, name_item)
            self._indicators_table.setItem(row, 1, score_item)
            self._indicators_table.setItem(row, 2, reason_item)

        # -- Recommended actions --
        self._actions_list.clear()
        actions = self._generate_recommendations(scan_results, counts, stage_counts)
        for action in actions:
            item = QListWidgetItem(action)
            self._actions_list.addItem(item)

    def clear(self) -> None:
        """Reset all widgets to their default empty state."""
        self._card_total.set_value("0")
        self._card_critical.set_value("0")
        self._card_high.set_value("0")
        self._card_medium.set_value("0")
        self._card_low.set_value("0")
        self._attack_widget.clear()
        self._indicators_table.setRowCount(0)
        self._actions_list.clear()

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                   #
    # ------------------------------------------------------------------ #
    def _on_indicator_clicked(self, row: int, _column: int) -> None:
        name_item = self._indicators_table.item(row, 0)
        if name_item:
            self.artifact_selected.emit(name_item.text())

    @staticmethod
    def _severity_color(severity: str) -> str:
        return {
            "Critical": COLOR_CRITICAL,
            "High": COLOR_HIGH,
            "Medium": COLOR_MEDIUM,
            "Low": COLOR_LOW,
            "Info": COLOR_INFO,
        }.get(severity, COLOR_INFO)

    @staticmethod
    def _generate_recommendations(
        scan_results: List[Dict],
        severity_counts: Dict[str, int],
        stage_counts: Dict[str, int],
    ) -> List[str]:
        """Produce a list of automated investigative recommendations."""
        actions: List[str] = []

        if severity_counts.get("Critical", 0) > 0:
            actions.append(
                "[URGENT] Isolate and preserve evidence for critical-severity artifacts immediately."
            )

        if severity_counts.get("High", 0) > 0:
            actions.append(
                "Review high-severity artifacts for signs of active compromise."
            )

        if stage_counts.get("Persistence", 0) > 0:
            actions.append(
                "Investigate persistence mechanisms - check startup entries, scheduled tasks, and services."
            )

        if stage_counts.get("Credential Access", 0) > 0:
            actions.append(
                "Check for credential theft indicators - review SAM/NTDS dumps and browser credential stores."
            )

        if stage_counts.get("Exfiltration", 0) > 0:
            actions.append(
                "Examine network artifacts for data exfiltration - check DNS logs, HTTP uploads, and cloud sync activity."
            )

        if stage_counts.get("Lateral Movement", 0) > 0:
            actions.append(
                "Trace lateral movement paths - review RDP, PsExec, WMI, and SMB connections."
            )

        if stage_counts.get("Defense Evasion", 0) > 0:
            actions.append(
                "Inspect defense evasion techniques - look for log tampering, timestomping, and AV disabling."
            )

        if stage_counts.get("Execution", 0) > 0:
            actions.append(
                "Analyze execution artifacts - review prefetch, shimcache, amcache, and PowerShell logs."
            )

        if stage_counts.get("Impact", 0) > 0:
            actions.append(
                "Assess impact scope - check for ransomware indicators, data destruction, or service disruption."
            )

        # Fallback when no specific triggers fired
        if not actions:
            if len(scan_results) == 0:
                actions.append("Load a disk image and run a risk scan to populate this dashboard.")
            else:
                actions.append("No high-priority recommendations at this time. Continue routine analysis.")

        # Generic trailing advice
        actions.append("Generate a forensic report to document findings and maintain chain-of-custody.")

        return actions
