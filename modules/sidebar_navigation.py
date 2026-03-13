"""
ForensAI - Sidebar Navigation
===============================
Collapsible sidebar with workflow-stage sections and keyboard shortcuts.
Provides SOC-optimized dark navigation: Ingest -> Analyze -> Correlate -> Tools

Features:
    - Collapses from 200px (full) to 60px (icon-only) with smooth animation
    - Section headers that collapse/expand their child button groups
    - Active state highlighting with accent border
    - Keyboard shortcuts for rapid navigation
    - Self-contained dark styling independent of application theme
"""

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QFrame,
    QSizePolicy,
    QSpacerItem,
    QScrollArea,
)
from PySide6.QtCore import (
    Qt,
    Signal,
    Property,
    QPropertyAnimation,
    QEasingCurve,
    QSize,
)
from PySide6.QtGui import QIcon, QKeySequence, QShortcut


_BG = "#1A1A2E"
_SECTION_BG = "#16213E"
_ACTIVE_BG = "#0F3460"
_ACCENT = "#E94560"
_TEXT = "#C8C8D0"
_TEXT_DIM = "#8888A0"
_HOVER_BG = "#1E2A4A"
_BORDER = "#2A2A4E"

EXPANDED_WIDTH = 200
COLLAPSED_WIDTH = 60


class SidebarButton(QPushButton):
    """Sidebar navigation button with icon, text, and icon-only mode support.

    Parameters
    ----------
    text : str
        The visible label (also used as the logical section name).
    icon : QIcon or None
        Optional icon displayed to the left of the label.
    shortcut_key : str or None
        Human-readable shortcut string shown in the tooltip (e.g. ``"Ctrl+1"``).
    parent : QWidget or None
        Parent widget.
    """

    def __init__(
        self,
        text: str,
        icon: QIcon | None = None,
        shortcut_key: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._label_text = text
        self._icon_only = False
        self._active = False

        if icon is not None and not icon.isNull():
            self.setIcon(icon)
            self.setIconSize(QSize(20, 20))

        self.setText(text)
        self.setCursor(Qt.PointingHandCursor)
        self.setCheckable(False)
        self.setFixedHeight(36)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._apply_style()

        if shortcut_key:
            self.setToolTip(f"{text}  ({shortcut_key})")
        else:
            self.setToolTip(text)


    def set_icon_only(self, icon_only: bool) -> None:
        """Toggle between icon-only and icon+text display."""
        self._icon_only = icon_only
        self.setText("" if icon_only else self._label_text)
        self._apply_style()

    def set_active(self, active: bool) -> None:
        """Highlight or un-highlight this button as the active section."""
        self._active = active
        self._apply_style()

    @property
    def section_name(self) -> str:
        """Return the logical name associated with this button."""
        return self._label_text


    def _apply_style(self) -> None:
        bg = _ACTIVE_BG if self._active else "transparent"
        left_border = f"3px solid {_ACCENT}" if self._active else "3px solid transparent"
        text_align = "center" if self._icon_only else "left"
        padding = "0px 6px" if self._icon_only else "0px 10px 0px 8px"

        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg};
                color: {_TEXT};
                border: none;
                border-left: {left_border};
                border-radius: 0px;
                text-align: {text_align};
                padding: {padding};
                font-size: 13px;
                font-family: "Segoe UI", "Inter", sans-serif;
            }}
            QPushButton:hover {{
                background-color: {_HOVER_BG};
            }}
            QPushButton:pressed {{
                background-color: {_ACTIVE_BG};
            }}
        """)


class SidebarSectionHeader(QWidget):
    """Clickable section header that can collapse/expand its child group.

    Signals
    -------
    toggled(bool)
        Emitted when the user clicks the header. ``True`` means the section
        is now expanded; ``False`` means collapsed.
    """

    toggled = Signal(bool)

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._title = title
        self._expanded = True
        self._icon_only = False

        self.setFixedHeight(28)
        self.setCursor(Qt.PointingHandCursor)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 8, 0)
        layout.setSpacing(4)

        self._arrow_label = QLabel("\u25BE")
        self._arrow_label.setFixedWidth(14)
        self._arrow_label.setAlignment(Qt.AlignCenter)
        self._arrow_label.setStyleSheet(
            f"color: {_TEXT_DIM}; font-size: 10px; background: transparent;"
        )

        self._text_label = QLabel(title)
        self._text_label.setStyleSheet(
            f"color: {_TEXT_DIM}; font-size: 11px; font-weight: 600; "
            f"letter-spacing: 1px; background: transparent; "
            f'font-family: "Segoe UI", "Inter", sans-serif;'
        )

        layout.addWidget(self._arrow_label)
        layout.addWidget(self._text_label, 1)

        self.setStyleSheet(f"background-color: {_SECTION_BG}; border: none;")


    @property
    def expanded(self) -> bool:
        """Whether this section is currently expanded."""
        return self._expanded

    def set_icon_only(self, icon_only: bool) -> None:
        """Switch between full header and a thin separator line."""
        self._icon_only = icon_only
        self._text_label.setVisible(not icon_only)
        self._arrow_label.setVisible(not icon_only)
        if icon_only:
            self.setFixedHeight(8)
            self.setStyleSheet(
                f"background-color: {_SECTION_BG}; "
                f"border-top: 1px solid {_BORDER}; border-bottom: none; "
                f"border-left: none; border-right: none;"
            )
        else:
            self.setFixedHeight(28)
            self.setStyleSheet(f"background-color: {_SECTION_BG}; border: none;")


    def mousePressEvent(self, event) -> None:
        if not self._icon_only:
            self._expanded = not self._expanded
            self._arrow_label.setText("\u25BE" if self._expanded else "\u25B8")
            self.toggled.emit(self._expanded)
        super().mousePressEvent(event)


class _SectionGroup:
    """Tracks a header and its child buttons so they collapse together."""

    def __init__(self, header: SidebarSectionHeader) -> None:
        self.header = header
        self.buttons: list[SidebarButton] = []
        header.toggled.connect(self._on_toggle)

    def _on_toggle(self, expanded: bool) -> None:
        for btn in self.buttons:
            btn.setVisible(expanded)


class SidebarNavigation(QWidget):
    """Main collapsible sidebar navigation widget.

    The sidebar displays workflow-stage sections (INGEST, ANALYZE, CORRELATE,
    TOOLS) each containing navigation buttons with optional keyboard shortcuts.
    It collapses from 200 px to a 60 px icon-only rail via smooth animation.

    Signals
    -------
    navigation_clicked(str)
        Emitted with the button label when a navigation item is activated
        (e.g. ``"File Listing"``).
    """

    navigation_clicked = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._expanded = True
        self._current_width = EXPANDED_WIDTH
        self._active_button: SidebarButton | None = None
        self._buttons: dict[str, SidebarButton] = {}
        self._sections: list[_SectionGroup] = []
        self._anim: QPropertyAnimation | None = None

        self.setObjectName("sidebarNavigation")
        self.setFixedWidth(EXPANDED_WIDTH)
        self.setMinimumHeight(400)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

        self._build_ui()
        self._apply_container_style()


    def _get_sidebar_width(self) -> int:
        return self._current_width

    def _set_sidebar_width(self, w: int) -> None:
        self._current_width = w
        self.setFixedWidth(w)

    sidebarWidth = Property(int, _get_sidebar_width, _set_sidebar_width)


    def _build_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        self._toggle_btn = QPushButton()
        self._toggle_btn.setFixedHeight(44)
        self._toggle_btn.setCursor(Qt.PointingHandCursor)
        self._toggle_btn.clicked.connect(self.toggle_collapsed)
        self._update_toggle_button()
        root_layout.addWidget(self._toggle_btn)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(
            f"color: {_BORDER}; background: {_BORDER}; max-height: 1px;"
        )
        root_layout.addWidget(sep)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setStyleSheet(
            f"QScrollArea {{ background: {_BG}; border: none; }}"
            f"QScrollBar:vertical {{ background: {_BG}; width: 6px; border: none; }}"
            f"QScrollBar::handle:vertical {{ background: {_BORDER}; min-height: 30px; "
            f"border-radius: 3px; }}"
            f"QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}"
        )

        container = QWidget()
        self._nav_layout = QVBoxLayout(container)
        self._nav_layout.setContentsMargins(0, 6, 0, 6)
        self._nav_layout.setSpacing(0)

        self._add_section(
            "INGEST",
            [
                ("Add Evidence", None, "Ctrl+1"),
                ("Remove Evidence", None, "Ctrl+2"),
                ("Mount Image", None, "Ctrl+3"),
            ],
        )

        self._add_section(
            "ANALYZE",
            [
                ("File Listing", None, "Ctrl+4"),
                ("File Search", None, "Ctrl+5"),
                ("Registry", None, "Ctrl+6"),
                ("Priority Scan", None, "Ctrl+7"),
            ],
        )

        self._add_section(
            "CORRELATE",
            [
                ("Mind Map", None, "Ctrl+8"),
                ("Case Audit", None, "Ctrl+9"),
            ],
        )

        self._add_section(
            "TOOLS",
            [
                ("Disk Imaging", None, "Ctrl+0"),
                ("Convert E01", None, None),
                ("Report Generator", None, None),
                ("Veriphone API", None, None),
            ],
        )

        self._nav_layout.addSpacerItem(
            QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding)
        )

        scroll.setWidget(container)
        root_layout.addWidget(scroll, 1)

    def _add_section(
        self,
        title: str,
        items: list[tuple[str, QIcon | None, str | None]],
    ) -> None:
        """Create a collapsible section with a header and child buttons."""
        header = SidebarSectionHeader(title)
        self._nav_layout.addWidget(header)

        group = _SectionGroup(header)

        for label, icon, shortcut_key in items:
            btn = SidebarButton(
                text=label,
                icon=icon if icon is not None else QIcon(),
                shortcut_key=shortcut_key,
            )
            btn.clicked.connect(
                lambda _checked=False, name=label: self._on_button_clicked(name)
            )
            self._nav_layout.addWidget(btn)
            self._buttons[label] = btn
            group.buttons.append(btn)

            if shortcut_key:
                shortcut = QShortcut(QKeySequence(shortcut_key), self)
                shortcut.activated.connect(
                    lambda name=label: self._on_button_clicked(name)
                )

        self._sections.append(group)


    def _apply_container_style(self) -> None:
        """Apply the self-contained dark style to the sidebar container."""
        self.setStyleSheet(
            f"SidebarNavigation {{ background-color: {_BG}; "
            f"border-right: 1px solid {_BORDER}; }}"
        )

    def _update_toggle_button(self) -> None:
        """Refresh the toggle button label and style after collapse state changes."""
        arrow = "\u276E" if self._expanded else "\u276F"
        text = f"  {arrow}  ForensAI" if self._expanded else arrow
        align = "left" if self._expanded else "center"
        self._toggle_btn.setText(text)
        self._toggle_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {_SECTION_BG};
                color: {_ACCENT};
                border: none;
                font-size: 14px;
                font-weight: 700;
                text-align: {align};
                padding: 0px 10px;
                font-family: "Segoe UI", "Inter", sans-serif;
            }}
            QPushButton:hover {{
                background-color: {_HOVER_BG};
            }}
        """)


    def toggle_collapsed(self) -> None:
        """Animate the sidebar between expanded (200 px) and collapsed (60 px)."""
        target = COLLAPSED_WIDTH if self._expanded else EXPANDED_WIDTH
        self._expanded = not self._expanded

        anim = QPropertyAnimation(self, b"sidebarWidth")
        anim.setDuration(200)
        anim.setStartValue(self._current_width)
        anim.setEndValue(target)
        anim.setEasingCurve(QEasingCurve.InOutCubic)
        anim.finished.connect(self._on_animation_finished)
        self._anim = anim
        anim.start()

    def _on_animation_finished(self) -> None:
        """Update child widgets after the collapse/expand animation completes."""
        icon_only = not self._expanded
        for btn in self._buttons.values():
            btn.set_icon_only(icon_only)
        for section in self._sections:
            section.header.set_icon_only(icon_only)
        self._update_toggle_button()


    def _on_button_clicked(self, section_name: str) -> None:
        """Handle a navigation button click or shortcut activation."""
        self.set_active(section_name)
        self.navigation_clicked.emit(section_name)

    def set_active(self, section_name: str) -> None:
        """Highlight *section_name* and deactivate the previous selection.

        Parameters
        ----------
        section_name : str
            The label of the button to activate (e.g. ``"File Listing"``).
        """
        if self._active_button is not None:
            self._active_button.set_active(False)

        btn = self._buttons.get(section_name)
        if btn is not None:
            btn.set_active(True)
            self._active_button = btn


    @property
    def is_expanded(self) -> bool:
        """Return ``True`` when the sidebar is in expanded (full-width) mode."""
        return self._expanded

    @property
    def is_collapsed(self) -> bool:
        """Return ``True`` when the sidebar is in collapsed (icon-only) mode."""
        return not self._expanded

    @property
    def button_names(self) -> list[str]:
        """Return the ordered list of all navigation item labels."""
        return list(self._buttons.keys())
