"""
ForensAI - Acquisition Dialog
Qt dialog for physical disk acquisition with safety features.
"""

import os
import sqlite3
import time
from datetime import datetime
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QPushButton, QProgressBar, QTextEdit, QLineEdit, QGroupBox,
    QFormLayout, QFileDialog, QMessageBox, QCheckBox, QRadioButton,
    QButtonGroup
)
from PySide6.QtCore import QThread, Signal, Qt
from modules.acquire import (
    list_physical_disks_windows,
    list_logical_drives_windows,
    acquire_raw_windows,
    acquire_with_ewfacquire,
    write_metadata_json,
    is_admin,
    AcquisitionError
)


class AcquisitionThread(QThread):
    """Thread for running disk acquisition without blocking UI."""

    progress_update = Signal(int, int, float)
    acquisition_complete = Signal(dict)
    acquisition_error = Signal(str)
    log_message = Signal(str)

    def __init__(self, output_path, hash_types, output_format='raw', metadata=None,
                 drive_number=None, drive_letter=None, source_type='physical'):
        super().__init__()
        self.drive_number = drive_number
        self.drive_letter = drive_letter
        self.source_type = source_type
        self.output_path = output_path
        self.hash_types = hash_types
        self.output_format = output_format
        self.metadata = metadata or {}
        self.abort_requested = False

    def run(self):
        """Execute the acquisition."""
        try:
            if self.source_type == 'physical':
                self.log_message.emit(f"Starting acquisition of PHYSICALDRIVE{self.drive_number}")
            else:
                self.log_message.emit(f"Starting acquisition of Logical Drive {self.drive_letter}")

            self.log_message.emit(f"Output: {self.output_path}")
            self.log_message.emit(f"Format: {self.output_format.upper()}")
            self.log_message.emit(f"Hashes: {', '.join(self.hash_types)}")
            self.log_message.emit("-" * 60)

            if self.output_format == 'raw':
                if self.source_type == 'physical':
                    result = acquire_raw_windows(
                        drive_number=self.drive_number,
                        output_path=self.output_path,
                        progress_callback=self._progress_callback,
                        abort_check=self._abort_check,
                        compute_hashes=self.hash_types,
                        buffer_size=4 * 1024 * 1024,
                        metadata=self.metadata
                    )
                else:
                    result = acquire_raw_windows(
                        drive_letter=self.drive_letter,
                        output_path=self.output_path,
                        progress_callback=self._progress_callback,
                        abort_check=self._abort_check,
                        compute_hashes=self.hash_types,
                        buffer_size=4 * 1024 * 1024,
                        metadata=self.metadata
                    )
            elif self.output_format == 'e01':
                if self.source_type == 'logical':
                    raise AcquisitionError("E01 format not yet supported for logical drives")
                result = acquire_with_ewfacquire(
                    drive_number=self.drive_number,
                    output_path=self.output_path,
                    progress_callback=self._progress_callback,
                    abort_check=self._abort_check,
                    metadata=self.metadata
                )
            else:
                raise AcquisitionError(f"Unknown output format: {self.output_format}")

            result.update(self.metadata)

            metadata_path = write_metadata_json(self.output_path, result)
            self.log_message.emit(f"\nMetadata written to: {metadata_path}")

            self._write_to_database(result)

            self.acquisition_complete.emit(result)

        except Exception as e:
            self.log_message.emit(f"\nERROR: {str(e)}")
            self.acquisition_error.emit(str(e))

    def _progress_callback(self, bytes_read, total_bytes, speed_mbps):
        """Callback for progress updates."""
        self.progress_update.emit(bytes_read, total_bytes, speed_mbps)

    def _abort_check(self):
        """Check if abort was requested."""
        return self.abort_requested

    def request_abort(self):
        """Request abortion of acquisition."""
        self.abort_requested = True
        self.log_message.emit("\nABORT REQUESTED - Stopping acquisition...")

    def _write_to_database(self, result):
        """Write acquisition record to database."""
        try:
            db_path = 'tools/new_database_mappings.db'
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    source_type TEXT,
                    output_path TEXT NOT NULL,
                    size_bytes INTEGER,
                    md5 TEXT,
                    sha1 TEXT,
                    sha256 TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    duration_seconds REAL,
                    tool_version TEXT,
                    operator TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            if self.source_type == 'physical':
                source_str = f"PHYSICALDRIVE{self.drive_number}"
            else:
                source_str = f"LogicalDrive:{self.drive_letter}"

            hashes = result.get('hashes', {})
            cursor.execute('''
                INSERT INTO evidence (
                    source, source_type, output_path, size_bytes,
                    md5, sha1, sha256,
                    started_at, finished_at, duration_seconds,
                    tool_version, operator, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                source_str,
                self.source_type,
                result.get('output_path', ''),
                result.get('size_bytes', 0),
                hashes.get('md5', ''),
                hashes.get('sha1', ''),
                hashes.get('sha256', ''),
                result.get('started_at', ''),
                result.get('finished_at', ''),
                result.get('duration_seconds', 0),
                'ForensAI 1.0.0',
                self.metadata.get('operator', ''),
                self.metadata.get('notes', '')
            ))

            conn.commit()
            conn.close()

            self.log_message.emit("Database record created successfully")

        except Exception as e:
            self.log_message.emit(f"Warning: Failed to write to database: {str(e)}")


class AcquireDialog(QDialog):
    """Dialog for physical and logical disk acquisition (like FTK Imager)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create Disk Image")

        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMaximizeButtonHint |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint
        )

        self.setMinimumSize(850, 800)
        self.resize(900, 850)
        self.setModal(True)

        self.setSizeGripEnabled(True)

        self.physical_disks = []
        self.logical_drives = []
        self.acquisition_thread = None
        self.total_bytes_size = 0
        self.last_bytes_read = 0
        self.last_progress_time = 0
        self.acquisition_finished = False
        self.current_source_type = 'physical'

        self.init_ui()
        self.check_prerequisites()
        self.load_sources()

    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        groupbox_style = """
            QGroupBox {
                font-weight: bold;
                font-size: 13px;
                border: 2px solid #bdc3c7;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 5px;
                color: #2c3e50;
            }
        """

        source_group = QGroupBox("Select Evidence Source")
        source_group.setStyleSheet(groupbox_style)
        source_layout = QVBoxLayout()
        source_layout.setSpacing(10)

        source_type_layout = QHBoxLayout()
        source_type_layout.setSpacing(20)
        self.source_type_group = QButtonGroup()

        self.source_physical = QRadioButton("Physical Drive")
        self.source_physical.setChecked(True)
        self.source_physical.setStyleSheet("font-weight: bold; font-size: 12px;")
        self.source_physical.toggled.connect(self.on_source_type_changed)
        self.source_type_group.addButton(self.source_physical)
        source_type_layout.addWidget(self.source_physical)

        self.source_logical = QRadioButton("Logical Drive (Volume/Partition)")
        self.source_logical.setStyleSheet("font-weight: bold; font-size: 12px;")
        self.source_type_group.addButton(self.source_logical)
        source_type_layout.addWidget(self.source_logical)

        source_type_layout.addStretch()
        source_layout.addLayout(source_type_layout)

        combo_style = """
            QComboBox {
                padding: 8px;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                font-size: 12px;
            }
            QComboBox:focus {
                border: 2px solid #3498db;
            }
        """

        self.physical_label = QLabel("Physical Drive:")
        self.physical_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        source_layout.addWidget(self.physical_label)

        self.disk_combo = QComboBox()
        self.disk_combo.setMinimumHeight(35)
        self.disk_combo.setStyleSheet(combo_style)
        self.disk_combo.currentIndexChanged.connect(self.on_disk_selected)
        source_layout.addWidget(self.disk_combo)

        self.logical_label = QLabel("Logical Drive (Volume):")
        self.logical_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        self.logical_label.setVisible(False)
        source_layout.addWidget(self.logical_label)

        self.logical_combo = QComboBox()
        self.logical_combo.setMinimumHeight(35)
        self.logical_combo.setStyleSheet(combo_style)
        self.logical_combo.currentIndexChanged.connect(self.on_logical_selected)
        self.logical_combo.setVisible(False)
        source_layout.addWidget(self.logical_combo)

        self.disk_info_label = QLabel("No source selected")
        self.disk_info_label.setWordWrap(True)
        self.disk_info_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.disk_info_label.setCursor(Qt.IBeamCursor)
        self.disk_info_label.setStyleSheet("""
            padding: 10px;
            background-color: #ecf0f1;
            border-radius: 4px;
            border-left: 4px solid #3498db;
            font-size: 11px;
        """)
        source_layout.addWidget(self.disk_info_label)

        source_group.setLayout(source_layout)
        layout.addWidget(source_group)

        output_group = QGroupBox("Output Settings")
        output_group.setStyleSheet(groupbox_style)
        output_layout = QFormLayout()
        output_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        output_layout.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        output_layout.setVerticalSpacing(12)
        output_layout.setHorizontalSpacing(15)

        input_style = """
            QLineEdit {
                padding: 8px;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                font-size: 12px;
                min-height: 25px;
            }
            QLineEdit:focus {
                border: 2px solid #3498db;
            }
            QLineEdit:read-only {
                background-color: #ecf0f1;
            }
        """

        browse_button_style = """
            QPushButton {
                background-color: #ecf0f1;
                color: #2c3e50;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                padding: 8px 15px;
                font-size: 12px;
                min-width: 90px;
                min-height: 25px;
            }
            QPushButton:hover {
                background-color: #d5dbdb;
                border: 1px solid #95a5a6;
            }
            QPushButton:pressed {
                background-color: #bdc3c7;
            }
        """

        output_dir_layout = QHBoxLayout()
        output_dir_layout.setSpacing(8)
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setReadOnly(True)
        self.output_dir_edit.setStyleSheet(input_style)
        self.output_dir_button = QPushButton("Browse...")
        self.output_dir_button.setStyleSheet(browse_button_style)
        self.output_dir_button.clicked.connect(self.select_output_directory)
        output_dir_layout.addWidget(self.output_dir_edit)
        output_dir_layout.addWidget(self.output_dir_button)
        output_layout.addRow("Output Directory:", output_dir_layout)

        format_layout = QHBoxLayout()
        format_layout.setSpacing(20)
        self.format_button_group = QButtonGroup()
        self.format_raw = QRadioButton("Raw (.dd)")
        self.format_e01 = QRadioButton("E01 (requires ewfacquire)")
        self.format_raw.setChecked(True)
        self.format_button_group.addButton(self.format_raw)
        self.format_button_group.addButton(self.format_e01)
        format_layout.addWidget(self.format_raw)
        format_layout.addWidget(self.format_e01)
        format_layout.addStretch()
        output_layout.addRow("Format:", format_layout)

        hash_layout = QHBoxLayout()
        hash_layout.setSpacing(20)
        self.hash_md5 = QCheckBox("MD5")
        self.hash_sha1 = QCheckBox("SHA1")
        self.hash_sha256 = QCheckBox("SHA256")
        self.hash_md5.setChecked(True)
        self.hash_sha1.setChecked(True)
        hash_layout.addWidget(self.hash_md5)
        hash_layout.addWidget(self.hash_sha1)
        hash_layout.addWidget(self.hash_sha256)
        hash_layout.addStretch()
        output_layout.addRow("Compute Hashes:", hash_layout)

        self.operator_edit = QLineEdit()
        self.operator_edit.setPlaceholderText("Enter your name")
        self.operator_edit.setStyleSheet(input_style)
        output_layout.addRow("Operator:", self.operator_edit)

        self.notes_edit = QLineEdit()
        self.notes_edit.setPlaceholderText("Optional case notes")
        self.notes_edit.setStyleSheet(input_style)
        output_layout.addRow("Notes:", self.notes_edit)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        confirm_group = QGroupBox("Confirmation Required")
        confirm_group.setStyleSheet(groupbox_style)
        confirm_layout = QVBoxLayout()
        confirm_layout.setSpacing(10)

        confirm_label = QLabel(
            "<b>⚠️ WARNING:</b> To start acquisition, you must type the exact confirmation "
            "string below. This ensures you understand which disk will be imaged."
        )
        confirm_label.setWordWrap(True)
        confirm_label.setStyleSheet("padding: 8px; font-size: 11px;")
        confirm_layout.addWidget(confirm_label)

        self.confirmation_label = QLabel("Waiting for disk selection...")
        self.confirmation_label.setWordWrap(True)
        self.confirmation_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.confirmation_label.setCursor(Qt.IBeamCursor)
        self.confirmation_label.setStyleSheet("""
            color: #c0392b;
            font-weight: bold;
            font-size: 13px;
            padding: 8px;
            background-color: #fadbd8;
            border-radius: 4px;
            border-left: 4px solid #c0392b;
        """)
        confirm_layout.addWidget(self.confirmation_label)

        self.confirmation_edit = QLineEdit()
        self.confirmation_edit.setPlaceholderText("Type confirmation string here")
        self.confirmation_edit.setStyleSheet(input_style)
        self.confirmation_edit.setMinimumHeight(35)
        self.confirmation_edit.textChanged.connect(self.check_can_start)
        confirm_layout.addWidget(self.confirmation_edit)

        confirm_group.setLayout(confirm_layout)
        layout.addWidget(confirm_group)

        progress_group = QGroupBox("Acquisition Progress")
        progress_group.setStyleSheet(groupbox_style)
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(10)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p%")
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                text-align: center;
                height: 30px;
                font-size: 12px;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3498db, stop:1 #2980b9
                );
                border-radius: 3px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)

        self.progress_label = QLabel("Ready to start")
        self.progress_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.progress_label.setCursor(Qt.IBeamCursor)
        self.progress_label.setStyleSheet("""
            padding: 8px;
            background-color: #ecf0f1;
            border-radius: 4px;
            font-size: 11px;
        """)
        progress_layout.addWidget(self.progress_label)

        log_label = QLabel("Log:")
        log_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        progress_layout.addWidget(log_label)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMinimumHeight(120)
        self.log_text.setMaximumHeight(300)
        self.log_text.setStyleSheet("""
            QTextEdit {
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                padding: 8px;
                background-color: #f8f9fa;
                font-family: 'Courier New', monospace;
                font-size: 10px;
            }
        """)
        progress_layout.addWidget(self.log_text)

        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        button_layout.setContentsMargins(0, 10, 0, 0)

        self.start_button = QPushButton("Start Acquisition")
        self.start_button.setMinimumHeight(40)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                font-size: 13px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
                color: #ecf0f1;
            }
        """)
        self.start_button.clicked.connect(self.start_acquisition)
        self.start_button.setEnabled(False)
        button_layout.addWidget(self.start_button)

        self.abort_button = QPushButton("Abort")
        self.abort_button.setMinimumHeight(40)
        self.abort_button.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                font-size: 13px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
                color: #ecf0f1;
            }
        """)
        self.abort_button.clicked.connect(self.abort_acquisition)
        self.abort_button.setEnabled(False)
        button_layout.addWidget(self.abort_button)

        button_layout.addStretch()

        self.close_button = QPushButton("Close")
        self.close_button.setMinimumHeight(40)
        self.close_button.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                font-size: 13px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        self.close_button.clicked.connect(self.close)
        button_layout.addWidget(self.close_button)

        layout.addLayout(button_layout)

    def check_prerequisites(self):
        """Check if prerequisites are met."""
        if not is_admin():
            QMessageBox.critical(
                self,
                "Administrator Required",
                "Administrator privileges are required to acquire physical disks.\n\n"
                "Please restart ForensAI as Administrator."
            )
            self.disk_combo.setEnabled(False)
            self.start_button.setEnabled(False)
            return False

        return True

    def load_sources(self):
        """Load available physical disks and logical drives."""
        try:
            self.physical_disks = list_physical_disks_windows()

            if self.physical_disks:
                for disk in self.physical_disks:
                    label = (
                        f"PHYSICALDRIVE{disk['number']} - "
                        f"{disk['model']} ({disk['size_gb']} GB)"
                    )
                    self.disk_combo.addItem(label, disk)
                self.log(f"Found {len(self.physical_disks)} physical disk(s)")
            else:
                self.log("No physical disks found")

        except AcquisitionError as e:
            self.log(f"Error loading physical disks: {str(e)}")

        try:
            self.logical_drives = list_logical_drives_windows()

            if self.logical_drives:
                for drive in self.logical_drives:
                    if drive['size'] == 0:
                        continue
                    label = (
                        f"{drive['drive_letter']} [{drive['label']}] - "
                        f"{drive['file_system']} ({drive['size_gb']} GB) - {drive['drive_type']}"
                    )
                    self.logical_combo.addItem(label, drive)
                self.log(f"Found {len(self.logical_drives)} logical drive(s)")
            else:
                self.log("No logical drives found")

        except AcquisitionError as e:
            self.log(f"Error loading logical drives: {str(e)}")

    def on_source_type_changed(self, checked):
        """Handle source type radio button change."""
        if self.source_physical.isChecked():
            self.current_source_type = 'physical'
            self.physical_label.setVisible(True)
            self.disk_combo.setVisible(True)
            self.logical_label.setVisible(False)
            self.logical_combo.setVisible(False)
            self.on_disk_selected(self.disk_combo.currentIndex())
        else:
            self.current_source_type = 'logical'
            self.physical_label.setVisible(False)
            self.disk_combo.setVisible(False)
            self.logical_label.setVisible(True)
            self.logical_combo.setVisible(True)
            self.on_logical_selected(self.logical_combo.currentIndex())

        self.check_can_start()

    def on_logical_selected(self, index):
        """Handle logical drive selection."""
        if index < 0:
            return

        drive = self.logical_combo.itemData(index)
        if not drive:
            return

        info_text = (
            f"<b>Drive Letter:</b> {drive['drive_letter']}<br>"
            f"<b>Label:</b> {drive['label']}<br>"
            f"<b>File System:</b> {drive['file_system']}<br>"
            f"<b>Size:</b> {drive['size_gb']} GB ({drive['size']:,} bytes)<br>"
            f"<b>Free Space:</b> {drive['free_space_gb']} GB<br>"
            f"<b>Type:</b> {drive['drive_type']}<br>"
            f"<b>Device Path:</b> {drive['device_path']}"
        )
        self.disk_info_label.setText(info_text)

        letter = drive['drive_letter'].replace(':', '')
        confirm_string = f"CONFIRM DRIVE {letter}"
        self.confirmation_label.setText(f"Type exactly: {confirm_string}")
        self.confirmation_edit.clear()
        self.check_can_start()

    def on_disk_selected(self, index):
        """Handle disk selection."""
        if index < 0:
            return

        disk = self.disk_combo.itemData(index)
        if not disk:
            return

        info_text = (
            f"<b>Device:</b> {disk['device_path']}<br>"
            f"<b>Model:</b> {disk['model']}<br>"
            f"<b>Size:</b> {disk['size_gb']} GB ({disk['size']:,} bytes)<br>"
            f"<b>Serial:</b> {disk['serial']}<br>"
            f"<b>Interface:</b> {disk['interface']}"
        )
        self.disk_info_label.setText(info_text)

        confirm_string = f"CONFIRM PHYSICALDRIVE{disk['number']}"
        self.confirmation_label.setText(f"Type exactly: {confirm_string}")
        self.confirmation_edit.clear()
        self.check_can_start()

    def select_output_directory(self):
        """Select output directory."""
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if directory:
            self.output_dir_edit.setText(directory)
            self.check_can_start()

    def check_can_start(self):
        """Check if all requirements are met to start acquisition."""
        if self.current_source_type == 'physical':
            if not self.physical_disks or self.disk_combo.currentIndex() < 0:
                self.start_button.setEnabled(False)
                return

            disk = self.disk_combo.currentData()
            if not disk:
                self.start_button.setEnabled(False)
                return

            expected_confirm = f"CONFIRM PHYSICALDRIVE{disk['number']}"
        else:
            if not self.logical_drives or self.logical_combo.currentIndex() < 0:
                self.start_button.setEnabled(False)
                return

            drive = self.logical_combo.currentData()
            if not drive:
                self.start_button.setEnabled(False)
                return

            letter = drive['drive_letter'].replace(':', '')
            expected_confirm = f"CONFIRM DRIVE {letter}"

        actual_confirm = self.confirmation_edit.text().strip()

        output_dir = self.output_dir_edit.text().strip()

        can_start = (
            actual_confirm == expected_confirm and
            output_dir != "" and
            os.path.isdir(output_dir)
        )

        self.start_button.setEnabled(can_start)

    def start_acquisition(self):
        """Start the acquisition process."""
        hash_types = []
        if self.hash_md5.isChecked():
            hash_types.append('md5')
        if self.hash_sha1.isChecked():
            hash_types.append('sha1')
        if self.hash_sha256.isChecked():
            hash_types.append('sha256')

        if not hash_types:
            QMessageBox.warning(self, "Warning", "Please select at least one hash type.")
            return

        output_format = 'raw' if self.format_raw.isChecked() else 'e01'

        timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        output_dir = self.output_dir_edit.text().strip()
        ext = '.dd' if output_format == 'raw' else '.E01'

        if self.current_source_type == 'physical':
            disk = self.disk_combo.currentData()
            if not disk:
                return

            output_path = os.path.join(output_dir, f"physical_drive{disk['number']}_{timestamp}{ext}")

            metadata = {
                'operator': self.operator_edit.text().strip(),
                'notes': self.notes_edit.text().strip(),
                'source_type': 'physical',
                'source_device': disk['device_path'],
                'source_model': disk['model'],
                'source_serial': disk['serial'],
                'source_size_bytes': disk['size']
            }

            reply = QMessageBox.question(
                self,
                "Confirm Acquisition",
                f"Ready to acquire PHYSICAL DRIVE:\n\n"
                f"Device: {disk['device_path']}\n"
                f"Model: {disk['model']}\n"
                f"Size: {disk['size_gb']} GB\n"
                f"Output: {output_path}\n"
                f"Format: {output_format.upper()}\n"
                f"Hashes: {', '.join(hash_types)}\n\n"
                f"This operation may take a long time.\n"
                f"Continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply != QMessageBox.Yes:
                return

            self.total_bytes_size = disk['size']

            self.acquisition_thread = AcquisitionThread(
                output_path=output_path,
                hash_types=hash_types,
                output_format=output_format,
                metadata=metadata,
                drive_number=disk['number'],
                source_type='physical'
            )
        else:
            drive = self.logical_combo.currentData()
            if not drive:
                return

            if output_format == 'e01':
                QMessageBox.warning(self, "Warning", "E01 format is not yet supported for logical drives. Please use Raw (.dd) format.")
                return

            letter = drive['drive_letter'].replace(':', '')
            output_path = os.path.join(output_dir, f"logical_drive_{letter}_{timestamp}{ext}")

            metadata = {
                'operator': self.operator_edit.text().strip(),
                'notes': self.notes_edit.text().strip(),
                'source_type': 'logical',
                'source_device': drive['device_path'],
                'source_drive_letter': drive['drive_letter'],
                'source_label': drive['label'],
                'source_file_system': drive['file_system'],
                'source_size_bytes': drive['size'],
                'source_drive_type': drive['drive_type']
            }

            reply = QMessageBox.question(
                self,
                "Confirm Acquisition",
                f"Ready to acquire LOGICAL DRIVE:\n\n"
                f"Drive: {drive['drive_letter']} [{drive['label']}]\n"
                f"File System: {drive['file_system']}\n"
                f"Size: {drive['size_gb']} GB\n"
                f"Type: {drive['drive_type']}\n"
                f"Output: {output_path}\n"
                f"Format: {output_format.upper()}\n"
                f"Hashes: {', '.join(hash_types)}\n\n"
                f"This operation may take a long time.\n"
                f"Continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply != QMessageBox.Yes:
                return

            self.total_bytes_size = drive['size']

            self.acquisition_thread = AcquisitionThread(
                output_path=output_path,
                hash_types=hash_types,
                output_format=output_format,
                metadata=metadata,
                drive_letter=drive['drive_letter'],
                source_type='logical'
            )

        self.last_bytes_read = 0
        self.last_progress_time = time.time()
        self.acquisition_finished = False

        self.disk_combo.setEnabled(False)
        self.logical_combo.setEnabled(False)
        self.source_physical.setEnabled(False)
        self.source_logical.setEnabled(False)
        self.output_dir_button.setEnabled(False)
        self.start_button.setEnabled(False)
        self.abort_button.setEnabled(True)
        self.confirmation_edit.setEnabled(False)

        self.log_text.clear()

        self.acquisition_thread.progress_update.connect(self.on_progress_update)
        self.acquisition_thread.acquisition_complete.connect(self.on_acquisition_complete)
        self.acquisition_thread.acquisition_error.connect(self.on_acquisition_error)
        self.acquisition_thread.log_message.connect(self.log)

        self.acquisition_thread.start()

    def abort_acquisition(self):
        """Abort the current acquisition."""
        if self.acquisition_thread and self.acquisition_thread.isRunning():
            reply = QMessageBox.question(
                self,
                "Abort Acquisition",
                "Are you sure you want to abort the acquisition?\n\n"
                "The partial image file will be deleted.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.acquisition_thread.request_abort()
                self.abort_button.setEnabled(False)

    def on_progress_update(self, bytes_read, total_bytes, speed_mbps):
        """Handle progress updates."""
        current_time = time.time()

        bytes_read = max(bytes_read, self.last_bytes_read)

        if bytes_read == self.last_bytes_read and (current_time - self.last_progress_time) > 3.0:
            if speed_mbps < 0.1 and not self.acquisition_finished:
                self.total_bytes_size = bytes_read
                self.log(f"Device read completed at {bytes_read / (1024*1024):.2f} MB (less than reported size)")

        self.last_bytes_read = bytes_read
        self.last_progress_time = current_time

        effective_total = self.total_bytes_size

        if effective_total <= 0:
            effective_total = total_bytes

        if bytes_read > effective_total and effective_total > 0:
            self.total_bytes_size = bytes_read
            effective_total = bytes_read

        if effective_total > 0:
            progress = min(int((bytes_read / effective_total) * 100), 100)

            current_progress = self.progress_bar.value()
            if progress >= current_progress:
                self.progress_bar.setValue(progress)

            mb_read = bytes_read / (1024 * 1024)
            mb_total = effective_total / (1024 * 1024)

            self.progress_label.setText(
                f"Progress: {progress}% ({mb_read:.2f} MB / {mb_total:.2f} MB) - "
                f"Speed: {speed_mbps:.2f} MB/s"
            )
        else:
            mb_read = bytes_read / (1024 * 1024)
            self.progress_label.setText(
                f"Reading: {mb_read:.2f} MB - Speed: {speed_mbps:.2f} MB/s"
            )

    def on_acquisition_complete(self, result):
        """Handle acquisition completion."""
        self.acquisition_finished = True

        bytes_written = result.get('bytes_written', 0)
        mb_written = bytes_written / (1024 * 1024)
        speed = result.get('speed_mbps', 0)

        self.progress_bar.setValue(100)
        self.progress_label.setText(
            f"Progress: 100% ({mb_written:.2f} MB / {mb_written:.2f} MB) - "
            f"Speed: {speed:.2f} MB/s - COMPLETE"
        )

        self.abort_button.setEnabled(False)

        hashes = result.get('hashes', {})
        hash_text = '\n'.join([f"{k.upper()}: {v}" for k, v in hashes.items()])

        QMessageBox.information(
            self,
            "Acquisition Complete",
            f"Acquisition completed successfully!\n\n"
            f"Output: {result['output_path']}\n"
            f"Size: {result['size_bytes']:,} bytes\n"
            f"Duration: {result['duration_seconds']:.2f} seconds\n"
            f"Speed: {result['speed_mbps']:.2f} MB/s\n\n"
            f"Hashes:\n{hash_text}\n\n"
            f"Metadata has been saved to:\n{result['output_path']}.metadata.json"
        )

        self.log("\n=== ACQUISITION COMPLETE ===")

    def on_acquisition_error(self, error_msg):
        """Handle acquisition error."""
        self.abort_button.setEnabled(False)
        QMessageBox.critical(self, "Acquisition Error", f"Acquisition failed:\n\n{error_msg}")

    def log(self, message):
        """Add message to log."""
        self.log_text.append(message)
        self.log_text.verticalScrollBar().setValue(
            self.log_text.verticalScrollBar().maximum()
        )
