"""
ForensAI - Forensic Report Generator GUI Dialog
================================================
PySide6 GUI dialog for generating comprehensive forensic evidence reports.

Integrates with the main ForensAI application to provide a user-friendly
interface for creating court-admissible forensic reports.
"""

import os
import sys
from pathlib import Path
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal, QSize
from PySide6.QtGui import QIcon, QFont
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QFileDialog, QCheckBox,
    QTextEdit, QProgressBar, QMessageBox, QComboBox,
    QWidget, QScrollArea
)

from modules.forensic_report_generator import ForensicReportGenerator

# Import notes manager
try:
    from managers.notes_manager import get_notes_manager
    NOTES_AVAILABLE = True
except ImportError:
    NOTES_AVAILABLE = False


class ReportGeneratorThread(QThread):
    """Background thread for report generation."""

    progress = Signal(str)  # Progress message
    finished = Signal(dict)  # Result dictionary
    error = Signal(str)  # Error message

    def __init__(self, config):
        """
        Initialize thread.

        Args:
            config: Dictionary with report generation configuration
        """
        super().__init__()
        self.config = config

    def run(self):
        """Run report generation in background thread."""
        try:
            self.progress.emit("Initializing report generator...")

            # Create generator
            generator = ForensicReportGenerator(
                case_id=self.config['case_id'],
                operator=self.config['operator'],
                master_image=self.config['master_image'],
                output_dir=self.config['output_dir'],
                derived_iso=self.config.get('derived_iso'),
                parsed_artifacts_dir=self.config.get('artifacts_dir'),
                bulk_extractor_dir=self.config.get('bulk_extractor_dir'),
                checkpoints_dir=self.config.get('checkpoints_dir'),
                logfile=self.config.get('logfile')
            )

            # Add notes if provided
            if self.config.get('notes'):
                generator.notes = self.config['notes']

            # Add investigator notes if provided
            if self.config.get('investigator_notes'):
                # Append investigator notes to existing notes
                if generator.notes:
                    generator.notes += "\n\n---\n\n## INVESTIGATOR NOTES\n\n" + self.config['investigator_notes']
                else:
                    generator.notes = "## INVESTIGATOR NOTES\n\n" + self.config['investigator_notes']

            # Inject session data if provided
            session_data = self.config.get('session_data')
            if session_data:
                self.progress.emit(f"DEBUG: Session data present: has_data={session_data.get('has_data')}, total_files={session_data.get('total_files', 0)}")

            if session_data and session_data.get('has_data'):
                self.progress.emit("Loading files from ForensAI session...")

                # Import ArtifactInfo class
                from modules.forensic_report_generator import ArtifactInfo
                from datetime import datetime, timezone

                files_to_load = session_data.get('files', [])
                self.progress.emit(f"DEBUG: Found {len(files_to_load)} files in session data")

                # Convert session files to ArtifactInfo objects
                for idx, file_info in enumerate(files_to_load):
                    try:
                        artifact = ArtifactInfo(
                            path=file_info.get('name', 'unknown'),
                            name=file_info.get('name', 'unknown'),
                            size=file_info.get('size_bytes', 0),
                            artifact_type=file_info.get('type', 'unknown').lower()
                        )
                        artifact.inode = file_info.get('inode', '')

                        # Parse timestamps if available
                        try:
                            if file_info.get('created'):
                                # Timestamps from ForensAI might be in various formats
                                artifact.created_utc = datetime.now(timezone.utc)
                        except:
                            pass

                        try:
                            if file_info.get('modified'):
                                artifact.modified_utc = datetime.now(timezone.utc)
                        except:
                            pass

                        # Check if notable
                        generator._check_notable(artifact)

                        generator.artifacts.append(artifact)

                        # Progress update every 100 files
                        if (idx + 1) % 100 == 0:
                            self.progress.emit(f"Loaded {idx + 1} files...")
                    except Exception as e:
                        self.progress.emit(f"DEBUG: Error loading file {idx}: {e}")
                        continue

                # Update statistics
                generator.stats['total_files'] = len(generator.artifacts)
                generator.stats['total_size'] = session_data.get('total_size', 0)
                generator.stats['notable_artifacts'] = sum(1 for a in generator.artifacts if a.notable_reasons)

                self.progress.emit(f"✓ Loaded {len(generator.artifacts):,} files from session")
                self.progress.emit(f"DEBUG: Artifacts list now has {len(generator.artifacts)} items")
            else:
                self.progress.emit("DEBUG: No session data to load (will scan artifacts directory instead)")

            # Inject risk scan results if available
            if session_data and session_data.get('risk_scan_results'):
                self.progress.emit(f"Loading {len(session_data['risk_scan_results'])} risk scan results...")
                generator.set_risk_scan_results(session_data['risk_scan_results'])

            self.progress.emit("Verifying master image...")

            # Generate report
            result = generator.generate_report(
                formats=self.config['formats'],
                include_screenshots=self.config.get('include_screenshots', False)
            )

            self.progress.emit("Report generation complete!")
            self.finished.emit(result)

        except Exception as e:
            self.error.emit(f"Report generation failed: {str(e)}")


class ReportGeneratorDialog(QDialog):
    """Main dialog for forensic report generation."""

    def __init__(self, parent=None, current_image_path=None, session_data=None):
        """
        Initialize report generator dialog.

        Args:
            parent: Parent widget
            current_image_path: Path to currently loaded image (optional)
            session_data: Dictionary with current ForensAI session data (optional)
        """
        super().__init__(parent)

        self.current_image_path = current_image_path
        self.session_data = session_data or {'has_data': False, 'total_files': 0}
        self.generator_thread = None

        self.setWindowTitle("ForensAI - Generate Forensic Report")
        self.setWindowIcon(QIcon('Icons/logo.ico'))
        self.setMinimumWidth(850)
        self.setMinimumHeight(700)
        self.resize(900, 750)

        self.init_ui()

        # Pre-fill with current image if available
        if self.current_image_path:
            self.master_image_edit.setText(self.current_image_path)

        # Trigger checkbox toggle to set initial state
        if hasattr(self, 'use_session_checkbox'):
            self.on_session_checkbox_toggled(self.use_session_checkbox.isChecked())

    def init_ui(self):
        """Initialize user interface."""
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Forensic Evidence Report Generator")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #2c3e50; padding: 10px 0;")
        layout.addWidget(title)

        subtitle = QLabel("Generate comprehensive, court-admissible forensic reports")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #7f8c8d; font-size: 12px; padding-bottom: 10px;")
        layout.addWidget(subtitle)

        # Create scroll area for form
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)

        form_widget = QWidget()
        form_layout = QVBoxLayout(form_widget)
        form_layout.setSpacing(15)
        form_layout.setContentsMargins(10, 10, 10, 10)

        # Add global styling
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

        # Input field styling
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
        """

        # Browse button styling
        browse_button_style = """
            QPushButton {
                background-color: #ecf0f1;
                color: #2c3e50;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                padding: 8px 15px;
                font-size: 12px;
                min-width: 80px;
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

        # === Required Information ===
        required_group = QGroupBox("Required Information")
        required_group.setStyleSheet(groupbox_style)
        required_layout = QFormLayout()
        required_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        required_layout.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        required_layout.setVerticalSpacing(12)
        required_layout.setHorizontalSpacing(15)

        # Case ID
        self.case_id_edit = QLineEdit()
        self.case_id_edit.setStyleSheet(input_style)
        self.case_id_edit.setPlaceholderText("e.g., CASE-2025-001")
        # Auto-generate case ID suggestion
        suggested_id = f"CASE-{datetime.now().strftime('%Y-%m-%d-%H%M%S')}"
        self.case_id_edit.setText(suggested_id)
        required_layout.addRow("Case ID:", self.case_id_edit)

        # Operator Name
        self.operator_edit = QLineEdit()
        self.operator_edit.setStyleSheet(input_style)
        self.operator_edit.setPlaceholderText("e.g., John Doe")
        # Try to get username from environment
        import getpass
        try:
            username = getpass.getuser()
            self.operator_edit.setText(username)
        except:
            pass
        required_layout.addRow("Operator Name:", self.operator_edit)

        # Master Image
        master_layout = QHBoxLayout()
        master_layout.setSpacing(8)
        self.master_image_edit = QLineEdit()
        self.master_image_edit.setStyleSheet(input_style)
        self.master_image_edit.setPlaceholderText("Path to master evidence image (.dd)")
        master_browse_btn = QPushButton("Browse...")
        master_browse_btn.setStyleSheet(browse_button_style)
        master_browse_btn.clicked.connect(self.browse_master_image)
        master_layout.addWidget(self.master_image_edit)
        master_layout.addWidget(master_browse_btn)
        required_layout.addRow("Master Image:", master_layout)

        # Output Directory
        output_layout = QHBoxLayout()
        output_layout.setSpacing(8)
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setStyleSheet(input_style)
        self.output_dir_edit.setPlaceholderText("Directory where reports will be saved")
        output_browse_btn = QPushButton("Browse...")
        output_browse_btn.setStyleSheet(browse_button_style)
        output_browse_btn.clicked.connect(self.browse_output_dir)
        output_layout.addWidget(self.output_dir_edit)
        output_layout.addWidget(output_browse_btn)
        required_layout.addRow("Output Directory:", output_layout)

        required_group.setLayout(required_layout)
        form_layout.addWidget(required_group)

        # === Optional Information ===
        optional_group = QGroupBox("Optional Information (Enhances Report)")
        optional_group.setStyleSheet(groupbox_style)
        optional_layout = QFormLayout()
        optional_layout.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        optional_layout.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        optional_layout.setVerticalSpacing(12)
        optional_layout.setHorizontalSpacing(15)

        # Derived ISO
        derived_layout = QHBoxLayout()
        derived_layout.setSpacing(8)
        self.derived_iso_edit = QLineEdit()
        self.derived_iso_edit.setStyleSheet(input_style)
        self.derived_iso_edit.setPlaceholderText("Path to derived ISO (if created)")
        derived_browse_btn = QPushButton("Browse...")
        derived_browse_btn.setStyleSheet(browse_button_style)
        derived_browse_btn.clicked.connect(self.browse_derived_iso)
        derived_layout.addWidget(self.derived_iso_edit)
        derived_layout.addWidget(derived_browse_btn)
        optional_layout.addRow("Derived ISO:", derived_layout)

        # Artifacts Directory
        artifacts_layout = QHBoxLayout()
        artifacts_layout.setSpacing(8)
        self.artifacts_dir_edit = QLineEdit()
        self.artifacts_dir_edit.setStyleSheet(input_style)
        self.artifacts_dir_edit.setPlaceholderText("Directory containing extracted artifacts")
        artifacts_browse_btn = QPushButton("Browse...")
        artifacts_browse_btn.setStyleSheet(browse_button_style)
        artifacts_browse_btn.clicked.connect(self.browse_artifacts_dir)
        artifacts_layout.addWidget(self.artifacts_dir_edit)
        artifacts_layout.addWidget(artifacts_browse_btn)
        optional_layout.addRow("Artifacts Directory:", artifacts_layout)

        # Bulk Extractor Directory
        bulk_layout = QHBoxLayout()
        bulk_layout.setSpacing(8)
        self.bulk_extractor_edit = QLineEdit()
        self.bulk_extractor_edit.setStyleSheet(input_style)
        self.bulk_extractor_edit.setPlaceholderText("Directory containing bulk_extractor output")
        bulk_browse_btn = QPushButton("Browse...")
        bulk_browse_btn.setStyleSheet(browse_button_style)
        bulk_browse_btn.clicked.connect(self.browse_bulk_extractor)
        bulk_layout.addWidget(self.bulk_extractor_edit)
        bulk_layout.addWidget(bulk_browse_btn)
        optional_layout.addRow("Bulk Extractor:", bulk_layout)

        # Logfile
        logfile_layout = QHBoxLayout()
        logfile_layout.setSpacing(8)
        self.logfile_edit = QLineEdit()
        self.logfile_edit.setStyleSheet(input_style)
        self.logfile_edit.setPlaceholderText("Path to acquisition/processing log")
        logfile_browse_btn = QPushButton("Browse...")
        logfile_browse_btn.setStyleSheet(browse_button_style)
        logfile_browse_btn.clicked.connect(self.browse_logfile)
        logfile_layout.addWidget(self.logfile_edit)
        logfile_layout.addWidget(logfile_browse_btn)
        optional_layout.addRow("Logfile:", logfile_layout)

        optional_group.setLayout(optional_layout)
        form_layout.addWidget(optional_group)

        # === Current Session Data ===
        session_group = QGroupBox("ForensAI Current Session Data")
        session_group.setStyleSheet(groupbox_style)
        session_layout = QVBoxLayout()
        session_layout.setSpacing(10)

        # Show session data info
        if self.session_data and self.session_data.get('has_data'):
            info_label = QLabel(
                f"✅ ForensAI has <b>{self.session_data['total_files']:,} files</b> loaded from current evidence image.<br>"
                f"Total size: <b>{self.session_data['total_size'] / (1024*1024):.2f} MB</b>"
            )
            info_label.setWordWrap(True)
            info_label.setStyleSheet("color: #28a745; padding: 10px; background-color: #d4edda; border-radius: 5px;")
            session_layout.addWidget(info_label)

            # Checkbox to use current session
            self.use_session_checkbox = QCheckBox(
                "Use files from current ForensAI session (recommended)"
            )
            self.use_session_checkbox.setChecked(True)  # Default to using session data
            self.use_session_checkbox.setStyleSheet("font-weight: bold;")
            self.use_session_checkbox.toggled.connect(self.on_session_checkbox_toggled)
            session_layout.addWidget(self.use_session_checkbox)

            note_label = QLabel(
                "💡 This will include all files visible in the 'Listing' tab in your report."
            )
            note_label.setStyleSheet("font-style: italic; color: #666; font-size: 10px;")
            session_layout.addWidget(note_label)

        else:
            # No session data available
            warning_label = QLabel(
                "⚠️ No files currently loaded in ForensAI.<br>"
                "Load an evidence image first (File → Add Evidence File) to include parsed files in the report."
            )
            warning_label.setWordWrap(True)
            warning_label.setStyleSheet("color: #856404; padding: 10px; background-color: #fff3cd; border-radius: 5px;")
            session_layout.addWidget(warning_label)

            self.use_session_checkbox = QCheckBox("Use files from current ForensAI session")
            self.use_session_checkbox.setEnabled(False)
            self.use_session_checkbox.setChecked(False)
            session_layout.addWidget(self.use_session_checkbox)

        session_group.setLayout(session_layout)
        form_layout.addWidget(session_group)

        # === Report Options ===
        options_group = QGroupBox("Report Options")
        options_group.setStyleSheet(groupbox_style)
        options_layout = QVBoxLayout()
        options_layout.setSpacing(12)

        # Output formats
        formats_label = QLabel("Output Formats:")
        formats_label.setFont(QFont("Arial", 10, QFont.Bold))
        options_layout.addWidget(formats_label)

        formats_container = QHBoxLayout()
        self.html_checkbox = QCheckBox("HTML Report")
        self.html_checkbox.setChecked(True)
        self.json_checkbox = QCheckBox("JSON Manifest")
        self.json_checkbox.setChecked(True)
        self.pdf_checkbox = QCheckBox("PDF Report")
        self.pdf_checkbox.setChecked(False)

        formats_container.addWidget(self.html_checkbox)
        formats_container.addWidget(self.json_checkbox)
        formats_container.addWidget(self.pdf_checkbox)
        formats_container.addStretch()
        options_layout.addLayout(formats_container)

        # PDF note
        pdf_note = QLabel("📝 Note: PDF generation requires wkhtmltopdf or weasyprint")
        pdf_note.setStyleSheet("color: #666; font-size: 10px; font-style: italic;")
        options_layout.addWidget(pdf_note)

        # Include screenshots
        self.screenshots_checkbox = QCheckBox("Include screenshots in report")
        self.screenshots_checkbox.setChecked(False)
        options_layout.addWidget(self.screenshots_checkbox)

        # Case Notes
        notes_label = QLabel("Case Notes (optional):")
        notes_label.setFont(QFont("Arial", 10, QFont.Bold))
        options_layout.addWidget(notes_label)

        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText(
            "Enter any additional notes about this case (e.g., investigation focus, "
            "key items to highlight, special circumstances...)"
        )
        self.notes_edit.setMaximumHeight(80)
        options_layout.addWidget(self.notes_edit)

        options_group.setLayout(options_layout)
        form_layout.addWidget(options_group)

        scroll.setWidget(form_widget)
        layout.addWidget(scroll)

        # === Progress Area ===
        self.progress_group = QGroupBox("Progress")
        self.progress_group.setStyleSheet(groupbox_style)
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(10)

        self.progress_text = QTextEdit()
        self.progress_text.setReadOnly(True)
        self.progress_text.setMaximumHeight(120)
        self.progress_text.setFont(QFont("Courier", 9))
        self.progress_text.setStyleSheet("""
            QTextEdit {
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                padding: 8px;
                background-color: #f8f9fa;
            }
        """)
        progress_layout.addWidget(self.progress_text)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #3498db;
            }
        """)
        progress_layout.addWidget(self.progress_bar)

        self.progress_group.setLayout(progress_layout)
        self.progress_group.setVisible(False)
        layout.addWidget(self.progress_group)

        # === Buttons ===
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        button_layout.setContentsMargins(0, 15, 0, 0)

        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.setIcon(QIcon.fromTheme("document-save"))
        self.generate_btn.setMinimumHeight(40)
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
                padding: 8px 20px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.generate_btn.clicked.connect(self.generate_report)

        self.cancel_btn = QPushButton("Close")
        self.cancel_btn.setMinimumHeight(40)
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                font-size: 13px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
                padding: 8px 20px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        self.cancel_btn.clicked.connect(self.close)

        button_layout.addStretch()
        button_layout.addWidget(self.generate_btn)
        button_layout.addWidget(self.cancel_btn)
        button_layout.addStretch()

        layout.addLayout(button_layout)

    def browse_master_image(self):
        """Browse for master image file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Master Evidence Image",
            "",
            "Disk Images (*.dd *.raw *.img *.001 *.E01);;All Files (*.*)"
        )
        if file_path:
            self.master_image_edit.setText(file_path)

    def browse_derived_iso(self):
        """Browse for derived ISO file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Derived ISO",
            "",
            "ISO Images (*.iso);;All Files (*.*)"
        )
        if file_path:
            self.derived_iso_edit.setText(file_path)

    def browse_output_dir(self):
        """Browse for output directory."""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory"
        )
        if dir_path:
            self.output_dir_edit.setText(dir_path)

    def browse_artifacts_dir(self):
        """Browse for artifacts directory."""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Artifacts Directory"
        )
        if dir_path:
            self.artifacts_dir_edit.setText(dir_path)

    def browse_bulk_extractor(self):
        """Browse for bulk_extractor directory."""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Bulk Extractor Output Directory"
        )
        if dir_path:
            self.bulk_extractor_edit.setText(dir_path)

    def browse_logfile(self):
        """Browse for logfile."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Logfile",
            "",
            "Log Files (*.log *.txt);;All Files (*.*)"
        )
        if file_path:
            self.logfile_edit.setText(file_path)

    def on_session_checkbox_toggled(self, checked):
        """Handle session checkbox toggle."""
        if checked:
            # Disable artifacts directory field when using session data
            self.artifacts_dir_edit.setEnabled(False)
            self.artifacts_dir_edit.setPlaceholderText(
                "Using files from ForensAI session (see above)"
            )
        else:
            # Re-enable artifacts directory field
            self.artifacts_dir_edit.setEnabled(True)
            self.artifacts_dir_edit.setPlaceholderText(
                "Directory containing extracted artifacts"
            )

    def validate_inputs(self):
        """
        Validate user inputs.

        Returns:
            Tuple of (valid: bool, error_message: str)
        """
        # Check required fields
        if not self.case_id_edit.text().strip():
            return False, "Case ID is required"

        if not self.operator_edit.text().strip():
            return False, "Operator name is required"

        master_image = self.master_image_edit.text().strip()
        if not master_image:
            return False, "Master image path is required"

        if not os.path.exists(master_image):
            return False, f"Master image not found: {master_image}"

        if not os.path.isfile(master_image):
            return False, f"Master image is not a file: {master_image}"

        output_dir = self.output_dir_edit.text().strip()
        if not output_dir:
            return False, "Output directory is required"

        # Check at least one format is selected
        if not (self.html_checkbox.isChecked() or
                self.json_checkbox.isChecked() or
                self.pdf_checkbox.isChecked()):
            return False, "Please select at least one output format"

        # Validate optional paths if provided
        derived_iso = self.derived_iso_edit.text().strip()
        if derived_iso and not os.path.exists(derived_iso):
            return False, f"Derived ISO not found: {derived_iso}"

        artifacts_dir = self.artifacts_dir_edit.text().strip()
        if artifacts_dir and not os.path.exists(artifacts_dir):
            return False, f"Artifacts directory not found: {artifacts_dir}"

        bulk_dir = self.bulk_extractor_edit.text().strip()
        if bulk_dir and not os.path.exists(bulk_dir):
            return False, f"Bulk extractor directory not found: {bulk_dir}"

        logfile = self.logfile_edit.text().strip()
        if logfile and not os.path.exists(logfile):
            return False, f"Logfile not found: {logfile}"

        return True, ""

    def generate_report(self):
        """Generate forensic report."""
        # Validate inputs
        valid, error_msg = self.validate_inputs()
        if not valid:
            QMessageBox.warning(self, "Validation Error", error_msg)
            return

        # Confirm generation
        reply = QMessageBox.question(
            self,
            "Confirm Report Generation",
            "This may take several minutes depending on image size.\n\n"
            "Do you want to proceed with report generation?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )

        if reply != QMessageBox.Yes:
            return

        # Collect investigator notes from notes manager
        investigator_notes = []
        if NOTES_AVAILABLE:
            try:
                notes_mgr = get_notes_manager()
                all_notes = notes_mgr.get_all_notes()

                # Group notes by type
                notes_by_type = {}
                for note in all_notes:
                    artifact_type = note.artifact_type
                    if artifact_type not in notes_by_type:
                        notes_by_type[artifact_type] = []
                    notes_by_type[artifact_type].append(note)

                # Format notes for report
                for artifact_type, notes in notes_by_type.items():
                    investigator_notes.append(f"\n### {artifact_type.upper()} ARTIFACTS\n")
                    for note in notes:
                        investigator_notes.append(f"**{note.artifact_name}**")
                        if note.ai_generated:
                            investigator_notes.append("  _(AI-Generated)_")
                        investigator_notes.append(f"\n{note.content}\n")

            except Exception as e:
                print(f"Warning: Could not load investigator notes: {e}")

        # Prepare configuration
        config = {
            'case_id': self.case_id_edit.text().strip(),
            'operator': self.operator_edit.text().strip(),
            'master_image': self.master_image_edit.text().strip(),
            'output_dir': self.output_dir_edit.text().strip(),
            'derived_iso': self.derived_iso_edit.text().strip() or None,
            'artifacts_dir': self.artifacts_dir_edit.text().strip() or None,
            'bulk_extractor_dir': self.bulk_extractor_edit.text().strip() or None,
            'logfile': self.logfile_edit.text().strip() or None,
            'notes': self.notes_edit.toPlainText().strip(),
            'investigator_notes': '\n'.join(investigator_notes) if investigator_notes else None,
            'include_screenshots': self.screenshots_checkbox.isChecked(),
            'formats': [],
            'session_data': None  # Will be filled if using session
        }

        # Check if using session data
        if hasattr(self, 'use_session_checkbox') and self.use_session_checkbox.isChecked():
            if self.session_data and self.session_data.get('has_data'):
                # Pass session data to thread
                config['session_data'] = self.session_data
                self.progress_text.append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] "
                    f"Using {self.session_data['total_files']:,} files from ForensAI session"
                )

        # Collect selected formats
        if self.html_checkbox.isChecked():
            config['formats'].append('html')
        if self.json_checkbox.isChecked():
            config['formats'].append('json')
        if self.pdf_checkbox.isChecked():
            config['formats'].append('pdf')

        # Show progress UI
        self.progress_group.setVisible(True)
        self.progress_bar.setVisible(True)
        self.progress_text.clear()
        self.progress_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] Starting report generation...")

        # Disable generate button
        self.generate_btn.setEnabled(False)
        self.generate_btn.setText("Generating...")

        # Create and start background thread
        self.generator_thread = ReportGeneratorThread(config)
        self.generator_thread.progress.connect(self.update_progress)
        self.generator_thread.finished.connect(self.generation_complete)
        self.generator_thread.error.connect(self.generation_error)
        self.generator_thread.start()

    def update_progress(self, message):
        """Update progress display."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.progress_text.append(f"[{timestamp}] {message}")
        # Auto-scroll to bottom
        self.progress_text.verticalScrollBar().setValue(
            self.progress_text.verticalScrollBar().maximum()
        )

    def generation_complete(self, result):
        """Handle report generation completion."""
        self.progress_bar.setVisible(False)
        self.generate_btn.setEnabled(True)
        self.generate_btn.setText("Generate Report")

        # Show result
        if result['status'] in ['success', 'partial']:
            # Build success message
            message = f"Report generated successfully!\n\n"
            message += f"Case ID: {result['case_id']}\n"
            message += f"Status: {result['status'].upper()}\n\n"

            if result.get('report_html'):
                message += f"HTML Report: {result['report_html']}\n"
            if result.get('report_pdf'):
                message += f"PDF Report: {result['report_pdf']}\n"
            if result.get('manifest_json'):
                message += f"JSON Manifest: {result['manifest_json']}\n"
            if result.get('artifacts_csv'):
                message += f"CSV Artifacts: {result['artifacts_csv']}\n"

            message += f"\n{result['summary']}"

            if result.get('warnings'):
                message += "\n\nWarnings:\n"
                for warning in result['warnings']:
                    message += f"  • {warning}\n"

            msg_box = QMessageBox(self)
            msg_box.setIcon(QMessageBox.Information)
            msg_box.setWindowTitle("Report Generated")
            msg_box.setText(message)
            msg_box.setStandardButtons(QMessageBox.Ok)

            # Add button to open report directory
            open_btn = msg_box.addButton("Open Report Folder", QMessageBox.ActionRole)

            msg_box.exec_()

            # Check if user clicked "Open Report Folder"
            if msg_box.clickedButton() == open_btn:
                import subprocess
                import platform

                output_dir = result.get('report_html', '')
                if output_dir:
                    output_dir = os.path.dirname(output_dir)
                else:
                    output_dir = self.output_dir_edit.text().strip()

                # Open folder in file explorer
                if platform.system() == 'Windows':
                    os.startfile(output_dir)
                elif platform.system() == 'Darwin':  # macOS
                    subprocess.call(['open', output_dir])
                else:  # Linux
                    subprocess.call(['xdg-open', output_dir])
        else:
            # Show error
            error_msg = f"Report generation failed!\n\n{result['summary']}"
            if result.get('warnings'):
                error_msg += "\n\nDetails:\n"
                for warning in result['warnings']:
                    error_msg += f"  • {warning}\n"

            QMessageBox.critical(self, "Report Generation Failed", error_msg)

    def generation_error(self, error_message):
        """Handle report generation error."""
        self.progress_bar.setVisible(False)
        self.generate_btn.setEnabled(True)
        self.generate_btn.setText("Generate Report")

        QMessageBox.critical(
            self,
            "Report Generation Error",
            f"An error occurred during report generation:\n\n{error_message}"
        )
