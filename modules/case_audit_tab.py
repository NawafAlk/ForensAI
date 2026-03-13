"""
ForensAI - Case Audit Tab
==========================
Professional forensic accountability dashboard.

Provides:
- Media detection report
- Complete audit trail browser
- Integrity verification
- Export for court use

Philosophy: "Prove every decision. Show every step. Make it court-ready."
"""

from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QTextBrowser, QGroupBox, QTreeWidget,
                               QTreeWidgetItem, QSplitter, QComboBox, QMessageBox,
                               QFileDialog, QProgressDialog, QFrame)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor
from typing import Dict, List, Optional
import json

try:
    from managers.audit_logger import get_audit_logger
    from managers.media_detector import detect_media, MediaInfo
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False


class IntegrityCheckThread(QThread):
    """Background thread for integrity verification."""

    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, case_id):
        super().__init__()
        self.case_id = case_id

    def run(self):
        """Verify audit chain integrity."""
        try:
            audit_logger = get_audit_logger(case_id=self.case_id)
            results = audit_logger.verify_integrity()
            self.finished.emit(results)
        except Exception as e:
            self.error.emit(str(e))


class CaseAuditTab(QWidget):
    """
    Case Audit Tab - Forensic Accountability Dashboard.

    The machine truth: Logs, hashes, timestamps, cryptographic chains.
    Everything needed to prove forensic defensibility in court.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.image_handler = None
        self.media_info: Optional[MediaInfo] = None
        self.case_id = "default"
        self.integrity_thread = None

        self.init_ui()

    def init_ui(self):
        """Initialize user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Header
        header = self._create_header()
        layout.addWidget(header)

        # Main content splitter
        splitter = QSplitter(Qt.Vertical)

        # Top: Statistics and Media Info
        top_widget = QWidget()
        top_layout = QHBoxLayout(top_widget)
        top_layout.setSpacing(10)

        # Statistics card
        self.stats_card = self._create_statistics_card()
        top_layout.addWidget(self.stats_card)

        # Media detection card
        self.media_card = self._create_media_card()
        top_layout.addWidget(self.media_card)

        splitter.addWidget(top_widget)

        # Bottom: Audit log browser
        audit_widget = self._create_audit_browser()
        splitter.addWidget(audit_widget)

        splitter.setSizes([300, 400])
        layout.addWidget(splitter)

        # Bottom action bar
        action_bar = self._create_action_bar()
        layout.addWidget(action_bar)

    def _create_header(self) -> QWidget:
        """Create header with title and status."""
        header = QWidget()
        layout = QHBoxLayout(header)
        layout.setContentsMargins(0, 0, 0, 10)

        title = QLabel("Case Audit Dashboard")
        title.setObjectName("auditTitle")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        layout.addStretch()

        # Case ID label
        self.case_label = QLabel(f"Case ID: {self.case_id}")
        self.case_label.setObjectName("caseLabel")
        layout.addWidget(self.case_label)

        return header

    def _create_statistics_card(self) -> QGroupBox:
        """Create statistics card."""
        card = QGroupBox("Case Statistics")
        card.setObjectName("statsCard")

        layout = QVBoxLayout(card)
        layout.setSpacing(5)

        # Placeholder stats (will be updated when data loads)
        self.stat_files = QLabel("Files Analyzed: <b>0</b>")
        self.stat_flagged = QLabel("High Risk Artifacts: <b>0</b>")
        self.stat_ai = QLabel("AI Explanations: <b>0</b>")
        self.stat_logs = QLabel("Audit Entries: <b>0</b>")
        self.stat_overwrite = QLabel("Overwrite Analysis: <i>Enabled</i>")
        self.stat_integrity = QLabel("Chain Integrity: <i>Not verified</i>")

        for stat in [self.stat_files, self.stat_flagged, self.stat_ai,
                     self.stat_logs, self.stat_overwrite, self.stat_integrity]:
            stat.setObjectName("statLabel")
            layout.addWidget(stat)

        layout.addStretch()

        return card

    def _create_media_card(self) -> QGroupBox:
        """Create media detection card."""
        card = QGroupBox("Media Analysis")
        card.setObjectName("mediaCard")

        layout = QVBoxLayout(card)

        self.media_browser = QTextBrowser()
        self.media_browser.setMaximumHeight(180)
        self.media_browser.setHtml("<p style='color: #7f8c8d;'>No image loaded</p>")
        layout.addWidget(self.media_browser)

        return card

    def _create_audit_browser(self) -> QWidget:
        """Create audit log browser."""
        widget = QGroupBox("Audit Trail Browser")
        widget.setObjectName("auditCard")

        layout = QVBoxLayout(widget)

        # Filter bar
        filter_bar = QHBoxLayout()

        filter_label = QLabel("Filter:")
        filter_bar.addWidget(filter_label)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "All Events",
            "Rule Firings Only",
            "AI Interactions Only"
        ])
        self.filter_combo.currentIndexChanged.connect(self.apply_filter)
        filter_bar.addWidget(self.filter_combo)

        filter_bar.addStretch()

        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_audit_logs)
        filter_bar.addWidget(refresh_btn)

        layout.addLayout(filter_bar)

        # Audit log tree
        self.audit_tree = QTreeWidget()
        self.audit_tree.setHeaderLabels(['Timestamp', 'Type', 'Artifact', 'Details'])
        self.audit_tree.setColumnWidth(0, 180)
        self.audit_tree.setColumnWidth(1, 120)
        self.audit_tree.setColumnWidth(2, 250)
        self.audit_tree.itemDoubleClicked.connect(self.show_log_details)
        layout.addWidget(self.audit_tree)

        return widget

    def _create_action_bar(self) -> QWidget:
        """Create bottom action bar."""
        widget = QFrame()
        widget.setFrameStyle(QFrame.StyledPanel)
        widget.setObjectName("actionBar")

        layout = QHBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)

        layout.addStretch()

        # Verify Integrity button
        verify_btn = QPushButton("Verify Integrity")
        verify_btn.setObjectName("successButton")
        verify_btn.clicked.connect(self.verify_integrity)
        layout.addWidget(verify_btn)

        # Export JSON button
        export_json_btn = QPushButton("Export Logs (JSON)")
        export_json_btn.setObjectName("primaryButton")
        export_json_btn.clicked.connect(lambda: self.export_logs("json"))
        layout.addWidget(export_json_btn)

        # Export CSV button
        export_csv_btn = QPushButton("Export Logs (CSV)")
        export_csv_btn.setObjectName("primaryButton")
        export_csv_btn.clicked.connect(lambda: self.export_logs("csv"))
        layout.addWidget(export_csv_btn)

        # View Media Report button
        media_report_btn = QPushButton("View Media Report")
        media_report_btn.setObjectName("primaryButton")
        media_report_btn.clicked.connect(self.view_media_report)
        layout.addWidget(media_report_btn)

        return widget

    def set_image_handler(self, image_handler):
        """Set image handler and load media info."""
        self.image_handler = image_handler

        # Load media information
        try:
            self.media_info = detect_media(image_handler)
            self._update_media_card()
        except Exception as e:
            self.media_browser.setHtml(
                f"<p style='color: #e74c3c;'>Media detection failed: {str(e)}</p>"
            )

        # Load audit logs
        self.load_audit_logs()

        # Update statistics
        self.update_statistics()

    def _update_media_card(self):
        """Update media detection card with info."""
        if not self.media_info:
            return

        html = "<style>"
        html += "p { margin: 5px 0; }"
        html += ".warning { color: #e74c3c; font-weight: bold; }"
        html += ".ok { color: #27ae60; }"
        html += ".label { color: #7f8c8d; }"
        html += "</style>"

        html += f"<p><span class='label'>Type:</span> <b>{self.media_info.media_type}</b>"
        if self.media_info.media_subtype:
            html += f" ({self.media_info.media_subtype})"
        html += "</p>"

        size_gb = self.media_info.total_size_bytes / (1024**3)
        html += f"<p><span class='label'>Capacity:</span> {size_gb:.2f} GB</p>"

        # TRIM status
        if self.media_info.trim_enabled:
            conf = self.media_info.trim_confidence * 100
            html += f"<p class='warning'>TRIM: ENABLED ({conf:.0f}% confidence)</p>"
            html += f"<p class='warning'>Recovery Probability: LOW</p>"
        else:
            html += f"<p class='ok'>TRIM: Not detected</p>"

        # Acquisition info
        if self.media_info.acquisition_tool:
            html += f"<p><span class='label'>Tool:</span> {self.media_info.acquisition_tool}</p>"

        if self.media_info.acquisition_date:
            html += f"<p><span class='label'>Date:</span> {self.media_info.acquisition_date}</p>"

        if self.media_info.acquisition_hash_verified:
            html += f"<p class='ok'>Hash: Verified</p>"

        self.media_browser.setHtml(html)

    def load_audit_logs(self):
        """Load audit logs into browser."""
        try:
            audit_logger = get_audit_logger(case_id=self.case_id)

            # Clear tree
            self.audit_tree.clear()

            # Load all logs
            self.all_logs = []

            # Load rule logs
            if audit_logger.rule_log_path.exists():
                with open(audit_logger.rule_log_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        log = json.loads(line)
                        log['_type'] = 'rule_firing'
                        self.all_logs.append(log)

            # Load AI logs
            if audit_logger.ai_log_path.exists():
                with open(audit_logger.ai_log_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        log = json.loads(line)
                        log['_type'] = 'ai_interaction'
                        self.all_logs.append(log)

            # Sort by timestamp
            self.all_logs.sort(key=lambda x: x['timestamp'], reverse=True)

            # Apply current filter
            self.apply_filter()

        except Exception as e:
            QMessageBox.warning(
                self,
                "Load Error",
                f"Failed to load audit logs:\n{str(e)}"
            )

    def apply_filter(self):
        """Apply filter to audit log display."""
        self.audit_tree.clear()

        filter_type = self.filter_combo.currentText()

        for log in self.all_logs:
            # Apply filter
            if filter_type == "Rule Firings Only" and log['_type'] != 'rule_firing':
                continue
            if filter_type == "AI Interactions Only" and log['_type'] != 'ai_interaction':
                continue

            # Add to tree
            item = QTreeWidgetItem(self.audit_tree)

            # Timestamp
            timestamp = log['timestamp'].replace('T', ' ').replace('Z', '')
            item.setText(0, timestamp)

            # Type
            log_type = "Rule Firing" if log['_type'] == 'rule_firing' else "AI Interaction"
            item.setText(1, log_type)

            # Artifact
            artifact_name = log.get('artifact_name', 'N/A')
            item.setText(2, artifact_name)

            # Details
            if log['_type'] == 'rule_firing':
                details = f"Score: {log['final_score']}/100 ({log['severity']})"
            else:
                details = f"Model: {log['model']}, {log['duration_ms']}ms"

            item.setText(3, details)

            # Store full log
            item.setData(0, Qt.UserRole, log)

    def show_log_details(self, item, column):
        """Show detailed view of log entry."""
        log = item.data(0, Qt.UserRole)

        if not log:
            return

        # Format log as HTML
        html = "<style>"
        html += "body { font-family: monospace; font-size: 11px; }"
        html += "h3 { color: #2c3e50; }"
        html += "pre { background: #ecf0f1; padding: 10px; border-radius: 4px; }"
        html += ".key { color: #7f8c8d; }"
        html += "</style>"

        html += f"<h3>{log['_type'].replace('_', ' ').title()}</h3>"

        # Format as JSON
        log_copy = dict(log)
        log_copy.pop('_type', None)

        html += "<pre>"
        html += json.dumps(log_copy, indent=2)
        html += "</pre>"

        # Show in dialog
        from PySide6.QtWidgets import QDialog, QVBoxLayout, QTextBrowser, QPushButton

        dialog = QDialog(self)
        dialog.setWindowTitle("Log Entry Details")
        dialog.resize(600, 500)

        layout = QVBoxLayout(dialog)

        browser = QTextBrowser()
        browser.setHtml(html)
        layout.addWidget(browser)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)

        dialog.exec()

    def update_statistics(self):
        """Update statistics card."""
        try:
            audit_logger = get_audit_logger(case_id=self.case_id)

            # Count rule logs
            rule_count = 0
            if audit_logger.rule_log_path.exists():
                with open(audit_logger.rule_log_path, 'r') as f:
                    rule_count = sum(1 for _ in f)

            # Count AI logs
            ai_count = 0
            if audit_logger.ai_log_path.exists():
                with open(audit_logger.ai_log_path, 'r') as f:
                    ai_count = sum(1 for _ in f)

            total_logs = rule_count + ai_count

            # Update labels
            self.stat_logs.setText(f"Audit Entries: <b>{total_logs:,}</b>")
            self.stat_ai.setText(f"AI Explanations: <b>{ai_count:,}</b>")

            # These would be updated from actual case data
            # self.stat_files.setText(f"Files Analyzed: <b>{files_count:,}</b>")
            # self.stat_flagged.setText(f"High Risk Artifacts: <b>{flagged_count:,}</b>")

        except Exception as e:
            pass

    def verify_integrity(self):
        """Verify cryptographic integrity of audit chain."""
        # Show progress
        progress = QProgressDialog("Verifying audit chain integrity...", None, 0, 0, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setCancelButton(None)
        progress.show()

        # Start verification thread
        self.integrity_thread = IntegrityCheckThread(self.case_id)
        self.integrity_thread.finished.connect(lambda r: self._show_integrity_results(r, progress))
        self.integrity_thread.error.connect(lambda e: self._show_integrity_error(e, progress))
        self.integrity_thread.start()

    def _show_integrity_results(self, results, progress_dialog):
        """Show integrity verification results."""
        progress_dialog.close()

        # Update status label with hash
        if results['all_valid']:
            hash_display = results.get('final_hash_short', '')
            if hash_display:
                self.stat_integrity.setText(
                    f"Chain Integrity: <b style='color: #27ae60;'>✓ Verified</b> (SHA256: {hash_display})"
                )
            else:
                self.stat_integrity.setText(
                    "Chain Integrity: <b style='color: #27ae60;'>VALID</b>"
                )
        else:
            self.stat_integrity.setText(
                "Chain Integrity: <b style='color: #e74c3c;'>✗ INVALID</b>"
            )

        # Show detailed results
        msg = "Integrity Verification Results\n\n"

        msg += f"Rule Logs: {'VALID' if results['rule_logs']['valid'] else 'INVALID'}\n"
        msg += f"  Entries: {results['rule_logs']['entries']}\n"
        msg += f"  {results['rule_logs']['message']}\n\n"

        msg += f"AI Logs: {'VALID' if results['ai_logs']['valid'] else 'INVALID'}\n"
        msg += f"  Entries: {results['ai_logs']['entries']}\n"
        msg += f"  {results['ai_logs']['message']}\n\n"

        # Add final hash to message
        if 'final_hash' in results:
            msg += f"Chain Hash (SHA256):\n{results['final_hash']}\n\n"

        if results['all_valid']:
            msg += "✓ All logs verified. Cryptographic chain is intact."
            QMessageBox.information(self, "Integrity Verified", msg)
        else:
            msg += "✗ TAMPERING DETECTED! Chain integrity compromised."
            QMessageBox.critical(self, "Integrity Failed", msg)

    def _show_integrity_error(self, error, progress_dialog):
        """Show integrity error."""
        progress_dialog.close()
        QMessageBox.critical(
            self,
            "Verification Error",
            f"Failed to verify integrity:\n{error}"
        )

    def export_logs(self, format_type: str):
        """Export audit logs."""
        try:
            audit_logger = get_audit_logger(case_id=self.case_id)

            # Ask for save location
            ext = "json" if format_type == "json" else "csv"
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Audit Logs",
                f"case_audit_{self.case_id}.{ext}",
                f"{ext.upper()} Files (*.{ext})"
            )

            if file_path:
                # Export
                result_path = audit_logger.export_logs(
                    output_format=format_type,
                    output_path=file_path
                )

                QMessageBox.information(
                    self,
                    "Export Complete",
                    f"Audit logs exported to:\n{result_path}"
                )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Failed to export logs:\n{str(e)}"
            )

    def view_media_report(self):
        """Show detailed media report."""
        if not self.media_info:
            QMessageBox.warning(self, "No Media", "No media information available.")
            return

        # Generate detailed report
        report = self.media_info.export_report()

        html = "<style>"
        html += "body { font-family: sans-serif; }"
        html += "h2 { color: #2c3e50; }"
        html += ".section { margin: 15px 0; }"
        html += ".label { color: #7f8c8d; font-weight: bold; }"
        html += ".warning { color: #e74c3c; font-weight: bold; }"
        html += "</style>"

        html += "<h2>Media Detection Report</h2>"

        html += "<div class='section'>"
        html += f"<p><span class='label'>Media Type:</span> {report['media_type']}"
        if report.get('media_subtype'):
            html += f" ({report['media_subtype']})"
        html += "</p>"

        size_gb = report['total_size_bytes'] / (1024**3)
        html += f"<p><span class='label'>Capacity:</span> {size_gb:.2f} GB</p>"
        html += f"<p><span class='label'>Sectors:</span> {report['total_sectors']:,}</p>"
        html += "</div>"

        # TRIM
        if report['trim_enabled']:
            html += "<div class='section'>"
            html += f"<p class='warning'>TRIM STATUS: ENABLED</p>"
            html += f"<p class='warning'>Confidence: {report['trim_confidence']*100:.0f}%</p>"
            html += f"<p class='warning'>Recovery Probability: LOW</p>"
            html += "</div>"

        # Acquisition
        if report.get('acquisition_tool'):
            html += "<div class='section'>"
            html += "<h3>Acquisition Details</h3>"
            html += f"<p><span class='label'>Tool:</span> {report['acquisition_tool']}</p>"
            html += f"<p><span class='label'>Date:</span> {report['acquisition_date']}</p>"
            html += f"<p><span class='label'>Mode:</span> {report['acquisition_mode']}</p>"
            html += f"<p><span class='label'>Hash Verified:</span> {'Yes' if report['acquisition_hash_verified'] else 'No'}</p>"

            if report.get('ewf_case_number'):
                html += f"<p><span class='label'>Case Number:</span> {report['ewf_case_number']}</p>"
            if report.get('ewf_examiner_name'):
                html += f"<p><span class='label'>Examiner:</span> {report['ewf_examiner_name']}</p>"

            html += "</div>"

        # Warnings
        if report.get('warning_flags'):
            html += "<div class='section'>"
            html += "<h3>Warnings</h3>"
            html += "<ul>"
            for warning in report['warning_flags']:
                html += f"<li class='warning'>{warning}</li>"
            html += "</ul>"
            html += "</div>"

        # Show in dialog
        from PySide6.QtWidgets import QDialog, QVBoxLayout, QTextBrowser, QPushButton

        dialog = QDialog(self)
        dialog.setWindowTitle("Media Detection Report")
        dialog.resize(600, 500)

        layout = QVBoxLayout(dialog)

        browser = QTextBrowser()
        browser.setHtml(html)
        layout.addWidget(browser)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)

        dialog.exec()

    def clear(self):
        """Clear all data."""
        self.audit_tree.clear()
        self.media_browser.setHtml("<p style='color: #7f8c8d;'>No image loaded</p>")
        self.media_info = None
        self.all_logs = []

        # Reset stats
        self.stat_files.setText("Files Analyzed: <b>0</b>")
        self.stat_flagged.setText("High Risk Artifacts: <b>0</b>")
        self.stat_ai.setText("AI Explanations: <b>0</b>")
        self.stat_logs.setText("Audit Entries: <b>0</b>")
        self.stat_integrity.setText("Chain Integrity: <i>Not verified</i>")
