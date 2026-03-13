"""
ForensAI - Priority Tab
========================
Displays risk-scored artifacts in Critical/High/Medium/Low priority tiers.

Shows:
- Files sorted by risk score
- Severity indicators
- One-click AI explanations
- Recommendations for investigation
"""

from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget,
                               QTreeWidgetItem, QPushButton, QLabel, QTextEdit,
                               QSplitter, QProgressDialog, QMessageBox, QHeaderView)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon, QColor, QBrush
from typing import Dict, List
from datetime import datetime

try:
    from managers.risk_scorer import get_risk_scorer, RiskScorer
    from managers.ai_service import get_ai_service
    from managers.notes_manager import get_notes_manager, Note
    from managers.audit_logger import get_audit_logger
    RISK_SCORING_AVAILABLE = True
except ImportError:
    RISK_SCORING_AVAILABLE = False


class RiskScoringThread(QThread):
    """Background thread for scoring files."""

    progress = Signal(int, int)  # current, total
    file_scored = Signal(dict)  # file_data with score
    finished = Signal(list)  # all scored files

    def __init__(self, files_to_score):
        super().__init__()
        self.files = files_to_score

    def run(self):
        """Score all files in background."""
        scorer = get_risk_scorer()
        scored_files = []

        for idx, file_data in enumerate(self.files):
            try:
                score_result = scorer.score_file(file_data)

                file_data['risk_score'] = score_result.score
                file_data['severity'] = score_result.severity
                file_data['risk_reasons'] = score_result.reasons
                file_data['risk_details'] = score_result.details
                file_data['recommendations'] = score_result.recommendations
                file_data['overwrite_analysis'] = score_result.overwrite_analysis

                scored_files.append(file_data)
                self.file_scored.emit(file_data)
                self.progress.emit(idx + 1, len(self.files))
            except Exception as e:
                # Skip files that fail scoring
                print(f"Warning: Failed to score file: {e}")
                pass

        self.finished.emit(scored_files)


class AIExplanationThread(QThread):
    """Background thread for AI risk explanation."""

    finished = Signal(str)
    error = Signal(str)

    def __init__(self, artifact, score, reasons):
        super().__init__()
        self.artifact = artifact
        self.score = score
        self.reasons = reasons

    def run(self):
        """Generate AI explanation in background."""
        try:
            ai_service = get_ai_service()
            explanation = ai_service.explain_risk_score(
                self.artifact,
                self.score,
                self.reasons
            )
            self.finished.emit(explanation)
        except Exception as e:
            self.error.emit(str(e))


class PriorityTab(QWidget):
    """Priority tab showing risk-scored artifacts."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.image_handler = None
        self.scored_files = []
        self.scoring_thread = None
        self.ai_thread = None
        self.media_warning = None  # For TRIM warning banner
        self.case_id = "default"  # Will be set when image loads

        self.init_ui()

    def init_ui(self):
        """Initialize user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel("Priority View - Risk-Scored Artifacts")
        title.setObjectName("priorityTitle")
        header_layout.addWidget(title)

        header_layout.addStretch()

        # Scan button
        self.scan_button = QPushButton("Scan for Threats")
        self.scan_button.setObjectName("scanButton")
        self.scan_button.clicked.connect(self.scan_files)
        self.scan_button.setEnabled(False)
        header_layout.addWidget(self.scan_button)

        layout.addWidget(header)

        # Main splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left: Priority tree
        self.priority_tree = QTreeWidget()
        self.priority_tree.setHeaderLabels(['Artifact', 'Score', 'Severity'])
        self.priority_tree.setColumnWidth(0, 400)
        self.priority_tree.setColumnWidth(1, 60)
        self.priority_tree.setColumnWidth(2, 100)
        self.priority_tree.itemClicked.connect(self.on_item_clicked)
        splitter.addWidget(self.priority_tree)

        # Right: Details panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(10, 10, 10, 10)

        # Details title
        details_title = QLabel("Artifact Details")
        details_title.setObjectName("detailsTitle")
        details_layout.addWidget(details_title)

        # Details text
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setPlaceholderText("Select an artifact to view details...")
        details_layout.addWidget(self.details_text)

        # Button layout
        button_layout = QHBoxLayout()

        # AI Explain button
        self.explain_button = QPushButton("AI Explain Risk")
        self.explain_button.setObjectName("aiExplainButton")
        self.explain_button.setEnabled(False)
        self.explain_button.clicked.connect(self.explain_risk)
        button_layout.addWidget(self.explain_button)

        # Save as Investigator Note button
        self.save_note_button = QPushButton("Save as Note")
        self.save_note_button.setObjectName("successButton")
        self.save_note_button.setEnabled(False)
        self.save_note_button.clicked.connect(self.save_as_note)
        button_layout.addWidget(self.save_note_button)

        # View Audit Trail button
        self.audit_button = QPushButton("View Audit Trail")
        self.audit_button.setObjectName("primaryButton")
        self.audit_button.setEnabled(False)
        self.audit_button.clicked.connect(self.view_audit_trail)
        button_layout.addWidget(self.audit_button)

        details_layout.addLayout(button_layout)

        splitter.addWidget(details_widget)
        splitter.setSizes([500, 500])

        layout.addWidget(splitter)

        # Info label
        self.info_label = QLabel("Load an evidence image and click 'Scan for Threats' to analyze files")
        self.info_label.setObjectName("infoLabel")
        layout.addWidget(self.info_label)

    def set_image_handler(self, image_handler):
        """Set image handler and enable scanning."""
        self.image_handler = image_handler
        self.scan_button.setEnabled(True)

        # Detect media type and show TRIM warning if needed
        try:
            from managers.media_detector import detect_media

            media_info = detect_media(image_handler)

            if media_info.trim_enabled:
                # Remove old warning if exists
                if self.media_warning:
                    self.media_warning.setParent(None)

                # Create new warning banner
                self.media_warning = QLabel(
                    f"  WARNING: TRIM DETECTED ({media_info.trim_confidence*100:.0f}% confidence) - "
                    f"Deleted file recovery probability is LOW"
                )
                self.media_warning.setObjectName("warningBanner")
                # Insert at top of layout (position 0)
                self.layout().insertWidget(0, self.media_warning)

                self.info_label.setText(
                    f"Media: {media_info.media_type} ({media_info.media_subtype}) | "
                    f"Click 'Scan for Threats' to analyze files"
                )
            else:
                self.info_label.setText(
                    f"Media: {media_info.media_type} | "
                    f"Click 'Scan for Threats' to analyze files"
                )
        except Exception as e:
            # Silently continue if media detection fails
            self.info_label.setText("Click 'Scan for Threats' to analyze all files in the image")

    def scan_files(self):
        """Scan all files in image and score them."""
        if not self.image_handler:
            QMessageBox.warning(self, "No Image", "Please load an evidence image first.")
            return

        # Collect all files from image
        self.info_label.setText("Collecting files from image...")
        files_to_score = []

        try:
            # Get all partitions
            partitions = self.image_handler.get_partitions()

            if not partitions:
                # No partitions, try root
                if self.image_handler.has_filesystem(0):
                    self._collect_files_recursive(0, None, "", files_to_score)
            else:
                # Collect from each partition
                for addr, desc, start, length in partitions:
                    desc_str = desc.decode('utf-8') if isinstance(desc, bytes) else desc

                    # Skip unallocated/special partitions
                    if "Unallocated" in desc_str or "Table" in desc_str:
                        continue

                    if self.image_handler.has_filesystem(start):
                        self._collect_files_recursive(start, None, "", files_to_score)

        except Exception as e:
            QMessageBox.critical(self, "Scan Error", f"Failed to scan files:\n{str(e)}")
            self.info_label.setText("Scan failed")
            return

        if not files_to_score:
            QMessageBox.information(self, "No Files", "No files found to analyze.")
            self.info_label.setText("No files found")
            return

        # Show progress and start scoring
        progress = QProgressDialog("Scoring files for risk...", "Cancel", 0, len(files_to_score), self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setWindowTitle("Risk Analysis")
        progress.show()

        # Start scoring thread
        self.scoring_thread = RiskScoringThread(files_to_score)
        self.scoring_thread.progress.connect(lambda curr, total: progress.setValue(curr))
        self.scoring_thread.finished.connect(lambda results: self.display_results(results, progress))
        self.scoring_thread.start()

    def _collect_files_recursive(self, start_offset, inode, path_prefix, files_list):
        """Recursively collect all files."""
        try:
            entries = self.image_handler.get_directory_contents(start_offset, inode)

            for entry in entries:
                entry_name = entry.get("name", "")

                if entry_name in [".", ".."]:
                    continue

                full_path = f"{path_prefix}/{entry_name}" if path_prefix else entry_name

                if entry.get("is_directory"):
                    # Recurse into directory
                    self._collect_files_recursive(
                        start_offset,
                        entry.get("inode_number"),
                        full_path,
                        files_list
                    )
                else:
                    # Add file to list
                    files_list.append({
                        'name': entry_name,
                        'path': full_path,
                        'size': entry.get("size", 0),
                        'created': entry.get("created", ""),
                        'modified': entry.get("modified", ""),
                        'accessed': entry.get("accessed", ""),
                        'inode': entry.get("inode_number"),
                        'offset': start_offset
                    })

                    # Limit to prevent memory issues (remove this for full scan)
                    if len(files_list) >= 10000:
                        return

        except Exception:
            pass

    def display_results(self, scored_files, progress_dialog):
        """Display scored files in tree."""
        progress_dialog.close()

        self.scored_files = scored_files
        self.priority_tree.clear()

        # Group by severity
        critical = []
        high = []
        medium = []
        low = []
        info = []

        for file_data in scored_files:
            severity = file_data.get('severity', 'info')

            if severity == 'critical':
                critical.append(file_data)
            elif severity == 'high':
                high.append(file_data)
            elif severity == 'medium':
                medium.append(file_data)
            elif severity == 'low':
                low.append(file_data)
            else:
                info.append(file_data)

        # Create top-level categories
        if critical:
            self._add_category("CRITICAL", critical, QColor(231, 76, 60))

        if high:
            self._add_category("HIGH", high, QColor(230, 126, 34))

        if medium:
            self._add_category("MEDIUM", medium, QColor(241, 196, 15))

        if low:
            self._add_category("LOW", low, QColor(52, 152, 219))

        # Update info label
        total_flagged = len(critical) + len(high) + len(medium) + len(low)
        self.info_label.setText(
            f"Found {total_flagged} flagged artifacts: "
            f"{len(critical)} Critical, {len(high)} High, "
            f"{len(medium)} Medium, {len(low)} Low"
        )

        # Expand critical by default
        if self.priority_tree.topLevelItemCount() > 0:
            self.priority_tree.topLevelItem(0).setExpanded(True)

    def _add_category(self, name, files, color):
        """Add category with files."""
        category = QTreeWidgetItem(self.priority_tree)
        category.setText(0, f"{name} ({len(files)} items)")
        category.setForeground(0, QBrush(color))
        category.setFont(0, category.font(0))
        font = category.font(0)
        font.setBold(True)
        category.setFont(0, font)

        # Sort by score descending
        files.sort(key=lambda x: x.get('risk_score', 0), reverse=True)

        for file_data in files:
            item = QTreeWidgetItem(category)
            item.setText(0, file_data.get('path', 'unknown'))
            item.setText(1, str(file_data.get('risk_score', 0)))
            item.setText(2, file_data.get('severity', 'info').upper())
            item.setData(0, Qt.UserRole, file_data)

    def on_item_clicked(self, item, column):
        """Handle item selection."""
        file_data = item.data(0, Qt.UserRole)

        if not file_data:
            return

        # Display details with rule weights
        details = f"<b>File:</b> {file_data.get('name', 'unknown')}<br>"
        details += f"<b>Path:</b> {file_data.get('path', 'unknown')}<br>"
        details += f"<b>Size:</b> {file_data.get('size', 0):,} bytes<br>"
        details += f"<b>Risk Score:</b> {file_data.get('risk_score', 0)}/100<br>"
        details += f"<b>Severity:</b> {file_data.get('severity', 'info').upper()}<br><br>"

        reasons = file_data.get('risk_reasons', [])
        details_dict = file_data.get('risk_details', {})

        if reasons:
            # Get rule weights
            try:
                scorer = RiskScorer()
                details += "<b>Rule Chain:</b><ul>"
                total_weight = 0

                for reason in reasons:
                    weight = scorer.RULE_WEIGHTS.get(reason, 0)
                    total_weight += weight
                    desc = details_dict.get(reason, reason)
                    details += f"<li><b>[{weight} pts]</b> {desc}</li>"

                details += "</ul>"

                # Show weight calculation if capped
                final_score = file_data.get('risk_score', 0)
                if total_weight > 100:
                    details += f"<i style='color: #7f8c8d;'>Total weight: {total_weight} pts → Capped at {final_score}</i><br><br>"

            except:
                # Fallback to simple list if scorer unavailable
                details += "<b>Flagged For:</b><ul>"
                for reason in reasons:
                    desc = details_dict.get(reason, reason)
                    details += f"<li>{desc}</li>"
                details += "</ul>"

        recommendations = file_data.get('recommendations', [])
        if recommendations:
            details += "<b>Recommendations:</b><ul>"
            for rec in recommendations:
                details += f"<li>{rec}</li>"
            details += "</ul>"

        # Display overwrite analysis if available
        overwrite_analysis = file_data.get('overwrite_analysis')
        if overwrite_analysis:
            details += "<br><hr>"
            details += "<b style='color: #e74c3c;'>⚠ Overwrite Analysis:</b><br>"
            details += f"<b>Risk:</b> {overwrite_analysis.overwrite_risk_pct}% of file area affected<br>"
            details += f"<b>Clusters:</b> {overwrite_analysis.clusters_total} total, "
            details += f"{overwrite_analysis.clusters_intact} intact, "
            details += f"{overwrite_analysis.clusters_reused} reused, "
            details += f"{overwrite_analysis.clusters_wiped} wiped<br>"

            if overwrite_analysis.overwritten_by:
                details += "<b>Reused by:</b><ul>"
                for filepath, timestamp, count in overwrite_analysis.overwritten_by[:3]:
                    import os
                    filename = os.path.basename(filepath)
                    details += f"<li>{filename} ({count} clusters at {timestamp})</li>"
                details += "</ul>"

            recovery = "✓ Yes" if overwrite_analysis.recovery_feasible else "✗ Unlikely"
            details += f"<b>Recovery Feasible:</b> {recovery}<br>"

        self.details_text.setHtml(details)
        self.explain_button.setEnabled(True)
        self.audit_button.setEnabled(True)
        self.save_note_button.setEnabled(False)  # Disable until AI explanation generated
        self.save_note_button.setText("📝 Save as Note")  # Reset text
        self.current_selected_file = file_data

    def explain_risk(self):
        """Get AI explanation of risk."""
        if not hasattr(self, 'current_selected_file'):
            return

        file_data = self.current_selected_file

        # Check AI availability
        ai_service = get_ai_service()
        if not ai_service.is_available():
            QMessageBox.warning(
                self,
                "AI Unavailable",
                "Groq AI service is not available.\n\n"
                "Please configure your Groq API key in Options > API Keys."
            )
            return

        # Show progress
        progress = QProgressDialog("Generating AI explanation...", None, 0, 0, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setCancelButton(None)
        progress.show()

        # Start AI thread
        self.ai_thread = AIExplanationThread(
            file_data,
            file_data.get('risk_score', 0),
            file_data.get('risk_reasons', [])
        )
        self.ai_thread.finished.connect(lambda exp: self.show_ai_explanation(exp, progress))
        self.ai_thread.error.connect(lambda err: self.show_ai_error(err, progress))
        self.ai_thread.start()

    def show_ai_explanation(self, explanation, progress_dialog):
        """Show AI explanation dialog."""
        progress_dialog.close()

        # Store explanation for potential saving
        self.last_ai_explanation = explanation

        # Add to current details
        current_html = self.details_text.toHtml()
        ai_section = f"<br><hr><b>AI Risk Analysis:</b><br><p>{explanation}</p>"
        self.details_text.setHtml(current_html + ai_section)

        # Enable save button
        self.save_note_button.setEnabled(True)

    def show_ai_error(self, error, progress_dialog):
        """Show AI error."""
        progress_dialog.close()
        QMessageBox.critical(self, "AI Error", f"Failed to generate explanation:\n{error}")

    def save_as_note(self):
        """Save current AI explanation as an investigator note."""
        if not hasattr(self, 'current_selected_file') or not hasattr(self, 'last_ai_explanation'):
            return

        file_data = self.current_selected_file
        explanation = self.last_ai_explanation

        try:
            # Get notes manager
            from managers.notes_manager import get_notes_manager, Note

            notes_mgr = get_notes_manager()

            # Create structured note with metadata
            artifact_id = str(file_data.get('inode', file_data.get('name', '')))
            artifact_name = file_data.get('name', 'Unknown')

            # Build note content with metadata
            note_content = f"""AI Risk Analysis - {artifact_name}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Risk Score: {file_data.get('risk_score', 0)}/100
Severity: {file_data.get('severity', 'unknown').upper()}

--- Explanation ---
{explanation}

--- Context ---
Path: {file_data.get('path', 'Unknown')}
Size: {file_data.get('size', 0):,} bytes
"""
            # Add overwrite analysis if available
            if file_data.get('overwrite_analysis'):
                oa = file_data['overwrite_analysis']
                note_content += f"""
Overwrite Analysis:
- Risk: {oa.overwrite_risk_pct}% of file affected
- Clusters: {oa.clusters_intact} intact / {oa.clusters_total} total
- Recovery Feasible: {'Yes' if oa.recovery_feasible else 'No'}
"""

            # Save note
            note = notes_mgr.add_note(
                artifact_type='file',
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                content=note_content,
                ai_generated=True,
                tags=['ai-analysis', 'risk-assessment', file_data.get('severity', 'unknown')]
            )

            # Show confirmation
            QMessageBox.information(
                self,
                "Note Saved",
                f"AI explanation saved as investigator note.\n\n"
                f"Note ID: {note.note_id}\n"
                f"This note will be included in the final forensic report."
            )

            # Disable save button (already saved)
            self.save_note_button.setEnabled(False)

            # Update button text to indicate saved
            self.save_note_button.setText("✓ Saved as Note")

        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save note:\n{e}")

    def view_audit_trail(self):
        """Show audit trail for selected artifact."""
        if not hasattr(self, 'current_selected_file'):
            return

        file_data = self.current_selected_file
        artifact_id = str(file_data.get('inode', file_data.get('name', '')))

        try:
            # Get audit logger
            audit_logger = get_audit_logger(case_id=self.case_id)

            # Get audit history
            history = audit_logger.get_artifact_history(artifact_id)

            # Format for display
            audit_html = "<h2>Audit Trail</h2>"
            audit_html += f"<p><b>Artifact:</b> {file_data.get('name', 'unknown')}<br>"
            audit_html += f"<b>ID:</b> {artifact_id}</p>"

            # Rule firing events
            if history['rule_logs']:
                audit_html += "<h3>Risk Assessments:</h3>"
                for log in history['rule_logs']:
                    audit_html += "<div style='border: 1px solid #bdc3c7; padding: 10px; margin: 10px 0; border-radius: 4px;'>"
                    audit_html += f"<p><b>Timestamp:</b> {log['timestamp']}</p>"
                    audit_html += f"<p><b>Score:</b> {log['final_score']}/100 ({log['severity'].upper()})</p>"
                    audit_html += f"<p><b>Rules Fired:</b> {len(log['rules_fired'])}</p>"
                    audit_html += "<ul>"
                    for rule in log['rules_fired']:
                        audit_html += f"<li>[{rule['weight']} pts] {rule['code']}</li>"
                    audit_html += "</ul>"
                    audit_html += f"<p style='color: #7f8c8d; font-size: 11px;'>"
                    audit_html += f"Log ID: <code>{log['log_id']}</code><br>"
                    audit_html += f"Input Hash: <code>{log['input_hash'][:16]}...</code></p>"
                    audit_html += "</div>"

            # AI interactions
            if history['ai_logs']:
                audit_html += "<h3>AI Interactions:</h3>"
                for log in history['ai_logs']:
                    audit_html += "<div style='border: 1px solid #bdc3c7; padding: 10px; margin: 10px 0; border-radius: 4px;'>"
                    audit_html += f"<p><b>Timestamp:</b> {log['timestamp']}</p>"
                    audit_html += f"<p><b>Model:</b> {log['model']}<br>"
                    audit_html += f"<b>Purpose:</b> {log['interaction_purpose']}<br>"
                    audit_html += f"<b>Duration:</b> {log['duration_ms']}ms</p>"
                    audit_html += f"<p><b>Prompt:</b> <pre style='background: #ecf0f1; padding: 5px; font-size: 10px; overflow-x: auto;'>{log['prompt'][:200]}...</pre></p>"
                    audit_html += f"<p><b>Response:</b> <pre style='background: #ecf0f1; padding: 5px; font-size: 10px;'>{log['response'][:300]}...</pre></p>"
                    audit_html += f"<p style='color: #7f8c8d; font-size: 11px;'>Log ID: <code>{log['log_id']}</code></p>"
                    audit_html += "</div>"

            if not history['rule_logs'] and not history['ai_logs']:
                audit_html += "<p style='color: #7f8c8d;'>No audit trail found for this artifact.</p>"
                audit_html += "<p><i>Note: Audit logging may not have been enabled when this file was analyzed.</i></p>"

            # Show in dialog
            from PySide6.QtWidgets import QDialog, QVBoxLayout, QTextBrowser, QPushButton, QHBoxLayout

            dialog = QDialog(self)
            dialog.setWindowTitle(f"Audit Trail - {file_data.get('name', 'unknown')}")
            dialog.resize(700, 500)

            layout = QVBoxLayout(dialog)

            browser = QTextBrowser()
            browser.setHtml(audit_html)
            browser.setOpenExternalLinks(False)
            layout.addWidget(browser)

            # Button layout
            btn_layout = QHBoxLayout()
            btn_layout.addStretch()

            # Export button
            export_btn = QPushButton("Export to JSON")
            export_btn.clicked.connect(lambda: self._export_audit_trail(artifact_id))
            btn_layout.addWidget(export_btn)

            # Close button
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.close)
            btn_layout.addWidget(close_btn)

            layout.addLayout(btn_layout)

            dialog.exec()

        except Exception as e:
            QMessageBox.critical(
                self,
                "Audit Trail Error",
                f"Failed to retrieve audit trail:\n{str(e)}"
            )

    def _export_audit_trail(self, artifact_id):
        """Export audit trail for artifact."""
        try:
            from PySide6.QtWidgets import QFileDialog
            import json

            audit_logger = get_audit_logger(case_id=self.case_id)
            history = audit_logger.get_artifact_history(artifact_id)

            # Ask user for save location
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Audit Trail",
                f"audit_trail_{artifact_id}.json",
                "JSON Files (*.json)"
            )

            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(history, f, indent=2)

                QMessageBox.information(
                    self,
                    "Export Complete",
                    f"Audit trail exported to:\n{file_path}"
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Failed to export audit trail:\n{str(e)}"
            )

    def clear(self):
        """Clear all data."""
        self.priority_tree.clear()
        self.details_text.clear()
        self.scored_files = []
        self.explain_button.setEnabled(False)
        self.audit_button.setEnabled(False)

        # Remove media warning if exists
        if self.media_warning:
            self.media_warning.setParent(None)
            self.media_warning = None

        self.info_label.setText("Load an evidence image and click 'Scan for Threats' to analyze files")
