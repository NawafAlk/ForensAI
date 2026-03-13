"""
Metadata viewer tab for displaying file system metadata and AI explanations.

Shows inode-level details (timestamps, permissions, size, MFT attributes)
via SleuthKit's istat tool and provides AI-powered forensic explanations
of metadata anomalies through the Groq API.
"""

import os
import datetime
from PySide6.QtWidgets import (QTextEdit, QSizePolicy, QWidget, QVBoxLayout,
                               QPushButton, QHBoxLayout, QDialog, QLabel,
                               QDialogButtonBox, QMessageBox, QProgressDialog)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon
import hashlib
import re

try:
    import magic
    MAGIC_AVAILABLE = True
except (ImportError, OSError):
    MAGIC_AVAILABLE = False

try:
    from managers.ai_service import get_ai_service
    from managers.notes_manager import get_notes_manager, Note
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False


class AIExplanationThread(QThread):
    """Background thread for AI explanation generation."""

    finished = Signal(str)
    error = Signal(str)

    def __init__(self, file_data):
        super().__init__()
        self.file_data = file_data

    def run(self):
        """Generate AI explanation in background."""
        try:
            ai_service = get_ai_service()
            explanation = ai_service.explain_file_artifact(self.file_data)
            self.finished.emit(explanation)
        except Exception as e:
            self.error.emit(str(e))


class MetadataViewer(QWidget):
    def __init__(self, image_handler):
        super(MetadataViewer, self).__init__()
        self.image_handler = image_handler
        self.current_file_data = None
        self.ai_thread = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        self.metadata_text_edit = QTextEdit()
        self.metadata_text_edit.setReadOnly(True)
        self.metadata_text_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.metadata_text_edit)

        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(10, 5, 10, 5)

        if AI_AVAILABLE:
            self.explain_button = QPushButton("🤖 Explain This Artifact")
            self.explain_button.setToolTip("Use AI to explain the forensic significance of this file")
            self.explain_button.clicked.connect(self.on_explain_clicked)
            self.explain_button.setEnabled(False)
            self.explain_button.setStyleSheet("""
                QPushButton {
                    background-color: #3498db;
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #2980b9;
                }
                QPushButton:disabled {
                    background-color: #95a5a6;
                }
            """)
            button_layout.addWidget(self.explain_button)

        button_layout.addStretch()
        layout.addLayout(button_layout)

    def display_metadata(self, data):
        inode_number = data.get('inode_number')
        offset = data.get('start_offset')

        file_content, metadata = self.image_handler.get_file_content(inode_number, offset)

        if metadata is None:
            self.metadata_text_edit.setHtml("<b>No metadata available.</b>")
            if AI_AVAILABLE:
                self.explain_button.setEnabled(False)
            return

        def format_time(timestamp):
            if timestamp is None or timestamp == 0:
                return "N/A"
            try:
                return datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
            except Exception:
                return "N/A"

        created_time = format_time(metadata.crtime) if hasattr(metadata, 'crtime') else 'N/A'
        modified_time = format_time(metadata.mtime) if hasattr(metadata, 'mtime') else 'N/A'
        accessed_time = format_time(metadata.atime) if hasattr(metadata, 'atime') else 'N/A'
        changed_time = format_time(metadata.ctime) if hasattr(metadata, 'ctime') else 'N/A'

        md5_hash = hashlib.md5(file_content).hexdigest() if file_content else "N/A"
        sha256_hash = hashlib.sha256(file_content).hexdigest() if file_content else "N/A"

        if MAGIC_AVAILABLE and file_content:
            try:
                mime_type = magic.from_buffer(file_content)
            except:
                mime_type = "N/A"
        else:
            mime_type = "N/A"

        size = metadata.size if metadata.size else 'N/A'
        if isinstance(size, str):
            try:
                size = int(size)
            except ValueError:
                size = 'N/A'
        else:
            size = self.image_handler.get_readable_size(size)

        extended_metadata = f"<b style='font-size: 20px; font-family: Courier New;'>Metadata</b>"
        extended_metadata += f"<table style='margin-left: 10px; font-family: Courier New;'>"
        extended_metadata += f"<tr><th style='text-align: left;'>Name:</th><td style='padding-left: 20px;'>{data.get('name', 'N/A')}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Type:</th><td style='padding-left: 20px;'>{data.get('type')}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>MIME Type:</th><td style='padding-left: 20px;'>{mime_type}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Size:</th><td style='padding-left: 20px;'>{size}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Modified:</th><td style='padding-left: 20px;'>{modified_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Accessed:</th><td style='padding-left: 20px;'>{accessed_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Created:</th><td style='padding-left: 20px;'>{created_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>Changed:</th><td style='padding-left: 20px;'>{changed_time}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>MD5:</th><td style='padding-left: 20px;'>{md5_hash}</td></tr>"
        extended_metadata += f"<tr><th style='text-align: left;'>SHA-256:</th><td style='padding-left: 20px;'>{sha256_hash}</td></tr>"
        extended_metadata += f"</table>"
        extended_metadata += f"<br>"
        extended_metadata += f"<br>"

        if os.name == 'nt':
            istat_output = self.run_istat(offset, inode_number, self.image_handler.image_path)
            extended_metadata += (
                f"<b style='font-size: 20px; font-family: Courier New;'>From The Sleuth Kit istat Tool</b>")
            extended_metadata += (f"<div style='margin-left: 15px; font-family: Courier New;'>")
            extended_metadata += (f"<pre>{istat_output}</pre>")
            extended_metadata += (f"</div>")

        self.metadata_text_edit.setHtml(extended_metadata)

        if AI_AVAILABLE:
            self.current_file_data = {
                'name': data.get('name', 'unknown'),
                'path': data.get('name', ''),
                'type': data.get('type', 'file'),
                'mime_type': mime_type,
                'size': metadata.size if metadata.size else 0,
                'created': created_time,
                'modified': modified_time,
                'accessed': accessed_time,
                'changed': changed_time,
                'md5': md5_hash,
                'sha256': sha256_hash,
                'inode': inode_number,
                'offset': offset
            }
            self.explain_button.setEnabled(True)

    def on_explain_clicked(self):
        """Handle Explain button click."""
        if not self.current_file_data:
            QMessageBox.warning(self, "No File Selected", "Please select a file first.")
            return

        ai_service = get_ai_service()
        if not ai_service.is_available():
            QMessageBox.warning(
                self,
                "AI Service Unavailable",
                "Groq AI service is not available.\n\n"
                "Please configure your Groq API key in Options > API Keys."
            )
            return

        progress = QProgressDialog("Generating AI explanation...", "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setWindowTitle("AI Analysis")
        progress.setCancelButton(None)
        progress.show()

        self.ai_thread = AIExplanationThread(self.current_file_data)
        self.ai_thread.finished.connect(lambda explanation: self.show_explanation_dialog(explanation, progress))
        self.ai_thread.error.connect(lambda error: self.show_error_dialog(error, progress))
        self.ai_thread.start()

    def show_explanation_dialog(self, explanation: str, progress: QProgressDialog):
        """Show AI explanation in a dialog with save option."""
        progress.close()

        dialog = QDialog(self)
        dialog.setWindowTitle("AI Forensic Explanation")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(400)

        layout = QVBoxLayout(dialog)

        title_label = QLabel(f"<b>Artifact:</b> {self.current_file_data['name']}")
        title_label.setStyleSheet("font-size: 12pt; padding: 10px;")
        layout.addWidget(title_label)

        explanation_text = QTextEdit()
        explanation_text.setPlainText(explanation)
        explanation_text.setReadOnly(False)
        explanation_text.setStyleSheet("""
            QTextEdit {
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                padding: 10px;
                font-size: 11pt;
                line-height: 1.6;
            }
        """)
        layout.addWidget(explanation_text)

        info_label = QLabel("💡 You can edit this explanation before saving it as a note.")
        info_label.setStyleSheet("color: #7f8c8d; font-style: italic; padding: 5px;")
        layout.addWidget(info_label)

        button_box = QDialogButtonBox()

        save_button = button_box.addButton("Save as Note", QDialogButtonBox.AcceptRole)
        save_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                padding: 6px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)

        close_button = button_box.addButton("Close", QDialogButtonBox.RejectRole)

        button_box.accepted.connect(lambda: self.save_explanation_as_note(
            explanation_text.toPlainText(),
            dialog
        ))
        button_box.rejected.connect(dialog.reject)

        layout.addWidget(button_box)

        dialog.exec_()

    def save_explanation_as_note(self, explanation: str, dialog: QDialog):
        """Save AI explanation as an investigator note."""
        try:
            notes_manager = get_notes_manager()

            artifact_id = f"{self.current_file_data['inode']}@{self.current_file_data['offset']}"

            note = Note(
                artifact_type='file',
                artifact_id=artifact_id,
                artifact_name=self.current_file_data['name'],
                content=explanation,
                ai_generated=True,
                edited=True
            )

            notes_manager.add_note(note)

            QMessageBox.information(
                self,
                "Note Saved",
                f"Explanation saved as investigator note for:\n{self.current_file_data['name']}\n\n"
                "This note will be included in generated forensic reports."
            )

            dialog.accept()

        except Exception as e:
            QMessageBox.critical(
                self,
                "Save Error",
                f"Failed to save note:\n{str(e)}"
            )

    def show_error_dialog(self, error: str, progress: QProgressDialog):
        """Show error dialog if AI generation fails."""
        progress.close()

        QMessageBox.critical(
            self,
            "AI Explanation Failed",
            f"Failed to generate explanation:\n\n{error}"
        )

    def run_istat(self, offset, inode_number, image_path):
        import subprocess

        if image_path is None:
            raise ValueError("Image path value is None!")
        if inode_number is None:
            raise ValueError("Inode number value is None!")

        metadata_cmd = ["tools/sleuthkit-4.12.1-win32/bin/istat.exe"]

        if offset is not None:
            metadata_cmd.extend(["-o", str(offset)])

        metadata_cmd.extend([image_path, str(inode_number)])

        metadata_result = subprocess.run(
            metadata_cmd,
            capture_output=True,
            text=True,
            check=True
        )

        metadata_content = metadata_result.stdout

        match = re.search(r"(init_size: \d+)", metadata_content)

        if match:
            end_index = match.end()
            metadata_content = metadata_content[:end_index]

        return metadata_content

    def clear(self):
        self.metadata_text_edit.clear()
        self.current_file_data = None
        if AI_AVAILABLE:
            self.explain_button.setEnabled(False)
