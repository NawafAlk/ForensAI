"""
Windows Registry hive viewer and extractor for forensic analysis.

Parses SAM, SYSTEM, SOFTWARE, NTUSER.DAT and other registry hives using
the python-registry library. Displays the registry tree structure with
key/value details and provides AI-powered explanations of registry artifacts.
"""

import os
import tempfile

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QTextEdit, QToolBar, QLabel,
                               QSplitter, QTableWidget, QTableWidgetItem, QComboBox, QSizePolicy, QPushButton,
                               QMenu, QApplication, QHeaderView, QMessageBox, QProgressDialog, QDialog,
                               QDialogButtonBox)
from Registry import Registry
from Registry.Registry import RegistryValue, RegistryKey

try:
    from managers.ai_service import get_ai_service
    from managers.notes_manager import get_notes_manager, Note
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False


class AIRegistryExplanationThread(QThread):
    """Background thread for AI registry explanation."""

    finished = Signal(str)
    error = Signal(str)

    def __init__(self, key_path, values):
        super().__init__()
        self.key_path = key_path
        self.values = values

    def run(self):
        """Generate AI explanation in background."""
        try:
            ai_service = get_ai_service()
            explanation = ai_service.explain_registry_key(self.key_path, self.values)
            self.finished.emit(explanation)
        except Exception as e:
            self.error.emit(str(e))


class RegistryExtractor(QWidget):
    def __init__(self, image_handler):
        super().__init__()
        self.image_handler = image_handler
        self.hive_icon = QIcon("Icons/icons8-hive-48.png")
        self.key_icon = QIcon("Icons/icons8-key-48_blue.png")
        self.value_icon = QIcon("Icons/icons8-wasp-48.png")
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.setLayout(main_layout)

        self.toolbar = QToolBar("Toolbar")
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.toolbar)

        self.icon_label = QLabel()
        self.icon_label.setPixmap(QIcon("Icons/icons8-registry-editor-96.png").pixmap(48, 48))
        self.toolbar.addWidget(self.icon_label)

        self.label = QLabel("Registry Browser")
        self.label.setStyleSheet("""
            QLabel {
                font-size: 20px; /* Slightly larger size for the title */
                color: #37c6d0; /* Hex color for the text */
                font-weight: bold; /* Make the text bold */
                margin-left: 8px; /* Space between icon and label */
            }
        """)
        self.toolbar.addWidget(self.label)

        spacer = QLabel()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

        self.hiveSelector = QComboBox()
        self.hiveSelector.addItems(["SOFTWARE", "SYSTEM", "SAM", "SECURITY", "DEFAULT", "COMPONENTS"])
        self.toolbar.addWidget(self.hiveSelector)

        self.loadHiveButton = QPushButton("Load")
        self.loadHiveButton.clicked.connect(self.load_selected_hive)
        self.toolbar.addWidget(self.loadHiveButton)

        self.splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(self.splitter)

        self.treeWidget = QTreeWidget()
        self.treeWidget.header().hide()
        self.treeWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.treeWidget.customContextMenuRequested.connect(self.onTreeContextMenuRequested)
        self.splitter.addWidget(self.treeWidget)

        self.detailsSplitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.detailsSplitter)

        self.metadataPanel = QTextEdit()
        self.metadataPanel.setReadOnly(True)
        self.detailsSplitter.addWidget(self.metadataPanel)

        self.tableWidget = QTableWidget()
        self.tableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tableWidget.setSelectionBehavior(QTableWidget.SelectRows)
        self.tableWidget.verticalHeader().setVisible(False)
        self.detailsSplitter.addWidget(self.tableWidget)

        self.splitter.setSizes([300, 700])
        self.detailsSplitter.setStretchFactor(0, 1)
        self.detailsSplitter.setStretchFactor(1, 1)

        self.treeWidget.itemClicked.connect(self.on_item_clicked)

    def onCustomContextMenuRequested(self, position):
        contextMenu = QMenu(self)
        copyAction = contextMenu.addAction("Copy")

        action = contextMenu.exec_(self.tableWidget.mapToGlobal(position))

        if action == copyAction:
            selectedIndexes = self.tableWidget.selectedIndexes()
            if selectedIndexes:
                selectedText = selectedIndexes[0].data()
                QApplication.clipboard().setText(selectedText)

    def onTreeContextMenuRequested(self, position):
        """Handle tree widget context menu (registry keys)."""
        item = self.treeWidget.itemAt(position)
        if not item:
            return

        registry_object = item.data(0, Qt.UserRole)
        if not isinstance(registry_object, RegistryKey):
            return

        menu = QMenu(self)

        if AI_AVAILABLE:
            explain_action = menu.addAction("AI Explain This Key")
            explain_action.triggered.connect(lambda: self.explain_registry_key(registry_object))

        menu.exec_(self.treeWidget.viewport().mapToGlobal(position))

    def explain_registry_key(self, registry_key):
        """Generate AI explanation for registry key."""
        if not AI_AVAILABLE:
            QMessageBox.warning(self, "AI Unavailable", "AI features are not available.")
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

        key_path = registry_key.path()

        values_data = []
        try:
            for value in registry_key.values():
                values_data.append({
                    'name': value.name(),
                    'type': value.value_type_str(),
                    'data': str(value.value())[:100]
                })
        except:
            values_data = []

        progress = QProgressDialog("Generating AI explanation...", None, 0, 0, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setWindowTitle("AI Analysis")
        progress.setCancelButton(None)
        progress.show()

        self.ai_thread = AIRegistryExplanationThread(key_path, values_data)
        self.ai_thread.finished.connect(lambda exp: self.show_registry_explanation(exp, progress, key_path))
        self.ai_thread.error.connect(lambda err: self.show_ai_error(err, progress))
        self.ai_thread.start()

    def show_registry_explanation(self, explanation, progress_dialog, key_path):
        """Show AI explanation dialog for registry key."""
        progress_dialog.close()

        dialog = QDialog(self)
        dialog.setWindowTitle("AI Registry Key Explanation")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(400)

        layout = QVBoxLayout(dialog)

        title_label = QLabel(f"<b>Registry Key:</b> {key_path}")
        title_label.setWordWrap(True)
        title_label.setStyleSheet("font-size: 11pt; padding: 10px;")
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
            }
        """)
        layout.addWidget(explanation_text)

        info_label = QLabel("You can edit this explanation before saving it as a note.")
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

        button_box.accepted.connect(lambda: self.save_registry_note(
            explanation_text.toPlainText(),
            key_path,
            dialog
        ))
        button_box.rejected.connect(dialog.reject)

        layout.addWidget(button_box)

        dialog.exec_()

    def save_registry_note(self, explanation, key_path, dialog):
        """Save registry explanation as note."""
        try:
            notes_manager = get_notes_manager()

            note = Note(
                artifact_type='registry',
                artifact_id=key_path,
                artifact_name=key_path.split('\\')[-1],
                content=explanation,
                ai_generated=True,
                edited=True
            )

            notes_manager.add_note(note)

            QMessageBox.information(
                self,
                "Note Saved",
                f"Explanation saved as investigator note for:\n{key_path}\n\n"
                "This note will be included in generated forensic reports."
            )

            dialog.accept()

        except Exception as e:
            QMessageBox.critical(
                self,
                "Save Error",
                f"Failed to save note:\n{str(e)}"
            )

    def show_ai_error(self, error, progress_dialog):
        """Show AI error dialog."""
        progress_dialog.close()
        QMessageBox.critical(
            self,
            "AI Explanation Failed",
            f"Failed to generate explanation:\n\n{error}"
        )

    def load_selected_hive(self):
        try:
            selectedHive = self.hiveSelector.currentText()

            partitions = self.image_handler.get_partitions()

            if not partitions:
                print("No partitions found.")
                return

            for partition in partitions:
                start_offset = partition[2]
                fs_type = self.image_handler.get_fs_type(start_offset)
                fs_info = self.image_handler.get_fs_info(start_offset)
                if fs_type == "NTFS":
                    hive_data = self.image_handler.get_registry_hive(fs_info,
                                                                     f"/Windows/System32/config/{selectedHive}")
                    if hive_data:
                        with tempfile.NamedTemporaryFile(delete=False) as temp_hive:
                            temp_hive.write(hive_data)
                            temp_hive_path = temp_hive.name

                        with open(temp_hive_path, "rb") as hive_file:
                            reg = Registry.Registry(hive_file)
                            self.display_registry_hive(selectedHive, reg.root())

                        os.remove(temp_hive_path)
        except Exception as e:
            print(f"An error occurred while loading the selected hive: {e}")

    def display_registry_hive(self, hive_name, root_key):
        self.treeWidget.clear()
        hive_item = QTreeWidgetItem(self.treeWidget, [hive_name])
        hive_item.setIcon(0, self.hive_icon)
        hive_item.setData(0, Qt.UserRole, root_key)
        self.display_registry_keys(hive_item, root_key)

    def display_registry_keys(self, parent_item, registry_key):
        subkeys = registry_key.subkeys()
        items = [QTreeWidgetItem(parent_item, [subkey.name()]) for subkey in subkeys]
        for item, subkey in zip(items, subkeys):
            item.setData(0, Qt.UserRole, subkey)
            item.setIcon(0, self.key_icon)
            self.display_registry_keys(item, subkey)
            self.display_registry_values(item, subkey)

    def display_registry_values(self, parent_key_item, registry_key):
        values = registry_key.values()
        items = [QTreeWidgetItem(parent_key_item, [value.name() or "(Default)"]) for value in
                 values]
        for item, value in zip(items, values):
            item.setData(0, Qt.UserRole, value)
            item.setIcon(0, self.value_icon)

    def display_metadata(self, registry_object):
        metadata = {
            "Name": registry_object.name(),
            "Number of Subkeys": len(registry_object.subkeys()),
            "Number of Values": len(registry_object.values()),
            "Last Modified": registry_object.timestamp().strftime("%Y-%m-%d %H:%M:%S"),
        }

        details = '<html><head/><body>'
        details += '<p style="font-size:14px; font-family: Courier New; "><b>Metadata Information</b></p>'

        for key, value in metadata.items():
            details += f'<p style="margin-left: 10px; font-size: 12px; font-family: Courier New;"><b>{key}:</b> {value}</p>'

        details += '</body></html>'

        self.metadataPanel.setHtml(details)

    def setup_table(self, values):
        self.tableWidget.clear()
        self.tableWidget.setRowCount(len(values))
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setHorizontalHeaderLabels(["Name", "Type", "Value"])

        self.tableWidget.setColumnWidth(0, 150)
        self.tableWidget.setColumnWidth(1, 150)
        self.tableWidget.setColumnWidth(2, 450)

        header = self.tableWidget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

        for i, value in enumerate(values):
            self.tableWidget.setItem(i, 0, QTableWidgetItem(value.name()))
            self.tableWidget.setItem(i, 1, QTableWidgetItem(str(value.value_type_str())))
            self.tableWidget.setItem(i, 2, QTableWidgetItem(str(value.value())))

    def display_values_in_table(self, values):
        self.setup_table(values)

    def on_item_clicked(self, item, column):
        registry_object = item.data(0, Qt.UserRole)

        if isinstance(registry_object, RegistryKey):
            self.display_metadata(registry_object)
            self.display_values_in_table(registry_object.values())

        elif isinstance(registry_object, RegistryValue):
            self.setup_table([registry_object])

    def clear(self):
        self.treeWidget.clear()
        self.metadataPanel.clear()
        self.tableWidget.clear()
