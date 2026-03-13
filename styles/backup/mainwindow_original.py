import configparser
import hashlib
import os

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QFont, QPalette, QBrush, QAction, QActionGroup
from PySide6.QtWidgets import (QMainWindow, QMenuBar, QMenu, QToolBar, QDockWidget, QTreeWidget, QTabWidget,
                               QFileDialog, QTreeWidgetItem, QTableWidget, QMessageBox, QTableWidgetItem,
                               QDialog, QVBoxLayout, QInputDialog, QDialogButtonBox, QHeaderView, QLabel, QLineEdit,
                               QFormLayout, QApplication)

from managers.database_manager import DatabaseManager
from managers.evidence_utils import ImageHandler
from managers.image_manager import ImageManager
from modules.about import AboutDialog
from modules.acquire_dialog import AcquireDialog
from modules.converter import Main
from modules.exif_tab import ExifViewer
from modules.file_carving import FileCarvingWidget
from modules.hex_tab import HexViewer
from modules.list_files import FileSearchWidget
from modules.metadata_tab import MetadataViewer
from modules.registry import RegistryExtractor
from modules.report_generator_dialog import ReportGeneratorDialog
from modules.text_tab import TextViewer
from modules.unified_application_manager import UnifiedViewer
from modules.verification import VerificationWidget
from modules.veriphone_api import VeriphoneWidget
from modules.virus_total_tab import VirusTotal
from modules.priority_tab import PriorityTab
from modules.case_audit_tab import CaseAuditTab
from ui.mindmap import MindMapWidget

SECTOR_SIZE = 512


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.image_mounted = False
        self.current_offset = None
        self.current_image_path = None
        self.image_handler = None
        self.image_manager = ImageManager()
        self.db_manager = DatabaseManager('tools/new_database_mappings.db')
        self.current_selected_data = None
        self.current_file_content = None

        self.evidence_files = []

        self.image_manager.operationCompleted.connect(
            lambda success, message: (
                QMessageBox.information(self, "Image Operation", message) if success else QMessageBox.critical(self,
                                                                                                               "Image "
                                                                                                               "Operation",
                                                                                                               message),
                setattr(self, "image_mounted", not self.image_mounted) if success else None)[1])

        self.api_keys = configparser.ConfigParser()
        self.api_keys.read('config.ini')

        self.initialize_ui()

    def initialize_ui(self):
        self.setWindowTitle('ForensAI 1.0.0')
        self.setWindowIcon(QIcon('Icons/logo.ico'))

        if os.name == 'nt':
            import ctypes
            myappid = 'ForensAI'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

        self.setGeometry(100, 100, 1200, 800)

        menu_bar = QMenuBar(self)
        file_actions = {
            'Add Evidence File': self.load_image_evidence,
            'Remove Evidence File': self.remove_image_evidence,
            'Image Mounting': self.image_manager.mount_image,
            'Image Unmounting': self.image_manager.dismount_image,
            'separator': None,
            'Exit': self.close
        }

        self.create_menu(menu_bar, 'File', file_actions)

        view_menu = QMenu('View', self)

        full_screen_action = QAction("Full Screen", self)
        full_screen_action.triggered.connect(self.showFullScreen)
        view_menu.addAction(full_screen_action)

        normal_screen_action = QAction("Normal Screen", self)
        normal_screen_action.triggered.connect(self.showNormal)
        view_menu.addAction(normal_screen_action)

        view_menu.addSeparator()

        theme_group = QActionGroup(self)
        theme_group.setExclusive(True)

        light_theme_action = QAction("Light Mode", self)
        light_theme_action.setCheckable(True)
        light_theme_action.setChecked(True)
        light_theme_action.triggered.connect(lambda: self.apply_stylesheet('light'))
        theme_group.addAction(light_theme_action)
        view_menu.addAction(light_theme_action)

        dark_theme_action = QAction("Dark Mode", self)
        dark_theme_action.setCheckable(True)
        dark_theme_action.triggered.connect(lambda: self.apply_stylesheet('dark'))
        theme_group.addAction(dark_theme_action)
        view_menu.addAction(dark_theme_action)

        menu_bar.addMenu(view_menu)

        self.apply_stylesheet('light')

        tools_menu = QMenu('Tools', self)

        acquire_action = QAction("Acquire Physical Disk", self)
        acquire_action.triggered.connect(self.show_acquire_dialog)
        tools_menu.addAction(acquire_action)

        tools_menu.addSeparator()

        verify_image_action = QAction("Verify Image", self)
        verify_image_action.triggered.connect(self.verify_image)
        tools_menu.addAction(verify_image_action)

        conversion_action = QAction("Convert E01 to DD/RAW", self)
        conversion_action.triggered.connect(self.show_conversion_widget)
        tools_menu.addAction(conversion_action)

        tools_menu.addSeparator()

        report_generator_action = QAction("Generate Forensic Report", self)
        report_generator_action.triggered.connect(self.show_report_generator_dialog)
        tools_menu.addAction(report_generator_action)

        tools_menu.addSeparator()

        veriphone_api_action = QAction("Veriphone API", self)
        veriphone_api_action.triggered.connect(self.show_veriphone_widget)
        tools_menu.addAction(veriphone_api_action)

        help_menu = QMenu('Help', self)
        help_menu.addAction("About")
        help_menu.triggered.connect(lambda: AboutDialog(self).exec_())

        options_menu = QMenu('Options', self)
        api_key_action = QAction("API Keys", self)
        api_key_action.triggered.connect(self.show_api_key_dialog)
        options_menu.addAction(api_key_action)

        menu_bar.addMenu(view_menu)
        menu_bar.addMenu(tools_menu)
        menu_bar.addMenu(help_menu)
        menu_bar.addMenu(options_menu)

        self.setMenuBar(menu_bar)

        self.main_toolbar = QToolBar('Main Toolbar', self)
        self.main_toolbar.setToolTip("Main Toolbar")

        load_image_action = QAction(QIcon('Icons/icons8-evidence-48.png'), "Load Image", self)
        load_image_action.triggered.connect(self.load_image_evidence)
        self.main_toolbar.addAction(load_image_action)

        remove_image_action = QAction(QIcon('Icons/icons8-evidence-96.png'), "Remove Image", self)
        remove_image_action.triggered.connect(self.remove_image_evidence)
        self.main_toolbar.addAction(remove_image_action)

        self.main_toolbar.addSeparator()

        self.verify_image_button = QAction(QIcon('Icons/icons8-verify-blue.png'), "Verify Image", self)
        self.verify_image_button.triggered.connect(self.verify_image)
        self.main_toolbar.addAction(self.verify_image_button)

        self.main_toolbar.addSeparator()

        self.mount_image_button = QAction(QIcon('Icons/devices/icons8-hard-disk-48.png'), "Mount Image", self)
        self.mount_image_button.triggered.connect(self.image_manager.mount_image)
        self.main_toolbar.addAction(self.mount_image_button)

        self.unmount_image_button = QAction(QIcon('Icons/devices/icons8-hard-disk-48_red.png'), "Unmount Image",
                                            self)
        self.unmount_image_button.triggered.connect(self.image_manager.dismount_image)
        self.main_toolbar.addAction(self.unmount_image_button)

        self.addToolBar(Qt.TopToolBarArea, self.main_toolbar)

        self.tree_viewer = QTreeWidget(self)
        self.tree_viewer.setIconSize(QSize(16, 16))
        self.tree_viewer.setHeaderHidden(True)
        self.tree_viewer.itemExpanded.connect(self.on_item_expanded)
        self.tree_viewer.itemClicked.connect(self.on_item_clicked)
        self.tree_viewer.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_viewer.customContextMenuRequested.connect(self.open_tree_context_menu)

        tree_dock = QDockWidget('Tree View', self)

        tree_dock.setWidget(self.tree_viewer)
        self.addDockWidget(Qt.LeftDockWidgetArea, tree_dock)

        self.result_viewer = QTabWidget(self)
        self.setCentralWidget(self.result_viewer)

        self.listing_table = QTableWidget()
        self.listing_table.setSortingEnabled(True)
        self.listing_table.verticalHeader().setVisible(False)

        self.listing_table.setAlternatingRowColors(True)
        self.listing_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.listing_table.setIconSize(QSize(24, 24))
        self.listing_table.setColumnCount(8)

        header = self.listing_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        header.setSectionResizeMode(7, QHeaderView.Stretch)

        self.listing_table.setHorizontalHeaderLabels(
            ['Name', 'Inode', 'Type', 'Size', 'Created Date', 'Accessed Date', 'Modified Date', 'Changed Date']
        )

        self.listing_table.itemDoubleClicked.connect(self.on_listing_table_item_clicked)
        self.listing_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.listing_table.customContextMenuRequested.connect(self.open_listing_context_menu)
        self.listing_table.setSelectionBehavior(QTableWidget.SelectRows)

        palette = self.listing_table.palette()
        palette.setBrush(QPalette.Highlight, QBrush(Qt.lightGray))
        self.listing_table.setPalette(palette)

        header = self.listing_table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft)

        self.result_viewer.addTab(self.listing_table, 'Listing')

        self.deleted_files_widget = FileCarvingWidget(self)
        self.result_viewer.addTab(self.deleted_files_widget, 'Deleted Files')

        self.registry_extractor_widget = RegistryExtractor(self.image_handler)
        self.result_viewer.addTab(self.registry_extractor_widget, 'Registry')

        self.file_search_widget = FileSearchWidget(self.image_handler)
        self.result_viewer.addTab(self.file_search_widget, 'File Search')

        self.mindmap_widget = MindMapWidget()
        self.result_viewer.addTab(self.mindmap_widget, 'Mind Map')

        self.priority_widget = PriorityTab(self)
        self.result_viewer.addTab(self.priority_widget, 'Priority')

        self.case_audit_widget = CaseAuditTab(self)
        self.result_viewer.addTab(self.case_audit_widget, 'Case Audit')

        self.viewer_tab = QTabWidget(self)

        self.hex_viewer = HexViewer(self)
        self.viewer_tab.addTab(self.hex_viewer, 'Hex')

        self.text_viewer = TextViewer(self)
        self.viewer_tab.addTab(self.text_viewer, 'Text')

        self.application_viewer = UnifiedViewer(self)
        self.application_viewer.layout.setContentsMargins(0, 0, 0, 0)
        self.application_viewer.layout.setSpacing(0)
        self.viewer_tab.addTab(self.application_viewer, 'Application')

        self.metadata_viewer = MetadataViewer(self.image_handler)
        self.viewer_tab.addTab(self.metadata_viewer, 'File Metadata')

        self.exif_viewer = ExifViewer(self)
        self.viewer_tab.addTab(self.exif_viewer, 'Exif Data')

        self.virus_total_api = VirusTotal()
        self.viewer_tab.addTab(self.virus_total_api, 'Virus Total API')

        virus_total_key = self.api_keys.get('API_KEYS', 'virustotal', fallback='')
        self.virus_total_api.set_api_key(virus_total_key)

        self.viewer_dock = QDockWidget('Utils', self)
        self.viewer_dock.setWidget(self.viewer_tab)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.viewer_dock)

        self.viewer_dock.setMinimumSize(1200, 222)
        self.viewer_dock.setMaximumSize(1200, 222)
        self.viewer_dock.visibilityChanged.connect(self.on_viewer_dock_focus)
        self.viewer_tab.currentChanged.connect(self.display_content_for_active_tab)

        self.enable_tabs(False)

    def apply_stylesheet(self, theme='light'):
        if theme == 'dark':
            qss_file = 'styles/dark_theme.qss'
        else:
            qss_file = 'styles/light_theme.qss'

        try:
            with open(qss_file, 'r') as f:
                stylesheet = f.read()
            QApplication.instance().setStyleSheet(stylesheet)
        except Exception as e:
            print(f"Error loading stylesheet {qss_file}: {e}")

    def show_api_key_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("API Key Configuration")
        dialog.setFixedWidth(600)

        layout = QFormLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)

        groq_label = QLabel("Groq API Key (AI Analysis):")
        groq_input = QLineEdit()
        groq_input.setText(self.api_keys.get('API_KEYS', 'groq', fallback=''))
        groq_input.setMinimumWidth(400)
        groq_input.setPlaceholderText("Get free key at console.groq.com")
        layout.addRow(groq_label, groq_input)

        virus_total_label = QLabel("VirusTotal API Key:")
        virus_total_input = QLineEdit()
        virus_total_input.setText(self.api_keys.get('API_KEYS', 'virustotal', fallback=''))
        virus_total_input.setMinimumWidth(400)
        layout.addRow(virus_total_label, virus_total_input)

        veriphone_label = QLabel("Veriphone API Key:")
        veriphone_input = QLineEdit()
        veriphone_input.setText(self.api_keys.get('API_KEYS', 'veriphone', fallback=''))
        veriphone_input.setMinimumWidth(400)
        layout.addRow(veriphone_label, veriphone_input)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(
            lambda: self.save_api_keys(groq_input.text(), virus_total_input.text(), veriphone_input.text(), dialog))
        button_box.rejected.connect(dialog.reject)
        layout.addRow(button_box)

        dialog.setLayout(layout)
        dialog.exec_()

    def save_api_keys(self, groq_key, virus_total_key, veriphone_key, dialog):
        if not self.api_keys.has_section('API_KEYS'):
            self.api_keys.add_section('API_KEYS')

        self.api_keys.set('API_KEYS', 'groq', groq_key)
        self.api_keys.set('API_KEYS', 'virustotal', virus_total_key)
        self.api_keys.set('API_KEYS', 'veriphone', veriphone_key)

        with open('config.ini', 'w') as config_file:
            self.api_keys.write(config_file)

        dialog.accept()

        from managers.ai_service import get_ai_service
        ai_service = get_ai_service()
        ai_service.set_api_key(groq_key)

        self.virus_total_api.set_api_key(virus_total_key)

        if hasattr(self, 'veriphone_widget'):
            self.veriphone_widget.set_api_key(veriphone_key)

    def show_acquire_dialog(self):
        """Show the acquisition dialog."""
        acquire_dialog = AcquireDialog(self)
        acquire_dialog.exec_()

    def show_conversion_widget(self):
        self.select_dialog = Main()
        self.select_dialog.show()

    def export_current_session_data(self):
        """
        Export current session data (ALL files from loaded image) for report generation.

        Recursively traverses the entire file tree to collect ALL files from ALL partitions,
        not just the currently visible folder.

        Returns:
            Dictionary with session data including files, metadata, and statistics
        """
        session_data = {
            'files': [],
            'total_files': 0,
            'total_size': 0,
            'image_path': self.current_image_path,
            'has_data': False
        }

        if not self.image_handler or not self.current_image_path:
            return session_data

        try:
            root_items_count = self.tree_viewer.topLevelItemCount()

            for i in range(root_items_count):
                root_item = self.tree_viewer.topLevelItem(i)
                item_text = root_item.text(0)

                child_count = root_item.childCount()

                if child_count > 0:
                    for j in range(child_count):
                        child_item = root_item.child(j)
                        child_data = child_item.data(0, Qt.UserRole)
                        child_text = child_item.text(0)

                        if not child_data:
                            continue

                        if child_data.get("is_unallocated"):
                            continue

                        start_offset = child_data.get("start_offset")
                        if start_offset is None:
                            continue

                        self._collect_files_recursive(
                            session_data,
                            start_offset,
                            inode=None,
                            path_prefix="",
                            partition_name=child_text
                        )
                else:
                    item_data = root_item.data(0, Qt.UserRole)

                    if not item_data:
                        continue

                    if item_data.get("is_unallocated"):
                        continue

                    start_offset = item_data.get("start_offset")
                    if start_offset is None:
                        continue

                    self._collect_files_recursive(
                        session_data,
                        start_offset,
                        inode=None,
                        path_prefix="",
                        partition_name=item_text
                    )

        except Exception as e:
            print(f"Error during session data export: {e}")

        session_data['total_files'] = len(session_data['files'])
        session_data['has_data'] = session_data['total_files'] > 0

        return session_data

    def _collect_files_recursive(self, session_data, start_offset, inode, path_prefix, partition_name=""):
        """
        Recursively collect all files from a directory tree.

        Args:
            session_data: Dictionary to store collected files
            start_offset: Partition offset
            inode: Inode number of current directory (None for root)
            path_prefix: Current path prefix for building full paths
            partition_name: Name of the partition for debug output
        """
        try:
            entries = self.image_handler.get_directory_contents(start_offset, inode)

            for entry in entries:
                entry_name = entry.get("name", "")

                if entry_name in [".", ".."]:
                    continue

                full_path = f"{path_prefix}/{entry_name}" if path_prefix else entry_name

                if entry.get("is_directory"):
                    self._collect_files_recursive(
                        session_data,
                        start_offset,
                        entry.get("inode_number"),
                        full_path,
                        partition_name
                    )
                else:
                    file_info = {
                        'name': full_path,
                        'inode': str(entry.get("inode_number", "")),
                        'type': entry.get("type", ""),
                        'size': str(entry.get("size", 0)),
                        'created': entry.get("created", ""),
                        'accessed': entry.get("accessed", ""),
                        'modified': entry.get("modified", ""),
                        'changed': entry.get("changed", "")
                    }

                    try:
                        size_bytes = int(entry.get("size", 0))
                    except:
                        size_bytes = 0

                    file_info['size_bytes'] = size_bytes
                    session_data['files'].append(file_info)
                    session_data['total_size'] += size_bytes

        except Exception as e:
            pass

    def show_report_generator_dialog(self):
        """Show the forensic report generator dialog."""
        current_image = self.current_image_path if hasattr(self, 'current_image_path') else None

        session_data = self.export_current_session_data()

        report_dialog = ReportGeneratorDialog(
            self,
            current_image_path=current_image,
            session_data=session_data
        )
        report_dialog.exec_()

    def show_veriphone_widget(self):
        if not hasattr(self, 'veriphone_widget'):
            self.veriphone_widget = VeriphoneWidget()
            veriphone_key = self.api_keys.get('API_KEYS', 'veriphone', fallback='')
            self.veriphone_widget.set_api_key(veriphone_key)
        self.veriphone_widget.show()

    def verify_image(self):
        if self.image_handler is None:
            QMessageBox.warning(self, "Verify Image", "No image is currently loaded.")
            return

        self.verification_widget = VerificationWidget(self.image_handler)
        self.verification_widget.show()

        if self.verification_widget.is_verified:
            self.verify_image_button.setIcon(QIcon('Icons/icons8-verify-48_gren.png'))
        else:
            self.verify_image_button.setIcon(QIcon('Icons/icons8-verify-blue.png'))

    def enable_tabs(self, state):
        self.result_viewer.setEnabled(state)
        self.viewer_tab.setEnabled(state)
        self.listing_table.setEnabled(state)
        self.deleted_files_widget.setEnabled(state)
        self.registry_extractor_widget.setEnabled(state)

    def create_menu(self, menu_bar, menu_name, actions):
        menu = QMenu(menu_name, self)
        for action_name, action_function in actions.items():
            if action_name == 'separator':
                menu.addSeparator()
            else:
                action = menu.addAction(action_name)
                action.triggered.connect(action_function)
        menu_bar.addMenu(menu)
        return menu

    @staticmethod
    def create_tree_item(parent, text, icon_path, data):
        item = QTreeWidgetItem(parent)
        item.setText(0, text)
        item.setIcon(0, QIcon(icon_path))
        item.setData(0, Qt.UserRole, data)
        return item

    def on_viewer_dock_focus(self, visible):
        if visible:
            self.viewer_dock.setMaximumSize(16777215, 16777215)
        else:
            current_height = self.viewer_dock.size().height()
            self.viewer_dock.setMinimumSize(1200, current_height)
            self.viewer_dock.setMaximumSize(1200, current_height)

    def clear_ui(self):
        self.listing_table.clearContents()
        self.listing_table.setRowCount(0)
        self.clear_viewers()
        self.current_image_path = None
        self.current_offset = None
        self.image_mounted = False
        self.file_search_widget.clear()
        self.evidence_files.clear()
        self.deleted_files_widget.clear()
        self.priority_widget.clear()
        self.case_audit_widget.clear()

    def clear_viewers(self):
        self.hex_viewer.clear_content()
        self.text_viewer.clear_content()
        self.application_viewer.clear()
        self.metadata_viewer.clear()
        self.exif_viewer.clear_content()
        self.registry_extractor_widget.clear()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Exit Confirmation', 'Are you sure you want to exit?',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            if self.image_mounted:
                dismount_reply = QMessageBox.question(self, 'Dismount Image',
                                                      'Do you want to dismount the mounted image before exiting?',
                                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                                      QMessageBox.StandardButton.Yes)

                if dismount_reply == QMessageBox.StandardButton.Yes:
                    self.image_manager.dismount_image()

            event.accept()
        else:
            event.ignore()

    def load_image_evidence(self):
        """Open an image with a specific filter on Kali Linux."""
        supported_image_extensions = ["*.e01", "*.E01", "*.s01", "*.S01",
                                      "*.l01", "*.L01", "*.raw", "*.RAW",
                                      "*.img", "*.IMG", "*.dd", "*.DD",
                                      "*.iso", "*.ISO", "*.ad1", "*.AD1",
                                      "*.001", "*.s01", "*.ex01", "*.dmg",
                                      "*.sparse", "*.sparseimage"]

        file_filter = "Supported Image Files ({})".format(" ".join(supported_image_extensions))

        image_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", file_filter)

        if image_path:
            image_path = os.path.normpath(image_path)
            self.image_handler = ImageHandler(image_path)
            self.evidence_files.append(image_path)
            self.current_image_path = image_path
            self.load_partitions_into_tree(image_path)

            self.deleted_files_widget.set_image_handler(self.image_handler)
            self.registry_extractor_widget.image_handler = self.image_handler
            self.file_search_widget.image_handler = self.image_handler
            self.metadata_viewer.image_handler = self.image_handler
            self.mindmap_widget.set_image_handler(self.image_handler, start_offset=0)
            self.priority_widget.set_image_handler(self.image_handler)
            self.case_audit_widget.set_image_handler(self.image_handler)

            self.enable_tabs(True)

    def remove_image_evidence(self):
        if not self.evidence_files:
            QMessageBox.warning(self, "Remove Evidence", "No evidence is currently loaded.")
            return

        options = self.evidence_files + ["Remove All"]
        selected_option, ok = QInputDialog.getItem(self, "Remove Evidence File",
                                                   "Select an evidence file to remove or 'Remove All':",
                                                   options, 0, False)

        if ok:
            if selected_option == "Remove All":
                self.tree_viewer.invisibleRootItem().takeChildren()
                self.clear_ui()
                QMessageBox.information(self, "Remove Evidence", "All evidence files have been removed.")
            else:
                self.evidence_files.remove(selected_option)
                self.remove_from_tree_viewer(selected_option)
                self.clear_ui()
                QMessageBox.information(self, "Remove Evidence", f"{selected_option} has been removed.")
        if not self.evidence_files:
            self.clear_ui()
            self.enable_tabs(False)
            self.verify_image_button.setIcon(QIcon('Icons/icons8-verify-blue.png'))

    def remove_from_tree_viewer(self, evidence_name):
        root = self.tree_viewer.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            if item.text(0) == evidence_name:
                root.removeChild(item)
                break

    def load_partitions_into_tree(self, image_path):
        """Load partitions from an image into the tree viewer."""
        root_item_tree = self.create_tree_item(self.tree_viewer, image_path,
                                               self.db_manager.get_icon_path('device', 'media-optical'),
                                               {"start_offset": 0})

        partitions = self.image_handler.get_partitions()

        if not partitions:
            if self.image_handler.has_filesystem(0):
                self.populate_contents(root_item_tree, {"start_offset": 0})
            else:
                size_in_bytes = self.image_handler.get_size()
                readable_size = self.image_handler.get_readable_size(size_in_bytes)
                unallocated_item_text = f"Unallocated Space: Size: {readable_size}"
                self.create_tree_item(root_item_tree, unallocated_item_text,
                                      self.db_manager.get_icon_path('file', 'unknown'),
                                      {"is_unallocated": True, "start_offset": 0,
                                       "end_offset": size_in_bytes // SECTOR_SIZE})
            return

        for addr, desc, start, length in partitions:
            end = start + length - 1
            size_in_bytes = length * SECTOR_SIZE
            readable_size = self.image_handler.get_readable_size(size_in_bytes)
            fs_type = self.image_handler.get_fs_type(start)
            desc_str = desc.decode('utf-8') if isinstance(desc, bytes) else desc
            item_text = f"vol{addr} ({desc_str}: {start}-{end}, Size: {readable_size}, FS: {fs_type})"
            icon_path = self.db_manager.get_icon_path('device', 'drive-harddisk')
            data = {"inode_number": None, "start_offset": start, "end_offset": end}
            item = self.create_tree_item(root_item_tree, item_text, icon_path, data)

            special_partitions = ["Primary Table", "Safety Table", "GPT Header"]
            is_special = any(special_case in desc_str for special_case in special_partitions)
            is_unallocated = "Unallocated" in desc_str or "Microsoft reserved" in desc_str

            if is_special:
                item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)
            elif is_unallocated:
                item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                self.create_tree_item(item, f"Unallocated Space: Size: {readable_size}",
                                      self.db_manager.get_icon_path('file', 'unknown'),
                                      {"is_unallocated": True, "start_offset": start, "end_offset": end})
            else:
                if self.image_handler.check_partition_contents(start):
                    item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
                else:
                    item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)

    def populate_contents(self, item, data, inode=None):
        if self.current_image_path is None:
            return

        entries = self.image_handler.get_directory_contents(data["start_offset"], inode)

        for entry in entries:
            child_item = QTreeWidgetItem(item)
            child_item.setText(0, entry["name"])

            if entry["is_directory"]:
                sub_entries = self.image_handler.get_directory_contents(data["start_offset"], entry["inode_number"])
                has_sub_entries = bool(sub_entries)

                self.populate_item(child_item, entry["name"], entry["inode_number"], data["start_offset"],
                                   is_directory=True)
                child_item.setChildIndicatorPolicy(
                    QTreeWidgetItem.ShowIndicator if has_sub_entries else QTreeWidgetItem.DontShowIndicatorWhenChildless)
            else:
                self.populate_item(child_item, entry["name"], entry["inode_number"], data["start_offset"],
                                   is_directory=False)

    def populate_item(self, child_item, entry_name, inode_number, start_offset, is_directory):
        if is_directory:
            icon_key = 'folder'
        else:
            file_extension = entry_name.split('.')[-1].lower() if '.' in entry_name else 'unknown'
            icon_key = file_extension

        icon_path = self.db_manager.get_icon_path('folder' if is_directory else 'file', icon_key)

        child_item.setIcon(0, QIcon(icon_path))
        child_item.setData(0, Qt.UserRole, {
            "inode_number": inode_number,
            "type": 'directory' if is_directory else 'file',
            "start_offset": start_offset,
            "name": entry_name
        })

    def on_item_expanded(self, item):
        if item.childCount() > 0:
            return

        data = item.data(0, Qt.UserRole)
        if data is None:
            return

        if data.get("inode_number") is None:
            self.populate_contents(item, data)
        else:
            self.populate_contents(item, data, data.get("inode_number"))

    def on_item_clicked(self, item, column):
        self.clear_viewers()

        data = item.data(0, Qt.UserRole)
        self.current_selected_data = data
        self.current_file_content = None

        if data.get("is_unallocated"):
            unallocated_space = self.image_handler.read_unallocated_space(data["start_offset"], data["end_offset"])
            if unallocated_space is not None:
                self.update_viewer_with_file_content(unallocated_space, data)
            else:
                print("Invalid size for unallocated space or unable to read.")
        elif data.get("type") == "directory":
            entries = self.image_handler.get_directory_contents(data["start_offset"], data.get("inode_number"))
            self.populate_listing_table(entries, data["start_offset"])
        elif data.get("inode_number") is not None:
            file_content, _ = self.image_handler.get_file_content(data["inode_number"], data[
                "start_offset"])
            if file_content:
                self.update_viewer_with_file_content(file_content, data)
            else:
                print("Unable to read file content.")
        elif data.get("start_offset") is not None:
            entries = self.image_handler.get_directory_contents(data["start_offset"], 5)
            self.populate_listing_table(entries, data["start_offset"])
            if self.mindmap_widget and self.image_handler:
                self.mindmap_widget.set_image_handler(self.image_handler, data["start_offset"])
        else:
            print("Clicked item is not a file, directory, or unallocated space.")

        self.display_content_for_active_tab()

    def display_content_for_active_tab(self):
        if not self.current_selected_data:
            return

        if self.current_selected_data.get("is_carved"):
            if self.current_file_content:
                self.update_viewer_with_file_content(self.current_file_content, self.current_selected_data)
            return

        inode_number = self.current_selected_data.get("inode_number")
        offset = self.current_selected_data.get("start_offset", self.current_offset)

        if inode_number:
            file_content, _ = self.image_handler.get_file_content(inode_number, offset)
            if file_content:
                self.update_viewer_with_file_content(file_content, self.current_selected_data)

    def update_viewer_with_file_content(self, file_content, data):
        index = self.viewer_tab.currentIndex()
        if index == 0:
            self.hex_viewer.display_hex_content(file_content)
        elif index == 1:
            self.text_viewer.display_text_content(file_content)
        elif index == 2:
            full_file_path = data.get("name", "")
            self.application_viewer.display_application_content(file_content, full_file_path)
        elif index == 3:
            self.metadata_viewer.display_metadata(data)

        elif index == 4:
            self.exif_viewer.load_and_display_exif_data(file_content)
        elif index == 5:
            file_hash = hashlib.md5(file_content).hexdigest()
            self.virus_total_api.set_file_hash(file_hash)
            self.virus_total_api.set_file_content(file_content, data.get("name", ""))

    def populate_listing_table(self, entries, offset):
        self.listing_table.setRowCount(0)

        for entry in entries:
            entry_name = entry["name"]
            inode_number = entry["inode_number"]
            description = "Directory" if entry["is_directory"] else "File"
            size_in_bytes = entry["size"] if "size" in entry else 0
            readable_size = self.image_handler.get_readable_size(size_in_bytes)
            created = entry["created"] if "created" in entry else None
            accessed = entry["accessed"] if "accessed" in entry else None
            modified = entry["modified"] if "modified" in entry else None
            changed = entry["changed"] if "changed" in entry else None
            icon_name, icon_type = ('folder', 'folder') if entry["is_directory"] else (
                'file', entry_name.split('.')[-1].lower() if '.' in entry_name else 'unknown')

            self.insert_row_into_listing_table(entry_name, inode_number, description, icon_type, icon_name, offset,
                                               readable_size, created, accessed, modified, changed)

    def insert_row_into_listing_table(self, entry_name, entry_inode, description, icon_name, icon_type, offset, size,
                                      created, accessed, modified, changed):
        icon_path = self.db_manager.get_icon_path(icon_type, icon_name)
        icon = QIcon(icon_path)
        row_position = self.listing_table.rowCount()
        self.listing_table.insertRow(row_position)

        name_item = QTableWidgetItem(entry_name)
        name_item.setIcon(icon)
        name_item.setData(Qt.UserRole, {
            "inode_number": entry_inode,
            "start_offset": offset,
            "type": "directory" if icon_type == 'folder' else 'file',
            "name": entry_name,
            "size": size,
        })

        self.listing_table.setItem(row_position, 0, name_item)
        self.listing_table.setItem(row_position, 1, QTableWidgetItem(str(entry_inode)))
        self.listing_table.setItem(row_position, 2, QTableWidgetItem(description))
        self.listing_table.setItem(row_position, 3, QTableWidgetItem(size))
        self.listing_table.setItem(row_position, 4, QTableWidgetItem(str(created)))
        self.listing_table.setItem(row_position, 5, QTableWidgetItem(str(accessed)))
        self.listing_table.setItem(row_position, 6, QTableWidgetItem(str(modified)))
        self.listing_table.setItem(row_position, 7, QTableWidgetItem(str(changed)))

    def on_listing_table_item_clicked(self, item):
        row = item.row()
        column = item.column()

        inode_item = self.listing_table.item(row, 1)
        inode_number = int(inode_item.text())
        data = self.listing_table.item(row, 0).data(Qt.UserRole)

        self.current_selected_data = data
        self.current_file_content = None

        if data.get("type") == "directory":
            entries = self.image_handler.get_directory_contents(data["start_offset"], inode_number)
            self.populate_listing_table(entries, data["start_offset"])
        else:
            file_content, metadata = self.image_handler.get_file_content(inode_number, data["start_offset"])
            if file_content:
                self.update_viewer_with_file_content(file_content, data)

        self.display_content_for_active_tab()

    def open_listing_context_menu(self, position):
        indexes = self.listing_table.selectedIndexes()
        if indexes:
            selected_item = self.listing_table.item(indexes[0].row(),
                                                    0)
            data = selected_item.data(Qt.UserRole)
            menu = QMenu()

            export_action = menu.addAction("Export")
            export_action.triggered.connect(lambda: self.export_item_from_table(data))

            menu.exec_(self.listing_table.viewport().mapToGlobal(position))

    def export_item_from_table(self, data):
        dest_dir = QFileDialog.getExistingDirectory(self, "Select Destination Directory")
        if dest_dir:
            if data.get("type") == "directory":
                self.export_directory(data["inode_number"], data["start_offset"], dest_dir, data["name"])
            else:
                self.export_file(data["inode_number"], data["start_offset"], dest_dir, data["name"])

    def open_tree_context_menu(self, position):
        indexes = self.tree_viewer.selectedIndexes()
        if indexes:
            selected_item = self.tree_viewer.itemFromIndex(indexes[0])
            menu = QMenu()

            if selected_item and selected_item.parent() is None:
                view_os_info_action = menu.addAction("View Image Information")
                view_os_info_action.triggered.connect(lambda: self.view_os_information(indexes[0]))

            export_action = menu.addAction("Export")
            export_action.triggered.connect(self.export_item)

            menu.exec_(self.tree_viewer.viewport().mapToGlobal(position))

    def export_item(self):
        indexes = self.tree_viewer.selectedIndexes()
        if indexes:
            selected_item = self.tree_viewer.itemFromIndex(indexes[0])
            data = selected_item.data(0, Qt.UserRole)
            dest_dir = QFileDialog.getExistingDirectory(self, "Select Destination Directory")
            if dest_dir:
                if data.get("type") == "directory":
                    self.export_directory(data["inode_number"], data["start_offset"], dest_dir, selected_item.text(0))
                else:
                    self.export_file(data["inode_number"], data["start_offset"], dest_dir, selected_item.text(0))

    def export_directory(self, inode_number, offset, dest_dir, dir_name):
        new_dest_dir = os.path.join(dest_dir, dir_name)
        os.makedirs(new_dest_dir, exist_ok=True)
        entries = self.image_handler.get_directory_contents(offset, inode_number)
        for entry in entries:
            entry_name = entry.get("name")
            if entry["is_directory"]:
                self.export_directory(entry["inode_number"], offset, new_dest_dir, entry_name)
            else:
                self.export_file(entry["inode_number"], offset, new_dest_dir, entry_name)

    def export_file(self, inode_number, offset, dest_dir, file_name):
        file_content, _ = self.image_handler.get_file_content(inode_number, offset)
        if file_content:
            file_path = os.path.join(dest_dir, file_name)
            with open(file_path, 'wb') as f:
                f.write(file_content)

    def view_os_information(self, index):
        item = self.tree_viewer.itemFromIndex(index)
        if item is None or item.parent() is not None:
            return

        partitions = self.image_handler.get_partitions()
        table = QTableWidget()

        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Partition", "OS Information", "File System Type"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.horizontalHeader().setFont(QFont("Arial", 10, QFont.Bold))
        table.verticalHeader().setVisible(False)

        partition_icon = QIcon('Icons/devices/drive-harddisk.svg')
        os_icon = QIcon('Icons/start-here.svg')

        for row, part in enumerate(partitions):
            start_offset = part[2]
            fs_type = self.image_handler.get_fs_type(start_offset)

            os_version = None
            if fs_type == "NTFS":
                os_version = self.image_handler.get_windows_version(start_offset)

            table.insertRow(row)
            partition_item = QTableWidgetItem(f"Partition {part[0]}")
            partition_item.setIcon(partition_icon)
            os_version_item = QTableWidgetItem(os_version if os_version else "N/A")
            if os_version:
                os_version_item.setIcon(os_icon)
            fs_type_item = QTableWidgetItem(fs_type or "Unrecognized")

            table.setItem(row, 0, partition_item)
            table.setItem(row, 1, os_version_item)
            table.setItem(row, 2, fs_type_item)

        table.resizeRowsToContents()
        table.resizeColumnsToContents()

        dialog = QDialog(self)
        dialog.setWindowTitle("OS and File System Information")
        dialog.resize(460, 320)
        layout = QVBoxLayout(dialog)
        layout.addWidget(table)

        buttonBox = QDialogButtonBox(QDialogButtonBox.Ok)
        buttonBox.accepted.connect(dialog.accept)
        layout.addWidget(buttonBox)

        dialog.exec_()
