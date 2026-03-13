"""
File listing and search widget for browsing forensic image contents.

Displays files from a loaded disk image in a filterable table with
extension-based checkboxes, keyword search, and sortable size columns.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QVBoxLayout, QTableWidget, QTableWidgetItem, QWidget, QHeaderView, \
    QGroupBox, QCheckBox, QGridLayout, QLabel, QToolBar, QLineEdit, QSpacerItem, QSizePolicy


class SizeTableWidgetItem(QTableWidgetItem):
    """Table widget item that sorts numerically by size stored in UserRole data."""

    def __lt__(self, other):
        return int(self.data(Qt.UserRole)) < int(other.data(Qt.UserRole))


class FileSearchWidget(QWidget):
    """
    Filterable file listing table for browsing disk image contents.

    Displays all files from a forensic image with columns for name, size,
    type, and timestamps. Supports extension-based filtering via checkboxes
    and keyword search across filenames.
    """

    def __init__(self, image_handler):
        super(FileSearchWidget, self).__init__()
        self.image_handler = image_handler
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.toolbar = QToolBar()
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.toolbar)

        self.icon_label = QLabel()
        self.icon_label.setPixmap(QPixmap('Icons/icons8-piece-of-evidence-50.png'))
        self.icon_label.setFixedSize(48, 48)
        self.toolbar.addWidget(self.icon_label)

        self.title_label = QLabel("File Search")
        self.title_label.setStyleSheet("""
            QLabel {
                font-size: 20px;
                color: #37c6d0;
                font-weight: bold;
                margin-left: 8px;
            }
        """)
        self.toolbar.addWidget(self.title_label)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

        self.extensionGroupBox = QGroupBox()
        self.extensionLayout = QGridLayout()

        self.fileTypes = ['', '.txt', '.jpg', '.jpeg', '.png', '.pdf', '.doc',
                          '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
        self.checkBoxes = {}

        row = 0
        col = 0
        for fileType in self.fileTypes:
            checkBox = QCheckBox(fileType if fileType else 'All')
            checkBox.stateChanged.connect(self.on_file_type_selected)
            self.extensionLayout.addWidget(checkBox, row, col)
            self.checkBoxes[fileType] = checkBox
            col += 1
            if col >= 6:
                row += 1
                col = 0

        self.extensionGroupBox.setLayout(self.extensionLayout)
        self.toolbar.addWidget(self.extensionGroupBox)

        small_spacer = QWidget()
        small_spacer.setFixedWidth(50)
        self.toolbar.addWidget(small_spacer)

        self.searchBar = QLineEdit()
        self.searchBar.setPlaceholderText("Search files by name or ext.")
        self.searchBar.textChanged.connect(self.on_search_bar_selected)
        self.searchBar.setFixedHeight(35)
        self.searchBar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.toolbar.addWidget(self.searchBar)

        end_spacer = QWidget()
        end_spacer.setFixedWidth(10)
        self.toolbar.addWidget(end_spacer)

        self.filesTable = QTableWidget()
        self.filesTable.verticalHeader().setVisible(False)

        self.filesTable.setSelectionBehavior(QTableWidget.SelectRows)
        self.filesTable.setEditTriggers(QTableWidget.NoEditTriggers)

        self.filesTable.setColumnCount(8)

        self.filesTable.setHorizontalHeaderLabels(
            ['Id', 'Name', 'Path', 'Size', 'Created', 'Accessed', 'Modified', 'Changed'])

        header = self.filesTable.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Interactive)
        header.setSectionResizeMode(4, QHeaderView.Interactive)
        header.setSectionResizeMode(5, QHeaderView.Interactive)
        header.setSectionResizeMode(6, QHeaderView.Interactive)
        header.setSectionResizeMode(7, QHeaderView.Interactive)

        self.filesTable.setColumnWidth(0, 30)
        self.filesTable.setColumnWidth(3, 70)
        self.filesTable.setColumnWidth(4, 130)
        self.filesTable.setColumnWidth(5, 130)
        self.filesTable.setColumnWidth(6, 130)
        self.filesTable.setColumnWidth(7, 130)

        layout.addWidget(self.filesTable)

        self.filesTable.resizeEvent = self.handle_resize_event

    def handle_resize_event(self, event):
        total_width = self.filesTable.width()
        remaining_width = total_width - (self.filesTable.columnWidth(0) +
                                         self.filesTable.columnWidth(3) +
                                         self.filesTable.columnWidth(4) +
                                         self.filesTable.columnWidth(5) +
                                         self.filesTable.columnWidth(6) +
                                         self.filesTable.columnWidth(7))

        self.filesTable.setColumnWidth(1, remaining_width // 2)
        self.filesTable.setColumnWidth(2, remaining_width // 2)

        super(QTableWidget, self.filesTable).resizeEvent(event)

    def on_search_bar_selected(self):
        search_query = self.searchBar.text().strip()
        if search_query:
            self.search_files(search_query)
        else:
            self.on_file_type_selected()

    def search_files(self, search_query):
        self.clear()
        files = self.image_handler.search_files(search_query)
        for file in files:
            self.populate_table_row(file)

    def on_file_type_selected(self):
        selectedExtensions = [ext for ext, cb in self.checkBoxes.items() if cb.isChecked()]
        self.list_files(None if '' in selectedExtensions else ([] if not selectedExtensions else selectedExtensions))

    def populate_table_row(self, file):
        row_pos = self.filesTable.rowCount()
        self.filesTable.insertRow(row_pos)
        self.filesTable.setItem(row_pos, 0, QTableWidgetItem(str(row_pos + 1)))
        self.filesTable.setItem(row_pos, 1, QTableWidgetItem(file['name']))
        self.filesTable.setItem(row_pos, 2, QTableWidgetItem(file['path']))
        size_item = SizeTableWidgetItem(self.image_handler.get_readable_size(file['size']))
        size_item.setData(Qt.UserRole, file['size'])
        self.filesTable.setItem(row_pos, 3, size_item)
        self.filesTable.setItem(row_pos, 4, QTableWidgetItem(file['created']))
        self.filesTable.setItem(row_pos, 5, QTableWidgetItem(file['accessed']))
        self.filesTable.setItem(row_pos, 6, QTableWidgetItem(file['modified']))
        self.filesTable.setItem(row_pos, 7, QTableWidgetItem(file['changed']))

    def list_files(self, extension):
        self.filesTable.setSortingEnabled(False)
        self.filesTable.setRowCount(0)
        self.filesTable.clearContents()
        if extension is not None and not extension:
            return
        files = self.image_handler.list_files(extension)
        for file in files:
            self.populate_table_row(file)
        self.filesTable.setSortingEnabled(True)

    def clear(self):
        self.filesTable.setRowCount(0)
        self.filesTable.clearContents()
        for checkBox in self.checkBoxes.values():
            checkBox.setChecked(False)
