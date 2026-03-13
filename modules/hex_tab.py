"""
Hex viewer tab for low-level binary inspection of forensic artifacts.

Provides paginated hex display, byte-level search (text and hex patterns),
offset navigation, and file export for selected evidence files.
"""

import os
from functools import lru_cache

from PySide6.QtCore import Qt, QObject, Signal, QThread
from PySide6.QtGui import QAction, QIcon, QFont, QResizeEvent
from PySide6.QtWidgets import (QToolBar, QLabel, QMessageBox, QWidget, QVBoxLayout,
                               QLineEdit, QTableWidget, QHeaderView, QTableWidgetItem, QListWidget,
                               QSizePolicy, QFrame, QApplication, QMenu, QAbstractItemView, QFileDialog,
                               QToolButton, QComboBox, QSplitter)


class SearchWorker(QObject):
    search_finished = Signal(list)

    def __init__(self, hex_viewer_manager, query):
        super().__init__()
        self.hex_viewer_manager = hex_viewer_manager
        self.query = query

    def run(self):
        matches = self.hex_viewer_manager.search(self.query)
        self.search_finished.emit(matches)


class HexViewerManager:
    LINES_PER_PAGE = 1024

    def __init__(self, hex_content, byte_content):
        self.hex_content = hex_content
        self.byte_content = byte_content
        self.num_total_pages = (len(hex_content) // 32) // self.LINES_PER_PAGE
        if (len(hex_content) // 32) % self.LINES_PER_PAGE:
            self.num_total_pages += 1

    @lru_cache(maxsize=None)
    def format_hex(self, page=0):
        start_index = page * self.LINES_PER_PAGE * 32
        end_index = start_index + (self.LINES_PER_PAGE * 32)
        lines = []
        chunk_starts = range(start_index, end_index, 32)
        for start in chunk_starts:
            if start >= len(self.hex_content):
                break
            lines.append(self.format_hex_chunk(start))
        return '\n'.join(lines)

    def format_hex_chunk(self, start):
        hex_part = []
        ascii_repr = []
        for j in range(start, start + 32, 2):
            chunk = self.hex_content[j:j + 2]
            if not chunk:
                break
            chunk_int = int(chunk, 16)
            hex_part.append(chunk.upper())
            ascii_repr.append(chr(chunk_int) if 32 <= chunk_int <= 126 else '.')
        hex_line = ' '.join(hex_part)
        padding = ' ' * (48 - len(hex_line))
        ascii_line = ''.join(ascii_repr)
        line = f'0x{start // 2:08x}: {hex_line}{padding}  {ascii_line}'
        return line

    def total_pages(self):
        return self.num_total_pages

    def search(self, query):
        if all(part.isalnum() or part.isspace() for part in query.split()):
            try:
                query_bytes = bytes.fromhex(query.replace(" ", ""))
                return self.search_by_hex(query_bytes)
            except ValueError:
                pass

        if query.startswith("0x"):
            return self.search_by_address(query)
        else:
            return self.search_by_string(query)

    def search_by_address(self, address):
        """Searches for the line that contains the given address (offset)"""
        try:
            address_int = int(address, 16)
            line_number = address_int // 16
            if 0 <= line_number < len(self.byte_content) // 16:
                return [line_number]
            else:
                return []
        except ValueError:
            return []

    def search_by_string(self, query):
        matches = []
        query_bytes = query.encode('utf-8')

        start = 0
        while start < len(self.byte_content):
            position = self.byte_content.find(query_bytes, start)
            if position == -1:
                break
            start = position + 1
            line_number = position // 16
            matches.append(line_number)

        return matches

    def search_by_hex(self, hex_query):
        if all(part.isalnum() for part in hex_query.split()):
            try:
                query_bytes = bytes.fromhex(hex_query.replace(" ", ""))
            except ValueError:
                return []
        else:
            return []

        matches = []
        start = 0
        while start < len(self.byte_content):
            position = self.byte_content[start:].find(query_bytes)
            if position == -1:
                break
            start += position
            line_number = start // 16
            matches.append(line_number)
            start += len(query_bytes)
        return matches


class HexViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.hex_viewer_manager = None
        self.current_page = 0

        self.context_menu = QMenu(self)
        self.copy_action = QAction("Copy", self)
        self.copy_action.triggered.connect(self.copy_to_clipboard)
        self.context_menu.addAction(self.copy_action)

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

        self.initialize_ui()

    def show_context_menu(self, pos):
        self.context_menu.exec_(self.mapToGlobal(pos))

    def copy_to_clipboard(self):
        selected_text = ""

        selected_indexes = self.hex_table.selectedIndexes()
        if selected_indexes:
            selected_indexes.sort(key=lambda index: index.row())

            for i, index in enumerate(selected_indexes):
                selected_text += index.data(Qt.DisplayRole)

                if index.column() == 16:
                    selected_text += "\n"
                else:
                    next_index = selected_indexes[i + 1] if i + 1 < len(selected_indexes) else None

                    if next_index and next_index.row() == index.row():
                        selected_text += " "

        if selected_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(selected_text)

    def initialize_ui(self):
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.layout.setAlignment(Qt.AlignCenter)

        self.setup_toolbar()
        self.layout.addWidget(self.toolbar)

        self.splitter = QSplitter(Qt.Horizontal, self)

        self.setup_hex_table()
        self.hex_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.splitter.addWidget(self.hex_table)

        self.search_results_layout = QVBoxLayout()

        self.search_results_frame = QFrame(self)
        self.search_results_frame.setMaximumWidth(210)
        self.search_results_frame.setStyleSheet(" border-radius: 2px; padding: 2px;")
        self.search_results_frame.setSizePolicy(QSizePolicy.Fixed,
                                                QSizePolicy.Expanding)

        self.search_results_title = QLabel("Search Results", self.search_results_frame)
        self.search_results_title.setAlignment(Qt.AlignCenter)
        self.search_results_layout.addWidget(self.search_results_title)

        self.search_results_widget = QListWidget(self.search_results_frame)
        self.search_results_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.search_results_widget.itemClicked.connect(self.search_result_clicked)

        self.search_results_widget.setMaximumWidth(180)
        self.search_results_layout.addWidget(self.search_results_widget)

        self.search_results_frame.setLayout(self.search_results_layout)

        self.splitter.addWidget(self.search_results_frame)

        self.splitter.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.layout.addWidget(self.splitter)

        self.setLayout(self.layout)

    def resizeEvent(self, event: QResizeEvent):
        """Handle window resizing to update layout."""
        total_width = event.size().width()
        total_height = event.size().height()

        self.splitter.setSizes([int(total_width * 0.75), int(total_width * 0.25)])

        super().resizeEvent(event)


    def setup_toolbar(self):
        self.toolbar = QToolBar(self)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setMovable(False)
        self.toolbar.setContextMenuPolicy(Qt.PreventContextMenu)

        self.first_action = QAction(QIcon("Icons/icons8-thick-arrow-pointing-up-50.png"), "First", self)
        self.first_action.triggered.connect(self.load_first_page)
        self.toolbar.addAction(self.first_action)

        self.prev_action = QAction(QIcon("Icons/icons8-left-arrow-50.png"), "Previous", self)
        self.prev_action.triggered.connect(self.previous_page)
        self.toolbar.addAction(self.prev_action)

        self.page_entry = QLineEdit(self)
        self.page_entry.setMaximumWidth(40)
        self.page_entry.setPlaceholderText("1")
        self.page_entry.returnPressed.connect(self.go_to_page_by_entry)
        self.toolbar.addWidget(self.page_entry)

        self.total_pages_label = QLabel(" of ")
        self.toolbar.addWidget(self.total_pages_label)

        self.next_action = QAction(QIcon("Icons/icons8-right-arrow-50.png"), "Next", self)
        self.next_action.triggered.connect(self.next_page)
        self.toolbar.addAction(self.next_action)

        self.last_action = QAction(QIcon("Icons/icons8-down-50.png"), "Last", self)
        self.last_action.triggered.connect(self.load_last_page)
        self.toolbar.addAction(self.last_action)

        spacer = QWidget(self)
        spacer.setFixedSize(50, 0)
        self.toolbar.addWidget(spacer)

        self.toolbar.addWidget(QLabel("Font Size: "))

        self.font_size_combobox = QComboBox(self)
        self.font_size_combobox.addItems(["8", "10", "12", "14", "16", "18", "20", "24", "28", "32", "36"])
        self.font_size_combobox.currentTextChanged.connect(self.update_font_size)
        self.toolbar.addWidget(self.font_size_combobox)

        spacer = QWidget(self)
        spacer.setFixedSize(50, 0)
        self.toolbar.addWidget(spacer)

        self.export_button = QToolButton(self)
        self.export_button.setObjectName("exportButton")
        self.export_button.setText("Export")
        self.export_button.setPopupMode(QToolButton.MenuButtonPopup)

        self.export_menu = QMenu(self)

        self.text_format_action = QAction("Text (.txt)", self)
        self.text_format_action.triggered.connect(lambda: self.export_content("txt"))
        self.export_menu.addAction(self.text_format_action)

        self.html_format_action = QAction("HTML (.html)", self)
        self.html_format_action.triggered.connect(lambda: self.export_content("html"))
        self.export_menu.addAction(self.html_format_action)

        self.export_button.setMenu(self.export_menu)
        self.toolbar.addWidget(self.export_button)

        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

        self.search_bar = QLineEdit(self)
        self.search_bar.setMaximumWidth(200)
        self.search_bar.setFixedHeight(35)
        self.search_bar.setContentsMargins(10, 0, 10, 0)
        self.search_bar.setPlaceholderText("Search...")
        self.search_bar.returnPressed.connect(self.trigger_search)
        self.toolbar.addWidget(self.search_bar)

    def update_font_size(self):
        selected_size = int(self.font_size_combobox.currentText())

        current_font = self.hex_table.font()
        current_font.setPointSize(selected_size)
        self.hex_table.setFont(current_font)

        address_width = selected_size * 10
        byte_width = selected_size * 3
        ascii_width = selected_size * 8

        self.hex_table.setColumnWidth(0, address_width)
        for i in range(1, 17):
            self.hex_table.setColumnWidth(i, byte_width)
        self.hex_table.setColumnWidth(17, ascii_width)

        header_font = self.hex_table.horizontalHeader().font()
        header_font.setPointSize(selected_size)
        self.hex_table.horizontalHeader().setFont(header_font)

        if self.hex_table.horizontalHeader().length() > self.hex_table.viewport().width():
            self.hex_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        else:
            self.hex_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

    def setup_hex_table(self):
        self.hex_table = QTableWidget()

        font = QFont("Courier")
        font.setLetterSpacing(QFont.AbsoluteSpacing, 2)
        self.hex_table.setFont(font)

        self.hex_table.setColumnCount(18)
        self.hex_table.setHorizontalHeaderLabels(['Address'] + [f'{i:02X}' for i in range(16)] + ['ASCII'])
        self.hex_table.verticalHeader().setVisible(False)

        header = self.hex_table.horizontalHeader()

        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)

        for i in range(1, 17):
            header.setSectionResizeMode(i, QHeaderView.Fixed)
            self.hex_table.setColumnWidth(i, 35)

        header.setSectionResizeMode(17, QHeaderView.Stretch)

        header.setStretchLastSection(True)

        self.hex_table.setColumnWidth(0, 150)
        self.hex_table.setColumnWidth(17, 250)

        self.hex_table.setShowGrid(False)
        self.hex_table.setAlternatingRowColors(True)
        self.hex_table.setEditTriggers(QAbstractItemView.NoEditTriggers)

    def display_hex_content(self, file_content):
        hex_content = file_content.hex()
        self.search_results_widget.clear()

        self.search_bar.setText("")
        self.hex_viewer_manager = HexViewerManager(hex_content, file_content)
        self.update_navigation_states()
        self.display_current_page()
        self.page_entry.setText("")

    def export_content(self, selected_format):
        if not self.hex_viewer_manager:
            QMessageBox.warning(self, "No Content", "No content available to export.")
            return

        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly

        if selected_format == "txt":
            file_name, _ = QFileDialog.getSaveFileName(
                self, "Export Hex Content", "", "Text Files (*.txt)", options=options
            )
            self.export_as_text(file_name)
        elif selected_format == "html":
            file_name, _ = QFileDialog.getSaveFileName(
                self, "Export Hex Content", "", "HTML Files (*.html)", options=options
            )
            self.export_as_html(file_name)
        else:
            QMessageBox.warning(self, "Unsupported Format", "Unsupported export format selected.")

    def export_as_text(self, file_name):
        with open(file_name, "w") as text_file:
            header_line = "Address     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F        ASCII"
            text_file.write(header_line + "\n")

            text_file.write("\n")

            formatted_hex = self.hex_viewer_manager.format_hex(self.current_page)
            text_file.write(formatted_hex)

    def export_as_html(self, file_name):
        html_content = "<html><body>\n"
        html_content += "<pre>\n"

        header_line = '<div style="font-size:14px; color:#888;">Generated by ForensAI</div>'
        html_content += header_line + "<br><br>\n"

        directory, filename = os.path.split(file_name)
        html_content += f'<span style="color:blue;">Directory: {directory}</span><br>\n'
        html_content += f'<span style="color:blue;">File Name: {filename}</span><br><br>\n'

        header_line = ('<span style="color:green;">Address     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F        '
                       'ASCII</span>')
        html_content += header_line + "<br>\n"

        html_content += self.hex_viewer_manager.format_hex(self.current_page).replace("\n", "<br>")
        html_content += "</pre>\n"
        html_content += "</body></html>"

        with open(file_name, "w") as html_file:
            html_file.write(html_content)

    def parse_hex_line(self, line):
        if ":" not in line:
            return None, None, None
        address, rest = line.split(":", maxsplit=1)
        hex_chunk, ascii_repr = rest.split("  ", maxsplit=1)
        return address.strip(), hex_chunk.strip(), ascii_repr.strip()

    def clear_content(self):
        self.hex_table.clear()

    def load_first_page(self):
        try:
            self.current_page = 0
            self.display_current_page()
        except (AttributeError, IndexError) as e:
            print(f"Error occurred: {e}")

    def load_last_page(self):
        try:
            self.current_page = self.hex_viewer_manager.total_pages() - 1
            self.display_current_page()
        except (AttributeError, IndexError) as e:
            print(f"Error occurred: {e}")

    def next_page(self):
        try:
            if self.current_page < self.hex_viewer_manager.total_pages() - 1:
                self.current_page += 1
            self.display_current_page()
        except (AttributeError, IndexError) as e:
            print(f"Error occurred: {e}")

    def previous_page(self):
        try:
            if self.current_page > 0:
                self.current_page -= 1
            self.display_current_page()
        except (AttributeError, IndexError) as e:
            print(f"Error occurred: {e}")

    def search_result_clicked(self, item):
        address = item.text().split(":")[1].strip()
        self.navigate_to_address(address)

    def display_current_page(self):
        formatted_hex = self.hex_viewer_manager.format_hex(self.current_page)

        self.hex_table.setRowCount(0)
        self.hex_table.setHorizontalHeaderLabels(['Address'] + [f'{i:02X}' for i in range(16)] + ['ASCII'])

        hex_lines = formatted_hex.split('\n')

        self.hex_table.setRowCount(len(hex_lines))

        for row, line in enumerate(hex_lines):
            address, hex_chunk, ascii_repr = self.parse_hex_line(line)
            if not address or not hex_chunk:
                continue

            address_item = QTableWidgetItem(address + ":")
            address_item.setTextAlignment(Qt.AlignCenter)
            self.hex_table.setItem(row, 0, address_item)

            for col, byte in enumerate(hex_chunk.split()):
                byte_item = QTableWidgetItem(byte)
                byte_item.setTextAlignment(Qt.AlignCenter)
                byte_item.setBackground(Qt.white)
                self.hex_table.setItem(row, col + 1, byte_item)

            ascii_item = QTableWidgetItem(ascii_repr)
            ascii_item.setTextAlignment(Qt.AlignCenter)
            self.hex_table.setItem(row, 17, ascii_item)

        self.update_navigation_states()

    def go_to_page_by_entry(self):
        try:
            page_num = int(self.page_entry.text()) - 1
            if 0 <= page_num < self.hex_viewer_manager.total_pages():
                self.current_page = page_num
                self.display_current_page()
                self.update_navigation_states()
            else:
                QMessageBox.warning(self, "Invalid Page", "Page number out of range.")
        except ValueError:
            QMessageBox.warning(self, "Invalid Page", "Please enter a valid page number.")

    def update_navigation_states(self):
        if not self.hex_viewer_manager:
            self.prev_action.setEnabled(False)
            self.next_action.setEnabled(False)
            return

        self.prev_action.setEnabled(self.current_page > 0)
        self.next_action.setEnabled(self.current_page < self.hex_viewer_manager.total_pages() - 1)
        self.page_entry.setText(str(self.current_page + 1))
        self.total_pages_label.setText(f"of {self.hex_viewer_manager.total_pages()}")

    def update_total_pages_label(self):
        total_pages = self.hex_viewer_manager.total_pages()
        current_page = self.current_page + 1
        self.total_pages_label.setText(f"{current_page} of {total_pages}")

    def trigger_search(self):
        query = self.search_bar.text()
        if not query:
            QMessageBox.warning(self, "Search Error", "Please enter a search query.")
            return

        if hasattr(self, 'search_thread') and self.search_thread.isRunning():
            self.search_thread.quit()
            self.search_thread.wait()

        self.search_thread = QThread()
        self.search_worker = SearchWorker(self.hex_viewer_manager, query)
        self.search_worker.moveToThread(self.search_thread)

        self.search_worker.search_finished.connect(self.handle_search_results)
        self.search_thread.started.connect(self.search_worker.run)
        self.search_thread.finished.connect(self.cleanup_thread_resources)

        self.search_thread.start()

    def cleanup_thread_resources(self):
        if hasattr(self, 'search_worker'):
            self.search_worker.deleteLater()
            del self.search_worker
        if hasattr(self, 'search_thread'):
            self.search_thread.deleteLater()
            del self.search_thread

    def closeEvent(self, event):
        if hasattr(self, 'search_thread') and self.search_thread.isRunning():
            self.search_thread.quit()
            self.search_thread.wait()
        super().closeEvent(event)

    def handle_search_results(self, matches):
        self.search_results_widget.clear()
        if matches:
            for match in matches:
                address = f"0x{match * 16:08x}"
                self.search_results_widget.addItem(f"Address: {address}")

            self.search_results_frame.setVisible(True)
            self.splitter.setSizes([self.width() * 0.6, self.width() * 0.4])

        else:
            QMessageBox.warning(self, "Search Result", "No matches found.")
            self.splitter.setSizes([self.width() * 0.75, self.width() * 0.25])

    def navigate_to_address(self, address):
        try:
            address_int = int(address, 16)

            line = address_int // 16

            self.current_page = line // self.hex_viewer_manager.LINES_PER_PAGE
            self.display_current_page()

            row_in_page = line % self.hex_viewer_manager.LINES_PER_PAGE
            self.hex_table.selectRow(row_in_page)
            for col in range(1, 17):
                item = self.hex_table.item(row_in_page, col)
                if item:
                    item.setBackground(Qt.yellow)
            self.update_navigation_states()
        except ValueError:
            QMessageBox.warning(self, "Navigation Error", "Invalid address.")
