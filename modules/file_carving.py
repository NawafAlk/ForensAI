import datetime
import io
import os
import struct
from concurrent.futures import ThreadPoolExecutor
import zipfile

import cv2
from PIL import Image, UnidentifiedImageError
from PyPDF2 import PdfReader
from PyPDF2.errors import PdfReadError
from PySide6.QtCore import QSize, QUrl
from PySide6.QtCore import Qt
from PySide6.QtCore import Signal, Slot
from PySide6.QtGui import QIcon, QAction, QDesktopServices, QPixmap, QPainter
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QToolBar, QSizePolicy, QHBoxLayout, \
    QCheckBox, QHeaderView
from PySide6.QtWidgets import QMenu
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QPushButton, QLabel, QTabWidget
try:
    from moviepy.editor import VideoFileClip  # moviepy 1.x
except ImportError:
    from moviepy import VideoFileClip  # moviepy 2.x
from pdf2image import convert_from_path

from managers.carving_confidence import CarvingConfidence, ConfidenceResult, CONFIDENCE_TIERS


class NumericTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        self_value = self.text().split()[0]  # Extract numeric part of the text
        other_value = other.text().split()[0]  # Extract numeric part of the text
        self_unit = self.text().split()[1]  # Extract unit part of the text
        other_unit = other.text().split()[1]  # Extract unit part of the text
        units = {'B': 0, 'KB': 1, 'MB': 2, 'GB': 3, 'TB': 4}

        # Convert to bytes for comparison
        self_bytes = float(self_value) * (1024 ** units[self_unit])
        other_bytes = float(other_value) * (1024 ** units[other_unit])

        return self_bytes < other_bytes


class FileCarvingWidget(QWidget):
    # Signal: name, size, type, modification_date, file_path, confidence_score, confidence_details
    file_carved = Signal(str, str, str, str, str, int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent  # Store reference to main window
        self.image_handler = None
        self.executor = ThreadPoolExecutor(max_workers=4)  # ThreadPoolExecutor for background tasks
        self.carved_files = []
        self.carved_file_names = set()  # Track carved file names to avoid duplicates
        self.confidence_evaluator = CarvingConfidence()  # Initialize confidence evaluator
        self.carving_stats = {'complete': 0, 'good': 0, 'partial': 0, 'damaged': 0, 'fragment': 0}
        self._stop_carving_flag = False  # Flag to signal carving should stop
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)  # Set the spacing to zero

        self.toolbar = QToolBar()
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.layout.addWidget(self.toolbar)

        self.icon_label = QLabel()
        self.icon_label.setPixmap(QPixmap('Icons/icons8-carving-64.png'))
        self.icon_label.setFixedSize(48, 48)
        self.toolbar.addWidget(self.icon_label)

        self.title_label = QLabel("File Carving")
        self.title_label.setStyleSheet("""
            QLabel {
                font-size: 20px; /* Slightly larger size for the title */
                color: #37c6d0; /* Hex color for the text */
                font-weight: bold; /* Make the text bold */
                margin-left: 8px; /* Space between icon and label */
            }
        """)
        self.toolbar.addWidget(self.title_label)

        self.spacer = QLabel()
        self.spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(self.spacer)

        self.table_widget = self.create_table_widget()
        self.table_widget.verticalHeader().setVisible(False)
        self.table_widget.resizeEvent = self.handle_resize_event

        self.list_widget = self.create_list_widget()

        self.fileTypeLayout = QHBoxLayout()
        self.fileTypes = {"All": QCheckBox("All"), "PDF": QCheckBox("PDF"), "JPG": QCheckBox("JPG"),
                          "PNG": QCheckBox("PNG"), "GIF": QCheckBox("GIF"), "WAV": QCheckBox("WAV"),
                          "MOV": QCheckBox("MOV"), "MP4": QCheckBox("MP4"), "WMV": QCheckBox("WMV"),
                          "ZIP": QCheckBox("ZIP"), 'BMP': QCheckBox("BMP"), "DOCX": QCheckBox("DOCX"),
                          "XLSX": QCheckBox("XLSX"), "PPTX": QCheckBox("PPTX")}

        for fileType, checkBox in self.fileTypes.items():
            self.fileTypeLayout.addWidget(checkBox)

        # Adding a widget to contain the file type checkboxes
        self.fileTypeWidget = QWidget()
        self.fileTypeWidget.setLayout(self.fileTypeLayout)
        self.toolbar.addWidget(self.fileTypeWidget)

        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_carving)

        self.toolbar.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_carving)
        self.stop_button.setEnabled(False)

        self.toolbar.addWidget(self.stop_button)
        self.layout.addWidget(self.tab_widget)

        # Summary bar for carving statistics
        self.summary_bar = QLabel("")
        self.summary_bar.setStyleSheet("""
            QLabel {
                background-color: #2d2d2d;
                color: #ffffff;
                padding: 8px 12px;
                font-size: 12px;
                border-top: 1px solid #444;
            }
        """)
        self.summary_bar.setVisible(False)
        self.layout.addWidget(self.summary_bar)

        self.file_carved.connect(self.display_carved_file)

    def create_table_widget(self):
        table_widget = QTableWidget()
        table_widget.setColumnCount(7)  # Id, Name, Size, Type, Confidence, Date, Path
        table_widget.setSelectionBehavior(QTableWidget.SelectRows)
        table_widget.setEditTriggers(QTableWidget.NoEditTriggers)
        table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table_widget.setSortingEnabled(True)

        # Include Confidence column
        table_widget.setHorizontalHeaderLabels(['Id', 'Name', 'Size', 'Type', 'Confidence', 'Date', 'Path'])
        table_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        table_widget.customContextMenuRequested.connect(self.open_context_menu)

        # Add click handler for file preview
        table_widget.cellClicked.connect(self.on_carved_file_clicked)

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(table_widget, "File List")
        return table_widget

    def create_list_widget(self):
        list_widget = QListWidget()
        # remove space between items
        list_widget.setViewMode(QListWidget.IconMode)

        list_widget.setIconSize(QSize(100, 100))
        list_widget.setResizeMode(QListWidget.Adjust)
        list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        list_widget.customContextMenuRequested.connect(self.open_context_menu)

        # Add click handler for file preview
        list_widget.itemClicked.connect(self.on_carved_list_item_clicked)

        toolbar = QToolBar()

        # Define actions
        action_small_size = (QAction("Small Size", self))
        action_small_size.setIcon(QIcon('Icons/icons8-small-icons-50.png'))

        action_medium_size = (QAction("Medium Size", self))
        action_medium_size.setIcon(QIcon('Icons/icons8-medium-icons-50.png'))

        action_large_size = (QAction("Large Size", self))
        action_large_size.setIcon(QIcon('Icons/icons8-large-icons-50.png'))

        # Set icons

        # Connect actions to new slot methods
        action_small_size.triggered.connect(self.set_small_size)
        action_medium_size.triggered.connect(self.set_medium_size)
        action_large_size.triggered.connect(self.set_large_size)

        # Add actions to the toolbar
        toolbar.addAction(action_small_size)
        toolbar.addAction(action_medium_size)
        toolbar.addAction(action_large_size)

        # Create a layout and add the toolbar and the list widget to it
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(toolbar)
        layout.addWidget(list_widget)

        # Create a new widget, set its layout and add it to the tab widget
        widget = QWidget()
        widget.setLayout(layout)
        self.tab_widget.addTab(widget, "Thumbnails")

        # self.tab_widget.addTab(list_widget, "Thumbnails")
        return list_widget

    def set_icon_size(self, size):
        self.list_widget.setIconSize(QSize(size, size))
        for index in range(self.list_widget.count()):
            item = self.list_widget.item(index)
            item.setSizeHint(QSize(size + 20, size + 20))  # Provide some padding around the icon

    def set_small_size(self):
        self.set_icon_size(50)

    def set_medium_size(self):
        self.set_icon_size(100)

    def set_large_size(self):
        self.set_icon_size(200)

    def start_carving(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.clear_ui()
        self.carved_files.clear()
        self.carved_file_names.clear()
        self.carving_stats = {'complete': 0, 'good': 0, 'partial': 0, 'damaged': 0, 'fragment': 0}

        # Ensure the 'carved_files' and 'thumbnails' directories exist
        if not os.path.exists("carved_files"):
            os.makedirs("carved_files")
        thumbnail_folder = os.path.join("carved_files", "thumbnails")
        if not os.path.exists(thumbnail_folder):
            os.makedirs(thumbnail_folder)

        selected_file_types = [fileType.lower() for fileType, checkbox in self.fileTypes.items() if
                               checkbox.isChecked()]
        self.executor.submit(self.carve_files, selected_file_types)

    def stop_carving(self):
        self._stop_carving_flag = True  # Set flag to signal carving should stop
        self.start_button.setEnabled(True)  # Re-enable the start button
        self.stop_button.setEnabled(False)  # Disable the stop button

    def set_image_handler(self, image_handler):
        self.image_handler = image_handler
        self.start_button.setEnabled(True)

    def open_context_menu(self, position):
        menu = QMenu()
        open_location_action = QAction("Open File Location")
        open_location_action.triggered.connect(self.open_file_location)

        open_image_action = QAction("Open Image")
        open_image_action.triggered.connect(self.open_image)

        menu.addAction(open_location_action)
        menu.addAction(open_image_action)
        menu.exec_(self.table_widget.viewport().mapToGlobal(position))

    def open_image(self):
        if self.tab_widget.currentIndex() == 0:  # If the table tab is active
            current_item = self.table_widget.currentItem()
        else:  # If the thumbnail tab is active
            current_item = self.list_widget.currentItem()

        if current_item:
            file_name = current_item.text()
            for file_info in self.carved_files:
                if file_info[0] == file_name:
                    file_path = file_info[3]  # The file path is now at index 3
                    QDesktopServices.openUrl(QUrl.fromLocalFile(file_path))
                    break

    def open_file_location(self):
        current_item = self.list_widget.currentItem()
        if current_item:
            file_name = current_item.text()
            for file_info in self.carved_files:
                if file_info[0] == file_name:
                    file_path = file_info[3]  # The file path is now at index 3
                    QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(file_path)))
                    break

    def setup_buttons(self):
        self.start_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_carving_thread)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_carving_thread)

    def start_carving_thread(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        # Launch carving in a background thread
        self.executor.submit(self.carve_files)

    def stop_carving_thread(self):
        self.executor.shutdown(wait=False)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def is_valid_file(self, data, file_type):
        """Validate file integrity and format correctness

        FORENSIC MODE: Validation DISABLED - All files are carved regardless of damage state.
        This is best practice in digital forensics to preserve all potential evidence,
        including corrupted or partially damaged files.

        Args:
            data: File content bytes
            file_type: File type string

        Returns:
            bool: Always True (validation disabled for forensic purposes)
        """
        # FORENSIC BEST PRACTICE: Always return True to carve ALL files (damaged or undamaged)
        # Corrupted files may still contain valuable evidence and should be preserved
        return True

        # Original validation code preserved but disabled:
        """
        try:
            if file_type == 'pdf':
                # Validate PDF by trying to read it with PyPDF2
                pdf = PdfReader(io.BytesIO(data))
                # Ensure it has at least one page
                if len(pdf.pages) < 1:
                    return False
                # Try to actually access the first page to ensure it's not corrupted
                try:
                    first_page = pdf.pages[0]
                    # Try to get mediabox (this will fail if page is corrupted)
                    mediabox = first_page.mediabox
                    # Verify mediabox has valid dimensions
                    if not mediabox or len(mediabox) < 4:
                        return False
                    # Try to get page content (this catches more corruption issues)
                    contents = first_page.get_contents()
                    # Try to extract text (this validates the page can be processed)
                    _ = first_page.extract_text()
                    # Check if page object is properly formed
                    if '/Type' not in first_page:
                        return False
                except (KeyError, IndexError, AttributeError, TypeError, PdfReadError, RecursionError):
                    # Page exists in structure but is corrupted/unrenderable
                    return False
                except Exception:
                    # Catch any other PDF-related errors
                    return False

            elif file_type in ['jpg', 'jpeg']:
                # Validate JPEG images
                image = Image.open(io.BytesIO(data))
                image.verify()
                # Reopen to check if we can actually load it
                image = Image.open(io.BytesIO(data))
                image.load()
                # Check for valid dimensions
                if image.width <= 0 or image.height <= 0:
                    return False

            elif file_type == 'png':
                # Validate PNG images
                image = Image.open(io.BytesIO(data))
                image.verify()
                # Check PNG signature
                if not data.startswith(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'):
                    return False
                # Check IEND chunk at end
                if not data.endswith(b'\x49\x45\x4E\x44\xAE\x42\x60\x82'):
                    return False

            elif file_type == 'gif':
                # Validate GIF images
                image = Image.open(io.BytesIO(data))
                image.verify()
                # Check GIF signature
                if not (data.startswith(b'GIF87a') or data.startswith(b'GIF89a')):
                    return False

            elif file_type == 'bmp':
                # Enhanced BMP validation
                if len(data) < 54:  # Minimum BMP header size
                    return False
                # Check BMP signature
                if not data.startswith(b'BM'):
                    return False
                # Try to open with PIL
                image = Image.open(io.BytesIO(data))
                image.verify()
                # Check dimensions
                width = int.from_bytes(data[18:22], byteorder='little')
                height = int.from_bytes(data[22:26], byteorder='little')
                if width <= 0 or width > 50000 or height <= 0 or height > 50000:
                    return False

            elif file_type == 'wav':
                # Enhanced WAV validation
                if len(data) < 44:  # Minimum WAV header size
                    return False
                # Check RIFF header
                if not data.startswith(b'RIFF'):
                    return False
                # Check WAVE format
                if data[8:12] != b'WAVE':
                    return False
                # Verify file size in header matches actual size
                file_size = int.from_bytes(data[4:8], byteorder='little') + 8
                if abs(file_size - len(data)) > 1024:  # Allow small discrepancy
                    return False

            elif file_type == 'mov':
                # MOV validation - check for valid atoms
                if len(data) < 8:
                    return False
                # MOV files should have recognizable atoms
                valid_atoms = [b'ftyp', b'moov', b'mdat', b'free', b'wide']
                # Check first atom type
                if len(data) >= 8:
                    atom_type = data[4:8]
                    if atom_type not in valid_atoms:
                        return False
                # Verify atom size is reasonable
                atom_size = int.from_bytes(data[0:4], 'big')
                if atom_size <= 0 or atom_size > len(data):
                    return False

            elif file_type == 'wmv':
                # WMV/ASF validation
                if len(data) < 30:
                    return False
                # Check ASF header GUID
                asf_header = b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C'
                if not data.startswith(asf_header):
                    return False
                # Check object size
                if len(data) >= 24:
                    object_size = int.from_bytes(data[16:24], byteorder='little')
                    if object_size <= 30 or object_size > len(data):
                        return False

            elif file_type == 'zip':
                # ZIP validation
                try:
                    zip_file = zipfile.ZipFile(io.BytesIO(data))
                    # Test ZIP integrity
                    if zip_file.testzip() is not None:
                        return False
                    # Check it has at least one file
                    if len(zip_file.namelist()) < 1:
                        return False
                except zipfile.BadZipFile:
                    return False

            else:
                return True

            return True

        except (IOError, UnidentifiedImageError, PdfReadError, ValueError, struct.error) as e:
            return False
        except Exception as e:
            return False
        """
        # End of disabled validation code

    def carve_pdf_files(self, chunk, global_offset):
        pdf_start_signature = b'%PDF-'
        pdf_linearization_signature = b'/Linearized'
        pdf_end_signature = b'%%EOF'
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(pdf_start_signature, offset)
            if start_index == -1:
                break

            linearization_index = chunk.find(pdf_linearization_signature, start_index, start_index + 1024)
            linearized = linearization_index != -1
            expected_size = None

            if linearized:
                file_size_start = chunk.find(b'/L ', linearization_index, linearization_index + 1024) + 3
                file_size_end = chunk.find(b'/', file_size_start)
                if file_size_end == -1:
                    file_size_end = chunk.find(b' ', file_size_start)
                if file_size_end != -1:
                    try:
                        expected_size = int(chunk[file_size_start:file_size_end].split()[0])
                        pdf_content = chunk[start_index:start_index + expected_size]

                        carving_meta = {
                            'header_found': True,
                            'footer_found': b'%%EOF' in pdf_content[-20:],
                            'expected_size': expected_size,
                            'actual_size': len(pdf_content),
                            'truncated': False,
                            'linearized': True
                        }

                        if self.is_valid_file(pdf_content, 'pdf'):
                            self.save_file(pdf_content, 'pdf', 'carved_files',
                                           global_offset + start_index, carving_meta)
                            offset = start_index + expected_size
                            continue
                    except ValueError:
                        pass

            end_index = chunk.find(pdf_end_signature, start_index)
            footer_found = end_index != -1

            if footer_found:
                end_index += len(pdf_end_signature)
                pdf_content = chunk[start_index:end_index]
            else:
                pdf_content = chunk[start_index:]

            carving_meta = {
                'header_found': True,
                'footer_found': footer_found,
                'expected_size': expected_size,
                'actual_size': len(pdf_content),
                'truncated': not footer_found,
                'linearized': linearized
            }

            if self.is_valid_file(pdf_content, 'pdf'):
                self.save_file(pdf_content, 'pdf', 'carved_files',
                               global_offset + start_index, carving_meta)

            if footer_found:
                offset = end_index
            else:
                offset = start_index + 1

    def carve_wav_files(self, chunk, global_offset):
        wav_start_signature = b'RIFF'
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(wav_start_signature, offset)
            if start_index == -1:
                break

            if chunk[start_index + 8:start_index + 12] != b'WAVE':
                offset = start_index + 4
                continue

            file_size_bytes = chunk[start_index + 4:start_index + 8]
            expected_size = int.from_bytes(file_size_bytes, byteorder='little') + 8
            truncated = start_index + expected_size > len(chunk)

            if truncated:
                wav_content = chunk[start_index:]
                offset = len(chunk)
            else:
                wav_content = chunk[start_index:start_index + expected_size]
                offset = start_index + expected_size

            carving_meta = {
                'header_found': True,
                'footer_found': not truncated,  # WAV doesn't have footer, use size match
                'expected_size': expected_size,
                'actual_size': len(wav_content),
                'truncated': truncated
            }

            if self.is_valid_file(wav_content, 'wav'):
                self.save_file(wav_content, 'wav', 'carved_files',
                               global_offset + start_index, carving_meta)

    def carve_mov_files(self, chunk, global_offset):
        mov_signatures = [
            # b'ftyp', b'moov', b'mdat', #b'pnot', b'udta', #b'uuid',
            # b'moof', b'free', b'skip', b'jP2 ', b'wide', b'load',
            # b'ctab', b'imap', b'matt', b'kmat', b'clip', b'crgn',
            # b'sync', b'chap', b'tmcd', b'scpt', b'ssrc', b'PICT'
            b'moov', b'mdat', b'free', b'wide'
        ]

        mov_file_found = False
        mov_data = b''
        mov_file_offset = global_offset
        mov_file_size = 0
        truncated = False
        offset = 0

        while offset < len(chunk):
            if offset + 8 > len(chunk):
                # Not enough data for an atom header
                truncated = mov_file_found
                break

            atom_size = int.from_bytes(chunk[offset:offset + 4], 'big')
            atom_type = chunk[offset + 4:offset + 8]

            if atom_type not in mov_signatures:
                if mov_file_found:
                    # End of MOV file
                    break
                else:
                    # Not a MOV file or just a stray header, skip ahead
                    offset += 4
                    continue

            mov_file_found = True
            mov_file_size += atom_size

            if offset + atom_size > len(chunk):
                # Atom extends beyond this chunk, store what we have
                mov_data += chunk[offset:]
                truncated = True
                break
            else:
                # We have the whole atom, store it
                mov_data += chunk[offset:offset + atom_size]

            offset += atom_size

        if mov_file_found and mov_data:
            carving_meta = {
                'header_found': True,
                'footer_found': not truncated,
                'expected_size': mov_file_size,
                'actual_size': len(mov_data),
                'truncated': truncated
            }

            # Validate MOV file before saving
            if self.is_valid_file(mov_data, 'mov'):
                self.save_file(mov_data, 'mov', 'carved_files', mov_file_offset, carving_meta)

    def carve_mp4_files(self, chunk, global_offset):
        """Carve MP4 files from chunk data.
        MP4 files are MPEG-4 containers that start with ftyp atom.
        Common brands: isom, mp41, mp42, avc1, iso2, M4V, etc.
        """
        ftyp_signature = b'ftyp'
        mp4_atoms = [b'ftyp', b'moov', b'mdat', b'free', b'skip', b'wide', b'moof']

        current_offset = 0

        while current_offset < len(chunk):
            # Look for ftyp atom which typically starts MP4 files
            ftyp_index = chunk.find(ftyp_signature, current_offset + 4, current_offset + 1024)

            if ftyp_index == -1:
                current_offset += 1024 if current_offset + 1024 < len(chunk) else len(chunk)
                continue

            # Check if there's an atom size before ftyp (ftyp should be at offset+4)
            potential_start = ftyp_index - 4
            if potential_start < 0:
                current_offset = ftyp_index + 4
                continue

            # Verify it's a valid ftyp atom
            if potential_start + 8 > len(chunk):
                break

            atom_size = int.from_bytes(chunk[potential_start:potential_start + 4], 'big')
            atom_type = chunk[potential_start + 4:potential_start + 8]

            if atom_type != b'ftyp' or atom_size < 8 or atom_size > 1024 * 1024:
                current_offset = ftyp_index + 4
                continue

            # Check for MP4 brand indicators in ftyp atom
            if potential_start + 12 <= len(chunk):
                brand = chunk[potential_start + 8:potential_start + 12]
                mp4_brands = [b'isom', b'mp41', b'mp42', b'avc1', b'iso2', b'M4V ', b'M4A ',
                              b'iso3', b'iso4', b'iso5', b'iso6', b'mmp4', b'mp71']

                if brand not in mp4_brands:
                    current_offset = ftyp_index + 4
                    continue

            # Found valid MP4 ftyp atom, now collect all atoms
            mp4_data = b''
            mp4_offset = potential_start
            parse_offset = potential_start
            truncated = False
            expected_total_size = 0

            while parse_offset < len(chunk):
                if parse_offset + 8 > len(chunk):
                    truncated = True
                    break

                atom_size = int.from_bytes(chunk[parse_offset:parse_offset + 4], 'big')
                atom_type = chunk[parse_offset + 4:parse_offset + 8]

                # Check if this is a valid MP4 atom
                if atom_type not in mp4_atoms:
                    # Reached end of MP4 file
                    break

                expected_total_size += atom_size

                # Check atom size validity
                if atom_size < 8 or atom_size > len(chunk) - parse_offset:
                    if atom_type == b'mdat' and atom_size == 1:
                        # Extended size atom (64-bit size)
                        if parse_offset + 16 <= len(chunk):
                            atom_size = int.from_bytes(chunk[parse_offset + 8:parse_offset + 16], 'big')
                        else:
                            truncated = True
                            break
                    else:
                        # Invalid atom or extends beyond chunk
                        if len(mp4_data) > 0:
                            truncated = True
                            break
                        else:
                            # Skip this potential MP4
                            current_offset = ftyp_index + 4
                            break

                # Add atom data
                if parse_offset + atom_size <= len(chunk):
                    mp4_data += chunk[parse_offset:parse_offset + atom_size]
                    parse_offset += atom_size
                else:
                    # Atom extends beyond chunk
                    mp4_data += chunk[parse_offset:]
                    truncated = True
                    break

            # Save MP4 file if we collected data
            if len(mp4_data) > 0:
                carving_meta = {
                    'header_found': True,
                    'footer_found': not truncated,
                    'expected_size': expected_total_size if expected_total_size > 0 else None,
                    'actual_size': len(mp4_data),
                    'truncated': truncated
                }

                if self.is_valid_file(mp4_data, 'mp4'):
                    self.save_file(mp4_data, 'mp4', 'carved_files',
                                   global_offset + mp4_offset, carving_meta)

            current_offset = parse_offset if parse_offset > current_offset else ftyp_index + 4

    def carve_jpg_files(self, chunk, global_offset):
        jpg_start_signature = b'\xFF\xD8\xFF'
        jpg_end_signature = b'\xFF\xD9'
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(jpg_start_signature, offset)
            if start_index == -1:
                break

            end_index = chunk.find(jpg_end_signature, start_index)
            footer_found = end_index != -1

            if footer_found:
                jpg_content = chunk[start_index:end_index + len(jpg_end_signature)]
                offset = end_index + len(jpg_end_signature)
            else:
                # No footer found - carve up to end of chunk (truncated)
                jpg_content = chunk[start_index:]
                offset = len(chunk)

            # Capture carving metadata
            carving_meta = {
                'header_found': True,
                'footer_found': footer_found,
                'expected_size': None,  # JPG has no size field
                'actual_size': len(jpg_content),
                'truncated': not footer_found
            }

            # Check if it's a valid JPG file
            if self.is_valid_file(jpg_content, 'jpg'):
                self.save_file(jpg_content, 'jpg', 'carved_files',
                               global_offset + start_index, carving_meta)

            if not footer_found:
                break  # Stop if truncated

    def carve_gif_files(self, chunk, global_offset):
        gif_start_signature = b'\x47\x49\x46\x38'
        gif_end_signature = b'\x00\x3B'
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(gif_start_signature, offset)
            if start_index == -1:
                break

            end_index = chunk.find(gif_end_signature, start_index)
            footer_found = end_index != -1

            if footer_found:
                gif_content = chunk[start_index:end_index + len(gif_end_signature)]
                offset = end_index + len(gif_end_signature)
            else:
                gif_content = chunk[start_index:]
                offset = len(chunk)

            # Capture carving metadata
            carving_meta = {
                'header_found': True,
                'footer_found': footer_found,
                'expected_size': None,
                'actual_size': len(gif_content),
                'truncated': not footer_found
            }

            # Check if it's a valid GIF file
            if self.is_valid_file(gif_content, 'gif'):
                self.save_file(gif_content, 'gif', 'carved_files',
                               global_offset + start_index, carving_meta)

            if not footer_found:
                break

    def carve_png_files(self, chunk, global_offset):
        png_start_signature = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
        png_end_signature = b'\x49\x45\x4E\x44\xAE\x42\x60\x82'
        offset = 0
        while offset < len(chunk):
            start_index = chunk.find(png_start_signature, offset)
            if start_index == -1:
                break

            end_index = chunk.find(png_end_signature, start_index)
            footer_found = end_index != -1

            if footer_found:
                png_content = chunk[start_index:end_index + len(png_end_signature)]
                offset = end_index + len(png_end_signature)
            else:
                png_content = chunk[start_index:]
                offset = len(chunk)

            # Capture carving metadata
            carving_meta = {
                'header_found': True,
                'footer_found': footer_found,
                'expected_size': None,
                'actual_size': len(png_content),
                'truncated': not footer_found
            }

            # Check if it's a valid PNG file
            if self.is_valid_file(png_content, 'png'):
                self.save_file(png_content, 'png', 'carved_files',
                               global_offset + start_index, carving_meta)

            if not footer_found:
                break

    def carve_wmv_files(self, chunk, global_offset):
        # Define ASF header signature
        asf_header_signature = b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C'

        current_offset = 0

        while current_offset < len(chunk):
            # Search for ASF header
            start_index = chunk.find(asf_header_signature, current_offset)
            if start_index == -1:
                break

            # Find the file properties object header within the first 512 bytes of the file
            max_search_size = min(start_index + 512, len(chunk))
            file_properties_header = b'\xA1\xDC\xAB\x8C\x47\xA9\xCF\x11\x8E\xE4\x00\xC0\x0C\x20\x53\x65'
            file_properties_index = chunk.find(file_properties_header, start_index, max_search_size)
            if file_properties_index == -1:
                current_offset = start_index + 1
                continue

            # Extract the file size located at offset 40 within the object
            file_size_offset = file_properties_index + 40
            file_size_bytes = chunk[file_size_offset:file_size_offset + 8]
            expected_size = int.from_bytes(file_size_bytes, byteorder='little')

            # Calculate end index based on file size
            end_index = start_index + expected_size
            truncated = end_index > len(chunk)

            # Extract WMV content
            if truncated:
                wmv_content = chunk[start_index:]
            else:
                wmv_content = chunk[start_index:end_index]

            carving_meta = {
                'header_found': True,
                'footer_found': not truncated,
                'expected_size': expected_size,
                'actual_size': len(wmv_content),
                'truncated': truncated
            }

            # Validate WMV file before saving
            if self.is_valid_file(wmv_content, 'wmv'):
                self.save_file(wmv_content, 'wmv', 'carved_files',
                               global_offset + start_index, carving_meta)
            current_offset = end_index if not truncated else len(chunk)

    def carve_zip_files(self, chunk, global_offset):
        # Define ZIP header signatures
        local_file_header_signature = b'\x50\x4b\x03\x04'
        end_of_central_dir_signature = b'\x50\x4b\x05\x06'

        current_pos = 0
        zip_file_parts = []  # List to hold all parts of the ZIP file
        start_offset = None

        while current_pos < len(chunk):
            # Search for local file header
            local_header_index = chunk.find(local_file_header_signature, current_pos)
            if local_header_index == -1:
                break

            if start_offset is None:
                start_offset = local_header_index

            # Extract compressed size from local file header
            compressed_size = struct.unpack("<I", chunk[local_header_index + 18:local_header_index + 22])[0]

            # Calculate next local file header index
            next_local_header_index = local_header_index + 30 + compressed_size

            # Extract file content
            file_content = chunk[local_header_index:next_local_header_index]
            zip_file_parts.append(file_content)  # Add the file content to the ZIP parts list

            # Move to next local file header
            current_pos = next_local_header_index

        # Now, find and append the Central Directory and End of Central Directory Record
        end_central_dir_index = chunk.find(end_of_central_dir_signature, current_pos)
        eocd_found = end_central_dir_index != -1

        if eocd_found:
            # Extract comment length and calculate the total end of the ZIP file structure
            comment_length = struct.unpack("<H", chunk[end_central_dir_index + 20:end_central_dir_index + 22])[0]
            zip_end = end_central_dir_index + 22 + comment_length

            # Extract the Central Directory and End of Central Directory Record
            zip_file_structure = chunk[current_pos:zip_end]
            zip_file_parts.append(zip_file_structure)  # Add this to the ZIP parts list

        # Combine all parts into a single ZIP file content
        if zip_file_parts:
            complete_zip_file_content = b''.join(zip_file_parts)

            carving_meta = {
                'header_found': True,
                'footer_found': eocd_found,
                'expected_size': None,
                'actual_size': len(complete_zip_file_content),
                'truncated': not eocd_found
            }

            # Validate ZIP file before saving
            if self.is_valid_file(complete_zip_file_content, 'zip'):
                self.save_file(complete_zip_file_content, 'zip', 'carved_files',
                               global_offset + (start_offset or 0), carving_meta)

        return None

    def carve_bmp_files(self, chunk, global_offset):
        bmp_start_signature = b'BM'  # BMP files start with 'BM'
        header_size = 14  # The static header size for BMP files

        current_offset = 0
        while current_offset < len(chunk) - header_size:
            # Look for the BMP signature
            start_index = chunk.find(bmp_start_signature, current_offset)
            if start_index == -1:
                break  # No more BMP files found

            # Verify there's enough chunk left to read the BMP size
            if start_index + header_size > len(chunk) - 4:
                break  # Not enough data for size

            # Read file size directly from header
            expected_size = int.from_bytes(chunk[start_index + 2:start_index + 6], byteorder='little')

            # Sanity check for BMP size (adjust max and min size as per your need)
            if expected_size < 100 or expected_size > 5000000:
                current_offset = start_index + 2
                continue  # Not a valid BMP size, skip to next possible start

            # Read and check dimensions for further validation
            bmp_width = int.from_bytes(chunk[start_index + 18:start_index + 22], byteorder='little')
            bmp_height = int.from_bytes(chunk[start_index + 22:start_index + 26], byteorder='little')

            # Reasonable dimensions check (adjust max width/height as per your need)
            if bmp_width <= 0 or bmp_width > 10000 or bmp_height <= 0 or bmp_height > 10000:
                current_offset = start_index + 2
                continue  # Unreasonable dimensions, likely not a BMP

            # Extract the BMP file
            truncated = start_index + expected_size > len(chunk)
            if not truncated:
                bmp_content = chunk[start_index:start_index + expected_size]
                current_offset = start_index + expected_size
            else:
                bmp_content = chunk[start_index:]
                current_offset = len(chunk)

            carving_meta = {
                'header_found': True,
                'footer_found': not truncated,  # BMP has no footer, use size match
                'expected_size': expected_size,
                'actual_size': len(bmp_content),
                'truncated': truncated
            }

            # Validate BMP file before saving
            if self.is_valid_file(bmp_content, 'bmp'):
                self.save_file(bmp_content, 'bmp', 'carved_files',
                               global_offset + start_index, carving_meta)

            if truncated:
                break

        # Return if more data is needed or if processing is complete
        return None

    def carve_office_files(self, chunk, global_offset, target_type=None):
        """Carve Office files (.docx, .xlsx, .pptx) which are ZIP-based

        Args:
            chunk: Data chunk to search
            global_offset: Offset in the image
            target_type: Specific type to carve ('docx', 'xlsx', 'pptx'), or None for all
        """
        # Office files are ZIP archives with specific internal structure
        local_file_header_signature = b'\x50\x4b\x03\x04'
        end_of_central_dir_signature = b'\x50\x4b\x05\x06'

        current_pos = 0

        while current_pos < len(chunk):
            # Find ZIP header (Office files are ZIP archives)
            start_index = chunk.find(local_file_header_signature, current_pos)
            if start_index == -1:
                break

            # Find end of ZIP file
            end_central_dir_index = chunk.find(end_of_central_dir_signature, start_index)
            eocd_found = end_central_dir_index != -1

            if not eocd_found:
                current_pos = start_index + 4
                continue

            # Calculate end of file including comment
            try:
                comment_length = struct.unpack("<H", chunk[end_central_dir_index + 20:end_central_dir_index + 22])[0]
                zip_end = end_central_dir_index + 22 + comment_length
            except:
                current_pos = start_index + 4
                continue

            # Extract potential Office file
            office_content = chunk[start_index:zip_end]

            # Determine if it's an Office file and what type
            office_type = self.identify_and_validate_office_file(office_content)

            # Only save if it matches the target type (or no target specified)
            if office_type:
                if target_type is None or office_type == target_type:
                    carving_meta = {
                        'header_found': True,
                        'footer_found': eocd_found,
                        'expected_size': None,
                        'actual_size': len(office_content),
                        'truncated': not eocd_found
                    }
                    self.save_file(office_content, office_type, 'carved_files',
                                   global_offset + start_index, carving_meta)
                current_pos = zip_end
            else:
                current_pos = start_index + 4

        return None

    def identify_and_validate_office_file(self, content):
        """Identify and validate if ZIP content is a valid, undamaged Office file

        FORENSIC MODE: Relaxed validation - attempts to identify Office files even if damaged.
        This preserves potentially valuable corrupted documents for forensic analysis.

        Returns:
            str: File type ('docx', 'xlsx', 'pptx') if identifiable, None otherwise
        """
        try:
            # Try to open as ZIP - this will fail if file is corrupted
            zip_file = zipfile.ZipFile(io.BytesIO(content))

            # FORENSIC MODE: Don't reject corrupted files, try to identify them anyway
            # Test the ZIP file integrity
            # if zip_file.testzip() is not None:
            #     # File is corrupted - but we still try to identify it
            #     pass

            file_list = zip_file.namelist()

            # Required files for each Office type
            docx_required = ['[Content_Types].xml', 'word/document.xml']
            xlsx_required = ['[Content_Types].xml', 'xl/workbook.xml']
            pptx_required = ['[Content_Types].xml', 'ppt/presentation.xml']

            # Check for DOCX
            if all(f in file_list for f in docx_required):
                # Validate by checking Content_Types.xml
                try:
                    content_types = zip_file.read('[Content_Types].xml').decode('utf-8', errors='ignore')
                    if 'wordprocessingml' in content_types:
                        # FORENSIC MODE: Don't verify readability, just identify
                        # zip_file.read('word/document.xml')
                        return 'docx'
                except:
                    # FORENSIC MODE: If structure looks like DOCX, save it anyway
                    return 'docx'

            # Check for XLSX
            elif all(f in file_list for f in xlsx_required):
                try:
                    content_types = zip_file.read('[Content_Types].xml').decode('utf-8', errors='ignore')
                    if 'spreadsheetml' in content_types:
                        # FORENSIC MODE: Don't verify readability, just identify
                        # zip_file.read('xl/workbook.xml')
                        return 'xlsx'
                except:
                    # FORENSIC MODE: If structure looks like XLSX, save it anyway
                    return 'xlsx'

            # Check for PPTX
            elif all(f in file_list for f in pptx_required):
                try:
                    content_types = zip_file.read('[Content_Types].xml').decode('utf-8', errors='ignore')
                    if 'presentationml' in content_types:
                        # FORENSIC MODE: Don't verify readability, just identify
                        # zip_file.read('ppt/presentation.xml')
                        return 'pptx'
                except:
                    # FORENSIC MODE: If structure looks like PPTX, save it anyway
                    return 'pptx'

            # If it has [Content_Types].xml but doesn't match above, check content
            elif '[Content_Types].xml' in file_list:
                try:
                    content_types = zip_file.read('[Content_Types].xml').decode('utf-8', errors='ignore')
                    if 'wordprocessingml' in content_types and any('word/' in f for f in file_list):
                        return 'docx'
                    elif 'spreadsheetml' in content_types and any('xl/' in f for f in file_list):
                        return 'xlsx'
                    elif 'presentationml' in content_types and any('ppt/' in f for f in file_list):
                        return 'pptx'
                except:
                    pass

            return None  # Not a valid Office file

        except zipfile.BadZipFile:
            # Corrupted ZIP file
            return None
        except Exception as e:
            # Any other error means invalid file
            return None

    def carve_files(self, selected_file_types):
        try:
            self._stop_carving_flag = False
            chunk_size = 1024 * 1024 * 100
            offset = 0

            while offset < self.image_handler.get_size():
                chunk = self.image_handler.read(offset, chunk_size)
                if not chunk:
                    break

                if self._stop_carving_flag:
                    self._stop_carving_flag = False
                    self.start_button.setEnabled(True)
                    self.stop_button.setEnabled(False)
                    return

                # Call the carve function for each selected file type
                for file_type in selected_file_types:
                    if file_type == 'all':
                        self.carve_wav_files(chunk, offset)
                        self.carve_mov_files(chunk, offset)
                        self.carve_mp4_files(chunk, offset)
                        self.carve_pdf_files(chunk, offset)
                        self.carve_jpg_files(chunk, offset)
                        self.carve_gif_files(chunk, offset)
                        self.carve_png_files(chunk, offset)
                        self.carve_wmv_files(chunk, offset)
                        self.carve_zip_files(chunk, offset)
                        self.carve_bmp_files(chunk, offset)
                        self.carve_office_files(chunk, offset, target_type=None)  # Carve all office types
                    elif file_type == 'wav':
                        self.carve_wav_files(chunk, offset)
                    elif file_type == 'mov':
                        self.carve_mov_files(chunk, offset)
                    elif file_type == 'mp4':
                        self.carve_mp4_files(chunk, offset)
                    elif file_type == 'pdf':
                        self.carve_pdf_files(chunk, offset)
                    elif file_type == 'jpg':
                        self.carve_jpg_files(chunk, offset)
                    elif file_type == 'gif':
                        self.carve_gif_files(chunk, offset)
                    elif file_type == 'png':
                        self.carve_png_files(chunk, offset)
                    elif file_type == 'wmv':
                        self.carve_wmv_files(chunk, offset)
                    elif file_type == 'zip':
                        self.carve_zip_files(chunk, offset)
                    elif file_type == 'bmp':
                        self.carve_bmp_files(chunk, offset)
                    elif file_type == 'docx':
                        self.carve_office_files(chunk, offset, target_type='docx')
                    elif file_type == 'xlsx':
                        self.carve_office_files(chunk, offset, target_type='xlsx')
                    elif file_type == 'pptx':
                        self.carve_office_files(chunk, offset, target_type='pptx')

                offset += chunk_size
        finally:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            # Update the summary bar with carving statistics
            self.update_summary_bar()

    def update_summary_bar(self):
        """Update the summary bar with carving statistics."""
        total = sum(self.carving_stats.values())
        if total == 0:
            self.summary_bar.setVisible(False)
            return

        # Build summary text with colored tier counts
        parts = [f"Carved {total} files: "]
        tier_parts = []

        if self.carving_stats['complete'] > 0:
            tier_parts.append(f"<span style='color:#4CAF50'>{self.carving_stats['complete']} Complete</span>")
        if self.carving_stats['good'] > 0:
            tier_parts.append(f"<span style='color:#8BC34A'>{self.carving_stats['good']} Good</span>")
        if self.carving_stats['partial'] > 0:
            tier_parts.append(f"<span style='color:#FFC107'>{self.carving_stats['partial']} Partial</span>")
        if self.carving_stats['damaged'] > 0:
            tier_parts.append(f"<span style='color:#FF9800'>{self.carving_stats['damaged']} Damaged</span>")
        if self.carving_stats['fragment'] > 0:
            tier_parts.append(f"<span style='color:#F44336'>{self.carving_stats['fragment']} Fragment</span>")

        summary_text = parts[0] + ", ".join(tier_parts)
        self.summary_bar.setText(summary_text)
        self.summary_bar.setTextFormat(Qt.RichText)
        self.summary_bar.setVisible(True)

    def save_file(self, file_content, file_type, file_path, offset, carving_meta=None):
        # Ensure the 'carved_files' directory exists
        if not os.path.exists("carved_files"):
            os.makedirs("carved_files")

        offset_hex = format(offset, 'x')
        file_name = f"{offset_hex}.{file_type}"
        file_path = os.path.join("carved_files", file_name)
        with open(file_path, "wb") as f:
            f.write(file_content)
        modification_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_size = str(len(file_content))

        # Calculate confidence score
        confidence_result = self.confidence_evaluator.evaluate(
            file_path, file_type, carving_meta or {}, file_content
        )

        # Update carving statistics
        tier_key = confidence_result.tier.lower()
        if tier_key in self.carving_stats:
            self.carving_stats[tier_key] += 1

        # Format details for tooltip
        confidence_details = '\n'.join(confidence_result.details)

        self.carved_files.append((file_name, file_size, file_type, file_path,
                                  modification_date, confidence_result.score, confidence_details))
        self.file_carved.emit(file_name, file_size, file_type, modification_date,
                              file_path, confidence_result.score, confidence_details)
        self.carved_file_names.add(file_name)

    def get_confidence_color(self, score):
        """Get QColor for confidence score based on tier."""
        from PySide6.QtGui import QColor
        if score >= 90:
            return QColor('#4CAF50')  # Green - Complete
        elif score >= 70:
            return QColor('#8BC34A')  # Light Green - Good
        elif score >= 50:
            return QColor('#FFC107')  # Yellow - Partial
        elif score >= 30:
            return QColor('#FF9800')  # Orange - Damaged
        else:
            return QColor('#F44336')  # Red - Fragment

    def get_confidence_tier_name(self, score):
        """Get tier name for confidence score."""
        if score >= 90:
            return 'Complete'
        elif score >= 70:
            return 'Good'
        elif score >= 50:
            return 'Partial'
        elif score >= 30:
            return 'Damaged'
        else:
            return 'Fragment'

    def add_confidence_badge(self, pixmap, confidence_score):
        """Add a confidence badge overlay to a pixmap thumbnail."""
        from PySide6.QtGui import QColor, QFont, QPen, QBrush

        # Check if pixmap is valid
        if pixmap.isNull() or pixmap.width() <= 0 or pixmap.height() <= 0:
            return pixmap  # Return original if invalid

        # Create a copy of the pixmap to draw on
        result = QPixmap(pixmap.size())
        result.fill(Qt.transparent)

        painter = QPainter()
        if not painter.begin(result):
            return pixmap  # Return original if painter fails to start

        painter.setRenderHint(QPainter.Antialiasing)

        # Draw the original pixmap
        painter.drawPixmap(0, 0, pixmap)

        # Get tier color
        color = self.get_confidence_color(confidence_score)

        # Draw colored border around the thumbnail based on confidence
        border_width = 3
        pen = QPen(color, border_width)
        painter.setPen(pen)
        painter.drawRect(border_width // 2, border_width // 2,
                         pixmap.width() - border_width, pixmap.height() - border_width)

        # Draw confidence badge in top-right corner
        badge_size = 32
        badge_x = pixmap.width() - badge_size - 4
        badge_y = 4

        # Badge background circle
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(color))
        painter.drawEllipse(badge_x, badge_y, badge_size, badge_size)

        # Badge text
        painter.setPen(Qt.white)
        font = QFont()
        font.setPixelSize(11)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(badge_x, badge_y, badge_size, badge_size,
                         Qt.AlignCenter, f"{confidence_score}")

        painter.end()
        return result

    @Slot(str, str, str, str, str, int, str)
    def display_carved_file(self, name, size, type_, modification_date, file_path,
                            confidence_score, confidence_details):
        row = self.table_widget.rowCount()
        readable_size = self.image_handler.get_readable_size(int(size))
        self.table_widget.insertRow(row)

        # Set Id column manually
        self.table_widget.setItem(row, 0, QTableWidgetItem(str(row + 1)))  # Setting the 'Id' field
        self.table_widget.setItem(row, 1, QTableWidgetItem(name))
        self.table_widget.setItem(row, 2, NumericTableWidgetItem(readable_size))
        self.table_widget.setItem(row, 3, QTableWidgetItem(type_))

        # Confidence column with color coding
        confidence_item = QTableWidgetItem(f"{confidence_score}%")
        confidence_item.setTextAlignment(Qt.AlignCenter)
        confidence_item.setToolTip(confidence_details)
        confidence_item.setBackground(self.get_confidence_color(confidence_score))
        self.table_widget.setItem(row, 4, confidence_item)

        self.table_widget.setItem(row, 5, QTableWidgetItem(modification_date))
        self.table_widget.setItem(row, 6, QTableWidgetItem(file_path))

        # Set column resize modes
        header = self.table_widget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)  # Id column fixed width
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Name column stretches dynamically
        header.setSectionResizeMode(2, QHeaderView.Fixed)  # Size column fixed width
        header.setSectionResizeMode(3, QHeaderView.Fixed)  # Type column fixed width
        header.setSectionResizeMode(4, QHeaderView.Fixed)  # Confidence column fixed width
        header.setSectionResizeMode(5, QHeaderView.Fixed)  # Date column fixed width
        header.setSectionResizeMode(6, QHeaderView.Stretch)  # File Path column stretches dynamically

        # Set fixed widths for non-stretch columns
        self.table_widget.setColumnWidth(0, 30)  # Id column width
        self.table_widget.setColumnWidth(2, 70)  # Size column width
        self.table_widget.setColumnWidth(3, 50)  # Type column width
        self.table_widget.setColumnWidth(4, 80)  # Confidence column width
        self.table_widget.setColumnWidth(5, 130)  # Date column width

        # Only proceed if the file type is one of the supported image, video, or office formats
        if type_.lower() in ['jpg', 'jpeg', 'png', 'gif', 'mov', 'mp4', 'pdf', 'wmv', 'bmp', 'docx', 'xlsx', 'pptx']:
            file_full_path = os.path.join("carved_files", name)
            thumbnail_folder = os.path.join("carved_files", "thumbnails")  # Folder to save thumbnails

            if not os.path.exists(thumbnail_folder):
                os.makedirs(thumbnail_folder)  # Create the thumbnail folder if it doesn't exist

            if type_.lower() == 'mov':
                thumbnail_path = os.path.join(thumbnail_folder, name.replace('.mov', '.png'))
                with VideoFileClip(file_full_path) as clip:
                    clip.save_frame(thumbnail_path, t=0.5)  # save frame at 0.5 seconds
                pixmap = QPixmap(thumbnail_path)

            elif type_.lower() == 'mp4':
                # Extract thumbnail from MP4 using cv2
                capture = cv2.VideoCapture(file_full_path)
                success, image = capture.read()
                capture.release()  # Release the capture object explicitly
                if success:
                    thumbnail_path = os.path.join(thumbnail_folder, name.replace('.mp4', '.png'))
                    cv2.imwrite(thumbnail_path, image)
                    pixmap = QPixmap(thumbnail_path)
                else:
                    print("Failed to extract thumbnail from MP4 file")

            elif type_.lower() == 'pdf':
                # Convert the first page of the PDF to a thumbnail
                images = convert_from_path(file_full_path)
                thumbnail_path = os.path.join(thumbnail_folder, name.replace('.pdf', '.png'))
                images[0].save(thumbnail_path, 'PNG')
                # Create the QPixmap from the full path
                pixmap = QPixmap(thumbnail_path)

            elif type_.lower() == 'wmv':
                capture = cv2.VideoCapture(file_full_path)
                success, image = capture.read()
                capture.release()  # Release the capture object explicitly
                if success:
                    thumbnail_path = os.path.join(thumbnail_folder, name.replace('.wmv', '.png'))
                    cv2.imwrite(thumbnail_path, image)
                    pixmap = QPixmap(thumbnail_path)
                else:
                    print("Failed to extract thumbnail from WMV file")

            elif type_.lower() in ['docx', 'xlsx', 'pptx']:
                # For office files, use generic icons
                icon_map = {
                    'docx': 'Icons/file-types/word-icon.png',
                    'xlsx': 'Icons/file-types/excel-icon.png',
                    'pptx': 'Icons/file-types/powerpoint-icon.png'
                }
                icon_path = icon_map.get(type_.lower(), 'Icons/file-types/office-icon.png')

                # Check if icon exists, otherwise use a default
                if not os.path.exists(icon_path):
                    # Create a simple colored square as a placeholder
                    color_map = {
                        'docx': Qt.blue,
                        'xlsx': Qt.darkGreen,
                        'pptx': Qt.darkRed
                    }
                    pixmap = QPixmap(150, 150)
                    color = color_map.get(type_.lower(), Qt.gray)
                    pixmap.fill(color)

                    # Add text label
                    painter = QPainter(pixmap)
                    painter.setPen(Qt.white)
                    painter.drawText(pixmap.rect(), Qt.AlignCenter, type_.upper())
                    painter.end()
                else:
                    pixmap = QPixmap(icon_path)

            else:
                # For image files, use the original file path
                thumbnail_path = file_full_path
                pixmap = QPixmap(thumbnail_path)

            # Scale the pixmap to the icon size while maintaining aspect ratio
            pixmap = pixmap.scaled(QSize(150, 150), Qt.KeepAspectRatio, Qt.SmoothTransformation)

            # Add confidence badge overlay to thumbnail
            pixmap = self.add_confidence_badge(pixmap, confidence_score)

            icon = QIcon(pixmap)

            # Create a QListWidgetItem, set its icon, and provide a size hint to ensure the text is visible
            item = QListWidgetItem(icon, name)
            # Set a fixed size for the QListWidgetItem with some extra space for the text
            item.setSizeHint(QSize(200, 200))  # Adjust the width as necessary to fit the text
            item.setToolTip(f"Confidence: {confidence_score}%\n{confidence_details}")

            # Store file data in the item for preview functionality
            item_data = {
                "name": name,
                "type": "file",
                "size": int(size),
                "file_type": type_,
                "path": file_path,
                "is_carved": True,
                "confidence": confidence_score,
                "confidence_details": confidence_details
            }
            item.setData(Qt.UserRole, item_data)

            # Set the item flags to not be movable and to be selectable
            item.setFlags(item.flags() & ~Qt.ItemIsDragEnabled & ~Qt.ItemIsDropEnabled)

            # Add the QListWidgetItem to the list widget
            self.list_widget.addItem(item)

    def clear(self):
        self.table_widget.setRowCount(0)
        self.list_widget.clear()
        self.carved_files.clear()
        self.carving_stats = {'complete': 0, 'good': 0, 'partial': 0, 'damaged': 0, 'fragment': 0}
        self.summary_bar.setVisible(False)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def clear_ui(self):
        self.table_widget.setRowCount(0)
        self.list_widget.clear()
        self.summary_bar.setVisible(False)

    def on_carved_file_clicked(self, row, column):
        """Handle click on carved file to show preview in viewer tabs."""
        # Get the file path from the table (column 6 - after adding Confidence column)
        file_path_item = self.table_widget.item(row, 6)  # File Path column
        if not file_path_item:
            return

        file_path = file_path_item.text()

        # Check if file exists
        if not os.path.exists(file_path):
            print(f"Carved file not found: {file_path}")
            return

        try:
            # Read the carved file content
            with open(file_path, 'rb') as f:
                file_content = f.read()

            # Get file name and type for metadata
            file_name = self.table_widget.item(row, 1).text()  # Name column
            file_type = self.table_widget.item(row, 3).text()  # Type column

            # Create data dict similar to what the tree viewer uses
            file_data = {
                "name": file_name,
                "type": "file",
                "size": len(file_content),
                "file_type": file_type,
                "path": file_path,
                "is_carved": True  # Flag to indicate this is a carved file
            }

            # Get reference to mainwindow
            if self.main_window and hasattr(self.main_window, 'update_viewer_with_file_content'):
                # Clear existing viewers
                if hasattr(self.main_window, 'clear_viewers'):
                    self.main_window.clear_viewers()

                # Store file content for tab switching
                self.main_window.current_file_content = file_content

                # Update the current selected data
                self.main_window.current_selected_data = file_data

                # Display in viewer tabs
                self.main_window.update_viewer_with_file_content(file_content, file_data)

                # Make sure viewer tabs are visible
                if hasattr(self.main_window, 'viewer_dock'):
                    self.main_window.viewer_dock.show()

                print(f"Displaying carved file in preview: {file_name}")
            else:
                print("Could not access main window preview tabs")

        except Exception as e:
            print(f"Error loading carved file for preview: {e}")
            import traceback
            traceback.print_exc()

    def on_carved_list_item_clicked(self, item):
        """Handle click on carved file in list/icon view to show preview."""
        # Get the file path stored in the item data
        file_data = item.data(Qt.UserRole)
        if not file_data or 'path' not in file_data:
            return

        file_path = file_data['path']

        # Check if file exists
        if not os.path.exists(file_path):
            print(f"Carved file not found: {file_path}")
            return

        try:
            # Read the carved file content
            with open(file_path, 'rb') as f:
                file_content = f.read()

            # Use the file_data from the item
            file_data['is_carved'] = True

            # Get reference to mainwindow
            if self.main_window and hasattr(self.main_window, 'update_viewer_with_file_content'):
                # Clear existing viewers
                if hasattr(self.main_window, 'clear_viewers'):
                    self.main_window.clear_viewers()

                # Store file content for tab switching
                self.main_window.current_file_content = file_content

                # Update the current selected data
                self.main_window.current_selected_data = file_data

                # Display in viewer tabs
                self.main_window.update_viewer_with_file_content(file_content, file_data)

                # Make sure viewer tabs are visible
                if hasattr(self.main_window, 'viewer_dock'):
                    self.main_window.viewer_dock.show()

                print(f"Displaying carved file in preview: {file_data.get('name', 'Unknown')}")
            else:
                print("Could not access main window preview tabs")

        except Exception as e:
            print(f"Error loading carved file for preview: {e}")
            import traceback
            traceback.print_exc()

    def handle_resize_event(self, event):
        # Calculate total width of the table
        total_width = self.table_widget.width()

        # Fixed columns: Id, Size, Type, Confidence, Date
        fixed_width = (self.table_widget.columnWidth(0) +  # Id
                       self.table_widget.columnWidth(2) +  # Size
                       self.table_widget.columnWidth(3) +  # Type
                       self.table_widget.columnWidth(4) +  # Confidence
                       self.table_widget.columnWidth(5))   # Date

        # Remaining space for dynamic columns
        remaining_width = total_width - fixed_width

        # Allocate remaining space proportionally
        self.table_widget.setColumnWidth(1, remaining_width // 2)  # Name column
        self.table_widget.setColumnWidth(6, remaining_width // 2)  # File Path column

        super(QTableWidget, self.table_widget).resizeEvent(event)
