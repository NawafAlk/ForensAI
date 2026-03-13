"""
Veriphone API widget for phone number verification during investigations.

Queries the Veriphone REST API to validate phone numbers extracted from
forensic artifacts and displays carrier, country, and line-type details.
"""

import requests
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap, QIcon
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QTextBrowser, QLineEdit, QLabel, QToolBar,
                               QSizePolicy, QMessageBox)


class VeriphoneWidget(QWidget):
    """
    Phone number verification widget using the Veriphone REST API.

    Validates phone numbers extracted from forensic artifacts and displays
    carrier information, country, line type, and validity status.
    """

    def __init__(self):
        super().__init__()
        self.api_key = None
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setSpacing(0)
        self.layout.setContentsMargins(0, 0, 0, 0)

        self.setFixedSize(600, 400)

        self.setWindowTitle("Veriphone Phone Number Verification")

        self.setWindowIcon(QIcon('Icons/logo.ico'))

        self.toolbar = QToolBar("Veriphone Toolbar", self)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.layout.addWidget(self.toolbar)

        self.phone_input = QLineEdit(self)
        self.phone_input.setFixedSize(300, 30)
        self.phone_input.setPlaceholderText("Enter phone number with country code")
        self.toolbar.addWidget(self.phone_input)
        self.phone_input.returnPressed.connect(self.verify_phone_number)

        spacer = QWidget(self)
        spacer.setFixedSize(10, 10)
        self.toolbar.addWidget(spacer)

        verify_button = QPushButton("Verify", self)
        verify_button.clicked.connect(self.verify_phone_number)
        self.toolbar.addWidget(verify_button)

        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

        self.logo_label = QLabel(self)
        self.logo_pixmap = QPixmap("Icons/logo_veriphone.png")
        self.logo_label.setPixmap(self.logo_pixmap.scaled(120, 70, Qt.KeepAspectRatio,
                                                          Qt.SmoothTransformation))
        self.toolbar.addWidget(self.logo_label)

        self.info_text_edit = QTextBrowser(self)
        self.info_text_edit.setReadOnly(True)
        self.layout.addWidget(self.info_text_edit)

    def set_api_key(self, key):
        self.api_key = key

    def use_api_key(self):
        if not self.api_key:
            raise ValueError("API key not set")

    def verify_phone_number(self):
        if not self.api_key:
            QMessageBox.warning(self, "API Key Not Set",
                                "Please set the API key in the Options menu before verifying a phone number.")
            return

        phone_number = self.phone_input.text()
        if phone_number:
            self.update_veriphone_info(phone_number)
        else:
            QMessageBox.warning(self, "Input Error", "Please enter a phone number to verify.")

    def update_veriphone_info(self, phone_number):
        data = self.verify_phone_with_veriphone(phone_number)
        if data.get('status') == 'success':
            info_text = self.format_data_as_html(data)
            self.info_text_edit.setHtml(info_text)
        else:
            self.info_text_edit.setText("Failed to fetch data or phone number is invalid.")

    def verify_phone_with_veriphone(self, phone_number):
        url = f"https://api.veriphone.io/v2/verify?phone={phone_number}&key={self.api_key}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {"status": "error", "message": "Failed to verify phone number."}

    def format_data_as_html(self, data):
        phone_region = data.get('phone_region', 'N/A')
        country = data.get('country', 'N/A')
        country_code = data.get('country_code', 'N/A')
        country_prefix = data.get('country_prefix', 'N/A')
        international_number = data.get('international_number', 'N/A')
        local_number = data.get('local_number', 'N/A')
        e164 = data.get('e164', 'N/A')
        carrier = data.get('carrier', 'N/A')

        html_content = f"""
        <div style="font-family: Arial;">
            <h2>Veriphone Information</h2>
            <p><strong>Phone Number:</strong> {data.get('phone', 'N/A')}</p>
            <p><strong>Valid:</strong> {data.get('phone_valid', 'N/A')}</p>
            <p><strong>Carrier:</strong> {carrier}</p>
            <p><strong>Type:</strong> {data.get('phone_type', 'N/A')}</p>
            <p><strong>Region:</strong> {phone_region}</p>
            <p><strong>Country:</strong> {country}</p>
            <p><strong>Country Code:</strong> {country_code}</p>
            <p><strong>Country Prefix:</strong> {country_prefix}</p>
            <p><strong>International Number:</strong> {international_number}</p>
            <p><strong>Local Number:</strong> {local_number}</p>
            <p><strong>E164 Format:</strong> {e164}</p>

        </div>
        """
        return html_content
