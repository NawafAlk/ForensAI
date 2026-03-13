"""
About dialog displaying ForensAI version, credits, and license information.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap, QFont, QPalette, QColor
from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout


class AboutDialog(QDialog):
    """Modal dialog showing ForensAI application version, author credits, and license."""

    def __init__(self, parent=None):
        super(AboutDialog, self).__init__(parent)

        self.setWindowTitle("About ForensAI")
        layout = QVBoxLayout(self)

        # Load and scale the logo
        logo = QLabel(self)
        pixmap = QPixmap('Icons/logo_about.png')  # Inverted logo for about dialog
        # Adjust the logo size here
        scaled_pixmap = pixmap.scaled(400, 400, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo.setPixmap(scaled_pixmap)
        logo.setAlignment(Qt.AlignCenter)  # Center the logo
        layout.addWidget(logo)

        # Software information
        title_label = QLabel("ForensAI - Toolkit for Retrieval and Analysis of Cyber Evidence")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont('Arial', 20, QFont.Bold))  # Set the font, size, and weight
        title_label.setPalette(QPalette(QColor('blue')))  # Set the text color
        layout.addWidget(title_label)

        version_label = QLabel("Version 1.0.0")
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)

        author_label = QLabel("Built By : Nawaf & Manu")
        author_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(author_label)

        # Add a button to close the dialog
        button_layout = QHBoxLayout()
        button_layout.addStretch()  # Add stretchable space on the left
        close_button = QPushButton("Close")
        close_button.setFixedSize(100, 30)  # Set the size of the button
        close_button.clicked.connect(self.close)
        button_layout.addWidget(close_button)  # Add the button to the layout
        button_layout.addStretch()  # Add stretchable space on the right

        # Add the QHBoxLayout to the main QVBoxLayout
        layout.addLayout(button_layout)

        self.setLayout(layout)
        # Set the size of the dialog
        self.setFixedSize(500, 700)
