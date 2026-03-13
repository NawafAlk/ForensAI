"""
ForensAI - AI-Powered Digital Forensics Analysis Platform.

Entry point for the application. Initializes the PySide6 GUI
and launches the main forensic analysis window.
"""

from PySide6.QtWidgets import QApplication
from modules.mainwindow import MainWindow


if __name__ == '__main__':
    app = QApplication([])

    window = MainWindow()
    window.show()
    app.exec()


