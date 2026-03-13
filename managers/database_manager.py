"""
SQLite database manager for file-type icon mappings and acquisition records.

Provides lookup of file extension to icon path from the mappings database.
"""

from sqlite3 import connect as sqlite3_connect


class DatabaseManager:
    """Manages the SQLite database for file-type icon resolution."""

    def __init__(self, db_path):
        self.db_conn = sqlite3_connect(db_path)

    def __del__(self):
        self.db_conn.close()

    def get_icon_path(self, icon_type, identifier):
        c = self.db_conn.cursor()
        try:
            c.execute("SELECT path FROM icons WHERE type = ? AND extention = ?", (icon_type, identifier))
            result = c.fetchone()

            if result:
                return result[0]

            if icon_type == 'folder':
                c.execute("SELECT path FROM icons WHERE type = ? AND extention = 'folder'", (icon_type,))

                result = c.fetchone()
                return result[0] if result else 'Icons/mimetypes/application-x-zerosize.svg'
            else:
                return 'Icons/mimetypes/application-x-zerosize.svg'
        finally:
            c.close()

