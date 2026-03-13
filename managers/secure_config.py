"""
Encrypted API key storage manager for ForensAI.

Replaces plaintext config.ini storage with encrypted storage using
cryptography.Fernet for encryption and system keyring for master key
management. Falls back gracefully to plain config.ini if dependencies
are not available.
"""

import configparser
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Attempt to import optional encryption dependencies
try:
    from cryptography.fernet import Fernet, InvalidToken
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    logger.warning(
        "cryptography package not installed. "
        "API keys will be stored in plaintext config.ini. "
        "Install with: pip install cryptography"
    )

try:
    import keyring
    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False
    logger.warning(
        "keyring package not installed. "
        "API keys will be stored in plaintext config.ini. "
        "Install with: pip install keyring"
    )

ENCRYPTION_AVAILABLE = HAS_CRYPTOGRAPHY and HAS_KEYRING

KEYRING_SERVICE = "ForensAI"
KEYRING_USERNAME = "master_key"
ENCRYPTED_SECTION_PREFIX = "encrypted_"


class SecureConfig:
    """Encrypted configuration storage with config.ini fallback.

    When both ``cryptography`` and ``keyring`` are available, values are
    encrypted with Fernet and the master key is held in the OS keyring.
    If either dependency is missing the class transparently falls back to
    reading and writing plaintext values in config.ini.
    """

    def __init__(self, config_path: str = "config.ini") -> None:
        self._config_path = config_path
        self._config = configparser.ConfigParser()
        if os.path.exists(self._config_path):
            self._config.read(self._config_path, encoding="utf-8")

        self._cipher: Optional[object] = None
        if ENCRYPTION_AVAILABLE:
            try:
                self._cipher = self._get_cipher()
            except Exception as exc:
                logger.warning(
                    "Failed to initialise encryption cipher, "
                    "falling back to plaintext: %s", exc
                )

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def _get_or_create_key(self) -> bytes:
        """Retrieve the Fernet master key from the system keyring.

        If no key exists yet a new one is generated and stored.
        """
        stored_key = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        if stored_key is not None:
            return stored_key.encode("utf-8")

        new_key = Fernet.generate_key()
        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, new_key.decode("utf-8"))
        logger.info("Generated and stored new ForensAI master encryption key in system keyring.")
        return new_key

    def _get_cipher(self):
        """Create a Fernet cipher instance from the master key."""
        key = self._get_or_create_key()
        return Fernet(key)

    # ------------------------------------------------------------------
    # Encryption helpers
    # ------------------------------------------------------------------

    def _encrypt(self, value: str) -> str:
        """Encrypt a string value and return it as a base64-encoded string."""
        if self._cipher is None:
            raise RuntimeError("Encryption is not available.")
        token = self._cipher.encrypt(value.encode("utf-8"))
        return token.decode("utf-8")

    def _decrypt(self, encrypted: str) -> str:
        """Decrypt a base64-encoded encrypted value back to a string."""
        if self._cipher is None:
            raise RuntimeError("Encryption is not available.")
        plaintext = self._cipher.decrypt(encrypted.encode("utf-8"))
        return plaintext.decode("utf-8")

    # ------------------------------------------------------------------
    # Internal persistence helpers
    # ------------------------------------------------------------------

    def _encrypted_section(self, section: str) -> str:
        """Return the config.ini section name used for encrypted values."""
        return f"{ENCRYPTED_SECTION_PREFIX}{section}"

    def _save_config(self) -> None:
        """Write the current in-memory config back to disk."""
        with open(self._config_path, "w", encoding="utf-8") as fh:
            self._config.write(fh)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, section: str, key: str, fallback: str = "") -> str:
        """Get a configuration value.

        Resolution order:
        1. Encrypted storage (if encryption is available).
        2. Plaintext config.ini (enables seamless migration).
        """
        # Try encrypted storage first
        if self._cipher is not None:
            enc_section = self._encrypted_section(section)
            if self._config.has_section(enc_section) and self._config.has_option(enc_section, key):
                try:
                    return self._decrypt(self._config.get(enc_section, key))
                except (InvalidToken, Exception) as exc:
                    logger.warning(
                        "Failed to decrypt [%s] %s, falling back to plaintext: %s",
                        section, key, exc,
                    )

        # Fallback to plaintext section
        if self._config.has_section(section) and self._config.has_option(section, key):
            return self._config.get(section, key)

        return fallback

    def set(self, section: str, key: str, value: str) -> None:
        """Encrypt and store a configuration value.

        If encryption is unavailable the value is stored as plaintext in
        config.ini instead.
        """
        if self._cipher is not None:
            enc_section = self._encrypted_section(section)
            if not self._config.has_section(enc_section):
                self._config.add_section(enc_section)
            self._config.set(enc_section, key, self._encrypt(value))
        else:
            # Fallback: store plaintext
            if not self._config.has_section(section):
                self._config.add_section(section)
            self._config.set(section, key, value)

        self._save_config()

    def delete(self, section: str, key: str) -> None:
        """Remove a configuration value from both encrypted and plaintext storage."""
        changed = False

        # Remove from encrypted section
        enc_section = self._encrypted_section(section)
        if self._config.has_section(enc_section) and self._config.has_option(enc_section, key):
            self._config.remove_option(enc_section, key)
            # Clean up empty sections
            if not self._config.options(enc_section):
                self._config.remove_section(enc_section)
            changed = True

        # Remove from plaintext section
        if self._config.has_section(section) and self._config.has_option(section, key):
            self._config.remove_option(section, key)
            if not self._config.options(section):
                self._config.remove_section(section)
            changed = True

        if changed:
            self._save_config()

    def migrate_from_plaintext(self) -> None:
        """Migrate all plaintext keys in config.ini to encrypted storage.

        After migration the original plaintext values are cleared from the
        config file. This is a no-op when encryption is not available.
        """
        if self._cipher is None:
            logger.warning("Encryption not available; skipping migration.")
            return

        migrated_count = 0
        sections_to_process = [
            s for s in self._config.sections()
            if not s.startswith(ENCRYPTED_SECTION_PREFIX)
        ]

        for section in sections_to_process:
            enc_section = self._encrypted_section(section)
            for key in list(self._config.options(section)):
                plaintext_value = self._config.get(section, key)
                if not plaintext_value:
                    continue

                # Store encrypted version
                if not self._config.has_section(enc_section):
                    self._config.add_section(enc_section)
                self._config.set(enc_section, key, self._encrypt(plaintext_value))

                # Clear the plaintext value
                self._config.remove_option(section, key)
                migrated_count += 1

            # Remove empty plaintext sections
            if not self._config.options(section):
                self._config.remove_section(section)

        if migrated_count:
            self._save_config()
            logger.info("Migrated %d plaintext config values to encrypted storage.", migrated_count)
        else:
            logger.info("No plaintext values found to migrate.")

    def has_section(self, section: str) -> bool:
        """Check whether a section exists in either encrypted or plaintext storage."""
        enc_section = self._encrypted_section(section)
        return (
            self._config.has_section(enc_section)
            or self._config.has_section(section)
        )


# ------------------------------------------------------------------
# Singleton accessor
# ------------------------------------------------------------------

_instance: Optional[SecureConfig] = None


def get_secure_config() -> SecureConfig:
    """Return the singleton SecureConfig instance."""
    global _instance
    if _instance is None:
        _instance = SecureConfig()
    return _instance
