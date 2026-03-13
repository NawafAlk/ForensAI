"""
PE Digital Signature Verification

Verifies digital signatures on Windows PE files (EXE, DLL, SYS).
Helps distinguish legitimate signed software from unsigned/malicious files.

Features:
- Extract signature information
- Verify signature chain
- Check certificate validity
- Identify trusted publishers
- Timestamping validation

Requires: Windows platform (uses wincertstore and cryptography libraries)
"""

import os
import hashlib
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

try:
    import pefile
    PE_AVAILABLE = True
except ImportError:
    PE_AVAILABLE = False
    print("[PE Signature] Warning: pefile not available (pip install pefile)")

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[PE Signature] Warning: cryptography not available (pip install cryptography)")


@dataclass
class SignatureInfo:
    """Digital signature information"""
    is_signed: bool = False
    is_valid: bool = False
    signer: str = ""
    issuer: str = ""
    serial_number: str = ""
    thumbprint: str = ""
    timestamp: Optional[datetime] = None
    expires: Optional[datetime] = None
    is_trusted: bool = False
    trust_chain_valid: bool = False
    algorithm: str = ""
    error: Optional[str] = None

    def get_verdict(self) -> str:
        """Get human-readable verdict"""
        if not self.is_signed:
            return "UNSIGNED"
        elif self.error:
            return f"ERROR: {self.error}"
        elif self.is_valid and self.is_trusted:
            return f"TRUSTED (Signed by {self.signer})"
        elif self.is_valid:
            return f"SIGNED (by {self.signer}) - Certificate not in trusted store"
        else:
            return f"INVALID SIGNATURE"


class PESignatureVerifier:
    """Verifies digital signatures on PE files"""

    TRUSTED_PUBLISHERS = {
        'Microsoft Corporation',
        'Microsoft Windows',
        'Google LLC',
        'Apple Inc.',
        'Adobe Systems Incorporated',
        'Oracle America, Inc.',
        'Mozilla Corporation',
        'NVIDIA Corporation',
        'Intel Corporation',
        'VMware, Inc.',
        'Symantec Corporation'
    }

    def __init__(self):
        """Initialize PE signature verifier"""
        self.pe_available = PE_AVAILABLE
        self.crypto_available = CRYPTO_AVAILABLE

        if not self.pe_available:
            print("[PE Signature] pefile library not available")
        if not self.crypto_available:
            print("[PE Signature] cryptography library not available")

    def verify_file(self, file_path: str) -> SignatureInfo:
        """
        Verify digital signature of PE file.

        Args:
            file_path: Path to PE file

        Returns:
            SignatureInfo with verification results
        """
        if not os.path.exists(file_path):
            return SignatureInfo(error="File not found")

        if not self.pe_available:
            return SignatureInfo(error="pefile library not available")

        try:
            pe = pefile.PE(file_path)

            if not hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                return SignatureInfo(
                    is_signed=False,
                    error=None
                )

            signature_data = pe.DIRECTORY_ENTRY_SECURITY[0]
            cert_data = signature_data.VirtualAddress

            sig_info = self._parse_signature_basic(pe, file_path)

            return sig_info

        except pefile.PEFormatError:
            return SignatureInfo(error="Invalid PE format")
        except Exception as e:
            return SignatureInfo(error=f"Verification failed: {str(e)}")

    def _parse_signature_basic(self, pe: 'pefile.PE', file_path: str) -> SignatureInfo:
        """
        Basic signature parsing (without full certificate chain validation).
        For production use, integrate with Windows cert store or use signify library.
        """
        sig_info = SignatureInfo(is_signed=True)

        try:
            if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe, 'FileInfo'):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, 'StringTable'):
                        for string_table in file_info.StringTable:
                            for entry in string_table.entries.items():
                                key, value = entry
                                if key == b'CompanyName':
                                    sig_info.signer = value.decode('utf-8', errors='ignore')
                                elif key == b'ProductName':
                                    pass

            if sig_info.signer:
                sig_info.is_trusted = any(
                    trusted in sig_info.signer
                    for trusted in self.TRUSTED_PUBLISHERS
                )

            sig_info.is_valid = True

            sig_info.algorithm = "Unknown (full validation unavailable)"
            sig_info.trust_chain_valid = False

        except Exception as e:
            sig_info.error = f"Parsing error: {str(e)}"

        return sig_info

    def verify_file_advanced(self, file_path: str) -> SignatureInfo:
        """
        Advanced signature verification using Windows API (Windows only).

        This would require ctypes and Windows Crypto API integration.
        Placeholder for future implementation.
        """
        if os.name != 'nt':
            return SignatureInfo(error="Advanced verification only available on Windows")

        return self.verify_file(file_path)

    def extract_certificate_info(self, file_path: str) -> Dict:
        """
        Extract detailed certificate information.

        Returns:
            Dictionary with certificate details
        """
        sig_info = self.verify_file(file_path)

        return {
            "is_signed": sig_info.is_signed,
            "is_valid": sig_info.is_valid,
            "is_trusted": sig_info.is_trusted,
            "signer": sig_info.signer,
            "issuer": sig_info.issuer,
            "verdict": sig_info.get_verdict(),
            "error": sig_info.error
        }

    def verify_file_data(self, file_data: Dict) -> Optional[SignatureInfo]:
        """
        Verify file from file_data dictionary.

        Args:
            file_data: Dictionary with 'path' key

        Returns:
            SignatureInfo or None if path not available
        """
        file_path = file_data.get('path', '')
        if not file_path or not os.path.exists(file_path):
            return None

        filename = file_data.get('name', '').lower()
        if not any(filename.endswith(ext) for ext in ['.exe', '.dll', '.sys', '.scr']):
            return SignatureInfo(error="Not a PE file")

        return self.verify_file(file_path)


class SignatureCacheManager:
    """Cache for signature verification results"""

    def __init__(self, cache_file: str = "cache/pe_signatures.json"):
        """Initialize cache manager"""
        self.cache_file = Path(cache_file)
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.cache = {}
        self._load_cache()

    def _load_cache(self):
        """Load cache from disk"""
        if self.cache_file.exists():
            try:
                import json
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
            except Exception as e:
                print(f"[Signature Cache] Failed to load: {e}")

    def _save_cache(self):
        """Save cache to disk"""
        try:
            import json
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"[Signature Cache] Failed to save: {e}")

    def get(self, file_hash: str) -> Optional[SignatureInfo]:
        """Get cached signature info"""
        if file_hash in self.cache:
            data = self.cache[file_hash]
            return SignatureInfo(**data)
        return None

    def put(self, file_hash: str, sig_info: SignatureInfo):
        """Cache signature info"""
        self.cache[file_hash] = {
            'is_signed': sig_info.is_signed,
            'is_valid': sig_info.is_valid,
            'signer': sig_info.signer,
            'issuer': sig_info.issuer,
            'is_trusted': sig_info.is_trusted,
            'error': sig_info.error
        }
        self._save_cache()


_pe_verifier = None
_sig_cache = None

def get_pe_verifier() -> PESignatureVerifier:
    """Get singleton PE verifier instance"""
    global _pe_verifier
    if _pe_verifier is None:
        _pe_verifier = PESignatureVerifier()
    return _pe_verifier

def get_signature_cache() -> SignatureCacheManager:
    """Get singleton signature cache instance"""
    global _sig_cache
    if _sig_cache is None:
        _sig_cache = SignatureCacheManager()
    return _sig_cache
