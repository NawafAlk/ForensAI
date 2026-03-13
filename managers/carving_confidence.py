"""
Carving Confidence System

Evaluates the quality/integrity of carved files based on multiple dimensions:
- Structural integrity (header/footer presence)
- Size consistency (expected vs actual)
- Parsability (can the file be opened/validated)

Each carved file receives a confidence score 0-100 with a tier classification.
"""

import io
import struct
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from PIL import Image

try:
    from PyPDF2 import PdfReader
    from PyPDF2.errors import PdfReadError
except ImportError:
    PdfReader = None
    PdfReadError = Exception

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False


@dataclass
class ConfidenceResult:
    """Result of confidence evaluation for a carved file."""
    score: int
    structural: int
    size_match: int
    parsability: int
    tier: str
    tier_color: str
    details: List[str] = field(default_factory=list)


CONFIDENCE_TIERS = {
    'complete': {'min': 90, 'max': 100, 'color': '#4CAF50', 'name': 'Complete'},
    'good': {'min': 70, 'max': 89, 'color': '#8BC34A', 'name': 'Good'},
    'partial': {'min': 50, 'max': 69, 'color': '#FFC107', 'name': 'Partial'},
    'damaged': {'min': 30, 'max': 49, 'color': '#FF9800', 'name': 'Damaged'},
    'fragment': {'min': 0, 'max': 29, 'color': '#F44336', 'name': 'Fragment'},
}


def get_tier(score: int) -> tuple:
    """Get tier name and color for a given score."""
    for tier_key, tier_info in CONFIDENCE_TIERS.items():
        if tier_info['min'] <= score <= tier_info['max']:
            return tier_info['name'], tier_info['color']
    return 'Fragment', '#F44336'


class CarvingConfidence:
    """Evaluates confidence scores for carved files."""

    WEIGHT_STRUCTURAL = 0.40
    WEIGHT_SIZE = 0.30
    WEIGHT_PARSABILITY = 0.30

    def __init__(self):
        """Initialize the confidence evaluator."""
        self.evaluators = {
            'jpg': self._evaluate_jpg,
            'jpeg': self._evaluate_jpg,
            'png': self._evaluate_png,
            'gif': self._evaluate_gif,
            'bmp': self._evaluate_bmp,
            'pdf': self._evaluate_pdf,
            'mp4': self._evaluate_mp4,
            'mov': self._evaluate_mov,
            'wmv': self._evaluate_wmv,
            'wav': self._evaluate_wav,
            'zip': self._evaluate_zip,
            'docx': self._evaluate_office,
            'xlsx': self._evaluate_office,
            'pptx': self._evaluate_office,
        }

    def evaluate(self, file_path: str, file_type: str,
                 carving_metadata: Optional[Dict[str, Any]] = None,
                 file_content: Optional[bytes] = None) -> ConfidenceResult:
        """
        Evaluate confidence for a carved file.

        Args:
            file_path: Path to the carved file
            file_type: File type (e.g., 'jpg', 'png', 'pdf')
            carving_metadata: Metadata captured during carving process
            file_content: Optional pre-loaded file content (avoids re-reading)

        Returns:
            ConfidenceResult with score, component scores, tier, and details
        """
        metadata = carving_metadata or {}
        details = []

        if file_content is None:
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
            except Exception as e:
                details.append(f"Failed to read file: {e}")
                tier_name, tier_color = get_tier(0)
                return ConfidenceResult(
                    score=0,
                    structural=0,
                    size_match=0,
                    parsability=0,
                    tier=tier_name,
                    tier_color=tier_color,
                    details=details
                )

        file_type_lower = file_type.lower()
        evaluator = self.evaluators.get(file_type_lower, self._evaluate_generic)

        structural, size_match, parsability, type_details = evaluator(
            file_content, file_path, metadata
        )
        details.extend(type_details)

        overall = int(
            structural * self.WEIGHT_STRUCTURAL +
            size_match * self.WEIGHT_SIZE +
            parsability * self.WEIGHT_PARSABILITY
        )

        tier_name, tier_color = get_tier(overall)

        details.insert(0, f"Overall: {overall}% ({tier_name})")
        details.insert(1, f"Structure: {structural}%, Size: {size_match}%, Parsability: {parsability}%")

        return ConfidenceResult(
            score=overall,
            structural=structural,
            size_match=size_match,
            parsability=parsability,
            tier=tier_name,
            tier_color=tier_color,
            details=details
        )

    def _evaluate_jpg(self, content: bytes, file_path: str,
                      metadata: Dict) -> tuple:
        """Evaluate JPEG file confidence."""
        details = []
        structural = 0
        size_match = 100
        parsability = 0

        if content[:3] == b'\xFF\xD8\xFF':
            structural += 25
            details.append("Valid JPEG header (FFD8FF)")
        else:
            details.append("Missing or invalid JPEG header")

        if content[-2:] == b'\xFF\xD9':
            structural += 75
            details.append("Valid JPEG footer (FFD9)")
        elif b'\xFF\xD9' in content:
            structural += 50
            details.append("JPEG footer found but not at file end")
        else:
            details.append("Missing JPEG footer (truncated)")
            if metadata.get('truncated'):
                details.append("File was truncated at chunk boundary")

        if metadata.get('footer_found') is False:
            size_match = 50
            details.append("No footer found during carving")

        try:
            img = Image.open(io.BytesIO(content))
            img.verify()
            parsability = 70
            details.append("PIL verify() passed")

            img = Image.open(io.BytesIO(content))
            img.load()
            parsability = 100
            details.append(f"Image loadable: {img.size[0]}x{img.size[1]}")
        except Exception as e:
            details.append(f"PIL validation failed: {str(e)[:50]}")

        return structural, size_match, parsability, details

    def _evaluate_png(self, content: bytes, file_path: str,
                      metadata: Dict) -> tuple:
        """Evaluate PNG file confidence."""
        details = []
        structural = 0
        size_match = 100
        parsability = 0

        png_header = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
        png_footer = b'\x49\x45\x4E\x44\xAE\x42\x60\x82'

        if content[:8] == png_header:
            structural += 25
            details.append("Valid PNG header")
        else:
            details.append("Missing or invalid PNG header")

        if content[-12:-4] == b'\x00\x00\x00\x00IEND' or content.endswith(png_footer):
            structural += 75
            details.append("Valid PNG IEND footer")
        elif png_footer in content:
            structural += 50
            details.append("IEND chunk found but not at end")
        else:
            details.append("Missing PNG IEND chunk (truncated)")

        if len(content) > 24:
            try:
                ihdr_pos = content.find(b'IHDR')
                if ihdr_pos > 0:
                    width = struct.unpack('>I', content[ihdr_pos + 4:ihdr_pos + 8])[0]
                    height = struct.unpack('>I', content[ihdr_pos + 8:ihdr_pos + 12])[0]
                    if 0 < width < 50000 and 0 < height < 50000:
                        details.append(f"IHDR dimensions: {width}x{height}")
                    else:
                        size_match = 50
                        details.append(f"Suspicious dimensions: {width}x{height}")
            except Exception:
                pass

        try:
            img = Image.open(io.BytesIO(content))
            img.verify()
            parsability = 70
            details.append("PIL verify() passed")

            img = Image.open(io.BytesIO(content))
            img.load()
            parsability = 100
            details.append(f"Image loadable: {img.size[0]}x{img.size[1]}")
        except Exception as e:
            details.append(f"PIL validation failed: {str(e)[:50]}")

        return structural, size_match, parsability, details

    def _evaluate_gif(self, content: bytes, file_path: str,
                      metadata: Dict) -> tuple:
        """Evaluate GIF file confidence."""
        details = []
        structural = 0
        size_match = 100
        parsability = 0

        if content[:6] in (b'GIF87a', b'GIF89a'):
            structural += 40
            details.append(f"Valid GIF header: {content[:6].decode('ascii')}")
        else:
            details.append("Missing or invalid GIF header")

        if content[-1:] == b'\x3B':
            structural += 60
            details.append("Valid GIF trailer (0x3B)")
        elif b'\x3B' in content[-10:]:
            structural += 40
            details.append("GIF trailer found near end")
        else:
            details.append("Missing GIF trailer")

        try:
            img = Image.open(io.BytesIO(content))
            img.verify()
            parsability = 70
            details.append("PIL verify() passed")

            img = Image.open(io.BytesIO(content))
            img.load()
            parsability = 100
            details.append(f"GIF loadable: {img.size[0]}x{img.size[1]}")
        except Exception as e:
            details.append(f"PIL validation failed: {str(e)[:50]}")

        return structural, size_match, parsability, details

    def _evaluate_bmp(self, content: bytes, file_path: str,
                      metadata: Dict) -> tuple:
        """Evaluate BMP file confidence."""
        details = []
        structural = 0
        size_match = 0
        parsability = 0

        if content[:2] == b'BM':
            structural += 50
            details.append("Valid BMP header (BM)")
        else:
            details.append("Missing BMP header")

        if len(content) >= 6:
            try:
                declared_size = struct.unpack('<I', content[2:6])[0]
                actual_size = len(content)

                if declared_size == actual_size:
                    size_match = 100
                    structural += 50
                    details.append(f"File size matches header: {actual_size} bytes")
                elif 0.9 <= actual_size / declared_size <= 1.1:
                    size_match = 70
                    structural += 30
                    details.append(f"Size close: declared {declared_size}, actual {actual_size}")
                else:
                    size_match = 30
                    details.append(f"Size mismatch: declared {declared_size}, actual {actual_size}")
            except Exception:
                size_match = 50
                details.append("Could not parse BMP size field")

        try:
            img = Image.open(io.BytesIO(content))
            img.verify()
            parsability = 70
            details.append("PIL verify() passed")

            img = Image.open(io.BytesIO(content))
            img.load()
            parsability = 100
            details.append(f"BMP loadable: {img.size[0]}x{img.size[1]}")
        except Exception as e:
            details.append(f"PIL validation failed: {str(e)[:50]}")

        return structural, size_match, parsability, details

    def _evaluate_pdf(self, content: bytes, file_path: str,
                      metadata: Dict) -> tuple:
        """Evaluate PDF file confidence."""
        details = []
        structural = 0
        size_match = 100
        parsability = 0

        if content[:5] == b'%PDF-':
            structural += 25
            version = content[5:8].decode('ascii', errors='ignore')
            details.append(f"Valid PDF header (version {version})")
        else:
            details.append("Missing PDF header")

        if b'%%EOF' in content[-1024:]:
            structural += 50
            details.append("Valid PDF trailer (%%EOF)")
        elif b'%%EOF' in content:
            structural += 30
            details.append("%%EOF found but not near end")
        else:
            details.append("Missing PDF trailer")

        if b'/Linearized' in content[:1024]:
            structural += 25
            details.append("Linearized PDF detected")

            try:
                l_pos = content.find(b'/L ', 0, 2048)
                if l_pos > 0:
                    l_end = content.find(b'/', l_pos + 3)
                    if l_end == -1:
                        l_end = content.find(b' ', l_pos + 3)
                    if l_end > l_pos:
                        declared_size = int(content[l_pos + 3:l_end].split()[0])
                        actual_size = len(content)
                        if 0.95 <= actual_size / declared_size <= 1.05:
                            size_match = 100
                            details.append(f"Size matches /L field: {declared_size}")
                        else:
                            size_match = 60
                            details.append(f"Size differs from /L: declared {declared_size}, actual {actual_size}")
            except Exception:
                pass
        else:
            structural += 15

        if PdfReader is not None:
            try:
                reader = PdfReader(io.BytesIO(content))
                page_count = len(reader.pages)
                if page_count > 0:
                    parsability = 80
                    details.append(f"PyPDF2 parsed {page_count} pages")

                    try:
                        first_page = reader.pages[0]
                        _ = first_page.mediabox
                        parsability = 100
                        details.append("First page accessible")
                    except Exception:
                        details.append("Page access limited")
                else:
                    parsability = 50
                    details.append("PDF has no pages")
            except PdfReadError as e:
                details.append(f"PyPDF2 error: {str(e)[:50]}")
            except Exception as e:
                details.append(f"PDF parsing failed: {str(e)[:50]}")
        else:
            parsability = 50
            details.append("PyPDF2 not available for validation")

        return structural, size_match, parsability, details

    def _evaluate_mp4(self, content: bytes, file_path: str,
                      metadata: Dict) -> tuple:
        """Evaluate MP4 file confidence."""
        details = []
        structural = 0
        size_match = 100
        parsability = 0

        if len(content) >= 12:
            atom_type = content[4:8]
            if atom_type == b'ftyp':
                structural += 40
                brand = content[8:12].decode('ascii', errors='ignore')
                details.append(f"Valid ftyp atom, brand: {brand}")

                mp4_brands = ['isom', 'mp41', 'mp42', 'avc1', 'iso2', 'M4V ', 'M4A ']
                if brand in mp4_brands:
                    structural += 30
                    details.append("Recognized MP4 brand")
                else:
                    structural += 15
                    details.append("Unknown brand")
            else:
                details.append(f"First atom is {atom_type}, not ftyp")

        valid_atoms = [b'ftyp', b'moov', b'mdat', b'free', b'skip', b'wide', b'moof', b'uuid']
        atom_count = 0
        offset = 0
        while offset < min(len(content), 10000):
            if offset + 8 > len(content):
                break
            try:
                atom_size = struct.unpack('>I', content[offset:offset + 4])[0]
                atom_type = content[offset + 4:offset + 8]
                if atom_type in valid_atoms:
                    atom_count += 1
                if atom_size < 8:
                    break
                offset += atom_size
            except Exception:
                break

        if atom_count >= 2:
            structural += 30
            details.append(f"Found {atom_count} valid atoms")

        if CV2_AVAILABLE:
            try:
                import tempfile
                with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name

                cap = cv2.VideoCapture(tmp_path)
                if cap.isOpened():
                    ret, frame = cap.read()
                    if ret:
                        parsability = 100
                        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                        details.append(f"Video playable, ~{frame_count} frames")
                    else:
                        parsability = 50
                        details.append("Video opened but no frames readable")
                    cap.release()
                else:
                    details.append("cv2 could not open video")

                import os
                os.unlink(tmp_path)
            except Exception as e:
                details.append(f"cv2 validation failed: {str(e)[:50]}")
        else:
            parsability = 50
            details.append("cv2 not available for validation")

        return structural, size_match, parsability, details

    def _evaluate_mov(self, content: bytes, file_path: str,
                      metadata: Dict) -> tuple:
        """Evaluate MOV file confidence (similar to MP4)."""
        details = []
        structural = 0
        size_match = 100
        parsability = 0

        valid_atoms = [b'ftyp', b'moov', b'mdat', b'free', b'wide', b'skip', b'pnot']

        if len(content) >= 8:
            atom_type = content[4:8]
            if atom_type in valid_atoms:
                structural += 40
                details.append(f"Valid first atom: {atom_type.decode('ascii', errors='ignore')}")

                if atom_type == b'ftyp' and len(content) >= 12:
                    brand = content[8:12].decode('ascii', errors='ignore')
                    details.append(f"Brand: {brand}")
            else:
                details.append(f"Unexpected first atom: {atom_type}")

        atom_count = 0
        offset = 0
        total_atom_size = 0
        while offset < len(content):
            if offset + 8 > len(content):
                break
            try:
                atom_size = struct.unpack('>I', content[offset:offset + 4])[0]
                atom_type = content[offset + 4:offset + 8]

                if atom_size == 0:
                    atom_size = len(content) - offset

                if atom_type in valid_atoms:
                    atom_count += 1
                    total_atom_size += atom_size

                if atom_size < 8:
                    break
                offset += atom_size
            except Exception:
                break

        if atom_count >= 2:
            structural += 30
            details.append(f"Found {atom_count} valid atoms")

        if total_atom_size > 0:
            coverage = total_atom_size / len(content)
            if coverage > 0.9:
                structural += 30
                details.append(f"Atom coverage: {coverage:.1%}")
            else:
                structural += int(30 * coverage)
                details.append(f"Partial atom coverage: {coverage:.1%}")

        if CV2_AVAILABLE:
            try:
                import tempfile
                with tempfile.NamedTemporaryFile(suffix='.mov', delete=False) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name

                cap = cv2.VideoCapture(tmp_path)
                if cap.isOpened():
                    ret, frame = cap.read()
                    if ret:
                        parsability = 100
                        details.append("Video playable")
                    else:
                        parsability = 50
                        details.append("Video opened but frames not readable")
                    cap.release()
                else:
                    details.append("cv2 could not open video")

                import os
                os.unlink(tmp_path)
            except Exception as e:
                details.append(f"cv2 validation failed: {str(e)[:50]}")
        else:
            parsability = 50
            details.append("cv2 not available")

        return structural, size_match, parsability, details

    def _evaluate_wmv(self, content: bytes, file_path: str,
                      metadata: Dict) -> tuple:
        """Evaluate WMV/ASF file confidence."""
        details = []
        structural = 0
        size_match = 100
        parsability = 0

        asf_header = b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C'

        if content[:16] == asf_header:
            structural += 50
            details.append("Valid ASF header GUID")
        else:
            details.append("Missing ASF header")

        if len(content) >= 24:
            try:
                header_size = struct.unpack('<Q', content[16:24])[0]
                if header_size > 0 and header_size < len(content):
                    structural += 25
                    details.append(f"Header size: {header_size} bytes")

                    file_props_guid = b'\xA1\xDC\xAB\x8C\x47\xA9\xCF\x11\x8E\xE4\x00\xC0\x0C\x20\x53\x65'
                    if file_props_guid in content[:min(1024, len(content))]:
                        structural += 25
                        details.append("File properties object found")
            except Exception:
                pass

        if CV2_AVAILABLE:
            try:
                import tempfile
                with tempfile.NamedTemporaryFile(suffix='.wmv', delete=False) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name

                cap = cv2.VideoCapture(tmp_path)
                if cap.isOpened():
                    ret, frame = cap.read()
                    if ret:
                        parsability = 100
                        details.append("Video playable")
                    else:
                        parsability = 50
                        details.append("Video opened but frames not readable")
                    cap.release()

                import os
                os.unlink(tmp_path)
            except Exception as e:
                details.append(f"cv2 validation failed: {str(e)[:50]}")
        else:
            parsability = 50
            details.append("cv2 not available")

        return structural, size_match, parsability, details

    def _evaluate_wav(self, content: bytes, file_path: str,
                      metadata: Dict) -> tuple:
        """Evaluate WAV file confidence."""
        details = []
        structural = 0
        size_match = 0
        parsability = 0

        if content[:4] == b'RIFF':
            structural += 30
            details.append("Valid RIFF header")
        else:
            details.append("Missing RIFF header")

        if len(content) >= 12 and content[8:12] == b'WAVE':
            structural += 30
            details.append("Valid WAVE format marker")
        else:
            details.append("Missing WAVE marker")

        if len(content) >= 8:
            try:
                declared_size = struct.unpack('<I', content[4:8])[0] + 8
                actual_size = len(content)

                if declared_size == actual_size:
                    size_match = 100
                    structural += 40
                    details.append(f"Size matches header: {actual_size} bytes")
                elif 0.9 <= actual_size / declared_size <= 1.1:
                    size_match = 70
                    structural += 20
                    details.append(f"Size close: declared {declared_size}, actual {actual_size}")
                else:
                    size_match = 30
                    details.append(f"Size mismatch: declared {declared_size}, actual {actual_size}")
            except Exception:
                size_match = 50

        if b'fmt ' in content[:100]:
            details.append("fmt chunk found")
            parsability += 30

        if b'data' in content[:1000]:
            details.append("data chunk found")
            parsability += 30

        if structural >= 60 and size_match >= 70:
            parsability += 40
            details.append("Structure appears valid")

        return structural, size_match, parsability, details

    def _evaluate_zip(self, content: bytes, file_path: str,
                      metadata: Dict) -> tuple:
        """Evaluate ZIP file confidence."""
        details = []
        structural = 0
        size_match = 100
        parsability = 0

        if content[:4] == b'PK\x03\x04':
            structural += 25
            details.append("Valid ZIP local file header (PK)")
        else:
            details.append("Missing ZIP header")

        eocd_pos = content.rfind(b'PK\x05\x06')
        if eocd_pos > 0:
            structural += 50
            details.append("End of central directory found")

            if eocd_pos + 22 <= len(content):
                try:
                    total_entries = struct.unpack('<H', content[eocd_pos + 10:eocd_pos + 12])[0]
                    details.append(f"Declares {total_entries} files")
                except Exception:
                    pass
        else:
            details.append("Missing end of central directory (truncated)")

        if b'PK\x01\x02' in content:
            structural += 25
            details.append("Central directory entries found")

        try:
            zf = zipfile.ZipFile(io.BytesIO(content))
            file_list = zf.namelist()
            parsability = 70
            details.append(f"zipfile opened: {len(file_list)} entries")

            bad_file = zf.testzip()
            if bad_file is None:
                parsability = 100
                details.append("ZIP integrity check passed")
            else:
                parsability = 60
                details.append(f"Corrupted entry: {bad_file}")
            zf.close()
        except zipfile.BadZipFile as e:
            details.append(f"Bad ZIP: {str(e)[:50]}")
        except Exception as e:
            details.append(f"ZIP parsing failed: {str(e)[:50]}")

        return structural, size_match, parsability, details

    def _evaluate_office(self, content: bytes, file_path: str,
                         metadata: Dict) -> tuple:
        """Evaluate Office files (DOCX, XLSX, PPTX) which are ZIP-based."""
        details = []

        structural, size_match, parsability, zip_details = self._evaluate_zip(
            content, file_path, metadata
        )

        for detail in zip_details:
            details.append(f"[ZIP] {detail}")

        try:
            zf = zipfile.ZipFile(io.BytesIO(content))
            file_list = zf.namelist()

            if '[Content_Types].xml' in file_list:
                structural = min(100, structural + 10)
                details.append("[Content_Types].xml present")

                content_types = zf.read('[Content_Types].xml').decode('utf-8', errors='ignore')

                if 'wordprocessingml' in content_types and any('word/' in f for f in file_list):
                    details.append("Identified as DOCX")
                    if 'word/document.xml' in file_list:
                        parsability = min(100, parsability + 10)
                        details.append("word/document.xml present")
                elif 'spreadsheetml' in content_types and any('xl/' in f for f in file_list):
                    details.append("Identified as XLSX")
                    if 'xl/workbook.xml' in file_list:
                        parsability = min(100, parsability + 10)
                        details.append("xl/workbook.xml present")
                elif 'presentationml' in content_types and any('ppt/' in f for f in file_list):
                    details.append("Identified as PPTX")
                    if 'ppt/presentation.xml' in file_list:
                        parsability = min(100, parsability + 10)
                        details.append("ppt/presentation.xml present")

            zf.close()
        except Exception as e:
            details.append(f"Office structure check failed: {str(e)[:50]}")

        return structural, size_match, parsability, details

    def _evaluate_generic(self, content: bytes, file_path: str,
                          metadata: Dict) -> tuple:
        """Generic evaluation for unknown file types."""
        details = []
        structural = 50
        size_match = 100 if not metadata.get('truncated') else 50
        parsability = 50

        details.append("Generic file type - limited validation")

        if metadata.get('header_found'):
            details.append("Header was found during carving")

        if metadata.get('footer_found'):
            structural = 75
            details.append("Footer was found during carving")
        elif metadata.get('footer_found') is False:
            structural = 40
            details.append("No footer found during carving")

        if metadata.get('truncated'):
            size_match = 40
            details.append("File was truncated at boundary")

        details.append(f"File size: {len(content)} bytes")

        return structural, size_match, parsability, details
