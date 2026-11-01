"""
file_analyzer.py - Digital Evidence File Analyzer Module

This module analyzes digital evidence files by inspecting their:
1. File information (name, extension, size, timestamps).
2. File signatures (magic bytes) to determine the true underlying format.
3. Mime-type and forensic category.
4. Hidden file status (e.g. dotfiles on Unix/Linux).
5. Extension vs signature discrepancies (mismatches).

Forensic principles applied:
- Never trust file extensions: extensions are easily changed by users or attackers.
- Never execute uploaded files: analyze contents passively in memory or temporary read-only buffers.
- An extension mismatch is an anomaly to be manually reviewed, not conclusive proof of malicious activity.
"""

import os
import re
import io
import datetime
from typing import Dict, List, Any, Optional

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

# Chunk size for reading streams safely
CHUNK_SIZE = 8192

# Forensic Categories required by ForensiX
CATEGORIES = [
    'Images',
    'Documents',
    'Videos',
    'Audio',
    'Archives',
    'Executables',
    'Text files',
    'Unknown files'
]

# Common File Signatures (Magic Numbers)
# Format: (magic_bytes, offset, name, category, expected_extensions, mime_type)
SIGNATURE_TABLE = [
    # Images
    (b'\xFF\xD8\xFF', 0, 'JPEG image', 'Images', ['jpg', 'jpeg', 'jpe', 'jfif'], 'image/jpeg'),
    (b'\x89PNG\r\n\x1a\n', 0, 'PNG image', 'Images', ['png'], 'image/png'),
    (b'GIF87a', 0, 'GIF87a image', 'Images', ['gif'], 'image/gif'),
    (b'GIF89a', 0, 'GIF89a image', 'Images', ['gif'], 'image/gif'),
    (b'BM', 0, 'BMP image', 'Images', ['bmp', 'dib'], 'image/bmp'),
    (b'II*\x00', 0, 'TIFF image (little-endian)', 'Images', ['tif', 'tiff'], 'image/tiff'),
    (b'MM\x00*', 0, 'TIFF image (big-endian)', 'Images', ['tif', 'tiff'], 'image/tiff'),
    (b'RIFF', 0, 'WebP image', 'Images', ['webp'], 'image/webp'),  # checked with WEBP at offset 8

    # Documents
    (b'%PDF-', 0, 'PDF document', 'Documents', ['pdf'], 'application/pdf'),
    (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 0, 'Microsoft Office Legacy Document (OLE CFBF)', 'Documents', ['doc', 'xls', 'ppt', 'msg'], 'application/msword'),
    (b'{\\rtf', 0, 'Rich Text Format (RTF)', 'Documents', ['rtf'], 'text/rtf'),

    # Archives / Packages
    (b'PK\x03\x04', 0, 'ZIP archive / OpenXML Document', 'Archives', ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk'], 'application/zip'),
    (b'\x1F\x8B', 0, 'GZIP compressed archive', 'Archives', ['gz', 'gzip', 'tgz'], 'application/gzip'),
    (b'BZh', 0, 'BZIP2 compressed archive', 'Archives', ['bz2'], 'application/x-bzip2'),
    (b'7z\xBC\xAF\x27\x1C', 0, '7-Zip compressed archive', 'Archives', ['7z'], 'application/x-7z-compressed'),
    (b'Rar!\x1A\x07', 0, 'RAR compressed archive', 'Archives', ['rar'], 'application/vnd.rar'),

    # Executables & Binaries
    (b'MZ', 0, 'Windows Portable Executable (EXE/DLL)', 'Executables', ['exe', 'dll', 'sys', 'scr', 'ocx'], 'application/x-dosexec'),
    (b'\x7FELF', 0, 'ELF Executable / Shared Object (Linux/Unix)', 'Executables', ['elf', 'so', 'bin', 'out'], 'application/x-executable'),
    (b'\xFE\xED\xFA\xCE', 0, 'Mach-O binary (32-bit big-endian)', 'Executables', ['dylib', 'bin'], 'application/x-mach-binary'),
    (b'\xFE\xED\xFA\xCF', 0, 'Mach-O binary (64-bit big-endian)', 'Executables', ['dylib', 'bin'], 'application/x-mach-binary'),
    (b'\xCE\xFA\xED\xFE', 0, 'Mach-O binary (32-bit little-endian)', 'Executables', ['dylib', 'bin'], 'application/x-mach-binary'),
    (b'\xCF\xFA\xED\xFE', 0, 'Mach-O binary (64-bit little-endian)', 'Executables', ['dylib', 'bin'], 'application/x-mach-binary'),

    # Audio & Video
    (b'ID3', 0, 'MP3 audio with ID3v2 tag', 'Audio', ['mp3'], 'audio/mpeg'),
    (b'fLaC', 0, 'FLAC audio', 'Audio', ['flac'], 'audio/flac'),
    (b'OggS', 0, 'Ogg audio/video stream', 'Audio', ['ogg', 'oga', 'ogv'], 'audio/ogg'),
    (b'RIFF', 0, 'WAV audio', 'Audio', ['wav'], 'audio/wav'),  # checked with WAVE at offset 8
    (b'RIFF', 0, 'AVI video', 'Videos', ['avi'], 'video/x-msvideo'),  # checked with AVI at offset 8
    (b'\x1A\x45\xDF\xA3', 0, 'Matroska / WebM video', 'Videos', ['mkv', 'webm'], 'video/webm'),
]

# Expected MIME-types and categories for known extensions (for mismatch checking)
EXTENSION_KNOWLEDGE_BASE = {
    # Images
    'jpg': {'category': 'Images', 'mimes': ['image/jpeg'], 'name': 'JPEG Image'},
    'jpeg': {'category': 'Images', 'mimes': ['image/jpeg'], 'name': 'JPEG Image'},
    'png': {'category': 'Images', 'mimes': ['image/png'], 'name': 'PNG Image'},
    'gif': {'category': 'Images', 'mimes': ['image/gif'], 'name': 'GIF Image'},
    'bmp': {'category': 'Images', 'mimes': ['image/bmp', 'image/x-ms-bmp'], 'name': 'Bitmap Image'},
    'webp': {'category': 'Images', 'mimes': ['image/webp'], 'name': 'WebP Image'},
    'tif': {'category': 'Images', 'mimes': ['image/tiff'], 'name': 'TIFF Image'},
    'tiff': {'category': 'Images', 'mimes': ['image/tiff'], 'name': 'TIFF Image'},
    'svg': {'category': 'Images', 'mimes': ['image/svg+xml', 'text/xml', 'text/plain'], 'name': 'SVG Vector Image'},

    # Documents
    'pdf': {'category': 'Documents', 'mimes': ['application/pdf'], 'name': 'PDF Document'},
    'doc': {'category': 'Documents', 'mimes': ['application/msword', 'application/vnd.ms-office'], 'name': 'Microsoft Word (Legacy)'},
    'docx': {'category': 'Documents', 'mimes': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'], 'name': 'Microsoft Word (DOCX)'},
    'xls': {'category': 'Documents', 'mimes': ['application/vnd.ms-excel', 'application/vnd.ms-office'], 'name': 'Microsoft Excel (Legacy)'},
    'xlsx': {'category': 'Documents', 'mimes': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'], 'name': 'Microsoft Excel (XLSX)'},
    'ppt': {'category': 'Documents', 'mimes': ['application/vnd.ms-powerpoint', 'application/vnd.ms-office'], 'name': 'Microsoft PowerPoint (Legacy)'},
    'pptx': {'category': 'Documents', 'mimes': ['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'], 'name': 'Microsoft PowerPoint (PPTX)'},
    'rtf': {'category': 'Documents', 'mimes': ['text/rtf', 'application/rtf'], 'name': 'Rich Text Format'},
    'odt': {'category': 'Documents', 'mimes': ['application/vnd.oasis.opendocument.text', 'application/zip'], 'name': 'OpenDocument Text'},

    # Text files
    'txt': {'category': 'Text files', 'mimes': ['text/plain', 'application/x-empty'], 'name': 'Plain Text'},
    'csv': {'category': 'Text files', 'mimes': ['text/csv', 'text/plain'], 'name': 'CSV Spreadsheet'},
    'json': {'category': 'Text files', 'mimes': ['application/json', 'text/plain'], 'name': 'JSON Data'},
    'xml': {'category': 'Text files', 'mimes': ['application/xml', 'text/xml', 'text/plain'], 'name': 'XML Document'},
    'html': {'category': 'Text files', 'mimes': ['text/html', 'text/plain'], 'name': 'HTML Web Page'},
    'htm': {'category': 'Text files', 'mimes': ['text/html', 'text/plain'], 'name': 'HTML Web Page'},
    'log': {'category': 'Text files', 'mimes': ['text/plain'], 'name': 'System / Application Log'},
    'md': {'category': 'Text files', 'mimes': ['text/markdown', 'text/plain'], 'name': 'Markdown Document'},
    'py': {'category': 'Text files', 'mimes': ['text/x-python', 'text/plain', 'text/x-script.python'], 'name': 'Python Script'},
    'sh': {'category': 'Text files', 'mimes': ['text/x-shellscript', 'text/plain'], 'name': 'Shell Script'},

    # Archives
    'zip': {'category': 'Archives', 'mimes': ['application/zip'], 'name': 'ZIP Archive'},
    'tar': {'category': 'Archives', 'mimes': ['application/x-tar'], 'name': 'TAR Archive'},
    'gz': {'category': 'Archives', 'mimes': ['application/gzip', 'application/x-gzip'], 'name': 'GZIP Archive'},
    'bz2': {'category': 'Archives', 'mimes': ['application/x-bzip2'], 'name': 'BZIP2 Archive'},
    '7z': {'category': 'Archives', 'mimes': ['application/x-7z-compressed'], 'name': '7-Zip Archive'},
    'rar': {'category': 'Archives', 'mimes': ['application/vnd.rar', 'application/x-rar-compressed', 'application/x-rar'], 'name': 'RAR Archive'},

    # Executables
    'exe': {'category': 'Executables', 'mimes': ['application/x-dosexec', 'application/x-msdownload'], 'name': 'Windows Executable'},
    'dll': {'category': 'Executables', 'mimes': ['application/x-dosexec', 'application/x-msdownload'], 'name': 'Dynamic Link Library'},
    'sys': {'category': 'Executables', 'mimes': ['application/x-dosexec'], 'name': 'System Driver'},
    'elf': {'category': 'Executables', 'mimes': ['application/x-executable', 'application/x-pie-executable'], 'name': 'Linux ELF Executable'},
    'bin': {'category': 'Executables', 'mimes': ['application/octet-stream', 'application/x-executable'], 'name': 'Binary Executable / Data'},

    # Audio & Video
    'mp3': {'category': 'Audio', 'mimes': ['audio/mpeg'], 'name': 'MP3 Audio'},
    'wav': {'category': 'Audio', 'mimes': ['audio/wav', 'audio/x-wav'], 'name': 'WAV Audio'},
    'ogg': {'category': 'Audio', 'mimes': ['audio/ogg'], 'name': 'Ogg Audio'},
    'flac': {'category': 'Audio', 'mimes': ['audio/flac'], 'name': 'FLAC Audio'},
    'mp4': {'category': 'Videos', 'mimes': ['video/mp4'], 'name': 'MP4 Video'},
    'avi': {'category': 'Videos', 'mimes': ['video/x-msvideo'], 'name': 'AVI Video'},
    'mkv': {'category': 'Videos', 'mimes': ['video/x-matroska', 'video/webm'], 'name': 'Matroska Video'},
    'webm': {'category': 'Videos', 'mimes': ['video/webm'], 'name': 'WebM Video'},
}


def sanitize_filename(filename: str) -> str:
    """
    Sanitize an uploaded filename safely to prevent directory traversal
    while preserving forensic attributes like leading dots for hidden files.

    Args:
        filename: Raw filename string from the client or filesystem.

    Returns:
        Safe filename string without paths, null bytes, or dangerous sequences.
    """
    if not filename:
        return 'unnamed_file'

    # Strip null bytes and control characters
    cleaned = filename.replace('\x00', '').strip()

    # Normalize backslashes (Windows) to forward slashes (POSIX)
    cleaned = cleaned.replace('\\', '/')

    # Take only the base filename (strips any path traversal like ../../)
    base_name = os.path.basename(cleaned)

    # Remove any internal relative traversal remnants
    while '..' in base_name:
        base_name = base_name.replace('..', '.')

    base_name = base_name.strip()
    if not base_name or base_name in ('.', '..'):
        return 'unnamed_file'

    return base_name


def is_hidden_file(filename: str, file_path: Optional[str] = None) -> bool:
    """
    Detect whether a file is considered hidden.
    On Unix/Linux/macOS, files whose name starts with '.' are hidden.
    On Windows (if supported and path given), check file attributes.

    Args:
        filename: Filename to evaluate.
        file_path: Optional full path to inspect OS-level hidden flags.

    Returns:
        bool: True if the file is hidden, False otherwise.
    """
    # 1. Standard Unix/Linux dotfile rule
    base_name = os.path.basename(filename.strip())
    if base_name.startswith('.'):
        return True

    # 2. Windows filesystem attribute check if path exists on Windows
    if file_path and os.path.exists(file_path) and os.name == 'nt':
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(file_path))
            if attrs != -1 and (attrs & FILE_ATTRIBUTE_HIDDEN):
                return True
        except Exception:
            pass

    return False


def get_file_extension(filename: str) -> str:
    """
    Extract the lowercase extension from a filename without the dot.
    Correctly handles files with multiple dots and dotfiles.

    Examples:
        'document.pdf' -> 'pdf'
        '.hidden.txt'  -> 'txt'
        '.bashrc'      -> ''
        'archive.tar.gz' -> 'gz'
    """
    clean_name = sanitize_filename(filename)
    if '.' not in clean_name:
        return ''

    # Handle dotfiles without extension like '.bashrc' or '.gitignore'
    parts = clean_name.split('.')
    if clean_name.startswith('.') and len(parts) == 2:
        return ''

    ext = parts[-1].lower().strip()
    return ext


def format_file_size(size_bytes: int) -> str:
    """
    Convert a size in bytes to a human-readable string.
    """
    if size_bytes == 0:
        return "0 Bytes"

    units = ['Bytes', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(size_bytes)

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    if unit_index == 0:
        return f"{int(size)} Bytes"
    return f"{size:.2f} {units[unit_index]}"


def get_magic_bytes_preview(header_bytes: bytes, max_len: int = 16) -> Dict[str, str]:
    """
    Generate hexadecimal and printable ASCII representations of the leading bytes.
    This provides investigators with direct file signature verification.

    Args:
        header_bytes: Raw bytes from the beginning of the file.
        max_len: Number of bytes to display (default: 16).

    Returns:
        dict with 'hex' and 'ascii' string representations.
    """
    snippet = header_bytes[:max_len]
    hex_str = ' '.join(f"{b:02X}" for b in snippet)

    ascii_chars = []
    for b in snippet:
        # Printable ASCII is between 32 and 126
        if 32 <= b <= 126:
            ascii_chars.append(chr(b))
        else:
            ascii_chars.append('.')
    ascii_str = ''.join(ascii_chars)

    return {
        'hex': hex_str or 'None (Empty file)',
        'ascii': ascii_str or ''
    }


def is_text_data(buffer: bytes) -> bool:
    """
    Check if a byte buffer consists predominantly of printable text characters
    (ASCII / UTF-8 text).
    """
    if not buffer:
        return True

    # If null byte exists in initial bytes, likely binary
    if b'\x00' in buffer[:512]:
        return False

    try:
        buffer.decode('utf-8')
        return True
    except UnicodeDecodeError:
        pass

    # Count printable characters
    printable = sum(1 for b in buffer if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(buffer)) > 0.85


def inspect_signature(header_bytes: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Identify file format, MIME type, and category using magic bytes table
    and python-magic library.

    Args:
        header_bytes: The initial byte buffer of the file (typically 4096-8192 bytes).
        filename: Filename for contextual resolution if needed.

    Returns:
        dict containing:
            - mime_type (str)
            - detected_format (str)
            - category (str)
            - expected_extensions (list)
    """
    header_len = len(header_bytes)

    # 1. Handle empty file
    if header_len == 0:
        return {
            'mime_type': 'application/x-empty',
            'detected_format': 'Empty file (0 bytes)',
            'category': 'Text files',
            'expected_extensions': ['txt', 'empty']
        }

    # 2. Check Special Sub-type signatures
    # RIFF container checks (WAV vs WebP vs AVI)
    if header_bytes.startswith(b'RIFF') and header_len >= 12:
        tag = header_bytes[8:12]
        if tag == b'WEBP':
            return {
                'mime_type': 'image/webp',
                'detected_format': 'WebP image',
                'category': 'Images',
                'expected_extensions': ['webp']
            }
        elif tag == b'WAVE':
            return {
                'mime_type': 'audio/wav',
                'detected_format': 'WAV audio',
                'category': 'Audio',
                'expected_extensions': ['wav']
            }
        elif tag == b'AVI ':
            return {
                'mime_type': 'video/x-msvideo',
                'detected_format': 'AVI video',
                'category': 'Videos',
                'expected_extensions': ['avi']
            }

    # MP4 / QuickTime ftyp check
    if header_len >= 12 and header_bytes[4:8] == b'ftyp':
        brand = header_bytes[8:12]
        return {
            'mime_type': 'video/mp4',
            'detected_format': f'ISO Base Media / MP4 ({brand.decode("latin1", errors="ignore").strip()})',
            'category': 'Videos',
            'expected_extensions': ['mp4', 'm4v', 'mov']
        }

    # OpenXML Office documents inside ZIP container
    if header_bytes.startswith(b'PK\x03\x04'):
        if b'word/' in header_bytes or b'[Content_Types].xml' in header_bytes:
            # Check if it looks like Word, Excel, or PowerPoint based on fragments
            if b'word/' in header_bytes:
                return {
                    'mime_type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    'detected_format': 'Microsoft Word Document (DOCX)',
                    'category': 'Documents',
                    'expected_extensions': ['docx']
                }
            elif b'xl/' in header_bytes:
                return {
                    'mime_type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    'detected_format': 'Microsoft Excel Spreadsheet (XLSX)',
                    'category': 'Documents',
                    'expected_extensions': ['xlsx']
                }
            elif b'ppt/' in header_bytes:
                return {
                    'mime_type': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                    'detected_format': 'Microsoft PowerPoint Presentation (PPTX)',
                    'category': 'Documents',
                    'expected_extensions': ['pptx']
                }
        return {
            'mime_type': 'application/zip',
            'detected_format': 'ZIP compressed archive / OpenXML container',
            'category': 'Archives',
            'expected_extensions': ['zip', 'jar', 'apk', 'docx', 'xlsx', 'pptx']
        }

    # 3. Check Table of Standard Signatures
    for sig, offset, name, cat, exts, mime in SIGNATURE_TABLE:
        if header_len >= offset + len(sig):
            if header_bytes[offset:offset + len(sig)] == sig:
                return {
                    'mime_type': mime,
                    'detected_format': name,
                    'category': cat,
                    'expected_extensions': exts
                }

    # 4. Check for Plain Text / Code / JSON / XML / HTML
    if is_text_data(header_bytes):
        text_start = header_bytes[:256].lstrip()
        if text_start.startswith(b'<?xml') or text_start.startswith(b'<html') or text_start.startswith(b'<!DOCTYPE html'):
            return {
                'mime_type': 'text/html' if b'html' in text_start.lower() else 'application/xml',
                'detected_format': 'HTML or XML markup document',
                'category': 'Text files',
                'expected_extensions': ['html', 'htm', 'xml']
            }
        if text_start.startswith(b'{') or text_start.startswith(b'['):
            return {
                'mime_type': 'application/json',
                'detected_format': 'JSON text data',
                'category': 'Text files',
                'expected_extensions': ['json', 'txt']
            }
        return {
            'mime_type': 'text/plain',
            'detected_format': 'Plain text (ASCII or UTF-8)',
            'category': 'Text files',
            'expected_extensions': ['txt', 'log', 'csv', 'md', 'py', 'sh', 'json', 'xml', 'sql']
        }

    # 5. Query python-magic if available as authoritative fallback
    if HAS_MAGIC:
        try:
            detected_mime = magic.from_buffer(header_bytes, mime=True)
            detected_desc = magic.from_buffer(header_bytes)
            category = categorize_mime(detected_mime, detected_desc)
            return {
                'mime_type': detected_mime,
                'detected_format': detected_desc,
                'category': category,
                'expected_extensions': []
            }
        except Exception:
            pass

    # 6. Default fallback for unknown binary content
    return {
        'mime_type': 'application/octet-stream',
        'detected_format': 'Unknown binary data',
        'category': 'Unknown files',
        'expected_extensions': []
    }


def categorize_mime(mime_type: str, description: str = "") -> str:
    """
    Map a MIME type and description to one of the 8 ForensiX forensic categories.
    """
    mime = (mime_type or '').lower().strip()
    desc = (description or '').lower().strip()

    if mime.startswith('image/'):
        return 'Images'
    if mime.startswith('video/'):
        return 'Videos'
    if mime.startswith('audio/'):
        return 'Audio'

    # Documents
    if mime == 'application/pdf' or 'pdf' in desc:
        return 'Documents'
    if mime in ('application/msword', 'application/rtf', 'text/rtf') or 'word' in desc or 'excel' in desc or 'powerpoint' in desc:
        return 'Documents'
    if 'officedocument' in mime or 'opendocument' in mime:
        return 'Documents'

    # Archives
    if mime in ('application/zip', 'application/x-tar', 'application/gzip', 'application/x-bzip2',
                 'application/x-7z-compressed', 'application/vnd.rar', 'application/x-rar-compressed', 'application/x-rar'):
        return 'Archives'
    if any(k in desc for k in ['zip archive', 'tar archive', 'gzip', '7-zip', 'rar archive']):
        return 'Archives'

    # Executables
    if mime in ('application/x-dosexec', 'application/x-executable', 'application/x-pie-executable',
                 'application/x-elf', 'application/x-sharedlib', 'application/x-mach-binary'):
        return 'Executables'
    if any(k in desc for k in ['pe32', 'executable', 'elf', 'mach-o', 'ms-dos']):
        return 'Executables'

    # Text files
    if mime.startswith('text/') or mime in ('application/json', 'application/xml', 'application/javascript', 'application/x-yaml'):
        return 'Text files'

    return 'Unknown files'


def check_extension_mismatch(extension: str, signature_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare the declared filename extension against the detected file signature.

    Returns:
        dict:
            - is_mismatch (bool): True if extension and signature disagree
            - warning_message (str or None): Forensic note
            - claimed_format (str or None): What the extension implies
    """
    ext = (extension or '').lower().strip()
    detected_cat = signature_info.get('category', 'Unknown files')
    expected_exts = signature_info.get('expected_extensions', [])
    detected_format = signature_info.get('detected_format', 'Unknown')
    detected_mime = signature_info.get('mime_type', 'application/octet-stream')

    # Case 1: No extension at all
    if not ext:
        return {
            'is_mismatch': False,
            'warning_message': None,
            'claimed_format': 'No extension'
        }

    # What does the extension claim to be according to knowledge base?
    kb_entry = EXTENSION_KNOWLEDGE_BASE.get(ext)
    claimed_format = kb_entry['name'] if kb_entry else f".{ext} file"
    claimed_category = kb_entry['category'] if kb_entry else None

    # Case 2: We have an expected extensions list for this signature
    if expected_exts:
        if ext in expected_exts:
            return {
                'is_mismatch': False,
                'warning_message': None,
                'claimed_format': claimed_format
            }
        else:
            # Clear mismatch: signature explicitly expects a different extension set
            expected_str = ', '.join([f".{e}" for e in expected_exts[:4]])
            msg = (
                f"File extension '.{ext}' does not match detected format '{detected_format}'. "
                f"Expected extension for this signature: {expected_str}."
            )
            return {
                'is_mismatch': True,
                'warning_message': msg,
                'claimed_format': claimed_format
            }

    # Case 3: Signature didn't have a rigid list, but categories disagree
    if claimed_category and claimed_category != detected_cat:
        if detected_cat != 'Unknown files':
            msg = (
                f"File extension '.{ext}' implies a {claimed_category} ({claimed_format}), "
                f"but detected file category is {detected_cat} ({detected_format})."
            )
            return {
                'is_mismatch': True,
                'warning_message': msg,
                'claimed_format': claimed_format
            }

    # Case 4: Extension claims to be a well-known binary format (like PDF, JPEG, EXE),
    # but the content is unknown binary or generic text
    if kb_entry and kb_entry['category'] in ('Images', 'Documents', 'Executables', 'Archives', 'Videos', 'Audio'):
        if detected_mime == 'text/plain' or detected_cat == 'Unknown files':
            msg = (
                f"File is named with extension '.{ext}' ({claimed_format}), but lacks the required "
                f"cryptographic/structural signature of a valid {claimed_format}."
            )
            return {
                'is_mismatch': True,
                'warning_message': msg,
                'claimed_format': claimed_format
            }

    return {
        'is_mismatch': False,
        'warning_message': None,
        'claimed_format': claimed_format
    }


def analyze_file_stream(file_stream, raw_filename: str, client_mtime: Optional[float] = None, file_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform a complete forensic analysis on an uploaded or local file stream.
    Reads chunk by chunk safely to measure size and capture the initial signature.

    Args:
        file_stream: A readable binary stream (supporting .read()).
        raw_filename: The original filename as reported by the client.
        client_mtime: Optional timestamp in seconds passed from client JS lastModified.
        file_path: Optional existing file path on disk to query filesystem stat.

    Returns:
        dict: Detailed forensic analysis data.
    """
    safe_name = sanitize_filename(raw_filename)
    extension = get_file_extension(safe_name)
    is_hidden = is_hidden_file(raw_filename, file_path)

    # Read leading header for signature detection
    header_buffer = bytearray()
    total_bytes = 0

    # Ensure stream is at start
    try:
        file_stream.seek(0)
    except Exception:
        pass

    while True:
        chunk = file_stream.read(CHUNK_SIZE)
        if not chunk:
            break
        if len(header_buffer) < 8192:
            needed = 8192 - len(header_buffer)
            header_buffer.extend(chunk[:needed])
        total_bytes += len(chunk)

    header_bytes = bytes(header_buffer)

    # Signature Analysis
    signature_info = inspect_signature(header_bytes, safe_name)
    preview = get_magic_bytes_preview(header_bytes, max_len=16)
    mismatch_info = check_extension_mismatch(extension, signature_info)

    # Timestamps Gathering
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    mtime_str = "Not provided in upload"
    ctime_str = "Not available (HTTP upload)"
    atime_str = "Not available (HTTP upload)"

    if client_mtime:
        try:
            mtime_dt = datetime.datetime.fromtimestamp(client_mtime / 1000.0, tz=datetime.timezone.utc)
            mtime_str = mtime_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            pass

    if file_path and os.path.exists(file_path):
        try:
            stat = os.stat(file_path)
            mtime_str = datetime.datetime.fromtimestamp(stat.st_mtime, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            atime_str = datetime.datetime.fromtimestamp(stat.st_atime, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            ctime_str = datetime.datetime.fromtimestamp(stat.st_ctime, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            pass

    # Objective forensic assessment note
    if mismatch_info['is_mismatch']:
        forensic_assessment = (
            "Anomaly Detected: File extension does not match internal file signature. "
            "In forensic investigations, this may occur due to accidental renaming, format conversion, "
            "or intentional obfuscation (masquerading). Human manual verification is recommended."
        )
    elif is_hidden:
        forensic_assessment = (
            "Hidden File Detected: The filename contains a leading period, designating it as a hidden file "
            "on Unix-like operating systems. Verify authorization and origin of this file."
        )
    elif signature_info['category'] == 'Executables':
        forensic_assessment = (
            "Executable Binary: File contains an executable header. ForensiX does not execute or run "
            "binaries. Use dedicated sandbox or disassembler tools if static/dynamic malware analysis is required."
        )
    else:
        forensic_assessment = (
            "Consistent: File structure and declared extension are consistent with known forensic signatures. "
            "No superficial anomalies detected."
        )

    return {
        'filename': safe_name,
        'original_filename': raw_filename,
        'extension': extension if extension else '(none)',
        'file_size_bytes': total_bytes,
        'file_size_human': format_file_size(total_bytes),
        'is_hidden': is_hidden,
        'mime_type': signature_info['mime_type'],
        'detected_format': signature_info['detected_format'],
        'category': signature_info['category'],
        'magic_hex': preview['hex'],
        'magic_ascii': preview['ascii'],
        'is_mismatch': mismatch_info['is_mismatch'],
        'mismatch_warning': mismatch_info['warning_message'],
        'claimed_format': mismatch_info['claimed_format'],
        'forensic_assessment': forensic_assessment,
        'timestamps': {
            'last_modified': mtime_str,
            'created_time': ctime_str,
            'accessed_time': atime_str,
            'analyzed_at': now_utc,
            'note': 'HTTP uploads convey client modification time only. Creation/access times require raw disk forensic access.'
        }
    }


def summarize_file_analysis(file_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Summarize a collection of file analysis results for the dashboard view.

    Returns:
        dict:
            - total_files (int)
            - total_size_bytes (int)
            - total_size_human (str)
            - category_counts (dict): counts for each category
            - hidden_count (int)
            - mismatch_count (int)
    """
    total_files = len(file_results)
    total_size = sum(f.get('file_size_bytes', 0) for f in file_results)
    hidden_count = sum(1 for f in file_results if f.get('is_hidden'))
    mismatch_count = sum(1 for f in file_results if f.get('is_mismatch'))

    # Initialize all 8 categories with 0
    category_counts = {cat: 0 for cat in CATEGORIES}
    for f in file_results:
        cat = f.get('category', 'Unknown files')
        if cat in category_counts:
            category_counts[cat] += 1
        else:
            category_counts['Unknown files'] += 1

    return {
        'total_files': total_files,
        'total_size_bytes': total_size,
        'total_size_human': format_file_size(total_size),
        'category_counts': category_counts,
        'hidden_count': hidden_count,
        'mismatch_count': mismatch_count
    }
