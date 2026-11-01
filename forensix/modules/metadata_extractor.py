"""
metadata_extractor.py - Digital Evidence Metadata Extraction Module (Debugged & Enhanced)

This module extracts embedded metadata from digital evidence files:
1. Images: Dual-engine extraction using Pillow (root IFD, Exif IFD, GPS IFD, _getexif())
   and ExifRead for comprehensive EXIF recovery.
   Extracts: Make, Model, LensMake, LensModel, DateTimeOriginal, DateTimeDigitized,
   ISO, FNumber, ExposureTime, FocalLength, Flash, Orientation, and GPSInfo.
2. PDF Documents: Title, Author, Subject, Creator, Producer, Creation Date,
   Modification Date, and Page Count via pypdf.
3. Word Documents (DOCX): Title, Author, Subject, Created Date, Modified Date,
   and Last Modified By via python-docx.

Forensic Principles Applied:
- Distinguish between:
  * EXIF metadata not present (e.g. stripped by social media / privacy tools).
  * EXIF metadata present but specific camera tags not populated.
  * Metadata extraction error (corrupted or malformed file).
- Never invent or guess camera information or GPS coordinates.
- Raw EXIF inspection section for forensic auditing and verification.
- Safe read-only stream handling without executing or modifying evidence.
"""

import io
import re
import datetime
import json
import hashlib
from fractions import Fraction
from typing import Dict, Any, List, Optional, Tuple

from PIL import Image, ExifTags
import exifread
import pypdf
import docx

# Supported File Extensions
SUPPORTED_EXTENSIONS = {
    'jpg': 'image',
    'jpeg': 'image',
    'png': 'image',
    'tif': 'image',
    'tiff': 'image',
    'pdf': 'pdf',
    'docx': 'docx'
}

# Signatures for File Type Validation
MAGIC_SIGNATURES = [
    (b'\xFF\xD8\xFF', 'image/jpeg', 'image'),
    (b'\x89PNG\r\n\x1a\n', 'image/png', 'image'),
    (b'II*\x00', 'image/tiff', 'image'),
    (b'MM\x00*', 'image/tiff', 'image'),
    (b'%PDF-', 'application/pdf', 'pdf'),
    (b'PK\x03\x04', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'docx'),
]

# Flash mode mapping
FLASH_VALUES = {
    0: 'Flash did not fire',
    1: 'Flash fired',
    5: 'Strobe return light not detected',
    7: 'Strobe return light detected',
    9: 'Flash fired, compulsory flash mode',
    13: 'Flash fired, compulsory flash mode, return light not detected',
    15: 'Flash fired, compulsory flash mode, return light detected',
    16: 'Flash did not fire, compulsory flash mode',
    24: 'Flash did not fire, auto mode',
    25: 'Flash fired, auto mode',
    29: 'Flash fired, auto mode, return light not detected',
    31: 'Flash fired, auto mode, return light detected',
    32: 'No flash function',
    65: 'Flash fired, red-eye reduction mode',
    69: 'Flash fired, red-eye reduction mode, return light not detected',
    71: 'Flash fired, red-eye reduction mode, return light detected',
    73: 'Flash fired, compulsory flash mode, red-eye reduction mode',
    77: 'Flash fired, compulsory flash mode, red-eye reduction mode, return light not detected',
    79: 'Flash fired, compulsory flash mode, red-eye reduction mode, return light detected',
    89: 'Flash fired, auto mode, red-eye reduction mode',
    93: 'Flash fired, auto mode, return light not detected, red-eye reduction mode',
    95: 'Flash fired, auto mode, return light detected, red-eye reduction mode',
}

# Orientation mapping
ORIENTATION_VALUES = {
    1: '1 (Horizontal / Normal)',
    2: '2 (Mirror horizontal)',
    3: '3 (Rotate 180°)',
    4: '4 (Mirror vertical)',
    5: '5 (Mirror horizontal and rotate 270° CW)',
    6: '6 (Rotate 90° CW)',
    7: '7 (Mirror horizontal and rotate 90° CW)',
    8: '8 (Rotate 270° CW)'
}


def sanitize_filename(filename: str) -> str:
    """Safe basename extraction preventing path traversal."""
    if not filename:
        return 'unnamed_evidence'
    clean = filename.replace('\x00', '').replace('\\', '/').strip()
    base = clean.split('/')[-1].strip()
    return base if base else 'unnamed_evidence'


def validate_file_type(file_stream, filename: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate that the file has a supported extension and matching binary signature.
    """
    safe_name = sanitize_filename(filename)
    parts = safe_name.rsplit('.', 1)
    if len(parts) < 2:
        return False, 'unsupported', f"File '{safe_name}' has no extension. Supported formats: JPG, JPEG, PNG, TIFF, PDF, DOCX."

    ext = parts[1].lower().strip()
    if ext not in SUPPORTED_EXTENSIONS:
        return False, 'unsupported', f"Extension '.{ext}' is not supported. Supported formats: JPG, JPEG, PNG, TIFF, PDF, DOCX."

    expected_type = SUPPORTED_EXTENSIONS[ext]

    try:
        file_stream.seek(0)
        header = file_stream.read(16)
        file_stream.seek(0)
    except Exception as e:
        return False, 'error', f"Unable to read file header: {str(e)}"

    if len(header) == 0:
        return False, 'empty', "Uploaded file is empty (0 bytes). No metadata to extract."

    sig_match = False
    for magic_bytes, mime, mtype in MAGIC_SIGNATURES:
        if header.startswith(magic_bytes):
            sig_match = True
            if mtype == expected_type or (expected_type == 'image' and mtype == 'image'):
                return True, expected_type, None
            break

    if not sig_match and ext in ('jpg', 'jpeg', 'png', 'tif', 'tiff', 'pdf'):
        return False, 'mismatch', f"File signature does not match declared '.{ext}' extension. Possible masquerading or corrupted header."

    return True, expected_type, None


def compute_file_sha256(file_stream) -> Tuple[str, int]:
    """
    Compute SHA-256 hash and file size in bytes using chunked streaming (64 KB chunks).
    Preserves and resets stream position to 0.
    """
    file_stream.seek(0)
    hasher = hashlib.sha256()
    size = 0
    while True:
        chunk = file_stream.read(65536)
        if not chunk:
            break
        hasher.update(chunk)
        size += len(chunk)
    file_stream.seek(0)
    return hasher.hexdigest(), size


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable units."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def _format_ratio(val: Any) -> Optional[float]:
    """Helper to convert ExifRead Ratio or tuple to float."""
    if val is None:
        return None
    try:
        if hasattr(val, 'num') and hasattr(val, 'den'):
            return float(val.num) / float(val.den) if val.den != 0 else 0.0
        if isinstance(val, Fraction):
            return float(val)
        if isinstance(val, (tuple, list)) and len(val) == 2:
            return float(val[0]) / float(val[1]) if val[1] != 0 else 0.0
        return float(val)
    except (ZeroDivisionError, ValueError, TypeError):
        return None


def _parse_dms_component(comp: Any) -> float:
    """Parse a single degree/minute/second component from EXIF into float."""
    res = _format_ratio(comp)
    if res is not None:
        return res
    if hasattr(comp, 'values') and len(comp.values) > 0:
        return _parse_dms_component(comp.values[0])
    try:
        return float(comp)
    except Exception:
        return 0.0


def _clean_str(val: Any) -> str:
    """Normalize and strip string values; return 'Not Available' if empty or None."""
    if val is None:
        return 'Not Available'
    s = str(val).strip()
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', s)
    return s if s else 'Not Available'


def _format_exposure_time(val: Any) -> str:
    """Format exposure time in human-friendly format (e.g. 1/500 sec)."""
    if val is None:
        return 'Not Available'
    try:
        if isinstance(val, (tuple, list)) and len(val) == 2:
            return f"{val[0]}/{val[1]} sec"
        if isinstance(val, Fraction):
            return f"{val.numerator}/{val.denominator} sec"
        f = float(val)
        if 0 < f < 1:
            denom = round(1.0 / f)
            return f"1/{denom} sec ({f:.4f}s)"
        return f"{f:.2f} sec"
    except Exception:
        s = str(val).strip()
        if s and not s.endswith('sec'):
            return s + " sec"
        return s if s else 'Not Available'


def _format_fnumber(val: Any) -> str:
    """Format aperture (F-number) as f/2.8."""
    if val is None:
        return 'Not Available'
    f = _format_ratio(val)
    if f is not None and f > 0:
        return f"f/{f:.1f}"
    try:
        return f"f/{float(val):.1f}"
    except Exception:
        return _clean_str(val)


def _format_focal_length(val: Any) -> str:
    """Format focal length as 50.0 mm."""
    if val is None:
        return 'Not Available'
    f = _format_ratio(val)
    if f is not None and f > 0:
        return f"{f:.1f} mm"
    try:
        return f"{float(val):.1f} mm"
    except Exception:
        return _clean_str(val)


def _format_flash(val: Any) -> str:
    """Format flash setting into human-readable description."""
    if val is None:
        return 'Not Available'
    try:
        val_int = int(val)
        if val_int in FLASH_VALUES:
            return FLASH_VALUES[val_int]
        return f"Code {val_int}" if val_int != 0 else 'Flash did not fire'
    except Exception:
        return _clean_str(val)


def _format_orientation(val: Any) -> str:
    """Format orientation into readable description."""
    if val is None:
        return 'Not Available'
    try:
        val_int = int(val)
        return ORIENTATION_VALUES.get(val_int, f"{val_int}")
    except Exception:
        return _clean_str(val)


def _format_iso(val: Any) -> str:
    """Format ISO speed rating."""
    if val is None:
        return 'Not Available'
    if isinstance(val, (tuple, list)) and len(val) > 0:
        return str(val[0])
    return str(val)


def parse_gps_coordinates_unified(gps_data: Any, exifread_tags: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and compute GPS coordinates from Pillow GPSInfo dict or ExifRead tags.
    Handles rational tuples, fractions, degrees/minutes/seconds, and altitude.
    """
    lat_vals, lat_ref = None, None
    lon_vals, lon_ref = None, None
    alt_val = None

    # 1. Try from Pillow GPSInfo dict if available
    if isinstance(gps_data, dict):
        lat_vals = gps_data.get(2) or gps_data.get('GPSLatitude')
        lat_ref = gps_data.get(1) or gps_data.get('GPSLatitudeRef')
        lon_vals = gps_data.get(4) or gps_data.get('GPSLongitude')
        lon_ref = gps_data.get(3) or gps_data.get('GPSLongitudeRef')
        alt_val = gps_data.get(6) or gps_data.get('GPSAltitude')

    # 2. Try from ExifRead tags if Pillow was missing GPS
    if not (lat_vals and lat_ref and lon_vals and lon_ref) and exifread_tags:
        lat_tag = exifread_tags.get('GPS GPSLatitude')
        lat_ref_tag = exifread_tags.get('GPS GPSLatitudeRef')
        lon_tag = exifread_tags.get('GPS GPSLongitude')
        lon_ref_tag = exifread_tags.get('GPS GPSLongitudeRef')

        if lat_tag and lat_ref_tag and lon_tag and lon_ref_tag:
            lat_vals = lat_tag.values if hasattr(lat_tag, 'values') else lat_tag
            lat_ref = lat_ref_tag.values if hasattr(lat_ref_tag, 'values') else lat_ref_tag
            lon_vals = lon_tag.values if hasattr(lon_tag, 'values') else lon_tag
            lon_ref = lon_ref_tag.values if hasattr(lon_ref_tag, 'values') else lon_ref_tag

        if not alt_val and exifread_tags.get('GPS GPSAltitude'):
            alt_tag = exifread_tags.get('GPS GPSAltitude')
            alt_val = alt_tag.values[0] if hasattr(alt_tag, 'values') else alt_tag

    if not (lat_vals and lat_ref and lon_vals and lon_ref):
        return {
            'has_gps': False,
            'latitude_dms': 'Not Available',
            'longitude_dms': 'Not Available',
            'latitude_decimal': 'Not Available',
            'longitude_decimal': 'Not Available',
            'altitude': 'Not Available',
            'copyable_coordinates': None,
            'warning': None
        }

    try:
        lat_ref_str = str(lat_ref).strip().upper()
        lon_ref_str = str(lon_ref).strip().upper()

        if len(lat_vals) >= 3 and len(lon_vals) >= 3:
            lat_deg = _parse_dms_component(lat_vals[0])
            lat_min = _parse_dms_component(lat_vals[1])
            lat_sec = _parse_dms_component(lat_vals[2])

            lon_deg = _parse_dms_component(lon_vals[0])
            lon_min = _parse_dms_component(lon_vals[1])
            lon_sec = _parse_dms_component(lon_vals[2])

            lat_dec = lat_deg + (lat_min / 60.0) + (lat_sec / 3600.0)
            if lat_ref_str in ('S', 'SOUTH'):
                lat_dec = -lat_dec

            lon_dec = lon_deg + (lon_min / 60.0) + (lon_sec / 3600.0)
            if lon_ref_str in ('W', 'WEST'):
                lon_dec = -lon_dec

            lat_dms = f"{int(lat_deg)}° {int(lat_min)}' {lat_sec:.2f}\" {lat_ref_str[0]}"
            lon_dms = f"{int(lon_deg)}° {int(lon_min)}' {lon_sec:.2f}\" {lon_ref_str[0]}"

            alt_str = 'Not Available'
            if alt_val is not None:
                alt_num = _format_ratio(alt_val)
                if alt_num is not None:
                    alt_str = f"{alt_num:.1f} meters"

            return {
                'has_gps': True,
                'latitude_dms': lat_dms,
                'longitude_dms': lon_dms,
                'latitude_decimal': f"{lat_dec:.6f}",
                'longitude_decimal': f"{lon_dec:.6f}",
                'altitude': alt_str,
                'copyable_coordinates': f"{lat_dec:.6f}, {lon_dec:.6f}",
                'warning': (
                    "Sensitive Location Data Detected: This image contains embedded GPS coordinates. "
                    "In forensic investigations, geographical data must be handled with care to protect privacy "
                    "and operational security."
                )
            }
    except Exception:
        pass

    return {
        'has_gps': False,
        'latitude_dms': 'Not Available',
        'longitude_dms': 'Not Available',
        'latitude_decimal': 'Not Available',
        'longitude_decimal': 'Not Available',
        'altitude': 'Not Available',
        'copyable_coordinates': None,
        'warning': None
    }


def parse_gps_coordinates(tags: Dict[str, Any]) -> Dict[str, Any]:
    """Compatibility wrapper for tests expecting tags dictionary."""
    return parse_gps_coordinates_unified(None, tags)


def make_metadata_field(name: str, val: Any, is_mandatory: bool = False, key: str = "", is_error: bool = False, error_msg: str = "") -> Dict[str, Any]:
    """
    Construct a field dictionary with a clean 3-state status:
    1. 'present' - Value is extracted and valid.
    2. 'not_recorded' - Optional field not recorded in file (normal in digital forensics).
    3. 'error' - Actual extraction/decoding error occurred.
    """
    if is_error:
        return {
            'name': name,
            'value': error_msg or 'Extraction Error',
            'status': 'error',
            'status_label': 'Extraction Error',
            'status_badge': 'badge-danger',
            'is_mandatory': is_mandatory,
            'key': key
        }
    if val is None or val == 'Not Available' or val == '':
        return {
            'name': name,
            'value': 'Not Available',
            'status': 'not_recorded',
            'status_label': 'Not Recorded in File',
            'status_badge': 'badge-secondary',
            'is_mandatory': is_mandatory,
            'key': key
        }
    return {
        'name': name,
        'value': str(val),
        'status': 'present',
        'status_label': 'Present',
        'status_badge': 'badge-success',
        'is_mandatory': is_mandatory,
        'key': key
    }


def extract_image_metadata(file_stream, filename: str) -> Dict[str, Any]:
    """
    Extract image metadata using Pillow (primary) and ExifRead (secondary/augmenter).
    Parses root IFD (Make, Model, Orientation), Exif IFD (optics, exposure, dates),
    and GPS IFD separately and accurately.
    """
    # 1. Image Dimensions & Format via Pillow
    try:
        file_stream.seek(0)
        with Image.open(file_stream) as pil_img:
            width, height = pil_img.size
            img_format = pil_img.format or 'Unknown'
            img_mode = pil_img.mode
            color_palette = f"{len(pil_img.getcolors())} colors" if pil_img.mode == 'P' and pil_img.getcolors() else 'Not Available'

            # 2. Extract EXIF via Pillow getexif() and Sub-IFDs
            pillow_exif = pil_img.getexif()

            # Root 0th IFD tags (Make, Model, Software, Orientation, DateTime)
            root_tags = {}
            raw_exif_debug_list = []

            if pillow_exif:
                for tag_id, val in pillow_exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, f"Tag_0x{tag_id:04X}")
                    root_tags[tag_name] = val
                    raw_exif_debug_list.append({
                        'tag_id': f"0x{tag_id:04X} ({tag_id})",
                        'name': tag_name,
                        'ifd': '0th (Root)',
                        'value': str(val)[:120]
                    })

            # Exif Sub-IFD (DateTimeOriginal, ISO, FNumber, ExposureTime, FocalLength, LensMake, LensModel)
            exif_ifd_tags = {}
            try:
                exif_sub = pillow_exif.get_ifd(ExifTags.IFD.Exif)
                if exif_sub:
                    for tag_id, val in exif_sub.items():
                        tag_name = ExifTags.TAGS.get(tag_id, f"Tag_0x{tag_id:04X}")
                        exif_ifd_tags[tag_name] = val
                        raw_exif_debug_list.append({
                            'tag_id': f"0x{tag_id:04X} ({tag_id})",
                            'name': tag_name,
                            'ifd': 'Exif Sub-IFD',
                            'value': str(val)[:120]
                        })
            except Exception:
                pass

            # GPS Sub-IFD
            gps_ifd_tags = {}
            try:
                gps_sub = pillow_exif.get_ifd(ExifTags.IFD.GPSInfo)
                if gps_sub:
                    for tag_id, val in gps_sub.items():
                        tag_name = ExifTags.GPSTAGS.get(tag_id, f"GPS_0x{tag_id:04X}")
                        gps_ifd_tags[tag_name] = val
                        raw_exif_debug_list.append({
                            'tag_id': f"GPS 0x{tag_id:02X} ({tag_id})",
                            'name': tag_name,
                            'ifd': 'GPS Sub-IFD',
                            'value': str(val)[:120]
                        })
            except Exception:
                pass

            # Fallback check using classic _getexif()
            classic_tags = {}
            try:
                if hasattr(pil_img, '_getexif') and callable(pil_img._getexif):
                    raw_c = pil_img._getexif()
                    if raw_c:
                        for tag_id, val in raw_c.items():
                            tag_name = ExifTags.TAGS.get(tag_id, f"Tag_0x{tag_id:04X}")
                            classic_tags[tag_name] = val
                            if tag_id == 34853 and isinstance(val, dict):
                                gps_ifd_tags.update(val)
            except Exception:
                pass

    except Exception as e:
        raise ValueError(f"Corrupted or invalid image data: {str(e)}")

    # 3. Secondary Extraction via ExifRead
    file_stream.seek(0)
    exifread_tags = {}
    try:
        exifread_tags = exifread.process_file(file_stream, details=True)
        # Add any additional tags found by ExifRead to debug list if not already present
        known_debug_names = {item['name'] for item in raw_exif_debug_list}
        for k, v in exifread_tags.items():
            clean_k = k.replace('Image ', '').replace('EXIF ', '').replace('GPS ', '')
            if clean_k not in known_debug_names and k not in known_debug_names:
                raw_exif_debug_list.append({
                    'tag_id': 'ExifRead Tag',
                    'name': k,
                    'ifd': 'ExifRead Engine',
                    'value': str(v)[:120]
                })
    except Exception:
        pass

    # Helper function to get tag value across Pillow root, sub-IFD, classic, or ExifRead
    def get_tag(*possible_names):
        for name in possible_names:
            # 1. Pillow root IFD
            if name in root_tags and root_tags[name] is not None:
                return root_tags[name]
            # 2. Pillow Exif Sub-IFD
            if name in exif_ifd_tags and exif_ifd_tags[name] is not None:
                return exif_ifd_tags[name]
            # 3. Pillow classic _getexif
            if name in classic_tags and classic_tags[name] is not None:
                return classic_tags[name]
            # 4. ExifRead with prefixes
            if name in exifread_tags:
                return exifread_tags[name]
            if f"Image {name}" in exifread_tags:
                return exifread_tags[f"Image {name}"]
            if f"EXIF {name}" in exifread_tags:
                return exifread_tags[f"EXIF {name}"]
            if f"GPS {name}" in exifread_tags:
                return exifread_tags[f"GPS {name}"]
        return None

    # Extract required fields:
    # 1. Make
    make = get_tag('Make')

    # 2. Model
    model = get_tag('Model')

    # 3. LensMake
    lens_make = get_tag('LensMake')

    # 4. LensModel
    lens_model = get_tag('LensModel') or get_tag('Lens') or get_tag('LensSpecification')

    # 5. DateTimeOriginal
    datetime_original = get_tag('DateTimeOriginal') or get_tag('DateTime')

    # 6. DateTimeDigitized
    datetime_digitized = get_tag('DateTimeDigitized')

    # 7. ISO
    iso = get_tag('ISOSpeedRatings', 'PhotographicSensitivity', 'ISO')

    # 8. FNumber (Aperture)
    fnumber = get_tag('FNumber', 'ApertureValue')

    # 9. ExposureTime (Shutter Speed)
    exposure_time = get_tag('ExposureTime', 'ShutterSpeedValue')

    # 10. FocalLength
    focal_length = get_tag('FocalLength')

    # 11. Flash
    flash = get_tag('Flash')

    # 12. Orientation
    orientation = get_tag('Orientation')

    # 13. GPSInfo
    gps_info = parse_gps_coordinates_unified(gps_ifd_tags, exifread_tags)

    # Software
    software = get_tag('Software')

    # Status classification: Accurate 4-tier camera status
    total_raw_tags = len(raw_exif_debug_list)

    has_make = bool(make and make != 'Not Available')
    has_model = bool(model and model != 'Not Available')
    has_optics = any([
        bool(lens_make and lens_make != 'Not Available'),
        bool(lens_model and lens_model != 'Not Available'),
        bool(iso and iso != 'Not Available'),
        bool(fnumber and fnumber != 'Not Available'),
        bool(exposure_time and exposure_time != 'Not Available'),
        bool(focal_length and focal_length != 'Not Available')
    ])

    if total_raw_tags == 0:
        exif_status = 'NOT_PRESENT'
        camera_status = 'No EXIF Metadata Found'
        exif_status_label = 'No EXIF Metadata Found'
        exif_status_class = 'badge-secondary'
        exif_message = (
            "No EXIF metadata block found in this image. "
            "Camera specifications and shooting parameters were either never embedded by the capture device "
            "or were stripped during web upload, social media processing, or image editing. "
            "ForensiX will never invent or guess camera details."
        )
    elif has_make and has_model:
        exif_status = 'PRESENT_FULL'
        camera_status = 'Camera Details Available'
        exif_status_label = 'Camera Details Available'
        exif_status_class = 'badge-success'
        exif_message = (
            f"Camera hardware details recovered ({make} {model}). "
            f"EXIF metadata block parsed ({total_raw_tags} raw tags recovered). "
            f"Device specifications, optics, and shooting parameters extracted."
        )
    elif has_make or has_model or has_optics:
        exif_status = 'PRESENT_PARTIAL'
        camera_status = 'Partial Camera Metadata'
        exif_status_label = 'Partial Camera Metadata'
        exif_status_class = 'badge-warning'
        exif_message = (
            f"Partial camera metadata detected ({total_raw_tags} raw tags recovered). "
            f"Some camera or optical fields were found, but complete camera identification "
            f"(both Make and Model) is not recorded in the file."
        )
    else:
        exif_status = 'GENERAL_EXIF'
        camera_status = 'General EXIF Metadata Available'
        exif_status_label = 'General EXIF Metadata Available'
        exif_status_class = 'badge-info'
        exif_message = (
            f"EXIF metadata block detected ({total_raw_tags} raw tags recovered), "
            f"but camera hardware details are missing. "
            f"Inspect the Raw EXIF Inspection table below for available general tags."
        )

    _make_field = make_metadata_field

    # Structured Groups separating Mandatory baseline image properties from Optional EXIF metadata
    groups = [
        {
            'title': 'Core Image Properties',
            'badge': 'Mandatory Container Properties',
            'badge_class': 'badge-info',
            'icon': 'fas fa-image',
            'description': 'These properties are intrinsic to the image container and will always be present in any valid image file.',
            'fields': [
                _make_field('Image Width', f"{width} pixels", is_mandatory=True, key='width'),
                _make_field('Image Height', f"{height} pixels", is_mandatory=True, key='height'),
                _make_field('Image Format', img_format, is_mandatory=True, key='format'),
                _make_field('Color Mode', img_mode, is_mandatory=True, key='color_mode'),
                _make_field('Color Palette', color_palette, is_mandatory=True, key='palette'),
            ]
        },
        {
            'title': 'Camera Details',
            'badge': 'Optional EXIF Metadata',
            'badge_class': 'badge-secondary',
            'icon': 'fas fa-camera',
            'description': 'Recorded by physical digital cameras and smartphones. Typically omitted or stripped by web services.',
            'fields': [
                _make_field('Camera Make', _clean_str(make), is_mandatory=False, key='make'),
                _make_field('Camera Model', _clean_str(model), is_mandatory=False, key='model'),
                _make_field('Lens Manufacturer', _clean_str(lens_make), is_mandatory=False, key='lens_make'),
                _make_field('Lens Model', _clean_str(lens_model), is_mandatory=False, key='lens_model'),
                _make_field('Processing Software', _clean_str(software), is_mandatory=False, key='software'),
            ]
        },
        {
            'title': 'Date and Time',
            'badge': 'Optional EXIF Metadata',
            'badge_class': 'badge-secondary',
            'icon': 'fas fa-calendar-clock',
            'description': 'Internal device clocks record these timestamps if configured on the camera.',
            'fields': [
                _make_field('Date Taken (DateTimeOriginal)', _clean_str(datetime_original), is_mandatory=False, key='date_taken'),
                _make_field('Date Digitized (DateTimeDigitized)', _clean_str(datetime_digitized), is_mandatory=False, key='date_digitized'),
            ]
        },
        {
            'title': 'Exposure & Optics',
            'badge': 'Optional EXIF Metadata',
            'badge_class': 'badge-secondary',
            'icon': 'fas fa-sliders',
            'description': 'Photographic shooting settings captured by the camera sensor at the moment of capture.',
            'fields': [
                _make_field('Orientation', _format_orientation(orientation), is_mandatory=False, key='orientation'),
                _make_field('ISO Speed', _format_iso(iso), is_mandatory=False, key='iso'),
                _make_field('Aperture (F-Number)', _format_fnumber(fnumber), is_mandatory=False, key='aperture'),
                _make_field('Shutter Speed (ExposureTime)', _format_exposure_time(exposure_time), is_mandatory=False, key='shutter_speed'),
                _make_field('Focal Length', _format_focal_length(focal_length), is_mandatory=False, key='focal_length'),
                _make_field('Flash Setting', _format_flash(flash), is_mandatory=False, key='flash'),
            ]
        },
        {
            'title': 'GPS Location Information',
            'badge': 'Optional Geolocation Tags',
            'badge_class': 'badge-warning' if gps_info['has_gps'] else 'badge-secondary',
            'icon': 'fas fa-location-dot',
            'description': 'Geographical telemetry captured if GPS hardware was enabled on the device.',
            'fields': [
                _make_field('GPS Latitude (DMS)', gps_info['latitude_dms'], is_mandatory=False, key='gps_lat_dms'),
                _make_field('GPS Longitude (DMS)', gps_info['longitude_dms'], is_mandatory=False, key='gps_lon_dms'),
                _make_field('GPS Latitude (Decimal)', gps_info['latitude_decimal'], is_mandatory=False, key='gps_lat_dec'),
                _make_field('GPS Longitude (Decimal)', gps_info['longitude_decimal'], is_mandatory=False, key='gps_lon_dec'),
                _make_field('GPS Altitude', gps_info['altitude'], is_mandatory=False, key='gps_altitude'),
            ]
        }
    ]

    return {
        'groups': groups,
        'gps_info': gps_info,
        'has_exif': total_raw_tags > 0,
        'raw_tag_count': total_raw_tags,
        'raw_tags_list': raw_exif_debug_list,
        'exif_status': exif_status,
        'exif_status_label': exif_status_label,
        'camera_status': camera_status,
        'exif_status_class': exif_status_class,
        'exif_message': exif_message
    }


def parse_pdf_date(date_str: Any) -> str:
    """Parse PDF date format (e.g. 'D:20261101152030+05'00'') into readable string."""
    if not date_str:
        return 'Not Available'
    raw = str(date_str).strip()
    if raw.startswith("D:"):
        raw = raw[2:]
    match = re.match(r'^(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?', raw)
    if match:
        year, month, day, hour, minute, second = match.groups()
        month = month or '01'
        day = day or '01'
        hour = hour or '00'
        minute = minute or '00'
        second = second or '00'
        return f"{year}-{month}-{day} {hour}:{minute}:{second} UTC"
    return raw


def extract_pdf_metadata(file_stream, filename: str) -> Dict[str, Any]:
    """Extract metadata from PDF document using pypdf."""
    file_stream.seek(0)
    try:
        reader = pypdf.PdfReader(file_stream)
        num_pages = len(reader.pages)
        is_encrypted = reader.is_encrypted
        meta = reader.metadata or {}
    except Exception as e:
        raise ValueError(f"Malformed or encrypted PDF document: {str(e)}")

    title = meta.get('/Title') or getattr(meta, 'title', None)
    author = meta.get('/Author') or getattr(meta, 'author', None)
    subject = meta.get('/Subject') or getattr(meta, 'subject', None)
    creator = meta.get('/Creator') or getattr(meta, 'creator', None)
    producer = meta.get('/Producer') or getattr(meta, 'producer', None)
    creation_date = meta.get('/CreationDate') or getattr(meta, 'creation_date', None)
    modification_date = meta.get('/ModDate') or getattr(meta, 'modification_date', None)

    raw_debug_list = []
    if meta:
        for k, v in meta.items():
            raw_debug_list.append({
                'tag_id': str(k),
                'name': str(k).replace('/', ''),
                'ifd': 'PDF Info Dict',
                'value': str(v)[:120]
            })

    groups = [
        {
            'title': 'Container & Security Properties',
            'badge': 'Mandatory Container Properties',
            'badge_class': 'badge-info',
            'icon': 'fas fa-shield-halved',
            'description': 'Intrinsic PDF document container structure and security flags.',
            'fields': [
                make_metadata_field('Total Page Count', f"{num_pages} pages", is_mandatory=True, key='pages'),
                make_metadata_field('Encryption Status', 'Encrypted' if is_encrypted else 'Unencrypted (Standard)', is_mandatory=True, key='encrypted'),
            ]
        },
        {
            'title': 'Document Properties',
            'badge': 'Optional Document Metadata',
            'badge_class': 'badge-secondary',
            'icon': 'fas fa-file-pdf',
            'description': 'Standard document attributes populated in PDF Info dictionary by authoring software.',
            'fields': [
                make_metadata_field('Document Title', _clean_str(title), is_mandatory=False, key='title'),
                make_metadata_field('Document Author', _clean_str(author), is_mandatory=False, key='author'),
                make_metadata_field('Subject / Topic', _clean_str(subject), is_mandatory=False, key='subject'),
                make_metadata_field('Application Creator', _clean_str(creator), is_mandatory=False, key='creator'),
                make_metadata_field('PDF Producer', _clean_str(producer), is_mandatory=False, key='producer'),
            ]
        },
        {
            'title': 'Date and Time',
            'badge': 'Optional Document Metadata',
            'badge_class': 'badge-secondary',
            'icon': 'fas fa-calendar-clock',
            'description': 'Creation and modification timestamps recorded in PDF Info dictionary.',
            'fields': [
                make_metadata_field('Creation Date', parse_pdf_date(creation_date), is_mandatory=False, key='creation_date'),
                make_metadata_field('Modification Date', parse_pdf_date(modification_date), is_mandatory=False, key='modification_date'),
            ]
        }
    ]

    gps_info = {
        'has_gps': False,
        'latitude_dms': 'Not Available',
        'longitude_dms': 'Not Available',
        'latitude_decimal': 'Not Available',
        'longitude_decimal': 'Not Available',
        'altitude': 'Not Available',
        'copyable_coordinates': None,
        'warning': None
    }

    return {
        'groups': groups,
        'gps_info': gps_info,
        'has_exif': bool(meta),
        'raw_tag_count': len(meta),
        'raw_tags_list': raw_debug_list,
        'exif_status': 'PRESENT_FULL' if meta else 'NOT_PRESENT',
        'exif_status_label': 'PDF Info Dictionary Present' if meta else 'No PDF Metadata',
        'exif_status_class': 'badge-success' if meta else 'badge-secondary',
        'exif_message': 'PDF document structure and metadata dictionary parsed.' if meta else 'No PDF Info dictionary present.'
    }


def extract_docx_metadata(file_stream, filename: str) -> Dict[str, Any]:
    """Extract metadata from Word Document (DOCX) using python-docx."""
    file_stream.seek(0)
    try:
        doc = docx.Document(file_stream)
        props = doc.core_properties
    except Exception as e:
        raise ValueError(f"Malformed or invalid DOCX document: {str(e)}")

    def _format_dt(dt_val):
        if not dt_val:
            return 'Not Available'
        if isinstance(dt_val, datetime.datetime):
            return dt_val.strftime('%Y-%m-%d %H:%M:%S UTC')
        return str(dt_val)

    raw_debug_list = []
    for prop_name in ['title', 'author', 'subject', 'last_modified_by', 'revision', 'created', 'modified', 'keywords', 'category']:
        val = getattr(props, prop_name, None)
        if val is not None:
            raw_debug_list.append({
                'tag_id': f"docx:{prop_name}",
                'name': prop_name.replace('_', ' ').title(),
                'ifd': 'DOCX Core Properties',
                'value': str(val)[:120]
            })

    groups = [
        {
            'title': 'Document Properties',
            'badge': 'Optional Document Metadata',
            'badge_class': 'badge-secondary',
            'icon': 'fas fa-file-word',
            'description': 'Standard Word OpenXML core properties recorded by word processor.',
            'fields': [
                make_metadata_field('Document Title', _clean_str(props.title), is_mandatory=False, key='title'),
                make_metadata_field('Document Author', _clean_str(props.author), is_mandatory=False, key='author'),
                make_metadata_field('Subject / Topic', _clean_str(props.subject), is_mandatory=False, key='subject'),
                make_metadata_field('Last Modified By', _clean_str(props.last_modified_by), is_mandatory=False, key='last_modified_by'),
                make_metadata_field('Revision Number', str(props.revision) if props.revision else 'Not Available', is_mandatory=False, key='revision'),
                make_metadata_field('Keywords', _clean_str(props.keywords), is_mandatory=False, key='keywords'),
                make_metadata_field('Category', _clean_str(props.category), is_mandatory=False, key='category'),
            ]
        },
        {
            'title': 'Date and Time',
            'badge': 'Optional Document Metadata',
            'badge_class': 'badge-secondary',
            'icon': 'fas fa-calendar-clock',
            'description': 'Timestamps recorded during document drafting and printing.',
            'fields': [
                make_metadata_field('Created Date', _format_dt(props.created), is_mandatory=False, key='created_date'),
                make_metadata_field('Modified Date', _format_dt(props.modified), is_mandatory=False, key='modified_date'),
                make_metadata_field('Last Printed Date', _format_dt(props.last_printed), is_mandatory=False, key='last_printed'),
            ]
        }
    ]

    gps_info = {
        'has_gps': False,
        'latitude_dms': 'Not Available',
        'longitude_dms': 'Not Available',
        'latitude_decimal': 'Not Available',
        'longitude_decimal': 'Not Available',
        'altitude': 'Not Available',
        'copyable_coordinates': None,
        'warning': None
    }

    return {
        'groups': groups,
        'gps_info': gps_info,
        'has_exif': True,
        'raw_tag_count': len(raw_debug_list),
        'raw_tags_list': raw_debug_list,
        'exif_status': 'PRESENT_FULL',
        'exif_status_label': 'Word Core Properties Present',
        'exif_status_class': 'badge-success',
        'exif_message': 'Microsoft Word core properties successfully extracted.'
    }


def extract_metadata(file_stream, filename: str) -> Dict[str, Any]:
    """
    Main controller for metadata extraction.
    Distinguishes:
    1. Validation errors (unsupported extension / mismatch).
    2. Corrupted files (caught ValueError with clear error description).
    3. Normal files with EXIF vs Normal files without EXIF.
    """
    safe_name = sanitize_filename(filename)

    # 1. Validation
    is_valid, detected_type, error_msg = validate_file_type(file_stream, safe_name)
    if not is_valid:
        return {
            'success': False,
            'filename': safe_name,
            'error': error_msg,
            'error_type': 'validation_error'
        }

    # 2. Extract based on format
    try:
        if detected_type == 'image':
            data = extract_image_metadata(file_stream, safe_name)
            format_name = "Image (EXIF Metadata)"
        elif detected_type == 'pdf':
            data = extract_pdf_metadata(file_stream, safe_name)
            format_name = "PDF Document (Metadata Stream)"
        elif detected_type == 'docx':
            data = extract_docx_metadata(file_stream, safe_name)
            format_name = "Word Document (DOCX OpenXML)"
        else:
            return {
                'success': False,
                'filename': safe_name,
                'error': f"Unsupported format category: {detected_type}",
                'error_type': 'unsupported_format'
            }
    except ValueError as ve:
        return {
            'success': False,
            'filename': safe_name,
            'error': str(ve),
            'error_type': 'corrupted_file'
        }
    except Exception as e:
        return {
            'success': False,
            'filename': safe_name,
            'error': f"Metadata extraction error: {str(e)}",
            'error_type': 'extraction_failure'
        }

    # 3. Calculate SHA-256 and file size
    sha256_hash, file_size_bytes = compute_file_sha256(file_stream)
    file_size_formatted = format_file_size(file_size_bytes)

    # 4. Calculate coverage & status metrics
    total_fields = 0
    available_fields = 0
    not_recorded_fields = 0
    extraction_errors = 0

    flat_dict = {
        'file_name': safe_name,
        'file_format': format_name,
        'sha256': sha256_hash,
        'file_size_bytes': file_size_bytes,
        'file_size_formatted': file_size_formatted,
        'exif_status': data.get('exif_status'),
        'camera_status': data.get('camera_status', data.get('exif_status_label')),
        'extracted_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'properties': {},
        'raw_exif_tags': data.get('raw_tags_list', [])
    }

    for group in data['groups']:
        for field in group['fields']:
            total_fields += 1
            st = field.get('status')
            if not st:
                st = 'not_recorded' if field.get('value') == 'Not Available' else 'present'

            if st == 'present':
                available_fields += 1
                flat_dict['properties'][field['name']] = field['value']
            elif st == 'error':
                extraction_errors += 1
                flat_dict['properties'][field['name']] = None
            else:
                not_recorded_fields += 1
                flat_dict['properties'][field['name']] = None

    available_pct = round((available_fields / total_fields) * 100, 1) if total_fields > 0 else 0.0

    stats = {
        'total_fields': total_fields,
        'available_fields': available_fields,
        'not_recorded_fields': not_recorded_fields,
        'extraction_errors': extraction_errors,
        'missing_fields': not_recorded_fields,  # backward compatibility alias
        'coverage_pct': available_pct,          # backward compatibility alias
        'available_pct': available_pct
    }

    # 5. Forensic Caveat / Evaluation
    if data['gps_info']['has_gps']:
        assessment = (
            "Geographical Telemetry Identified: The evidence file contains explicit GPS coordinates. "
            "Verify acquisition source and chain-of-custody. Note that EXIF timestamps and coordinates "
            "can be altered or spoofed; corroborating cell tower, network, or file-system records is recommended."
        )
    elif data.get('exif_status') == 'NOT_PRESENT':
        assessment = (
            "No EXIF Header Detected: The file contains no embedded EXIF tags. In digital investigations, "
            "this indicates the file was either generated by an application that does not record EXIF, or "
            "the metadata was stripped (e.g. social media upload, messaging app transfer, or privacy scrubbing). "
            "No camera or device details can be inferred."
        )
    elif available_fields > 5:
        assessment = (
            "Substantial Metadata Present: Multiple properties recovered. These provide valuable investigative "
            "leads (camera model, application software, editing dates). Note that metadata alone does not "
            "conclusively prove user identity without corroborating forensic evidence."
        )
    else:
        assessment = (
            "Sparse Metadata Present: Baseline properties were recovered, but several standard EXIF/document "
            "tags were not populated by the capture device."
        )

    return {
        'success': True,
        'filename': safe_name,
        'format_name': format_name,
        'detected_type': detected_type,
        'sha256': sha256_hash,
        'file_size': file_size_bytes,
        'file_size_formatted': file_size_formatted,
        'groups': data['groups'],
        'gps_info': data['gps_info'],
        'has_gps': data['gps_info']['has_gps'],
        'raw_tags_list': data.get('raw_tags_list', []),
        'exif_status': data.get('exif_status'),
        'exif_status_label': data.get('exif_status_label'),
        'camera_status': data.get('camera_status', data.get('exif_status_label')),
        'exif_status_class': data.get('exif_status_class'),
        'exif_message': data.get('exif_message'),
        'stats': stats,
        'forensic_assessment': assessment,
        'export_json': json.dumps(flat_dict, indent=2)
    }


def compare_image_metadata(file_stream1, filename1: str, file_stream2, filename2: str) -> Dict[str, Any]:
    """
    Compare metadata, cryptographic integrity, and camera status between two digital evidence files.

    Forensic Principles Applied:
    1. Rename Detection: Renaming a file in the operating system only updates directory records;
       it does NOT alter the underlying binary byte stream or embedded EXIF metadata.
    2. Identical SHA-256 hashes confirm bit-level content identity.
    3. Do not claim a file was renamed solely from matching hashes (matching hashes can also
       result from copying, downloading, or bitwise duplication without renaming).
    4. Metadata fields are separated into:
       - Identical fields (both populated, matching values)
       - Different fields (both populated, differing values)
       - Missing fields (categorized: File 1 only, File 2 only, or unrecorded in both)
    """
    safe_name1 = sanitize_filename(filename1)
    safe_name2 = sanitize_filename(filename2)

    # 1. Validate both files
    valid1, type1, err1 = validate_file_type(file_stream1, safe_name1)
    if not valid1:
        return {'success': False, 'error': f"File 1 ('{safe_name1}') validation failed: {err1}"}

    valid2, type2, err2 = validate_file_type(file_stream2, safe_name2)
    if not valid2:
        return {'success': False, 'error': f"File 2 ('{safe_name2}') validation failed: {err2}"}

    # 2. Extract metadata for both
    meta1 = extract_metadata(file_stream1, safe_name1)
    if not meta1.get('success'):
        return {'success': False, 'error': f"Analysis error on File 1 ('{safe_name1}'): {meta1.get('error')}"}

    meta2 = extract_metadata(file_stream2, safe_name2)
    if not meta2.get('success'):
        return {'success': False, 'error': f"Analysis error on File 2 ('{safe_name2}'): {meta2.get('error')}"}

    # 3. Cryptographic hash comparison & rename detection
    sha256_1 = meta1.get('sha256', '')
    sha256_2 = meta2.get('sha256', '')
    hashes_match = bool(sha256_1 and sha256_2 and sha256_1.lower() == sha256_2.lower())

    if hashes_match:
        identical_content = True
        match_title = "Identical Content Detected – Filename or file path may differ."
        match_badge = "Identical File Contents"
        match_badge_class = "badge-success"
        rename_explanation = (
            "Forensic Analysis: The two analyzed evidence files possess identical SHA-256 cryptographic hashes. "
            "Their underlying binary byte streams and embedded metadata structures are 100% byte-for-byte identical. "
            "In digital forensics, renaming a file only alters its directory entry in the filesystem "
            "(e.g., Master File Table record on NTFS or inode entry on Linux); it does not alter the file's binary contents "
            "or embedded EXIF metadata."
        )
        forensic_disclaimer = (
            "Cautionary Forensic Note: Investigators must not claim that a file was renamed solely from matching hashes. "
            "While matching cryptographic hashes confirm bit-level content identity, identical content can also arise from "
            "copying, downloading identical evidence, or saving duplicates without any rename action having occurred."
        )
    else:
        identical_content = False
        match_title = "Different File Content – Cryptographic hashes do not match."
        match_badge = "Different Content"
        match_badge_class = "badge-warning"
        rename_explanation = (
            "Forensic Analysis: The two analyzed files have distinct SHA-256 cryptographic hashes. "
            "Their binary contents are not identical. Even a single byte alteration, image crop, re-compression, "
            "or metadata modification alters the cryptographic hash completely."
        )
        forensic_disclaimer = None

    # 4. Compare all extracted properties across both files
    props1 = {}
    for g in meta1.get('groups', []):
        for f in g.get('fields', []):
            props1[f['name']] = {
                'value': f['value'],
                'status': f.get('status', 'not_recorded'),
                'group': g['title'],
                'is_mandatory': f.get('is_mandatory', False)
            }

    props2 = {}
    for g in meta2.get('groups', []):
        for f in g.get('fields', []):
            props2[f['name']] = {
                'value': f['value'],
                'status': f.get('status', 'not_recorded'),
                'group': g['title'],
                'is_mandatory': f.get('is_mandatory', False)
            }

    all_field_names = list(dict.fromkeys(list(props1.keys()) + list(props2.keys())))

    identical_fields = []
    different_fields = []
    missing_fields = []

    for name in all_field_names:
        f1 = props1.get(name, {'value': 'Not Available', 'status': 'not_recorded', 'group': 'General'})
        f2 = props2.get(name, {'value': 'Not Available', 'status': 'not_recorded', 'group': 'General'})
        group = f1.get('group') if f1.get('group') != 'General' else f2.get('group', 'General')

        st1 = f1['status']
        st2 = f2['status']
        v1 = f1['value']
        v2 = f2['value']

        # Both present
        if st1 == 'present' and st2 == 'present':
            if v1 == v2:
                identical_fields.append({
                    'name': name,
                    'group': group,
                    'value': v1
                })
            else:
                different_fields.append({
                    'name': name,
                    'group': group,
                    'val1': v1,
                    'val2': v2
                })
        else:
            # Missing in at least one file
            if st1 == 'present' and st2 != 'present':
                state_label = f"Recorded in {safe_name1} only"
                missing_type = 'file1_only'
            elif st1 != 'present' and st2 == 'present':
                state_label = f"Recorded in {safe_name2} only"
                missing_type = 'file2_only'
            else:
                state_label = "Not Recorded in Either File"
                missing_type = 'both_missing'

            missing_fields.append({
                'name': name,
                'group': group,
                'val1': v1,
                'val2': v2,
                'status1': st1,
                'status2': st2,
                'state_label': state_label,
                'missing_type': missing_type
            })

    return {
        'success': True,
        'file1': {
            'filename': safe_name1,
            'sha256': sha256_1,
            'file_size': meta1['file_size_formatted'],
            'camera_status': meta1.get('camera_status', meta1.get('exif_status_label')),
            'detected_type': meta1.get('detected_type'),
            'meta': meta1
        },
        'file2': {
            'filename': safe_name2,
            'sha256': sha256_2,
            'file_size': meta2['file_size_formatted'],
            'camera_status': meta2.get('camera_status', meta2.get('exif_status_label')),
            'detected_type': meta2.get('detected_type'),
            'meta': meta2
        },
        'hashes_match': hashes_match,
        'identical_content': identical_content,
        'match_title': match_title,
        'match_badge': match_badge,
        'match_badge_class': match_badge_class,
        'rename_explanation': rename_explanation,
        'forensic_disclaimer': forensic_disclaimer,
        'identical_fields': identical_fields,
        'different_fields': different_fields,
        'missing_fields': missing_fields,
        'stats': {
            'identical_count': len(identical_fields),
            'different_count': len(different_fields),
            'missing_count': len(missing_fields),
            'total_compared': len(all_field_names)
        }
    }
