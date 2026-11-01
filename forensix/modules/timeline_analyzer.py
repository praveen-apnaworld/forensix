"""
timeline_analyzer.py - Forensic Timeline Generation and Analysis Engine

This module extracts, organizes, and correlates chronological events across digital evidence.

Forensic Principles:
1. Filesystem Timestamps (MACB):
   - Modified (mtime): Time when the file contents were last modified.
   - Accessed (atime): Time when the file was last read. Note: modern operating systems
     often mount filesystems with 'relatime' or 'noatime', meaning atime may not update
     on every access to improve I/O performance.
   - Changed/Created (ctime / birthtime): On Linux, ctime reflects inode/metadata change
     time (permissions, ownership, renames), NOT necessarily creation time. True birthtime
     is filesystem-dependent (e.g. ext4, NTFS, APFS).
   - Filesystem timestamps do NOT conclusively prove human activity.
2. Investigation Milestones:
   - Evidence Registered, Hash Calculated, Metadata Extracted, Keyword Searched.
   - Application investigation timestamps are strictly separated from original file activity.
3. Integrity:
   - Read-only processing: Original evidence files are NEVER modified.
"""

import os
import io
import csv
import json
import platform
from datetime import datetime, timezone

# Optional third-party parsers for embedded document timestamps
try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import docx
except ImportError:
    docx = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
except ImportError:
    Image = None
    TAGS = {}


def format_epoch_timestamp(epoch_seconds: float) -> str:
    """Converts a float unix epoch to standard ISO 'YYYY-MM-DD HH:MM:SS' format."""
    if epoch_seconds is None or epoch_seconds <= 0:
        return None
    try:
        dt = datetime.fromtimestamp(epoch_seconds)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return None


def get_system_timezone_info() -> str:
    """Returns local timezone identifier and UTC offset."""
    try:
        now = datetime.now().astimezone()
        tz_name = now.tzname() or 'Local'
        offset = now.strftime('%z')
        formatted_offset = f"UTC{offset[:3]}:{offset[3:]}" if offset else "UTC"
        return f"{tz_name} ({formatted_offset})"
    except Exception:
        return "Local System Timezone"


def get_linux_birthtime(file_path: str) -> float:
    """
    Safely retrieves actual file creation time (birthtime) on Linux using statx syscall.
    Returns float epoch seconds if supported and available, or None if unsupported.
    """
    if platform.system() != 'Linux':
        return None
    try:
        import ctypes
        import ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        if not hasattr(libc, 'syscall'):
            return None

        class struct_statx_timestamp(ctypes.Structure):
            _fields_ = [
                ('tv_sec', ctypes.c_int64),
                ('tv_nsec', ctypes.c_uint32),
                ('__reserved', ctypes.c_int32),
            ]

        class struct_statx(ctypes.Structure):
            _fields_ = [
                ('stx_mask', ctypes.c_uint32),
                ('stx_blksize', ctypes.c_uint32),
                ('stx_attributes', ctypes.c_uint64),
                ('stx_nlink', ctypes.c_uint32),
                ('stx_uid', ctypes.c_uint32),
                ('stx_gid', ctypes.c_uint32),
                ('stx_mode', ctypes.c_uint16),
                ('__spare0', ctypes.c_uint16 * 1),
                ('stx_ino', ctypes.c_uint64),
                ('stx_size', ctypes.c_uint64),
                ('stx_blocks', ctypes.c_uint64),
                ('stx_attributes_mask', ctypes.c_uint64),
                ('stx_atime', struct_statx_timestamp),
                ('stx_btime', struct_statx_timestamp),  # Birth time
                ('stx_ctime', struct_statx_timestamp),
                ('stx_mtime', struct_statx_timestamp),
                ('stx_rdev_major', ctypes.c_uint32),
                ('stx_rdev_minor', ctypes.c_uint32),
                ('stx_dev_major', ctypes.c_uint32),
                ('stx_dev_minor', ctypes.c_uint32),
                ('stx_mnt_id', ctypes.c_uint64),
                ('stx_dio_mem_align', ctypes.c_uint32),
                ('stx_dio_offset_align', ctypes.c_uint32),
                ('__spare3', ctypes.c_uint64 * 12),
            ]

        machine = platform.machine().lower()
        if machine in ('x86_64', 'amd64'):
            sys_statx = 332
        elif machine in ('aarch64', 'arm64'):
            sys_statx = 397
        elif machine.startswith('arm'):
            sys_statx = 397
        elif machine in ('i386', 'i686'):
            sys_statx = 383
        elif machine == 'riscv64':
            sys_statx = 291
        else:
            return None

        sx = struct_statx()
        AT_FDCWD = -100
        STATX_BTIME = 0x00000800  # Want stx_btime
        ret = libc.syscall(sys_statx, AT_FDCWD, os.fsencode(file_path), 0, STATX_BTIME, ctypes.byref(sx))
        if ret == 0 and (sx.stx_mask & STATX_BTIME) and sx.stx_btime.tv_sec > 0:
            return float(sx.stx_btime.tv_sec) + (float(sx.stx_btime.tv_nsec) / 1e9)
    except Exception:
        pass
    return None


def extract_filesystem_timestamps(file_path: str, filename: str, evidence_id: str = None, case_id: str = None) -> list[dict]:
    """
    Extracts MACB filesystem timestamps from a physical evidence file on disk.
    
    Forensic Principles:
    - mtime = Last content modification
    - ctime = Inode metadata change (NEVER interpreted as file creation)
    - atime = Last access
    - birthtime = Actual file creation time (only when supported & available)
    
    If creation time is unavailable, 'Creation Time Not Available' is clearly marked.
    """
    if not file_path or not os.path.exists(file_path):
        return []
    
    events = []
    tz_info = get_system_timezone_info()
    os_name = platform.system()
    
    try:
        st = os.stat(file_path)
    except Exception:
        return []
    
    file_size = st.st_size
    ref_case = case_id or "GENERAL-CASE"
    ref_evd = evidence_id or f"EVD-{filename}"
    
    # Check birthtime availability
    # 1. os.stat st_birthtime (macOS, BSD)
    birthtime = getattr(st, 'st_birthtime', None)
    # 2. Linux statx syscall (ext4, xfs, btrfs)
    if (birthtime is None or birthtime <= 0) and os_name == 'Linux':
        birthtime = get_linux_birthtime(file_path)
        
    has_birthtime = (birthtime is not None and birthtime > 0)
    creation_display = format_epoch_timestamp(birthtime) if has_birthtime else "Creation Time Not Available"

    # 1. Created Event (ONLY if birthtime is supported and available)
    if has_birthtime:
        events.append({
            'filename': filename,
            'file_path': file_path,
            'file_size': file_size,
            'event_type': 'Created',
            'timestamp': creation_display,
            'timestamp_raw': birthtime,
            'evidence_id': ref_evd,
            'case_id': ref_case,
            'event_source': 'Filesystem Birthtime (Actual Creation)',
            'category': 'filesystem',
            'badge_class': 'badge-success',
            'icon': 'fa-file-circle-plus',
            'precision': 'Subsecond / Nanosecond',
            'timezone_info': tz_info,
            'creation_time_display': creation_display,
            'forensic_notes': 'Actual file creation time (birthtime). Physical moment the file was allocated on the filesystem. Distinct from mtime and ctime.'
        })

    # 2. Modified Event (mtime)
    if st.st_mtime and st.st_mtime > 0:
        dt_str = format_epoch_timestamp(st.st_mtime)
        if dt_str:
            events.append({
                'filename': filename,
                'file_path': file_path,
                'file_size': file_size,
                'event_type': 'Modified',
                'timestamp': dt_str,
                'timestamp_raw': st.st_mtime,
                'evidence_id': ref_evd,
                'case_id': ref_case,
                'event_source': 'Filesystem Metadata (mtime)',
                'category': 'filesystem',
                'badge_class': 'badge-warning',
                'icon': 'fa-pen-to-square',
                'precision': 'Second / Subsecond',
                'timezone_info': tz_info,
                'creation_time_display': creation_display,
                'forensic_notes': 'Last content modification (mtime). Recorded by the filesystem when file data/payload was altered.'
            })

    # 3. Metadata Changed Event (ctime) - NEVER interpreted as file creation!
    if st.st_ctime and st.st_ctime > 0:
        dt_str = format_epoch_timestamp(st.st_ctime)
        if dt_str:
            events.append({
                'filename': filename,
                'file_path': file_path,
                'file_size': file_size,
                'event_type': 'Metadata Changed',
                'timestamp': dt_str,
                'timestamp_raw': st.st_ctime,
                'evidence_id': ref_evd,
                'case_id': ref_case,
                'event_source': f'Filesystem Inode Status Change (ctime) [{os_name}]',
                'category': 'filesystem',
                'badge_class': 'badge-secondary',
                'icon': 'fa-arrows-rotate',
                'precision': 'Second / Subsecond',
                'timezone_info': tz_info,
                'creation_time_display': creation_display,
                'forensic_notes': "Inode metadata change (ctime). Recorded when permissions, ownership, link count, or directory attributes changed. Forensic rule: ctime is NEVER interpreted as file creation time."
            })

    # 4. Accessed Event (atime)
    if st.st_atime and st.st_atime > 0:
        dt_str = format_epoch_timestamp(st.st_atime)
        if dt_str:
            events.append({
                'filename': filename,
                'file_path': file_path,
                'file_size': file_size,
                'event_type': 'Accessed',
                'timestamp': dt_str,
                'timestamp_raw': st.st_atime,
                'evidence_id': ref_evd,
                'case_id': ref_case,
                'event_source': 'Filesystem Metadata (atime)',
                'category': 'filesystem',
                'badge_class': 'badge-info',
                'icon': 'fa-eye',
                'precision': 'Second / Subsecond',
                'timezone_info': tz_info,
                'creation_time_display': creation_display,
                'forensic_notes': "Last access time (atime). Recorded when file contents were read. Caution: modern Linux kernels with 'relatime' or 'noatime' may not update atime on every read."
            })

    return events


def parse_pdf_date_string(pdf_date: str) -> str:
    """
    Parses PDF date format D:YYYYMMDDHHmmSS[OHH'mm'] to standard 'YYYY-MM-DD HH:MM:SS'.
    """
    if not pdf_date:
        return None
    cleaned = pdf_date.strip()
    if cleaned.startswith("D:"):
        cleaned = cleaned[2:]
    # Take first 14 digits YYYYMMDDHHMMSS
    digits = "".join([c for c in cleaned if c.isdigit()])
    if len(digits) >= 14:
        try:
            dt = datetime.strptime(digits[:14], "%Y%m%d%H%M%S")
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return None
    elif len(digits) >= 8:
        try:
            dt = datetime.strptime(digits[:8], "%Y%m%d")
            return dt.strftime('%Y-%m-%d 00:00:00')
        except Exception:
            return None
    return None


def extract_embedded_document_timestamps(file_path: str, filename: str, evidence_id: str = None, case_id: str = None) -> list[dict]:
    """
    Extracts application-level document metadata timestamps embedded inside files (PDF, DOCX, EXIF).
    """
    if not file_path or not os.path.exists(file_path):
        return []
    
    events = []
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    ref_case = case_id or "GENERAL-CASE"
    ref_evd = evidence_id or f"EVD-{filename}"
    tz_info = get_system_timezone_info()

    # 1. PDF Embedded Creation / ModDate
    if ext == 'pdf' and pypdf is not None:
        try:
            with open(file_path, 'rb') as f:
                reader = pypdf.PdfReader(f)
                meta = reader.metadata or {}
                
                creation_raw = meta.get('/CreationDate')
                c_str = parse_pdf_date_string(str(creation_raw)) if creation_raw else None
                if c_str:
                    try:
                        c_epoch = datetime.strptime(c_str, '%Y-%m-%d %H:%M:%S').timestamp()
                    except Exception:
                        c_epoch = 0
                    events.append({
                        'filename': filename,
                        'file_path': file_path,
                        'file_size': os.path.getsize(file_path),
                        'event_type': 'Created',
                        'timestamp': c_str,
                        'timestamp_raw': c_epoch,
                        'evidence_id': ref_evd,
                        'case_id': ref_case,
                        'event_source': 'PDF Document Metadata (/CreationDate)',
                        'category': 'embedded',
                        'badge_class': 'badge-success',
                        'icon': 'fa-file-pdf',
                        'precision': 'Second',
                        'timezone_info': tz_info,
                        'forensic_notes': 'Extracted directly from PDF Info Dictionary. Reflects when authoring software compiled the document.'
                    })
                    
                mod_raw = meta.get('/ModDate')
                m_str = parse_pdf_date_string(str(mod_raw)) if mod_raw else None
                if m_str and m_str != c_str:
                    try:
                        m_epoch = datetime.strptime(m_str, '%Y-%m-%d %H:%M:%S').timestamp()
                    except Exception:
                        m_epoch = 0
                    events.append({
                        'filename': filename,
                        'file_path': file_path,
                        'file_size': os.path.getsize(file_path),
                        'event_type': 'Modified',
                        'timestamp': m_str,
                        'timestamp_raw': m_epoch,
                        'evidence_id': ref_evd,
                        'case_id': ref_case,
                        'event_source': 'PDF Document Metadata (/ModDate)',
                        'category': 'embedded',
                        'badge_class': 'badge-warning',
                        'icon': 'fa-file-pdf',
                        'precision': 'Second',
                        'timezone_info': tz_info,
                        'forensic_notes': 'Extracted from PDF Info Dictionary. Reflects document revision or signature timestamp.'
                    })
        except Exception:
            pass

    # 2. DOCX OpenXML Core Properties
    elif ext == 'docx' and docx is not None:
        try:
            doc = docx.Document(file_path)
            props = doc.core_properties
            if props.created:
                c_str = props.created.strftime('%Y-%m-%d %H:%M:%S')
                events.append({
                    'filename': filename,
                    'file_path': file_path,
                    'file_size': os.path.getsize(file_path),
                    'event_type': 'Created',
                    'timestamp': c_str,
                    'timestamp_raw': props.created.timestamp(),
                    'evidence_id': ref_evd,
                    'case_id': ref_case,
                    'event_source': 'Word OpenXML Properties (dcterms:created)',
                    'category': 'embedded',
                    'badge_class': 'badge-success',
                    'icon': 'fa-file-word',
                    'precision': 'Second',
                    'timezone_info': 'UTC (standard OpenXML specification)',
                    'forensic_notes': 'Document authoring creation timestamp stored in docProps/core.xml.'
                })
            if props.modified:
                m_str = props.modified.strftime('%Y-%m-%d %H:%M:%S')
                events.append({
                    'filename': filename,
                    'file_path': file_path,
                    'file_size': os.path.getsize(file_path),
                    'event_type': 'Modified',
                    'timestamp': m_str,
                    'timestamp_raw': props.modified.timestamp(),
                    'evidence_id': ref_evd,
                    'case_id': ref_case,
                    'event_source': 'Word OpenXML Properties (dcterms:modified)',
                    'category': 'embedded',
                    'badge_class': 'badge-warning',
                    'icon': 'fa-file-word',
                    'precision': 'Second',
                    'timezone_info': 'UTC (standard OpenXML specification)',
                    'forensic_notes': 'Last document save timestamp recorded in docProps/core.xml.'
                })
        except Exception:
            pass

    # 3. JPEG/TIFF EXIF DateTimeOriginal
    elif ext in {'jpg', 'jpeg', 'tiff', 'tif'} and Image is not None:
        try:
            with Image.open(file_path) as im:
                exif = im.getexif()
                if exif:
                    # 0x9003 = DateTimeOriginal, 0x0132 = DateTime
                    dto_raw = exif.get(0x9003) or exif.get(0x0132)
                    if dto_raw and isinstance(dto_raw, str):
                        # Format is YYYY:MM:DD HH:MM:SS
                        dto_clean = dto_raw.strip().replace('\x00', '')
                        if len(dto_clean) >= 19 and dto_clean[4] == ':' and dto_clean[7] == ':':
                            formatted_dt = f"{dto_clean[:4]}-{dto_clean[5:7]}-{dto_clean[8:10]} {dto_clean[11:19]}"
                            try:
                                dt_epoch = datetime.strptime(formatted_dt, '%Y-%m-%d %H:%M:%S').timestamp()
                            except Exception:
                                dt_epoch = 0
                            events.append({
                                'filename': filename,
                                'file_path': file_path,
                                'file_size': os.path.getsize(file_path),
                                'event_type': 'Created',
                                'timestamp': formatted_dt,
                                'timestamp_raw': dt_epoch,
                                'evidence_id': ref_evd,
                                'case_id': ref_case,
                                'event_source': 'EXIF Camera Shutter (DateTimeOriginal)',
                                'category': 'embedded',
                                'badge_class': 'badge-success',
                                'icon': 'fa-camera',
                                'precision': 'Second',
                                'timezone_info': 'Camera Local Clock (EXIF Standard)',
                                'forensic_notes': 'Recorded by camera hardware clock at the moment the shutter was pressed.'
                            })
        except Exception:
            pass

    return events


def collect_case_database_events(db, case_id: str = None) -> list[dict]:
    """
    Collects forensic investigation milestones recorded in SQLite database tables.
    """
    events = []
    tz_info = get_system_timezone_info()

    # Query cases
    case_query = 'SELECT * FROM cases'
    case_params = ()
    if case_id:
        case_query += ' WHERE case_id = ? OR id = ?'
        case_params = (case_id, case_id)
    
    case_rows = db.execute(case_query, case_params).fetchall()
    case_map = {c['id']: c['case_id'] for c in case_rows}
    case_names = {c['id']: c['title'] for c in case_rows}

    for c in case_rows:
        cid = c['case_id']
        if c['created_at']:
            try:
                ep = datetime.strptime(c['created_at'][:19], '%Y-%m-%d %H:%M:%S').timestamp()
            except Exception:
                ep = 0
            events.append({
                'filename': f"Case Record ({cid})",
                'file_path': None,
                'file_size': 0,
                'event_type': 'Case Opened',
                'timestamp': c['created_at'][:19],
                'timestamp_raw': ep,
                'evidence_id': 'CASE-INIT',
                'case_id': cid,
                'event_source': 'ForensiX Case Management Database',
                'category': 'investigation',
                'badge_class': 'badge-primary',
                'icon': 'fa-folder-open',
                'precision': 'Second',
                'timezone_info': tz_info,
                'forensic_notes': f"Investigation case '{c['title']}' created by {c['investigator']}."
            })

    # Query registered evidence
    if case_rows:
        case_ids_list = [c['id'] for c in case_rows]
        placeholders = ','.join(['?'] * len(case_ids_list))
        ev_rows = db.execute(f'SELECT * FROM evidence WHERE case_id IN ({placeholders})', case_ids_list).fetchall()
    else:
        ev_rows = db.execute('SELECT * FROM evidence').fetchall()

    ev_id_map = {}
    for ev in ev_rows:
        ev_id_map[ev['id']] = ev
        cid_str = case_map.get(ev['case_id'], f"CASE-{ev['case_id']}")
        ev_code = ev['evidence_id']
        fname = ev['filename']
        st_path = ev['stored_path']
        f_size = ev['file_size'] or 0

        # Registration event
        if ev['added_at']:
            try:
                ep = datetime.strptime(ev['added_at'][:19], '%Y-%m-%d %H:%M:%S').timestamp()
            except Exception:
                ep = 0
            events.append({
                'filename': fname,
                'file_path': st_path,
                'file_size': f_size,
                'event_type': 'Evidence Registered',
                'timestamp': ev['added_at'][:19],
                'timestamp_raw': ep,
                'evidence_id': ev_code,
                'case_id': cid_str,
                'event_source': 'ForensiX Evidence Manager',
                'category': 'investigation',
                'badge_class': 'badge-info',
                'icon': 'fa-box-archive',
                'precision': 'Second',
                'timezone_info': tz_info,
                'forensic_notes': f"Evidence item registered into case {cid_str} (Source: {ev['source'] or 'N/A'})."
            })

        # Physical file timestamps if on disk
        if st_path and os.path.exists(st_path):
            fs_events = extract_filesystem_timestamps(st_path, fname, evidence_id=ev_code, case_id=cid_str)
            events.extend(fs_events)
            doc_events = extract_embedded_document_timestamps(st_path, fname, evidence_id=ev_code, case_id=cid_str)
            events.extend(doc_events)

    # Query hash_records
    if ev_rows:
        ev_pk_list = [ev['id'] for ev in ev_rows]
        placeholders = ','.join(['?'] * len(ev_pk_list))
        hash_rows = db.execute(f'SELECT * FROM hash_records WHERE evidence_id IN ({placeholders})', ev_pk_list).fetchall()
        for h in hash_rows:
            ev_item = ev_id_map.get(h['evidence_id'])
            if ev_item and h['computed_at']:
                cid_str = case_map.get(ev_item['case_id'], 'GENERAL-CASE')
                try:
                    ep = datetime.strptime(h['computed_at'][:19], '%Y-%m-%d %H:%M:%S').timestamp()
                except Exception:
                    ep = 0
                events.append({
                    'filename': ev_item['filename'],
                    'file_path': ev_item['stored_path'],
                    'file_size': ev_item['file_size'] or 0,
                    'event_type': 'Hash Calculated',
                    'timestamp': h['computed_at'][:19],
                    'timestamp_raw': ep,
                    'evidence_id': ev_item['evidence_id'],
                    'case_id': cid_str,
                    'event_source': 'ForensiX Hash Analyzer',
                    'category': 'investigation',
                    'badge_class': 'badge-purple',
                    'icon': 'fa-fingerprint',
                    'precision': 'Second',
                    'timezone_info': tz_info,
                    'forensic_notes': f"Cryptographic integrity baseline computed. SHA-256: {h['sha256'][:16]}..."
                })

    # Query analysis_results
    if ev_rows:
        ev_pk_list = [ev['id'] for ev in ev_rows]
        placeholders = ','.join(['?'] * len(ev_pk_list))
        an_rows = db.execute(f'SELECT * FROM analysis_results WHERE evidence_id IN ({placeholders})', ev_pk_list).fetchall()
        for a in an_rows:
            ev_item = ev_id_map.get(a['evidence_id'])
            if ev_item and a['analyzed_at']:
                cid_str = case_map.get(ev_item['case_id'], 'GENERAL-CASE')
                a_type = a['analysis_type'].lower()
                if a_type == 'metadata':
                    ev_type = 'Metadata Extracted'
                    icon = 'fa-tags'
                elif a_type == 'keyword':
                    ev_type = 'Keyword Search Performed'
                    icon = 'fa-magnifying-glass'
                else:
                    ev_type = f"{a['analysis_type'].title()} Analyzed"
                    icon = 'fa-microscope'

                try:
                    ep = datetime.strptime(a['analyzed_at'][:19], '%Y-%m-%d %H:%M:%S').timestamp()
                except Exception:
                    ep = 0

                events.append({
                    'filename': ev_item['filename'],
                    'file_path': ev_item['stored_path'],
                    'file_size': ev_item['file_size'] or 0,
                    'event_type': ev_type,
                    'timestamp': a['analyzed_at'][:19],
                    'timestamp_raw': ep,
                    'evidence_id': ev_item['evidence_id'],
                    'case_id': cid_str,
                    'event_source': f"ForensiX {a['analysis_type'].title()} Engine",
                    'category': 'investigation',
                    'badge_class': 'badge-cyan',
                    'icon': icon,
                    'precision': 'Second',
                    'timezone_info': tz_info,
                    'forensic_notes': f"Automated forensic analysis record ({a['analysis_type']})."
                })

    # Query chain_of_custody
    if ev_rows:
        ev_pk_list = [ev['id'] for ev in ev_rows]
        placeholders = ','.join(['?'] * len(ev_pk_list))
        cust_rows = db.execute(f'SELECT * FROM chain_of_custody WHERE evidence_id IN ({placeholders})', ev_pk_list).fetchall()
        for c in cust_rows:
            ev_item = ev_id_map.get(c['evidence_id'])
            if ev_item and c['timestamp']:
                cid_str = case_map.get(ev_item['case_id'], 'GENERAL-CASE')
                try:
                    ep = datetime.strptime(c['timestamp'][:19], '%Y-%m-%d %H:%M:%S').timestamp()
                except Exception:
                    ep = 0
                events.append({
                    'filename': ev_item['filename'],
                    'file_path': ev_item['stored_path'],
                    'file_size': ev_item['file_size'] or 0,
                    'event_type': f"Custody: {c['action']}",
                    'timestamp': c['timestamp'][:19],
                    'timestamp_raw': ep,
                    'evidence_id': ev_item['evidence_id'],
                    'case_id': cid_str,
                    'event_source': 'Chain of Custody Ledger',
                    'category': 'custody',
                    'badge_class': 'badge-success',
                    'icon': 'fa-shield-halved',
                    'precision': 'Second',
                    'timezone_info': tz_info,
                    'forensic_notes': f"Custodian: {c['performed_by']}. Details: {c['details'] or 'N/A'}"
                })

    return events


def parse_date_filter_boundary(date_str: str, is_end: bool = False) -> str:
    """Normalizes date string YYYY-MM-DD to comparable ISO string."""
    if not date_str:
        return None
    cleaned = date_str.strip()
    if not cleaned:
        return None
    if len(cleaned) == 10:  # YYYY-MM-DD
        return f"{cleaned} 23:59:59" if is_end else f"{cleaned} 00:00:00"
    return cleaned


def generate_timeline(events: list[dict], sort_order: str = 'desc', date_from: str = None, date_to: str = None, filename_query: str = None, event_type_filter: str = None, case_id_filter: str = None, evidence_id_filter: str = None) -> dict:
    """
    Deduplicates, filters, sorts, and summarizes chronological evidence events.
    
    Args:
        events: Raw list of event dictionaries
        sort_order: 'asc' (oldest first) or 'desc' (newest first)
        date_from: Filter start date string (e.g. '2026-01-01')
        date_to: Filter end date string (e.g. '2026-12-31')
        filename_query: Case-insensitive search on filename
        event_type_filter: Specific event type (e.g. 'Created', 'Modified', 'Accessed') or 'ALL'
        case_id_filter: Specific Case ID or 'ALL'
        evidence_id_filter: Specific Evidence ID or 'ALL'
        
    Returns:
        Structured dictionary with filtered events, statistics, and metadata.
    """
    # Deduplicate events based on (filename, event_type, timestamp, event_source)
    seen = set()
    deduped_events = []
    
    for ev in events:
        ts = ev.get('timestamp')
        if not ts:
            continue
        key = (ev.get('filename'), ev.get('event_type'), ts, ev.get('event_source'))
        if key not in seen:
            seen.add(key)
            deduped_events.append(ev)
            
    # Apply Filters
    filtered_events = []
    
    date_from_iso = parse_date_filter_boundary(date_from, is_end=False)
    date_to_iso = parse_date_filter_boundary(date_to, is_end=True)
    fname_q = filename_query.strip().lower() if filename_query else None
    ev_type_q = event_type_filter.strip().lower() if event_type_filter and event_type_filter != 'ALL' else None
    case_q = case_id_filter.strip().lower() if case_id_filter and case_id_filter != 'ALL' else None
    evd_q = evidence_id_filter.strip().lower() if evidence_id_filter and evidence_id_filter != 'ALL' else None

    for ev in deduped_events:
        ts = ev.get('timestamp', '')
        
        # 1. Date Range Filter
        if date_from_iso and ts < date_from_iso:
            continue
        if date_to_iso and ts > date_to_iso:
            continue
            
        # 2. Filename Search Filter
        if fname_q and fname_q not in ev.get('filename', '').lower():
            continue
            
        # 3. Event Type Filter
        if ev_type_q and ev_type_q != 'all':
            curr_type = ev.get('event_type', '').lower()
            if ev_type_q not in curr_type:
                continue
                
        # 4. Case ID Filter
        if case_q and case_q != 'all':
            if case_q not in ev.get('case_id', '').lower():
                continue
                
        # 5. Evidence ID Filter
        if evd_q and evd_q != 'all':
            if evd_q not in ev.get('evidence_id', '').lower():
                continue
                
        filtered_events.append(ev)

    # Sort events chronologically
    reverse_sort = (sort_order.lower() == 'desc')
    filtered_events.sort(key=lambda x: (x.get('timestamp', ''), x.get('timestamp_raw', 0)), reverse=reverse_sort)

    # Calculate real forensic statistics
    total_events = len(filtered_events)
    unique_files = set(ev['filename'] for ev in filtered_events if ev.get('filename'))
    
    created_count = 0
    modified_count = 0
    metadata_changed_count = 0
    accessed_count = 0
    investigation_count = 0
    type_distribution = {}

    for ev in filtered_events:
        etype = ev.get('event_type', 'Unknown')
        type_distribution[etype] = type_distribution.get(etype, 0) + 1
        
        lower_type = etype.lower()
        if 'metadata changed' in lower_type:
            metadata_changed_count += 1
        elif 'created' in lower_type:
            created_count += 1
        elif 'modified' in lower_type:
            modified_count += 1
        elif 'accessed' in lower_type:
            accessed_count += 1
        else:
            investigation_count += 1

    date_earliest = filtered_events[-1]['timestamp'] if reverse_sort and filtered_events else (filtered_events[0]['timestamp'] if filtered_events else None)
    date_latest = filtered_events[0]['timestamp'] if reverse_sort and filtered_events else (filtered_events[-1]['timestamp'] if filtered_events else None)

    return {
        'total_events': total_events,
        'total_files': len(unique_files),
        'created_events': created_count,
        'modified_events': modified_count,
        'metadata_changed_events': metadata_changed_count,
        'accessed_events': accessed_count,
        'investigation_events': investigation_count,
        'type_distribution': type_distribution,
        'sort_order': sort_order.lower(),
        'date_earliest': date_earliest,
        'date_latest': date_latest,
        'events': filtered_events,
        'filters': {
            'date_from': date_from or '',
            'date_to': date_to or '',
            'filename_query': filename_query or '',
            'event_type_filter': event_type_filter or 'ALL',
            'case_id_filter': case_id_filter or 'ALL',
            'evidence_id_filter': evidence_id_filter or 'ALL'
        }
    }


def export_timeline_json(timeline_data: dict, case_id: str = None) -> str:
    """Exports timeline events as structured JSON."""
    payload = {
        'forensix_version': '1.0.0',
        'export_type': 'Forensic Chronological Timeline',
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'case_id': case_id or 'GENERAL-INVESTIGATION',
        'summary_statistics': {
            'total_events': timeline_data.get('total_events', 0),
            'total_files_analyzed': timeline_data.get('total_files', 0),
            'created_events': timeline_data.get('created_events', 0),
            'modified_events': timeline_data.get('modified_events', 0),
            'metadata_changed_events': timeline_data.get('metadata_changed_events', 0),
            'accessed_events': timeline_data.get('accessed_events', 0),
            'investigation_events': timeline_data.get('investigation_events', 0),
            'date_range_start': timeline_data.get('date_earliest'),
            'date_range_end': timeline_data.get('date_latest')
        },
        'applied_filters': timeline_data.get('filters', {}),
        'timeline_events': timeline_data.get('events', [])
    }
    return json.dumps(payload, indent=2)


def export_timeline_csv(timeline_data: dict, case_id: str = None) -> str:
    """Exports timeline events as standard RFC-4180 CSV string."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Header
    writer.writerow([
        'Timestamp',
        'Event Type',
        'Filename',
        'Case ID',
        'Evidence ID',
        'Event Source',
        'Precision',
        'Timezone',
        'Forensic Notes'
    ])

    for ev in timeline_data.get('events', []):
        writer.writerow([
            ev.get('timestamp', ''),
            ev.get('event_type', ''),
            ev.get('filename', ''),
            ev.get('case_id', case_id or 'GENERAL-INVESTIGATION'),
            ev.get('evidence_id', ''),
            ev.get('event_source', ''),
            ev.get('precision', 'Second'),
            ev.get('timezone_info', ''),
            ev.get('forensic_notes', '')
        ])

    return output.getvalue()
