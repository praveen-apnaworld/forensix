"""
keyword_search.py - Forensic Keyword Search Engine for ForensiX Toolkit

This module provides high-performance, forensic text extraction and exact/case-insensitive
keyword search across authorized evidence files.

Supported formats:
- TXT, LOG: Plaintext logs and text evidence
- CSV: Delimited row records
- JSON: Structured data and configuration payloads
- PDF: Document evidence with page-level mapping (using pypdf)
- DOCX: Word documents with paragraph and table mapping (using python-docx)

Security & Integrity:
- Read-only processing: Original evidence streams are NEVER altered.
- Unsupported binary formats (images, executables, raw byte files) are safely identified
  and skipped without pretending to search them.
- Sensitive secret redaction: Sensitive tokens (passwords, API keys, secret hashes) are
  masked in context previews to prevent accidental exposure during presentations or reports.
"""

import os
import io
import re
import csv
import json
import html
from datetime import datetime

# Third-party forensic parsing libraries
try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import docx
except ImportError:
    docx = None


SUPPORTED_EXTENSIONS = {'txt', 'log', 'csv', 'json', 'pdf', 'docx'}

UNSUPPORTED_BINARY_EXTENSIONS = {
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp',
    'exe', 'dll', 'sys', 'dat', 'bin', 'so', 'elf',
    'zip', 'tar', 'gz', '7z', 'rar', 'bz2',
    'mp3', 'mp4', 'avi', 'wav', 'mov', 'mkv',
    'pcap', 'pcapng', 'db', 'sqlite', 'iso'
}

# Regex patterns for redacting sensitive secrets following keywords
SENSITIVE_SECRET_PATTERNS = [
    re.compile(r'((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|bearer|auth[_-]?token|pin)\s*[:=]\s*)(["\']?)([^"\'\s,;]+)(["\']?)', re.IGNORECASE),
    re.compile(r'((?:private[_-]?key|secret[_-]?key)\s*[:=]\s*)(["\']?)([^"\'\s,;]+)(["\']?)', re.IGNORECASE),
]


def redact_sensitive_values(text: str) -> str:
    """
    Masks credential values in context previews to protect sensitive secrets.
    Example: 'password=SuperSecret123!' -> 'password=[REDACTED]'
    """
    if not text:
        return ""
    
    redacted = text
    for pattern in SENSITIVE_SECRET_PATTERNS:
        def _replace_secret(match):
            prefix = match.group(1)
            q1 = match.group(2) or ''
            secret_val = match.group(3)
            q2 = match.group(4) or ''
            
            # If already redacted, leave it
            if secret_val == '[REDACTED]':
                return match.group(0)
            
            return f"{prefix}{q1}[REDACTED]{q2}"
        
        redacted = pattern.sub(_replace_secret, redacted)
    return redacted


def sanitize_search_terms(query_str: str) -> list[str]:
    """
    Parses a raw query string into a list of unique, non-empty search terms.
    Supports comma, semicolon, or newline-separated keywords.
    """
    if not query_str:
        return []
    
    # Split by commas, semicolons, or newlines
    raw_terms = re.split(r'[\r\n,;]+', query_str)
    cleaned_terms = []
    seen = set()
    
    for term in raw_terms:
        stripped = term.strip()
        if stripped and stripped not in seen:
            seen.add(stripped)
            cleaned_terms.append(stripped)
            
    return cleaned_terms


def get_file_extension(filename: str) -> str:
    """Extracts lowercase file extension without dot."""
    if not filename or '.' not in filename:
        return ''
    return filename.rsplit('.', 1)[-1].lower().strip()


def extract_text_segments(file_stream, filename: str, ext: str) -> dict:
    """
    Extracts text segments with location telemetry from supported evidence file streams.
    
    Returns dict:
    {
        'supported': bool,
        'readable': bool,
        'file_type': str,
        'error': str or None,
        'segments': [
            {
                'location_type': 'Line' | 'Page' | 'Row/Line' | 'Paragraph',
                'location_label': str,
                'line_number': int or None,
                'page_number': int or None,
                'text': str
            }, ...
        ]
    }
    """
    ext = ext.lower().strip()
    
    if ext in UNSUPPORTED_BINARY_EXTENSIONS:
        return {
            'supported': False,
            'readable': False,
            'file_type': ext.upper(),
            'error': f'Unsupported binary file type (.{ext}). Keyword text indexing is not applicable.',
            'segments': []
        }
    
    if ext not in SUPPORTED_EXTENSIONS:
        return {
            'supported': False,
            'readable': False,
            'file_type': ext.upper() if ext else 'UNKNOWN',
            'error': f'File format (.{ext or "unknown"}) is not supported for text extraction.',
            'segments': []
        }
    
    segments = []
    
    # Ensure stream is at beginning
    if hasattr(file_stream, 'seek'):
        file_stream.seek(0)
    
    raw_bytes = file_stream.read() if hasattr(file_stream, 'read') else file_stream
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raw_bytes = str(raw_bytes).encode('utf-8', errors='replace')
    
    try:
        # 1. Plaintext & Log Files
        if ext in {'txt', 'log'}:
            # Handle encodings gracefully
            text_content = None
            for enc in ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']:
                try:
                    text_content = raw_bytes.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            
            if text_content is None:
                text_content = raw_bytes.decode('utf-8', errors='replace')
            
            lines = text_content.splitlines()
            for idx, line in enumerate(lines, 1):
                if line.strip():  # Skip purely empty lines to save space
                    segments.append({
                        'location_type': 'Line',
                        'location_label': f'Line {idx}',
                        'line_number': idx,
                        'page_number': None,
                        'text': line
                    })
            
            return {
                'supported': True,
                'readable': True,
                'file_type': ext.upper(),
                'error': None,
                'segments': segments
            }
        
        # 2. CSV Files
        elif ext == 'csv':
            # Decode bytes
            text_content = None
            for enc in ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']:
                try:
                    text_content = raw_bytes.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            if text_content is None:
                text_content = raw_bytes.decode('utf-8', errors='replace')
            
            f_io = io.StringIO(text_content)
            reader = csv.reader(f_io)
            for row_idx, row in enumerate(reader, 1):
                row_str = " | ".join(row)
                if row_str.strip():
                    segments.append({
                        'location_type': 'Row/Line',
                        'location_label': f'Row {row_idx}',
                        'line_number': row_idx,
                        'page_number': None,
                        'text': row_str
                    })
            
            return {
                'supported': True,
                'readable': True,
                'file_type': 'CSV',
                'error': None,
                'segments': segments
            }
        
        # 3. JSON Files
        elif ext == 'json':
            text_content = None
            for enc in ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']:
                try:
                    text_content = raw_bytes.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            if text_content is None:
                text_content = raw_bytes.decode('utf-8', errors='replace')
            
            # Validate JSON format or parse lines
            try:
                parsed = json.loads(text_content)
                # Formatted pretty JSON for line-by-line inspection
                formatted_lines = json.dumps(parsed, indent=2).splitlines()
            except Exception:
                # If malformed JSON, fall back to raw lines
                formatted_lines = text_content.splitlines()
            
            for line_idx, line in enumerate(formatted_lines, 1):
                if line.strip():
                    segments.append({
                        'location_type': 'Line',
                        'location_label': f'Line {line_idx}',
                        'line_number': line_idx,
                        'page_number': None,
                        'text': line
                    })
            
            return {
                'supported': True,
                'readable': True,
                'file_type': 'JSON',
                'error': None,
                'segments': segments
            }
        
        # 4. PDF Documents (pypdf)
        elif ext == 'pdf':
            if pypdf is None:
                return {
                    'supported': True,
                    'readable': False,
                    'file_type': 'PDF',
                    'error': 'pypdf library is not installed on system.',
                    'segments': []
                }
            
            try:
                pdf_file = io.BytesIO(raw_bytes)
                reader = pypdf.PdfReader(pdf_file)
                
                if reader.is_encrypted:
                    try:
                        reader.decrypt('')
                    except Exception:
                        return {
                            'supported': True,
                            'readable': False,
                            'file_type': 'PDF',
                            'error': 'Encrypted or password-protected PDF document. Password required.',
                            'segments': []
                        }
                
                total_pages = len(reader.pages)
                for p_idx in range(total_pages):
                    page = reader.pages[p_idx]
                    page_text = page.extract_text() or ''
                    page_num = p_idx + 1
                    
                    lines = page_text.splitlines()
                    for l_idx, line in enumerate(lines, 1):
                        if line.strip():
                            segments.append({
                                'location_type': 'Page',
                                'location_label': f'Page {page_num}',
                                'line_number': l_idx,
                                'page_number': page_num,
                                'text': line
                            })
                
                return {
                    'supported': True,
                    'readable': True,
                    'file_type': 'PDF',
                    'error': None,
                    'segments': segments
                }
            except Exception as e:
                return {
                    'supported': True,
                    'readable': False,
                    'file_type': 'PDF',
                    'error': f'Corrupted or unreadable PDF document ({str(e)}).',
                    'segments': []
                }
        
        # 5. Microsoft Word Documents (DOCX)
        elif ext == 'docx':
            if docx is None:
                return {
                    'supported': True,
                    'readable': False,
                    'file_type': 'DOCX',
                    'error': 'python-docx library is not installed on system.',
                    'segments': []
                }
            
            try:
                doc_file = io.BytesIO(raw_bytes)
                document = docx.Document(doc_file)
                
                # Extract paragraphs
                for p_idx, para in enumerate(document.paragraphs, 1):
                    p_text = para.text.strip()
                    if p_text:
                        segments.append({
                            'location_type': 'Paragraph',
                            'location_label': f'Paragraph {p_idx}',
                            'line_number': p_idx,
                            'page_number': None,
                            'text': p_text
                        })
                
                # Extract tables
                for t_idx, table in enumerate(document.tables, 1):
                    for r_idx, row in enumerate(table.rows, 1):
                        row_cells = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                        if row_cells:
                            row_text = " | ".join(row_cells)
                            segments.append({
                                'location_type': 'Table',
                                'location_label': f'Table {t_idx}, Row {r_idx}',
                                'line_number': r_idx,
                                'page_number': None,
                                'text': row_text
                            })
                
                return {
                    'supported': True,
                    'readable': True,
                    'file_type': 'DOCX',
                    'error': None,
                    'segments': segments
                }
            except Exception as e:
                return {
                    'supported': True,
                    'readable': False,
                    'file_type': 'DOCX',
                    'error': f'Corrupted or unreadable DOCX document ({str(e)}).',
                    'segments': []
                }
                
    except Exception as e:
        return {
            'supported': True,
            'readable': False,
            'file_type': ext.upper(),
            'error': f'Extraction failed: {str(e)}',
            'segments': []
        }
    
    return {
        'supported': False,
        'readable': False,
        'file_type': ext.upper(),
        'error': 'Unhandled file format.',
        'segments': []
    }


def build_highlighted_context(text: str, match_start: int, match_end: int, keyword: str = "", case_sensitive: bool = False, window: int = 50) -> tuple[str, str]:
    """
    Extracts surrounding context with redaction and HTML highlight tags.
    Redacts sensitive secrets (e.g. passwords, API keys) in the window before highlighting.
    
    Returns:
        (clean_context_redacted, html_highlighted_context)
    """
    start_idx = max(0, match_start - window)
    end_idx = min(len(text), match_end + window)
    
    prefix = '...' if start_idx > 0 else ''
    suffix = '...' if end_idx < len(text) else ''
    
    raw_window = text[start_idx:end_idx]
    redacted_window = redact_sensitive_values(raw_window)
    clean_preview = f"{prefix}{redacted_window}{suffix}"
    
    # Highlight occurrences of the keyword in redacted_window
    kw_target = keyword if keyword else text[match_start:match_end]
    flags = 0 if case_sensitive else re.IGNORECASE
    kw_pattern = re.compile(re.escape(kw_target), flags)
    
    last_idx = 0
    html_parts = [html.escape(prefix)] if prefix else []
    for m in kw_pattern.finditer(redacted_window):
        html_parts.append(html.escape(redacted_window[last_idx:m.start()]))
        html_parts.append(f'<mark class="kw-highlight">{html.escape(m.group(0))}</mark>')
        last_idx = m.end()
    html_parts.append(html.escape(redacted_window[last_idx:]))
    if suffix:
        html_parts.append(html.escape(suffix))
        
    highlighted_html = "".join(html_parts)
    return clean_preview, highlighted_html


def search_file(file_stream, filename: str, keywords: list[str], case_sensitive: bool = False, match_mode: str = 'ANY') -> dict:
    """
    Searches a single evidence file stream for the provided keywords.
    
    Args:
        file_stream: BytesIO or file-like stream
        filename: Name of the file
        keywords: List of cleaned search terms
        case_sensitive: Whether match is case-sensitive
        match_mode: 'ANY' (match if at least 1 keyword found) or 'ALL' (match only if all keywords found)
        
    Returns:
        Result dictionary with match details, occurrence counts, and telemetry.
    """
    ext = get_file_extension(filename)
    extraction = extract_text_segments(file_stream, filename, ext)
    
    if not extraction['supported'] or not extraction['readable']:
        return {
            'filename': filename,
            'file_type': extraction['file_type'],
            'supported': extraction['supported'],
            'readable': extraction['readable'],
            'error': extraction['error'],
            'matched': False,
            'total_occurrences': 0,
            'keyword_counts': {kw: 0 for kw in keywords},
            'matches': []
        }
    
    segments = extraction['segments']
    matches = []
    keyword_counts = {kw: 0 for kw in keywords}
    
    # Precompile regexes for exact keyword matching
    term_regexes = []
    for kw in keywords:
        flags = 0 if case_sensitive else re.IGNORECASE
        # Exact literal match using re.escape
        pattern = re.compile(re.escape(kw), flags)
        term_regexes.append((kw, pattern))
    
    for seg in segments:
        seg_text = seg['text']
        for kw, pat in term_regexes:
            for m in pat.finditer(seg_text):
                keyword_counts[kw] += 1
                clean_context, html_context = build_highlighted_context(
                    seg_text, m.start(), m.end(), keyword=kw, case_sensitive=case_sensitive, window=50
                )
                matches.append({
                    'keyword': kw,
                    'matched_text': m.group(0),
                    'location_type': seg['location_type'],
                    'location_label': seg['location_label'],
                    'line_number': seg['line_number'],
                    'page_number': seg['page_number'],
                    'context': clean_context,
                    'highlighted_html': html_context
                })
    
    # Evaluate ANY vs ALL matching
    if match_mode.upper() == 'ALL':
        is_matched = all(keyword_counts[kw] > 0 for kw in keywords) if keywords else False
    else:  # ANY
        is_matched = any(keyword_counts[kw] > 0 for kw in keywords) if keywords else False
    
    # If mode is ALL but some keywords were missing, discard or suppress matches according to logic
    total_occ = sum(keyword_counts.values()) if is_matched else 0
    if not is_matched and match_mode.upper() == 'ALL':
        matches = []
        keyword_counts = {kw: 0 for kw in keywords}
    
    return {
        'filename': filename,
        'file_type': extraction['file_type'],
        'supported': True,
        'readable': True,
        'error': None,
        'matched': is_matched,
        'total_occurrences': total_occ,
        'keyword_counts': keyword_counts,
        'matches': matches
    }


def search_evidence_set(file_items: list, keywords: list[str], case_sensitive: bool = False, match_mode: str = 'ANY', file_type_filter: str = 'ALL') -> dict:
    """
    Executes keyword search across an authorized set of evidence files.
    
    Args:
        file_items: List of tuples (file_stream_or_path, filename)
        keywords: List of raw or cleaned search terms
        case_sensitive: Boolean flag
        match_mode: 'ANY' or 'ALL'
        file_type_filter: 'ALL' or specific extension (e.g. 'pdf', 'txt')
        
    Returns:
        Structured search summary and results table data.
    """
    cleaned_keywords = sanitize_search_terms(",".join(keywords)) if isinstance(keywords, list) else sanitize_search_terms(keywords)
    
    total_scanned = 0
    matching_files = []
    unsupported_files = []
    keyword_overall_counts = {kw: 0 for kw in cleaned_keywords}
    
    file_type_filter = (file_type_filter or 'ALL').strip().lower()
    
    for item in file_items:
        # Handle either tuple (stream, filename) or path string
        if isinstance(item, tuple):
            stream_or_path, filename = item
            is_path = False
        else:
            stream_or_path = item
            filename = os.path.basename(item)
            is_path = True
        
        ext = get_file_extension(filename)
        
        # Apply file type filter if specified
        if file_type_filter != 'all' and ext != file_type_filter:
            continue
        
        total_scanned += 1
        
        try:
            if is_path:
                with open(stream_or_path, 'rb') as f:
                    file_res = search_file(f, filename, cleaned_keywords, case_sensitive, match_mode)
            else:
                file_res = search_file(stream_or_path, filename, cleaned_keywords, case_sensitive, match_mode)
            
            if not file_res['supported'] or not file_res['readable']:
                unsupported_files.append({
                    'filename': filename,
                    'file_type': file_res['file_type'],
                    'error': file_res['error'] or 'Unsupported or unreadable file'
                })
            elif file_res['matched']:
                matching_files.append(file_res)
                for kw, cnt in file_res['keyword_counts'].items():
                    keyword_overall_counts[kw] += cnt
                    
        except Exception as e:
            unsupported_files.append({
                'filename': filename,
                'file_type': ext.upper() if ext else 'UNKNOWN',
                'error': f'Failed to process file: {str(e)}'
            })
            
    total_occurrences = sum(keyword_overall_counts.values())
    
    return {
        'search_terms': cleaned_keywords,
        'case_sensitive': case_sensitive,
        'match_mode': match_mode.upper(),
        'file_type_filter': file_type_filter.upper(),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_files_scanned': total_scanned,
        'total_matching_files': len(matching_files),
        'total_occurrences': total_occurrences,
        'unsupported_or_unreadable_count': len(unsupported_files),
        'keyword_counts': keyword_overall_counts,
        'results': matching_files,
        'unsupported_files': unsupported_files
    }


def export_results_json(results_data: dict, case_id: str = None) -> str:
    """
    Exports search results as formatted JSON string.
    """
    export_payload = {
        'forensix_version': '1.0.0',
        'export_type': 'Keyword Search Report',
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'case_id': case_id or 'GENERAL-INVESTIGATION',
        'search_parameters': {
            'search_terms': results_data.get('search_terms', []),
            'case_sensitive': results_data.get('case_sensitive', False),
            'match_mode': results_data.get('match_mode', 'ANY'),
            'file_type_filter': results_data.get('file_type_filter', 'ALL')
        },
        'summary_statistics': {
            'total_files_scanned': results_data.get('total_files_scanned', 0),
            'total_matching_files': results_data.get('total_matching_files', 0),
            'total_occurrences': results_data.get('total_occurrences', 0),
            'unsupported_or_unreadable_count': results_data.get('unsupported_or_unreadable_count', 0),
            'keyword_counts': results_data.get('keyword_counts', {})
        },
        'matching_files': results_data.get('results', []),
        'unsupported_files': results_data.get('unsupported_files', [])
    }
    return json.dumps(export_payload, indent=2)


def export_results_csv(results_data: dict, case_id: str = None) -> str:
    """
    Exports search results as standard RFC-4180 CSV string.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    
    # Header
    writer.writerow([
        'Case ID',
        'Search Timestamp',
        'Search Terms',
        'Match Mode',
        'Filename',
        'File Type',
        'Matched Keyword',
        'Location Type',
        'Location Details',
        'Line Number',
        'Page Number',
        'Occurrence Context Preview'
    ])
    
    case_str = case_id or 'GENERAL-INVESTIGATION'
    timestamp_str = results_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    terms_str = "; ".join(results_data.get('search_terms', []))
    mode_str = results_data.get('match_mode', 'ANY')
    
    for file_item in results_data.get('results', []):
        fname = file_item['filename']
        ftype = file_item['file_type']
        for match in file_item.get('matches', []):
            writer.writerow([
                case_str,
                timestamp_str,
                terms_str,
                mode_str,
                fname,
                ftype,
                match.get('keyword', ''),
                match.get('location_type', ''),
                match.get('location_label', ''),
                match.get('line_number') or '',
                match.get('page_number') or '',
                match.get('context', '')
            ])
            
    return output.getvalue()
