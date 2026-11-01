"""
app.py - Main Flask Application for Digital Forensics Toolkit

This is the entry point of our application. When you run this file,
it starts the web server and handles all the page requests.

How it works:
1. Flask receives a request (e.g., user clicks "Dashboard")
2. It finds the matching route (e.g., @app.route('/'))
3. The route function runs and returns an HTML page
4. The browser displays that page
"""

import os
import uuid
import shutil
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, Response, session, send_file, abort

from config import Config
from database.db import get_db, close_db, init_db, init_app, check_or_migrate_reports_table
from modules.hash_analyzer import (
    compute_hashes, compare_hashes, validate_hash_format, format_file_size
)
from modules.file_analyzer import (
    analyze_file_stream, summarize_file_analysis, sanitize_filename
)
from modules.metadata_extractor import extract_metadata, compare_image_metadata
from modules.keyword_search import (
    search_evidence_set, export_results_json, export_results_csv, sanitize_search_terms
)
from modules.timeline_analyzer import (
    extract_filesystem_timestamps, extract_embedded_document_timestamps,
    collect_case_database_events, generate_timeline, export_timeline_json, export_timeline_csv
)
from modules.report_generator import (
    PDFReportGenerator, fetch_case_report_data, record_generated_report
)
import json
import zipfile
import io


def create_app():
    """
    Application Factory - creates and configures the Flask app.

    This pattern is recommended by Flask. It lets us create multiple
    instances of the app (useful for testing).
    """
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure required folders exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

    # Register database functions with the app
    init_app(app)

    # Initialize the database (creates tables if they don't exist)
    with app.app_context():
        init_db()

    # ================================================================
    # ROUTES - Each route maps a URL to a page
    # ================================================================

    @app.route('/')
    def dashboard():
        """
        Dashboard - The main landing page.
        Shows real statistics from the database (no fake data).
        """
        db = get_db()

        # Count total cases
        total_cases = db.execute('SELECT COUNT(*) FROM cases').fetchone()[0]

        # Count total evidence files
        total_evidence = db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]

        # Count total reports
        total_reports = db.execute('SELECT COUNT(*) FROM reports').fetchone()[0]

        # Get file type distribution for the chart
        file_types = db.execute(
            'SELECT file_type, COUNT(*) as count FROM evidence '
            'WHERE file_type IS NOT NULL GROUP BY file_type'
        ).fetchall()

        # Get recent cases (last 5)
        recent_cases = db.execute(
            'SELECT * FROM cases ORDER BY created_at DESC LIMIT 5'
        ).fetchall()

        # Get recent audit logs (last 10)
        recent_activity = db.execute(
            'SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10'
        ).fetchall()

        # Get recent reports (last 5)
        recent_reports = db.execute(
            'SELECT r.*, c.case_id as case_number, c.title as case_title '
            'FROM reports r JOIN cases c ON r.case_id = c.id '
            'ORDER BY r.generated_at DESC LIMIT 5'
        ).fetchall()

        return render_template('dashboard.html',
                               total_cases=total_cases,
                               total_evidence=total_evidence,
                               total_reports=total_reports,
                               file_types=file_types,
                               recent_cases=recent_cases,
                               recent_activity=recent_activity,
                               recent_reports=recent_reports)

    @app.route('/cases')
    def cases():
        """Cases page - list all investigation cases."""
        db = get_db()
        all_cases = db.execute(
            'SELECT * FROM cases ORDER BY created_at DESC'
        ).fetchall()
        return render_template('cases.html', cases=all_cases)

    @app.route('/cases/new', methods=['POST'])
    def create_case():
        """Create a new investigation case."""
        db = get_db()
        case_id = (request.form.get('case_id') or '').strip().upper()
        title = (request.form.get('title') or '').strip()
        description = (request.form.get('description') or '').strip()
        investigator = (request.form.get('investigator') or 'Lead Forensic Examiner').strip()

        if not case_id or not title:
            flash('Case ID and Title are required fields.', 'error')
            return redirect(request.referrer or url_for('cases'))

        existing = db.execute('SELECT id FROM cases WHERE case_id = ?', (case_id,)).fetchone()
        if existing:
            flash(f'Case with ID "{case_id}" already exists. Please choose a unique Case ID.', 'error')
            return redirect(request.referrer or url_for('cases'))

        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.execute(
            '''
            INSERT INTO cases (case_id, title, description, investigator, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'Open', ?, ?)
            ''',
            (case_id, title, description, investigator, now_str, now_str)
        )
        case_row = db.execute('SELECT id FROM cases WHERE case_id = ?', (case_id,)).fetchone()
        db.execute(
            '''
            INSERT INTO audit_logs (case_id, action, details, performed_by, timestamp)
            VALUES (?, 'Create Case', ?, ?, ?)
            ''',
            (case_row['id'], f'Created investigation case {case_id}: {title}', investigator, now_str)
        )
        db.commit()
        flash(f'Investigation case "{case_id}" successfully registered.', 'success')
        return redirect(request.referrer or url_for('cases'))

    @app.route('/api/cases/<case_identifier>/evidence')
    def get_case_evidence(case_identifier):
        """Dynamic JSON API returning registered evidence items for a specific case."""
        db = get_db()
        case_row = db.execute(
            'SELECT * FROM cases WHERE id = ? OR case_id = ?', (case_identifier, case_identifier)
        ).fetchone()
        if not case_row:
            return jsonify({'error': 'Case not found', 'evidence': [], 'count': 0}), 404

        ev_rows = db.execute(
            'SELECT id, evidence_id, filename, file_type, file_size, description, added_at '
            'FROM evidence WHERE case_id = ? ORDER BY id ASC',
            (case_row['id'],)
        ).fetchall()

        evidence_list = []
        for r in ev_rows:
            evidence_list.append({
                'id': r['id'],
                'evidence_id': r['evidence_id'],
                'filename': r['filename'],
                'file_type': r['file_type'] or 'UNKNOWN',
                'file_size': r['file_size'] or 0,
                'file_size_formatted': format_file_size(r['file_size'] or 0),
                'description': r['description'] or '',
                'added_at': (r['added_at'] or '')[:19]
            })

        return jsonify({
            'case_id': case_row['case_id'],
            'case_title': case_row['title'],
            'case_pk': case_row['id'],
            'count': len(evidence_list),
            'evidence': evidence_list
        })

    @app.route('/evidence')
    def evidence():
        """Evidence Manager page."""
        db = get_db()
        all_cases = db.execute('SELECT * FROM cases ORDER BY created_at DESC').fetchall()
        all_evidence = db.execute(
            'SELECT e.*, c.case_id as case_number, c.title as case_title '
            'FROM evidence e JOIN cases c ON e.case_id = c.id '
            'ORDER BY e.added_at DESC'
        ).fetchall()
        return render_template('evidence.html', cases=all_cases, evidence_list=all_evidence)

    @app.route('/evidence/register', methods=['POST'])
    def register_evidence():
        """Register an uploaded evidence file into a specific case."""
        db = get_db()
        case_id = request.form.get('case_id')
        evidence_file = request.files.get('evidence_file')
        description = (request.form.get('description') or 'Seized digital media').strip()
        source = (request.form.get('source') or 'Investigative intake').strip()
        acq_method = (request.form.get('acquisition_method') or 'Logical Acquisition').strip()

        if not case_id:
            flash('Please select an investigation case to register evidence.', 'error')
            return redirect(request.referrer or url_for('evidence'))

        case_row = db.execute('SELECT * FROM cases WHERE id = ? OR case_id = ?', (case_id, case_id)).fetchone()
        if not case_row:
            flash('Specified case does not exist.', 'error')
            return redirect(request.referrer or url_for('evidence'))

        if not evidence_file or not evidence_file.filename:
            flash('Please choose a file to register as evidence.', 'error')
            return redirect(request.referrer or url_for('evidence'))

        raw_filename = sanitize_filename(evidence_file.filename) or 'evidence.bin'
        now_dt = datetime.now()
        now_str = now_dt.strftime('%Y-%m-%d %H:%M:%S')

        ev_count = db.execute('SELECT COUNT(*) as cnt FROM evidence WHERE case_id = ?', (case_row['id'],)).fetchone()['cnt']
        safe_case = sanitize_filename(case_row['case_id']).replace(' ', '_')
        ev_code = f"EVD-{safe_case[-4:]}-{ev_count + 1:03d}"

        upload_dir = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)
        dest_filename = f"{safe_case}_{uuid.uuid4().hex[:6]}_{raw_filename}"
        dest_path = os.path.join(upload_dir, dest_filename)
        evidence_file.save(dest_path)

        f_size = os.path.getsize(dest_path)
        ext = raw_filename.rsplit('.', 1)[-1].upper() if '.' in raw_filename else 'BIN'

        db.execute(
            '''
            INSERT INTO evidence (evidence_id, case_id, filename, original_path, stored_path, description, source, acquisition_method, file_size, file_type, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (ev_code, case_row['id'], raw_filename, f"/intake/{raw_filename}", dest_path, description, source, acq_method, f_size, ext, now_str)
        )
        new_ev = db.execute('SELECT id FROM evidence WHERE case_id = ? AND evidence_id = ?', (case_row['id'], ev_code)).fetchone()

        with open(dest_path, 'rb') as f:
            h_res = compute_hashes(f)
        db.execute(
            '''
            INSERT INTO hash_records (evidence_id, md5, sha1, sha256, verification_status, verified_at, verified_by)
            VALUES (?, ?, ?, ?, 'Verified Authentic', ?, 'System Intake')
            ''',
            (new_ev['id'], h_res['md5'], h_res['sha1'], h_res['sha256'], now_str)
        )
        db.execute(
            '''
            INSERT INTO chain_of_custody (evidence_id, action, performed_by, details, timestamp)
            VALUES (?, 'Evidence Intake', ?, ?, ?)
            ''',
            (new_ev['id'], 'Lead Forensic Examiner', f'Initial intake and bit-stream baseline verification of {raw_filename}', now_str)
        )
        db.commit()
        flash(f'Evidence "{raw_filename}" ({ev_code}) successfully registered under case {case_row["case_id"]}.', 'success')
        return redirect(request.referrer or url_for('reports'))

    @app.route('/hash-analyzer', methods=['GET', 'POST'])
    def hash_analyzer():
        """
        Hash Analyzer page.

        GET:  Display the hash analyzer form.
        POST: Compute hashes for an uploaded file, or compare hashes.

        The file is processed in memory and NEVER saved to disk permanently.
        This protects the original evidence and avoids unnecessary storage.
        """
        result = None
        comparison = None
        error = None

        if request.method == 'POST':
            action = request.form.get('action', 'compute')

            try:
                if action == 'compute':
                    # --- COMPUTE HASHES ---
                    # Check if a file was actually uploaded
                    if 'file' not in request.files:
                        error = 'No file was selected. Please choose a file to analyze.'
                    else:
                        file = request.files['file']

                        if file.filename == '' or file.filename is None:
                            error = 'No file was selected. Please choose a file to analyze.'
                        else:
                            # Compute all three hashes from the file stream
                            # The file is read in chunks — never fully loaded into memory
                            hashes = compute_hashes(file.stream)

                            result = {
                                'filename': file.filename,
                                'file_size_bytes': hashes['file_size'],
                                'file_size_human': format_file_size(hashes['file_size']),
                                'md5': hashes['md5'],
                                'sha1': hashes['sha1'],
                                'sha256': hashes['sha256'],
                                'computed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            }

                elif action == 'compare':
                    # --- COMPARE HASH ---
                    # Check if a file was uploaded for comparison
                    if 'compare_file' not in request.files:
                        error = 'No file was selected for comparison.'
                    else:
                        file = request.files['compare_file']

                        if file.filename == '' or file.filename is None:
                            error = 'No file was selected for comparison.'
                        else:
                            expected_hash = request.form.get('expected_hash', '').strip()
                            algorithm = request.form.get('algorithm', 'sha256').strip()

                            if not expected_hash:
                                error = 'Please enter an expected hash value to compare against.'
                            else:
                                # Validate the expected hash format
                                validation = validate_hash_format(expected_hash, algorithm)
                                if not validation['valid']:
                                    error = validation['error']
                                else:
                                    # Compute all hashes for the uploaded file
                                    hashes = compute_hashes(file.stream)

                                    # Get the computed hash for the selected algorithm
                                    computed = hashes.get(algorithm, '')

                                    # Compare computed vs expected
                                    cmp_result = compare_hashes(computed, expected_hash)

                                    comparison = {
                                        'filename': file.filename,
                                        'file_size_human': format_file_size(hashes['file_size']),
                                        'algorithm': algorithm.upper(),
                                        'computed_hash': cmp_result['computed'],
                                        'expected_hash': cmp_result['expected'],
                                        'match': cmp_result['match'],
                                        'status': cmp_result['status'],
                                        'all_hashes': {
                                            'md5': hashes['md5'],
                                            'sha1': hashes['sha1'],
                                            'sha256': hashes['sha256']
                                        }
                                    }

            except Exception as e:
                error = f'An error occurred while processing the file: {str(e)}'

        return render_template('hash_analyzer.html',
                               result=result,
                               comparison=comparison,
                               error=error)

    @app.route('/file-analyzer', methods=['GET', 'POST'])
    def file_analyzer():
        """
        File Analyzer page.

        GET:  Display the file analyzer upload form.
        POST: Analyze uploaded evidence files (supports multiple files).
              Inspects file headers, verifies signatures against extensions,
              detects hidden files, and categorizes without executing any file.
        """
        results = None
        summary = None
        error = None

        if request.method == 'POST':
            try:
                # Check for uploaded files
                uploaded_files = request.files.getlist('files')

                # If no files or single file with empty filename
                valid_files = [f for f in uploaded_files if f and f.filename and f.filename.strip()]

                if not valid_files:
                    error = 'No files were selected for analysis. Please choose one or more evidence files.'
                else:
                    # Optional client modification timestamps passed as JSON
                    client_timestamps = {}
                    timestamps_raw = request.form.get('client_timestamps')
                    if timestamps_raw:
                        try:
                            client_timestamps = json.loads(timestamps_raw)
                        except Exception:
                            pass

                    analyzed_list = []
                    for file_obj in valid_files:
                        raw_name = file_obj.filename
                        client_mtime = client_timestamps.get(raw_name)

                        # Analyze the stream safely in memory
                        file_info = analyze_file_stream(
                            file_stream=file_obj.stream,
                            raw_filename=raw_name,
                            client_mtime=client_mtime
                        )
                        analyzed_list.append(file_info)

                    results = analyzed_list
                    summary = summarize_file_analysis(results)

            except Exception as e:
                error = f'An error occurred during file analysis: {str(e)}'

        return render_template('file_analyzer.html',
                               results=results,
                               summary=summary,
                               error=error)

    @app.route('/metadata', methods=['GET', 'POST'])
    def metadata():
        """
        Metadata Extractor page.

        GET:  Display the metadata extractor upload form and comparison interface.
        POST: Extract EXIF (images), PDF metadata, or Word (DOCX) properties,
              or perform side-by-side comparison between two digital evidence files.
        """
        result = None
        comparison = None
        error = None
        active_tab = request.args.get('tab', 'single')

        if request.method == 'POST':
            action = request.form.get('action', 'extract')
            if action == 'compare':
                active_tab = 'compare'
                try:
                    file1 = request.files.get('file1')
                    file2 = request.files.get('file2')
                    if not file1 or not file1.filename or not file1.filename.strip() or \
                       not file2 or not file2.filename or not file2.filename.strip():
                        error = 'Please select two evidence files to perform side-by-side comparison.'
                    else:
                        comp_res = compare_image_metadata(file1.stream, file1.filename, file2.stream, file2.filename)
                        if comp_res.get('success'):
                            comparison = comp_res
                        else:
                            error = comp_res.get('error', 'Metadata comparison failed.')
                except Exception as e:
                    error = f'An error occurred during metadata comparison: {str(e)}'
            else:
                active_tab = 'single'
                try:
                    if 'file' not in request.files:
                        error = 'No file was selected for metadata extraction.'
                    else:
                        file_obj = request.files['file']
                        if not file_obj or not file_obj.filename or not file_obj.filename.strip():
                            error = 'No file was selected for metadata extraction.'
                        else:
                            analysis = extract_metadata(file_obj.stream, file_obj.filename)
                            if analysis.get('success'):
                                result = analysis
                                # Track recent files in session for rename detection in single file workflow
                                cur_sha256 = analysis.get('sha256')
                                cur_name = analysis.get('filename')
                                history = session.get('metadata_upload_history', {})
                                if cur_sha256 and cur_sha256 in history and history[cur_sha256] != cur_name:
                                    result['identical_content_detected'] = True
                                    result['previous_identical_filename'] = history[cur_sha256]
                                history[cur_sha256] = cur_name
                                session['metadata_upload_history'] = history
                            else:
                                error = analysis.get('error', 'Failed to extract metadata.')
                except Exception as e:
                    error = f'An error occurred during metadata extraction: {str(e)}'

        return render_template('metadata.html',
                               result=result,
                               comparison=comparison,
                               active_tab=active_tab,
                               error=error)

    @app.route('/metadata/compare', methods=['GET', 'POST'])
    def metadata_compare():
        """Direct route for evidence metadata comparison."""
        if request.method == 'GET':
            return redirect(url_for('metadata', tab='compare'))
        return metadata()

    @app.route('/metadata/export-json', methods=['POST'])
    def metadata_export_json():
        """
        Download extracted metadata analysis as a JSON file.
        """
        export_content = request.form.get('export_data', '{}')
        orig_name = request.form.get('filename', 'evidence')
        safe_name = sanitize_filename(orig_name)
        base_name = safe_name.rsplit('.', 1)[0]
        download_name = f"{base_name}_metadata.json"

        return Response(
            export_content,
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename="{download_name}"',
                'Cache-Control': 'no-cache'
            }
        )

    @app.route('/keyword-search', methods=['GET', 'POST'])
    def keyword_search():
        """
        Keyword Search page.
        GET: Display search interface with evidence source selectors.
        POST: Scan evidence files for exact/case-insensitive keywords and return matches.
        """
        db = get_db()
        all_cases = db.execute('SELECT * FROM cases ORDER BY created_at DESC').fetchall()

        results = None
        error = None
        search_query = ''
        case_sensitive = False
        match_mode = 'ANY'
        file_type_filter = 'ALL'
        evidence_source = 'sample' if not all_cases else 'sample'
        selected_case_id = ''
        export_json_payload = ''

        if request.method == 'POST':
            search_query = request.form.get('search_query', '').strip()
            case_sensitive = True if request.form.get('case_sensitive') in ('1', 'on', 'true') else False
            match_mode = request.form.get('match_mode', 'ANY').upper()
            file_type_filter = request.form.get('file_type_filter', 'ALL').strip().lower()
            evidence_source = request.form.get('evidence_source', 'sample').strip().lower()
            selected_case_id = request.form.get('case_id', '').strip()

            cleaned_keywords = sanitize_search_terms(search_query)

            if not cleaned_keywords:
                error = 'Please enter at least one valid keyword or search term.'
            else:
                file_items = []

                if evidence_source == 'sample':
                    # Authorized sample evidence repository
                    sample_dir = os.path.join(os.path.dirname(__file__), 'sample_evidence')
                    if os.path.exists(sample_dir):
                        for fname in sorted(os.listdir(sample_dir)):
                            fpath = os.path.join(sample_dir, fname)
                            if os.path.isfile(fpath):
                                file_items.append(fpath)
                    if not file_items:
                        error = 'No sample evidence files found in repository.'

                elif evidence_source == 'case':
                    # Investigation case evidence registered in SQLite
                    if not selected_case_id:
                        error = 'Please select an investigation case to search.'
                    else:
                        case_evidences = db.execute(
                            'SELECT * FROM evidence WHERE case_id = (SELECT id FROM cases WHERE case_id = ? OR id = ?)',
                            (selected_case_id, selected_case_id)
                        ).fetchall()

                        for ev in case_evidences:
                            st_path = ev['stored_path']
                            if st_path and os.path.exists(st_path):
                                file_items.append(st_path)
                            elif st_path:
                                fallback_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(st_path))
                                if os.path.exists(fallback_path):
                                    file_items.append(fallback_path)

                        if not file_items:
                            error = f'No registered evidence files found on disk for Case {selected_case_id}.'

                else:  # evidence_source == 'upload'
                    uploaded_files = request.files.getlist('files')
                    valid_files = [f for f in uploaded_files if f and f.filename and f.filename.strip()]

                    if not valid_files:
                        error = 'Please select at least one evidence file or archive to search.'
                    else:
                        for f_obj in valid_files:
                            safe_name = sanitize_filename(f_obj.filename)
                            # Safe handling of ZIP archives
                            if safe_name.lower().endswith('.zip'):
                                try:
                                    zf = zipfile.ZipFile(f_obj.stream)
                                    for zinfo in zf.infolist():
                                        # Prevent zip slip / directory traversal
                                        if zinfo.is_dir() or '..' in zinfo.filename or zinfo.filename.startswith(('/', '\\')):
                                            continue
                                        # Size limit check (25MB max per uncompressed file)
                                        if zinfo.file_size > 25 * 1024 * 1024:
                                            continue
                                        member_bytes = zf.read(zinfo.filename)
                                        member_name = os.path.basename(zinfo.filename)
                                        if member_name:
                                            file_items.append((io.BytesIO(member_bytes), member_name))
                                except Exception as ze:
                                    error = f'Failed to process ZIP archive: {str(ze)}'
                                    break
                            else:
                                file_bytes = f_obj.read()
                                file_items.append((io.BytesIO(file_bytes), safe_name))

                if not error:
                    if not file_items:
                        error = 'No files were available to scan for the selected source.'
                    else:
                        try:
                            results = search_evidence_set(
                                file_items=file_items,
                                keywords=cleaned_keywords,
                                case_sensitive=case_sensitive,
                                match_mode=match_mode,
                                file_type_filter=file_type_filter
                            )
                            export_json_payload = export_results_json(results, case_id=selected_case_id)
                        except Exception as se:
                            error = f'Search execution error: {str(se)}'

        return render_template('keyword_search.html',
                               cases=all_cases,
                               results=results,
                               error=error,
                               search_query=search_query,
                               case_sensitive=case_sensitive,
                               match_mode=match_mode,
                               file_type_filter=file_type_filter,
                               evidence_source=evidence_source,
                               selected_case_id=selected_case_id,
                               export_json_payload=export_json_payload)

    @app.route('/keyword-search/export-json', methods=['POST'])
    def keyword_search_export_json():
        """Download keyword search results as JSON."""
        export_payload = request.form.get('export_data', '{}')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"forensix_keyword_search_{timestamp}.json"
        return Response(
            export_payload,
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Cache-Control': 'no-cache'
            }
        )

    @app.route('/keyword-search/export-csv', methods=['POST'])
    def keyword_search_export_csv():
        """Download keyword search results as CSV."""
        export_payload = request.form.get('export_data', '{}')
        try:
            results_data = json.loads(export_payload)
            csv_content = export_results_csv(results_data)
        except Exception:
            csv_content = 'Error generating CSV export.'

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"forensix_keyword_search_{timestamp}.csv"
        return Response(
            csv_content,
            mimetype='text/csv; charset=utf-8',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Cache-Control': 'no-cache'
            }
        )

    @app.route('/timeline', methods=['GET', 'POST'])
    def timeline():
        """
        Timeline Analyzer page.
        GET/POST: Collects filesystem and investigation timestamps,
        sorts chronologically, applies filters, and renders the visual timeline.
        """
        db = get_db()
        all_cases = db.execute('SELECT * FROM cases ORDER BY created_at DESC').fetchall()

        # Extract parameters from POST form or GET query args
        evidence_source = request.form.get('evidence_source', request.args.get('evidence_source', 'sample')).strip().lower()
        sort_order = request.form.get('sort_order', request.args.get('sort_order', 'desc')).strip().lower()
        date_from = request.form.get('date_from', request.args.get('date_from', '')).strip()
        date_to = request.form.get('date_to', request.args.get('date_to', '')).strip()
        filename_query = request.form.get('filename_query', request.args.get('filename_query', '')).strip()
        event_type_filter = request.form.get('event_type_filter', request.args.get('event_type_filter', 'ALL')).strip()
        selected_case_id = request.form.get('case_id', request.args.get('case_id', '')).strip()

        error = None
        raw_events = []

        # 1. Evidence Source: Preloaded Sample Evidence
        if evidence_source == 'sample':
            sample_dir = os.path.join(os.path.dirname(__file__), 'sample_evidence')
            if os.path.exists(sample_dir):
                for fname in sorted(os.listdir(sample_dir)):
                    fpath = os.path.join(sample_dir, fname)
                    if os.path.isfile(fpath):
                        # Extract filesystem MACB
                        fs_evs = extract_filesystem_timestamps(fpath, fname, evidence_id=f"EVD-{fname}", case_id="SAMPLE-EVIDENCE")
                        raw_events.extend(fs_evs)
                        # Extract document embedded timestamps (PDF/DOCX/EXIF)
                        doc_evs = extract_embedded_document_timestamps(fpath, fname, evidence_id=f"EVD-{fname}", case_id="SAMPLE-EVIDENCE")
                        raw_events.extend(doc_evs)
            if not raw_events:
                error = 'No sample evidence files found in sample_evidence directory.'

        # 2. Evidence Source: Case Database
        elif evidence_source == 'case':
            db_events = collect_case_database_events(db, case_id=selected_case_id if selected_case_id else None)
            raw_events.extend(db_events)
            if not raw_events:
                if selected_case_id:
                    error = f'No evidence or investigation records found for Case {selected_case_id}.'
                else:
                    error = 'No investigation cases or evidence records found in the database. Try scanning the Sample Evidence suite.'

        # 3. Evidence Source: Uploaded Files
        else:  # upload
            uploaded_files = request.files.getlist('files')
            valid_files = [f for f in uploaded_files if f and f.filename and f.filename.strip()]
            if not valid_files:
                error = 'Please select at least one evidence file or archive to analyze.'
            else:
                upload_tmp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'timeline_tmp')
                os.makedirs(upload_tmp_dir, exist_ok=True)
                for f_obj in valid_files:
                    safe_name = sanitize_filename(f_obj.filename)
                    if safe_name.lower().endswith('.zip'):
                        try:
                            zf = zipfile.ZipFile(f_obj.stream)
                            for zinfo in zf.infolist():
                                if zinfo.is_dir() or '..' in zinfo.filename or zinfo.filename.startswith(('/', '\\')):
                                    continue
                                if zinfo.file_size > 25 * 1024 * 1024:
                                    continue
                                member_name = os.path.basename(zinfo.filename)
                                if member_name:
                                    target_p = os.path.join(upload_tmp_dir, member_name)
                                    with open(target_p, 'wb') as tf:
                                        tf.write(zf.read(zinfo.filename))
                                    raw_events.extend(extract_filesystem_timestamps(target_p, member_name, evidence_id=f"EVD-{member_name}", case_id="UPLOADED-ARCHIVE"))
                                    raw_events.extend(extract_embedded_document_timestamps(target_p, member_name, evidence_id=f"EVD-{member_name}", case_id="UPLOADED-ARCHIVE"))
                        except Exception as ze:
                            error = f'Failed to process ZIP archive: {str(ze)}'
                            break
                    else:
                        target_p = os.path.join(upload_tmp_dir, safe_name)
                        f_obj.save(target_p)
                        raw_events.extend(extract_filesystem_timestamps(target_p, safe_name, evidence_id=f"EVD-{safe_name}", case_id="UPLOADED-EVIDENCE"))
                        raw_events.extend(extract_embedded_document_timestamps(target_p, safe_name, evidence_id=f"EVD-{safe_name}", case_id="UPLOADED-EVIDENCE"))

        timeline_data = generate_timeline(
            events=raw_events,
            sort_order=sort_order,
            date_from=date_from,
            date_to=date_to,
            filename_query=filename_query,
            event_type_filter=event_type_filter,
            case_id_filter=selected_case_id
        )

        export_json_payload = export_timeline_json(timeline_data, case_id=selected_case_id)

        return render_template('timeline.html',
                               timeline=timeline_data,
                               cases=all_cases,
                               error=error,
                               evidence_source=evidence_source,
                               sort_order=sort_order,
                               date_from=date_from,
                               date_to=date_to,
                               filename_query=filename_query,
                               event_type_filter=event_type_filter,
                               selected_case_id=selected_case_id,
                               export_json_payload=export_json_payload)

    @app.route('/timeline/export-json', methods=['POST'])
    def timeline_export_json():
        """Download timeline analysis as structured JSON."""
        export_payload = request.form.get('export_data', '{}')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"forensix_timeline_{timestamp}.json"
        return Response(
            export_payload,
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Cache-Control': 'no-cache'
            }
        )

    @app.route('/timeline/export-csv', methods=['POST'])
    def timeline_export_csv():
        """Download timeline analysis as standard CSV."""
        export_payload = request.form.get('export_data', '{}')
        try:
            timeline_data = json.loads(export_payload)
            csv_content = export_timeline_csv(timeline_data)
        except Exception:
            csv_content = 'Error generating CSV export.'

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"forensix_timeline_{timestamp}.csv"
        return Response(
            csv_content,
            mimetype='text/csv; charset=utf-8',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Cache-Control': 'no-cache'
            }
        )

    @app.route('/reports')
    def reports():
        """Reports page - generate and archive professional forensic PDF reports."""
        db = get_db()
        check_or_migrate_reports_table(db)
        all_cases = db.execute('SELECT * FROM cases ORDER BY created_at DESC').fetchall()

        filter_case_id = request.args.get('filter_case_id', '').strip()
        filter_report_id = request.args.get('filter_report_id', '').strip()
        filter_date = request.args.get('filter_date', '').strip()

        query = (
            'SELECT r.*, c.case_id as case_number, c.title as case_title '
            'FROM reports r JOIN cases c ON r.case_id = c.id '
            'WHERE 1=1'
        )
        params = []

        if filter_case_id:
            query += ' AND (c.id = ? OR c.case_id = ?)'
            params.extend([filter_case_id, filter_case_id])

        if filter_report_id:
            query += ' AND (r.report_id LIKE ? OR r.report_title LIKE ?)'
            params.extend([f"%{filter_report_id}%", f"%{filter_report_id}%"])

        if filter_date:
            query += ' AND r.generated_at LIKE ?'
            params.append(f"{filter_date}%")

        query += ' ORDER BY r.generated_at DESC'
        all_reports = db.execute(query, params).fetchall()

        # Retrieve default investigator & organization from settings
        inv_setting = db.execute("SELECT value FROM settings WHERE key = 'investigator_name'").fetchone()
        org_setting = db.execute("SELECT value FROM settings WHERE key = 'organization'").fetchone()
        default_investigator = inv_setting['value'] if inv_setting else 'Lead Forensic Examiner'
        default_org = org_setting['value'] if org_setting else 'ForensiX Cyber Forensics Laboratory'

        return render_template('reports.html',
                               reports=all_reports,
                               cases=all_cases,
                               default_investigator=default_investigator,
                               default_org=default_org,
                               filter_case_id=filter_case_id,
                               filter_report_id=filter_report_id,
                               filter_date=filter_date)

    @app.route('/reports/generate', methods=['POST'])
    def generate_report_post():
        """Handle POST request to generate a professional PDF report."""
        db = get_db()
        check_or_migrate_reports_table(db)
        case_id = (request.form.get('case_id') or '').strip()
        report_title = (request.form.get('report_title') or "Digital Forensics Examination Report").strip()
        investigator_name = (request.form.get('investigator_name') or "Lead Forensic Examiner").strip()
        organization = (request.form.get('organization') or "ForensiX Cyber Forensics Laboratory").strip()
        include_gps = request.form.get('include_gps') in ('1', 'true', 'True', True)
        keywords_query = request.form.get('keywords_query', '')
        evidence_scope = (request.form.get('evidence_scope') or 'ALL').strip().upper()

        if not case_id:
            flash('Please select an investigation case to generate a report.', 'error')
            return redirect(url_for('reports'))

        case_row = db.execute('SELECT * FROM cases WHERE id = ? OR case_id = ?', (case_id, case_id)).fetchone()
        if not case_row:
            flash(f'Investigation case "{case_id}" was not found.', 'error')
            return redirect(url_for('reports'))

        # Evidence filtering
        selected_evidence_ids = None
        if evidence_scope == 'SELECTED':
            raw_selected = request.form.getlist('evidence_ids')
            if not raw_selected:
                flash('Please select at least one evidence item to include in the report.', 'error')
                return redirect(url_for('reports'))

            clean_selected = [str(x).strip() for x in raw_selected if str(x).strip()]
            if clean_selected:
                placeholders = ','.join(['?'] * len(clean_selected))
                valid_evs = db.execute(
                    f'SELECT id, evidence_id FROM evidence WHERE case_id = ? AND (evidence_id IN ({placeholders}) OR id IN ({placeholders}))',
                    [case_row['id']] + clean_selected + clean_selected
                ).fetchall()
                if not valid_evs:
                    flash('None of the selected evidence items belong to this investigation case.', 'error')
                    return redirect(url_for('reports'))
                selected_evidence_ids = [str(r['id']) for r in valid_evs]
            else:
                flash('Please select at least one evidence item to include in the report.', 'error')
                return redirect(url_for('reports'))

        try:
            report_data = fetch_case_report_data(
                db, case_id=case_row['id'],
                selected_evidence_ids=selected_evidence_ids,
                include_gps=include_gps,
                keywords_query=keywords_query
            )
            if not report_data:
                flash(f'Failed to retrieve report data for case {case_row["case_id"]}.', 'error')
                return redirect(url_for('reports'))

            # Generate unique Report ID and safe filename
            now_dt = datetime.now()
            report_id = f"RPT-{now_dt.strftime('%Y%m')}-{uuid.uuid4().hex[:4].upper()}"
            safe_case_tag = sanitize_filename(case_row['case_id']).replace(' ', '_')
            filename = f"ForensiX_Report_{safe_case_tag}_{now_dt.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:4]}.pdf"

            reports_dir = app.config['REPORTS_FOLDER']
            os.makedirs(reports_dir, exist_ok=True)
            output_path = os.path.join(reports_dir, filename)

            report_meta = {
                'report_id': report_id,
                'report_title': report_title,
                'investigator_name': investigator_name,
                'organization': organization,
                'generated_at': now_dt.strftime('%Y-%m-%d %H:%M:%S'),
                'include_gps': include_gps
            }

            pdf_gen = PDFReportGenerator()
            pdf_gen.generate_report(
                case=report_data['case'],
                evidence_list=report_data['evidence_list'],
                report_meta=report_meta,
                timeline_data=report_data['timeline_data'],
                keyword_findings=report_data['keyword_findings'],
                summary_data=report_data['summary_data'],
                output_path=output_path
            )

            file_size = os.path.getsize(output_path)
            ev_count = len(report_data['evidence_list'])
            stored_ev_ids = ','.join([e.get('evidence_id') or str(e.get('id')) for e in report_data['evidence_list']])

            record_generated_report(
                db=db,
                case_id_pk=case_row['id'],
                report_id=report_id,
                report_title=report_title,
                report_filename=filename,
                file_path=output_path,
                file_size=file_size,
                generated_by=investigator_name,
                evidence_count=ev_count,
                selected_evidence_ids=stored_ev_ids
            )

            flash(f'Forensic Report {report_id} successfully compiled and archived ({ev_count} evidence items).', 'success')
        except Exception as e:
            flash(f'Failed to generate PDF report: {str(e)}', 'error')

        return redirect(url_for('reports'))

    @app.route('/reports/download/<int:report_id>')
    def download_report(report_id):
        """Download archived report PDF."""
        db = get_db()
        r = db.execute('SELECT * FROM reports WHERE id = ?', (report_id,)).fetchone()
        if not r:
            abort(404)

        file_path = r['file_path']
        if not file_path or not os.path.exists(file_path):
            file_path = os.path.join(app.config['REPORTS_FOLDER'], r['report_filename'])

        if not os.path.exists(file_path):
            flash('The requested report PDF file could not be found on the server filesystem.', 'error')
            return redirect(url_for('reports'))

        # Security check: Ensure file resides within REPORTS_FOLDER
        real_reports_dir = os.path.realpath(app.config['REPORTS_FOLDER'])
        real_file_path = os.path.realpath(file_path)
        if not real_file_path.startswith(real_reports_dir):
            abort(403)

        return send_file(
            real_file_path,
            as_attachment=True,
            download_name=r['report_filename'],
            mimetype='application/pdf'
        )

    @app.route('/reports/view/<int:report_id>')
    def view_report_pdf(report_id):
        """View archived report PDF inline in browser."""
        db = get_db()
        r = db.execute('SELECT * FROM reports WHERE id = ?', (report_id,)).fetchone()
        if not r:
            abort(404)

        file_path = r['file_path']
        if not file_path or not os.path.exists(file_path):
            file_path = os.path.join(app.config['REPORTS_FOLDER'], r['report_filename'])

        if not os.path.exists(file_path):
            flash('The requested report PDF file could not be found on the server filesystem.', 'error')
            return redirect(url_for('reports'))

        real_reports_dir = os.path.realpath(app.config['REPORTS_FOLDER'])
        real_file_path = os.path.realpath(file_path)
        if not real_file_path.startswith(real_reports_dir):
            abort(403)

        return send_file(
            real_file_path,
            as_attachment=False,
            mimetype='application/pdf'
        )

    @app.route('/reports/delete/<int:report_id>', methods=['POST'])
    def delete_report(report_id):
        """
        Permanently delete an archived forensic report.
        Deletes the physical PDF file, records the action in audit_logs,
        and removes the report record from the database.
        """
        db = get_db()
        report = db.execute('SELECT * FROM reports WHERE id = ?', (report_id,)).fetchone()
        if not report:
            flash(f'Report #{report_id} was not found or has already been deleted.', 'error')
            return redirect(url_for('reports'))

        # Authorization check: only authorized investigators/examiners can delete reports
        auth_role = request.form.get('auth_role') or session.get('user_role', 'investigator')
        if auth_role in ('guest', 'viewer', 'unauthorized'):
            abort(403)

        inv_setting = db.execute("SELECT value FROM settings WHERE key = 'investigator_name'").fetchone()
        examiner = (
            request.form.get('examiner_name')
            or session.get('investigator_name')
            or (inv_setting['value'] if inv_setting else None)
            or report['generated_by']
            or 'Lead Forensic Examiner'
        ).strip()

        report_identifier = report['report_id'] or f"RPT-{report['id']}"
        report_title = report['report_title'] or report['report_filename']
        case_id_val = report['case_id']

        try:
            # 1. Delete physical PDF file from storage if it exists
            file_path = report['file_path']
            if not file_path or not os.path.exists(file_path):
                file_path = os.path.join(app.config['REPORTS_FOLDER'], report['report_filename'])

            if file_path and os.path.exists(file_path):
                real_reports_dir = os.path.realpath(app.config['REPORTS_FOLDER'])
                real_file_path = os.path.realpath(file_path)
                # Verify file is inside REPORTS_FOLDER
                if real_file_path.startswith(real_reports_dir):
                    try:
                        os.remove(real_file_path)
                    except OSError as err:
                        app.logger.warning(f"Could not remove PDF file {real_file_path}: {err}")

            # 2. Add an Audit Log entry (Audit records are permanently preserved)
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            audit_details = (
                f"Report ID: {report_identifier} | Title: '{report_title}' | "
                f"Examiner: {examiner} | Permanently deleted PDF report file and database index."
            )
            db.execute(
                '''
                INSERT INTO audit_logs (case_id, action, details, performed_by, timestamp)
                VALUES (?, 'REPORT_DELETED', ?, ?, ?)
                ''',
                (case_id_val, audit_details, examiner, now_str)
            )

            # 3. Delete database record from reports table
            db.execute('DELETE FROM reports WHERE id = ?', (report_id,))
            db.commit()

            flash(f'Forensic Report {report_identifier} was permanently deleted and logged in audit trail.', 'success')
        except Exception as e:
            db.rollback()
            flash(f'Failed to delete forensic report: {str(e)}', 'error')

        return redirect(url_for('reports'))

    @app.route('/reports/create-sample-case', methods=['POST'])
    def create_sample_case_report():
        """Preload a complete demonstration case with evidence files for evaluation."""
        db = get_db()
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        demo_case_id = f"CASE-{datetime.now().strftime('%Y')}-DEMO"

        # Check if case exists
        existing = db.execute('SELECT * FROM cases WHERE case_id = ?', (demo_case_id,)).fetchone()
        if not existing:
            db.execute(
                '''
                INSERT INTO cases (case_id, title, description, investigator, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    demo_case_id,
                    "Suspected Intellectual Property Exfiltration",
                    "Forensic triage and timeline reconstruction of electronic media seized during internal audit.",
                    "Lead Forensic Examiner",
                    "Open",
                    now_str,
                    now_str
                )
            )
            case_row = db.execute('SELECT * FROM cases WHERE case_id = ?', (demo_case_id,)).fetchone()
        else:
            case_row = existing

        case_pk = case_row['id']

        # Populate sample evidence from sample_evidence/
        sample_dir = os.path.join(os.path.dirname(__file__), 'sample_evidence')
        if os.path.exists(sample_dir):
            sample_files = [
                'case_brief.docx',
                'exif_with_gps.jpg',
                'suspicious_invoice.pdf',
                'access_log.log',
                'credentials.csv'
            ]
            upload_dir = app.config['UPLOAD_FOLDER']
            os.makedirs(upload_dir, exist_ok=True)

            for i, sf_name in enumerate(sample_files, start=1):
                src_path = os.path.join(sample_dir, sf_name)
                if not os.path.exists(src_path):
                    continue
                ev_code = f"EVD-{demo_case_id[-4:]}-{i:03d}"

                # Check if evidence already exists in this case
                ev_existing = db.execute('SELECT * FROM evidence WHERE case_id = ? AND filename = ?', (case_pk, sf_name)).fetchone()
                if ev_existing:
                    continue

                dest_path = os.path.join(upload_dir, f"{demo_case_id}_{sf_name}")
                shutil.copy2(src_path, dest_path)
                f_size = os.path.getsize(dest_path)
                ext = sf_name.rsplit('.', 1)[-1].lower()

                db.execute(
                    '''
                    INSERT INTO evidence (evidence_id, case_id, filename, original_path, stored_path, description, source, acquisition_method, file_size, file_type, added_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        ev_code,
                        case_pk,
                        sf_name,
                        f"/evidence_intake/{sf_name}",
                        dest_path,
                        f"Sample evidence recovered during triage ({ext.upper()})",
                        "Corporate Workstation Seizure",
                        "Direct Bit-Stream Acquisition",
                        f_size,
                        ext.upper(),
                        now_str
                    )
                )

                ev_new = db.execute('SELECT * FROM evidence WHERE case_id = ? AND evidence_id = ?', (case_pk, ev_code)).fetchone()
                if ev_new:
                    # Compute & store hash
                    with open(dest_path, 'rb') as f:
                        hashes = compute_hashes(f)
                    db.execute(
                        '''
                        INSERT INTO hash_records (evidence_id, md5, sha1, sha256, computed_at, verification_status)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ''',
                        (ev_new['id'], hashes['md5'], hashes['sha1'], hashes['sha256'], now_str, 'Verified / Match')
                    )

            db.commit()

        flash(f'Demonstration Case "{demo_case_id}" registered with evidence suite.', 'success')
        return redirect(url_for('reports'))

    @app.route('/settings')
    def settings():
        """Settings page."""
        db = get_db()
        all_settings = db.execute('SELECT * FROM settings').fetchall()
        settings_dict = {row['key']: row['value'] for row in all_settings}
        return render_template('settings.html', settings=settings_dict)

    return app


# ================================================================
# Run the application
# ================================================================
if __name__ == '__main__':
    app = create_app()
    print("\n" + "=" * 60)
    print("  Digital Forensics Toolkit v1.0.0")
    print("  Open your browser and go to: http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    app.run(debug=True, host='127.0.0.1', port=5000)
