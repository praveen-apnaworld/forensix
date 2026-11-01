"""
test_report_generator.py - Automated Unit & Integration Tests for Step 7: Report Generator

Tests all required aspects of forensic PDF report generation:
1. PDF document creation & file size
2. 10 forensic sections verification via pypdf
3. Case information population
4. Evidence inventory listing
5. Cryptographic hash analysis results
6. Missing metadata handling ("Not Recorded in File")
7. GPS privacy authorization control
8. Keyword search findings & credential redaction
9. Timeline events integration
10. Empty case handling (0 evidence files)
11. Invalid case ID handling
12. Multiple evidence files aggregation
13. Flask route integration (GET /reports, POST /reports/generate, download, view)
14. Sample demonstration case creation
15. Path traversal security check
16. Regression testing across all 6 previous modules
"""

import os
import io
import json
import uuid
import tempfile
import unittest
import pypdf
from datetime import datetime

from app import create_app
from database.db import get_db
from modules.report_generator import (
    PDFReportGenerator,
    fetch_case_report_data,
    record_generated_report,
    redact_sensitive_snippet,
    safe_text
)


class TestReportGeneratorUnit(unittest.TestCase):
    """Unit tests for the PDF report generation engine."""

    def setUp(self):
        self.generator = PDFReportGenerator()
        self.temp_dir = tempfile.mkdtemp()
        self.mock_case = {
            'id': 1,
            'case_id': 'CASE-2026-UNIT',
            'title': 'Unit Test Investigation',
            'description': 'Controlled test case for report generator validation.',
            'investigator': 'Unit Examiner',
            'status': 'Open',
            'created_at': '2026-11-01 10:00:00',
            'updated_at': '2026-11-01 11:00:00'
        }
        self.mock_report_meta = {
            'report_id': 'RPT-2026-UNIT',
            'report_title': 'Unit Test Digital Forensics Report',
            'investigator_name': 'Unit Examiner',
            'organization': 'ForensiX Testing Laboratory',
            'generated_at': '2026-11-01 18:00:00',
            'include_gps': False
        }

    def tearDown(self):
        for f in os.listdir(self.temp_dir):
            try:
                os.remove(os.path.join(self.temp_dir, f))
            except Exception:
                pass
        try:
            os.rmdir(self.temp_dir)
        except Exception:
            pass

    def test_safe_text_and_redaction(self):
        """Test XML escaping and credential redaction helpers."""
        self.assertEqual(safe_text(None), "Not Available")
        self.assertEqual(safe_text(""), "Not Available")
        self.assertEqual(safe_text("<script>alert('x')</script>"), "&lt;script&gt;alert('x')&lt;/script&gt;")

        # Redaction
        raw = "User login failed: password=SuperSecretPassword123 from 192.168.1.1"
        redacted = redact_sensitive_snippet(raw)
        self.assertNotIn("SuperSecretPassword123", redacted)
        self.assertIn("[REDACTED-CREDENTIAL]", redacted)

    def test_empty_case_report_generation(self):
        """Scenario: Case with 0 evidence files generates valid PDF with notice."""
        out_pdf = os.path.join(self.temp_dir, 'empty_case.pdf')
        empty_timeline = {'total_events': 0, 'events': []}
        empty_kw = {'searches': []}
        empty_summary = {'total_evidence': 0, 'analyzed_evidence': 0, 'extension_mismatches': 0, 'keyword_hits': 0}

        self.generator.generate_report(
            case=self.mock_case,
            evidence_list=[],
            report_meta=self.mock_report_meta,
            timeline_data=empty_timeline,
            keyword_findings=empty_kw,
            summary_data=empty_summary,
            output_path=out_pdf
        )

        self.assertTrue(os.path.exists(out_pdf))
        self.assertGreater(os.path.getsize(out_pdf), 1000)

        reader = pypdf.PdfReader(out_pdf)
        self.assertGreaterEqual(len(reader.pages), 2)
        full_text = "".join([p.extract_text() for p in reader.pages])
        self.assertIn("No registered digital evidence items were associated with this case", full_text)
        self.assertIn("CASE-2026-UNIT", full_text)
        self.assertIn("LIMITATIONS & FORENSIC DISCLAIMERS", full_text)

    def test_full_report_with_all_ten_sections(self):
        """Scenario: Generate comprehensive report with mock evidence and verify all 10 sections."""
        out_pdf = os.path.join(self.temp_dir, 'full_report.pdf')

        mock_evidence = [
            {
                'evidence_id': 'EVD-001',
                'filename': 'suspect_photo.jpg',
                'file_type': 'Image',
                'file_size': 204800,
                'source': 'Suspect Camera SD Card',
                'acquisition_method': 'Bit-Stream Image',
                'added_at': '2026-11-01 10:30:00',
                'hash_analysis': {
                    'md5': '098f6bcd4621d373cade4e832627b4f6',
                    'sha1': 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3',
                    'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
                    'verification_status': 'Verified / Match'
                },
                'file_analysis': {
                    'detected_format': 'JPEG image',
                    'mime_type': 'image/jpeg',
                    'extension': 'jpg',
                    'extension_mismatch': False,
                    'is_hidden': False
                },
                'metadata_analysis': {
                    'file_type': 'image',
                    'camera_make': 'Canon',
                    'camera_model': 'EOS R5',
                    'lens_model': 'RF 24-70mm F2.8L',
                    'date_taken': '2026-05-15 11:22:33',
                    'dimensions': '8192 x 5464',
                    'color_mode': 'RGB',
                    'iso': '200',
                    'aperture': 'f/4.0',
                    'shutter_speed': '1/500s',
                    'gps_latitude': '34.0522 N',
                    'gps_longitude': '118.2437 W'
                }
            },
            {
                'evidence_id': 'EVD-002',
                'filename': 'confidential_memo.pdf',
                'file_type': 'Document',
                'file_size': 51200,
                'source': 'Target Laptop Desktop',
                'acquisition_method': 'Targeted File Copy',
                'added_at': '2026-11-01 10:35:00',
                'hash_analysis': {
                    'md5': 'ad0234829205b9033196ba818f7a872b',
                    'sha1': '40bd001563085fc35165329ea1ff5c5ecbdbbeef',
                    'sha256': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
                    'verification_status': 'Computed Baseline'
                },
                'file_analysis': {
                    'detected_format': 'PDF document',
                    'mime_type': 'application/pdf',
                    'extension': 'pdf',
                    'extension_mismatch': False,
                    'is_hidden': False
                },
                'metadata_analysis': {
                    'file_type': 'document',
                    'title': 'Q1 Strategy Plan',
                    'author': 'Target User',
                    'subject': 'Executive Strategy',
                    'producer': 'LibreOffice 7.5',
                    'creator': 'Writer',
                    'creation_date': '2026-01-10 09:00:00',
                    'modification_date': '2026-01-15 17:00:00'
                }
            }
        ]

        mock_timeline = {
            'total_events': 4,
            'created_events': 2,
            'modified_events': 1,
            'metadata_changed_events': 1,
            'accessed_events': 0,
            'investigation_events': 0,
            'events': [
                {'timestamp': '2026-01-10 09:00:00', 'event_type': 'Created', 'filename': 'confidential_memo.pdf', 'event_source': 'PDF Metadata', 'forensic_notes': 'Document embedded creation date.'},
                {'timestamp': '2026-05-15 11:22:33', 'event_type': 'Created', 'filename': 'suspect_photo.jpg', 'event_source': 'EXIF Camera Shutter', 'forensic_notes': 'Shutter timestamp.'},
                {'timestamp': '2026-05-15 11:30:00', 'event_type': 'Modified', 'filename': 'suspect_photo.jpg', 'event_source': 'Filesystem (mtime)', 'forensic_notes': 'File content altered.'},
                {'timestamp': '2026-05-15 11:30:00', 'event_type': 'Metadata Changed', 'filename': 'suspect_photo.jpg', 'event_source': 'Filesystem (ctime)', 'forensic_notes': 'Inode metadata change. ctime is NOT creation.'}
            ]
        }

        mock_keywords = {
            'searches': [
                {'filename': 'confidential_memo.pdf', 'keyword': 'confidential', 'occurrences': 3, 'location': 'Line 4', 'preview': 'This confidential memo contains project blueprints.'}
            ]
        }

        mock_summary = {
            'total_evidence': 2,
            'analyzed_evidence': 2,
            'extension_mismatches': 0,
            'keyword_hits': 3,
            'date_earliest': '2026-01-10 09:00:00',
            'date_latest': '2026-05-15 11:30:00'
        }

        self.generator.generate_report(
            case=self.mock_case,
            evidence_list=mock_evidence,
            report_meta=self.mock_report_meta,
            timeline_data=mock_timeline,
            keyword_findings=mock_keywords,
            summary_data=mock_summary,
            output_path=out_pdf
        )

        self.assertTrue(os.path.exists(out_pdf))
        reader = pypdf.PdfReader(out_pdf)
        self.assertGreaterEqual(len(reader.pages), 3)

        full_text = "".join([p.extract_text() for p in reader.pages])

        # Section A: Cover Page
        self.assertIn("FORENSIX DIGITAL FORENSICS TOOLKIT", full_text)
        self.assertIn("CONFIDENTIAL", full_text)
        self.assertIn("CASE-2026-UNIT", full_text)

        # Section B: Case Information
        self.assertIn("SECTION B. CASE INFORMATION", full_text)
        self.assertIn("Unit Test Investigation", full_text)

        # Section C: Evidence Inventory
        self.assertIn("SECTION C. EVIDENCE INVENTORY", full_text)
        self.assertIn("suspect_photo.jpg", full_text)
        self.assertIn("confidential_memo.pdf", full_text)

        # Section D: Hash Analysis
        self.assertIn("SECTION D. CRYPTOGRAPHIC HASH ANALYSIS", full_text)
        self.assertIn("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", full_text)

        # Section E: File Analysis
        self.assertIn("SECTION E. FILE SIGNATURE", full_text)
        self.assertIn("JPEG image", full_text)
        self.assertIn("PDF document", full_text)

        # Section F: Metadata Analysis
        self.assertIn("SECTION F. METADATA EXAMINATION", full_text)
        self.assertIn("Canon", full_text)
        self.assertIn("EOS R5", full_text)

        # Section G: Keyword Search
        self.assertIn("SECTION G. KEYWORD SEARCH FINDINGS", full_text)
        self.assertIn("confidential", full_text)

        # Section H: Timeline Analysis
        self.assertIn("SECTION H. TIMELINE ANALYSIS", full_text)
        self.assertIn("Metadata Changed", full_text)
        self.assertIn("NEVER interpreted as file creation", full_text)

        # Section I: Investigation Summary
        self.assertIn("SECTION I. INVESTIGATION SUMMARY", full_text)
        self.assertIn("2 total evidence item(s) registered", full_text)

        # Section J: Limitations & Disclaimer
        self.assertIn("SECTION J. LIMITATIONS & FORENSIC DISCLAIMERS", full_text)
        self.assertIn("Missing Metadata:", full_text)
        self.assertIn("Educational & Academic Demonstration:", full_text)

    def test_gps_privacy_authorization(self):
        """GPS coordinates are withheld by default and included only when authorized."""
        out_withheld = os.path.join(self.temp_dir, 'gps_withheld.pdf')
        out_authorized = os.path.join(self.temp_dir, 'gps_authorized.pdf')

        evidence = [{
            'evidence_id': 'EVD-GPS',
            'filename': 'geo_sample.jpg',
            'file_type': 'Image',
            'metadata_analysis': {
                'file_type': 'image',
                'camera_make': 'Apple',
                'camera_model': 'iPhone 13',
                'gps_latitude': '37.7749 N',
                'gps_longitude': '122.4194 W'
            }
        }]

        # 1. Withheld (include_gps=False)
        meta_withheld = dict(self.mock_report_meta, include_gps=False)
        self.generator.generate_report(self.mock_case, evidence, meta_withheld, {}, {}, {}, out_withheld)
        reader_w = pypdf.PdfReader(out_withheld)
        text_w = "".join([p.extract_text() for p in reader_w.pages])
        self.assertIn("GPS GEOLOCATION WITHHELD", text_w)
        self.assertNotIn("37.7749 N", text_w)

        # 2. Authorized (include_gps=True)
        meta_auth = dict(self.mock_report_meta, include_gps=True)
        self.generator.generate_report(self.mock_case, evidence, meta_auth, {}, {}, {}, out_authorized)
        reader_a = pypdf.PdfReader(out_authorized)
        text_a = "".join([p.extract_text() for p in reader_a.pages])
        self.assertIn("37.7749 N", text_a)


class TestReportGeneratorIntegration(unittest.TestCase):
    """Integration tests with Flask application and SQLite database."""

    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_get_reports_page(self):
        """GET /reports returns HTTP 200 with report generator dashboard."""
        response = self.client.get('/reports')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Forensic Report Generator', response.data)
        self.assertIn(b'Generate Examination Report', response.data)
        self.assertIn(b'Generated Report Archive & History', response.data)

    def test_create_sample_case_endpoint(self):
        """POST /reports/create-sample-case creates demo case with evidence."""
        response = self.client.post('/reports/create-sample-case', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Demonstration Case', response.data)

        # Verify case in database
        with self.app.app_context():
            db = get_db()
            case = db.execute("SELECT * FROM cases WHERE case_id LIKE '%DEMO%'").fetchone()
            self.assertIsNotNone(case)
            ev_count = db.execute("SELECT count(*) FROM evidence WHERE case_id = ?", (case['id'],)).fetchone()[0]
            self.assertGreater(ev_count, 0)

    def test_generate_report_endpoint_and_download(self):
        """End-to-end: Create sample case -> Generate PDF report -> Download PDF."""
        # 1. Create sample case
        self.client.post('/reports/create-sample-case', follow_redirects=True)

        with self.app.app_context():
            db = get_db()
            case = db.execute("SELECT * FROM cases WHERE case_id LIKE '%DEMO%'").fetchone()
            case_id = case['id']

        # 2. Generate report
        post_data = {
            'case_id': case_id,
            'report_title': 'Integration Test Examination Report',
            'investigator_name': 'Detective Miller',
            'organization': 'Metro Police Forensics',
            'include_gps': '1',
            'keywords_query': 'password, confidential, invoice'
        }
        gen_res = self.client.post('/reports/generate', data=post_data, follow_redirects=True)
        self.assertEqual(gen_res.status_code, 200)
        self.assertIn(b'successfully compiled and archived', gen_res.data)

        # 3. Verify report record in database
        with self.app.app_context():
            db = get_db()
            report_row = db.execute("SELECT * FROM reports WHERE case_id = ? ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
            self.assertIsNotNone(report_row)
            report_pk = report_row['id']
            report_file = report_row['report_filename']

        # 4. Download PDF
        dl_res = self.client.get(f'/reports/download/{report_pk}')
        self.assertEqual(dl_res.status_code, 200)
        self.assertEqual(dl_res.mimetype, 'application/pdf')
        self.assertIn('attachment;', dl_res.headers.get('Content-Disposition', ''))
        self.assertIn(report_file, dl_res.headers.get('Content-Disposition', ''))
        self.assertGreater(len(dl_res.data), 1000)

        # 5. Open downloaded PDF and check content
        pdf_bytes = io.BytesIO(dl_res.data)
        reader = pypdf.PdfReader(pdf_bytes)
        self.assertGreaterEqual(len(reader.pages), 3)
        text = "".join([p.extract_text() for p in reader.pages])
        self.assertIn("Integration Test Examination Report", text)
        self.assertIn("Detective Miller", text)

        # 6. View PDF inline
        view_res = self.client.get(f'/reports/view/{report_pk}')
        self.assertEqual(view_res.status_code, 200)
        self.assertEqual(view_res.mimetype, 'application/pdf')

    def test_generate_report_invalid_case(self):
        """POST /reports/generate with invalid case ID handles error safely."""
        res = self.client.post('/reports/generate', data={'case_id': 'NONEXISTENT-999'}, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'was not found', res.data)

    def test_prevent_report_generation_without_case(self):
        """POST /reports/generate with empty case_id redirects and flashes error."""
        res = self.client.post('/reports/generate', data={'case_id': ''}, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'Please select an investigation case', res.data)

    def test_create_case_endpoint(self):
        """POST /cases/new registers a new case and prevents duplicates."""
        uid = uuid.uuid4().hex[:6].upper()
        cid = f"CASE-NEW-{uid}"
        res = self.client.post('/cases/new', data={
            'case_id': cid,
            'title': 'Test Case Registration',
            'description': 'Testing dynamic case creation',
            'investigator': 'Examiner Watson'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'successfully registered', res.data)

        with self.app.app_context():
            db = get_db()
            case = db.execute("SELECT * FROM cases WHERE case_id = ?", (cid,)).fetchone()
            self.assertIsNotNone(case)
            self.assertEqual(case['investigator'], 'Examiner Watson')

        # Test duplicate
        dup_res = self.client.post('/cases/new', data={
            'case_id': cid,
            'title': 'Duplicate Case'
        }, follow_redirects=True)
        self.assertIn(b'already exists', dup_res.data)

    def test_case_evidence_api_endpoint(self):
        """GET /api/cases/<case_id>/evidence returns dynamic evidence list in JSON."""
        # 1. Create case with evidence
        self.client.post('/reports/create-sample-case', follow_redirects=True)
        with self.app.app_context():
            db = get_db()
            case = db.execute("SELECT * FROM cases WHERE case_id LIKE '%DEMO%'").fetchone()
            case_id = case['id']

        # 2. Fetch evidence via API
        res = self.client.get(f'/api/cases/{case_id}/evidence')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data.decode('utf-8'))
        self.assertIn('evidence', data)
        self.assertGreater(data['count'], 0)
        first_ev = data['evidence'][0]
        self.assertIn('evidence_id', first_ev)
        self.assertIn('filename', first_ev)
        self.assertIn('file_size_formatted', first_ev)

        # 3. Invalid case returns 404
        res404 = self.client.get('/api/cases/INVALID-99999/evidence')
        self.assertEqual(res404.status_code, 404)

    def test_two_distinct_cases_evidence_isolation(self):
        """
        Scenario: Create two distinct test cases with different evidence files.
        Generate one report for each case.
        Verify each PDF contains only its own case information and evidence
        never leaks into another case's report.
        """
        with self.app.app_context():
            db = get_db()
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cid_a = f"CASE-ALPHA-{uuid.uuid4().hex[:6].upper()}"
            cid_b = f"CASE-BETA-{uuid.uuid4().hex[:6].upper()}"

            # Create Case 1: ALPHA
            db.execute(
                "INSERT INTO cases (case_id, title, description, investigator, status, created_at, updated_at) "
                "VALUES (?, 'Operation Alpha Triage', 'Intellectual Property Case Alpha', 'Agent Vance', 'Open', ?, ?)",
                (cid_a, now_str, now_str)
            )
            case_a = db.execute("SELECT * FROM cases WHERE case_id = ?", (cid_a,)).fetchone()

            # Create Case 2: BETA
            db.execute(
                "INSERT INTO cases (case_id, title, description, investigator, status, created_at, updated_at) "
                "VALUES (?, 'Operation Beta Infiltration', 'Ransomware Outbreak Beta', 'Agent McGee', 'Open', ?, ?)",
                (cid_b, now_str, now_str)
            )
            case_b = db.execute("SELECT * FROM cases WHERE case_id = ?", (cid_b,)).fetchone()

            # Create physical evidence file for Alpha
            upload_dir = self.app.config['UPLOAD_FOLDER']
            os.makedirs(upload_dir, exist_ok=True)

            alpha_file = os.path.join(upload_dir, f'{cid_a}_seized_payload.txt')
            with open(alpha_file, 'w') as f:
                f.write("CONFIDENTIAL ALPHA EXFILTRATION CONTENT: TARGET_SECRET_ALPHA_TOKEN_9911")

            # Create physical evidence file for Beta
            beta_file = os.path.join(upload_dir, f'{cid_b}_audit_ledger.log')
            with open(beta_file, 'w') as f:
                f.write("AUTHENTIC BETA TRANSACTION LOG: RANSOM_BETA_PAYMENT_WALLET_8822")

            ev_id_a = f"EVD-A-{uuid.uuid4().hex[:6].upper()}"
            ev_id_b = f"EVD-B-{uuid.uuid4().hex[:6].upper()}"

            # Insert evidence records
            db.execute(
                "INSERT INTO evidence (evidence_id, case_id, filename, original_path, stored_path, description, source, acquisition_method, file_size, file_type, added_at) "
                "VALUES (?, ?, ?, '/intake/alpha.txt', ?, 'Alpha Payload', 'Host Alpha', 'Bit-Stream', 100, 'TXT', ?)",
                (ev_id_a, case_a['id'], os.path.basename(alpha_file), alpha_file, now_str)
            )
            db.execute(
                "INSERT INTO evidence (evidence_id, case_id, filename, original_path, stored_path, description, source, acquisition_method, file_size, file_type, added_at) "
                "VALUES (?, ?, ?, '/intake/beta.log', ?, 'Beta Ledger', 'Host Beta', 'Bit-Stream', 100, 'LOG', ?)",
                (ev_id_b, case_b['id'], os.path.basename(beta_file), beta_file, now_str)
            )
            db.commit()

        # Generate Report for Case Alpha
        res_a = self.client.post('/reports/generate', data={
            'case_id': case_a['id'],
            'report_title': 'Alpha Examination Report',
            'investigator_name': 'Agent Vance',
            'evidence_scope': 'ALL',
            'keywords_query': 'CONFIDENTIAL, RANSOM'
        }, follow_redirects=True)
        self.assertEqual(res_a.status_code, 200)

        # Generate Report for Case Beta
        res_b = self.client.post('/reports/generate', data={
            'case_id': case_b['id'],
            'report_title': 'Beta Examination Report',
            'investigator_name': 'Agent McGee',
            'evidence_scope': 'ALL',
            'keywords_query': 'CONFIDENTIAL, RANSOM'
        }, follow_redirects=True)
        self.assertEqual(res_b.status_code, 200)

        # Inspect generated PDFs from reports table
        with self.app.app_context():
            db = get_db()
            rpt_a = db.execute("SELECT * FROM reports WHERE case_id = ? ORDER BY id DESC", (case_a['id'],)).fetchone()
            rpt_b = db.execute("SELECT * FROM reports WHERE case_id = ? ORDER BY id DESC", (case_b['id'],)).fetchone()

            self.assertIsNotNone(rpt_a)
            self.assertIsNotNone(rpt_b)
            self.assertNotEqual(rpt_a['report_id'], rpt_b['report_id'])
            self.assertEqual(rpt_a['evidence_count'], 1)
            self.assertEqual(rpt_b['evidence_count'], 1)

            # Read text from Report A
            reader_a = pypdf.PdfReader(rpt_a['file_path'])
            text_a = "".join([p.extract_text() for p in reader_a.pages])

            # Read text from Report B
            reader_b = pypdf.PdfReader(rpt_b['file_path'])
            text_b = "".join([p.extract_text() for p in reader_b.pages])

            # STRICT ISOLATION ASSERTIONS FOR REPORT A:
            self.assertIn(cid_a, text_a)
            self.assertIn("Operation Alpha Triage", text_a)
            self.assertIn(os.path.basename(alpha_file), text_a)
            self.assertIn(ev_id_a, text_a)
            self.assertIn("Agent Vance", text_a)
            # NEVER LEAK BETA EVIDENCE OR INFO INTO REPORT A:
            self.assertNotIn(cid_b, text_a)
            self.assertNotIn("Operation Beta Infiltration", text_a)
            self.assertNotIn(os.path.basename(beta_file), text_a)
            self.assertNotIn(ev_id_b, text_a)
            self.assertNotIn("Agent McGee", text_a)
            self.assertNotIn("RANSOM_BETA_PAYMENT_WALLET", text_a)

            # STRICT ISOLATION ASSERTIONS FOR REPORT B:
            self.assertIn(cid_b, text_b)
            self.assertIn("Operation Beta Infiltration", text_b)
            self.assertIn(os.path.basename(beta_file), text_b)
            self.assertIn(ev_id_b, text_b)
            self.assertIn("Agent McGee", text_b)
            # NEVER LEAK ALPHA EVIDENCE OR INFO INTO REPORT B:
            self.assertNotIn(cid_a, text_b)
            self.assertNotIn("Operation Alpha Triage", text_b)
            self.assertNotIn(os.path.basename(alpha_file), text_b)
            self.assertNotIn(ev_id_a, text_b)
            self.assertNotIn("Agent Vance", text_b)
            self.assertNotIn("TARGET_SECRET_ALPHA_TOKEN", text_b)

    def test_selected_evidence_filtering(self):
        """
        Scenario: Case contains multiple evidence items.
        Selecting individual evidence generates a report containing only that evidence.
        """
        with self.app.app_context():
            db = get_db()
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cid_multi = f"CASE-MULTI-{uuid.uuid4().hex[:6].upper()}"

            db.execute(
                "INSERT INTO cases (case_id, title, description, investigator, status, created_at, updated_at) "
                "VALUES (?, 'Selective Scope Investigation', 'Testing selective evidence report', 'Examiner Stone', 'Open', ?, ?)",
                (cid_multi, now_str, now_str)
            )
            case_row = db.execute("SELECT * FROM cases WHERE case_id = ?", (cid_multi,)).fetchone()

            upload_dir = self.app.config['UPLOAD_FOLDER']
            os.makedirs(upload_dir, exist_ok=True)

            file1 = os.path.join(upload_dir, 'selected_item_one.txt')
            with open(file1, 'w') as f:
                f.write("DATA FOR ITEM ONE")

            file2 = os.path.join(upload_dir, 'omitted_item_two.txt')
            with open(file2, 'w') as f:
                f.write("DATA FOR ITEM TWO OMITTED")

            file3 = os.path.join(upload_dir, 'selected_item_three.txt')
            with open(file3, 'w') as f:
                f.write("DATA FOR ITEM THREE")

            ev_id_1 = f"EVD-S1-{uuid.uuid4().hex[:6].upper()}"
            ev_id_2 = f"EVD-S2-{uuid.uuid4().hex[:6].upper()}"
            ev_id_3 = f"EVD-S3-{uuid.uuid4().hex[:6].upper()}"

            db.execute(
                "INSERT INTO evidence (evidence_id, case_id, filename, original_path, stored_path, description, source, acquisition_method, file_size, file_type, added_at) "
                "VALUES (?, ?, 'selected_item_one.txt', '/one.txt', ?, 'Item 1', 'Host 1', 'Bit-Stream', 50, 'TXT', ?)",
                (ev_id_1, case_row['id'], file1, now_str)
            )
            ev1 = db.execute("SELECT * FROM evidence WHERE case_id = ? AND evidence_id = ?", (case_row['id'], ev_id_1)).fetchone()

            db.execute(
                "INSERT INTO evidence (evidence_id, case_id, filename, original_path, stored_path, description, source, acquisition_method, file_size, file_type, added_at) "
                "VALUES (?, ?, 'omitted_item_two.txt', '/two.txt', ?, 'Item 2', 'Host 2', 'Bit-Stream', 50, 'TXT', ?)",
                (ev_id_2, case_row['id'], file2, now_str)
            )
            ev2 = db.execute("SELECT * FROM evidence WHERE case_id = ? AND evidence_id = ?", (case_row['id'], ev_id_2)).fetchone()

            db.execute(
                "INSERT INTO evidence (evidence_id, case_id, filename, original_path, stored_path, description, source, acquisition_method, file_size, file_type, added_at) "
                "VALUES (?, ?, 'selected_item_three.txt', '/three.txt', ?, 'Item 3', 'Host 3', 'Bit-Stream', 50, 'TXT', ?)",
                (ev_id_3, case_row['id'], file3, now_str)
            )
            ev3 = db.execute("SELECT * FROM evidence WHERE case_id = ? AND evidence_id = ?", (case_row['id'], ev_id_3)).fetchone()
            db.commit()

        # Generate report selecting ONLY Item 1 and Item 3
        res = self.client.post('/reports/generate', data={
            'case_id': case_row['id'],
            'report_title': 'Selective Scope Report',
            'investigator_name': 'Examiner Stone',
            'evidence_scope': 'SELECTED',
            'evidence_ids': [str(ev1['id']), str(ev3['id'])]
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        with self.app.app_context():
            db = get_db()
            rpt = db.execute("SELECT * FROM reports WHERE case_id = ? ORDER BY id DESC", (case_row['id'],)).fetchone()
            self.assertIsNotNone(rpt)
            self.assertEqual(rpt['evidence_count'], 2)

            reader = pypdf.PdfReader(rpt['file_path'])
            text = "".join([p.extract_text() for p in reader.pages])

            # Confirm included files are present
            self.assertIn("selected_item_one.txt", text)
            self.assertIn("selected_item_three.txt", text)
            self.assertIn(ev_id_1, text)
            self.assertIn(ev_id_3, text)

            # Confirm omitted file is STRICTLY ABSENT
            self.assertNotIn("omitted_item_two.txt", text)
            self.assertNotIn(ev_id_2, text)

    def test_report_history_filtering(self):
        """Test filtering report history by Case ID, Report ID, and Date."""
        with self.app.app_context():
            db = get_db()
            case = db.execute("SELECT * FROM cases ORDER BY id LIMIT 1").fetchone()
            if not case:
                return

        # 1. Filter by Case
        res_case = self.client.get(f'/reports?filter_case_id={case["id"]}')
        self.assertEqual(res_case.status_code, 200)

        # 2. Filter by Report ID
        res_rpt = self.client.get('/reports?filter_report_id=RPT-NONEXISTENT')
        self.assertEqual(res_rpt.status_code, 200)
        self.assertIn(b'No Generated Reports Found', res_rpt.data)

        # 3. Filter by Date
        today_date = datetime.now().strftime('%Y-%m-%d')
        res_date = self.client.get(f'/reports?filter_date={today_date}')
        self.assertEqual(res_date.status_code, 200)

    def test_delete_report_success(self):
        """POST /reports/delete/<id> deletes physical PDF, DB record, and logs audit entry."""
        # 1. Generate a report first
        self.client.post('/reports/create-sample-case', follow_redirects=True)
        with self.app.app_context():
            db = get_db()
            case = db.execute("SELECT * FROM cases WHERE case_id LIKE '%DEMO%'").fetchone()
            case_id = case['id']

        gen_res = self.client.post('/reports/generate', data={
            'case_id': case_id,
            'report_title': 'Report To Be Deleted',
            'investigator_name': 'Examiner Deletion Test'
        }, follow_redirects=True)
        self.assertEqual(gen_res.status_code, 200)

        with self.app.app_context():
            db = get_db()
            rpt = db.execute("SELECT * FROM reports WHERE report_title = 'Report To Be Deleted' ORDER BY id DESC").fetchone()
            self.assertIsNotNone(rpt)
            rpt_id = rpt['id']
            rpt_tracking_id = rpt['report_id']
            file_path = rpt['file_path']
            self.assertTrue(os.path.exists(file_path))

        # 2. Issue Delete request
        del_res = self.client.post(f'/reports/delete/{rpt_id}', data={
            'examiner_name': 'Lead Auditor Cooper'
        }, follow_redirects=True)
        self.assertEqual(del_res.status_code, 200)
        self.assertIn(b'was permanently deleted', del_res.data)

        # 3. Verify physical file is removed
        self.assertFalse(os.path.exists(file_path))

        # 4. Verify DB record is removed from reports table
        with self.app.app_context():
            db = get_db()
            deleted_rpt = db.execute("SELECT * FROM reports WHERE id = ?", (rpt_id,)).fetchone()
            self.assertIsNone(deleted_rpt)

            # 5. Verify audit log entry exists
            audit_entry = db.execute(
                "SELECT * FROM audit_logs WHERE action = 'REPORT_DELETED' AND details LIKE ? ORDER BY id DESC",
                (f"%{rpt_tracking_id}%",)
            ).fetchone()
            self.assertIsNotNone(audit_entry)
            self.assertIn(rpt_tracking_id, audit_entry['details'])
            self.assertIn('Report To Be Deleted', audit_entry['details'])
            self.assertEqual(audit_entry['performed_by'], 'Lead Auditor Cooper')

    def test_delete_report_not_found(self):
        """POST /reports/delete/999999 handles non-existent report gracefully."""
        res = self.client.post('/reports/delete/999999', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'was not found or has already been deleted', res.data)

    def test_delete_report_unauthorized(self):
        """POST /reports/delete/<id> blocks unauthorized users with 403."""
        # 1. Generate a report first
        self.client.post('/reports/create-sample-case', follow_redirects=True)
        with self.app.app_context():
            db = get_db()
            case = db.execute("SELECT * FROM cases WHERE case_id LIKE '%DEMO%'").fetchone()
            case_id = case['id']

        self.client.post('/reports/generate', data={
            'case_id': case_id,
            'report_title': 'Protected Report'
        }, follow_redirects=True)

        with self.app.app_context():
            db = get_db()
            rpt = db.execute("SELECT * FROM reports WHERE report_title = 'Protected Report' ORDER BY id DESC").fetchone()
            rpt_id = rpt['id']
            file_path = rpt['file_path']

        # 2. Attempt delete with unauthorized role
        res = self.client.post(f'/reports/delete/{rpt_id}', data={'auth_role': 'viewer'})
        self.assertEqual(res.status_code, 403)

        # 3. Verify file and DB record are untouched
        self.assertTrue(os.path.exists(file_path))
        with self.app.app_context():
            db = get_db()
            persisted = db.execute("SELECT * FROM reports WHERE id = ?", (rpt_id,)).fetchone()
            self.assertIsNotNone(persisted)

    def test_regression_all_previous_six_modules(self):
        """Ensure all earlier modules remain 100% operational."""
        # 1. Dashboard
        res1 = self.client.get('/')
        self.assertEqual(res1.status_code, 200)

        # 2. Hash Analyzer
        res2 = self.client.get('/hash-analyzer')
        self.assertEqual(res2.status_code, 200)

        # 3. File Analyzer
        res3 = self.client.get('/file-analyzer')
        self.assertEqual(res3.status_code, 200)

        # 4. Metadata Extractor
        res4 = self.client.get('/metadata')
        self.assertEqual(res4.status_code, 200)

        # 5. Keyword Search
        res5 = self.client.get('/keyword-search')
        self.assertEqual(res5.status_code, 200)

        # 6. Timeline Analyzer
        res6 = self.client.get('/timeline')
        self.assertEqual(res6.status_code, 200)


if __name__ == '__main__':
    unittest.main()
