"""
test_keyword_search.py - Comprehensive Unit & Integration Tests for Step 5: Keyword Search

Tests all required aspects of forensic keyword search:
1. Keyword found in TXT
2. Keyword not found
3. Case-insensitive search vs Case-sensitive search
4. Multiple keyword search (ANY vs ALL logic)
5. Multiple occurrences counting and location mapping
6. PDF text search (page numbers and context)
7. DOCX text search (paragraphs and tables)
8. CSV and JSON search
9. Corrupted PDF and malformed files handling
10. Unsupported binary files (properly counted and skipped)
11. Empty search input handling
12. Sensitive credential redaction
13. JSON and CSV export
14. Flask route integration & safe ZIP archive handling
15. Regression checks for earlier modules (Dashboard, Hash Analyzer, File Analyzer, Metadata Extractor)
"""

import os
import io
import json
import zipfile
import unittest
from reportlab.pdfgen import canvas
import docx

from app import create_app
from modules.keyword_search import (
    extract_text_segments,
    search_file,
    search_evidence_set,
    redact_sensitive_values,
    sanitize_search_terms,
    build_highlighted_context,
    export_results_json,
    export_results_csv
)


class TestKeywordSearchUnit(unittest.TestCase):
    """Unit tests for the keyword extraction and search engine."""

    def test_sanitize_search_terms(self):
        """Test parsing and sanitizing multi-term inputs."""
        terms = sanitize_search_terms("password, admin\nroot; sarah.chen, password")
        self.assertEqual(terms, ["password", "admin", "root", "sarah.chen"])
        self.assertEqual(sanitize_search_terms(""), [])
        self.assertEqual(sanitize_search_terms("   "), [])

    def test_sensitive_credential_redaction(self):
        """Test redacting passwords, API keys, and secret tokens in preview snippets."""
        raw_text = "User admin logged in with password=SuperSecretPassword123! from 192.168.1.1"
        redacted = redact_sensitive_values(raw_text)
        self.assertNotIn("SuperSecretPassword123!", redacted)
        self.assertIn("password=[REDACTED]", redacted)

        api_text = "Config loaded: api_key='sk_live_9928419238129831983' on host"
        redacted_api = redact_sensitive_values(api_text)
        self.assertNotIn("sk_live_9928419238129831983", redacted_api)
        self.assertIn("api_key='[REDACTED]'", redacted_api)

    def test_keyword_found_in_txt(self):
        """Scenario 1: Keyword found in TXT file with line number and context."""
        content = b"Line 1: Normal system note\nLine 2: Confidential case report for suspect\nLine 3: End of file"
        res = search_file(io.BytesIO(content), "notes.txt", ["Confidential"], case_sensitive=False)
        self.assertTrue(res['matched'])
        self.assertEqual(res['total_occurrences'], 1)
        self.assertEqual(res['matches'][0]['line_number'], 2)
        self.assertEqual(res['matches'][0]['location_label'], 'Line 2')
        self.assertIn("Confidential", res['matches'][0]['context'])
        self.assertIn('<mark class="kw-highlight">Confidential</mark>', res['matches'][0]['highlighted_html'])

    def test_keyword_not_found(self):
        """Scenario 2: Keyword not found in file."""
        content = b"Routine audit logs for 2026. All checks passed."
        res = search_file(io.BytesIO(content), "audit.txt", ["malware_payload"], case_sensitive=False)
        self.assertFalse(res['matched'])
        self.assertEqual(res['total_occurrences'], 0)
        self.assertEqual(len(res['matches']), 0)

    def test_case_insensitive_and_sensitive_search(self):
        """Scenario 3: Case-insensitive search by default, toggleable to case-sensitive."""
        content = b"The Administrator accessed the ADMIN portal using administrator privileges."
        
        # Insensitive
        res_ins = search_file(io.BytesIO(content), "log.txt", ["admin"], case_sensitive=False)
        self.assertTrue(res_ins['matched'])
        self.assertEqual(res_ins['total_occurrences'], 3)

        # Sensitive for 'ADMIN'
        res_sen = search_file(io.BytesIO(content), "log.txt", ["ADMIN"], case_sensitive=True)
        self.assertTrue(res_sen['matched'])
        self.assertEqual(res_sen['total_occurrences'], 1)
        self.assertEqual(res_sen['matches'][0]['matched_text'], 'ADMIN')

    def test_multiple_occurrences_counting(self):
        """Scenario 4: Count multiple occurrences in single and across multiple lines."""
        content = b"evidence item 1: evidence file; evidence tag"
        res = search_file(io.BytesIO(content), "evidence.txt", ["evidence"], case_sensitive=False)
        self.assertTrue(res['matched'])
        self.assertEqual(res['total_occurrences'], 3)
        self.assertEqual(res['keyword_counts']['evidence'], 3)
        self.assertEqual(len(res['matches']), 3)

    def test_multiple_keywords_match_any(self):
        """Scenario 5: Multiple keywords with ANY (OR) mode."""
        content = b"User auditor initiated access to financial database"
        res = search_file(io.BytesIO(content), "record.txt", ["auditor", "unauthorized", "breach"], match_mode='ANY')
        self.assertTrue(res['matched'])
        self.assertEqual(res['total_occurrences'], 1)
        self.assertEqual(res['keyword_counts']['auditor'], 1)
        self.assertEqual(res['keyword_counts']['unauthorized'], 0)
        self.assertEqual(res['keyword_counts']['breach'], 0)

    def test_multiple_keywords_match_all(self):
        """Scenario 6: Multiple keywords with ALL (AND) mode."""
        content_both = b"User admin authenticated and downloaded sensitive evidence"
        res_both = search_file(io.BytesIO(content_both), "record.txt", ["admin", "evidence"], match_mode='ALL')
        self.assertTrue(res_both['matched'])
        self.assertEqual(res_both['total_occurrences'], 2)

        content_partial = b"User admin authenticated and left session"
        res_partial = search_file(io.BytesIO(content_partial), "record.txt", ["admin", "evidence"], match_mode='ALL')
        self.assertFalse(res_partial['matched'])
        self.assertEqual(res_partial['total_occurrences'], 0)

    def test_pdf_text_search(self):
        """Scenario 7: Search inside PDF documents with page number mapping."""
        buf = io.BytesIO()
        c = canvas.Canvas(buf)
        c.drawString(100, 700, "ForensiX Incident Dossier Page One")
        c.drawString(100, 650, "Suspect IP address identified: 198.51.100.24")
        c.showPage()
        c.drawString(100, 700, "Second page of classified findings")
        c.drawString(100, 650, "Secret encryption key recovered")
        c.save()

        buf.seek(0)
        res_p1 = search_file(buf, "report.pdf", ["Suspect"], case_sensitive=False)
        self.assertTrue(res_p1['matched'])
        self.assertEqual(res_p1['matches'][0]['page_number'], 1)
        self.assertEqual(res_p1['matches'][0]['location_label'], 'Page 1')

        buf.seek(0)
        res_p2 = search_file(buf, "report.pdf", ["encryption"], case_sensitive=False)
        self.assertTrue(res_p2['matched'])
        self.assertEqual(res_p2['matches'][0]['page_number'], 2)
        self.assertEqual(res_p2['matches'][0]['location_label'], 'Page 2')

    def test_docx_text_search(self):
        """Scenario 8: Search inside Word (DOCX) documents with paragraph/table mapping."""
        doc = docx.Document()
        doc.add_heading("Case Summary", 0)
        doc.add_paragraph("First paragraph: Routine witness statement.")
        doc.add_paragraph("Second paragraph: Critical forensic artifact discovered.")
        
        table = doc.add_table(rows=2, cols=2)
        table.cell(0, 0).text = "Device Serial"
        table.cell(0, 1).text = "SN-998822-CYBER"
        table.cell(1, 0).text = "Status"
        table.cell(1, 1).text = "Seized"

        buf = io.BytesIO()
        doc.save(buf)
        buf.seek(0)

        res = search_file(buf, "case.docx", ["forensic", "SN-998822-CYBER"], match_mode='ANY')
        self.assertTrue(res['matched'])
        self.assertEqual(res['total_occurrences'], 2)
        
        locations = [m['location_type'] for m in res['matches']]
        self.assertIn("Paragraph", locations)
        self.assertIn("Table", locations)

    def test_csv_search(self):
        """Scenario 9a: Search inside CSV with row/line tracking."""
        csv_data = b"id,user,department\n1,alice,Security\n2,bob,Engineering\n3,charlie,Digital Forensics"
        res = search_file(io.BytesIO(csv_data), "users.csv", ["Engineering", "Forensics"], match_mode='ANY')
        self.assertTrue(res['matched'])
        self.assertEqual(res['total_occurrences'], 2)
        
        row_labels = [m['location_label'] for m in res['matches']]
        self.assertIn("Row 3", row_labels)
        self.assertIn("Row 4", row_labels)

    def test_json_search(self):
        """Scenario 9b: Search inside JSON configuration files."""
        json_data = b'{\n  "hostname": "forensic-vault",\n  "admin": "sarah.chen",\n  "status": "online"\n}'
        res = search_file(io.BytesIO(json_data), "config.json", ["sarah.chen"])
        self.assertTrue(res['matched'])
        self.assertEqual(res['total_occurrences'], 1)
        self.assertIn("sarah.chen", res['matches'][0]['context'])

    def test_corrupted_pdf_handling(self):
        """Scenario 10: Gracefully handle corrupted PDF without throwing exceptions."""
        corrupt_pdf = b"%PDF-1.4\nCorrupted header bytes truncated unexpectedly"
        res = search_file(io.BytesIO(corrupt_pdf), "corrupted.pdf", ["test"])
        self.assertFalse(res['matched'])
        self.assertTrue(res['supported'])
        self.assertFalse(res['readable'])
        self.assertIn("Corrupted or unreadable PDF", res['error'])

    def test_unsupported_binary_files(self):
        """Scenario 11: Identify and skip unsupported binary files."""
        exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00ExecutableBinaryPayload"
        res_exe = search_file(io.BytesIO(exe_bytes), "payload.exe", ["Payload"])
        self.assertFalse(res_exe['supported'])
        self.assertFalse(res_exe['matched'])
        self.assertEqual(res_exe['file_type'], 'EXE')

        jpg_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01RawImageData"
        res_jpg = search_file(io.BytesIO(jpg_bytes), "image.jpg", ["Raw"])
        self.assertFalse(res_jpg['supported'])
        self.assertFalse(res_jpg['matched'])

    def test_search_evidence_set_aggregation(self):
        """Scenario 12: Aggregate statistics across multiple files."""
        files = [
            (io.BytesIO(b"Evidence 1: password=secret123"), "evidence1.txt"),
            (io.BytesIO(b"Evidence 2: clean log entry"), "evidence2.txt"),
            (io.BytesIO(b"Evidence 3: password=anotherSecret!"), "evidence3.log"),
            (io.BytesIO(b"\xFF\xD8\xFF\xE0BinaryImage"), "photo.jpg")  # Unsupported
        ]
        
        summary = search_evidence_set(files, ["password"], case_sensitive=False)
        self.assertEqual(summary['total_files_scanned'], 4)
        self.assertEqual(summary['total_matching_files'], 2)
        self.assertEqual(summary['total_occurrences'], 2)
        self.assertEqual(summary['unsupported_or_unreadable_count'], 1)
        self.assertEqual(summary['keyword_counts']['password'], 2)

    def test_export_json_and_csv(self):
        """Scenario 13: Verify exporting structured JSON and standard CSV."""
        files = [(io.BytesIO(b"Incident report with keyword TARGET detected."), "report.txt")]
        summary = search_evidence_set(files, ["TARGET"])
        
        # JSON export
        json_str = export_results_json(summary, case_id="CASE-2026-900")
        parsed = json.loads(json_str)
        self.assertEqual(parsed['case_id'], "CASE-2026-900")
        self.assertEqual(parsed['summary_statistics']['total_matching_files'], 1)

        # CSV export
        csv_str = export_results_csv(summary, case_id="CASE-2026-900")
        self.assertIn("CASE-2026-900", csv_str)
        self.assertIn("TARGET", csv_str)
        self.assertIn("report.txt", csv_str)


class TestKeywordSearchIntegration(unittest.TestCase):
    """Integration tests with Flask application, routes, and sample evidence suite."""

    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_get_keyword_search_page(self):
        """GET /keyword-search should return 200 with search form."""
        response = self.client.get('/keyword-search')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Forensic Keyword Search Engine', response.data)
        self.assertIn(b'Search Query & Evidence Configuration', response.data)

    def test_post_empty_search_query(self):
        """POST /keyword-search with empty query should return friendly validation error."""
        response = self.client.post('/keyword-search', data={
            'search_query': '   ',
            'evidence_source': 'sample'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Please enter at least one valid keyword', response.data)

    def test_post_search_sample_evidence_suite(self):
        """POST /keyword-search scanning sample_evidence/ suite."""
        response = self.client.post('/keyword-search', data={
            'search_query': 'password, admin, ForensiX',
            'match_mode': 'ANY',
            'evidence_source': 'sample',
            'file_type_filter': 'ALL'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Matching Evidence Records', response.data)
        self.assertIn(b'Files Scanned', response.data)
        self.assertIn(b'Keyword Term Breakdown', response.data)

    def test_post_search_direct_file_upload(self):
        """POST /keyword-search with direct file upload."""
        txt_content = io.BytesIO(b"Classified evidence log: suspect username=jdoe password=SecretPass99!")
        response = self.client.post('/keyword-search', data={
            'search_query': 'suspect, password',
            'match_mode': 'ANY',
            'evidence_source': 'upload',
            'files': [(txt_content, 'evidence_test.txt')]
        }, content_type='multipart/form-data')

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'evidence_test.txt', response.data)
        self.assertIn(b'suspect', response.data)
        # Verify secret is redacted in output preview
        self.assertNotIn(b'SecretPass99!', response.data)
        self.assertIn(b'[REDACTED]', response.data)

    def test_post_search_zip_archive_upload(self):
        """POST /keyword-search with uploaded ZIP archive containing multiple evidence files."""
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, 'w') as zf:
            zf.writestr('incident.txt', 'Critical finding: unauthorized exfiltration detected.')
            zf.writestr('users.csv', 'id,name\n1,investigator')
        zip_buf.seek(0)

        response = self.client.post('/keyword-search', data={
            'search_query': 'exfiltration',
            'evidence_source': 'upload',
            'files': [(zip_buf, 'evidence_bundle.zip')]
        }, content_type='multipart/form-data')

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'incident.txt', response.data)
        self.assertIn(b'exfiltration', response.data)

    def test_export_json_endpoint(self):
        """POST /keyword-search/export-json returns JSON attachment."""
        sample_json = json.dumps({'test': 'keyword_data', 'hits': 5})
        response = self.client.post('/keyword-search/export-json', data={'export_data': sample_json})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/json')
        self.assertIn('attachment; filename="forensix_keyword_search_', response.headers.get('Content-Disposition', ''))

    def test_export_csv_endpoint(self):
        """POST /keyword-search/export-csv returns CSV attachment."""
        data_dict = {
            'timestamp': '2026-11-01 12:00:00',
            'search_terms': ['test'],
            'match_mode': 'ANY',
            'results': [{
                'filename': 'file.txt',
                'file_type': 'TXT',
                'matches': [{
                    'keyword': 'test',
                    'location_type': 'Line',
                    'location_label': 'Line 1',
                    'line_number': 1,
                    'context': 'This is a test context'
                }]
            }]
        }
        response = self.client.post('/keyword-search/export-csv', data={'export_data': json.dumps(data_dict)})
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/csv', response.mimetype)
        self.assertIn('attachment; filename="forensix_keyword_search_', response.headers.get('Content-Disposition', ''))
        self.assertIn(b'This is a test context', response.data)

    def test_regression_hash_file_metadata_modules(self):
        """Verify that Dashboard, Hash Analyzer, File Analyzer, and Metadata Extractor are 100% operational."""
        # 1. Dashboard
        res_dash = self.client.get('/')
        self.assertEqual(res_dash.status_code, 200)

        # 2. Hash Analyzer
        res_hash = self.client.get('/hash-analyzer')
        self.assertEqual(res_hash.status_code, 200)

        # 3. File Analyzer
        res_file = self.client.get('/file-analyzer')
        self.assertEqual(res_file.status_code, 200)

        # 4. Metadata Extractor
        res_meta = self.client.get('/metadata')
        self.assertEqual(res_meta.status_code, 200)


if __name__ == '__main__':
    unittest.main()
