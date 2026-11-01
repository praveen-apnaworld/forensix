"""
test_file_analyzer.py - Automated Unit & Integration Tests for File Analyzer Module

Verifies:
1. Filename sanitization and path traversal prevention.
2. Hidden file detection (Unix dotfiles).
3. Extension extraction across various naming patterns.
4. File signature inspection (JPEG, PNG, PDF, ZIP, PE executable, Plain Text, Empty, Unknown).
5. Extension vs signature mismatch detection (masquerading).
6. Magic bytes hex preview formatting.
7. Safe stream analysis and metadata aggregation.
8. Flask route integration (GET, POST multiple files, empty uploads).
9. Real sample evidence validation.
10. Regression check: ensures Hash Analyzer remains completely intact.
"""

import io
import os
import sys
import unittest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.file_analyzer import (
    sanitize_filename,
    is_hidden_file,
    get_file_extension,
    format_file_size,
    get_magic_bytes_preview,
    inspect_signature,
    check_extension_mismatch,
    analyze_file_stream,
    summarize_file_analysis,
    CATEGORIES
)
from app import create_app


class TestFileAnalyzerUnit(unittest.TestCase):
    """Unit tests for file analysis functions."""

    def test_sanitize_filename_path_traversal(self):
        """Ensure path traversal payloads are completely neutralized."""
        self.assertEqual(sanitize_filename('../../etc/passwd'), 'passwd')
        self.assertEqual(sanitize_filename('..\\..\\Windows\\System32\\cmd.exe'), 'cmd.exe')
        self.assertEqual(sanitize_filename('folder/subfolder/evidence.pdf'), 'evidence.pdf')
        self.assertEqual(sanitize_filename('/absolute/path/test.jpg'), 'test.jpg')

    def test_sanitize_filename_preserves_hidden_dot(self):
        """Ensure leading dots for hidden files are preserved without allowing traversal."""
        self.assertEqual(sanitize_filename('.hidden_log.txt'), '.hidden_log.txt')
        self.assertEqual(sanitize_filename('../../.secret_notes'), '.secret_notes')
        self.assertEqual(sanitize_filename(''), 'unnamed_file')
        self.assertEqual(sanitize_filename('.'), 'unnamed_file')
        self.assertEqual(sanitize_filename('..'), 'unnamed_file')

    def test_is_hidden_file(self):
        """Test hidden file identification based on POSIX dotfile convention."""
        self.assertTrue(is_hidden_file('.evidence.txt'))
        self.assertTrue(is_hidden_file('.bash_history'))
        self.assertTrue(is_hidden_file('path/to/.confidential'))
        self.assertFalse(is_hidden_file('regular_file.txt'))
        self.assertFalse(is_hidden_file('image.jpeg'))

    def test_get_file_extension(self):
        """Test file extension extraction under different filename formats."""
        self.assertEqual(get_file_extension('document.pdf'), 'pdf')
        self.assertEqual(get_file_extension('archive.tar.gz'), 'gz')
        self.assertEqual(get_file_extension('.hidden_evidence.txt'), 'txt')
        self.assertEqual(get_file_extension('.bashrc'), '')
        self.assertEqual(get_file_extension('Makefile'), '')
        self.assertEqual(get_file_extension('PHOTO.JPEG'), 'jpeg')

    def test_format_file_size(self):
        """Test file size formatting into human-readable units."""
        self.assertEqual(format_file_size(0), '0 Bytes')
        self.assertEqual(format_file_size(512), '512 Bytes')
        self.assertEqual(format_file_size(1024), '1.00 KB')
        self.assertEqual(format_file_size(1048576), '1.00 MB')
        self.assertEqual(format_file_size(1073741824), '1.00 GB')

    def test_get_magic_bytes_preview(self):
        """Test hex and ASCII preview generation."""
        header = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01'
        preview = get_magic_bytes_preview(header, max_len=10)
        self.assertEqual(preview['hex'], 'FF D8 FF E0 00 10 4A 46 49 46')
        self.assertEqual(preview['ascii'], '......JFIF')

        empty_preview = get_magic_bytes_preview(b'')
        self.assertIn('Empty', empty_preview['hex'])

    def test_inspect_signature_jpeg(self):
        """Identify JPEG file signature."""
        jpeg_header = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        sig = inspect_signature(jpeg_header, 'test.jpg')
        self.assertEqual(sig['category'], 'Images')
        self.assertEqual(sig['mime_type'], 'image/jpeg')
        self.assertIn('JPEG', sig['detected_format'])

    def test_inspect_signature_png(self):
        """Identify PNG file signature."""
        png_header = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
        sig = inspect_signature(png_header, 'test.png')
        self.assertEqual(sig['category'], 'Images')
        self.assertEqual(sig['mime_type'], 'image/png')
        self.assertIn('PNG', sig['detected_format'])

    def test_inspect_signature_pdf(self):
        """Identify PDF file signature."""
        pdf_header = b'%PDF-1.4\n1 0 obj\n<<>>\n'
        sig = inspect_signature(pdf_header, 'test.pdf')
        self.assertEqual(sig['category'], 'Documents')
        self.assertEqual(sig['mime_type'], 'application/pdf')
        self.assertIn('PDF', sig['detected_format'])

    def test_inspect_signature_zip(self):
        """Identify ZIP file signature."""
        zip_header = b'PK\x03\x04\x14\x00\x00\x00\x08\x00'
        sig = inspect_signature(zip_header, 'archive.zip')
        self.assertEqual(sig['category'], 'Archives')
        self.assertIn('application/zip', sig['mime_type'])

    def test_inspect_signature_windows_pe(self):
        """Identify Windows PE Executable signature (MZ header)."""
        pe_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
        sig = inspect_signature(pe_header, 'malware.exe')
        self.assertEqual(sig['category'], 'Executables')
        self.assertEqual(sig['mime_type'], 'application/x-dosexec')
        self.assertIn('Executable', sig['detected_format'])

    def test_inspect_signature_plain_text(self):
        """Identify ASCII / UTF-8 text file."""
        text_data = b'Case Report Log: Subject logged in at 14:00 UTC.\nStatus: Active.\n'
        sig = inspect_signature(text_data, 'notes.txt')
        self.assertEqual(sig['category'], 'Text files')
        self.assertEqual(sig['mime_type'], 'text/plain')

    def test_inspect_signature_empty_file(self):
        """Identify empty (0 byte) file safely."""
        sig = inspect_signature(b'', 'empty.txt')
        self.assertEqual(sig['mime_type'], 'application/x-empty')
        self.assertIn('Empty', sig['detected_format'])

    def test_inspect_signature_unknown_binary(self):
        """Identify unknown binary data without standard header."""
        unknown_data = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44] * 8)
        sig = inspect_signature(unknown_data, 'unknown.dat')
        self.assertEqual(sig['category'], 'Unknown files')
        self.assertEqual(sig['mime_type'], 'application/octet-stream')

    def test_extension_mismatch_detection(self):
        """Test detection of deliberate extension mismatches (masquerading)."""
        jpeg_header = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        sig = inspect_signature(jpeg_header, 'invoice.pdf')

        # File is JPEG but named with .pdf
        mismatch_res = check_extension_mismatch('pdf', sig)
        self.assertTrue(mismatch_res['is_mismatch'])
        self.assertIn("does not match detected format", mismatch_res['warning_message'])

        # File is JPEG and named with .jpg -> should NOT be a mismatch
        valid_res = check_extension_mismatch('jpg', sig)
        self.assertFalse(valid_res['is_mismatch'])
        self.assertIsNone(valid_res['warning_message'])

        # File is JPEG and named with .jpeg -> should NOT be a mismatch
        valid_res2 = check_extension_mismatch('jpeg', sig)
        self.assertFalse(valid_res2['is_mismatch'])

    def test_analyze_file_stream_full(self):
        """Test end-to-end stream analysis for a single file."""
        stream = io.BytesIO(b'%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF')
        res = analyze_file_stream(stream, 'sample_case.pdf', client_mtime=1700000000000)

        self.assertEqual(res['filename'], 'sample_case.pdf')
        self.assertEqual(res['extension'], 'pdf')
        self.assertEqual(res['category'], 'Documents')
        self.assertEqual(res['mime_type'], 'application/pdf')
        self.assertFalse(res['is_mismatch'])
        self.assertFalse(res['is_hidden'])
        self.assertIn('Consistent', res['forensic_assessment'])
        self.assertIn('2023', res['timestamps']['last_modified'])

    def test_summarize_file_analysis(self):
        """Test summary aggregation across multiple file records."""
        records = [
            {'category': 'Images', 'file_size_bytes': 1000, 'is_hidden': False, 'is_mismatch': False},
            {'category': 'Images', 'file_size_bytes': 2000, 'is_hidden': True, 'is_mismatch': True},
            {'category': 'Documents', 'file_size_bytes': 5000, 'is_hidden': False, 'is_mismatch': False},
            {'category': 'Text files', 'file_size_bytes': 500, 'is_hidden': False, 'is_mismatch': False},
        ]
        summary = summarize_file_analysis(records)
        self.assertEqual(summary['total_files'], 4)
        self.assertEqual(summary['total_size_bytes'], 8500)
        self.assertEqual(summary['hidden_count'], 1)
        self.assertEqual(summary['mismatch_count'], 1)
        self.assertEqual(summary['category_counts']['Images'], 2)
        self.assertEqual(summary['category_counts']['Documents'], 1)
        self.assertEqual(summary['category_counts']['Text files'], 1)
        self.assertEqual(summary['category_counts']['Executables'], 0)


class TestFileAnalyzerIntegration(unittest.TestCase):
    """Integration tests with Flask application and sample evidence files."""

    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_get_file_analyzer_page(self):
        """GET /file-analyzer should return status 200 with the upload UI."""
        response = self.client.get('/file-analyzer')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'File Analyzer', response.data)
        self.assertIn(b'Evidence File Inspection', response.data)

    def test_post_empty_upload(self):
        """POST /file-analyzer with no files should show friendly error."""
        response = self.client.post('/file-analyzer', data={}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'No files were selected', response.data)

    def test_post_single_file_analysis(self):
        """POST /file-analyzer with a valid text file."""
        data = {
            'files': (io.BytesIO(b'Forensic test log evidence\n'), 'evidence_log.txt')
        }
        response = self.client.post('/file-analyzer', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'evidence_log.txt', response.data)
        self.assertIn(b'Text files', response.data)

    def test_post_multiple_files_with_mismatch(self):
        """POST /file-analyzer with multiple files including an extension mismatch."""
        valid_pdf = (io.BytesIO(b'%PDF-1.4 test\n%%EOF'), 'doc.pdf')
        fake_pdf = (io.BytesIO(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00'), 'suspicious_invoice.pdf')
        hidden_txt = (io.BytesIO(b'Hidden credentials\n'), '.audit_secret.txt')

        data = {
            'files': [valid_pdf, fake_pdf, hidden_txt]
        }
        response = self.client.post('/file-analyzer', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)

        # Check that results rendered in table
        self.assertIn(b'doc.pdf', response.data)
        self.assertIn(b'suspicious_invoice.pdf', response.data)
        self.assertIn(b'.audit_secret.txt', response.data)
        self.assertIn(b'Mismatch Warning', response.data)
        self.assertIn(b'Hidden', response.data)

    def test_actual_sample_evidence_directory(self):
        """Verify the generated files in sample_evidence/ are parsed accurately."""
        sample_dir = os.path.join(os.path.dirname(__file__), '..', 'sample_evidence')
        self.assertTrue(os.path.exists(sample_dir))

        expected_files = [
            'valid_image.jpg',
            'valid_document.pdf',
            'valid_notes.txt',
            '.hidden_evidence.txt',
            'suspicious_invoice.pdf',
            'unknown_payload.dat'
        ]
        for fname in expected_files:
            fpath = os.path.join(sample_dir, fname)
            self.assertTrue(os.path.exists(fpath), f"Sample file missing: {fname}")

            with open(fpath, 'rb') as f:
                res = analyze_file_stream(f, fname, file_path=fpath)

            if fname == 'valid_image.jpg':
                self.assertEqual(res['category'], 'Images')
                self.assertFalse(res['is_mismatch'])
            elif fname == 'valid_document.pdf':
                self.assertEqual(res['category'], 'Documents')
                self.assertFalse(res['is_mismatch'])
            elif fname == 'valid_notes.txt':
                self.assertEqual(res['category'], 'Text files')
                self.assertFalse(res['is_mismatch'])
            elif fname == '.hidden_evidence.txt':
                self.assertTrue(res['is_hidden'])
                self.assertEqual(res['category'], 'Text files')
            elif fname == 'suspicious_invoice.pdf':
                self.assertTrue(res['is_mismatch'], "suspicious_invoice.pdf must be flagged as mismatch")
                self.assertEqual(res['category'], 'Images')
            elif fname == 'unknown_payload.dat':
                self.assertEqual(res['category'], 'Unknown files')

    def test_hash_analyzer_unbroken(self):
        """Regression check: Hash Analyzer routes and functionality remain fully intact."""
        # 1. GET /hash-analyzer
        res_get = self.client.get('/hash-analyzer')
        self.assertEqual(res_get.status_code, 200)
        self.assertIn(b'Hash Analyzer', res_get.data)

        # 2. POST /hash-analyzer compute
        data_hash = {
            'action': 'compute',
            'file': (io.BytesIO(b'forensic test file content'), 'test.txt')
        }
        res_post = self.client.post('/hash-analyzer', data=data_hash, content_type='multipart/form-data')
        self.assertEqual(res_post.status_code, 200)
        self.assertIn(b'SHA-256', res_post.data)
        self.assertIn(b'Computed Successfully', res_post.data)


if __name__ == '__main__':
    unittest.main()
