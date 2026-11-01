"""
test_metadata_extractor.py - Automated Tests for Metadata Extractor Module

Test Coverage:
1. File type & signature validation (JPG, PNG, TIFF, PDF, DOCX, empty, unsupported, mismatch).
2. Image EXIF extraction (Make, Model, Date Taken, Dimensions, Orientation, ISO, Aperture, Shutter Speed, Focal Length).
3. GPS coordinates extraction, DMS formatting, Decimal conversion, and privacy warning.
4. Missing GPS handling (ensuring GPS is marked 'Not Available' without inventing data).
5. Stripped/clean image handling (zero EXIF).
6. PNG image properties extraction.
7. PDF document metadata extraction (Title, Author, Subject, Creator, Producer, Dates, Pages).
8. Word (DOCX) metadata extraction (Title, Author, Subject, Last Modified By, Dates).
9. Corrupted and malformed file handling.
10. JSON export formatting.
11. Flask route integration (GET, POST analysis, POST JSON download).
12. Real sample evidence validation from sample_evidence/.
13. Regression check: Hash Analyzer and File Analyzer remain 100% functional.
"""

import io
import os
import sys
import json
import unittest
from PIL import Image
import piexif
from reportlab.pdfgen import canvas
import docx

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.metadata_extractor import (
    validate_file_type,
    extract_metadata,
    parse_gps_coordinates,
    sanitize_filename,
    compare_image_metadata
)
from app import create_app


class TestMetadataExtractorUnit(unittest.TestCase):
    """Unit tests for metadata extractor engine."""

    def test_sanitize_filename(self):
        """Verify path traversal prevention."""
        self.assertEqual(sanitize_filename('../../evidence.jpg'), 'evidence.jpg')
        self.assertEqual(sanitize_filename('..\\..\\secret.pdf'), 'secret.pdf')
        self.assertEqual(sanitize_filename(''), 'unnamed_evidence')

    def test_validate_file_type_supported(self):
        """Verify supported extensions and matching signatures."""
        jpg_buf = io.BytesIO(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01')
        valid, ftype, err = validate_file_type(jpg_buf, 'test.jpg')
        self.assertTrue(valid)
        self.assertEqual(ftype, 'image')
        self.assertIsNone(err)

        pdf_buf = io.BytesIO(b'%PDF-1.4\n')
        valid, ftype, err = validate_file_type(pdf_buf, 'document.pdf')
        self.assertTrue(valid)
        self.assertEqual(ftype, 'pdf')

    def test_validate_file_type_empty(self):
        """Verify empty file is rejected gracefully."""
        empty_buf = io.BytesIO(b'')
        valid, ftype, err = validate_file_type(empty_buf, 'empty.jpg')
        self.assertFalse(valid)
        self.assertIn('empty', err.lower())

    def test_validate_file_type_unsupported(self):
        """Verify unsupported extensions are rejected."""
        exe_buf = io.BytesIO(b'MZ\x90\x00')
        valid, ftype, err = validate_file_type(exe_buf, 'program.exe')
        self.assertFalse(valid)
        self.assertIn('not supported', err.lower())

    def test_validate_file_type_signature_mismatch(self):
        """Verify signature mismatch (e.g. text file named .jpg) is detected."""
        fake_jpg = io.BytesIO(b'Plain text content disguised as image.')
        valid, ftype, err = validate_file_type(fake_jpg, 'fake.jpg')
        self.assertFalse(valid)
        self.assertIn('signature does not match', err.lower())

    def test_extract_jpeg_with_exif_and_gps(self):
        """Test extraction of camera details, exposure, dates, and GPS coordinates."""
        im = Image.new('RGB', (400, 300), 'teal')
        zeroth_ifd = {
            piexif.ImageIFD.Make: 'Canon',
            piexif.ImageIFD.Model: 'EOS R5',
            piexif.ImageIFD.DateTime: '2026:10:15 14:30:00',
            piexif.ImageIFD.Orientation: 1
        }
        exif_ifd = {
            piexif.ExifIFD.DateTimeOriginal: '2026:10:15 14:30:00',
            piexif.ExifIFD.ISOSpeedRatings: 200,
            piexif.ExifIFD.FNumber: (28, 10),
            piexif.ExifIFD.ExposureTime: (1, 1000),
            piexif.ExifIFD.FocalLength: (50, 1)
        }
        gps_ifd = {
            piexif.GPSIFD.GPSLatitudeRef: 'N',
            piexif.GPSIFD.GPSLatitude: ((37, 1), (46, 1), (2980, 100)),
            piexif.GPSIFD.GPSLongitudeRef: 'W',
            piexif.GPSIFD.GPSLongitude: ((122, 1), (25, 1), (1020, 100)),
            piexif.GPSIFD.GPSAltitude: (120, 1)
        }
        exif_bytes = piexif.dump({'0th': zeroth_ifd, 'Exif': exif_ifd, 'GPS': gps_ifd})
        buf = io.BytesIO()
        im.save(buf, format='JPEG', exif=exif_bytes)

        res = extract_metadata(buf, 'canon_gps.jpg')
        self.assertTrue(res['success'])
        self.assertTrue(res['has_gps'])

        # Verify GPS conversion
        self.assertIn('37° 46\' 29.80" N', res['gps_info']['latitude_dms'])
        self.assertIn('122° 25\' 10.20" W', res['gps_info']['longitude_dms'])
        self.assertEqual(res['gps_info']['latitude_decimal'], '37.774944')
        self.assertEqual(res['gps_info']['longitude_decimal'], '-122.419500')
        self.assertIn('Sensitive Location Data', res['gps_info']['warning'])

        # Check grouped fields
        flat_props = {}
        for g in res['groups']:
            for f in g['fields']:
                flat_props[f['name']] = f['value']

        self.assertEqual(flat_props['Camera Make'], 'Canon')
        self.assertEqual(flat_props['Camera Model'], 'EOS R5')
        self.assertEqual(flat_props['ISO Speed'], '200')
        self.assertEqual(flat_props['Aperture (F-Number)'], 'f/2.8')
        self.assertIn('1/1000', flat_props['Shutter Speed (ExposureTime)'])
        self.assertEqual(flat_props['Focal Length'], '50.0 mm')
        self.assertEqual(flat_props['Image Width'], '400 pixels')
        self.assertEqual(flat_props['Image Height'], '300 pixels')

    def test_extract_jpeg_missing_gps(self):
        """Test image with camera EXIF but missing GPS data (never invent coordinates)."""
        im = Image.new('RGB', (100, 100), 'red')
        zeroth = {piexif.ImageIFD.Make: 'Sony', piexif.ImageIFD.Model: 'Alpha 7'}
        exif_bytes = piexif.dump({'0th': zeroth})
        buf = io.BytesIO()
        im.save(buf, format='JPEG', exif=exif_bytes)

        res = extract_metadata(buf, 'sony_no_gps.jpg')
        self.assertTrue(res['success'])
        self.assertFalse(res['has_gps'])
        self.assertEqual(res['gps_info']['latitude_dms'], 'Not Available')
        self.assertEqual(res['gps_info']['latitude_decimal'], 'Not Available')
        self.assertIsNone(res['gps_info']['copyable_coordinates'])

    def test_extract_jpeg_stripped_no_exif(self):
        """Test clean JPEG image with zero EXIF tags."""
        im = Image.new('RGB', (150, 80), 'black')
        buf = io.BytesIO()
        im.save(buf, format='JPEG')

        res = extract_metadata(buf, 'clean.jpg')
        self.assertTrue(res['success'])
        self.assertFalse(res['has_gps'])

        flat_props = {f['name']: f['value'] for g in res['groups'] for f in g['fields']}
        self.assertEqual(flat_props['Image Width'], '150 pixels')
        self.assertEqual(flat_props['Image Height'], '80 pixels')
        self.assertEqual(flat_props['Camera Make'], 'Not Available')
        self.assertEqual(flat_props['Camera Model'], 'Not Available')
        self.assertEqual(flat_props['ISO Speed'], 'Not Available')

    def test_extract_png_metadata(self):
        """Test PNG properties extraction."""
        im = Image.new('RGBA', (250, 120), (10, 20, 30, 200))
        buf = io.BytesIO()
        im.save(buf, format='PNG')

        res = extract_metadata(buf, 'graphic.png')
        self.assertTrue(res['success'])
        self.assertEqual(res['detected_type'], 'image')

        flat_props = {f['name']: f['value'] for g in res['groups'] for f in g['fields']}
        self.assertEqual(flat_props['Image Width'], '250 pixels')
        self.assertEqual(flat_props['Image Height'], '120 pixels')
        self.assertEqual(flat_props['Image Format'], 'PNG')
        self.assertEqual(flat_props['Color Mode'], 'RGBA')

    def test_extract_pdf_metadata(self):
        """Test PDF document properties extraction."""
        buf = io.BytesIO()
        c = canvas.Canvas(buf)
        c.setTitle('Financial Audit Report')
        c.setAuthor('Auditor Jane Doe')
        c.setSubject('2026 Q3 Compliance')
        c.setCreator('Forensic Canvas Engine')
        c.drawString(100, 700, 'Confidential financial audit.')
        c.save()

        res = extract_metadata(buf, 'audit.pdf')
        self.assertTrue(res['success'])
        self.assertEqual(res['detected_type'], 'pdf')

        flat_props = {f['name']: f['value'] for g in res['groups'] for f in g['fields']}
        self.assertEqual(flat_props['Document Title'], 'Financial Audit Report')
        self.assertEqual(flat_props['Document Author'], 'Auditor Jane Doe')
        self.assertEqual(flat_props['Subject / Topic'], '2026 Q3 Compliance')
        self.assertEqual(flat_props['Total Page Count'], '1 pages')
        self.assertEqual(flat_props['Encryption Status'], 'Unencrypted (Standard)')

    def test_extract_docx_metadata(self):
        """Test Word document core properties extraction."""
        doc = docx.Document()
        doc.add_heading('Witness Statement', 0)
        props = doc.core_properties
        props.title = 'Statement of Subject'
        props.author = 'Detective Miller'
        props.subject = 'Internal Incident #902'
        props.last_modified_by = 'Sergeant Baker'

        buf = io.BytesIO()
        doc.save(buf)

        res = extract_metadata(buf, 'statement.docx')
        self.assertTrue(res['success'])
        self.assertEqual(res['detected_type'], 'docx')

        flat_props = {f['name']: f['value'] for g in res['groups'] for f in g['fields']}
        self.assertEqual(flat_props['Document Title'], 'Statement of Subject')
        self.assertEqual(flat_props['Document Author'], 'Detective Miller')
        self.assertEqual(flat_props['Subject / Topic'], 'Internal Incident #902')
        self.assertEqual(flat_props['Last Modified By'], 'Sergeant Baker')

    def test_extract_corrupted_image(self):
        """Verify that malformed/corrupted files fail gracefully with error messages."""
        corrupt_buf = io.BytesIO(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01CORRUPTED_TRUNCATED_BYTES')
        res = extract_metadata(corrupt_buf, 'corrupt.jpg')
        self.assertFalse(res['success'])
        self.assertEqual(res['error_type'], 'corrupted_file')
        self.assertIn('Corrupted or invalid image data', res['error'])

    def test_export_json_validity(self):
        """Verify export_json is valid parsable JSON."""
        im = Image.new('RGB', (50, 50))
        buf = io.BytesIO()
        im.save(buf, format='JPEG')

        res = extract_metadata(buf, 'test.jpg')
        parsed = json.loads(res['export_json'])
        self.assertEqual(parsed['file_name'], 'test.jpg')
        self.assertIn('properties', parsed)

    def test_jpeg_with_camera_make_and_model(self):
        """Task 12: Test a JPEG containing camera Make and Model EXIF tags."""
        im = Image.new('RGB', (200, 200), 'navy')
        zeroth = {
            piexif.ImageIFD.Make: 'Fujifilm',
            piexif.ImageIFD.Model: 'X-T5'
        }
        exif_bytes = piexif.dump({'0th': zeroth})
        buf = io.BytesIO()
        im.save(buf, format='JPEG', exif=exif_bytes)

        res = extract_metadata(buf, 'fujifilm.jpg')
        self.assertTrue(res['success'])

        flat_props = {f['name']: f['value'] for g in res['groups'] for f in g['fields']}
        self.assertEqual(flat_props['Camera Make'], 'Fujifilm')
        self.assertEqual(flat_props['Camera Model'], 'X-T5')
        self.assertEqual(flat_props['GPS Latitude (Decimal)'], 'Not Available')

        # Check raw tags debug list
        raw_names = [t['name'] for t in res['raw_tags_list']]
        self.assertIn('Make', raw_names)
        self.assertIn('Model', raw_names)

    def test_jpeg_without_exif_metadata(self):
        """Task 12: Test a JPEG without EXIF metadata (verifies no fake camera info is generated)."""
        im = Image.new('RGB', (100, 100), 'gray')
        buf = io.BytesIO()
        im.save(buf, format='JPEG')  # Save clean without EXIF

        res = extract_metadata(buf, 'clean_no_exif.jpg')
        self.assertTrue(res['success'])
        self.assertEqual(res['exif_status'], 'NOT_PRESENT')

        flat_props = {f['name']: f['value'] for g in res['groups'] for f in g['fields']}
        self.assertEqual(flat_props['Camera Make'], 'Not Available')
        self.assertEqual(flat_props['Camera Model'], 'Not Available')
        self.assertEqual(flat_props['ISO Speed'], 'Not Available')
        self.assertEqual(flat_props['Aperture (F-Number)'], 'Not Available')
        self.assertEqual(flat_props['Shutter Speed (ExposureTime)'], 'Not Available')
        self.assertEqual(flat_props['GPS Latitude (Decimal)'], 'Not Available')

        # Verify raw tags list is empty
        self.assertEqual(len(res['raw_tags_list']), 0)
        self.assertIn('No EXIF metadata block found', res['exif_message'])

    def test_jpeg_with_partial_exif_metadata(self):
        """Task 12: Test a JPEG with partial EXIF metadata (e.g. only ISO and FocalLength, no Make/Model)."""
        im = Image.new('RGB', (120, 120), 'olive')
        exif_ifd = {
            piexif.ExifIFD.ISOSpeedRatings: 800,
            piexif.ExifIFD.FocalLength: (35, 1)
        }
        exif_bytes = piexif.dump({'Exif': exif_ifd})
        buf = io.BytesIO()
        im.save(buf, format='JPEG', exif=exif_bytes)

        res = extract_metadata(buf, 'partial_exif.jpg')
        self.assertTrue(res['success'])
        self.assertEqual(res['exif_status'], 'PRESENT_PARTIAL')

        flat_props = {f['name']: f['value'] for g in res['groups'] for f in g['fields']}
        # Partial tags present:
        self.assertEqual(flat_props['ISO Speed'], '800')
        self.assertEqual(flat_props['Focal Length'], '35.0 mm')
        # Absent tags must remain 'Not Available' (no guessing):
        self.assertEqual(flat_props['Camera Make'], 'Not Available')
        self.assertEqual(flat_props['Camera Model'], 'Not Available')
        self.assertEqual(flat_props['Lens Manufacturer'], 'Not Available')
        self.assertFalse(res['has_gps'])
        self.assertEqual(flat_props['GPS Latitude (Decimal)'], 'Not Available')

    def test_three_metadata_statuses_and_summary_stats(self):
        """Test the 3 metadata statuses (present, not_recorded, error) and summary metrics."""
        im = Image.new('RGB', (100, 100), 'purple')
        zeroth = {piexif.ImageIFD.Make: 'Nikon'}
        exif_bytes = piexif.dump({'0th': zeroth})
        buf = io.BytesIO()
        im.save(buf, format='JPEG', exif=exif_bytes)

        res = extract_metadata(buf, 'nikon_test.jpg')
        self.assertTrue(res['success'])
        stats = res['stats']

        # Verify summary stats keys exist
        self.assertIn('total_fields', stats)
        self.assertIn('available_fields', stats)
        self.assertIn('not_recorded_fields', stats)
        self.assertIn('extraction_errors', stats)
        self.assertIn('available_pct', stats)

        # Extraction errors should be 0 for standard file
        self.assertEqual(stats['extraction_errors'], 0)
        # Sum should match
        self.assertEqual(stats['total_fields'], stats['available_fields'] + stats['not_recorded_fields'] + stats['extraction_errors'])

        # Verify 3 statuses across fields
        core_group = next(g for g in res['groups'] if g['title'] == 'Core Image Properties')
        self.assertEqual(core_group['badge'], 'Mandatory Container Properties')
        width_field = next(f for f in core_group['fields'] if f['name'] == 'Image Width')
        self.assertTrue(width_field['is_mandatory'])
        self.assertEqual(width_field['status'], 'present')
        self.assertEqual(width_field['status_label'], 'Present')

        cam_group = next(g for g in res['groups'] if g['title'] == 'Camera Details')
        self.assertEqual(cam_group['badge'], 'Optional EXIF Metadata')
        make_field = next(f for f in cam_group['fields'] if f['name'] == 'Camera Make')
        self.assertEqual(make_field['status'], 'present')
        self.assertEqual(make_field['value'], 'Nikon')

        model_field = next(f for f in cam_group['fields'] if f['name'] == 'Camera Model')
        self.assertEqual(model_field['status'], 'not_recorded')
        self.assertEqual(model_field['status_label'], 'Not Recorded in File')
        self.assertEqual(model_field['value'], 'Not Available')
        self.assertFalse(model_field['is_mandatory'])

    def test_scenario_1_original_camera_photo_status(self):
        """Scenario 1: Original camera photo with Make & Model -> 'Camera Details Available'."""
        im = Image.new('RGB', (320, 240), 'blue')
        zeroth = {
            piexif.ImageIFD.Make: 'Sony',
            piexif.ImageIFD.Model: 'ILCE-7M4'
        }
        exif_bytes = piexif.dump({'0th': zeroth})
        buf = io.BytesIO()
        im.save(buf, format='JPEG', exif=exif_bytes)

        res = extract_metadata(buf, 'original_camera.jpg')
        self.assertTrue(res['success'])
        self.assertEqual(res['camera_status'], 'Camera Details Available')
        self.assertEqual(res['exif_status_label'], 'Camera Details Available')
        self.assertEqual(res['exif_status'], 'PRESENT_FULL')
        self.assertIn('Camera hardware details recovered', res['exif_message'])

    def test_scenario_2_renamed_photo_identical_sha256(self):
        """Scenario 2: Renamed photo -> identical SHA-256 and EXIF, rename detection message."""
        im = Image.new('RGB', (200, 150), 'green')
        zeroth = {piexif.ImageIFD.Make: 'Canon', piexif.ImageIFD.Model: 'EOS R6'}
        exif_bytes = piexif.dump({'0th': zeroth})
        buf = io.BytesIO()
        im.save(buf, format='JPEG', exif=exif_bytes)
        img_bytes = buf.getvalue()

        file1 = io.BytesIO(img_bytes)
        file2 = io.BytesIO(img_bytes)

        comp = compare_image_metadata(file1, 'IMG_0042.jpg', file2, 'suspect_evidence_renamed.jpg')
        self.assertTrue(comp['success'])
        self.assertTrue(comp['hashes_match'])
        self.assertTrue(comp['identical_content'])
        self.assertEqual(comp['match_title'], 'Identical Content Detected – Filename or file path may differ.')
        self.assertIn('renaming a file only alters its directory entry in the filesystem', comp['rename_explanation'])
        self.assertIn('must not claim that a file was renamed solely from matching hashes', comp['forensic_disclaimer'])
        self.assertGreater(comp['stats']['identical_count'], 0)
        self.assertEqual(comp['stats']['different_count'], 0)

    def test_scenario_3_modified_photo_different_sha256(self):
        """Scenario 3: Same photo with modified content -> different SHA-256 and differing fields."""
        im1 = Image.new('RGB', (200, 200), 'white')
        im2 = Image.new('RGB', (200, 200), 'black')  # Modified pixel content
        zeroth = {piexif.ImageIFD.Make: 'Nikon', piexif.ImageIFD.Model: 'Z7'}
        exif_bytes = piexif.dump({'0th': zeroth})

        buf1 = io.BytesIO()
        im1.save(buf1, format='JPEG', exif=exif_bytes)

        buf2 = io.BytesIO()
        im2.save(buf2, format='JPEG', exif=exif_bytes)

        comp = compare_image_metadata(buf1, 'original.jpg', buf2, 'modified.jpg')
        self.assertTrue(comp['success'])
        self.assertFalse(comp['hashes_match'])
        self.assertFalse(comp['identical_content'])
        self.assertEqual(comp['match_title'], 'Different File Content – Cryptographic hashes do not match.')
        self.assertNotEqual(comp['file1']['sha256'], comp['file2']['sha256'])

    def test_scenario_4_image_without_exif_status(self):
        """Scenario 4: Image without EXIF -> 'No EXIF Metadata Found'."""
        im = Image.new('RGB', (100, 100), 'cyan')
        buf = io.BytesIO()
        im.save(buf, format='JPEG')  # Zero EXIF

        res = extract_metadata(buf, 'clean.jpg')
        self.assertTrue(res['success'])
        self.assertEqual(res['camera_status'], 'No EXIF Metadata Found')
        self.assertEqual(res['exif_status_label'], 'No EXIF Metadata Found')
        self.assertEqual(res['exif_status'], 'NOT_PRESENT')

    def test_scenario_5_partial_and_general_exif_status(self):
        """Scenario 5: Partial EXIF vs General EXIF status."""
        # 5a. Partial: Only Make is present
        im_make = Image.new('RGB', (80, 80), 'yellow')
        buf_make = io.BytesIO()
        im_make.save(buf_make, format='JPEG', exif=piexif.dump({'0th': {piexif.ImageIFD.Make: 'Olympus'}}))
        res_make = extract_metadata(buf_make, 'olympus_no_model.jpg')
        self.assertEqual(res_make['camera_status'], 'Partial Camera Metadata')
        self.assertEqual(res_make['exif_status'], 'PRESENT_PARTIAL')

        # 5b. Partial: Optics tags present without Make or Model
        im_optics = Image.new('RGB', (80, 80), 'orange')
        buf_optics = io.BytesIO()
        im_optics.save(buf_optics, format='JPEG', exif=piexif.dump({'Exif': {piexif.ExifIFD.ISOSpeedRatings: 400}}))
        res_optics = extract_metadata(buf_optics, 'optics_only.jpg')
        self.assertEqual(res_optics['camera_status'], 'Partial Camera Metadata')
        self.assertEqual(res_optics['exif_status'], 'PRESENT_PARTIAL')

        # 5c. General EXIF: Software/Orientation present without camera hardware or optics
        im_gen = Image.new('RGB', (80, 80), 'gray')
        buf_gen = io.BytesIO()
        im_gen.save(buf_gen, format='JPEG', exif=piexif.dump({'0th': {
            piexif.ImageIFD.Software: 'Adobe Photoshop 2026',
            piexif.ImageIFD.Orientation: 1
        }}))
        res_gen = extract_metadata(buf_gen, 'photoshop_export.jpg')
        self.assertEqual(res_gen['camera_status'], 'General EXIF Metadata Available')
        self.assertEqual(res_gen['exif_status_label'], 'General EXIF Metadata Available')
        self.assertEqual(res_gen['exif_status'], 'GENERAL_EXIF')

    def test_compare_image_metadata_missing_fields_separated(self):
        """Verify comparison engine separates missing fields (file1 only, file2 only, both missing)."""
        # File A with Make and ISO
        im_a = Image.new('RGB', (100, 100), 'red')
        buf_a = io.BytesIO()
        im_a.save(buf_a, format='JPEG', exif=piexif.dump({
            '0th': {piexif.ImageIFD.Make: 'Leica'},
            'Exif': {piexif.ExifIFD.ISOSpeedRatings: 100}
        }))

        # File B with Make only
        im_b = Image.new('RGB', (100, 100), 'red')
        buf_b = io.BytesIO()
        im_b.save(buf_b, format='JPEG', exif=piexif.dump({
            '0th': {piexif.ImageIFD.Make: 'Leica'}
        }))

        comp = compare_image_metadata(buf_a, 'leica_a.jpg', buf_b, 'leica_b.jpg')
        self.assertTrue(comp['success'])
        missing = comp['missing_fields']
        self.assertGreater(len(missing), 0)

        # ISO should be in missing categorized as file1_only
        iso_missing = next((m for m in missing if m['name'] == 'ISO Speed'), None)
        self.assertIsNotNone(iso_missing)
        self.assertEqual(iso_missing['missing_type'], 'file1_only')
        self.assertIn('Recorded in leica_a.jpg only', iso_missing['state_label'])


class TestMetadataExtractorIntegration(unittest.TestCase):
    """Integration tests with Flask application and sample evidence suite."""

    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_get_metadata_page(self):
        """GET /metadata should return HTTP 200 with extraction form."""
        response = self.client.get('/metadata')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Metadata Extractor', response.data)
        self.assertIn(b'Extract Metadata', response.data)

    def test_post_empty_file_upload(self):
        """POST /metadata without a file should show friendly error message."""
        response = self.client.post('/metadata', data={}, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'No file was selected', response.data)

    def test_post_image_with_gps(self):
        """POST /metadata with EXIF and GPS image."""
        sample_path = os.path.join(os.path.dirname(__file__), '..', 'sample_evidence', 'exif_with_gps.jpg')
        self.assertTrue(os.path.exists(sample_path))

        with open(sample_path, 'rb') as f:
            data = {'file': (f, 'exif_with_gps.jpg')}
            response = self.client.post('/metadata', data=data, content_type='multipart/form-data')

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Sony', response.data)
        self.assertIn(b'ILCE-7M4', response.data)
        self.assertIn(b'Geographical Location Telemetry Detected', response.data)
        self.assertIn(b'37.774944', response.data)

    def test_post_json_export_download(self):
        """POST /metadata/export-json should return downloadable JSON attachment."""
        data = {
            'filename': 'evidence_test.jpg',
            'export_data': json.dumps({'sample': 'metadata_content'})
        }
        response = self.client.post('/metadata/export-json', data=data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/json')
        self.assertIn('attachment; filename="evidence_test_metadata.json"', response.headers.get('Content-Disposition', ''))
        self.assertIn(b'metadata_content', response.data)

    def test_sample_evidence_files_extraction(self):
        """Verify all files in sample_evidence/ parse with expected properties."""
        sample_dir = os.path.join(os.path.dirname(__file__), '..', 'sample_evidence')

        # 1. exif_with_gps.jpg
        with open(os.path.join(sample_dir, 'exif_with_gps.jpg'), 'rb') as f:
            res = extract_metadata(f, 'exif_with_gps.jpg')
            self.assertTrue(res['success'])
            self.assertTrue(res['has_gps'])

        # 2. exif_no_gps.jpg
        with open(os.path.join(sample_dir, 'exif_no_gps.jpg'), 'rb') as f:
            res = extract_metadata(f, 'exif_no_gps.jpg')
            self.assertTrue(res['success'])
            self.assertFalse(res['has_gps'])

        # 3. no_exif_image.jpg
        with open(os.path.join(sample_dir, 'no_exif_image.jpg'), 'rb') as f:
            res = extract_metadata(f, 'no_exif_image.jpg')
            self.assertTrue(res['success'])
            self.assertFalse(res['has_gps'])

        # 4. evidence_chart.png
        with open(os.path.join(sample_dir, 'evidence_chart.png'), 'rb') as f:
            res = extract_metadata(f, 'evidence_chart.png')
            self.assertTrue(res['success'])

        # 5. investigation_report.pdf
        with open(os.path.join(sample_dir, 'investigation_report.pdf'), 'rb') as f:
            res = extract_metadata(f, 'investigation_report.pdf')
            self.assertTrue(res['success'])
            self.assertEqual(res['detected_type'], 'pdf')

        # 6. case_brief.docx
        with open(os.path.join(sample_dir, 'case_brief.docx'), 'rb') as f:
            res = extract_metadata(f, 'case_brief.docx')
            self.assertTrue(res['success'])
            self.assertEqual(res['detected_type'], 'docx')

        # 7. corrupted_image.jpg
        with open(os.path.join(sample_dir, 'corrupted_image.jpg'), 'rb') as f:
            res = extract_metadata(f, 'corrupted_image.jpg')
            self.assertFalse(res['success'])

    def test_get_metadata_compare_tab(self):
        """GET /metadata?tab=compare should return comparison view."""
        response = self.client.get('/metadata?tab=compare')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Compare Two Images', response.data)
        self.assertIn(b'Evidence Image A', response.data)
        self.assertIn(b'Evidence Image B', response.data)

    def test_post_compare_identical_files(self):
        """POST /metadata with action=compare and identical files should display rename detection banner."""
        sample_path = os.path.join(os.path.dirname(__file__), '..', 'sample_evidence', 'exif_with_gps.jpg')
        with open(sample_path, 'rb') as f1, open(sample_path, 'rb') as f2:
            data = {
                'action': 'compare',
                'file1': (f1, 'original_photo.jpg'),
                'file2': (f2, 'renamed_copy.jpg')
            }
            response = self.client.post('/metadata', data=data, content_type='multipart/form-data')

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Identical Content Detected', response.data)
        self.assertIn(b'Filename or file path may differ.', response.data)
        self.assertIn(b'Identical Metadata Fields', response.data)

    def test_post_compare_different_files(self):
        """POST /metadata with action=compare and different files should display differing banner."""
        sample1 = os.path.join(os.path.dirname(__file__), '..', 'sample_evidence', 'exif_with_gps.jpg')
        sample2 = os.path.join(os.path.dirname(__file__), '..', 'sample_evidence', 'exif_no_gps.jpg')
        with open(sample1, 'rb') as f1, open(sample2, 'rb') as f2:
            data = {
                'action': 'compare',
                'file1': (f1, 'photo1.jpg'),
                'file2': (f2, 'photo2.jpg')
            }
            response = self.client.post('/metadata', data=data, content_type='multipart/form-data')

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Different File Content', response.data)
        self.assertIn(b'Cryptographic & File Integrity Comparison', response.data)

    def test_post_single_metadata_includes_sha256_and_camera_status(self):
        """POST /metadata single file analysis includes SHA-256 and accurate camera status."""
        sample_path = os.path.join(os.path.dirname(__file__), '..', 'sample_evidence', 'exif_with_gps.jpg')
        with open(sample_path, 'rb') as f:
            data = {'file': (f, 'exif_with_gps.jpg')}
            response = self.client.post('/metadata', data=data, content_type='multipart/form-data')

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'SHA-256 Hash', response.data)
        self.assertIn(b'Camera Details Available', response.data)

    def test_regression_hash_and_file_analyzers(self):
        """Ensure Hash Analyzer and File Analyzer remain 100% functional."""
        # Check Hash Analyzer GET & POST
        res_hash_get = self.client.get('/hash-analyzer')
        self.assertEqual(res_hash_get.status_code, 200)

        res_hash_post = self.client.post('/hash-analyzer', data={
            'action': 'compute',
            'file': (io.BytesIO(b'forensic test string'), 'test.txt')
        }, content_type='multipart/form-data')
        self.assertEqual(res_hash_post.status_code, 200)
        self.assertIn(b'SHA-256', res_hash_post.data)

        # Check File Analyzer GET & POST
        res_file_get = self.client.get('/file-analyzer')
        self.assertEqual(res_file_get.status_code, 200)

        res_file_post = self.client.post('/file-analyzer', data={
            'files': [(io.BytesIO(b'Test note content'), 'note.txt')]
        }, content_type='multipart/form-data')
        self.assertEqual(res_file_post.status_code, 200)
        self.assertIn(b'note.txt', res_file_post.data)


if __name__ == '__main__':
    unittest.main()
