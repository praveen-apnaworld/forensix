"""
test_timeline_analyzer.py - Comprehensive Unit & Integration Tests for Step 6: Timeline Analyzer

Tests all required aspects of forensic timeline analysis:
1. Chronological sorting (asc)
2. Reverse chronological sorting (desc)
3. Missing timestamps handling
4. Multiple event types (Created, Modified, Accessed, Registered, Hash, Metadata, Keyword)
5. Date filtering (date_from, date_to)
6. Filename filtering
7. Timezone handling and precision
8. CSV and JSON export
9. Duplicate events deduplication
10. Invalid input handling
11. Flask route integration & sample evidence scan
12. Regression checks for earlier modules (Dashboard, Hash Analyzer, File Analyzer, Metadata Extractor, Keyword Search)
"""

import os
import io
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime

from app import create_app
from modules.timeline_analyzer import (
    extract_filesystem_timestamps,
    extract_embedded_document_timestamps,
    generate_timeline,
    export_timeline_json,
    export_timeline_csv,
    format_epoch_timestamp,
    get_system_timezone_info,
    get_linux_birthtime
)


class TestTimelineAnalyzerUnit(unittest.TestCase):
    """Unit tests for the timeline generation and timestamp extraction engine."""

    def test_format_epoch_timestamp(self):
        """Test timestamp epoch formatting helper."""
        ts = format_epoch_timestamp(1761984000.0)
        self.assertIsNotNone(ts)
        self.assertRegex(ts, r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')
        self.assertIsNone(format_epoch_timestamp(None))
        self.assertIsNone(format_epoch_timestamp(-100))

    def test_timezone_info_retrieval(self):
        """Test timezone telemetry retrieval."""
        tz_str = get_system_timezone_info()
        self.assertTrue(len(tz_str) > 0)
        self.assertIn("UTC", tz_str)

    def test_chronological_sorting_asc_and_desc(self):
        """Scenarios 1 & 2: Test sorting oldest to newest and newest to oldest."""
        events = [
            {'filename': 'a.txt', 'event_type': 'Modified', 'timestamp': '2026-05-10 14:00:00', 'timestamp_raw': 100},
            {'filename': 'b.txt', 'event_type': 'Created', 'timestamp': '2026-01-01 08:30:00', 'timestamp_raw': 50},
            {'filename': 'c.txt', 'event_type': 'Accessed', 'timestamp': '2026-10-20 22:15:00', 'timestamp_raw': 200}
        ]

        # Ascending: Oldest to Newest
        res_asc = generate_timeline(events, sort_order='asc')
        self.assertEqual(res_asc['total_events'], 3)
        self.assertEqual(res_asc['events'][0]['filename'], 'b.txt')
        self.assertEqual(res_asc['events'][-1]['filename'], 'c.txt')

        # Descending: Newest to Oldest
        res_desc = generate_timeline(events, sort_order='desc')
        self.assertEqual(res_desc['events'][0]['filename'], 'c.txt')
        self.assertEqual(res_desc['events'][-1]['filename'], 'b.txt')

    def test_missing_timestamps_handling(self):
        """Scenario 3: Missing timestamps should be safely skipped or handled without errors."""
        events = [
            {'filename': 'valid.txt', 'event_type': 'Modified', 'timestamp': '2026-04-12 10:00:00', 'timestamp_raw': 10},
            {'filename': 'invalid.txt', 'event_type': 'Created', 'timestamp': None, 'timestamp_raw': None},
            {'filename': 'empty.txt', 'event_type': 'Accessed', 'timestamp': '', 'timestamp_raw': 0}
        ]
        res = generate_timeline(events)
        self.assertEqual(res['total_events'], 1)
        self.assertEqual(res['events'][0]['filename'], 'valid.txt')

    def test_multiple_event_types_classification(self):
        """Scenario 4: Verify accurate classification and counting of multiple event types."""
        events = [
            {'filename': 'f1.txt', 'event_type': 'Created', 'timestamp': '2026-01-01 00:00:00'},
            {'filename': 'f1.txt', 'event_type': 'Modified', 'timestamp': '2026-01-02 00:00:00'},
            {'filename': 'f1.txt', 'event_type': 'Accessed', 'timestamp': '2026-01-03 00:00:00'},
            {'filename': 'f1.txt', 'event_type': 'Evidence Registered', 'timestamp': '2026-01-04 00:00:00'},
            {'filename': 'f1.txt', 'event_type': 'Hash Calculated', 'timestamp': '2026-01-05 00:00:00'},
            {'filename': 'f1.txt', 'event_type': 'Metadata Extracted', 'timestamp': '2026-01-06 00:00:00'},
            {'filename': 'f1.txt', 'event_type': 'Keyword Search Performed', 'timestamp': '2026-01-07 00:00:00'}
        ]
        res = generate_timeline(events)
        self.assertEqual(res['total_events'], 7)
        self.assertEqual(res['created_events'], 1)
        self.assertEqual(res['modified_events'], 1)
        self.assertEqual(res['accessed_events'], 1)
        self.assertEqual(res['investigation_events'], 4)
        self.assertEqual(res['total_files'], 1)

    def test_date_range_filtering(self):
        """Scenario 5: Filter events strictly within a date boundary."""
        events = [
            {'filename': 'jan.txt', 'event_type': 'Modified', 'timestamp': '2026-01-15 12:00:00'},
            {'filename': 'mar.txt', 'event_type': 'Modified', 'timestamp': '2026-03-20 12:00:00'},
            {'filename': 'aug.txt', 'event_type': 'Modified', 'timestamp': '2026-08-05 12:00:00'}
        ]
        # Range: Feb 1 to Apr 1
        res = generate_timeline(events, date_from='2026-02-01', date_to='2026-04-01')
        self.assertEqual(res['total_events'], 1)
        self.assertEqual(res['events'][0]['filename'], 'mar.txt')

    def test_filename_filtering(self):
        """Scenario 6: Case-insensitive substring filtering on filenames."""
        events = [
            {'filename': 'server_access_log.txt', 'event_type': 'Modified', 'timestamp': '2026-02-01 10:00:00'},
            {'filename': 'CONFIDENTIAL_REPORT.pdf', 'event_type': 'Created', 'timestamp': '2026-02-02 10:00:00'},
            {'filename': 'invoice.pdf', 'event_type': 'Accessed', 'timestamp': '2026-02-03 10:00:00'}
        ]
        res = generate_timeline(events, filename_query='report')
        self.assertEqual(res['total_events'], 1)
        self.assertEqual(res['events'][0]['filename'], 'CONFIDENTIAL_REPORT.pdf')

    def test_duplicate_events_deduplication(self):
        """Scenario 8: Exact duplicate events should be cleanly deduplicated."""
        dup = {
            'filename': 'target.txt',
            'event_type': 'Modified',
            'timestamp': '2026-03-01 12:00:00',
            'event_source': 'Filesystem Metadata'
        }
        events = [dup, dup, dup]
        res = generate_timeline(events)
        self.assertEqual(res['total_events'], 1)

    def test_invalid_input_handling(self):
        """Scenario 9: Handle empty lists and invalid date bounds safely."""
        res_empty = generate_timeline([])
        self.assertEqual(res_empty['total_events'], 0)
        self.assertEqual(res_empty['total_files'], 0)
        self.assertIsNone(res_empty['date_earliest'])

        # Non-existent file stat check
        evs = extract_filesystem_timestamps('/nonexistent/path/file.dat', 'file.dat')
        self.assertEqual(evs, [])

    def test_json_and_csv_export(self):
        """Scenario 10: Verify structured JSON and CSV exports."""
        events = [{
            'filename': 'evidence.txt',
            'event_type': 'Modified',
            'timestamp': '2026-04-01 15:30:00',
            'evidence_id': 'EVD-99',
            'case_id': 'CASE-2026-A',
            'event_source': 'Filesystem Metadata (mtime)',
            'precision': 'Second',
            'timezone_info': 'UTC+05:30',
            'forensic_notes': 'Altered by suspect.'
        }]
        timeline = generate_timeline(events)

        # JSON
        json_out = export_timeline_json(timeline, case_id='CASE-2026-A')
        parsed = json.loads(json_out)
        self.assertEqual(parsed['case_id'], 'CASE-2026-A')
        self.assertEqual(parsed['summary_statistics']['total_events'], 1)

        # CSV
        csv_out = export_timeline_csv(timeline, case_id='CASE-2026-A')
        self.assertIn('CASE-2026-A', csv_out)
        self.assertIn('EVD-99', csv_out)
        self.assertIn('evidence.txt', csv_out)
        self.assertIn('Altered by suspect.', csv_out)

    def test_linux_timestamps_mtime_ctime_atime(self):
        """Verify mtime, ctime, and atime are extracted with proper distinct event types and explanations."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"Linux timestamp test")
            temp_path = f.name
        
        try:
            events = extract_filesystem_timestamps(temp_path, os.path.basename(temp_path))
            event_types = [ev['event_type'] for ev in events]
            self.assertIn('Modified', event_types)
            self.assertIn('Metadata Changed', event_types)
            self.assertIn('Accessed', event_types)
            
            # Verify explanations
            for ev in events:
                if ev['event_type'] == 'Modified':
                    self.assertIn('Last content modification (mtime)', ev['forensic_notes'])
                elif ev['event_type'] == 'Metadata Changed':
                    self.assertIn('Inode metadata change (ctime)', ev['forensic_notes'])
                elif ev['event_type'] == 'Accessed':
                    self.assertIn('Last access time (atime)', ev['forensic_notes'])
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_ctime_never_interpreted_as_created(self):
        """Forensic rule: ctime (inode status change) must NEVER be interpreted as file creation time."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"Strict ctime check")
            temp_path = f.name

        try:
            # Force birthtime lookup to return None to simulate filesystem without creation time
            with patch('modules.timeline_analyzer.get_linux_birthtime', return_value=None):
                with patch('os.stat') as mock_stat:
                    mock_res = MagicMock()
                    mock_res.st_mtime = 1700000000.0
                    mock_res.st_ctime = 1700000100.0  # ctime is present
                    mock_res.st_atime = 1700000200.0
                    mock_res.st_size = 50
                    # Ensure st_birthtime is absent
                    del mock_res.st_birthtime
                    mock_stat.return_value = mock_res

                    events = extract_filesystem_timestamps(temp_path, 'test_ctime.txt')
                    event_types = [e['event_type'] for e in events]
                    
                    # Must NOT have 'Created' event
                    self.assertNotIn('Created', event_types)
                    # Must have 'Metadata Changed'
                    self.assertIn('Metadata Changed', event_types)
                    
                    # Verify ctime event specifies it is an inode metadata change, not creation
                    ctime_ev = next(e for e in events if e['event_type'] == 'Metadata Changed')
                    self.assertIn('NEVER interpreted as file creation time', ctime_ev['forensic_notes'])
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_unavailable_birthtime_handling(self):
        """When birthtime is unavailable, display 'Creation Time Not Available' and emit 0 Created events."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"No birthtime")
            temp_path = f.name

        try:
            with patch('modules.timeline_analyzer.get_linux_birthtime', return_value=None):
                with patch('os.stat') as mock_stat:
                    mock_res = MagicMock()
                    mock_res.st_mtime = 1700000000.0
                    mock_res.st_ctime = 1700000100.0
                    mock_res.st_atime = 1700000200.0
                    mock_res.st_size = 20
                    del mock_res.st_birthtime
                    mock_stat.return_value = mock_res

                    events = extract_filesystem_timestamps(temp_path, 'notes.txt')
                    
                    # 0 created events
                    created_events = [e for e in events if e['event_type'] == 'Created']
                    self.assertEqual(len(created_events), 0)
                    
                    # All other events must report creation_time_display == 'Creation Time Not Available'
                    for ev in events:
                        self.assertEqual(ev.get('creation_time_display'), 'Creation Time Not Available')

                    # Timeline statistics check
                    timeline = generate_timeline(events)
                    self.assertEqual(timeline['created_events'], 0)
                    self.assertEqual(timeline['modified_events'], 1)
                    self.assertEqual(timeline['metadata_changed_events'], 1)
                    self.assertEqual(timeline['accessed_events'], 1)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_linux_birthtime_statx_real_file(self):
        """Test get_linux_birthtime using statx on Linux."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b"statx birthtime test")
            temp_path = f.name

        try:
            btime = get_linux_birthtime(temp_path)
            # On Linux ext4/btrfs/xfs, btime is a positive float epoch timestamp
            if btime is not None:
                self.assertIsInstance(btime, float)
                self.assertGreater(btime, 1500000000.0)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_metadata_changed_filtering(self):
        """Test event_type_filter for 'Metadata Changed'."""
        events = [
            {'filename': 'a.txt', 'event_type': 'Modified', 'timestamp': '2026-03-01 12:00:00'},
            {'filename': 'a.txt', 'event_type': 'Metadata Changed', 'timestamp': '2026-03-01 12:05:00'},
            {'filename': 'a.txt', 'event_type': 'Accessed', 'timestamp': '2026-03-01 12:10:00'},
        ]
        res = generate_timeline(events, event_type_filter='Metadata Changed')
        self.assertEqual(res['total_events'], 1)
        self.assertEqual(res['events'][0]['event_type'], 'Metadata Changed')
        self.assertEqual(res['metadata_changed_events'], 1)



class TestTimelineAnalyzerIntegration(unittest.TestCase):
    """Integration tests with Flask application and sample evidence suite."""

    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_get_timeline_page(self):
        """GET /timeline returns HTTP 200 with Timeline dashboard."""
        response = self.client.get('/timeline')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Forensic Timeline Analyzer', response.data)
        self.assertIn(b'Timeline Event Filters & Evidence Scope', response.data)
        self.assertIn(b'Total Events', response.data)

    def test_post_timeline_sample_evidence_scan(self):
        """POST /timeline scanning sample_evidence/ suite."""
        response = self.client.post('/timeline', data={
            'evidence_source': 'sample',
            'sort_order': 'desc',
            'event_type_filter': 'ALL'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Chronological Evidence Sequence', response.data)
        self.assertIn(b'Total Events', response.data)
        self.assertIn(b'Modified', response.data)

    def test_post_timeline_with_date_filter(self):
        """POST /timeline with date range filter."""
        response = self.client.post('/timeline', data={
            'evidence_source': 'sample',
            'date_from': '2020-01-01',
            'date_to': '2030-12-31',
            'sort_order': 'asc'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Chronological Evidence Sequence', response.data)

    def test_post_timeline_upload_file(self):
        """POST /timeline with direct file upload."""
        txt_content = io.BytesIO(b"Timeline test content")
        response = self.client.post('/timeline', data={
            'evidence_source': 'upload',
            'files': [(txt_content, 'timeline_sample.txt')]
        }, content_type='multipart/form-data')

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'timeline_sample.txt', response.data)

    def test_export_json_endpoint(self):
        """POST /timeline/export-json returns downloadable JSON file."""
        sample_json = json.dumps({'total_events': 3, 'events': []})
        response = self.client.post('/timeline/export-json', data={'export_data': sample_json})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/json')
        self.assertIn('attachment; filename="forensix_timeline_', response.headers.get('Content-Disposition', ''))

    def test_export_csv_endpoint(self):
        """POST /timeline/export-csv returns downloadable CSV file."""
        timeline_dict = {
            'events': [{
                'timestamp': '2026-03-10 12:00:00',
                'event_type': 'Modified',
                'filename': 'test.log',
                'evidence_id': 'EVD-01',
                'case_id': 'CASE-01',
                'event_source': 'Filesystem',
                'precision': 'Second',
                'timezone_info': 'UTC',
                'forensic_notes': 'Testing export.'
            }]
        }
        response = self.client.post('/timeline/export-csv', data={'export_data': json.dumps(timeline_dict)})
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/csv', response.mimetype)
        self.assertIn('attachment; filename="forensix_timeline_', response.headers.get('Content-Disposition', ''))
        self.assertIn(b'test.log', response.data)

    def test_regression_all_previous_five_modules(self):
        """Ensure Modules 1-5 remain 100% operational."""
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


if __name__ == '__main__':
    unittest.main()
