"""
test_hash_analyzer.py - Automated Tests for the Hash Analyzer Module

These tests verify that:
1. Hash computation returns correct values for known inputs.
2. Hash comparison correctly identifies matching and mismatching hashes.
3. Hash format validation catches invalid inputs.
4. File size formatting produces correct human-readable strings.
5. Edge cases (empty files, large content) are handled properly.

Run these tests with:
    python -m pytest tests/test_hash_analyzer.py -v

Or from the project root:
    python -m pytest tests/ -v
"""

import io
import hashlib
import unittest
import sys
import os

# Add the project root to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.hash_analyzer import (
    compute_hashes,
    compute_single_hash,
    compare_hashes,
    validate_hash_format,
    format_file_size
)


class TestComputeHashes(unittest.TestCase):
    """Test the compute_hashes function."""

    def test_known_content(self):
        """Test hashes for a string with a known correct hash value."""
        # "hello world" is a classic test string.
        # We verify our function produces the exact same hash as hashlib directly.
        content = b"hello world"
        file_stream = io.BytesIO(content)

        result = compute_hashes(file_stream)

        # Compare against hashlib's direct computation
        self.assertEqual(result['md5'], hashlib.md5(content).hexdigest())
        self.assertEqual(result['sha1'], hashlib.sha1(content).hexdigest())
        self.assertEqual(result['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(result['file_size'], len(content))

    def test_empty_file(self):
        """Test hashes for an empty file."""
        # Even an empty file has a valid hash (the hash of "nothing").
        file_stream = io.BytesIO(b"")
        result = compute_hashes(file_stream)

        # Known hashes for empty input
        self.assertEqual(result['md5'], 'd41d8cd98f00b204e9800998ecf8427e')
        self.assertEqual(result['sha1'], 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
        self.assertEqual(result['sha256'],
                         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        self.assertEqual(result['file_size'], 0)

    def test_file_size_tracking(self):
        """Test that file size is correctly tracked."""
        content = b"A" * 10000  # 10,000 bytes
        file_stream = io.BytesIO(content)
        result = compute_hashes(file_stream)

        self.assertEqual(result['file_size'], 10000)

    def test_large_content_chunked(self):
        """Test that chunked reading produces correct hashes for large files."""
        # Create content larger than CHUNK_SIZE (8192 bytes) to ensure
        # multi-chunk reading works correctly.
        content = b"X" * 50000  # 50 KB, will need multiple chunks
        file_stream = io.BytesIO(content)

        result = compute_hashes(file_stream)

        # Verify against direct hashlib computation (which reads all at once)
        self.assertEqual(result['md5'], hashlib.md5(content).hexdigest())
        self.assertEqual(result['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(result['file_size'], 50000)

    def test_binary_content(self):
        """Test hashing of binary content (non-text data)."""
        # Simulate binary file content (like an image or executable)
        content = bytes(range(256)) * 10
        file_stream = io.BytesIO(content)

        result = compute_hashes(file_stream)

        self.assertEqual(result['md5'], hashlib.md5(content).hexdigest())
        self.assertEqual(result['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(result['file_size'], 2560)

    def test_hash_format(self):
        """Test that returned hashes are valid lowercase hexadecimal strings."""
        content = b"test data"
        file_stream = io.BytesIO(content)
        result = compute_hashes(file_stream)

        # MD5 should be 32 hex characters
        self.assertEqual(len(result['md5']), 32)
        self.assertTrue(all(c in '0123456789abcdef' for c in result['md5']))

        # SHA-1 should be 40 hex characters
        self.assertEqual(len(result['sha1']), 40)
        self.assertTrue(all(c in '0123456789abcdef' for c in result['sha1']))

        # SHA-256 should be 64 hex characters
        self.assertEqual(len(result['sha256']), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in result['sha256']))


class TestComputeSingleHash(unittest.TestCase):
    """Test the compute_single_hash function."""

    def test_md5(self):
        content = b"hello"
        result = compute_single_hash(io.BytesIO(content), 'md5')
        self.assertEqual(result, hashlib.md5(content).hexdigest())

    def test_sha1(self):
        content = b"hello"
        result = compute_single_hash(io.BytesIO(content), 'sha1')
        self.assertEqual(result, hashlib.sha1(content).hexdigest())

    def test_sha256(self):
        content = b"hello"
        result = compute_single_hash(io.BytesIO(content), 'sha256')
        self.assertEqual(result, hashlib.sha256(content).hexdigest())

    def test_case_insensitive_algorithm(self):
        """Algorithm name should be case-insensitive."""
        content = b"test"
        r1 = compute_single_hash(io.BytesIO(content), 'MD5')
        r2 = compute_single_hash(io.BytesIO(content), 'md5')
        self.assertEqual(r1, r2)

    def test_invalid_algorithm(self):
        """Should raise ValueError for unsupported algorithms."""
        with self.assertRaises(ValueError):
            compute_single_hash(io.BytesIO(b"test"), 'sha512')


class TestCompareHashes(unittest.TestCase):
    """Test the compare_hashes function."""

    def test_matching_hashes(self):
        """Identical hashes should produce a MATCH."""
        hash_val = 'd41d8cd98f00b204e9800998ecf8427e'
        result = compare_hashes(hash_val, hash_val)

        self.assertTrue(result['match'])
        self.assertEqual(result['status'], 'MATCH')

    def test_mismatching_hashes(self):
        """Different hashes should produce a NO MATCH."""
        hash1 = 'd41d8cd98f00b204e9800998ecf8427e'
        hash2 = 'a41d8cd98f00b204e9800998ecf8427e'
        result = compare_hashes(hash1, hash2)

        self.assertFalse(result['match'])
        self.assertEqual(result['status'], 'NO MATCH')

    def test_case_insensitive_comparison(self):
        """Hash comparison should be case-insensitive."""
        hash_lower = 'd41d8cd98f00b204e9800998ecf8427e'
        hash_upper = 'D41D8CD98F00B204E9800998ECF8427E'
        result = compare_hashes(hash_lower, hash_upper)

        self.assertTrue(result['match'])

    def test_whitespace_handling(self):
        """Hashes with leading/trailing whitespace should still match."""
        hash_val = 'd41d8cd98f00b204e9800998ecf8427e'
        hash_with_spaces = '  d41d8cd98f00b204e9800998ecf8427e  '
        result = compare_hashes(hash_val, hash_with_spaces)

        self.assertTrue(result['match'])

    def test_result_contains_normalized_hashes(self):
        """Result should contain lowercase, stripped versions of both hashes."""
        result = compare_hashes(' ABC123 ', '  abc123  ')
        self.assertEqual(result['computed'], 'abc123')
        self.assertEqual(result['expected'], 'abc123')


class TestValidateHashFormat(unittest.TestCase):
    """Test the validate_hash_format function."""

    def test_valid_md5(self):
        """A 32-character hex string is a valid MD5."""
        result = validate_hash_format('d41d8cd98f00b204e9800998ecf8427e', 'md5')
        self.assertTrue(result['valid'])
        self.assertIsNone(result['error'])

    def test_valid_sha1(self):
        """A 40-character hex string is a valid SHA-1."""
        result = validate_hash_format('da39a3ee5e6b4b0d3255bfef95601890afd80709', 'sha1')
        self.assertTrue(result['valid'])

    def test_valid_sha256(self):
        """A 64-character hex string is a valid SHA-256."""
        hash_val = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        result = validate_hash_format(hash_val, 'sha256')
        self.assertTrue(result['valid'])

    def test_empty_hash(self):
        """Empty string should be invalid."""
        result = validate_hash_format('', 'md5')
        self.assertFalse(result['valid'])
        self.assertIn('empty', result['error'].lower())

    def test_whitespace_only(self):
        """Whitespace-only string should be invalid."""
        result = validate_hash_format('   ', 'md5')
        self.assertFalse(result['valid'])

    def test_non_hex_characters(self):
        """Strings with non-hex characters should be invalid."""
        result = validate_hash_format('d41d8cd98f00b204e9800998ecf8427z', 'md5')
        self.assertFalse(result['valid'])
        self.assertIn('invalid characters', result['error'].lower())

    def test_wrong_length_for_algorithm(self):
        """Hash with wrong length for the specified algorithm should be invalid."""
        # MD5 expects 32 chars, but we provide 40
        result = validate_hash_format('da39a3ee5e6b4b0d3255bfef95601890afd80709', 'md5')
        self.assertFalse(result['valid'])
        self.assertIn('32', result['error'])

    def test_valid_without_algorithm(self):
        """Without specifying algorithm, any valid-length hex string should pass."""
        # 32 chars (MD5 length)
        result = validate_hash_format('d41d8cd98f00b204e9800998ecf8427e')
        self.assertTrue(result['valid'])

    def test_invalid_length_without_algorithm(self):
        """Without algorithm, a hex string of non-standard length should fail."""
        result = validate_hash_format('abcdef123456')  # 12 chars, matches nothing
        self.assertFalse(result['valid'])

    def test_none_input(self):
        """None input should be invalid."""
        result = validate_hash_format(None, 'md5')
        self.assertFalse(result['valid'])


class TestFormatFileSize(unittest.TestCase):
    """Test the format_file_size function."""

    def test_zero_bytes(self):
        self.assertEqual(format_file_size(0), '0 Bytes')

    def test_bytes(self):
        self.assertEqual(format_file_size(500), '500 Bytes')

    def test_kilobytes(self):
        self.assertEqual(format_file_size(1024), '1.00 KB')

    def test_megabytes(self):
        self.assertEqual(format_file_size(1048576), '1.00 MB')

    def test_gigabytes(self):
        self.assertEqual(format_file_size(1073741824), '1.00 GB')

    def test_fractional(self):
        # 1536 bytes = 1.5 KB
        self.assertEqual(format_file_size(1536), '1.50 KB')


class TestFlaskHashRoute(unittest.TestCase):
    """Test the hash analyzer Flask route (integration tests)."""

    def setUp(self):
        """Set up a test Flask client."""
        # Import here to avoid issues if Flask isn't in the test environment
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from app import create_app
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_get_hash_page(self):
        """GET /hash-analyzer should return 200."""
        response = self.client.get('/hash-analyzer')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Hash Analyzer', response.data)

    def test_compute_hashes_via_post(self):
        """POST with a file should compute and display hashes."""
        data = {
            'action': 'compute',
            'file': (io.BytesIO(b'test content'), 'test.txt')
        }
        response = self.client.post(
            '/hash-analyzer',
            data=data,
            content_type='multipart/form-data'
        )
        self.assertEqual(response.status_code, 200)
        # The response should contain the MD5 of "test content"
        expected_md5 = hashlib.md5(b'test content').hexdigest()
        self.assertIn(expected_md5.encode(), response.data)

    def test_compute_no_file(self):
        """POST without a file should show an error message."""
        data = {'action': 'compute'}
        response = self.client.post(
            '/hash-analyzer',
            data=data,
            content_type='multipart/form-data'
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'No file was selected', response.data)

    def test_compare_matching_hash(self):
        """POST compare with matching hash should show MATCH."""
        content = b'forensic test'
        expected = hashlib.sha256(content).hexdigest()
        data = {
            'action': 'compare',
            'compare_file': (io.BytesIO(content), 'evidence.txt'),
            'algorithm': 'sha256',
            'expected_hash': expected
        }
        response = self.client.post(
            '/hash-analyzer',
            data=data,
            content_type='multipart/form-data'
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'MATCH', response.data)

    def test_compare_mismatching_hash(self):
        """POST compare with wrong hash should show NO MATCH."""
        content = b'forensic test'
        wrong_hash = '0' * 64  # Definitely not the right SHA-256
        data = {
            'action': 'compare',
            'compare_file': (io.BytesIO(content), 'evidence.txt'),
            'algorithm': 'sha256',
            'expected_hash': wrong_hash
        }
        response = self.client.post(
            '/hash-analyzer',
            data=data,
            content_type='multipart/form-data'
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'NO MATCH', response.data)

    def test_compare_invalid_hash_format(self):
        """POST compare with invalid hash should show a validation error."""
        data = {
            'action': 'compare',
            'compare_file': (io.BytesIO(b'test'), 'test.txt'),
            'algorithm': 'sha256',
            'expected_hash': 'not-a-valid-hash!'
        }
        response = self.client.post(
            '/hash-analyzer',
            data=data,
            content_type='multipart/form-data'
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'invalid characters', response.data.lower())

    def test_compare_empty_expected_hash(self):
        """POST compare with empty expected hash should show error."""
        data = {
            'action': 'compare',
            'compare_file': (io.BytesIO(b'test'), 'test.txt'),
            'algorithm': 'sha256',
            'expected_hash': ''
        }
        response = self.client.post(
            '/hash-analyzer',
            data=data,
            content_type='multipart/form-data'
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'enter an expected hash', response.data.lower())

    def test_dashboard_still_works(self):
        """Ensure the dashboard is not broken by our changes."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dashboard', response.data)


if __name__ == '__main__':
    unittest.main()
