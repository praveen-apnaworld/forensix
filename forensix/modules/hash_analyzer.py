"""
hash_analyzer.py - Cryptographic Hash Calculator Module

This module computes cryptographic hashes (MD5, SHA-1, SHA-256) for files.
Hashes are like digital fingerprints — if even one byte in a file changes,
the hash will be completely different.

How it works:
1. We read the file in small chunks (not all at once) to handle large files.
2. Each chunk is fed into the hash algorithm.
3. After processing all chunks, we get the final hash value.

Why chunked reading?
- A 1 GB file loaded entirely into memory would use 1 GB of RAM.
- Reading in 8 KB chunks uses only 8 KB of RAM regardless of file size.

Security note:
- We NEVER execute uploaded files.
- We NEVER modify the original file.
- Files are processed in memory and not saved permanently.
"""

import hashlib
import re


# Size of each chunk we read (8 KB is efficient for most systems)
CHUNK_SIZE = 8192

# Supported hash algorithms
SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256']


def compute_hashes(file_stream):
    """
    Compute MD5, SHA-1, and SHA-256 hashes for a file.

    Instead of loading the entire file into memory, we read it in small
    chunks. This is called "streaming" and works even for very large files.

    Args:
        file_stream: A file-like object (e.g., from Flask's request.files).
                     Must support .read(size) method.

    Returns:
        dict: A dictionary containing:
            - 'md5': The MD5 hash as a hexadecimal string
            - 'sha1': The SHA-1 hash as a hexadecimal string
            - 'sha256': The SHA-256 hash as a hexadecimal string
            - 'file_size': Size of the file in bytes

    Example:
        >>> result = compute_hashes(open('test.txt', 'rb'))
        >>> print(result['md5'])
        'd41d8cd98f00b204e9800998ecf8427e'  # hash of empty file
    """
    # Create hash objects for each algorithm
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    # Track total bytes read (this gives us the file size)
    total_bytes = 0

    # Read the file chunk by chunk
    while True:
        chunk = file_stream.read(CHUNK_SIZE)

        # If chunk is empty, we've reached the end of the file
        if not chunk:
            break

        # Feed this chunk to all three hash algorithms
        md5_hash.update(chunk)
        sha1_hash.update(chunk)
        sha256_hash.update(chunk)

        total_bytes += len(chunk)

    # Return the final hash values as hexadecimal strings
    # hexdigest() converts the binary hash to a readable hex string
    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest(),
        'file_size': total_bytes
    }


def compute_single_hash(file_stream, algorithm):
    """
    Compute a single hash for a file using the specified algorithm.

    Args:
        file_stream: A file-like object.
        algorithm: One of 'md5', 'sha1', 'sha256'.

    Returns:
        str: The hash value as a hexadecimal string.

    Raises:
        ValueError: If an unsupported algorithm is specified.
    """
    algorithm = algorithm.lower().strip()

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Supported: {', '.join(SUPPORTED_ALGORITHMS)}"
        )

    # Create the appropriate hash object
    if algorithm == 'md5':
        hash_obj = hashlib.md5()
    elif algorithm == 'sha1':
        hash_obj = hashlib.sha1()
    elif algorithm == 'sha256':
        hash_obj = hashlib.sha256()

    # Read and hash in chunks
    while True:
        chunk = file_stream.read(CHUNK_SIZE)
        if not chunk:
            break
        hash_obj.update(chunk)

    return hash_obj.hexdigest()


def compare_hashes(computed_hash, expected_hash):
    """
    Compare a computed hash with an expected hash value.

    We use a case-insensitive comparison because hash values are
    hexadecimal and can be written in uppercase or lowercase.

    Args:
        computed_hash: The hash we calculated from the file.
        expected_hash: The hash value the user expects (e.g., from a download page).

    Returns:
        dict: A dictionary containing:
            - 'match': True if hashes match, False otherwise
            - 'computed': The computed hash (lowercase)
            - 'expected': The expected hash (lowercase, stripped)
            - 'status': 'MATCH' or 'NO MATCH'
    """
    # Normalize both hashes: strip whitespace and convert to lowercase
    computed_clean = computed_hash.strip().lower()
    expected_clean = expected_hash.strip().lower()

    match = computed_clean == expected_clean

    return {
        'match': match,
        'computed': computed_clean,
        'expected': expected_clean,
        'status': 'MATCH' if match else 'NO MATCH'
    }


def validate_hash_format(hash_string, algorithm=None):
    """
    Validate that a hash string looks like a valid hexadecimal hash.

    Each algorithm produces hashes of a specific length:
    - MD5:    32 hex characters (128 bits)
    - SHA-1:  40 hex characters (160 bits)
    - SHA-256: 64 hex characters (256 bits)

    Args:
        hash_string: The hash string to validate.
        algorithm: Optional. If provided, also checks the expected length.

    Returns:
        dict: A dictionary containing:
            - 'valid': True if the hash format is valid
            - 'error': Error message if invalid, None if valid
    """
    if not hash_string or not hash_string.strip():
        return {'valid': False, 'error': 'Hash value cannot be empty.'}

    cleaned = hash_string.strip()

    # Check if it contains only valid hexadecimal characters (0-9, a-f, A-F)
    if not re.match(r'^[0-9a-fA-F]+$', cleaned):
        return {
            'valid': False,
            'error': 'Hash contains invalid characters. Only hex characters (0-9, a-f) are allowed.'
        }

    # Expected lengths for each algorithm
    expected_lengths = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64
    }

    if algorithm and algorithm.lower() in expected_lengths:
        expected_len = expected_lengths[algorithm.lower()]
        if len(cleaned) != expected_len:
            return {
                'valid': False,
                'error': (
                    f'{algorithm.upper()} hash must be exactly {expected_len} characters long, '
                    f'but got {len(cleaned)} characters.'
                )
            }
    else:
        # If no algorithm specified, check if length matches any known algorithm
        valid_lengths = list(expected_lengths.values())
        if len(cleaned) not in valid_lengths:
            return {
                'valid': False,
                'error': (
                    f'Hash length ({len(cleaned)}) does not match any supported algorithm. '
                    f'Expected: MD5 (32), SHA-1 (40), or SHA-256 (64) characters.'
                )
            }

    return {'valid': True, 'error': None}


def format_file_size(size_bytes):
    """
    Convert a file size in bytes to a human-readable string.

    Examples:
        0        → "0 Bytes"
        1024     → "1.00 KB"
        1048576  → "1.00 MB"

    Args:
        size_bytes: File size in bytes.

    Returns:
        str: Human-readable file size string.
    """
    if size_bytes == 0:
        return "0 Bytes"

    units = ['Bytes', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(size_bytes)

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    if unit_index == 0:
        return f"{int(size)} Bytes"
    else:
        return f"{size:.2f} {units[unit_index]}"
