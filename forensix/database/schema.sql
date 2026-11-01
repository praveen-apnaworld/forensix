-- schema.sql - Database Schema for Digital Forensics Toolkit
-- 
-- This file defines all the tables (like spreadsheets) that store
-- our forensic investigation data. SQLite uses this to create the database.
--
-- Run this once when setting up the application.

-- ============================================================
-- Table 1: cases
-- Stores investigation case records.
-- Each case is like a folder for a specific investigation.
-- ============================================================
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT UNIQUE NOT NULL,          -- e.g., "CASE-2026-0001"
    title TEXT NOT NULL,                    -- Short title for the case
    description TEXT,                       -- Detailed description
    investigator TEXT NOT NULL,             -- Who is investigating
    status TEXT DEFAULT 'Open',             -- Open, Closed, or Archived
    created_at TEXT NOT NULL,               -- When the case was created
    updated_at TEXT NOT NULL                -- Last time the case was modified
);

-- ============================================================
-- Table 2: evidence
-- Stores information about each piece of evidence.
-- Each evidence belongs to one case.
-- ============================================================
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT UNIQUE NOT NULL,       -- e.g., "EVD-0001"
    case_id INTEGER NOT NULL,              -- Which case this belongs to
    filename TEXT NOT NULL,                 -- Original file name
    original_path TEXT,                     -- Where the file came from
    stored_path TEXT NOT NULL,              -- Where we saved it on the server
    description TEXT,                       -- What this evidence is
    source TEXT,                            -- Where it was acquired from
    acquisition_method TEXT,                -- How it was acquired (e.g., "USB copy")
    file_size INTEGER,                      -- Size in bytes
    file_type TEXT,                         -- Detected file type
    added_at TEXT NOT NULL,                 -- When it was added
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

-- ============================================================
-- Table 3: hash_records
-- Stores cryptographic hashes for evidence integrity verification.
-- Hashes are like digital fingerprints of files.
-- ============================================================
CREATE TABLE IF NOT EXISTS hash_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,           -- Which evidence this hash belongs to
    md5 TEXT,                               -- MD5 hash value
    sha1 TEXT,                              -- SHA-1 hash value
    sha256 TEXT,                            -- SHA-256 hash value
    computed_at TEXT NOT NULL,              -- When the hash was computed
    verification_status TEXT DEFAULT 'Pending',  -- Pending, Verified, or Mismatch
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
);

-- ============================================================
-- Table 4: analysis_results
-- Stores results from various analysis tools.
-- Results are stored as JSON text for flexibility.
-- ============================================================
CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,           -- Which evidence was analyzed
    analysis_type TEXT NOT NULL,            -- "file", "metadata", "keyword", "timeline"
    results_json TEXT NOT NULL,             -- Analysis results in JSON format
    analyzed_at TEXT NOT NULL,              -- When the analysis was performed
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
);

-- ============================================================
-- Table 5: chain_of_custody
-- Tracks every action performed on evidence.
-- This is critical in real forensics to prove evidence wasn't tampered with.
-- ============================================================
CREATE TABLE IF NOT EXISTS chain_of_custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,           -- Which evidence this action relates to
    action TEXT NOT NULL,                   -- What was done (e.g., "Acquired", "Analyzed")
    performed_by TEXT NOT NULL,             -- Who did it
    details TEXT,                           -- Additional details about the action
    timestamp TEXT NOT NULL,                -- When it happened
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
);

-- ============================================================
-- Table 6: reports
-- Tracks generated PDF reports.
-- ============================================================
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT UNIQUE,                 -- e.g., "RPT-2026-0001"
    case_id INTEGER NOT NULL,              -- Which case the report is for
    report_title TEXT,                     -- Title of the report
    report_filename TEXT NOT NULL,          -- Name of the PDF file
    file_path TEXT,                        -- Path to the saved PDF file
    file_size INTEGER,                     -- Size in bytes
    generated_at TEXT NOT NULL,             -- When the report was generated
    generated_by TEXT,                      -- Who generated it
    evidence_count INTEGER DEFAULT 0,       -- Count of evidence items included in report
    selected_evidence_ids TEXT,             -- Comma-separated or JSON list of included evidence IDs
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

-- ============================================================
-- Table 7: audit_logs
-- Records every important action in the application.
-- Like a security camera for the app — tracks who did what and when.
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,                       -- Related case (optional)
    action TEXT NOT NULL,                  -- What happened
    details TEXT,                           -- Additional context
    performed_by TEXT,                      -- Who did it
    timestamp TEXT NOT NULL                 -- When it happened
);

-- ============================================================
-- Table 8: settings
-- Stores application settings as key-value pairs.
-- ============================================================
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,              -- Setting name
    value TEXT                              -- Setting value
);

-- Insert default settings
INSERT OR IGNORE INTO settings (key, value) VALUES ('investigator_name', 'Investigator');
INSERT OR IGNORE INTO settings (key, value) VALUES ('organization', 'Cybersecurity Lab');
