# Sample Digital Evidence Files

This directory contains standardized test evidence files for testing and demonstrating the **ForensiX Digital Forensics Toolkit**.

## Included Test Evidence Files

### 1. Metadata Extractor Test Files (Step 4)

| File Name | Format | Included Metadata | Purpose & Expected Behavior |
|-----------|--------|-------------------|-----------------------------|
| `exif_with_gps.jpg` | JPEG | Camera (Sony Alpha 7 IV), Date Taken, ISO 400, f/2.8, 1/500s, 50mm, **GPS Lat: 37° 46' 29.80" N, Lon: 122° 25' 10.20" W**, Altitude | **Full EXIF & GPS Test:** Validates camera properties, exposure settings, GPS extraction, and sensitive location warning banner. |
| `exif_no_gps.jpg` | JPEG | Camera (Nikon D850), Date Taken, ISO 100, f/4.0, 1/250s, 85mm. **No GPS data.** | **Missing GPS Test:** Validates that camera properties are extracted while GPS fields are cleanly reported as "Not Available" without inventing data. |
| `no_exif_image.jpg` | JPEG | Dimensions only (100x100 RGB). **Zero EXIF tags.** | **Clean / Stripped Image Test:** Validates that dimensions are reported and all EXIF tags are marked as "Not Available". |
| `evidence_chart.png` | PNG | Dimensions (150x150 RGBA). | **PNG Metadata Test:** Validates non-JPEG image property extraction (width, height, color mode, alpha channel). |
| `investigation_report.pdf` | PDF | Title, Author (Marcus Vance), Subject, Creator, Producer, Creation Date | **PDF Metadata Test:** Validates PDF Document Properties extraction using pypdf. |
| `case_brief.docx` | DOCX | Title, Author (Sarah Chen), Subject, Last Modified By (Agent Rossi) | **DOCX Metadata Test:** Validates Microsoft Word OpenXML Core Properties extraction using python-docx. |
| `corrupted_image.jpg` | JPEG | Truncated byte stream | **Corrupted File Test:** Validates error handling distinguishing corrupt files from missing metadata. |

---

### 2. File Analyzer Test Files (Step 3)

| File Name | Format | Signature | Purpose & Expected Result |
|-----------|--------|-----------|---------------------------|
| `valid_image.jpg` | JPEG | `FF D8 FF E0` | Baseline valid JPEG. Expected: **Normal**. |
| `valid_document.pdf` | PDF | `%PDF-1.4` | Baseline valid PDF. Expected: **Normal**. |
| `valid_notes.txt` | TXT | UTF-8 Text | Baseline plain text. Expected: **Normal**. |
| `.hidden_evidence.txt` | TXT | UTF-8 Text | Unix dotfile. Expected: **Hidden = Yes**. |
| `suspicious_invoice.pdf` | JPEG named `.pdf` | `FF D8 FF E0` | **Masquerading Test:** Expected: **Warning: Mismatch Detected**. |
| `unknown_payload.dat` | Binary | `AA BB CC DD ...` | Unknown binary format. Expected: **Unknown files**. |

---

## How to Test the Metadata Extractor

1. Navigate to **[http://127.0.0.1:5000/metadata](http://127.0.0.1:5000/metadata)**.
2. Select or drag-and-drop `exif_with_gps.jpg`:
   - Inspect the **Sensitive Location Warning** with GPS coordinates in both DMS and Decimal.
   - Click the **"Copy Coordinates"** button to copy `37.774944, -122.419500`.
   - Inspect the **Camera Details**, **Exposure & Optics**, and **Date and Time** tables.
   - Click **"Export as JSON"** to download the raw metadata report.
3. Test `exif_no_gps.jpg`:
   - Verify camera properties are populated, while GPS coordinates show **"Not Available"**.
4. Test `investigation_report.pdf`:
   - Verify Document Title, Author, Subject, Creator, and Page Count.
5. Test `case_brief.docx`:
   - Verify Document Title, Author, Subject, and Last Modified By.
6. Test `corrupted_image.jpg`:
   - Verify the error notification clearly identifies a corrupted image.

---

### 3. Keyword Search Test Files (Step 5)

| File Name | Format | Content & Keywords | Purpose & Expected Behavior |
|-----------|--------|---------------------|-----------------------------|
| `access_log.log` | LOG | Users `root`, `admin`, `sarah.chen`, `password`, `token` | **Log & Credential Search:** Line number tracking, redaction of sensitive credentials. |
| `credentials.csv` | CSV | Accounts, emails, passwords | **CSV Record Search:** Row/line tracking and `[REDACTED]` masking of password values. |
| `system_config.json` | JSON | `SYS-FORENSIX-SRV01`, `api_key`, `security_policy` | **JSON Structured Search:** Key and value search with line mapping. |
| `investigation_report.pdf` | PDF | Multi-page text | **PDF Page Mapping:** Page number telemetry and surrounding context. |
| `case_brief.docx` | DOCX | Paragraphs & tables | **DOCX Search:** Paragraph and table cell text extraction. |

## How to Test Keyword Search

1. Navigate to **[http://127.0.0.1:5000/keyword-search](http://127.0.0.1:5000/keyword-search)**.
2. In the **Search Keywords** box, enter:
   ```text
   password
   admin
   sarah.chen
   ForensiX
   ```
3. Select **Match ANY (OR)** and **Preloaded Sample Evidence Suite**.
4. Click **Execute Search**.
5. Observe the **Summary Dashboard**:
   - Total Files Scanned (17)
   - Matching Files
   - Total Occurrences
   - Unsupported Files Safely Handled (images, binary files)
6. Check the **Results Table**:
   - Matched keywords highlighted with yellow badge.
   - Sensitive password values redacted as `password=[REDACTED]`.
   - Click the **Eye icon** on any row to open the full Occurrence Details Modal.
7. Test **Export JSON** and **Export CSV** buttons to download structured evidence reports.
