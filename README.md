# Java Class Extractor from Memory Dump

A Python tool to extract Java class files (`.class`) from memory dump files. It scans for the CAFEBABE magic header and reconstructs class files while preserving the integrity of Java versions and attributes. It also provides optional dump analysis and verification of extracted files.

---

## Features

- Extract Java classes from raw memory dumps.
- Handles standard and heuristic extraction when class size cannot be determined exactly.
- Supports Java class versions from 1.1 to Java 21.
- Detects duplicate classes and avoids redundant extraction.
- Logs all extracted classes with offset, size, version, and MD5 hash.
- Optional dump pattern analysis.
- Verifies that extracted files start with the CAFEBABE header.
- Compatible with large memory dumps.

---

## Requirements

- Python 3.8 or higher
- Standard Python libraries:
  - `os`
  - `struct`
  - `logging`
  - `pathlib`
  - `hashlib`
  - `argparse`

No external dependencies are required.

---

## Installation

1. Clone or download this repository.
2. Make sure Python 3 is installed and accessible in your environment.
3. Place your memory dump file in a known directory.

---

## Usage

```bash
python3 extract_java_classes.py <dump_file> [options]
