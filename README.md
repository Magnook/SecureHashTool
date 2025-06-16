# 🛡️ SecureHashTool

This tool allows you to recursively scan folders or individual files, calculate their MD5, SHA1, and SHA256 hashes, and check the results against VirusTotal.

## 🚀 Features
- Scan individual files or entire folders (recursively)
- Handle `.zip` archives and scan their contents
- Automatically calculate MD5, SHA1, and SHA256 hashes
- Query VirusTotal to detect known malware by hash
- Print detailed results in terminal 

## 🧰 Requirements

- Python 3.8+
- `requests` library

Install requirements:

```bash
pip install -r requirements.txt

```
## 🧰 How to use

```bash
python scanner.py --folder "C:\Users\me\Documents\myfiles"

python scanner.py --file "C:\Users\me\Downloads\suspect.zip"

```
## 🚀 Output Example

```bash
[SCAN] Scanning: C:\Path\to\file.exe
File      : C:\Path\to\file.exe
  MD5     : abcd1234...
  SHA1    : efgh5678...
  SHA256  : 1234abcd...
  VT      : 3 detections / 70 engines
--------------------------------------------------
