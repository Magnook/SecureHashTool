import os
import zipfile
import argparse
import hashlib
import requests
import time

# 🔑 Insert your VirusTotal API key here
API_KEY = 'YOUR_API_KEY'


def check_virustotal(hash_value):
    """Query VirusTotal API for a given file hash."""
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            detections = stats.get('malicious', 0)
            total = sum(stats.values())

            return {
                'malicious': detections,
                'total_engines': total
            }

        elif response.status_code == 404:
            print(f"[VT] Hash {hash_value} not found on VirusTotal.")
            return {'malicious': 0, 'total_engines': 0}

        elif response.status_code == 429:
            print("[VT] Rate limit exceeded. Waiting...")
            time.sleep(60)
            return check_virustotal(hash_value)

        else:
            print(f"[VT] API error: {response.status_code}")
            return None

    except Exception as e:
        print(f"[VT] Error during request: {e}")
        return None


def calculate_hash(file_path):
    """Calculate MD5, SHA1, and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }

    except Exception as e:
        print(f"[HASH] Error processing {file_path}: {e}")
        return None


def scan_file(file_path):
    """Scan a single file or zip archive."""
    scanned = []

    if zipfile.is_zipfile(file_path):
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                for name in zip_ref.namelist():
                    try:
                        with zip_ref.open(name) as file:
                            content = file.read()
                            md5 = hashlib.md5(content).hexdigest()
                            sha1 = hashlib.sha1(content).hexdigest()
                            sha256 = hashlib.sha256(content).hexdigest()

                            vt_result = check_virustotal(sha256)

                            scanned.append({
                                'file': f"{file_path} -> {name}",
                                'md5': md5,
                                'sha1': sha1,
                                'sha256': sha256,
                                'vt_malicious': vt_result['malicious'] if vt_result else 'N/A',
                                'vt_total': vt_result['total_engines'] if vt_result else 'N/A'
                            })
                    except Exception as e:
                        print(f"[ZIP] Error reading {name} in {file_path}: {e}")
        except Exception as e:
            print(f"[ZIP] Error opening zip file {file_path}: {e}")
    else:
        hash_result = calculate_hash(file_path)
        if hash_result:
            vt_result = check_virustotal(hash_result['sha256'])

            scanned.append({
                'file': file_path,
                'md5': hash_result['md5'],
                'sha1': hash_result['sha1'],
                'sha256': hash_result['sha256'],
                'vt_malicious': vt_result['malicious'] if vt_result else 'N/A',
                'vt_total': vt_result['total_engines'] if vt_result else 'N/A'
            })

    return scanned


def scan_folder(folder):
    """Recursively scan all files in a folder."""
    results = []

    for root, dirs, files in os.walk(folder):
        for file in files:
            path = os.path.join(root, file)
            print(f"[SCAN] Scanning: {path}")
            results.extend(scan_file(path))

    return results


def main():
    parser = argparse.ArgumentParser(description="Scan files or folders and check hashes on VirusTotal.")
    parser.add_argument("--folder", help="Path to folder to scan")
    parser.add_argument("--file", help="Path to a single file to scan")

    args = parser.parse_args()

    if args.folder:
        results = scan_folder(args.folder)
    elif args.file:
        results = scan_file(args.file)
    else:
        print("[!] You must provide either --folder or --file")
        return

    print("\n--- 🧠 Final Results ---")
    for item in results:
        print(f"File      : {item['file']}")
        print(f"  MD5     : {item['md5']}")
        print(f"  SHA1    : {item['sha1']}")
        print(f"  SHA256  : {item['sha256']}")
        print(f"  VT      : {item['vt_malicious']} detections / {item['vt_total']} engines")
        print("--------------------------------------------------")


if __name__ == "__main__":
    main()
