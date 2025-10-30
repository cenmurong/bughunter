# mass_scan.py
# Copyright (c) 2024 cenmurong.
#
# This software is provided for security research and educational use.
# Any action and/or activity related to this material is solely your responsibility.
# UPADTE COMING SOOONNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN~

import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

TOOLS_PATH = "misc/tools.py"
MAX_THREADS = 15
SQLMAP_TIMEOUT = 180

def scan_target(url):
    url = url.strip()
    if not url:
        return "SKIP"
    
    output_dir = f"scan_results/scan_{url.split('//')[1].split('/')[0]}"
    cmd = [
        "python3", TOOLS_PATH, url,
        "--output-dir", output_dir,
        "--yes",
        "--timeout", "15",
        "--silent"  # Tambahkan flag silent di sini
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SQLMAP_TIMEOUT)
        if result.returncode == 0:
            return f"SUCCESS: {url}"
        else:
            return f"FAILED: {url}"
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: {url}"

def run_mass_scan_from_crawler():
    urls_file = "crawled_urls.txt"
    if not os.path.exists(urls_file):
        print(f"[ERROR] {urls_file} tidak ditemukan! Jalankan crawler dulu.")
        return
    
    with open(urls_file) as f:
        urls = [line.strip() for line in f if line.strip()]
    
    print(f"[RUN] Mass Full Scan {len(urls)} URL dari crawler dengan {MAX_THREADS} thread...")
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(scan_target, url) for url in urls]
        with tqdm(as_completed(futures), total=len(futures), desc="Scanning", unit="url") as pbar:
            for future in pbar:
                tqdm.write(future.result()) # Gunakan tqdm.write untuk output yang aman
    
    print(f"\n[SUCCESS] Mass scan selesai! Cek scan_results/")

if __name__ == "__main__":
    run_mass_scan_from_crawler()