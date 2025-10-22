except KeyboardInterrupt:
            self.log("warn", "Bruteforce interrupted by user (Ctrl+C).")

        self.log_done(f"Bruteforce login finished. Found: {len(found)} results.")

    def generate_hackerone_report(self):
        critical = [f for f in self.findings if f['severity'] == 'critical']
        high = [f for f in self.findings if f['severity'] == 'high']
        if not (critical or high):
            return "No findings with Critical or High severity to report."
        report = f"# [High] Multiple Security Issues on {self.host} (Risk Score: {self.total_score}/100)\n\n## Summary\nDuring authorized testing, the following vulnerabilities were identified:\n\n"

        for f in critical + high:
            report += f"- (Score: {f['score']}) {f['message']}\n"
            if 'evidence' in f:
                report += f"  - **Evidence**: {json.dumps(f['evidence'], indent=2)}\n"
        report += "\n## Impact\nThese issues could lead to data leakage, account takeover, or service disruption.\n\n## Remediation\n- Implement proper input validation and output encoding.\n- Apply security headers (CSP, HSTS).\n- Restrict access to sensitive paths.\n- Validate file uploads to prevent execution of malicious files.\n"
        return report

    def generate_reports(self, output_dir="report"):
        main_report_dir = output_dir
        run_timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        sanitized_host = re.sub(r'[^a-zA-Z0-9_-]', '_', self.host)
        run_report_dir = os.path.join(main_report_dir, f"report_{sanitized_host}_{run_timestamp_str}")
        os.makedirs(run_report_dir, exist_ok=True)

        json_path = os.path.join(run_report_dir, "report.json")
        md_path = os.path.join(run_report_dir, "hackerone_report.md")
        html_path = os.path.join(run_report_dir, "report.html")

        with open(json_path, "w") as f:
            json.dump({"target": self.target, "total_score": self.total_score, "findings": self.findings}, f, indent=2)

        h1_report = self.generate_hackerone_report()
        with open(md_path, "w") as f:
            f.write(h1_report)

        severity_counts = {s: 0 for s in SEVERITY_SCORES.keys()}
        for f in self.findings:
            severity_counts[f['severity']] += 1
        html = f"""
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
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Bug Hunter V.1 Report</h1>
                <h2>Target: {self.host}</h2>
                <h3>Total Risk Score: <span style="color: #ff4500; font-weight: bold;">{self.total_score} / 100</span></h3>

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
                            <th onclick="sortTable(2)">Message</th>
                            <th onclick="sortTable(3)">Timestamp</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for i, f in enumerate(self.findings):
            evidence_str = json.dumps(f.get('evidence', {}), indent=2) if 'evidence' in f else "N/A"
            html += """
            <tr class='severity-{}'>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>
                    <span class="evidence-toggle" onclick="toggleEvidence('evidence-{}')">Show/Hide</span>
                    <div id="evidence-{}" class="evidence-content">
                        <pre>{}</pre>
                    </div>
                </td>
            </tr>
            """.format(
                f.get('severity', 'N/A').lower(),
                f.get('severity', 'N/A').capitalize(),
                f.get('score', 'N/A'),
                f.get('message', 'N/A'),
                f.get('timestamp', 'N/A'),
                i,
                i,
                evidence_str
            )
        html += """
                    </tbody>
                </table>
            </div>
            <script>
                const ctx = document.getElementById('severityChart').getContext('2d');
                new Chart(ctx, {{
                    type: 'bar',
                    data: {{
                        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                        datasets: [{{ 
                            label: 'Severity Distribution',
                            data: [{severity_counts['critical']}, {severity_counts['high']}, {severity_counts['medium']}, {severity_counts['low']}, {severity_counts['info']}],
                            backgroundColor: ['#600', '#7a2d00', '#8c5a00', '#2a522a', '#2c3e50'],
                            borderWidth: 1
                        }}]
                    }},
                    options: {{
                        indexAxis: 'y',
                        responsive: true,
                        scales: {{
                            x: {{ beginAtZero: true, ticks: {{ color: '#e0e0e0' }} }},
                            y: {{ ticks: {{ color: '#e0e0e0' }} }}
                        }}
                    }}
                }});

                function filterTable() {{
                    const severityFilter = document.getElementById('severityFilter').value.toLowerCase();
                    const searchInput = document.getElementById('searchInput').value.toLowerCase();
                    const table = document.getElementById('findingsTable');
                    const tr = table.getElementsByTagName('tr');

                    for (let i = 1; i < tr.length; i++) {{ // Start from 1 to skip header
                        const severityTd = tr[i].getElementsByTagName("TD")[0];
                        const messageTd = tr[i].getElementsByTagName("TD")[2];
                        if (severityTd && messageTd) {{ 
                            const severityMatch = severityFilter === '' || severityTd.textContent.toLowerCase().includes(severityFilter);
                            const searchMatch = messageTd.textContent.toLowerCase().includes(searchInput);
                            if (severityMatch && searchMatch) {{ 
                                tr[i].style.display = '';
                            }} else {{ 
                                tr[i].style.display = 'none';
                            }}
                        }} 
                    }};
                }}

                function toggleEvidence(id) {{
                    const el = document.getElementById(id);
                    if (el.style.display === 'block') {{
                        el.style.display = 'none';
                    }} else {{
                        el.style.display = 'block';
                    }}
                }}

                function sortTable(n) {{
                    const table = document.getElementById("findingsTable");
                    let rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
                    switching = true;
                    dir = "asc"; 
                    while (switching) {{
                        switching = false;
                        rows = table.rows;
                        for (i = 1; i < (rows.length - 1); i++) {{
                            shouldSwitch = false;
                            x = rows[i].getElementsByTagName("TD")[n];
                            y = rows[i + 1].getElementsByTagName("TD")[n];
                            let xContent = isNaN(parseFloat(x.innerHTML)) ? x.innerHTML.toLowerCase() : parseFloat(x.innerHTML);
                            let yContent = isNaN(parseFloat(y.innerHTML)) ? y.innerHTML.toLowerCase() : parseFloat(y.innerHTML);
                            if (dir == "asc") {{
                                if (xContent > yContent) {{
                                    shouldSwitch = true;
                                    break;
                                }}
                            }} else if (dir == "desc") {{
                                if (xContent < yContent) {{
                                    shouldSwitch = true;
                                    break;
                                }}
                            }}
                        }}
                        if (shouldSwitch) {{
                            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                            switching = true;
                            switchcount++;
                        }} else {{
                            if (switchcount == 0 && dir == "asc") {{
                                dir = "desc";
                                switching = true;
                            }}
                        }}
                    }}
                }}
            </script>
        </body>
        </html>
        """.format(
                f.get('severity', 'N/A').lower(),
                f.get('severity', 'N/A').capitalize(),
                f.get('score', 'N/A'),
                f.get('message', 'N/A'),
                f.get('timestamp', 'N/A'),
                i,
                i,
                evidence_str
            )
        with open(html_path, "w") as f:
            f.write(html)

        self.log("info", f"Reports saved in directory: {run_report_dir}")

    def run(self, auto_confirm: bool = False) -> None:
        print(f"\n🎯 Bug Hunter Pro v.1 — Ultimate Auto Vuln Hunter & Blinking Alerts")
        print(f"Target: {self.target}")
        if self.scope_regex:
            print(f"Scope Regex: {self.scope_regex}")
        if self.cookie:
            print("Authentication: Enabled (cookie provided)")
        if self.proxy:
            print(f"Proxy: {self.proxy}")
        print(f"Shell files: {', '.join(self.shell_files)}")
        print(f"Config file: {self.config_path}")
        print("="*60)
        if not auto_confirm:
            print("\n[❗] WARNING:")
            print("1. This tool is for educational purposes only.")
            print("2. Do not use on government systems without written permission.")
            print("3. Ensure shell files (shell/konz.php, shell/konz.php.jpg) are used only for legal testing.")
            confirm = input("\nType '1' to continue: ")
            if confirm.strip() != '1':
                print("[❌] Aborted.")
                return
        try:
            self.check_dependencies()
        except Exception:
            self.log("warn", "Dependency check failed. Continuing without it.")

        if self.dry_run:
            self.log("info", "Dry-run mode enabled: no active network scanning will be performed. Network-requiring modules will be skipped.")
            self.visited_urls.add(self.base_url)
            self.log_done("Dry-run setup complete.")
            return
        self.log_step("Starting crawling with Playwright from base URL")
        self.crawl_with_playwright(self.base_url)
        self.log_done(f"Crawling finished. Visited {len(self.visited_urls)} URLs and found {len(self.dynamic_params)} dynamic parameters.")
        self.run_arjun()
        self.auto_register()
        modules = [
            ("Technology Detection", self.detect_tech),
            ("WHOIS Information", self.run_whois),
            ("Port Scan (Nmap)", self.run_port_scan),
            ("Sensitive API Search", self.find_sensitive_api_endpoints),
            ("Web Cache Deception Check", self.check_web_cache_deception),
            ("HTTP Method Switching Test", self.check_http_method_switching),
            ("Array-Based IDOR Check", self.check_array_based_idor),
            ("Subdomain Enumeration (Subfinder)", self.run_subfinder),
            ("Sensitive Paths Scan", self.check_sensitive_paths),
            ("Directory Discovery (Gobuster)", self.run_gobuster),
            ("CORS Check", self.check_cors),
            ("Security Headers Check", self.check_security_headers),
            ("Cookie Security Check", self.check_cookie_security),
            ("XSS Check", self.check_xss),
            ("SQLi Check", self.check_sqli),
            ("LFI/RFI Check", self.check_lfi_rfi),
            ("SSRF Check", self.check_ssrf),
            ("SSRF OAST Check", self.check_ssrf_oast),
            ("Internal Access via SSRF Check", self.check_internal_access_via_ssrf),
            ("SSTI Check", self.check_ssti),
            ("Open Redirect Check", self.check_open_redirect),
            ("CSRF Check", self.check_csrf),
            ("IDOR Check", self.check_idor),
            ("API Key Leakage Check", self.check_api_leakage),
            ("WAF Bypass Check", self.check_waf_bypass),
            ("File Upload Check", self.check_file_upload),
            ("CRLF Injection Check", self.check_crlf_injection),
            ("OS Command Injection Check", self.check_command_injection),
            ("Nuclei Scan", self.run_nuclei),
            ("Database Finder", lambda: self.find_databases(check_ports=not getattr(self, 'no_port_scan', False), deep_scan=getattr(self, 'db_deep_scan', False), timeout=getattr(self, 'db_timeout', 5))),
            ("CloudFlare Bypass", lambda: self.bypass_cloudflare(use_tor=getattr(self, 'cf_use_tor', False), aggressive=getattr(self, 'cf_aggressive', False), timeout=getattr(self, 'cf_timeout', 10))),
        ]
        for name, func in modules:
            if self.in_scope_only:
                self.log("info", f"--- Starting: {name} (in scope only) ---")
            else:
                self.log("info", f"--- Starting: {name} ---")
            try:
                func()
            except Exception as e:
                self.log("error", f"{name} failed: {e}")
        self.generate_reports(output_dir=self.output_dir)
        print(f"\nScan finished. Total Risk Score: {self.total_score}/100")
        print("\n[⚠️] Warning: If shells were successfully uploaded, ensure you manually remove them from the server!")

    def run_specific_module(self, module_name: str) -> None:
        """Runs only a specific module."""
        
        
        module_map = {
            "detect_tech": self.detect_tech,
            "whois": self.run_whois,
            "port_scan": self.run_port_scan,
            "sensitive_api": self.find_sensitive_api_endpoints,
            "web_cache_deception": self.check_web_cache_deception,
            "http_method_switching": self.check_http_method_switching,
            "array_idor": self.check_array_based_idor,
            "subfinder": self.run_subfinder,
            "sensitive_paths": self.check_sensitive_paths,
            "gobuster": self.run_gobuster,
            "cors": self.check_cors,
            "security_headers": self.check_security_headers,
            "cookie_security": self.check_cookie_security,
            "xss": self.check_xss,
            "sqli": self.check_sqli,
            "lfi_rfi": self.check_lfi_rfi,
            "ssrf": self.check_ssrf,
            "ssrf_oast": self.check_ssrf_oast,
            "ssrf_internal": self.check_internal_access_via_ssrf,
            "ssti": self.check_ssti,
            "open_redirect": self.check_open_redirect,
            "csrf": self.check_csrf,
            "idor": self.check_idor,
            "api_leakage": self.check_api_leakage,
            "waf_bypass": self.check_waf_bypass,
            "file_upload": self.check_file_upload,
            "crlf_injection": self.check_crlf_injection,
            "command_injection": self.check_command_injection,
            "nuclei": self.run_nuclei,
            "dbfinder": lambda: self.find_databases(
                check_ports=not getattr(self, 'no_port_scan', False),
                deep_scan=getattr(self, 'db_deep_scan', False),
                timeout=getattr(self, 'db_timeout', 5)
            ),
            "cfbypass": lambda: self.bypass_cloudflare(
                use_tor=getattr(self, 'cf_use_tor', False),
                aggressive=getattr(self, 'cf_aggressive', False),
                timeout=getattr(self, 'cf_timeout', 10)
            ),
            "bruteforce": lambda: self.bruteforce_login(
                wordlist=getattr(self, 'bruteforce_wordlist', None),
                username=getattr(self, 'bruteforce_username', None),
                max_workers=getattr(self, 'bruteforce_threads', 5),
                stop_on_success=getattr(self, 'bruteforce_stop_on_success', False),
                throttle_delay=getattr(self, 'bruteforce_throttle', None)
            ),
        }
        
        func = module_map.get(module_name)
        if func:
            self.log("info", f"--- Running specific module: {module_name} ---")
            func()
            self.generate_reports(output_dir=self.output_dir)
        else:
            self.log("error", f"Module '{module_name}' not recognized. Available modules: {', '.join(sorted(module_map.keys()))}")

def main():
    parser = argparse.ArgumentParser(description="Bug Hunter Pro v.1 — For legal bug bounty hunting")
    parser.add_argument("url", help="Target URL (e.g., https://target.com)")
    parser.add_argument("--output-dir", default="report", help="Directory to save all reports")
    parser.add_argument("--cookie", help="Cookie for authenticated session")
    parser.add_argument("--proxy", help="Proxy to use (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--wordlist", help="Path to wordlist for Gobuster and bruteforce")
    parser.add_argument("--module", help="Run only a specific module (e.g., xss, ssrf_internal)")
    parser.add_argument("--yes", action="store_true", help="Skip initial confirmation")
    parser.add_argument("--dry-run", action="store_true", help="Run in dry-run mode (no active scanning)")
    parser.add_argument("--bruteforce-wordlist", help="Path to wordlist for bruteforce login")
    parser.add_argument("--bruteforce-username", help="Target username for bruteforce (optional)")
    parser.add_argument("--bruteforce-threads", type=int, default=5, help="Number of workers for bruteforce")
    parser.add_argument("--bruteforce-stop-on-success", action="store_true", help="Stop bruteforce after finding one valid credential")
    parser.add_argument("--bruteforce-throttle", type=float, default=None, help="Delay (seconds) between bruteforce attempts; defaults to --delay / config")
    parser.add_argument("--no-ports", action="store_true", help="Disable database port check")
    parser.add_argument("--deep-scan", action="store_true", help="Enable deep scan for backup files")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout for requests in seconds (default: 5)")
    parser.add_argument("--cf-bypass", action="store_true", help="Attempt to bypass CloudFlare protection")
    parser.add_argument("--cf-aggressive", action="store_true", help="Use more aggressive CloudFlare bypass techniques")
    parser.add_argument("--use-tor", action="store_true", help="Attempt bypass using Tor network")
    parser.add_argument("--modules", help="Run multiple specific modules, comma-separated (e.g., dbfinder,cfbypass)")

    args = parser.parse_args()

    if not re.match(r'^https?://', args.url):
        print(f"{Fore.YELLOW}URL does not have a scheme (http/https). Adding 'https://' by default.{Style.RESET_ALL}")
        args.url = 'https://' + args.url

    hunter = BugHunterPro(
        target=args.url,
        cookie=args.cookie,
        proxy=args.proxy,
        wordlist=args.wordlist
    )
    hunter.dry_run = bool(args.dry_run)
    bruteforce_opts = {
        'wordlist': args.bruteforce_wordlist,
        'username': args.bruteforce_username,
        'threads': args.bruteforce_threads,
        'stop_on_success': args.bruteforce_stop_on_success,
        'throttle': args.bruteforce_throttle
    }
    hunter.output_dir = args.output_dir
    hunter.enable_dbfinder = bool(args.deep_scan or (not args.no_ports))
    hunter.no_port_scan = bool(args.no_ports)
    hunter.db_deep_scan = bool(args.deep_scan)
    hunter.db_timeout = int(args.timeout)

    hunter.enable_cfbypass = bool(args.cf_bypass)
    hunter.cf_aggressive = bool(args.cf_aggressive)
    hunter.cf_use_tor = bool(args.use_tor)
    hunter.cf_timeout = int(args.timeout) if args.timeout else 10
    hunter.bruteforce_wordlist = args.bruteforce_wordlist
    hunter.bruteforce_username = args.bruteforce_username
    hunter.bruteforce_threads = args.bruteforce_threads
    hunter.bruteforce_stop_on_success = args.bruteforce_stop_on_success
    hunter.bruteforce_throttle = args.bruteforce_throttle

   
    if args.modules:
        
        modules_to_run = [m.strip() for m in args.modules.split(',')]
        print(f"{Fore.CYAN}Will run specific modules: {', '.join(modules_to_run)}{Style.RESET_ALL}")
        for module_name in modules_to_run:
            hunter.run_specific_module(module_name) 
        hunter.generate_reports(output_dir=hunter.output_dir)
    elif args.module:
        
        hunter.run_specific_module(args.module)
        hunter.generate_reports(output_dir=hunter.output_dir)
    else:
        
        hunter.run(auto_confirm=args.yes)

if __name__ == "__main__":
    main()