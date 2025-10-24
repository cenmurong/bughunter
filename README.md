# Bug Hunter V1.1
```
d8888b. db    db  d888b  db   db db    db d8b   db d888888b d88888b d8888b. 
88  `8D 88    88 88' Y8b 88   88 88    88 888o  88 `~~88~~' 88'     88  `8D 
88oooY' 88    88 88      88ooo88 88    88 88V8o 88    88    88ooooo 88oobY' 
88~~~b. 88    88 88  ooo 88~~~88 88    88 88 V8o88    88    88~~~~~ 88`8b   
88   8D 88b  d88 88. ~8~ 88   88 88b  d88 88  V888    88    88.     88 `88. 
Y8888P' ~Y8888P'  Y888P  YP   YP ~Y8888P' VP   V8P    YP    Y88888P 88   YD V1.1
```

If you find this tool useful, don't forget to **star ⭐** this repository and **follow my GitHub account** for future projects\!

## Key Features

  * **Interactive Menu:** An easy-to-use interface (`master.py`) to run various scan modes.
  * **Flexible Scan Modes:**
      * **Full Scan:** Runs all modules, deep scan, port scan, CF bypass, and auto-register.
      * **Specific Module Scan:** Allows you to run only specific modules (e.g., `xss`, `sqli`, `ssrf_internal`).
  * **In-Depth Reconnaissance:**
      * Integration with **Subfinder** for subdomain discovery.
      * Integration with **httpx** to find live web servers.
  * **Dynamic Crawling:** Uses **Playwright** for deep crawling on modern (JavaScript-heavy) web applications to discover more endpoints and parameters.
  * **External Tool Integration:**
      * Uses **Nuclei** for template-based scanning.
      * Uses **Nmap** for port scanning and service detection.
  * **Bypass & Evasion:**
      * Includes CloudFlare bypass attempts (using `cloudscraper` and Playwright).
      * Uses various User-Agents and WAF Bypass payloads.
  * **Comprehensive Reporting:** Automatically generates reports in multiple formats (`.html`, `.json`, `.md`, `.csv`) in the `scan_results` directory, complete with an interactive dashboard.
  * **Configurable:** All payloads and settings (like common paths, API paths, and user agents) can be customized via the `config.json` file.
  * **Other Features:** Includes a proxy downloader, login bruteforce, and automatic user registration attempts.

## Modules (Vulnerabilities Checked)

`BugHunterPro` (`tools.py`) comes with modules to test a wide range of vulnerability categories:

  * **Injection:**
      * Cross-Site Scripting (XSS)
      * SQL Injection (Error-based & Time-based)
      * Server-Side Template Injection (SSTI)
      * OS Command Injection
      * CRLF Injection
      * NoSQL Injection
      * XML External Entity (XXE)
  * **Broken Access Control:**
      * Insecure Direct Object Reference (IDOR)
      * Local File Inclusion (LFI)
      * Remote File Inclusion (RFI)
      * Cross-Site Request Forgery (CSRF)
  * **Server-Side Request Forgery (SSRF):**
      * Regular SSRF checks
      * Out-of-Band (OAST) SSRF checks
      * Internal service access checks
  * **Security Misconfiguration:**
      * Missing Security Headers
      * CORS Misconfiguration
      * Insecure File Upload
      * GraphQL Introspection
      * OAuth Misconfiguration
      * Default Credentials
  * **Data Exposure & Leaks:**
      * API Token Leaks (in JS files)
      * API Endpoint Leakage
      * Session Fixation
  * **Miscellaneous:**
      * Open Redirect
      * JWT Misconfiguration
      * Prototype Pollution
      * WAF Bypass

## Installation

1.  **Clone this repository:**

    ```bash
    git clone https://github.com/cenmurong/bughunter
    cd bughunter
    ```

2.  **Install Python dependencies:**
    Make sure you have **Python 3.8+**.

    ```bash
    pip install -r requirements.txt
    ```

3.  **Install Playwright browsers:**
    (Required for dynamic crawling and CF bypass)

    ```bash
    playwright install
    ```

4.  **Install External Dependencies (REQUIRED):**
    This tool relies on several popular Go-based tools. Ensure you have [Go installed](https://go.dev/doc/install) and your `GOPATH` is set up correctly.

    ```bash
    # Install nuclei
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

    # Install subfinder
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

    # Install httpx
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    ```

    You also need **Nmap**. Install it using your system's package manager:

    ```bash
    # On Debian/Ubuntu
    sudo apt update && sudo apt install nmap

    # On macOS (using Homebrew)
    brew install nmap
    ```

    **IMPORTANT:** Ensure all these binaries (`nuclei`, `subfinder`, `httpx`, `nmap`) are accessible from your system's `PATH`.

## Usage

### 1\. Primary Usage (Interactive Menu)

Run the `master.py` script to display the menu:

```bash
python3 master.py
```

#### Menu Options

  * **[1] Gather Targets (Dorking & Indexing)**

      * Runs the `misc/indexing.py` script to gather targets based on dorks in `payloads/dork.txt`.
      * Results are saved in the `output` directory.

  * **[2] Scan URL (Full Scan)**

      * Asks for a target URL.
      * Runs a full scan using `tools.py` with all features enabled (`--deep-scan`, `--full-port-scan`, `--cf-bypass`, `--auto-register`).
      * You will be asked if you want to include the SSRF scan (which can be time-consuming).

  * **[3] Scan URL (Specific Module)**

      * Asks for a target URL and the name of the module to run.
      * Module examples: `xss`, `sqli`, `lfi`, `ssrf_internal`, `security_headers`.
      * See the full list of modules above or in `tools.py` (the `run_specific_module` function).

  * **[4] Download/Update Proxy List**

      * Runs the `misc/downloader.py` script to download a new proxy list.

  * **[0] Exit**

      * Exits the application.

### 2\. Advanced Usage (Directly via `tools.py`)

You can also run `tools.py` directly for more granular control.

**Example: Run a specific module with a cookie**

```bash
python3 misc/tools.py https://target.com --module xss --cookie "session=..."
```

**Example: Run multiple modules**

```bash
python3 misc/tools.py https://target.com --modules "lfi,sqli,ssti"
```

**Example: Run a full scan (like Option 2) from the command line**

```bash
python3 misc/tools.py https://target.com --deep-scan --full-port-scan --cf-bypass --auto-register --yes
```

Use `-h` to see all available flags:

```bash
python3 misc/tools.py -h
```
```
xss, sqli, ssti, lfi, rfi, crlf, command_injection, xxe, nosql_injection, ssrf, ssrf_internal, open_redirect, csrf, idor, file_upload, cors, graphql, default_creds, oauth, security_headers, waf_bypass, api_leakage, jwt, prototype_pollution, session_fixation, api_token_leak
```
## Configuration

You can customize payloads, user-agents, and paths by editing the `config.json` file directly.

## Connect With Me

<p>
  <a href="https://x.com/cenmurong"><img src="https://img.shields.io/badge/X-000000?style=for-the-badge&logo=x&logoColor=white" /></a>
  <a href="https://discord.com/users/451101979331002370"><img src="https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white" /></a>
  <a href="https://instagram.com/asaptrfr"><img src="https://img.shields.io/badge/Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white" /></a>
</p>

## Disclaimer

This tool is created for educational and security research purposes. The user is fully responsible for all actions taken using this tool. Do not use this tool for illegal activities.

## License

[cenmurong](https://github.com/cenmurong). All Rights Reserved.
Please include the original source if you copy or use this code.
