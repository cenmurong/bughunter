import subprocess
import os
import shlex
import sys
import time
from urllib.parse import urlparse
from colorama import init, Fore, Style
from tqdm import tqdm
init(autoreset=True)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = SCRIPT_DIR 
TOOL_NAME = "Bug Hunter"
VERSION = "V.1"

def _get_timestamp():
    return time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())

def log(level, message):
    """Logging function with color and WIB timestamp."""
    timestamp = _get_timestamp()
    color_map = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "warn": Fore.YELLOW,
        "error": Fore.RED,
        "run": Fore.MAGENTA
    }
    icon_map = {"info": "[INFO]", "success": "[SUCCESS]", "warn": "[WARN]", "error": "[ERROR]", "run": "[RUN]"}
    color = color_map.get(level, Fore.WHITE)
    message = message.encode('ascii', errors='replace').decode('ascii') 
    print(f"{color}[{timestamp}] {icon_map.get(level, ' ')} {message}{Style.RESET_ALL}")

def loading_animation():
    """Displays a top-to-bottom loading animation with the banner."""
    log("run", "Initializing Bug Hunter V1.1...")
    time.sleep(1) 
    
    banner_lines = rf"""{Fore.WHITE}
@&@&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&@@@
@&&&@@@@@@@@&@@@@@#B@@&&@@@@@@@@@@@@@@@@&@@@@@&@@@
@@&&&@@@@@@@&&@@@@?B@&J#@&@@@@@@&@@@&&@@&@@@@&&@@@
@@@@&@@@@@&&B&@@@YJ@&?7@@@@@@@&J#@&5G#@@&&@@@&&@@@
@G7&@&@@&@BBGB&@#!#G!:G@@@&#&#7J@#7?5B##@&@@#&@@&@
&&!P@@@@5##7?JPP&G5!^5@@&GJPGY5BY!7Y?55B#&@&&&@G~#
!@B~&@@@BG&PPP5P#P^^7BP?~:^^:?77?YPPGGP&G&&&&@#!5!
7P@!?@@@@5Y7~J?Y55?:77.   ....7?5J7??^7JG&&@@#7B5 
J^B&??5P#5:~^~!^~::^.  .     .:.:~~~^^:~B@&#Y~PP7:
!!#@P:^!YJ....        :             :?B#P?^7GB~!.
.^!7G@&5Y.~7^.         ^          .:7J7!:?#&&G~:. 
  .:.~P&@5  ..        .:          ...   ~@&GPJ    
       ^7P?           :!: .            ^&#PY!     
       :J#@?           .^             :#@@BJ^     
     :7G@@@@Y.      ::::.:::..       ^B@@@@@@@5^   
   .!G&@@@@@@#7:    .....::..:.    .7?&@@@@@@@&J. 
. ^5B&#B@@@@@@???^.      ..     .:^^!~@@@@@@&@@@B!
 ~#&#BG&@@@@&@Y.Y!77^        .:^^. .~.#@@&&@#&@@@#
7#&&&#@@@@@&@@#7!..~??!^:.:^~~:.   :!!Y@&@&@@#&@@@
BJB@@@@@@@@&@@Y^!~  .~?JJ??~.      :~~.G@@@&@&#@@@
YY@@@@@@@@@@@G  7J    .~~:        .::  7@@@@&@@@@@
B@@@@@@@@@@&Y.   .::         . ....    .B@@@@@@@@@
@@@@@@@@@@P^           ^:   :^..        :P&@@@@@@@
@@@@@@@@G^            .7: :^.!^           :?#@@@@@
""".strip().split('\n')

    os.system('cls' if os.name == 'nt' else 'clear') 
    for line in banner_lines:
        print(line)
        time.sleep(0.05) 

    time.sleep(1) 

def run_command(command, interactive=False):
    """Run a shell command safely and display output in real-time."""
    try:
        if interactive:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='ascii', errors='replace')
            for line in tqdm(process.stdout, desc="Running command", unit="line", ascii=True):
                line = line.encode('ascii', errors='replace').decode('ascii') 
                print(line.strip())
            return_code = process.wait()
        else:
            args = shlex.split(command)
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='ascii', errors='replace')
            for line in tqdm(process.stdout, desc="Running command", unit="line", ascii=True):
                line = line.encode('ascii', errors='replace').decode('ascii') 
                print(line.strip())
            return_code = process.poll()
        if return_code != 0:
            log("error", f"Command failed with exit code {return_code}")
        return return_code
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.encode('ascii', errors='replace').decode('ascii') if e.stderr else "Unknown error"
        log("error", f"Command failed with exit code {e.returncode}: {error_msg}")
        return 1
    except FileNotFoundError as e:
        log("error", f"Command not found: {str(e).encode('ascii', errors='replace').decode('ascii')}")
        return 1
    except Exception as e:
        log("error", f"Failed to run command: {str(e).encode('ascii', errors='replace').decode('ascii')}")
        return 1

def find_latest_output_dir():
    """Find the latest output directory from indexing.py."""
    output_base_dir = "output"
    if not os.path.isdir(output_base_dir):
        log("warn", f"Output directory {output_base_dir} not found")
        return None
    all_subdirs = [os.path.join(output_base_dir, d) for d in os.listdir(output_base_dir) if os.path.isdir(os.path.join(output_base_dir, d))]
    if not all_subdirs:
        log("warn", "No subdirectories found in output directory")
        return None
    latest_subdir = max(all_subdirs, key=os.path.getmtime)
    return latest_subdir

def find_report_files(base_dir):
    """Find all report.json files in the scan directory."""
    json_files = []
    if not os.path.isdir(base_dir):
        log("warn", f"Directory {base_dir} does not exist")
        return []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file == "report.json":
                json_files.append(os.path.join(root, file))
    return json_files

def display_menu():
    """Display the main menu with available options."""
    print() 
    print(Fore.GREEN + "            BUG HUNTER V 1.1")
    print("  [1] Gather Targets (Dorking & Indexing)")
    print("  [2] Scan URL (Full Scan)")
    print("  [3] Scan URL (Specific Module)")
    print("  [4] Download/Update Proxy List")
    print("\n  [0] Exit")
    print(Fore.CYAN + Style.BRIGHT + ""*1)
    print(Fore.YELLOW + "Available Modules for Specific Scan Please Check on README.md")

def run_indexing():
    """Step 1: Run Indexing."""
    indexing_script_path = os.path.join(SCRIPT_DIR, "misc", "indexing.py")
    log("run", "Step 1: Running 'indexing.py' to gather targets")
    if not os.path.exists(indexing_script_path):
        log("error", "'misc/indexing.py' not found. Ensure folder structure is correct")
        return False
    command = ["python3", os.path.join("misc", "indexing.py")]
    if run_command(" ".join(command), interactive=True) != 0:
        log("error", "Process 'indexing.py' failed or was canceled")
        return False
    log("success", "Process 'indexing.py' completed")
    return True

def scan_single_url(full_scan=True, module=None):
    """Run a scan for a single URL."""
    url = input(f"\n{Fore.YELLOW}Enter the URL to scan: {Style.RESET_ALL}").strip()
    if not url:
        log("warn", "URL cannot be empty")
        return False
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        log("info", "URL does not have a valid scheme or netloc. Applying default scheme...")
        if 'localhost' in url or '127.0.0.1' in url or 'testphp.vulnweb.com' in url:
            url = 'http://' + url
        else:
            url = 'https://' + url
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            log("error", f"Invalid URL: {url}")
            return False

    tools_script_path = os.path.join(SCRIPT_DIR, "misc", "tools.py")
    if not os.path.exists(tools_script_path):
        log("error", f"'{tools_script_path}' not found")
        return False

    timestamp = _get_timestamp()
    scan_output_dir = os.path.join(PROJECT_ROOT, "scan_results", f"scan_{timestamp}")
    os.makedirs(scan_output_dir, exist_ok=True)
    log("run", f"Starting scan: {url}")
    log("info", f"Scan results will be saved in: {scan_output_dir}")

    command = f"python3 {shlex.quote(tools_script_path)} {shlex.quote(url)} --output-dir {shlex.quote(scan_output_dir)} --yes"
    if full_scan:
        command += " --deep-scan --full-port-scan --cf-bypass --auto-register"
        log("run", "Running Full Scan with all features enabled:")
        log("info", "- Deep Scan & Full Port Scan")
        log("info", "- CloudFlare Bypass Attempt")
        log("info", "- Automatic Registration & Login Bruteforce")

        use_ssrf = input(f"{Fore.YELLOW}Do you want to include SSRF scan? (y/n, default: y): {Style.RESET_ALL}").lower().strip()
        if use_ssrf == 'n':
            command += " --no-ssrf"
            log("info", "SSRF scan will be skipped.")
        else:
            log("info", "SSRF scan will be included.")
    else:
        if module:
            command += f" --module {shlex.quote(module)}"
            log("run", f"Running specific module: {module}")
        else:
            module = input(f"{Fore.YELLOW}Enter module name (e.g., xss, oauth, security_headers): {Style.RESET_ALL}").strip()
            if not module:
                log("warn", "Module name cannot be empty")
                return False
            command += f" --module {shlex.quote(module)}"
            log("run", f"Running specific module: {module}")

    rc = run_command(command, interactive=True)
    if rc != 0:
        log("error", f"Scan for {url} failed (exit code: {rc})")
        return False

    report_files = find_report_files(scan_output_dir)
    if report_files:
        log("success", f"Scan complete. Found {len(report_files)} reports in '{scan_output_dir}'")
        for rp in report_files:
            print(f"  - {rp}")
    else:
        log("warn", f"Scan finished, but no 'report.json' found in '{scan_output_dir}'")
    return True

def run_proxy_downloader():
    """Run the proxy downloader from utilities."""
    log("run", "Running proxy downloader...")
    downloader_path = os.path.join(SCRIPT_DIR, "misc", "downloader.py")
    if not os.path.exists(downloader_path):
        log("error", f"'{downloader_path}' not found")
        return
    try:
        count = int(input(f"{Fore.YELLOW}How many active proxies to collect? (default: 50): {Style.RESET_ALL}") or 50)
    except ValueError:
        count = 50
    command = f"python3 {shlex.quote(downloader_path)} --count {count}"
    run_command(command, interactive=True)
    log("success", "Proxy download process completed")

def main():
    """Main function to display the menu and run the workflow."""
    loading_animation()
    while True:
        display_menu()
        choice = input(f"{Fore.YELLOW}Select an option: {Style.RESET_ALL}").strip()

        if choice == '1':
            run_indexing()
        elif choice == '2':
            scan_single_url(full_scan=True)
        elif choice == '3':
            scan_single_url(full_scan=False)
        elif choice == '4':
            run_proxy_downloader()
        elif choice == '0':
            log("info", "Thank you for using Bug Hunter V1. See you later!")
            sys.exit(0)
        else:
            log("error", "Invalid choice. Please try again.")
        
        input(f"\n{Fore.GREEN}Press Enter to return to the main menu...{Style.RESET_ALL}")

def run_proxy_downloader(auto_count=None):
    """Run the proxy downloader from utilities."""
    log("run", "Running proxy downloader...")
    downloader_path = os.path.join(SCRIPT_DIR, "misc", "downloader.py")
    if not os.path.exists(downloader_path):
        log("error", f"'{downloader_path}' not found")
        return
    count = auto_count or int(input(f"{Fore.YELLOW}How many active proxies to collect? (default: 50): {Style.RESET_ALL}") or 50)
    command = f"python3 {shlex.quote(downloader_path)} --count {count}"
    run_command(command, interactive=True)
    log("success", "Proxy download process completed")

if __name__ == "__main__":
    main()