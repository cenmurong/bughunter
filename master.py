import subprocess
import os
import shlex
import sys
import time
from colorama import init, Fore, Style
init(autoreset=True)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
TOOL_NAME = "Bug Hunter"
VERSION = "V.1"

def log(level, message):
    """Logging function with color."""
    color_map = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "warn": Fore.YELLOW,
        "error": Fore.RED,
        "run": Fore.MAGENTA
    }
    icon_map = {"info": "ℹ️", "success": "✅", "warn": "⚠️", "error": "❌", "run": "🚀"}
    color = color_map.get(level, Fore.WHITE)
    print(f"{color}{icon_map.get(level, ' ')} {message}{Style.RESET_ALL}")

def run_command(command, interactive=False):
    """Run a shell command safely and display the output in real-time."""
    try:
        if interactive:
            return subprocess.run(command, shell=True, check=True).returncode
        else:
            args = shlex.split(command)
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    print(output.strip())
            return process.poll()
    except Exception as e:
        log("error", f"Failed to run command: {e}")
        return 1

def find_latest_output_dir():
    """Find the latest output directory from indexing.py."""
    output_base_dir = "output"
    if not os.path.isdir(output_base_dir):
        return None
    
    all_subdirs = [os.path.join(output_base_dir, d) for d in os.listdir(output_base_dir) if os.path.isdir(os.path.join(output_base_dir, d))]
    if not all_subdirs:
        return None
        
    latest_subdir = max(all_subdirs, key=os.path.getmtime)
    return latest_subdir

def find_report_files(base_dir):
    """Find all report.json files in the scan directory."""
    json_files = []
    if not os.path.isdir(base_dir):
        return []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file == "report.json":
                json_files.append(os.path.join(root, file))
    return json_files

def display_menu():
    """Display the main menu with a more attractive banner."""
    banner = rf"""
{Fore.CYAN}{'='*68}
8888b. db    db  d888b  db   db db    db d8b   db d888888b d88888b d8888b. 
88  `8D 88    88 88' Y8b 88   88 88    88 888o  88 `~~88~~' 88'     88  `8D 
88oooY' 88    88 88      88ooo88 88    88 88V8o 88    88    88ooooo 88oobY' 
88~~~b. 88    88 88  ooo 88~~~88 88    88 88 V8o88    88    88~~~~~ 88`8b   
88   8D 88b  d88 88. ~8~ 88   88 88b  d88 88  V888    88    88.     88 `88. 
Y8888P' ~Y8888P'  Y888P  YP   YP ~Y8888P' VP   V8P    YP    Y88888P 88   YD {Fore.YELLOW}{Style.BRIGHT}{VERSION}{Style.RESET_ALL}
{Fore.CYAN}{'='*68}{Style.RESET_ALL}
"""
    print(banner)
    print(Fore.GREEN + "   🕵️  Menu---")
    print("  [1] Gather Targets (Dorking & Indexing)")
    print("  [2] Scan URL (Full Scan)")
    print("  [3] Download/Update Proxy List")
    print("\n  [0] Exit")
    print()
    print(Fore.CYAN + Style.BRIGHT + "="*68)

def run_indexing():
    """Step 1: Run Indexing."""
    indexing_script_path = os.path.join(SCRIPT_DIR, "misc", "indexing.py")
    log("run", "Step 1: Running 'indexing.py' to gather targets.")
    if not os.path.exists(indexing_script_path):
        log("error", "'misc/indexing.py' not found. Make sure the folder structure is correct.")
        return False

    if run_command(f"cd {shlex.quote(PROJECT_ROOT)} && python3 {shlex.quote(os.path.join('tools', 'misc', 'indexing.py'))}", interactive=True) != 0:
        log("error", "Process 'indexing.py' failed or was canceled.")
        return False
    
    log("success", "Process 'indexing.py' completed.")
    return True


def scan_single_url():
    """Running a scan for a single URL."""
    url = input(f"\n{Fore.YELLOW}Enter the URL to scan: {Style.RESET_ALL}").strip()
    if not url:
        log("warn", "URL cannot be empty.")
        return False

    if not url.startswith('http://') and not url.startswith('https://'):
        log("info", "URL does not have a scheme (http/https). Adding 'https://' by default.")
        url = 'https://' + url

    tools_script_path = os.path.join(SCRIPT_DIR, "misc", "tools.py")
    if not os.path.exists(tools_script_path):
        log("error", f"'{tools_script_path}' not found. Make sure the folder structure is correct.")
        return False

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    scan_output_dir = os.path.join(PROJECT_ROOT, "scan_results", f"scan_{timestamp}")
    os.makedirs(scan_output_dir, exist_ok=True)
    log("run", f"Starting scan: {url}")
    log("info", f"Scan results will be saved in: {scan_output_dir}")
    command = f"python3 {shlex.quote(tools_script_path)} {shlex.quote(url)} --output-dir {shlex.quote(scan_output_dir)} --yes"
    log("run", "Activating ALL scan modules (Full Scan)")
    rc = run_command(command, interactive=True)
    if rc != 0:
        log("error", f"Scan process for {url} failed (exit code: {rc}). See terminal output for details.")
        return False
    report_files = find_report_files(scan_output_dir)
    if report_files:
        log("success", f"Scan complete. Found {len(report_files)} reports in '{scan_output_dir}'")
        for rp in report_files:
            print(f"  - {rp}")
    else:
        log("warn", f"Scan finished, but no 'report.json' file was found in '{scan_output_dir}'")

    return True
    
def run_internal_pentest():
    """Running internal pentest (SSRF) on a single URL."""
    url = input(f"\n{Fore.YELLOW}Enter the URL to be tested for Internal SSRF: {Style.RESET_ALL}").strip()
    if not url:
        log("warn", "URL cannot be empty.")
        return False

    tools_script_path = os.path.join(SCRIPT_DIR, "misc", "tools.py")
    log("run", f"Starting Internal Pentest for {url} with 'tools.py'.")
    if not os.path.exists(tools_script_path):
        log("error", "'misc/tools.py' not found.")
        return False

    scan_output_dir = os.path.join(PROJECT_ROOT, "scans", f"internal_pentest_{int(time.time())}")
    os.makedirs(scan_output_dir, exist_ok=True)
    log("info", f"Scan results will be saved in: {scan_output_dir}")

    command = f"python3 {shlex.quote(tools_script_path)} {shlex.quote(url)} --output-dir {shlex.quote(scan_output_dir)} --module ssrf_internal"
    run_command(command, interactive=True)
    log("success", f"Internal Pentest for {url} completed.")
    return True

def run_proxy_downloader():
    """Running the proxy downloader from utilities."""
    log("run", "Running proxy downloader...")
    downloader_path = os.path.join(SCRIPT_DIR, "misc", "downloader.py")
    if not os.path.exists(downloader_path):
        log("error", f"'{downloader_path}' not found.")
        return
    
    try:
        count = int(input(f"{Fore.YELLOW}How many active proxies do you want to collect? (default: 50): {Style.RESET_ALL}") or 50)
    except ValueError:
        count = 50

    run_command(f"python3 {shlex.quote(downloader_path)} --count {count}", interactive=True)
    log("success", "Proxy download process completed.")

def main():
    """Main function to display the menu and run the workflow."""
    while True:
        display_menu()
        choice = input(f"{Fore.YELLOW}Select an option (1-3): {Style.RESET_ALL}")

        if choice == '1':
            run_indexing()
        elif choice == '2':
            scan_single_url()
        elif choice == '3':
            run_proxy_downloader()
        elif choice == '0':
            log("info", "Thank you for using Bug Hunter V1. See you later!")
            sys.exit(0)
        else:
            log("error", "Invalid choice. Please try again.")
        
        input(f"\n{Fore.GREEN}Press Enter to return to the main menu...{Style.RESET_ALL}")

if __name__ == "__main__":
    main()