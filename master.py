# Copyright (c) 2024 cenmurong. All Rights Reserved.
#
# This tool is for educational purposes only. The author is not responsible for any
# misuse or damage caused by this program. Use at your own risk.

import subprocess
import os
import re
import shlex
import sys
import time
import threading

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
misc_path = os.path.join(SCRIPT_DIR, 'misc')
if misc_path not in sys.path:
    sys.path.insert(0, misc_path)

from mass_scan import run_mass_scan_from_crawler
from tools import BugHunterPro
from urllib.parse import urlparse
from queue import Queue, Empty
from colorama import init, Fore, Style
from tqdm import tqdm

init(autoreset=True)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = SCRIPT_DIR
TOOL_NAME = "Bug Hunter"
VERSION = "V1.5.5"

stop_event = None


def _get_timestamp():
    return time.strftime('%H:%M:%S', time.localtime())


def log(level, message):
    global stop_event
    if stop_event and stop_event.is_set():
        return
    timestamp = _get_timestamp()
    color_map = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "warn": Fore.YELLOW,
        "error": Fore.RED,
        "run": Fore.MAGENTA}
    icon_map = {
        "info": "[INFO]",
        "success": "[SUCCESS]",
        "warn": "[WARN]",
        "error": "[ERROR]",
        "run": "[RUN]"}
    color = color_map.get(level, Fore.WHITE)
    message = message.encode('ascii', errors='replace').decode('ascii')
    print(f"{color}[{timestamp}] {icon_map.get(level,
                                               ' ')} {message}{Style.RESET_ALL}")


def loading_animation():
    log("run", "Initializing Bug Hunter V1.5.5...")
    time.sleep(1)


def is_already_formatted_log(line):

    pattern = r'(\x1b\[\d+m)?\[\d{2}:\d{2}:\d{2}\]\s\[\w+\]'
    return re.match(pattern, line)


def _enqueue_output(out, queue):
    try:
        for line in iter(out.readline, ''):
            queue.put(line)
    finally:
        out.close()


def run_command(command):
    global stop_event
    try:
        log("run", f"Executing command: {command}")
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='ascii',
            errors='replace'
        )
        for line in iter(process.stdout.readline, ''):
            if stop_event and stop_event.is_set():
                process.terminate()
                log("warn", "Command terminated by user.")
                return -1
            log("info", line.strip())
        return_code = process.wait()
        return return_code
    except Exception as e:
        log("error", f"Command execution failed: {str(e)}")
        return -1


def display_banner():
    banner = """
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
#&&&#@@@@@&@@#7!..~??!^:.:^~~:.   :!!Y@&@&@@#&@@@
BJB@@@@@@@@&@@Y^!~  .~?JJ??~.      :~~.G@@@&@&#@@@
YY@@@@@@@@@@@G  7J    .~~:        .::  7@@@@&@@@@@
B@@@@@@@@@@&Y.   .::         . ....    .B@@@@@@@@@
@@@@@@@@@@P^           ^:   :^..        :P&@@@@@@@
@@@@@@@@@@G^            .7: :^.!^         :?#@@@@@
"""
    print(banner)


def display_menu():
    os.system('clear' if os.name == 'posix' else 'cls')
    display_banner()
    print(f"{Fore.YELLOW}=== {TOOL_NAME} {VERSION} Menu ==={Style.RESET_ALL}")
    print("1. Scan URL (Full Scan)")
    print("2. Scan URL (Specific Module)")
    print("3. Gather Targets (Dorking & Indexing)")
    print("4. Update Proxies")
    print("5. Mass Scan from Crawled URLs")
    print("0. Exit")
    print("-" * 40)


def find_report_files(directory):
    report_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                report_files.append(os.path.join(root, file))
    return report_files


def run_indexing(choices=None):
    global stop_event
    log("run", "Starting indexing process...")

    misc_path = os.path.join(SCRIPT_DIR, 'misc')
    if misc_path not in sys.path:
        sys.path.insert(0, misc_path)
    try:

        from indexing import SQLiIndexer, get_interactive_choices

        if choices is None:
            choices = get_interactive_choices()

        indexer = SQLiIndexer(**choices)
        indexer.run_indexing()
        log("success", "Indexing completed")
    except Exception as e:
        log("error", f"Indexing failed: {str(e)}")


def scan_single_url(full_scan=True, url=None, module=None, include_ssrf=True):
    global stop_event

    is_cli_call = url is None

    if url is None:
        url = input(
            f"{Fore.YELLOW}Enter URL to scan: {Style.RESET_ALL}").strip()

    if not url:
        log("error", "URL cannot be empty")
        return False

    log("warn", "These tools are for educational purposes only. Do not use them on government websites without official permission.")

    scan_output_dir = os.path.join(
        PROJECT_ROOT, "scan_results", f"scan_{
            _get_timestamp()}")
    os.makedirs(scan_output_dir, exist_ok=True)

    command = f"python3 {
        os.path.join(
            SCRIPT_DIR, 'misc', 'tools.py')} {
        shlex.quote(url)} --output-dir {
                shlex.quote(scan_output_dir)} --yes"
    if full_scan:
        command += " --deep-scan"
        if is_cli_call:
            confirm = input(
                f"Do you want to include internal SSRF scanning? (y/n, default: n): "
            ).lower()
            if confirm == 'n':
                include_ssrf = False
        if not include_ssrf:
            log("warn", "Internal SSRF scan will be skipped as per user request.")
            command += " --no-ssrf"
        else:
            log("info", "Internal SSRF scan enabled.")
        log("run", "Running full scan")
    else:

        if module is None:
            base_modules = "crawler,subfinder,httpx"
            additional_module = input(
                f"{
                    Fore.YELLOW}Enter additional module (e.g., xss, sql, or press Enter for none): {
                    Style.RESET_ALL}").strip()

            module = f"{base_modules},{additional_module}" if additional_module else base_modules

        command += f" --modules {shlex.quote(module)}"
        log("run", f"Running modules: {module}")

    rc = run_command(command)
    if rc != 0:
        log("error", f"Scan for {url} failed (exit code: {rc})")
        return False

    if stop_event and stop_event.is_set():
        log("info", "Scan terminated due to stop signal")
        return False

    report_files = find_report_files(scan_output_dir)
    if report_files:
        log("success",
            f"Scan complete. Found {len(report_files)} reports in '{scan_output_dir}'")
        for rp in report_files:
            print(f"  - {rp}")
    else:
        log("warn",
            f"Scan finished, but no 'report.json' found in '{scan_output_dir}'")
    return True


def run_proxy_downloader(auto_count=None):
    global stop_event
    log("run", "Running proxy downloader...")
    downloader_path = os.path.join(SCRIPT_DIR, "misc", "downloader.py")

    if not os.path.exists(downloader_path):
        log("error", f"'{downloader_path}' not found")
        return
    count = 50
    if auto_count:
        count = auto_count
    else:
        try:
            count = int(
                input(
                    f"{
                        Fore.YELLOW}How many active proxies to collect? (default: 50): {
                        Style.RESET_ALL}") or 50)
        except ValueError:
            log("warn", "Invalid input. Using default value of 50.")

    command = f"python3 {shlex.quote(downloader_path)} --count {count}"
    rc = run_command(command)
    if stop_event and stop_event.is_set():
        log("info", "Proxy download terminated due to stop signal")
        return
    if rc == 0:
        log("success", "Proxy download process completed")
    else:
        log("error", f"Proxy download failed with exit code: {rc}")


def main():
    global stop_event
    loading_animation()
    log("warn", "This tool is for educational purposes and security testing only. Do not use it on government websites without official permission.")

    while True:
        display_menu()
        choice = input(
            f"{Fore.YELLOW}Select an option: {Style.RESET_ALL}").strip()
        if not choice.isdigit():
            log("error", "Invalid choice. Please enter a number.")
            continue
        choice = int(choice)

        if choice == 1:
            scan_single_url(full_scan=True)
        elif choice == 2:
            scan_single_url(full_scan=False)
        elif choice == 3:
            run_indexing()
        elif choice == 4:
            run_proxy_downloader()
        elif choice == 5:
            run_mass_scan_from_crawler()
        elif choice == 0:
            log("info", "Thank you for using Bug Hunter V1. See you later!")
            sys.exit(0)
        else:
            log("error", "Invalid choice. Please try again.")

        if stop_event and stop_event.is_set():
            log("info", "Exiting due to stop signal")
            break

        input(
            f"\n{
                Fore.GREEN}Press Enter to return to the main menu...{
                Style.RESET_ALL}")


if __name__ == "__main__":
    main()
