import eel
import threading
from master import run_indexing, scan_single_url, run_proxy_downloader, log
import sys
import time
from datetime import datetime
import pytz
import pyautogui


wib = pytz.timezone('Asia/Jakarta')


stop_event = threading.Event()

if 'master' in sys.modules:
    sys.modules['master'].stop_event = stop_event


def gui_log(level, message):
    if level == "raw":
        eel.addLog(message, "white")
        return

    timestamp = datetime.now(wib).strftime('%H:%M:%S')
    color_map = {
        "info": "cyan",
        "success": "green",
        "warn": "yellow",
        "error": "red",
        "run": "magenta"
    }
    icon_map = {
        "info": "[INFO]",
        "success": "[SUCCESS]",
        "warn": "[WARN]",
        "error": "[ERROR]",
        "run": "[RUN]"
    }
    color = color_map.get(level, "black")
    icon = icon_map.get(level, " ")
    log_message = f"[{timestamp}] {icon} {message}"
    if 'master' in sys.modules:
        sys.modules['master'].log = gui_log
    eel.addLog(log_message, color)
    eel.sleep(0.01)


def run_with_stop(event, func, *args, **kwargs):
    result = False
    try:

        result = func(*args, **kwargs)
        if event.is_set():
            gui_log("info", "Process was stopped by user.")
    except Exception as e:
        gui_log("error", f"Process interrupted or failed: {str(e)}")
    finally:
        event.clear()
        eel.updateStopButtonState(False)
        eel.resetGuiState()
        return result


@eel.expose
def start_indexing():
    gui_log("warn", "Indexing hanya bisa dilakukan di CLI")
    eel.showDialog(
        "Fitur indexing hanya dapat dijalankan melalui antarmuka baris perintah (CLI).",
        "alert",
        lambda _: None)
    return {"status": "ok", "value": None}


@eel.expose
def start_scan(full_scan, url, module=None, include_ssrf=True, callback=None):
    if not stop_event.is_set():
        stop_event.clear()
        eel.updateStopButtonState(True)
        if not url and full_scan:
            gui_log("error", "URL cannot be empty")
            if callback:
                callback(False)
            return None

        final_modules_str = None
        if full_scan:
            mode = "Full Scan"
        else:

            base_modules = ["crawler", "subfinder", "httpx"]
            if module:
                additional_modules = [m.strip() for m in module.split(
                    ',') if m.strip() and m not in base_modules]
                final_modules_list = base_modules + additional_modules
            else:
                final_modules_list = base_modules
            final_modules_str = ",".join(final_modules_list)
            mode = f"Specific Modules: {final_modules_str}"

        gui_log(
            "info",
            f"Starting {mode}: url={url}, include_ssrf={include_ssrf}")

        def scan_wrapper():
            result = run_with_stop(
                stop_event,
                scan_single_url,
                full_scan=full_scan,
                url=url,
                module=final_modules_str,
                include_ssrf=include_ssrf)
            if callback:
                eel._execute_callback(callback, result)
        threading.Thread(target=scan_wrapper, daemon=True).start()
        return None
    else:
        gui_log("warn", "Another process is running or was stopped.")
        if callback:
            callback(False)
        return None


@eel.expose
def start_proxy_downloader(count, callback=None):
    if not stop_event.is_set():
        stop_event.clear()
        eel.updateStopButtonState(True)
        try:
            count = int(count) if count else 0
        except ValueError:
            count = 50
        gui_log("info", f"Starting proxy downloader with count: {count}")
        threading.Thread(
            target=lambda: run_with_stop(
                stop_event,
                run_proxy_downloader,
                auto_count=count),
            daemon=True).start()
        return None
    else:
        gui_log("warn", "Another process is running or was stopped.")
        return None


@eel.expose
def stop_process():
    if not stop_event.is_set():
        gui_log("info", "Sending stop signal...")
        stop_event.set()
        eel.updateStatus("Stopping process...")
        return {"status": "ok", "value": None}
    else:
        gui_log("warn", "Stop signal already sent.")
        return {"status": "ok", "value": None}


if __name__ == "__main__":
    eel.init('gui')
    gui_log("run", "Initializing Bug Hunter GUI...")
    try:

        screen_width, screen_height = pyautogui.size()

        window_width, window_height = 1000, 900

        left = (screen_width - window_width) // 2
        top = (screen_height - window_height) // 2

        eel.start(
            'index.html', size=(
                window_width, window_height), position=(
                left, top), port=0)
    except EnvironmentError as e:
        if "Can't find Google Chrome/Chromium installation" in str(e):
            print("\n" + "="*80)
            print(
                "ERROR: Google Chrome or Chromium browser is not installed or not found by Eel.")
            print("Please install Google Chrome or Chromium to run the GUI.")
            print("  - For Windows/macOS: Download from google.com/chrome")
            print("  - For Linux (Debian/Ubuntu): sudo apt install chromium-browser")
            print("  - For Linux (Fedora): sudo dnf install chromium")
            print("="*80 + "\n")
        else:
            print(f"An unexpected environment error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
