import requests
import os
import sys
import random
from colorama import init, Fore, Style
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from tqdm import tqdm

init(autoreset=True)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOADS_DIR = os.path.join(SCRIPT_DIR, '..', 'payloads')
PROXY_FILE_PATH = os.path.join(PAYLOADS_DIR, 'proxies.txt')


def check_proxy(proxy):
    """Checks if a proxy is active with a short timeout."""
    try:
        response = requests.get("http://httpbin.org/ip",
                                proxies={'http': proxy, 'https': proxy},
                                timeout=7)
        if response.status_code == 200:
            return proxy
    except requests.exceptions.RequestException:
        pass
    return None


def log(level, message):
    """Simple logging function for the downloader."""
    color_map = {
        "info": Fore.CYAN,
        "success": Fore.GREEN,
        "warn": Fore.YELLOW,
        "error": Fore.RED,
        "run": Fore.MAGENTA
    }
    icon_map = {
        "info": "[INFO]",
        "success": "[SUCCESS]",
        "warn": "[WARN]",
        "error": "[ERROR]",
        "run": "[RUN]"}
    color = color_map.get(level, Fore.WHITE)
    print(f"{color}{icon_map.get(level, ' ')} {message}{Style.RESET_ALL}")


def collect_and_save_proxies():
    """Fetches a list of free proxies from public sources and saves them to a file."""
    parser = argparse.ArgumentParser(
        description="Proxy Downloader and Verifier.")
    parser.add_argument(
        "--count",
        type=int,
        default=50,
        help="The number of active proxies to collect.")
    args = parser.parse_args()
    desired_count = args.count

    log("run",
        f"Collecting raw proxy list, targeting {desired_count} active proxies...")
    proxy_sources = [
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"
    ]

    initial_proxies = set()
    for source in proxy_sources:
        try:
            response = requests.get(source, timeout=15)
            if response.status_code == 200:
                proxies = response.text.strip().split('\n')
                for p in proxies:
                    p_clean = p.strip().replace("http://", "")
                    if p_clean:
                        initial_proxies.add(p_clean)
        except requests.RequestException as e:
            log("warn",
                f"Failed to fetch proxies from {source.split('/')[2]}: {e}")

    if not initial_proxies:
        log("error", "Failed to collect proxies from all sources.")
        return False

    log(
        "info",
        f"Collected {
            len(initial_proxies)} raw proxies. Verifying until {desired_count} active proxies are found...")

    active_proxies = set()
    with ThreadPoolExecutor(max_workers=100) as executor:
        shuffled_proxies = list(initial_proxies)
        random.shuffle(shuffled_proxies)
        futures = {executor.submit(check_proxy, proxy)
                   for proxy in shuffled_proxies}
        with tqdm(total=desired_count, desc="Checking Proxies", ascii=True) as pbar:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    active_proxies.add(result)
                    pbar.update(1)
                if len(active_proxies) >= desired_count:
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

    if active_proxies:
        os.makedirs(os.path.dirname(PROXY_FILE_PATH), exist_ok=True)
        with open(PROXY_FILE_PATH, 'w', encoding='utf-8') as f:
            for proxy in active_proxies:
                f.write(proxy + '\n')
        log(
            "success", f"Successfully saved {
                len(active_proxies)} active proxies to {
                os.path.basename(PROXY_FILE_PATH)}.")
        return True
    else:
        log("error", "No active proxies were found after verification.")
        return False


if __name__ == "__main__":
    if not collect_and_save_proxies():
        sys.exit(1)
