
import os
import sys
import json
import time
import hashlib
import getpass
from pathlib import Path

import requests

# =========================
# CONFIG
# =========================

VERSION = "5.1"
BASE_URL = "https://www.virustotal.com/api/v3"

CONFIG_DIR = Path.home() / ".vt_scanner"
CONFIG_FILE = CONFIG_DIR / "config.json"
STORAGE = Path.home() / "storage" / "shared"

TIMEOUT = 30
MAX_UPLOAD_SIZE = 32 * 1024 * 1024

# =========================
# COLOR THEME
# =========================

RESET = "\033[0m"
BOLD = "\033[1m"

YELLOW = "\033[93m"
GREEN = "\033[92m"
LIGHT_GREEN = "\033[96m"
RED = "\033[91m"
DEEP_RED = "\033[38;5;196m"
DARK_RED = "\033[1;38;5;160m"

def yellow(t):
    return f"{YELLOW}{t}{RESET}"

def green(t):
    return f"{GREEN}{t}{RESET}"

def light_green(t):
    return f"{LIGHT_GREEN}{t}{RESET}"

def red(t):
    return f"{RED}{t}{RESET}"

def deep_red(t):
    return f"{DEEP_RED}{BOLD}{t}{RESET}"

def dark_red(t):
    return f"{DARK_RED}{t}{RESET}"

# =========================
# UI
# =========================

def clear():
    os.system("clear")

def line():
    print(yellow("─" * 48))

def header():
    clear()
    print(yellow("╔" + "═" * 46 + "╗"))
    print(yellow("║") + yellow("           VT SCANNER v" + VERSION + "              ") + yellow("║"))
    print(yellow("║") + yellow("           VIRUSTOTAL API TOOL                ") + yellow("║"))
    print(yellow("╚" + "═" * 46 + "╝"))
    print()

def pause():
    input(yellow("\nPress ENTER to continue..."))

def menu_item(number, title):
    print(yellow(f"  [{number}] {title}"))

def spinner(message, duration=1):
    symbols = ["|", "/", "-", "\\"]
    end = time.time() + duration

    while time.time() < end:
        for symbol in symbols:
            sys.stdout.write(
                "\r" + yellow("  " + symbol + " ") +
                light_green(message)
            )
            sys.stdout.flush()
            time.sleep(0.08)

    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()

# =========================
# API KEY
# =========================

def save_key(api_key):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    try:
        os.chmod(CONFIG_DIR, 0o700)
    except OSError:
        pass

    with open(CONFIG_FILE, "w") as f:
        json.dump({"api_key": api_key}, f)

    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass

def load_key():
    try:
        data = json.loads(CONFIG_FILE.read_text())
        return data.get("api_key")
    except Exception:
        return None

def setup_key(first_launch=False):
    while True:
        header()

        print(yellow("FIRST TIME API SETUP" if first_launch else "API KEY SETUP"))
        line()

        print(light_green("Enter your VirusTotal API key."))
        print(yellow("Your key will be stored locally."))
        print()

        show = input(yellow("Show key while typing? (Y/N): ")).strip().lower()

        if show == "y":
            key = input(yellow("API KEY: ")).strip()
        else:
            key = getpass.getpass(yellow("API KEY (hidden): ")).strip()

        if not key:
            print(red("\nAPI key cannot be empty."))
            time.sleep(1)
            continue

        save_key(key)

        print(green("\nAPI key saved successfully."))
        time.sleep(1)
        return key

def get_key():
    key = load_key()

    if not key:
        return setup_key(first_launch=True)

    return key

def api_settings():
    while True:
        header()
        print(yellow("API SETTINGS"))
        line()

        menu_item(1, "SHOW API KEY")
        menu_item(2, "UPDATE API KEY")
        menu_item(3, "DELETE API KEY")
        menu_item(4, "BACK")

        choice = input(yellow("\nSelect: ")).strip()

        if choice == "1":
            key = load_key()
            header()

            if key:
                print(yellow("SAVED API KEY"))
                line()
                print(light_green(key))
            else:
                print(red("No API key saved."))

            pause()

        elif choice == "2":
            setup_key()
            pause()

        elif choice == "3":
            if CONFIG_FILE.exists():
                CONFIG_FILE.unlink()
                print(green("\nAPI key deleted."))
            else:
                print(yellow("\nNo saved API key."))

            pause()

        elif choice == "4":
            return

        else:
            print(red("Invalid option."))
            time.sleep(1)

# =========================
# API REQUEST
# =========================

def api_request(method, endpoint, api_key, **kwargs):
    headers = kwargs.pop("headers", {})
    headers["x-apikey"] = api_key

    return requests.request(
        method,
        BASE_URL + endpoint,
        headers=headers,
        timeout=TIMEOUT,
        **kwargs
    )

# =========================
# HASH
# =========================

def calculate_hash(path):
    sha = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(chunk)

    return sha.hexdigest()

# =========================
# VERDICT
# =========================

def get_verdict(stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    if malicious >= 10:
        return "CRITICAL MALWARE DETECTED", DEEP_RED

    if malicious > 0:
        return "MALICIOUS FILE DETECTED", RED

    if suspicious > 0:
        return "SUSPICIOUS FILE", YELLOW

    if total > 0:
        return "NO DETECTIONS REPORTED", LIGHT_GREEN

    return "INCONCLUSIVE", YELLOW

# =========================
# ENGINE REPORT
# =========================

def engine_report(results):
    print()
    print(yellow("ANTIVIRUS ENGINE RESULTS"))
    line()

    if not results:
        print(yellow("No engine results available."))
        return

    for name, result in sorted(results.items()):
        category = result.get("category", "unknown")
        detection = result.get("result") or "No detection"
        version = result.get("engine_version") or "N/A"
        update = result.get("engine_update") or "N/A"

        if category == "malicious":
            status = deep_red("MALICIOUS")
        elif category == "suspicious":
            status = yellow("SUSPICIOUS")
        elif category in ("undetected", "harmless"):
            status = light_green("UNDETECTED")
        else:
            status = green(category.upper())

        print(yellow("┌─ " + name))
        print(yellow("│  Status : ") + status)
        print(yellow("│  Result : ") + (
            deep_red(str(detection))
            if category == "malicious"
            else yellow(str(detection))
            if category == "suspicious"
            else light_green(str(detection))
        ))
        print(yellow("│  Version: ") + green(str(version)))
        print(yellow("│  Update : ") + green(str(update)))
        print(yellow("└" + "─" * 38))

# =========================
# FINAL REPORT
# =========================

def show_report(filename, stats, results):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    total = sum(stats.values())

    engine_report(results)

    verdict, color = get_verdict(stats)

    print()
    print(yellow("FINAL SCAN REPORT"))
    print(yellow("╔" + "═" * 46 + "╗"))

    print(yellow("  File       : ") + light_green(filename))
    print(yellow("  Malicious  : ") + (
        deep_red(str(malicious)) if malicious >= 10
        else red(str(malicious)) if malicious
        else light_green("0")
    ))
    print(yellow("  Suspicious : ") + (
        yellow(str(suspicious)) if suspicious
        else light_green("0")
    ))
    print(yellow("  Undetected : ") + light_green(str(undetected)))
    print(yellow("  Harmless   : ") + green(str(harmless)))
    print(yellow("  Total      : ") + green(str(total)))

    print(yellow("╠" + "═" * 46 + "╣"))
    print(color + BOLD + "  VERDICT: " + verdict + RESET)
    print(yellow("╚" + "═" * 46 + "╝"))

    print(yellow(
        "\nNote: No detections does not guarantee a file is safe."
    ))

# =========================
# ANALYSIS POLLING
# =========================

def get_analysis(analysis_id, api_key):
    for attempt in range(20):
        response = api_request(
            "GET",
            f"/analyses/{analysis_id}",
            api_key
        )

        if response.status_code != 200:
            print(red(
                f"\nAnalysis failed: HTTP {response.status_code}"
            ))
            return None

        data = response.json().get("data", {})
        attributes = data.get("attributes", {})

        if attributes.get("status") == "completed":
            return attributes

        spinner(f"Analysis running ({attempt + 1}/20)", 10)

    print(yellow("\nAnalysis is taking longer than expected."))
    return None

# =========================
# FILE SCANNER
# =========================

def scan_file(path):
    path = Path(path).expanduser()

    if not path.is_file():
        print(red("\nFile not found."))
        pause()
        return

    if path.stat().st_size > MAX_UPLOAD_SIZE:
        print(red("\nFile exceeds 32 MB upload limit."))
        pause()
        return

    api_key = get_key()

    if not api_key:
        return

    header()
    print(yellow("FILE SCANNER"))
    line()

    print(yellow("File: ") + light_green(path.name))
    print(yellow("Size: ") + green(
        f"{path.stat().st_size / 1024:.2f} KB"
    ))

    spinner("Calculating SHA-256", 1)

    try:
        file_hash = calculate_hash(path)
    except Exception as error:
        print(red(f"\nHash error: {error}"))
        pause()
        return

    print(yellow("SHA-256: ") + light_green(file_hash))

    spinner("Checking VirusTotal database", 1)

    try:
        response = api_request(
            "GET",
            f"/files/{file_hash}",
            api_key
        )

        if response.status_code == 200:
            data = response.json()["data"]["attributes"]

            print(green("\nExisting report found."))

            show_report(
                path.name,
                data.get("last_analysis_stats", {}),
                data.get("last_analysis_results", {})
            )

            pause()
            return

        if response.status_code != 404:
            print(red(f"\nAPI error: HTTP {response.status_code}"))
            print(yellow(response.text[:500]))
            pause()
            return

        print(yellow("\nNo existing report."))
        print(yellow("Uploading file to VirusTotal."))

        print(red(
            "\nWARNING: Uploaded files may be shared with "
            "VirusTotal security partners."
        ))

        confirm = input(yellow("Continue upload? (Y/N): ")).strip().lower()

        if confirm != "y":
            print(yellow("Upload cancelled."))
            pause()
            return

        with open(path, "rb") as f:
            upload_response = api_request(
                "POST",
                "/files",
                api_key,
                files={"file": (path.name, f)}
            )

        if upload_response.status_code not in (200, 201):
            print(red(
                f"\nUpload failed: HTTP {upload_response.status_code}"
            ))
            print(yellow(upload_response.text[:500]))
            pause()
            return

        analysis_id = upload_response.json()["data"]["id"]

        print(green("\nUpload successful."))

        analysis = get_analysis(analysis_id, api_key)

        if not analysis:
            pause()
            return

        show_report(
            path.name,
            analysis.get("stats", {}),
            analysis.get("results", {})
        )

    except requests.RequestException as error:
        print(red(f"\nNetwork error: {error}"))

    except Exception as error:
        print(red(f"\nScan error: {error}"))

    pause()

# =========================
# STORAGE BROWSER
# =========================

def browse_storage():
    if not STORAGE.exists():
        print(yellow("Storage permission not configured."))
        print(light_green("Run: termux-setup-storage"))
        pause()
        return

    current = STORAGE

    while True:
        header()
        print(yellow("STORAGE BROWSER"))
        line()
        print(yellow("Path: ") + light_green(str(current)))
        line()

        try:
            items = sorted(
                current.iterdir(),
                key=lambda x: (not x.is_dir(), x.name.lower())
            )
        except PermissionError:
            print(red("Permission denied."))
            pause()
            return

        if not items:
            print(yellow("Folder is empty."))

        for index, item in enumerate(items, 1):
            if item.is_dir():
                label = yellow("[DIR]  " + item.name)
            else:
                label = light_green("[FILE] " + item.name)

            print(yellow(f"  {index:02d}. ") + label)

        print()
        print(yellow("  [0] BACK"))
        print(yellow("  [B] UP ONE FOLDER"))

        choice = input(yellow("\nSelect item: ")).strip()

        if choice == "0":
            return

        if choice.lower() == "b":
            if current != STORAGE:
                current = current.parent
            continue

        if not choice.isdigit():
            print(red("Invalid selection."))
            time.sleep(1)
            continue

        number = int(choice)

        if number < 1 or number > len(items):
            print(red("Invalid selection."))
            time.sleep(1)
            continue

        selected = items[number - 1]

        if selected.is_dir():
            current = selected
        else:
            print(yellow("\nSelected: ") + light_green(selected.name))

            confirm = input(yellow("Scan this file? (Y/N): ")).strip().lower()

            if confirm == "y":
                scan_file(selected)

# =========================
# MAIN MENU
# =========================

def main():
    # First launch: API setup BEFORE main menu
    api_key = load_key()

    if not api_key:
        api_key = setup_key(first_launch=True)

    while True:
        header()

        print(yellow("MAIN MENU"))
        line()

        menu_item(1, "SCAN FILE BY PATH")
        menu_item(2, "BROWSE & SCAN FILE NO FILE PATE")
        menu_item(3, "API KEY SETTINGS")
        menu_item(4, "EXIT")

        line()

        choice = input(yellow("Select option: ")).strip()

        if choice == "1":
            header()
            print(yellow("SCAN FILE"))
            path = input(yellow("Enter file path: ")).strip()
            scan_file(path)

        elif choice == "2":
            browse_storage()

        elif choice == "3":
            api_settings()

        elif choice == "4":
            print(yellow("\nGoodbye!"))
            break

        else:
            print(red("\nInvalid option."))
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(yellow("\n\nScanner stopped."))
