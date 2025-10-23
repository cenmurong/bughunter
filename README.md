# Bug Hunter V.1

```
d8888b. db    db  d888b  db   db db    db d8b   db d888888b d88888b d8888b. 
88  `8D 88    88 88' Y8b 88   88 88    88 888o  88 `~~88~~' 88'     88  `8D 
88oooY' 88    88 88      88ooo88 88    88 88V8o 88    88    88ooooo 88oobY' 
88~~~b. 88    88 88  ooo 88~~~88 88    88 88 V8o88    88    88~~~~~ 88`8b   
88   8D 88b  d88 88. ~8~ 88   88 88b  d88 88  V888    88    88.     88 `88. 
Y8888P' ~Y8888P'  Y888P  YP   YP ~Y8888P' VP   V8P    YP    Y88888P 88   YD 
```


Bug Hunter is a command-line tool designed to assist in the process of bug hunting in web applications. This tool automates several tasks such as target searching using dorks, indexing, and vulnerability scanning on URLs.

## Features

*   **Gather Targets**: Uses Google Dorks to find potential targets and index the results.
*   **Scan URL**: Performs a full scan on a single URL to find common vulnerabilities.
*   **Download Proxy**: Downloads and updates a list of proxies that can be used for scanning.
*   **Interactive Menu**: An easy-to-use interface to run various features.

## Installation

1.  **Clone this repository:**
    ```
    git clone https://github.com/cenmurong/bughunter
    cd bughunter
    ```

2.  **Install dependencies:**
    Make sure you have Python 3 on your system.
    ```
    pip install -r requirements.txt
    ```

## Usage

Run the main script to display the menu:
```
python3 master.py
```

### Menu Options

*   **[1] Gather Targets (Dorking & Indexing)**
    *   This option will run the `indexing.py` script to gather targets based on the dorks in `payloads/dork.txt`.
    *   The results will be saved in the `output` directory.

*   **[2] Scan URL (Full Scan)**
    *   Asks you to enter the URL to be scanned.
    *   Runs a full scan on the URL using all available modules in `misc/tools.py`.
    *   The scan results will be saved in the `scan_results` directory.

*   **[3] Download/Update Proxy List**
    *   Runs the `downloader.py` script to download a new proxy list.
    *   You will be asked to enter the number of active proxies you want to collect.

*   **[0] Exit**
    *   Exit the application.

## Disclaimer

This tool is created for educational and security research purposes. The user is fully responsible for all actions taken using this tool. Do not use this tool for illegal activities.

## License

[cenmurong](https://github.com/cenmurong). All Rights Reserved.
Please include the original source if you copy or use this code.
