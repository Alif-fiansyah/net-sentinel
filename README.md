# Net-Sentinel

A lightweight, terminal-based local network mapper and port scanner built with Python, Scapy, and Rich. Net-Sentinel enables administrators and security enthusiasts to perform rapid ARP host discovery, DNS resolution, and multi-threaded service inspection directly from their command line.

---

## Features

- **ARP Discovery:** Discovers active devices on a local subnet using fast broadcast ARP packets.
- **Hostname Lookup:** Automatically resolves local hostnames via reverse DNS mapping.
- **Multi-Threaded Port Scanner:** Rapidly scans common target ports concurrently using Python's `ThreadPoolExecutor`.
- **Banner Grabbing:** Queries open ports to extract service banners and protocol responses for quick fingerprinting.
- **Cyberpunk TUI Output:** Displays structured, colored ASCII-style terminal tables and progress bars powered by the `rich` library.

---

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Alif-fiansyah/net-sentinel.git](https://github.com/Alif-fiansyah/net-sentinel.git)
   cd net-sentinel
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv env
   source env/bin/activate
   ```

3.  **Install dependencies:**
    ```bash
    pip install scapy rich

---

## Usage Examples
Note: Raw socket operations and packet forging require root privileges. Use sudo env "PATH=$PATH" to retain the active virtual environment path.
### Network Sweep (Host Discovery)
Syntax:
```bash
sudo env "PATH=$PATH" python scanner.py -t <subnet_cidr>
```

Example:
```bash
sudo env "PATH=$PATH" python scanner.py -t 192.168.1.0/24
```

### Interactive Port Scanning
Once the initial host table is rendered, Net-Sentinel prompts for a target IP address:
```bash
[?] Masukkan salah satu IP dari tabel di atas untuk memindai celahnya: 192.168.1.127
```

### Sample Output
```text
📡 NET-SENTINEL: RADAR JARINGAN LOKAL
+----+---------------+-------------------+------------+
| No | IP Address    | MAC Address       | Hostname   |
+----+---------------+-------------------+------------+
|  1 | 192.168.1.1   | dc:2c:6e:6f:aa:31 | _gateway   |
|  2 | 192.168.1.127 | 3c:da:6d:d4:e5:d3 | N/A        |
+----+---------------+-------------------+------------+
[*] Total perangkat terdeteksi: 2

Laporan Port & Layanan: 192.168.1.127
+------+---------+------------------------------+
| Port | Layanan | Banner/Identifikasi          |
+------+---------+------------------------------+
|   80 | HTTP    | HTTP/1.0 501 Not Implemented |
+------+---------+------------------------------+
```

---

## Tech Stack & Architecture

- **Language:** Python 3
- **Network Engine:** Scapy (Layer 2 ARP broadcast / Layer 3 analysis)
- **Concurrency:** `concurrent.futures.ThreadPoolExecutor` for non-blocking socket checks
- **Terminal UI:** `rich` (Console styling, tables, progress bars)
- **Low-level Networking:** Python standard `socket` library for service banners and TCP handshakes

---

## Disclaimer
This tool is developed strictly for educational purposes, legitimate network audits, and authorized administrative usage. Scanning targets without explicit authorization is illegal.
