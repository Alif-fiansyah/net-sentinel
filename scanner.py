import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
import scapy.all as scapy
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table

console = Console()

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    8080: "HTTP-Proxy",
}


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "N/A"


def scan_network(ip_range):
    console.print(
        f"\n[bold blue][*] Menyiapkan radar ARP untuk target: {ip_range}...[/bold blue]"
    )
    arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(
        pdst=ip_range
    )
    answered_list = scapy.srp(arp_request, timeout=1, verbose=False)[0]

    clients = []
    for elem in answered_list:
        ip = elem[1].psrc
        clients.append(
            {"ip": ip, "mac": elem[1].hwsrc, "hostname": get_hostname(ip)}
        )
    return clients


def display_tui(results_list):
    table = Table(
        title="📡 NET-SENTINEL: RADAR JARINGAN LOKAL",
        style="cyan",
        title_style="bold magenta",
    )
    table.add_column("No", justify="right", style="magenta")
    table.add_column("IP Address", style="bold green")
    table.add_column("MAC Address", style="yellow")
    table.add_column("Hostname", style="dim white")

    for index, client in enumerate(results_list):
        table.add_row(
            str(index + 1), client["ip"], client["mac"], client["hostname"]
        )

    console.print(table)
    console.print(
        f"[bold green][*] Total perangkat terdeteksi: {len(results_list)}[/bold green]\n"
    )


def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.7)
            if sock.connect_ex((ip, port)) == 0:
                if port in (80, 8080):
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(128).decode("utf-8", errors="ignore").strip()
                return (
                    port,
                    COMMON_PORTS.get(port, "Unknown"),
                    banner.splitlines()[0] if banner else "Banner kosong",
                )
    except Exception:
        pass
    return None


def threaded_port_scan(ip):
    console.print(
        f"\n[bold yellow][*] Memulai multi-threaded port scan pada {ip}...[/bold yellow]"
    )
    open_services = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(COMMON_PORTS))

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(grab_banner, ip, port) for port in COMMON_PORTS
            ]
            for future in futures:
                res = future.result()
                if res:
                    open_services.append(res)
                progress.advance(task)

    port_table = Table(
        title=f"Laporan Port & Layanan: {ip}",
        style="red",
        title_style="bold red",
    )
    port_table.add_column("Port", justify="right", style="cyan")
    port_table.add_column("Layanan", style="bold yellow")
    port_table.add_column("Banner/Identifikasi", style="green")

    if open_services:
        for port, service, banner in open_services:
            port_table.add_row(str(port), service, banner)
        console.print(port_table)
    else:
        console.print(
            "[bold green][+] Target terkunci rapat (tidak ada port umum yang terbuka).[/bold green]"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Net-Sentinel: Scanner & Port Mapper"
    )
    parser.add_argument("-t", "--target", dest="target", required=True)
    options = parser.parse_args()

    try:
        scan_result = scan_network(options.target)
        display_tui(scan_result)

        target_ip = console.input(
            "[bold cyan][?] Masukkan IP target untuk dipindai (Enter untuk keluar): [/bold cyan]"
        )
        if target_ip.strip():
            threaded_port_scan(target_ip.strip())
    except KeyboardInterrupt:
        console.print(
            "\n[bold red][!] Dibatalkan oleh pengguna. Keluar dari Net-Sentinel...[/bold red]"
        )