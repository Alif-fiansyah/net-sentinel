import argparse
import scapy.all as scapy
import socket
from rich.console import Console
from rich.table import Table
from rich.progress import track

# Inisialisasi antarmuka terminal visual
console = Console()

def scan_network(ip_range):
    console.print(f"\n[bold blue][*] Menyiapkan radar ARP untuk target: {ip_range}...[/bold blue]")
    
    # Menembakkan paket ARP
    arp_request_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip_range)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    clients_list = []
    for element in answered_list:
        clients_list.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return clients_list

def display_tui(results_list):
    # Membuat tabel berdesain hacker/cyberpunk
    table = Table(title="📡 NET-SENTINEL: RADAR JARINGAN LOKAL", style="cyan", title_style="bold magenta")
    table.add_column("No", justify="right", style="magenta")
    table.add_column("IP Address", style="bold green")
    table.add_column("MAC Address", style="yellow")
    
    for index, client in enumerate(results_list):
        table.add_row(str(index + 1), client['ip'], client['mac'])
        
    console.print(table)
    console.print(f"[bold green][*] Total perangkat hidup terdeteksi: {len(results_list)}[/bold green]\n")

def port_scan(ip):
    console.print(f"\n[bold yellow][*] Memulai pemindaian celah keamanan (Port Scan) pada {ip}...[/bold yellow]")
    
    # Daftar port yang paling sering dieksploitasi oleh hacker
    common_ports = [21, 22, 23, 80, 443, 445, 3306, 8080]
    open_ports = []
    
    # Memindai dengan progress bar visual
    for port in track(common_ports, description="Menganalisis pintu jaringan..."):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) # Batas waktu tunggu setengah detik per port
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            open_ports.append(port)
        sock.close()
        
    # Menampilkan hasil pemindaian celah
    console.print("-" * 50)
    if open_ports:
        for p in open_ports:
            console.print(f"[bold red][!] WASPADA: Port {p} TERBUKA (Potensi Kerentanan!)[/bold red]")
    else:
        console.print("[bold green][+] Perangkat ini terkunci rapat (Tidak ada port umum yang terbuka).[/bold green]")
    console.print("-" * 50)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Net-Sentinel: Scanner & Port Mapper")
    parser.add_argument("-t", "--target", dest="target", required=True)
    options = parser.parse_args()

    try:
        # Tahap 1: Pemetaan Jaringan
        scan_result = scan_network(options.target)
        display_tui(scan_result)
        
        # Tahap 2: Pemindaian Celah (Interaktif)
        target_ip = console.input("[bold cyan][?] Masukkan salah satu IP dari tabel di atas untuk memindai celahnya\n(atau tekan Enter untuk keluar): [/bold cyan]")
        
        if target_ip:
            port_scan(target_ip.strip())
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Dibatalkan oleh pengguna. Keluar dari Net-Sentinel...[/bold red]")