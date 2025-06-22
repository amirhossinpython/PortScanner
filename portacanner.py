import socket
import subprocess
import sys

try:
    from nmap import PortScanner
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-nmap"])
    from nmap import PortScanner

def get_ip_from_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def scan_ports(ip, ports_range=(1, 1000)):
    open_ports = []
    for port in range(ports_range[0], ports_range[1] + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except:
            pass
    return open_ports

def nmap_scan(ip):
    nm = PortScanner()
    nm.scan(ip, arguments='-sV -T4')  
    return nm[ip]


domain = input("Enter the website domain (e.g., example.com): ")


ip = get_ip_from_domain(domain)
if not ip:
    print("Error: Could not resolve the domain.")
    exit()

print(f"\n🔎 Target IP: {ip}")


print("\n🛡️ Scanning common ports...")
open_ports = scan_ports(ip, (20, 100))
print(f"✅ Open ports: {open_ports}")


try:
    print("\n🔦 Running advanced scan with Nmap...")
    nmap_results = nmap_scan(ip)
    for proto in nmap_results.all_protocols():
        print(f"\n📡 Protocol: {proto}")
        ports = nmap_results[proto].keys()
        for port in ports:
            print(f"Port {port}: {nmap_results[proto][port]['state']} ({nmap_results[proto][port]['name']})")
except:
    print("Nmap scan failed. Make sure 'python-nmap' is installed.")
