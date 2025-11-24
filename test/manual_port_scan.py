import socket
import threading
from queue import Queue
import ipaddress
import subprocess
import platform

# -----------------------------------------------------------------------
# 1. DESCUBRIR HOSTS ACTIVOS (ARP + ICMP)
# -----------------------------------------------------------------------

def ping_host(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-w", "500", ip]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

def discover_hosts(network_cidr):
    print(f"\n🔎 Escaneando red {network_cidr}...")
    alive_hosts = []

    net = ipaddress.ip_network(network_cidr, strict=False)
    for ip in net.hosts():
        ip = str(ip)
        if ping_host(ip):
            print(f"🟢 Host activo: {ip}")
            alive_hosts.append(ip)

    return alive_hosts

# -----------------------------------------------------------------------
# 2. ESCANEO DE PUERTOS (TCP CONNECT)
# -----------------------------------------------------------------------

def scan_port(ip, port, results):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)

    try:
        if s.connect_ex((ip, port)) == 0:
            banner = ""
            try:
                s.send(b"HELLO\r\n")
                banner = s.recv(64).decode(errors="ignore").strip()
            except:
                pass

            results.append((port, "open", banner))
    except:
        pass
    finally:
        s.close()

def scan_host(ip, max_threads=500):
    print(f"\n🔎 Escaneando puertos de {ip}...\n")

    results = []
    q = Queue()

    for p in range(1, 65536):
        q.put(p)

    def worker():
        while not q.empty():
            port = q.get()
            scan_port(ip, port, results)
            q.task_done()

    threads = []
    for _ in range(max_threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    return sorted(results)



# -----------------------------------------------------------------------
# 3. ESCANEO COMPLETO DE RED
# -----------------------------------------------------------------------

def full_network_scan(network_cidr):
    alive = discover_hosts(network_cidr)

    if not alive:
        print("\n❌ No se encontraron hosts activos.")
        return

    print(f"\n📌 {len(alive)} hosts encontrados.\n")

    for host in alive:
        ports = scan_host(host)
        print(f"\n===== RESULTADOS PARA {host} =====")
        for p, state, banner in ports:
            service = banner if banner else "unknown"
            print(f"PORT {p} OPEN | SERVICE: {service}")
        print("\n===============================\n")


# -----------------------------------------------------------------------
# EJECUCIÓN
# -----------------------------------------------------------------------

if __name__ == "__main__":
    red = input("Ingrese red CIDR (ej: 192.168.1.0/24): ")
    full_network_scan(red)
