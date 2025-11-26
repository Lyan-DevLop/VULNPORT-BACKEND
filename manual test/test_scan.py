# test_scan.py

import asyncio

from app.services.scanner.port_scanner import port_scanner


async def test():
    ip = "scanme.nmap.org"
    ports = [22, 80, 443]

    print(f"🔍 Probando escaneo de {ip}...")

    result = await port_scanner.scan_ports(ip, ports)

    print("\n=== RESULTADOS ===")
    for port, data in result.items():
        print(f"Port {port}: {data}")

    print("\n✅ Escaneo completado.")


if __name__ == "__main__":
    asyncio.run(test())
