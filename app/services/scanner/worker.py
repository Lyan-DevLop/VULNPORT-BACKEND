import asyncio
from datetime import datetime, date
from typing import Callable, Awaitable, Dict, List, Optional

from sqlalchemy.orm import Session

from app.services.scanner.port_scanner import port_scanner
from app.services.scanner.os_detector import detect_os
from app.services.external.nvd_cve_lookup import cve_lookup_service
from app.services.risk_model.risk_evaluator import risk_evaluator

from app.models.hosts import Host
from app.models.ports import Port
from app.models.vulnerabilities import Vulnerability
from app.models.risk import RiskAssessment

from app.utils.network import discover_active_hosts
from app.core.logger import get_logger

log = get_logger(__name__)


class ScanWorker:
    """
    Orquestador de escaneos:
    - Escaneo de puertos
    - Detección de SO
    - Consulta NVD
    - Evaluación de riesgo
    - Persistencia en BD
    """

    # ESCANEO INDIVIDUAL
    async def scan_single_host(
        self,
        ip: str,
        ports: List[int],
        db: Optional[Session] = None,
        on_update: Optional[Callable[[Dict], Awaitable[None]]] = None,
    ):
        """
        Escaneo de un solo host:
        - Escaneo TCP
        - Banner grabbing
        - Detección de OS
        - Búsqueda de CVEs por servicio detectado
        - Evaluación de riesgo
        - Persistencia en BD (si se pasa `db`)
        - Reporte parcial vía callback on_update (ej. WebSocket)
        """

        # 1 — Detección de OS
        os_name = detect_os(ip)
        if on_update:
            await on_update(
                {"type": "status", "message": f"Detectado OS para {ip}: {os_name}"}
            )

        # 2 — Escaneo de puertos (solo abiertos/filtrando en port_scanner)
        if on_update:
            await on_update(
                {"type": "status", "message": f"Escaneando puertos en {ip}..."}
            )

        port_results = await port_scanner.scan_ports(ip, ports)

        # 3 — Buscar CVEs por cada puerto abierto
        if on_update:
            await on_update(
                {"type": "status", "message": "Buscando CVEs en NVD para puertos abiertos..."}
            )

        all_vulns: Dict[int, List[Dict]] = {}

        for port, data in port_results.items():
            status = data.get("status")
            if status not in ("open", "open|filtered", "filtered"):
                # Solo nos interesan abiertos o filtrando
                continue

            service_name = data.get("service_name")
            service_version = data.get("service_version")

            cves = await cve_lookup_service.search_cves_for_service(
                service_name=service_name,
                version=service_version,
            )
            all_vulns[port] = cves

        # 4 — Evaluar riesgo (usando un wrapper similar al que ya tenías)
        if on_update:
            await on_update(
                {"type": "status", "message": "Evaluando riesgo para el host..."}
            )

        # Construimos puertos "fake" con vulnerabilidades para el risk_evaluator
        fake_ports = self._fake_port_objects(port_results, all_vulns)

        # Host fake mínimo con ip_address (si risk_evaluator lo usa)
        FakeHost = type("FakeHost", (), {})
        fake_host = FakeHost()
        fake_host.ip_address = ip

        risk_info = risk_evaluator.evaluate(host=fake_host, ports=fake_ports)

        # 5 — Persistencia en BD
        if db is not None:
            self._persist_scan_result(
                db=db,
                ip=ip,
                os_name=os_name,
                port_results=port_results,
                all_vulns=all_vulns,
                risk_info=risk_info,
            )

        # 6 — Resultado final en memoria
        result = {
            "ip": ip,
            "os": os_name,
            "ports": port_results,
            "vulnerabilities": all_vulns,
            "risk": risk_info,
        }

        if on_update:
            await on_update(
                {
                    "type": "result",
                    "message": "Escaneo completo",
                    "result": result,
                }
            )

        return result

    # ESCANEO DE RANGO COMPLETO (USA scan_single_host)
    async def scan_network_range(
        self,
        cidr: str,
        ports: List[int],
        db: Optional[Session] = None,
        on_update: Optional[Callable[[Dict], Awaitable[None]]] = None,
        detect_os_flag: bool = True,
    ):
        """
        Escaneo de todos los hosts ACTIVOS en una red:
        - Descubre hosts activos con ARP
        - Por cada host llama a scan_single_host (con NVD + riesgo + persistencia)
        Ideal para usar con WebSockets pasando on_update.
        """

        # Encontrar hosts activos en la red
        if on_update:
            await on_update(
                {"type": "status", "message": f"Descubriendo hosts activos en {cidr}..."}
            )

        active_hosts = discover_active_hosts(cidr)

        if not active_hosts:
            if on_update:
                await on_update(
                    {"type": "status", "message": "No se detectaron hosts activos."}
                )
            return {}

        results: Dict[str, Dict] = {}
        total = len(active_hosts)

        for idx, ip in enumerate(active_hosts, start=1):
            progress = round(idx / total * 100, 2)

            if on_update:
                await on_update(
                    {
                        "type": "progress",
                        "message": f"Escaneando host {ip} ({idx}/{total})",
                        "current_ip": ip,
                        "progress": progress,
                    }
                )

            # Para cada host se reutiliza el flujo completo
            host_result = await self.scan_single_host(
                ip=ip,
                ports=ports,
                db=db,
                on_update=on_update,
            )

            results[ip] = host_result

        if on_update:
            await on_update(
                {
                    "type": "result",
                    "message": "Escaneo de red completo",
                    "result": results,
                }
            )

        return results

    # PERSISTENCIA EN BD
    def _persist_scan_result(
        self,
        db: Session,
        ip: str,
        os_name: Optional[str],
        port_results: Dict[int, Dict],
        all_vulns: Dict[int, List[Dict]],
        risk_info: Optional[Dict],
    ) -> None:
        """
        Sincroniza el resultado del escaneo con la base de datos:
        - Host
        - Ports
        - Vulnerabilities
        - RiskAssessment
        """
        try:
            # HOST
            host: Host = (
                db.query(Host).filter(Host.ip_address == ip).one_or_none()
            )
            if host is None:
                host = Host(ip_address=ip)
                db.add(host)
                db.flush()  # para obtener host.id

            host.os_detected = os_name
            host.scan_date = datetime.utcnow()

            # Consideramos "puertos relevantes" solo open / open|filtered / filtered
            relevant_status = {"open", "open|filtered", "filtered"}
            relevant_ports = [
                (port, data)
                for port, data in port_results.items()
                if data.get("status") in relevant_status
            ]

            host.total_ports = len(relevant_ports)

            high_risk_count = 0

            #  PORTS + VULNS 
            for port_number, pdata in relevant_ports:
                protocol = pdata.get("protocol", "tcp")
                service_name = pdata.get("service_name")
                service_version = pdata.get("service_version")
                status = pdata.get("status", "open")

                # Buscar o crear puerto
                port_obj: Port = (
                    db.query(Port)
                    .filter(
                        Port.host_id == host.id,
                        Port.port_number == port_number,
                        Port.protocol == protocol,
                    )
                    .one_or_none()
                )

                if port_obj is None:
                    port_obj = Port(
                        host_id=host.id,
                        port_number=port_number,
                        protocol=protocol,
                    )
                    db.add(port_obj)
                    db.flush()

                port_obj.service_name = service_name
                port_obj.service_version = service_version
                port_obj.status = status
                port_obj.scanned_at = datetime.utcnow()

                # Limpiar vulnerabilidades previas del puerto
                db.query(Vulnerability).filter(
                    Vulnerability.port_id == port_obj.id
                ).delete()

                cve_list = all_vulns.get(port_number, [])

                for cve in cve_list:
                    pub_date = self._parse_date(cve.get("published_date"))

                    vuln = Vulnerability(
                        port_id=port_obj.id,
                        cve_id=cve.get("cve_id"),
                        cvss_score=cve.get("cvss_score"),
                        severity=cve.get("severity"),
                        description=cve.get("description"),
                        published_date=pub_date,
                        source=cve.get("source", "NVD"),
                    )
                    db.add(vuln)

                # Contar puertos de alto riesgo
                if any(
                    v.get("severity") in ("HIGH", "CRITICAL") for v in cve_list
                ):
                    high_risk_count += 1

            host.high_risk_count = high_risk_count

            # RISK ASSESSMENT
            if risk_info:
                score = (
                    risk_info.get("overall_risk_score")
                    or risk_info.get("score")
                )
                level = risk_info.get("risk_level") or risk_info.get("level")
                model_version = risk_info.get("model_version")

                ra = RiskAssessment(
                    host_id=host.id,
                    overall_risk_score=score,
                    risk_level=level,
                    model_version=model_version,
                )
                db.add(ra)

            db.commit()
            log.info(f"Persistencia completada para host {ip}")

        except Exception as e:
            db.rollback()
            log.exception(f"Error persistiendo resultados para host {ip}: {e}")


    # HELPERS (para la red neural y utilidades)
    def _parse_date(self, value) -> Optional[date]:
        """
        Convierte cadenas ISO8601 o datetime a date.
        """
        if not value:
            return None

        if isinstance(value, date) and not isinstance(value, datetime):
            return value

        try:
            if isinstance(value, datetime):
                return value.date()
            if isinstance(value, str):
                # Quitar Z si viene como 2024-01-01T12:00:00Z
                v = value.replace("Z", "")
                return datetime.fromisoformat(v).date()
        except Exception:
            return None

        return None

    def _fake_port_objects(self, port_results, vulns):
        """
        Convierte resultados básicos en objetos simulados
        para alimentar el risk_evaluator.
        """

        fake_ports = []

        for port, data in port_results.items():

            class FakePort:
                port_number = port
                status = data.get("status")
                vulnerabilities = []

            for v in vulns.get(port, []):
                class FakeVuln:
                    cvss_score = v.get("cvss_score")

                FakePort.vulnerabilities.append(FakeVuln)

            fake_ports.append(FakePort)

        return fake_ports


# Instancia global reutilizable
scan_worker = ScanWorker()


