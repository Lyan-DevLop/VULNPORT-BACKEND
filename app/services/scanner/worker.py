from __future__ import annotations

from datetime import date, datetime
from typing import Awaitable, Callable, Dict, List, Optional

from sqlalchemy.orm import Session, Session as SASession

from app.core.logger import get_logger
from app.database import SessionLocal
from app.models.hosts import Host
from app.models.ports import Port
from app.models.risk import RiskAssessment
from app.models.vulnerabilities import Vulnerability
from app.services.external.nvd_cve_lookup import cve_lookup_service
from app.services.risk_model.risk_evaluator import risk_evaluator
from app.services.scanner.os_detector import detect_os
from app.services.scanner.port_scanner import port_scanner
from app.utils.network import discover_active_hosts

log = get_logger(__name__)


class ScanWorker:
    """
    Worker central de análisis:
    - Escaneo backend (scan_single_host)
    - Procesamiento reporte agente (process_agent_report)
    Ambos terminan en:
      NVD -> Risk -> Persistencia (Host/Port/Vuln/RiskAssessment)
    """

    # 1) ESCANEO INDIVIDUAL
    async def scan_single_host(
        self,
        ip: str,
        ports: List[int],
        db: Optional[Session] = None,
        on_update: Optional[Callable[[Dict], Awaitable[None]]] = None,
        user_id: Optional[int] = None,
    ):
        """Escaneo individual + análisis + persistencia"""

        local_db = None
        if db is None:
            local_db = SessionLocal()
            db = local_db

        try:
            # 1 — Detección de SO
            os_name = detect_os(ip)
            if on_update:
                await on_update({"type": "status", "message": f"Detectado OS: {os_name}"})

            # 2 — Escaneo de puertos
            if on_update:
                await on_update({"type": "status", "message": "Escaneando puertos..."})

            port_results = await port_scanner.scan_ports(ip, ports)

            # 3 — Buscar CVEs para puertos abiertos
            if on_update:
                await on_update({"type": "status", "message": "Buscando CVEs en NVD..."})

            all_vulns = await self._lookup_vulns_for_ports(port_results)

            # 4 — Evaluación de riesgo
            if on_update:
                await on_update({"type": "status", "message": "Evaluando riesgo..."})

            risk_info = self._evaluate_risk(ip=ip, port_results=port_results, all_vulns=all_vulns)

            # 5 — Persistencia
            self._persist_scan_result(
                db=db,
                ip=ip,
                os_name=os_name,
                port_results=port_results,
                all_vulns=all_vulns,
                risk_info=risk_info,
                user_id=user_id,
            )

            result = {
                "ip": ip,
                "os": os_name,
                "ports": port_results,
                "vulnerabilities": all_vulns,
                "risk": risk_info,
            }

            if on_update:
                await on_update({"type": "result", "result": result})

            return result

        finally:
            if local_db:
                local_db.close()

    # 2) ESCANEO DE RANGO
    async def scan_network_range(
        self,
        cidr: str,
        ports: List[int],
        db: Optional[Session] = None,
        on_update: Optional[Callable[[Dict], Awaitable[None]]] = None,
        detect_os_flag: bool = True,
        user_id: Optional[int] = None,
    ):
        """Escaneo de rango -> cada host usa sesión independiente"""

        if on_update:
            await on_update({"type": "status", "message": f"Descubriendo hosts activos ({cidr})..."})

        active_hosts = discover_active_hosts(cidr)
        if not active_hosts:
            if on_update:
                await on_update({"type": "status", "message": "No hay hosts activos."})
            return {}

        results: Dict[str, Dict] = {}
        total = len(active_hosts)

        for idx, ip in enumerate(active_hosts, start=1):
            progress = round(idx / total * 100, 2)

            if on_update:
                await on_update(
                    {
                        "type": "progress",
                        "message": f"Escaneando {ip} ({idx}/{total})",
                        "current_ip": ip,
                        "progress": progress,
                    }
                )

            host_db = SessionLocal()
            try:
                result = await self.scan_single_host(
                    ip=ip,
                    ports=ports,
                    db=host_db,
                    on_update=on_update,
                    user_id=user_id,
                )
                results[ip] = result
            finally:
                host_db.close()

        if on_update:
            await on_update({"type": "result", "message": "Escaneo completo", "result": results})

        return results

    # 3) PROCESAR REPORTE DE AGENTE
    async def process_agent_report(
        self,
        *,
        ip: str,
        agent_ports: List[dict],
        db: SASession,
        user_id: Optional[int] = None,
        on_update: Optional[Callable[[Dict], Awaitable[None]]] = None,
    ) -> Dict:
        """
        Entra un reporte del agente (ya escaneado localmente).
        Aquí hacemos:
          - Detect OS (consistencia)
          - NVD lookup
          - Risk
          - Persistencia en Host/Port/Vuln/RiskAssessment
        """

        os_name = detect_os(ip)
        if on_update:
            await on_update({"type": "status", "message": f"[AGENT] Detectado OS: {os_name}"})

        # Convertir reporte agente a formato interno
        port_results: Dict[int, Dict] = {}
        for p in agent_ports:
            try:
                port_number = int(p.get("port"))
            except Exception:
                continue

            status = p.get("status") or "open"
            protocol = p.get("protocol") or "tcp"

            port_results[port_number] = {
                "protocol": protocol,
                "status": status,
                "service_name": p.get("service_name"),
                "service_version": p.get("service_version"),
            }

        if on_update:
            await on_update({"type": "status", "message": "[AGENT] Buscando CVEs en NVD..."})

        all_vulns = await self._lookup_vulns_for_ports(port_results)

        if on_update:
            await on_update({"type": "status", "message": "[AGENT] Evaluando riesgo..."})

        risk_info = self._evaluate_risk(ip=ip, port_results=port_results, all_vulns=all_vulns)

        self._persist_scan_result(
            db=db,
            ip=ip,
            os_name=os_name,
            port_results=port_results,
            all_vulns=all_vulns,
            risk_info=risk_info,
            user_id=user_id,
        )

        result = {
            "ip": ip,
            "os": os_name,
            "ports": port_results,
            "vulnerabilities": all_vulns,
            "risk": risk_info,
        }

        if on_update:
            await on_update({"type": "result", "result": result})

        return result

    # 4) APLICAR CIERRE DE PUERTOS
    def apply_closed_ports(
        self,
        *,
        db: SASession,
        ip: str,
        closed_ports: List[int],
        protocol: Optional[str] = None,
    ) -> None:
        """
        Cuando el agente confirma un close_port, reflejamos en la tabla Port:
          - status = "closed"
          - scanned_at = now
        Sin necesidad de un scan completo.
        """
        if not closed_ports:
            return

        host = db.query(Host).filter(Host.ip_address == ip).one_or_none()
        if not host:
            return

        q = db.query(Port).filter(
            Port.host_id == host.id,
            Port.port_number.in_(closed_ports),
        )

        # Si el Port tiene protocol, filtramos si se pasa
        if protocol:
            try:
                q = q.filter(Port.protocol == protocol)
            except Exception:
                pass

        ports = q.all()
        for p in ports:
            p.status = "closed"
            p.scanned_at = datetime.utcnow()

        # No  se recalcula riesgo aquí para no meter latencia extra.
        # El siguiente reporte/scan actualizará risk_assessment.
        db.commit()

    # HELPERS: NVD + RISK
    async def _lookup_vulns_for_ports(self, port_results: Dict[int, Dict]) -> Dict[int, List[Dict]]:
        all_vulns: Dict[int, List[Dict]] = {}

        for port, data in port_results.items():
            if data.get("status") not in ("open", "open|filtered", "filtered"):
                continue

            try:
                cves = await cve_lookup_service.search_cves_for_service(
                    service_name=data.get("service_name"),
                    version=data.get("service_version"),
                )
                all_vulns[port] = cves
            except Exception as e:
                log.exception(f"Error consultando NVD para port={port}: {e}")
                all_vulns[port] = []

        return all_vulns

    def _evaluate_risk(self, *, ip: str, port_results: Dict[int, Dict], all_vulns: Dict[int, List[Dict]]) -> Dict:
        fake_ports = self._fake_port_objects(port_results, all_vulns)

        FakeHost = type("FakeHost", (), {})
        fake_host = FakeHost()
        fake_host.ip_address = ip

        return risk_evaluator.evaluate(fake_host, fake_ports)

    # PERSISTENCIA (NO DUPLICA, NO SATURA)
    def _persist_scan_result(
        self,
        db: SASession,
        ip: str,
        os_name: Optional[str],
        port_results: Dict[int, Dict],
        all_vulns: Dict[int, List[Dict]],
        risk_info: Optional[Dict],
        user_id: Optional[int] = None,
    ):
        """
        Persistencia completa:
        - Host upsert por ip
        - Port upsert por (host_id, port_number, protocol)
        - Vulnerability refresh por puerto (borra e inserta)
        - RiskAssessment: SOLO UNO (borra anteriores e inserta el último)
        """

        try:
            host = db.query(Host).filter(Host.ip_address == ip).one_or_none()
            if host is None:
                host = Host(ip_address=ip, user_id=user_id)
                db.add(host)
                db.flush()

            host.os_detected = os_name
            host.scan_date = datetime.utcnow()

            relevant_ports = [
                (p, d)
                for p, d in port_results.items()
                if d.get("status") in ("open", "open|filtered", "filtered")
            ]

            host.total_ports = len(relevant_ports)

            high_risk = 0

            for port_number, pdata in relevant_ports:
                protocol = pdata.get("protocol", "tcp")

                port = (
                    db.query(Port)
                    .filter(
                        Port.host_id == host.id,
                        Port.port_number == port_number,
                        Port.protocol == protocol,
                    )
                    .one_or_none()
                )

                if port is None:
                    port = Port(
                        host_id=host.id,
                        port_number=port_number,
                        protocol=protocol,
                    )
                    db.add(port)
                    db.flush()

                port.service_name = pdata.get("service_name")
                port.service_version = pdata.get("service_version")
                port.status = pdata.get("status")
                port.scanned_at = datetime.utcnow()

                # Refresh de vulnerabilidades SOLO para ese puerto
                db.query(Vulnerability).filter(Vulnerability.port_id == port.id).delete()

                for v in all_vulns.get(port_number, []):
                    pub_date = self._parse_date(v.get("published_date"))

                    db.add(
                        Vulnerability(
                            port_id=port.id,
                            cve_id=v.get("cve_id"),
                            cvss_score=v.get("cvss_score"),
                            severity=v.get("severity"),
                            description=v.get("description"),
                            published_date=pub_date,
                            source=v.get("source", "NVD"),
                        )
                    )

                    if v.get("severity") in ("HIGH", "CRITICAL"):
                        high_risk += 1

            host.high_risk_count = high_risk

            # NO SATURAR risk_assessment: dejamos solo el último
            db.query(RiskAssessment).filter(RiskAssessment.host_id == host.id).delete()

            if risk_info:
                db.add(
                    RiskAssessment(
                        host_id=host.id,
                        overall_risk_score=risk_info.get("overall_risk_score"),
                        risk_level=risk_info.get("risk_level"),
                        model_version=risk_info.get("model_version"),
                    )
                )

            db.commit()

        except Exception as e:
            db.rollback()
            log.exception(f"Error persistiendo {ip}: {e}")

    # HELPERS
    def _parse_date(self, value):
        if not value:
            return None
        try:
            if isinstance(value, datetime):
                return value.date()
            if isinstance(value, date):
                return value
            if isinstance(value, str):
                return datetime.fromisoformat(value.replace("Z", "")).date()
        except Exception:
            return None
        return None

    def _fake_port_objects(self, port_results, vulns):
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


scan_worker = ScanWorker()
