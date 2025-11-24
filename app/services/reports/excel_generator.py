from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from datetime import datetime


class ExcelReportGenerator:

    def generate_host_excel(self, host, ports, risk_assessments, output_path: str) -> str:
        wb = Workbook()

        # HOJA: Información del Host
        ws = wb.active
        ws.title = "Host Info"

        ws.append(["Campo", "Valor"])
        ws.append(["IP Address", host.ip_address])
        ws.append(["Hostname", host.hostname or "N/A"])
        ws.append(["Sistema Operativo Detectado", host.os_detected or "N/A"])
        ws.append(["Fecha de Escaneo", host.scan_date.strftime("%Y-%m-%d %H:%M")])
        ws.append(["Total Puertos Escaneados", host.total_ports])
        ws.append(["Puertos Alto Riesgo", host.high_risk_count])

        # Encabezado en negrita
        for cell in ws["1:1"]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="0000AAFF", fill_type="solid")


        # HOJA: Puertos Escaneados
        ws_ports = wb.create_sheet("Ports")

        ws_ports.append(["Puerto", "Protocolo", "Estado", "Servicio", "Versión", "Fecha Scaneo"])

        for p in ports:
            ws_ports.append([
                p.port_number,
                p.protocol,
                p.status,
                p.service_name or "N/A",
                p.service_version or "N/A",
                p.scanned_at.strftime("%Y-%m-%d %H:%M"),
            ])

        for cell in ws_ports["1:1"]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="00AAAAAA", fill_type="solid")


        # HOJA: Vulnerabilidades (NVD)
        ws_vuln = wb.create_sheet("Vulnerabilities")
        ws_vuln.append(["CVE", "CVSS", "Severidad", "Descripción", "Publicación"])

        for p in ports:
            for v in p.vulnerabilities:
                ws_vuln.append([
                    v.cve_id,
                    v.cvss_score,
                    v.severity,
                    v.description[:150] + "..." if v.description else "N/A",
                    v.published_date.strftime("%Y-%m-%d") if v.published_date else "N/A",
                ])

        for cell in ws_vuln["1:1"]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="00AA0000", fill_type="solid")


        # HOJA: Evaluación de Riesgo
        ws_risk = wb.create_sheet("Risk Assessment")

        if risk_assessments:
            ra = risk_assessments[-1]

            ws_risk.append(["Campo", "Valor"])
            ws_risk.append(["Nivel de Riesgo", ra.risk_level])
            ws_risk.append(["Puntaje 0-100", ra.overall_risk_score])
            ws_risk.append(["Versión Modelo", ra.model_version])
            ws_risk.append(["Fecha Evaluada", ra.evaluated_at.strftime("%Y-%m-%d %H:%M")])

        else:
            ws_risk.append(["Sin evaluación de riesgo disponible"])

        for cell in ws_risk["1:1"]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="00FF8800", fill_type="solid")


        # GUARDAR DOCUMENTO
        wb.save(output_path)
        return output_path
