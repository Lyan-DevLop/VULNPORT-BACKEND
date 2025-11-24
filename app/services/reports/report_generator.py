# app/services/reports/report_generator.py

from datetime import datetime
from typing import List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet

from app.models.hosts import Host
from app.models.ports import Port
from app.models.vulnerabilities import Vulnerability
from app.models.risk import RiskAssessment

import os


class ReportGenerator:

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = self.styles["Title"]
        self.header_style = self.styles["Heading2"]
        self.small_header = self.styles["Heading3"]
        self.body_style = self.styles["BodyText"]

    # PÚBLICO: Generar reporte PDF
    def generate_host_report(self,
                             host: Host,
                             ports: List[Port],
                             risk_assessments: List[RiskAssessment],
                             output_path: str) -> str:
        """
        Genera un reporte PDF con:
            - Información del host
            - Puertos abiertos/cerrados
            - Vulnerabilidades
            - Evaluación de riesgo
        """

        doc = SimpleDocTemplate(output_path, pagesize=letter)
        elements = []


        # TÍTULO
        elements.append(Paragraph(f"Reporte de Análisis - {host.ip_address}", self.title_style))
        elements.append(Spacer(1, 15))

        # INFO DEL HOST
        elements.append(Paragraph("Información del Host", self.header_style))
        elements.append(Spacer(1, 10))

        host_table = [
            ["Campo", "Valor"],
            ["IP Address", host.ip_address],
            ["Hostname", host.hostname or "N/A"],
            ["Sistema Operativo Detectado", host.os_detected or "N/A"],
            ["Fecha de Escaneo", host.scan_date.strftime("%Y-%m-%d %H:%M")],
            ["Total de Puertos Escaneados", str(host.total_ports)],
            ["Puertos de Alto Riesgo", str(host.high_risk_count)],
        ]

        host_table_obj = Table(host_table)
        host_table_obj.setStyle(self._table_style_basic())
        elements.append(host_table_obj)
        elements.append(Spacer(1, 20))

        # PUERTOS ESCANEADOS
        elements.append(Paragraph("Puertos Escaneados", self.header_style))
        elements.append(Spacer(1, 10))

        port_table = [["Puerto", "Protocolo", "Estado", "Servicio", "Versión", "Fecha Escaneo"]]

        for p in ports:
            port_table.append([
                str(p.port_number),
                p.protocol.upper(),
                p.status,
                p.service_name or "N/A",
                p.service_version or "N/A",
                p.scanned_at.strftime("%Y-%m-%d %H:%M")
            ])

        port_table_obj = Table(port_table, repeatRows=1)
        port_table_obj.setStyle(self._table_style_bordered())
        elements.append(port_table_obj)
        elements.append(Spacer(1, 25))

        # VULNERABILIDADES
        elements.append(Paragraph("Vulnerabilidades Detectadas (NVD)", self.header_style))
        elements.append(Spacer(1, 10))

        vuln_table = [["CVE", "CVSS", "Severidad", "Descripción", "Fecha Publicación"]]

        for p in ports:
            for v in p.vulnerabilities:
                vuln_table.append([
                    v.cve_id,
                    str(v.cvss_score or "N/A"),
                    self._severity_color(v.severity),
                    (v.description[:150] + "...") if v.description else "N/A",
                    str(v.published_date) if v.published_date else "N/A",
                ])

        if len(vuln_table) > 1:
            vuln_table_obj = Table(vuln_table, repeatRows=1)
            vuln_table_obj.setStyle(self._table_style_bordered())
            elements.append(vuln_table_obj)
        else:
            elements.append(Paragraph("No se encontraron vulnerabilidades.", self.body_style))

        elements.append(Spacer(1, 25))

        # EVALUACIÓN DE RIESGO
        elements.append(Paragraph("Evaluación de Riesgo", self.header_style))
        elements.append(Spacer(1, 10))

        if risk_assessments:
            ra = risk_assessments[-1]  # Tomamos la evaluación más reciente

            risk_table = [
                ["Campo", "Valor"],
                ["Nivel de Riesgo", ra.risk_level],
                ["Puntaje de Riesgo (0-100)", str(ra.overall_risk_score)],
                ["Versión del Modelo", ra.model_version or "N/A"],
                ["Fecha Evaluada", ra.evaluated_at.strftime("%Y-%m-%d %H:%M")]
            ]

            risk_table_obj = Table(risk_table)
            risk_table_obj.setStyle(self._table_style_basic())
            elements.append(risk_table_obj)
        else:
            elements.append(Paragraph("Aún no se ha realizado una evaluación de riesgo.", self.body_style))

        # GENERAR DOC
        doc.build(elements)
        return output_path


    # ESTILOS
    def _table_style_basic(self):
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ])

    def _table_style_bordered(self):
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.gray),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.darkgray),
        ])

    # COLORES PARA SEVERIDAD
    def _severity_color(self, severity: str | None) -> str:
        """
        Devuelve texto enriquecido con color según severidad.
        """
        if not severity:
            return "N/A"

        sev = severity.upper()
        colors_map = {
            "CRITICAL": "<font color='red'><b>CRITICAL</b></font>",
            "HIGH": "<font color='maroon'><b>HIGH</b></font>",
            "MEDIUM": "<font color='orange'><b>MEDIUM</b></font>",
            "LOW": "<font color='green'><b>LOW</b></font>",
        }

        return colors_map.get(sev, sev)
