from datetime import datetime
from typing import List
import os

from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfgen.canvas import Canvas


class ReportGenerator:
    """
    Generador PDF profesional VULNPORTS:
    - Portada con logo
    - Encabezado/pie de página
    - Tablas estilizadas
    - Separadores
    - Landscape para tablas grandes
    - Renders limpios y legibles
    """

    LOGO_PATH = "app/static/logo.png" #Ajustar logo o icono del sistema

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title = self.styles["Title"]
        self.header = self.styles["Heading2"]
        self.subheader = self.styles["Heading3"]
        self.text = self.styles["BodyText"]

    # PORTADA
    def _cover_page(self, canvas: Canvas, doc):
        canvas.saveState()

        canvas.setFillColorRGB(0.05, 0.09, 0.18)
        canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1)

        if os.path.exists(self.LOGO_PATH):
            canvas.drawImage(
                self.LOGO_PATH, 190, 500, width=240, height=100,
                preserveAspectRatio=True, mask='auto'
            )
        else:
            canvas.setFillColor(colors.lightgrey)
            canvas.rect(200, 500, 200, 80, fill=1)
            canvas.setFillColor(colors.black)
            canvas.drawString(240, 540, "VULNPORTS LOGO")

        canvas.setFont("Helvetica-Bold", 28)
        canvas.setFillColor(colors.white)
        canvas.drawString(120, 420, "Reporte de Seguridad - Host Individual")

        canvas.setFont("Helvetica", 14)
        canvas.drawString(
            150, 390,
            f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )

        canvas.restoreState()

    # ENCABEZADO - PIE DE PÁGINA
    def _header_footer(self, canvas: Canvas, doc):
        canvas.saveState()

        canvas.setFont("Helvetica-Bold", 10)
        canvas.setFillColor(colors.grey)
        canvas.drawString(40, 560 if doc.pagesize == landscape(letter) else 760, "VULNPORTS — Reporte de Seguridad")

        page_number = canvas.getPageNumber()
        canvas.setFont("Helvetica", 9)
        canvas.drawString(40, 30, f"Página {page_number}")
        canvas.drawRightString(550, 30, "Sistema de Análisis de Vulnerabilidades — VULNPORTS")

        canvas.restoreState()

    # ESTILO TABLAS
    def _styled_table(self, data, color):
        tbl = Table(data, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), color),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        return tbl

    # REPORTE SINGLE-HOST (PDF en modo Landscape)
    def generate_host_report(self, host, ports, risk_assessments, output_path: str) -> str:

        doc = SimpleDocTemplate(
            output_path,
            pagesize=landscape(letter),
            title="Reporte Host VULNPORTS"
        )

        # Portada
        doc.build([Spacer(1, 1)], onFirstPage=self._cover_page)

        # Contenido real
        elements = [PageBreak()]

        # ---------------------------- INFO HOST ----------------------------
        elements.append(Paragraph("Información del Host", self.header))
        elements.append(Spacer(1, 10))

        t1 = [
            ["Campo", "Valor"],
            ["IP", host.ip_address],
            ["Hostname", host.hostname or "N/A"],
            ["Sistema Operativo", host.os_detected or "N/A"],
            ["Fecha Escaneo", host.scan_date.strftime("%Y-%m-%d %H:%M")],
            ["Puertos Escaneados", host.total_ports],
            ["Puertos Alto Riesgo", host.high_risk_count],
        ]
        elements.append(self._styled_table(t1, colors.darkblue))
        elements.append(Spacer(1, 25))

        # ---------------------------- PUERTOS ----------------------------
        elements.append(Paragraph("Puertos Escaneados", self.header))
        elements.append(Spacer(1, 10))

        ports_rows = [["Puerto", "Protocolo", "Estado", "Servicio", "Versión", "Fecha"]]
        for p in ports:
            ports_rows.append([
                p.port_number, p.protocol.upper(), p.status,
                p.service_name, p.service_version,
                p.scanned_at.strftime("%Y-%m-%d %H:%M")
            ])

        elements.append(self._styled_table(ports_rows, colors.grey))
        elements.append(Spacer(1, 25))

        # ---------------------------- VULNERABILIDADES ----------------------------
        elements.append(Paragraph("Vulnerabilidades Detectadas", self.header))
        elements.append(Spacer(1, 10))

        vuln_rows = [["CVE", "CVSS", "Severidad", "Descripción", "Publicación"]]

        for p in ports:
            for v in p.vulnerabilities:
                vuln_rows.append([
                    v.cve_id,
                    v.cvss_score,
                    v.severity,
                    (v.description[:150] + "...") if v.description else "N/A",
                    v.published_date.strftime("%Y-%m-%d") if v.published_date else "N/A"
                ])

        if len(vuln_rows) > 1:
            elements.append(self._styled_table(vuln_rows, colors.red))
        else:
            elements.append(Paragraph("No se encontraron vulnerabilidades.", self.text))

        elements.append(Spacer(1, 25))

        # ---------------------------- RIESGO ----------------------------
        elements.append(Paragraph("Evaluación de Riesgo", self.header))
        elements.append(Spacer(1, 10))

        if risk_assessments:
            ra = risk_assessments[-1]

            t4 = [
                ["Campo", "Valor"],
                ["Nivel de Riesgo", ra.risk_level],
                ["Puntaje (0-100)", ra.overall_risk_score],
                ["Modelo", ra.model_version],
                ["Fecha", ra.evaluated_at.strftime("%Y-%m-%d %H:%M")]
            ]

            elements.append(self._styled_table(t4, colors.orange))
        else:
            elements.append(Paragraph("Sin evaluación de riesgo registrada.", self.text))

        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)

        return output_path

    # REPORTE MULTI-HOST
    def generate_network_report(self, hosts, output_path: str) -> str:

        doc = SimpleDocTemplate(
            output_path,
            pagesize=landscape(letter),
            title="Reporte General de Red VULNPORTS"
        )

        elements: List = []

        elements.append(Paragraph("Reporte General de Red", self.title))
        elements.append(Paragraph(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M')}", self.text))
        elements.append(Spacer(1, 25))

        # ---------------------------- RESUMEN ----------------------------
        elements.append(Paragraph("Resumen de Hosts", self.header))
        elements.append(Spacer(1, 10))

        summary = [["IP", "Hostname", "OS", "Escaneo", "Puertos", "Altos Riesgos", "Nivel", "Score"]]

        hosts_sorted = sorted(hosts, key=lambda h: str(h.ip_address))

        for h in hosts_sorted:
            ra = h.risk_assessments[-1] if h.risk_assessments else None
            summary.append([
                h.ip_address,
                h.hostname or "N/A",
                h.os_detected or "N/A",
                h.scan_date.strftime("%Y-%m-%d %H:%M"),
                h.total_ports,
                h.high_risk_count,
                ra.risk_level if ra else "N/A",
                ra.overall_risk_score if ra else None
            ])

        elements.append(self._styled_table(summary, colors.darkblue))
        elements.append(Spacer(1, 30))

        # ---------------------------- PUERTOS ----------------------------
        elements.append(Paragraph("Puertos Escaneados (Global)", self.header))
        elements.append(Spacer(1, 10))

        port_rows = [["Host", "Puerto", "Protocolo", "Estado", "Servicio", "Versión", "Fecha"]]
        for h in hosts_sorted:
            for p in h.ports:
                port_rows.append([
                    h.ip_address, p.port_number, p.protocol.upper(),
                    p.status, p.service_name, p.service_version,
                    p.scanned_at.strftime("%Y-%m-%d %H:%M")
                ])

        elements.append(self._styled_table(port_rows, colors.grey))
        elements.append(Spacer(1, 30))

        # ---------------------------- VULNERABILIDADES ----------------------------
        elements.append(Paragraph("Vulnerabilidades (Global)", self.header))
        elements.append(Spacer(1, 10))

        vuln_rows = [["Host", "Puerto", "CVE", "CVSS", "Severidad", "Descripción", "Fecha"]]
        for h in hosts_sorted:
            for p in h.ports:
                for v in p.vulnerabilities:
                    vuln_rows.append([
                        h.ip_address, p.port_number, v.cve_id,
                        v.cvss_score, v.severity,
                        (v.description[:150] + "...") if v.description else "N/A",
                        v.published_date.strftime("%Y-%m-%d") if v.published_date else "N/A"
                    ])

        elements.append(self._styled_table(vuln_rows, colors.red))

        doc.build(
            elements,
            onFirstPage=self._header_footer,
            onLaterPages=self._header_footer
        )

        return output_path
