"""
SIEM PDF Report Generator
Generates professional, detailed PDF reports for SIEM alerts, analytics, and LLM-powered SOC analyst summaries.
"""

import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Image,
    Flowable,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT


SEVERITY_COLORS = {
    "critical": HexColor("#dc2626"),
    "error": HexColor("#dc2626"),
    "warning": HexColor("#ea580c"),
    "high": HexColor("#ea580c"),
    "medium": HexColor("#ca8a04"),
    "info": HexColor("#16a34a"),
    "low": HexColor("#16a34a"),
    "unknown": HexColor("#6b7280"),
}

SEVERITY_BG_COLORS = {
    "critical": HexColor("#fecaca"),
    "error": HexColor("#fecaca"),
    "warning": HexColor("#fed7aa"),
    "high": HexColor("#fed7aa"),
    "medium": HexColor("#fef08a"),
    "info": HexColor("#bbf7d0"),
    "low": HexColor("#bbf7d0"),
    "unknown": HexColor("#e5e7eb"),
}


class SIEMPDFReport:
    def __init__(
        self,
        output_path: str,
        data: Dict[str, Any],
        llm_analysis: Optional[str] = None,
    ):
        self.output_path = output_path
        self.data = data
        self.llm_analysis = llm_analysis
        self.doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.elements = []

    def _setup_custom_styles(self):
        self.styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self.styles["Heading1"],
                fontSize=28,
                spaceAfter=8,
                alignment=TA_CENTER,
                textColor=HexColor("#0f172a"),
                fontName="Helvetica-Bold",
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ReportSubtitle",
                parent=self.styles["Normal"],
                fontSize=11,
                spaceAfter=20,
                alignment=TA_CENTER,
                textColor=HexColor("#64748b"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SectionHeader",
                parent=self.styles["Heading2"],
                fontSize=16,
                spaceBefore=24,
                spaceAfter=12,
                textColor=HexColor("#0f172a"),
                borderPadding=8,
                borderColor=HexColor("#3b82f6"),
                borderWidth=2,
                fontName="Helvetica-Bold",
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SubsectionHeader",
                parent=self.styles["Heading3"],
                fontSize=13,
                spaceBefore=16,
                spaceAfter=8,
                textColor=HexColor("#1e293b"),
                fontName="Helvetica-Bold",
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ReportBody",
                parent=self.styles["Normal"],
                fontSize=10,
                spaceAfter=10,
                alignment=TA_JUSTIFY,
                leading=14,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ReportBodySmall",
                parent=self.styles["Normal"],
                fontSize=9,
                spaceAfter=6,
                alignment=TA_LEFT,
                leading=12,
                textColor=HexColor("#475569"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="AlertText",
                parent=self.styles["Normal"],
                fontSize=9,
                spaceAfter=4,
                leading=12,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="BulletPoint",
                parent=self.styles["Normal"],
                fontSize=10,
                spaceAfter=6,
                leading=14,
                leftIndent=20,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="KeyValue",
                parent=self.styles["Normal"],
                fontSize=10,
                spaceAfter=4,
                leading=12,
            )
        )

    def generate(self) -> str:
        self._add_cover_page()
        self._add_executive_summary()
        if self.llm_analysis:
            self._add_llm_detailed_analysis()
        self._add_threat_intelligence()
        self._add_ml_findings()
        self._add_alerts_section()
        self._add_analytics_section()
        self._add_recommendations()
        self._add_appendix()
        self.doc.build(self.elements)
        return self.output_path

    def _add_cover_page(self):
        self.elements.append(Spacer(1, 1.5 * inch))
        self.elements.append(
            Paragraph("🛡️ SIEM SECURITY ANALYSIS REPORT", self.styles["ReportTitle"])
        )
        self.elements.append(Spacer(1, 20))

        formatted_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_type = self.data.get("detectedType", "Unknown")
        subtitle = f"Generated: {formatted_time} | Log Source Type: {log_type}"
        self.elements.append(Paragraph(subtitle, self.styles["ReportSubtitle"]))

        self.elements.append(Spacer(1, 30))

        stats = self.data.get("stats", {}) if self.data else {}
        total_logs = (
            stats.get("total", self.data.get("totalLines", 0)) if self.data else 0
        )
        parsed_lines = self.data.get("parsedLines", total_logs) if self.data else 0
        attack_summary = self.data.get("attackSummary", {}) if self.data else {}
        total_attacks = attack_summary.get("totalAttacks", 0) if attack_summary else 0
        ml_attacks = len(self.data.get("mlAttacks", [])) if self.data else 0

        risk_score = attack_summary.get("riskScore", 0) if attack_summary else 0
        risk_level = "LOW"
        if risk_score > 70:
            risk_level = "CRITICAL"
        elif risk_score > 50:
            risk_level = "HIGH"
        elif risk_score > 30:
            risk_level = "MEDIUM"

        # KPI Cards
        kpi_data = [
            ["Total Events", str(total_logs)],
            [
                "Parsed Successfully",
                f"{parsed_lines} ({int(parsed_lines / total_logs * 100) if total_logs > 0 else 0}%)",
            ],
            ["Risk Level", risk_level],
            ["ML Detected Threats", str(ml_attacks)],
        ]

        kpi_table = Table(kpi_data, colWidths=[2.5 * inch, 2.5 * inch])
        kpi_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), HexColor("#f1f5f9")),
                    ("BACKGROUND", (1, 0), (1, -1), HexColor("#e2e8f0")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), HexColor("#0f172a")),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 12),
                    ("GRID", (0, 0), (-1, -1), 1, HexColor("#cbd5e1")),
                    ("TOPPADDING", (0, 0), (-1, -1), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ]
            )
        )
        self.elements.append(kpi_table)

        self.elements.append(Spacer(1, 20))

        # Risk Score Bar
        risk_color = SEVERITY_COLORS.get(risk_level.lower(), SEVERITY_COLORS["unknown"])
        risk_bg = SEVERITY_BG_COLORS.get(
            risk_level.lower(), SEVERITY_BG_COLORS["unknown"]
        )

        risk_table = Table(
            [[f"Overall Risk Score: {risk_score}/100 ({risk_level})"]],
            colWidths=[5.5 * inch],
        )
        risk_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), risk_bg),
                    ("TEXTCOLOR", (0, 0), (-1, -1), risk_color),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 16),
                    ("TOPPADDING", (0, 0), (-1, -1), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                    ("BOX", (0, 0), (-1, -1), 3, risk_color),
                ]
            )
        )
        self.elements.append(risk_table)
        self.elements.append(PageBreak())

    def _add_executive_summary(self):
        self.elements.append(
            Paragraph("1. EXECUTIVE SUMMARY", self.styles["SectionHeader"])
        )

        stats = self.data.get("stats", {}) if self.data else {}
        total_logs = (
            stats.get("total", self.data.get("totalLines", 0)) if self.data else 0
        )
        parsed_lines = self.data.get("parsedLines", total_logs) if self.data else 0
        failed_lines = self.data.get("failedLines", 0) if self.data else 0

        entries = self.data.get("entries", []) if self.data else []
        ml_attacks = self.data.get("mlAttacks", []) if self.data else []

        attack_summary = self.data.get("attackSummary", {}) if self.data else {}
        attack_types = attack_summary.get("attackTypes", []) if attack_summary else []

        summary_text = f"""
This comprehensive security report presents the analysis of <b>{total_logs:,}</b> log events from the SIEM system. 
The analysis successfully parsed <b>{parsed_lines:,}</b> events ({int(parsed_lines / total_logs * 100) if total_logs > 0 else 0}% success rate) 
with <b>{failed_lines:,}</b> events failing to parse.
"""
        self.elements.append(Paragraph(summary_text, self.styles["ReportBody"]))

        if ml_attacks:
            self.elements.append(Spacer(1, 10))
            threat_text = f"""
<b>🚨 Threat Detection Summary:</b><br/>
The ML-based threat detection engine identified <b>{len(ml_attacks)}</b> potential security threats across the analyzed logs. 
"""
            if attack_types:
                threat_text += f"Primary attack categories detected: <b>{', '.join(attack_types[:5])}</b>."
            self.elements.append(Paragraph(threat_text, self.styles["ReportBody"]))
        else:
            self.elements.append(
                Paragraph(
                    "✅ <b>No ML-detected threats</b> were found in the analyzed log sample. The security posture appears normal.",
                    self.styles["ReportBody"],
                )
            )

        self.elements.append(Spacer(1, 15))

    def _add_llm_detailed_analysis(self):
        self.elements.append(PageBreak())
        self.elements.append(
            Paragraph("2. AI-POWERED THREAT ANALYSIS", self.styles["SectionHeader"])
        )
        self.elements.append(
            Paragraph(
                "This section contains detailed threat analysis generated by our AI SOC Analyst.",
                self.styles["ReportBodySmall"],
            )
        )
        self.elements.append(Spacer(1, 15))

        lines = self.llm_analysis.split("\n")
        in_section = None
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Check if this is a section header
            if any(
                keyword in line.upper()
                for keyword in [
                    "EXECUTIVE SUMMARY",
                    "KEY FINDINGS",
                    "ATTACK CHAIN",
                    "THREAT INTELLIGENCE",
                    "RISK ASSESSMENT",
                    "RECOMMENDATIONS",
                    "INCIDENT RESPONSE",
                ]
            ):
                if in_section:
                    self.elements.append(Spacer(1, 10))
                self.elements.append(
                    Paragraph(f"<b>{line}</b>", self.styles["SubsectionHeader"])
                )
                in_section = line
            elif line.startswith("-") or line.startswith("•"):
                self.elements.append(
                    Paragraph(f"• {line[1:].strip()}", self.styles["BulletPoint"])
                )
            elif line[0].isdigit() and "." in line[:3]:
                self.elements.append(Paragraph(line, self.styles["ReportBody"]))
            else:
                self.elements.append(Paragraph(line, self.styles["ReportBody"]))

        self.elements.append(Spacer(1, 15))

    def _add_threat_intelligence(self):
        self.elements.append(PageBreak())
        self.elements.append(
            Paragraph("3. THREAT INTELLIGENCE & IOCs", self.styles["SectionHeader"])
        )

        entries = self.data.get("entries", []) if self.data else []

        # Extract unique IPs
        ip_counts = {}
        user_counts = {}

        for entry in entries:
            if "source" in entry and entry["source"]:
                ip = entry["source"].get("ip")
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            elif entry.get("sourceIp"):
                ip_counts[entry.get("sourceIp")] = (
                    ip_counts.get(entry.get("sourceIp"), 0) + 1
                )

            if "user" in entry and entry["user"]:
                user = entry["user"].get("name")
                if user:
                    user_counts[user] = user_counts.get(user, 0) + 1
            elif entry.get("targetUser"):
                user_counts[entry.get("targetUser")] = (
                    user_counts.get(entry.get("targetUser"), 0) + 1
                )

        # Top Malicious IPs
        if ip_counts:
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[
                :10
            ]
            self.elements.append(
                Paragraph(
                    "<b>Top Source IP Addresses (by event count)</b>",
                    self.styles["SubsectionHeader"],
                )
            )

            ip_data = [["Rank", "IP Address", "Events", "Risk Assessment"]]
            for i, (ip, count) in enumerate(sorted_ips, 1):
                risk = "HIGH" if count > 100 else "MEDIUM" if count > 50 else "LOW"
                ip_data.append([str(i), ip, str(count), risk])

            ip_table = Table(
                ip_data, colWidths=[0.5 * inch, 2.5 * inch, 1 * inch, 1.5 * inch]
            )
            ip_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1e293b")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), white),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            self.elements.append(ip_table)
            self.elements.append(Spacer(1, 15))

        # Top Target Users
        if user_counts:
            sorted_users = sorted(
                user_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]
            self.elements.append(
                Paragraph(
                    "<b>Most Targeted User Accounts</b>",
                    self.styles["SubsectionHeader"],
                )
            )

            user_data = [["Rank", "Username", "Events", "Priority"]]
            for i, (user, count) in enumerate(sorted_users, 1):
                priority = (
                    "CRITICAL" if count > 50 else "HIGH" if count > 20 else "MEDIUM"
                )
                user_data.append([str(i), user, str(count), priority])

            user_table = Table(
                user_data, colWidths=[0.5 * inch, 2.5 * inch, 1 * inch, 1.5 * inch]
            )
            user_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#7c3aed")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), white),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            self.elements.append(user_table)

        self.elements.append(Spacer(1, 15))

    def _add_ml_findings(self):
        ml_attacks = self.data.get("mlAttacks", []) if self.data else []

        if not ml_attacks:
            return

        self.elements.append(PageBreak())
        self.elements.append(
            Paragraph("4. ML-BASED THREAT DETECTION", self.styles["SectionHeader"])
        )
        self.elements.append(
            Paragraph(
                f"The machine learning classifier identified <b>{len(ml_attacks)}</b> potential threat events.",
                self.styles["ReportBody"],
            )
        )
        self.elements.append(Spacer(1, 10))

        # Group by attack type
        attack_groups = {}
        for attack in ml_attacks:
            attack_type = attack.get("attackType", "unknown")
            if attack_type not in attack_groups:
                attack_groups[attack_type] = []
            attack_groups[attack_type].append(attack)

        for attack_type, attacks in attack_groups.items():
            self.elements.append(
                Paragraph(
                    f"<b>🔴 {attack_type.replace('_', ' ').upper()}</b> - {len(attacks)} detections",
                    self.styles["SubsectionHeader"],
                )
            )

            for attack in attacks[:5]:
                entry = attack.get("entry", {})
                conf = attack.get("confidence", 0) * 100
                self.elements.append(
                    Paragraph(
                        f"• {entry.get('message', 'N/A')[:150]}",
                        self.styles["ReportBodySmall"],
                    )
                )
                self.elements.append(
                    Paragraph(
                        f"  Confidence: {conf:.1f}% | Severity: {entry.get('severity', 'unknown').upper()}",
                        self.styles["ReportBodySmall"],
                    )
                )

            if len(attacks) > 5:
                self.elements.append(
                    Paragraph(
                        f"  ... and {len(attacks) - 5} more {attack_type} events",
                        self.styles["ReportBodySmall"],
                    )
                )
            self.elements.append(Spacer(1, 10))

        self.elements.append(Spacer(1, 10))

    def _add_alerts_section(self):
        alerts = self.data.get("alerts", []) if self.data else []

        if not alerts:
            return

        self.elements.append(PageBreak())
        self.elements.append(
            Paragraph("5. SECURITY ALERTS", self.styles["SectionHeader"])
        )
        self.elements.append(
            Paragraph(
                f"Total alerts generated: <b>{len(alerts)}</b>. Showing top 15 alerts.",
                self.styles["ReportBody"],
            )
        )
        self.elements.append(Spacer(1, 10))

        for i, alert in enumerate(alerts[:15], 1):
            severity = alert.get("severity", "info").lower()
            color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["unknown"])
            bg = SEVERITY_BG_COLORS.get(severity, SEVERITY_BG_COLORS["unknown"])

            header = f"Alert #{i}: {alert.get('type', 'Unknown Alert')}"

            # Alert header with severity
            header_table = Table([[header]], colWidths=[6 * inch])
            header_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), bg),
                        ("TEXTCOLOR", (0, 0), (-1, -1), color),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 11),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("BOX", (0, 0), (-1, -1), 1, color),
                    ]
                )
            )
            self.elements.append(header_table)

            self.elements.append(
                Paragraph(
                    f"<b>Timestamp:</b> {alert.get('timestamp', 'N/A')} | <b>Source:</b> {alert.get('source', 'N/A')}",
                    self.styles["AlertText"],
                )
            )
            self.elements.append(
                Paragraph(
                    f"<b>Message:</b> {alert.get('message', 'N/A')}",
                    self.styles["AlertText"],
                )
            )
            self.elements.append(Spacer(1, 8))

        if len(alerts) > 15:
            self.elements.append(
                Paragraph(
                    f"... and <b>{len(alerts) - 15}</b> more alerts. See full report for complete list.",
                    self.styles["ReportBody"],
                )
            )

        self.elements.append(Spacer(1, 15))

    def _add_analytics_section(self):
        self.elements.append(PageBreak())
        self.elements.append(
            Paragraph("6. LOG ANALYTICS & STATISTICS", self.styles["SectionHeader"])
        )

        stats = self.data.get("stats", {}) if self.data else {}

        # Severity Distribution
        self.elements.append(
            Paragraph(
                "<b>6.1 Severity Distribution</b>", self.styles["SubsectionHeader"]
            )
        )
        sev_data = [["Severity Level", "Event Count", "Percentage"]]
        by_sev = stats.get("bySeverity", {})
        total_sev = sum(by_sev.values()) if by_sev else 1

        for sev in ["critical", "error", "warning", "info", "debug"]:
            count = by_sev.get(sev, 0)
            pct = (count / total_sev * 100) if total_sev > 0 else 0
            sev_data.append([sev.upper(), str(count), f"{pct:.1f}%"])

        sev_table = Table(sev_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        sev_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), HexColor("#334155")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), white),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
                ]
            )
        )
        self.elements.append(sev_table)
        self.elements.append(Spacer(1, 15))

        # Log Types
        by_type = stats.get("byType", {})
        if by_type:
            self.elements.append(
                Paragraph(
                    "<b>6.2 Log Type Distribution</b>", self.styles["SubsectionHeader"]
                )
            )
            type_data = [["Log Type", "Count"]]
            for log_type, count in sorted(
                by_type.items(), key=lambda x: x[1], reverse=True
            )[:10]:
                type_data.append([log_type, str(count)])

            type_table = Table(type_data, colWidths=[3.5 * inch, 1.5 * inch])
            type_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#0f172a")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), white),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
                    ]
                )
            )
            self.elements.append(type_table)
            self.elements.append(Spacer(1, 15))

        # Top Sources
        top_sources = stats.get("topSources", [])[:10]
        if top_sources:
            self.elements.append(
                Paragraph(
                    "<b>6.3 Top Source IP Addresses</b>",
                    self.styles["SubsectionHeader"],
                )
            )
            source_data = [["Rank", "IP Address", "Event Count", "Activity Level"]]
            for i, src in enumerate(top_sources, 1):
                count = src.get("count", 0)
                level = "HIGH" if count > 100 else "MEDIUM" if count > 50 else "LOW"
                source_data.append([str(i), src.get("ip", "N/A"), str(count), level])

            source_table = Table(
                source_data, colWidths=[0.5 * inch, 2.5 * inch, 1.5 * inch, 1.5 * inch]
            )
            source_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1e293b")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), white),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
                    ]
                )
            )
            self.elements.append(source_table)

        self.elements.append(Spacer(1, 15))

    def _add_recommendations(self):
        self.elements.append(PageBreak())
        self.elements.append(
            Paragraph("7. RECOMMENDATIONS & REMEDIATION", self.styles["SectionHeader"])
        )

        recommendations = [
            (
                "Critical",
                "Immediately investigate all critical and high-severity alerts. Isolate affected systems if compromise is suspected.",
            ),
            (
                "High Priority",
                "Review and block suspicious IP addresses with high event counts. Implement additional monitoring on targeted accounts.",
            ),
            (
                "Medium Priority",
                "Enable enhanced logging for critical systems. Review access controls for accounts with failed authentication attempts.",
            ),
            (
                "Best Practices",
                "Ensure all systems are patched and up-to-date. Implement MFA for all privileged accounts. Regular review of security logs.",
            ),
            (
                "Monitoring",
                "Set up real-time alerts for threshold-based detections. Create correlation rules for multi-stage attack patterns.",
            ),
            (
                "Response",
                "Document and test incident response procedures. Ensure backup and recovery mechanisms are functional.",
            ),
        ]

        for priority, recommendation in recommendations:
            priority_color = (
                HexColor("#dc2626")
                if priority == "Critical"
                else HexColor("#ea580c")
                if priority == "High Priority"
                else HexColor("#16a34a")
            )

            self.elements.append(
                Paragraph(
                    f"<font color='{priority_color}'><b>◆ {priority}</b></font>",
                    self.styles["SubsectionHeader"],
                )
            )
            self.elements.append(Paragraph(recommendation, self.styles["ReportBody"]))
            self.elements.append(Spacer(1, 10))

        self.elements.append(Spacer(1, 15))

    def _add_appendix(self):
        self.elements.append(PageBreak())
        self.elements.append(Paragraph("8. APPENDIX", self.styles["SectionHeader"]))

        self.elements.append(
            Paragraph("<b>Report Metadata</b>", self.styles["SubsectionHeader"])
        )

        metadata = [
            ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            [
                "Log Source Type",
                self.data.get("detectedType", "Unknown") if self.data else "Unknown",
            ],
            ["Total Lines", str(self.data.get("totalLines", 0)) if self.data else "0"],
            [
                "Parsed Lines",
                str(self.data.get("parsedLines", 0)) if self.data else "0",
            ],
            [
                "Failed Lines",
                str(self.data.get("failedLines", 0)) if self.data else "0",
            ],
            [
                "ML Attacks Detected",
                str(len(self.data.get("mlAttacks", []))) if self.data else "0",
            ],
            [
                "Total Alerts",
                str(len(self.data.get("alerts", []))) if self.data else "0",
            ],
            ["Analysis Engine", "Cyber Chakshu SIEM v2.0 + AI SOC Analyst"],
        ]

        meta_table = Table(metadata, colWidths=[2 * inch, 4 * inch])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), HexColor("#f1f5f9")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), HexColor("#0f172a")),
                    ("ALIGN", (0, 0), (0, -1), "LEFT"),
                    ("ALIGN", (1, 0), (1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        self.elements.append(meta_table)

        self.elements.append(Spacer(1, 30))

        # Footer
        footer_text = """
        <b>Disclaimer:</b> This report is generated automatically by Cyber Chakshu SIEM system. 
        The analysis is based on log data and machine learning models. 
        Human review is recommended for critical security decisions.
        """
        self.elements.append(Paragraph(footer_text, self.styles["ReportBodySmall"]))
        self.elements.append(Spacer(1, 10))
        self.elements.append(
            Paragraph(
                "© 2024 Cyber Chakshu SIEM | Security Analysis Report",
                self.styles["ReportSubtitle"],
            )
        )
