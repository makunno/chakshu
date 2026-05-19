"""
Forensic PDF Report Generator
Generates professional PDF reports combining AI analysis and anti-forensic findings.
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
    ListFlowable,
    ListItem,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY


SEVERITY_COLORS = {
    "CRITICAL": HexColor("#dc2626"),
    "HIGH": HexColor("#ea580c"),
    "MEDIUM": HexColor("#ca8a04"),
    "LOW": HexColor("#16a34a"),
    "UNKNOWN": HexColor("#6b7280"),
}

SEVERITY_BG_COLORS = {
    "CRITICAL": HexColor("#fecaca"),
    "HIGH": HexColor("#fed7aa"),
    "MEDIUM": HexColor("#fef08a"),
    "LOW": HexColor("#bbf7d0"),
    "UNKNOWN": HexColor("#e5e7eb"),
}


class ForensicPDFReport:
    def __init__(
        self,
        output_path: str,
        image_path: str,
        ai_results: Dict[str, Any],
        antiforensic_results: Dict[str, Any],
    ):
        self.output_path = output_path
        self.image_path = image_path
        self.ai_results = ai_results
        self.antiforensic_results = antiforensic_results
        self.doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.elements = []

    def _setup_custom_styles(self):
        self.styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self.styles["Heading1"],
                fontSize=24,
                spaceAfter=6,
                alignment=TA_CENTER,
                textColor=HexColor("#1f2937"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ReportSubtitle",
                parent=self.styles["Normal"],
                fontSize=10,
                spaceAfter=20,
                alignment=TA_CENTER,
                textColor=HexColor("#6b7280"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SectionHeader",
                parent=self.styles["Heading2"],
                fontSize=14,
                spaceBefore=20,
                spaceAfter=10,
                textColor=HexColor("#1f2937"),
                borderPadding=5,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SubSectionHeader",
                parent=self.styles["Heading3"],
                fontSize=12,
                spaceBefore=12,
                spaceAfter=6,
                textColor=HexColor("#374151"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ReportBody",
                parent=self.styles["Normal"],
                fontSize=10,
                spaceAfter=8,
                alignment=TA_JUSTIFY,
                leading=14,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="FindingText",
                parent=self.styles["Normal"],
                fontSize=9,
                spaceAfter=4,
                leftIndent=20,
                leading=12,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="RiskBadge",
                parent=self.styles["Normal"],
                fontSize=16,
                alignment=TA_CENTER,
                textColor=white,
            )
        )

    def generate(self) -> str:
        self._add_header()
        self._add_executive_summary()
        self._add_ai_findings()
        self._add_antiforensic_analysis()
        self._add_summary_statistics()
        self._add_recommendations()
        self.doc.build(self.elements)
        return self.output_path

    def _add_header(self):
        self.elements.append(
            Paragraph("FORENSIC ANALYSIS REPORT", self.styles["ReportTitle"])
        )
        timestamp = self.ai_results.get("timestamp", datetime.now().isoformat())
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                formatted_time = timestamp
        else:
            formatted_time = "N/A"
        model = self.ai_results.get("model", "Unknown")
        subtitle = f"Image: {os.path.basename(self.image_path)} • {formatted_time} • Model: {model}"
        self.elements.append(Paragraph(subtitle, self.styles["ReportSubtitle"]))
        risk_level = self.ai_results.get("risk_level", "UNKNOWN")
        risk_color = SEVERITY_COLORS.get(risk_level, SEVERITY_COLORS["UNKNOWN"])
        bg_color = SEVERITY_BG_COLORS.get(risk_level, SEVERITY_BG_COLORS["UNKNOWN"])
        risk_table = Table(
            [[f"Risk Level: {risk_level}"]],
            colWidths=[3 * inch],
        )
        risk_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                    ("TEXTCOLOR", (0, 0), (-1, -1), risk_color),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 14),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 2, risk_color),
                ]
            )
        )
        self.elements.append(risk_table)
        self.elements.append(Spacer(1, 20))

    def _add_executive_summary(self):
        self.elements.append(
            Paragraph("EXECUTIVE SUMMARY", self.styles["SectionHeader"])
        )
        summary = self.ai_results.get("summary", "No summary available.")
        self.elements.append(Paragraph(summary, self.styles["ReportBody"]))
        analysis_time = self.ai_results.get("analysis_time_seconds", 0)
        findings_count = len(self.ai_results.get("findings", []))
        af_summary = self.antiforensic_results.get("summary", {})
        af_indicators = af_summary.get("total_indicators", 0)
        summary_text = f"Analysis completed in {analysis_time:.1f} seconds. "
        summary_text += f"AI analysis identified {findings_count} findings. "
        summary_text += (
            f"Anti-forensic analysis detected {af_indicators} potential indicators."
        )
        self.elements.append(Paragraph(summary_text, self.styles["ReportBody"]))
        self.elements.append(Spacer(1, 10))

    def _add_ai_findings(self):
        self.elements.append(
            Paragraph("AI ANALYSIS FINDINGS", self.styles["SectionHeader"])
        )
        findings = self.ai_results.get("findings", [])
        if not findings:
            self.elements.append(
                Paragraph(
                    "No significant findings detected by AI analysis.",
                    self.styles["ReportBody"],
                )
            )
            return
        for i, finding in enumerate(findings, 1):
            self._add_finding(finding, i)
        self.elements.append(Spacer(1, 10))

    def _add_finding(self, finding: Dict[str, Any], index: int):
        severity = finding.get("severity", "UNKNOWN")
        technique = finding.get("technique", "Unknown")
        evidence = finding.get("evidence", "N/A")
        explanation = finding.get("explanation", "N/A")
        recommendation = finding.get("recommendation", "N/A")
        confidence = finding.get("confidence", 0.0)
        sev_color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"])
        bg_color = SEVERITY_BG_COLORS.get(severity, SEVERITY_BG_COLORS["UNKNOWN"])
        header_data = [
            [
                f"Finding #{index}: {technique}",
                f"{severity}",
                f"{confidence * 100:.0f}% conf",
            ]
        ]
        header_table = Table(header_data, colWidths=[4 * inch, 1 * inch, 1 * inch])
        header_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), HexColor("#f3f4f6")),
                    ("BACKGROUND", (1, 0), (1, 0), bg_color),
                    ("TEXTCOLOR", (0, 0), (0, 0), HexColor("#1f2937")),
                    ("TEXTCOLOR", (1, 0), (1, 0), sev_color),
                    ("TEXTCOLOR", (2, 0), (2, 0), HexColor("#6b7280")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                    ("ALIGN", (0, 0), (0, 0), "LEFT"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 1, HexColor("#d1d5db")),
                ]
            )
        )
        self.elements.append(header_table)
        content_data = [
            ["Evidence:", evidence[:200] + "..." if len(evidence) > 200 else evidence],
            [
                "Explanation:",
                explanation[:200] + "..." if len(explanation) > 200 else explanation,
            ],
            [
                "Recommendation:",
                recommendation[:200] + "..."
                if len(recommendation) > 200
                else recommendation,
            ],
        ]
        content_table = Table(content_data, colWidths=[1.2 * inch, 4.8 * inch])
        content_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("TEXTCOLOR", (0, 0), (-1, -1), HexColor("#374151")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        self.elements.append(content_table)
        self.elements.append(Spacer(1, 8))

    def _add_antiforensic_analysis(self):
        self.elements.append(
            Paragraph("ANTI-FORENSIC ANALYSIS", self.styles["SectionHeader"])
        )
        categories = [
            (
                "TIMESTOMPING DETECTION",
                "timestomping",
                "Detects manipulation of file timestamps",
            ),
            (
                "SHADOW COPY DELETION",
                "shadow_copy_deletion",
                "Evidence of VSS deletion attempts",
            ),
            (
                "HIDDEN DATA STREAMS (ADS)",
                "hidden_streams",
                "Alternate Data Streams detection",
            ),
            ("LOG CLEARING EVIDENCE", "log_clearing", "Evidence of log file clearing"),
            (
                "REGISTRY TAMPERING",
                "registry_tampering",
                "Registry modification indicators",
            ),
            (
                "FILE DELETION TRACKING",
                "file_deletion",
                "Deleted file recovery opportunities",
            ),
            ("MFT ANOMALIES", "mft_anomalies", "Master File Table irregularities"),
        ]
        for title, key, description in categories:
            self._add_antiforensic_category(title, key, description)
        self.elements.append(Spacer(1, 10))

    def _add_antiforensic_category(self, title: str, key: str, description: str):
        findings = self.antiforensic_results.get(key, [])
        count = len(findings)
        if count > 0:
            indicator_color = HexColor("#ea580c")
            status = f"[{count} indicator{'s' if count != 1 else ''}]"
        else:
            indicator_color = HexColor("#16a34a")
            status = "[Clear]"
        header_data = [[f"{title} {status}"]]
        header_table = Table(header_data, colWidths=[6 * inch])
        header_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f3f4f6")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), indicator_color),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 11),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 1, indicator_color),
                ]
            )
        )
        self.elements.append(header_table)
        self.elements.append(
            Paragraph(f"<i>{description}</i>", self.styles["FindingText"])
        )
        if findings:
            for finding in findings[:15]:
                clean_finding = finding.replace("<", "&lt;").replace(">", "&gt;")
                self.elements.append(
                    Paragraph(f"• {clean_finding}", self.styles["FindingText"])
                )
            if len(findings) > 15:
                self.elements.append(
                    Paragraph(
                        f"  ... and {len(findings) - 15} more",
                        self.styles["FindingText"],
                    )
                )
        else:
            self.elements.append(
                Paragraph(
                    "  No indicators found in this category.",
                    self.styles["FindingText"],
                )
            )
        self.elements.append(Spacer(1, 6))

    def _add_summary_statistics(self):
        self.elements.append(
            Paragraph("SUMMARY STATISTICS", self.styles["SectionHeader"])
        )
        summary = self.antiforensic_results.get("summary", {})
        total_indicators = summary.get("total_indicators", 0)
        risk_level = summary.get("risk_level", "LOW")
        stats_data = [
            ["Category", "Indicators"],
            ["Timestomping", str(summary.get("total_timestomping_indicators", 0))],
            [
                "Shadow Copy Deletion",
                str(summary.get("total_shadow_copy_indicators", 0)),
            ],
            ["Hidden Streams (ADS)", str(summary.get("total_ads_indicators", 0))],
            ["Log Clearing", str(summary.get("total_log_clearing_indicators", 0))],
            ["Registry Tampering", str(summary.get("total_registry_indicators", 0))],
            ["File Deletion", str(summary.get("total_deletion_indicators", 0))],
            ["MFT Anomalies", str(summary.get("total_mft_anomalies", 0))],
            ["TOTAL", str(total_indicators)],
        ]
        stats_table = Table(stats_data, colWidths=[3 * inch, 1.5 * inch])
        stats_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), HexColor("#374151")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
                    ("BACKGROUND", (0, -1), (-1, -1), HexColor("#e5e7eb")),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                    ("ALIGN", (0, 0), (0, -1), "LEFT"),
                    ("GRID", (0, 0), (-1, -1), 1, HexColor("#d1d5db")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        self.elements.append(stats_table)
        self.elements.append(Spacer(1, 10))
        risk_color = SEVERITY_COLORS.get(risk_level, SEVERITY_COLORS["LOW"])
        bg_color = SEVERITY_BG_COLORS.get(risk_level, SEVERITY_BG_COLORS["LOW"])
        risk_table = Table(
            [[f"Overall Anti-Forensic Risk Level: {risk_level}"]],
            colWidths=[4 * inch],
        )
        risk_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                    ("TEXTCOLOR", (0, 0), (-1, -1), risk_color),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 12),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 2, risk_color),
                ]
            )
        )
        self.elements.append(risk_table)
        self.elements.append(Spacer(1, 10))

    def _add_recommendations(self):
        self.elements.append(Paragraph("RECOMMENDATIONS", self.styles["SectionHeader"]))
        recommendations = self.ai_results.get("recommendations", [])
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                clean_rec = rec.replace("<", "&lt;").replace(">", "&gt;")
                self.elements.append(
                    Paragraph(f"{i}. {clean_rec}", self.styles["ReportBody"])
                )
        else:
            default_recommendations = [
                "Preserve the original forensic image in a secure location with chain of custody documentation.",
                "Document all findings with timestamps and maintain detailed analysis notes.",
                "If anti-forensic techniques are detected, investigate the timeline around those events.",
                "Cross-reference findings with external threat intelligence sources.",
                "Consider engaging additional forensic expertise for critical findings.",
            ]
            for i, rec in enumerate(default_recommendations, 1):
                self.elements.append(
                    Paragraph(f"{i}. {rec}", self.styles["ReportBody"])
                )
        af_summary = self.antiforensic_results.get("summary", {})
        af_risk = af_summary.get("risk_level", "LOW")
        if af_risk in ["HIGH", "MEDIUM"]:
            self.elements.append(Spacer(1, 10))
            self.elements.append(
                Paragraph(
                    "Additional Anti-Forensic Investigation Steps:",
                    self.styles["SubSectionHeader"],
                )
            )
            af_recommendations = [
                "Conduct detailed timeline analysis around detected anomalies.",
                "Examine Windows Event Logs for evidence of vssadmin or wevtutil commands.",
                "Analyze $MFT and $UsnJrnl for file system manipulation evidence.",
                "Review Registry hives for persistence mechanisms and tool artifacts.",
                "Search for known anti-forensic tool signatures and artifacts.",
            ]
            for rec in af_recommendations:
                self.elements.append(Paragraph(f"• {rec}", self.styles["FindingText"]))
