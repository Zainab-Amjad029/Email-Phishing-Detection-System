from io import BytesIO
from datetime import datetime
import re
from email.parser import Parser
from email.policy import default

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    PageBreak,
)
from reportlab.platypus.flowables import Flowable


class RiskScoreBar(Flowable):
    def __init__(self, score, width=5 * inch, height=14):
        Flowable.__init__(self)
        self.score = score
        self.width = width
        self.height = height

    def draw(self):
        canvas = self.canv
        score = max(0, min(100, self.score))

        if score >= 80:
            fill_color = colors.HexColor("#dc3545")
        elif score >= 50:
            fill_color = colors.HexColor("#fd7e14")
        else:
            fill_color = colors.HexColor("#198754")

        canvas.setStrokeColor(colors.HexColor("#dee2e6"))
        canvas.setFillColor(colors.HexColor("#e9ecef"))
        canvas.rect(0, 0, self.width, self.height, fill=1, stroke=1)

        fill_width = (score / 100) * self.width
        canvas.setFillColor(fill_color)
        canvas.rect(0, 0, fill_width, self.height, fill=1, stroke=0)

        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawCentredString(
            self.width / 2,
            3,
            f"{score}% Risk"
        )


def _risk_level(score):
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def _extract_urls(text):
    return re.findall(r"https?://\S+", text or "")


def _parse_email_headers(text):
    if not text:
        return None

    header_text = text
    if "\n\n" in text:
        header_text = text.split("\n\n", 1)[0]

    try:
        return Parser(policy=default).parsestr(header_text)
    except Exception:
        return None


def _extract_sender(text):
    msg = _parse_email_headers(text)
    if msg is not None:
        sender = msg.get("From")
        if sender:
            return sender.strip()

    match = re.search(r"^\s*From:\s*(.+)$", text or "", re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else None


def _extract_receiver(text):
    msg = _parse_email_headers(text)
    if msg is not None:
        receiver = msg.get("To")
        if receiver:
            return receiver.strip()

    match = re.search(r"^\s*To:\s*(.+)$", text or "", re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else None


def _extract_subject(text):
    msg = _parse_email_headers(text)
    if msg is not None:
        subject = msg.get("Subject")
        if subject:
            return subject.strip()

    match = re.search(r"^\s*Subject:\s*(.+)$", text or "", re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else None


def _email_excerpt(text, limit=1200):
    body = (text or "").strip()
    if not body:
        return "No email content available."
    if len(body) <= limit:
        return body
    return body[:limit] + "\n\n[Content truncated for report]"


def _escape(text):
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )


def _add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(
        doc.leftMargin,
        0.45 * inch,
        "AI Phishing Email Detector — Automated Security Report"
    )
    canvas.drawRightString(
        A4[0] - doc.rightMargin,
        0.45 * inch,
        f"Page {doc.page}"
    )
    canvas.restoreState()


def generate_scan_pdf(scan, username, confidence=None, phishing_prob=None, safe_prob=None, ai_prediction=None, ai_confidence=None, ai_enabled=False):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="AI Phishing Scan Report",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor("#0d6efd"),
        spaceAfter=6,
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#212529"),
        spaceBefore=14,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="ReportBody",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        name="Muted",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.grey,
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="EmailBody",
        parent=styles["Code"],
        fontSize=8,
        leading=11,
        leftIndent=8,
        rightIndent=8,
        backColor=colors.HexColor("#f8f9fa"),
        borderPadding=8,
    ))
    styles.add(ParagraphStyle(
        name="ResultBadge",
        parent=styles["Heading1"],
        fontSize=18,
        alignment=TA_CENTER,
        spaceAfter=4,
    ))

    story = []
    prediction = scan.get("prediction", "UNKNOWN")
    risk_score = int(scan.get("risk_score", 0))
    risk_level = scan.get("risk_level") or _risk_level(risk_score)
    reasons = scan.get("reasons", [])
    if isinstance(reasons, str):
        reasons = [r.strip() for r in reasons.split(" | ") if r.strip()]

    email_text = scan.get("email_text", "")
    scan_date = scan.get("scan_date") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_id = scan.get("id", "N/A")

    story.append(Paragraph("AI Phishing Email Detector", styles["ReportTitle"]))
    story.append(Paragraph("Email Threat Analysis Report", styles["Heading3"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Generated: {scan_date}",
        styles["Muted"],
    ))
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0d6efd")))
    story.append(Spacer(1, 18))

    result_hex = "#dc3545" if prediction == "PHISHING" else "#198754"
    story.append(Paragraph(
        f'<font color="{result_hex}"><b>{prediction}</b></font>',
        styles["ResultBadge"],
    ))
    story.append(Paragraph(
        f"Threat Level: <b>{risk_level}</b>",
        styles["ReportBody"],
    ))
    story.append(Spacer(1, 10))
    story.append(RiskScoreBar(risk_score))
    story.append(Spacer(1, 18))

    summary_rows = [
        ["Field", "Value"],
        ["Scan ID", str(scan_id)],
        ["Classification", prediction],
        ["Risk Score", f"{risk_score}%"],
        ["Risk Level", risk_level],
    ]

    if confidence is not None:
        summary_rows.append(["Model Confidence", f"{confidence}%"])

    if ai_prediction is not None and ai_confidence is not None:
        summary_rows.append(["AI Prediction", ai_prediction])
        summary_rows.append(["AI Confidence", f"{ai_confidence}%"])

    if phishing_prob is not None and safe_prob is not None:
        summary_rows.append(["Phishing Probability", f"{round(phishing_prob * 100, 2)}%"])
        summary_rows.append(["Safe Probability", f"{round(safe_prob * 100, 2)}%"])

    summary_rows.extend([
        ["URLs Detected", str(len(_extract_urls(email_text)))],
        ["Indicators Found", str(len(reasons))],
    ])

    summary_table = Table(summary_rows, colWidths=[2.1 * inch, 4.4 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f0f4f8")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(Paragraph("Executive Summary", styles["SectionHeading"]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Detection Reasons", styles["SectionHeading"]))
    if reasons:
        reason_rows = [["#", "Indicator", "Category"]]
        for idx, reason in enumerate(reasons, start=1):
            category = "General"
            lower_reason = reason.lower()
            if any(token in lower_reason for token in ["suspicious word", "suspicious phrase", "suspicious language", "urgent", "pressure", "phishing score"]):
                category = "Content Warning"
            elif any(token in lower_reason for token in ["url", "link", "shortened", "domain"]):
                category = "URL Risk"
            elif any(token in lower_reason for token in ["spf", "dkim", "dmarc", "sender", "authentication", "spoof"]):
                category = "Header Analysis"
            elif any(token in lower_reason for token in ["ai check", "machine learning", "model detected", "phishing score"]):
                category = "AI Insight"
            elif "final decision" in lower_reason:
                category = "Conclusion"

            reason_text = Paragraph(_escape(reason), styles["ReportBody"])
            reason_rows.append([str(idx), reason_text, Paragraph(category, styles["ReportBody"])])

        reason_table = Table(reason_rows, colWidths=[0.4 * inch, 3.8 * inch, 2.3 * inch], repeatRows=1)
        reason_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#212529")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(reason_table)
    else:
        story.append(Paragraph("No specific threat indicators were recorded.", styles["ReportBody"]))

    story.append(Spacer(1, 16))
    story.append(Paragraph("Email Metadata", styles["SectionHeading"]))

    metadata_rows = [["Property", "Details"]]
    sender = _extract_sender(email_text)
    receiver = _extract_receiver(email_text)
    subject = _extract_subject(email_text)
    urls = _extract_urls(email_text)

    metadata_rows.append(["Sender", sender or "Not detected"])
    metadata_rows.append(["Receiver", receiver or "Not detected"])
    metadata_rows.append(["Subject", subject or "Not detected"])
    metadata_rows.append(["Character Count", str(len(email_text))])
    metadata_rows.append(["Line Count", str(len(email_text.splitlines()) if email_text else 0)])

    metadata_table = Table(metadata_rows, colWidths=[1.8 * inch, 4.7 * inch])
    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6c757d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(metadata_table)

    if urls:
        story.append(Spacer(1, 12))
        story.append(Paragraph("URLs Found in Email", styles["SectionHeading"]))
        url_rows = [["#", "URL"]]
        for idx, url in enumerate(urls[:15], start=1):
            url_rows.append([str(idx), url])
        if len(urls) > 15:
            url_rows.append(["...", f"({len(urls) - 15} additional URLs not shown)"])

        url_table = Table(url_rows, colWidths=[0.4 * inch, 6.1 * inch])
        url_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dc3545")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff5f5")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(url_table)

    story.append(PageBreak())
    story.append(Paragraph("Email Content (Excerpt)", styles["SectionHeading"]))
    story.append(Paragraph(_escape(_email_excerpt(email_text)), styles["EmailBody"]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Analysis Methodology", styles["SectionHeading"]))
    methodology = [
        "1. Machine learning model analyzes email text patterns and linguistic features.",
        "2. Rule-based engine checks for suspicious keywords, URLs, and text formatting.",
        "3. Risk score combines ML phishing probability with rule-based indicators.",
        "4. Final classification is PHISHING when the ML model predicts class 1.",
    ]
    for line in methodology:
        story.append(Paragraph(line, styles["ReportBody"]))
        story.append(Spacer(1, 4))

    if phishing_prob is not None:
        story.append(Spacer(1, 8))
        story.append(Paragraph("ML Probability Breakdown", styles["SectionHeading"]))
        ml_rows = [
            ["Metric", "Value"],
            ["Phishing Probability", f"{round(phishing_prob * 100, 2)}%"],
            ["Safe Probability", f"{round(safe_prob * 100, 2)}%"],
            ["Model Confidence", f"{confidence}%"],
            ["Final Risk Score", f"{risk_score}%"],
        ]
        ml_table = Table(ml_rows, colWidths=[2.5 * inch, 4 * inch])
        ml_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(ml_table)

    story.append(Spacer(1, 16))
    story.append(Paragraph("Security Recommendations", styles["SectionHeading"]))

    recommendations = [
        "Do not click links or open attachments in suspicious emails.",
        "Do not provide credentials, passwords, or personal information via email.",
        "Verify the sender's identity through a separate trusted communication channel.",
        "Report phishing attempts to your IT security team or email provider.",
        "Enable multi-factor authentication on all important accounts.",
        "Hover over links to inspect the actual destination before clicking.",
    ]

    if risk_level == "HIGH":
        recommendations.extend([
            "Quarantine this email immediately and do not interact with it.",
            "Contact your IT security department for further investigation.",
            "Check account activity for unauthorized access if credentials may have been exposed.",
        ])
    elif risk_level == "MEDIUM":
        recommendations.append(
            "Treat this email with caution until the sender can be independently verified."
        )

    for tip in recommendations:
        story.append(Paragraph(f"• {tip}", styles["ReportBody"]))
        story.append(Spacer(1, 3))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6")))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "<b>Disclaimer:</b> This report is generated by an automated AI-assisted phishing "
        "detection system. Results should be reviewed by a security professional and are "
        "not a substitute for human judgment or enterprise security policies.",
        styles["Muted"],
    ))

    doc.build(story, onFirstPage=_add_page_number, onLaterPages=_add_page_number)
    buffer.seek(0)
    return buffer
