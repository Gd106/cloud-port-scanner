"""PDF (ReportLab), CSV and JSON report builders."""
import csv
import io
import json
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

PROJECT_TITLE = "Python-Based Cloud Port Scanner and Security Reporter"

NAVY = colors.HexColor("#0a1628")
BLUE = colors.HexColor("#1d6fa5")
LIGHT = colors.HexColor("#eef3f8")
GRID = colors.HexColor("#c9d4e0")
RISK_COLORS = {
    "HIGH": colors.HexColor("#c62828"),
    "MEDIUM": colors.HexColor("#e07b00"),
    "LOW": colors.HexColor("#1565c0"),
    "INFO": colors.HexColor("#2e7d32"),
    "NONE": colors.HexColor("#546e7a"),
}
RISK_LABEL = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Informational", "NONE": "None"}


def fmt_time(iso):
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %Y, %H:%M:%S %Z").strip()
    except ValueError:
        return str(iso)


def fmt_duration(seconds):
    if seconds is None:
        return "-"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    minutes, rest = divmod(seconds, 60)
    return f"{int(minutes)} min {rest:.1f} s"


# ---------------------------------------------------------------- CSV
def to_csv(scan):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(["scan_id", "target", "resolved_ip", "scan_started", "scan_completed", "duration_seconds",
                     "port", "probable_service", "status", "risk", "explanation", "mitigation"])
    base = [scan["id"], scan["target"], scan["resolved_ip"], scan["started_at"], scan["completed_at"] or "",
            scan["duration_seconds"] if scan["duration_seconds"] is not None else ""]
    if scan["open_ports"]:
        for p in scan["open_ports"]:
            writer.writerow(base + [p["port"], p["service"], p["status"], p["risk"],
                                    p["explanation"], p["mitigation"]])
    else:
        writer.writerow(base + ["", "", "no open ports found", "NONE", "", ""])
    return out.getvalue()


# --------------------------------------------------------------- JSON
def to_json(scan):
    keys = ["id", "target", "resolved_ip", "start_port", "end_port", "timeout", "workers", "status",
            "started_at", "completed_at", "duration_seconds", "total_scanned", "open_count",
            "closed_count", "filtered_count", "high_count", "medium_count", "overall_risk"]
    document = {
        "report": PROJECT_TITLE,
        "scan": {k: scan[k] for k in keys},
        "open_ports": scan["open_ports"],
        "recommendations": scan["recommendations"],
        "summary": scan["summary"],
        "disclaimer": scan["disclaimer"],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------- PDF
def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6b7c8f"))
    canvas.drawString(15 * mm, 9 * mm, f"{PROJECT_TITLE}  |  For authorized security assessment only")
    canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def generate_pdf(scan, path):
    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, leading=11)
    cell_bold = ParagraphStyle("cellb", parent=small, fontName="Helvetica-Bold")
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=NAVY, fontSize=13, spaceBefore=12, spaceAfter=6)
    title = ParagraphStyle("title", parent=styles["Title"], textColor=colors.white, fontSize=17,
                           leading=21, alignment=0)
    subtitle = ParagraphStyle("sub", parent=body, textColor=colors.HexColor("#8fd3ff"), fontSize=11)

    def P(text, style=small):
        return Paragraph(escape(str(text)), style)

    def risk_para(risk):
        return Paragraph(f'<font color="{RISK_COLORS.get(risk, colors.black).hexval()}"><b>'
                         f'{RISK_LABEL.get(risk, risk)}</b></font>'.replace("0x", "#"), small)

    ports = scan["open_ports"]
    story = []

    banner = Table([[Paragraph(escape(PROJECT_TITLE), title)], [Paragraph("Security Scan Report", subtitle)]],
                   colWidths=[180 * mm])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (0, 0), 14), ("BOTTOMPADDING", (0, -1), (-1, -1), 12),
        ("LINEBELOW", (0, -1), (-1, -1), 3, colors.HexColor("#00c853")),
    ]))
    story += [banner, Spacer(1, 8)]

    story.append(Paragraph("1. Scan Details", h2))
    details = [
        ("Scan ID", scan["id"]),
        ("Target (IP / hostname)", scan["target"]),
        ("Resolved IP address", scan["resolved_ip"]),
        ("Scan date and time", fmt_time(scan["started_at"])),
        ("Completed", fmt_time(scan["completed_at"])),
        ("Scan duration", fmt_duration(scan["duration_seconds"])),
        ("Port range", f"{scan['start_port']} - {scan['end_port']}"),
        ("Total ports scanned", scan["total_scanned"]),
        ("Total open ports", scan["open_count"]),
        ("Closed / filtered ports", f"{scan['closed_count']} / {scan['filtered_count']}"),
        ("Scan status", scan["status"].capitalize()),
        ("Overall risk level", RISK_LABEL.get(scan["overall_risk"], scan["overall_risk"])),
    ]
    table = Table([[P(k, cell_bold), P(v)] for k, v in details], colWidths=[55 * mm, 125 * mm])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, GRID),
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(table)

    story.append(Paragraph("2. Detected Services and Risk Classification", h2))
    if ports:
        rows = [[P(h, cell_bold) for h in ("Port", "Probable service", "Status", "Risk level")]]
        for p in ports:
            rows.append([P(p["port"]), P(p["service"] + ("" if p["service"] == "Unknown" else " (probable)")), P(p["status"].capitalize()),
                         risk_para(p["risk"])])
        t = Table(rows, colWidths=[25 * mm, 80 * mm, 30 * mm, 45 * mm], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.5, GRID),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No open ports were detected in the scanned range.", body))

    if ports:
        story.append(Paragraph("3. Security Analysis", h2))
        rows = [[P(h, cell_bold) for h in ("Port / service", "Explanation", "Recommended mitigation")]]
        for p in ports:
            rows.append([P(f"{p['port']} / {p['service']}"), P(p["explanation"]), P(p["mitigation"])])
        t = Table(rows, colWidths=[28 * mm, 76 * mm, 76 * mm], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT), ("GRID", (0, 0), (-1, -1), 0.5, GRID),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)

    story.append(Paragraph("4. Security Recommendations", h2))
    for i, r in enumerate(scan["recommendations"], 1):
        ports_txt = f" (ports: {', '.join(str(x) for x in r['ports'])})" if r["ports"] else ""
        color = RISK_COLORS.get(r["priority"], colors.black).hexval().replace("0x", "#")
        story.append(Paragraph(
            f'{i}. <font color="{color}"><b>[{RISK_LABEL[r["priority"]]}]</b></font> '
            f'<b>{escape(r["title"])}</b>{escape(ports_txt)}<br/>{escape(r["detail"])}', body))
        story.append(Spacer(1, 4))

    story.append(Paragraph("5. Final Security Summary", h2))
    story.append(Paragraph(escape(scan["summary"]), body))

    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=16 * mm,
                            title=f"Security Report - Scan {scan['id']}", author=PROJECT_TITLE)
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return path
