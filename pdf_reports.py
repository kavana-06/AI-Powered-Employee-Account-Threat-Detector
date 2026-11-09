
from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from xml.sax.saxutils import escape


def safe_value(value, default="N/A"):
    """Convert values into safe display text."""

    if value is None:
        return default

    value = str(value).strip()

    if not value:
        return default

    return value


def generate_security_report(activity):

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor("#172554"),
        alignment=TA_CENTER,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#64748b"),
        alignment=TA_CENTER,
        spaceAfter=18
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#1e3a8a"),
        spaceBefore=12,
        spaceAfter=8
    )

    normal_style = styles["BodyText"]

    story = []

    # ---------------------------------
    # REPORT HEADER
    # ---------------------------------

    story.append(
        Paragraph("SENTINEL AI", title_style)
    )

    story.append(
        Paragraph(
            "EMPLOYEE SECURITY ANALYSIS REPORT",
            subtitle_style
        )
    )

    generated_time = datetime.now().strftime(
        "%d %B %Y, %I:%M %p"
    )

    story.append(
        Paragraph(
            f"Report generated: {generated_time}",
            normal_style
        )
    )

    story.append(Spacer(1, 12))

    # ---------------------------------
    # ACTIVITY DETAILS
    # ---------------------------------

    story.append(
        Paragraph(
            "1. Employee Activity Details",
            heading_style
        )
    )

    details = [
        ["Activity ID", safe_value(activity.get("id"))],
        ["Department", safe_value(activity.get("department"))],
        [
            "Usual Location",
            safe_value(activity.get("usual_location"))
        ],
        [
            "Login Location",
            safe_value(activity.get("location"))
        ],
        [
            "Activity Date",
            safe_value(activity.get("created_at"))
        ],
    ]

    details_table = Table(
        details,
        colWidths=[55 * mm, 110 * mm]
    )

    details_table.setStyle(TableStyle([
        (
            "BACKGROUND",
            (0, 0),
            (0, -1),
            colors.HexColor("#e2e8f0")
        ),
        (
            "TEXTCOLOR",
            (0, 0),
            (-1, -1),
            colors.HexColor("#1e293b")
        ),
        (
            "FONTNAME",
            (0, 0),
            (0, -1),
            "Helvetica-Bold"
        ),
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.5,
            colors.HexColor("#cbd5e1")
        ),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    story.append(details_table)

    # ---------------------------------
    # THREAT ANALYSIS
    # ---------------------------------

    story.append(
        Paragraph(
            "2. Threat Analysis",
            heading_style
        )
    )

    prediction = safe_value(
        activity.get("prediction")
    )

    probability = safe_value(
        activity.get("threat_probability")
    )

    is_threat = prediction.strip().upper() == "POTENTIAL THREAT"

    threat_color = (
        colors.HexColor("#dc2626")
        if is_threat
        else colors.HexColor("#15803d")
    )

    analysis_data = [
        ["Prediction", escape(prediction)],
        [
            "Threat Probability",
            escape(f"{probability}%")
        ],
    ]

    analysis_table = Table(
        analysis_data,
        colWidths=[55 * mm, 110 * mm]
    )

    analysis_table.setStyle(TableStyle([
        (
            "BACKGROUND",
            (0, 0),
            (0, -1),
            colors.HexColor("#e2e8f0")
        ),
        (
            "TEXTCOLOR",
            (0, 0),
            (-1, -1),
            colors.HexColor("#1e293b")
        ),
        (
            "TEXTCOLOR",
            (1, 0),
            (1, 0),
            threat_color
        ),
        (
            "FONTNAME",
            (1, 0),
            (1, 0),
            "Helvetica-Bold"
        ),
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.5,
            colors.HexColor("#cbd5e1")
        ),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))

    story.append(analysis_table)

    # ---------------------------------
    # ACTIVITY INPUTS
    # ---------------------------------

    story.append(
        Paragraph(
            "3. Employee Activity Indicators",
            heading_style
        )
    )

    input_data = activity.get("input_data", {})

    if not isinstance(input_data, dict):
        input_data = {}

    indicator_fields = [
        ("Login Hour", "login_hour"),
        ("Usual Login Hour", "usual_login_hour"),
        ("Login Hour Deviation", "login_hour_deviation"),
        ("Files Downloaded", "files_downloaded"),
        ("Failed Login Attempts", "failed_login_attempts"),
        ("Trusted Device", "device_trusted"),
        ("Sensitive Files Accessed", "sensitive_files_accessed"),
        ("USB Connected", "usb_connected"),
        ("Unusual Location", "location_unusual"),
        ("After Hours Activity", "after_hours"),
    ]

    indicator_data = [
        ["Indicator", "Recorded Value"]
    ]

    for label, field in indicator_fields:

        value = safe_value(
            input_data.get(field)
        )

        indicator_data.append([
            label,
            escape(value)
        ])

    indicator_table = Table(
        indicator_data,
        colWidths=[85 * mm, 80 * mm],
        repeatRows=1
    )

    indicator_table.setStyle(TableStyle([
        (
            "BACKGROUND",
            (0, 0),
            (-1, 0),
            colors.HexColor("#1e3a8a")
        ),
        (
            "TEXTCOLOR",
            (0, 0),
            (-1, 0),
            colors.white
        ),
        (
            "FONTNAME",
            (0, 0),
            (-1, 0),
            "Helvetica-Bold"
        ),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [
                colors.white,
                colors.HexColor("#f1f5f9")
            ]
        ),
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.4,
            colors.HexColor("#cbd5e1")
        ),
        ("PADDING", (0, 0), (-1, -1), 7),
    ]))

    story.append(indicator_table)

    # ---------------------------------
    # INVESTIGATION DETAILS
    # ---------------------------------

    story.append(
        Paragraph(
            "4. Investigation Details",
            heading_style
        )
    )

    investigation_status = safe_value(
        activity.get("investigation_status"),
        "NEW"
    )

    investigation_notes = safe_value(
        activity.get("investigation_notes"),
        "No investigation notes recorded."
    )

    updated_at = safe_value(
        activity.get("investigation_updated_at"),
        "Not updated"
    )

    notes_paragraph = Paragraph(
        escape(investigation_notes).replace("\n", "<br/>"),
        normal_style
    )

    investigation_data = [
        [
            "Investigation Status",
            escape(investigation_status)
        ],
        [
            "Last Updated",
            escape(updated_at)
        ],
        [
            "Investigation Notes",
            notes_paragraph
        ]
    ]

    investigation_table = Table(
        investigation_data,
        colWidths=[55 * mm, 110 * mm]
    )

    investigation_table.setStyle(TableStyle([
        (
            "BACKGROUND",
            (0, 0),
            (0, -1),
            colors.HexColor("#e2e8f0")
        ),
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.5,
            colors.HexColor("#cbd5e1")
        ),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    story.append(investigation_table)

    # ---------------------------------
    # DISCLAIMER
    # ---------------------------------

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "<b>Disclaimer:</b> This report contains an automated "
            "machine learning assessment. A potential threat "
            "prediction is an alert for further investigation, "
            "not proof of malicious activity.",
            normal_style
        )
    )

    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "Generated by SENTINEL AI | Confidential Security Report",
            subtitle_style
        )
    )

    # ---------------------------------
    # BUILD PDF
    # ---------------------------------

    document.build(story)

    buffer.seek(0)

    return buffer
