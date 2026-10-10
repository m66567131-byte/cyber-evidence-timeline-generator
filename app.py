import os
import json
import hashlib
import re
from datetime import datetime, timezone
from xml.sax.saxutils import escape

import pandas as pd
from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


# ==================================================
# APPLICATION CONFIGURATION
# ==================================================

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

ALLOWED_EXTENSIONS = {".csv", ".json"}
DISPLAY_LIMIT = 500

COLUMNS = [
    "Timestamp",
    "Activity",
    "Source",
    "User",
    "IP/Host",
    "File/Device",
    "Status"
]

analysis_data = {
    "events": None,
    "filename": "",
    "sha256": ""
}


# ==================================================
# SHA-256
# ==================================================

def calculate_sha256(path):
    digest = hashlib.sha256()

    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


# ==================================================
# FILE VALIDATION
# ==================================================

def allowed_file(filename):
    extension = os.path.splitext(filename)[1].lower()
    return extension in ALLOWED_EXTENSIONS


# ==================================================
# COLUMN DETECTION
# ==================================================

def find_column(df, candidates):
    lookup = {
        str(column).strip().lower(): column
        for column in df.columns
    }

    for candidate in candidates:
        if candidate.lower() in lookup:
            return lookup[candidate.lower()]

    return None


# ==================================================
# LOAD EVIDENCE
# ==================================================

def load_evidence(path):
    extension = os.path.splitext(path)[1].lower()

    if extension == ".csv":
        df = pd.read_csv(
            path,
            encoding="utf-8-sig",
            low_memory=False
        )

    elif extension == ".json":
        with open(path, "r", encoding="utf-8-sig") as file:
            content = json.load(file)

        if isinstance(content, list):
            df = pd.DataFrame(content)

        elif isinstance(content, dict):
            if isinstance(content.get("events"), list):
                df = pd.DataFrame(content["events"])
            else:
                df = pd.DataFrame([content])

        else:
            raise ValueError("Unsupported JSON format.")

    else:
        raise ValueError("Please upload a CSV or JSON file.")

    if df.empty:
        raise ValueError("The evidence file contains no records.")

    df.columns = [str(column).strip() for column in df.columns]

    return df


# ==================================================
# TIMESTAMP PARSING
# ==================================================

def parse_timestamp_column(series):
    values = series.astype("string").str.strip()
    numeric_values = pd.to_numeric(values, errors="coerce")

    if numeric_values.notna().mean() > 0.8:
        valid_values = numeric_values.dropna()

        if valid_values.empty:
            return pd.to_datetime(
                series,
                errors="coerce",
                utc=True
            )

        magnitude = valid_values.abs().median()

        if magnitude >= 1e17:
            unit = "ns"
        elif magnitude >= 1e14:
            unit = "us"
        elif magnitude >= 1e11:
            unit = "ms"
        else:
            unit = "s"

        return pd.to_datetime(
            numeric_values,
            unit=unit,
            errors="coerce",
            utc=True
        )

    return pd.to_datetime(
        series,
        errors="coerce",
        utc=True,
        format="mixed"
    )


def select_timestamp_column(df):
    candidates = [
        "timestamp",
        "epochtime",
        "datetime",
        "event_time",
        "date_time",
        "time"
    ]

    available = []

    for candidate in candidates:
        column = find_column(df, [candidate])

        if column is not None and column not in available:
            available.append(column)

    if not available:
        raise ValueError(
            "Timestamp column not found. "
            "Expected timestamp, datetime or epochtime."
        )

    best_column = None
    best_timestamps = None
    best_score = (-1, -1)

    for column in available:
        parsed = parse_timestamp_column(df[column])

        score = (
            int(parsed.dropna().nunique()),
            int(parsed.notna().sum())
        )

        if score > best_score:
            best_score = score
            best_column = column
            best_timestamps = parsed

    if best_timestamps is None or best_timestamps.notna().sum() == 0:
        raise ValueError(
            "No valid timestamps found in the evidence file."
        )

    return best_column, best_timestamps


# ==================================================
# NORMALIZE EVENTS AND DETECT SUSPICIOUS ACTIVITY
# ==================================================

def normalize_events(df):
    _, timestamps = select_timestamp_column(df)

    event_id_col = find_column(
        df, ["event_id", "eventid", "event id"]
    )

    activity_col = find_column(
        df,
        [
            "activity",
            "description",
            "action",
            "event_description",
            "message"
        ]
    )

    source_col = find_column(
        df,
        ["source", "source_name", "provider_name", "log_name"]
    )

    channel_col = find_column(
        df, ["channel", "log_channel"]
    )

    user_col = find_column(
        df, ["user", "username", "account_name", "user_sid"]
    )

    host_col = find_column(
        df, ["ip/host", "computer_name", "hostname", "host", "ip"]
    )

    file_col = find_column(
        df,
        [
            "file/device",
            "file_path",
            "filename_path",
            "filename",
            "filename_other",
            "device"
        ]
    )

    result = pd.DataFrame(index=df.index)

    result["Timestamp"] = timestamps

    if activity_col is not None:
        activity = df[activity_col].fillna("").astype(str)
    else:
        activity = pd.Series("", index=df.index, dtype="string")

    if event_id_col is not None:
        event_ids = df[event_id_col].fillna("").astype(str)

        if activity_col is None:
            activity = "Windows Event ID " + event_ids
        else:
            activity = activity.where(
                activity.str.strip() != "",
                "Windows Event ID " + event_ids
            )

        activity = activity.where(
            event_ids.str.strip() == "",
            activity + " (Event ID " + event_ids + ")"
        )

    if source_col is not None:
        sources = df[source_col].fillna("").astype(str)

        activity = activity.where(
            sources.str.strip() == "",
            activity + " - " + sources
        )

        result["Source"] = sources

    elif channel_col is not None:
        result["Source"] = df[channel_col].fillna("").astype(str)

    else:
        result["Source"] = "Unknown"

    result["Activity"] = activity.astype(str)

    result["User"] = (
        df[user_col].fillna("").astype(str)
        if user_col is not None
        else "Not Available"
    )

    result["IP/Host"] = (
        df[host_col].fillna("").astype(str)
        if host_col is not None
        else "Not Available"
    )

    result["File/Device"] = (
        df[file_col].fillna("").astype(str)
        if file_col is not None
        else "Not Available"
    )

    result = result.dropna(subset=["Timestamp"]).copy()

    if result.empty:
        raise ValueError("No valid timestamp records were found.")

    result = result.sort_values("Timestamp").reset_index(drop=True)

    searchable_text = (
        result["Activity"].fillna("").astype(str) + " " +
        result["Source"].fillna("").astype(str) + " " +
        result["User"].fillna("").astype(str) + " " +
        result["File/Device"].fillna("").astype(str)
    ).str.lower()

    suspicious_pattern = (
        r"failed login|logon failure|audit failure|"
        r"file deleted|file deletion|deleted file|"
        r"unauthorized|malware|credential|ransomware|"
        r"privilege escalation|account locked|password reset|"
        r"audit log cleared|security log cleared|"
        r"\b4625\b|\b1102\b|\b4720\b|\b4728\b|"
        r"\b4732\b|\b7045\b"
    )

    suspicious_mask = searchable_text.str.contains(
        suspicious_pattern,
        regex=True,
        na=False
    )

    result["Status"] = "Normal - No rule matched"

    result.loc[
        suspicious_mask,
        "Status"
    ] = "Suspicious - Review"

    result["Timestamp"] = result["Timestamp"].dt.strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    return result[COLUMNS]


# ==================================================
# APPLY SEARCH, DATE AND STATUS FILTERS
# ==================================================

def filter_events(events, search="", from_date="", to_date="",
                  status_filter="all"):

    filtered = events.copy()

    if search:
        search_mask = filtered.astype(str).apply(
            lambda column: column.str.contains(
                search,
                case=False,
                na=False,
                regex=False
            )
        ).any(axis=1)

        filtered = filtered[search_mask]

    timestamps = pd.to_datetime(
        filtered["Timestamp"],
        errors="coerce",
        utc=True
    )

    if from_date:
        start = pd.Timestamp(from_date, tz="UTC")
        filtered = filtered[timestamps >= start]

    if to_date:
        timestamps = pd.to_datetime(
            filtered["Timestamp"],
            errors="coerce",
            utc=True
        )

        end = (
            pd.Timestamp(to_date, tz="UTC")
            + pd.Timedelta(days=1)
        )

        filtered = filtered[timestamps < end]

    if status_filter == "suspicious":
        filtered = filtered[
            filtered["Status"].str.startswith(
                "Suspicious", na=False
            )
        ]

    elif status_filter == "normal":
        filtered = filtered[
            filtered["Status"].str.startswith(
                "Normal", na=False
            )
        ]

    return filtered


# ==================================================
# DASHBOARD
# ==================================================

def render_dashboard(
    error=None,
    search="",
    from_date="",
    to_date="",
    status_filter="all"
):

    events = analysis_data["events"]

    if events is None:
        return render_template(
            "index.html",
            error=error,
            data=None,
            total_events=0,
            normal_events=0,
            suspicious_events=0,
            sha256_hash="",
            file_hash="",
            search=search,
            from_date=from_date,
            to_date=to_date,
            status_filter=status_filter,
            report_ready=False
        )

    filtered = filter_events(
        events,
        search,
        from_date,
        to_date,
        status_filter
    )

    total = len(filtered)

    suspicious_count = int(
        filtered["Status"].str.startswith(
            "Suspicious", na=False
        ).sum()
    )

    normal_count = total - suspicious_count

    visible_events = filtered.head(DISPLAY_LIMIT)

    if not visible_events.empty:
        table_html = visible_events.to_html(
            index=False,
            classes="evidence-table",
            border=0,
            escape=True,
            na_rep=""
        )

        if total > DISPLAY_LIMIT:
            table_html += (
                f"<p>Showing {DISPLAY_LIMIT} of "
                f"{total} matching events.</p>"
            )

    else:
        table_html = (
            "<table><thead><tr><th>Result</th></tr></thead>"
            "<tbody><tr><td>No matching events found."
            "</td></tr></tbody></table>"
        )

    return render_template(
        "index.html",
        error=error,
        data=table_html,
        total_events=total,
        normal_events=normal_count,
        suspicious_events=suspicious_count,
        sha256_hash=analysis_data["sha256"],
        file_hash=analysis_data["sha256"],
        search=search,
        from_date=from_date,
        to_date=to_date,
        status_filter=status_filter,
        report_ready=True
    )


# ==================================================
# PDF REPORT
# ==================================================

def build_pdf(events, filename, digest):

    report_path = os.path.join(
        REPORT_FOLDER,
        "forensic_report.pdf"
    )

    doc = SimpleDocTemplate(
        report_path,
        pagesize=landscape(A4),
        rightMargin=24,
        leftMargin=24,
        topMargin=28,
        bottomMargin=28
    )

    styles = getSampleStyleSheet()

    cell_style = ParagraphStyle(
        "CellStyle",
        parent=styles["BodyText"],
        fontSize=7,
        leading=9
    )

    header_style = ParagraphStyle(
        "HeaderStyle",
        parent=cell_style,
        fontName="Helvetica-Bold",
        textColor=colors.white
    )

    suspicious = events[
        events["Status"].str.startswith(
            "Suspicious", na=False
        )
    ]

    normal_count = len(events) - len(suspicious)

    story = [
        Paragraph(
            "Cyber Evidence Timeline Generator",
            styles["Title"]
        ),
        Paragraph(
            "Digital Forensics Summary Report",
            styles["Heading2"]
        ),
        Spacer(1, 10),
        Paragraph(
            "Evidence file: " + escape(str(filename)),
            styles["BodyText"]
        ),
        Paragraph(
            "Generated: " +
            datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
            styles["BodyText"]
        ),
        Spacer(1, 8),
        Paragraph(
            f"Total Events: {len(events)}",
            styles["BodyText"]
        ),
        Paragraph(
            f"Normal Events: {normal_count}",
            styles["BodyText"]
        ),
        Paragraph(
            f"Suspicious Events: {len(suspicious)}",
            styles["BodyText"]
        ),
        Spacer(1, 10),
        Paragraph("SHA-256 File Hash", styles["Heading3"]),
        Paragraph(escape(str(digest)), cell_style),
        Spacer(1, 15),
        Paragraph(
            "Suspicious Events - Review Required",
            styles["Heading2"]
        ),
        Spacer(1, 8)
    ]

    table_columns = [
        "Timestamp",
        "Activity",
        "Source",
        "User",
        "IP/Host",
        "File/Device",
        "Status"
    ]

    table_data = [
        [Paragraph(escape(column), header_style)
         for column in table_columns]
    ]

    for _, row in suspicious.iterrows():
        table_data.append([
            Paragraph(escape(str(row[column])[:100]), cell_style)
            for column in table_columns
        ])

    if len(table_data) == 1:
        story.append(
            Paragraph(
                "No suspicious events matched the configured rules.",
                styles["BodyText"]
            )
        )

    else:
        usable_width = landscape(A4)[0] - 48
        weights = [1.3, 2.2, 1.3, 1.1, 1.3, 2.0, 1.2]

        column_widths = [
            usable_width * weight / sum(weights)
            for weight in weights
        ]

        table = Table(
            table_data,
            colWidths=column_widths,
            repeatRows=1
        )

        table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#12343B")
                ),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#EDF4F5")]
                )
            ])
        )

        story.append(table)

    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            "Suspicious events are rule-based findings that "
            "require manual investigation. They do not "
            "automatically prove a cyberattack.",
            styles["Italic"]
        )
    )

    doc.build(story)

    return report_path


# ==================================================
# MAIN ROUTE
# ==================================================

@app.route("/", methods=["GET", "POST"])
def index():

    if request.method == "POST":

        upload = request.files.get("file")

        if upload is not None and upload.filename:

            if not allowed_file(upload.filename):
                return render_dashboard(
                    error="Please upload a CSV or JSON file."
                )

            original_name = secure_filename(upload.filename)

            if not original_name:
                return render_dashboard(
                    error="Invalid filename."
                )

            unique_name = datetime.now().strftime(
                "%Y%m%d_%H%M%S_%f"
            )

            path = os.path.join(
                UPLOAD_FOLDER,
                f"{unique_name}_{original_name}"
            )

            try:
                upload.save(path)

                digest = calculate_sha256(path)
                raw_df = load_evidence(path)
                events = normalize_events(raw_df)

                analysis_data["events"] = events
                analysis_data["filename"] = original_name
                analysis_data["sha256"] = digest

                return render_dashboard()

            except Exception as exc:
                app.logger.exception("Evidence analysis failed")

                return render_dashboard(
                    error=f"Analysis failed: {exc}"
                )

        return render_dashboard(
            search=request.form.get("search", "").strip(),
            from_date=request.form.get("from_date", ""),
            to_date=request.form.get("to_date", ""),
            status_filter=request.form.get(
                "status_filter", "all"
            )
        )

    # GET requests support the HTML filter forms.
    return render_dashboard(
        search=request.args.get("search", "").strip(),
        from_date=request.args.get("from_date", ""),
        to_date=request.args.get("to_date", ""),
        status_filter=request.args.get("status_filter", "all")
    )


# ==================================================
# PDF DOWNLOAD
# ==================================================

@app.route("/download-report")
def download_report():

    if analysis_data["events"] is None:
        return render_dashboard(
            error="Upload evidence before downloading a report."
        )

    try:
        report_path = build_pdf(
            analysis_data["events"],
            analysis_data["filename"],
            analysis_data["sha256"]
        )

        return send_file(
            report_path,
            as_attachment=True,
            download_name="forensic_report.pdf"
        )

    except Exception as exc:
        app.logger.exception("PDF generation failed")

        return render_dashboard(
            error=f"Could not generate PDF: {exc}"
        )


# ==================================================
# FILE SIZE ERROR HANDLER
# ==================================================

@app.errorhandler(413)
def file_too_large(_error):
    return render_dashboard(
        error="File is too large. Maximum size is 25 MB."
    ), 413


# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":
    app.run(debug=True)