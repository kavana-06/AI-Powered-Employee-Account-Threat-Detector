
import json
import sqlite3

from flask import Blueprint, send_file, jsonify
from flask_login import login_required

from pdf_reports import generate_security_report


pdf_bp = Blueprint("pdf", __name__)

DATABASE = "sentinel.db"


@pdf_bp.route(
    "/api/activities/<int:activity_id>/report",
    methods=["GET"]
)
@login_required
def download_security_report(activity_id):

    try:
        # Connect to the database.
        connection = sqlite3.connect(DATABASE)
        connection.row_factory = sqlite3.Row

        try:
            row = connection.execute(
                "SELECT * FROM activities WHERE id = ?",
                (activity_id,)
            ).fetchone()

        finally:
            connection.close()

        # Check whether the activity exists.
        if row is None:
            return jsonify({
                "error": "Activity not found"
            }), 404

        activity = dict(row)

        # Safely decode the stored input data.
        try:
            activity["input_data"] = json.loads(
                activity.get("input_data") or "{}"
            )

        except (json.JSONDecodeError, TypeError):
            activity["input_data"] = {}

        # Generate the PDF report.
        pdf_buffer = generate_security_report(activity)

        if pdf_buffer is None:
            raise ValueError("PDF generation returned no file.")

        # Return the generated PDF.
        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"SENTINEL_AI_Report_{activity_id}.pdf"
        )

    except Exception as error:

        print(
            f"Security report generation failed "
            f"for activity {activity_id}: {error}"
        )

        return jsonify({
            "error": "Could not generate security report"
        }), 500
