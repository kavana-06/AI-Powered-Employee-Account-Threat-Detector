
import os
import re
import json
import math
import hmac
import sqlite3

from datetime import datetime

import joblib
import pandas as pd

from dotenv import load_dotenv

from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    flash
)

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required
)

from flask_wtf.csrf import CSRFProtect

from werkzeug.security import (
    check_password_hash,
    generate_password_hash
)

from werkzeug.exceptions import RequestEntityTooLarge

from pdf_routes import pdf_bp
from bulk_detection import detect_bulk_threats


# =====================================================
# 1. ENVIRONMENT CONFIGURATION
# =====================================================

load_dotenv()

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SENTINEL_HTTPS") == "1"
)

SECRET_KEY = os.environ.get("SENTINEL_SECRET_KEY")
ADMIN_USERNAME = os.environ.get("SENTINEL_ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("SENTINEL_ADMIN_PASSWORD")

if not SECRET_KEY or not ADMIN_USERNAME or not ADMIN_PASSWORD:
    raise RuntimeError(
        "Set SENTINEL_SECRET_KEY, SENTINEL_ADMIN_USERNAME "
        "and SENTINEL_ADMIN_PASSWORD in your .env file."
    )

app.config["SECRET_KEY"] = SECRET_KEY

DATABASE = "sentinel.db"

ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)

csrf = CSRFProtect(app)

app.register_blueprint(pdf_bp)


# =====================================================
# 2. LOGIN CONFIGURATION
# =====================================================

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"

login_manager.login_message = (
    "Please log in to access SENTINEL AI."
)

login_manager.login_message_category = "warning"


class Admin(UserMixin):

    def __init__(self, username):
        self.id = username


@login_manager.user_loader
def load_user(user_id):

    if user_id == ADMIN_USERNAME:
        return Admin(ADMIN_USERNAME)

    return None


@login_manager.unauthorized_handler
def unauthorized():

    if request.path.startswith("/api/") or request.path == "/predict":

        return jsonify({
            "status": "error",
            "error": "Authentication required. Please log in."
        }), 401

    return redirect(url_for("login"))


# =====================================================
# 3. LOAD MACHINE LEARNING MODEL
# =====================================================

try:

    model = joblib.load("employee_threat_model.pkl")

except FileNotFoundError:

    raise RuntimeError(
        "employee_threat_model.pkl was not found. "
        "Place the trained model in the project folder."
    )

except Exception as error:

    raise RuntimeError(
        f"Could not load the trained ML model: {error}"
    )


# =====================================================
# 4. MODEL FEATURES
# =====================================================

REQUIRED_FIELDS = [
    "department",
    "usual_location",
    "location",
    "usual_login_hour",
    "login_hour",
    "login_hour_deviation",
    "files_downloaded",
    "failed_login_attempts",
    "device_trusted",
    "sensitive_files_accessed",
    "usb_connected",
    "location_unusual",
    "after_hours"
]

NUMERIC_FIELDS = [
    "usual_login_hour",
    "login_hour",
    "login_hour_deviation",
    "files_downloaded",
    "failed_login_attempts",
    "device_trusted",
    "sensitive_files_accessed",
    "usb_connected",
    "location_unusual",
    "after_hours"
]

BINARY_FIELDS = [
    "device_trusted",
    "usb_connected",
    "location_unusual",
    "after_hours"
]

COUNT_FIELDS = [
    "login_hour_deviation",
    "files_downloaded",
    "failed_login_attempts",
    "sensitive_files_accessed"
]

INVESTIGATION_STATUSES = [
    "NEW",
    "UNDER INVESTIGATION",
    "RESOLVED",
    "FALSE ALARM"
]

MAX_CSV_ROWS = 5000


# =====================================================
# 5. DATABASE CONNECTION
# =====================================================

def get_connection():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


# =====================================================
# 6. DATABASE INITIALIZATION
# =====================================================

def initialize_database():

    connection = get_connection()

    try:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS activities (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                created_at TEXT NOT NULL,

                department TEXT NOT NULL,

                usual_location TEXT NOT NULL,

                location TEXT NOT NULL,

                prediction TEXT NOT NULL,

                threat_probability REAL NOT NULL,

                input_data TEXT NOT NULL

            )
        """)

        columns = [
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(activities)"
            ).fetchall()
        ]

        if "investigation_status" not in columns:

            connection.execute("""
                ALTER TABLE activities
                ADD COLUMN investigation_status
                TEXT NOT NULL DEFAULT 'NEW'
            """)

        if "investigation_notes" not in columns:

            connection.execute("""
                ALTER TABLE activities
                ADD COLUMN investigation_notes
                TEXT NOT NULL DEFAULT ''
            """)

        if "investigation_updated_at" not in columns:

            connection.execute("""
                ALTER TABLE activities
                ADD COLUMN investigation_updated_at TEXT
            """)

        connection.commit()

        print(
            "SENTINEL AI database initialized successfully."
        )

    finally:

        connection.close()


# =====================================================
# 7. NORMALIZE CSV COLUMN NAMES
# =====================================================

def normalize_column_name(name):

    name = str(name).strip().lower()

    name = re.sub(
        r"[^a-z0-9]+",
        "_",
        name
    )

    return name.strip("_")


# =====================================================
# 8. VALIDATE EMPLOYEE RECORD
# =====================================================

def validate_employee_record(data):

    if not isinstance(data, dict):

        raise ValueError(
            "Invalid employee record."
        )

    missing_fields = [
        field
        for field in REQUIRED_FIELDS
        if field not in data
    ]

    if missing_fields:

        raise ValueError(
            "Missing required fields: "
            + ", ".join(missing_fields)
        )

    cleaned = {}

    # Validate text fields.
    for field in [
        "department",
        "usual_location",
        "location"
    ]:

        value = data[field]

        if pd.isna(value):

            raise ValueError(
                f"{field} cannot be empty."
            )

        value = str(value).strip()

        if not value:

            raise ValueError(
                f"{field} cannot be empty."
            )

        cleaned[field] = value

    # Validate numerical fields.
    for field in NUMERIC_FIELDS:

        value = data[field]

        if isinstance(value, bool):

            raise ValueError(
                f"{field} must be numeric."
            )

        try:

            value = float(value)

        except (ValueError, TypeError):

            raise ValueError(
                f"{field} must be numeric."
            )

        if not math.isfinite(value):

            raise ValueError(
                f"{field} must be a finite number."
            )

        cleaned[field] = value

    # Validate login hours.
    for field in [
        "usual_login_hour",
        "login_hour"
    ]:

        value = cleaned[field]

        if not 0 <= value <= 23:

            raise ValueError(
                f"{field} must be between 0 and 23."
            )

        if not value.is_integer():

            raise ValueError(
                f"{field} must be a whole number."
            )

    # Validate count fields.
    for field in COUNT_FIELDS:

        value = cleaned[field]

        if value < 0:

            raise ValueError(
                f"{field} cannot be negative."
            )

        if not value.is_integer():

            raise ValueError(
                f"{field} must be a whole number."
            )

    # Validate binary fields.
    for field in BINARY_FIELDS:

        if cleaned[field] not in (0, 1):

            raise ValueError(
                f"{field} must be 0 or 1."
            )

    return cleaned


# =====================================================
# 9. IDENTIFY THREAT CLASS
# =====================================================

def identify_threat_class():

    if not hasattr(model, "classes_"):

        raise ValueError(
            "The trained model does not expose class labels."
        )

    classes = list(model.classes_)

    for label in classes:

        normalized_label = str(label).strip().lower()

        if normalized_label in [
            "1",
            "true",
            "threat",
            "potential threat",
            "potential_threat",
            "dangerous"
        ]:

            return label

    raise ValueError(
        "Could not identify the threat class in the trained model. "
        "Check the labels used during model training."
    )


# =====================================================
# 10. PREDICT EMPLOYEE THREAT
# =====================================================

def analyze_employee(data):

    cleaned_data = validate_employee_record(data)

    input_data = pd.DataFrame([{
        field: cleaned_data[field]
        for field in REQUIRED_FIELDS
    }])

    try:

        prediction = model.predict(input_data)[0]

        probabilities = model.predict_proba(input_data)[0]

    except Exception as error:

        raise ValueError(
            f"Machine learning prediction failed: {error}"
        )

    threat_class = identify_threat_class()

    classes = list(model.classes_)

    threat_index = classes.index(threat_class)

    probability = float(
        probabilities[threat_index]
    )

    if not math.isfinite(probability):

        raise ValueError(
            "Invalid threat probability."
        )

    if not 0 <= probability <= 1:

        raise ValueError(
            "Threat probability is out of range."
        )

    probability = round(
        probability * 100,
        2
    )

    is_threat = prediction == threat_class

    result = (
        "POTENTIAL THREAT"
        if is_threat
        else "NORMAL"
    )

    activity_id = save_activity(
        cleaned_data,
        result,
        probability
    )

    return {
        "activity_id": activity_id,
        "prediction": result,
        "threat_probability": probability,
        "department": cleaned_data["department"],
        "location": cleaned_data["location"]
    }


# =====================================================
# 11. SAVE ACTIVITY TO DATABASE
# =====================================================

def save_activity(data, result, probability):

    connection = get_connection()

    try:

        cursor = connection.execute("""

            INSERT INTO activities (

                created_at,

                department,

                usual_location,

                location,

                prediction,

                threat_probability,

                input_data

            )

            VALUES (?, ?, ?, ?, ?, ?, ?)

        """, (
            datetime.now().isoformat(timespec="seconds"),
            data["department"],
            data["usual_location"],
            data["location"],
            result,
            probability,
            json.dumps(data)
        ))

        activity_id = cursor.lastrowid

        connection.commit()

        return activity_id

    finally:

        connection.close()


# =====================================================
# 12. ADMIN LOGIN
# =====================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        username_valid = hmac.compare_digest(
            username,
            ADMIN_USERNAME
        )

        password_valid = check_password_hash(
            ADMIN_PASSWORD_HASH,
            password
        )

        if username_valid and password_valid:

            login_user(
                Admin(ADMIN_USERNAME)
            )

            flash(
                "Welcome to SENTINEL AI!",
                "success"
            )

            next_page = request.args.get("next")

            if (
                next_page
                and next_page.startswith("/")
                and not next_page.startswith("//")
            ):

                return redirect(next_page)

            return redirect(
                url_for("home")
            )

        flash(
            "Invalid username or password.",
            "danger"
        )

    return render_template("login.html")


# =====================================================
# 13. ADMIN LOGOUT
# =====================================================

@app.route("/logout", methods=["POST"])
@login_required
def logout():

    logout_user()

    flash(
        "You have been logged out successfully.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# =====================================================
# 14. DASHBOARD
# =====================================================

@app.route("/", methods=["GET"])
@login_required
def home():

    return render_template("index.html")


# =====================================================
# 15. HEALTH CHECK
# =====================================================

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "status": "success",
        "message": "SENTINEL AI API is running!"
    })


# =====================================================
# 16. MANUAL THREAT DETECTION
# =====================================================

@app.route("/predict", methods=["POST"])
@login_required
def predict():

    try:

        data = request.get_json(silent=True)

        if not isinstance(data, dict):

            return jsonify({
                "status": "error",
                "error": "Send a valid JSON object."
            }), 400

        result = analyze_employee(data)

        return jsonify({
            "status": "success",
            "message": "Employee activity analyzed successfully.",
            **result
        })

    except (ValueError, TypeError) as error:

        return jsonify({
            "status": "error",
            "error": str(error)
        }), 400

    except Exception:

        app.logger.exception(
            "Manual prediction failed."
        )

        return jsonify({
            "status": "error",
            "error": "Internal prediction error."
        }), 500


# =====================================================
# 17. BULK CSV DETECTION
# =====================================================

def detect_csv_threats(uploaded_file):

    try:

        dataframe = pd.read_csv(uploaded_file)

    except Exception as error:

        raise ValueError(
            f"Could not read CSV file: {error}"
        )

    if dataframe.empty:

        raise ValueError(
            "The CSV file contains no records."
        )

    if len(dataframe) > MAX_CSV_ROWS:

        raise ValueError(
            f"CSV cannot contain more than "
            f"{MAX_CSV_ROWS} records."
        )

    # Normalize headers.
    dataframe.columns = [
        normalize_column_name(column)
        for column in dataframe.columns
    ]

    if dataframe.columns.duplicated().any():

        raise ValueError(
            "The CSV contains duplicate column names after normalization."
        )

    missing_fields = [
        field
        for field in REQUIRED_FIELDS
        if field not in dataframe.columns
    ]

    if missing_fields:

        raise ValueError(
            "CSV is missing these required columns: "
            + ", ".join(missing_fields)
        )

    results = []

    for index, row in dataframe.iterrows():

        try:

            employee_data = row[REQUIRED_FIELDS].to_dict()

            result = analyze_employee(employee_data)

            result["row_number"] = int(index) + 2

            if "employee_id" in dataframe.columns:

                result["employee_id"] = str(
                    row["employee_id"]
                )

            results.append(result)

        except (ValueError, TypeError) as error:

            raise ValueError(
                f"Invalid data on CSV row {int(index) + 2}: "
                f"{str(error)}"
            )

    total = len(results)

    threats = sum(
        1
        for item in results
        if item["prediction"] == "POTENTIAL THREAT"
    )

    normal = total - threats

    return {
        "total_records": total,
        "threats_detected": threats,
        "normal_records": normal,
        "results": results
    }


# =====================================================
# 18. BULK PDF AND CSV DETECTION
# =====================================================

@app.route("/api/bulk-detect", methods=["POST"])
@login_required
def bulk_detect():

    try:

        if "file" not in request.files:

            return jsonify({
                "status": "error",
                "error": "Please upload a CSV or PDF file."
            }), 400

        uploaded_file = request.files["file"]

        if not uploaded_file.filename:

            return jsonify({
                "status": "error",
                "error": "No file selected."
            }), 400

        filename = uploaded_file.filename.lower()

        # CSV upload.
        if filename.endswith(".csv"):

            results = detect_csv_threats(
                uploaded_file
            )

            return jsonify({
                "status": "success",
                "file_type": "CSV",
                "message": "Bulk CSV analysis completed.",
                **results
            })

        # PDF upload.
        elif filename.endswith(".pdf"):

            file_signature = uploaded_file.stream.read(5)

            uploaded_file.stream.seek(0)

            if file_signature != b"%PDF-":

                return jsonify({
                    "status": "error",
                    "error": "The uploaded file is not a valid PDF."
                }), 400

            results = detect_bulk_threats(
                uploaded_file.stream,
                model
            )

            return jsonify({
                "status": "success",
                "file_type": "PDF",
                "message": "Bulk PDF analysis completed.",
                **results
            })

        else:

            return jsonify({
                "status": "error",
                "error": "Only CSV and PDF files are supported."
            }), 400

    except ValueError as error:

        return jsonify({
            "status": "error",
            "error": str(error)
        }), 400

    except Exception:

        app.logger.exception(
            "Bulk detection failed."
        )

        return jsonify({
            "status": "error",
            "error": "Could not analyze the uploaded file."
        }), 500


# =====================================================
# 19. FILE SIZE ERROR
# =====================================================

@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(error):

    return jsonify({
        "status": "error",
        "error": "File is too large. Maximum upload size is 16 MB."
    }), 413


# =====================================================
# 20. GET ACTIVITY HISTORY
# =====================================================

@app.route("/api/activities", methods=["GET"])
@login_required
def get_activities():

    try:

        limit = request.args.get(
            "limit",
            default=50,
            type=int
        )

        if limit is None or not 1 <= limit <= 500:

            return jsonify({
                "error": "Limit must be between 1 and 500."
            }), 400

        connection = get_connection()

        try:

            rows = connection.execute("""

                SELECT *
                FROM activities
                ORDER BY id DESC
                LIMIT ?

            """, (limit,)).fetchall()

        finally:

            connection.close()

        activities = []

        for row in rows:

            activity = dict(row)

            activity["input_data"] = json.loads(
                activity["input_data"]
            )

            activities.append(activity)

        return jsonify({
            "status": "success",
            "total_returned": len(activities),
            "activities": activities
        })

    except Exception:

        app.logger.exception(
            "Activity retrieval failed."
        )

        return jsonify({
            "error": "Could not retrieve activities."
        }), 500


# =====================================================
# 21. GET ONE ACTIVITY
# =====================================================

@app.route(
    "/api/activities/<int:activity_id>",
    methods=["GET"]
)
@login_required
def get_activity(activity_id):

    try:

        connection = get_connection()

        try:

            row = connection.execute("""

                SELECT *
                FROM activities
                WHERE id = ?

            """, (activity_id,)).fetchone()

        finally:

            connection.close()

        if row is None:

            return jsonify({
                "error": "Activity not found."
            }), 404

        activity = dict(row)

        activity["input_data"] = json.loads(
            activity["input_data"]
        )

        return jsonify({
            "status": "success",
            "activity": activity
        })

    except Exception:

        app.logger.exception(
            "Activity details retrieval failed."
        )

        return jsonify({
            "error": "Could not retrieve activity details."
        }), 500


# =====================================================
# 22. UPDATE THREAT INVESTIGATION
# =====================================================

@app.route(
    "/api/activities/<int:activity_id>/investigation",
    methods=["PATCH"]
)
@login_required
def update_investigation(activity_id):

    connection = None

    try:

        data = request.get_json(silent=True)

        if not isinstance(data, dict):

            return jsonify({
                "error": "Send a valid JSON object."
            }), 400

        status = data.get(
            "investigation_status"
        )

        notes = data.get(
            "investigation_notes",
            ""
        )

        if status not in INVESTIGATION_STATUSES:

            return jsonify({
                "error": "Invalid investigation status.",
                "allowed_statuses": INVESTIGATION_STATUSES
            }), 400

        if not isinstance(notes, str):

            return jsonify({
                "error": "Investigation notes must be text."
            }), 400

        if len(notes) > 5000:

            return jsonify({
                "error": "Investigation notes cannot exceed 5000 characters."
            }), 400

        connection = get_connection()

        existing = connection.execute("""

            SELECT id, prediction
            FROM activities
            WHERE id = ?

        """, (activity_id,)).fetchone()

        if existing is None:

            return jsonify({
                "error": "Activity not found."
            }), 404

        if existing["prediction"] != "POTENTIAL THREAT":

            return jsonify({
                "error": "Only potential threats can be investigated."
            }), 400

        updated_at = datetime.now().isoformat(
            timespec="seconds"
        )

        connection.execute("""

            UPDATE activities

            SET
                investigation_status = ?,
                investigation_notes = ?,
                investigation_updated_at = ?

            WHERE id = ?

        """, (
            status,
            notes.strip(),
            updated_at,
            activity_id
        ))

        connection.commit()

        return jsonify({
            "status": "success",
            "activity_id": activity_id,
            "investigation_status": status,
            "investigation_notes": notes.strip(),
            "investigation_updated_at": updated_at,
            "message": "Investigation updated successfully."
        })

    except Exception:

        app.logger.exception(
            "Investigation update failed."
        )

        return jsonify({
            "error": "Could not update investigation."
        }), 500

    finally:

        if connection is not None:
            connection.close()


# =====================================================
# 23. SECURITY STATISTICS
# =====================================================

@app.route("/api/stats", methods=["GET"])
@login_required
def get_stats():

    try:

        connection = get_connection()

        try:

            row = connection.execute("""

                SELECT

                    COUNT(*) AS total,

                    COALESCE(
                        SUM(
                            CASE
                                WHEN prediction = 'NORMAL'
                                THEN 1 ELSE 0
                            END
                        ), 0
                    ) AS normal,

                    COALESCE(
                        SUM(
                            CASE
                                WHEN prediction = 'POTENTIAL THREAT'
                                THEN 1 ELSE 0
                            END
                        ), 0
                    ) AS threats

                FROM activities

            """).fetchone()

        finally:

            connection.close()

        return jsonify({
            "status": "success",
            "total_activities": row["total"],
            "normal_activities": row["normal"],
            "potential_threats": row["threats"]
        })

    except Exception:

        app.logger.exception(
            "Statistics retrieval failed."
        )

        return jsonify({
            "error": "Could not retrieve statistics."
        }), 500


# =====================================================
# 24. START APPLICATION
# =====================================================

if __name__ == "__main__":

    initialize_database()

    print("========================================")
    print("       SENTINEL AI SECURITY SYSTEM")
    print("========================================")
    print(" ADMIN AUTHENTICATION ENABLED")
    print(" THREAT DETECTION ENABLED")
    print(" THREAT INVESTIGATION ENABLED")
    print(" PDF REPORT GENERATION ENABLED")
    print(" BULK PDF DETECTION ENABLED")
    print(" BULK CSV DETECTION ENABLED")
    print("========================================")

    app.run(
        debug=True,
        port=5000
    )
