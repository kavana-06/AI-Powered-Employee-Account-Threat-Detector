
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pandas as pd
import joblib
import sqlite3
import json
import math
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Database configuration
DATABASE = "sentinel.db"

# Load trained ML model
model = joblib.load("employee_threat_model.pkl")

# Features expected by the model
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

# Valid investigation statuses
INVESTIGATION_STATUSES = [
    "NEW",
    "UNDER INVESTIGATION",
    "RESOLVED",
    "FALSE ALARM"
]


# -----------------------------------------
# DATABASE INITIALIZATION AND MIGRATION
# -----------------------------------------

def initialize_database():

    connection = sqlite3.connect(DATABASE)

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

    # Check existing database columns
    columns = [
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(activities)"
        ).fetchall()
    ]

    # Add investigation status to existing databases
    if "investigation_status" not in columns:
        connection.execute("""
            ALTER TABLE activities
            ADD COLUMN investigation_status
            TEXT NOT NULL DEFAULT 'NEW'
        """)

    # Add investigation notes
    if "investigation_notes" not in columns:
        connection.execute("""
            ALTER TABLE activities
            ADD COLUMN investigation_notes
            TEXT NOT NULL DEFAULT ''
        """)

    # Add investigation update timestamp
    if "investigation_updated_at" not in columns:
        connection.execute("""
            ALTER TABLE activities
            ADD COLUMN investigation_updated_at TEXT
        """)

    connection.commit()
    connection.close()

    print("Database initialized successfully!")


# -----------------------------------------
# SAVE EMPLOYEE ACTIVITY
# -----------------------------------------

def save_activity(data, result, probability):

    connection = sqlite3.connect(DATABASE)

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
    connection.close()

    return activity_id


# -----------------------------------------
# DASHBOARD
# -----------------------------------------

@app.route("/", methods=["GET"])
def home():

    return render_template("index.html")


# -----------------------------------------
# HEALTH CHECK
# -----------------------------------------

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "message": "Sentinel AI API is running!",
        "status": "success"
    })


# -----------------------------------------
# PREDICT EMPLOYEE ACTIVITY
# -----------------------------------------

@app.route("/predict", methods=["POST"])
def predict():

    try:

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "error": "Send a valid JSON object"
            }), 400

        # Check missing fields
        missing_fields = [
            field for field in REQUIRED_FIELDS
            if field not in data
        ]

        if missing_fields:
            return jsonify({
                "error": "Missing required fields",
                "missing_fields": missing_fields
            }), 400

        # Validate numeric fields
        for field in NUMERIC_FIELDS:

            if isinstance(data[field], bool):
                raise ValueError(
                    f"{field} must be numeric"
                )

            try:
                data[field] = float(data[field])
            except (ValueError, TypeError):
                raise ValueError(
                    f"{field} must be numeric"
                )

            if not math.isfinite(data[field]):
                raise ValueError(
                    f"{field} must be finite"
                )

        # Validate login hours
        if not 0 <= data["usual_login_hour"] <= 23:
            raise ValueError(
                "Usual login hour must be between 0 and 23"
            )

        if not 0 <= data["login_hour"] <= 23:
            raise ValueError(
                "Login hour must be between 0 and 23"
            )

        # Validate non-negative values
        count_fields = [
            "login_hour_deviation",
            "files_downloaded",
            "failed_login_attempts",
            "sensitive_files_accessed"
        ]

        for field in count_fields:

            if data[field] < 0:
                raise ValueError(
                    f"{field} cannot be negative"
                )

        # Validate binary fields
        for field in BINARY_FIELDS:

            if data[field] not in (0, 1):
                raise ValueError(
                    f"{field} must be 0 or 1"
                )

        # Validate text fields
        for field in [
            "department",
            "usual_location",
            "location"
        ]:

            if (
                not isinstance(data[field], str)
                or not data[field].strip()
            ):
                raise ValueError(
                    f"{field} must be a non-empty string"
                )

            data[field] = data[field].strip()

        # Prepare model input
        input_data = pd.DataFrame([
            {
                field: data[field]
                for field in REQUIRED_FIELDS
            }
        ])

        # Machine learning prediction
        prediction = int(model.predict(input_data)[0])

        probability = float(
            model.predict_proba(input_data)[0][1]
        )

        if not math.isfinite(probability):
            raise ValueError("Invalid model probability")

        if not 0 <= probability <= 1:
            raise ValueError("Model probability is out of range")

        probability = round(probability * 100, 2)

        result = (
            "POTENTIAL THREAT"
            if prediction == 1
            else "NORMAL"
        )

        # Save prediction permanently
        activity_id = save_activity(
            data,
            result,
            probability
        )

        return jsonify({
            "status": "success",
            "activity_id": activity_id,
            "prediction": result,
            "threat_probability": probability,
            "message": "Activity analyzed and saved successfully"
        })

    except (ValueError, TypeError) as error:

        return jsonify({
            "error": f"Invalid input: {str(error)}"
        }), 400

    except Exception:

        app.logger.exception("Prediction failed")

        return jsonify({
            "error": "Internal prediction error"
        }), 500


# -----------------------------------------
# GET ACTIVITY HISTORY
# -----------------------------------------

@app.route("/api/activities", methods=["GET"])
def get_activities():

    try:

        limit = request.args.get(
            "limit",
            default=50,
            type=int
        )

        if limit is None or not 1 <= limit <= 500:
            return jsonify({
                "error": "Limit must be between 1 and 500"
            }), 400

        connection = sqlite3.connect(DATABASE)
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT *
            FROM activities
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

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

        app.logger.exception("Activity retrieval failed")

        return jsonify({
            "error": "Could not retrieve activities"
        }), 500


# -----------------------------------------
# GET ONE ACTIVITY
# -----------------------------------------

@app.route("/api/activities/<int:activity_id>", methods=["GET"])
def get_activity(activity_id):

    try:

        connection = sqlite3.connect(DATABASE)
        connection.row_factory = sqlite3.Row

        row = connection.execute("""
            SELECT *
            FROM activities
            WHERE id = ?
        """, (activity_id,)).fetchone()

        connection.close()

        if row is None:
            return jsonify({
                "error": "Activity not found"
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

        app.logger.exception("Activity details retrieval failed")

        return jsonify({
            "error": "Could not retrieve activity details"
        }), 500


# -----------------------------------------
# UPDATE THREAT INVESTIGATION
# -----------------------------------------

@app.route(
    "/api/activities/<int:activity_id>/investigation",
    methods=["PATCH"]
)
def update_investigation(activity_id):

    try:

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "error": "Send a valid JSON object"
            }), 400

        status = data.get("investigation_status")
        notes = data.get("investigation_notes", "")

        # Validate status
        if status not in INVESTIGATION_STATUSES:
            return jsonify({
                "error": "Invalid investigation status",
                "allowed_statuses": INVESTIGATION_STATUSES
            }), 400

        # Validate notes
        if not isinstance(notes, str):
            return jsonify({
                "error": "Investigation notes must be text"
            }), 400

        if len(notes) > 5000:
            return jsonify({
                "error": "Investigation notes cannot exceed 5000 characters"
            }), 400

        connection = sqlite3.connect(DATABASE)

        # Check if activity exists
        existing = connection.execute("""
            SELECT id, prediction
            FROM activities
            WHERE id = ?
        """, (activity_id,)).fetchone()

        if existing is None:
            connection.close()

            return jsonify({
                "error": "Activity not found"
            }), 404

        # Only investigate detected threats
        if existing[1] != "POTENTIAL THREAT":
            connection.close()

            return jsonify({
                "error": "Only potential threats can be investigated"
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
        connection.close()

        return jsonify({
            "status": "success",
            "activity_id": activity_id,
            "investigation_status": status,
            "investigation_notes": notes.strip(),
            "investigation_updated_at": updated_at,
            "message": "Investigation updated successfully"
        })

    except Exception:

        app.logger.exception("Investigation update failed")

        return jsonify({
            "error": "Could not update investigation"
        }), 500


# -----------------------------------------
# SECURITY STATISTICS
# -----------------------------------------

@app.route("/api/stats", methods=["GET"])
def get_stats():

    try:

        connection = sqlite3.connect(DATABASE)

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

        connection.close()

        return jsonify({
            "status": "success",
            "total_activities": row[0],
            "normal_activities": row[1],
            "potential_threats": row[2]
        })

    except Exception:

        app.logger.exception("Statistics retrieval failed")

        return jsonify({
            "error": "Could not retrieve statistics"
        }), 500


# -----------------------------------------
# START APPLICATION
# -----------------------------------------

if __name__ == "__main__":

    initialize_database()

    print("================================")
    print(" SENTINEL AI DATABASE INITIALIZED")
    print(" THREAT INVESTIGATION ENABLED")
    print(" SENTINEL AI SERVER STARTING")
    print("================================")

    app.run(
        debug=True,
        port=5000
    )
