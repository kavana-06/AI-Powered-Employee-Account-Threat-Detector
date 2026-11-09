
import re

import pandas as pd
import pdfplumber


# All 13 features required by the trained ML model.
MODEL_FEATURES = [
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
    "after_hours",
]

NUMERIC_FIELDS = [
    "usual_login_hour",
    "login_hour",
    "login_hour_deviation",
    "files_downloaded",
    "failed_login_attempts",
    "sensitive_files_accessed",
]

BINARY_FIELDS = [
    "device_trusted",
    "usb_connected",
    "location_unusual",
    "after_hours",
]


def normalize_column_name(name):
    """Convert column names into a consistent format."""

    name = str(name).strip().lower()
    name = re.sub(r"[^a-z0-9]+", "_", name)

    return name.strip("_")


def prepare_records(dataframe):
    """Validate and prepare employee records for the ML model."""

    dataframe = dataframe.copy()

    dataframe.columns = [
        normalize_column_name(column)
        for column in dataframe.columns
    ]

    dataframe = dataframe.dropna(how="all").copy()

    # Check that every required model feature exists.
    missing_columns = [
        column
        for column in MODEL_FEATURES
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise ValueError(
            "Your file is missing required model columns: "
            + ", ".join(missing_columns)
        )

    # Remove records with missing required values.
    dataframe = dataframe.dropna(
        subset=MODEL_FEATURES
    ).copy()

    if dataframe.empty:
        raise ValueError(
            "No valid employee records were found. "
            "Check that the file contains complete values."
        )

    # Convert numerical columns.
    for column in NUMERIC_FIELDS + BINARY_FIELDS:
        dataframe[column] = pd.to_numeric(
            dataframe[column],
            errors="coerce"
        )

    # Reject invalid numerical values.
    if dataframe[NUMERIC_FIELDS + BINARY_FIELDS].isna().any().any():
        raise ValueError(
            "Some activity columns contain invalid numerical values."
        )

    # Check that numerical activity values are whole numbers.
    for column in NUMERIC_FIELDS + BINARY_FIELDS:
        if not dataframe[column].apply(
            lambda value: float(value).is_integer()
        ).all():
            raise ValueError(
                f"Column '{column}' must contain whole numbers."
            )

    # Binary columns must contain only 0 or 1.
    for column in BINARY_FIELDS:
        if not dataframe[column].isin([0, 1]).all():
            raise ValueError(
                f"Column '{column}' must contain only 0 or 1."
            )

    # Department and location must not be empty.
    for column in ["department", "usual_location", "location"]:
        dataframe[column] = dataframe[column].astype(str).str.strip()

        if (dataframe[column] == "").any():
            raise ValueError(
                f"Column '{column}' contains empty values."
            )

    model_data = dataframe[MODEL_FEATURES].copy()

    return dataframe, model_data


def extract_csv_records(csv_file):
    """Read and validate employee activity records from CSV."""

    try:
        dataframe = pd.read_csv(csv_file)

    except Exception as error:
        raise ValueError(
            f"Could not read the CSV file: {error}"
        )

    return prepare_records(dataframe)


def extract_pdf_records(pdf_file):
    """Extract employee activity records from tabular PDFs."""

    extracted_tables = []

    try:
        with pdfplumber.open(pdf_file) as pdf:

            for page in pdf.pages:

                tables = page.extract_tables()

                for table in tables:

                    if not table or len(table) < 2:
                        continue

                    headers = [
                        normalize_column_name(column)
                        if column is not None else ""
                        for column in table[0]
                    ]

                    if not all(headers):
                        continue

                    rows = []

                    for row in table[1:]:

                        if not row or len(row) != len(headers):
                            continue

                        cleaned_row = [
                            str(value).strip()
                            if value is not None else ""
                            for value in row
                        ]

                        # Ignore repeated header rows.
                        normalized_row = [
                            normalize_column_name(value)
                            for value in cleaned_row
                        ]

                        if normalized_row == headers:
                            continue

                        rows.append(cleaned_row)

                    if rows:
                        extracted_tables.append(
                            pd.DataFrame(
                                rows,
                                columns=headers
                            )
                        )

    except Exception as error:
        raise ValueError(
            f"Could not read the PDF file: {error}"
        )

    if not extracted_tables:
        raise ValueError(
            "No readable tables were found in the PDF. "
            "Please upload a PDF containing selectable table text."
        )

    combined = pd.concat(
        extracted_tables,
        ignore_index=True
    )

    return prepare_records(combined)


def identify_threat_class(model):
    """Find the threat class in the trained model."""

    if not hasattr(model, "classes_"):
        raise ValueError(
            "The trained model does not expose its class labels."
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
            "dangerous",
        ]:
            return label

    raise ValueError(
        "Could not identify the threat class in the trained model. "
        "Check the labels used when training the model."
    )


def detect_bulk_threats(uploaded_file, model, file_type=None):
    """
    Analyze CSV or PDF employee records using the trained ML model.

    Returns:
        total_records
        threats_detected
        normal_records
        results
    """

    filename = getattr(uploaded_file, "filename", "") or ""

    # Determine file type.
    if file_type is None:

        if filename and "." in filename:
            file_type = filename.rsplit(".", 1)[-1].lower()
        else:
            # Backward compatibility: the Flask app previously passed
            # uploaded_file.stream for PDF processing.
            file_type = "pdf"

    file_type = file_type.lower().lstrip(".")

    # Extract records based on file type.
    if file_type == "csv":

        original_data, model_data = extract_csv_records(
            uploaded_file
        )

    elif file_type == "pdf":

        original_data, model_data = extract_pdf_records(
            uploaded_file
        )

    else:
        raise ValueError(
            "Unsupported file format. Please upload a CSV or PDF."
        )

    # Run model predictions.
    try:
        predictions = model.predict(model_data)

        if not hasattr(model, "predict_proba"):
            raise ValueError(
                "The trained model does not support probability predictions."
            )

        probabilities = model.predict_proba(model_data)

    except Exception as error:
        raise ValueError(
            f"Model prediction failed: {error}"
        )

    # Identify which probability column represents a threat.
    threat_class = identify_threat_class(model)
    classes = list(model.classes_)
    threat_index = classes.index(threat_class)

    threat_results = []

    for index, prediction in enumerate(predictions):

        probability = float(
            probabilities[index][threat_index]
        ) * 100

        is_threat = prediction == threat_class

        row = original_data.iloc[index]

        # Use uploaded employee ID if available.
        if "employee_id" in original_data.columns:
            employee_id = str(row["employee_id"])
        else:
            employee_id = f"Employee {index + 1}"

        threat_results.append({
            "employee_id": employee_id,
            "department": str(row["department"]),
            "location": str(row["location"]),
            "prediction": (
                "POTENTIAL THREAT"
                if is_threat else "NORMAL"
            ),
            "threat_probability": round(probability, 2),
        })

    # Calculate summary statistics.
    total_records = len(threat_results)

    threats_detected = sum(
        result["prediction"] == "POTENTIAL THREAT"
        for result in threat_results
    )

    normal_records = sum(
        result["prediction"] == "NORMAL"
        for result in threat_results
    )

    return {
        "status": "success",
        "file_type": file_type.upper(),
        "message": "Bulk threat analysis completed.",
        "total_records": total_records,
        "threats_detected": threats_detected,
        "normal_records": normal_records,

        # Compatibility with older dashboard/API code.
        "threat_count": threats_detected,
        "normal_count": normal_records,

        "results": threat_results,
    }
