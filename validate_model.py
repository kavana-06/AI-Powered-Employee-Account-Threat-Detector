
import pandas as pd
import numpy as np
import joblib

from sklearn.base import clone
from sklearn.model_selection import StratifiedGroupKFold, cross_validate
from sklearn.metrics import confusion_matrix, classification_report


# ==========================================
# 1. LOAD DATASET AND TRAINED MODEL
# ==========================================

DATASET_PATH = "dataset/employee_activity.csv"
MODEL_PATH = "employee_threat_model.pkl"

print("\n========================================")
print("       SENTINEL AI - MODEL VALIDATION")
print("========================================")

df = pd.read_csv(DATASET_PATH)
pipeline = joblib.load(MODEL_PATH)

print("\nDataset loaded successfully!")
print("Model loaded successfully!")


# ==========================================
# 2. PREPARE FEATURES AND TARGET
# ==========================================

required_columns = [
    "employee_id",
    "activity_date",
    "is_threat",
    "threat_type"
]

for column in required_columns:
    if column not in df.columns:
        raise ValueError(f"Missing required column: {column}")

X = df.drop(
    columns=required_columns
)

y = df["is_threat"].astype(int)

# Employee IDs are used only for grouping.
groups = df["employee_id"]

print("\n===== DATASET INFORMATION =====")

print("Total records:", len(df))
print("Total employees:", groups.nunique())
print("Total features:", X.shape[1])

print("\nClass distribution:")
print(y.value_counts().rename({
    0: "Normal",
    1: "Threat"
}))

print("\nRecords per employee:")
print(groups.value_counts().describe())


# ==========================================
# 3. DATA QUALITY CHECKS
# ==========================================

print("\n===== DATA QUALITY CHECKS =====")

print("\nMissing values:")
print(df.isnull().sum())

duplicate_count = X.duplicated().sum()

print("\nDuplicate feature rows:", duplicate_count)

# Check whether identical feature combinations
# have conflicting target labels.

duplicate_check = pd.concat(
    [X, y.rename("is_threat")],
    axis=1
)

label_counts = duplicate_check.groupby(
    list(X.columns),
    dropna=False
)["is_threat"].nunique()

conflicting_rows = (label_counts > 1).sum()

print(
    "Feature combinations with conflicting labels:",
    conflicting_rows
)


# ==========================================
# 4. THREAT PATTERN ANALYSIS
# ==========================================

print("\n===== THREAT PATTERN ANALYSIS =====")

analysis_columns = [
    "department",
    "usual_location",
    "location",
    "login_hour",
    "device_trusted",
    "usb_connected",
    "location_unusual",
    "after_hours",
    "failed_login_attempts"
]

for column in analysis_columns:

    if column not in df.columns:
        continue

    print(f"\n--- {column} ---")

    summary = df.groupby(
        column,
        dropna=False
    )["is_threat"].agg(
        records="count",
        threat_rate="mean"
    )

    summary = summary.sort_values(
        by="threat_rate",
        ascending=False
    )

    print(summary)


# ==========================================
# 5. EMPLOYEE-GROUPED CROSS-VALIDATION
# ==========================================

print("\n===== EMPLOYEE-GROUPED CROSS VALIDATION =====")

print(
    "\nEach employee will be kept entirely "
    "inside one fold."
)

cv = StratifiedGroupKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)

# Verify that employees do not appear in
# both training and testing sets.

for fold, (train_idx, test_idx) in enumerate(
    cv.split(X, y, groups),
    start=1
):

    train_employees = set(
        groups.iloc[train_idx]
    )

    test_employees = set(
        groups.iloc[test_idx]
    )

    overlap = train_employees.intersection(
        test_employees
    )

    print(f"\nFold {fold}")

    print(
        "Training employees:",
        len(train_employees)
    )

    print(
        "Testing employees:",
        len(test_employees)
    )

    print(
        "Employee overlap:",
        len(overlap)
    )

    print(
        "Testing class distribution:",
        y.iloc[test_idx].value_counts().to_dict()
    )

    assert len(overlap) == 0, (
        "Employee leakage detected!"
    )


# ==========================================
# 6. EVALUATE MODEL
# ==========================================

scoring = [
    "accuracy",
    "precision",
    "recall",
    "f1",
    "roc_auc"
]

print("\nTraining and evaluating model folds...")

scores = cross_validate(
    clone(pipeline),
    X,
    y,
    groups=groups,
    cv=cv,
    scoring=scoring,
    return_train_score=False,
    n_jobs=-1
)

print("\n===== GROUPED MODEL RESULTS =====")

for metric in scoring:

    values = scores[f"test_{metric}"]

    print(
        f"{metric.upper()}: "
        f"{values.mean():.4f} "
        f"(+/- {values.std():.4f})"
    )


# ==========================================
# 7. FEATURE IMPORTANCE
# ==========================================

print("\n===== FEATURE IMPORTANCE =====")

try:

    preprocessor = pipeline.named_steps[
        "preprocessor"
    ]

    classifier = pipeline.named_steps[
        "classifier"
    ]

    feature_names = (
        preprocessor.get_feature_names_out()
    )

    importance_values = (
        classifier.feature_importances_
    )

    importance_df = pd.DataFrame({
        "Feature": feature_names,
        "Importance": importance_values
    })

    importance_df = importance_df.sort_values(
        by="Importance",
        ascending=False
    )

    print(
        importance_df.head(15).to_string(
            index=False
        )
    )

except Exception as error:

    print(
        "Could not calculate feature importance:",
        error
    )


# ==========================================
# 8. IN-SAMPLE DIAGNOSTIC
# ==========================================

print("\n===== IN-SAMPLE DIAGNOSTIC =====")

print(
    "NOTE: This uses the complete dataset "
    "with the already-trained model."
)

print(
    "It is NOT an independent test result."
)

predictions = pipeline.predict(X)

print("\nClassification Report:")

print(
    classification_report(
        y,
        predictions,
        target_names=[
            "Normal",
            "Threat"
        ],
        zero_division=0
    )
)

print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y,
        predictions
    )
)


# ==========================================
# 9. FINAL SUMMARY
# ==========================================

print("\n========================================")
print("       VALIDATION COMPLETED")
print("========================================")

print("Total records:", len(df))
print("Unique employees:", groups.nunique())

print(
    "Employee leakage:",
    "NONE - all folds checked successfully"
)

print(
    "\nRemember: these results evaluate "
    "the dataset, not real-world attack detection."
)

print("\nSENTINEL AI validation finished!")
