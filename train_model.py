
import pandas as pd
import joblib

from sklearn.model_selection import GroupShuffleSplit
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    balanced_accuracy_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)


# ==========================================
# 1. LOAD DATASET
# ==========================================

print("\n======================================")
print("       SENTINEL AI MODEL TRAINING")
print("======================================")

df = pd.read_csv("dataset/employee_activity.csv")

print("\nDataset loaded successfully!")
print("Dataset shape:", df.shape)


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
        raise ValueError(f"Missing column: {column}")

X = df.drop(columns=required_columns)

y = df["is_threat"].astype(int)

groups = df["employee_id"]

if y.nunique() != 2:
    raise ValueError("Dataset must contain both normal and threat records.")

print("\nTotal records:", len(df))
print("Unique employees:", groups.nunique())
print("Features:", X.shape[1])

print("\nClass distribution:")
print(y.value_counts())


# ==========================================
# 3. EMPLOYEE-GROUPED TRAIN/TEST SPLIT
# ==========================================

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_idx, test_idx = next(
    splitter.split(X, y, groups)
)

X_train = X.iloc[train_idx]
X_test = X.iloc[test_idx]

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

train_employees = set(groups.iloc[train_idx])
test_employees = set(groups.iloc[test_idx])

overlap = train_employees.intersection(test_employees)

print("\n===== EMPLOYEE-GROUPED SPLIT =====")

print("Training employees:", len(train_employees))
print("Testing employees:", len(test_employees))
print("Training records:", len(X_train))
print("Testing records:", len(X_test))
print("Employee overlap:", len(overlap))

if overlap:
    raise ValueError("Employee leakage detected!")

if y_train.nunique() != 2 or y_test.nunique() != 2:
    raise ValueError(
        "Both training and testing sets must contain both classes. "
        "Try a different random_state."
    )

print("\nTraining class distribution:")
print(y_train.value_counts())

print("\nTesting class distribution:")
print(y_test.value_counts())


# ==========================================
# 4. IDENTIFY FEATURE TYPES
# ==========================================

numeric_features = X.select_dtypes(
    include=["int64", "float64"]
).columns.tolist()

categorical_features = X.select_dtypes(
    include=["object", "category", "bool"]
).columns.tolist()

print("\nNumeric features:", len(numeric_features))
print("Categorical features:", len(categorical_features))


# ==========================================
# 5. CREATE PREPROCESSING PIPELINE
# ==========================================

numeric_transformer = Pipeline(
    steps=[
        (
            "imputer",
            SimpleImputer(strategy="median")
        )
    ]
)

categorical_transformer = Pipeline(
    steps=[
        (
            "imputer",
            SimpleImputer(strategy="most_frequent")
        ),
        (
            "encoder",
            OneHotEncoder(handle_unknown="ignore")
        )
    ]
)

preprocessor = ColumnTransformer(
    transformers=[
        (
            "num",
            numeric_transformer,
            numeric_features
        ),
        (
            "cat",
            categorical_transformer,
            categorical_features
        )
    ]
)


# ==========================================
# 6. CREATE RANDOM FOREST MODEL
# ==========================================

classifier = RandomForestClassifier(
    n_estimators=200,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

pipeline = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("classifier", classifier)
    ]
)


# ==========================================
# 7. TRAIN MODEL
# ==========================================

print("\nTraining model...")

pipeline.fit(X_train, y_train)

print("Model training completed!")


# ==========================================
# 8. TEST MODEL
# ==========================================

predictions = pipeline.predict(X_test)

probabilities = pipeline.predict_proba(X_test)

threat_class_index = list(
    pipeline.classes_
).index(1)

threat_probabilities = probabilities[
    :, threat_class_index
]


# ==========================================
# 9. EVALUATE MODEL
# ==========================================

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)

balanced_accuracy = balanced_accuracy_score(
    y_test,
    predictions
)

roc_auc = roc_auc_score(
    y_test,
    threat_probabilities
)

print("\n===== MODEL PERFORMANCE =====")

print(f"Accuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1 Score: {f1:.4f}")
print(f"Balanced Accuracy: {balanced_accuracy:.4f}")
print(f"ROC-AUC: {roc_auc:.4f}")


# ==========================================
# 10. CLASSIFICATION REPORT
# ==========================================

print("\n===== CLASSIFICATION REPORT =====")

print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Normal", "Threat"],
        zero_division=0
    )
)


# ==========================================
# 11. CONFUSION MATRIX
# ==========================================

print("\n===== CONFUSION MATRIX =====")

print(
    confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    )
)


# ==========================================
# 12. FEATURE IMPORTANCE
# ==========================================

print("\n===== TOP 10 IMPORTANT FEATURES =====")

feature_names = (
    pipeline.named_steps[
        "preprocessor"
    ].get_feature_names_out()
)

importance_values = (
    pipeline.named_steps[
        "classifier"
    ].feature_importances_
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
    importance_df.head(10).to_string(
        index=False
    )
)


# ==========================================
# 13. SAVE TRAINED MODEL
# ==========================================

joblib.dump(
    pipeline,
    "employee_threat_model.pkl"
)

print("\nModel saved successfully!")
print("File: employee_threat_model.pkl")


# ==========================================
# 14. FINAL SUMMARY
# ==========================================

print("\n======================================")
print("       TRAINING COMPLETED")
print("======================================")

print("Training employees:", len(train_employees))
print("Testing employees:", len(test_employees))
print("Employee overlap:", len(overlap))

print("\nSENTINEL AI model is ready!")
