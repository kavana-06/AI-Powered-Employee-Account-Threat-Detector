
import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta

# Reproducible dataset
random.seed(42)
np.random.seed(42)

# Employee information
departments = [
    "IT",
    "HR",
    "Finance",
    "Marketing",
    "Sales"
]

locations = [
    "Bengaluru",
    "Mumbai",
    "Delhi",
    "Chennai",
    "Hyderabad"
]

employees = []

for i in range(1, 31):
    employees.append({
        "employee_id": f"EMP{i:03d}",
        "department": random.choice(departments),
        "usual_location": random.choice(locations),
        "usual_login_hour": random.randint(8, 10)
    })

records = []

start_date = datetime(2026, 1, 1)

# Generate 30 days of employee activity
for employee in employees:

    for day in range(30):

        activity_date = start_date + timedelta(days=day)

        # Decide whether this activity is suspicious
        is_suspicious = random.random() < 0.08

        login_hour = int(np.clip(
            np.random.normal(employee["usual_login_hour"], 1),
            0, 23
        ))

        location = employee["usual_location"]
        files_downloaded = random.randint(0, 20)
        failed_login_attempts = random.randint(0, 1)
        device_trusted = 1
        sensitive_files_accessed = random.randint(0, 2)
        usb_connected = 0

        threat_type = "Normal"

        if is_suspicious:

            threat = random.choice([
                "Unusual Login",
                "Excessive Downloads",
                "Unusual Location",
                "Multiple Suspicious Activities"
            ])

            threat_type = threat

            if threat == "Unusual Login":
                login_hour = random.choice([0, 1, 2, 3, 4, 5])

            elif threat == "Excessive Downloads":
                files_downloaded = random.randint(500, 2500)

            elif threat == "Unusual Location":
                location = random.choice([
                    loc for loc in locations
                    if loc != employee["usual_location"]
                ])

            elif threat == "Multiple Suspicious Activities":
                login_hour = random.choice([0, 2, 3, 4])
                files_downloaded = random.randint(500, 2000)
                failed_login_attempts = random.randint(3, 8)
                device_trusted = 0
                sensitive_files_accessed = random.randint(10, 30)
                usb_connected = 1

        location_unusual = int(
            location != employee["usual_location"]
        )

        after_hours = int(
            login_hour < 6 or login_hour > 21
        )

        records.append({
            "employee_id": employee["employee_id"],
            "department": employee["department"],
            "activity_date": activity_date.strftime("%Y-%m-%d"),
            "usual_location": employee["usual_location"],
            "location": location,
            "usual_login_hour": employee["usual_login_hour"],
            "login_hour": login_hour,
            "login_hour_deviation": abs(
                login_hour - employee["usual_login_hour"]
            ),
            "files_downloaded": files_downloaded,
            "failed_login_attempts": failed_login_attempts,
            "device_trusted": device_trusted,
            "sensitive_files_accessed": sensitive_files_accessed,
            "usb_connected": usb_connected,
            "location_unusual": location_unusual,
            "after_hours": after_hours,
            "is_threat": int(is_suspicious),
            "threat_type": threat_type
        })

# Convert to DataFrame
df = pd.DataFrame(records)

# Save dataset
output_path = "dataset/employee_activity.csv"
df.to_csv(output_path, index=False)

print("\n======================================")
print(" EMPLOYEE ACTIVITY DATASET GENERATED")
print("======================================")

print(f"\nTotal records: {len(df)}")
print(f"Total employees: {df['employee_id'].nunique()}")
print(f"Normal activities: {(df['is_threat'] == 0).sum()}")
print(f"Suspicious activities: {(df['is_threat'] == 1).sum()}")

print("\nThreat distribution:")
print(df["threat_type"].value_counts())

print(f"\nDataset saved successfully: {output_path}")

print("\nFirst five records:")
print(df.head())
