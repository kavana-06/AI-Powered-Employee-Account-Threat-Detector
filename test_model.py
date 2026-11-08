
import pandas as pd
import joblib

# Load trained model
model = joblib.load("employee_threat_model.pkl")

# Create sample employee activities
test_data = pd.DataFrame([
    {
        "department": "IT",
        "usual_location": "Bengaluru",
        "location": "Bengaluru",
        "usual_login_hour": 9,
        "login_hour": 9,
        "login_hour_deviation": 0,
        "files_downloaded": 10,
        "failed_login_attempts": 0,
        "device_trusted": 1,
        "sensitive_files_accessed": 0,
        "usb_connected": 0,
        "location_unusual": 0,
        "after_hours": 0
    },
    {
        "department": "Finance",
        "usual_location": "Mumbai",
        "location": "Chennai",
        "usual_login_hour": 9,
        "login_hour": 2,
        "login_hour_deviation": 7,
        "files_downloaded": 600,
        "failed_login_attempts": 5,
        "device_trusted": 0,
        "sensitive_files_accessed": 15,
        "usb_connected": 1,
        "location_unusual": 1,
        "after_hours": 1
    }
])

# Predict threats
predictions = model.predict(test_data)
probabilities = model.predict_proba(test_data)[:, 1]

# Display results
for i in range(len(test_data)):

    print("\nEmployee Activity:", i + 1)

    if predictions[i] == 1:
        print("Prediction: POTENTIAL THREAT")
    else:
        print("Prediction: NORMAL")

    print(f"Threat score: {probabilities[i] * 100:.2f}%")

print("\nPrediction testing completed!")
