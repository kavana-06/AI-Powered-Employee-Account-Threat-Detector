# 🛡️ SENTINEL AI — AI Employee Account Threat Detector

**An AI-powered web application that detects suspicious employee account activity and helps security teams investigate potential threats.**

🌐 **Live Demo:** https://ai-powered-employee-account-threat.onrender.com

## 📌 About the Project

SENTINEL AI is a machine-learning-based security application designed to identify unusual employee account activity and detect potential insider threats.

It analyzes employee login behavior, locations, device trust, file downloads, failed login attempts, and other security indicators to classify suspicious activity.

## ✨ Features

- **AI Threat Detection:** Predicts whether employee activity is normal or potentially threatening.
- **Admin Authentication:** Secure administrator login and logout.
- **Security Dashboard:** Displays security statistics and activity information.
- **Activity History:** Stores and displays detected activity records.
- **Threat Investigation:** Allows administrators to review threats and update investigation status and notes.
- **Bulk Detection:** Supports CSV and PDF activity uploads.
- **PDF Reports:** Generates downloadable security reports.
- **Interactive Interface:** Web-based dashboard with a responsive frontend.

## 🧰 Technologies Used

| Category | Technologies |
|---|---|
| Backend | Python, Flask |
| Machine Learning | Scikit-learn, Joblib |
| Data Processing | Pandas, NumPy |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript |
| Authentication | Flask-Login, Flask-WTF |
| PDF Processing | pdfplumber |
| Deployment | Render, Gunicorn |
| Version Control | Git, GitHub |

## ⚙️ How It Works

1. An administrator logs into SENTINEL AI.
2. Employee account activity is submitted.
3. The application processes the activity data.
4. The trained machine learning model evaluates the activity.
5. The application displays the prediction.
6. Potential threats can be reviewed in the Threat Investigation section.

## 🚀 Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/kavana-06/AI-Powered-Employee-Account-Threat-Detector.git
```

### 2. Open the project folder

```bash
cd AI-Powered-Employee-Account-Threat-Detector
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure environment variables

Create a `.env` file and configure the required application settings:

- `SENTINEL_SECRET_KEY`
- `SENTINEL_ADMIN_USERNAME`
- `SENTINEL_ADMIN_PASSWORD`

Use your own secure values. Never upload `.env` to GitHub.

### 7. Run the application

```bash
python app.py
```

Open your browser at:

```text
http://127.0.0.1:5000
```

## 🔐 Security Notes

- Keep secret keys and administrator credentials private.
- Do not upload `.env` or database files containing private information.
- Use strong administrator passwords.
- This project is intended as a security monitoring and educational demonstration tool.

## 👨‍💻 Author

**Kavana**

GitHub: [@kavana-06](https://github.com/kavana-06)

---

⭐ If you find this project interesting, consider giving the repository a star!
