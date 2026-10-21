# ConsentGuard 🛡️

**Purpose-Based Consent Recording & Withdrawal Prototype**

ConsentGuard is a prototype designed to record user consent, support consent withdrawal, enforce consent-based data access, and maintain an audit trail of system activities.

## Project Overview

ConsentGuard demonstrates how a system can make data-access decisions based on a user's consent preferences and the applicable notice version.

## Key Features

- **Consent Management:** Grant, deny, and withdraw consent for different purposes.
- **Purpose-Based Access Control:** Allow or deny data access based on consent status.
- **Security Overview:** Display access-related statistics.
- **Audit Logging:** Record relevant consent and data-access events.
- **Audit Export:** Export audit records as a CSV file.
- **Consent Notice:** Support notice-version checks.
- **Automated Tests:** Test backend API behaviour.

## Technologies Used

- Python
- Flask
- SQLite
- HTML, CSS, and JavaScript
- Git and GitHub

## Project Structure

```text
CONSENT GUARD/
├── backend/
│   ├── api.py
│   ├── database.py
│   ├── test_api.py
│   └── consentguard.db
├── app.py
├── dashboard.html
├── start-consentguard.bat
└── README.md
```

The database file may be created locally when the application runs and may be excluded from version control.

## Getting Started

### Requirements

- Python
- A code editor such as Visual Studio Code
- Git (optional, for version control)

### Run the Backend

On Windows, double-click `start-consentguard.bat` from the project folder.

Alternatively, open a terminal in the `backend` folder and run:

```powershell
.\.venv\Scripts\python.exe api.py
```

Keep the backend terminal open while using the dashboard.

### Open the Dashboard

Open `dashboard.html` in your browser and use the consent controls and Data-Access Simulator to test the prototype.

The backend API runs locally at `http://127.0.0.1:5001`.

## Run Automated Tests

From the project root, run:

```powershell
cd backend
.\.venv\Scripts\python.exe -m unittest -v test_api
```

A successful run should finish with `OK`.

## Team

**Team Name:** SPARK

**Team Members:**
- Yash Chandra
- Pradeep Yadav

## Disclaimer

ConsentGuard is a prototype developed for demonstration and educational purposes. It is not a production-ready consent-management or security platform.
