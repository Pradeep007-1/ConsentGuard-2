# ConsentGuard
### Purpose-Based Consent Recording & Policy Enforcement System

> **System Overview:**  
> ConsentGuard gives users complete control over how their personal data is used and prevents downstream services from accessing data without valid, purpose-specific consent. If consent is withdrawn or the privacy notice changes, data access is blocked immediately.

---

## ⚡ Quick Start: Running ConsentGuard

### 1. Launch the Backend Server
* **Windows Shortcut:** Double-click `start-consentguard.bat` in the project root.
* **Or via PowerShell / Terminal:**
  ```powershell
  python app.py
  # or: python backend/api.py
  ```

### 2. Open the Web Application
Open your browser and navigate to:  
👉 **[http://127.0.0.1:5001](http://127.0.0.1:5001)**

---

## 🧭 Navigation & Features (5 Clean Pages)

The application is organized into 5 easy-to-understand pages:

1. **Dashboard**
   * Simple welcome banner: *"Welcome to ConsentGuard — You control how your data is used."*
   * Three clear purpose cards: **Analytics**, **Marketing**, and **Service Improvement**.
   * Instant status indicators: `Granted`, `Not Granted`, or `Notice Changed`.
   * Current privacy notice and real-time downstream protection summaries.

2. **Manage Consent**
   * Independently grant or withdraw permission for each purpose.
   * Clear plain-English explanations of how data is used and which fields are protected.
   * `✓ Grant Consent` and `✕ Withdraw Consent` buttons.
   * Displays the exact date and time of your last action.
   * Withdrawing one permission never affects the others.

3. **Test Data Access (The Main Feature)**
   * Demonstrates the Mock Data-Sharing API simulator in plain English.
   * Select a sample user and a requested purpose.
   * Click **"Request Data Access"** to evaluate the real-time permission check.
   * If allowed: Shows a green **ACCESS ALLOWED** banner, **HTTP 200**, and safe sample data.
   * If denied: Shows a red **ACCESS BLOCKED** banner, **HTTP 403**, and explains why (*e.g., "You withdrew your consent"* or *"The privacy notice changed"*).

4. **Activity History**
   * A clean, readable activity log showing Date/Time, User, Purpose, Action, Result, and Reason.
   * Filter events by user or action.
   * One-click **Export CSV** and **Export JSON**.
   * One-click **Verify Integrity** button that mathematically checks the append-only SHA-256 hash chain.

5. **Privacy Notice**
   * Displays the active notice text and version (e.g. `v1.0`).
   * Plain-English breakdown of all 3 data-use purposes.
   * Interactive **"Update Notice to v2.0"** button: Demonstrates that when privacy terms change, previous consents automatically expire, and fresh consent is required before services can access data again.

*(An optional **Diagnostic Tests (14)** tab is also available in the navbar to execute the automated live test suite.)*

---

## 🔄 End-to-End System Verification Flow

Follow this verification flow to test the complete lifecycle:

1. **Show the Dashboard:**
   * Point out the three separate consent cards: Analytics, Marketing, Service Improvement.
   * Show that permissions default to `Not Granted`.
2. **Grant Analytics Consent:**
   * Switch to **Manage Consent** and click **✓ Grant Consent** on **Analytics**.
   * Status turns green: `Granted`.
3. **Test Allowed Access (HTTP 200):**
   * Switch to **Test Data Access**.
   * Select **Analytics** and click **Request Data Access**.
   * Point out the green **✓ ACCESS ALLOWED (HTTP 200)** banner and the sample analytics data released.
4. **Demonstrate Purpose Independence:**
   * Select **Marketing** in the simulator and click **Request Data Access**.
   * Point out the red **✕ ACCESS BLOCKED (HTTP 403)** banner with the explanation: *"You have not granted consent for this purpose."*
5. **Withdraw Consent & Show Immediate Revocation:**
   * Return to **Manage Consent** and click **✕ Withdraw Consent** on **Analytics**.
   * Back in **Test Data Access**, request Analytics data again.
   * Show that access is immediately blocked with **HTTP 403 (WITHDRAWN)**.
6. **Demonstrate Privacy Notice Versioning:**
   * Open **Privacy Notice** and click **Update Notice to v2.0**.
   * Return to **Manage Consent**: Notice the amber alert: *"Your previous consent was granted under an older notice. Please grant fresh consent to allow access."*
   * Click **Grant Consent Under Current Notice**.
   * Back in **Test Data Access**, request access again: Access is now restored under v2.0!
7. **Show the Activity History:**
   * Open **Activity History** to show all actions recorded with timestamps and reasons.
   * Click **Verify Integrity** to show the green checkmark proving the tamper-proof hash chain.

---

## 🧪 Automated Test Suite

ConsentGuard includes comprehensive automated tests that run against the live Flask server and SQLite database:

```powershell
# Run the 15-test pytest lifecycle suite:
python -m pytest tests/test_consent.py -v

# Run the 18-test backend unit test suite:
python backend/test_api.py
```

All tests execute with 100% PASS rates.
