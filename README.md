# ConsentGuard
### Enterprise Purpose-Based Consent Recording, Downstream Policy Enforcement & Merkle DAG Audit System

> **Problem Statement (AIORI-3 / PS-002):**  
> In conventional enterprise architectures, consent is stored as passive database flags that downstream microservices, analytical pipelines, and third-party consumers routinely bypass. ConsentGuard implements active, cryptographic purpose-based consent enforcement. If consent is absent, denied, withdrawn, or granted under an outdated privacy notice, downstream access is immediately blocked at the Policy Enforcement Point (PEP). Every grant, withdrawal, and data-release decision is cryptographically anchored to an immutable SHA-256 Merkle DAG audit ledger.

---

## ⚡ Quick Start: Running ConsentGuard

### 1. One-Click Setup & Launch
* **Windows:**
  ```cmd
  run.bat
  ```
* **Linux / macOS / WSL:**
  ```bash
  chmod +x run.sh
  ./run.sh
  ```
* **Or via Python directly:**
  ```bash
  python seed.py
  python backend/api.py
  ```

### 2. Access the Application
Open your browser and navigate to:  
👉 **[http://localhost:5001](http://localhost:5001)**  
Live Cloud Deployment: 👉 **[https://consent-guard-2.vercel.app](https://consent-guard-2.vercel.app)**

---

## 🏆 Offline Hackathon Live Demonstration

ConsentGuard provides an automated, self-contained 9-stage demonstration that runs entirely in an isolated disposable sandbox database (zero risk to production data):

```bash
python demo_backend.py
```

### Demonstration Lifecycle Sequence:
1. **Grant Consent:** User opts into `Analytics` under active Notice v1.0.
2. **Downstream Data Share (ALLOW):** Authorized downstream partner requests telemetry; PEP validates active consent and releases permitted fields only (`HTTP 200`).
3. **Withdraw Consent:** User withdraws `Analytics` consent.
4. **Downstream Data Share Blocked (DENY):** Partner requests data again; PEP immediately blocks access (`HTTP 403 WITHDRAWN`).
5. **Publish New Notice:** Privacy administrator publishes Notice v2.0 atomically (`is_active = 1`).
6. **Outdated Consent Blocked (DENY):** Consent granted under Notice v1.0 is flagged as stale; PEP denies downstream access (`HTTP 403 NOTICE_MISMATCH`).
7. **Re-Consent Under Current Notice (ALLOW):** User re-consents under Notice v2.0; downstream access is immediately restored.
8. **Cryptographic Ledger Verification (VALID):** Mathematical scan verifies the complete SHA-256 Merkle DAG hash chain across all recorded events.
9. **Forensic Tamper Detection (INVALID):** An unauthorized database update is injected in the isolated sandbox; the forensic scanner immediately detects payload alteration (`ROW_HASH_TAMPERED`) and halts.

---

## 🏛️ System Architecture

```
                                 ┌────────────────────────────────────────────────┐
                                 │                 Frontend UI                    │
                                 │     (Dashboard / Simulator / Audit Viewer)     │
                                 └──────────────────────┬─────────────────────────┘
                                                        │
                              Bearer Token / Cookie / X-Admin-Key / X-API-Key
                                                        │
                                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                ConsentGuard Flask Backend Engine                                │
│                                                                                                 │
│  ┌───────────────────────┐   ┌──────────────────────────────┐   ┌────────────────────────────┐  │
│  │ Authenticated Subject │   │ Database-Driven Purposes     │   │ Downstream Consumers       │  │
│  │ & Token Resolver      │   │ (Analytics, Marketing, etc.) │   │ (partner-all, limited)     │  │
│  └───────────┬───────────┘   └──────────────┬───────────────┘   └─────────────┬──────────────┘  │
│              │                              │                                 │                 │
│              └──────────────────────────────┼─────────────────────────────────┘                 │
│                                             ▼                                                   │
│                        ┌─────────────────────────────────────────┐                              │
│                        │    Policy Enforcement Point (PEP)       │                              │
│                        │  evaluate_policy_and_consent(...)       │                              │
│                        │  - Fail-Closed Architecture             │                              │
│                        │  - Notice Hash Invalidation             │                              │
│                        │  - Field-Level Minimization             │                              │
│                        └────────────────────┬────────────────────┘                              │
│                                             │                                                   │
│                                             ▼                                                   │
│                        ┌─────────────────────────────────────────┐                              │
│                        │    Cryptographic Merkle DAG Ledger      │                              │
│                        │  - Canonical JSON SHA-256 Hashing       │                              │
│                        │  - Advisory Locks & Mutex Serialization │                              │
│                        │  - DB Triggers (UPDATE/DELETE Blocked)  │                              │
│                        │  - Automatic PII/Secret Redaction       │                              │
│                        └────────────────────┬────────────────────┘                              │
└─────────────────────────────────────────────┼───────────────────────────────────────────────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
          Local Storage (Offline)                         Cloud Storage (Production)
          SQLite (WAL + Triggers)                         Neon Serverless PostgreSQL
```

---

## 🔒 Security & Cryptographic Integrity

### 1. Canonical JSON Audit Hashing (RFC 8785)
Every audit event computes an immutable cryptographic hash over canonical JSON:
$$\text{row\_hash} = \text{SHA-256}(\text{JSON}(\text{prev\_hash}, \text{user\_id}, \text{purpose}, \text{action}, \text{http\_status}, \text{reason\_code}, \text{notice\_version}, \text{notice\_hash}, \text{details}, \dots))$$
* **Multi-Parent Merkle DAG:** Multi-instance serverless deployments occasionally generate concurrent sibling writes off the same parent. The verification engine supports Merkle DAG topology verification while detecting tampering or orphaned records.
* **Dual-Verifier Compatibility:** Historical pipe-delimited records are verified via backward-compatible fallback, preventing legacy data breakage.

### 2. Database Immutability Triggers
Direct modifications to historical audit records are blocked at the database engine level:
```sql
CREATE TRIGGER trg_prevent_audit_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'Audit events are cryptographically immutable: UPDATE is blocked.');
END;

CREATE TRIGGER trg_prevent_audit_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'Audit events are cryptographically immutable: DELETE is blocked.');
END;
```

### 3. PII & Credential Sanitization
Audit event details automatically redact email addresses to `[REDACTED_EMAIL]` and API keys / bearer tokens to `[REDACTED_SECRET]`, ensuring GDPR/DPDP regulatory compliance.

### 4. Constant-Time Admin Authorization
Administrative endpoints (`/api/notice/update`, `/api/notice/reset`, `/api/demo/reset`) enforce constant-time credential comparison (`hmac.compare_digest`) via the `X-Admin-Key` header, while seamlessly permitting authenticated dashboard users.

---

## 📡 API Reference

### 1. Downstream Partner Sharing
#### `POST /api/share/request`
Evaluates downstream consumer requests against user consent, notice validity, and field authorization.
* **Headers:** `X-API-Key: <partner_key>` or JSON `"api_key": "<key>"`
* **Request Body:**
  ```json
  {
    "user_id": "demo-user",
    "purpose": "Analytics",
    "requested_fields": ["page_views"]
  }
  ```
* **Validation Pipeline (in strict order):**
  1. Invalid / missing API key $\rightarrow$ `HTTP 401 UNAUTHORIZED`
  2. Consumer not authorized for purpose $\rightarrow$ `HTTP 403 FORBIDDEN`
  3. Invalid purpose $\rightarrow$ `HTTP 400 BAD_REQUEST`
  4. Unknown user $\rightarrow$ `HTTP 404 NOT_FOUND`
  5. Missing, withdrawn, or stale consent $\rightarrow$ `HTTP 403 FORBIDDEN`
  6. Unauthorized fields $\rightarrow$ `HTTP 403 FORBIDDEN`
  7. Valid request $\rightarrow$ `HTTP 200 OK` (Releases permitted fields only)

### 2. Consent Management
* `GET /api/consents`: Returns itemized consent records for authenticated user.
* `POST /api/consents`: Records consent grant, withdrawal, or denial.
  * Rejects outdated notice hashes with `409 STALE_NOTICE`.
  * Withdrawal is idempotent: repeating withdrawal returns `200 CONSENT_ALREADY_WITHDRAWN` without duplicate audit rows.

### 3. Privacy Notices
* `GET /api/notice`: Returns active notice version, text, and SHA-256 hash.
* `POST /api/notice/update`: Atomically publishes notice change; rejects conflicts with `409 VERSION_EXISTS`.
* `POST /api/notice/reset`: Resets active notice to v1.0 without destroying historical versions.

### 4. Audit & Verification
* `GET /api/audit`: Returns user-scoped audit ledger.
* `GET /api/audit/verify`: Scans and cryptographically verifies the SHA-256 Merkle DAG ledger.
* `GET /api/audit/export?format=csv|json`: Exports audit trail for compliance inspection.

---

## 🧪 Comprehensive Automated Test Suite

ConsentGuard includes **84 automated tests** with 100% test passage:

```powershell
# Run the complete test suite (84 tests):
python -m pytest tests/ -v
python backend/test_api.py -v

# Run the dedicated Hackathon Enterprise Suite (28 tests):
python -m pytest tests/test_enterprise_suite.py -v

# Run cryptographic Merkle DAG integrity tests (8 tests):
python -m pytest tests/test_audit_chain.py -v

# Run authentication & cross-user isolation tests (14 tests):
python -m pytest tests/test_auth_and_isolation.py -v

# Run core consent & PEP policy tests (16 tests):
python -m pytest tests/test_consent.py -v
```

---

## ⚙️ Environment Configuration

Copy `.env.example` to `.env`:
```bash
# Flask Session Security
SECRET_KEY=consentguard-production-secret-key-change-in-production

# Administrative Infrastructure Key
ADMIN_KEY=cg_admin_secret_key_hackathon

# Seeded Downstream Consumer Keys
PARTNER_ALL_KEY=key_partner_all_enterprise
PARTNER_LIMITED_KEY=key_partner_limited_research

# PostgreSQL Connection URL (Optional for local SQLite)
# DATABASE_URL=postgresql://user:password@ep-host.pooler.neon.tech/neondb?sslmode=require
```

---

## 🚀 Cloud Deployment (Vercel & Neon PostgreSQL)

ConsentGuard is configured for zero-configuration deployment to Vercel:
1. Connect repository to Vercel.
2. In Vercel Project Settings, add `DATABASE_URL` (Neon PostgreSQL) and `SECRET_KEY`.
3. Deploy! Serverless Python functions run via `api/index.py` using pure-Python `pg8000` drivers with zero C-extension overhead.
