# ConsentGuard
### Enterprise Purpose-Based Consent Recording, Downstream Policy Enforcement & Merkle DAG Audit System

> **Problem Statement (AIORI-3 / PS-002):**  
> In conventional enterprise architectures, consent is stored as passive database flags that downstream microservices, analytical pipelines, and third-party consumers routinely bypass. ConsentGuard implements active, cryptographic purpose-based consent enforcement. If consent is absent, denied, withdrawn, or granted under an outdated privacy notice, downstream access is immediately blocked at the Policy Enforcement Point (PEP). Every grant, withdrawal, and data-release decision is cryptographically anchored to an immutable SHA-256 Merkle DAG audit ledger.

---

## 📋 Table of Contents
1. [Quick Start & Startup Instructions](#-quick-start--startup-instructions)
2. [Offline Hackathon Setup & Environment](#-offline-hackathon-setup--environment)
3. [Synthetic Demonstration Accounts & Credentials](#-synthetic-demonstration-accounts--credentials)
4. [System Architecture](#-system-architecture)
5. [Database Architecture & Schema](#-database-architecture--schema)
6. [Authentication Architecture](#-authentication-architecture)
7. [Authorization & Access Control](#-authorization--access-control)
8. [Consent Lifecycle Protocol](#-consent-lifecycle-protocol)
9. [Privacy Notice Management & Versioning](#-privacy-notice-management--versioning)
10. [Merkle DAG & Tamper-Evident Audit Ledger](#-merkle-dag--tamper-evident-audit-ledger)
11. [Audit Verification Engine](#-audit-verification-engine)
12. [Purpose-Based Data Sharing & PEP Authorization](#-purpose-based-data-sharing--pep-authorization)
13. [Cybersecurity Protections & Controls](#-cybersecurity-protections--controls)
14. [Step-by-Step Live Cybersecurity Demonstration](#-step-by-step-live-cybersecurity-demonstration)
15. [Automated Testing Suite (124 Tests)](#-automated-testing-suite-124-tests)
16. [Comprehensive API Endpoint Documentation](#-comprehensive-api-endpoint-documentation)
17. [Troubleshooting Guide](#-troubleshooting-guide)

---

## ⚡ Quick Start & Startup Instructions

### 1. One-Click Launcher (Recommended)
ConsentGuard is pre-configured with 1-click startup scripts that automatically set offline environment variables, activate virtual environments, initialize the local SQLite database, seed synthetic accounts, validate dependencies, and launch the server.

* **Windows:**
  ```cmd
  start-consentguard.bat
  ```
  *(Alternatively: `run.bat`)*

* **Linux / macOS / WSL:**
  ```bash
  chmod +x run.sh
  ./run.sh
  ```

* **Manual Startup (Cross-Platform):**
  ```bash
  # 1. Initialize and seed local SQLite database
  python seed.py

  # 2. Start ConsentGuard backend server
  python app.py
  ```

### 2. Access the Local Application
Once started, open your web browser and navigate to:
* **Web UI / Application:** [http://localhost:5001](http://localhost:5001)
* **Administrative Dashboard:** [http://localhost:5001/dashboard](http://localhost:5001/dashboard)
* **Safe Health Diagnostics:** [http://localhost:5001/api/health](http://localhost:5001/api/health)

### 3. Graceful Shutdown
To stop the ConsentGuard server at any time:
* Press **`CTRL + C`** in the console window. The SQLite WAL (Write-Ahead Logging) buffers will flush cleanly to disk without database corruption.

---

## 🔌 Offline Hackathon Setup & Environment

ConsentGuard is engineered to execute **100% offline with zero cloud dependencies**. During local evaluation, no internet connection or external network requests are made.

### Guaranteed Offline Isolation:
* **`LOCAL_MODE=1` & `OFFLINE_MODE=1`:** Enforced by default in `start-consentguard.bat`, `run.sh`, and `app.py`.
* **Zero Production DB Access:** When in local mode, `database.get_database_url()` strictly returns an empty string `""`, completely ignoring any cloud PostgreSQL connection strings and preventing accidental queries to production or remote servers.
* **Storage Location:** All local state is persisted in `backend/consentguard.db` (SQLite 3.x with WAL mode, foreign keys, and cryptographic integrity triggers).

---

## 👥 Synthetic Demonstration Accounts & Credentials

The system seeds synthetic enterprise accounts and consumer partner API keys during database initialization (`seed.py`):

### 1. User Evaluation Accounts
| Role | Name | Email | Password | Privileges |
| :--- | :--- | :--- | :--- | :--- |
| **Demo User** | Demo User | `demo@consentguard.local` | `demo123` | Active user subject with sample consents |
| **Security Admin** | Security Administrator | `admin@consentguard.local` | `AdminPass123!` | Notice bump, notice reset, consumer API key revocation |
| **Regular User** | Synthetic Regular User | `user@consentguard.local` | `UserPass123!` | Standard user; strictly blocked from admin routes |
| **Demo Subject 1** | User 1 (Demo) | `user1@consentguard.local` | `demo123` | Multi-user consent comparison subject |
| **Demo Subject 2** | User 2 (Demo) | `user2@consentguard.local` | `demo123` | Multi-user consent comparison subject |

### 2. Administrative Master Secret
* **Admin Key Header:** `X-Admin-Key: cg_admin_offline_key_2026`
* Enforced on all sensitive administrative mutations (`/api/notice/update`, `/api/notice/reset`, `/api/consumers/revoke`, `/api/demo/reset`).

### 3. Downstream Partner Consumer API Keys
| Consumer ID | Consumer Name | API Key | Allowed Purposes | Permitted Fields |
| :--- | :--- | :--- | :--- | :--- |
| `partner-all` | Partner All-Access Enterprise | `key_partner_all_enterprise` | Analytics, Marketing, Service Improvement | Purpose-specific approved fields |
| `partner-limited` | Partner Limited Research | `key_partner_limited_research` | **Analytics only** | `["page_views", "feature_usage"]` only |

---

## 🏛️ System Architecture

ConsentGuard employs a layered, fail-closed architecture where data access decisions are decoupled from data storage and strictly governed by a centralized Policy Enforcement Point (PEP).

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
│                        │  - Consumer Verification                │                              │
│                        │  - Notice Hash Invalidation             │                              │
│                        │  - Field-Level Minimization             │                              │
│                        └────────────────────┬────────────────────┘                              │
│                                             │                                                   │
│                                             ▼                                                   │
│                        ┌─────────────────────────────────────────┐                              │
│                        │    Cryptographic Merkle DAG Ledger      │                              │
│                        │  - Canonical JSON SHA-256 Hashing       │                              │
│                        │  - Multi-Parent Branch Support          │                              │
│                        │  - Mutex & Advisory Lock Serialization  │                              │
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

### Architectural Principles:
1. **Decoupled Policy Enforcement:** Downstream services cannot query data directly; all access is mediated through the PEP (`/api/share/request`).
2. **Fail-Closed Philosophy:** Any ambiguity, database failure, unauthenticated state, or stale notice results in immediate access denial (`HTTP 401` or `HTTP 403`).
3. **Data Minimization:** Consumers receive only the exact subset of fields authorized for their purpose and permitted by the user's active consent.
4. **Tamper-Evident Auditing:** Every decision (grant, withdrawal, allow, deny) is hashed into an immutable Merkle Directed Acyclic Graph (DAG).

---

## 🗄️ Database Architecture & Schema

ConsentGuard features a unified database abstraction layer supporting both local offline SQLite and cloud PostgreSQL:

### Database Engines & Concurrency Handling:
* **SQLite (Local Offline Mode):**
  * `PRAGMA journal_mode = WAL;` (Write-Ahead Logging enables concurrent readers while writing).
  * `PRAGMA busy_timeout = 5000;` (Prevents database lock contention under load).
  * `PRAGMA foreign_keys = ON;` (Strict relational referential integrity).
  * `_sqlite_audit_lock = threading.Lock()` (Serializes concurrent audit event appending).
* **PostgreSQL (Cloud Production Mode):**
  * Connection management via pure-Python `pg8000` DBAPI (zero native C dependencies).
  * Concurrency serialization via transaction-level advisory locks: `SELECT pg_advisory_xact_lock(7429184);`

### Relational Schema:
1. **`users`**:
   * `id` (TEXT PRIMARY KEY), `name`, `email` (UNIQUE), `password_hash`, `is_demo` (INTEGER), `is_admin` (INTEGER), `created_at` (TIMESTAMP).
2. **`notice_versions`**:
   * `id` (INTEGER PRIMARY KEY), `version` (TEXT UNIQUE), `text` (TEXT), `hash` (TEXT), `is_active` (INTEGER), `created_at` (TIMESTAMP).
3. **`purposes`**:
   * `id` (TEXT PRIMARY KEY), `name` (TEXT), `description` (TEXT), `allowed_fields` (JSON TEXT), `mock_data` (JSON TEXT), `created_at` (TIMESTAMP).
4. **`consents`**:
   * `id` (INTEGER PRIMARY KEY), `user_id` (FOREIGN KEY -> `users.id`), `purpose` (FOREIGN KEY -> `purposes.id`), `granted` (INTEGER 0/1), `notice_version` (TEXT), `notice_hash` (TEXT), `created_at` (TIMESTAMP), `updated_at` (TIMESTAMP), `withdrawn_at` (TIMESTAMP).
   * Unique constraint: `UNIQUE (user_id, purpose)`.
5. **`consumers`**:
   * `id` (INTEGER PRIMARY KEY), `consumer_id` (TEXT UNIQUE), `name` (TEXT), `api_key_hash` (TEXT), `allowed_purposes` (JSON TEXT), `is_active` (INTEGER 0/1), `created_at` (TIMESTAMP).
6. **`audit_events`** *(Immutable Cryptographic Ledger)*:
   * `id` (INTEGER PRIMARY KEY AUTOINCREMENT), `user_id` (TEXT), `consumer_id` (TEXT), `purpose` (TEXT), `action` (TEXT), `http_status` (INTEGER), `reason_code` (TEXT), `notice_version` (TEXT), `notice_hash` (TEXT), `short_notice_hash` (TEXT), `source` (TEXT), `prev_hash` (TEXT 64 chars), `row_hash` (TEXT 64 chars), `details` (TEXT), `created_at` (TIMESTAMP).

---

## 🔑 Authentication Architecture

ConsentGuard provides production-grade, offline authentication:

### 1. Password Security
* User passwords are encrypted using **PBKDF2 with SHA-256** and high-iteration salting via `werkzeug.security.generate_password_hash`. Raw passwords are never stored in memory or on disk.

### 2. Cryptographically Signed Bearer Tokens
* Upon successful login (`POST /api/auth/login` or `/api/auth/demo-login`), the server generates a cryptographically signed timed token prefixed with `cg_tok_`.
* **Signing Mechanism:** Tokens are serialized using `itsdangerous.URLSafeTimedSerializer` with an enterprise HMAC secret and specific salt (`TOKEN_SALT = "cg_auth_token_salt"`).
* **Expiration & Revocation:** Configured via `TOKEN_MAX_AGE_SECONDS` (default: 86,400 seconds / 24 hours). Expired tokens are rejected with HTTP 401 `TOKEN_EXPIRED`.
* **Tamper Rejection:** Any signature alteration triggers `BadSignature` and is rejected with HTTP 401 `INVALID_TOKEN`.
* **Backward Compatibility:** Seamlessly supports legacy raw user IDs for automated testing fixtures.

### 3. Session Management
* Secure cookie sessions configured with `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="Lax"`, and permanent session expiration.

---

## 🛡️ Authorization & Access Control

Access control is enforced at three distinct administrative and tenant boundaries:

### 1. Role-Based Access Control (RBAC)
* **Standard Registered Users:** Allowed only to view and modify their own consents, review their personal audit trails, and access simulator tools for their identity.
* **Security Administrators (`is_admin = 1`):** Authorized to bump privacy notices, reset notices, register new downstream consumers, and revoke consumer API keys.
* **Constant-Time Administrative Key:** Administrative API endpoints enforce constant-time string comparison (`hmac.compare_digest`) on `X-Admin-Key` to eliminate side-channel timing attacks.

### 2. Cross-User Isolation Boundary (`resolve_subject`)
* When an authenticated user submits a request, `resolve_subject` strictly verifies that `req_user == auth_user['id']`.
* If a client attempts to supply another user's ID in the query string or JSON payload, the backend blocks the cross-account snooping attempt immediately:
  ```json
  {
    "error": "Forbidden: Cannot access or modify data for another user.",
    "reason_code": "FORBIDDEN_CROSS_USER_ACCESS"
  }
  ```
  *(HTTP 403 Forbidden)*

---

## 🔄 Consent Lifecycle Protocol

Consent decisions follow an auditable state machine with timestamp preservation:

```
    ┌──────────────┐
    │  No Consent  │
    └──────┬───────┘
           │  Grant Decision (Notice v1.0)
           ▼
    ┌──────────────┐
    │    ACTIVE    │◄─────────────────────────────┐
    │ (granted=1)  │                              │ Re-Consent
    └──────┬───────┘                              │ (Active Notice)
           │                                      │
           ├───────────────────┐                  │
           │ Withdraw Decision │ Notice Bumps     │
           ▼                   ▼ to v2.0          │
    ┌──────────────┐    ┌──────────────┐          │
    │  WITHDRAWN   │    │    STALE     ├──────────┘
    │ (granted=0)  │    │(needs_recons)│
    └──────────────┘    └──────────────┘
```

1. **Grant Decision (`action = "grant"`):**
   * Sets `granted = 1`, records `created_at` and `updated_at` (canonical UTC ISO 8601).
   * Binds the consent decision to the currently active notice version (`notice_version`) and its deterministic SHA-256 hash (`notice_hash`).
   * Appends a `consent_granted` audit event to the Merkle DAG ledger.
2. **Withdrawal Decision (`action = "withdraw"`):**
   * Sets `granted = 0` and preserves `created_at` while updating `updated_at` and `withdrawn_at`.
   * **Idempotency:** Re-withdrawing an already withdrawn consent returns HTTP 200/201 without polluting the ledger with redundant records.
   * Immediately terminates downstream access at the PEP.
3. **Stale Consent Handling:**
   * When an administrator updates the privacy notice, pre-existing consents are flagged as stale (`needs_reconsent = True`).
   * The Policy Enforcement Point blocks all downstream sharing until the user grants fresh consent under the active notice.

---

## 📜 Privacy Notice Management & Versioning

Privacy notices are first-class, versioned entities in ConsentGuard:

### 1. Deterministic Notice Hashing
The notice hash is calculated strictly from the notice text:
$$\text{notice\_hash} = \text{SHA-256}(\text{notice\_text})$$
Any alteration to disclosures, terms, or third-party sharing agreements changes the 64-character hexadecimal digest deterministically.

### 2. Atomic Publishing (`POST /api/notice/update`)
* Updates are executed within a database transaction:
  * Prior active notice is set to `is_active = 0`.
  * New notice version is inserted or updated with `is_active = 1`.
* **Conflict Prevention:** If a notice version already exists with different text/hash, the backend rejects the overwrite with HTTP 409 `VERSION_EXISTS` to preserve historical integrity.
* **Audit Recording:** Appends a `notice_update` audit event containing the version bump and hash.

---

## 🌳 Merkle DAG & Tamper-Evident Audit Ledger

ConsentGuard implements a cryptographic **Merkle Directed Acyclic Graph (DAG)** audit system:

### 1. Canonical JSON Serialization (RFC 8785)
To prevent hash mismatches caused by key reordering or whitespace discrepancies, payloads are serialized using strict canonical JSON:
```python
canonical_bytes = json.dumps(
    payload,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False
).encode("utf-8")
```

### 2. SHA-256 Hash Chaining
Each audit row computes its cryptographic self-hash from its payload and its parent's hash:
$$\text{row\_hash} = \text{SHA-256}(\text{prev\_hash} \,\|\, \text{user\_id} \,\|\, \text{purpose} \,\|\, \text{action} \,\|\, \text{http\_status} \,\|\, \text{reason\_code} \,\|\, \text{details} \,\|\, \dots)$$
* **Genesis Anchor:** The first record in the chain references `GENESIS_PREV_HASH` (`"0" * 64`).
* **Multi-Parent Branch Support:** High-throughput concurrent worker threads can legitimately produce sibling records sharing the same `prev_hash`. The verification algorithm validates branches as legitimate Merkle DAG forks while enforcing strict cryptographic hash validity on every node.

### 3. Database Engine Immutability Triggers
Even if an attacker gains direct SQL access, SQLite database triggers reject updates and deletions:
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

---

## 🔍 Audit Verification Engine

The audit verification engine (`database.verify_audit_chain` and `GET /api/audit/verify`) performs a rigorous forensic scan across all audit records:

### Verification Assertions:
1. **Self-Hash Verification:** Re-computes the canonical SHA-256 hash for every row. If any field was modified, flags `ROW_HASH_TAMPERED`.
2. **Genesis Verification:** Validates that root records link to `GENESIS_PREV_HASH`.
3. **Ancestor Reference Check:** Confirms that every `prev_hash` exists as a valid record in the ledger. Flags `BROKEN_ANCESTOR_LINK` if a parent is missing.
4. **Branch Analysis:** Accurately counts valid DAG branches without misinterpreting same-millisecond timestamps as corruption.

### Verification Response Schema:
```json
{
  "status": "intact",
  "total_records": 1731,
  "valid_records": 1731,
  "invalid_records": 0,
  "broken_references": 0,
  "detected_tampering": false,
  "branches_count": 0,
  "tampered_records": [],
  "error_details": []
}
```
*(Returns `HTTP 200` when intact, `HTTP 409` if tampering or broken links are detected).*

---

## 🤝 Purpose-Based Data Sharing & PEP Authorization

Downstream consumer authorization is centralized at the **Policy Enforcement Point (PEP)** via `POST /api/share/request`.

### 8-Step Authorization Pipeline:
1. **API Key Validity Check:** Verifies consumer API key against hashed values in `consumers`. Invalid key $\rightarrow$ `HTTP 401 INVALID_API_KEY`.
2. **Consumer Revocation Status:** Checks `is_active == 1`. Revoked consumer $\rightarrow$ `HTTP 401 API_KEY_REVOKED`.
3. **Consumer Purpose Authorization:** Verifies that requested purpose is within consumer's `allowed_purposes`. Out-of-scope $\rightarrow$ `HTTP 403 CONSUMER_NOT_AUTHORIZED`.
4. **Purpose Validity:** Confirms purpose exists in `purposes` table. Invalid $\rightarrow$ `HTTP 400 INVALID_PURPOSE`.
5. **Subject Existence:** Confirms user exists in database. Missing $\rightarrow$ `HTTP 404 USER_NOT_FOUND`.
6. **Active Consent Verification:** Checks `consents` table for `granted == 1`.
   * Never consented $\rightarrow$ `HTTP 403 NO_CONSENT`
   * Withdrawn $\rightarrow$ `HTTP 403 WITHDRAWN`
7. **Notice Version Freshness:** Confirms consent was granted under active notice version and hash. Stale consent $\rightarrow$ `HTTP 403 NOTICE_OUTDATED_RECONSENT_REQUIRED`.
8. **Field Minimization & Data Release:** Compares `requested_fields` against allowed fields for the purpose. Unauthorized fields $\rightarrow$ `HTTP 403 UNAUTHORIZED_FIELDS`. Valid request $\rightarrow$ `HTTP 200` returning only permitted data.

---

## 🛡️ Cybersecurity Protections & Controls

| Threat / Vulnerability | Mitigation Implemented | Implementation Detail |
| :--- | :--- | :--- |
| **SQL Injection (SQLi)** | 100% Parameterized Queries | All database operations use `?` parameter substitution; zero string concatenation. |
| **Tampering with Audit Logs** | SQLite Database Triggers | `trg_prevent_audit_update` and `trg_prevent_audit_delete` abort direct mutations. |
| **Denial of Service (DoS)** | 2MB Payload Limit | `app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024` rejects oversized bodies (`HTTP 413`). |
| **Brute Force / Flooding** | In-Memory Sliding-Window Limiter | `InMemoryRateLimiter` restricts auth endpoints to 40 req/min and general API to 600 req/min (`HTTP 429`). |
| **Crash via Malformed JSON** | Safe Dictionary Extractor | `get_request_json()` safely parses lists, strings, and primitives without `AttributeError`. |
| **Cross-Origin Attacks** | CORS Regex Allow-List | Explicit origin filtering for `localhost`, `127.0.0.1`, and authorized frontend domains. |
| **Credential / Token Leakage** | Automated Redaction | `sanitize_audit_details` strips email addresses, Bearer tokens, and API keys before logging. |
| **Information Disclosure** | Fail-Closed Error Handlers | Database errors return sanitized 503 `DATABASE_UNAVAILABLE` with zero stack traces or credentials. |
| **Clickjacking / MIME Sniffing**| OWASP Security Headers | Injected on every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`. |
| **Side-Channel Timing Attacks**| Constant-Time Comparisons | `hmac.compare_digest` used for all administrative key and API key checks. |

---

## 🎯 Step-by-Step Live Cybersecurity Demonstration

ConsentGuard includes an automated, self-contained demonstration script [`demo_live_security.py`](file:///d:/CONSENT/ConsentGuard/demo_live_security.py) that proves all security controls in an isolated sandbox database:

```bash
python demo_live_security.py
```

### 6 Attack Scenarios Demonstrated:
1. **Scenario 1: Unauthorized Access Attempt**
   * Attempts unauthenticated access to `/api/consents` $\rightarrow$ Rejected with `HTTP 401 UNAUTHENTICATED`.
   * Submits forged Bearer token $\rightarrow$ Rejected with `HTTP 401 INVALID_TOKEN`.
   * Non-admin user attempts notice update $\rightarrow$ Rejected with `HTTP 403 ADMIN_PRIVILEGES_REQUIRED`.
2. **Scenario 2: Purpose Scope Violation**
   * `partner-limited` (authorized strictly for Analytics) requests Marketing data $\rightarrow$ Blocked with `HTTP 403 CONSUMER_NOT_AUTHORIZED`.
3. **Scenario 3: Consent Withdrawal Lifecycle**
   * User grants consent $\rightarrow$ Consumer access allowed (`HTTP 200`).
   * User revokes consent $\rightarrow$ Repeated consumer request immediately blocked (`HTTP 403 WITHDRAWN`).
4. **Scenario 4: Notice Version Change Protocol**
   * User consents under Notice v1.0 $\rightarrow$ Administrator updates notice to v2.0.
   * Consumer repeats request $\rightarrow$ Blocked with `HTTP 403 NOTICE_OUTDATED_RECONSENT_REQUIRED`.
5. **Scenario 5: Merkle DAG Tampering Detection**
   * Verifies intact DAG ledger across synthetic events.
   * Clones an isolated test database and directly modifies row payload in SQLite.
   * Forensic scanner runs again $\rightarrow$ Accurately flags `ROW_HASH_TAMPERED` at modified ID with zero damage to real history.
6. **Scenario 6: Consumer API-Key Revocation**
   * Administrator registers new research consumer $\rightarrow$ Data access succeeds (`HTTP 200`).
   * Administrator revokes consumer API key $\rightarrow$ Subsequent requests rejected with `HTTP 401 API_KEY_REVOKED`.

---

## 🧪 Automated Testing Suite (124 Tests)

ConsentGuard maintains an extensive automated test suite with **124 passing tests** across all security, consent, audit, and offline domains:

```powershell
# 1. Run all 124 pytest tests across the entire suite:
python -m pytest tests/ -v

# 2. Run dedicated Part 11 Automated Testing Suite (41 tests):
python -m pytest tests/test_part11_automated_suite.py -v

# 3. Run Enterprise Integration Suite (45 tests):
python -m pytest tests/test_enterprise_suite.py -v

# 4. Run API unit test suite (18 tests):
python backend/test_api.py

# 5. Inspect cryptographic ledger integrity (1,731 records):
python backend/reconcile_audit_ledger.py --inspect
```

### Test Suite Summary:
* **Part 11 Suite (`test_part11_automated_suite.py`):** 41 tests (100% pass)
* **Enterprise Suite (`test_enterprise_suite.py`):** 45 tests (100% pass)
* **Domain Test Suites (`test_audit_chain.py`, `test_auth_and_isolation.py`, `test_consent.py`):** 38 tests (100% pass)
* **Total Pytest Count:** **124 Passed | 0 Failed**

---

## 📡 Comprehensive API Endpoint Documentation

| Method | Endpoint Path | Auth Required | Request Body / Query Params | Success Response | Error Codes |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `GET` | `/api/health` | None | None | `{"status": "ok", "application_status": "healthy", ...}` | `503 DATABASE_UNAVAILABLE` |
| `POST`| `/api/auth/signup` | None | `{"name": "...", "email": "...", "password": "..."}` | `{"success": true, "token": "cg_tok_...", "user": {...}}` | `400 INVALID_EMAIL`, `400 WEAK_PASSWORD`, `409 USER_EXISTS` |
| `POST`| `/api/auth/login` | None | `{"email": "...", "password": "..."}` | `{"success": true, "token": "cg_tok_...", "user": {...}}` | `400 MISSING_CREDENTIALS`, `401 INVALID_CREDENTIALS` |
| `POST`| `/api/auth/demo-login` | None | `{"user_id": "demo-user"}` | `{"success": true, "token": "cg_tok_...", "user": {...}}` | `400 INVALID_DEMO_USER` |
| `POST`| `/api/auth/logout` | Session / Token | None | `{"success": true, "message": "Logged out successfully."}` | None |
| `GET` | `/api/auth/me` | Session / Token | None | `{"authenticated": true, "user": {...}}` | `401 INVALID_TOKEN`, `401 TOKEN_EXPIRED` |
| `GET` | `/api/consents` | Bearer Token | `user_id` (optional in test mode) | `[{"purpose": "Analytics", "granted": 1, ...}]` | `401 UNAUTHENTICATED`, `403 FORBIDDEN_CROSS_USER_ACCESS` |
| `POST`| `/api/consents` | Bearer Token | `{"purpose": "...", "action": "grant\|withdraw\|deny"}` | `{"granted": true/false, "purpose": "...", ...}` | `400 INVALID_PURPOSE`, `400 INVALID_ACTION`, `409 STALE_NOTICE` |
| `GET` | `/api/consent/status` | Bearer Token | `purpose` (optional) | `{"user_id": "...", "status": "active", ...}` | `400 INVALID_PURPOSE`, `401 UNAUTHENTICATED` |
| `GET` | `/api/consent/history` | Bearer Token | `limit` (int, 1-1000) | `[{"action": "grant", "timestamp": "...", ...}]` | `401 UNAUTHENTICATED` |
| `GET` | `/api/stats` | None / User | `user_id` (optional) | `{"active_consents": 1, "allowed_requests": 5, ...}` | None |
| `GET` | `/api/access-logs` | Session / Token | `limit` (int, 1-1000) | `[{"consumer_id": "partner-all", "allowed": true, ...}]`| `401 UNAUTHENTICATED` |
| `GET` | `/api/notice` | None | None | `{"notice_version": "1.0", "notice_hash": "...", ...}` | None |
| `POST`| `/api/notice/update` | `X-Admin-Key` | `{"notice_version": "2.0", "notice_text": "..."}` | `{"notice_version": "2.0", "notice_hash": "...", ...}` | `401 ADMIN_AUTH_REQUIRED`, `403 ADMIN_PRIVILEGES_REQUIRED`, `409 VERSION_EXISTS` |
| `POST`| `/api/notice/reset` | `X-Admin-Key` | `{"source": "admin"}` | `{"notice_version": "1.0", "notice_hash": "...", ...}` | `401 ADMIN_AUTH_REQUIRED`, `403 ADMIN_PRIVILEGES_REQUIRED` |
| `POST`| `/api/share/request` | `X-API-Key` | `{"user_id": "...", "purpose": "...", "requested_fields": [...]}` | `{"allowed": true, "data": {...}, "reason_code": "ACTIVE_CONSENT"}` | `401 INVALID_API_KEY`, `401 API_KEY_REVOKED`, `403 CONSUMER_NOT_AUTHORIZED`, `403 NO_CONSENT`, `403 WITHDRAWN`, `403 NOTICE_OUTDATED_RECONSENT_REQUIRED`, `403 UNAUTHORIZED_FIELDS` |
| `GET` | `/api/consumers` | `X-Admin-Key` | None | `[{"consumer_id": "partner-all", "is_active": 1, ...}]` | `401 ADMIN_AUTH_REQUIRED`, `403 ADMIN_PRIVILEGES_REQUIRED` |
| `POST`| `/api/consumers/create`| `X-Admin-Key` | `{"consumer_id": "...", "name": "...", "allowed_purposes": [...]}` | `{"success": true, "api_key": "key_...", ...}` | `400 MISSING_CONSUMER_ID`, `409 CONSUMER_EXISTS` |
| `POST`| `/api/consumers/revoke`| `X-Admin-Key` | `{"consumer_id": "..."}` | `{"success": true, "message": "API key revoked."}` | `400 MISSING_CONSUMER_ID`, `404 CONSUMER_NOT_FOUND` |
| `POST`| `/api/consumers/restore`| `X-Admin-Key`| `{"consumer_id": "..."}` | `{"success": true, "message": "Consumer restored."}` | `400 MISSING_CONSUMER_ID`, `404 CONSUMER_NOT_FOUND` |
| `GET` | `/api/audit` | Session / Token | `limit` (int, 1-1000) | `[{"id": 1, "action": "user_login", "row_hash": "...", ...}]`| `401 UNAUTHENTICATED` |
| `GET` | `/api/audit/verify` | None / User | `strict=true\|false` | `{"status": "intact", "valid_records": 1731, ...}` | `409 ROW_HASH_TAMPERED`, `409 BROKEN_ANCESTOR_LINK` |
| `GET` | `/api/audit/export` | Session / Token | `format=csv\|json` | CSV attachment or JSON array | `401 UNAUTHENTICATED` |

---

## 🔧 Troubleshooting Guide

### 1. Port 5001 Already in Use
* **Symptom:** `OSError: [Errno 48] Address already in use: ('0.0.0.0', 5001)`
* **Solution:**
  * **Windows:**
    ```cmd
    netstat -ano | findstr :5001
    taskkill /PID <PID_NUMBER> /F
    ```
  * **Linux / Mac:**
    ```bash
    lsof -i :5001
    kill -9 <PID_NUMBER>
    ```

### 2. Missing Python Packages
* **Symptom:** `ModuleNotFoundError: No module named 'flask'` or `'flask_cors'`
* **Solution:** Ensure virtual environment is activated, then install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

### 3. Database Locked Error on Windows
* **Symptom:** `sqlite3.OperationalError: database is locked`
* **Solution:** ConsentGuard configures `PRAGMA busy_timeout = 5000;` and WAL mode automatically. If another process crashed and left a file lock on `consentguard.db`, close existing terminal instances running python and restart `start-consentguard.bat`.

### 4. Downstream Partner Request Denied with 401
* **Symptom:** `{"allowed": false, "reason_code": "INVALID_API_KEY"}`
* **Solution:** Ensure `X-API-Key` matches the seeded keys:
  * Partner-All: `key_partner_all_enterprise`
  * Partner-Limited: `key_partner_limited_research`

---

## 🏆 Summary for Hackathon Evaluators & Judges

ConsentGuard transforms compliance from a passive legal checkbox into an **active cryptographic enforcement gate**:

1. **Active Gatekeeping:** Consumer requests are blocked at runtime by the PEP if consent is absent, revoked, or outdated.
2. **Deterministic Cryptographic Verification:** All decisions are anchored in a Merkle DAG; tampering with a single bit breaks self-hash verification.
3. **Database-Level Immutability:** Triggers prevent administrative or rogue database updates or deletions of audit history.
4. **100% Offline Operational Readiness:** Zero cloud dependencies, zero external network calls, and instant 1-click execution.
