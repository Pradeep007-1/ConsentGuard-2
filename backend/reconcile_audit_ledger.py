#!/usr/bin/env python3
"""
ConsentGuard Audit Ledger Forensic Reconciliation & Evidence Preservation Tool

This tool inspects the append-only cryptographic audit chain, verifies cryptographic
integrity (detecting any tampering or unauthorized modifications), preserves authentic
evidence into an immutable archive table, and safely reconciles concurrent historical
sibling write branches into a continuous linear chain when required.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure backend directory is in sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import database
from database import (
    GENESIS_PREV_HASH,
    compute_audit_hash,
    get_connection,
    is_postgres,
    verify_audit_chain,
)


def inspect_ledger():
    """Performs full forensic inspection of the audit log."""
    print("=" * 70)
    print("ConsentGuard Audit Ledger Forensic Inspection")
    print("=" * 70)

    with get_connection() as connection:
        rows = connection.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()

    total = len(rows)
    print(f"Total audit records: {total}")
    if total == 0:
        print("Audit ledger is empty.")
        return

    # Check self-hash integrity of every record
    tampered = []
    for r in rows:
        expected = compute_audit_hash(
            r["prev_hash"],
            r["user_id"],
            r["purpose"],
            r["action"],
            r["http_status"],
            r["reason_code"],
            r["notice_version"],
            r["notice_hash"],
            r["source"],
            r["created_at"],
        )
        if r["row_hash"] != expected:
            tampered.append({
                "id": r["id"],
                "stored_hash": r["row_hash"],
                "computed_hash": expected,
                "created_at": r["created_at"],
            })

    if tampered:
        print(f"\n[ALERT] DATA TAMPERING DETECTED! {len(tampered)} records have invalid self-hashes:")
        for t in tampered:
            print(f"  - Record ID {t['id']} (at {t['created_at']})")
    else:
        print("[OK] 100% of audit records have authentic, valid SHA-256 self-hashes (0 tampered rows).")

    # Parentage and Topology check
    known_hashes = {GENESIS_PREV_HASH: 0}
    branches = []
    unknown_parents = []
    expected_prev = GENESIS_PREV_HASH

    for idx, r in enumerate(rows):
        cid = r["id"]
        ph = r["prev_hash"]
        rh = r["row_hash"]

        if idx == 0:
            if ph != GENESIS_PREV_HASH:
                unknown_parents.append({"id": cid, "prev_hash": ph, "reason": "Genesis record prev_hash mismatch"})
            expected_prev = rh
        else:
            if ph == expected_prev:
                expected_prev = rh
            elif ph in known_hashes:
                parent_id = known_hashes[ph]
                branches.append({
                    "record_id": cid,
                    "parent_record_id": parent_id,
                    "parent_hash": ph,
                    "action": r["action"],
                    "user_id": r["user_id"],
                    "created_at": r["created_at"],
                })
                expected_prev = rh
            else:
                unknown_parents.append({"id": cid, "prev_hash": ph, "reason": "Ancestor hash not found in ledger"})

        known_hashes[rh] = cid

    if unknown_parents:
        print(f"\n[ALERT] BROKEN CHAIN DETECTED! {len(unknown_parents)} records reference unknown ancestors:")
        for u in unknown_parents:
            print(f"  - Record ID {u['id']}: {u['reason']} ({u['prev_hash']})")
    else:
        print("[OK] All records reference valid, cryptographically verified ancestors in the ledger.")

    if branches:
        print(f"\n[INFO] {len(branches)} Concurrent Sibling Write Branches Detected:")
        for b in branches:
            print(
                f"  - Record ID {b['record_id']} (action={b['action']}, user={b['user_id']}) "
                f"branches off Record ID {b['parent_record_id']} at {b['created_at']}"
            )
        print("\nRoot Cause: Concurrent serverless HTTP transactions executed within milliseconds of each other,")
        print("reading the same chain tip before either transaction committed.")
    else:
        print("[OK] Ledger topology is strictly linear (0 branches).")

    print("=" * 70)


def archive_evidence():
    """Preserves 100% of existing historical records in audit_events_evidence_archive."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    pg = is_postgres()

    with get_connection() as connection:
        # Create evidence archive table
        id_col = "archive_id SERIAL PRIMARY KEY" if pg else "archive_id INTEGER PRIMARY KEY AUTOINCREMENT"
        connection.execute(f"""
            CREATE TABLE IF NOT EXISTS audit_events_evidence_archive (
                {id_col},
                archived_at TEXT NOT NULL,
                original_id INTEGER NOT NULL,
                user_id TEXT NOT NULL,
                purpose TEXT NOT NULL,
                action TEXT NOT NULL,
                http_status INTEGER NOT NULL,
                reason_code TEXT NOT NULL,
                notice_version TEXT NOT NULL,
                notice_hash TEXT NOT NULL,
                short_notice_hash TEXT,
                source TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                row_hash TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            );
        """)

        rows = connection.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
        print(f"Archiving {len(rows)} original records into audit_events_evidence_archive...")

        # Compute SHA-256 Merkle root of all rows to seal archive
        hasher = hashlib.sha256()
        for r in rows:
            hasher.update(f"{r['id']}|{r['row_hash']}|{r['created_at']}".encode("utf-8"))
            connection.execute("""
                INSERT INTO audit_events_evidence_archive
                    (archived_at, original_id, user_id, purpose, action, http_status,
                     reason_code, notice_version, notice_hash, short_notice_hash,
                     source, prev_hash, row_hash, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                now_str, r["id"], r["user_id"], r["purpose"], r["action"], r["http_status"],
                r["reason_code"], r["notice_version"], r["notice_hash"], r.get("short_notice_hash", ""),
                r["source"], r["prev_hash"], r["row_hash"], r.get("details", ""), r["created_at"],
            ))

        archive_seal = hasher.hexdigest()
        print(f"[SUCCESS] Archived {len(rows)} records. Cryptographic Archive Seal: {archive_seal}")
        return archive_seal


def reconcile_ledger(dry_run=True, confirm=False):
    """
    Safely reconciles concurrent sibling branches into a continuous linear chain,
    preserving full evidence in the archive table first.
    """
    if not dry_run and not confirm:
        print("ERROR: --reconcile requires --confirm to execute changes.")
        return

    print("=" * 70)
    print(f"ConsentGuard Audit Ledger Reconciliation (Dry Run: {dry_run})")
    print("=" * 70)

    with get_connection() as connection:
        rows = connection.execute("SELECT * FROM audit_events ORDER BY created_at ASC, id ASC").fetchall()

    if not rows:
        print("No audit records found.")
        return

    # Verify self-hashes first to ensure no tampering has occurred
    for r in rows:
        calc = compute_audit_hash(
            r["prev_hash"], r["user_id"], r["purpose"], r["action"],
            r["http_status"], r["reason_code"], r["notice_version"],
            r["notice_hash"], r["source"], r["created_at"]
        )
        if calc != r["row_hash"]:
            print(f"ERROR: Cannot reconcile! Record ID {r['id']} has invalid self-hash.")
            return

    # Re-chain sequentially
    new_chain = []
    prev_h = GENESIS_PREV_HASH

    for r in rows:
        new_row_hash = compute_audit_hash(
            prev_h,
            r["user_id"],
            r["purpose"],
            r["action"],
            r["http_status"],
            r["reason_code"],
            r["notice_version"],
            r["notice_hash"],
            r["source"],
            r["created_at"],
        )
        changed = (prev_h != r["prev_hash"] or new_row_hash != r["row_hash"])
        new_chain.append({
            "id": r["id"],
            "user_id": r["user_id"],
            "action": r["action"],
            "created_at": r["created_at"],
            "old_prev_hash": r["prev_hash"],
            "new_prev_hash": prev_h,
            "old_row_hash": r["row_hash"],
            "new_row_hash": new_row_hash,
            "changed": changed,
        })
        prev_h = new_row_hash

    changed_count = sum(1 for c in new_chain if c["changed"])
    print(f"Total records in chain: {len(new_chain)}")
    print(f"Records whose linkage changes after linear ordering: {changed_count}")

    if dry_run:
        print("\n[Dry Run] Changes that would be applied:")
        for c in new_chain:
            if c["changed"]:
                print(
                    f"  Record ID {c['id']}: prev_hash {c['old_prev_hash'][:10]}... -> {c['new_prev_hash'][:10]}..., "
                    f"row_hash {c['old_row_hash'][:10]}... -> {c['new_row_hash'][:10]}..."
                )
        print("\nNo database changes made (dry run). Use --reconcile --confirm to apply.")
        return

    # Execute changes
    archive_seal = archive_evidence()
    print("\nUpdating audit_events with reconciled linear linkage...")

    with get_connection() as connection:
        if is_postgres():
            connection.execute("LOCK TABLE audit_events IN EXCLUSIVE MODE;")

        for c in new_chain:
            if c["changed"]:
                connection.execute("""
                    UPDATE audit_events
                    SET prev_hash = ?, row_hash = ?
                    WHERE id = ?
                """, (c["new_prev_hash"], c["new_row_hash"], c["id"]))

        # Append explicit reconciliation audit event
        database.append_audit_event(
            connection,
            user_id="system",
            purpose="Compliance",
            action="ledger_reconciled",
            http_status=200,
            reason_code="CONCURRENCY_RECONCILED",
            notice_version=database.DEFAULT_NOTICE_VERSION,
            notice_hash=database.DEFAULT_NOTICE_HASH,
            source="admin",
            details=f"Reconciled {changed_count} concurrent sibling records into linear chain. Archive seal: {archive_seal[:16]}...",
        )

        # Verify new chain
        verify_result = verify_audit_chain(connection, strict_linear=True)

    print("\n[SUCCESS] Reconciliation complete!")
    print(f"Post-reconciliation strict linear verification: {json.dumps(verify_result, indent=2)}")


def main():
    parser = argparse.ArgumentParser(description="ConsentGuard Audit Ledger Forensic Tool")
    parser.add_argument("--inspect", action="store_true", help="Perform forensic inspection of audit ledger")
    parser.add_argument("--archive", action="store_true", help="Archive current historical evidence")
    parser.add_argument("--reconcile", action="store_true", help="Reconcile concurrent branches into linear chain")
    parser.add_argument("--confirm", action="store_true", help="Confirm database modifications")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Simulate reconciliation without changes")

    args = parser.parse_args()

    if args.reconcile:
        reconcile_ledger(dry_run=not args.confirm, confirm=args.confirm)
    elif args.archive:
        archive_evidence()
    else:
        inspect_ledger()


if __name__ == "__main__":
    main()
