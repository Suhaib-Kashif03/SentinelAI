import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.models import ScanResponse, CommandScanResponse, SecretScanResponse
from backend.secret_detector import redact_secrets


def get_database_path() -> Path:
    """
    Return the SQLite database path.
    """
    project_root = Path(__file__).resolve().parent.parent
    data_dir = project_root / "data"
    data_dir.mkdir(exist_ok=True)

    return data_dir / "sentinelai_audit.db"


def get_connection() -> sqlite3.Connection:
    """
    Create SQLite connection.
    """
    db_path = get_database_path()
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    """
    Initialize audit logging database.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            input_type TEXT NOT NULL,
            decision TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            categories TEXT NOT NULL,
            reasons TEXT NOT NULL,
            matched_rules TEXT NOT NULL,
            redacted_content TEXT NOT NULL,
            content_preview TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            command TEXT,
            detected_shell TEXT,
            command_chain_detected INTEGER DEFAULT 0
        )
        """
    )

    connection.commit()
    connection.close()


def hash_content(content: str) -> str:
    """
    Create SHA-256 hash of original content.

    This allows correlation without storing raw sensitive input.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def safe_model_dump(model: Any) -> Dict[str, Any]:
    """
    Convert Pydantic model to dictionary.
    Supports Pydantic v1 and v2.
    """
    if hasattr(model, "model_dump"):
        return model.model_dump()

    return model.dict()


def build_content_preview(redacted_content: str, max_length: int = 500) -> str:
    """
    Create short redacted preview for audit display.
    """
    if len(redacted_content) <= max_length:
        return redacted_content

    return redacted_content[:max_length] + "...[TRUNCATED]"


def extract_matched_rules(result_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract matched rules from different response types.
    """
    if "matched_rules" in result_dict:
        return result_dict.get("matched_rules", [])

    if "secrets_found" in result_dict:
        return result_dict.get("secrets_found", [])

    return []


def log_scan_event(
    original_content: str,
    scan_result: Any
) -> int:
    """
    Save a scan result into the audit database.

    Raw content is not stored directly.
    Redacted content and SHA-256 hash are stored instead.
    """
    init_db()

    result_dict = safe_model_dump(scan_result)

    input_type = result_dict.get("input_type", "unknown")
    decision = result_dict.get("decision", "UNKNOWN")
    risk_score = int(result_dict.get("risk_score", 0))

    categories = result_dict.get("categories", [])
    reasons = result_dict.get("reasons", [])
    matched_rules = extract_matched_rules(result_dict)

    if "redacted_content" in result_dict:
        redacted_content = result_dict.get("redacted_content", "")
    else:
        redacted_content = redact_secrets(original_content)

    content_preview = build_content_preview(redacted_content)
    content_hash = hash_content(original_content)

    command = result_dict.get("command")
    detected_shell = result_dict.get("detected_shell")
    command_chain_detected = bool(result_dict.get("command_chain_detected", False))

    timestamp = datetime.now(timezone.utc).isoformat()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO audit_events (
            timestamp,
            input_type,
            decision,
            risk_score,
            categories,
            reasons,
            matched_rules,
            redacted_content,
            content_preview,
            content_hash,
            command,
            detected_shell,
            command_chain_detected
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            input_type,
            decision,
            risk_score,
            json.dumps(categories),
            json.dumps(reasons),
            json.dumps(matched_rules),
            redacted_content,
            content_preview,
            content_hash,
            command,
            detected_shell,
            1 if command_chain_detected else 0
        )
    )

    event_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return int(event_id)


def parse_event_row(row: sqlite3.Row) -> Dict[str, Any]:
    """
    Convert SQLite row into API-friendly dictionary.
    """
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "input_type": row["input_type"],
        "decision": row["decision"],
        "risk_score": row["risk_score"],
        "categories": json.loads(row["categories"]),
        "reasons": json.loads(row["reasons"]),
        "matched_rules": json.loads(row["matched_rules"]),
        "redacted_content": row["redacted_content"],
        "content_preview": row["content_preview"],
        "content_hash": row["content_hash"],
        "command": row["command"],
        "detected_shell": row["detected_shell"],
        "command_chain_detected": bool(row["command_chain_detected"])
    }


def list_audit_events(
    limit: int = 50,
    decision: Optional[str] = None,
    input_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    List recent audit events.
    """
    init_db()

    limit = max(1, min(limit, 200))

    query = "SELECT * FROM audit_events"
    filters = []
    params = []

    if decision:
        filters.append("decision = ?")
        params.append(decision)

    if input_type:
        filters.append("input_type = ?")
        params.append(input_type)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(query, params)
    rows = cursor.fetchall()

    connection.close()

    return [parse_event_row(row) for row in rows]


def get_audit_event(event_id: int) -> Optional[Dict[str, Any]]:
    """
    Get a single audit event by ID.
    """
    init_db()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM audit_events WHERE id = ?",
        (event_id,)
    )

    row = cursor.fetchone()
    connection.close()

    if row is None:
        return None

    return parse_event_row(row)


def get_audit_stats() -> Dict[str, Any]:
    """
    Return summary statistics for the dashboard/API.
    """
    init_db()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) AS count FROM audit_events")
    total_events = cursor.fetchone()["count"]

    cursor.execute(
        """
        SELECT decision, COUNT(*) AS count
        FROM audit_events
        GROUP BY decision
        """
    )
    decisions = {
        row["decision"]: row["count"]
        for row in cursor.fetchall()
    }

    cursor.execute(
        """
        SELECT input_type, COUNT(*) AS count
        FROM audit_events
        GROUP BY input_type
        """
    )
    input_types = {
        row["input_type"]: row["count"]
        for row in cursor.fetchall()
    }

    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM audit_events
        WHERE risk_score >= 80
        """
    )
    high_risk_events = cursor.fetchone()["count"]

    cursor.execute(
        """
        SELECT timestamp
        FROM audit_events
        ORDER BY id DESC
        LIMIT 1
        """
    )
    latest_row = cursor.fetchone()
    latest_event_timestamp = latest_row["timestamp"] if latest_row else None

    cursor.execute("SELECT categories FROM audit_events")
    category_counts: Dict[str, int] = {}

    for row in cursor.fetchall():
        categories = json.loads(row["categories"])

        for category in categories:
            category_counts[category] = category_counts.get(category, 0) + 1

    connection.close()

    return {
        "total_events": total_events,
        "decisions": decisions,
        "input_types": input_types,
        "categories": category_counts,
        "high_risk_events": high_risk_events,
        "latest_event_timestamp": latest_event_timestamp
    }