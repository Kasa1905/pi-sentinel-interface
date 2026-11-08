"""
pi-sentinel-interface :: backend/app.py

Flask API for the Edge-Based NIDS dashboard.

Storage modes:
  * PostgreSQL (via SQLAlchemy) when the database is reachable.
  * In-memory MOCK mode automatically when PostgreSQL is not running
    (or when FORCE_MOCK=1 is set). The API behaves identically in both modes.

Environment variables (all optional):
  DATABASE_URL  SQLAlchemy URL. Default: postgresql://postgres:postgres@localhost:5432/pi_sentinel
  FORCE_MOCK    Set to "1" to skip PostgreSQL and use in-memory storage.
  PORT          Port to listen on. Default: 5000
"""

import logging
import os
import threading
from collections import Counter, deque
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import distinct, func, text

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/pi_sentinel",
)
FORCE_MOCK = os.environ.get("FORCE_MOCK", "0") == "1"
PORT = int(os.environ.get("PORT", "5000"))

ALLOWED_PROTOCOLS = ("TCP", "UDP", "ICMP", "ARP")
RECENT_LOGS_LIMIT = 25
MOCK_BUFFER_SIZE = 5000
NODE_ONLINE_WINDOW_SECONDS = 10
MAX_BATCH_SIZE = 5000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("pi-sentinel")

# --------------------------------------------------------------------------- #
# App + DB setup
# --------------------------------------------------------------------------- #
app = Flask(__name__)
CORS(app)  # Allow the dashboard (file:// or other origin) to call the API.

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "connect_args": {"connect_timeout": 3},
}

db = SQLAlchemy(app)


class PacketLog(db.Model):
    __tablename__ = "packet_logs"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), nullable=False)
    protocol = db.Column(db.String(8), nullable=False, index=True)
    packet_size = db.Column(db.Integer, nullable=False)


# --------------------------------------------------------------------------- #
# Storage layer (PostgreSQL or in-memory mock)
# --------------------------------------------------------------------------- #
USE_DB = False
_state_lock = threading.Lock()
_last_ingest_at = None  # datetime (UTC) of the last successful ingest

# Mock-mode storage
_mock_logs = deque(maxlen=MOCK_BUFFER_SIZE)
_mock_total = 0
_mock_sources = set()
_mock_protocols = Counter()


def init_storage():
    """Try PostgreSQL. Fall back to in-memory mock mode on any failure."""
    global USE_DB

    if FORCE_MOCK:
        USE_DB = False
        log.warning("FORCE_MOCK=1 -> running in in-memory MOCK mode.")
        return

    try:
        with app.app_context():
            db.session.execute(text("SELECT 1"))
            db.create_all()
        USE_DB = True
        log.info("Connected to PostgreSQL. Persistent storage enabled.")
    except Exception as exc:  # noqa: BLE001 - any connection problem -> fallback
        USE_DB = False
        log.warning(
            "PostgreSQL unavailable (%s). Falling back to in-memory MOCK mode.",
            exc.__class__.__name__,
        )


def storage_mode():
    return "postgresql" if USE_DB else "mock-memory"


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_iso(dt):
    return dt.replace(microsecond=0).isoformat() + "Z"


def parse_timestamp(value):
    """Accept ISO-8601 strings (with or without Z/offset) or epoch seconds."""
    if value is None or value == "":
        return utcnow()
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
        text_value = str(value).strip()
        if text_value.endswith("Z"):
            text_value = text_value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text_value)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def validate_packet(raw):
    """Return (clean_dict, None) on success or (None, error_message)."""
    if not isinstance(raw, dict):
        return None, "packet must be a JSON object"

    source_ip = str(raw.get("source_ip", "")).strip()
    destination_ip = str(raw.get("destination_ip", "")).strip()
    protocol = str(raw.get("protocol", "")).strip().upper()

    if not source_ip or not destination_ip:
        return None, "source_ip and destination_ip are required"
    if len(source_ip) > 45 or len(destination_ip) > 45:
        return None, "IP address too long"
    if protocol not in ALLOWED_PROTOCOLS:
        return None, f"protocol must be one of {', '.join(ALLOWED_PROTOCOLS)}"

    try:
        packet_size = int(raw.get("packet_size"))
    except (TypeError, ValueError):
        return None, "packet_size must be an integer"
    if packet_size < 0 or packet_size > 65535:
        return None, "packet_size out of range (0-65535)"

    timestamp = parse_timestamp(raw.get("timestamp"))
    if timestamp is None:
        return None, "timestamp is not a valid ISO-8601 string or epoch value"

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "packet_size": packet_size,
    }, None


def store_packets(packets):
    """Persist validated packets in the active storage backend."""
    global _mock_total, _last_ingest_at

    if USE_DB:
        db.session.bulk_insert_mappings(PacketLog, packets)
        db.session.commit()
    else:
        with _state_lock:
            for pkt in packets:
                _mock_logs.append(pkt)
                _mock_total += 1
                _mock_sources.add(pkt["source_ip"])
                _mock_protocols[pkt["protocol"]] += 1

    with _state_lock:
        _last_ingest_at = utcnow()


def collect_stats():
    """Return (total, unique_source_ips, unique_ips_all, protocol_counts, recent_logs)."""
    protocol_counts = {proto: 0 for proto in ALLOWED_PROTOCOLS}

    if USE_DB:
        total = db.session.query(func.count(PacketLog.id)).scalar() or 0
        unique_sources = (
            db.session.query(func.count(distinct(PacketLog.source_ip))).scalar() or 0
        )
        src_ips = {row[0] for row in db.session.query(distinct(PacketLog.source_ip)).all()}
        dst_ips = {row[0] for row in db.session.query(distinct(PacketLog.destination_ip)).all()}
        unique_all = len(src_ips | dst_ips)

        for proto, count in (
            db.session.query(PacketLog.protocol, func.count(PacketLog.id))
            .group_by(PacketLog.protocol)
            .all()
        ):
            if proto in protocol_counts:
                protocol_counts[proto] = int(count)

        rows = (
            db.session.query(PacketLog)
            .order_by(PacketLog.id.desc())
            .limit(RECENT_LOGS_LIMIT)
            .all()
        )
        recent = [
            {
                "id": row.id,
                "timestamp": to_iso(row.timestamp),
                "source_ip": row.source_ip,
                "destination_ip": row.destination_ip,
                "protocol": row.protocol,
                "packet_size": row.packet_size,
            }
            for row in rows
        ]
        return int(total), int(unique_sources), unique_all, protocol_counts, recent

    with _state_lock:
        total = _mock_total
        unique_sources = len(_mock_sources)
        buffer_copy = list(_mock_logs)
        for proto in ALLOWED_PROTOCOLS:
            protocol_counts[proto] = int(_mock_protocols.get(proto, 0))

    all_ips = set(_mock_sources)
    for pkt in buffer_copy:
        all_ips.add(pkt["destination_ip"])

    newest_first = buffer_copy[-RECENT_LOGS_LIMIT:][::-1]
    start_id = total
    recent = []
    for offset, pkt in enumerate(newest_first):
        recent.append(
            {
                "id": start_id - offset,
                "timestamp": to_iso(pkt["timestamp"]),
                "source_ip": pkt["source_ip"],
                "destination_ip": pkt["destination_ip"],
                "protocol": pkt["protocol"],
                "packet_size": pkt["packet_size"],
            }
        )
    return total, unique_sources, len(all_ips), protocol_counts, recent


def node_status():
    with _state_lock:
        last = _last_ingest_at
    if last is None:
        return "Awaiting Data", None
    age = utcnow() - last
    if age <= timedelta(seconds=NODE_ONLINE_WINDOW_SECONDS):
        return "Online", to_iso(last)
    return "Offline", to_iso(last)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/api/v1/logs", methods=["POST"])
def ingest_logs():
    """
    Ingest batched packet metadata.

    Accepted body shapes:
      [ {packet}, {packet}, ... ]
      { "node_id": "...", "logs": [ {packet}, ... ] }
      { "packets": [ {packet}, ... ] }
    Each packet: timestamp, source_ip, destination_ip, protocol, packet_size.
    """
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    if isinstance(payload, list):
        batch = payload
    elif isinstance(payload, dict):
        batch = payload.get("logs", payload.get("packets"))
    else:
        batch = None

    if not isinstance(batch, list):
        return jsonify({"error": "Expected a list of packets, or an object with a 'logs' list"}), 400
    if len(batch) == 0:
        return jsonify({"error": "Batch is empty"}), 400
    if len(batch) > MAX_BATCH_SIZE:
        return jsonify({"error": f"Batch too large (max {MAX_BATCH_SIZE})"}), 413

    valid_packets = []
    errors = []
    for index, raw in enumerate(batch):
        clean, error = validate_packet(raw)
        if error:
            errors.append({"index": index, "error": error})
        else:
            valid_packets.append(clean)

    if not valid_packets:
        return jsonify({"accepted": 0, "rejected": len(errors), "errors": errors[:10]}), 422

    try:
        store_packets(valid_packets)
    except Exception as exc:  # noqa: BLE001
        if USE_DB:
            db.session.rollback()
        log.exception("Failed to store packets")
        return jsonify({"error": f"Storage failure: {exc.__class__.__name__}"}), 500

    return (
        jsonify(
            {
                "accepted": len(valid_packets),
                "rejected": len(errors),
                "errors": errors[:10],
                "storage_mode": storage_mode(),
            }
        ),
        201,
    )


@app.route("/api/v1/dashboard-stats", methods=["GET"])
def dashboard_stats():
    """Aggregate stats + most recent logs, designed for 2-second polling."""
    try:
        total, unique_sources, unique_all, protocol_counts, recent = collect_stats()
    except Exception as exc:  # noqa: BLE001
        if USE_DB:
            db.session.rollback()
        log.exception("Failed to collect stats")
        return jsonify({"error": f"Stats failure: {exc.__class__.__name__}"}), 500

    status, last_seen = node_status()

    return jsonify(
        {
            "total_packets": total,
            "unique_ips": unique_sources,
            "unique_ips_all": unique_all,
            "protocol_distribution": protocol_counts,
            "recent_logs": recent,
            "node_status": status,
            "last_ingest_at": last_seen,
            "storage_mode": storage_mode(),
            "server_time": to_iso(utcnow()),
        }
    )


@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "storage_mode": storage_mode()})


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
init_storage()

if __name__ == "__main__":
    log.info("Starting pi-sentinel backend on http://0.0.0.0:%d (storage: %s)", PORT, storage_mode())
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
