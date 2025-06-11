import sqlite3
import json
from hashlib import sha256
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / 'scan_cache.sqlite3'


def _get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        'CREATE TABLE IF NOT EXISTS scans (hash TEXT PRIMARY KEY, result TEXT)'
    )
    return conn


def message_hash(data: bytes) -> str:
    return sha256(data).hexdigest()


def get(hash_val: str):
    conn = _get_connection()
    cur = conn.execute('SELECT result FROM scans WHERE hash=?', (hash_val,))
    row = cur.fetchone()
    conn.close()
    if row:
        return json.loads(row[0])
    return None


def set(hash_val: str, result: dict):
    conn = _get_connection()
    conn.execute(
        'INSERT OR REPLACE INTO scans (hash, result) VALUES (?, ?)',
        (hash_val, json.dumps(result)),
    )
    conn.commit()
    conn.close()


def all_results() -> list[dict]:
    """Return all cached scan results as a list of dicts."""
    conn = _get_connection()
    cur = conn.execute('SELECT result FROM scans')
    rows = [json.loads(row[0]) for row in cur.fetchall()]
    conn.close()
    return rows