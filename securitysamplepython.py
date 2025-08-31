# Intentionally mixed: some functions are safe, others have common security flaws.
# Do not deploy. Use only for scanner/LLM testing.

import os
import sqlite3
import subprocess
import json
import yaml
import pickle
import requests
import hashlib
import secrets
from pathlib import Path

DB_PATH = "app.db"
UPLOADS = Path("uploads")
ALLOWED_HOSTS = {"example.com", "api.example.com"}
HARDCODED_SECRET = "supersecret"  # hardcoded secret in repo

# Small CHange to force refresh
# ---------- Database ----------

def get_user_by_id_safe(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row

def get_user_by_id_unsafe(user_id: str):
    # SQL injection via string concatenation
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT id, name FROM users WHERE id = {user_id}"
    cur.execute(query)  # untrusted input directly in SQL
    row = cur.fetchone()
    conn.close()
    return row

# Comments
# ---------- Commands ----------

def create_archive_safe(src_dir: str):
    # uses exec without shell + explicit args
    subprocess.run(["tar", "czf", "/tmp/backup.tar.gz", src_dir], check=False)

def create_archive_unsafe(src_dir: str):
    # command injection via shell=True and concatenation
    cmd = "tar czf /tmp/backup.tar.gz " + src_dir
    subprocess.run(cmd, shell=True)  # user-controlled argument

# ---------- Serialization / Parsing ----------

def parse_config_safe(yaml_text: str):
    # safe loader
    return yaml.safe_load(yaml_text)

def parse_config_unsafe(yaml_text: str):
    # arbitrary object construction on load
    return yaml.load(yaml_text, Loader=yaml.Loader)

def deserialize_safe(s: str):
    # use JSON instead of pickle
    return json.loads(s)

def deserialize_unsafe(b: bytes):
    # arbitrary code execution risk
    return pickle.loads(b)

# ---------- Filesystem ----------

def save_upload_safe(filename: str, data: bytes):
    target = (UPLOADS / Path(filename).name).resolve()
    UPLOADS.mkdir(exist_ok=True)
    # enforce directory containment
    if not str(target).startswith(str(UPLOADS.resolve())):
        raise ValueError("invalid path")
    with open(target, "wb") as f:
        f.write(data)

def save_upload_unsafe(filename: str, data: bytes):
    # path traversal via "../../../etc/passwd" etc.
    with open(UPLOADS / filename, "wb") as f:
        f.write(data)

# ---------- Networking ----------

def fetch_metadata_safe(url: str):
    # allowlist basic check to mitigate SSRF
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ValueError("disallowed host")
    return requests.get(url, timeout=3).text

def fetch_metadata_unsafe(url: str):
    # SSRF: fetch arbitrary URLs including internal endpoints
    return requests.get(url, timeout=3).text

# ---------- Crypto / tokens ----------

def token_safe() -> str:
    return secrets.token_urlsafe(32)

def token_unsafe(username: str) -> str:
    # predictable token derived from username (and hardcoded secret)
    return hashlib.md5((username + HARDCODED_SECRET).encode()).hexdigest()

# ---------- Debug server example (doesn't run, for static scan only) ----------

def start_debug_server_unsafe():
    # exposing interactive debugger in production
    try:
        from flask import Flask
    except Exception:
        return
    app = Flask(__name__)
    app.config["SECRET_KEY"] = HARDCODED_SECRET
    app.run(host="0.0.0.0", port=5000, debug=True)
