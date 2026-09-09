import hashlib
import argparse
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, make_response, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash


DATA_DIR = Path(os.environ.get("CTIA_DATA_DIR", "/data"))
DATABASE = DATA_DIR / "ctia-pilot.db"
COOKIE_NAME = "ctia_session"
SESSION_SECONDS = 8 * 60 * 60
RATE_WINDOW_SECONDS = 60
MAX_FAILED_ATTEMPTS = 5
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("CTIA_SECRET_KEY", secrets.token_hex(32)),
    MAX_CONTENT_LENGTH=64 * 1024,
)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect_database():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def get_db():
    if "db" not in g:
        g.db = connect_database()
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def initialize_database():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with connect_database() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
                must_change_password INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS failed_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                client_address TEXT NOT NULL,
                attempted_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS device_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                device_name TEXT NOT NULL,
                normal_operation INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            """
        )
        if db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None:
            reset_device(db)


def reset_device(db):
    now = utc_now()
    db.execute("DELETE FROM sessions")
    db.execute("DELETE FROM failed_logins")
    db.execute("DELETE FROM users")
    db.execute("DELETE FROM device_state")
    db.execute(
        """INSERT INTO users
           (username, password_hash, role, must_change_password, enabled, created_at, updated_at)
           VALUES (?, ?, 'admin', 1, 1, ?, ?)""",
        (DEFAULT_USERNAME, generate_password_hash(DEFAULT_PASSWORD), now, now),
    )
    db.execute(
        "INSERT INTO device_state (singleton, device_name, normal_operation, updated_at) VALUES (1, ?, 0, ?)",
        ("CTIA Password Pilot", now),
    )
    db.commit()


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(db, user_id):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (token_digest(token), user_id, secrets.token_urlsafe(24), now, now + SESSION_SECONDS),
    )
    db.commit()
    return token


def delete_current_session(db):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),))
        db.commit()


def load_current_user():
    g.user = None
    g.auth_session = None
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return
    now = int(time.time())
    db = get_db()
    db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    row = db.execute(
        """SELECT s.token_hash, s.csrf_token, s.expires_at,
                  u.id, u.username, u.role, u.must_change_password, u.enabled
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ? AND s.expires_at > ?""",
        (token_digest(token), now),
    ).fetchone()
    db.commit()
    if row and row["enabled"]:
        g.auth_session = row
        g.user = row


@app.before_request
def enforce_session_and_provisioning():
    load_current_user()
    if g.user and g.user["must_change_password"]:
        allowed = {"change_password", "logout", "healthz", "static"}
        if request.endpoint not in allowed:
            flash("Change the shared default password before normal operation.", "warning")
            return redirect(url_for("change_password"))


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def require_csrf():
    supplied = request.form.get("csrf_token", "")
    expected = g.auth_session["csrf_token"] if g.auth_session else ""
    if not expected or not secrets.compare_digest(supplied, expected):
        abort(400, "Invalid CSRF token")


def validate_password(password):
    problems = []
    if len(password) < 8:
        problems.append("Password must contain at least 8 characters.")
    if password == DEFAULT_PASSWORD:
        problems.append("Password cannot be the shared default value.")
    lowered = password.lower()
    if any(lowered[index] == lowered[index + 1] == lowered[index + 2] for index in range(max(0, len(lowered) - 2))):
        problems.append("Password cannot contain more than 2 repetitive characters.")
    for index in range(max(0, len(lowered) - 2)):
        values = [ord(char) for char in lowered[index : index + 3]]
        if all(char.isalpha() for char in lowered[index : index + 3]) or all(char.isdigit() for char in lowered[index : index + 3]):
            if values[1] - values[0] == values[2] - values[1] and abs(values[1] - values[0]) == 1:
                problems.append("Password cannot contain more than 2 sequential characters.")
                break
    return problems


def client_address():
    return request.remote_addr or "unknown"


def rate_limit_status(db, username):
    cutoff = int(time.time()) - RATE_WINDOW_SECONDS
    address = client_address()
    db.execute("DELETE FROM failed_logins WHERE attempted_at < ?", (cutoff,))
    count = db.execute(
        "SELECT COUNT(*) FROM failed_logins WHERE username = ? AND client_address = ? AND attempted_at >= ?",
        (username, address, cutoff),
    ).fetchone()[0]
    db.commit()
    return count >= MAX_FAILED_ATTEMPTS


@app.context_processor
def shared_template_context():
    return {
        "current_user": getattr(g, "user", None),
        "csrf_token": g.auth_session["csrf_token"] if getattr(g, "auth_session", None) else "",
    }


@app.get("/healthz")
def healthz():
    return {"status": "ok", "profile": "CTIA 3.2.1"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        if rate_limit_status(db, username):
            response = make_response(render_template("login.html", rate_limited=True), 429)
            response.headers["Retry-After"] = str(RATE_WINDOW_SECONDS)
            return response
        user = db.execute("SELECT * FROM users WHERE username = ? AND enabled = 1", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            db.execute(
                "INSERT INTO failed_logins (username, client_address, attempted_at) VALUES (?, ?, ?)",
                (username, client_address(), int(time.time())),
            )
            db.commit()
            flash("Invalid username or password.", "error")
            return render_template("login.html"), 401
        db.execute("DELETE FROM failed_logins WHERE username = ? AND client_address = ?", (username, client_address()))
        db.commit()
        token = create_session(db, user["id"])
        destination = url_for("change_password") if user["must_change_password"] else url_for("index")
        response = make_response(redirect(destination))
        response.set_cookie(
            COOKIE_NAME,
            token,
            max_age=SESSION_SECONDS,
            httponly=True,
            secure=os.environ.get("CTIA_COOKIE_SECURE", "false").lower() == "true",
            samesite="Strict",
        )
        return response
    return render_template("login.html", rate_limited=False)


@app.post("/logout")
@login_required
def logout():
    require_csrf()
    delete_current_session(get_db())
    response = make_response(redirect(url_for("login")))
    response.delete_cookie(COOKIE_NAME)
    return response


@app.get("/")
@login_required
def index():
    state = get_db().execute("SELECT * FROM device_state WHERE singleton = 1").fetchone()
    return render_template("index.html", state=state)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        require_csrf()
        current = request.form.get("current_password", "")
        password = request.form.get("new_password", "")
        confirmation = request.form.get("confirm_password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()
        problems = validate_password(password)
        if not check_password_hash(user["password_hash"], current):
            problems.insert(0, "Current password is incorrect.")
        if password != confirmation:
            problems.append("New password and confirmation do not match.")
        if problems:
            for problem in problems:
                flash(problem, "error")
            return render_template("change_password.html"), 400
        now = utc_now()
        db.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = ? WHERE id = ?",
            (generate_password_hash(password), now, user["id"]),
        )
        if user["role"] == "admin":
            db.execute("UPDATE device_state SET normal_operation = 1, updated_at = ? WHERE singleton = 1", (now,))
        db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?", (user["id"], g.auth_session["token_hash"]))
        db.commit()
        flash("Password changed. The shared default is no longer valid.", "success")
        return redirect(url_for("index"))
    return render_template("change_password.html")


@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    db = get_db()
    if request.method == "POST":
        require_csrf()
        username = request.form.get("username", "").strip()
        role = request.form.get("role", "operator")
        password = request.form.get("password", "")
        problems = validate_password(password)
        if not username or len(username) > 40 or not username.replace("_", "").replace("-", "").isalnum():
            problems.append("Username must be 1-40 letters, numbers, underscores, or hyphens.")
        if role not in {"admin", "operator"}:
            problems.append("Invalid role.")
        if problems:
            for problem in problems:
                flash(problem, "error")
        else:
            try:
                now = utc_now()
                db.execute(
                    """INSERT INTO users
                       (username, password_hash, role, must_change_password, enabled, created_at, updated_at)
                       VALUES (?, ?, ?, 0, 1, ?, ?)""",
                    (username, generate_password_hash(password), role, now, now),
                )
                db.commit()
                flash(f"User {username} created. Existing password values remain unreadable.", "success")
                return redirect(url_for("users"))
            except sqlite3.IntegrityError:
                flash("That username already exists.", "error")
    rows = db.execute("SELECT id, username, role, enabled, created_at FROM users ORDER BY id").fetchall()
    return render_template("users.html", users=rows)


@app.route("/device", methods=["GET", "POST"])
@admin_required
def device():
    db = get_db()
    if request.method == "POST":
        require_csrf()
        name = request.form.get("device_name", "").strip()
        if not name or len(name) > 80:
            flash("Device name must contain 1-80 characters.", "error")
        else:
            db.execute("UPDATE device_state SET device_name = ?, updated_at = ? WHERE singleton = 1", (name, utc_now()))
            db.commit()
            flash("Privileged device configuration updated.", "success")
            return redirect(url_for("device"))
    state = db.execute("SELECT * FROM device_state WHERE singleton = 1").fetchone()
    return render_template("device.html", state=state)


@app.post("/factory-reset")
@admin_required
def factory_reset():
    require_csrf()
    db = get_db()
    reset_device(db)
    response = make_response(redirect(url_for("login")))
    response.delete_cookie(COOKIE_NAME)
    return response


initialize_database()


def command_line(argv=None):
    parser = argparse.ArgumentParser(description="CTIA Section 3.2.1 password pilot")
    parser.add_argument(
        "--factory-reset",
        action="store_true",
        help="reset users, sessions, and device configuration without Web UI authentication",
    )
    args = parser.parse_args(argv)
    if args.factory_reset:
        with app.app_context():
            reset_device(get_db())
        print("Factory reset complete. Default credential restored to admin/admin; enrollment is required.")
        return 0
    app.run(host="0.0.0.0", port=int(os.environ.get("CTIA_PORT", "8080")))
    return 0


if __name__ == "__main__":
    raise SystemExit(command_line())
