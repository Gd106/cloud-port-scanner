"""Python-Based Cloud Port Scanner and Security Reporter - Flask application."""
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import timedelta, datetime
from functools import wraps

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import database
import report_generator
import scanner
import security_analyzer as analyzer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


def _load_secret_key():
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    os.makedirs(database.DB_DIR, exist_ok=True)
    path = os.path.join(database.DB_DIR, "secret.key")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(key)
    return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",  # set to 1 when served over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=64 * 1024,
)
os.makedirs(REPORTS_DIR, exist_ok=True)
database.init_db()

_start_lock = threading.Lock()
_DUMMY_HASH = generate_password_hash("not-a-real-password")
_failed_logins = {}          # (ip, username) -> [timestamps]
LOGIN_LIMIT, LOGIN_WINDOW = 5, 300


# ------------------------------------------------------------- helpers
def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def json_error(message, status=400):
    return jsonify(error=message), status


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            if request.path.startswith("/api/"):
                return json_error("Authentication required. Please log in again.", 401)
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def _login_locked(key):
    cutoff = time.time() - LOGIN_WINDOW
    attempts = [t for t in _failed_logins.get(key, []) if t > cutoff]
    _failed_logins[key] = attempts
    return len(attempts) >= LOGIN_LIMIT


# ---------------------------------------------------- request lifecycle
@app.before_request
def load_user_and_check_csrf():
    g.user = None
    uid = session.get("user_id")
    if uid:
        g.user = database.get_user_by_id(uid)
        if g.user is None:
            session.pop("user_id", None)

    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token") or ""
        expected = session.get("_csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            if request.path.startswith("/api/"):
                return json_error("Security token missing or expired. Reload the page and try again.", 400)
            abort(400)


@app.context_processor
def inject_user():
    return {"current_user": g.get("user")}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net data:; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    if request.path.startswith("/api/") or g.get("user"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(413)
@app.errorhandler(500)
def handle_error(err):
    code = getattr(err, "code", 500) or 500
    messages = {400: "Bad request or expired security token. Go back, reload the page and try again.",
                404: "The page or resource you requested was not found.",
                405: "That action is not allowed here.",
                413: "The request was too large.",
                500: "Something went wrong on the server."}
    if request.path.startswith("/api/"):
        return json_error(messages.get(code, "Error"), code)
    return render_template("error.html", code=code, message=messages.get(code, "Error")), code


# ------------------------------------------------------- public pages
@app.route("/")
def index():
    return render_template("index.html", active="home")


@app.route("/about")
def about():
    return render_template("about.html", active="about")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    errors, form = [], {}
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        form = {"username": username, "email": email}

        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            errors.append("Username must be 3-30 characters: letters, digits, dot, underscore or hyphen.")
        if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}", email) or len(email) > 254:
            errors.append("Enter a valid email address.")
        if len(password) < 8 or len(password) > 128 or not re.search(r"[A-Za-z]", password) \
                or not re.search(r"\d", password):
            errors.append("Password must be 8-128 characters and contain at least one letter and one digit.")
        if password != confirm:
            errors.append("Passwords do not match.")

        if not errors:
            try:
                database.create_user(username, email, generate_password_hash(password), now_iso())
            except sqlite3.IntegrityError:
                errors.append("That username or email is already registered.")
            else:
                flash("Account created successfully. Please log in.", "success")
                return redirect(url_for("login"))
    return render_template("register.html", errors=errors, form=form, active="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    error = None
    next_url = safe_next(request.values.get("next", ""))
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = (request.remote_addr, identifier.lower())
        if _login_locked(key):
            error = "Too many failed attempts. Please wait 5 minutes and try again."
            return render_template("login.html", error=error, next_url=next_url, active="login"), 429
        user = database.get_user_by_login(identifier) if identifier else None
        valid = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
        if user and valid:
            _failed_logins.pop(key, None)
            session.clear()                       # new session on login (prevents fixation)
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(next_url or url_for("dashboard"))
        _failed_logins.setdefault(key, []).append(time.time())
        error = "Invalid username or password."
    return render_template("login.html", error=error, next_url=next_url, active="login")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# --------------------------------------------------- application pages
def _scan_page(template, active, scan_id=None):
    if scan_id is None:
        scan_id = request.args.get("scan", type=int)
    if scan_id is not None and database.get_scan(g.user["id"], scan_id) is None:
        abort(404)
    return render_template(template, scan_id=scan_id, active=active)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", active="dashboard")


@app.route("/scanner")
@login_required
def scanner_page():
    return render_template("scanner.html", active="scanner",
                           max_ports=scanner.MAX_PORTS_PER_SCAN,
                           max_workers=scanner.MAX_WORKERS)


@app.route("/results")
@app.route("/results/<int:scan_id>")
@login_required
def results_page(scan_id=None):
    return _scan_page("results.html", "results", scan_id)


@app.route("/analysis")
@login_required
def analysis_page():
    return _scan_page("analysis.html", "analysis")


@app.route("/recommendations")
@login_required
def recommendations_page():
    return _scan_page("recommendations.html", "recommendations")


@app.route("/history")
@login_required
def history_page():
    return render_template("history.html", active="history")


@app.route("/reports")
@login_required
def reports_page():
    return _scan_page("reports.html", "reports")


# ---------------------------------------------------------- scan payloads
def _serialize(scan):
    scan = dict(scan)
    scan["total_requested"] = scan["end_port"] - scan["start_port"] + 1
    return scan


def _full_payload(scan_row):
    """Complete scan document (from the database) used by API, exports and PDF."""
    scan = _serialize(scan_row)
    ports = database.get_scan_ports(scan["id"])
    scan["open_ports"] = ports
    scan["recommendations"] = analyzer.generate_recommendations(ports)
    scan["summary"] = analyzer.build_summary(scan, ports)
    scan["disclaimer"] = analyzer.DISCLAIMER
    scan["progress_percent"] = 100 if scan["status"] == "completed" else (
        round(100 * scan["total_scanned"] / scan["total_requested"]) if scan["total_requested"] else 0)
    return scan


def _live_payload(scan_row, job):
    """Progress view for a scan that is still running."""
    scan = _serialize(scan_row)
    snap = job.snapshot()
    overrides = database.get_risk_overrides(job.user_id)
    ports = [analyzer.analyze_port(p["port"], overrides) for p in snap["open_ports"]]
    summary = analyzer.summarize(ports)
    scan.update({
        "status": "running",
        "total_scanned": snap["scanned"],
        "open_count": len(ports),
        "closed_count": snap["closed"],
        "filtered_count": snap["filtered"],
        "high_count": summary["counts"]["HIGH"],
        "medium_count": summary["counts"]["MEDIUM"],
        "overall_risk": summary["overall"],
        "open_ports": ports,
        "recommendations": [],
        "summary": "Scan in progress...",
        "disclaimer": analyzer.DISCLAIMER,
        "progress_percent": round(100 * snap["scanned"] / snap["total"]) if snap["total"] else 0,
    })
    return scan


def _scan_view(user_id, scan_id):
    row = database.get_scan(user_id, scan_id)
    if row is None:
        return None
    job = scanner.get_job(scan_id)
    if job is not None and job.user_id == user_id:
        return _live_payload(row, job)
    return _full_payload(row)


def _finished_scan_or_error(scan_id):
    row = database.get_scan(g.user["id"], scan_id)
    if row is None:
        return None, json_error("Scan not found.", 404)
    if scanner.get_job(scan_id) is not None or row["status"] == "running":
        return None, json_error("The scan is still running. Wait for it to finish.", 409)
    return _full_payload(row), None


# -------------------------------------------------------------- scan job
def _run_job(job):
    try:
        scanner.run_scan(job)
        snap = job.snapshot()
        overrides = database.get_risk_overrides(job.user_id)
        ports = [analyzer.analyze_port(p["port"], overrides) for p in snap["open_ports"]]
        summary = analyzer.summarize(ports)
        database.finish_scan(
            job.scan_id, job.outcome, now_iso(), job.duration, snap["scanned"], snap["closed"],
            snap["filtered"], summary["counts"]["HIGH"], summary["counts"]["MEDIUM"],
            summary["overall"], ports)
        row = database.get_scan(job.user_id, job.scan_id)
        if row:                                         # keep JSON/CSV copies in reports/
            payload = _full_payload(row)
            _write_file(f"scan_{job.scan_id}_report.json", report_generator.to_json(payload))
            _write_file(f"scan_{job.scan_id}_report.csv", report_generator.to_csv(payload), "utf-8-sig")
    except Exception:                                   # noqa: BLE001 - never leave a scan 'running'
        app.logger.exception("Scan %s failed", job.scan_id)
        database.fail_scan(job.scan_id, now_iso(), "Internal error while scanning.")
    finally:
        scanner.remove_job(job.scan_id)


def _write_file(name, content, encoding="utf-8"):
    with open(os.path.join(REPORTS_DIR, name), "w", encoding=encoding, newline="") as fh:
        fh.write(content)


# --------------------------------------------------------------- API
@app.route("/api/scan", methods=["POST"])
@login_required
def api_start_scan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Request body must be valid JSON.")
    uid = g.user["id"]
    try:
        params = scanner.parse_scan_request(data)
        target, ip = scanner.resolve_target(params["target"])
        authorized = [r["target"] for r in database.list_authorized_targets(uid)]
        scanner.check_authorization(target, ip, authorized)
    except scanner.ScanError as exc:
        return json_error(str(exc), exc.status)

    with _start_lock:
        if scanner.user_has_running_job(uid):
            return json_error("You already have a scan running. Wait for it to finish or cancel it.", 409)
        scan_id = database.create_scan(uid, target, ip, params["start_port"], params["end_port"],
                                       params["timeout"], params["workers"], now_iso())
        job = scanner.ScanJob(scan_id, uid, target, ip, params["start_port"], params["end_port"],
                              params["timeout"], params["workers"])
        scanner.register_job(job)
    threading.Thread(target=_run_job, args=(job,), daemon=True).start()
    return jsonify(scan_id=scan_id, status="running", total_requested=job.total), 202


@app.route("/api/scan/<int:scan_id>", methods=["GET"])
@login_required
def api_get_scan(scan_id):
    view = _scan_view(g.user["id"], scan_id)
    if view is None:
        return json_error("Scan not found.", 404)
    return jsonify(view)


@app.route("/api/scan/<int:scan_id>", methods=["DELETE"])
@login_required
def api_delete_scan(scan_id):
    row = database.get_scan(g.user["id"], scan_id)
    if row is None:
        return json_error("Scan not found.", 404)
    if scanner.get_job(scan_id) is not None:
        return json_error("Cancel the running scan before deleting it.", 409)
    database.delete_scan(g.user["id"], scan_id)
    for ext in ("pdf", "json", "csv"):
        try:
            os.remove(os.path.join(REPORTS_DIR, f"scan_{scan_id}_report.{ext}"))
        except OSError:
            pass
    return jsonify(deleted=scan_id)


@app.route("/api/scan/<int:scan_id>/cancel", methods=["POST"])
@login_required
def api_cancel_scan(scan_id):
    if database.get_scan(g.user["id"], scan_id) is None:
        return json_error("Scan not found.", 404)
    job = scanner.get_job(scan_id)
    if job is None:
        return json_error("This scan is not running.", 409)
    job.cancel_event.set()
    return jsonify(status="cancelling")


@app.route("/api/dashboard", methods=["GET"])
@login_required
def api_dashboard():
    stats = database.dashboard_stats(g.user["id"])
    stats["recent_scans"] = database.list_scans(g.user["id"], limit=5)
    return jsonify(stats)


@app.route("/api/history", methods=["GET"])
@login_required
def api_history():
    scans = database.list_scans(g.user["id"])
    running = {s["id"] for s in scans if scanner.get_job(s["id"])}
    for s in scans:
        if s["id"] in running:
            s["status"] = "running"
    return jsonify(scans=scans)


@app.route("/api/scan/<int:scan_id>/report", methods=["GET"])
@login_required
def api_report_pdf(scan_id):
    payload, err = _finished_scan_or_error(scan_id)
    if err:
        return err
    path = os.path.join(REPORTS_DIR, f"scan_{scan_id}_report.pdf")
    report_generator.generate_pdf(payload, path)
    return send_file(path, mimetype="application/pdf", as_attachment=True,
                     download_name=f"security_report_scan_{scan_id}.pdf")


@app.route("/api/scan/<int:scan_id>/export/csv", methods=["GET"])
@login_required
def api_export_csv(scan_id):
    payload, err = _finished_scan_or_error(scan_id)
    if err:
        return err
    content = report_generator.to_csv(payload)
    _write_file(f"scan_{scan_id}_report.csv", content, "utf-8-sig")
    return Response(content.encode("utf-8-sig"), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_report.csv"})


@app.route("/api/scan/<int:scan_id>/export/json", methods=["GET"])
@login_required
def api_export_json(scan_id):
    payload, err = _finished_scan_or_error(scan_id)
    if err:
        return err
    content = report_generator.to_json(payload)
    _write_file(f"scan_{scan_id}_report.json", content)
    return Response(content, mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_report.json"})


# ----------------------------------------------------- authorized targets
@app.route("/api/authorized-targets", methods=["GET"])
@login_required
def api_list_authorized():
    return jsonify(targets=database.list_authorized_targets(g.user["id"]))


@app.route("/api/authorized-targets", methods=["POST"])
@login_required
def api_add_authorized():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Request body must be valid JSON.")
    if data.get("confirm") is not True:
        return json_error("You must confirm that you own this system or have written permission to test it.")
    note = str(data.get("note", "")).strip()[:200]
    try:
        entry = scanner.validate_authorized_entry(data.get("target"))
    except scanner.ScanError as exc:
        return json_error(str(exc), exc.status)
    try:
        new_id = database.add_authorized_target(g.user["id"], entry, note, now_iso())
    except sqlite3.IntegrityError:
        return json_error("That target is already on your authorized list.", 409)
    return jsonify(id=new_id, target=entry), 201


@app.route("/api/authorized-targets/<int:target_id>", methods=["DELETE"])
@login_required
def api_delete_authorized(target_id):
    if not database.delete_authorized_target(g.user["id"], target_id):
        return json_error("Entry not found.", 404)
    return jsonify(deleted=target_id)


# ------------------------------------------------------------ risk rules
@app.route("/api/risk-rules", methods=["GET"])
@login_required
def api_risk_rules():
    overrides = database.get_risk_overrides(g.user["id"])
    rules = []
    for port in sorted(set(analyzer.KNOWLEDGE) | set(overrides)):
        base, explanation, mitigation = analyzer.KNOWLEDGE.get(port, analyzer.UNKNOWN_ENTRY)
        current = overrides.get(port, base)
        rules.append({"port": port, "service": scanner.probable_service(port), "default_risk": base,
                      "risk": current, "overridden": current != base,
                      "explanation": explanation, "mitigation": mitigation})
    return jsonify(rules=rules, levels=list(analyzer.VALID_RISKS))


@app.route("/api/risk-rules", methods=["POST"])
@login_required
def api_set_risk_rule():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Request body must be valid JSON.")
    try:
        port = int(data.get("port"))
    except (TypeError, ValueError):
        return json_error("Port must be a whole number.")
    risk = str(data.get("risk", "")).upper()
    if not 1 <= port <= 65535:
        return json_error("Port must be between 1 and 65535.")
    if risk not in analyzer.VALID_RISKS:
        return json_error("Risk must be one of: " + ", ".join(analyzer.VALID_RISKS) + ".")
    if risk == analyzer.default_risk(port):
        database.delete_risk_override(g.user["id"], port)
    else:
        database.set_risk_override(g.user["id"], port, risk)
    return jsonify(port=port, risk=risk)


@app.route("/api/risk-rules/<int:port>", methods=["DELETE"])
@login_required
def api_reset_risk_rule(port):
    database.delete_risk_override(g.user["id"], port)
    return jsonify(port=port, risk=analyzer.default_risk(port))


if __name__ == "__main__":
    # Bound to 127.0.0.1 so only this computer can reach the app.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
