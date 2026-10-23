import os, sqlite3, secrets, hmac, json, urllib.request, urllib.parse, urllib.error
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("NOXCHAT_DB_PATH", os.path.join(APP_DIR, "bot_database.db"))
ADMIN_PASSWORD = os.environ.get("NOXCHAT_ADMIN_PASSWORD", "")
BOT_TOKEN = os.environ.get("NOXCHAT_BOT_TOKEN", "")
SECRET_KEY = os.environ.get("NOXCHAT_WEB_SECRET", "")
app = Flask(__name__)
app.secret_key = SECRET_KEY or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
                  MAX_CONTENT_LENGTH=256 * 1024)

DEFAULT_SETTINGS = {
    "random_chat_enabled": "1",
    "random_wait_seconds": "60",
    "required_channel": "@Aghrab_moto",
    "channel_url": "https://t.me/Aghrab_moto",
    "home_button_text": "به یه ناشناس وصلم کن 🎲",
    "membership_message": "کاربرگرامی برای استفاده از این بخش باید داخل کانال‌های گفته‌شده عضو شوید ✅",
    "search_message": "در حال جست‌وجو هستیم؛ لطفاً کمی صبر کن…",
    "not_found_message": "ببخشید 🥲 هیچکس نبود که بهش وصلت کنم. دوباره می‌تونی تلاش کنی ❤️",
}

def connect():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    return con

def init_admin_tables():
    # Uses the same SQLite file as the bot, but does not modify existing bot tables.
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS admin_settings (
            key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS admin_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, chat_id TEXT NOT NULL,
            url TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS admin_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, details TEXT NOT NULL,
            created_at TEXT NOT NULL, actor TEXT NOT NULL
        )""")
        for k, v in DEFAULT_SETTINGS.items():
            con.execute("INSERT OR IGNORE INTO admin_settings(key,value,updated_at,updated_by) VALUES(?,?,?,?)",
                        (k, v, datetime.now().isoformat(timespec="seconds"), "system"))
        con.execute("INSERT OR IGNORE INTO admin_channels(title,chat_id,url,enabled,created_at) VALUES(?,?,?,?,?)",
                    ("عقرب", "@Aghrab_moto", "https://t.me/Aghrab_moto", 1,
                     datetime.now().isoformat(timespec="seconds")))

def audit(action, details):
    with connect() as con:
        con.execute("INSERT INTO admin_audit(action,details,created_at,actor) VALUES(?,?,?,?)",
                    (action, details[:1000], datetime.now().isoformat(timespec="seconds"),
                     str(session.get("admin", "admin"))))

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def protect_post():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        expected = session.get("csrf", "")
        if not sent or not expected or not hmac.compare_digest(sent, expected):
            abort(400, "درخواست نامعتبر است. صفحه را تازه‌سازی کنید.")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def table_exists(con, name):
    return con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None

def safe_count(con, table, where=""):
    if not table_exists(con, table):
        return 0
    try:
        return con.execute(f"SELECT COUNT(*) FROM {table} {where}").fetchone()[0]
    except sqlite3.Error:
        return 0

def get_setting(key, fallback=""):
    with connect() as con:
        row = con.execute("SELECT value FROM admin_settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else fallback

@app.route("/login", methods=["GET", "POST"])
def login():
    if not ADMIN_PASSWORD:
        return render_template("setup_required.html")
    if request.method == "POST":
        password = request.form.get("password", "")
        if hmac.compare_digest(password, ADMIN_PASSWORD):
            session.clear()
            session["admin"] = "owner"
            session["csrf"] = secrets.token_urlsafe(24)
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("رمز عبور اشتباه است.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("از پنل خارج شدید.", "success")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    with connect() as con:
        stats = {
            "users": safe_count(con, "users"),
            "blocked": safe_count(con, "users", "WHERE is_blocked=1"),
            "queue": safe_count(con, "random_queue"),
            "active_chats": safe_count(con, "conversations", "WHERE status='active'"),
            "chats_total": safe_count(con, "conversations"),
            "new_today": 0,
            "online": 0,
        }
        if table_exists(con, "users"):
            cols = {r["name"] for r in con.execute("PRAGMA table_info(users)")}
            if "created_at" in cols:
                stats["new_today"] = con.execute(
                    "SELECT COUNT(*) FROM users WHERE substr(created_at,1,10)=?",
                    (datetime.now().date().isoformat(),)).fetchone()[0]
            if "last_active" in cols:
                cutoff = (datetime.now() - timedelta(minutes=5)).isoformat()
                stats["online"] = con.execute(
                    "SELECT COUNT(*) FROM users WHERE last_active IS NOT NULL AND last_active>=?",
                    (cutoff,)).fetchone()[0]
        latest = []
        if table_exists(con, "users"):
            cols = {r["name"] for r in con.execute("PRAGMA table_info(users)")}
            select_cols = ["user_id"]
            for c in ("username", "full_name", "created_at", "last_active", "is_blocked"):
                if c in cols: select_cols.append(c)
            latest = [dict(r) for r in con.execute(
                f"SELECT {','.join(select_cols)} FROM users ORDER BY user_id DESC LIMIT 8")]
    return render_template("dashboard.html", stats=stats, latest=latest,
                           chat_enabled=get_setting("random_chat_enabled", "1") == "1")

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        values = {
            "random_chat_enabled": "1" if request.form.get("random_chat_enabled") == "1" else "0",
            "random_wait_seconds": str(max(10, min(300, int(request.form.get("random_wait_seconds", "60"))))),
            "required_channel": request.form.get("required_channel", "").strip()[:200],
            "channel_url": request.form.get("channel_url", "").strip()[:500],
            "home_button_text": request.form.get("home_button_text", "").strip()[:150],
            "membership_message": request.form.get("membership_message", "").strip()[:2000],
            "search_message": request.form.get("search_message", "").strip()[:1000],
            "not_found_message": request.form.get("not_found_message", "").strip()[:1000],
        }
        with connect() as con:
            for k, v in values.items():
                con.execute("""INSERT INTO admin_settings(key,value,updated_at,updated_by) VALUES(?,?,?,?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
                    (k, v, datetime.now().isoformat(timespec="seconds"), session["admin"]))
        audit("settings_saved", "تنظیمات عمومی ذخیره شد")
        flash("تنظیمات در دیتابیس ذخیره شد. برای اعمال زنده، کد ربات باید این تنظیمات را بخواند.", "success")
        return redirect(url_for("settings"))
    with connect() as con:
        vals = {r["key"]: r["value"] for r in con.execute("SELECT key,value FROM admin_settings")}
    return render_template("settings.html", s={**DEFAULT_SETTINGS, **vals})

@app.route("/channels", methods=["GET", "POST"])
@login_required
def channels():
    if request.method == "POST":
        title = request.form.get("title", "").strip()[:100]
        chat_id = request.form.get("chat_id", "").strip()[:200]
        url = request.form.get("url", "").strip()[:500]
        if not title or not chat_id or not (url.startswith("https://t.me/") or url.startswith("https://telegram.me/")):
            flash("نام، شناسه کانال و لینک معتبر t.me لازم است.", "error")
        else:
            with connect() as con:
                con.execute("INSERT INTO admin_channels(title,chat_id,url,enabled,created_at) VALUES(?,?,?,?,?)",
                            (title, chat_id, url, 1, datetime.now().isoformat(timespec="seconds")))
            audit("channel_added", f"{title} | {chat_id}")
            flash("کانال به فهرست پنل اضافه شد؛ اتصال بررسی عضویت به کد ربات نیاز دارد.", "success")
        return redirect(url_for("channels"))
    with connect() as con:
        rows = [dict(r) for r in con.execute("SELECT * FROM admin_channels ORDER BY id DESC")]
    return render_template("channels.html", channels=rows)

@app.post("/channels/<int:channel_id>/toggle")
@login_required
def toggle_channel(channel_id):
    with connect() as con:
        row = con.execute("SELECT enabled,title FROM admin_channels WHERE id=?", (channel_id,)).fetchone()
        if not row: abort(404)
        con.execute("UPDATE admin_channels SET enabled=? WHERE id=?", (0 if row["enabled"] else 1, channel_id))
    audit("channel_toggled", f'{row["title"]}: {not bool(row["enabled"])}')
    flash("وضعیت کانال تغییر کرد.", "success")
    return redirect(url_for("channels"))

@app.post("/channels/<int:channel_id>/delete")
@login_required
def delete_channel(channel_id):
    with connect() as con:
        row = con.execute("SELECT title FROM admin_channels WHERE id=?", (channel_id,)).fetchone()
        if not row: abort(404)
        con.execute("DELETE FROM admin_channels WHERE id=?", (channel_id,))
    audit("channel_deleted", row["title"])
    flash("کانال از فهرست پنل حذف شد.", "success")
    return redirect(url_for("channels"))

@app.route("/users")
@login_required
def users():
    q = request.args.get("q", "").strip()[:100]
    page = max(1, min(100000, request.args.get("page", 1, type=int)))
    with connect() as con:
        if not table_exists(con, "users"):
            rows, total = [], 0
        else:
            cols = {r["name"] for r in con.execute("PRAGMA table_info(users)")}
            allowed = ["user_id"] + [c for c in ("username","full_name","phone","age","gender","created_at","last_active","is_blocked","coins") if c in cols]
            where, args = "", []
            if q:
                if q.isdigit():
                    where = "WHERE user_id=?"; args = [int(q)]
                elif "username" in cols:
                    where = "WHERE username LIKE ? OR full_name LIKE ?"; args = [f"%{q}%", f"%{q}%"]
                else:
                    where = "WHERE CAST(user_id AS TEXT) LIKE ?"; args = [f"%{q}%"]
            total = con.execute(f"SELECT COUNT(*) FROM users {where}", args).fetchone()[0]
            rows = [dict(r) for r in con.execute(
                f"SELECT {','.join(allowed)} FROM users {where} ORDER BY user_id DESC LIMIT 30 OFFSET ?",
                args + [(page-1)*30])]
    return render_template("users.html", users=rows, q=q, page=page, total=total)

@app.post("/users/<int:user_id>/block")
@login_required
def block_user(user_id):
    with connect() as con:
        if not table_exists(con, "users"): abort(404)
        cur = con.execute("UPDATE users SET is_blocked=1 WHERE user_id=?", (user_id,))
        if cur.rowcount == 0: flash("کاربر پیدا نشد.", "error")
        else:
            audit("user_blocked", str(user_id))
            flash(f"کاربر {user_id} مسدود شد.", "success")
    return redirect(request.referrer or url_for("users"))

@app.post("/users/<int:user_id>/unblock")
@login_required
def unblock_user(user_id):
    with connect() as con:
        if not table_exists(con, "users"): abort(404)
        cur = con.execute("UPDATE users SET is_blocked=0 WHERE user_id=?", (user_id,))
        if cur.rowcount == 0: flash("کاربر پیدا نشد.", "error")
        else:
            audit("user_unblocked", str(user_id))
            flash(f"مسدودی کاربر {user_id} برداشته شد.", "success")
    return redirect(request.referrer or url_for("users"))

@app.route("/broadcast", methods=["GET", "POST"])
@login_required
def broadcast():
    if request.method == "POST":
        text = request.form.get("message", "").strip()
        confirm = request.form.get("confirm") == "yes"
        if not confirm:
            flash("برای ارسال همگانی، تأیید نهایی را فعال کن.", "error")
        elif not text:
            flash("متن پیام خالی است.", "error")
        elif not BOT_TOKEN:
            flash("متغیر NOXCHAT_BOT_TOKEN روی سرور تنظیم نشده؛ ارسال انجام نشد.", "error")
        else:
            with connect() as con:
                if not table_exists(con, "users"):
                    flash("جدول کاربران پیدا نشد.", "error")
                    return redirect(url_for("broadcast"))
                ids = [r[0] for r in con.execute("SELECT user_id FROM users WHERE COALESCE(is_blocked,0)=0")]
            ok = fail = 0
            # Deliberately throttled. Telegram's limits may vary; review before large campaigns.
            for uid in ids:
                payload = urllib.parse.urlencode({"chat_id": uid, "text": text}).encode()
                req = urllib.request.Request(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                                             data=payload, method="POST")
                try:
                    with urllib.request.urlopen(req, timeout=8) as response:
                        result = json.loads(response.read().decode("utf-8"))
                        if result.get("ok"): ok += 1
                        else: fail += 1
                except Exception:
                    fail += 1
                import time; time.sleep(0.05)
            audit("broadcast", f"sent={ok}; failed={fail}; recipients={len(ids)}")
            flash(f"ارسال تمام شد: موفق {ok}، ناموفق {fail}.", "success")
        return redirect(url_for("broadcast"))
    with connect() as con:
        count = safe_count(con, "users", "WHERE COALESCE(is_blocked,0)=0")
    return render_template("broadcast.html", recipients=count)

@app.route("/audit")
@login_required
def audit_page():
    with connect() as con:
        rows = [dict(r) for r in con.execute("SELECT * FROM admin_audit ORDER BY id DESC LIMIT 100")]
    return render_template("audit.html", rows=rows)

@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message=getattr(e, "description", "درخواست نامعتبر است.")), 400
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="صفحه یا مورد درخواستی پیدا نشد."), 404

init_admin_tables()

if __name__ == "__main__":
    if not ADMIN_PASSWORD:
        print("WARNING: set NOXCHAT_ADMIN_PASSWORD before using the dashboard.")
    # For local testing only. For public deployment use a production WSGI server + HTTPS.
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "5000")), debug=False)
