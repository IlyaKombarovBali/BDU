"""Регистрация, сессии и закладки «к изучению» (таблицы в site.db)."""
import hashlib
import os
import re
import secrets
import smtplib
import sqlite3
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
SITE_DB = ROOT / "site.db"
BOOKMARK_PATH_MAX = 512
TITLE_MAX = 220
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\u0400-\u04FF]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", re.IGNORECASE)
RESET_TOKEN_HOURS = 2


def _conn():
    con = sqlite3.connect(SITE_DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def upgrade_site_db_auth(db_path):
    """
    Создаёт таблицы/индексы учётных записей и закладок в указанном site.db
    (копия с прода, другой путь и т.д.). Идемпотентно.
    """
    p = Path(db_path).resolve()
    con = sqlite3.connect(str(p))
    try:
        con.execute("PRAGMA foreign_keys=ON")
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS user_bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                title TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(user_id, path),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_bookmarks_user ON user_bookmarks(user_id);
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_pwreset_token ON password_resets(token_hash);
            """
        )
        cols = [r[1] for r in con.execute("PRAGMA table_info(users)").fetchall()]
        if cols and "email" not in cols:
            con.execute("ALTER TABLE users ADD COLUMN email TEXT")
        try:
            con.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email "
                "ON users(email) WHERE email IS NOT NULL AND trim(email) != ''"
            )
        except sqlite3.OperationalError:
            pass
        con.commit()
    finally:
        con.close()


def init_auth_db():
    upgrade_site_db_auth(SITE_DB)


def smtp_configured() -> bool:
    return bool((os.environ.get("SMTP_HOST") or "").strip())


def public_base_url() -> str:
    return (os.environ.get("PUBLIC_BASE_URL") or "http://127.0.0.1:5000").rstrip("/")


def validate_email_optional(email: str):
    if not (email or "").strip():
        return None
    e = email.strip()
    if not EMAIL_RE.match(e):
        return "Некорректный email."
    return None


def send_password_reset_email(to_addr: str, reset_link: str) -> bool:
    if not smtp_configured():
        return False
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT") or "587")
    user = os.environ.get("SMTP_USER", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    mail_from = os.environ.get("SMTP_FROM", user).strip()
    if not mail_from:
        return False
    msg = EmailMessage()
    msg["Subject"] = "ПРО ИБ — восстановление пароля"
    msg["From"] = mail_from
    msg["To"] = to_addr
    msg.set_content(
        f"Здравствуйте.\n\n"
        f"Чтобы задать новый пароль, перейдите по ссылке (действует {RESET_TOKEN_HOURS} ч.):\n"
        f"{reset_link}\n\n"
        f"Если вы не запрашивали сброс, проигнорируйте письмо.\n"
    )
    try:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return True
    except OSError:
        return False


def get_user_by_email_normalized(email: str):
    e = (email or "").strip().lower()
    if not e:
        return None
    con = _conn()
    try:
        row = con.execute(
            "SELECT id, username, email FROM users WHERE lower(trim(email)) = ?",
            (e,),
        ).fetchone()
        if not row:
            return None
        return {"id": row["id"], "username": row["username"], "email": row["email"]}
    finally:
        con.close()


def create_password_reset_and_send(email: str) -> bool:
    """Создаёт токен и шлёт письмо. False если SMTP не настроен или отправка не удалась."""
    user = get_user_by_email_normalized(email)
    if not user or not (user.get("email") or "").strip():
        return False
    raw = secrets.token_urlsafe(32)
    th = hashlib.sha256(raw.encode()).hexdigest()
    exp = (datetime.now(timezone.utc) + timedelta(hours=RESET_TOKEN_HOURS)).isoformat()
    con = _conn()
    try:
        con.execute(
            "UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0",
            (user["id"],),
        )
        con.execute(
            "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user["id"], th, exp),
        )
        con.commit()
    finally:
        con.close()
    link = f"{public_base_url()}/reset-password?token={raw}"
    return send_password_reset_email(user["email"].strip(), link)


def verify_reset_token(raw_token: str):
    if not raw_token or len(raw_token) > 500:
        return None
    th = hashlib.sha256(raw_token.encode()).hexdigest()
    con = _conn()
    try:
        row = con.execute(
            """
            SELECT id, user_id, expires_at FROM password_resets
            WHERE token_hash = ? AND used = 0
            """,
            (th,),
        ).fetchone()
        if not row:
            return None
        try:
            es = str(row["expires_at"]).replace("Z", "+00:00")
            exp = datetime.fromisoformat(es)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        if datetime.now(timezone.utc) > exp:
            return None
        return {"reset_id": row["id"], "user_id": row["user_id"]}
    finally:
        con.close()


def apply_password_reset(raw_token: str, new_password: str):
    if len(new_password or "") < 8:
        return False, "Пароль не короче 8 символов."
    info = verify_reset_token(raw_token)
    if not info:
        return False, "Ссылка недействительна или устарела."
    pw_hash = generate_password_hash(new_password)
    con = _conn()
    try:
        con.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (pw_hash, info["user_id"]),
        )
        con.execute(
            "UPDATE password_resets SET used = 1 WHERE id = ?",
            (info["reset_id"],),
        )
        con.commit()
        return True, None
    finally:
        con.close()


def update_user_email(user_id: int, email: str):
    e = (email or "").strip().lower() or None
    con = _conn()
    try:
        con.execute(
            "UPDATE users SET email = ? WHERE id = ?",
            (e, int(user_id)),
        )
        con.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, "Этот email уже привязан к другому аккаунту."
    finally:
        con.close()


def normalize_full_path(full_path: str) -> str:
    if not full_path:
        return "/"
    fp = full_path.split("#", 1)[0]
    if len(fp) > BOOKMARK_PATH_MAX:
        fp = fp[:BOOKMARK_PATH_MAX]
    if fp.endswith("?"):
        fp = fp[:-1]
    return fp or "/"


def path_only(full_path: str) -> str:
    return full_path.split("?", 1)[0].rstrip("/") or "/"


def is_bookmarkable_path(full_path: str) -> bool:
    fp = normalize_full_path(full_path)
    if "\x00" in fp or ".." in fp:
        return False
    if not fp.startswith("/") or fp.startswith("//"):
        return False
    po = path_only(fp)
    skip = {
        "/login",
        "/register",
        "/logout",
        "/static",
        "/profile",
        "/forgot-password",
        "/reset-password",
    }
    if po in skip or po.startswith("/static/"):
        return False
    patterns = (
        r"^/$",
        r"^/laws$",
        r"^/news$",
        r"^/full_cve$",
        r"^/search$",
        r"^/search_laws$",
        r"^/search_news$",
        r"^/tools$",
        r"^/tools/[^/]+$",
        r"^/donate$",
        r"^/feedback$",
        r"^/cve/[^/]+$",
        r"^/law/\d+$",
        r"^/news/\d+$",
    )
    for p in patterns:
        if re.match(p, po):
            return True
    return False


def default_title_for_path(full_path: str) -> str:
    fp = normalize_full_path(full_path)
    import bookmark_meta

    return bookmark_meta.bookmark_title_from_path_normalized(fp)


def safe_relative_url(url: str):
    """Только внутренняя ссылка для ?next= после входа."""
    if not url or not isinstance(url, str):
        return None
    u = url.strip()
    if len(u) > BOOKMARK_PATH_MAX:
        u = u[:BOOKMARK_PATH_MAX]
    if not u.startswith("/") or u.startswith("//"):
        return None
    if "\x00" in u or ".." in u.split("?", 1)[0]:
        return None
    if is_bookmarkable_path(u):
        return u
    po = path_only(u)
    if po in ("/profile", "/register"):
        return u
    return None


def validate_registration(username: str, password: str, password2: str, email: str = ""):
    if not USERNAME_RE.match(username or ""):
        return "Логин: 3–32 символа, буквы/цифры/подчёркивание."
    if len(password or "") < 8:
        return "Пароль не короче 8 символов."
    if password != password2:
        return "Пароли не совпадают."
    eerr = validate_email_optional(email)
    if eerr:
        return eerr
    return None


def create_user(username: str, password: str, email: str = None):
    username = (username or "").strip().lower()
    em = (email or "").strip().lower() or None
    pw_hash = generate_password_hash(password)
    con = _conn()
    try:
        cur = con.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, pw_hash, em),
        )
        con.commit()
        uid = cur.lastrowid
        return True, uid, None
    except sqlite3.IntegrityError:
        return False, None, "Такой логин или email уже занят."
    finally:
        con.close()


def authenticate(username: str, password: str):
    if not username or not password:
        return None
    con = _conn()
    try:
        row = con.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username.strip().lower(),),
        ).fetchone()
        if not row or not check_password_hash(row["password_hash"], password):
            return None
        return {"id": row["id"], "username": row["username"]}
    finally:
        con.close()


def get_user_by_id(uid):
    if not uid:
        return None
    con = _conn()
    try:
        row = con.execute(
            "SELECT id, username, email FROM users WHERE id = ?", (int(uid),)
        ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
        }
    finally:
        con.close()


def is_bookmarked(user_id: int, full_path: str) -> bool:
    fp = normalize_full_path(full_path)
    con = _conn()
    try:
        r = con.execute(
            "SELECT 1 FROM user_bookmarks WHERE user_id = ? AND path = ?",
            (user_id, fp),
        ).fetchone()
        return r is not None
    finally:
        con.close()


def add_bookmark(user_id: int, full_path: str, title: str):
    fp = normalize_full_path(full_path)
    if not is_bookmarkable_path(fp):
        return False, "Недопустимый адрес страницы."
    t = (title or default_title_for_path(fp)).strip()[:TITLE_MAX]
    if not t:
        t = default_title_for_path(fp)
    con = _conn()
    try:
        con.execute(
            "INSERT INTO user_bookmarks (user_id, path, title) VALUES (?, ?, ?)",
            (user_id, fp, t),
        )
        con.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, "Уже в списке «к изучению»."
    finally:
        con.close()


def remove_bookmark(user_id: int, bookmark_id: int) -> bool:
    con = _conn()
    try:
        cur = con.execute(
            "DELETE FROM user_bookmarks WHERE id = ? AND user_id = ?",
            (bookmark_id, user_id),
        )
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def list_bookmarks(user_id: int):
    con = _conn()
    try:
        rows = con.execute(
            """
            SELECT id, path, title, created_at
            FROM user_bookmarks
            WHERE user_id = ?
            ORDER BY datetime(created_at) DESC
            """,
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
