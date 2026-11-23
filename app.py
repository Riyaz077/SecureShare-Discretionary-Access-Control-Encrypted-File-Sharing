from __future__ import annotations

import base64
import io
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "encrypted_files"
DB_PATH = DATA_DIR / "secureshare.db"
LOGO_PATH = BASE_DIR / "static" / "images" / "secureshare-logo.png"
MAX_FILE_SIZE = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {"pdf", "txt", "csv", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg", "zip"}
PERMISSIONS = ("read", "write", "download", "delete")

st.set_page_config(
    page_title="SecureShare | Secure File Management",
    page_icon=str(LOGO_PATH) if LOGO_PATH.exists() else "🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_css() -> None:
    css_path = BASE_DIR / "static" / "style.css"
    if css_path.exists():
        st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@contextmanager
def db_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with db_connection() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT UNIQUE NOT NULL,
                size INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                can_read INTEGER DEFAULT 0,
                can_write INTEGER DEFAULT 0,
                can_download INTEGER DEFAULT 0,
                can_delete INTEGER DEFAULT 0,
                granted_at TEXT NOT NULL,
                UNIQUE(file_id, user_id),
                FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                ip_address TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL
            );
            """
        )


def encryption_key() -> bytes:
    raw = os.environ.get("FILE_ENCRYPTION_KEY", "").strip()
    if not raw:
        key_file = DATA_DIR / "dev_encryption_key.txt"
        if not key_file.exists():
            key_file.write_text(
                base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode("ascii"),
                encoding="utf-8",
            )
        raw = key_file.read_text(encoding="utf-8").strip()
    try:
        key = base64.urlsafe_b64decode(raw.encode("ascii"))
        if len(key) != 32:
            raise ValueError("Expected 32 bytes")
        return key
    except Exception as exc:
        raise RuntimeError("FILE_ENCRYPTION_KEY must be a URL-safe Base64-encoded 32-byte key.") from exc


def log_event(actor_id: int | None, action: str, details: str) -> None:
    with db_connection() as con:
        con.execute(
            "INSERT INTO audit_logs(actor_id, action, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?)",
            (actor_id, action, details[:500], "Streamlit session", now()),
        )


def get_user_by_identity(identity: str) -> sqlite3.Row | None:
    with db_connection() as con:
        return con.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identity.strip(), identity.strip().lower()),
        ).fetchone()


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def fetch_file_access(file_id: int, permission: str, actor_id: int) -> sqlite3.Row | None:
    if permission not in PERMISSIONS:
        return None
    with db_connection() as con:
        row = con.execute(
            f"""SELECT f.*, p.can_read, p.can_write, p.can_download, p.can_delete
                FROM files f
                LEFT JOIN permissions p ON p.file_id = f.id AND p.user_id = ?
                WHERE f.id = ?""",
            (actor_id, file_id),
        ).fetchone()
    if not row:
        return None
    if row["owner_id"] == actor_id:
        return row
    if not row[f"can_{permission}"]:
        log_event(actor_id, "ACCESS_DENIED", f"{permission} denied for file #{file_id}")
        return None
    return row


def get_owned_files(user_id: int) -> list[sqlite3.Row]:
    with db_connection() as con:
        return con.execute(
            "SELECT * FROM files WHERE owner_id = ? ORDER BY uploaded_at DESC", (user_id,)
        ).fetchall()


def get_shared_files(user_id: int) -> list[sqlite3.Row]:
    with db_connection() as con:
        return con.execute(
            """SELECT f.*, u.username AS owner_name,
                      p.can_read, p.can_write, p.can_download, p.can_delete
               FROM permissions p
               JOIN files f ON f.id = p.file_id
               JOIN users u ON u.id = f.owner_id
               WHERE p.user_id = ? ORDER BY p.granted_at DESC""",
            (user_id,),
        ).fetchall()


def get_recent_logs(user_id: int, limit: int = 8) -> list[sqlite3.Row]:
    with db_connection() as con:
        return con.execute(
            "SELECT * FROM audit_logs WHERE actor_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()


def get_all_logs(limit: int = 200) -> list[sqlite3.Row]:
    with db_connection() as con:
        return con.execute(
            """SELECT a.*, u.username FROM audit_logs a
               LEFT JOIN users u ON u.id = a.actor_id
               ORDER BY a.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()


def do_register(username: str, email: str, password: str) -> tuple[bool, str]:
    username, email = username.strip(), email.strip().lower()
    if len(username) < 3 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(password) < 8:
        return False, "Use a username with at least 3 characters, a valid email, and a password with at least 8 characters."
    try:
        with db_connection() as con:
            cur = con.execute(
                "INSERT INTO users(username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, generate_password_hash(password), now()),
            )
            user_id = int(cur.lastrowid)
        log_event(user_id, "ACCOUNT_CREATED", f"Account created for {username}")
        return True, "Account created. You can now sign in."
    except sqlite3.IntegrityError:
        return False, "That username or email is already registered."


def do_login(identity: str, password: str) -> tuple[bool, str, sqlite3.Row | None]:
    user = get_user_by_identity(identity)
    if user and check_password_hash(user["password_hash"], password):
        log_event(int(user["id"]), "LOGIN_SUCCESS", "Successful sign-in")
        return True, "Signed in successfully.", user
    log_event(int(user["id"]) if user else None, "LOGIN_FAILED", f"Failed sign-in attempt for {identity.strip()}")
    return False, "Invalid username/email or password.", None


def fmt_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def logo_header() -> None:
    png_logo = BASE_DIR / "static" / "images" / "secureshare-logo.png"
    if png_logo.exists():
        encoded = base64.b64encode(png_logo.read_bytes()).decode("ascii")
        st.markdown(
            f'''<div class="ss-brand"><img src="data:image/png;base64,{encoded}" />
            <div><div class="ss-brand-name">SecureShare</div>
            <div class="ss-brand-sub">DISCRETIONARY ACCESS CONTROL · ENCRYPTED FILE SHARING</div></div></div>''',
            unsafe_allow_html=True,
        )
    else:
        st.markdown("<div class='ss-brand-name'>🔐 SecureShare</div>", unsafe_allow_html=True)


def login_screen() -> None:
    logo_header()
    left, right = st.columns([1.08, 0.92], gap="large", vertical_alignment="center")

    with left:
        st.markdown(
            "<div class='ss-eyebrow'><span class='ss-eyebrow-dot'></span> PRIVATE BY DESIGN &nbsp;·&nbsp; BUILT FOR CONTROL</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<div class='ss-hero-title'>Your files.<br><span>Your rules.</span></div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p class='ss-hero-copy'>A more considered way to protect, manage and share your files. "
            "Strong encryption meets permissions that stay in your hands.</p>",
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <div class="ss-feature-list">
              <div class="ss-feature-item">
                <div class="ss-feature-icon">◈</div>
                <div><b>Encrypted at rest</b><span>AES-256-GCM authenticated encryption protects stored file contents.</span></div>
                <div class="ss-feature-arrow">↗</div>
              </div>
              <div class="ss-feature-item">
                <div class="ss-feature-icon">⌘</div>
                <div><b>Access on your terms</b><span>Grant or revoke read, write, download and delete permissions per person.</span></div>
                <div class="ss-feature-arrow">↗</div>
              </div>
              <div class="ss-feature-item">
                <div class="ss-feature-icon">≋</div>
                <div><b>Visibility that matters</b><span>Review account activity, file events and permission changes in one place.</span></div>
                <div class="ss-feature-arrow">↗</div>
              </div>
            </div>
            <div class="ss-trust-row">
              <span><i></i> AES-256-GCM</span>
              <span><i></i> Discretionary access control</span>
              <span><i></i> Activity history</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with right:
        with st.container(border=True, key="ss_auth_card"):
            st.markdown(
                "<div class='ss-auth-kicker'>SECURE WORKSPACE</div>"
                "<div class='ss-auth-title'>Welcome to SecureShare</div>"
                "<div class='ss-auth-copy'>Sign in to continue to your private file workspace.</div>",
                unsafe_allow_html=True,
            )
            mode = st.radio(
                "Welcome",
                ["Sign in", "Create account"],
                horizontal=True,
                label_visibility="collapsed",
                key="auth_mode",
            )
            st.markdown("<div class='ss-auth-divider'></div>", unsafe_allow_html=True)
            if mode == "Sign in":
                with st.form("login_form"):
                    identity = st.text_input("Username or email", placeholder="you@example.com")
                    password = st.text_input("Password", type="password", placeholder="Enter your password")
                    submitted = st.form_submit_button("Sign in securely  →", use_container_width=True, type="primary")
                if submitted:
                    ok, message, user = do_login(identity, password)
                    if ok and user:
                        st.session_state.user_id = int(user["id"])
                        st.session_state.username = user["username"]
                        st.session_state.page = "Dashboard"
                        st.rerun()
                    st.error(message)
            else:
                with st.form("register_form"):
                    username = st.text_input("Username", placeholder="Choose a username")
                    email = st.text_input("Email address", placeholder="you@example.com")
                    password = st.text_input("Password", type="password", help="At least 8 characters")
                    confirm = st.text_input("Confirm password", type="password")
                    submitted = st.form_submit_button("Create your account  →", use_container_width=True, type="primary")
                if submitted:
                    if password != confirm:
                        st.error("The passwords do not match.")
                    else:
                        ok, message = do_register(username, email, password)
                        if ok:
                            st.success(message)
                        else:
                            st.error(message)
            st.markdown(
                "<div class='ss-auth-foot'><span class='ss-lock'>▣</span> Your workspace is protected with encrypted file storage.</div>",
                unsafe_allow_html=True,
            )



def dashboard_page(user_id: int) -> None:
    owned = get_owned_files(user_id)
    shared = get_shared_files(user_id)
    logs = get_recent_logs(user_id)
    with db_connection() as con:
        grant_count = con.execute(
            "SELECT COUNT(*) FROM permissions p JOIN files f ON f.id = p.file_id WHERE f.owner_id = ?",
            (user_id,),
        ).fetchone()[0]
    st.title(f"Welcome back, {st.session_state.username}")
    st.caption("Your secure file workspace at a glance.")
    cols = st.columns(4)
    metrics = [("MY FILES", len(owned)), ("SHARED WITH ME", len(shared)), ("ACTIVE GRANTS", int(grant_count)), ("RECENT EVENTS", len(logs))]
    for col, (label, value) in zip(cols, metrics):
        with col:
            st.markdown(f"<div class='ss-metric'><div>{label}</div><strong>{value}</strong></div>", unsafe_allow_html=True)

    st.subheader("Upload and encrypt a file")
    st.caption("Allowed: PDF, TXT, CSV, DOC/DOCX, XLS/XLSX, PNG/JPG and ZIP · Maximum 10 MB")
    uploaded = st.file_uploader("Choose a file", type=sorted(ALLOWED_EXTENSIONS), key="dashboard_upload")
    if uploaded is not None:
        if st.button("Encrypt and upload", type="primary"):
            data = uploaded.getvalue()
            if len(data) > MAX_FILE_SIZE:
                st.error("Maximum upload size is 10 MB.")
            elif not allowed_file(uploaded.name):
                st.error("File type not allowed.")
            else:
                safe_name = secure_filename(uploaded.name) or "uploaded_file"
                stored_name = secrets.token_hex(20) + ".enc"
                nonce = os.urandom(12)
                encrypted = nonce + AESGCM(encryption_key()).encrypt(nonce, data, None)
                (UPLOAD_DIR / stored_name).write_bytes(encrypted)
                with db_connection() as con:
                    con.execute(
                        "INSERT INTO files(owner_id, original_name, stored_name, size, uploaded_at) VALUES (?, ?, ?, ?, ?)",
                        (user_id, safe_name, stored_name, len(data), now()),
                    )
                log_event(user_id, "FILE_UPLOADED", f"Uploaded {safe_name} ({len(data)} bytes)")
                st.success("File encrypted and uploaded successfully.")
                st.rerun()

    st.subheader("My files")
    if not owned:
        st.info("You have not uploaded any files yet.")
    else:
        for row in owned:
            with st.container(border=True):
                c1, c2, c3, c4 = st.columns([3, 1, 1, 1.3])
                c1.markdown(f"**📄 {row['original_name']}**")
                c1.caption(f"Uploaded {row['uploaded_at']}")
                c2.write(fmt_bytes(int(row["size"])))
                c3.write("🔒 Encrypted")
                if c4.button("Manage access", key=f"manage_{row['id']}"):
                    st.session_state.selected_file_id = int(row["id"])
                    st.session_state.page = "Share files"
                    st.rerun()
                d1, d2 = st.columns([1, 1])
                if d1.button("Download", key=f"own_download_{row['id']}"):
                    download_file(int(row["id"]), user_id)
                if d2.button("Delete", key=f"own_delete_{row['id']}"):
                    delete_file(int(row["id"]), user_id)
                    st.rerun()

    st.subheader("Shared with me")
    if not shared:
        st.info("No files have been shared with you yet.")
    else:
        for row in shared:
            with st.container(border=True):
                st.markdown(f"**📄 {row['original_name']}** · shared by **{row['owner_name']}**")
                granted = [p.title() for p in PERMISSIONS if row[f"can_{p}"]]
                st.caption("Permissions: " + (", ".join(granted) if granted else "No permissions granted"))
                c1, c2 = st.columns([1, 4])
                if row["can_download"] and c1.button("Download", key=f"shared_download_{row['id']}"):
                    download_file(int(row["id"]), user_id)
                if not row["can_download"]:
                    c1.caption("Download not permitted")

    st.subheader("Recent security activity")
    render_logs(logs)


def download_file(file_id: int, user_id: int) -> None:
    row = fetch_file_access(file_id, "download", user_id)
    if not row:
        st.error("You do not have permission to download this file.")
        return
    path = UPLOAD_DIR / row["stored_name"]
    if not path.exists():
        st.error("The encrypted file was not found in storage.")
        return
    blob = path.read_bytes()
    if len(blob) < 13:
        st.error("The encrypted file is invalid or incomplete.")
        return
    nonce, ciphertext = blob[:12], blob[12:]
    try:
        plain = AESGCM(encryption_key()).decrypt(nonce, ciphertext, None)
    except Exception:
        st.error("Decryption or authentication failed. The file may be corrupted or the encryption key may have changed.")
        return
    log_event(user_id, "FILE_DOWNLOADED", f"Downloaded {row['original_name']}")
    st.download_button(
        "Download decrypted file",
        data=plain,
        file_name=row["original_name"],
        mime="application/octet-stream",
        key=f"download_ready_{file_id}_{secrets.token_hex(3)}",
    )


def delete_file(file_id: int, user_id: int) -> None:
    row = fetch_file_access(file_id, "delete", user_id)
    if not row:
        st.error("You do not have permission to delete this file.")
        return
    (UPLOAD_DIR / row["stored_name"]).unlink(missing_ok=True)
    with db_connection() as con:
        con.execute("DELETE FROM files WHERE id = ?", (file_id,))
    log_event(user_id, "FILE_DELETED", f"Deleted {row['original_name']}")
    st.success("File deleted.")


def share_page(user_id: int) -> None:
    st.title("Share files")
    owned = get_owned_files(user_id)
    if not owned:
        st.info("Upload a file first to manage access.")
        return
    ids = [int(row["id"]) for row in owned]
    labels = {int(row["id"]): f"{row['original_name']} (#{row['id']})" for row in owned}
    default_id = st.session_state.get("selected_file_id", ids[0])
    if default_id not in ids:
        default_id = ids[0]
    file_id = st.selectbox("Select a file", ids, index=ids.index(default_id), format_func=lambda x: labels[x])
    st.session_state.selected_file_id = int(file_id)
    with db_connection() as con:
        grants = con.execute(
            """SELECT p.*, u.username, u.email FROM permissions p
               JOIN users u ON u.id = p.user_id WHERE p.file_id = ? ORDER BY u.username""",
            (file_id,),
        ).fetchall()
    st.markdown("### Grant or update permissions")
    with st.form(f"grant_form_{file_id}"):
        identity = st.text_input("Collaborator username or email")
        c1, c2, c3, c4 = st.columns(4)
        read = c1.checkbox("Read")
        write = c2.checkbox("Write")
        download = c3.checkbox("Download")
        delete = c4.checkbox("Delete")
        submitted = st.form_submit_button("Save permissions", type="primary")
    if submitted:
        target = get_user_by_identity(identity)
        if not target:
            st.error("No account found for that username or email.")
        elif int(target["id"]) == user_id:
            st.warning("You already own this file.")
        else:
            with db_connection() as con:
                con.execute(
                    """INSERT INTO permissions(file_id,user_id,can_read,can_write,can_download,can_delete,granted_at)
                       VALUES(?,?,?,?,?,?,?)
                       ON CONFLICT(file_id,user_id) DO UPDATE SET
                       can_read=excluded.can_read, can_write=excluded.can_write,
                       can_download=excluded.can_download, can_delete=excluded.can_delete,
                       granted_at=excluded.granted_at""",
                    (file_id, int(target["id"]), int(read), int(write), int(download), int(delete), now()),
                )
            log_event(user_id, "PERMISSION_GRANTED", f"Updated access for {target['username']} on file #{file_id}")
            st.success(f"Permissions saved for {target['username']}.")
            st.rerun()

    st.markdown("### Current access grants")
    if not grants:
        st.info("No collaborators have access to this file yet.")
    for grant in grants:
        with st.container(border=True):
            c1, c2 = st.columns([4, 1])
            c1.markdown(f"**{grant['username']}** · {grant['email']}")
            perms = [p.title() for p in PERMISSIONS if grant[f"can_{p}"]]
            c1.caption("Permissions: " + (", ".join(perms) if perms else "None"))
            if c2.button("Revoke", key=f"revoke_{file_id}_{grant['user_id']}"):
                with db_connection() as con:
                    con.execute("DELETE FROM permissions WHERE file_id = ? AND user_id = ?", (file_id, grant["user_id"]))
                log_event(user_id, "PERMISSION_REVOKED", f"Revoked user #{grant['user_id']} access to file #{file_id}")
                st.success("Access revoked.")
                st.rerun()
    st.caption("Note: Write is stored as a DAC permission grant for future editing functionality; an in-app file editor is not implemented in this project.")


def render_logs(rows: list[sqlite3.Row]) -> None:
    if not rows:
        st.info("No security events to display.")
        return
    st.dataframe(
        [{"Time (UTC)": r["created_at"], "Action": r["action"], "Details": r["details"]} for r in rows],
        use_container_width=True,
        hide_index=True,
    )


def audit_page() -> None:
    st.title("Security audit trail")
    st.caption("Recent application security events. The underlying SQLite audit log is application-level, not tamper-proof.")
    rows = get_all_logs(200)
    if not rows:
        st.info("No audit events have been recorded yet.")
        return
    st.dataframe(
        [{"Time (UTC)": r["created_at"], "User": r["username"] or "System", "Action": r["action"], "Details": r["details"]}
         for r in rows],
        use_container_width=True,
        hide_index=True,
    )


def main() -> None:
    load_css()
    init_db()
    if "user_id" not in st.session_state:
        login_screen()
        return

    user_id = int(st.session_state.user_id)
    with st.sidebar:
        logo_header()
        st.markdown(f"Signed in as **{st.session_state.username}**")
        st.divider()
        page = st.radio("WORKSPACE", ["Dashboard", "Share files", "Audit trail"], key="navigation")
        st.divider()
        st.caption("SECURITY")
        st.markdown("🔐 AES-256-GCM\n\n🛡️ Discretionary Access Control\n\n📋 Activity logging")
        if st.button("Sign out", use_container_width=True):
            log_event(user_id, "LOGOUT", "User signed out")
            for key in ("user_id", "username", "selected_file_id", "navigation", "page"):
                st.session_state.pop(key, None)
            st.rerun()

    if page == "Dashboard":
        dashboard_page(user_id)
    elif page == "Share files":
        share_page(user_id)
    elif page == "Audit trail":
        audit_page()

    st.markdown("<div class='ss-footer'>SecureShare · Discretionary Access Control · Python + Streamlit + AES-256-GCM</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()
