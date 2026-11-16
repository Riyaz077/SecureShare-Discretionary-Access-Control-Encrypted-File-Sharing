import os, io, sqlite3, secrets, base64
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
UPLOAD_DIR = DATA_DIR / 'encrypted_files'
DB_PATH = DATA_DIR / 'secureshare.db'
ALLOWED_EXTENSIONS = {'pdf','txt','csv','doc','docx','xls','xlsx','png','jpg','jpeg','zip'}
MAX_FILE_SIZE = 10 * 1024 * 1024

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'change-this-development-secret-key')
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
DATA_DIR.mkdir(exist_ok=True); UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def encryption_key():
    raw = os.environ.get('FILE_ENCRYPTION_KEY')
    if not raw:
        key_file = DATA_DIR / 'dev_encryption_key.txt'
        if not key_file.exists():
            key_file.write_text(base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode())
        raw = key_file.read_text().strip()
    try:
        key = base64.urlsafe_b64decode(raw)
        if len(key) != 32: raise ValueError
        return key
    except Exception as exc:
        raise RuntimeError('FILE_ENCRYPTION_KEY must be a URL-safe base64 encoded 32-byte key.') from exc


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_db():
    with db() as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL,
            original_name TEXT NOT NULL, stored_name TEXT UNIQUE NOT NULL,
            size INTEGER NOT NULL, uploaded_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL, can_read INTEGER DEFAULT 0,
            can_write INTEGER DEFAULT 0, can_download INTEGER DEFAULT 0,
            can_delete INTEGER DEFAULT 0, granted_at TEXT NOT NULL,
            UNIQUE(file_id,user_id),
            FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER,
            action TEXT NOT NULL, details TEXT NOT NULL, ip_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE SET NULL
        );
        ''')


def now(): return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

def log_event(actor_id, action, details):
    with db() as con:
        con.execute('INSERT INTO audit_logs(actor_id,action,details,ip_address,created_at) VALUES(?,?,?,?,?)',
                    (actor_id, action, details[:500], request.remote_addr, now()))

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please sign in to continue.', 'warning'); return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapped

def allowed_file(name):
    return '.' in name and name.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def file_access(file_id, permission):
    with db() as con:
        row = con.execute('''SELECT f.*, p.can_read,p.can_write,p.can_download,p.can_delete
            FROM files f LEFT JOIN permissions p ON p.file_id=f.id AND p.user_id=? WHERE f.id=?''',
            (session['user_id'],file_id)).fetchone()
    if not row: abort(404)
    if row['owner_id'] == session['user_id']: return row
    if not row[f'can_{permission}']:
        log_event(session['user_id'], 'ACCESS_DENIED', f'{permission} denied for file #{file_id}')
        abort(403)
    return row

@app.route('/')
def index():
    if 'user_id' not in session: return render_template('landing.html')
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username=request.form.get('username','').strip(); email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
        if len(username)<3 or len(password)<8 or '@' not in email:
            flash('Use a username (3+ characters), valid email, and password (8+ characters).','danger')
        else:
            try:
                with db() as con:
                    cur=con.execute('INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)',
                        (username,email,generate_password_hash(password),now()))
                    uid=cur.lastrowid
                log_event(uid,'ACCOUNT_CREATED',f'Account created for {username}')
                flash('Account created. You can now sign in.','success'); return redirect(url_for('login'))
            except sqlite3.IntegrityError: flash('That username or email is already registered.','danger')
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        identity=request.form.get('identity','').strip()
        with db() as con: user=con.execute('SELECT * FROM users WHERE username=? OR email=?',(identity,identity.lower())).fetchone()
        if user and check_password_hash(user['password_hash'],request.form.get('password','')):
            session.clear(); session['user_id']=user['id']; session['username']=user['username']
            log_event(user['id'],'LOGIN_SUCCESS','Successful sign-in'); return redirect(url_for('dashboard'))
        log_event(user['id'] if user else None,'LOGIN_FAILED',f'Failed sign-in attempt for {identity}')
        flash('Invalid username/email or password.','danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    uid=session['user_id']; log_event(uid,'LOGOUT','User signed out'); session.clear(); return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    uid=session['user_id']
    with db() as con:
        owned=con.execute('SELECT * FROM files WHERE owner_id=? ORDER BY uploaded_at DESC',(uid,)).fetchall()
        shared=con.execute('''SELECT f.*,u.username AS owner_name,p.can_read,p.can_write,p.can_download,p.can_delete
          FROM permissions p JOIN files f ON f.id=p.file_id JOIN users u ON u.id=f.owner_id
          WHERE p.user_id=? ORDER BY p.granted_at DESC''',(uid,)).fetchall()
        logs=con.execute('SELECT * FROM audit_logs WHERE actor_id=? ORDER BY id DESC LIMIT 8',(uid,)).fetchall()
        counts=con.execute('SELECT COUNT(*) FROM files WHERE owner_id=?',(uid,)).fetchone()[0]
        grants=con.execute('SELECT COUNT(*) FROM permissions p JOIN files f ON f.id=p.file_id WHERE f.owner_id=?',(uid,)).fetchone()[0]
    return render_template('dashboard.html',owned=owned,shared=shared,logs=logs,file_count=counts,grant_count=grants)

@app.route('/upload',methods=['POST'])
@login_required
def upload():
    f=request.files.get('file')
    if not f or not f.filename: flash('Choose a file first.','warning'); return redirect(url_for('dashboard'))
    if not allowed_file(f.filename): flash('File type not allowed. See the README for supported formats.','danger'); return redirect(url_for('dashboard'))
    data=f.read(MAX_FILE_SIZE+1)
    if len(data)>MAX_FILE_SIZE: flash('Maximum upload size is 10 MB.','danger'); return redirect(url_for('dashboard'))
    safe=secure_filename(f.filename)
    stored=secrets.token_hex(20)+'.enc'; nonce=os.urandom(12)
    encrypted=nonce+AESGCM(encryption_key()).encrypt(nonce,data,None)
    (UPLOAD_DIR/stored).write_bytes(encrypted)
    with db() as con:
        con.execute('INSERT INTO files(owner_id,original_name,stored_name,size,uploaded_at) VALUES(?,?,?,?,?)',
                    (session['user_id'],safe,stored,len(data),now()))
    log_event(session['user_id'],'FILE_UPLOADED',f'Uploaded {safe} ({len(data)} bytes)')
    flash('File encrypted and uploaded successfully.','success'); return redirect(url_for('dashboard'))

@app.route('/file/<int:file_id>/download')
@login_required
def download(file_id):
    row=file_access(file_id,'download')
    path=UPLOAD_DIR/row['stored_name']
    if not path.exists(): abort(404)
    blob=path.read_bytes(); nonce, ciphertext=blob[:12],blob[12:]
    try: plain=AESGCM(encryption_key()).decrypt(nonce,ciphertext,None)
    except Exception: abort(500)
    log_event(session['user_id'],'FILE_DOWNLOADED',f'Downloaded {row["original_name"]}')
    return send_file(io.BytesIO(plain),as_attachment=True,download_name=row['original_name'])

@app.route('/file/<int:file_id>/delete',methods=['POST'])
@login_required
def delete_file(file_id):
    row=file_access(file_id,'delete')
    (UPLOAD_DIR/row['stored_name']).unlink(missing_ok=True)
    with db() as con: con.execute('DELETE FROM files WHERE id=?',(file_id,))
    log_event(session['user_id'],'FILE_DELETED',f'Deleted {row["original_name"]}')
    flash('File deleted.','success'); return redirect(url_for('dashboard'))

@app.route('/file/<int:file_id>/share',methods=['GET','POST'])
@login_required
def share(file_id):
    row=file_access(file_id,'read')
    if row['owner_id'] != session['user_id']: abort(403)
    with db() as con:
        grants=con.execute('''SELECT p.*,u.username,u.email FROM permissions p JOIN users u ON u.id=p.user_id WHERE p.file_id=?''',(file_id,)).fetchall()
    if request.method=='POST':
        identity=request.form.get('identity','').strip()
        with db() as con: target=con.execute('SELECT * FROM users WHERE username=? OR email=?',(identity,identity.lower())).fetchone()
        if not target: flash('No account found for that username or email.','danger')
        elif target['id']==session['user_id']: flash('You already own this file.','warning')
        else:
            flags=[int(request.form.get(k)=='on') for k in ('read','write','download','delete')]
            with db() as con:
                con.execute('''INSERT INTO permissions(file_id,user_id,can_read,can_write,can_download,can_delete,granted_at)
                  VALUES(?,?,?,?,?,?,?) ON CONFLICT(file_id,user_id) DO UPDATE SET can_read=excluded.can_read,
                  can_write=excluded.can_write,can_download=excluded.can_download,can_delete=excluded.can_delete,granted_at=excluded.granted_at''',
                  (file_id,target['id'],*flags,now()))
            log_event(session['user_id'],'PERMISSION_GRANTED',f'Updated access for {target["username"]} on {row["original_name"]}')
            flash('Permissions saved.','success'); return redirect(url_for('share',file_id=file_id))
    return render_template('share.html',file=row,grants=grants)

@app.route('/file/<int:file_id>/revoke/<int:user_id>',methods=['POST'])
@login_required
def revoke(file_id,user_id):
    with db() as con:
        owner=con.execute('SELECT * FROM files WHERE id=? AND owner_id=?',(file_id,session['user_id'])).fetchone()
        if not owner: abort(403)
        con.execute('DELETE FROM permissions WHERE file_id=? AND user_id=?',(file_id,user_id))
    log_event(session['user_id'],'PERMISSION_REVOKED',f'Revoked user #{user_id} access to file #{file_id}')
    flash('Access revoked.','success'); return redirect(url_for('share',file_id=file_id))

@app.route('/audit')
@login_required
def audit():
    with db() as con:
        logs=con.execute('''SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 200''').fetchall()
    return render_template('audit.html',logs=logs)

@app.errorhandler(403)
def forbidden(_): return render_template('error.html',code=403,message='You do not have permission to perform this action.'),403
@app.errorhandler(404)
def not_found(_): return render_template('error.html',code=404,message='The requested resource was not found.'),404

init_db()
if __name__=='__main__': app.run(debug=os.environ.get('FLASK_DEBUG')=='1')
