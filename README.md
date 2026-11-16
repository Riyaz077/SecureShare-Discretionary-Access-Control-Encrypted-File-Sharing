# SecureShare — Discretionary Access Control & Encrypted File Sharing

A Python/Flask cybersecurity portfolio project that demonstrates **Discretionary Access Control (DAC)** through owner-managed file permissions, AES-256-GCM encryption at rest, password hashing, and security audit events.

> Internship connection: This project extends the topic stated in the Sri Tech Software Services internship certificate: **Discretionary Access Control (DAC) with Network Security and Cryptography**. It is a portfolio implementation, not a claim that this exact application was built during that internship.

## The problem

Teams exchange sensitive files, but broad or poorly managed access can expose confidential information. SecureShare gives each file owner control over who can read, download, modify (permission demonstration), or delete a file, while recording security-relevant events.

## Features

- User registration and login with Werkzeug password hashing.
- DAC: file owners grant, update, and revoke permissions for individual users.
- Per-file permissions: read, write, download, and delete.
- AES-256-GCM authenticated encryption before file bytes are written to disk.
- Decryption only after the download permission check succeeds.
- Audit trail for account creation, successful/failed login, upload, download, delete, permission changes, and denied access.
- Responsive dashboard for owned files, shared files, permission grants, and recent activity.
- SQLite database; encrypted file blobs are stored separately.

## Technology stack

Python 3.10+ · Flask · SQLite · Cryptography (AES-GCM) · Werkzeug · HTML · CSS

## Run locally

1. Install Python 3.10 or newer.
2. Open a terminal in this project directory.
3. Create a virtual environment: `python -m venv .venv`
4. Activate it:
   - Windows PowerShell: `.venv\\Scripts\\Activate.ps1`
   - macOS/Linux: `source .venv/bin/activate`
5. Install dependencies: `pip install -r requirements.txt`
6. Start the app: `python run.py`
7. Open `http://127.0.0.1:5000` in your browser.
8. Register two test accounts. Sign in as the file owner, upload a document, then use **Manage access** to share it with the second account.

On first run, a local development encryption key and SQLite database are created in `data/`. The `data/` directory is ignored by Git.

## Configuration and deployment

For any deployment, set environment variables outside the repository:

- `FLASK_SECRET_KEY`: a long, random secret used to sign sessions.
- `FILE_ENCRYPTION_KEY`: URL-safe base64 encoding of exactly 32 random bytes. Generate one with:

  ```bash
  python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
  ```

- `FLASK_DEBUG=0`

Never commit `.env`, encryption keys, the SQLite database, uploaded documents, or real user data. Back up the encryption key securely: losing it makes encrypted files unrecoverable. Use HTTPS and a production WSGI server (for example, Gunicorn) for deployment. Configure persistent storage for both the database and encrypted files on your hosting provider.

## Permission model

| Permission | Meaning in this demo |
|---|---|
| Read | Allows access to the shared file's permission context |
| Write | Stored as a DAC grant for a future in-app editor; no file editor is implemented |
| Download | Allows the application to decrypt and deliver the file |
| Delete | Allows deletion of the shared file (owners always retain full control) |

The owner always has full control. A collaborator's permissions are checked server-side for download and delete actions. The UI intentionally does not expose a file-editing feature, so `write` is currently a recorded permission rather than an implemented editor.

## Security notes and limitations

This is an educational portfolio project, not a production-certified secure file service. Before real organizational use, add CSRF protection, rate limiting, email verification, password reset, malware scanning, content-type validation, secure cookie and HTTPS configuration, stronger session controls, database migrations, backup/key-rotation procedures, and centralized/tamper-evident audit logging. The current audit trail is stored in the same SQLite database and is not tamper-proof. The demo key file is for local development only. Do not upload sensitive or real confidential documents.

## Suggested screenshots for GitHub and LinkedIn

1. Landing page — secure file sharing overview.
2. Dashboard — uploaded files, access grants, and activity.
3. Manage access — DAC permissions and collaborator list.
4. Audit trail — recorded security events.

## Suggested future enhancements

- File versioning and secure in-browser preview.
- Policy-based anomaly scoring for unusual download frequency or repeated denied access.
- Email notifications when access is granted or revoked.
- Role/group support alongside DAC.
- Automated tests and security scanning in CI.

## License

MIT — see `LICENSE`.

## Deploy on Render

Create a **Web Service** connected to this GitHub repository. Set the root directory to `.` if the repository root contains `app.py` and `requirements.txt`. Use:

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT`

Add these environment variables in Render (never commit their values):

- `FLASK_SECRET_KEY`: a long random secret.
- `FILE_ENCRYPTION_KEY`: URL-safe base64-encoded 32-byte key (generate using the command in the Configuration section above).
- `FLASK_DEBUG`: `0`

**Important demo limitation:** this app stores its SQLite database, encryption key fallback, and encrypted uploads in the local `data/` directory. Render's default filesystem is ephemeral, so accounts, uploaded files, and the locally generated key can be lost on restart, spin-down, or redeploy. The free Render web service does not support persistent disks. Treat a free deployment as a public demonstration only; do not upload sensitive documents or rely on data persistence. For durable use, migrate the database and file storage to persistent managed services, or use an eligible paid service with a persistent disk mounted at the data path and configure the app to use it.
