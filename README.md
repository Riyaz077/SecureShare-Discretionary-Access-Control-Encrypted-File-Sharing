# SecureShare — Streamlit Edition

A Streamlit migration of the original SecureShare Flask project. It retains the existing SQLite schema and the original security workflow: Werkzeug password hashing, AES-256-GCM encrypted file blobs, owner-managed DAC permissions, download/delete authorization checks, and audit events.

## Run locally (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
# or use the included launcher
python run.py
```

Open the URL printed by Streamlit (normally http://localhost:8501).

## Run locally (macOS/Linux)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Features

- Register and sign in using username/email and password.
- Passwords are stored using Werkzeug's password hashing.
- Upload allowed file types up to 10 MB.
- Encrypt uploaded file contents using AES-256-GCM before writing the blob to disk.
- Download only after owner or DAC `download` authorization succeeds.
- Owners can grant/update/revoke `read`, `write`, `download`, and `delete` permissions for another registered user.
- Delete operations are checked against owner status or DAC `delete` permission.
- View owned files, files shared with the signed-in user, dashboard counts, and audit events.

The `write` permission is stored as a DAC grant, as in the original project, but an in-app file editor is not implemented.

## Encryption key

For local development, the app creates `data/dev_encryption_key.txt` on first run if `FILE_ENCRYPTION_KEY` is not set. Back up this key securely. Losing or changing it makes existing encrypted files undecryptable.

For Streamlit Community Cloud, add `FILE_ENCRYPTION_KEY` under **App settings → Secrets**. Generate a key with:

```bash
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Paste the generated value as a secret:

```toml
FILE_ENCRYPTION_KEY = "paste-generated-value-here"
```

## Important deployment limitation

This starter retains SQLite and local encrypted-file storage to stay close to the original Flask app. Streamlit Community Cloud's local filesystem is not durable across all restarts/redeployments. Treat the hosted version as a demo only; do not store important or confidential files there. For persistent use, migrate the database and encrypted blobs to durable managed services and back up the encryption key.

## Existing database compatibility

The app uses the same `users`, `files`, `permissions`, and `audit_logs` SQLite table layout as the original Flask source. If you copy an existing `data/secureshare.db` into this project, the same accounts and permission records can be reused. Copy the matching encrypted blobs and the exact original encryption key as well; otherwise previously uploaded files cannot be decrypted.

## Security scope

This is an educational portfolio project, not a production-certified file-sharing service. Before handling real confidential data, add rate limiting, CSRF-equivalent protections for state-changing actions, secure persistent storage, malware scanning, robust backup/key rotation, and independent security testing.
