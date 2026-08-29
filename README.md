# Repair Service Booking

Authentication and role-access foundation for:

- **RSB-4 — FR-01 — User Logs In and Out**
- **RSB-5 — FR-02 — User Accesses Role-Appropriate Functions**

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python init_db.py
```

`init_db.py` prompts separately for the `customer1` and `staff1` passwords. Only
Werkzeug password hashes are saved in `repair_service.db`.

## Run

Set a fresh secret value in the shell that launches the application:

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Open <http://127.0.0.1:5000>. The application has no public account creation or
password recovery functionality; use one of the two pre-provisioned accounts.
Customers are directed to `/customer`, while Repair Staff are directed to
`/staff`. Attempts to access the other role's area return HTTP 403 Forbidden.

## Test

```bash
python -m unittest discover -s tests -v
```
