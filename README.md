# Repair Service Booking

Authentication and role-access foundation for:

- **RSB-4 — FR-01 — User Logs In and Out**
- **RSB-5 — FR-02 — User Accesses Role-Appropriate Functions**
- **RSB-6 — FR-03 — Customer Creates a Repair Booking**
- **RSB-7 — FR-04 — Customer Views Own Booking and Current Status**

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
Customers can create a booking at `/customer/bookings/create` using the frozen
Device Category options Phone, Tablet, or Laptop. New bookings are associated
with the authenticated Customer and start in the Submitted state.
Customers can view only their own bookings at `/customer/bookings` and open
their own read-only booking details. Ownership filtering is enforced in SQLite
queries using the authenticated Customer ID.

## Test

```bash
python -m unittest discover -s tests -v
```
