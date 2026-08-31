# Repair Service Booking

Authentication and role-access foundation for:

- **RSB-4 — FR-01 — User Logs In and Out**
- **RSB-5 — FR-02 — User Accesses Role-Appropriate Functions**
- **RSB-6 — FR-03 — Customer Creates a Repair Booking**
- **RSB-7 — FR-04 — Customer Views Own Booking and Current Status**
- **RSB-8 — FR-05 — Staff Reviews a Submitted Booking**
- **RSB-9 — FR-06 — Staff Updates Repair Progress**
- **RSB-10 — FR-07 — Customer Cancels an Eligible Booking**

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
Repair Staff can view only the Submitted booking queue at `/staff/bookings` and
review a submitted booking with the explicit Accept or Reject actions. The
server permits only Submitted-to-Accepted and Submitted-to-Rejected transitions;
Repair Staff can then update repair progress only from Accepted to In Progress
and from In Progress to Completed. Completed bookings are terminal; cancellation
is available only to the owning Customer while the persisted status is Submitted
or Accepted. A cancelled booking is terminal.

## Architecture

Browser → Gunicorn WSGI server → Flask server-rendered Jinja application →
Python `sqlite3` → SQLite database. On EC2, systemd manages the persistent
Gunicorn process.

## Test

```bash
python -m unittest discover -s tests -v
```

## EC2 deployment

The application is deployed on Ubuntu EC2 with Gunicorn and a separately
configured `repair-service-booking.service`. From the cloned repository:

Current EC2 public URL: <http://3.106.226.72:5000/>. This public IPv4 address
may change if the instance is stopped and started because no Elastic IP is
configured.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python init_db.py
```

Keep the fixed Flask secret outside the repository. On EC2 the systemd service
reads `/home/ubuntu/.config/repair-service-booking.env` through
`EnvironmentFile`; that file contains a locally generated `SECRET_KEY` value
and should be readable only by its owner. Never commit it.

For an interactive verification while the virtual environment is active:

```bash
set -a
source /home/ubuntu/.config/repair-service-booking.env
set +a
gunicorn --workers 1 --bind 0.0.0.0:5000 'app:create_app()'
```

The EC2 systemd unit runs the same Gunicorn command persistently, uses
`Restart=on-failure`, and reads the external `EnvironmentFile`. After the unit
has been installed or changed, use:

```bash
sudo systemctl daemon-reload
sudo systemctl start repair-service-booking
sudo systemctl status repair-service-booking
sudo systemctl enable repair-service-booking
```

Allow the selected application port (`TCP 5000` for this deployment) in the EC2
Security Group from the required source range before testing the public IPv4
address. Do not commit secrets, passwords, the SQLite runtime database,
environment files, or private keys.

## Known limitations

- The deployment uses a single EC2 instance.
- SQLite is appropriate for this small assessment application, but is not
  intended for high-concurrency production use.
- Only the two pre-provisioned demo roles/accounts are supported; there is no
  public registration or password recovery.
- The deployment currently uses HTTP rather than HTTPS.
- The public IPv4 address may change after an EC2 stop/start because no Elastic
  IP is configured.
