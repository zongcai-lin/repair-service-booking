from getpass import getpass
import secrets

from werkzeug.security import generate_password_hash

from app import create_app
from db import get_db, init_db


DEMO_USERS = (
    ("customer1", "Customer"),
    ("staff1", "Repair Staff"),
)


def prompt_for_password(username):
    while True:
        password = getpass(f"Password for {username}: ")
        if not password:
            print("Password cannot be empty.")
            continue
        if password != getpass(f"Confirm password for {username}: "):
            print("Passwords do not match.")
            continue
        return password


def main():
    passwords = {
        username: prompt_for_password(username) for username, _role in DEMO_USERS
    }

    # Database provisioning does not start the web server or create user sessions.
    # Supply an ephemeral key so setup does not depend on the production secret.
    app = create_app({"SECRET_KEY": secrets.token_hex(32)})
    with app.app_context():
        init_db()
        database = get_db()
        for username, role in DEMO_USERS:
            database.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_hash = excluded.password_hash,
                    role = excluded.role
                """,
                (username, generate_password_hash(passwords[username]), role),
            )
        database.commit()

    print("Database initialised with customer1 and staff1.")


if __name__ == "__main__":
    main()
