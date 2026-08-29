import sqlite3
import tempfile
import unittest
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

from app import create_app
from db import get_db, init_db


class AuthenticationTests(unittest.TestCase):
    CUSTOMER_PASSWORD = "customer-test-password"
    STAFF_PASSWORD = "staff-test-password"

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "test.db"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-only-secret",
                "DATABASE": str(self.database_path),
            }
        )
        with self.app.app_context():
            init_db()
            database = get_db()
            database.executemany(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (
                    (
                        "customer1",
                        generate_password_hash(self.CUSTOMER_PASSWORD),
                        "Customer",
                    ),
                    (
                        "staff1",
                        generate_password_hash(self.STAFF_PASSWORD),
                        "Repair Staff",
                    ),
                ),
            )
            database.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def login(self, username, password):
        return self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )

    def test_1_customer_valid_login_succeeds(self):
        response = self.login("customer1", self.CUSTOMER_PASSWORD)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Logged in successfully", response.data)
        self.assertIn(b"customer1", response.data)
        self.assertIn(b"Customer", response.data)
        with self.client.session_transaction() as current_session:
            self.assertEqual(set(current_session), {"user_id"})

    def test_2_staff_valid_login_succeeds(self):
        response = self.login("staff1", self.STAFF_PASSWORD)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Logged in successfully", response.data)
        self.assertIn(b"staff1", response.data)
        self.assertIn(b"Repair Staff", response.data)

    def test_3_invalid_password_is_rejected_with_feedback(self):
        response = self.login("customer1", "wrong-password")
        self.assertIn(b"Invalid username or password.", response.data)
        with self.client.session_transaction() as current_session:
            self.assertNotIn("user_id", current_session)

    def test_4_unknown_username_is_rejected(self):
        response = self.login("unknown-user", "some-password")
        self.assertIn(b"Invalid username or password.", response.data)
        with self.client.session_transaction() as current_session:
            self.assertNotIn("user_id", current_session)

    def test_5_unauthenticated_root_redirects_to_login(self):
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_6_logout_clears_session_and_returns_to_login(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        response = self.client.post("/logout", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Log In", response.data)
        with self.client.session_transaction() as current_session:
            self.assertEqual(dict(current_session), {})

    def test_7_root_after_logout_redirects_to_login(self):
        self.login("staff1", self.STAFF_PASSWORD)
        self.client.post("/logout")
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_8_database_contains_hashes_not_plaintext_passwords(self):
        connection = sqlite3.connect(self.database_path)
        table_names = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
        rows = connection.execute(
            "SELECT username, password_hash FROM users ORDER BY username"
        ).fetchall()
        connection.close()

        self.assertEqual(table_names, [("users",)])
        stored_hashes = {username: password_hash for username, password_hash in rows}
        self.assertNotEqual(stored_hashes["customer1"], self.CUSTOMER_PASSWORD)
        self.assertNotEqual(stored_hashes["staff1"], self.STAFF_PASSWORD)
        self.assertTrue(
            check_password_hash(stored_hashes["customer1"], self.CUSTOMER_PASSWORD)
        )
        self.assertTrue(
            check_password_hash(stored_hashes["staff1"], self.STAFF_PASSWORD)
        )

    def test_9_stale_user_session_is_cleared_and_redirected_to_login(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        with self.client.session_transaction() as current_session:
            self.assertIn("user_id", current_session)
            user_id = current_session["user_id"]

        with self.app.app_context():
            database = get_db()
            database.execute("DELETE FROM users WHERE id = ?", (user_id,))
            database.commit()

        response = self.client.get("/", follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")
        with self.client.session_transaction() as current_session:
            self.assertEqual(dict(current_session), {})


if __name__ == "__main__":
    unittest.main()
