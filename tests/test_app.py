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

        self.assertEqual(table_names, [("bookings",), ("users",)])
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

    def test_10_customer_login_redirects_to_customer_area(self):
        response = self.client.post(
            "/login",
            data={"username": "customer1", "password": self.CUSTOMER_PASSWORD},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/customer")

        response = self.client.get("/customer")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Customer Area", response.data)

    def test_11_staff_login_redirects_to_staff_area(self):
        response = self.client.post(
            "/login",
            data={"username": "staff1", "password": self.STAFF_PASSWORD},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/staff")

        response = self.client.get("/staff")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Repair Staff Area", response.data)

    def test_12_customer_cannot_access_staff_area(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        response = self.client.get("/staff")
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Access denied", response.data)

    def test_13_staff_cannot_access_customer_area(self):
        self.login("staff1", self.STAFF_PASSWORD)
        response = self.client.get("/customer")
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Access denied", response.data)

    def test_14_unauthenticated_customer_area_redirects_to_login(self):
        response = self.client.get("/customer", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_15_unauthenticated_staff_area_redirects_to_login(self):
        response = self.client.get("/staff", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_16_logout_makes_each_role_area_inaccessible(self):
        role_cases = (
            ("customer1", self.CUSTOMER_PASSWORD, "/customer"),
            ("staff1", self.STAFF_PASSWORD, "/staff"),
        )
        for username, password, protected_path in role_cases:
            with self.subTest(username=username):
                self.login(username, password)
                self.client.post("/logout")

                with self.client.session_transaction() as current_session:
                    self.assertEqual(dict(current_session), {})

                response = self.client.get(protected_path, follow_redirects=False)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["Location"], "/login")

    def booking_count(self):
        with self.app.app_context():
            return get_db().execute("SELECT COUNT(*) FROM bookings").fetchone()[0]

    def valid_booking_data(self):
        return {
            "device_category": "Phone",
            "device_make_model": "Example Model",
            "issue_description": "The device does not power on.",
        }

    def test_17_customer_can_access_create_booking_form(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        response = self.client.get("/customer/bookings/create")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Create Booking", response.data)
        for category in (b"Phone", b"Tablet", b"Laptop"):
            self.assertIn(category, response.data)
        self.assertNotIn(b">Other<", response.data)

    def test_18_unauthenticated_create_booking_redirects_to_login(self):
        response = self.client.get(
            "/customer/bookings/create",
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_19_staff_get_create_booking_returns_forbidden(self):
        self.login("staff1", self.STAFF_PASSWORD)
        response = self.client.get("/customer/bookings/create")
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Access denied", response.data)

    def test_20_staff_post_create_booking_returns_forbidden_without_insert(self):
        self.login("staff1", self.STAFF_PASSWORD)
        response = self.client.post(
            "/customer/bookings/create",
            data=self.valid_booking_data(),
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Access denied", response.data)
        self.assertEqual(self.booking_count(), 0)

    def test_21_valid_customer_submission_persists_one_booking(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        response = self.client.post(
            "/customer/bookings/create",
            data=self.valid_booking_data(),
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Repair booking submitted successfully.", response.data)
        self.assertEqual(self.booking_count(), 1)

    def test_22_booking_uses_authenticated_customer_id(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        submitted_data = self.valid_booking_data()
        submitted_data.update(
            {
                "customer_id": "2",
                "status": "Completed",
                "created_at": "not-a-system-time",
                "updated_at": "not-a-system-time",
            }
        )
        self.client.post("/customer/bookings/create", data=submitted_data)

        with self.app.app_context():
            customer_id = get_db().execute(
                "SELECT id FROM users WHERE username = ?",
                ("customer1",),
            ).fetchone()["id"]
            booking = get_db().execute("SELECT * FROM bookings").fetchone()

        self.assertEqual(booking["customer_id"], customer_id)
        self.assertEqual(booking["status"], "Submitted")
        self.assertNotEqual(booking["created_at"], "not-a-system-time")
        self.assertNotEqual(booking["updated_at"], "not-a-system-time")

    def test_23_persisted_initial_status_is_submitted(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        self.client.post(
            "/customer/bookings/create",
            data=self.valid_booking_data(),
        )
        with self.app.app_context():
            status = get_db().execute(
                "SELECT status FROM bookings"
            ).fetchone()["status"]
        self.assertEqual(status, "Submitted")

    def test_24_missing_device_category_is_rejected(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        submitted_data = self.valid_booking_data()
        submitted_data["device_category"] = ""
        response = self.client.post(
            "/customer/bookings/create",
            data=submitted_data,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Device Category is required.", response.data)
        self.assertEqual(self.booking_count(), 0)

    def test_25_unsupported_device_category_is_rejected(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        submitted_data = self.valid_booking_data()
        submitted_data["device_category"] = "Other"
        response = self.client.post(
            "/customer/bookings/create",
            data=submitted_data,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Select a supported Device Category.", response.data)
        self.assertEqual(self.booking_count(), 0)

    def test_26_blank_device_make_model_is_rejected(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        submitted_data = self.valid_booking_data()
        submitted_data["device_make_model"] = "   "
        response = self.client.post(
            "/customer/bookings/create",
            data=submitted_data,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Device Make / Model is required.", response.data)
        self.assertEqual(self.booking_count(), 0)

    def test_27_blank_issue_description_is_rejected(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        submitted_data = self.valid_booking_data()
        submitted_data["issue_description"] = "\t\n"
        response = self.client.post(
            "/customer/bookings/create",
            data=submitted_data,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Issue Description is required.", response.data)
        self.assertEqual(self.booking_count(), 0)

    def test_28_invalid_submission_preserves_valid_entered_values(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        response = self.client.post(
            "/customer/bookings/create",
            data={
                "device_category": "Tablet",
                "device_make_model": "Example Tablet 10",
                "issue_description": "",
            },
        )
        self.assertIn(b'value="Tablet" selected', response.data)
        self.assertIn(b'value="Example Tablet 10"', response.data)
        self.assertEqual(self.booking_count(), 0)

    def test_29_created_and_updated_timestamps_are_populated(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        self.client.post(
            "/customer/bookings/create",
            data=self.valid_booking_data(),
        )
        with self.app.app_context():
            booking = get_db().execute(
                "SELECT created_at, updated_at FROM bookings"
            ).fetchone()
        self.assertTrue(booking["created_at"])
        self.assertTrue(booking["updated_at"])
        self.assertEqual(booking["created_at"], booking["updated_at"])

    def test_30_valid_submission_persists_all_customer_entered_fields(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        submitted_data = {
            "device_category": "Laptop",
            "device_make_model": "ExampleBook Pro",
            "issue_description": "Screen flickers after startup.",
        }
        self.client.post("/customer/bookings/create", data=submitted_data)
        with self.app.app_context():
            booking = get_db().execute(
                """
                SELECT device_category, device_make_model, issue_description
                FROM bookings
                """
            ).fetchone()
        self.assertEqual(dict(booking), submitted_data)


if __name__ == "__main__":
    unittest.main()
