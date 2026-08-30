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

    def user_id_for(self, username):
        with self.app.app_context():
            return get_db().execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()["id"]

    def insert_test_booking(
        self,
        customer_id,
        device_make_model="Owned Test Device",
        status="Submitted",
    ):
        with self.app.app_context():
            database = get_db()
            cursor = database.execute(
                """
                INSERT INTO bookings (
                    customer_id,
                    device_category,
                    device_make_model,
                    issue_description,
                    status
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    customer_id,
                    "Phone",
                    device_make_model,
                    "Test issue description",
                    status,
                ),
            )
            database.commit()
            return cursor.lastrowid

    def booking_for(self, booking_id):
        with self.app.app_context():
            return get_db().execute(
                "SELECT * FROM bookings WHERE id = ?",
                (booking_id,),
            ).fetchone()

    def set_booking_timestamps(self, booking_id, timestamp):
        # A fixed historical value makes the RSB-8 updated_at assertion
        # deterministic even when SQLite operations occur in the same second.
        with self.app.app_context():
            database = get_db()
            database.execute(
                """
                UPDATE bookings
                SET created_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (timestamp, timestamp, booking_id),
            )
            database.commit()

    def create_test_only_customer(self):
        # RSB-7 ownership evidence needs two owners, but customer2 exists only
        # inside this isolated test database and is never runtime provisioning.
        with self.app.app_context():
            database = get_db()
            cursor = database.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (
                    "customer2",
                    generate_password_hash("test-only-password"),
                    "Customer",
                ),
            )
            database.commit()
            return cursor.lastrowid

    def test_31_customer_can_access_my_bookings(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        response = self.client.get("/customer/bookings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"My Bookings", response.data)

    def test_32_unauthenticated_booking_views_redirect_to_login(self):
        for path in ("/customer/bookings", "/customer/bookings/1"):
            with self.subTest(path=path):
                response = self.client.get(path, follow_redirects=False)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["Location"], "/login")

    def test_33_staff_booking_views_return_forbidden(self):
        self.login("staff1", self.STAFF_PASSWORD)
        for path in ("/customer/bookings", "/customer/bookings/1"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 403)
                self.assertIn(b"Access denied", response.data)

    def test_34_customer_sees_booking_created_through_real_route(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        self.client.post(
            "/customer/bookings/create",
            data={
                "device_category": "Laptop",
                "device_make_model": "Visible ExampleBook",
                "issue_description": "Visible test issue",
            },
        )
        response = self.client.get("/customer/bookings")
        self.assertIn(b"Visible ExampleBook", response.data)
        self.assertIn(b"Submitted", response.data)

    def test_35_views_show_current_persisted_status(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id, status="In Progress")
        self.login("customer1", self.CUSTOMER_PASSWORD)

        list_response = self.client.get("/customer/bookings")
        detail_response = self.client.get(f"/customer/bookings/{booking_id}")
        self.assertIn(b"In Progress", list_response.data)
        self.assertIn(b"In Progress", detail_response.data)

    def test_36_booking_list_contains_only_authenticated_customer_rows(self):
        customer1_id = self.user_id_for("customer1")
        customer2_id = self.create_test_only_customer()
        self.insert_test_booking(customer1_id, "Customer One Device")
        self.insert_test_booking(customer2_id, "Customer Two Private Device")
        self.login("customer1", self.CUSTOMER_PASSWORD)

        response = self.client.get("/customer/bookings")
        self.assertIn(b"Customer One Device", response.data)
        self.assertNotIn(b"Customer Two Private Device", response.data)

    def test_37_customer_can_open_own_booking_details(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id, "Detail Test Device")
        self.login("customer1", self.CUSTOMER_PASSWORD)

        response = self.client.get(f"/customer/bookings/{booking_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Detail Test Device", response.data)
        self.assertIn(b"Test issue description", response.data)
        self.assertIn(b"Submitted", response.data)

    def test_38_customer_cannot_access_another_customer_booking(self):
        customer2_id = self.create_test_only_customer()
        booking_id = self.insert_test_booking(
            customer2_id,
            "Private Customer Two Device",
        )
        self.login("customer1", self.CUSTOMER_PASSWORD)

        response = self.client.get(f"/customer/bookings/{booking_id}")
        self.assertEqual(response.status_code, 404)
        self.assertIn(b"Booking not found", response.data)
        self.assertNotIn(b"Private Customer Two Device", response.data)

    def test_39_customer_without_bookings_sees_empty_state(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        response = self.client.get("/customer/bookings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No repair bookings yet", response.data)

    def test_40_viewing_routes_do_not_change_booking_data(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id, "Read Only Device")
        with self.app.app_context():
            before = tuple(
                get_db().execute(
                    "SELECT * FROM bookings WHERE id = ?",
                    (booking_id,),
                ).fetchone()
            )

        self.login("customer1", self.CUSTOMER_PASSWORD)
        self.client.get("/customer/bookings")
        self.client.get(f"/customer/bookings/{booking_id}")

        with self.app.app_context():
            after = tuple(
                get_db().execute(
                    "SELECT * FROM bookings WHERE id = ?",
                    (booking_id,),
                ).fetchone()
            )
        self.assertEqual(after, before)

    def test_41_staff_can_access_submitted_bookings_queue(self):
        self.login("staff1", self.STAFF_PASSWORD)
        response = self.client.get("/staff/bookings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Submitted Bookings", response.data)

    def test_42_unauthenticated_staff_queue_redirects_to_login(self):
        response = self.client.get("/staff/bookings", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_43_customer_cannot_access_staff_queue(self):
        self.login("customer1", self.CUSTOMER_PASSWORD)
        response = self.client.get("/staff/bookings")
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Access denied", response.data)

    def test_44_staff_can_open_submitted_booking_for_review(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id, "Reviewable Device")
        self.login("staff1", self.STAFF_PASSWORD)

        response = self.client.get(f"/staff/bookings/{booking_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Reviewable Device", response.data)
        self.assertIn(b"Accept", response.data)
        self.assertIn(b"Reject", response.data)

    def test_45_customer_cannot_open_staff_review_page(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id)
        self.login("customer1", self.CUSTOMER_PASSWORD)

        response = self.client.get(f"/staff/bookings/{booking_id}")
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"Access denied", response.data)

    def test_46_staff_queue_displays_submitted_bookings(self):
        customer_id = self.user_id_for("customer1")
        self.insert_test_booking(customer_id, "Submitted Queue Device")
        self.login("staff1", self.STAFF_PASSWORD)

        response = self.client.get("/staff/bookings")
        self.assertIn(b"Submitted Queue Device", response.data)
        self.assertIn(b"Submitted", response.data)

    def test_47_staff_queue_excludes_accepted_and_rejected_bookings(self):
        customer_id = self.user_id_for("customer1")
        self.insert_test_booking(customer_id, "Accepted Queue Device", "Accepted")
        self.insert_test_booking(customer_id, "Rejected Queue Device", "Rejected")
        self.login("staff1", self.STAFF_PASSWORD)

        response = self.client.get("/staff/bookings")
        self.assertNotIn(b"Accepted Queue Device", response.data)
        self.assertNotIn(b"Rejected Queue Device", response.data)

    def test_48_staff_can_accept_submitted_booking(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id)
        self.login("staff1", self.STAFF_PASSWORD)

        response = self.client.post(
            f"/staff/bookings/{booking_id}/review",
            data={"action": "accept"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.booking_for(booking_id)["status"], "Accepted")

    def test_49_accept_persists_exact_accepted_status(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id)
        self.login("staff1", self.STAFF_PASSWORD)
        self.client.post(
            f"/staff/bookings/{booking_id}/review",
            data={"action": "accept"},
        )

        self.assertEqual(self.booking_for(booking_id)["status"], "Accepted")

    def test_50_accept_preserves_created_at_and_refreshes_updated_at(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id)
        original_time = "2000-01-01 00:00:00"
        self.set_booking_timestamps(booking_id, original_time)
        self.login("staff1", self.STAFF_PASSWORD)
        self.client.post(
            f"/staff/bookings/{booking_id}/review",
            data={"action": "accept"},
        )

        booking = self.booking_for(booking_id)
        self.assertEqual(booking["created_at"], original_time)
        self.assertNotEqual(booking["updated_at"], original_time)

    def test_51_staff_can_reject_submitted_booking(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id)
        self.login("staff1", self.STAFF_PASSWORD)

        response = self.client.post(
            f"/staff/bookings/{booking_id}/review",
            data={"action": "reject"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.booking_for(booking_id)["status"], "Rejected")

    def test_52_reject_persists_exact_rejected_status(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id)
        self.login("staff1", self.STAFF_PASSWORD)
        self.client.post(
            f"/staff/bookings/{booking_id}/review",
            data={"action": "reject"},
        )

        self.assertEqual(self.booking_for(booking_id)["status"], "Rejected")

    def test_53_reject_preserves_created_at_and_refreshes_updated_at(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id)
        original_time = "2000-01-01 00:00:00"
        self.set_booking_timestamps(booking_id, original_time)
        self.login("staff1", self.STAFF_PASSWORD)
        self.client.post(
            f"/staff/bookings/{booking_id}/review",
            data={"action": "reject"},
        )

        booking = self.booking_for(booking_id)
        self.assertEqual(booking["created_at"], original_time)
        self.assertNotEqual(booking["updated_at"], original_time)

    def test_54_customer_cannot_post_accept_or_reject(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id)
        self.login("customer1", self.CUSTOMER_PASSWORD)

        for action in ("accept", "reject"):
            with self.subTest(action=action):
                response = self.client.post(
                    f"/staff/bookings/{booking_id}/review",
                    data={"action": action},
                )
                self.assertEqual(response.status_code, 403)
                self.assertEqual(self.booking_for(booking_id)["status"], "Submitted")

    def test_55_arbitrary_actions_cannot_set_other_workflow_states(self):
        customer_id = self.user_id_for("customer1")
        self.login("staff1", self.STAFF_PASSWORD)

        for attempted_action in ("In Progress", "Completed", "Cancelled", "other"):
            with self.subTest(attempted_action=attempted_action):
                booking_id = self.insert_test_booking(customer_id)
                response = self.client.post(
                    f"/staff/bookings/{booking_id}/review",
                    data={"action": attempted_action, "status": attempted_action},
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.booking_for(booking_id)["status"], "Submitted")

    def test_56_accepted_booking_cannot_be_reviewed_again(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id, status="Accepted")
        before = tuple(self.booking_for(booking_id))
        self.login("staff1", self.STAFF_PASSWORD)

        response = self.client.post(
            f"/staff/bookings/{booking_id}/review",
            data={"action": "reject"},
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(tuple(self.booking_for(booking_id)), before)

    def test_57_rejected_booking_cannot_be_reviewed_again(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id, status="Rejected")
        before = tuple(self.booking_for(booking_id))
        self.login("staff1", self.STAFF_PASSWORD)

        response = self.client.post(
            f"/staff/bookings/{booking_id}/review",
            data={"action": "accept"},
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(tuple(self.booking_for(booking_id)), before)

    def test_58_failed_review_leaves_booking_unchanged(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id, status="Accepted")
        before = tuple(self.booking_for(booking_id))
        self.login("staff1", self.STAFF_PASSWORD)

        self.client.post(
            f"/staff/bookings/{booking_id}/review",
            data={"action": "Completed"},
        )
        self.assertEqual(tuple(self.booking_for(booking_id)), before)

    def test_59_customer_view_displays_accepted_after_staff_review(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id, "Accepted Customer View")
        self.login("staff1", self.STAFF_PASSWORD)
        self.client.post(
            f"/staff/bookings/{booking_id}/review",
            data={"action": "accept"},
        )
        self.client.post("/logout")
        self.login("customer1", self.CUSTOMER_PASSWORD)

        response = self.client.get(f"/customer/bookings/{booking_id}")
        self.assertIn(b"Accepted", response.data)

    def test_60_customer_view_displays_rejected_after_staff_review(self):
        customer_id = self.user_id_for("customer1")
        booking_id = self.insert_test_booking(customer_id, "Rejected Customer View")
        self.login("staff1", self.STAFF_PASSWORD)
        self.client.post(
            f"/staff/bookings/{booking_id}/review",
            data={"action": "reject"},
        )
        self.client.post("/logout")
        self.login("customer1", self.CUSTOMER_PASSWORD)

        response = self.client.get(f"/customer/bookings/{booking_id}")
        self.assertIn(b"Rejected", response.data)


if __name__ == "__main__":
    unittest.main()
