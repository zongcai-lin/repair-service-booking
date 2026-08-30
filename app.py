import os
from pathlib import Path

from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from db import get_db, init_app as init_db_app


DEVICE_CATEGORIES = ("Phone", "Tablet", "Laptop")


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE=str(Path(app.root_path) / "repair_service.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    if test_config is None:
        secret_key = os.environ.get("SECRET_KEY")
        if not secret_key:
            raise RuntimeError("SECRET_KEY environment variable is required.")
        app.config["SECRET_KEY"] = secret_key
    else:
        app.config.from_mapping(test_config)

    init_db_app(app)

    def load_current_user():
        user_id = session.get("user_id")
        if user_id is None:
            return None

        user = get_db().execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if user is None:
            session.clear()
        return user

    def show_role_area(
        required_role,
        area_title,
        show_create_booking=False,
        show_my_bookings=False,
        success_message=None,
    ):
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != required_role:
            return render_template("access_denied.html"), 403
        return render_template(
            "authenticated.html",
            area_title=area_title,
            show_create_booking=show_create_booking,
            show_my_bookings=show_my_bookings,
            success_message=success_message,
            user=user,
        )

    @app.route("/login", methods=("GET", "POST"))
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if user is None or not check_password_hash(user["password_hash"], password):
                session.clear()
                return render_template(
                    "login.html",
                    error="Invalid username or password.",
                    username=username,
                )

            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))

        if session.get("user_id") is not None:
            return redirect(url_for("index"))
        return render_template("login.html")

    @app.get("/")
    def index():
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] == "Customer":
            return redirect(url_for("customer"))
        if user["role"] == "Repair Staff":
            return redirect(url_for("staff"))
        return render_template("access_denied.html"), 403

    @app.get("/customer")
    def customer():
        success_message = None
        if request.args.get("booking_created") == "1":
            success_message = "Repair booking submitted successfully."
        return show_role_area(
            "Customer",
            "Customer Area",
            show_create_booking=True,
            show_my_bookings=True,
            success_message=success_message,
        )

    @app.get("/staff")
    def staff():
        return show_role_area("Repair Staff", "Repair Staff Area")

    @app.route("/customer/bookings/create", methods=("GET", "POST"))
    def create_booking():
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "Customer":
            return render_template("access_denied.html"), 403

        form_values = {
            "device_category": request.form.get("device_category", ""),
            "device_make_model": request.form.get("device_make_model", ""),
            "issue_description": request.form.get("issue_description", ""),
        }
        errors = {}

        if request.method == "POST":
            if not form_values["device_category"]:
                errors["device_category"] = "Device Category is required."
            elif form_values["device_category"] not in DEVICE_CATEGORIES:
                errors["device_category"] = "Select a supported Device Category."

            if not form_values["device_make_model"].strip():
                errors["device_make_model"] = "Device Make / Model is required."

            if not form_values["issue_description"].strip():
                errors["issue_description"] = "Issue Description is required."

            if not errors:
                database = get_db()
                database.execute(
                    """
                    INSERT INTO bookings (
                        customer_id,
                        device_category,
                        device_make_model,
                        issue_description
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        user["id"],
                        form_values["device_category"],
                        form_values["device_make_model"].strip(),
                        form_values["issue_description"].strip(),
                    ),
                )
                database.commit()
                return redirect(url_for("customer", booking_created="1"))

        return render_template(
            "create_booking.html",
            categories=DEVICE_CATEGORIES,
            errors=errors,
            form_values=form_values,
            user=user,
        )

    @app.get("/customer/bookings")
    def my_bookings():
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))

        # RSB-5 role rule: Customer viewing routes enforce access on the server;
        # hiding their links from Staff would not prevent a direct URL request.
        if user["role"] != "Customer":
            return render_template("access_denied.html"), 403

        # RSB-7 / BR-01: Apply the authenticated Customer ID in the database
        # query so another Customer's rows never reach the template or browser.
        bookings = get_db().execute(
            """
            SELECT id, device_category, device_make_model, status, created_at
            FROM bookings
            WHERE customer_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            (user["id"],),
        ).fetchall()

        # RSB-7 is read-only: persisted status is displayed as queried, while
        # cancellation and status-transition controls remain for later stories.
        return render_template("my_bookings.html", bookings=bookings, user=user)

    @app.get("/customer/bookings/<int:booking_id>")
    def booking_detail(booking_id):
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))

        # RSB-5 role rule: Staff cannot use Customer booking-detail routes even
        # when they know a valid booking identifier.
        if user["role"] != "Customer":
            return render_template("access_denied.html"), 403

        # RSB-7 / BR-01: Combining booking ID and authenticated owner ID in one
        # query prevents another Customer's data from ever being returned.
        booking = get_db().execute(
            """
            SELECT
                id,
                device_category,
                device_make_model,
                issue_description,
                status,
                created_at,
                updated_at
            FROM bookings
            WHERE id = ? AND customer_id = ?
            """,
            (booking_id, user["id"]),
        ).fetchone()

        if booking is None:
            # Use the same 404 for missing and differently owned records so the
            # response does not reveal whether another Customer's booking exists.
            return render_template("booking_not_found.html"), 404

        # Scope boundary: this page only displays the current persisted record;
        # cancellation and repair-status updates are intentionally absent.
        return render_template("booking_detail.html", booking=booking, user=user)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    return app


if __name__ == "__main__":
    create_app().run()
