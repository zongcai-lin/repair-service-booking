import os
from pathlib import Path

from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from db import get_db, init_app as init_db_app


DEVICE_CATEGORIES = ("Phone", "Tablet", "Laptop")
REVIEW_ACTIONS = {"accept": "Accepted", "reject": "Rejected"}
PROGRESS_ACTIONS = {
    "start": ("Accepted", "In Progress"),
    "complete": ("In Progress", "Completed"),
}
CANCELLABLE_STATUSES = ("Submitted", "Accepted")


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
        show_review_queue=False,
        show_progress_queue=False,
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
            show_review_queue=show_review_queue,
            show_progress_queue=show_progress_queue,
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
        return show_role_area(
            "Repair Staff",
            "Repair Staff Area",
            show_review_queue=True,
            show_progress_queue=True,
        )

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

        # RSB-10 / BR-04: the detail page may offer cancellation only before
        # repair starts. This UI flag is not authorization; the POST repeats
        # ownership and current-state checks at the database mutation point.
        cancellation_error = None
        success_message = None
        if request.args.get("cancelled") == "1":
            success_message = "Booking cancelled successfully."
        return render_template(
            "booking_detail.html",
            booking=booking,
            can_cancel=booking["status"] in CANCELLABLE_STATUSES,
            cancellation_error=cancellation_error,
            success_message=success_message,
            user=user,
        )

    @app.route("/customer/bookings/<int:booking_id>/cancel", methods=("GET", "POST"))
    def cancel_booking(booking_id):
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))

        # RSB-5 / RSB-10: cancellation is a Customer request-side function.
        # Handle both GET and POST so a Staff-crafted direct URL is rejected
        # with the established 403 convention rather than relying on hidden UI.
        if user["role"] != "Customer":
            return render_template("access_denied.html"), 403
        if request.method == "GET":
            return redirect(url_for("booking_detail", booking_id=booking_id))

        database = get_db()
        booking = database.execute(
            """
            SELECT id, device_category, device_make_model, issue_description,
                   status, created_at, updated_at
            FROM bookings
            WHERE id = ? AND customer_id = ?
            """,
            (booking_id, user["id"]),
        ).fetchone()
        if booking is None:
            # Match RSB-7's missing/foreign-owner response: never reveal that
            # another Customer's booking exists through a cancellation attempt.
            return render_template("booking_not_found.html"), 404
        if request.form.get("action") != "cancel":
            # RSB-10 does not accept a browser-supplied status. The server owns
            # the single cancellation outcome and rejects arbitrary form input.
            return (
                render_template(
                    "booking_detail.html",
                    booking=booking,
                    can_cancel=booking["status"] in CANCELLABLE_STATUSES,
                    cancellation_error="Use the Cancel Booking action to cancel this booking.",
                    success_message=None,
                    user=user,
                ),
                400,
            )

        # RSB-10 / BR-01 and BR-04: bind the authenticated Customer ID and the
        # current persisted state into the UPDATE. This blocks stale pages from
        # cancelling after repair starts and makes Cancelled terminal here.
        cursor = database.execute(
            """
            UPDATE bookings
            SET status = 'Cancelled', updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND customer_id = ?
              AND status IN ('Submitted', 'Accepted')
            """,
            (booking_id, user["id"]),
        )
        database.commit()
        if cursor.rowcount != 1:
            current_booking = database.execute(
                """
                SELECT id, device_category, device_make_model, issue_description,
                       status, created_at, updated_at
                FROM bookings
                WHERE id = ? AND customer_id = ?
                """,
                (booking_id, user["id"]),
            ).fetchone()
            if current_booking is None:
                return render_template("booking_not_found.html"), 404
            return (
                render_template(
                    "booking_detail.html",
                    booking=current_booking,
                    can_cancel=False,
                    cancellation_error="This booking can no longer be cancelled.",
                    success_message=None,
                    user=user,
                ),
                409,
            )

        # created_at records the original request; cancellation is the latest
        # persisted business event, so only updated_at changes alongside status.
        return redirect(url_for("booking_detail", booking_id=booking_id, cancelled="1"))

    @app.get("/staff/bookings")
    def staff_booking_queue():
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))

        # RSB-5 / RSB-8: Staff-only routing is enforced before querying data;
        # navigation links alone cannot stop a Customer from requesting this URL.
        if user["role"] != "Repair Staff":
            return render_template("access_denied.html"), 403

        # RSB-8 review scope starts with Submitted work only. Filtering in the
        # query prevents Accepted/Rejected rows being offered for another review.
        bookings = get_db().execute(
            """
            SELECT id, device_category, device_make_model, status, created_at
            FROM bookings
            WHERE status = 'Submitted'
            ORDER BY created_at DESC, id DESC
            """
        ).fetchall()
        success_message = None
        if request.args.get("reviewed") in REVIEW_ACTIONS.values():
            success_message = "Booking review saved."
        return render_template(
            "staff_booking_queue.html",
            bookings=bookings,
            success_message=success_message,
            user=user,
        )

    @app.get("/staff/bookings/<int:booking_id>")
    def staff_review_booking(booking_id):
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "Repair Staff":
            return render_template("access_denied.html"), 403

        booking = get_db().execute(
            """
            SELECT id, device_category, device_make_model, issue_description,
                   status, created_at, updated_at
            FROM bookings
            WHERE id = ?
            """,
            (booking_id,),
        ).fetchone()
        if booking is None:
            return render_template("booking_not_found.html"), 404

        review_error = None
        if booking["status"] != "Submitted":
            review_error = "This booking can no longer be reviewed."
        return render_template(
            "staff_review_booking.html",
            booking=booking,
            review_error=review_error,
            user=user,
        )

    @app.post("/staff/bookings/<int:booking_id>/review")
    def review_booking(booking_id):
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))

        # RSB-5 / RSB-8: this POST repeats the Staff check so a crafted form
        # cannot use a Customer session to change a booking's persisted status.
        if user["role"] != "Repair Staff":
            return render_template("access_denied.html"), 403

        action = request.form.get("action", "")
        target_status = REVIEW_ACTIONS.get(action)
        database = get_db()
        booking = database.execute(
            """
            SELECT id, device_category, device_make_model, issue_description,
                   status, created_at, updated_at
            FROM bookings
            WHERE id = ?
            """,
            (booking_id,),
        ).fetchone()
        if booking is None:
            return render_template("booking_not_found.html"), 404
        if target_status is None:
            # Only named Accept/Reject actions are trusted; never map a client
            # supplied status value into the workflow or later RSB-9 states.
            return (
                render_template(
                    "staff_review_booking.html",
                    booking=booking,
                    review_error="Choose Accept or Reject to review this booking.",
                    user=user,
                ),
                400,
            )

        # The conditional UPDATE makes the current database value authoritative
        # immediately before mutation: RSB-8 permits Submitted -> Accepted or
        # Submitted -> Rejected only, and leaves every other state unchanged.
        cursor = database.execute(
            """
            UPDATE bookings
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'Submitted'
            """,
            (target_status, booking_id),
        )
        database.commit()
        if cursor.rowcount != 1:
            current_booking = database.execute(
                """
                SELECT id, device_category, device_make_model, issue_description,
                       status, created_at, updated_at
                FROM bookings
                WHERE id = ?
                """,
                (booking_id,),
            ).fetchone()
            return (
                render_template(
                    "staff_review_booking.html",
                    booking=current_booking,
                    review_error="This booking can no longer be reviewed.",
                    user=user,
                ),
                409,
            )

        return redirect(url_for("staff_booking_queue", reviewed=target_status))

    @app.get("/staff/bookings/progress")
    def staff_progress_queue():
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))

        # RSB-5 / RSB-9: progress is a Staff responsibility, so enforce this
        # on the server before any booking data can be returned to a Customer.
        if user["role"] != "Repair Staff":
            return render_template("access_denied.html"), 403

        # Submitted remains in the RSB-8 review queue, while Rejected and
        # Cancelled have no repair work. This queue is limited to the RSB-9
        # lifecycle states that Staff can inspect or progress.
        bookings = get_db().execute(
            """
            SELECT id, device_category, device_make_model, status, created_at
            FROM bookings
            WHERE status IN ('Accepted', 'In Progress', 'Completed')
            ORDER BY created_at DESC, id DESC
            """
        ).fetchall()
        success_message = None
        if request.args.get("progressed") in ("In Progress", "Completed"):
            success_message = "Repair progress saved."
        return render_template(
            "staff_progress_queue.html",
            bookings=bookings,
            success_message=success_message,
            user=user,
        )

    @app.get("/staff/bookings/<int:booking_id>/progress")
    def staff_progress_booking(booking_id):
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "Repair Staff":
            return render_template("access_denied.html"), 403

        booking = get_db().execute(
            """
            SELECT id, device_category, device_make_model, issue_description,
                   status, created_at, updated_at
            FROM bookings
            WHERE id = ?
            """,
            (booking_id,),
        ).fetchone()
        if booking is None:
            return render_template("booking_not_found.html"), 404

        return render_template("staff_progress_booking.html", booking=booking, user=user)

    @app.post("/staff/bookings/<int:booking_id>/progress")
    def update_repair_progress(booking_id):
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))

        # RSB-5 / BR-02: hiding these controls is not authorization; a direct
        # Customer POST must still be rejected before it can mutate a booking.
        if user["role"] != "Repair Staff":
            return render_template("access_denied.html"), 403

        action = request.form.get("action", "")
        transition = PROGRESS_ACTIONS.get(action)
        database = get_db()
        booking = database.execute(
            """
            SELECT id, device_category, device_make_model, issue_description,
                   status, created_at, updated_at
            FROM bookings
            WHERE id = ?
            """,
            (booking_id,),
        ).fetchone()
        if booking is None:
            return render_template("booking_not_found.html"), 404
        if transition is None:
            # RSB-9 never trusts status values from the browser. Named actions
            # prevent a crafted request from selecting any other lifecycle state.
            return (
                render_template(
                    "staff_progress_booking.html",
                    booking=booking,
                    progress_error="Choose Start Repair or Complete Repair.",
                    user=user,
                ),
                400,
            )

        expected_status, target_status = transition
        # RSB-9 / BR-03: the condition re-checks the persisted state at the
        # mutation point. Submitted therefore cannot bypass RSB-8 review, and
        # Completed never matches either active-state transition (terminal).
        cursor = database.execute(
            """
            UPDATE bookings
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = ?
            """,
            (target_status, booking_id, expected_status),
        )
        database.commit()
        if cursor.rowcount != 1:
            current_booking = database.execute(
                """
                SELECT id, device_category, device_make_model, issue_description,
                       status, created_at, updated_at
                FROM bookings
                WHERE id = ?
                """,
                (booking_id,),
            ).fetchone()
            return (
                render_template(
                    "staff_progress_booking.html",
                    booking=current_booking,
                    progress_error="This progress action is no longer available.",
                    user=user,
                ),
                409,
            )

        # created_at is the original request time; each allowed business change
        # refreshes only updated_at so Customer views show the shared record.
        return redirect(url_for("staff_progress_queue", progressed=target_status))

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    return app


if __name__ == "__main__":
    create_app().run()
