import os
from pathlib import Path

from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from db import get_db, init_app as init_db_app


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

    def show_role_area(required_role, area_title):
        user = load_current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != required_role:
            return render_template("access_denied.html"), 403
        return render_template(
            "authenticated.html",
            area_title=area_title,
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
        return show_role_area("Customer", "Customer Area")

    @app.get("/staff")
    def staff():
        return show_role_area("Repair Staff", "Repair Staff Area")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    return app


if __name__ == "__main__":
    create_app().run()
