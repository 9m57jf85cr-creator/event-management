from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from ..security import credentials_match, generate_csrf_token, is_safe_next_url

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next", "")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next", "")

        if credentials_match(current_app, username, password):
            session.clear()
            session["is_admin"] = True
            session.permanent = True
            generate_csrf_token()
            flash("Logged in as admin.", "success")
            if is_safe_next_url(next_url):
                return redirect(next_url)
            return redirect(url_for("events.home"))

        flash("Invalid admin credentials.", "error")

    return render_template(
        "login.html",
        next_url=next_url,
        admin_username=current_app.config["ADMIN_USERNAME"],
    )


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("events.home"))
