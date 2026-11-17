from flask import redirect, render_template, url_for

from basesentinel.web import web


@web.get("/")
def dashboard():
    return render_template("dashboard.html")


@web.get("/alerts")
def alerts():
    return render_template("alerts.html")


@web.get("/login")
def login():
    return render_template("login.html")


@web.get("/settings/enrollment")
def enrollment_settings():
    return render_template("enrollment_settings.html")


@web.get("/logout")
def logout():
    return redirect(url_for("web.login"))
