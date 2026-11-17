
from flask import redirect, render_template, url_for

from basesentinel.web import web


@web.get("/")
def dashboard():
    return render_template("dashboard.html")


@web.get("/login")
def login():
    return render_template("login.html")


@web.get("/logout")
def logout():
    return redirect(url_for("web.login"))
