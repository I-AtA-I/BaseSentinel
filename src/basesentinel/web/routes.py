from flask import redirect, render_template, url_for

from basesentinel.web import web


@web.get("/")
def dashboard():
    return render_template("dashboard.html")


@web.get("/events")
def events():
    return render_template("events.html")


@web.get("/events/<event_id>")
def event_detail(event_id):
    return render_template("event_detail.html", event_id=event_id)


@web.get("/alerts")
def alerts():
    return render_template("alerts.html")


@web.get("/login")
def login():
    return render_template("login.html")


@web.get("/settings/enrollment")
def enrollment_settings():
    return render_template("enrollment_settings.html")


@web.get("/agents")
def agents():
    return render_template("agents.html")


@web.get("/agent-invite")
def agent_invite():
    return render_template("agent_invite.html")


@web.get("/logout")
def logout():
    return redirect(url_for("web.login"))
