from flask import redirect, render_template, url_for

from basesentinel.web import web


@web.get("/")
def dashboard():
    return render_template("dashboard.html")


@web.get("/events")
def events():
    return render_template("events.html")

@web.get("/activities")
def activities():
    return render_template("activities.html")


@web.get("/events/<event_id>")
def event_detail(event_id):
    return render_template("event_detail.html", event_id=event_id)


@web.get("/alerts")
def alerts():
    return render_template("alerts.html")


@web.get("/alerts/<alert_id>")
def alert_detail(alert_id):
    return render_template("alert_detail.html", alert_id=alert_id)


@web.get("/detection-rules")
def detection_rules():
    return render_template("detection_rules.html")


@web.get("/reports")
def reports():
    return render_template("reports.html")


@web.get("/login")
def login():
    return render_template("login.html")


@web.get("/settings/enrollment")
def enrollment_settings():
    return render_template("enrollment_settings.html")


@web.get("/agent-health")
def agent_health():
    return render_template("agent_health.html")


@web.get("/agents")
def agents():
    return render_template("agents.html")


@web.get("/agents/<agent_id>")
def agent_detail(agent_id):
    return render_template("agent_detail.html", agent_id=agent_id)
@web.get("/agent-invite")
def agent_invite():
    return render_template("agent_invite.html")


@web.get("/logout")
def logout():
    return redirect(url_for("web.login"))
