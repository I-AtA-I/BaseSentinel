
import pytest

from basesentinel import create_app, db


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


@pytest.fixture
def app():
    app = create_app(TestConfig)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_dashboard_page_is_available(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"BaseSentinel" in response.data
    assert b"Event timeline" in response.data
    assert b"Severity distribution" in response.data


def test_login_page_is_available(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert b"Sign in" in response.data
    assert b"username" in response.data
    assert b"password" in response.data


def test_dashboard_references_javascript(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"/static/js/dashboard.js" in response.data


def test_dashboard_references_stylesheet(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"/static/css/dashboard.css" in response.data


def test_javascript_static_file_is_available(client):
    response = client.get("/static/js/dashboard.js")

    assert response.status_code == 200
    assert b"initializeDashboard" in response.data


def test_css_static_file_is_available(client):
    response = client.get("/static/css/dashboard.css")

    assert response.status_code == 200
    assert b".metric-grid" in response.data


def test_logout_redirects_to_login(client):
    response = client.get("/logout")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_api_health_endpoint_remains_available(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"



def test_alerts_page_is_available(client):
    response = client.get("/alerts")

    assert response.status_code == 200
    assert b"Alert management" in response.data
    assert b"Queue filters" in response.data
    assert b"/static/js/alerts.js" in response.data


def test_alerts_page_references_shared_stylesheet(client):
    response = client.get("/alerts")

    assert response.status_code == 200
    assert b"/static/css/dashboard.css" in response.data


def test_security_event_detail_page_is_available(client):
    response = client.get("/events/00000000-0000-0000-0000-000000000001")
    assert response.status_code == 200
    assert b"Event details" in response.data
    assert b"/static/js/event-detail.js" in response.data


def test_event_detail_javascript_is_available(client):
    response = client.get("/static/js/event-detail.js")
    assert response.status_code == 200
    assert b"DOMContentLoaded" in response.data


def test_alerts_javascript_static_file_is_available(client):
    response = client.get("/static/js/alerts.js")

    assert response.status_code == 200
    assert b"initializeAlerts" in response.data


def test_dashboard_alert_links_open_alert_workspace(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b'href="/alerts"' in response.data


def test_security_events_page_is_available(client):
    response = client.get("/events")
    assert response.status_code == 200
    assert b"Security events" in response.data
    assert b"/static/js/events.js" in response.data


def test_security_events_javascript_static_file_is_available(client):
    response = client.get("/static/js/events.js")
    assert response.status_code == 200
    assert b"DOMContentLoaded" in response.data
