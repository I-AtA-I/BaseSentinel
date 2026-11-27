
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
    response = client.get("/app/")

    assert response.status_code == 200
    assert b"BaseSentinel" in response.data
    assert b"Event timeline" in response.data
    assert b"Severity distribution" in response.data


def test_login_page_is_available(client):
    response = client.get("/app/login")

    assert response.status_code == 200
    assert b"Sign in" in response.data
    assert b"username" in response.data
    assert b"password" in response.data


def test_dashboard_references_javascript(client):
    response = client.get("/app/")

    assert response.status_code == 200
    assert b"/app/static/js/dashboard.js" in response.data


def test_dashboard_references_stylesheet(client):
    response = client.get("/app/")

    assert response.status_code == 200
    assert b"/app/static/css/dashboard.css" in response.data


def test_javascript_static_file_is_available(client):
    response = client.get("/app/static/js/dashboard.js")

    assert response.status_code == 200
    assert b"initializeDashboard" in response.data


def test_css_static_file_is_available(client):
    response = client.get("/app/static/css/dashboard.css")

    assert response.status_code == 200
    assert b".metric-grid" in response.data


def test_logout_redirects_to_login(client):
    response = client.get("/app/logout")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/app/login")


def test_api_health_endpoint_remains_available(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"



def test_alerts_page_is_available(client):
    response = client.get("/app/alerts")

    assert response.status_code == 200
    assert b"Alert management" in response.data
    assert b"Queue filters" in response.data
    assert b"/app/static/js/alerts.js" in response.data


def test_alert_detail_page_is_available(client):
    alert_id = "12345678-1234-1234-1234-123456789abc"
    response = client.get(f"/app/alerts/{alert_id}")

    assert response.status_code == 200
    assert b"ALERT DETAILS" in response.data
    assert b'data-alert-id="12345678-1234-1234-1234-123456789abc"' in response.data
    assert b"/app/static/js/alert-detail.js" in response.data


def test_alert_detail_javascript_is_available(client):
    response = client.get("/app/static/js/alert-detail.js")

    assert response.status_code == 200
    assert b"initializeAlertDetail" in response.data


def test_alerts_page_links_detection_titles_to_detail(client):
    response = client.get("/app/static/js/alerts.js")
    assert response.status_code == 200
    assert b'href="/alerts/${encodeURIComponent(alert.id)}"' in response.data


def test_alerts_page_references_shared_stylesheet(client):
    response = client.get("/app/alerts")

    assert response.status_code == 200
    assert b"/app/static/css/dashboard.css" in response.data


def test_alerts_javascript_static_file_is_available(client):
    response = client.get("/app/static/js/alerts.js")

    assert response.status_code == 200
    assert b"initializeAlerts" in response.data


def test_dashboard_alert_links_open_alert_workspace(client):
    response = client.get("/app/")

    assert response.status_code == 200
    assert b'href="/app/alerts"' in response.data


def test_security_events_page_is_available(client):
    response = client.get("/app/events")
    assert response.status_code == 200
    assert b">Events<" in response.data
    assert b"Timeline" in response.data
    assert b'value="security" selected' in response.data
    assert b'value="info"' in response.data
    assert b"/app/static/js/events.js" in response.data


def test_security_events_javascript_static_file_is_available(client):
    response = client.get("/app/static/js/events.js")
    assert response.status_code == 200
    assert b"DOMContentLoaded" in response.data



def test_security_event_detail_page_is_available(client):
    event_id = "12345678-1234-1234-1234-123456789abc"
    response = client.get(f"/app/events/{event_id}")

    assert response.status_code == 200
    assert b"EVENT DETAILS" in response.data
    assert b'data-event-id=\"12345678-1234-1234-1234-123456789abc\"' in response.data
    assert b"/app/static/js/event-detail.js" in response.data


def test_security_event_detail_javascript_is_available(client):
    response = client.get("/app/static/js/event-detail.js")

    assert response.status_code == 200
    assert b"initializeEventDetail" in response.data

def test_shared_navigation_is_consistent_across_workspace_pages(client):
    pages = ["/app/", "/app/events", "/app/alerts", "/app/agents", "/app/settings/enrollment"]
    expected_links = [
        b'href="/app/"',
        b'href="/app/events"',
        b'href="/app/alerts"',
        b'href="/app/agents"',
        b'href="/app/settings/enrollment"',
    ]
    for path in pages:
        response = client.get(path)
        assert response.status_code == 200
        for link in expected_links:
            assert link in response.data
        assert b"Event timeline</a>" not in response.data
        assert b"Security events</a>" not in response.data


def test_device_detail_page_is_available(client):
    agent_id = "12345678-1234-1234-1234-123456789abc"
    response = client.get(f"/app/agents/{agent_id}")
    assert response.status_code == 200
    assert b"Device alerts" in response.data
    assert b"Device events" in response.data
    assert b"agent-detail.js" in response.data


def test_device_detail_javascript_is_available(client):
    response = client.get("/app/static/js/agent-detail.js")
    assert response.status_code == 200
    assert b"loadDevice" in response.data




def test_dashboard_drilldown_links_are_available(client):
    response = client.get("/app/")
    assert response.status_code == 200
    javascript = client.get("/app/static/js/dashboard.js")
    assert javascript.status_code == 200
    assert b"/agents/${encodeURIComponent(agent.agent_id)}" in javascript.data
    assert b"severity_min=${item.severity}" in javascript.data


def test_events_page_supports_severity_drilldown_context(client):
    response = client.get("/app/events")
    assert response.status_code == 200
    assert b"severity-filter-context" in response.data
    javascript = client.get("/app/static/js/events.js")
    assert b"severityMin" in javascript.data
    assert b"/alerts?severity_min=" in javascript.data


def test_alerts_page_supports_exact_severity_drilldown(client):
    response = client.get("/app/alerts")
    assert response.status_code == 200
    assert b'value="10-10"' in response.data
    javascript = client.get("/app/static/js/alerts.js")
    assert b"severity_min" in javascript.data
    assert b"/events?severity_min=" in javascript.data



def test_agent_health_page_is_available(client):
    response = client.get("/app/agent-health")
    assert response.status_code == 200
    assert b"Agent health" in response.data
    assert b"/app/static/js/agent-health.js" in response.data


def test_agent_health_javascript_is_available(client):
    response = client.get("/app/static/js/agent-health.js")
    assert response.status_code == 200
    assert b"/operations/agents" in response.data
def test_detection_rules_page_is_available(client):
    response = client.get("/app/detection-rules")
    assert response.status_code == 200
    assert b"Custom detection rules" in response.data
    assert b"/app/static/js/detection-rules.js" in response.data


def test_detection_rules_javascript_is_available(client):
    response = client.get("/app/static/js/detection-rules.js")
    assert response.status_code == 200
    assert b"initialize" in response.data


def test_detection_rules_page_is_in_shared_navigation(client):
    response = client.get("/app/detection-rules")
    assert response.status_code == 200
    assert b'href="/app/detection-rules"' in response.data


def test_security_reports_page_is_available(client):
    response = client.get("/app/reports")
    assert response.status_code == 200
    assert b"Security reports" in response.data
    assert b"/app/static/js/reports.js" in response.data


def test_security_reports_javascript_is_available(client):
    response = client.get("/app/static/js/reports.js")
    assert response.status_code == 200
    assert b"/reports/security/summary" in response.data


def test_alert_detail_includes_investigation_timeline(client):
    response = client.get("/app/alerts/12345678-1234-1234-1234-123456789abc")
    assert response.status_code == 200
    assert b"Investigation timeline" in response.data
    javascript = client.get("/app/static/js/alert-detail.js")
    assert b"/operations/alerts/" in javascript.data



def test_public_homepage_is_available(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Security visibility" in response.data
    assert b"BaseSentinel Client" in response.data
    assert b"Coming soon" in response.data
    assert b'href="/app/"' in response.data


def test_workspace_is_mounted_under_app(client):
    response = client.get("/app/")
    assert response.status_code == 200
    assert b"Event timeline" in response.data
    assert b"/app/static/js/dashboard.js" in response.data


def test_legacy_workspace_paths_redirect_to_app(client):
    response = client.get("/events?severity_min=7")
    assert response.status_code == 308
    assert response.headers["Location"].endswith("/app/events?severity_min=7")


def test_api_health_endpoint_is_not_redirected(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"
