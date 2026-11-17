
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
