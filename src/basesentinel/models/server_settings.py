from basesentinel import db
from basesentinel.models.base import utcnow_naive


class ServerSettings(db.Model):
    __tablename__ = "server_settings"

    id = db.Column(db.SmallInteger, primary_key=True, default=1)
    server_id = db.Column(db.String(36), nullable=False, unique=True)
    server_secret_hash = db.Column(db.String(64), nullable=False)
    connection_password_hash = db.Column(db.String(256), nullable=True)
    enrollment_mode = db.Column(db.String(24), nullable=False, default="automatic")
    created_at = db.Column(db.DateTime(), nullable=False, default=utcnow_naive)
    updated_at = db.Column(db.DateTime(), nullable=False, default=utcnow_naive, onupdate=utcnow_naive)
