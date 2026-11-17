from datetime import datetime, timezone


def utcnow_naive() -> datetime:
    """Return the current UTC time without timezone information."""
    return datetime.now(timezone.utc).replace(tzinfo=None)