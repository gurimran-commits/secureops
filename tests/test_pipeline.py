import pytest

from secureops.api.routes import DemoTrafficRequest
from secureops.config import Settings
from secureops.detection.base import make_alert
from secureops.main import create_app
from secureops.response.firewall import FirewallError, validate_blockable_ip
from secureops.storage import SQLiteStore


def test_demo_traffic_alert_reaches_api(tmp_path):
    settings = Settings(
        interface=None,
        database_path=tmp_path / "secureops.sqlite3",
        packet_window_seconds=60,
        per_source_packet_threshold=5,
        per_source_window_seconds=10,
        max_packets_per_second=1000,
        max_unique_sources=100,
        protocol_flood_threshold=1000,
    )
    app = create_app(settings)

    demo_endpoint = _endpoint(app, "/api/demo/traffic")
    alerts_endpoint = _endpoint(app, "/api/alerts")

    response = demo_endpoint(DemoTrafficRequest(packets=8, source_count=1, protocol="TCP"))

    assert response["status"] == "ok"
    alerts = alerts_endpoint(status=None)
    assert alerts
    assert alerts[0]["detector"] == "ddos"
    assert alerts[0]["status"] == "ACTIVE"


def test_save_alert_updates_existing_active_alert(tmp_path):
    store = SQLiteStore(tmp_path / "secureops.sqlite3")
    first = make_alert(
        detector="ddos",
        severity="low",
        reason="single-source-packet-surge",
        observed_value=5,
        threshold=5,
        src_ip="10.0.0.10",
    )
    second = make_alert(
        detector="ddos",
        severity="medium",
        reason="single-source-packet-surge",
        observed_value=9,
        threshold=5,
        src_ip="10.0.0.10",
    )

    assert store.save_alert(first) is True
    assert store.save_alert(second) is False

    alerts = store.recent_alerts()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["observed_value"] == "9"


def test_firewall_rejects_loopback():
    with pytest.raises(FirewallError):
        validate_blockable_ip("127.0.0.1")


def _endpoint(app, path):
    for route in _walk_routes(app.routes):
        if getattr(route, "path", None) == path:
            return route.endpoint
    raise AssertionError(f"Route not found: {path}")


def _walk_routes(routes):
    for route in routes:
        yield route
        original_router = getattr(route, "original_router", None)
        if original_router is not None:
            yield from _walk_routes(original_router.routes)
        for child in getattr(route, "routes", []):
            yield child
