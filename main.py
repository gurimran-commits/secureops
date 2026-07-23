from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from secureops.analysis import TrafficAnalyzer
from secureops.api import build_router
from secureops.capture import CaptureService, ScapyPacketSource
from secureops.config import Settings, get_settings
from secureops.detection import DDoSDetector, DetectorRegistry
from secureops.detection.portscan import PortScanDetector
from secureops.logging import configure_logging
from secureops.storage import SQLiteStore
from secureops.detection.bruteforce import BruteForceDetector

def create_app(settings: Settings | None = None) -> FastAPI:
    configure_logging()
    settings = settings or get_settings()

    analyzer = TrafficAnalyzer(window_seconds=settings.packet_window_seconds)
    if settings.lab_mode:
        max_packets_per_second = 10
        protocol_flood_threshold = 50
        per_source_packet_threshold = 50
    else:
        max_packets_per_second = settings.max_packets_per_second
        protocol_flood_threshold = settings.protocol_flood_threshold
        per_source_packet_threshold = settings.per_source_packet_threshold

    detectors = DetectorRegistry(
        [  
            DDoSDetector(
                max_packets_per_second=max_packets_per_second,
                max_unique_sources=settings.max_unique_sources,
                protocol_flood_threshold=protocol_flood_threshold,
                per_source_packet_threshold=per_source_packet_threshold,
                per_source_window_seconds=settings.per_source_window_seconds,
            ),
            PortScanDetector(),
            BruteForceDetector(),
        ]
    )
    capture = CaptureService(ScapyPacketSource(interface=settings.interface))
    store = SQLiteStore(settings.database_path)

    app = FastAPI(title="SecureOps", version="0.1.0")
    app.include_router(
        build_router(
            analyzer=analyzer,
            detectors=detectors,
            capture=capture,
            store=store,
            max_alerts=settings.max_alerts,
            max_recent_packets=settings.max_recent_packets,
        )
    )

    dashboard_dir = Path(__file__).parent / "dashboard"
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")

    @app.get("/")
    def dashboard() -> FileResponse:
        return FileResponse(dashboard_dir / "index.html")

    return app


app = create_app()
