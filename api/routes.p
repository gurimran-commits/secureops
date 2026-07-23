from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from secureops.analysis import TrafficAnalyzer
from secureops.analysis.models import PacketEvent
from secureops.capture import CaptureService
from secureops.detection import DetectorRegistry
from secureops.detection.threatintel import ThreatIntel
from secureops.reporting.incident_report import (
    IncidentReportGenerator,
)
from secureops.correlation.correlator import (
    AttackCorrelator,
)
from secureops.storage import SQLiteStore
from fastapi.responses import FileResponse

from secureops.reporting.pdf_report import (
    PDFReportGenerator,
)
from secureops.phishing.detector import (
    PhishingDetector,
)


class DemoTrafficRequest(BaseModel):
    packets: int = Field(default=80, ge=1, le=500)
    source_count: int = Field(default=8, ge=1, le=100)
    protocol: str = Field(
        default="TCP",
        pattern="^(TCP|UDP|ICMP|OTHER|tcp|udp|icmp|other)$",
    )

class PhishingRequest(BaseModel):
    url: str
def build_router(
    *,
    analyzer: TrafficAnalyzer,
    detectors: DetectorRegistry,
    capture: CaptureService,
    store: SQLiteStore,
    max_alerts: int,
    max_recent_packets: int,
) -> APIRouter:

    router = APIRouter(prefix="/api")

    threat_intel = ThreatIntel()
    report_generator = IncidentReportGenerator()
    pdf_generator = PDFReportGenerator()
    correlator = AttackCorrelator()

    print("CORRELATOR OBJECT:", id(correlator))

    phishing_detector = PhishingDetector()
def handle_packet(event):

    snapshot = analyzer.record(event)

    store.save_packet(event)
    store.save_snapshot(snapshot)

    for alert in detectors.evaluate_packet(event):

        store.save_alert(alert)

        threat_intel.record_attack(
            ip=alert.src_ip or "unknown",
            attack_type=alert.detector,
            risk_score=alert.risk_score,
        )

        print(
            "CORRELATOR ADD:",
            alert.src_ip,
            alert.detector,
        )
        print(
            "ADD CORRELATOR:",
            id(correlator)
        )
        correlator.add_attack(
            ip=alert.src_ip or "unknown",
            attack_type=alert.detector,
        )
    for alert in detectors.evaluate_snapshot(snapshot):

        store.save_alert(alert)

        threat_intel.record_attack(
            ip=alert.src_ip or "unknown",
            attack_type=alert.detector,
            risk_score=alert.risk_score,
        )

        print(
            "CORRELATOR ADD:",
            alert.src_ip,
            alert.detector,
        )
        print(
            "ADD CORRELATOR:",
            id(correlator)
        )
        correlator.add_attack(
            ip=alert.src_ip or "unknown",
            attack_type=alert.detector,
        )

    @router.get("/health")
    def health() -> dict[str, object]:

        capture_status = capture.status()

        return {
            "status": "ok",
            "capture": _to_jsonable(capture_status),
            "storage": store.counts(),
        }

    @router.get("/metrics")
    def metrics() -> dict[str, object]:
        return _to_jsonable(analyzer.snapshot())

    @router.get("/alerts")
    def alerts() -> list[dict[str, Any]]:
        return store.recent_alerts(limit=max_alerts)

    @router.get("/attackers")
    def attackers():
        return threat_intel.get_attackers()

    @router.get("/campaigns")
    def campaigns():

        print(
            "CAMPAIGNS CORRELATOR:",
            id(correlator)
        )

        return correlator.get_campaigns()

    @router.get("/report/latest")
    def latest_report():

        attackers = threat_intel.get_attackers()

        if not attackers:
            return {
                "status": "error",
                "message": "No attackers recorded.",
            }

        highest_risk = max(
            attackers,
            key=lambda attacker: attacker["risk_score"],
        )

        return report_generator.generate(
            highest_risk
        )
    @router.get("/report/pdf")
    def pdf_report():

        attackers = threat_intel.get_attackers()

        if not attackers:
            return {
                "status": "error",
                "message": "No attackers recorded.",
            }

        highest_risk = max(
            attackers,
            key=lambda attacker: attacker["risk_score"],
        )

        filename = pdf_generator.generate(
            highest_risk
        )

        return FileResponse(
            filename,
            media_type="application/pdf",
            filename=filename,
        )
    @router.get("/packets")
    def packets() -> list[dict[str, Any]]:
        return store.recent_packets(
            limit=max_recent_packets
        )
    @router.post("/phishing/check")
    def check_phishing(
        request: PhishingRequest,
    ):

        return phishing_detector.analyze(
            request.url
        )
    @router.post("/capture/start")
    def start_capture() -> dict[str, object]:
        return _to_jsonable(
            capture.start(handle_packet)
        )

    @router.post("/capture/stop")
    def stop_capture() -> dict[str, object]:
        return _to_jsonable(capture.stop())

    @router.post("/demo/traffic")
    def demo_traffic(
        request: DemoTrafficRequest,
    ) -> dict[str, object]:

        for index in range(request.packets):

            source_number = (
                (index % request.source_count) + 1
            )

            event = PacketEvent.now(
                src_ip=f"10.10.0.{source_number}",
                dst_ip="172.16.1.10",
                protocol=request.protocol,
                size_bytes=96 + (index % 12) * 32,
                src_port=(
                    40000 + index
                    if request.protocol.upper()
                    in {"TCP", "UDP"}
                    else None
                ),
                dst_port=(
                    443
                    if request.protocol.upper()
                    == "TCP"
                    else 53
                ),
            )

            handle_packet(event)

        return {
            "status": "ok",
            "message": (
                f"Generated "
                f"{request.packets} demo packets."
            ),
            "metrics": _to_jsonable(
                analyzer.snapshot()
            ),
            "storage": store.counts(),
        }

    return router


def _to_jsonable(value: Any) -> Any:

    if is_dataclass(value):
        return _to_jsonable(asdict(value))

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            key: _to_jsonable(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [
            _to_jsonable(item)
            for item in value
        ]

    return value
