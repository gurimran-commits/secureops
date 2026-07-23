from __future__ import annotations
from fastapi import Depends
from secureops.security import verify_api_key
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query


from secureops.analysis import TrafficAnalyzer
from secureops.analysis.models import PacketEvent
from secureops.capture import CaptureService
from secureops.detection import DetectorRegistry
from secureops.detection.threatintel import ThreatIntel

from secureops.reporting.incident_report import (
    IncidentReportGenerator,
)

from secureops.reporting.pdf_report import (
    PDFReportGenerator,
)

from secureops.correlation.correlator import (
    AttackCorrelator,
)

from secureops.phishing.detector import (
    PhishingDetector,
)

from secureops.api.interfaces import (
    get_interfaces,
)

from fastapi.responses import FileResponse
from secureops.storage import SQLiteStore
from secureops.response.firewall import (
    FirewallError,
    block_ip,
    clear_secureops_rules,
    list_rules,
    unblock_ip,
    validate_blockable_ip,
)

from pydantic import BaseModel, Field
class DemoTrafficRequest(BaseModel):
    packets: int = Field(default=80, ge=1, le=500)
    source_count: int = Field(default=8, ge=1, le=100)
    protocol: str = Field(default="TCP", pattern="^(TCP|UDP|ICMP|OTHER|tcp|udp|icmp|other)$")

class PhishingRequest(BaseModel):
    url: str

class InterfaceRequest(BaseModel):
    interface: str
class FirewallRequest(BaseModel):
    ip: str
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
    phishing_detector = PhishingDetector()

    def handle_packet(event):
        snapshot = analyzer.record(event)
        store.save_packet(event)
        store.save_snapshot(snapshot)

        for alert in detectors.evaluate_packet(event):

            store.save_alert(alert)

            if alert.src_ip:
                threat_intel.record_attack(
                    ip=alert.src_ip,
                    attack_type=alert.detector,
                    risk_score=alert.risk_score,
                )

                correlator.add_attack(
                    ip=alert.src_ip,
                    attack_type=alert.detector,
                )

        for alert in detectors.evaluate_snapshot(snapshot):

            store.save_alert(alert)

            if alert.src_ip:
                threat_intel.record_attack(
                    ip=alert.src_ip,
                    attack_type=alert.detector,
                    risk_score=alert.risk_score,
                )

                correlator.add_attack(
                    ip=alert.src_ip,
                    attack_type=alert.detector,
                )
    
    @router.get("/attackers")
    def attackers():
        return threat_intel.get_attackers()


    @router.get("/campaigns")
    def campaigns():
        return correlator.get_campaigns()
    @router.get("/firewall/rules")
    def firewall_rules():
        try:
            return {
                "rules": list_rules()
            }
        except Exception as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
            
    @router.post("/firewall/block")
    def firewall_block(request: FirewallRequest):
        try:
            ip = validate_blockable_ip(request.ip)
            added = block_ip(ip)

            return {
                "status": "success",
                "ip": ip,
                "changed": added,
            }
        except FirewallError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    
    @router.post("/firewall/unblock")
    def firewall_unblock(request: FirewallRequest):
        try:
            ip = validate_blockable_ip(request.ip)
            removed = unblock_ip(ip)

            return {
                "status": "success",
                "ip": ip,
                "changed": removed,
            }
        except FirewallError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    
    @router.post("/firewall/clear")
    def firewall_clear():
        try:
            return {
                "status": "success",
                "removed": clear_secureops_rules(),
            }
        except Exception as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
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
            filename=Path(filename).name,
        )

    @router.delete("/report/latest")
    def delete_latest_report():
        return {
            "status": "success",
            "message": "Reports are generated on demand; no persisted report metadata to delete.",
        }
            
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
    @router.get("/interfaces")
    def interfaces():
        return get_interfaces()
    @router.get("/alerts")
    def alerts(
        _: None = Depends(verify_api_key),
        status: str | None = Query(default=None),
    ):   
        return store.recent_alerts(
            limit=max_alerts,
            status=status,
        )
        
    @router.post("/alerts/{alert_id}/resolve")
    def resolve_alert(alert_id: int):
        if store.resolve_alert(alert_id):
            return {
                "status": "success",
                "message": "Alert resolved.",
            }

        raise HTTPException(status_code=404, detail="Alert not found.")
    
    @router.delete("/alerts/{alert_id}")
    def delete_alert(alert_id: int):
        if store.delete_alert(alert_id):
            return {
                "status": "success",
                "message": "Alert deleted.",
            }

        raise HTTPException(status_code=404, detail="Alert not found.")
    @router.post("/alerts/clear")
    def clear_alerts():
        removed = store.clear_alerts()

        return {
            "status": "success",
            "removed": removed,
            "message": f"Removed {removed} alerts."
        }    
    @router.get("/interface/current")
    def current_interface():

        return {
            "interface": capture.source.interface
        }
    @router.get("/packets")
    def packets() -> list[dict[str, Any]]:
        return store.recent_packets(limit=max_recent_packets)

    @router.post("/capture/start")
    def start_capture() -> dict[str, object]:
        return _to_jsonable(capture.start(handle_packet))

    @router.post("/capture/stop")
    def stop_capture() -> dict[str, object]:
        return _to_jsonable(capture.stop())
    @router.post("/interface/select")
    def select_interface(
        request: InterfaceRequest,
    ):

        capture.stop()

        capture.source.interface = (
            request.interface
        )

        status = capture.start(handle_packet)

        return {
            "status": "ok",
            "interface": request.interface,
            "capture": _to_jsonable(status),
        }
    @router.post("/demo/traffic")
    def demo_traffic(request: DemoTrafficRequest) -> dict[str, object]:
        for index in range(request.packets):
            source_number = (index % request.source_count) + 1
            event = PacketEvent.now(
                src_ip=f"10.10.0.{source_number}",
                dst_ip="172.16.1.10",
                protocol=request.protocol,
                size_bytes=96 + (index % 12) * 32,
                src_port=40000 + index if request.protocol.upper() in {"TCP", "UDP"} else None,
                dst_port=443 if request.protocol.upper() == "TCP" else 53,
            )
            handle_packet(event)

        return {
            "status": "ok",
            "message": f"Generated {request.packets} demo packets.",
            "metrics": _to_jsonable(analyzer.snapshot()),
            "storage": store.counts(),
        }
    @router.post("/phishing/check")
    def check_phishing(
        request: PhishingRequest,
    ):
        return phishing_detector.analyze(
            request.url
        )
    return router
    


def _to_jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _to_jsonable(asdict(value))
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(item) for item in value]
    return value
