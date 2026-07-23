from __future__ import annotations

import logging
import os
import platform
from collections.abc import Callable
from threading import Event, Thread
from typing import Protocol

from secureops.analysis.models import (
    CaptureReadiness,
    CaptureStatus,
    PacketEvent,
)

logger = logging.getLogger(__name__)


class PacketSource(Protocol):
    interface: str | None

    def readiness(self) -> CaptureStatus:
        ...

    def run(
        self,
        on_packet: Callable[[PacketEvent], None],
        stop_event: Event,
    ) -> None:
        ...


class ScapyPacketSource:
    """Scapy adapter that normalizes packets into PacketEvent objects."""

    def __init__(
        self,
        interface: str | None = None,
    ) -> None:
        self.interface = interface

    def readiness(self) -> CaptureStatus:

        try:
            import scapy.all  # noqa: F401

        except ImportError:
            return CaptureStatus(
                readiness=CaptureReadiness.MISSING_SCAPY,
                running=False,
                interface=self.interface,
                message=(
                    "Scapy is not installed. "
                    "Install with: pip install -e .[capture]"
                ),
            )
        except Exception as exc:
            logger.warning("Scapy is installed but unavailable: %s", exc)
            return CaptureStatus(
                readiness=CaptureReadiness.DISABLED,
                running=False,
                interface=self.interface,
                message="Scapy is installed but could not be initialized.",
                last_error=str(exc),
            )

        if not _has_capture_privileges():
            return CaptureStatus(
                readiness=CaptureReadiness.NEEDS_ROOT,
                running=False,
                interface=self.interface,
                message=_permission_message(),
            )

        return CaptureStatus(
            readiness=CaptureReadiness.READY,
            running=False,
            interface=self.interface,
            message=(
                f"Packet capture is ready on "
                f"{platform.system() or 'this OS'}."
            ),
        )

    def run(
        self,
        on_packet: Callable[[PacketEvent], None],
        stop_event: Event,
    ) -> None:

        status = self.readiness()

        if status.readiness != CaptureReadiness.READY:
            raise RuntimeError(
                status.message
                or f"capture is {status.readiness}"
            )

        from scapy.all import (
            sniff,
            IP,
            TCP,
            UDP,
            ICMP,
        )

        packet_count = 0

        logger.info("starting packet capture on interface=%s", self.interface or "default")

        def handle(raw_packet):

            nonlocal packet_count

            if stop_event.is_set():
                return

            if not raw_packet.haslayer(IP):
                return

            ip = raw_packet[IP]

            protocol = "OTHER"
            src_port = None
            dst_port = None

            if raw_packet.haslayer(TCP):

                protocol = "TCP"

                src_port = int(
                    raw_packet[TCP].sport
                )

                dst_port = int(
                    raw_packet[TCP].dport
                )

            elif raw_packet.haslayer(UDP):

                protocol = "UDP"

                src_port = int(
                    raw_packet[UDP].sport
                )

                dst_port = int(
                    raw_packet[UDP].dport
                )

            elif raw_packet.haslayer(ICMP):

                protocol = "ICMP"

            packet_count += 1

            if packet_count % 1000 == 0:
                logger.info("captured %s packets", packet_count)

            event = PacketEvent.now(
                src_ip=str(ip.src),
                dst_ip=str(ip.dst),
                protocol=protocol,
                size_bytes=len(raw_packet),
                src_port=src_port,
                dst_port=dst_port,
            )

            on_packet(event)

        while not stop_event.is_set():

            sniff(
                iface=self.interface,
                prn=handle,
                store=False,
                timeout=1,
            )

        logger.info("packet capture stopped total_packets=%s", packet_count)


class CaptureService:
    """Threaded lifecycle wrapper."""

    def __init__(
        self,
        source: PacketSource,
    ) -> None:

        self.source = source
        self._stop_event = Event()
        self._thread: Thread | None = None
        self.last_error: str | None = None

    @property
    def running(self) -> bool:
        return (
            self._thread is not None
            and self._thread.is_alive()
        )

    def status(self) -> CaptureStatus:

        readiness = self.source.readiness()

        return CaptureStatus(
            readiness=readiness.readiness,
            running=self.running,
            interface=readiness.interface,
            message=readiness.message,
            last_error=self.last_error or readiness.last_error,
        )

    def start(
        self,
        on_packet: Callable[[PacketEvent], None],
    ) -> CaptureStatus:

        status = self.source.readiness()

        if status.readiness != CaptureReadiness.READY:

            self.last_error = status.message

            return self.status()

        if not self.running:

            self.last_error = None

            self._stop_event.clear()

            self._thread = Thread(
                target=self._run,
                args=(on_packet,),
                daemon=True,
            )

            self._thread.start()

        return self.status()

    def stop(self) -> CaptureStatus:

        self._stop_event.set()

        if self._thread is not None:

            self._thread.join(timeout=3)

            self._thread = None

        return self.status()

    def _run(
        self,
        on_packet: Callable[[PacketEvent], None],
    ) -> None:

        try:
            self.source.run(
                on_packet,
                self._stop_event,
            )

        except Exception as exc:

            self.last_error = str(exc)

            logger.exception(
                "packet capture stopped"
            )


def _has_capture_privileges() -> bool:

    if os.name == "nt":

        try:
            import ctypes

            return bool(
                ctypes.windll.shell32.IsUserAnAdmin()
            )

        except Exception:
            return False

    return (
        not hasattr(os, "geteuid")
        or os.geteuid() == 0
    )


def _permission_message() -> str:

    system = platform.system().lower()

    if system == "windows":
        return (
            "Packet capture on Windows requires "
            "Npcap and Administrator privileges."
        )

    if system == "darwin":
        return (
            "Packet capture on macOS requires sudo."
        )

    return (
        "Packet capture requires root or "
        "capture capabilities on Linux."
    )
