from secureops.gui.change_password_dialog import ChangePasswordDialog
from secureops.auth import session

import csv
import json
import logging
import math
import os
import sys
import webbrowser
from collections import Counter, deque
from datetime import datetime, timedelta
from statistics import mean
from zoneinfo import ZoneInfo
from secureops.config import API_KEY

import psutil
import pyqtgraph as pg
import requests

from PyQt6.QtCore import QObject, QPointF, QRectF, QRunnable, Qt, QThreadPool, QTimer, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QGroupBox,
    QFormLayout,
    QSpinBox,
    QMenu
)
from PyQt6.QtWidgets import QStackedWidget

API_URL = "http://127.0.0.1:8000/api"
REFRESH_MS = 1000
LOCAL_TZ = datetime.now().astimezone().tzinfo or ZoneInfo("Asia/Kolkata")
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")
logger = logging.getLogger(__name__)


COLORS = {
    "bg": "#06111f",
    "panel": "#081827",
    "panel2": "#0b1d31",
    "border": "#1d3b58",
    "grid": "#18324c",
    "text": "#eef6ff",
    "muted": "#9fb0c6",
    "blue": "#1687ff",
    "red": "#ff4248",
    "orange": "#ff9f0a",
    "green": "#27d66d",
    "purple": "#8b5cf6",
}


class ApiSignals(QObject):
    finished = pyqtSignal(object)
    failed = pyqtSignal(str)


class ApiWorker(QRunnable):
    def __init__(self, method, path, payload=None, timeout=4):
        super().__init__()
        self.method = method
        self.path = path
        self.payload = payload
        self.timeout = timeout
        self.signals = ApiSignals()

    @pyqtSlot()
    def run(self):
        try:
            result = api_request(self.method, self.path, self.payload, self.timeout)
            self.signals.finished.emit(result)
        except Exception as error:
            self.signals.failed.emit(str(error))


def api_request(method, path, payload=None, timeout=4):
    url = f"{API_URL}{path}"

    headers = {
        "X-API-Key": "SecureOps2026"
    }

    response = requests.request(
        method,
        url,
        json=payload,
        headers=headers,
        timeout=timeout,
    )

    if not response.content:
        response.raise_for_status()
        return {}

    try:
        data = response.json()
    except ValueError:
        data = {"text": response.text}

    if not response.ok:
        message = data.get("detail") if isinstance(data, dict) else response.text
        raise RuntimeError(
            message or f"{response.status_code} {response.reason}"
        )

    return data


def get_json(path, default):
    try:
        data = api_request("GET", path, timeout=3)
        return data if data is not None else default
    except Exception:
        return default


def post_json(path, payload=None):
    return api_request("POST", path, payload, timeout=4)


def fmt_int(value):
    try:
        return f"{int(float(value)):,}"
    except Exception:
        return "0"

def format_timestamp(timestamp):
    try:
        if timestamp in (None, ""):
            return ""
        if isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(float(timestamp), tz=ZoneInfo("UTC"))
        else:
            raw = str(timestamp).strip()
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            if " " in raw and "T" not in raw:
                raw = raw.replace(" ", "T", 1)
            dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo("UTC"))
        return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        value = str(timestamp)
        try:
            return datetime.fromisoformat(value[:19]).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return value[:19]


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def severity_color(value):
    severity = str(value).upper()
    if severity == "HIGH":
        return COLORS["red"]
    if severity == "MEDIUM":
        return COLORS["orange"]
    if severity == "LOW":
        return COLORS["green"]
    return COLORS["text"]


def table_item(value, color=None):
    item = QTableWidgetItem("" if value is None else str(value))
    if color:
        item.setForeground(QColor(color))
    return item


def normalize_status(value):
    status = str(value or "ACTIVE").upper()
    if status in {"RESOLVED", "CLOSED"}:
        return "RESOLVED"
    return "ACTIVE"


def normalize_alert(alert):
    alert_id = alert.get("id") or alert.get("alert_id") or ""
    detector = alert.get("detector") or alert.get("type") or "Alert"
    severity = (alert.get("severity") or "MEDIUM").upper()
    src_ip = alert.get("src_ip") or alert.get("source_ip") or alert.get("source") or "unknown"
    dst_ip = alert.get("dst_ip") or alert.get("destination_ip") or alert.get("destination") or ""
    reason = alert.get("reason") or alert.get("description") or "Suspicious activity detected"
    timestamp = alert.get("timestamp") or alert.get("time") or ""
    return {
        "id": alert_id,
        "time": format_timestamp(timestamp),
        "type": detector,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "severity": severity,
        "description": reason,
        "risk_score": alert.get("risk_score", ""),
        "confidence": alert.get("confidence", ""),
        "action": alert.get("action", ""),
        "status": normalize_status(alert.get("status")),
    }


def demo_alerts():
    return []


class Panel(QFrame):
    def __init__(self, title=None):
        
        super().__init__()
        self.setObjectName("Panel")
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(16, 14, 16, 14)
        self.layout.setSpacing(10)
        if title:
            label = QLabel(title)
            label.setObjectName("PanelTitle")
            self.layout.addWidget(label)


class MetricCard(QFrame):
    def __init__(self, title, color, subtitle, icon_text):
        super().__init__()
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred
        )
        self.setMinimumWidth(0)
        self.color = color
        self.points = deque(maxlen=24)
        self.setObjectName("MetricCard")

        root = QHBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(8)

        text_col = QVBoxLayout()
        text_col.setSpacing(4)
        self.title = QLabel(title.upper())
        self.title.setStyleSheet(f"color:{color}; font-size:13px; font-weight:700;")
        self.value = QLabel("0")
        self.value.setStyleSheet("color:white; font-size:30px; font-weight:800;")
        self.subtitle = QLabel(subtitle)
        self.subtitle.setStyleSheet(f"color:{COLORS['muted']}; font-size:13px;")
        text_col.addWidget(self.title)
        text_col.addWidget(self.value)
        text_col.addWidget(self.subtitle)

        self.spark = pg.PlotWidget()
        self.spark.setFixedSize(118, 56)
        self.spark.setBackground(None)
        self.spark.hideAxis("left")
        self.spark.hideAxis("bottom")
        self.spark.setMouseEnabled(False, False)
        self.spark_curve = self.spark.plot(pen=pg.mkPen(color, width=2))

        self.icon = QLabel(icon_text)
        self.icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon.setStyleSheet(f"color:{color}; font-size:38px; font-weight:800;")

        root.addLayout(text_col, 1)
        root.addWidget(self.spark)
        root.addWidget(self.icon)

    def set_value(self, value, spark_value=None):
        self.value.setText(str(value))
        if spark_value is not None:
            self.points.append(float(spark_value))
            self.spark_curve.setData(list(self.points))


class DonutChart(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumSize(170, 170)
        self.data = [
            ("DDoS", 35, COLORS["red"]),
            ("Port Scan", 25, COLORS["orange"]),
            ("Brute Force", 20, "#ffb21a"),
            ("Phishing", 10, COLORS["purple"]),
            ("Other", 10, "#64748b"),
        ]

    def set_counts(self, counts):
        total = sum(counts.values())
        if not total:
            return
        palette = [COLORS["red"], COLORS["orange"], "#ffb21a", COLORS["purple"], "#64748b"]
        top = counts.most_common(4)
        other = total - sum(value for _, value in top)
        rows = [(name, round(value * 100 / total, 1), palette[index]) for index, (name, value) in enumerate(top)]
        if other:
            rows.append(("Other", round(other * 100 / total, 1), palette[-1]))
        self.data = rows
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height()) - 20
        rect = QRectF(10, 10, side, side)
        start_angle = 90 * 16
        for _, value, color in self.data:
            span = int(-value / 100 * 360 * 16)
            painter.setPen(QPen(QColor(color), 34, Qt.PenStyle.SolidLine, Qt.PenCapStyle.FlatCap))
            painter.drawArc(rect.adjusted(17, 17, -17, -17), start_angle, span)
            start_angle += span
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(COLORS["bg"]))
        painter.drawEllipse(rect.adjusted(50, 50, -50, -50))


class SecureOpsDashboard(QMainWindow):
    def __init__(self, username="Administrator"):
        super().__init__()
        if not session.is_authenticated():
            QMessageBox.critical(
                None,
                "Access Denied",
                "Please login first."
            )
            raise SystemExit(1)

        self.current_user = username
        self.setWindowTitle("SecureOps SOC Dashboard")
        self.resize(1600, 900)
        self.setMinimumSize(1600, 900)
        self.traffic_points = deque(maxlen=90)
        self.alert_bars = deque(maxlen=28)
        self.last_alert_total = 0
        self.current_interface = "eth1 (192.168.100.20)"
        self.api_connected = False
        self.thread_pool = QThreadPool.globalInstance()
        self.refresh_inflight = False
        self.last_packets = deque(maxlen=120)
        self.last_pps_values = deque(maxlen=120)
        self.alert_cache = []

        pg.setConfigOptions(antialias=True)
        self._build_ui()
        self._apply_style()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.update_system_status()
        self.timer.start(REFRESH_MS)
        self.refresh()

    def run_api_task(self, method, path, on_success, payload=None, on_error=None, timeout=4):
        worker = ApiWorker(method, path, payload, timeout)
        worker.signals.finished.connect(on_success)
        worker.signals.failed.connect(on_error or self.handle_api_error)
        self.thread_pool.start(worker)

    def handle_api_error(self, message):
        self.statusBar().showMessage(f"Backend unavailable: {message}", 5000)

    def notify(self, message):
        self.statusBar().showMessage(message, 4000)
    def load_firewall_rules(self):

        try:

            data = requests.get(
                f"{API_URL}/firewall/rules",
                timeout=3
            ).json()

            rules = data.get(
                "rules",
                []
            )

            self.firewall_table.setRowCount(0)

            row = 0

            for line in rules:

                if "DROP" not in line:
                    continue

                parts = line.split()

                if len(parts) < 5:
                    continue

                self.firewall_table.insertRow(row)

                self.firewall_table.setItem(
                    row,
                    0,
                    QTableWidgetItem(parts[0])
                )

                self.firewall_table.setItem(
                    row,
                    1,
                    QTableWidgetItem(parts[3])
                )

                self.firewall_table.setItem(
                    row,
                    2,
                    QTableWidgetItem("DROP")
                )

                row += 1

        except Exception as error:

            logger.exception("Firewall API error: %s", error)

            for child in self.findChildren(QWidget):
                hint = child.minimumSizeHint()
                if hint.width() > 400:
                    logger.debug("%s minimum size hint=%s", type(child).__name__, hint)

    def load_firewall_rules(self):
        self.run_api_task("GET", "/firewall/rules", self._finish_firewall_rules, on_error=lambda error: self.notify(f"Firewall refresh failed: {error}"), timeout=4)

    def _finish_firewall_rules(self, data):
        rules = data.get("rules", []) if isinstance(data, dict) else []
        self.firewall_table.setSortingEnabled(False)
        self.firewall_table.setRowCount(0)
        row = 0
        for rule in rules:
            if isinstance(rule, dict):
                values = [
                    rule.get("rule", rule.get("id", "")),
                    rule.get("ip", rule.get("source_ip", "")),
                    rule.get("action", "DROP"),
                    format_timestamp(rule.get("timestamp", rule.get("created_at", ""))),
                    rule.get("packets_dropped", rule.get("drops", "")),
                ]
            else:
                line = str(rule)
                if "DROP" not in line.upper():
                    continue
                parts = line.split()
                source = parts[3] if len(parts) > 3 else ""
                values = [parts[0] if parts else "", source, "DROP", "", ""]
            self.firewall_table.insertRow(row)
            for col, value in enumerate(values):
                self.firewall_table.setItem(row, col, table_item(value))
            row += 1
        self.firewall_table.setSortingEnabled(True)
        self.firewall_table.resizeRowsToContents()
        self.filter_table(self.firewall_table, self.firewall_search.text())

    def _build_ui(self):
        shell = QWidget()
        root = QHBoxLayout(shell)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.pages = QStackedWidget()

        dashboard_page = self._content()

        firewall_page = QWidget()
        firewall_layout = QVBoxLayout(firewall_page)
        self.firewall_table = QTableWidget()

        self.setup_table(
            self.firewall_table
        )
       
        self.firewall_table.setColumnCount(5)

        self.firewall_table.setHorizontalHeaderLabels([
            "Rule",
            "Source IP",
            "Action",
            "Timestamp",
            "Packets Dropped"
        ])
        
        firewall_layout.addWidget(
            QLabel("Firewall Rules")
        )
        self.firewall_search = QLineEdit()
        self.firewall_search.setPlaceholderText("Search firewall rules...")
        self.firewall_search.textChanged.connect(lambda _: self.filter_table(self.firewall_table, self.firewall_search.text()))
        firewall_layout.addWidget(self.firewall_search)
        
        firewall_layout.addWidget(
            self.firewall_table,
            1
        )       
        
        self.intel_page = QWidget()

        intel_layout = QVBoxLayout(self.intel_page)

        intel_layout.addWidget(
            QLabel("Threat Intelligence Feed")
        )
        self.intel_search = QLineEdit()
        self.intel_search.setPlaceholderText("Search IP, country, reputation...")
        self.intel_search.textChanged.connect(lambda _: self.filter_table(self.intel_table, self.intel_search.text()))
        intel_layout.addWidget(self.intel_search)

        self.intel_table = QTableWidget()
        
        self.setup_table(
            self.intel_table,
        )
        intel_layout.addWidget(
            self.intel_table,
            1
        )
        buttons = QHBoxLayout()

        self.block_ip_input = QLineEdit()
        self.block_ip_input.setPlaceholderText("IP address to block")
        self.block_ip_btn = QPushButton("Block IP")
        self.refresh_rules_btn = QPushButton(
            "Refresh Rules"
        )

        self.remove_rule_btn = QPushButton(
            "Remove Selected"
        )

        self.clear_rules_btn = QPushButton(
            "Clear All Rules"
        )

        buttons.addWidget(
            self.block_ip_input
        )
        buttons.addWidget(
            self.block_ip_btn
        )
        buttons.addWidget(
            self.refresh_rules_btn
        )

        buttons.addWidget(
            self.remove_rule_btn
        )

        buttons.addWidget(
            self.clear_rules_btn
        )

        firewall_layout.addLayout(
            buttons
        )
        self.refresh_rules_btn.clicked.connect(
            self.load_firewall_rules
        )
        self.block_ip_btn.clicked.connect(
            lambda: self.block_ip(self.block_ip_input.text().strip())
        )

        self.remove_rule_btn.clicked.connect(
            self.remove_selected_rule
        )

        self.clear_rules_btn.clicked.connect(
            self.clear_all_rules
        )
        self.intel_table.setColumnCount(8)

        self.intel_table.setHorizontalHeaderLabels([
            "IP Address",
            "Risk Score",
            "Reputation",
            "Country",
            "Confidence",
            "Last Seen",
            "Attack Count",
            "Status"
        ])

        intel_layout.addWidget(
            self.intel_table
        )
        self.pages.addWidget(dashboard_page)
        self.pages.addWidget(firewall_page)
        self.pages.addWidget(
            self.intel_page
        )
        self.correlation_page = QWidget()

        correlation_layout = QVBoxLayout(
            self.correlation_page
        )

        correlation_layout.addWidget(
            QLabel("Attack Correlations")
        )
        self.correlation_search = QLineEdit()
        self.correlation_search.setPlaceholderText("Search campaign, host, alert, timeline...")
        self.correlation_search.textChanged.connect(lambda _: self.filter_table(self.correlation_table, self.correlation_search.text()))
        correlation_layout.addWidget(self.correlation_search)

        self.correlation_table = QTableWidget()

        self.setup_table(
            self.correlation_table,
        )
        correlation_layout.addWidget(
            self.correlation_table,
            1
        )
        self.correlation_table.setColumnCount(8)

        self.correlation_table.setHorizontalHeaderLabels([
            "IP Address",
            "Campaign Type",
            "Attack Chain",
            "Risk Score",
            "Attack Count",
            "Related Alerts",
            "Affected Hosts",
            "Timeline"
        ])

        correlation_layout.addWidget(
            self.correlation_table
        )

        self.pages.addWidget(
            self.correlation_page
        )
        report_page = QWidget()

        report_layout = QVBoxLayout(report_page)

        report_layout.addWidget(
            QLabel("Incident Report")
        )
        self.report_search = QLineEdit()
        self.report_search.setPlaceholderText("Search reports...")
        self.report_search.textChanged.connect(lambda _: self.filter_table(self.report_table, self.report_search.text()))
        report_layout.addWidget(self.report_search)

        self.report_table = QTableWidget()
       

        self.setup_table(
            self.report_table
        )

        self.report_table.setColumnCount(2)

        self.report_table.setHorizontalHeaderLabels([
            "Field",
            "Value"
        ])

        report_layout.addWidget(
            self.report_table,
            1
        )

        self.report_button = QPushButton(
            "Generate Latest Report"
        )

        self.pdf_button = QPushButton(
            "Download PDF Report"
        )
        self.export_report_button = QPushButton("Export Table")
        self.delete_report_button = QPushButton("Delete Selected")

        self.report_button.clicked.connect(
            self.load_report
        )

        self.pdf_button.clicked.connect(
            self.download_pdf
        )
        self.export_report_button.clicked.connect(
            lambda: self.export_table(self.report_table, "incident_report")
        )
        self.delete_report_button.clicked.connect(
            self.delete_report
        )

        report_layout.addWidget(
            self.report_button
        )

        report_layout.addWidget(
            self.pdf_button
        )
        report_layout.addWidget(
            self.export_report_button
        )
        report_layout.addWidget(
            self.delete_report_button
        )

        self.pages.addWidget(
            report_page
        )
        
        phishing_page = QWidget()

        phishing_layout = QVBoxLayout(
            phishing_page
        )

        phishing_layout.addWidget(
            QLabel("Phishing URL Analysis")
        )

        self.phishing_url_input = QLineEdit()

        self.phishing_url_input.setPlaceholderText(
            "https://example.com"
        )

        phishing_layout.addWidget(
            self.phishing_url_input
        )

        self.phishing_check_button = QPushButton(
        "Analyze URL"
        )

        phishing_layout.addWidget(
            self.phishing_check_button
        )

        self.phishing_result = QTableWidget()
        

        self.setup_table(
            self.phishing_result
        )

        self.phishing_result.setColumnCount(2)

        self.phishing_result.setHorizontalHeaderLabels([
            "Field",
            "Value"
        ])

        phishing_layout.addWidget(
            self.phishing_result,
            1
        )

        self.phishing_check_button.clicked.connect(
            self.run_phishing_check
        )

        self.pages.addWidget(
            phishing_page
        )
        traffic_page = QWidget()

        traffic_layout = QVBoxLayout(traffic_page)

        title = QLabel("Live Traffic Monitor")
        title.setStyleSheet("""
            font-size:20px;
            font-weight:bold;
            color:white;
            """)

        traffic_layout.addWidget(title)
        self.live_search = QLineEdit()
        self.live_search.setPlaceholderText("Search live traffic...")
        self.live_search.textChanged.connect(lambda _: self.filter_table(self.live_table, self.live_search.text()))
        traffic_layout.addWidget(self.live_search)
        stats = QHBoxLayout()

        self.live_packets = QLabel("Packets/sec : 0")
        self.live_bandwidth = QLabel("Bandwidth : 0 Mbps")
        self.live_protocols = QLabel("Protocols : -")
        self.live_sources = QLabel("Top Source : -")

        for label in [
            self.live_packets,
            self.live_bandwidth,
            self.live_protocols,
            self.live_sources,
        ]:
            label.setStyleSheet("""
            background:#0b1d31;
            border:1px solid #1d3b58;
            padding:12px;
            border-radius:6px;
            color:white;
            """)

            stats.addWidget(label)

        traffic_layout.addLayout(stats)
        self.live_table = QTableWidget()

        self.setup_table(
            self.live_table
        )

        self.live_table.setColumnCount(6)

        self.live_table.setHorizontalHeaderLabels([
            "Time",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Size",
            "Info", 
        ])

        traffic_layout.addWidget(
            self.live_table,
            1
        )
        self.pages.addWidget(
            traffic_page
        )
        alerts_page = QWidget()

        alerts_layout = QVBoxLayout(
            alerts_page
        )
        title = QLabel(
            "Alert Management"
        )

        title.setStyleSheet("""
        font-size:20px;
        font-weight:bold;
        color:white;
        """)
        top = QHBoxLayout()

        self.alert_search = QLineEdit()
        self.alert_search.setPlaceholderText(
            "Search by IP or detector..."
        )

        self.alert_filter = QComboBox()
        self.alert_filter.clear()
        self.alert_filter.addItems([
            "ALL",
            "ACTIVE",
            "RESOLVED",
            
        ])
        
        self.alert_search.textChanged.connect(
            self.filter_alerts
        )
        self.alert_filter.currentTextChanged.connect(
            self.filter_alerts
        )
        
        alerts_layout.addWidget(title)
        
        stats = QHBoxLayout()

        self.high_alerts = QLabel("HIGH\n0")
        self.medium_alerts = QLabel("MEDIUM\n0")
        self.low_alerts = QLabel("LOW\n0")
        self.total_alerts = QLabel("TOTAL\n0")

        for label, color in [
            (self.high_alerts, COLORS["red"]),
            (self.medium_alerts, COLORS["orange"]),
            (self.low_alerts, COLORS["green"]),
            (self.total_alerts, COLORS["blue"]),
        ]:

            label.setAlignment(Qt.AlignmentFlag.AlignCenter)

            label.setStyleSheet(f"""
                background:{COLORS['panel2']};
                border:1px solid {COLORS['border']};
                border-radius:8px;
                padding:12px;
                color:white;
                font-size:16px;
                font-weight:bold;
            """)

            stats.addWidget(label)

        alerts_layout.addLayout(stats)
    
        refresh = QPushButton("Refresh")

        refresh.clicked.connect(
            self.load_alerts
        )

        top.addWidget(
            self.alert_search
        )

        top.addWidget(
            self.alert_filter
        )

        top.addWidget(
            refresh
        )

        alerts_layout.addLayout(top)
        
        self.alerts_table = QTableWidget()

        self.setup_table(
            self.alerts_table
        )
        self.alerts_table.cellDoubleClicked.connect(
            self.show_alert_details
        )
        self.alerts_table.setColumnCount(10)

        self.alerts_table.setHorizontalHeaderLabels(
           [
               "ID",
               "Time",
               "Status",
               "Severity",
               "Detector",
               "Source IP",
               "Reason",
               "Risk",
               "Confidence",
               "Action",
            ]
        )    
        self.alerts_table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )

        self.alerts_table.customContextMenuRequested.connect(
            self.alert_context_menu
        )
        
        alerts_layout.addWidget(
            self.alerts_table,
            1
        )
        
        buttons = QHBoxLayout()

        export_btn = QPushButton(
            "Export CSV"
        )
        export_btn.clicked.connect(
            self.export_alerts_csv
        )

        clear_btn = QPushButton(
            "Clear Alerts"
        )
        
        export_btn.clicked.connect(
            self.export_alerts_csv
        )

        clear_btn.clicked.connect(
            self.clear_alerts
        )
        buttons.addWidget(
            export_btn
        )

        buttons.addWidget(
            clear_btn
        )

        alerts_layout.addLayout(
            buttons
        )
        self.pages.addWidget(
            alerts_page
        )
        
        settings_page = QWidget()

        settings_layout = QVBoxLayout(
            settings_page
        )
        title = QLabel("Settings")

        title.setStyleSheet("""
        font-size:22px;
        font-weight:bold;
        color:white;
        """)

        user_label = QLabel(f"👤 Logged in as: {self.current_user}")
        user_label.setStyleSheet("""
        font-size:15px;
        font-weight:bold;
        color:#9fb0c6;
        margin-top:-8px;
        margin-bottom:4px;
        padding:0px;
        """)

        settings_layout.addWidget(user_label)
        detection_group = QGroupBox(
            "Detection"
        )

        form = QFormLayout()

        self.syn_threshold = QSpinBox()
        self.syn_threshold.setRange(1, 10000)
        self.syn_threshold.setValue(100)
        self.udp_threshold = QSpinBox()
        self.udp_threshold.setRange(1, 10000)
        self.udp_threshold.setValue(100)
        self.icmp_threshold = QSpinBox()
        self.icmp_threshold.setRange(1, 10000)
        self.icmp_threshold.setValue(100)

        form.addRow(
            "SYN Threshold",
            self.syn_threshold
        )
        form.addRow(
            "UDP Threshold",
            self.udp_threshold
        )
        form.addRow(
            "ICMP Threshold",
            self.icmp_threshold
        )

        detection_group.setLayout(form)

        settings_layout.addWidget(
            detection_group
        )
        dashboard_group = QGroupBox(
           "Dashboard"
        )

        dashboard_form = QFormLayout()

        self.refresh_interval = QSpinBox()
        self.refresh_interval.setRange(1, 60)
        self.refresh_interval.setValue(1)
        self.refresh_interval.valueChanged.connect(lambda value: self.timer.setInterval(value * 1000) if hasattr(self, "timer") else None)
        self.max_packets = QSpinBox()
        self.max_packets.setRange(10, 10000)
        self.max_packets.setValue(100)
        self.theme_preference = QComboBox()
        self.theme_preference.addItems(["Dark SOC", "High Contrast"])
        self.theme_preference.currentTextChanged.connect(lambda _: self._apply_style())
        dashboard_form.addRow(
            "Refresh Interval (sec)",
            self.refresh_interval
        )

        dashboard_form.addRow(
            "Maximum Packets",
            self.max_packets
        )
        dashboard_form.addRow(
            "Theme",
            self.theme_preference
        )

        dashboard_group.setLayout(
            dashboard_form
        )
        settings_layout.addWidget(
            dashboard_group
        )
        capture_group = QGroupBox(
            "Capture"
        )

        capture_form = QFormLayout()

        self.default_interface = QComboBox()

        try:

            interfaces = get_json(
                "/interfaces",
                []
            )

            for interface in interfaces:

                if isinstance(interface, dict):

                    self.default_interface.addItem(
                        interface.get(
                            "name",
                            ""
                        )
                    )

            else:

                self.default_interface.addItem(
                    str(interface)
                )

        except Exception:

            pass

        capture_form.addRow(
            "Default Interface",
             self.default_interface
        )

        capture_group.setLayout(
            capture_form
        )

        settings_layout.addWidget(
            capture_group
        )
        auth_group = QGroupBox("Authentication")

        auth_layout = QVBoxLayout()

        change_password_btn = QPushButton("🔑 Change Password")
        change_password_btn.clicked.connect(self.change_password)

        logout_btn = QPushButton("🚪 Logout")
        logout_btn.clicked.connect(self.logout)

        auth_layout.addWidget(change_password_btn)
        auth_layout.addWidget(logout_btn)

        auth_group.setLayout(auth_layout)

        settings_layout.addWidget(auth_group)
        save_btn = QPushButton(
            "Save Settings"
        )
        save_btn.clicked.connect(
            self.save_settings
        )
        settings_layout.addWidget(
            save_btn
        )
        self.pages.addWidget(
            settings_page
        )
        about_page = QWidget()
        about_layout = QVBoxLayout(about_page)

        title = QLabel("About SecureOps")
        title.setStyleSheet("""
        font-size:22px;
        font-weight:bold;
        color:white;
        """)

        about_layout.addWidget(title)

        info = QLabel("""
        <b>SecureOps</b>

        Version: 1.0

        Mini Security Operations Center

        Features

        • Live Packet Monitoring
        • DDoS Detection
        • Port Scan Detection
        • Brute Force Detection
        • Threat Intelligence
        • Correlation Engine
        • Firewall Integration
        • Incident Reporting
        • PDF Reports
        • Phishing URL Detection

        Developed as a B.Tech Cybersecurity Project.
        """)

        info.setWordWrap(True)
        info.setStyleSheet("color:white;font-size:14px;")

        about_layout.addWidget(info)
        about_layout.addStretch()

        self.pages.addWidget(about_page)
        self.load_settings()
        root.addWidget(self._sidebar())
        root.addWidget(self.pages, 1)
        self.setCentralWidget(shell)
    
   

    def update_system_status(self):
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent

        values = [
            ("Packet Capture", "Running"),
            ("Threat Intel", "Connected"),
            ("Firewall", "Active"),
            ("Database", "Healthy"),
            ("CPU Usage", f"{cpu:.0f}%"),
            ("Memory Usage", f"{memory:.0f}%"),
            ("Disk Usage", f"{disk:.0f}%"),
        ]

        for label, (name, value) in zip(self.system_rows, values):
            label.setText(f"{name}    {value}")    
            
    def show_phishing_result(self, result):

        heuristic = result.get("heuristic", {})
        vt = result.get("virustotal", {})

        text = f"""
    URL
    ----------------------------------------
    {result.get("url")}

    FINAL VERDICT
    ----------------------------------------
    {result.get("final_verdict", "Unknown").upper()}

    Confidence
    ----------------------------------------
    {result.get("confidence", 0)}%

    LOCAL ANALYSIS
    ----------------------------------------
    Risk Score : {heuristic.get("risk_score", 0)}
    Verdict    : {heuristic.get("verdict", "").upper()}

    Reasons
    ----------------------------------------
    """

        reasons = heuristic.get("reasons", [])

        if reasons:
            text += "\n".join(f"• {reason}" for reason in reasons)
        else:
            text += "None"

        if vt.get("success"):

            text += f"""

    VirusTotal
    ----------------------------------------
    Malicious   : {vt.get("malicious", 0)}
    Suspicious  : {vt.get("suspicious", 0)}
    Harmless    : {vt.get("harmless", 0)}
    Undetected  : {vt.get("undetected", 0)}
    Reputation  : {vt.get("reputation", 0)}
    """

        else:

            text += f"""

    VirusTotal
    ----------------------------------------
    Unavailable

    Reason:
    {vt.get("error", "Unknown")}
    """

        QMessageBox.information(
            self,
            "SecureOps Phishing Analysis",
            text,
         )            
            
    def change_section(self, index):

        if index == 0:
            self.pages.setCurrentIndex(0)

        elif index == 6:      # Firewall
            self.pages.setCurrentIndex(1)
            
            self.load_firewall_rules()
        elif index == 3:   # Threat Intel

            self.pages.setCurrentIndex(2)

            self.load_threat_intel()
        
        elif index == 4:

            self.pages.setCurrentIndex(3)

            self.load_correlations()
        elif index == 5:    # Reports

            self.pages.setCurrentIndex(4)

            self.load_report()
        
        elif index == 7:

            self.pages.setCurrentIndex(5)
        elif index == 2:
            self.pages.setCurrentIndex(6)
            
        elif index == 1:
            self.pages.setCurrentIndex(7)
            self.load_alerts()
        
        elif index == 8:
            self.pages.setCurrentIndex(8)
        elif index == 9:
            self.pages.setCurrentIndex(9)
        else:
            QMessageBox.information(
                self,
                "SecureOps",
                f"{index} page not implemented yet"
            )
    def _sidebar(self):
        side = QFrame()
        side.setObjectName("Sidebar")
        side.setMaximumWidth(250)
        side.setMinimumWidth(180)
        layout = QVBoxLayout(side)
        layout.setContentsMargins(16, 18, 14, 18)
        layout.setSpacing(16)

        brand = QLabel("SecureOps SOC")
        brand.setObjectName("Brand")
        sub = QLabel("Advanced SOC Platform")
        sub.setObjectName("Muted")
        layout.addWidget(brand)
        layout.addWidget(sub)

        nav = QListWidget()
        nav.setObjectName("Nav")
        for item in [
            "Dashboard",
            "Alerts",
            "Live Traffic",
            "Threat Intel",
            "Correlations",
            "Reports",
            "Firewall",
            "Phishing Check",
            "Settings",
            "About",
        ]:
            nav.addItem(QListWidgetItem(item))
        nav.setCurrentRow(0)
        self.nav = nav

        nav.currentRowChanged.connect(
            self.change_section
        )
        layout.addWidget(nav, 1)

        status = Panel()
        status.layout.setSpacing(8)
        self.capture_status = QLabel("Capture Status\nRUNNING")
        self.side_interface = QLabel("Interface\neth1 (192.168.100.20)")
        self.side_uptime = QLabel("Uptime\n02:14:32")
        for label in [self.capture_status, self.side_interface, self.side_uptime]:
            label.setObjectName("StatusText")
            status.layout.addWidget(label)
        layout.addWidget(status)

        footer = QLabel("SecureOps v2.0.0\n© 2026 SecureOps Project")
        footer.setObjectName("Muted")
        layout.addWidget(footer)
        return side

    def _content(self):
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(18, 16, 18, 8)
        layout.setSpacing(12)

        header = QHBoxLayout()
        title = QLabel("Real-time Threat Monitoring & Detection")
        title.setObjectName("HeaderTitle")
        self.header_interface = QComboBox()
        self.header_interface.setFixedWidth(220)
        self.clock = QLabel("")
        self.clock.setObjectName("Clock")
        header.addWidget(title, 1)
        header.addWidget(QLabel("Interface"))
        header.addWidget(self.header_interface)
        header.addSpacing(12)
        header.addWidget(self.clock)
        layout.addLayout(header)

        cards = QGridLayout()
        cards.setSpacing(12)
        self.packet_card = MetricCard("Packets / Sec", COLORS["blue"], "Live", "!")
        self.alert_card = MetricCard("Total Alerts", COLORS["red"], "Last 24h", "!")
        self.threat_card = MetricCard("Threat Level", COLORS["orange"], "Elevated Risk", "!")
        self.blocked_card = MetricCard("Blocked IPs", COLORS["green"], "By Firewall", "+")
        self.uptime_card = MetricCard("Uptime", COLORS["purple"], "Running", ":")
        for index, card in enumerate([self.packet_card, self.alert_card, self.threat_card, self.blocked_card, self.uptime_card]):
            cards.addWidget(card, 0, index)
        layout.addLayout(cards)

        middle = QGridLayout()
        middle.setSpacing(12)
        middle.addWidget(self._traffic_panel(), 0, 0, 1, 2)
        middle.addWidget(self._alerts_panel(), 0, 2)
        middle.addWidget(self._attack_panel(), 0, 3)
        middle.setColumnStretch(0, 2)
        middle.setColumnStretch(1, 2)
        middle.setColumnStretch(2, 2)
        middle.setColumnStretch(3, 2)
        layout.addLayout(middle)

        lower = QGridLayout()
        lower.setSpacing(12)
        lower.addWidget(self._recent_alerts_panel(), 0, 0, 1, 3)
        lower.addWidget(self._interface_panel(), 0, 3)
        lower.addWidget(self._intel_panel(), 1, 0)
        lower.addWidget(self._correlation_panel(), 1, 1)
        lower.addWidget(self._system_panel(), 1, 2)
        lower.addWidget(self._actions_panel(), 1, 3)
        layout.addLayout(lower, 1)

        footer = QHBoxLayout()
        self.footer_packets = QLabel("Packets Captured: 0")
        self.footer_alerts = QLabel("Alerts (24h): 0")
        self.footer_blocked = QLabel("Blocked IPs: 0")
        self.footer_updated = QLabel("Last Updated: --")
        for label in [self.footer_packets, self.footer_alerts, self.footer_blocked, self.footer_updated]:
            label.setObjectName("Muted")
        footer.addWidget(self.footer_packets)
        footer.addWidget(self.footer_alerts)
        footer.addWidget(self.footer_blocked)
        footer.addStretch(1)
        footer.addWidget(self.footer_updated)
        layout.addLayout(footer)
        return content

    def _traffic_panel(self):
        panel = Panel("LIVE TRAFFIC  (Packets / Second)")
        self.traffic_plot = pg.PlotWidget()
        self.traffic_plot.setBackground(None)
        self.traffic_plot.showGrid(x=True, y=True, alpha=0.25)
        self.traffic_plot.setMouseEnabled(False, False)
        self.traffic_plot.getAxis("left").setTextPen(COLORS["muted"])
        self.traffic_plot.getAxis("bottom").setTextPen(COLORS["muted"])
        self.traffic_curve = self.traffic_plot.plot(pen=pg.mkPen(COLORS["blue"], width=2), fillLevel=0, brush=(22, 135, 255, 45))
        panel.layout.addWidget(self.traffic_plot, 1)
        return panel

    def _alerts_panel(self):
        panel = Panel("ALERTS OVER TIME  (Last 5 Minutes)")
        self.alert_plot = pg.PlotWidget()
        self.alert_plot.setBackground(None)
        self.alert_plot.showGrid(x=False, y=True, alpha=0.25)
        self.alert_plot.setMouseEnabled(False, False)
        self.alert_plot.getAxis("left").setTextPen(COLORS["muted"])
        self.alert_plot.getAxis("bottom").setTextPen(COLORS["muted"])
        panel.layout.addWidget(self.alert_plot, 1)
        return panel

    def _attack_panel(self):
        panel = Panel("TOP ATTACK TYPES  (Last 24h)")
        row = QHBoxLayout()
        self.donut = DonutChart()
        self.attack_legend = QVBoxLayout()
        row.addWidget(self.donut)
        row.addLayout(self.attack_legend, 1)
        panel.layout.addLayout(row)
        return panel

    def _recent_alerts_panel(self):
        panel = Panel("RECENT ALERTS")
        self.alert_table = QTableWidget(0, 6)
        self.setup_table(
            self.alert_table
        )
        
        self.alert_table.setHorizontalHeaderLabels(["Time", "Type", "Source IP", "Destination IP", "Severity", "Description"])
       
        panel.layout.addWidget(
            self.alert_table,
            1
        )
        return panel

    def _interface_panel(self):
        panel = Panel("INTERFACE CONTROL")
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumHeight(32)
        self.interface_list = QListWidget()
        self.interface_list.setFixedHeight(80)
        buttons = QHBoxLayout()
        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.setObjectName("DangerButton")
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.interface_combo.currentTextChanged.connect(self.select_interface)
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        panel.layout.addWidget(QLabel("Current Interface"))
        panel.layout.addWidget(self.interface_combo)
        panel.layout.addWidget(QLabel("Available Interfaces"))
        panel.layout.addWidget(self.interface_list)
        panel.layout.addLayout(buttons)
        panel.layout.addStretch()
        return panel

    def _intel_panel(self):
        panel = Panel("THREAT INTELLIGENCE FEED  (Latest)")
        self.intel_rows = QVBoxLayout()
        panel.layout.addLayout(self.intel_rows)
        button = QPushButton("View Full Feed")
        
        button.clicked.connect(self.open_threat_intel)
        panel.layout.addWidget(button)
        panel.layout.addWidget(button)
        panel.layout.addStretch()
        return panel

    def _correlation_panel(self):
        panel = Panel("CORRELATION SUMMARY")
        self.correlation_labels = []
        for name in ["Active Campaigns", "Correlated Alerts", "Unique Attackers", "Affected Targets", "Last Correlation"]:
            row = QLabel(f"{name}    0")
            row.setObjectName("DataRow")
            self.correlation_labels.append((name, row))
            panel.layout.addWidget(row)
        panel.layout.addStretch(1)
      
        button = QPushButton("View Correlations")
        button.clicked.connect(
            self.open_correlations
        )
        panel.layout.addWidget(button)
        panel.layout.addStretch()
        return panel

    def _system_panel(self):
        panel = Panel("SYSTEM STATUS")
        self.system_rows = []
        for name, value in [
            ("Packet Capture", "Running"),
            ("Threat Intel", "Connected"),
            ("Firewall", "Active"),
            ("Database", "Healthy"),
            ("CPU Usage", "18%"),
            ("Memory Usage", "42%"),
            ("Disk Usage", "68%"),
        ]:
            label = QLabel(f"{name}    {value}")
            label.setObjectName("DataRow")
            self.system_rows.append(label)
            panel.layout.addWidget(label)
        panel.layout.addStretch()
        return panel

    def _actions_panel(self):
        panel = Panel("QUICK ACTIONS")
        self.phishing_input = QLineEdit()
        self.phishing_input.setPlaceholderText("https://example.com")
        check = QPushButton("Check Phishing URL")
        report = QPushButton("Generate PDF Report")
        logs = QPushButton("View Firewall Logs")
        clear = QPushButton("Clear Old Alerts")
        check.clicked.connect(self.check_phishing)
        report.clicked.connect(self.generate_report)
        logs.clicked.connect(self.open_firewall_logs)
        clear.clicked.connect(self.clear_alerts)
        for widget in [self.phishing_input, check, report, logs, clear]:
            panel.layout.addWidget(widget)
        panel.layout.addStretch()    
        return panel
        
    def setup_table(self, table):

        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        table.setWordWrap(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSizeAdjustPolicy(QTableWidget.SizeAdjustPolicy.AdjustIgnored)
        table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def _apply_style(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background: {COLORS['bg']};
                color: {COLORS['text']};
                font-family: Segoe UI, Arial;
                font-size: 13px;
            }}
            #Sidebar {{
                background: #071523;
                border-right: 1px solid {COLORS['border']};
            }}
            #Brand {{
                color: {COLORS['blue']};
                font-size: 21px;
                font-weight: 800;
            }}
            #HeaderTitle {{
                color: white;
                font-size: 18px;
                font-weight: 650;
            }}
            #Clock {{
                font-size: 16px;
                color: white;
            }}
            #Muted {{
                color: {COLORS['muted']};
            }}
            #StatusText {{
                color: white;
                line-height: 130%;
            }}
            #Panel, #MetricCard {{
                background: {COLORS['panel']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
            #PanelTitle {{
                color: white;
                font-weight: 800;
                font-size: 14px;
            }}
            #DataRow {{
                color: #dbe8f7;
                padding: 2px 0;
            }}
            QListWidget#Nav {{
                background: transparent;
                border: none;
                color: #dbe8f7;
                outline: 0;
            }}
            QListWidget#Nav::item {{
                padding: 12px 14px;
                border-radius: 7px;
                margin: 2px 0;
            }}
            QListWidget#Nav::item:selected {{
                background: #075fc5;
                color: white;
            }}
            QTableWidget, QListWidget {{
                background: {COLORS['panel2']};
                border: 1px solid #17344f;
                border-radius: 5px;
                color: {COLORS['text']};
                gridline-color: #163047;
            }}
            QHeaderView::section {{
                background: #0c2034;
                color: #cbd7e6;
                border: none;
                padding: 7px;
            }}
            QPushButton {{
                background: #10283f;
                border: 1px solid #1d3b58;
                border-radius: 5px;
                color: white;
                padding: 8px 10px;
            }}
            QPushButton:hover {{
                background: #143653;
            }}
            QPushButton#DangerButton {{
                background: #3b1218;
                border-color: {COLORS['red']};
            }}
            QComboBox, QLineEdit {{
                background: #09192a;
                border: 1px solid #254560;
                border-radius: 5px;
                color: white;
                padding: 7px 10px;
            }}
        """)

    def refresh(self):
        self.update_system_status()
          
        now = datetime.now()
        self.clock.setText(now.strftime("%H:%M:%S\n%b %d, %Y"))
        if self.refresh_inflight:
            return
        self.refresh_inflight = True
        self.run_api_task("GET", "/metrics", lambda metrics: self._refresh_stage(metrics or {}, now), on_error=self._refresh_failed, timeout=3)

    def _refresh_stage(self, metrics, now):
        payload = {"metrics": metrics}
        paths = [
            ("alerts", "/alerts", []),
            ("attackers", "/attackers", []),
            ("campaigns", "/campaigns", []),
            ("health", "/health", {}),
            ("interfaces", "/interfaces", []),
            ("current", "/interface/current", {}),
        ]
        self._refresh_payload = payload
        self._refresh_remaining = len(paths)
        self._refresh_now = now
        for key, path, default in paths:
            self.run_api_task(
                "GET",
                path,
                lambda data, key=key, default=default: self._refresh_collect(key, data if data is not None else default),
                on_error=lambda error, key=key, default=default: self._refresh_collect(key, default),
                timeout=3,
            )

    def _refresh_collect(self, key, data):
        self._refresh_payload[key] = data
        self._refresh_remaining -= 1
        if self._refresh_remaining <= 0:
            self._finish_refresh(self._refresh_payload, self._refresh_now)

    def _refresh_failed(self, message):
        self.refresh_inflight = False
        self.handle_api_error(message)

    def _finish_refresh(self, payload, now):
        self.refresh_inflight = False
        metrics = payload.get("metrics", {})
        raw_alerts = payload.get("alerts", [])
        attackers = payload.get("attackers", [])
        campaigns = payload.get("campaigns", [])
        health = payload.get("health", {})
        interfaces = payload.get("interfaces", [])
        current = payload.get("current", {})

        self.api_connected = bool(metrics or raw_alerts or attackers or health)
        alerts = [normalize_alert(alert) for alert in raw_alerts] if isinstance(raw_alerts, list) else []
        self.alert_cache = alerts
        pps = metrics.get("packets_per_second", 0)
        packet_total = metrics.get("total_packets") or metrics.get("packet_count") or 0
        self.current_interface = current.get("interface") or self.current_interface
        capture = health.get("capture", {})
        running = capture.get("running", False)

        self._update_interfaces(interfaces)
        self._update_cards(pps, alerts, attackers, running, packet_total)
        self._update_charts(pps, alerts)
        self._update_table(alerts)
        self._update_attack_types(alerts)
        self._update_intel(attackers, alerts)
        self._update_correlations(campaigns, alerts, attackers)
        if self.pages.currentIndex() == 6:
            self.load_alerts()
        if self.pages.currentIndex() == 7:
            self.load_live_traffic()
        
        self.capture_status.setText(f"Capture Status\n{'RUNNING' if running else 'STOPPED'}")
        self.side_interface.setText(f"Interface\n{self.current_interface}")
        self.side_uptime.setText(f"Uptime\n{self.uptime_card.value.text()}")
        self.footer_packets.setText(f"Packets Captured: {fmt_int(packet_total)}")
        self.footer_alerts.setText(f"Alerts (24h): {len(alerts)}")
        self.footer_blocked.setText(f"Blocked IPs: {len(attackers) if isinstance(attackers, list) else 0}")
        self.footer_updated.setText(f"Last Updated: {now.strftime('%H:%M:%S')}     Auto-refresh: ON")

    def _update_interfaces(self, interfaces):
        names = []
        for item in interfaces if isinstance(interfaces, list) else []:
            if isinstance(item, dict):
                name = item.get("name") or item.get("interface") or item.get("id")
                ip = item.get("ip") or item.get("address")
                names.append(f"{name} ({ip})" if ip else str(name))
            else:
                names.append(str(item))
        if not names:
            names = ["lo (127.0.0.1)", "eth0 (10.0.2.15)", "eth1 (192.168.100.20)"]
        if self.interface_combo.count() != len(names):
            self.interface_combo.blockSignals(True)
            self.header_interface.clear()
            self.interface_combo.clear()
            self.interface_list.clear()
            self.header_interface.addItems(names)
            self.interface_combo.addItems(names)
            self.interface_list.addItems(names)
            self.interface_combo.blockSignals(False)

    def open_threat_intel(self):

        self.pages.setCurrentWidget(
            self.intel_page
        )

        self.load_threat_intel()
    
    def open_correlations(self):

        self.pages.setCurrentWidget(
            self.correlation_page
        )

        self.load_correlations()    

    def _update_cards(self, pps, alerts, attackers, running, packet_total=0):
        pps_value = safe_float(pps)
        severity_order = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        highest = "LOW"

        for alert in alerts:
            sev = alert.get("severity", "LOW").upper()
            if severity_order.get(sev, 1) > severity_order.get(highest, 1):
                highest = sev

        threat = highest
        uptime_seconds = (datetime.now().hour * 3600 + datetime.now().minute * 60 + datetime.now().second) % 86400
        uptime = str(timedelta(seconds=uptime_seconds)).split(".")[0]
        active = sum(1 for alert in alerts if alert.get("status") == "ACTIVE")
        resolved = sum(1 for alert in alerts if alert.get("status") == "RESOLVED")
        self.packet_card.title.setText("TOTAL PACKETS")
        self.packet_card.subtitle.setText(f"Current PPS {fmt_int(pps)}")
        self.packet_card.set_value(fmt_int(packet_total), pps_value)
        self.alert_card.title.setText("ACTIVE ALERTS")
        self.alert_card.subtitle.setText(f"Resolved {resolved}")
        self.alert_card.set_value(str(active), active)
        self.threat_card.set_value(
            threat,
            severity_order.get(threat, 1)
        )
        self.run_api_task(
            "GET",
            "/firewall/rules",
            self._update_firewall_card,
        )
        self.uptime_card.set_value(uptime, 1 if running else 0)
    
    def _update_firewall_card(self, data):
        rules = data.get("rules", [])
        blocked = sum(
            1 for rule in rules
            if "DROP" in rule
        )

        self.blocked_card.set_value(str(blocked), blocked)
        self.footer_blocked.setText(f"Blocked IPs: {blocked}")
    
    def _update_charts(self, pps, alerts):
        self.traffic_points.append(safe_float(pps))
        self.traffic_curve.setData(list(self.traffic_points))
        alert_delta = max(0, len(alerts) - self.last_alert_total)
        self.last_alert_total = len(alerts)
        self.alert_bars.append(alert_delta)
        self.alert_plot.clear()
        x = list(range(len(self.alert_bars)))
        bars = pg.BarGraphItem(x=x, height=list(self.alert_bars), width=0.65, brush=COLORS["red"])
        self.alert_plot.addItem(bars)

    def _update_table(self, alerts):

        self.alert_table.clearContents()

        rows = min(5, len(alerts))

        self.alert_table.setRowCount(rows)

        for row in range(rows):

            alert = alerts[row]

            values = [
                alert.get("time", ""),
                alert.get("type", ""),
                alert.get("src_ip", ""),
                alert.get("dst_ip", ""),
                alert.get("severity", ""),
                alert.get("description", ""),
            ]


            for col, value in enumerate(values):

                item = QTableWidgetItem(str(value))

                if col == 4:
                    severity = str(value).upper()

                    if severity == "HIGH":
                        item.setForeground(QColor(COLORS["red"]))

                    elif severity == "MEDIUM":
                        item.setForeground(QColor(COLORS["orange"]))

                    elif severity == "LOW" :
                        item.setForeground(QColor(COLORS["green"]))

                self.alert_table.setItem(row, col, item)

    def load_live_traffic(self):

        try:
            packets = get_json("/packets", [])[:100]
            
            total_packets = len(packets)

            total_bytes = sum(
                p.get("size_bytes", 0)
                for p in packets
            )

            bandwidth = total_bytes / 1024

            from collections import Counter

            protocols = Counter(
            p.get("protocol", "OTHER")
            for p in packets
            )

            sources = Counter(
                p.get("src_ip", "")
                for p in packets
            )

            top_source = "-"

            if sources:
                top_source = sources.most_common(1)[0][0]

            proto_text = ", ".join(
                f"{k}:{v}"
                for k, v in protocols.items()
            )
            
            self.live_packets.setText(
                f"Packets : {total_packets}"
            )

            self.live_bandwidth.setText(
                f"Bandwidth : {bandwidth:.2f} KB"
            )

            self.live_protocols.setText(
                f"Protocols : {proto_text}"
            )

            self.live_sources.setText(
                f"Top Source : {top_source}"
            )

            self.live_table.setRowCount(
                len(packets)
            )

            for row, packet in enumerate(packets):
  
                timestamp = format_timestamp(
                    packet.get("timestamp", "")
                )
                info = f'{packet.get("src_port","-")} → {packet.get("dst_port","-")}'
 
                values = [
                    timestamp,
                    packet.get("src_ip", ""),
                    packet.get("dst_ip", ""),
                    packet.get("protocol", ""),
                    str(packet.get("size_bytes", "")),
                    info,
                ]

                for col, value in enumerate(values):
                    item = QTableWidgetItem(str(value))

                    if col == 3:

                        protocol = str(value)

                        if protocol == "TCP":
                            item.setForeground(QColor("#1687ff"))

                        elif protocol == "UDP":
                            item.setForeground(QColor("#ff9f0a"))

                        elif protocol == "ICMP":
                            item.setForeground(QColor("#27d66d"))                       
                    
                    
                    self.live_table.setItem(
                        row,
                        col,
                        item
                    )

        except Exception as e:
            logger.exception("Traffic refresh error: %s", e)
    
    def load_live_traffic(self):
        self.run_api_task("GET", "/packets", self._finish_live_traffic, on_error=lambda error: self.notify(f"Traffic refresh failed: {error}"), timeout=3)

    def _finish_live_traffic(self, data):
        packets = data if isinstance(data, list) else []
        limit = self.max_packets.value() if hasattr(self, "max_packets") else 100
        packets = packets[:limit]
        total_packets = len(packets)
        total_bytes = sum(safe_float(p.get("size_bytes", 0)) for p in packets)
        protocols = Counter(p.get("protocol", "OTHER") or "OTHER" for p in packets)
        sources = Counter(p.get("src_ip", "") for p in packets if p.get("src_ip"))
        sizes = [safe_float(p.get("size_bytes", 0)) for p in packets]
        pps = total_packets
        self.last_pps_values.append(pps)
        avg_pps = mean(self.last_pps_values) if self.last_pps_values else 0
        peak_pps = max(self.last_pps_values) if self.last_pps_values else 0
        top_source = sources.most_common(1)[0][0] if sources else "-"
        proto_text = ", ".join(f"{k}:{v}" for k, v in protocols.most_common()) or "-"
        size_text = f"avg {mean(sizes):.0f}B / max {max(sizes):.0f}B" if sizes else "-"

        self.live_packets.setText(f"PPS now/avg/peak : {pps:.0f} / {avg_pps:.1f} / {peak_pps:.0f}")
        self.live_bandwidth.setText(f"Bandwidth : {total_bytes / 1024:.2f} KB")
        self.live_protocols.setText(f"Protocols : {proto_text}")
        self.live_sources.setText(f"Top Source : {top_source} | Size : {size_text}")

        self.live_table.setSortingEnabled(False)
        self.live_table.setRowCount(len(packets))
        for row, packet in enumerate(packets):
            timestamp = format_timestamp(packet.get("timestamp", ""))
            info = f'{packet.get("src_port","-")} -> {packet.get("dst_port","-")}'
            values = [
                timestamp,
                packet.get("src_ip", ""),
                packet.get("dst_ip", ""),
                packet.get("protocol", ""),
                str(packet.get("size_bytes", "")),
                info,
            ]
            for col, value in enumerate(values):
                color = None
                if col == 3:
                    color = {"TCP": "#1687ff", "UDP": "#ff9f0a", "ICMP": "#27d66d"}.get(str(value).upper())
                self.live_table.setItem(row, col, table_item(value, color))
        self.live_table.setSortingEnabled(True)
        self.live_table.resizeRowsToContents()
        self.filter_table(self.live_table, self.live_search.text())

    def load_alerts(self):

        try:
            status = self.alert_filter.currentText()

            if status == "ALL":
                alerts = get_json("/alerts", [])
            else:
                alerts = get_json(
                f"/alerts?status={status}",
                [],
            )
            logger.debug("Selected alert filter=%s loaded=%s", status, len(alerts))
            high = 0
            medium = 0
            low = 0

            for alert in alerts:

                severity = alert.get(
                    "severity",
                    ""
                ).upper()

                if severity == "HIGH":
                    high += 1

                elif severity == "MEDIUM":
                    medium += 1

                elif severity == "LOW":
                    low += 1

            self.high_alerts.setText(
                f"HIGH\n{high}"
            )

            self.medium_alerts.setText(
                f"MEDIUM\n{medium}"
            )

            self.low_alerts.setText(
                f"LOW\n{low}"
            )

            self.total_alerts.setText(
                f"TOTAL\n{len(alerts)}"
            )

            self.alerts_table.setRowCount(
                len(alerts)
            )
            
            for row, alert in enumerate(alerts):

                timestamp = alert.get("timestamp", "")

                if "T" in timestamp:
                    timestamp = timestamp.split("T")[1][:8]

                values = [
                    alert.get("id", ""),
                    timestamp,
                    alert.get("severity", "").upper(),
                    alert.get("detector", ""),
                    alert.get("src_ip", ""),
                    alert.get("reason", ""),
                    str(alert.get("risk_score", "")),
                    str(alert.get("confidence", "")),
                    alert.get("action", ""),
                ]

                for col, value in enumerate(values):

                    item = QTableWidgetItem(str(value))

                    if col == 1:

                        severity = str(value).upper()

                        if severity == "HIGH":
                            item.setForeground(QColor(COLORS["red"]))

                        elif severity == "MEDIUM":
                            item.setForeground(QColor(COLORS["orange"]))

                        elif severity == "LOW":
                            item.setForeground(QColor(COLORS["green"]))

                    self.alerts_table.setItem(
                        row,
                        col,
                        item
                    )
            
            
        

        except Exception as error:

            logger.exception("Alerts refresh error: %s", error)
    def load_alerts(self):
        status = self.alert_filter.currentText() if hasattr(self, "alert_filter") else "ALL"
        path = "/alerts" if status == "ALL" else f"/alerts?status={status}"
        self.run_api_task("GET", path, self._finish_alerts, on_error=lambda error: self.notify(f"Alerts refresh failed: {error}"), timeout=3)

    def _finish_alerts(self, data):
        alerts = [normalize_alert(alert) for alert in data] if isinstance(data, list) else []
        self.alert_cache = alerts
        counts = Counter(alert["severity"] for alert in alerts)
        active = sum(1 for alert in alerts if alert["status"] == "ACTIVE")
        resolved = sum(1 for alert in alerts if alert["status"] == "RESOLVED")
        self.high_alerts.setText(f"HIGH\n{counts.get('HIGH', 0)}")
        self.medium_alerts.setText(f"MEDIUM\n{counts.get('MEDIUM', 0)}")
        self.low_alerts.setText(f"LOW\n{counts.get('LOW', 0)}")
        self.total_alerts.setText(f"TOTAL\n{len(alerts)}\nA:{active} R:{resolved}")

        self.alerts_table.setSortingEnabled(False)
        self.alerts_table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            values = [
                alert.get("id", ""),
                alert.get("time", ""),
                alert.get("status", ""),
                alert.get("severity", ""),
                alert.get("type", ""),
                alert.get("src_ip", ""),
                alert.get("description", ""),
                alert.get("risk_score", ""),
                alert.get("confidence", ""),
                alert.get("action", ""),
            ]
            for col, value in enumerate(values):
                color = severity_color(value) if col == 3 else COLORS["green"] if value == "RESOLVED" else None
                self.alerts_table.setItem(row, col, table_item(value, color))
        self.alerts_table.setSortingEnabled(True)
        self.alerts_table.resizeRowsToContents()
        self.filter_alerts()

    def filter_alerts(self):

        search = self.alert_search.text().lower()

        status = self.alert_filter.currentText()

        for row in range(self.alerts_table.rowCount()):

            visible = True

            if search:

                text = ""

                for col in range(
                    self.alerts_table.columnCount()
                ):

                    item = self.alerts_table.item(
                        row,
                        col
                    )

                    if item:
                        text += item.text().lower()

                if search not in text:
                    visible = False

            if status != "ALL":

                item = self.alerts_table.item(
                    row,
                    2
                )

                if item and item.text().upper() != status:
                    visible = False

            self.alerts_table.setRowHidden(
                row,
                not visible
            )

    def filter_table(self, table, text):
        needle = text.lower().strip()
        for row in range(table.rowCount()):
            if not needle:
                table.setRowHidden(row, False)
                continue
            haystack = " ".join(
                table.item(row, col).text().lower()
                for col in range(table.columnCount())
                if table.item(row, col)
            )
            table.setRowHidden(row, needle not in haystack)
    
    def export_alerts_csv(self):
        self.export_table(self.alerts_table, "alerts")

    def export_table(self, table, basename):
        filename, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Table",
            f"{basename}.csv",
            "CSV Files (*.csv);;JSON Files (*.json)",
        )
        if not filename:
            return
        headers = [table.horizontalHeaderItem(col).text() for col in range(table.columnCount())]
        rows = []
        for row in range(table.rowCount()):
            if table.isRowHidden(row):
                continue
            rows.append([
                table.item(row, col).text() if table.item(row, col) else ""
                for col in range(table.columnCount())
            ])
        try:
            if filename.lower().endswith(".json"):
                with open(filename, "w", encoding="utf-8") as file:
                    json.dump([dict(zip(headers, row)) for row in rows], file, indent=2)
            else:
                with open(filename, "w", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    writer.writerow(headers)
                    writer.writerows(rows)
            self.notify(f"Exported {len(rows)} rows to {filename}")
        except Exception as error:
            QMessageBox.warning(self, "Export", f"Export failed:\n{error}")
    
    def clear_alerts(self):

        answer = QMessageBox.question(self, "Alerts", "Clear alerts using the SecureOps API?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.run_api_task(
            "POST",
            "/alerts/clear",
            lambda result: (self.notify("Alerts cleared."), self.load_alerts()),
            on_error=lambda error: QMessageBox.warning(self, "Alerts", f"Could not clear alerts:\n{error}"),
            timeout=5,
        )
    
    def save_settings(self):

        import json
        settings = {
            "syn_threshold":
                self.syn_threshold.value(),
            "udp_threshold":
                self.udp_threshold.value(),
            "icmp_threshold":
                self.icmp_threshold.value(),
            "refresh_interval":
                self.refresh_interval.value(),
            "max_packets":
                self.max_packets.value(),
            "default_interface":
                self.default_interface.currentText(),
            "theme":
                self.theme_preference.currentText(),
        }
        with open(
            SETTINGS_FILE,
            "w"
        ) as file:

            json.dump(
                settings,
                file,
                indent=4
            )

        self.timer.setInterval(self.refresh_interval.value() * 1000)
        self.select_interface(self.default_interface.currentText())
        self._apply_style()
        self.notify("Settings saved and applied.")
    
    def load_settings(self):

        import json
        import os

        if not os.path.exists(SETTINGS_FILE):
            return
        try:
            with open(
                SETTINGS_FILE,
                "r"
            ) as file:
                settings = json.load(file)
            self.syn_threshold.setValue(
                settings.get(
                    "syn_threshold",
                    100
                )
            )

            self.udp_threshold.setValue(
                settings.get(
                    "udp_threshold",
                    100
                )
            )

            self.icmp_threshold.setValue(
                settings.get(
                    "icmp_threshold",
                    100
                )
            )

            self.refresh_interval.setValue(
                settings.get(
                    "refresh_interval",
                    1
                )
            )

            self.max_packets.setValue(
                settings.get(
                    "max_packets",
                    100
                )
            )
            theme = settings.get("theme", "Dark SOC")
            theme_index = self.theme_preference.findText(theme)
            if theme_index >= 0:
                self.theme_preference.setCurrentIndex(theme_index)

            interface = settings.get(
                "default_interface",
                ""
            )

            index = self.default_interface.findText(
                interface
            )

            if index >= 0:

                self.default_interface.setCurrentIndex(
                    index
                )
            self.timer.setInterval(self.refresh_interval.value() * 1000) if hasattr(self, "timer") else None

        except Exception as error:

            logger.exception("Settings error: %s", error)
    
    def show_alert_details(self, row, column):

        values = []

        for col in range(self.alerts_table.columnCount()):

            item = self.alerts_table.item(row, col)

            values.append(
                item.text() if item else "-"
            )

        message = f"""
    ID: {values[0]}

    Time: {values[1]}

    Status: {values[2]}

    Severity: {values[3]}

    Detector: {values[4]}

    Source IP: {values[5]}

    Reason: {values[6]}

    Risk Score: {values[7]}

    Confidence: {values[8]}

    Action: {values[9] if len(values) > 9 else "-"}
    """

        QMessageBox.information(
            self,
            "Alert Details",
            message
        )
        
    def alert_context_menu(self, position):

        row = self.alerts_table.currentRow()

        if row < 0:
            return

        menu = QMenu(self)

        view_action = menu.addAction("View Details")
        copy_action = menu.addAction("Copy Source IP")
        block_action = menu.addAction("Block IP")
        intel_action = menu.addAction("View Threat Intelligence")
        report_action = menu.addAction("Generate Incident Report")
        resolve_action = menu.addAction("Mark as Resolved")
        action = menu.exec(
            self.alerts_table.viewport().mapToGlobal(position)
        )

        if action == view_action:

            self.show_alert_details(row, 0)

        elif action == copy_action:

            ip = self.alerts_table.item(row, 3).text()

            QApplication.clipboard().setText(ip)
        
        elif action == block_action:

            self.block_ip(ip)

        elif action == intel_action:

            self.pages.setCurrentIndex(2)   # Update this index if your Threat Intel page uses a different one
            self.load_threat_intel()

        elif action == report_action:

            self.generate_report()

        elif action == resolve_action:

            alert_id = self.alerts_table.item(row, 0).text()

            try:

                response = requests.post(
                    f"{API_URL}/alerts/{alert_id}/resolve",
                    timeout=3,
                )

                result = response.json()

                if result.get("status") == "success":

                    QMessageBox.information(
                        self,
                        "Alert",
                        "Alert marked as resolved."
                    )

                    self.load_alerts()

                else:

                    QMessageBox.warning(
                        self,
                        "Alert",
                        result.get("message", "Unable to resolve alert.")
                    )

            except Exception as error:

                QMessageBox.warning(
                    self,
                    "Error",
                    str(error)
                )   

        elif action == report_action:

            self.generate_report()   
            
    def alert_context_menu(self, position):
        row = self.alerts_table.currentRow()
        if row < 0:
            return
        alert_id_item = self.alerts_table.item(row, 0)
        status_item = self.alerts_table.item(row, 2)
        ip_item = self.alerts_table.item(row, 5)
        alert_id = alert_id_item.text() if alert_id_item else ""
        status = status_item.text() if status_item else ""
        ip = ip_item.text() if ip_item else ""

        menu = QMenu(self)
        view_action = menu.addAction("View Details")
        copy_action = menu.addAction("Copy Source IP")
        block_action = menu.addAction("Block IP")
        intel_action = menu.addAction("View Threat Intelligence")
        report_action = menu.addAction("Generate Incident Report")
        resolve_action = menu.addAction("Mark as Resolved")
        delete_action = menu.addAction("Delete Alert")
        resolve_action.setEnabled(bool(alert_id) and status != "RESOLVED")
        delete_action.setEnabled(bool(alert_id))

        action = menu.exec(self.alerts_table.viewport().mapToGlobal(position))
        if action == view_action:
            self.show_alert_details(row, 0)
        elif action == copy_action and ip:
            QApplication.clipboard().setText(ip)
            self.notify(f"Copied {ip}")
        elif action == block_action and ip:
            self.block_ip(ip)
        elif action == intel_action:
            self.pages.setCurrentIndex(2)
            self.load_threat_intel()
        elif action == report_action:
            self.generate_report()
        elif action == resolve_action:
            self.resolve_alert(alert_id)
        elif action == delete_action:
            self.delete_alert(alert_id)

    def resolve_alert(self, alert_id):
        if not alert_id:
            return
        self.run_api_task(
            "POST",
            f"/alerts/{alert_id}/resolve",
            lambda result: (self.notify("Alert marked as resolved."), self.load_alerts()),
            on_error=lambda error: QMessageBox.warning(self, "Alert", f"Could not resolve alert:\n{error}"),
            timeout=4,
        )

    def delete_alert(self, alert_id):
        if not alert_id:
            return
        answer = QMessageBox.question(self, "Alert", f"Delete alert {alert_id}?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.run_api_task(
            "DELETE",
            f"/alerts/{alert_id}",
            lambda result: (self.notify("Alert deleted."), self.load_alerts()),
            on_error=lambda error: QMessageBox.warning(self, "Alert", f"Could not delete alert:\n{error}"),
            timeout=4,
        )

    def block_ip(self, ip):

        try:

            response = requests.post(
                f"{API_URL}/firewall/block",
                json={
                    "ip": ip
                },
                timeout=3
            )

            result = response.json()

            if result.get("status") == "success":
 
                QMessageBox.information(
                    self,
                    "Firewall",
                    f"{ip} blocked successfully."
                )

                self.load_firewall_rules()
 
            else:
 
                QMessageBox.warning(
                    self,
                    "Firewall",
                    result.get("message")
                )

        except Exception as error:

            QMessageBox.warning(
                self,
                "Firewall",
                str(error)
            )
            
    def block_ip(self, ip):
        if not ip:
            QMessageBox.information(self, "Firewall", "Enter an IP address to block.")
            return
        self.run_api_task(
            "POST",
            "/firewall/block",
            lambda result: (self.notify(f"{ip} blocked." if result.get("changed", True) else f"{ip} was already blocked."), self.load_firewall_rules()),
            payload={"ip": ip},
            on_error=lambda error: QMessageBox.warning(self, "Firewall", f"Could not block {ip}:\n{error}"),
            timeout=5,
        )

    def remove_selected_rule(self):

        row = self.firewall_table.currentRow()

        if row < 0:
            return

        ip = self.firewall_table.item(row, 1).text()

        try:

            requests.post(
                f"{API_URL}/firewall/unblock",
                json={
                    "ip": ip
                }
            )

            self.load_firewall_rules()

        except Exception as error:

            QMessageBox.warning(
                self,
                "Firewall",
                str(error)
            )        
    
    def clear_firewall(self):

        answer = QMessageBox.question(
            self,
            "Firewall",
            "Clear every firewall rule?"
        )

        if answer != QMessageBox.StandardButton.Yes:
            return

        try:
 
            requests.post(
                f"{API_URL}/firewall/clear"
            )

            self.load_firewall_rules()

        except Exception as error:

            QMessageBox.warning(
                self,
                "Firewall",
                str(error)
            )
    def open_firewall_logs(self):
        self.nav.setCurrentRow(6)
        self.load_firewall_rules()
            
    def _update_attack_types(self, alerts):
        counts = Counter(alert["type"] for alert in alerts)
        self.donut.set_counts(counts)
        while self.attack_legend.count():
            item = self.attack_legend.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for name, value, color in self.donut.data:
            label = QLabel(f"{name:<14} {value:>4}%")
            label.setStyleSheet(f"color:{COLORS['text']}; border-left: 9px solid {color}; padding-left: 8px;")
            self.attack_legend.addWidget(label)
        self.attack_legend.addStretch(1)

    def _update_intel(self, attackers, alerts):
        while self.intel_rows.count():
            item = self.intel_rows.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if attackers:
            rows = attackers[:5]
            for attacker in rows:
                ip = attacker.get("ip", "unknown")
                risk = attacker.get("risk_score", 0)
                rep = attacker.get("reputation", "Suspicious")
                severity = "HIGH" if float(risk or 0) >= 70 else "MEDIUM"
                label = QLabel(f"{ip:<18} {rep:<24} {severity}")
                label.setObjectName("DataRow")
                self.intel_rows.addWidget(label)
        else:
            for alert in alerts[:5]:
                label = QLabel(f"{alert['src_ip']:<18} {alert['type']:<24} {alert['severity']}")
                label.setObjectName("DataRow")
                self.intel_rows.addWidget(label)
        self.intel_rows.addStretch(1)

    def _update_correlations(self, campaigns, alerts, attackers):
        values = {
            "Active Campaigns": len(campaigns) if isinstance(campaigns, list) else 3,
            "Correlated Alerts": len(alerts) + 2,
            "Unique Attackers": len({alert["src_ip"] for alert in alerts}),
            "Affected Targets": len({alert["dst_ip"] for alert in alerts}),
            "Last Correlation": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        if attackers:
            values["Unique Attackers"] = len(attackers)
        for name, label in self.correlation_labels:
            label.setText(f"{name}    {values[name]}")
    
    def load_threat_intel(self):

        try:

            data = requests.get(
                f"{API_URL}/attackers",
                timeout=3
            ).json()

            self.intel_table.setRowCount(
                len(data)
            )

            for row, attacker in enumerate(data):

                self.intel_table.setItem(
                    row,
                    0,
                    QTableWidgetItem(
                        str(attacker.get("ip", "Unknown"))
                    )
                )

                self.intel_table.setItem(
                    row,
                    1,
                    QTableWidgetItem(
                        str(attacker.get("risk_score", 0))
                    )
                )

                self.intel_table.setItem(
                    row,
                    2,
                    QTableWidgetItem(
                        str(attacker.get(
                            "reputation",
                            "Unknown"
                        ))
                    )
                )

                self.intel_table.setItem(
                    row,
                    3,
                    QTableWidgetItem(
                        str(attacker.get(
                            "country",
                            "Unknown"
                        ))
                    )
                )

        except Exception as error:

            logger.exception("Threat intel refresh error: %s", error)
    def load_threat_intel(self):
        self.run_api_task("GET", "/attackers", self._finish_threat_intel, on_error=lambda error: self.notify(f"Threat intel refresh failed: {error}"), timeout=3)

    def _finish_threat_intel(self, data):
        attackers = data if isinstance(data, list) else []
        self.intel_table.setSortingEnabled(False)
        self.intel_table.setRowCount(len(attackers))
        for row, attacker in enumerate(attackers):
            risk = attacker.get("risk_score", 0)
            values = [
                attacker.get("ip", "Unknown"),
                risk,
                attacker.get("reputation", "Unknown"),
                attacker.get("country", "Unknown"),
                attacker.get("confidence", ""),
                format_timestamp(attacker.get("last_seen", attacker.get("timestamp", ""))),
                attacker.get("attack_count", ""),
                attacker.get("status", "Tracked"),
            ]
            for col, value in enumerate(values):
                color = COLORS["red"] if col == 1 and safe_float(value) >= 70 else COLORS["orange"] if col == 1 and safe_float(value) >= 40 else None
                self.intel_table.setItem(row, col, table_item(value, color))
        self.intel_table.setSortingEnabled(True)
        self.intel_table.resizeRowsToContents()
        self.filter_table(self.intel_table, self.intel_search.text())

    def load_correlations(self):

        try:

            data = requests.get(
                f"{API_URL}/campaigns",
                timeout=3
            ).json()

            self.correlation_table.setRowCount(
                len(data)
            )

            for row, campaign in enumerate(data):

                self.correlation_table.setItem(
                    row,
                    0,
                    QTableWidgetItem(
                        str(campaign.get("ip", "Unknown"))
                    )
                )

                self.correlation_table.setItem(
                    row,
                    1,
                    QTableWidgetItem(
                        str(campaign.get(
                            "campaign_type",
                            "Unknown"
                        ))
                    )
                )

                self.correlation_table.setItem(
                    row,
                    2,
                    QTableWidgetItem(
                        ", ".join(
                            campaign.get(
                                "attack_chain",
                                []
                            )
                        )
                    )
                )

                self.correlation_table.setItem(
                    row,
                    3,
                    QTableWidgetItem(
                        str(
                            campaign.get(
                                "risk_score",
                                0
                            )
                        )
                    )
                )

                self.correlation_table.setItem(
                    row,
                    4,
                    QTableWidgetItem(
                        str(
                            campaign.get(
                                "attack_count",
                                0
                            )
                        )
                    )
                )

        except Exception as error:

            logger.exception("Correlation refresh error: %s", error)
            
    def load_correlations(self):
        self.run_api_task("GET", "/campaigns", self._finish_correlations, on_error=lambda error: self.notify(f"Correlation refresh failed: {error}"), timeout=3)

    def _finish_correlations(self, data):
        campaigns = data if isinstance(data, list) else []
        self.correlation_table.setSortingEnabled(False)
        self.correlation_table.setRowCount(len(campaigns))
        for row, campaign in enumerate(campaigns):
            chain = campaign.get("attack_chain", [])
            related = campaign.get("related_alerts", campaign.get("alert_ids", []))
            hosts = campaign.get("affected_hosts", campaign.get("targets", []))
            timeline = campaign.get("timeline", campaign.get("last_seen", campaign.get("timestamp", "")))
            if isinstance(timeline, list):
                timeline = " -> ".join(format_timestamp(item) for item in timeline)
            else:
                timeline = format_timestamp(timeline)
            values = [
                campaign.get("ip", campaign.get("source_ip", "Unknown")),
                campaign.get("campaign_type", campaign.get("type", "Unknown")),
                ", ".join(chain) if isinstance(chain, list) else chain,
                campaign.get("risk_score", 0),
                campaign.get("attack_count", 0),
                ", ".join(map(str, related)) if isinstance(related, list) else related,
                ", ".join(map(str, hosts)) if isinstance(hosts, list) else hosts,
                timeline,
            ]
            for col, value in enumerate(values):
                color = COLORS["red"] if col == 3 and safe_float(value) >= 70 else COLORS["orange"] if col == 3 and safe_float(value) >= 40 else None
                self.correlation_table.setItem(row, col, table_item(value, color))
        self.correlation_table.setSortingEnabled(True)
        self.correlation_table.resizeRowsToContents()
        self.filter_table(self.correlation_table, self.correlation_search.text())

    def load_report(self):

        try:

            data = requests.get(
                f"{API_URL}/report/latest",
                timeout=3
            ).json()

            self.report_table.setRowCount(
                len(data)
            )

            for row, (key, value) in enumerate(
                data.items()
            ):

                self.report_table.setItem(
                    row,
                    0,
                    QTableWidgetItem(
                        str(key)
                    )
                )

                self.report_table.setItem(
                    row,
                    1,
                    QTableWidgetItem(
                        str(value)
                    )
                )

        except Exception as error:

            logger.exception("Report refresh error: %s", error)
    def load_report(self):
        self.run_api_task("GET", "/report/latest", self._finish_report, on_error=lambda error: self.notify(f"Report refresh failed: {error}"), timeout=5)

    def _finish_report(self, data):
        report = data if isinstance(data, dict) else {}
        self.report_table.setSortingEnabled(False)
        self.report_table.setRowCount(len(report))
        for row, (key, value) in enumerate(report.items()):
            if "time" in str(key).lower() or "date" in str(key).lower():
                value = format_timestamp(value)
            self.report_table.setItem(row, 0, table_item(key))
            self.report_table.setItem(row, 1, table_item(value))
        self.report_table.setSortingEnabled(True)
        self.report_table.resizeRowsToContents()
        self.filter_table(self.report_table, self.report_search.text())

    def delete_report(self):
        answer = QMessageBox.question(self, "Reports", "Delete selected/generated report metadata using the API?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.run_api_task(
            "DELETE",
            "/report/latest",
            lambda result: (self.notify("Report deleted."), self.load_report()),
            on_error=lambda error: QMessageBox.warning(self, "Reports", f"Could not delete report:\n{error}"),
            timeout=5,
        )

    def download_pdf(self):

        try:

            import webbrowser

            webbrowser.open(
                f"{API_URL}/report/pdf"
            )

        except Exception as error:

            logger.exception("PDF open error: %s", error)
    def run_phishing_check(self):
        url = self.phishing_url_input.text().strip()
        if not url:
            QMessageBox.information(self, "Phishing", "Enter a URL to analyze.")
            return
        self.run_api_task(
            "POST",
            "/phishing/check",
            self._finish_phishing_check,
            payload={"url": url},
            on_error=lambda error: QMessageBox.warning(self, "Phishing", f"Analysis failed:\n{error}"),
            timeout=6,
        )

    def _finish_phishing_check(self, result):
        data = result if isinstance(result, dict) else {}
        preferred = ["url", "verdict", "risk_score", "indicators", "recommendations"]
        rows = []
        for key in preferred:
            if key in data:
                rows.append((key, data[key]))
        rows.extend((key, value) for key, value in data.items() if key not in preferred)
        self.phishing_result.setSortingEnabled(False)
        self.phishing_result.setRowCount(len(rows))
        for row, (key, value) in enumerate(rows):
            if isinstance(value, list):
                value = ", ".join(map(str, value))
            elif isinstance(value, dict):
                value = json.dumps(value, ensure_ascii=False)
            self.phishing_result.setItem(row, 0, table_item(key))
            color = None
            if str(key).lower() in {"verdict", "risk_score"}:
                color = COLORS["red"] if "phish" in str(value).lower() or safe_float(value) >= 70 else COLORS["green"]
            self.phishing_result.setItem(row, 1, table_item(value, color))
        self.phishing_result.setSortingEnabled(True)
        self.phishing_result.resizeRowsToContents()
    
    def remove_selected_rule(self):
        row = self.firewall_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Firewall", "Select a firewall rule to unblock.")
            return
        ip_item = self.firewall_table.item(row, 1)
        ip = ip_item.text() if ip_item else ""
        if not ip:
            return
        answer = QMessageBox.question(self, "Firewall", f"Unblock {ip}?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.run_api_task(
            "POST",
            "/firewall/unblock",
            lambda result: (self.notify(f"{ip} unblocked." if result.get("changed", True) else f"{ip} was not blocked by SecureOps."), self.load_firewall_rules()),
            payload={"ip": ip},
            on_error=lambda error: QMessageBox.warning(self, "Firewall", f"Could not unblock {ip}:\n{error}"),
            timeout=5,
        )


    def clear_all_rules(self):
        answer = QMessageBox.question(self, "Firewall", "Clear every firewall rule?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.run_api_task(
            "POST",
            "/firewall/clear",
            lambda result: (self.notify(f"Removed {result.get('removed', 0)} SecureOps firewall rule(s)."), self.load_firewall_rules()),
            on_error=lambda error: QMessageBox.warning(self, "Firewall", f"Could not clear firewall rules:\n{error}"),
            timeout=6,
        )
                            
    def start_capture(self):
        self.run_api_task(
            "POST",
            "/capture/start",
            lambda result: (self.capture_status.setText("Capture Status\nRUNNING"), self.notify("Packet capture started.")),
            on_error=lambda error: QMessageBox.warning(self, "SecureOps", f"Could not start capture:\n{error}"),
            timeout=5,
        )

    def stop_capture(self):
        self.run_api_task(
            "POST",
            "/capture/stop",
            lambda result: (self.capture_status.setText("Capture Status\nSTOPPED"), self.notify("Packet capture stopped.")),
            on_error=lambda error: QMessageBox.warning(self, "SecureOps", f"Could not stop capture:\n{error}"),
            timeout=5,
        )

    def select_interface(self, text):
        if not text:
            return
        interface = text.split(" (", 1)[0]
        self.current_interface = text
        self.run_api_task(
            "POST",
            "/interface/select",
            lambda result: self.notify(f"Interface selected: {interface}"),
            payload={"interface": interface},
            on_error=lambda error: self.notify(f"Interface selection failed: {error}"),
            timeout=4,
        )

    def check_phishing(self):
        url = self.phishing_input.text().strip()
        if not url:
            QMessageBox.information(self, "SecureOps", "Enter a URL to check.")
            return
        self.run_api_task(
            "POST",
            "/phishing/check",
            lambda result: self.show_phishing_result(result) ,
            payload={"url": url},
            on_error=lambda error: QMessageBox.warning(self, "Phishing Check", f"Check failed:\n{error}"),
            timeout=6,
        )
        
    def logout(self):

        reply = QMessageBox.question(
            self,
            "Logout",
            "Do you want to logout?",
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        self.close()

        from secureops.gui.login import LoginWindow

        self.login_window = LoginWindow()
        self.login_window.show()        
    
    def logout(self):

        reply = QMessageBox.question(
            self,
            "Logout",
            "Do you want to logout?",
            QMessageBox.StandardButton.Yes |
            QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        self.close()

        from secureops.gui.login import LoginWindow

        self.login_window = LoginWindow()
        self.login_window.show()
    def change_password(self):

        dialog = ChangePasswordDialog(
            self.current_user
        )

        if dialog.exec():

            QMessageBox.information(
                self,
                "SecureOps",
                "Your password has been updated successfully."
            )
    
    def generate_report(self):
        self.run_api_task(
            "GET",
            "/report/pdf",
            lambda result: self.notify("PDF report generated by the SecureOps API."),
            on_error=lambda error: QMessageBox.warning(self, "SecureOps", f"Could not generate report:\n{error}"),
            timeout=8,
        )

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = SecureOpsDashboard()
    window.show()
    sys.exit(app.exec())
