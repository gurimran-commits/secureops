from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path

LOCAL_TZ = ZoneInfo("Asia/Kolkata")
try:
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
    )
except ImportError:  # pragma: no cover - depends on deployment extras
    getSampleStyleSheet = None
    Paragraph = None
    SimpleDocTemplate = None
    Spacer = None


class PDFReportGenerator:

    def generate(
        self,
        attacker,
        filename=None,
    ):
        filename = filename or self._default_filename(attacker)
        if SimpleDocTemplate is None:
            self._generate_basic_pdf(attacker, filename)
            return filename

        doc = SimpleDocTemplate(filename)

        styles = getSampleStyleSheet()

        content = []

        content.append(
            Paragraph(
                "SECUREOPS INCIDENT REPORT",
                styles["Title"],
            )
        )

        content.append(Spacer(1, 20))

        content.append(
            Paragraph(
                f"Generated At: {datetime.now(LOCAL_TZ).strftime('%d %B %Y, %I:%M:%S %p IST')}",
                styles["Normal"],
            )
        )

        content.append(
            Paragraph(
                f"Attacker IP: {attacker['ip']}",
                styles["Normal"],
            )
        )

        content.append(
            Paragraph(
                f"Country: {attacker['country']}",
                styles["Normal"],
            )
        )

        content.append(
            Paragraph(
                f"City: {attacker['city']}",
                styles["Normal"],
            )
        )

        content.append(
            Paragraph(
                f"ISP: {attacker['isp']}",
                styles["Normal"],
            )
        )

        content.append(
            Paragraph(
                f"Threat Reputation: {attacker['reputation']}",
                styles["Normal"],
            )
        )

        content.append(
            Paragraph(
                f"Confidence: {attacker['confidence']}%",
                styles["Normal"],
            )
        )
        content.append(
            Paragraph(
                f"Attack Count: {attacker['attack_count']}",
                styles["Normal"],
            )
        )

        content.append(
            Paragraph(
                f"Risk Score: {attacker['risk_score']}",
                styles["Normal"],
            )
        )

        content.append(
            Paragraph(
                "Attack Types: "
                + ", ".join(attacker["attack_types"]),
                styles["Normal"],
            )
        )

        content.append(
            Paragraph(
                "Recommended Action: Block source IP and review logs.",
                styles["Normal"],
            )
        )

        doc.build(content)

        return filename

    def _default_filename(self, attacker):
        reports_dir = Path("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(LOCAL_TZ).strftime("%Y%m%d_%H%M%S")
        ip = str(attacker.get("ip", "unknown")).replace(":", "_").replace("/", "_")
        return str(reports_dir / f"SecureOps_Incident_Report_{ip}_{timestamp}.pdf")

    def _generate_basic_pdf(self, attacker, filename):
        lines = [
            "SECUREOPS INCIDENT REPORT",
            f"Generated At: {datetime.now(LOCAL_TZ).strftime('%d %B %Y, %I:%M:%S %p IST')}",
            f"Attacker IP: {attacker['ip']}",
            f"Country: {attacker['country']}",
            f"City: {attacker['city']}",
            f"ISP: {attacker['isp']}",
            f"Threat Reputation: {attacker['reputation']}",
            f"Confidence: {attacker['confidence']}%",
            f"Attack Count: {attacker['attack_count']}",
            f"Risk Score: {attacker['risk_score']}",
            "Attack Types: " + ", ".join(attacker["attack_types"]),
            "Recommended Action: Block source IP and review logs.",
        ]
        escaped_lines = [
            line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            for line in lines
        ]
        text_commands = ["BT", "/F1 12 Tf", "72 760 Td"]
        for index, line in enumerate(escaped_lines):
            if index:
                text_commands.append("0 -18 Td")
            text_commands.append(f"({line}) Tj")
        text_commands.append("ET")
        stream = "\n".join(text_commands).encode("ascii", errors="replace")

        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n"
            + stream
            + b"\nendstream",
        ]
        content = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for number, obj in enumerate(objects, start=1):
            offsets.append(len(content))
            content.extend(f"{number} 0 obj\n".encode("ascii"))
            content.extend(obj)
            content.extend(b"\nendobj\n")
        xref_at = len(content)
        content.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        content.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            content.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        content.extend(
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF\n".encode("ascii")
        )
        with open(filename, "wb") as file:
            file.write(content)
