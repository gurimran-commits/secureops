from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QMessageBox,
    QCheckBox,
)

from secureops.gui.dashboard import COLORS


class SetupPage(QWidget):

    create_requested = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.build_ui()

    def build_ui(self):

        layout = QVBoxLayout(self)

        layout.setContentsMargins(60, 40, 60, 40)
        layout.setSpacing(15)

        layout.addStretch()

        logo = QLabel("🛡")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet("font-size:48px;")
        layout.addWidget(logo)

        title = QLabel("Welcome to SecureOps")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f"""
            color:{COLORS["blue"]};
            font-size:30px;
            font-weight:bold;
        """)
        layout.addWidget(title)

        subtitle = QLabel(
            "Create your administrator account"
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(f"""
            color:{COLORS["muted"]};
            font-size:13px;
        """)
        layout.addWidget(subtitle)

        layout.addSpacing(25)

        layout.addWidget(QLabel("Username"))

        self.username = QLineEdit()
        self.username.setPlaceholderText(
            "Administrator username"
        )
        layout.addWidget(self.username)

        layout.addWidget(QLabel("Password"))

        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(
            QLineEdit.EchoMode.Password
        )
        layout.addWidget(self.password)

        layout.addWidget(QLabel("Confirm Password"))

        self.confirm = QLineEdit()
        self.confirm.setPlaceholderText(
            "Confirm password"
        )
        self.confirm.setEchoMode(
            QLineEdit.EchoMode.Password
        )
        layout.addWidget(self.confirm)

        self.show_password = QCheckBox(
            "Show Passwords"
        )
        self.show_password.toggled.connect(
            self.toggle_password
        )
        layout.addWidget(self.show_password)

        layout.addSpacing(10)

        self.create_button = QPushButton(
            "Create Administrator"
        )
        self.create_button.setMinimumHeight(45)
        self.create_button.clicked.connect(
            self.create_clicked
        )

        layout.addWidget(self.create_button)

        layout.addStretch()

    def toggle_password(self, checked):

        mode = (
            QLineEdit.EchoMode.Normal
            if checked
            else QLineEdit.EchoMode.Password
        )

        self.password.setEchoMode(mode)
        self.confirm.setEchoMode(mode)

    def create_clicked(self):

        username = self.username.text().strip()
        password = self.password.text()
        confirm = self.confirm.text()

        if not username:

            QMessageBox.warning(
                self,
                "SecureOps",
                "Please enter a username."
            )
            return

        if len(password) < 8:

            QMessageBox.warning(
                self,
                "SecureOps",
                "Password must be at least 8 characters."
            )
            return

        if password != confirm:

            QMessageBox.warning(
                self,
                "SecureOps",
                "Passwords do not match."
            )
            return

        self.create_requested.emit(
            username,
            password,
        )
