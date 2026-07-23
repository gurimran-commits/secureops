from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QMessageBox,
    QHBoxLayout,
    QCheckBox,
)

from secureops.gui.dashboard import COLORS


class LoginPage(QWidget):

    login_requested = pyqtSignal(str, str)

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

        title = QLabel("SecureOps")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f"""
            color:{COLORS["blue"]};
            font-size:34px;
            font-weight:bold;
        """)

        layout.addWidget(title)

        subtitle = QLabel("Intelligent Cyber Defense Platform")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(f"""
            color:{COLORS["muted"]};
            font-size:13px;
        """)

        layout.addWidget(subtitle)

        layout.addSpacing(25)

        user_label = QLabel("Username")
        layout.addWidget(user_label)

        self.username = QLineEdit()
        self.username.setPlaceholderText("Administrator username")
        layout.addWidget(self.username)

        pass_label = QLabel("Password")
        layout.addWidget(pass_label)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password)

        self.show_password = QCheckBox("Show Password")
        self.show_password.toggled.connect(self.toggle_password)
        layout.addWidget(self.show_password)

        layout.addSpacing(10)

        self.login_button = QPushButton("LOGIN")
        self.login_button.setMinimumHeight(45)
        self.login_button.clicked.connect(self.login_clicked)
        self.username.returnPressed.connect(self.password.setFocus)
        self.password.returnPressed.connect(self.login_button.click)
        self.username.setFocus()
        
        layout.addWidget(self.login_button)

        layout.addStretch()

    def toggle_password(self, checked):

        if checked:
            self.password.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password.setEchoMode(QLineEdit.EchoMode.Password)

    def login_clicked(self):

        username = self.username.text().strip()
        password = self.password.text()

        if not username:
            QMessageBox.warning(
                self,
                "SecureOps",
                "Please enter your username.",
            )
            return

        if not password:
            QMessageBox.warning(
                self,
                "SecureOps",
                "Please enter your password.",
            )
            return

        self.login_requested.emit(
            username,
            password,
        )
