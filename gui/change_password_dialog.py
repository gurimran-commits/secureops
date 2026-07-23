from PyQt6.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
    QCheckBox,
)

from secureops.auth.auth import AuthManager
from secureops.gui.theme import COLORS
class ChangePasswordDialog(QDialog):

    def __init__(self, username):
        super().__init__()

        self.username = username
        self.auth = AuthManager()

        self.setWindowTitle("Change Password")
        self.setFixedSize(420, 320)

        self.setStyleSheet(f"""
            QDialog {{
                background:{COLORS["bg"]};
            }}

            QLabel {{
                color:white;
                font-size:13px;
            }}

            QLineEdit {{
                padding:8px;
                border:1px solid {COLORS["border"]};
                border-radius:6px;
                background:{COLORS["panel2"]};
                color:white;
            }}

            QPushButton {{
                padding:10px;
                border-radius:6px;
            }}
        """)

        layout = QVBoxLayout(self)

        title = QLabel("<h2>Change Password</h2>")
        layout.addWidget(title)

        layout.addWidget(QLabel("Current Password"))

        self.current = QLineEdit()
        self.current.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.current)

        layout.addWidget(QLabel("New Password"))

        self.new = QLineEdit()
        self.new.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.new)

        layout.addWidget(QLabel("Confirm Password"))

        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.confirm)

        self.show = QCheckBox("Show Passwords")
        self.show.toggled.connect(self.toggle_passwords)
        layout.addWidget(self.show)

        buttons = QHBoxLayout()

        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)

        change = QPushButton("Change Password")
        change.clicked.connect(self.change_password)

        buttons.addWidget(cancel)
        buttons.addWidget(change)

        layout.addLayout(buttons)

    def toggle_passwords(self, checked):

        mode = (
            QLineEdit.EchoMode.Normal
            if checked
            else QLineEdit.EchoMode.Password
        )

        self.current.setEchoMode(mode)
        self.new.setEchoMode(mode)
        self.confirm.setEchoMode(mode)

    def change_password(self):

        current = self.current.text()
        new = self.new.text()
        confirm = self.confirm.text()

        if not self.auth.authenticate(
            self.username,
            current,
        ):
            QMessageBox.warning(
                self,
                "SecureOps",
                "Current password is incorrect."
            )
            return

        if len(new) < 8:
            QMessageBox.warning(
                self,
                "SecureOps",
                "Password must contain at least 8 characters."
            )
            return

        if new != confirm:
            QMessageBox.warning(
                self,
                "SecureOps",
                "Passwords do not match."
            )
            return

        self.auth.change_password(
            self.username,
            new,
        )

        QMessageBox.information(
            self,
            "SecureOps",
            "Password changed successfully."
        )

        self.accept()
