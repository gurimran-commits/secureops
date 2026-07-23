from __future__ import annotations

import sys

from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
)

from secureops.auth.auth import AuthManager
from secureops.gui.dashboard import SecureOpsDashboard
from secureops.gui.login_page import LoginPage
from secureops.gui.setup_page import SetupPage

from secureops.auth import session

class LoginWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.auth = AuthManager()

        self.setWindowTitle("SecureOps")
        self.resize(600, 500)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_page = LoginPage()
        self.setup_page = SetupPage()

        self.stack.addWidget(self.login_page)
        self.stack.addWidget(self.setup_page)

        self.login_page.login_requested.connect(
            self.handle_login
        )

        self.setup_page.create_requested.connect(
            self.handle_create_admin
        )

        if self.auth.admin_exists():
            self.stack.setCurrentWidget(self.login_page)
        else:
            self.stack.setCurrentWidget(self.setup_page)

    def handle_login(
        self,
        username: str,
        password: str,
    ):

        if self.auth.authenticate(
            username,
            password,
        ):

            session.login(username)
            self.dashboard = SecureOpsDashboard(username)
            self.dashboard.show()
            self.close()

        else:

            QMessageBox.critical(
                self,
                "Login Failed",
                "Invalid username or password.",
            )

    def handle_create_admin(
        self,
        username: str,
        password: str,
    ):

        if self.auth.create_admin(
            username,
            password,
        ):

            QMessageBox.information(
                self,
                "SecureOps",
                "Administrator created successfully.",
            )

            session.login(username)
            self.dashboard = SecureOpsDashboard(username)
            self.dashboard.show()
            self.close()
        else:

            QMessageBox.warning(
                self,
                "SecureOps",
                "Administrator already exists.",
            )


def main():

    app = QApplication(sys.argv)

    window = LoginWindow()

    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
    
