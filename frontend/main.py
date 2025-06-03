# main.py

import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QObject

from login_window import LoginWindow
from chat_window import ChatWindow


class MainApp(QObject):
    """
    Orchestrates transitions between LoginWindow and ChatWindow.
    """

    def __init__(self):
        super().__init__()

        # Instantiate windows but don’t show chat until login succeeds
        self.login_window = LoginWindow()
        self.chat_window  = None  # will be created after login

        # Connect login success signal to handler
        # LoginWindow is expected to emit login_success(token: str, wallet_id: str)
        self.login_window.login_success.connect(self.on_login_success)

        # Show login (which also handles registration flow)
        self.login_window.show()

    def on_login_success(self, access_token: str, wallet_id: str):
        """
        Called when LoginWindow emits login_success.
        We then close login window and open the ChatWindow.
        """
        # Hide and delete the login window
        self.login_window.close()
        self.login_window = None

        # Instantiate ChatWindow, passing token and wallet_id
        self.chat_window = ChatWindow(access_token=access_token, wallet_id=wallet_id)
        self.chat_window.show()


if __name__ == "__main__":
    # Create the QApplication (only once)
    app = QApplication(sys.argv)

    # ─── Load and apply style.qss ───────────────────────────────────────────
    try:
        with open("style.qss", "r") as f:
            qss = f.read()
            app.setStyleSheet(qss)
    except FileNotFoundError:
        print("Warning: style.qss not found. Continuing without stylesheet.")

    # ─── Instantiate MainApp (which shows the login window) ─────────────────
    main_app = MainApp()

    # Run the Qt event loop
    sys.exit(app.exec_())
