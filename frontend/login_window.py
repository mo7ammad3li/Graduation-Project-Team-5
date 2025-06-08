# login_window.py

import os
import requests
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QFormLayout,
    QTextEdit,
    QHBoxLayout,
    QFrame,
    QCheckBox,
)

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from crypto_helper import (
    KEY_DIR,
    load_rsa_private_key,
    get_last_rsa_rotation,
    update_last_rsa_rotation,
)

API_BASE = "http://127.0.0.1:5000/api"


class PaymentDialog(QDialog):
    """
    Shows the Monero subaddress and required amount, polls /api/subscription/status
    every 10 seconds until payment is confirmed. Includes a button to copy.
    """
    payment_confirmed = pyqtSignal()

    def __init__(self, wallet_id: str, subaddress: str, amount_required: float, parent=None):
        super().__init__(parent)
        self.wallet_id       = wallet_id
        self.subaddress      = subaddress
        self.amount_required = amount_required

        self.setObjectName("paymentDialog")
        self.setWindowTitle("Payment Required")
        self.setModal(True)
        self.resize(450, 220)

        layout = QVBoxLayout()

        info = QLabel(f"Please send exactly {amount_required:.8f} XMR to:")
        info.setWordWrap(True)
        layout.addWidget(info)

        addr_layout = QHBoxLayout()
        self.address_box = QTextEdit(self)
        self.address_box.setObjectName("addressBox")
        self.address_box.setReadOnly(True)
        self.address_box.setFixedHeight(60)
        self.address_box.setText(subaddress)
        addr_layout.addWidget(self.address_box)

        copy_btn = QPushButton("Copy Address")
        copy_btn.setObjectName("copyAddressButton")
        copy_btn.clicked.connect(self.copy_to_clipboard)
        addr_layout.addWidget(copy_btn, alignment=Qt.AlignTop)
        layout.addLayout(addr_layout)

        self.status_label = QLabel("Awaiting on-chain confirmation…")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

        # Poll every 10 seconds
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_payment)
        self.timer.start(10000)
        QTimer.singleShot(1000, self.check_payment)

    def copy_to_clipboard(self):
        QGuiApplication.clipboard().setText(self.subaddress)
        QMessageBox.information(self, "Message", "Subaddress copied to clipboard.")

    def check_payment(self):
        try:
            resp = requests.get(
                f"{API_BASE}/subscription/status",
                params={"wallet_id": self.wallet_id}
            )
            data = resp.json()
            if resp.status_code == 200 and data.get("verified"):
                self.timer.stop()
                self.status_label.setText("Payment received!")
                self.payment_confirmed.emit()
                QTimer.singleShot(800, self.accept)
        except Exception:
            # swallow and retry
            pass


class LoginWindow(QMainWindow):
    """
    Login/register window. Emits login_success(access_token, wallet_id).
    """
    login_success = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setObjectName("loginWindow")
        self.setWindowTitle("Scomm — Login or Register")
        self.resize(400, 300)

        # Ensure key directory exists
        KEY_DIR.mkdir(parents=True, exist_ok=True)

        tabs = QTabWidget()
        tabs.setObjectName("authTabs")
        tabs.addTab(self._create_login_tab(),    "Login")
        tabs.addTab(self._create_register_tab(), "Register")
        self.setCentralWidget(tabs)

    def _create_login_tab(self) -> QWidget:
        # Container so QSS can target "loginContainer"
        container = QFrame()
        container.setObjectName("loginContainer")
        layout = QVBoxLayout(container)

        form = QFormLayout()
        form.setObjectName("loginForm")

        # Wallet ID
        self.login_wallet_input = QLineEdit()
        self.login_wallet_input.setObjectName("loginWalletInput")
        self.login_wallet_input.setPlaceholderText("Monero wallet ID")
        form.addRow("Wallet ID:", self.login_wallet_input)

        # Password + "Show Password" checkbox
        pwd_layout = QHBoxLayout()
        self.login_password_input = QLineEdit()
        self.login_password_input.setObjectName("loginPasswordInput")
        self.login_password_input.setEchoMode(QLineEdit.Password)
        self.login_password_input.setPlaceholderText("Password")
        pwd_layout.addWidget(self.login_password_input)

        self.login_show_pwd_cb = QCheckBox("Show")
        self.login_show_pwd_cb.setObjectName("loginShowPwd")
        self.login_show_pwd_cb.stateChanged.connect(self._toggle_login_password)
        pwd_layout.addWidget(self.login_show_pwd_cb)

        form.addRow("Password:", pwd_layout)

        layout.addLayout(form)

        btn = QPushButton("Login")
        btn.setObjectName("loginButton")
        btn.clicked.connect(self.handle_login)
        layout.addWidget(btn, alignment=Qt.AlignCenter)

        return container

    def _create_register_tab(self) -> QWidget:
        # Container so QSS can target "registerContainer"
        container = QFrame()
        container.setObjectName("registerContainer")
        layout = QVBoxLayout(container)

        form = QFormLayout()
        form.setObjectName("registerForm")

        # Wallet ID
        self.reg_wallet_input = QLineEdit()
        self.reg_wallet_input.setObjectName("regWalletInput")
        self.reg_wallet_input.setPlaceholderText("Choose a Monero wallet ID")
        form.addRow("Wallet ID:", self.reg_wallet_input)

        # Password + "Show Password" checkbox
        pwd_layout = QHBoxLayout()
        self.reg_password_input = QLineEdit()
        self.reg_password_input.setObjectName("regPasswordInput")
        self.reg_password_input.setEchoMode(QLineEdit.Password)
        self.reg_password_input.setPlaceholderText("Choose a password")
        pwd_layout.addWidget(self.reg_password_input)

        self.reg_show_pwd_cb = QCheckBox("Show")
        self.reg_show_pwd_cb.setObjectName("regShowPwd")
        self.reg_show_pwd_cb.stateChanged.connect(self._toggle_register_password)
        pwd_layout.addWidget(self.reg_show_pwd_cb)

        form.addRow("Password:", pwd_layout)

        # Subscription months
        self.reg_period_input = QLineEdit()
        self.reg_period_input.setObjectName("regPeriodInput")
        self.reg_period_input.setPlaceholderText("Subscription months (e.g. 1)")
        form.addRow("Months:", self.reg_period_input)

        layout.addLayout(form)

        btn = QPushButton("Register")
        btn.setObjectName("registerButton")
        btn.clicked.connect(self.handle_register)
        layout.addWidget(btn, alignment=Qt.AlignCenter)

        return container

    def _toggle_login_password(self, state: int):
        """
        Show/hide the login password field based on the checkbox state.
        """
        if state == Qt.Checked:
            self.login_password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.login_password_input.setEchoMode(QLineEdit.Password)

    def _toggle_register_password(self, state: int):
        """
        Show/hide the register password field based on the checkbox state.
        """
        if state == Qt.Checked:
            self.reg_password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.reg_password_input.setEchoMode(QLineEdit.Password)

    def show_error(self, msg: str):
        QMessageBox.critical(self, "Error", msg)

    def show_message(self, msg: str):
        QMessageBox.information(self, "Message", msg)

    def handle_login(self):
        w = self.login_wallet_input.text().strip()
        p = self.login_password_input.text().strip()
        if not w or not p:
            self.show_error("Please enter both wallet ID and password.")
            return

        try:
            r = requests.post(
                f"{API_BASE}/login",
                json={"wallet_id": w, "password": p}
            )
            data = r.json()
            if r.status_code != 200:
                self.show_message(data.get("error", "Login failed."))
                return

            token = data.get("access_token")
            if not token:
                self.show_error("No access token received.")
                return

            # RSA key rotation check
            last_rot = get_last_rsa_rotation()
            now = datetime.utcnow()
            if (not last_rot) or ((now - last_rot) > timedelta(hours=24)):
                # Generate new 2048-bit RSA keypair
                new_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                priv_pem = new_priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                priv_path = KEY_DIR / f"{w}_private_key.pem"
                with open(priv_path, "wb") as f:
                    f.write(priv_pem)

                pub_pem = new_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode("utf-8")

                headers = {"Authorization": f"Bearer {token}"}
                resp_upd = requests.post(
                    f"{API_BASE}/update_pubkey",
                    json={"pubkey": pub_pem},
                    headers=headers
                )
                if resp_upd.status_code != 200:
                    self.show_error("Failed to update public key on server.")
                    return

                update_last_rsa_rotation()
                self.privkey = new_priv
            else:
                try:
                    self.privkey = load_rsa_private_key(w)
                except Exception:
                    self.show_error("Could not load your private key. It may be missing or corrupted.")
                    return

            self.login_success.emit(token, w)

        except Exception as e:
            self.show_error(f"Server error during login:\n{e}")

    def handle_register(self):
        w    = self.reg_wallet_input.text().strip()
        p    = self.reg_password_input.text().strip()
        mtxt = self.reg_period_input.text().strip()

        if not (w and p and mtxt):
            self.show_error("All fields are required for registration.")
            return

        # --- Strong Password Validation ---
        if len(p) < 9:
            self.show_error("Password must be at least 9 characters long.")
            return
        if not any(c.isupper() for c in p):
            self.show_error("Password must contain at least one uppercase letter.")
            return
        if not any(c.islower() for c in p):
            self.show_error("Password must contain at least one lowercase letter.")
            return
        if not any(c.isdigit() for c in p):
            self.show_error("Password must contain at least one digit.")
            return
        if not any(not c.isalnum() for c in p):
            self.show_error("Password must contain at least one special character.")
            return
        # -------------------------------------

        # parse months
        try:
            months = int(mtxt)
            if months <= 0:
                raise ValueError()
        except ValueError:
            self.show_error("Months must be a positive integer.")
            return

        # generate RSA keypair
        try:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub  = priv.public_key()
        except Exception as e:
            self.show_error(f"Failed to generate keypair:\n{e}")
            return

        # save private key
        priv_path = KEY_DIR / f"{w}_private_key.pem"
        try:
            pem = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(priv_path, "wb") as f:
                f.write(pem)
        except Exception as e:
            self.show_error(f"Could not save private key:\n{e}")
            return

        # serialize public key
        try:
            pub_pem = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")
        except Exception as e:
            self.show_error(f"Public-key serialization failed:\n{e}")
            return

        # call register endpoint
        try:
            r = requests.post(
                f"{API_BASE}/register",
                json={"wallet_id": w, "password": p, "pubkey": pub_pem, "months": months}
            )
            data = r.json()
            if r.status_code not in (200, 201):
                # cleanup key file
                try:
                    os.remove(priv_path)
                except OSError:
                    pass
                self.show_message(data.get("error", "Registration failed."))
                return

            sub = data.get("subaddress")
            amt = data.get("amount_required")
            if not sub or amt is None:
                self.show_error("Unexpected server response.")
                return

            dlg = PaymentDialog(w, sub, amt, parent=self)
            dlg.payment_confirmed.connect(lambda: self._auto_login(w, p))
            dlg.exec_()

        except Exception as e:
            self.show_error(f"Server error during registration:\n{e}")

    def _auto_login(self, w: str, p: str):
        try:
            r = requests.post(
                f"{API_BASE}/login",
                json={"wallet_id": w, "password": p}
            )
            data = r.json()
            if r.status_code != 200:
                self.show_message(data.get("error", "Auto-login failed."))
                return

            token = data.get("access_token")
            if not token:
                self.show_error("Auto-login: no token received.")
                return

            # RSA key rotation on auto-login as well
            last_rot = get_last_rsa_rotation()
            now = datetime.utcnow()
            if (not last_rot) or ((now - last_rot) > timedelta(hours=24)):
                # Generate new RSA keypair
                new_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                priv_pem = new_priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                priv_path = KEY_DIR / f"{w}_private_key.pem"
                with open(priv_path, "wb") as f:
                    f.write(priv_pem)

                pub_pem = new_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode("utf-8")

                headers = {"Authorization": f"Bearer {token}"}
                resp_upd = requests.post(
                    f"{API_BASE}/update_pubkey",
                    json={"pubkey": pub_pem},
                    headers=headers
                )
                if resp_upd.status_code != 200:
                    self.show_error("Failed to update public key on server.")
                    return

                update_last_rsa_rotation()
                self.privkey = new_priv
            else:
                try:
                    self.privkey = load_rsa_private_key(w)
                except Exception:
                    self.show_error("Could not load your private key. It may be missing or corrupted.")
                    return

            # Emit login_success with token and wallet_id
            self.login_success.emit(token, w)

        except Exception as e:
            self.show_error(f"Server error during auto-login:\n{e}")
