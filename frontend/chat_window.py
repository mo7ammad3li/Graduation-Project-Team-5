# chat_window.py

import os
import time
import requests
import socketio
import base64
import webbrowser
from pathlib import Path
from datetime import datetime

from PyQt5.QtCore import Qt, QTimer, QSize
from PyQt5.QtGui import QColor, QBrush, QFont, QIcon
from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QInputDialog,
    QDialog,
    QFormLayout,
    QDialogButtonBox,
    QRadioButton,
    QFrame,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QMenu,
    QAction,
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from crypto_helper import (
    KEY_DIR,
    load_rsa_private_key,
    load_rsa_public_key,
    save_aes_key,
    load_aes_key,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    aes_encrypt,
    aes_decrypt,
    get_last_rsa_rotation,
    update_last_rsa_rotation,
    format_timestamp_ms,
)

API_BASE = "http://127.0.0.1:5000/api"


# ─── ChannelMessageDialog ─────────────────────────────────────────────────────
class ChannelMessageDialog(QDialog):
    """
    WhatsApp-style channel view:
      - Scrollable message area with “bubbles” (sent on right, received on left).
      - Bottom input row with QLineEdit + “Attach” + “Send” buttons.
      - Pressing Enter in the input sends immediately.
      - Automatically decrypts AES_GCM messages (or shows “📷 Sent a picture” for images).
      - Uses dedicated /api/key-exchange endpoints to swap AES keys instead of in-channel “KEY_EXCHANGE:…” messages.
    """

    def __init__(self, parent, access_token, wallet_id, channel_id, peer_wallet):
        super().__init__(parent)
        self.access_token = access_token
        self.wallet_id    = wallet_id
        self.channel_id   = channel_id
        self.peer_wallet  = peer_wallet

        # ─── Window Basics ───────────────────────────
        self.setWindowTitle(f"Channel #{channel_id} (with {peer_wallet})")
        self.resize(600, 700)
        self.setFont(QFont("Segoe UI", 11))
        self.setObjectName("channelDialog")

        # ─── Root Layout ─────────────────────────────
        root_v = QVBoxLayout()
        root_v.setContentsMargins(12, 12, 12, 12)
        root_v.setSpacing(10)
        self.setLayout(root_v)

        # ─── Scroll Area ────────────────────────────
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.scroll_area.setStyleSheet("background: #f8f9fa;")
        self.scroll_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        msgs_container = QWidget()
        msgs_layout = QVBoxLayout(msgs_container)
        msgs_layout.setContentsMargins(8, 8, 8, 8)
        msgs_layout.setSpacing(8)
        msgs_layout.addStretch(1)

        self.messages_container = msgs_container
        self.messages_layout   = msgs_layout
        self.scroll_area.setWidget(msgs_container)
        root_v.addWidget(self.scroll_area, stretch=1)

        # ─── Refresh Button ─────────────────────────
        btn_refresh = QPushButton("🔄 Refresh")
        btn_refresh.setFixedWidth(100)
        btn_refresh.setStyleSheet("""
            QPushButton {
                padding: 6px;
                background: #ffffff;
                border: 1px solid #dee2e6;
                border-radius: 9px;
            }
            QPushButton:hover { background: #e9ecef; }
        """)
        btn_refresh.clicked.connect(self.load_channel_messages)
        root_v.addWidget(btn_refresh, alignment=Qt.AlignRight)

        # ─── Input Row ──────────────────────────────
        input_frame = QFrame()
        input_frame.setObjectName("inputFrame")
        input_frame.setFrameShape(QFrame.NoFrame)
        input_frame.setFixedHeight(56)
        input_frame.setStyleSheet("background: white; border-top: 1px solid #e0e0e0;")
        input_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        h = QHBoxLayout(input_frame)
        h.setContentsMargins(12, 8, 12, 8)
        h.setSpacing(8)

        # Message line edit
        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Type a message…")
        self.msg_input.setStyleSheet("""
            QLineEdit {
                font-size: 13px;
                padding: 8px;
                border: 1px solid `#e0e0e0`;
                border-radius: 9px;
                background: white;
            }
        """)
        self.msg_input.setFixedHeight(40)
        self.msg_input.returnPressed.connect(self.send_channel_message)
        h.addWidget(self.msg_input, stretch=1)

        # Attach button
        self.btn_attach = QPushButton()
        self.btn_attach.setIcon(QIcon(":/icons/attach.png"))
        self.btn_attach.setIconSize(QSize(20, 20))
        self.btn_attach.setFixedSize(36, 36)
        self.btn_attach.setStyleSheet("""
            QPushButton {
                border: none;
                background: transparent;
                border-radius: 9px;
            }
            QPushButton:hover { background: #f0f0f0; }
        """)
        self.btn_attach.clicked.connect(self.attach_image)
        h.addWidget(self.btn_attach)

        # Send button
        self.btn_send = QPushButton()
        self.btn_send.setIcon(QIcon(":/icons/send.png"))
        self.btn_send.setIconSize(QSize(20, 20))
        self.btn_send.setFixedSize(36, 36)
        self.btn_send.setStyleSheet("""
            QPushButton {
                border: none;
                background: #0084ff;
                border-radius: 9px;
            }
            QPushButton:hover { background: #0077e6; }
            QPushButton:pressed { background: #006acc; }
        """)
        self.btn_send.clicked.connect(self.send_channel_message)
        h.addWidget(self.btn_send)

        root_v.addWidget(input_frame)

        # ─── State & Startup ────────────────────────
        self.last_channel_timestamp = 0
        self.aes_keys = {}  # will store { "channel_<id>": (version, key_bytes) }

        # Immediately attempt to load an existing AES key (if previously saved)
        chat_id = f"channel_{self.channel_id}"
        try:
            keybytes = load_aes_key(chat_id, "v1")
            self.aes_keys[chat_id] = ("v1", keybytes)
        except FileNotFoundError:
            pass

        #  Poll for any pending key‐exchange entries before generating our own
        self._poll_key_exchanges()

        # If no AES key yet, send our wrapped AES to the peer via /api/key-exchange/send
        if chat_id not in self.aes_keys:
            try:
                self._send_channel_key_exchange()
            except Exception as e:
                QMessageBox.warning(self, "Warning", f"Channel AES-key exchange failed:\n{e}")

        # Load existing messages
        self.load_channel_messages()

        # Start polling for new channel messages (and new key-exchanges)
        self.poll_timer = QTimer(self)
        self.poll_timer.timeout.connect(self.load_new_channel_messages)
        self.poll_timer.start(3000)


    def _poll_key_exchanges(self):
        """
        Poll /api/key-exchange for any entries addressed to self.peer_wallet → self.wallet_id.
        For each matching entry:
          1) base64-decode the encrypted_key
          2) rsa_decrypt with our private key
          3) save the AES key locally (and store in memory)
          4) DELETE the entry at /api/key-exchange/<id>
        """
        try:
            resp = requests.get(
                f"{API_BASE}/key-exchange",
                headers={"Authorization": f"Bearer {self.access_token}"}
            )
            if resp.status_code != 200:
                return
            entries = resp.json()
        except Exception:
            return

        chat_id = f"channel_{self.channel_id}"
        for entry in entries:
            sender = entry.get("from")
            if sender != self.peer_wallet:
                continue  # skip anything not from our peer

            wrapped_b64 = entry.get("encrypted_key", "")
            try:
                wrapped = base64.b64decode(wrapped_b64)
                aes_bytes = rsa_decrypt(self.parent().privkey, wrapped)
                version = "v1"
                # Store in memory & on disk
                self.aes_keys[chat_id] = (version, aes_bytes)
                save_aes_key(chat_id, version, aes_bytes)
                # Delete the server‐side entry so it won’t reappear
                key_id = entry.get("id")
                requests.delete(
                    f"{API_BASE}/key-exchange/{key_id}",
                    headers={"Authorization": f"Bearer {self.access_token}"}
                )
            except Exception:
                pass


    def _send_channel_key_exchange(self):
        """
        Generate a fresh AES key, wrap under peer’s RSA public key,
        and send it via POST /api/key-exchange/send.
        """
        # 1) Fetch peer’s RSA public key from server
        resp = requests.get(f"{API_BASE}/user/{self.peer_wallet}")
        if resp.status_code != 200 or not resp.json().get("exists"):
            raise Exception("Failed to fetch peer’s public key")

        peer_pub_pem = resp.json()["pubkey"]
        peer_pubkey = load_rsa_public_key(self.peer_wallet, peer_pub_pem)

        # 2) Generate new AES-256 key (32 bytes)
        new_aes = os.urandom(32)
        version = "v1"
        self.aes_keys[f"channel_{self.channel_id}"] = (version, new_aes)

        # 3) Wrap under peer’s RSA (OAEP-SHA256)
        wrapped = peer_pubkey.encrypt(
            new_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        b64_wrapped = base64.b64encode(wrapped).decode("utf-8")

        # 4) Send via dedicated key-exchange endpoint
        ts = int(time.time() * 1000)
        json_payload = {
            "recipient_wallet": self.peer_wallet,
            "encrypted_key": b64_wrapped,
            "timestamp": ts
        }
        resp2 = requests.post(
            f"{API_BASE}/key-exchange/send",
            json=json_payload,
            headers={"Authorization": f"Bearer {self.access_token}"}
        )
        if resp2.status_code not in (200, 201):
            raise Exception(f"KEY_EXCHANGE send failed: {resp2.text}")

        # 5) Save the AES key locally
        save_aes_key(f"channel_{self.channel_id}", version, new_aes)


    def load_channel_messages(self):
        """
        Fetch all messages for self.channel_id, decrypt AES_GCM payloads,
        and display bubbles. (Key exchange entries are handled separately via _poll_key_exchanges().)
        """
        chat_id = f"channel_{self.channel_id}"

        # 1) Poll for any new key-exchange entries before loading history
        self._poll_key_exchanges()

        # 2) Clear old bubbles (except final stretch)
        while self.messages_layout.count() > 1:
            widget_item = self.messages_layout.takeAt(0).widget()
            if widget_item:
                widget_item.deleteLater()

        # 3) Fetch channel history
        try:
            resp = requests.get(
                f"{API_BASE}/channel/{self.channel_id}/messages",
                headers={"Authorization": f"Bearer {self.access_token}"}
            )
            if resp.status_code != 200:
                raise Exception(resp.text)
            all_msgs = resp.json()
            all_msgs.sort(key=lambda x: x["timestamp"])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load channel messages:\n{e}")
            return

        # 4) Process each message (only 'AES_GCM:' or plaintext/image)
        for m in all_msgs:
            sender     = m.get("from")
            ciphertext = m.get("message", "")
            sig_b64    = m.get("signature", "")
            ts         = m.get("timestamp", 0)

            # If it’s an AES_GCM payload and we have the AES key, decrypt
            if ciphertext.startswith("AES_GCM:") and chat_id in self.aes_keys:
                try:
                    b64_payload = ciphertext.split("AES_GCM:", 1)[1]
                    payload_bytes = base64.b64decode(b64_payload)
                    _, keybytes = self.aes_keys[chat_id]
                    aesgcm = AESGCM(keybytes)
                    nonce = payload_bytes[:12]
                    ct_and_tag = payload_bytes[12:]
                    plaintext_bytes = aesgcm.decrypt(nonce, ct_and_tag, None)
                    plaintext = plaintext_bytes.decode("utf-8", errors="ignore")
                except Exception:
                    plaintext = "[Decryption error]"
            else:
                # Plaintext or image-data URI
                plaintext = ciphertext

            # If plaintext is an image-data URI
            if plaintext.startswith("data:image/"):
                display_text = "📷 Sent a picture"
            else:
                display_text = plaintext

            # Add a bubble
            self._add_private_bubble(
                sender_label=("Me" if sender == self.wallet_id else sender),
                plaintext=display_text,
                ts=ts
            )
            if ts > self.last_channel_timestamp:
                self.last_channel_timestamp = ts

        # 5) Auto-scroll to bottom
        QTimer.singleShot(100, lambda: self.scroll_area.verticalScrollBar().setValue(
            self.scroll_area.verticalScrollBar().maximum()
        ))


    def load_new_channel_messages(self):
        """
        Poll for new channel messages (AES_GCM or plaintext) since last_timestamp,
        and check again for new key-exchange entries.
        """
        chat_id = f"channel_{self.channel_id}"

        # 1) Poll for key-exchange before loading any new messages
        self._poll_key_exchanges()

        try:
            resp = requests.get(
                f"{API_BASE}/channel/{self.channel_id}/messages",
                headers={"Authorization": f"Bearer {self.access_token}"}
            )
            if resp.status_code != 200:
                return
            ch_msgs = resp.json()
            ch_msgs.sort(key=lambda x: x["timestamp"])
        except Exception:
            return

        for m in ch_msgs:
            ts = m.get("timestamp", 0)
            if ts > self.last_channel_timestamp:
                sender     = m.get("from")
                ciphertext = m.get("message", "")
                sig_b64    = m.get("signature", "")

                # AES_GCM decryption
                if ciphertext.startswith("AES_GCM:") and chat_id in self.aes_keys:
                    try:
                        b64_payload = ciphertext.split("AES_GCM:", 1)[1]
                        payload_bytes = base64.b64decode(b64_payload)
                        _, keybytes = self.aes_keys[chat_id]
                        aesgcm = AESGCM(keybytes)
                        nonce = payload_bytes[:12]
                        ct_and_tag = payload_bytes[12:]
                        plaintext_bytes = aesgcm.decrypt(nonce, ct_and_tag, None)
                        plaintext = plaintext_bytes.decode("utf-8", errors="ignore")
                    except Exception:
                        plaintext = "[Decryption error]"
                else:
                    plaintext = ciphertext

                if plaintext.startswith("data:image/"):
                    display_text = "📷 Sent a picture"
                else:
                    display_text = plaintext

                self._add_private_bubble(
                    sender_label=("Me" if sender == self.wallet_id else sender),
                    plaintext=display_text,
                    ts=ts
                )
                self.last_channel_timestamp = ts


    # ──────────────────────────────────────────────────────────────────────────
    #  MESSAGE BUBBLE HELPERS (for both PRIVATE and CHANNEL)
    # ──────────────────────────────────────────────────────────────────────────

    def _add_private_bubble(self, sender_label: str, plaintext: str, ts: int):
        """
        Create a ‘bubble’ QFrame for chat:
          • Sent (sender_label=="Me") appear on right in light green
          • Received appear on left in white
          • Each bubble shows text (or “📷 Sent a picture”) and timestamp
        """
        sent_color = "#dcf8c6"    # light green
        recv_color = "#ffffff"    # white
        border_radius = 12

        bubble = QFrame()
        bubble.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        bubble.setFrameShape(QFrame.NoFrame)

        h = QHBoxLayout(bubble)
        h.setContentsMargins(0, 0, 0, 0)

        inner = QFrame()
        inner.setFrameShape(QFrame.StyledPanel)
        inner_v = QVBoxLayout(inner)
        inner_v.setContentsMargins(8, 6, 8, 6)
        inner_v.setSpacing(4)

        # ── Message QLabel ───────────────────────────
        msg_label = QLabel(plaintext)
        msg_label.setWordWrap(True)
        msg_label.setFont(QFont("Segoe UI", 11))
        if sender_label == "Me":
            msg_label.setStyleSheet("color: black;")
        else:
            msg_label.setStyleSheet("color: #000000;")
        inner_v.addWidget(msg_label)

        ts_label = QLabel(format_timestamp_ms(ts))
        ts_label.setAlignment(Qt.AlignRight)
        ts_label.setStyleSheet("color: gray; font-size: 8pt;")
        inner_v.addWidget(ts_label)

        if sender_label == "Me":
            inner.setStyleSheet(f"""
                background-color: {sent_color};
                border-radius: {border_radius}px;
            """)
            h.addStretch(1)
            h.addWidget(inner, 0, Qt.AlignRight)
        else:
            inner.setStyleSheet(f"""
                background-color: {recv_color};
                border-radius: {border_radius}px;
            """)
            h.addWidget(inner, 0, Qt.AlignLeft)
            h.addStretch(1)

        # Insert bubble above the final stretch
        self.messages_layout.insertWidget(self.messages_layout.count() - 1, bubble)

        # Auto-scroll to bottom
        QTimer.singleShot(100, lambda: self.scroll_area.verticalScrollBar().setValue(
            self.scroll_area.verticalScrollBar().maximum()
        ))


    # second third

    def send_channel_message(self):
        """
        Encrypt & send a new channel message using AES_GCM + RSA signature.
        (No change here—channel messages still use AES_GCM and are posted to /api/channel/<id>/message.)
        """
        text = self.msg_input.text().strip()
        if not text:
            return

        ts = int(time.time() * 1000)
        chat_id = f"channel_{self.channel_id}"

        try:
            # 1) Ensure an AES key exists (otherwise, we must have already done key-exchange via /api/key-exchange)
            if chat_id not in self.aes_keys:
                raise Exception("No AES key available for this channel")

            _, aes_key = self.aes_keys[chat_id]

            # 2) AES‐GCM encrypt the plaintext (or image data‐URI)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, text.encode("utf-8"), None)
            payload_bytes = nonce + ct
            b64_payload = base64.b64encode(payload_bytes).decode("utf-8")
            final_msg = "AES_GCM:" + b64_payload

            # 3) RSA‐sign the ciphertext payload
            sig_bytes = rsa_sign(self.parent().privkey, payload_bytes)
            b64_sig = base64.b64encode(sig_bytes).decode("utf-8")

            # 4) Build & POST the JSON
            json_payload = {
                "message": final_msg,
                "signature": b64_sig,
                "timestamp": ts
            }
            resp = requests.post(
                f"{API_BASE}/channel/{self.channel_id}/message",
                json=json_payload,
                headers={"Authorization": f"Bearer {self.access_token}"}
            )
            if resp.status_code not in (200, 201):
                raise Exception(resp.text)

            # 5) Locally decrypt/re‐display the outgoing text
            self._add_private_bubble("Me", text, ts)
            self.msg_input.clear()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send channel message:\n{str(e)}")


    def attach_image(self):
        """
        Open file dialog, read selected image, convert to base64 data URI, and insert into input.
        (Shared by both channel and private contexts.)
        """
        fname, _ = QFileDialog.getOpenFileName(
            self,
            "Select Image",
            "",
            "Images (*.png *.jpg *.jpeg)"
        )
        if not fname:
            return
        path = Path(fname)
        try:
            mime_type = ""
            ext = path.suffix.lower()
            if ext == ".png":
                mime_type = "image/png"
            elif ext in (".jpg", ".jpeg"):
                mime_type = "image/jpeg"
            else:
                QMessageBox.warning(self, "Error", "Unsupported image format.")
                return

            with open(path, "rb") as f:
                data = f.read()
            b64 = base64.b64encode(data).decode()
            data_uri = f"data:{mime_type};base64,{b64}"

            self.msg_input.setText(data_uri)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to attach image:\n{str(e)}")


# ──────────────────────────────────────────────────────────────────────────────
#  ChatWindow (main window with sidebar + private‐chat bubbles)
# ──────────────────────────────────────────────────────────────────────────────
class ChatWindow(QMainWindow):
    """
    WhatsApp‐style main chat window:
      - Left sidebar with “New Chat”, menu button, and conversation list
      - Right pane: top header (chat name), scrollable bubble area, and input row
      - Private messages and channels open in bubble format
      - Press Enter to send; menu for settings
      - Uses dedicated /api/key-exchange for private key exchange
    """
    def __init__(self, access_token: str, wallet_id: str, privkey=None):
        super().__init__()
        self.access_token = access_token
        self.wallet_id    = wallet_id
        self.privkey      = privkey or load_rsa_private_key(wallet_id)
        self.aes_key_map  = {}  # maps chat_id -> raw AES key bytes
        self.setup_ui()

        # Socket.IO setup
        self.sio = socketio.Client()

        @self.sio.event
        def connect():
            self.sio.emit("join", {"wallet_id": self.wallet_id})

        @self.sio.on("new_private_message")
        def on_new_private_message(data):
            sender = data.get("from")
            recipient = data.get("to")
            if recipient == self.wallet_id:
                # If this chat is currently open and not a channel, show it immediately:
                if self.current_partner == sender and not self.current_channel:
                    self._handle_incoming_private(sender, data.get("message", ""),
                                                  data.get("signature", ""),
                                                  data.get("timestamp", 0))
                    self.load_conversations()
                else:
                    # Mark unread if it’s not the current chat
                    self.mark_unread(sender, private=True)
                    self.load_conversations()

        @self.sio.on("new_channel_message")
        def on_new_channel_message(data):
            channel_id = str(data.get("channel_id"))
            if not (self.current_channel == channel_id and not self.current_partner):
                self.mark_unread(channel_id, private=False)
                self.load_conversations()

        # ─── Window Setup ────────────────────────────────────────────────
        self.setObjectName("chatWindow")
        self.setWindowTitle(f"Chat – {wallet_id}")
        self.resize(900, 600)
        self.setFont(QFont("Segoe UI", 11))

        # ─── Main Layout ────────────────────────────────────────────────
        root_splitter = QSplitter(Qt.Horizontal)
        root_splitter.setHandleWidth(1)

        # ===== LEFT SIDEBAR =====
        sidebar_frame = QFrame()
        sidebar_frame.setObjectName("sidebarFrame")
        sidebar_frame.setMinimumWidth(240)
        sidebar_layout = QVBoxLayout(sidebar_frame)
        sidebar_layout.setContentsMargins(8, 8, 8, 8)
        sidebar_layout.setSpacing(8)

        # Top Button Row
        top_button_row = QHBoxLayout()
        top_button_row.setContentsMargins(0, 0, 0, 0)
        top_button_row.setSpacing(4)

        self.btn_new_chat = QPushButton("New Chat")
        self.btn_new_chat.setFixedHeight(40)
        self.btn_new_chat.setStyleSheet("""
            QPushButton {
                font-size: 13px;
                padding: 8px 12px;
                background: #ffffff;
                border: 1px solid #e0e0e0;
                border-radius: 9px;
            }
            QPushButton:hover { background: #f5f5f5; }
        """)
        self.btn_new_chat.clicked.connect(self.new_chat)
        top_button_row.addWidget(self.btn_new_chat)

        self.menu_button = QPushButton("☰")
        self.menu_button.setFixedSize(40, 40)
        self.menu_button.setStyleSheet("""
            QPushButton {
                font-size: 20px;
                border: 1px solid #e0e0e0;
                border-radius: 9px;
                background: #ffffff;
            }
            QPushButton:hover { background: #f5f5f5; }
        """)
        top_button_row.addWidget(self.menu_button)
        sidebar_layout.addLayout(top_button_row)

        # Conversation List
        self.conversation_list = QListWidget()
        self.conversation_list.setObjectName("conversationList")
        self.conversation_list.setVerticalScrollMode(QListWidget.ScrollPerPixel)
        self.conversation_list.itemClicked.connect(self.on_conversation_selected)
        sidebar_layout.addWidget(self.conversation_list)

        root_splitter.addWidget(sidebar_frame)

        # ===== RIGHT PANE =====
        main_frame  = QFrame()
        main_frame.setObjectName("mainFrame")
        main_layout = QVBoxLayout(main_frame)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Header
        header_frame = QFrame()
        header_frame.setFixedHeight(56)
        header_frame.setStyleSheet("background: #ffffff; border-bottom: 1px solid #e0e0e0;")
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(16, 0, 16, 0)

        self.chat_title = QLabel("No chat selected")
        self.chat_title.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: 600;
                color: #000000;
            }
        """)
        header_layout.addWidget(self.chat_title)
        main_layout.addWidget(header_frame)

        # Message Area
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("border: none; background: #f8f9fa;")
        self.scroll_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.messages_container = QWidget()
        self.messages_layout = QVBoxLayout(self.messages_container)
        self.messages_layout.setContentsMargins(16, 16, 16, 16)
        self.messages_layout.setSpacing(8)
        self.messages_layout.addStretch(1)

        self.scroll_area.setWidget(self.messages_container)
        main_layout.addWidget(self.scroll_area)

        # Input Area
        input_frame = QFrame()
        input_frame.setFixedHeight(72)
        input_frame.setStyleSheet("background: #ffffff; border-top: 1px solid #e0e0e0;")
        input_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        input_layout = QHBoxLayout(input_frame)
        input_layout.setContentsMargins(16, 12, 16, 12)
        input_layout.setSpacing(8)

        self.message_input = QLineEdit()
        self.message_input.setObjectName("messageInput")
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.setStyleSheet("""
            QLineEdit {
                font-size: 14px;
                padding: 12px;
                border: 1px solid #e0e0e0;
                border-radius: 9px;
                background: #808080;
            }
        """)
        self.message_input.setFixedHeight(44)
        self.message_input.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.message_input)

        self.btn_attach = QPushButton()
        self.btn_attach.setIcon(QIcon(":/icons/attach.png"))
        self.btn_attach.setIconSize(QSize(20, 20))
        self.btn_attach.setFixedSize(44, 44)
        self.btn_attach.setStyleSheet("""
            QPushButton {
                border: black;
                background: grey;
                border-radius: 9px;
            }
            QPushButton:hover { background: #f0f0f0; }
        """)
        self.btn_attach.clicked.connect(self.attach_image)
        input_layout.addWidget(self.btn_attach)

        self.send_button = QPushButton()
        self.send_button.setObjectName("sendButton")
        self.send_button.setIcon(QIcon(":/icons/send.png"))
        self.send_button.setIconSize(QSize(20, 20))
        self.send_button.setFixedSize(44, 44)
        self.send_button.setStyleSheet("""
            QPushButton {
                border: none;
                background: #0084ff;
                border-radius: 9px;
            }
            QPushButton:hover { background: #0077e6; }
            QPushButton:pressed { background: #006acc; }
        """)
        self.send_button.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_button)

        main_layout.addWidget(input_frame)
        root_splitter.addWidget(main_frame)
        self.setCentralWidget(root_splitter)

        # ─── Menu Setup ───────────────────────────────────────────────
        menu = QMenu(self)
        actions = [
            ("Change Password", self.change_password),
            ("Renew Subscription", self.renew_subscription),
            ("Block User", self.block_user),
            ("Help", lambda: webbrowser.open(f"{API_BASE.replace('/api','')}/help")),
            ("Logout", self.logout)
        ]
        for text, callback in actions:
            action = QAction(text, self)
            action.triggered.connect(callback)
            menu.addAction(action)
        self.menu_button.setMenu(menu)

        # ─── State Management ──────────────────────────────────────────
        self.current_partner = None
        self.current_channel = None
        self.last_timestamp  = 0
        self._unread_map     = {}
        self.channel_list_data = []

        # Start Socket.IO connection
        self.sio.connect(
            "http://127.0.0.1:5000",
            headers={"Authorization": f"Bearer {self.access_token}"}
        )

        # Initial load
        self.load_conversations()
        self.private_poll_timer = QTimer(self)
        self.private_poll_timer.timeout.connect(self.poll_new_messages)
        self.private_poll_timer.start(3000)

    def _add_private_bubble(self, sender_label: str, plaintext: str, ts: int):
        """
        Create a ‘bubble’ QFrame for chat:
          • Sent (sender_label=="Me") appear on right in light green
          • Received appear on left in white
          • Each bubble shows text (or “📷 Sent a picture”) and timestamp
        """
        sent_color = "#dcf8c6"    # light green
        recv_color = "#ffffff"    # white
        border_radius = 12

        bubble = QFrame()
        bubble.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        bubble.setFrameShape(QFrame.NoFrame)

        h = QHBoxLayout(bubble)
        h.setContentsMargins(0, 0, 0, 0)

        inner = QFrame()
        inner.setFrameShape(QFrame.StyledPanel)
        inner_v = QVBoxLayout(inner)
        inner_v.setContentsMargins(8, 6, 8, 6)
        inner_v.setSpacing(4)

        # ── Message QLabel ───────────────────────────
        msg_label = QLabel(plaintext)
        msg_label.setWordWrap(True)
        msg_label.setFont(QFont("Segoe UI", 11))
        if sender_label == "Me":
            msg_label.setStyleSheet("color: black;")
        else:
            msg_label.setStyleSheet("color: #000000;")
        inner_v.addWidget(msg_label)

        ts_label = QLabel(format_timestamp_ms(ts))
        ts_label.setAlignment(Qt.AlignRight)
        ts_label.setStyleSheet("color: gray; font-size: 8pt;")
        inner_v.addWidget(ts_label)

        if sender_label == "Me":
            inner.setStyleSheet(f"""
                background-color: {sent_color};
                border-radius: {border_radius}px;
            """)
            h.addStretch(1)
            h.addWidget(inner, 0, Qt.AlignRight)
        else:
            inner.setStyleSheet(f"""
                background-color: {recv_color};
                border-radius: {border_radius}px;
            """)
            h.addWidget(inner, 0, Qt.AlignLeft)
            h.addStretch(1)

        # Insert bubble above the final stretch
        self.messages_layout.insertWidget(self.messages_layout.count() - 1, bubble)

        # Auto-scroll to bottom
        QTimer.singleShot(100, lambda: self.scroll_area.verticalScrollBar().setValue(
            self.scroll_area.verticalScrollBar().maximum()
        ))


    def setup_ui(self):
        """
        Placeholder in case additional setup is needed. For now,
        everything is initialized in __init__ directly.
        """
        pass

    def _get_private_chat_id(self, partner: str) -> str:
        return f"{self.wallet_id}_{partner}"

    # ──────────────────────────────────────────────────────────────────────────
    #  PRIVATE KEY-EXCHANGE + ENCRYPTION HANDLERS
    # ──────────────────────────────────────────────────────────────────────────

    def _poll_key_exchanges(self, partner: str):
        """
        Poll /api/key-exchange for any entries addressed to self.wallet_id from `partner`.
        For each matching entry:
          1) base64-decode the encrypted_key
          2) rsa_decrypt with our private key
          3) save the AES key locally (under "<self>_<partner>")
          4) DELETE the entry at /api/key-exchange/<id>
          5) store in self.aes_key_map
        """
        try:
            resp = requests.get(
                f"{API_BASE}/key-exchange",
                headers={"Authorization": f"Bearer {self.access_token}"}
            )
            if resp.status_code != 200:
                return
            entries = resp.json()
        except Exception:
            return

        chat_id = f"{self.wallet_id}_{partner}"
        for entry in entries:
            sender = entry.get("from")
            if sender != partner:
                continue  # skip entries not from our chat partner

            wrapped_b64 = entry.get("encrypted_key", "")
            try:
                wrapped = base64.b64decode(wrapped_b64)
                aes_bytes = rsa_decrypt(self.privkey, wrapped)
                version = "v1"
                # Save to disk & memory
                save_aes_key(chat_id, version, aes_bytes)
                self.aes_key_map[chat_id] = aes_bytes
                # Delete the server-side entry
                key_id = entry.get("id")
                requests.delete(
                    f"{API_BASE}/key-exchange/{key_id}",
                    headers={"Authorization": f"Bearer {self.access_token}"}
                )
            except Exception:
                pass


    def _get_or_create_aes_key(self, partner: str):
        """
        Retrieve or generate an AES key for private chat with `partner`.
        New flow:
        1) Poll /api/key-exchange for any pending entries from `partner`. If found, decrypt and use it.
        2) If no key in memory or disk, generate new AES, wrap under partner’s RSA, and POST /api/key-exchange/send.
        """
        chat_id = f"{self.wallet_id}_{partner}"

        # 1) Poll for an incoming wrapped AES key
        self._poll_key_exchanges(partner)
        if chat_id in self.aes_key_map:
            return self.aes_key_map[chat_id]

        # 2) Try to load from disk
        try:
            keybytes = load_aes_key(chat_id, "v1")
            self.aes_key_map[chat_id] = keybytes
            return keybytes
        except FileNotFoundError:
            pass

        # 3) No key → generate new AES and send via /api/key-exchange/send
        new_aes = os.urandom(32)

        # Fetch partner's RSA public key
        resp = requests.get(f"{API_BASE}/user/{partner}")
        if resp.status_code != 200 or not resp.json().get("exists"):
            raise Exception("Failed to fetch partner’s public key")
        partner_pub_pem = resp.json()["pubkey"]
        partner_pubkey = load_rsa_public_key(partner, partner_pub_pem)

        # Wrap under RSA-OAEP (SHA-256)
        wrapped = partner_pubkey.encrypt(
            new_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        b64_wrapped = base64.b64encode(wrapped).decode("utf-8")

        # Send KEY_EXCHANGE via dedicated endpoint
        ts = int(time.time() * 1000)
        json_payload = {
            "recipient_wallet": partner,
            "encrypted_key": b64_wrapped,
            "timestamp": ts
        }
        resp2 = requests.post(
            f"{API_BASE}/key-exchange/send",
            json=json_payload,
            headers={"Authorization": f"Bearer {self.access_token}"}
        )
        if resp2.status_code not in (200, 201):
            raise Exception("Failed to send key exchange to partner.")

        # Save new AES key locally
        save_aes_key(chat_id, "v1", new_aes)
        self.aes_key_map[chat_id] = new_aes
        return new_aes


    def _handle_incoming_private(self, sender: str, text: str, sig_b64: str, ts: int):
        """
        Handle incoming private messages: AES_GCM (with RSA signature) or plaintext.
        We no longer expect KEY_EXCHANGE: in `text`. Instead, key-exchange is polled separately.
        """
        # 1) Before handling any new ciphertext, attempt to poll for a key-exchange
        self._poll_key_exchanges(sender)

        # Fetch sender's public key (needed for signature verification)
        resp = requests.get(f"{API_BASE}/user/{sender}")
        data = resp.json()
        if resp.status_code != 200 or not data.get("exists"):
            return
        sender_pub_pem = data["pubkey"]
        sender_pubkey = load_rsa_public_key(sender, sender_pub_pem)

        # 2) AES_GCM payload
        if text.startswith("AES_GCM:"):
            b64_payload = text.split("AES_GCM:", 1)[1]
            payload_bytes = base64.b64decode(b64_payload)
            sig_bytes = base64.b64decode(sig_b64)

            # Verify signature
            if not rsa_verify(sender_pubkey, sig_bytes, payload_bytes):
                QMessageBox.critical(self, "Error", "Invalid signature—message tampered.")
                return

            chat_id = self._get_private_chat_id(sender)
            # Ensure key exists
            if chat_id not in self.aes_key_map:
                try:
                    keybytes = load_aes_key(chat_id, "v1")
                    self.aes_key_map[chat_id] = keybytes
                except FileNotFoundError:
                    QMessageBox.warning(self, "Error", "No AES key for this chat.")
                    return

            aes_key = self.aes_key_map[chat_id]
            try:
                aesgcm = AESGCM(aes_key)
                nonce = payload_bytes[:12]
                ct_and_tag = payload_bytes[12:]
                plaintext_bytes = aesgcm.decrypt(nonce, ct_and_tag, None)
                plaintext = plaintext_bytes.decode("utf-8", errors="ignore")
            except Exception:
                QMessageBox.critical(self, "Error", "Failed to decrypt message.")
                plaintext = "[Decryption error]"

            sender_label = "Me" if sender == self.wallet_id else sender
            self._add_private_bubble(sender_label, plaintext, ts)
            if ts > self.last_timestamp:
                self.last_timestamp = ts
            return

        # 3) Plaintext fallback
        sender_label = "Me" if sender == self.wallet_id else sender
        self._add_private_bubble(sender_label, text, ts)
        if ts > self.last_timestamp:
            self.last_timestamp = ts


    # ──────────────────────────────────────────────────────────────────────────
    #  LOAD & DISPLAY CONVERSATION LIST
    # ──────────────────────────────────────────────────────────────────────────

    def load_conversations(self):
        """
        Build and display a list of all private partners and channels:
          • For private: show “wallet_id – last_message_snippet”
          • For channel: show “[Group] name – last_message_snippet”
          • If last_message was a picture, use “📷 Sent a picture”
          • Mark unread items in red
        (No changes needed here for key-exchange.)
        """
        try:
            # 1) Fetch all private messages
            resp = requests.get(f"{API_BASE}/messages", headers={"Authorization": f"Bearer {self.access_token}"})
            if resp.status_code != 200:
                raise Exception(resp.text)
            msgs = resp.json()

            private_map = {}
            # Determine the latest snippet for each private partner
            for m in msgs:
                sender    = m.get("from")
                recipient = m.get("to")
                ts        = m.get("timestamp")
                ciphertext = m.get("message", "")
                if sender is None or recipient is None or ts is None:
                    continue

                # Determine the “other side” of this conversation
                partner = recipient if sender == self.wallet_id else sender

                # ─── TRY TO DECRYPT THIS CIPHERTEXT TO A PLAIN SNIPPET ───
                snippet = ""
                if ciphertext.startswith("AES_GCM:"):
                    chat_id = self._get_private_chat_id(partner)
                    if chat_id in self.aes_key_map:
                        try:
                            b64_payload = ciphertext.split("AES_GCM:", 1)[1]
                            payload_bytes = base64.b64decode(b64_payload)
                            aes_key = self.aes_key_map[chat_id]
                            plaintext_bytes = aes_decrypt(aes_key, payload_bytes)
                            snippet = plaintext_bytes.decode("utf-8", errors="ignore")
                        except Exception:
                            snippet = "[Encrypted]"
                    else:
                        snippet = "[Encrypted]"
                elif ciphertext.startswith("data:image/"):
                    snippet = "📷 Sent a picture"
                else:
                    snippet = ciphertext

                if sender == self.wallet_id:
                    snippet = f"Me: {snippet}"

                existing = private_map.get(partner)
                if not existing or existing["timestamp"] < ts:
                    private_map[partner] = {"last_msg": snippet, "timestamp": ts}

            # 2) Fetch channels
            resp2 = requests.get(f"{API_BASE}/channels", headers={"Authorization": f"Bearer {self.access_token}"})
            if resp2.status_code != 200:
                raise Exception(resp2.text)
            chans = resp2.json()

            channel_map = {}
            for c in chans:
                cid_str = str(c["id"])
                channel_map[cid_str] = {"name": c["name"], "last_msg": "", "timestamp": 0}

            for cid_str in channel_map.keys():
                resp_ch = requests.get(
                    f"{API_BASE}/channel/{cid_str}/messages",
                    headers={"Authorization": f"Bearer {self.access_token}"}
                )
                if resp_ch.status_code != 200:
                    continue
                ch_msgs = resp_ch.json()
                if not isinstance(ch_msgs, list) or not ch_msgs:
                    continue
                ch_msgs.sort(key=lambda x: x["timestamp"])
                last = ch_msgs[-1]
                snippet = last["message"]
                if snippet.startswith("AES_GCM:") or snippet.startswith("data:image/"):
                    snippet = "📷 Sent a picture"
                else:
                    snippet = snippet[:20] + "…" if len(snippet) > 23 else snippet

                channel_map[cid_str]["last_msg"] = snippet
                channel_map[cid_str]["timestamp"] = last["timestamp"]

            # 3) Combine & sort
            combined = []
            for p, info in private_map.items():
                combined.append({
                    "type": "private",
                    "key": p,
                    "display": p,
                    "last_msg": info["last_msg"],
                    "timestamp": info["timestamp"]
                })
            for cid_str, info in channel_map.items():
                combined.append({
                    "type": "channel",
                    "key": cid_str,
                    "display": f"[Group] {info['name']}",
                    "last_msg": info["last_msg"],
                    "timestamp": info["timestamp"]
                })

            combined.sort(key=lambda x: x["timestamp"], reverse=True)

            prev_partner = self.current_partner
            prev_channel = self.current_channel
            self.conversation_list.clear()

            for entry in combined:
                snippet = entry["last_msg"]
                if len(snippet) > 30:
                    snippet = snippet[:27] + "…"

                text = f"{entry['display']}  —  {snippet}"
                item = QListWidgetItem(text)
                if entry["key"] in self.unread_map:
                    item.setForeground(QBrush(QColor("red")))
                item.setData(Qt.UserRole, (entry["type"], entry["key"]))
                self.conversation_list.addItem(item)

            # Reselect previously selected item if still present
            for i in range(self.conversation_list.count()):
                it = self.conversation_list.item(i)
                it_type, it_key = it.data(Qt.UserRole)
                if (it_type == "private" and it_key == prev_partner) or \
                   (it_type == "channel" and it_key == prev_channel):
                    self.conversation_list.setCurrentItem(it)
                    break

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load conversations:\n{str(e)}")


    ## third part

    # ──────────────────────────────────────────────────────────────────────────
    #  HANDLING CONVERSATION SELECTION
    # ──────────────────────────────────────────────────────────────────────────

    def on_conversation_selected(self, item: QListWidgetItem):
        conv_type, key = item.data(Qt.UserRole)
        self.clear_unread(key)
        if conv_type == "private":
            self.load_private_history(key)
        else:
            self.open_channel_message_dialog(key)


    def load_private_history(self, partner):
        """
        Load full private history between self.wallet_id and partner into bubble area.
        """
        # 1) Set current state
        self.current_partner = partner
        self.current_channel = None

        # 2) Disable layout updates to avoid flicker while clearing
        self.messages_container.setEnabled(False)

        # 3) Clear existing bubbles (leave only the final stretch)
        while self.messages_layout.count() > 1:
            w = self.messages_layout.takeAt(0).widget()
            if w:
                w.deleteLater()

        # Reset the timestamp tracker
        self.last_timestamp = 0

        # 4) Ensure an AES key exists (or attempt to load from disk)
        chat_id = self._get_private_chat_id(partner)
        if chat_id not in self.aes_key_map:
            try:
                keybytes = load_aes_key(chat_id, "v1")
                self.aes_key_map[chat_id] = keybytes
            except FileNotFoundError:
                pass

        # 5) Update the header to show the partner’s wallet_id
        self.chat_title.setText(partner)

        try:
            # 6) Fetch all messages from the server
            resp = requests.get(f"{API_BASE}/messages", headers={"Authorization": f"Bearer {self.access_token}"})
            if resp.status_code != 200:
                raise Exception(resp.text)
            msgs = resp.json()
            if not isinstance(msgs, list):
                QMessageBox.critical(self, "Error", f"Expected list, got:\n{msgs}")
                return

            # 7) Filter to only messages between self.wallet_id and partner
            history = []
            for m in msgs:
                sender = m.get("from")
                recipient = m.get("to")
                ts = m.get("timestamp")
                text = m.get("message", "")
                sig = m.get("signature", "")
                if sender is None or recipient is None or ts is None:
                    continue

                # Only include if this is a two-way chat between us and partner
                if (sender == partner and recipient == self.wallet_id) or \
                   (sender == self.wallet_id and recipient == partner):
                    history.append({
                        "from": sender,
                        "message": text,
                        "signature": sig,
                        "timestamp": ts
                    })

            # 8) Sort by timestamp ascending
            history.sort(key=lambda x: x["timestamp"])

            # 9) For each message, decrypt and display a bubble
            for m in history:
                sender = m["from"]
                ciphertext = m["message"]
                sig = m["signature"]
                ts = m["timestamp"]

                if ciphertext.startswith("KEY_EXCHANGE:"):
                    b64_wrapped = ciphertext.split("KEY_EXCHANGE:", 1)[1]
                    wrapped = base64.b64decode(b64_wrapped)
                    try:
                        aes_bytes = rsa_decrypt(self.privkey, wrapped)
                        save_aes_key(chat_id, "v1", aes_bytes)
                        self.aes_key_map[chat_id] = aes_bytes
                    except Exception:
                        QMessageBox.critical(self, "Error", "Invalid KEY_EXCHANGE or decryption failed.")
                    if ts > self.last_timestamp:
                        self.last_timestamp = ts
                    continue

                display_text = ciphertext
                if ciphertext.startswith("AES_GCM:") and chat_id in self.aes_key_map:
                    try:
                        b64_payload = ciphertext.split("AES_GCM:", 1)[1]
                        payload_bytes = base64.b64decode(b64_payload)
                        aes_key = self.aes_key_map[chat_id]
                        aesgcm = AESGCM(aes_key)
                        nonce = payload_bytes[:12]
                        ct_and_tag = payload_bytes[12:]
                        plaintext_bytes = aesgcm.decrypt(nonce, ct_and_tag, None)
                        display_text = plaintext_bytes.decode("utf-8", errors="ignore")
                    except Exception:
                        display_text = "[Decryption error]"

                if display_text.startswith("data:image/"):
                    display_text = "📷 Sent a picture"

                sender_label = "Me" if sender == self.wallet_id else sender
                self._add_private_bubble(sender_label, display_text, ts)
                if ts > self.last_timestamp:
                    self.last_timestamp = ts

            # 10) Re-enable layout updates and scroll to bottom
            self.messages_container.setEnabled(True)
            QTimer.singleShot(100, lambda: self.scroll_area.verticalScrollBar().setValue(
                self.scroll_area.verticalScrollBar().maximum()
            ))

            # 11) Restart the private‐poll timer so new messages arrive automatically
            self.private_poll_timer.start(3000)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load messages:\n{str(e)}")


    def poll_new_messages(self):
        """
        Poll for new private messages in the currently open private chat.
        """
        if self.current_channel is not None:
            return
        if not self.current_partner:
            return

        try:
            resp = requests.get(f"{API_BASE}/messages", headers={"Authorization": f"Bearer {self.access_token}"})
            if resp.status_code != 200:
                return
            msgs = resp.json()
            if not isinstance(msgs, list):
                return

            for m in msgs:
                sender = m.get("from")
                recipient = m.get("to")
                ts = m.get("timestamp")
                text = m.get("message", "")
                sig = m.get("signature", "")
                if sender == self.current_partner and recipient == self.wallet_id and ts > self.last_timestamp:
                    self._handle_incoming_private(self.current_partner, text, sig, ts)

            self.load_conversations()
        except Exception:
            pass


    def send_message(self):
        """
        Encrypt and send a new private message, then display it in a bubble immediately.
        Always sends a KEY_EXCHANGE first if no AES key exists.
        """
        text = self.message_input.text().strip()
        if not text or not self.current_partner:
            return

        ts = int(time.time() * 1000)
        partner = self.current_partner
        chat_id = self._get_private_chat_id(partner)

        try:
            # 1) Ensure an AES key exists (or create one if first message)
            if chat_id not in self.aes_key_map:
                # Generate new AES key
                new_aes = os.urandom(32)
                # Fetch partner's RSA public key
                resp = requests.get(f"{API_BASE}/user/{partner}")
                resp.raise_for_status()
                peer_pub_pem = resp.json()["pubkey"]
                peer_pubkey = load_rsa_public_key(partner, peer_pub_pem)
                # Wrap under RSA-OAEP (SHA-256)
                wrapped = peer_pubkey.encrypt(
                    new_aes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                b64_wrapped = base64.b64encode(wrapped).decode("utf-8")
                # Send KEY_EXCHANGE
                json_payload = {
                    "to_wallet": partner,
                    "message": f"KEY_EXCHANGE:{b64_wrapped}",
                    "signature": "",
                    "timestamp": ts
                }
                resp1 = requests.post(
                    f"{API_BASE}/message/send",
                    json=json_payload,
                    headers={"Authorization": f"Bearer {self.access_token}"}
                )
                resp1.raise_for_status()
                # Save new AES key locally
                save_aes_key(chat_id, "v1", new_aes)
                self.aes_key_map[chat_id] = new_aes

            # 2) AES-GCM encrypt the plaintext
            aes_key = self.aes_key_map[chat_id]
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, text.encode("utf-8"), None)
            payload = nonce + ct
            b64_payload = base64.b64encode(payload).decode("utf-8")
            final_msg = "AES_GCM:" + b64_payload

            # 3) RSA-PSS sign the ciphertext payload
            sig_bytes = rsa_sign(self.privkey, payload)
            b64_sig = base64.b64encode(sig_bytes).decode("utf-8")

            # 4) Send the encrypted message
            json_payload = {
                "to_wallet": partner,
                "message": final_msg,
                "signature": b64_sig,
                "timestamp": ts
            }
            resp2 = requests.post(
                f"{API_BASE}/message/send",
                json=json_payload,
                headers={"Authorization": f"Bearer {self.access_token}"}
            )
            resp2.raise_for_status()

            # 5) Display outgoing bubble immediately
            self._add_private_bubble("Me", text, ts)
            self.last_timestamp = ts
            self.message_input.clear()
            self.load_conversations()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send message:\n{str(e)}")


    def attach_image(self):
        """
        Let user pick an image, convert to data‐URI, and put into message_input.
        """
        fname, _ = QFileDialog.getOpenFileName(
            self,
            "Select Image",
            "",
            "Images (*.png *.jpg *.jpeg)"
        )
        if not fname:
            return
        path = Path(fname)
        try:
            ext = path.suffix.lower()
            if ext == ".png":
                mime_type = "image/png"
            elif ext in (".jpg", ".jpeg"):
                mime_type = "image/jpeg"
            else:
                QMessageBox.warning(self, "Error", "Unsupported image format.")
                return

            data = path.read_bytes()
            b64 = base64.b64encode(data).decode("utf-8")
            data_uri = f"data:{mime_type};base64,{b64}"
            self.message_input.setText(data_uri)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to attach image:\n{str(e)}")


    # ──────────────────────────────────────────────────────────────────────────
    #  NEW CHAT & CHANNEL HANDLERS
    # ──────────────────────────────────────────────────────────────────────────

    def new_chat(self):
        """
        Prompt to choose between a new private chat (with a user)
        or a new ephemeral channel (1:1 with another user).
        """
        dlg = QDialog(self)
        dlg.setObjectName("newChatDialog")
        dlg.setWindowTitle("Start New Chat")
        v = QVBoxLayout(dlg)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(8)

        rb_private = QRadioButton("Chat with User")
        rb_private.setObjectName("radioPrivate")
        rb_channel = QRadioButton("Create Ephemeral Channel")
        rb_channel.setObjectName("radioChannel")
        rb_private.setChecked(True)

        v.addWidget(rb_private)
        v.addWidget(rb_channel)

        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        v.addWidget(btn_box)

        def on_ok():
            if rb_private.isChecked():
                dlg.accept()
                self.start_private_chat()
            else:
                dlg.accept()
                self.create_ephemeral_channel()

        btn_box.accepted.connect(on_ok)
        btn_box.rejected.connect(dlg.reject)
        dlg.exec_()


    def start_private_chat(self):
        """
        Prompt for a partner wallet_id to open a private chat.
        """
        partner, ok = QInputDialog.getText(self, "New Private Chat", "Enter wallet ID:")
        if not ok or not partner or partner == self.wallet_id:
            return

        resp = requests.get(f"{API_BASE}/user/{partner}")
        if resp.status_code == 200 and not resp.json().get("exists"):
            QMessageBox.warning(self, "Error", "User does not exist.")
            return

        self.current_partner = partner
        self.current_channel = None

        self.clear_unread(partner)
        self.load_conversations()

        while self.messages_layout.count() > 1:
            w = self.messages_layout.takeAt(0).widget()
            if w:
                w.deleteLater()

        self.last_timestamp = 0

        # Attempt key exchange if needed
        try:
            self._get_or_create_aes_key(partner)
        except Exception:
            pass

        self.chat_title.setText(partner)
        self.load_private_history(partner)


    def create_ephemeral_channel(self):
        """
        Prompt for channel name, lifetime (in days), and peer, then create channel.
        """
        dlg = QDialog(self)
        dlg.setObjectName("createChannelDialog")
        dlg.setWindowTitle("Create Ephemeral Channel")
        form = QFormLayout(dlg)

        name_input = QLineEdit()
        name_input.setObjectName("channelNameInput")
        name_input.setPlaceholderText("Channel name")
        form.addRow("Name:", name_input)

        lifetime_input = QLineEdit()
        lifetime_input.setObjectName("channelLifetimeInput")
        lifetime_input.setPlaceholderText("Lifetime in days (e.g. 1)")
        form.addRow("Lifetime (days):", lifetime_input)

        peer_input = QLineEdit()
        peer_input.setObjectName("channelPeerInput")
        peer_input.setPlaceholderText("Peer wallet ID")
        form.addRow("Peer:", peer_input)

        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        form.addRow(btn_box)

        def on_ok():
            name = name_input.text().strip()
            lifetime_str = lifetime_input.text().strip()
            peer = peer_input.text().strip()
            if not name or not lifetime_str or not peer:
                QMessageBox.warning(dlg, "Error", "All fields are required.")
                return
            if peer == self.wallet_id:
                QMessageBox.warning(dlg, "Error", "Cannot create channel with yourself.")
                return
            try:
                days = int(lifetime_str)
                if days <= 0:
                    raise ValueError
            except ValueError:
                QMessageBox.warning(dlg, "Error", "Lifetime must be a positive integer.")
                return

            expires_secs = days * 24 * 3600
            payload = {"peer_wallet": peer, "name": name, "lifetime_secs": expires_secs}
            try:
                resp = requests.post(
                    f"{API_BASE}/channel",
                    json=payload,
                    headers={"Authorization": f"Bearer {self.access_token}"}
                )
                if resp.status_code not in (200, 201):
                    raise Exception(resp.text)
                data = resp.json()
                channel_id = str(data["channel_id"])
                QMessageBox.information(dlg, "Success", f"Created channel ID: {channel_id}")
            except Exception as e:
                QMessageBox.critical(dlg, "Error", f"Failed to create channel:\n{str(e)}")
                return

            dlg.accept()
            self.load_conversations()

        btn_box.accepted.connect(on_ok)
        btn_box.rejected.connect(dlg.reject)
        dlg.exec_()


    # ──────────────────────────────────────────────────────────────────────────
    #  MENU ACTIONS: Change PW, Renew, Block, Help, Logout
    # ──────────────────────────────────────────────────────────────────────────

    def change_password(self):
        current_pw, ok1 = QInputDialog.getText(self, "Change Password", "Current Password:", QLineEdit.Password)
        if not ok1 or not current_pw:
            return
        new_pw, ok2 = QInputDialog.getText(self, "Change Password", "New Password:", QLineEdit.Password)
        if not ok2 or not new_pw:
            return
        confirm_pw, ok3 = QInputDialog.getText(self, "Change Password", "Confirm New Password:", QLineEdit.Password)
        if not ok3 or not confirm_pw:
            return
        if new_pw != confirm_pw:
            QMessageBox.warning(self, "Error", "New passwords do not match.")
            return

        payload = {"current_password": current_pw, "new_password": new_pw}
        try:
            resp = requests.post(
                f"{API_BASE}/change_password",
                json=payload,
                headers={"Authorization": f"Bearer {self.access_token}"}
            )
            data = resp.json()
            if resp.status_code != 200:
                QMessageBox.warning(self, "Failed", data.get("error", "Unknown error"))
                return
            QMessageBox.information(self, "Success", data.get("message", "Password changed successfully"))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Server error:\n{str(e)}")


    def renew_subscription(self):
        months, ok = QInputDialog.getInt(self, "Renew Subscription", "Months to renew:", min=1, max=12, value=1)
        if not ok:
            return
        payload = {"wallet_id": self.wallet_id, "months": months}
        try:
            resp = requests.post(
                f"{API_BASE}/subscription/renew",
                json=payload,
                headers={"Authorization": f"Bearer {self.access_token}"}
            )
            data = resp.json()
            if resp.status_code != 200:
                QMessageBox.warning(self, "Failed", data.get("error", "Unknown error"))
                return
            subaddress = data.get("subaddress")
            if not subaddress:
                QMessageBox.warning(self, "Failed", "No subaddress returned.")
                return
            from login_window import PaymentDialog
            dlg = PaymentDialog(wallet_id=self.wallet_id, subaddress=subaddress, amount_required=0, parent=self)
            dlg.exec_()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Server error:\n{str(e)}")


    def block_user(self):
        target, ok1 = QInputDialog.getText(self, "Block User", "Wallet ID to block:")
        if not ok1 or not target:
            return
        if target == self.wallet_id:
            QMessageBox.warning(self, "Error", "You cannot block yourself.")
            return
        note, ok2 = QInputDialog.getMultiLineText(self, "Block User", "Reason for blocking (optional):")
        if not ok2:
            return

        payload = {"blocked_wallet_id": target, "note": note}
        try:
            resp = requests.post(
                f"{API_BASE}/block",
                json=payload,
                headers={"Authorization": f"Bearer {self.access_token}"}
            )
            data = resp.json()
            if resp.status_code != 200:
                QMessageBox.warning(self, "Failed", data.get("error", "Unknown error"))
                return
            QMessageBox.information(self, "Success", data.get("message", "User blocked."))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Server error:\n{str(e)}")


    def logout(self):
        self.sio.disconnect()
        self.close()
        QApplication.instance().quit()


    # ──────────────────────────────────────────────────────────────────────────
    #  UNREAD / READ HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def mark_unread(self, key: str, private: bool):
        self.unread_map[key] = True

    def clear_unread(self, key: str):
        if key in self.unread_map:
            del self.unread_map[key]

    @property
    def unread_map(self):
        if not hasattr(self, "_unread_map"):
            self._unread_map = {}
        return self._unread_map
