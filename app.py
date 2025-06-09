import threading
import time
import json
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    get_jwt, verify_jwt_in_request
)
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from sqlalchemy import or_
from functools import wraps
from requests.auth import HTTPDigestAuth

# For validating new public keys
from cryptography.hazmat.primitives import serialization

# ─── Flask App & Config ────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)  # Allow Electron or any origin to hit the API

# SQLite for simplicity
app.config['SQLALCHEMY_DATABASE_URI']      = 'sqlite:///users.db'
app.config['SECRET_KEY']                   = 'bIQN08tjKvZgrMcGxaVzI0SMUzqyhRKE'
app.config['JWT_SECRET_KEY']               = '2UmzK7ukkNbAbdedESUwqhr522W41dwH'
app.config['JWT_ACCESS_TOKEN_EXPIRES']     = timedelta(hours=1)
app.config['PROPAGATE_EXCEPTIONS']         = True

db      = SQLAlchemy(app)
bcrypt  = Bcrypt(app)
jwt     = JWTManager(app)
migrate = Migrate(app, db)

# Flask-SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# ─── In-Memory JWT Blacklist ────────────────────────────────────────────────────

jwt_blacklist = set()

def token_not_revoked(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        jti = get_jwt()['jti']
        if jti in jwt_blacklist:
            return jsonify({'error': 'Token has been revoked'}), 401
        return fn(*args, **kwargs)
    return wrapper

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_headers, jwt_payload):
    return jwt_payload['jti'] in jwt_blacklist

# ─── Monero RPC Settings for Payments ──────────────────────────────────────────

RPC_URL      = "http://127.0.0.1:38083/json_rpc"
RPC_USER     = "mo"
RPC_PASSWORD = "m1@t2@m3@"
HEADERS      = {"Content-Type": "application/json"}

# ─── Track Pending Payment Monitors ────────────────────────────────────────────

monitoring_users = set()

# ─── Database Models ────────────────────────────────────────────────────────────

class User(db.Model):
    id                   = db.Column(db.Integer,   primary_key=True)
    wallet_id            = db.Column(db.String(100), unique=True, nullable=False)
    password_hash        = db.Column(db.String(100), nullable=False)
    subaddress           = db.Column(db.String(120), nullable=False)
    subaddress_index     = db.Column(db.Integer,    nullable=False)
    verified             = db.Column(db.Boolean,    default=False)
    pubkey               = db.Column(db.Text,       nullable=False)
    subscription_expires = db.Column(db.DateTime,   nullable=True)

class Message(db.Model):
    id                = db.Column(db.Integer, primary_key=True)
    sender_wallet     = db.Column(db.String(100), nullable=False)
    recipient_wallet  = db.Column(db.String(100), nullable=False)
    encrypted_message = db.Column(db.Text,        nullable=False)
    signature         = db.Column(db.Text,        nullable=True)
    timestamp         = db.Column(db.Integer,     nullable=False)

class BlockedUser(db.Model):
    id                 = db.Column(db.Integer, primary_key=True)
    blocker_wallet_id  = db.Column(db.String,  nullable=False)
    blocked_wallet_id  = db.Column(db.String,  nullable=False)
    note               = db.Column(db.String,  nullable=True)
    unblock_at         = db.Column(db.DateTime, nullable=True)

class Channel(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(100), nullable=False)
    owner_wallet  = db.Column(db.String(100), nullable=False)
    peer_wallet   = db.Column(db.String(100), nullable=False)
    expires_at    = db.Column(db.DateTime, nullable=False)
    is_closed     = db.Column(db.Boolean, default=False)

class ChannelMessage(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    channel_id    = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=False)
    sender_wallet = db.Column(db.String(100), nullable=False)
    encrypted     = db.Column(db.Text,    nullable=False)
    signature     = db.Column(db.Text,    nullable=True)
    timestamp     = db.Column(db.Integer, nullable=False)

class KeyExchange(db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    sender_wallet    = db.Column(db.String(100), nullable=False)
    recipient_wallet = db.Column(db.String(100), nullable=False)
    encrypted_key    = db.Column(db.Text, nullable=False)
    timestamp        = db.Column(db.Integer, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "from": self.sender_wallet,
            "to": self.recipient_wallet,
            "encrypted_key": self.encrypted_key,
            "timestamp": self.timestamp
        }

with app.app_context():
    db.create_all()

# ─── Background Cleanup Thread ─────────────────────────────────────────────────

def cleanup_channels():
    """
    Periodically close any channels whose expires_at < now.
    Deletes all ChannelMessage rows for closed channels.
    """
    while True:
        with app.app_context():
            now = datetime.utcnow()
            expired = Channel.query.filter(Channel.expires_at < now, Channel.is_closed == False).all()
            for ch in expired:
                ch.is_closed = True
                ChannelMessage.query.filter_by(channel_id=ch.id).delete()
            db.session.commit()
        time.sleep(60)

threading.Thread(target=cleanup_channels, daemon=True).start()

# ─── Monero Payment Monitor ─────────────────────────────────────────────────────

def monitor_payment(user_id, months=1):
    """
    Poll Monero daemon for incoming transfer to user.subaddress.
    Once payment ≥ 0.00001 XMR is detected, mark user as verified and extend subscription.
    """
    try:
        user = None
        while True:
            with app.app_context():
                user = User.query.get(user_id)
                if not user:
                    break

                payload = {
                    "jsonrpc": "2.0",
                    "id": "0",
                    "method": "get_transfers",
                    "params": {
                        "in": True,
                        "account_index": 0,
                        "subaddr_indices": [user.subaddress_index]
                    }
                }
                resp = requests.post(
                    RPC_URL,
                    headers=HEADERS,
                    data=json.dumps(payload),
                    auth=HTTPDigestAuth(RPC_USER, RPC_PASSWORD)
                )
                if resp.status_code == 200:
                    for tx in resp.json().get("result", {}).get("in", []):
                        amount = float(tx["amount"]) / 1e12
                        if tx["address"] == user.subaddress and amount >= 0.00001 * months:
                            user.verified = True
                            now = datetime.utcnow()
                            if user.subscription_expires and user.subscription_expires > now:
                                user.subscription_expires += timedelta(days=30 * months)
                            else:
                                user.subscription_expires = now + timedelta(days=30 * months)
                            db.session.commit()
                            return
            time.sleep(10)
    finally:
        # Remove from monitoring set when done or on error
        monitoring_users.discard(user_id)

# ─── Subscription Status Endpoint ───────────────────────────────────────────────

@app.route("/api/subscription/status", methods=["GET"])
def subscription_status():
    """
    Public endpoint: check if a user's payment has been confirmed.
    Client should call GET /api/subscription/status?wallet_id=<wallet_id>.
    Returns: {"verified": True/False}
    """
    wallet_id = request.args.get("wallet_id")
    if not wallet_id:
        return jsonify({"error": "Missing wallet_id"}), 400

    user = User.query.filter_by(wallet_id=wallet_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"verified": user.verified}), 200

# ─── Subscription Renewal Status Endpoint ───────────────────────────────────────

@app.route("/api/subscription/status/<wallet_id>", methods=["GET"])
@jwt_required()
def subscription_status_with_token(wallet_id):
    """
    Authenticated endpoint to fetch subscription expiry date and verified status.
    Returns: {"end_date": "YYYY-MM-DDTHH:MM:SS", "verified": True/False}
    """
    user = User.query.filter_by(wallet_id=wallet_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "end_date": user.subscription_expires.isoformat() if user.subscription_expires else None,
        "verified": user.verified
    }), 200

# ─── Subscription Enforcement ───────────────────────────────────────────────────

@app.before_request
def enforce_subscription():
    path = request.path
    exempt = {
        "/api/register",
        "/api/login",
        "/api/logout",
        "/api/user/",
        "/api/change_password",
        "/api/subscription/renew",
        "/api/subscription/status",      # allow checking status without token
        "/api/update_pubkey"            # allow public key updates without subscription check
    }
    if path.startswith("/api/") and not any(path.startswith(ex) for ex in exempt):
        try:
            verify_jwt_in_request()
            identity = get_jwt_identity()
            user = User.query.filter_by(wallet_id=identity).first()
            if not user:
                return jsonify({"error": "Invalid user"}), 401
            if user.subscription_expires and user.subscription_expires < datetime.utcnow():
                return jsonify({"error": "Subscription expired"}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 401

# ─── Socket.IO Handlers ─────────────────────────────────────────────────────────

@socketio.on("join")
def on_join(data):
    """
    Client calls emit("join", {"wallet_id": "..."}).
    We put their socket into:
      - Private room: "user_<wallet_id>"
      - All active channels they belong to: "channel_<channel_id>"
    """
    wallet_id = data.get("wallet_id")
    if not wallet_id:
        return

    # Join private room
    join_room(f"user_{wallet_id}")

    # Join every active channel room
    active_channels = Channel.query.filter(
        Channel.is_closed == False,
        Channel.expires_at > datetime.utcnow(),
        (Channel.owner_wallet == wallet_id) | (Channel.peer_wallet == wallet_id)
    ).all()
    for ch in active_channels:
        join_room(f"channel_{ch.id}")

# ─── API Endpoints ─────────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def api_register():
    data       = request.json or {}
    wallet_id  = data.get("wallet_id")
    password   = data.get("password")
    pubkey     = data.get("pubkey")
    months     = data.get("months")

    # Validate inputs
    if not wallet_id or not password or not pubkey:
        return jsonify({"error": "Missing wallet_id, password, or pubkey"}), 400
    if not isinstance(months, int) or months <= 0:
        return jsonify({"error": "Invalid months"}), 400
    if User.query.filter_by(wallet_id=wallet_id).first():
        return jsonify({"error": "Wallet already registered"}), 400

    # Create a new Monero subaddress for payment
    rpc = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": "create_address",
        "params": {"account_index": 0, "label": wallet_id}
    }
    r = requests.post(
        RPC_URL, headers=HEADERS, data=json.dumps(rpc),
        auth=HTTPDigestAuth(RPC_USER, RPC_PASSWORD)
    )
    if r.status_code != 200 or "result" not in r.json():
        return jsonify({"error": "Failed to create Monero subaddress"}), 500

    res = r.json()["result"]

    # Hash password & create User
    hashed_pw = bcrypt.generate_password_hash(password).decode()
    user = User(
        wallet_id=wallet_id,
        password_hash=hashed_pw,
        subaddress=res["address"],
        subaddress_index=res["address_index"],
        pubkey=pubkey
    )
    db.session.add(user)
    db.session.commit()

    # Start the payment monitor if not already monitoring
    if user.id not in monitoring_users:
        monitoring_users.add(user.id)
        threading.Thread(target=monitor_payment, args=(user.id, months), daemon=True).start()

    amount_required = 0.00001 * months
    return jsonify({
        "message": f"User registered. Send {amount_required:.8f} XMR to subaddress.",
        "subaddress": user.subaddress,
        "amount_required": amount_required
    }), 201

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    wallet_id = data.get("wallet_id")
    password  = data.get("password")
    user = User.query.filter_by(wallet_id=wallet_id).first()

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401
    if not user.verified:
        return jsonify({"error": "Account not verified"}), 403

    token = create_access_token(identity=wallet_id)
    return jsonify({"access_token": token, "token_type": "Bearer"}), 200

@app.route("/api/update_pubkey", methods=["POST"])
@jwt_required()
@token_not_revoked
def update_pubkey():
    """
    Replace the current user’s RSA public key with a new one.
    Client must send JSON { "pubkey": "<PEM string>" }.
    """
    data = request.get_json() or {}
    new_pubkey = data.get("pubkey")
    if not new_pubkey:
        return jsonify({"error": "Missing pubkey"}), 400

    me = get_jwt_identity()
    user = User.query.filter_by(wallet_id=me).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Validate that new_pubkey is valid PEM-formatted RSA public key
    try:
        serialization.load_pem_public_key(new_pubkey.encode("utf-8"))
    except Exception:
        return jsonify({"error": "Invalid public key format"}), 400

    user.pubkey = new_pubkey
    db.session.commit()
    return jsonify({"message": "Public key updated"}), 200

@app.route("/api/logout", methods=["POST"])
@jwt_required()
@token_not_revoked
def api_logout():
    jti = get_jwt()['jti']
    jwt_blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200

@app.route("/api/change_password", methods=["POST"])
@jwt_required()
@token_not_revoked
def api_change_password():
    data = request.get_json() or {}
    curr_pw = data.get("current_password")
    new_pw = data.get("new_password")
    if not curr_pw or not new_pw:
        return jsonify({"error": "Missing fields"}), 400

    wallet_id = get_jwt_identity()
    user = User.query.filter_by(wallet_id=wallet_id).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, curr_pw):
        return jsonify({"error": "Current password incorrect"}), 403

    user.password_hash = bcrypt.generate_password_hash(new_pw).decode()
    db.session.commit()
    return jsonify({"message": "Password changed successfully"}), 200

@app.route("/api/user/<wallet_id>", methods=["GET"])
def get_user_by_id(wallet_id):
    user = User.query.filter_by(wallet_id=wallet_id).first()
    if not user:
        return jsonify({"exists": False}), 200
    return jsonify({"exists": True, "pubkey": user.pubkey}), 200

@app.route("/api/block-list", methods=["GET"])
@jwt_required()
@token_not_revoked
def get_block_list():
    me = get_jwt_identity()
    blocked_entries = BlockedUser.query.filter_by(blocker_wallet_id=me).all()
    result = []
    for b in blocked_entries:
        entry = {
            "blocked_wallet_id": b.blocked_wallet_id,
            "note": b.note,
            "unblock_at": b.unblock_at.isoformat() if b.unblock_at else None
        }
        result.append(entry)
    return jsonify(result), 200

@app.route("/api/block", methods=["POST"])
@jwt_required()
@token_not_revoked
def block_user():
    data = request.json or {}
    blocker = get_jwt_identity()
    blocked = data.get("blocked_wallet_id")
    note    = data.get("note")
    ua      = data.get("unblock_at")

    if not blocked:
        return jsonify({"error": "Missing blocked_wallet_id"}), 400

    block = BlockedUser(
        blocker_wallet_id=blocker,
        blocked_wallet_id=blocked,
        note=note,
        unblock_at=datetime.fromisoformat(ua) if ua else None
    )
    db.session.add(block)
    db.session.commit()
    return jsonify({"message": "User blocked"}), 200

@app.route("/api/block/<blocked_wallet_id>", methods=["DELETE"])
@jwt_required()
@token_not_revoked
def unblock_user(blocked_wallet_id):
    blocker = get_jwt_identity()
    b = BlockedUser.query.filter_by(
        blocker_wallet_id=blocker,
        blocked_wallet_id=blocked_wallet_id
    ).first()
    if not b:
        return jsonify({"error": "Block not found"}), 404
    db.session.delete(b)
    db.session.commit()
    return jsonify({"message": "User unblocked"}), 200

@app.route("/api/message/send", methods=["POST"])
@jwt_required()
@token_not_revoked
def send_message():
    data      = request.get_json() or {}
    sender    = get_jwt_identity()
    recipient = data.get("to_wallet")
    msg_text  = data.get("message")
    sig       = data.get("signature")
    ts        = data.get("timestamp")
    if not recipient or not msg_text or ts is None or sig is None:
        return jsonify({"error": "Missing fields"}), 400
    if not User.query.filter_by(wallet_id=recipient).first():
        return jsonify({"error": "Recipient not found"}), 404

    # Block check
    now = datetime.utcnow()
    b = BlockedUser.query.filter(
        or_(
            (BlockedUser.blocker_wallet_id == sender)    & (BlockedUser.blocked_wallet_id == recipient),
            (BlockedUser.blocker_wallet_id == recipient) & (BlockedUser.blocked_wallet_id == sender)
        )
    ).first()
    if b:
        if b.unblock_at and now > b.unblock_at:
            db.session.delete(b)
            db.session.commit()
        else:
            return jsonify({"error": "Messaging blocked"}), 403

    m = Message(
        sender_wallet=sender,
        recipient_wallet=recipient,
        encrypted_message=msg_text,
        signature=sig,
        timestamp=ts
    )
    db.session.add(m)
    db.session.commit()

    payload = {"from": sender, "to": recipient, "message": msg_text, "signature": sig, "timestamp": ts}
    socketio.emit("new_private_message", payload, room=f"user_{recipient}")
    return jsonify({"message": "Message queued"}), 201

@app.route("/api/messages", methods=["GET"])
@jwt_required()
def get_messages():
    me = get_jwt_identity()
    msgs = Message.query.filter(
        or_(
            Message.recipient_wallet == me,
            Message.sender_wallet == me
        )
    ).order_by(Message.timestamp).all()
    result = []
    for m in msgs:
        result.append({
            "id": m.id,
            "from": m.sender_wallet,
            "to": m.recipient_wallet,
            "message": m.encrypted_message,
            "signature": m.signature,
            "timestamp": m.timestamp
        })
    return jsonify(result), 200

@app.route("/api/channel", methods=["POST"])
@jwt_required()
@token_not_revoked
def create_channel():
    data     = request.get_json() or {}
    owner    = get_jwt_identity()
    peer     = data.get("peer_wallet")
    name     = data.get("name")
    lifetime = data.get("lifetime_secs", 3600)

    if not peer or not name:
        return jsonify({"error": "Missing peer_wallet or name"}), 400
    if not User.query.filter_by(wallet_id=peer).first():
        return jsonify({"error": "Peer user not found"}), 404

    # Block check
    b = BlockedUser.query.filter(
        or_(
            (BlockedUser.blocker_wallet_id == owner) & (BlockedUser.blocked_wallet_id == peer),
            (BlockedUser.blocker_wallet_id == peer) & (BlockedUser.blocked_wallet_id == owner)
        )
    ).first()
    if b:
        return jsonify({"error": "Cannot open channel: blocked"}), 403

    expires = datetime.utcnow() + timedelta(seconds=lifetime)
    ch = Channel(name=name, owner_wallet=owner, peer_wallet=peer, expires_at=expires)
    db.session.add(ch)
    db.session.commit()

    return jsonify({
        "channel_id": ch.id,
        "expires_at": ch.expires_at.isoformat()
    }), 201

@app.route("/api/channels", methods=["GET"])
@jwt_required()
def list_channels():
    me  = get_jwt_identity()
    now = datetime.utcnow()
    chans = Channel.query.filter(
        Channel.is_closed == False,
        Channel.expires_at > now,
        or_(Channel.owner_wallet == me, Channel.peer_wallet == me)
    ).all()
    result = []
    for c in chans:
        peer = c.peer_wallet if c.owner_wallet == me else c.owner_wallet
        result.append({
            "id": c.id,
            "name": c.name,
            "peer_wallet": peer,
            "expires_at": c.expires_at.isoformat()
        })
    return jsonify(result), 200

@app.route("/api/channel/<int:channel_id>", methods=["DELETE"])
@jwt_required()
@token_not_revoked
def close_channel(channel_id):
    ch = Channel.query.get_or_404(channel_id)
    me = get_jwt_identity()
    if me not in (ch.owner_wallet, ch.peer_wallet):
        return jsonify({"error": "Not authorized"}), 403
    ch.is_closed = True
    ChannelMessage.query.filter_by(channel_id=channel_id).delete()
    db.session.commit()
    return jsonify({"message": "Channel closed"}), 200

@app.route("/api/channel/<int:channel_id>/message", methods=["POST"])
@jwt_required()
@token_not_revoked
def send_channel_message(channel_id):
    ch = Channel.query.get_or_404(channel_id)
    user = get_jwt_identity()
    if ch.is_closed or ch.expires_at < datetime.utcnow():
        return jsonify({"error": "Channel closed"}), 403
    if user not in (ch.owner_wallet, ch.peer_wallet):
        return jsonify({"error": "Not a participant"}), 403

    # Block check in channel
    b = BlockedUser.query.filter(
        or_(
            (BlockedUser.blocker_wallet_id == user) & (BlockedUser.blocked_wallet_id == ch.peer_wallet),
            (BlockedUser.blocker_wallet_id == ch.peer_wallet) & (BlockedUser.blocked_wallet_id == user)
        )
    ).first()
    if b:
        return jsonify({"error": "Channel messaging blocked"}), 403

    data = request.get_json() or {}
    msg_text = data.get("message")
    sig      = data.get("signature")
    ts       = data.get("timestamp")
    if not msg_text or ts is None or sig is None:
        return jsonify({"error": "Missing fields"}), 400

    m = ChannelMessage(
        channel_id=channel_id,
        sender_wallet=user,
        encrypted=msg_text,
        signature=sig,
        timestamp=ts
    )
    db.session.add(m)
    db.session.commit()

    payload = {
        "channel_id": channel_id,
        "from": user,
        "message": msg_text,
        "signature": sig,
        "timestamp": ts
    }
    socketio.emit("new_channel_message", payload, room=f"channel_{channel_id}")
    return jsonify({"message": "Channel message sent"}), 201

@app.route("/api/channel/<int:channel_id>/messages", methods=["GET"])
@jwt_required()
def get_channel_messages(channel_id):
    ch = Channel.query.get_or_404(channel_id)
    user = get_jwt_identity()
    if ch.is_closed:
        return jsonify({"error": "Channel closed"}), 403
    if user not in (ch.owner_wallet, ch.peer_wallet):
        return jsonify({"error": "Not a participant"}), 403

    since = request.args.get("since", type=int, default=0)
    query = ChannelMessage.query.filter_by(channel_id=channel_id)
    if since:
        query = query.filter(ChannelMessage.timestamp >= since)
    msgs = query.order_by(ChannelMessage.timestamp).all()
    result = []
    for m in msgs:
        result.append({
            "id": m.id,
            "from": m.sender_wallet,
            "message": m.encrypted,
            "signature": m.signature,
            "timestamp": m.timestamp
        })
    return jsonify(result), 200

@app.route("/api/key-exchange/send", methods=["POST"])
@jwt_required()
@token_not_revoked
def send_key_exchange():
    """
    Client must send:
      {
        "recipient_wallet": "<other_user_wallet_id>",
        "encrypted_key": "<base64-or‐PEM-string‐of‐AES‐key‐encrypted‐with‐recipient‐RSA>",
        "timestamp": <unix_timestamp_integer>
      }
    """
    data = request.get_json() or {}
    sender = get_jwt_identity()
    recipient = data.get("recipient_wallet")
    enc_key = data.get("encrypted_key")
    ts = data.get("timestamp")

    if not recipient or not enc_key or ts is None:
        return jsonify({"error": "Missing fields (recipient_wallet, encrypted_key, timestamp)"}), 400

    # Ensure recipient exists
    if not User.query.filter_by(wallet_id=recipient).first():
        return jsonify({"error": "Recipient not found"}), 404

    # Check for any blocking relationship 
    b = BlockedUser.query.filter(
        or_(
            (BlockedUser.blocker_wallet_id == sender) & (BlockedUser.blocked_wallet_id == recipient),
            (BlockedUser.blocker_wallet_id == recipient) & (BlockedUser.blocked_wallet_id == sender)
        )
    ).first()
    if b:
        return jsonify({"error": "Cannot exchange key: blocked"}), 403

    ke = KeyExchange(
        sender_wallet=sender,
        recipient_wallet=recipient,
        encrypted_key=enc_key,
        timestamp=ts
    )
    db.session.add(ke)
    db.session.commit()
    return jsonify({"message": "Key exchange entry created"}), 201

@app.route("/api/key-exchange", methods=["GET"])
@jwt_required()
def get_key_exchanges():
    """
    Returns all pending KeyExchange rows where recipient_wallet == current user.
    """
    me = get_jwt_identity()
    entries = KeyExchange.query.filter_by(recipient_wallet=me).order_by(KeyExchange.timestamp).all()
    result = [ ke.to_dict() for ke in entries ]
    return jsonify(result), 200

@app.route("/api/key-exchange/<int:key_id>", methods=["DELETE"])
@jwt_required()
def delete_key_exchange(key_id):
    """
    Delete a KeyExchange entry (either private or channel).
    """
    ke = KeyExchange.query.get_or_404(key_id)
    me = get_jwt_identity()
    # Only sender or recipient may delete their own key-exchange entry
    if me not in (ke.sender_wallet, ke.recipient_wallet):
        return jsonify({"error": "Not authorized"}), 403
    db.session.delete(ke)
    db.session.commit()
    return jsonify({"message": "Key exchange entry deleted"}), 200

@app.route("/api/subscription/renew", methods=["POST"])
def renew_subscription():
    """
    Public endpoint: user provides wallet_id and number of months.
    We create a new subaddress for payment and restart monitor_payment with requested months.
    """
    data = request.get_json() or {}
    wallet_id = data.get("wallet_id")
    months    = data.get("months", 1)

    if not wallet_id or not isinstance(months, int) or months <= 0:
        return jsonify({"error": "Missing or invalid fields"}), 400

    user = User.query.filter_by(wallet_id=wallet_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Create a fresh subaddress for the renewal payment
    rpc = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": "create_address",
        "params": {"account_index": 0, "label": f"{wallet_id}_renew_{int(time.time())}"}
    }
    r = requests.post(
        RPC_URL,
        headers=HEADERS,
        data=json.dumps(rpc),
        auth=HTTPDigestAuth(RPC_USER, RPC_PASSWORD)
    )
    if r.status_code != 200 or "result" not in r.json():
        return jsonify({"error": "Failed to create Monero subaddress"}), 500

    res = r.json()["result"]
    # Update user’s subaddress to the new one
    user.subaddress = res["address"]
    user.subaddress_index = res["address_index"]
    # Temporarily mark verified=False until payment is seen
    user.verified = False
    db.session.commit()

    # If a monitor is already running, return an error
    if user.id in monitoring_users:
        return jsonify({"error": "Payment monitor already running"}), 400

    monitoring_users.add(user.id)
    threading.Thread(target=monitor_payment, args=(user.id, months), daemon=True).start()

    return jsonify({"subaddress": user.subaddress}), 200

@app.route("/api/delete-account", methods=["DELETE"])
@jwt_required()
@token_not_revoked
def delete_account():
    me = get_jwt_identity()
    # Remove all related data
    Message.query.filter(
        (Message.sender_wallet == me) | (Message.recipient_wallet == me)
    ).delete()
    BlockedUser.query.filter(
        (BlockedUser.blocker_wallet_id == me) |
        (BlockedUser.blocked_wallet_id == me)
    ).delete()
    ChannelMessage.query.filter(ChannelMessage.sender_wallet == me).delete()
    # Also close any channels they own or peer
    channels_to_close = Channel.query.filter(
        (Channel.owner_wallet == me) | (Channel.peer_wallet == me)
    ).all()
    for ch in channels_to_close:
        ch.is_closed = True
        ChannelMessage.query.filter_by(channel_id=ch.id).delete()

    User.query.filter_by(wallet_id=me).delete()
    db.session.commit()
    return jsonify({"message": "Account permanently deleted"}), 200

@app.route("/help")
def help_page():
    """
    Simple Help page with instructions and E2EE overview.
    """
    return """
    <html>
      <head><title>Scomm Help</title></head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; padding: 20px;">
        <h1>Scomm Help</h1>
        <p>Welcome to Scomm! Below are some key points:</p>
        <h2>End-to-End Encryption</h2>
        <ul>
          <li>Each user has a daily-rotated RSA keypair. Public keys are stored on the server.</li>
          <li>Each private chat or ephemeral channel uses a fresh AES-256 key, wrapped under the peer’s RSA public key.</li>
          <li>Every message is encrypted with AES-GCM and signed with RSA-PSS (SHA-256).</li>
          <li>RSA keys rotate once every 24 hours. When you log in after 24 hours, a new RSA keypair is generated and uploaded.</li>
        </ul>
        <h2>Registration & Subscription</h2>
        <p>To register, provide your Monero wallet ID and an RSA public key. Send the required XMR to the subaddress provided to complete your subscription.</p>
        <h2>Chat & Ephemeral Channels</h2>
        <p>Create private chats or ephemeral channels (1:1 only) with other wallet IDs. Messages and images are end-to-end encrypted. Channels expire after their lifetime.</p>
        <h2>Troubleshooting</h2>
        <p>If you encounter errors, check your Monero daemon, ensure the server is running at <code>http://127.0.0.1:5000</code>, and confirm your JWT token is valid. For registration, be sure to send the exact amount of XMR to the subaddress.</p>
      </body>
    </html>
    """

# ─── Main Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Use socketio.run instead of app.run
    socketio.run(app, debug=True)
