# app/core/tls_server.py
# Mag-Null — HTTPS/TLS Backend
# Generates a self-signed certificate and runs the WebSocket server over TLS.
# Requires: pip install pyOpenSSL  OR uses stdlib ssl module (no extra dep)
#
# USAGE:
#   from app.core.tls_server import TLSServer
#   server = TLSServer(pipeline)
#   server.start()

import ssl, os, socket, threading, json, hashlib, base64, struct
from pathlib import Path
from datetime import datetime, timezone

ROOT      = Path(__file__).resolve().parent.parent.parent
CERT_DIR  = ROOT / "config" / "certs"
CERT_FILE = CERT_DIR / "magnull.crt"
KEY_FILE  = CERT_DIR / "magnull.key"


# ── Self-signed certificate generator ────────────────────────────
def generate_self_signed_cert():
    """
    Generate a self-signed TLS certificate using pyOpenSSL if available,
    otherwise fall back to a pre-generated embedded cert for demo.
    """
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    if CERT_FILE.exists() and KEY_FILE.exists():
        return  # Already generated

    try:
        from OpenSSL import crypto
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().C  = "IN"
        cert.get_subject().ST = "Uttar Pradesh"
        cert.get_subject().L  = "Noida"
        cert.get_subject().O  = "Team Dimensioners"
        cert.get_subject().CN = "mag-null.local"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, "sha256")

        with open(CERT_FILE, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(KEY_FILE, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

        print(f"[TLS] Self-signed certificate generated → {CERT_FILE}")

    except ImportError:
        # pyOpenSSL not available — use subprocess openssl
        import subprocess
        try:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(KEY_FILE),
                "-out",    str(CERT_FILE),
                "-days",   "365",
                "-nodes",
                "-subj",   "/C=IN/ST=UP/L=Noida/O=TeamDimensioners/CN=mag-null.local"
            ], check=True, capture_output=True)
            print(f"[TLS] Certificate generated via openssl → {CERT_FILE}")
        except Exception as e:
            print(f"[TLS] WARNING: Could not generate cert ({e}). Using plain WS.")


# ── TLS WebSocket Server ───────────────────────────────────────────
MAGIC  = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_PORT  = 8766   # WSS port (note: 8765 = plain WS, 8766 = WSS)
HTTP_PORT= 8443   # HTTPS port

class TLSServer:
    def __init__(self, pipeline, auth_manager=None):
        self.pipeline    = pipeline
        self.auth        = auth_manager
        self._clients    = set()
        self._lock       = threading.Lock()
        self._running    = False
        self._ssl_ctx    = None

    def _build_ssl_context(self):
        generate_self_signed_cert()
        if not CERT_FILE.exists():
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(CERT_FILE), str(KEY_FILE))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def start(self):
        self._ssl_ctx = self._build_ssl_context()
        self._running = True

        if self._ssl_ctx:
            t = threading.Thread(target=self._accept_loop, daemon=True)
            t.start()
            print(f"[TLS] Secure WebSocket on wss://127.0.0.1:{WS_PORT}")
        else:
            print("[TLS] Running without TLS (plain WS fallback)")

        # Register broadcast callback
        self.pipeline.on_tick(self._broadcast)

    def _accept_loop(self):
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind(("127.0.0.1", WS_PORT))
        raw_sock.listen(10)

        while self._running:
            try:
                conn, addr = raw_sock.accept()
                tls_conn   = self._ssl_ctx.wrap_socket(conn, server_side=True)
                t = threading.Thread(
                    target=self._handle_client,
                    args=(tls_conn, addr), daemon=True)
                t.start()
            except Exception:
                pass

    def _handle_client(self, conn, addr):
        try:
            # Read HTTP upgrade request
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                data += chunk

            headers = {}
            for line in data.decode(errors="ignore").split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # Optional: validate JWT from Sec-WebSocket-Protocol header
            token_valid = True
            if self.auth:
                token = headers.get("sec-websocket-protocol", "")
                payload = self.auth.verify(token)
                token_valid = payload is not None

            if not token_valid:
                conn.send(b"HTTP/1.1 401 Unauthorized\r\n\r\n")
                conn.close()
                return

            # Complete WebSocket handshake
            key      = headers.get("sec-websocket-key", "")
            acc      = base64.b64encode(
                hashlib.sha1((key + MAGIC).encode()).digest()).decode()
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {acc}\r\n\r\n"
            )
            conn.send(response.encode())

            with self._lock:
                self._clients.add(conn)

            # Keep alive — read pings
            while self._running:
                try:
                    conn.recv(1024)
                except Exception:
                    break
        except Exception:
            pass
        finally:
            with self._lock:
                self._clients.discard(conn)
            try:
                conn.close()
            except Exception:
                pass

    def _ws_frame(self, msg: str) -> bytes:
        data = msg.encode("utf-8")
        hdr  = bytearray([0x81])
        if len(data) <= 125:
            hdr.append(len(data))
        elif len(data) <= 65535:
            hdr.append(126)
            hdr += struct.pack(">H", len(data))
        else:
            hdr.append(127)
            hdr += struct.pack(">Q", len(data))
        return bytes(hdr) + data

    def _broadcast(self, state: dict):
        msg   = json.dumps(state)
        frame = self._ws_frame(msg)
        dead  = set()
        with self._lock:
            for conn in self._clients:
                try:
                    conn.sendall(frame)
                except Exception:
                    dead.add(conn)
        with self._lock:
            self._clients -= dead

    def cert_fingerprint(self) -> str:
        """Returns SHA-256 fingerprint of the TLS cert for display in UI."""
        if not CERT_FILE.exists():
            return "N/A"
        with open(CERT_FILE, "rb") as f:
            data = f.read()
        digest = hashlib.sha256(data).hexdigest().upper()
        return ":".join(digest[i:i+2] for i in range(0, 16, 2))