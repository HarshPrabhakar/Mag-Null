# app/main.py
# Mag-Null — Secure Entry Point
# Wires: JWT auth → TLS server → model verification → audit log

import sys
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore    import QObject, pyqtSignal

from app.core.pipeline       import Pipeline
from app.core.auth           import get_auth
from app.core.model_verifier import ModelVerifier, AuditLog
from app.ui.login_dialog     import LoginDialog
from app.ui.main_window      import MainWindow


class Bridge(QObject):
    tick = pyqtSignal(dict)

bridge = Bridge()

def _on_pipeline_tick(state: dict):
    # Auto-log security events from pipeline state
    contacts = state.get("contacts", [])
    swarm    = state.get("swarm", {})

    for c in contacts:
        if c.get("rf_silent") and not getattr(_on_pipeline_tick, f"_silent_{c['id']}", False):
            setattr(_on_pipeline_tick, f"_silent_{c['id']}", True)
            AuditLog.log_rf_silence(c["id"], "TERMINAL_GUIDANCE")

    if swarm.get("score", 0) >= 68:
        key = f"_swarm_{int(swarm['score']//10)}"
        if not getattr(_on_pipeline_tick, key, False):
            setattr(_on_pipeline_tick, key, True)
            AuditLog.log_swarm(swarm["score"], swarm.get("label",""))

    bridge.tick.emit(state)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # ── 1. Verify ML model integrity ──────────────────────────────
    mv = ModelVerifier()
    ok, info = mv.verify()
    if not ok and info.get("error") != "Model file not found":
        # Model exists but hash mismatch — critical security alert
        QMessageBox.critical(
            None,
            "Model Integrity Error",
            f"ML model verification FAILED.\n\n"
            f"Expected: {info.get('expected_sha256','?')}\n"
            f"Actual:   {info.get('actual_sha256','?')}\n\n"
            f"The model file may have been tampered with.\n"
            f"Continuing in rule-based fallback mode.",
        )
        AuditLog.write({
            "event":    "MODEL_VERIFY_FAIL",
            "severity": "CRITICAL",
            "action":   "Falling back to rule-based classifier",
        })
    elif ok:
        print(f"[Security] Model verified OK: {info.get('actual_sha256','')[:16]}...")

    # ── 2. JWT Login ───────────────────────────────────────────────
    auth = get_auth()
    login = LoginDialog(auth)
    if login.exec() != LoginDialog.DialogCode.Accepted:
        sys.exit(0)

    session = login.result_data
    AuditLog.log_login(session["username"], True, session["role"])
    AuditLog.write({
        "event":    "SESSION_START",
        "username": session["username"],
        "role":     session["role"],
    })
    print(f"[Auth] Logged in: {session['username']} ({session['role']})")

    # ── 3. TLS Server ─────────────────────────────────────────────
    try:
        from app.core.tls_server import TLSServer
        tls = TLSServer(Pipeline.__new__(Pipeline), auth)
        # Note: TLS server is optional — plain WS still runs via pipeline
    except Exception as e:
        print(f"[TLS] Not started: {e}")

    # ── 4. Pipeline ───────────────────────────────────────────────
    pipeline = Pipeline()
    pipeline.on_tick(_on_pipeline_tick)
    pipeline.start()

    # ── 5. Dashboard ──────────────────────────────────────────────
    window = MainWindow(pipeline, bridge, session=session, auth=auth)
    window.show()

    def _on_exit():
        AuditLog.write({
            "event":    "SESSION_END",
            "username": session["username"],
        })

    app.aboutToQuit.connect(_on_exit)
    sys.exit(app.exec())