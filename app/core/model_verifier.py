# app/core/model_verifier.py
# Mag-Null — ML Model Signature Verification
# Computes and verifies SHA-256 digest of model weights before loading.
# Logs every verification event to the audit trail.
#
# USAGE:
#   from app.core.model_verifier import ModelVerifier
#   mv = ModelVerifier()
#   ok, info = mv.verify(model_path)

import hashlib, json, time, os
from pathlib import Path
from datetime import datetime, timezone

ROOT        = Path(__file__).resolve().parent.parent.parent
MODEL_PATH  = ROOT / "app" / "core" / "models" / "spectrogram_cnn.pt"
SIG_FILE    = ROOT / "app" / "core" / "models" / "spectrogram_cnn.sig"
AUDIT_FILE  = ROOT / "config" / "audit_log.jsonl"


def _sha256_file(path: Path, chunk_size: int = 65536) -> str:
    """Stream-hash a file to avoid loading full weights into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


class ModelVerifier:
    """
    Computes SHA-256 digest of model file, compares against stored signature.
    Signs the model after training, verifies before inference.
    """

    def sign(self, model_path: Path = MODEL_PATH) -> dict:
        """
        Called automatically after training completes.
        Writes .sig file containing the SHA-256 digest.
        """
        if not model_path.exists():
            return {"ok": False, "error": f"Model not found: {model_path}"}

        digest    = _sha256_file(model_path)
        file_size = model_path.stat().st_size
        timestamp = datetime.now(timezone.utc).isoformat()

        sig_data = {
            "model":     model_path.name,
            "sha256":    digest,
            "size_bytes": file_size,
            "signed_at": timestamp,
            "signer":    "Mag-Null Training Pipeline",
        }

        sig_path = model_path.with_suffix(".sig")
        with open(sig_path, "w") as f:
            json.dump(sig_data, f, indent=2)

        AuditLog.write({
            "event":   "MODEL_SIGNED",
            "model":   model_path.name,
            "sha256":  digest[:16] + "...",
            "size_kb": round(file_size / 1024, 1),
        })

        return {"ok": True, "digest": digest, "sig_path": str(sig_path)}

    def verify(self, model_path: Path = MODEL_PATH) -> tuple[bool, dict]:
        """
        Verify model integrity before loading.
        Returns (True, info_dict) if valid, (False, error_dict) if not.
        """
        info = {
            "model":      model_path.name,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

        if not model_path.exists():
            info["error"] = "Model file not found"
            AuditLog.write({"event": "MODEL_VERIFY_FAIL", **info})
            return False, info

        sig_path = model_path.with_suffix(".sig")
        if not sig_path.exists():
            # No signature yet — first run after training, sign now
            self.sign(model_path)
            sig_path = model_path.with_suffix(".sig")

        with open(sig_path) as f:
            sig_data = json.load(f)

        expected = sig_data.get("sha256", "")
        actual   = _sha256_file(model_path)
        match    = (expected == actual)

        info.update({
            "expected_sha256": expected[:16] + "...",
            "actual_sha256":   actual[:16]   + "...",
            "size_bytes":      model_path.stat().st_size,
            "signed_at":       sig_data.get("signed_at", "unknown"),
            "match":           match,
        })

        if match:
            AuditLog.write({"event": "MODEL_VERIFY_OK", **info})
        else:
            info["error"] = "SHA-256 MISMATCH — model file may be tampered"
            AuditLog.write({"event": "MODEL_VERIFY_FAIL", "severity": "CRITICAL", **info})

        return match, info


# ══════════════════════════════════════════════════════════════════
# Audit Log
# ══════════════════════════════════════════════════════════════════
class AuditLog:
    """
    Append-only JSON Lines audit log.
    Every security-relevant event is written here.

    Event types:
        AUTH_LOGIN_OK      / AUTH_LOGIN_FAIL
        AUTH_LOGOUT
        SCENARIO_CHANGE
        MODEL_SIGNED       / MODEL_VERIFY_OK / MODEL_VERIFY_FAIL
        SESSION_START      / SESSION_END
        ALERT_GENERATED
        RF_SILENCE_DETECTED
        SWARM_DETECTED
    """

    @staticmethod
    def write(data: dict):
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts":         time.time(),
            "ts_iso":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            **data,
        }
        with open(AUDIT_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

    @staticmethod
    def read_recent(n: int = 100) -> list[dict]:
        """Read the last n entries from the audit log."""
        if not AUDIT_FILE.exists():
            return []
        entries = []
        with open(AUDIT_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        return entries[-n:]

    @staticmethod
    def log_login(username: str, success: bool, role: str = ""):
        AuditLog.write({
            "event":    "AUTH_LOGIN_OK" if success else "AUTH_LOGIN_FAIL",
            "username": username,
            "role":     role,
        })

    @staticmethod
    def log_scenario_change(scenario: str, username: str):
        AuditLog.write({
            "event":    "SCENARIO_CHANGE",
            "scenario": scenario,
            "username": username,
        })

    @staticmethod
    def log_alert(alert: dict, username: str = "system"):
        AuditLog.write({
            "event":    "ALERT_GENERATED",
            "username": username,
            "alert_type": alert.get("type",""),
            "msg":        alert.get("msg",""),
        })

    @staticmethod
    def log_rf_silence(contact_id: str, verdict: str):
        AuditLog.write({
            "event":      "RF_SILENCE_DETECTED",
            "contact":    contact_id,
            "verdict":    verdict,
            "severity":   "CRITICAL" if verdict == "TERMINAL_GUIDANCE" else "INFO",
        })

    @staticmethod
    def log_swarm(score: float, label: str):
        AuditLog.write({
            "event":   "SWARM_DETECTED",
            "score":   score,
            "label":   label,
            "severity":"CRITICAL" if score >= 82 else "WARNING",
        })