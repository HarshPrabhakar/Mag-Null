# silence.py
# Mag-Null Project — Team Dimensioners
# RF Silence Watchdog — detects terminal guidance mode

import numpy as np

class RFSilenceWatchdog:
    def __init__(self, timeout_ms=2500, slope_threshold=0.3):
        self.timeout_ms      = timeout_ms
        self.slope_threshold = slope_threshold
        self.contacts        = {}

    def update(self, cid, last_seen, rssi_history):
        self.contacts[cid] = {
            "last_seen":    last_seen,
            "rssi_history": list(rssi_history),
            "rf_silent":    self.contacts.get(cid, {}).get("rf_silent", False),
        }

    def check_all(self, current_time_ms):
        newly_silent = []
        for cid, data in self.contacts.items():
            if data["rf_silent"]:
                continue
            time_since = current_time_ms - data["last_seen"]
            if time_since > self.timeout_ms:
                data["rf_silent"] = True
                verdict  = self._verdict(cid)
                severity = "CRITICAL" if verdict == "TERMINAL_GUIDANCE" else "INFO"
                newly_silent.append({
                    "id":       cid,
                    "verdict":  verdict,
                    "severity": severity,
                    "msg":      f"{cid} — {verdict.replace('_',' ')}",
                })
        return newly_silent

    def _verdict(self, cid):
        h = self.contacts[cid].get("rssi_history", [])
        if len(h) < 5:
            return "OUT_OF_RANGE"
        recent = h[-10:]
        slope  = np.polyfit(range(len(recent)), recent, 1)[0]
        return "TERMINAL_GUIDANCE" if slope > self.slope_threshold else "OUT_OF_RANGE"

    def is_silent(self, cid):
        return self.contacts.get(cid, {}).get("rf_silent", False)

    def remove(self, cid):
        self.contacts.pop(cid, None)