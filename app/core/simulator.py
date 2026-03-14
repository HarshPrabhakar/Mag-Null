# simulator.py
# Mag-Null Project

# simulator.py
# Mag-Null Project — Team Dimensioners
# Generates synthetic IQ signal bursts for 4 drone protocols

import numpy as np

PROTOCOLS = {
    "AFHDS": {"hop_ms": 20, "bw_bins": 3,  "threat": 1, "channels": 16, "label": "FlySky"},
    "ELRS":  {"hop_ms": 4,  "bw_bins": 3,  "threat": 2, "channels": 24, "label": "ExpressLRS"},
    "FASST": {"hop_ms": 7,  "bw_bins": 6,  "threat": 2, "channels": 36, "label": "Futaba"},
    "DJI":   {"hop_ms": 10, "bw_bins": 64, "threat": 3, "channels": 8,  "label": "OcuSync 2.0"},
}

class DroneSimulator:
    def __init__(self):
        self.drones   = {}
        self.scenario = "idle"

    def load_scenario(self, key):
        self.scenario = key
        self.drones   = {}

        scenarios = {
            "idle":  [],
            "hobby": [{"id":"TGT-001","proto":"AFHDS","seed":42}],
            "fpv":   [{"id":"TGT-002","proto":"ELRS", "seed":17}],
            "dji":   [{"id":"TGT-003","proto":"DJI",  "seed":99}],
            "swarm": [
                {"id":"TGT-004","proto":"AFHDS","seed":11},
                {"id":"TGT-005","proto":"ELRS", "seed":22},
                {"id":"TGT-006","proto":"FASST","seed":33},
                {"id":"TGT-007","proto":"DJI",  "seed":44},
            ],
            "silent":[{"id":"TGT-009","proto":"DJI","seed":55,"silent_at":6000}],
        }

        for d in scenarios.get(key, []):
            p    = PROTOCOLS[d["proto"]]
            seed = d["seed"]
            rng  = _lcg_table(seed, p["channels"])
            self.drones[d["id"]] = {
                "proto":     d["proto"],
                "label":     p["label"],
                "threat":    p["threat"],
                "hop_ms":    p["hop_ms"],
                "bw_bins":   p["bw_bins"],
                "channels":  p["channels"],
                "hop_table": rng,
                "hop_idx":   0,
                "next_hop":  0,
                "silent_at": d.get("silent_at", None),
                "rf_silent": False,
                "hops":      0,
                "hop_hist":  [],
                "first_seen":None,
                "last_seen": None,
                "rssi_hist": [],
            }

    def generate_spectrum(self, t_ms):
        spectrum = np.full(512, -90.0)
        for cid, d in self.drones.items():
            if d["rf_silent"]:
                continue
            if d["silent_at"] and t_ms >= d["silent_at"]:
                d["rf_silent"] = True
                continue
            if d["first_seen"] is None:
                d["first_seen"] = t_ms
            if t_ms >= d["next_hop"]:
                d["hop_idx"]  = (d["hop_idx"] + 1) % d["channels"]
                d["next_hop"] = t_ms + d["hop_ms"]
                d["hops"]    += 1
                d["last_seen"] = t_ms

            center = _bin_for_channel(d["hop_table"][d["hop_idx"]], d["channels"])
            bw     = d["bw_bins"]
            proto  = d["proto"]

            if proto == "DJI":
                lo = max(0, center - bw // 2)
                hi = min(511, center + bw // 2)
                spectrum[lo:hi] = np.maximum(spectrum[lo:hi], -45.0)
            elif proto == "ELRS":
                for i in range(max(0, center-1), min(512, center+2)):
                    t_norm = (i - center + 1) / 3.0
                    spectrum[i] = max(spectrum[i], -55.0 + 10 * t_norm)
            else:
                for i in range(max(0, center-1), min(512, center+2)):
                    g = np.exp(-0.5 * ((i - center) / 0.8) ** 2)
                    spectrum[i] = max(spectrum[i], -60.0 + 20 * g)

            rssi = float(np.max(spectrum[max(0,center-2):center+3]))
            d["rssi_hist"].append(rssi)
            if len(d["rssi_hist"]) > 30:
                d["rssi_hist"].pop(0)
            d["hop_hist"].append(center)
            if len(d["hop_hist"]) > 32:
                d["hop_hist"].pop(0)

        return spectrum

    def get_drone_states(self):
        return dict(self.drones)


def _lcg_table(seed, n):
    vals, s = [], seed
    for _ in range(n):
        s = (1664525 * s + 1013904223) & 0xFFFFFFFF
        vals.append(s % 512)
    return vals

def _bin_for_channel(raw, n_ch):
    lo, hi = 50, 462
    return int(lo + (raw / 512) * (hi - lo))