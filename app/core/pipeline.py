# pipeline.py
# Mag-Null Project — Team Dimensioners
# Master tick loop — runs at 13 Hz, wires all DSP stages

import time
import threading
import numpy as np

from app.core.simulator import DroneSimulator
from app.core.dsp       import (NoiseFloorEstimator, detect_clusters,
                                classify_protocol, compute_swarm_score)
from app.core.silence   import RFSilenceWatchdog

TICK_INTERVAL = 0.075   # 75ms = 13 Hz
N_BINS        = 512

class Pipeline:
    def __init__(self):
        self.simulator  = DroneSimulator()
        self.noise_est  = NoiseFloorEstimator()
        self.watchdog   = RFSilenceWatchdog()
        self.lock       = threading.Lock()
        self._running   = False
        self._tick      = 0
        self._start_t   = time.time()
        self._state     = self._empty_state()
        self._callbacks = []
        self.simulator.load_scenario("idle")

    # ── Public API ──────────────────────────────────────────────
    def load_scenario(self, key):
        with self.lock:
            self.simulator.load_scenario(key)
            self.noise_est  = NoiseFloorEstimator()
            self.watchdog   = RFSilenceWatchdog()
            self._tick      = 0
            self._start_t   = time.time()

    def start(self):
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def stop(self):
        self._running = False

    def get_state(self):
        with self.lock:
            return dict(self._state)

    def on_tick(self, callback):
        self._callbacks.append(callback)

    # ── Tick Loop ───────────────────────────────────────────────
    def _loop(self):
        while self._running:
            t0 = time.perf_counter()
            state = self._tick_once()
            with self.lock:
                self._state = state
            for cb in self._callbacks:
                try:
                    cb(state)
                except Exception:
                    pass
            elapsed = time.perf_counter() - t0
            sleep   = max(0.0, TICK_INTERVAL - elapsed)
            time.sleep(sleep)

    def _tick_once(self):
        self._tick += 1
        sim_t  = int((time.time() - self._start_t) * 1000)
        uptime = round(time.time() - self._start_t, 1)

        # Stage 1 — generate/receive spectrum
        spectrum    = self.simulator.generate_spectrum(sim_t)
        drone_states = self.simulator.get_drone_states()

        # Stage 2 — noise floor
        noise_floor = self.noise_est.update(spectrum)

        # Stage 3 — waterfall row (normalised 0-1)
        wf_row = list(np.clip((spectrum - (-93)) / 52, 0, 1).round(3))

        # Stage 4/5/6 — build contact list from simulator states
        contacts  = []
        pipe_flags = [True, True, True, True, True, False, False]

        for cid, d in drone_states.items():
            self.watchdog.update(cid, d.get("last_seen", 0) or 0,
                                 d.get("rssi_hist", []))
            classified, conf = classify_protocol(
                d["hop_ms"],
                d["bw_bins"] * (80/512) * 1000,
                d["proto"] == "ELRS",
                d["proto"] == "DJI",
                d["hops"],
            )
            tl_map = {1:"LOW",2:"MEDIUM",3:"HIGH"}
            clr_map = {"LOW":"#00e5a0","MEDIUM":"#f5a623","HIGH":"#ff3355"}
            tl_str  = tl_map.get(d["threat"], "LOW")

            contacts.append({
                "id":         cid,
                "proto":      d["proto"],
                "label":      d["label"],
                "classified": classified,
                "cconf":      conf,
                "conf":       min(conf + 0.02 * d["hops"], 0.99),
                "hops":       d["hops"],
                "hop_hist":   d["hop_hist"][-16:],
                "hop_ms":     d["hop_ms"],
                "thr":        tl_str,
                "tl":         d["threat"],
                "color":      clr_map[tl_str],
                "bin":        d["hop_hist"][-1] if d["hop_hist"] else 256,
                "freq":       round(2400 + (d["hop_hist"][-1] if d["hop_hist"] else 256) * (80/512), 2),
                "first_seen": d["first_seen"],
                "last_seen":  d["last_seen"],
                "rf_silent":  d["rf_silent"],
                "silent_at":  d.get("silent_at"),
            })

        # Stage 7 — RF silence watchdog
        new_silent = self.watchdog.check_all(sim_t)
        if new_silent or any(c["rf_silent"] for c in contacts):
            pipe_flags[6] = True

        # Stage 8 — swarm analysis
        swarm = compute_swarm_score(contacts)
        if len(contacts) >= 2:
            pipe_flags[5] = True

        # Stage 9 — global threat
        gt, gt_level = self._global_threat(contacts)

        # Stage 10 — alerts
        alerts = []
        for ns in new_silent:
            alerts.append({
                "ts":   sim_t,
                "type": ns["severity"],
                "msg":  ns["msg"],
            })
        if swarm["score"] >= 68:
            alerts.append({
                "ts":   sim_t,
                "type": "WARNING",
                "msg":  f"Swarm score {swarm['score']} — {swarm['label']}",
            })

        return {
            "tick":          self._tick,
            "sim_time_ms":   sim_t,
            "uptime_s":      uptime,
            "scenario":      self.simulator.scenario,
            "spectrum":      list(spectrum.round(2)),
            "wf_row":        wf_row,
            "noise_floor":   round(float(np.median(noise_floor)), 2),
            "contacts":      contacts,
            "swarm":         swarm,
            "pipe_flags":    pipe_flags,
            "global_threat": gt,
            "gt_level":      gt_level,
            "alerts":        alerts,
            "n_contacts":    len(contacts),
            "n_alerts":      len(alerts),
        }

    def _global_threat(self, contacts):
        if any(c["rf_silent"] for c in contacts):
            return "TERMINAL", 5
        if any(c["tl"] >= 3 for c in contacts):
            return "CRITICAL", 4
        if any(c["tl"] >= 2 for c in contacts):
            return "WARNING", 3
        if contacts:
            return "ACTIVE", 2
        return "CLEAR", 1

    def _empty_state(self):
        return {
            "tick":0,"sim_time_ms":0,"uptime_s":0.0,
            "scenario":"idle","spectrum":[-90.0]*512,
            "wf_row":[0.0]*512,"noise_floor":-90.0,
            "contacts":[],"swarm":compute_swarm_score([]),
            "pipe_flags":[False]*7,"global_threat":"CLEAR",
            "gt_level":1,"alerts":[],"n_contacts":0,"n_alerts":0,
        }