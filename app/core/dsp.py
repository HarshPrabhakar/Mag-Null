# dsp.py
# Mag-Null Project

# dsp.py
# Mag-Null Project — Team Dimensioners
# FFT engine, noise floor, energy detection, classifier, swarm scorer

import numpy as np

# ── FFT ───────────────────────────────────────────────────────────
def compute_spectrum(iq_buffer):
    windowed = iq_buffer[:512] * np.hanning(512)
    fft_out  = np.fft.fft(windowed, n=512)
    power    = np.abs(fft_out) ** 2
    return 10 * np.log10(power + 1e-12)


# ── Noise Floor ───────────────────────────────────────────────────
class NoiseFloorEstimator:
    def __init__(self):
        self.history = []
        self.floor   = np.full(512, -90.0)

    def update(self, spectrum):
        self.history.append(spectrum.copy())
        if len(self.history) > 30:
            self.history.pop(0)
        if len(self.history) >= 5:
            self.floor = np.percentile(np.array(self.history), 12, axis=0)
        return self.floor


# ── Energy Detector ───────────────────────────────────────────────
def detect_clusters(spectrum, noise_floor, threshold_db=6.0):
    above    = spectrum > (noise_floor + threshold_db)
    clusters = []
    in_cl, start = False, 0
    for i in range(512):
        if above[i] and not in_cl:
            start, in_cl = i, True
        elif not above[i] and in_cl:
            if i - start >= 2:
                clusters.append((start, i - 1))
            in_cl = False
    if in_cl and 511 - start >= 2:
        clusters.append((start, 511))
    return clusters


# ── Feature Extractor ─────────────────────────────────────────────
def extract_features(hop_history, timestamps, bw_bins_list):
    if len(timestamps) < 2:
        return {"hop_ms": 0, "bw_khz": 0, "chirp": False, "ofdm": False}
    intervals = np.diff(timestamps)
    hop_ms    = float(np.median(intervals))
    bw_khz    = float(np.median(bw_bins_list)) * (80 / 512) * 1000
    chirp     = _detect_chirp(bw_bins_list)
    ofdm      = bw_khz > 5000
    return {"hop_ms": hop_ms, "bw_khz": bw_khz, "chirp": chirp, "ofdm": ofdm}

def _detect_chirp(bw_list):
    if len(bw_list) < 4:
        return False
    corr = np.corrcoef(range(len(bw_list)), bw_list)[0, 1]
    return bool(abs(corr) > 0.85)


# ── Protocol Classifier ───────────────────────────────────────────
def classify_protocol(hop_ms, bw_khz, chirp, ofdm, n_hops=0):
    conf_scale = min(1.0, 0.04 + n_hops * 0.055)
    if ofdm and bw_khz > 5000:
        return "DJI",   round(0.96 * conf_scale, 2)
    if chirp:
        return "ELRS",  round(0.93 * conf_scale, 2)
    if 18 <= hop_ms <= 22 and bw_khz < 700:
        return "AFHDS", round(0.88 * conf_scale, 2)
    if 5 <= hop_ms <= 9 and bw_khz < 1400:
        return "FASST", round(0.83 * conf_scale, 2)
    return "UNKNOWN",   round(0.40 * conf_scale, 2)


# ── Swarm Scorer ──────────────────────────────────────────────────
SWARM_LABELS = [
    (0,  15,  "NO SIGNAL",         "#4a6070"),
    (15, 30,  "SOLO OPERATOR",     "#00e5a0"),
    (30, 50,  "DUAL CONTACT",      "#00aaff"),
    (50, 68,  "COORDINATED PAIR",  "#f5a623"),
    (68, 82,  "SWARM DETECTED",    "#ff8800"),
    (82, 101, "ORGANIZED INTRUSION","#ff3355"),
]

def compute_swarm_score(contacts):
    N = len(contacts)
    if N == 0:
        return {"score":0,"label":"NO SIGNAL","color":"#4a6070",
                "factors":{"count":0,"diversity":0,"temporal":0,"threat":0,"simul":0},
                "assessment":"System on standby","recommendation":"Monitor"}

    count_s   = min(25.0, N * 6.25)
    protos    = set(c.get("proto","?") for c in contacts)
    div_s     = min(25.0, (len(protos) / 4) * 25)
    times     = [c.get("first_seen", 0) for c in contacts if c.get("first_seen")]
    if len(times) >= 2:
        spread = max(times) - min(times)
        temp_s = min(25.0, 25.0 * (1 - spread / 4000))
    else:
        temp_s = 0.0
    avg_tl  = sum(c.get("threat", 1) for c in contacts) / N
    thr_s   = min(15.0, ((avg_tl - 1) / 2) * 15)
    simul   = sum(1 for c in contacts
                  if len(times) >= 2 and (c.get("first_seen",0) - min(times)) <= 800)
    simul_s = min(10.0, simul * 5)

    score = round(count_s + div_s + temp_s + thr_s + simul_s, 1)
    label, color = "NO SIGNAL", "#4a6070"
    for lo, hi, lbl, clr in SWARM_LABELS:
        if lo <= score < hi:
            label, color = lbl, clr
            break

    return {
        "score":  score,
        "label":  label,
        "color":  color,
        "factors": {
            "count":     round(count_s, 1),
            "diversity": round(div_s, 1),
            "temporal":  round(temp_s, 1),
            "threat":    round(thr_s, 1),
            "simul":     round(simul_s, 1),
        },
        "assessment":    f"{N} contact(s) detected — {label}",
        "recommendation": _recommend(score),
    }

def _recommend(score):
    if score < 15:  return "System nominal"
    if score < 30:  return "Monitor — likely recreational"
    if score < 50:  return "Track — dual contact"
    if score < 68:  return "Alert operators — coordinated activity"
    if score < 82:  return "ACTIVATE RESPONSE PROTOCOL"
    return              "IMMEDIATE INTERCEPT — ORGANIZED ATTACK"