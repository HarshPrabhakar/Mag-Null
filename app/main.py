# main.py
# Mag-Null Project — Team Dimensioners
# Application entry point — boots the desktop window and pipeline

import sys
import os
import json
import threading
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QStatusBar
)
from PyQt6.QtCore  import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui   import QFont, QColor


from app.core.pipeline import Pipeline

# ── Signal bridge (pipeline thread → Qt main thread) ──────────────
class Bridge(QObject):
    tick = pyqtSignal(dict)

bridge = Bridge()

# ── Main Window ───────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self, pipeline):
        super().__init__()
        self.pipeline = pipeline
        self.setWindowTitle("Mag-Null — RF Drone Detection")
        self.setMinimumSize(1280, 800)
        self._build_ui()
        bridge.tick.connect(self._on_tick)

    def _build_ui(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #04070d; color: #c8d8e8; }
            QPushButton {
                background: #0a1220; border: 1px solid #1e3040;
                color: #c8d8e8; padding: 6px 16px; border-radius: 6px;
            }
            QPushButton:hover  { background: #0d1728; border-color: #0A6E8A; }
            QPushButton:pressed{ background: #0A6E8A; }
            QLabel { color: #c8d8e8; }
            QStatusBar { background: #070d17; color: #4a6070; font-size: 11px; }
        """)

        central = QWidget()
        root    = QVBoxLayout()
        root.setSpacing(0)
        root.setContentsMargins(0, 0, 0, 0)

        # ── Header ──
        header = QWidget()
        header.setFixedHeight(64)
        header.setStyleSheet("background:#070d17;border-bottom:1px solid #1e3040;")
        h_lay  = QHBoxLayout(header)
        h_lay.setContentsMargins(24, 0, 24, 0)

        logo = QLabel("MAG-NULL")
        logo.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        logo.setStyleSheet("color:#00e5a0;letter-spacing:4px;")

        self.threat_lbl = QLabel("● CLEAR")
        self.threat_lbl.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        self.threat_lbl.setStyleSheet("color:#00e5a0;")
        self.threat_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.contact_lbl = QLabel("0")
        self.contact_lbl.setFont(QFont("Arial", 28, QFont.Weight.Bold))
        self.contact_lbl.setStyleSheet("color:#00aaff;")

        contact_sub = QLabel("CONTACTS")
        contact_sub.setFont(QFont("Arial", 9))
        contact_sub.setStyleSheet("color:#4a6070;letter-spacing:2px;")

        cnt_col = QVBoxLayout()
        cnt_col.setSpacing(0)
        cnt_col.addWidget(self.contact_lbl)
        cnt_col.addWidget(contact_sub)

        h_lay.addWidget(logo)
        h_lay.addStretch()
        h_lay.addWidget(self.threat_lbl)
        h_lay.addStretch()
        h_lay.addLayout(cnt_col)

        # ── Scenario buttons ──
        btn_bar = QWidget()
        btn_bar.setFixedHeight(44)
        btn_bar.setStyleSheet("background:#04070d;border-bottom:1px solid #1e3040;")
        b_lay   = QHBoxLayout(btn_bar)
        b_lay.setContentsMargins(16, 0, 16, 0)
        b_lay.setSpacing(8)

        scenarios = ["idle", "hobby", "fpv", "dji", "swarm", "silent"]
        for s in scenarios:
            btn = QPushButton(s.upper())
            btn.setFixedHeight(28)
            btn.clicked.connect(lambda _, sc=s: self._switch(sc))
            b_lay.addWidget(btn)
        b_lay.addStretch()

        # ── Centre info area ──
        centre = QWidget()
        c_lay  = QVBoxLayout(centre)
        c_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

        info = QLabel("Mag-Null is running.\nSelect a scenario above to begin.")
        info.setFont(QFont("Courier New", 13))
        info.setStyleSheet("color:#4a6070;")
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.tick_lbl = QLabel("TICK 0")
        self.tick_lbl.setFont(QFont("Courier New", 11))
        self.tick_lbl.setStyleSheet("color:#1e3040;")
        self.tick_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.swarm_lbl = QLabel("SWARM SCORE  0")
        self.swarm_lbl.setFont(QFont("Arial", 14))
        self.swarm_lbl.setStyleSheet("color:#4a6070;")
        self.swarm_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        c_lay.addWidget(info)
        c_lay.addSpacing(16)
        c_lay.addWidget(self.tick_lbl)
        c_lay.addWidget(self.swarm_lbl)

        # ── Status bar ──
        sb = QStatusBar()
        sb.showMessage("Pipeline running at 13 Hz  |  No SDR hardware connected  |  Simulation mode")
        self.setStatusBar(sb)

        root.addWidget(header)
        root.addWidget(btn_bar)
        root.addWidget(centre, 1)
        central.setLayout(root)
        self.setCentralWidget(central)

    def _switch(self, scenario):
        self.pipeline.load_scenario(scenario)
        self.statusBar().showMessage(f"Scenario: {scenario.upper()} loaded")

    def _on_tick(self, state):
        # Update threat label
        gt    = state.get("global_threat", "CLEAR")
        colors = {
            "CLEAR":"#00e5a0","ACTIVE":"#00e5a0",
            "WARNING":"#f5a623","CRITICAL":"#ff3355","TERMINAL":"#ff3355"
        }
        c = colors.get(gt, "#c8d8e8")
        self.threat_lbl.setText(f"● {gt}")
        self.threat_lbl.setStyleSheet(f"color:{c};")

        # Update contact count
        n = state.get("n_contacts", 0)
        self.contact_lbl.setText(str(n))
        self.contact_lbl.setStyleSheet(
            "color:#ff3355;" if n > 0 else "color:#00aaff;"
        )

        # Update tick
        self.tick_lbl.setText(
            f"TICK {state['tick']}  |  "
            f"SIM {state['sim_time_ms']}ms  |  "
            f"UPTIME {state['uptime_s']}s"
        )

        # Update swarm
        sw = state.get("swarm", {})
        sc = sw.get("score", 0)
        lb = sw.get("label", "NO SIGNAL")
        cl = sw.get("color", "#4a6070")
        self.swarm_lbl.setText(f"SWARM SCORE  {sc}  —  {lb}")
        self.swarm_lbl.setStyleSheet(f"color:{cl};font-size:14px;")

        # Update window title
        self.setWindowTitle(f"Mag-Null — {n} CONTACTS — {gt}")


# ── Pipeline → Qt bridge ──────────────────────────────────────────
def _on_pipeline_tick(state):
    bridge.tick.emit(state)


# ── Entry Point ───────────────────────────────────────────────────
if __name__ == "__main__":
    app      = QApplication(sys.argv)
    pipeline = Pipeline()
    pipeline.on_tick(_on_pipeline_tick)
    pipeline.start()

    window = MainWindow(pipeline)
    window.show()

    sys.exit(app.exec())