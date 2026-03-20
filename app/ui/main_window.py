# main_window.py
# Mag-Null — Full Dashboard UI
# Team Dimensioners
# Security: JWT session display, Audit Log panel, TLS status, Model verification

import math
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QSplitter, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QScrollArea, QSizePolicy, QStatusBar,
    QTabWidget, QComboBox
)
from PyQt6.QtCore  import Qt, QTimer, pyqtSignal, QObject, QRectF, QPointF
from PyQt6.QtGui   import (
    QPainter, QColor, QPen, QBrush, QFont,
    QFontDatabase, QLinearGradient, QPolygonF,
    QImage, QPainterPath
)

# ── Colours ───────────────────────────────────────────────────────
C_BG     = "#04070d"
C_BG1    = "#070d17"
C_BG2    = "#0a1220"
C_BORDER = "#1e3040"
C_GREEN  = "#00e5a0"
C_AMBER  = "#f5a623"
C_RED    = "#ff3355"
C_BLUE   = "#00aaff"
C_TEXT   = "#c8d8e8"
C_DIM    = "#4a6070"
C_DIMMER = "#1e3040"

THREAT_COLORS = {
    "CLEAR":    C_GREEN,
    "ACTIVE":   C_GREEN,
    "WARNING":  C_AMBER,
    "CRITICAL": C_RED,
    "TERMINAL": C_RED,
}

PROTO_COLORS = {
    "AFHDS":   C_GREEN,
    "ELRS":    C_AMBER,
    "FASST":   C_AMBER,
    "DJI":     C_RED,
    "UNKNOWN": C_DIM,
}

GLOBAL_STYLE = f"""
QMainWindow, QWidget {{
    background-color: {C_BG};
    color: {C_TEXT};
    font-family: 'Segoe UI', Arial, sans-serif;
}}
QFrame {{ background-color: {C_BG}; }}
QPushButton {{
    background: {C_BG1};
    border: 1px solid {C_BORDER};
    color: {C_TEXT};
    padding: 5px 14px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
}}
QPushButton:hover  {{ background: {C_BG2}; border-color: {C_GREEN}; color: {C_GREEN}; }}
QPushButton:pressed{{ background: {C_GREEN}; color: {C_BG}; }}
QPushButton#active {{ background: {C_GREEN}; color: {C_BG}; border-color: {C_GREEN}; }}
QTableWidget {{
    background: {C_BG};
    border: none;
    gridline-color: {C_BORDER};
    color: {C_TEXT};
    font-size: 11px;
    selection-background-color: {C_BG2};
}}
QTableWidget::item {{ padding: 4px 8px; border-bottom: 1px solid {C_DIMMER}; }}
QTableWidget::item:selected {{ background: {C_BG2}; color: {C_GREEN}; }}
QHeaderView::section {{
    background: {C_BG2};
    color: {C_DIM};
    border: none;
    border-bottom: 1px solid {C_BORDER};
    padding: 5px 8px;
    font-size: 10px;
    letter-spacing: 1px;
    font-weight: 600;
}}
QScrollBar:vertical {{
    background: {C_BG};
    width: 4px;
    border-radius: 2px;
}}
QScrollBar::handle:vertical {{
    background: {C_BORDER};
    border-radius: 2px;
    min-height: 20px;
}}
QStatusBar {{
    background: {C_BG1};
    color: {C_DIM};
    font-size: 10px;
    border-top: 1px solid {C_BORDER};
}}
QSplitter::handle {{ background: {C_BORDER}; }}
QTabWidget::pane {{
    border: none;
    background: {C_BG};
}}
QTabBar::tab {{
    background: {C_BG2};
    color: {C_DIM};
    font-size: 9px;
    font-weight: 600;
    letter-spacing: 1px;
    padding: 5px 14px;
    border: none;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{
    color: {C_GREEN};
    border-bottom: 2px solid {C_GREEN};
    background: {C_BG};
}}
QTabBar::tab:hover {{ color: {C_TEXT}; }}
QComboBox {{
    background: {C_BG};
    border: 1px solid {C_BORDER};
    color: {C_TEXT};
    font-size: 9px;
    padding: 1px 4px;
    border-radius: 3px;
}}
QComboBox::drop-down {{ border: none; }}
QComboBox QAbstractItemView {{
    background: {C_BG1};
    color: {C_TEXT};
    selection-background-color: {C_BG2};
    border: 1px solid {C_BORDER};
}}
"""


# ══════════════════════════════════════════════════════════════════
# Waterfall Widget — live spectrogram
# ══════════════════════════════════════════════════════════════════
class WaterfallWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(200)
        self.history  = []
        self.max_rows = 120
        self._image   = None

    def push_row(self, wf_row):
        self.history.insert(0, wf_row)
        if len(self.history) > self.max_rows:
            self.history.pop()
        self._rebuild_image()
        self.update()

    def _rebuild_image(self):
        W, H = 512, len(self.history)
        if H == 0:
            return
        img = QImage(W, H, QImage.Format.Format_RGB32)
        for row_i, row in enumerate(self.history):
            for col_i, v in enumerate(row[:512]):
                img.setPixel(col_i, row_i, self._thermal(v))
        self._image = img

    @staticmethod
    def _thermal(t):
        t = max(0.0, min(1.0, t))
        if t < 0.18:
            r, g, b = 0, 0, int(t / 0.18 * 80)
        elif t < 0.38:
            p = (t - 0.18) / 0.20
            r, g, b = 0, int(p * 180), int(80 + p * 175)
        elif t < 0.58:
            p = (t - 0.38) / 0.20
            r, g, b = 0, int(180 + p * 75), int(255 - p * 255)
        elif t < 0.78:
            p = (t - 0.58) / 0.20
            r, g, b = int(p * 255), 255, 0
        else:
            p = (t - 0.78) / 0.22
            r, g, b = 255, int(255 - p * 255), 0
        return QColor(r, g, b).rgb()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(C_BG))
        if self._image:
            p.drawImage(self.rect(), self._image)
        p.setPen(QColor(C_DIM))
        p.setFont(QFont("Courier New", 8))
        p.drawText(6, 14, "SPECTROGRAM  2.4 GHz")
        p.drawText(6, self.height() - 6, "2400 MHz")
        p.drawText(self.width() - 80, self.height() - 6, "2480 MHz")


# ══════════════════════════════════════════════════════════════════
# Spectrum Bars Widget
# ══════════════════════════════════════════════════════════════════
class SpectrumWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(70)
        self.spectrum    = [-90.0] * 512
        self.noise_floor = -90.0

    def update_data(self, spectrum, noise_floor):
        self.spectrum    = spectrum
        self.noise_floor = noise_floor
        self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(C_BG1))
        W, H   = self.width(), self.height()
        N      = 128
        step   = 512 // N
        bw     = max(1, W // N - 1)
        mn, mx = -95, -40
        for i in range(N):
            val  = max(self.spectrum[i * step:(i + 1) * step])
            norm = max(0.0, min(1.0, (val - mn) / (mx - mn)))
            bh   = int(norm * (H - 12))
            bx   = int(i * W / N)
            col  = QColor(C_RED) if norm > 0.75 else QColor(C_AMBER) if norm > 0.45 else QColor(C_DIM)
            p.fillRect(bx, H - bh - 4, bw, bh, col)
        nf_norm = (self.noise_floor - mn) / (mx - mn)
        nf_y    = H - int(nf_norm * (H - 12)) - 4
        pen = QPen(QColor(C_DIMMER)); pen.setWidth(1); pen.setStyle(Qt.PenStyle.DashLine)
        p.setPen(pen)
        p.drawLine(0, nf_y, W, nf_y)
        p.setPen(QColor(C_DIM))
        p.setFont(QFont("Courier New", 7))
        p.drawText(4, 10, "SPECTRUM")


# ══════════════════════════════════════════════════════════════════
# Contact Table
# ══════════════════════════════════════════════════════════════════
COLS = ["ID", "PROTOCOL", "CLASSIFIED", "CONF", "FREQ MHz", "HOPS", "THREAT", "STATUS"]

class ContactTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(0, len(COLS), parent)
        self.setHorizontalHeaderLabels(COLS)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(False)
        self.setShowGrid(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.setColumnWidth(3, 80)

    def update_contacts(self, contacts):
        self.setRowCount(len(contacts))
        for r, c in enumerate(contacts):
            silent = c.get("rf_silent", False)
            tl     = c.get("thr", "LOW")
            tcol   = {1: C_GREEN, 2: C_AMBER, 3: C_RED}.get(c.get("tl", 1), C_GREEN)
            proto  = c.get("proto", "?")
            pcol   = PROTO_COLORS.get(proto, C_DIM)

            def cell(txt, color=C_TEXT, bold=False):
                item = QTableWidgetItem(str(txt))
                item.setForeground(QColor(color))
                if bold:
                    f = item.font(); f.setBold(True); item.setFont(f)
                return item

            self.setItem(r, 0, cell(c.get("id", "?"),          C_BLUE, True))
            self.setItem(r, 1, cell(proto,                       pcol,  True))
            self.setItem(r, 2, cell(c.get("classified", "?"),   pcol))
            self.setItem(r, 3, cell(f"{c.get('conf',0)*100:.0f}%", C_GREEN))
            self.setItem(r, 4, cell(f"{c.get('freq',0):.1f}"))
            self.setItem(r, 5, cell(c.get("hops", 0)))
            self.setItem(r, 6, cell(tl, tcol, True))
            st = "RF SILENT" if silent else "ACTIVE"
            sc = C_RED if silent else C_GREEN
            self.setItem(r, 7, cell(st, sc, silent))
            self.setRowHeight(r, 26)


# ══════════════════════════════════════════════════════════════════
# Swarm Panel
# ══════════════════════════════════════════════════════════════════
class SwarmPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(130)
        self.score   = 0
        self.label   = "NO SIGNAL"
        self.color   = C_DIM
        self.factors = {}
        self._pulse  = 0.0
        self._timer  = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(50)

    def _tick(self):
        self._pulse = (self._pulse + 0.08) % (2 * math.pi)
        if self.score >= 68:
            self.update()

    def update_swarm(self, sw):
        self.score   = sw.get("score", 0)
        self.label   = sw.get("label", "NO SIGNAL")
        self.color   = sw.get("color", C_DIM)
        self.factors = sw.get("factors", {})
        self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(C_BG1))
        W, H = self.width(), self.height()
        cx, cy, R = 65, H // 2 + 4, 44
        pen = QPen(QColor(C_BORDER)); pen.setWidth(6); pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen); p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(int(cx-R), int(cy-R), int(R*2), int(R*2))
        ang = int(self.score / 100 * 360 * 16)
        col = QColor(self.color)
        if self.score >= 68:
            col.setAlpha(int(180 + 75 * math.sin(self._pulse)))
        pen2 = QPen(col); pen2.setWidth(6); pen2.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen2)
        p.drawArc(int(cx-R), int(cy-R), int(R*2), int(R*2), 90*16, -ang)
        p.setPen(QColor(self.color))
        p.setFont(QFont("Arial Black", 20, QFont.Weight.Black))
        sc_txt = str(int(self.score))
        fm = p.fontMetrics()
        p.drawText(cx - fm.horizontalAdvance(sc_txt)//2, cy + 8, sc_txt)
        p.setPen(QColor(C_DIM))
        p.setFont(QFont("Courier New", 7))
        lbl = "SWARM SCORE"
        p.drawText(cx - fm.horizontalAdvance(lbl)//2 + 2, cy + 20, lbl)
        p.setPen(QColor(self.color))
        p.setFont(QFont("Arial", 9, QFont.Weight.Bold))
        p.drawText(125, cy - 28, self.label)
        factor_defs = [
            ("COUNT",     "count",     25),
            ("DIVERSITY", "diversity", 25),
            ("TEMPORAL",  "temporal",  25),
            ("THREAT",    "threat",    15),
            ("SIMUL",     "simul",     10),
        ]
        bar_x, bar_y, bar_h, bar_gap = 125, cy - 12, 12, 18
        bar_w = min(160, W - bar_x - 20)
        p.setFont(QFont("Courier New", 7))
        for i, (name, key, max_val) in enumerate(factor_defs):
            val  = self.factors.get(key, 0)
            norm = val / max_val if max_val > 0 else 0
            by   = bar_y + i * bar_gap
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(C_DIMMER))
            p.drawRoundedRect(bar_x, by, bar_w, bar_h, 3, 3)
            fw = int(norm * bar_w)
            if fw > 0:
                p.setBrush(QColor(self.color))
                p.drawRoundedRect(bar_x, by, fw, bar_h, 3, 3)
            p.setPen(QColor(C_DIM))
            p.drawText(bar_x + bar_w + 6, by + 9, f"{name}  {val:.0f}/{max_val}")


# ══════════════════════════════════════════════════════════════════
# Pipeline Panel
# ══════════════════════════════════════════════════════════════════
STAGE_NAMES = ["SDR SCAN", "FFT", "NOISE EST.", "ENERGY DET.", "CLASSIFIER", "SWARM", "RF SILENCE"]

class PipelinePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(48)
        self.flags = [False] * 7

    def update_flags(self, flags):
        self.flags = list(flags) + [False] * (7 - len(flags))
        self.update()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(C_BG1))
        W    = self.width()
        slot = W // 7
        cy   = self.height() // 2 - 2
        for i, (name, flag) in enumerate(zip(STAGE_NAMES, self.flags)):
            x   = i * slot + slot // 2
            col = QColor(C_GREEN if flag else C_DIMMER)
            p.setBrush(col); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(x - 5, cy - 5, 10, 10)
            if i < 6:
                lc  = QColor(C_GREEN if (flag and self.flags[i+1]) else C_DIMMER)
                pen = QPen(lc); pen.setWidth(1)
                p.setPen(pen)
                p.drawLine(x + 5, cy, x + slot - 5, cy)
            p.setPen(QColor(C_GREEN if flag else C_DIMMER))
            p.setFont(QFont("Courier New", 6))
            fm = p.fontMetrics()
            p.drawText(x - fm.horizontalAdvance(name)//2, cy + 16, name)


# ══════════════════════════════════════════════════════════════════
# Alert Log
# ══════════════════════════════════════════════════════════════════
class AlertLog(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(80)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll.setStyleSheet("border:none;")
        self.inner = QWidget()
        self.inner_layout = QVBoxLayout(self.inner)
        self.inner_layout.setContentsMargins(6, 4, 6, 4)
        self.inner_layout.setSpacing(2)
        self.inner_layout.addStretch()
        self.scroll.setWidget(self.inner)
        layout.addWidget(self.scroll)
        self._entries = []

    def push_alerts(self, alerts):
        for a in alerts:
            msg = a.get("msg", "")
            typ = a.get("type", "INFO")
            col = C_RED if typ in ("CRITICAL", "WARNING") else C_AMBER
            ts  = a.get("ts", 0)
            key = f"{ts}_{msg}"
            if key in self._entries:
                continue
            self._entries.append(key)
            lbl = QLabel(f"  {ts:6d}ms  {msg}")
            lbl.setStyleSheet(
                f"color:{col};font-family:'Courier New';font-size:9px;"
                f"padding:1px 0;background:{C_BG};")
            self.inner_layout.insertWidget(self.inner_layout.count() - 1, lbl)
            if len(self._entries) > 60:
                old = self.inner_layout.takeAt(0)
                if old and old.widget():
                    old.widget().deleteLater()
                self._entries.pop(0)
        sb = self.scroll.verticalScrollBar()
        sb.setValue(sb.maximum())


# ══════════════════════════════════════════════════════════════════
# ── NEW ── Audit Log Panel                                Feature 4
# ══════════════════════════════════════════════════════════════════
AUDIT_COLS = ["TIMESTAMP", "EVENT", "SEV", "DETAILS"]
AUDIT_EVENT_COLORS = {
    "AUTH_LOGIN_OK":       C_GREEN,
    "AUTH_LOGIN_FAIL":     C_RED,
    "AUTH_LOGOUT":         C_AMBER,
    "SCENARIO_CHANGE":     C_BLUE,
    "MODEL_SIGNED":        C_GREEN,
    "MODEL_VERIFY_OK":     C_GREEN,
    "MODEL_VERIFY_FAIL":   C_RED,
    "SESSION_START":       C_GREEN,
    "SESSION_END":         C_DIM,
    "ALERT_GENERATED":     C_AMBER,
    "RF_SILENCE_DETECTED": C_RED,
    "SWARM_DETECTED":      C_RED,
}

class AuditPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._shown   = set()
        self._filter  = "ALL"
        self._build()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(2000)

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Filter bar
        bar = QWidget()
        bar.setFixedHeight(28)
        bar.setStyleSheet(f"background:{C_BG2};border-bottom:1px solid {C_BORDER};")
        bar_h = QHBoxLayout(bar)
        bar_h.setContentsMargins(8, 0, 8, 0)
        bar_h.setSpacing(6)

        bar_h.addWidget(QLabel("FILTER:"))
        self.filter_box = QComboBox()
        self.filter_box.addItems(["ALL", "AUTH", "MODEL", "ALERTS", "RF", "CRITICAL"])
        self.filter_box.setFixedWidth(100)
        self.filter_box.currentTextChanged.connect(self._on_filter)
        bar_h.addWidget(self.filter_box)
        bar_h.addStretch()

        export_btn = QPushButton("EXPORT CSV")
        export_btn.setFixedHeight(20)
        export_btn.setStyleSheet(
            f"background:transparent;border:1px solid {C_BORDER};"
            f"color:{C_DIM};font-size:8px;letter-spacing:1px;padding:1px 8px;")
        export_btn.clicked.connect(self._export)
        bar_h.addWidget(export_btn)
        layout.addWidget(bar)

        # Table
        self.table = QTableWidget(0, len(AUDIT_COLS))
        self.table.setHorizontalHeaderLabels(AUDIT_COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setShowGrid(False)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed);  self.table.setColumnWidth(0, 152)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed);  self.table.setColumnWidth(1, 170)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed);  self.table.setColumnWidth(2, 68)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        # Status strip
        self.status_lbl = QLabel("  Ready")
        self.status_lbl.setFixedHeight(16)
        self.status_lbl.setStyleSheet(
            f"color:{C_DIM};font-size:8px;font-family:'Courier New';"
            f"background:{C_BG1};border-top:1px solid {C_BORDER};padding:0 6px;")
        layout.addWidget(self.status_lbl)

    def refresh(self):
        try:
            from app.core.model_verifier import AuditLog
            entries = AuditLog.read_recent(200)
        except Exception:
            return

        new_count = 0
        for entry in entries:
            uid = f"{entry.get('ts',0):.3f}_{entry.get('event','')}"
            if uid in self._shown:
                continue
            event = entry.get("event", "UNKNOWN")
            self._shown.add(uid)
            if not self._passes_filter(event):
                continue
            self._add_row(entry, event)
            new_count += 1

        if new_count:
            self.table.scrollToBottom()
            self.status_lbl.setText(
                f"  {self.table.rowCount()} entries  ·  {new_count} new  ·  filter: {self._filter}")
        while self.table.rowCount() > 500:
            self.table.removeRow(0)

    def _add_row(self, entry, event):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setRowHeight(r, 20)

        ts_str   = entry.get("ts_iso", "")
        severity = entry.get("severity", self._infer_sev(event))
        details  = "  ·  ".join(
            f"{k}={v}" for k, v in entry.items()
            if k not in {"ts", "ts_iso", "event", "severity"})

        ecol = AUDIT_EVENT_COLORS.get(event, C_TEXT)
        scol = {
            "CRITICAL": C_RED,
            "WARNING":  C_AMBER,
            "INFO":     C_DIM
        }.get(severity, C_DIM)

        def cell(txt, col=C_TEXT, bold=False, mono=False):
            item = QTableWidgetItem(str(txt))
            item.setForeground(QColor(col))
            f = item.font()
            if bold: f.setBold(True)
            if mono: f.setFamily("Courier New"); f.setPointSize(8)
            item.setFont(f)
            return item

        self.table.setItem(r, 0, cell(ts_str,   C_DIM,  mono=True))
        self.table.setItem(r, 1, cell(event,     ecol,   bold=True))
        self.table.setItem(r, 2, cell(severity,  scol,   bold=(severity == "CRITICAL")))
        self.table.setItem(r, 3, cell(details,   C_TEXT))

    def _infer_sev(self, event):
        if any(x in event for x in ("FAIL", "SILENCE", "SWARM")):
            return "CRITICAL"
        if any(x in event for x in ("WARN", "LOGOUT")):
            return "WARNING"
        return "INFO"

    def _passes_filter(self, event):
        f = self._filter
        if f == "ALL":      return True
        if f == "AUTH":     return "AUTH" in event
        if f == "MODEL":    return "MODEL" in event
        if f == "ALERTS":   return "ALERT" in event
        if f == "RF":       return "RF" in event or "SWARM" in event
        if f == "CRITICAL": return self._infer_sev(event) == "CRITICAL"
        return True

    def _on_filter(self, value):
        self._filter = value
        self._shown  = set()
        self.table.setRowCount(0)
        self.refresh()

    def _export(self):
        from pathlib import Path
        import time as _t
        out = Path.home() / f"magnull_audit_{int(_t.time())}.csv"
        with open(out, "w") as f:
            f.write(",".join(AUDIT_COLS) + "\n")
            for r in range(self.table.rowCount()):
                row = [f'"{(self.table.item(r,c) or QTableWidgetItem("")).text()}"'
                       for c in range(len(AUDIT_COLS))]
                f.write(",".join(row) + "\n")
        self.status_lbl.setText(f"  Exported → {out.name}")


# ══════════════════════════════════════════════════════════════════
# RF Silence Banner
# ══════════════════════════════════════════════════════════════════
class SilenceBanner(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(0)
        self._pulse = 0.0
        self._t = QTimer(self)
        self._t.timeout.connect(self._tick)
        self._t.start(60)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.lbl = QLabel("🔴  RF SILENCE — TERMINAL GUIDANCE SUSPECTED")
        self.lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl.setStyleSheet(
            f"font-family:'Courier New';font-weight:700;"
            f"font-size:12px;letter-spacing:2px;color:{C_RED};")
        layout.addWidget(self.lbl)

    def _tick(self):
        self._pulse = (self._pulse + 0.1) % (2 * math.pi)
        if self.height() > 0:
            alpha = int(160 + 95 * math.sin(self._pulse))
            self.setStyleSheet(
                f"background:rgba(255,51,85,{alpha/255:.2f});"
                f"border-bottom:1px solid {C_RED};")

    def show_banner(self, visible):
        self.setFixedHeight(32 if visible else 0)


# ══════════════════════════════════════════════════════════════════
# Main Window
# ══════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):

    # ── CHANGED: accepts session + auth ──────────────────────────
    def __init__(self, pipeline, bridge, session=None, auth=None):
        super().__init__()
        self.pipeline          = pipeline
        self._session          = session or {}          # JWT session dict
        self._auth             = auth                   # AuthManager instance
        self._active_scenario  = "idle"

        self.setWindowTitle("Mag-Null — RF Drone Detection")
        self.setMinimumSize(1280, 800)
        self.setStyleSheet(GLOBAL_STYLE)
        self._build_ui()
        bridge.tick.connect(self._on_tick)

    # ── Build UI ─────────────────────────────────────────────────
    def _build_ui(self):
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setCentralWidget(root)

        # ── Header ──────────────────────────────────────────────
        header = QWidget()
        header.setFixedHeight(60)
        header.setStyleSheet(f"background:{C_BG1};border-bottom:1px solid {C_BORDER};")
        h = QHBoxLayout(header)
        h.setContentsMargins(20, 0, 20, 0)

        logo = QLabel("MAG-NULL")
        logo.setFont(QFont("Arial Black", 18, QFont.Weight.Black))
        logo.setStyleSheet(f"color:{C_GREEN};letter-spacing:4px;")

        self.threat_lbl = QLabel("● CLEAR")
        self.threat_lbl.setFont(QFont("Arial Black", 18, QFont.Weight.Black))
        self.threat_lbl.setStyleSheet(f"color:{C_GREEN};")
        self.threat_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        cnt_col = QWidget()
        cnt_v   = QVBoxLayout(cnt_col)
        cnt_v.setSpacing(0); cnt_v.setContentsMargins(0, 0, 0, 0)
        self.cnt_lbl = QLabel("0")
        self.cnt_lbl.setFont(QFont("Arial Black", 28, QFont.Weight.Black))
        self.cnt_lbl.setStyleSheet(f"color:{C_BLUE};")
        self.cnt_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
        cnt_sub = QLabel("CONTACTS")
        cnt_sub.setStyleSheet(f"color:{C_DIM};font-size:9px;letter-spacing:2px;")
        cnt_sub.setAlignment(Qt.AlignmentFlag.AlignRight)
        cnt_v.addWidget(self.cnt_lbl)
        cnt_v.addWidget(cnt_sub)

        h.addWidget(logo)
        h.addStretch()
        h.addWidget(self.threat_lbl)
        h.addStretch()
        h.addWidget(cnt_col)

        # ── FEATURE 1: Session badge ─────────────────────────────
        uname   = self._session.get("username", "")
        role    = self._session.get("role", "").upper()
        if uname:
            role_col = {"ADMIN": C_RED, "OPERATOR": C_GREEN, "ANALYST": C_AMBER}.get(role, C_DIM)
            sess_lbl = QLabel(f"  {uname}  [{role}]")
            sess_lbl.setStyleSheet(
                f"color:{role_col};font-size:9px;font-family:'Courier New';"
                f"letter-spacing:1px;background:{C_BG2};"
                f"border:1px solid {C_BORDER};border-radius:3px;padding:2px 10px;")
            sess_lbl.setFixedHeight(22)
            h.addSpacing(16)
            h.addWidget(sess_lbl)

        root_layout.addWidget(header)

        # ── RF Silence Banner ────────────────────────────────────
        self.silence_banner = SilenceBanner()
        root_layout.addWidget(self.silence_banner)

        # ── Scenario Buttons ─────────────────────────────────────
        btn_bar = QWidget()
        btn_bar.setFixedHeight(40)
        btn_bar.setStyleSheet(f"background:{C_BG};border-bottom:1px solid {C_BORDER};")
        b = QHBoxLayout(btn_bar)
        b.setContentsMargins(12, 0, 12, 0)
        b.setSpacing(8)
        self._scenario_btns = {}
        for sc in ["idle", "hobby", "fpv", "dji", "swarm", "silent"]:
            btn = QPushButton(sc.upper())
            btn.setFixedHeight(26)
            btn.clicked.connect(lambda _, s=sc: self._switch(s))
            self._scenario_btns[sc] = btn
            b.addWidget(btn)
        b.addStretch()
        root_layout.addWidget(btn_bar)

        # ── Main Content ─────────────────────────────────────────
        splitter_v = QSplitter(Qt.Orientation.Vertical)
        splitter_v.setHandleWidth(2)

        splitter_h = QSplitter(Qt.Orientation.Horizontal)
        splitter_h.setHandleWidth(2)

        # Left column — waterfall + spectrum + contacts
        left_col = QWidget()
        left_v   = QVBoxLayout(left_col)
        left_v.setContentsMargins(0, 0, 0, 0)
        left_v.setSpacing(0)
        left_v.addWidget(self._panel_label("SPECTROGRAM  ·  2.4 GHz ISM BAND"))
        self.waterfall = WaterfallWidget()
        left_v.addWidget(self.waterfall, 3)
        self.spectrum_w = SpectrumWidget()
        left_v.addWidget(self.spectrum_w)
        left_v.addWidget(self._panel_label("THREAT CONTACTS"))
        self.contact_table = ContactTable()
        left_v.addWidget(self.contact_table, 2)
        splitter_h.addWidget(left_col)

        # Right column — tabbed: Alerts | Audit Log
        right_col = QWidget()
        right_v   = QVBoxLayout(right_col)
        right_v.setContentsMargins(0, 0, 0, 0)
        right_v.setSpacing(0)
        right_col.setMinimumWidth(280)
        right_col.setMaximumWidth(420)

        # ── FEATURE 4: Tabbed right panel with Audit Log ─────────
        self.right_tabs = QTabWidget()
        self.alert_log   = AlertLog()
        self.audit_panel = AuditPanel()
        self.right_tabs.addTab(self.alert_log,   "ALERTS")
        self.right_tabs.addTab(self.audit_panel, "AUDIT LOG")
        right_v.addWidget(self.right_tabs)

        # Scenario info
        info_hdr = self._panel_label("SCENARIO")
        right_v.addWidget(info_hdr)
        self.scenario_lbl = QLabel("  IDLE — No drones active")
        self.scenario_lbl.setStyleSheet(
            f"color:{C_DIM};font-size:10px;font-family:'Courier New';"
            f"padding:6px;background:{C_BG1};")
        self.scenario_lbl.setWordWrap(True)
        right_v.addWidget(self.scenario_lbl)
        right_v.addStretch()

        splitter_h.addWidget(right_col)
        splitter_h.setSizes([900, 320])
        splitter_v.addWidget(splitter_h)

        # Bottom — swarm + pipeline
        bottom = QWidget()
        bottom.setFixedHeight(148)
        bottom.setStyleSheet(f"background:{C_BG1};border-top:1px solid {C_BORDER};")
        bot_h = QHBoxLayout(bottom)
        bot_h.setContentsMargins(0, 0, 0, 0)
        bot_h.setSpacing(0)

        sw_wrap = QWidget()
        sw_wrap.setMinimumWidth(520)
        sw_v = QVBoxLayout(sw_wrap)
        sw_v.setContentsMargins(0, 0, 0, 0)
        sw_v.setSpacing(0)
        sw_v.addWidget(self._panel_label("SWARM INTELLIGENCE"))
        self.swarm_panel = SwarmPanel()
        sw_v.addWidget(self.swarm_panel)
        bot_h.addWidget(sw_wrap)

        div = QFrame()
        div.setFrameShape(QFrame.Shape.VLine)
        div.setStyleSheet(f"color:{C_BORDER};")
        bot_h.addWidget(div)

        pp_wrap = QWidget()
        pp_v = QVBoxLayout(pp_wrap)
        pp_v.setContentsMargins(0, 0, 0, 0)
        pp_v.setSpacing(0)
        pp_v.addWidget(self._panel_label("DETECTION PIPELINE"))
        self.pipeline_panel = PipelinePanel()
        pp_v.addWidget(self.pipeline_panel)
        bot_h.addWidget(pp_wrap, 1)

        splitter_v.addWidget(bottom)
        splitter_v.setSizes([600, 148])
        root_layout.addWidget(splitter_v, 1)

        # ── Status Bar ───────────────────────────────────────────
        sb = QStatusBar()
        sb.showMessage(
            "Pipeline running at 13 Hz  |  No SDR hardware  |  Simulation mode")
        self.setStatusBar(sb)
        self._sb = sb

    def _panel_label(self, txt):
        lbl = QLabel(f"  {txt}")
        lbl.setFixedHeight(20)
        lbl.setStyleSheet(
            f"background:{C_BG2};color:{C_DIM};font-size:9px;font-weight:600;"
            f"letter-spacing:2px;border-bottom:1px solid {C_BORDER};")
        return lbl

    # ── FEATURE 3+4: Scenario switch logs to audit trail ─────────
    def _switch(self, sc):
        self._active_scenario = sc
        self.pipeline.load_scenario(sc)

        for k, btn in self._scenario_btns.items():
            btn.setObjectName("active" if k == sc else "")
            btn.setStyle(btn.style())

        descs = {
            "idle":  "IDLE — No drones active",
            "hobby": "HOBBY — Single FlySky AFHDS drone (TGT-001)",
            "fpv":   "FPV — ExpressLRS racing drone (TGT-002)",
            "dji":   "DJI — OcuSync 2.0 commercial drone (TGT-003)",
            "swarm": "SWARM — 4 mixed-protocol drones, coordinated entry",
            "silent":"SILENT — DJI goes RF silent after 6 seconds",
        }
        self.scenario_lbl.setText("  " + descs.get(sc, sc))
        self._sb.showMessage(
            f"Scenario: {sc.upper()} loaded  |  13 Hz  |  Simulation mode")

        # Write to audit log
        try:
            from app.core.model_verifier import AuditLog
            AuditLog.log_scenario_change(sc, self._session.get("username", "system"))
        except Exception:
            pass

    # ── On Tick ──────────────────────────────────────────────────
    def _on_tick(self, state):
        gt  = state.get("global_threat", "CLEAR")
        col = THREAT_COLORS.get(gt, C_TEXT)
        self.threat_lbl.setText(f"● {gt}")
        self.threat_lbl.setStyleSheet(f"color:{col};")

        n = state.get("n_contacts", 0)
        self.cnt_lbl.setText(str(n))
        self.cnt_lbl.setStyleSheet(f"color:{C_RED};" if n > 0 else f"color:{C_BLUE};")

        self.waterfall.push_row(state.get("wf_row", [0]*512))
        self.spectrum_w.update_data(
            state.get("spectrum", [-90]*512),
            state.get("noise_floor", -90))
        self.contact_table.update_contacts(state.get("contacts", []))
        self.swarm_panel.update_swarm(state.get("swarm", {}))
        self.pipeline_panel.update_flags(state.get("pipe_flags", [False]*7))
        self.alert_log.push_alerts(state.get("alerts", []))

        any_silent = any(c.get("rf_silent") for c in state.get("contacts", []))
        self.silence_banner.show_banner(any_silent)

        self.setWindowTitle(f"Mag-Null — {n} CONTACTS — {gt}")