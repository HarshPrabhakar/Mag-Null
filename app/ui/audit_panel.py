# app/ui/audit_panel.py
# Mag-Null — Audit Log Panel
# Full-featured C2 audit trail widget shown in the dashboard.
# Displays every security + operational event in a scrollable, filterable table.

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QComboBox, QSizePolicy
)
from PyQt6.QtCore  import Qt, QTimer
from PyQt6.QtGui   import QColor, QFont

C_BG    = "#04070d"
C_BG1   = "#070d17"
C_BG2   = "#0a1220"
C_GREEN = "#00e5a0"
C_AMBER = "#f5a623"
C_RED   = "#ff3355"
C_BLUE  = "#00aaff"
C_DIM   = "#4a6070"
C_TEXT  = "#c8d8e8"
C_BORDER= "#1e3040"

# Event → colour mapping
EVENT_COLORS = {
    "AUTH_LOGIN_OK":        C_GREEN,
    "AUTH_LOGIN_FAIL":      C_RED,
    "AUTH_LOGOUT":          C_AMBER,
    "SCENARIO_CHANGE":      C_BLUE,
    "MODEL_SIGNED":         C_GREEN,
    "MODEL_VERIFY_OK":      C_GREEN,
    "MODEL_VERIFY_FAIL":    C_RED,
    "SESSION_START":        C_GREEN,
    "SESSION_END":          C_DIM,
    "ALERT_GENERATED":      C_AMBER,
    "RF_SILENCE_DETECTED":  C_RED,
    "SWARM_DETECTED":       C_RED,
}

SEVERITY_MAP = {
    "CRITICAL": C_RED,
    "WARNING":  C_AMBER,
    "INFO":     C_DIM,
}

COLS = ["TIMESTAMP", "EVENT", "SEVERITY", "DETAILS"]


class AuditPanel(QWidget):
    """
    Reads from AuditLog.read_recent() and displays in a table.
    Auto-refreshes every 2 seconds.
    Filterable by event type.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._shown_ids = set()    # track which entries are displayed
        self._filter    = "ALL"
        self._build()

        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self.refresh)
        self._refresh_timer.start(2000)

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Header bar ────────────────────────────────────────────
        hdr_bar = QWidget()
        hdr_bar.setFixedHeight(32)
        hdr_bar.setStyleSheet(
            f"background:{C_BG2};border-bottom:1px solid {C_BORDER};")
        hdr_h = QHBoxLayout(hdr_bar)
        hdr_h.setContentsMargins(10, 0, 10, 0)

        title = QLabel("AUDIT LOG  ·  C2 OPERATIONS")
        title.setStyleSheet(
            f"color:{C_DIM};font-size:9px;font-weight:600;letter-spacing:2px;")

        # Filter dropdown
        self.filter_box = QComboBox()
        self.filter_box.addItems(["ALL", "AUTH", "MODEL", "ALERTS", "RF", "CRITICAL"])
        self.filter_box.setFixedWidth(110)
        self.filter_box.setFixedHeight(20)
        self.filter_box.setStyleSheet(
            f"background:{C_BG};border:1px solid {C_BORDER};"
            f"color:{C_TEXT};font-size:9px;padding:1px 4px;")
        self.filter_box.currentTextChanged.connect(self._on_filter)

        # Clear button
        clear_btn = QPushButton("CLEAR")
        clear_btn.setFixedSize(55, 20)
        clear_btn.setStyleSheet(
            f"background:transparent;border:1px solid {C_BORDER};"
            f"color:{C_DIM};font-size:8px;letter-spacing:1px;")
        clear_btn.clicked.connect(self._clear)

        # Export button
        export_btn = QPushButton("EXPORT")
        export_btn.setFixedSize(60, 20)
        export_btn.setStyleSheet(
            f"background:transparent;border:1px solid {C_BORDER};"
            f"color:{C_DIM};font-size:8px;letter-spacing:1px;")
        export_btn.clicked.connect(self._export)

        hdr_h.addWidget(title)
        hdr_h.addStretch()
        hdr_h.addWidget(QLabel("FILTER:").setStyleSheet(
            f"color:{C_DIM};font-size:9px;") or QLabel("FILTER:"))
        hdr_h.addWidget(self.filter_box)
        hdr_h.addSpacing(6)
        hdr_h.addWidget(clear_btn)
        hdr_h.addSpacing(4)
        hdr_h.addWidget(export_btn)
        layout.addWidget(hdr_bar)

        # ── Table ─────────────────────────────────────────────────
        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.setStyleSheet(
            f"QTableWidget {{"
            f"  background:{C_BG}; border:none;"
            f"  gridline-color:{C_BORDER}; color:{C_TEXT}; font-size:10px;"
            f"}}"
            f"QTableWidget::item {{ padding:3px 8px; border-bottom:1px solid {C_BORDER}; }}"
            f"QHeaderView::section {{"
            f"  background:{C_BG2}; color:{C_DIM}; border:none;"
            f"  border-bottom:1px solid {C_BORDER}; padding:4px 8px;"
            f"  font-size:9px; letter-spacing:1px; font-weight:600;"
            f"}}"
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(False)
        self.table.setShowGrid(False)

        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed);   self.table.setColumnWidth(0, 155)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed);   self.table.setColumnWidth(1, 175)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed);   self.table.setColumnWidth(2, 80)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self.table)

        # ── Status strip ──────────────────────────────────────────
        self.status_lbl = QLabel("  Ready")
        self.status_lbl.setFixedHeight(18)
        self.status_lbl.setStyleSheet(
            f"color:{C_DIM};font-size:8px;font-family:'Courier New';"
            f"background:{C_BG1};border-top:1px solid {C_BORDER};padding:0 8px;")
        layout.addWidget(self.status_lbl)

    def refresh(self):
        """Pull latest entries from disk and add new rows."""
        try:
            from app.core.model_verifier import AuditLog
            entries = AuditLog.read_recent(200)
        except Exception:
            return

        new_count = 0
        for entry in entries:
            uid = f"{entry.get('ts',0):.3f}_{entry.get('event','')}"
            if uid in self._shown_ids:
                continue

            event = entry.get("event", "UNKNOWN")
            if not self._passes_filter(event):
                self._shown_ids.add(uid)
                continue

            self._shown_ids.add(uid)
            self._add_row(entry, event)
            new_count += 1

        if new_count > 0:
            self.table.scrollToBottom()
            total = self.table.rowCount()
            self.status_lbl.setText(
                f"  {total} entries  ·  {new_count} new  ·  "
                f"filter: {self._filter}")

        # Trim to 500 rows max
        while self.table.rowCount() > 500:
            self.table.removeRow(0)

    def _add_row(self, entry: dict, event: str):
        r   = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setRowHeight(r, 22)

        ts_str   = entry.get("ts_iso", "")
        severity = entry.get("severity", self._infer_severity(event))
        details  = self._format_details(entry)

        ecol  = EVENT_COLORS.get(event, C_TEXT)
        scol  = SEVERITY_MAP.get(severity, C_DIM)

        def cell(txt, col=C_TEXT, bold=False, mono=False):
            item = QTableWidgetItem(str(txt))
            item.setForeground(QColor(col))
            f = item.font()
            if bold:  f.setBold(True)
            if mono:  f.setFamily("Courier New"); f.setPointSize(9)
            item.setFont(f)
            return item

        self.table.setItem(r, 0, cell(ts_str,  C_DIM,  mono=True))
        self.table.setItem(r, 1, cell(event,   ecol,   bold=True))
        self.table.setItem(r, 2, cell(severity, scol,  bold=(severity=="CRITICAL")))
        self.table.setItem(r, 3, cell(details,  C_TEXT))

    def _format_details(self, entry: dict) -> str:
        skip  = {"ts", "ts_iso", "event", "severity"}
        parts = []
        for k, v in entry.items():
            if k not in skip:
                parts.append(f"{k}={v}")
        return "  ·  ".join(parts)

    def _infer_severity(self, event: str) -> str:
        if "FAIL" in event or "SILENCE" in event or "SWARM" in event:
            return "CRITICAL"
        if "WARN" in event or "LOGOUT" in event:
            return "WARNING"
        return "INFO"

    def _passes_filter(self, event: str) -> bool:
        f = self._filter
        if f == "ALL":      return True
        if f == "AUTH":     return "AUTH" in event
        if f == "MODEL":    return "MODEL" in event
        if f == "ALERTS":   return "ALERT" in event
        if f == "RF":       return "RF" in event or "SWARM" in event
        if f == "CRITICAL": return self._infer_severity(event) == "CRITICAL"
        return True

    def _on_filter(self, value: str):
        self._filter    = value
        self._shown_ids = set()
        self.table.setRowCount(0)
        self.refresh()

    def _clear(self):
        self.table.setRowCount(0)
        self._shown_ids = set()
        self.status_lbl.setText("  Cleared")

    def _export(self):
        """Export current view to CSV."""
        from pathlib import Path
        import time as _time

        out_path = Path.home() / f"magnull_audit_{int(_time.time())}.csv"
        with open(out_path, "w") as f:
            f.write(",".join(COLS) + "\n")
            for r in range(self.table.rowCount()):
                row = []
                for c in range(len(COLS)):
                    item = self.table.item(r, c)
                    val  = item.text() if item else ""
                    row.append(f'"{val}"')
                f.write(",".join(row) + "\n")

        self.status_lbl.setText(f"  Exported → {out_path.name}")