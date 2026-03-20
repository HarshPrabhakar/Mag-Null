# app/ui/login_dialog.py
# Mag-Null — Login Dialog
# Shows on startup before the dashboard is accessible.

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QWidget
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui  import QFont, QColor  

C_BG    = "#04070d"
C_BG1   = "#070d17"
C_BG2   = "#0a1220"
C_GREEN = "#00e5a0"
C_RED   = "#ff3355"
C_DIM   = "#4a6070"
C_TEXT  = "#c8d8e8"
C_BORDER= "#1e3040"

STYLE = f"""
QDialog, QWidget {{
    background-color: {C_BG};
    color: {C_TEXT};
    font-family: 'Segoe UI', Arial, sans-serif;
}}
QLineEdit {{
    background: {C_BG2};
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    color: {C_TEXT};
    padding: 8px 12px;
    font-size: 13px;
}}
QLineEdit:focus {{
    border-color: {C_GREEN};
}}
QPushButton#login_btn {{
    background: {C_GREEN};
    border: none;
    border-radius: 4px;
    color: {C_BG};
    padding: 10px;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 1px;
}}
QPushButton#login_btn:hover  {{ background: #00cfaa; }}
QPushButton#login_btn:pressed{{ background: #00b890; }}
QPushButton#cancel_btn {{
    background: transparent;
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    color: {C_DIM};
    padding: 10px;
    font-size: 12px;
}}
QPushButton#cancel_btn:hover {{ border-color: {C_RED}; color: {C_RED}; }}
"""


class LoginDialog(QDialog):
    def __init__(self, auth_manager, parent=None):
        super().__init__(parent)
        self.auth    = auth_manager
        self.result_data = None

        self.setWindowTitle("Mag-Null — Authentication Required")
        self.setFixedSize(400, 480)
        self.setModal(True)
        self.setStyleSheet(STYLE)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(0)

        # Logo
        logo = QLabel("MAG-NULL")
        logo.setFont(QFont("Arial Black", 22, QFont.Weight.Black))
        logo.setStyleSheet(f"color:{C_GREEN};letter-spacing:5px;")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo)

        sub = QLabel("RF DRONE DETECTION SYSTEM")
        sub.setStyleSheet(f"color:{C_DIM};font-size:9px;letter-spacing:3px;")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(sub)

        layout.addSpacing(8)

        # Divider
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"color:{C_BORDER};")
        layout.addWidget(line)

        layout.addSpacing(28)

        # Auth label
        auth_lbl = QLabel("OPERATOR AUTHENTICATION")
        auth_lbl.setStyleSheet(
            f"color:{C_DIM};font-size:9px;letter-spacing:3px;font-weight:600;")
        auth_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(auth_lbl)

        layout.addSpacing(14)

        # Username
        u_lbl = QLabel("USERNAME")
        u_lbl.setStyleSheet(
            f"color:{C_DIM};font-size:9px;letter-spacing:2px;font-weight:600;")
        layout.addWidget(u_lbl)
        layout.addSpacing(5)
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("operator")
        self.username_edit.setText("operator")
        layout.addWidget(self.username_edit)

        layout.addSpacing(16)

        # Password
        p_lbl = QLabel("PASSWORD")
        p_lbl.setStyleSheet(
            f"color:{C_DIM};font-size:9px;letter-spacing:2px;font-weight:600;")
        layout.addWidget(p_lbl)
        layout.addSpacing(5)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("••••••••••")
        self.password_edit.returnPressed.connect(self._attempt_login)
        layout.addWidget(self.password_edit)

        layout.addSpacing(8)

        # Error label
        self.error_lbl = QLabel("")
        self.error_lbl.setStyleSheet(
            f"color:{C_RED};font-size:10px;font-family:'Courier New';")
        self.error_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.error_lbl)

        layout.addSpacing(20)

        # Buttons
        btn_row = QHBoxLayout()
        cancel_btn = QPushButton("CANCEL")
        cancel_btn.setObjectName("cancel_btn")
        cancel_btn.setFixedHeight(40)
        cancel_btn.clicked.connect(self.reject)

        self.login_btn = QPushButton("AUTHENTICATE")
        self.login_btn.setObjectName("login_btn")
        self.login_btn.setFixedHeight(40)
        self.login_btn.clicked.connect(self._attempt_login)

        btn_row.addWidget(cancel_btn)
        btn_row.addSpacing(10)
        btn_row.addWidget(self.login_btn)
        layout.addLayout(btn_row)

        layout.addStretch()

        # Default credentials hint
        hint = QLabel("Default: operator / magnull2025")
        hint.setStyleSheet(
            f"color:{C_DIM};font-size:9px;font-family:'Courier New';")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(hint)

        # Focus
        self.password_edit.setFocus()

    def _attempt_login(self):
        username = self.username_edit.text().strip()
        password = self.password_edit.text()

        if not username or not password:
            self._show_error("Username and password required")
            return

        self.login_btn.setEnabled(False)
        self.login_btn.setText("AUTHENTICATING...")

        # Small delay to prevent brute-force feel
        QTimer.singleShot(400, lambda: self._do_login(username, password))

    def _do_login(self, username, password):
        result = self.auth.login(username, password)
        self.login_btn.setEnabled(True)
        self.login_btn.setText("AUTHENTICATE")

        if result["ok"]:
            self.result_data = result
            self.accept()
        else:
            self._show_error(f"✗  {result['error']}")
            self.password_edit.clear()
            self.password_edit.setFocus()

    def _show_error(self, msg):
        self.error_lbl.setText(msg)
        QTimer.singleShot(3500, lambda: self.error_lbl.setText(""))