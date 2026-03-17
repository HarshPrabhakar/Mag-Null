# main.py
# Mag-Null — Entry Point
# Team Dimensioners

import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore    import QObject, pyqtSignal

from app.core.pipeline    import Pipeline
from app.ui.main_window   import MainWindow


class Bridge(QObject):
    tick = pyqtSignal(dict)

bridge = Bridge()

def _on_pipeline_tick(state):
    bridge.tick.emit(state)

if __name__ == "__main__":
    app      = QApplication(sys.argv)
    pipeline = Pipeline()
    pipeline.on_tick(_on_pipeline_tick)
    pipeline.start()

    window = MainWindow(pipeline, bridge)
    window.show()

    sys.exit(app.exec())