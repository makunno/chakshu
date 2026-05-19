"""Cyber Chakshu SIEM Browser - Embedded webview to online frontend"""

import sys

from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout
from PySide6.QtCore import QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView


class Cyber ChakshuBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Chakshu SIEM")
        self.setGeometry(100, 100, 1400, 900)

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        self.webview = QWebEngineView()
        self.webview.setUrl(QUrl("https://freekhana-frontend.pages.dev"))

        layout.addWidget(self.webview)
        self.statusBar().showMessage("Loading Cyber Chakshu SIEM...")

        self.webview.loadFinished.connect(
            lambda _: self.statusBar().showMessage("Connected to Cyber Chakshu SIEM")
        )


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Cyber Chakshu SIEM")
    app.setApplicationVersion("2.0.0")

    window = Cyber ChakshuBrowser()
    window.show()

    return app.exec()


if __name__ == '__main__':
    sys.exit(main())
