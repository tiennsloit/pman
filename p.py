import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QComboBox, QTextEdit, QPushButton, 
                             QCheckBox, QGridLayout, QMessageBox)
from PyQt5.QtCore import Qt, QObject, pyqtSignal
import requests
import json
import urllib.parse
import threading
import logging
from datetime import datetime
import warnings
import re

class SignalEmitter(QObject):
    update_response = pyqtSignal(str)
    update_cookies = pyqtSignal(str)
    update_history = pyqtSignal(list)

class APITesterApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("API Tester")
        self.setGeometry(100, 100, 800, 600)
        self.session = requests.Session()
        self.request_in_progress = False
        self.request_history = []

        # Signal emitter for thread-safe UI updates
        self.emitter = SignalEmitter()

        # Setup logging
        logging.basicConfig(
            filename=f"api_tester_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger()

        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Grid layout for inputs
        grid_layout = QGridLayout()
        main_layout.addLayout(grid_layout)

        # Request History
        self.history_combo = QComboBox()
        self.history_combo.currentIndexChanged.connect(self.load_history)
        grid_layout.addWidget(QLabel("Request History:"), 0, 0)
        grid_layout.addWidget(self.history_combo, 0, 1)

        # API Request Section
        main_layout.addWidget(QLabel("API Request", styleSheet="font-weight: bold;"))

        # URL
        grid_layout.addWidget(QLabel("URL:"), 1, 0)
        self.url_entry = QLineEdit("https://defaulttenant.localhost.mar1.com:5001/api/account/health")
        grid_layout.addWidget(self.url_entry, 1, 1)

        # Method
        grid_layout.addWidget(QLabel("Method:"), 2, 0)
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST"])
        self.method_combo.setCurrentText("POST")
        grid_layout.addWidget(self.method_combo, 2, 1, alignment=Qt.AlignLeft)

        # Headers
        grid_layout.addWidget(QLabel("Headers (JSON):"), 3, 0)
        self.headers_text = QTextEdit()
        self.headers_text.setText('{\n  "Content-Type": "application/json"\n}')
        self.headers_text.setFixedHeight(80)
        grid_layout.addWidget(self.headers_text, 3, 1)

        # Body
        grid_layout.addWidget(QLabel("Body (JSON):"), 4, 0)
        self.body_text = QTextEdit()
        self.body_text.setText('{\n  "username": "your_username",\n  "password": "your_password"\n}')
        self.body_text.setFixedHeight(80)
        grid_layout.addWidget(self.body_text, 4, 1)

        # Proxy Section
        main_layout.addWidget(QLabel("Proxy Settings", styleSheet="font-weight: bold;"))

        # Proxy Enable Checkbox
        self.proxy_enabled = QCheckBox("Enable Proxy")
        self.proxy_enabled.setChecked(True)
        grid_layout.addWidget(self.proxy_enabled, 5, 0, 1, 2)

        # Proxy Host
        grid_layout.addWidget(QLabel("Proxy Host:"), 6, 0)
        self.proxy_host_entry = QLineEdit("your_proxy_host")
        grid_layout.addWidget(self.proxy_host_entry, 6, 1)

        # Proxy Port
        grid_layout.addWidget(QLabel("Proxy Port:"), 7, 0)
        self.proxy_port_entry = QLineEdit("your_proxy_port")
        grid_layout.addWidget(self.proxy_port_entry, 7, 1)

        # Proxy Credentials
        grid_layout.addWidget(QLabel("Proxy Username (optional):"), 8, 0)
        self.proxy_user_entry = QLineEdit()
        grid_layout.addWidget(self.proxy_user_entry, 8, 1)

        grid_layout.addWidget(QLabel("Proxy Password (optional):"), 9, 0)
        self.proxy_pass_entry = QLineEdit()
        self.proxy_pass_entry.setEchoMode(QLineEdit.Password)
        grid_layout.addWidget(self.proxy_pass_entry, 9, 1)

        # SSL Verification Checkbox
        self.ssl_verify = QCheckBox("Verify SSL Certificates")
        self.ssl_verify.setChecked(True)
        grid_layout.addWidget(self.ssl_verify, 10, 0, 1, 2)

        # Send Button and Status
        button_layout = QHBoxLayout()
        self.send_button = QPushButton("Send Request")
        self.send_button.clicked.connect(self.start_request_thread)
        button_layout.addWidget(self.send_button)
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: green;")
        button_layout.addWidget(self.status_label)
        button_layout.addStretch()
        main_layout.addLayout(button_layout)

        # Response Section
        main_layout.addWidget(QLabel("Response", styleSheet="font-weight: bold;"))
        self.response_text = QTextEdit()
        self.response_text.setReadOnly(True)
        self.response_text.setFixedHeight(100)
        main_layout.addWidget(self.response_text)

        # Cookies Section
        main_layout.addWidget(QLabel("Stored Cookies", styleSheet="font-weight: bold;"))
        self.cookies_text = QTextEdit()
        self.cookies_text.setReadOnly(True)
        self.cookies_text.setFixedHeight(80)
        main_layout.addWidget(self.cookies_text)

        main_layout.addStretch()

        # Connect signals after widgets are created
        self.emitter.update_response.connect(self.response_text.setText)
        self.emitter.update_cookies.connect(self.cookies_text.setText)
        self.emitter.update_history.connect(self.update_history_combo)

    def start_request_thread(self):
        if self.request_in_progress:
            return
        # Validate URL
        url = self.url_entry.text()
        if not re.match(r'^https?://', url):
            QMessageBox.critical(self, "Invalid Input", "URL must start with http:// or https://")
            return
        self.request_in_progress = True
        self.send_button.setEnabled(False)
        self.status_label.setText("Sending request...")
        self.status_label.setStyleSheet("color: blue;")
        threading.Thread(target=self.send_request, daemon=True).start()

    def send_request(self):
        # Suppress SSL warnings if verification is disabled
        if not self.ssl_verify.isChecked():
            warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

        # Update proxy settings
        proxies = {}
        if self.proxy_enabled.isChecked():
            proxy_host = self.proxy_host_entry.text()
            proxy_port = self.proxy_port_entry.text()
            proxy_user = self.proxy_user_entry.text()
            proxy_pass = self.proxy_pass_entry.text()

            if proxy_host and proxy_port:
                proxy_url = f"http://{proxy_host}:{proxy_port}"
                if proxy_user and proxy_pass:
                    proxy_url = f"http://{urllib.parse.quote(proxy_user)}:{urllib.parse.quote(proxy_pass)}@{proxy_host}:{proxy_port}"
                proxies = {
                    'http': proxy_url,
                    'https': proxy_url
                }
        self.session.proxies.update(proxies)

        # Get request details
        url = self.url_entry.text()
        method = self.method_combo.currentText()
        try:
            headers = json.loads(self.headers_text.toPlainText().strip())
            body = json.loads(self.body_text.toPlainText().strip()) if method == "POST" else None
        except json.JSONDecodeError as e:
            self.emitter.update_response.emit(f"Error: Invalid JSON in headers or body: {e}")
            self.logger.error(f"JSON decode error: {e}")
            self.emitter.update_response.emit("")
            self.emitter.update_cookies.emit("")
            self.reset_ui()
            return

        # Log request
        self.logger.info(f"Sending {method} request to {url} with headers {headers} and body {body}")

        # Save to history
        request_entry = {
            "url": url,
            "method": method,
            "headers": headers,
            "body": body
        }
        self.request_history.append(request_entry)
        self.emitter.update_history.emit([f"{r['method']} {r['url']}" for r in self.request_history])

        # Send request
        try:
            start_time = datetime.now()
            if method == "POST":
                response = self.session.post(url, headers=headers, json=body, verify=self.ssl_verify.isChecked())
            else:
                response = self.session.get(url, headers=headers, verify=self.ssl_verify.isChecked())
            response.raise_for_status()
            response_time = (datetime.now() - start_time).total_seconds()

            # Update UI via signals
            self.emitter.update_response.emit(f"Status: {response.status_code}\nResponse Time: {response_time:.2f} seconds\nBody:\n{response.text}")
            cookies = self.session.cookies.get_dict()
            self.emitter.update_cookies.emit(json.dumps(cookies, indent=2))
            self.logger.info(f"Request successful: {response.status_code}, {response.text[:100]}...")
        except requests.exceptions.RequestException as e:
            self.emitter.update_response.emit(f"Request failed: {e}")
            self.logger.error(f"Request failed: {e}")
        finally:
            self.reset_ui()

    def reset_ui(self):
        self.request_in_progress = False
        self.send_button.setEnabled(True)
        self.status_label.setText("Ready")
        self.status_label.setStyleSheet("color: green;")

    def update_history_combo(self, items):
        self.history_combo.clear()
        self.history_combo.addItems(items)

    def load_history(self, index):
        if index >= 0:
            request = self.request_history[index]
            self.url_entry.setText(request["url"])
            self.method_combo.setCurrentText(request["method"])
            self.headers_text.setText(json.dumps(request["headers"], indent=2))
            self.body_text.setText(json.dumps(request["body"], indent=2) if request["body"] else "")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = APITesterApp()
    window.show()
    sys.exit(app.exec_())