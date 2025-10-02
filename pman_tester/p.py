import sys
import os
import json
import re
import threading
import logging
import requests
import urllib.parse
from datetime import datetime
import warnings
from fnmatch import fnmatch
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QComboBox, QTextEdit, QPushButton, 
                             QCheckBox, QGridLayout, QMessageBox, QSplitter)
from PyQt5.QtCore import Qt, QObject, pyqtSignal

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
        self.session.trust_env = False  # Ignore HTTP_PROXY and HTTPS_PROXY environment variables
        self.request_in_progress = False
        self.request_history = []
        self.test_cookie_url = "https://defaulttenant.localhost.mar1.com:5001/api/account/user"  # Default test endpoint

        # Signal emitter for thread-safe UI updates
        self.emitter = SignalEmitter()

        # Setup logging
        logging.basicConfig(
            filename=f"api_tester_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            level=logging.DEBUG,  # Set to DEBUG for cookie troubleshooting
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger()
        self.logger.info("Initialized requests session with trust_env=False to ignore HTTP_PROXY and HTTPS_PROXY")

        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout()
        main_widget.setLayout(main_layout)

        # Left-side menu
        menu_widget = QWidget()
        menu_layout = QVBoxLayout()
        menu_widget.setLayout(menu_layout)
        menu_widget.setFixedWidth(150)

        # Request History Label and ComboBox
        menu_layout.addWidget(QLabel("Request History", styleSheet="font-weight: bold;"))
        self.history_combo = QComboBox()
        self.history_combo.currentIndexChanged.connect(self.load_history)
        menu_layout.addWidget(self.history_combo)

        # New Request Button
        self.new_button = QPushButton("+ New Request")
        self.new_button.clicked.connect(self.new_request)
        menu_layout.addWidget(self.new_button)

        # Duplicate and Delete Buttons
        self.duplicate_button = QPushButton("Duplicate Request")
        self.duplicate_button.clicked.connect(self.duplicate_request)
        menu_layout.addWidget(self.duplicate_button)

        self.delete_button = QPushButton("Delete Request")
        self.delete_button.clicked.connect(self.delete_request)
        menu_layout.addWidget(self.delete_button)

        # Clear Cookies Button
        self.clear_cookies_button = QPushButton("Clear Cookies")
        self.clear_cookies_button.clicked.connect(self.clear_cookies)
        menu_layout.addWidget(self.clear_cookies_button)

        # Save Cookies Button
        self.save_cookies_button = QPushButton("Save Cookies")
        self.save_cookies_button.clicked.connect(self.save_cookies)
        menu_layout.addWidget(self.save_cookies_button)

        # Test Cookie Button
        self.test_cookie_button = QPushButton("Test Cookie")
        self.test_cookie_button.clicked.connect(self.test_cookie)
        menu_layout.addWidget(self.test_cookie_button)

        # Set Cookies Button
        self.set_cookies_button = QPushButton("Set Cookies")
        self.set_cookies_button.clicked.connect(self.set_cookies)
        menu_layout.addWidget(self.set_cookies_button)

        menu_layout.addStretch()

        # Right-side input/output area
        content_widget = QWidget()
        content_layout = QVBoxLayout()
        content_widget.setLayout(content_layout)

        # Splitter for resizable layout
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(menu_widget)
        splitter.addWidget(content_widget)
        splitter.setSizes([150, 650])
        main_layout.addWidget(splitter)

        # Grid layout for inputs
        grid_layout = QGridLayout()
        content_layout.addLayout(grid_layout)

        # API Request Section
        content_layout.addWidget(QLabel("API Request", styleSheet="font-weight: bold;"))

        # URL
        grid_layout.addWidget(QLabel("URL:"), 0, 0)
        self.url_entry = QLineEdit()  # Empty by default
        grid_layout.addWidget(self.url_entry, 0, 1)

        # Method
        grid_layout.addWidget(QLabel("Method:"), 1, 0)
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH"])
        self.method_combo.setCurrentText("GET")  # Default to GET
        grid_layout.addWidget(self.method_combo, 1, 1, alignment=Qt.AlignLeft)

        # Headers
        grid_layout.addWidget(QLabel("Headers (JSON):"), 2, 0)
        self.headers_text = QTextEdit()  # Empty by default
        self.headers_text.setFixedHeight(80)
        grid_layout.addWidget(self.headers_text, 2, 1)

        # Body
        grid_layout.addWidget(QLabel("Body (JSON):"), 3, 0)
        self.body_text = QTextEdit()  # Empty by default
        self.body_text.setFixedHeight(80)
        grid_layout.addWidget(self.body_text, 3, 1)

        # Proxy Section
        content_layout.addWidget(QLabel("Proxy Settings", styleSheet="font-weight: bold;"))

        # Proxy Enable Checkbox
        self.proxy_enabled = QCheckBox("Enable Proxy")
        self.proxy_enabled.setChecked(False)  # Default disabled
        self.proxy_enabled.stateChanged.connect(self.save_settings)
        grid_layout.addWidget(self.proxy_enabled, 4, 0, 1, 2)

        # Proxy Host
        grid_layout.addWidget(QLabel("Proxy Host:"), 5, 0)
        self.proxy_host_entry = QLineEdit()
        self.proxy_host_entry.textChanged.connect(self.save_settings)
        grid_layout.addWidget(self.proxy_host_entry, 5, 1)

        # Proxy Port
        grid_layout.addWidget(QLabel("Proxy Port:"), 6, 0)
        self.proxy_port_entry = QLineEdit()
        self.proxy_port_entry.textChanged.connect(self.save_settings)
        grid_layout.addWidget(self.proxy_port_entry, 6, 1)

        # Proxy Credentials
        grid_layout.addWidget(QLabel("Proxy Username (optional):"), 7, 0)
        self.proxy_user_entry = QLineEdit()
        self.proxy_user_entry.textChanged.connect(self.save_settings)
        grid_layout.addWidget(self.proxy_user_entry, 7, 1)

        grid_layout.addWidget(QLabel("Proxy Password (optional):"), 8, 0)
        self.proxy_pass_entry = QLineEdit()
        self.proxy_pass_entry.setEchoMode(QLineEdit.Password)
        self.proxy_pass_entry.textChanged.connect(self.save_settings)
        grid_layout.addWidget(self.proxy_pass_entry, 8, 1)

        # Proxy Exceptions
        grid_layout.addWidget(QLabel("Proxy Exceptions (comma-separated, e.g., *localhost*,*.website1.com*):"), 9, 0)
        self.proxy_exceptions_entry = QLineEdit()
        self.proxy_exceptions_entry.setPlaceholderText("*localhost*,*.website1.com*")
        self.proxy_exceptions_entry.textChanged.connect(self.save_settings)
        grid_layout.addWidget(self.proxy_exceptions_entry, 9, 1)

        # SSL Verification Checkbox
        self.ssl_verify = QCheckBox("Verify SSL Certificates")
        self.ssl_verify.setChecked(True)  # Default enabled
        self.ssl_verify.stateChanged.connect(self.save_settings)
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
        content_layout.addLayout(button_layout)

        # Response Section
        content_layout.addWidget(QLabel("Response", styleSheet="font-weight: bold;"))
        self.response_text = QTextEdit()
        self.response_text.setReadOnly(False)  # Allow editing for manual input
        self.response_text.setFixedHeight(100)
        content_layout.addWidget(self.response_text)

        # Cookies Section
        content_layout.addWidget(QLabel("Stored Cookies (Editable JSON):", styleSheet="font-weight: bold;"))
        self.cookies_text = QTextEdit()
        self.cookies_text.setReadOnly(False)  # Allow editing for manual cookie input
        self.cookies_text.setFixedHeight(80)
        content_layout.addWidget(self.cookies_text)

        content_layout.addStretch()

        # Connect signals after widgets are created
        self.emitter.update_response.connect(self.update_response_text)
        self.emitter.update_cookies.connect(self.cookies_text.setText)
        self.emitter.update_history.connect(self.update_history_combo)

        # Load history and settings
        self.load_history_file()
        self.load_settings()

    def update_response_text(self, text):
        self.logger.debug(f"Updating response text area with: {text[:100]}...")
        self.response_text.clear()
        self.response_text.setText(text)

    def save_settings(self):
        settings = {
            "proxy_enabled": self.proxy_enabled.isChecked(),
            "proxy_host": self.proxy_host_entry.text(),
            "proxy_port": self.proxy_port_entry.text(),
            "proxy_user": self.proxy_user_entry.text(),
            "proxy_pass": self.proxy_pass_entry.text(),
            "proxy_exceptions": self.proxy_exceptions_entry.text(),
            "ssl_verify": self.ssl_verify.isChecked()
        }
        try:
            with open("settings.json", "w") as f:
                json.dump(settings, f, indent=2)
            self.logger.debug("Saved settings to settings.json")
        except Exception as e:
            self.logger.error(f"Failed to save settings: {e}")

    def load_settings(self):
        if os.path.exists("settings.json"):
            try:
                with open("settings.json") as f:
                    settings = json.load(f)
                self.proxy_enabled.setChecked(settings.get("proxy_enabled", False))
                self.proxy_host_entry.setText(settings.get("proxy_host", ""))
                self.proxy_port_entry.setText(settings.get("proxy_port", ""))
                self.proxy_user_entry.setText(settings.get("proxy_user", ""))
                self.proxy_pass_entry.setText(settings.get("proxy_pass", ""))
                self.proxy_exceptions_entry.setText(settings.get("proxy_exceptions", "*localhost*,*.website1.com*"))
                self.ssl_verify.setChecked(settings.get("ssl_verify", True))
                self.logger.debug("Loaded settings from settings.json")
            except Exception as e:
                self.logger.error(f"Failed to load settings: {e}")

    def save_history(self):
        try:
            with open("history.json", "w") as f:
                json.dump(self.request_history, f, indent=2)
            self.logger.debug("Saved request history to history.json")
        except Exception as e:
            self.logger.error(f"Failed to save history: {e}")

    def load_history_file(self):
        if os.path.exists("history.json"):
            try:
                with open("history.json") as f:
                    self.request_history = json.load(f)
                self.update_history_combo([r.get("name", f"{r['method']} {r['url']}") for r in self.request_history])
                self.logger.debug("Loaded request history from history.json")
                self.emitter.update_cookies.emit(json.dumps(self.session.cookies.get_dict(), indent=2))
            except Exception as e:
                self.logger.error(f"Failed to load history: {e}")

    def new_request(self):
        new_request = {
            "name": "New Request",
            "url": "",
            "method": "GET",
            "headers": {},
            "body": None
        }
        self.request_history.append(new_request)
        self.emitter.update_history.emit([r.get("name", f"{r['method']} {r['url']}") for r in self.request_history])
        self.history_combo.setCurrentIndex(len(self.request_history) - 1)
        self.url_entry.clear()
        self.method_combo.setCurrentText("GET")
        self.headers_text.clear()
        self.body_text.clear()
        self.save_history()
        self.logger.debug("Created new request")
        self.emitter.update_cookies.emit(json.dumps(self.session.cookies.get_dict(), indent=2))

    def duplicate_request(self):
        index = self.history_combo.currentIndex()
        if index >= 0:
            request = self.request_history[index]
            new_request = {
                "name": f"Copy of {request.get('name', request['method'] + ' ' + request['url'])}",
                "url": request["url"],
                "method": request["method"],
                "headers": request["headers"].copy(),
                "body": request["body"].copy() if request["body"] else None
            }
            self.request_history.append(new_request)
            self.emitter.update_history.emit([r.get("name", f"{r['method']} {r['url']}") for r in self.request_history])
            self.history_combo.setCurrentIndex(len(self.request_history) - 1)
            self.save_history()
            self.logger.debug(f"Duplicated request: {new_request['name']}")
            self.emitter.update_cookies.emit(json.dumps(self.session.cookies.get_dict(), indent=2))

    def delete_request(self):
        index = self.history_combo.currentIndex()
        if index >= 0:
            reply = QMessageBox.question(self, "Delete Request", 
                                       f"Are you sure you want to delete {self.history_combo.currentText()}?",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                deleted_request = self.request_history.pop(index)
                self.emitter.update_history.emit([r.get("name", f"{r['method']} {r['url']}") for r in self.request_history])
                self.save_history()
                self.logger.debug(f"Deleted request: {deleted_request.get('name', deleted_request['method'] + ' ' + deleted_request['url'])}")
                if not self.request_history:
                    self.url_entry.clear()
                    self.method_combo.setCurrentText("GET")
                    self.headers_text.clear()
                    self.body_text.clear()
                self.emitter.update_cookies.emit(json.dumps(self.session.cookies.get_dict(), indent=2))

    def clear_cookies(self):
        self.session.cookies.clear()
        self.emitter.update_cookies.emit("")
        self.logger.debug("Cleared session cookies")

    def save_cookies(self):
        self.emitter.update_cookies.emit(json.dumps(self.session.cookies.get_dict(), indent=2))
        self.logger.debug("Manually saved cookies (display updated)")

    def set_cookies(self):
        try:
            cookies_text = self.cookies_text.toPlainText().strip()
            if not cookies_text:
                QMessageBox.warning(self, "No Cookies", "No cookies provided to set")
                self.logger.warning("No cookies provided in Stored Cookies text area")
                return
            cookies_dict = json.loads(cookies_text)
            if not isinstance(cookies_dict, dict):
                raise ValueError("Cookies must be a JSON object")
            
            url = self.url_entry.text() or self.test_cookie_url
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.hostname if parsed_url.hostname else "defaulttenant.localhost.mar1.com"
            path = parsed_url.path or "/"
            
            self.session.cookies.clear()
            for key, value in cookies_dict.items():
                self.session.cookies.set(
                    name=key,
                    value=value,
                    domain=domain,
                    path=path,
                    secure=True,  # Ensure cookies are marked Secure for HTTPS
                    samesite='None'  # Set SameSite=None for cross-origin compatibility
                )
            self.emitter.update_cookies.emit(json.dumps(self.session.cookies.get_dict(), indent=2))
            self.logger.debug(f"Set cookies: {str(cookies_dict)} for domain={domain}, path={path}, secure=True, samesite=None")
            QMessageBox.information(self, "Success", "Cookies set successfully")
        except (json.JSONDecodeError, ValueError) as e:
            self.logger.error(f"Failed to set cookies: {e}")
            QMessageBox.critical(self, "Error", f"Failed to set cookies: Invalid JSON or format ({e})")

    def test_cookie(self):
        if self.request_in_progress:
            return
        cookies = self.session.cookies.get_dict()
        if not cookies:
            QMessageBox.critical(self, "No Cookies", "No cookies available to test")
            self.logger.warning("No cookies available for testing")
            return
        self.request_in_progress = True
        self.send_button.setEnabled(False)
        self.test_cookie_button.setEnabled(False)
        self.set_cookies_button.setEnabled(False)
        self.status_label.setText("Testing cookie...")
        self.status_label.setStyleSheet("color: blue;")
        self.emitter.update_cookies.emit(json.dumps(cookies, indent=2))
        threading.Thread(target=self.test_cookie_request, daemon=True).start()

    def test_cookie_request(self):
        if not self.ssl_verify.isChecked():
            warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

        url = self.test_cookie_url
        cookies = self.session.cookies.get_dict()
        if not cookies:
            self.logger.warning(f"No cookies available for test request to {url}")
            self.emitter.update_response.emit("Cookie test failed: No cookies available")
            self.reset_ui()
            return

        # Check proxy exceptions
        proxies = self.get_proxies(url)

        # Log cookies being sent
        cookie_jar = self.session.cookies
        cookie_details = [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path, "secure": c.secure, "samesite": c.get_nonstandard_attr('samesite')} for c in cookie_jar]
        self.logger.debug(f"Sending cookies to {url}: {json.dumps(cookie_details, indent=2)}")

        self.logger.info(f"Testing cookie with GET request to {url}, cookies: {str(cookies)}, proxies: {proxies}")

        try:
            response = self.session.get(url, headers={}, verify=self.ssl_verify.isChecked(), proxies=proxies)
            response.raise_for_status()
            response_text = f"Cookie Test Status: {response.status_code}\nBody:\n{response.text}"
            self.logger.info(f"Cookie test successful: Status {response.status_code}, headers: {json.dumps(dict(response.headers), indent=2)}")
            self.emitter.update_response.emit(response_text)
        except requests.exceptions.RequestException as e:
            response_text = f"Cookie test failed: {e}"
            self.logger.error(f"Cookie test failed: {e}")
            self.emitter.update_response.emit(response_text)
        finally:
            self.reset_ui()

    def start_request_thread(self):
        if self.request_in_progress:
            return
        url = self.url_entry.text()
        if not url:
            QMessageBox.critical(self, "Invalid Input", "URL cannot be empty")
            return
        if not re.match(r'^https?://', url):
            QMessageBox.critical(self, "Invalid Input", "URL must start with http:// or https://")
            return
        self.request_in_progress = True
        self.send_button.setEnabled(False)
        self.test_cookie_button.setEnabled(False)
        self.set_cookies_button.setEnabled(False)
        self.status_label.setText("Sending request...")
        self.status_label.setStyleSheet("color: blue;")
        self.emitter.update_cookies.emit(json.dumps(self.session.cookies.get_dict(), indent=2))
        threading.Thread(target=self.send_request, daemon=True).start()

    def get_proxies(self, url):
        """Determine if proxy should be used based on exceptions."""
        if not self.proxy_enabled.isChecked():
            self.logger.info("Proxy disabled; no proxy used")
            return {}
        
        # Parse URL to extract hostname
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname

        # Check proxy exceptions
        exceptions = self.proxy_exceptions_entry.text().strip()
        if exceptions:
            exception_list = [e.strip() for e in exceptions.split(",") if e.strip()]
            for pattern in exception_list:
                if fnmatch(hostname, pattern):
                    self.logger.info(f"URL {url} matches proxy exception {pattern}; bypassing proxy")
                    return {}
        
        # Configure proxy if no exceptions match
        proxy_host = self.proxy_host_entry.text()
        proxy_port = self.proxy_port_entry.text()
        proxy_user = self.proxy_user_entry.text()
        proxy_pass = self.proxy_pass_entry.text()

        if proxy_host and proxy_port:
            try:
                int(proxy_port)  # Validate port
            except ValueError:
                self.logger.error("Proxy port must be a number")
                return {}
            proxy_url = f"http://{proxy_host}:{proxy_port}"
            if proxy_user and proxy_pass:
                proxy_url = f"http://{urllib.parse.quote(proxy_user)}:{urllib.parse.quote(proxy_pass)}@{proxy_host}:{proxy_port}"
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            self.logger.info(f"Using proxy: {proxies}")
            return proxies
        else:
            self.logger.warning("Proxy enabled but host or port missing; no proxy used")
            return {}

    def send_request(self):
        if not self.ssl_verify.isChecked():
            warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

        url = self.url_entry.text()
        method = self.method_combo.currentText()
        try:
            headers_text = self.headers_text.toPlainText().strip()
            headers = json.loads(headers_text) if headers_text else {}
            body_text = self.body_text.toPlainText().strip()
            body = json.loads(body_text) if body_text and method in ["POST", "PUT", "PATCH"] else None
        except json.JSONDecodeError as e:
            response_text = f"Error: Invalid JSON in headers or body: {e}"
            self.emitter.update_response.emit(response_text)
            self.logger.error(f"JSON decode error: {e}")
            self.reset_ui()
            return

        # Get proxies based on URL and exceptions
        proxies = self.get_proxies(url)

        # Log cookies being sent
        cookies = self.session.cookies.get_dict()
        if cookies:
            cookie_jar = self.session.cookies
            cookie_details = [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path, "secure": c.secure, "samesite": c.get_nonstandard_attr('samesite')} for c in cookie_jar]
            self.logger.debug(f"Sending cookies to {url}: {json.dumps(cookie_details, indent=2)}")
        else:
            self.logger.warning(f"No cookies available for request to {url}")

        self.logger.info(f"Sending {method} request to {url} with headers {headers}, body {body}, cookies: {str(cookies)}, proxies: {proxies}")

        current_index = self.history_combo.currentIndex()
        if current_index >= 0:
            self.request_history[current_index] = {
                "name": f"{method} {url}",
                "url": url,
                "method": method,
                "headers": headers,
                "body": body
            }
        else:
            request_entry = {
                "name": f"{method} {url}",
                "url": url,
                "method": method,
                "headers": headers,
                "body": body
            }
            self.request_history.append(request_entry)

        self.emitter.update_history.emit([r.get("name", f"{r['method']} {r['url']}") for r in self.request_history])
        self.save_history()

        try:
            start_time = datetime.now()
            if method == "POST":
                response = self.session.post(url, headers=headers, json=body, verify=self.ssl_verify.isChecked(), proxies=proxies)
            elif method == "PUT":
                response = self.session.put(url, headers=headers, json=body, verify=self.ssl_verify.isChecked(), proxies=proxies)
            elif method == "DELETE":
                response = self.session.delete(url, headers=headers, json=body, verify=self.ssl_verify.isChecked(), proxies=proxies)
            elif method == "PATCH":
                response = self.session.patch(url, headers=headers, json=body, verify=self.ssl_verify.isChecked(), proxies=proxies)
            else:
                response = self.session.get(url, headers=headers, verify=self.ssl_verify.isChecked(), proxies=proxies)
            response.raise_for_status()
            response_time = (datetime.now() - start_time).total_seconds()

            self.logger.info(f"Response status: {response.status_code}, headers: {json.dumps(dict(response.headers), indent=2)}")
            response_text = f"Status: {response.status_code}\nResponse Time: {response_time:.2f} seconds\nBody:\n{response.text}"
            self.emitter.update_response.emit(response_text)
            cookies = self.session.cookies.get_dict()
            self.emitter.update_cookies.emit(json.dumps(cookies, indent=2))
            self.logger.info(f"Request successful: {response.status_code}, Response: {response.text[:100]}...")
        except requests.exceptions.RequestException as e:
            response_text = f"Request failed: {e}"
            self.emitter.update_response.emit(response_text)
            self.logger.error(f"Request failed: {e}")
        finally:
            self.reset_ui()

    def reset_ui(self):
        self.request_in_progress = False
        self.send_button.setEnabled(True)
        self.test_cookie_button.setEnabled(True)
        self.set_cookies_button.setEnabled(True)
        self.status_label.setText("Ready")
        self.status_label.setStyleSheet("color: green;")

    def update_history_combo(self, items):
        current_index = self.history_combo.currentIndex()
        self.history_combo.clear()
        self.history_combo.addItems(items)
        if current_index >= 0 and current_index < len(items):
            self.history_combo.setCurrentIndex(current_index)

    def load_history(self, index):
        if index >= 0:
            request = self.request_history[index]
            self.url_entry.setText(request["url"])
            self.method_combo.setCurrentText(request["method"])
            self.headers_text.setText(json.dumps(request["headers"], indent=2) if request["headers"] else "")
            self.body_text.setText(json.dumps(request["body"], indent=2) if request["body"] else "")
            self.emitter.update_cookies.emit(json.dumps(self.session.cookies.get_dict(), indent=2))

def main():
    app = QApplication(sys.argv)
    window = APITesterApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()