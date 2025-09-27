import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import json
import urllib.parse
import threading
import logging
from datetime import datetime
import os

class APITesterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("API Tester")
        self.session = requests.Session()  # Persist cookies across requests
        self.request_in_progress = False  # Prevent multiple simultaneous requests
        self.request_history = []  # Store request history

        # Setup logging
        logging.basicConfig(
            filename=f"api_tester_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger()

        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Request History Dropdown
        ttk.Label(main_frame, text="Request History:").grid(row=0, column=0, sticky=tk.W)
        self.history_combo = ttk.Combobox(main_frame, state="readonly", width=50)
        self.history_combo.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.history_combo.bind("<<ComboboxSelected>>", self.load_history)

        # API Request Section
        ttk.Label(main_frame, text="API Request").grid(row=1, column=0, columnspan=2, sticky=tk.W)
        
        # URL
        ttk.Label(main_frame, text="URL:", font=("Arial", 10)).grid(row=2, column=0, sticky=tk.W)
        self.url_entry = ttk.Entry(main_frame, width=50)
        self.url_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))
        self.url_entry.insert(0, "https://defaulttenant.localhost.mar1.com:5001/api/account/health")

        # Method
        ttk.Label(main_frame, text="Method:").grid(row=3, column=0, sticky=tk.W)
        self.method_combo = ttk.Combobox(main_frame, values=["GET", "POST"], state="readonly", width=10)
        self.method_combo.grid(row=3, column=1, sticky=tk.W)
        self.method_combo.set("POST")

        # Headers
        ttk.Label(main_frame, text="Headers (JSON):").grid(row=4, column=0, sticky=tk.W)
        self.headers_text = scrolledtext.ScrolledText(main_frame, width=50, height=5)
        self.headers_text.grid(row=4, column=1, sticky=(tk.W, tk.E))
        self.headers_text.insert(tk.END, '{\n  "Content-Type": "application/json"\n}')

        # Body
        ttk.Label(main_frame, text="Body (JSON):").grid(row=5, column=0, sticky=tk.W)
        self.body_text = scrolledtext.ScrolledText(main_frame, width=50, height=5)
        self.body_text.grid(row=5, column=1, sticky=(tk.W, tk.E))
        self.body_text.insert(tk.END, '{\n  "username": "your_username",\n  "password": "your_password"\n}')

        # Proxy Section
        ttk.Label(main_frame, text="Proxy Settings").grid(row=6, column=0, columnspan=2, sticky=tk.W)
        
        # Proxy Enable Checkbox
        self.proxy_enabled = tk.BooleanVar(value=True)
        self.proxy_checkbox = ttk.Checkbutton(
            main_frame, text="Enable Proxy", variable=self.proxy_enabled
        )
        self.proxy_checkbox.grid(row=7, column=0, columnspan=2, sticky=tk.W)

        # Proxy Host
        ttk.Label(main_frame, text="Proxy Host:").grid(row=8, column=0, sticky=tk.W)
        self.proxy_host_entry = ttk.Entry(main_frame, width=50)
        self.proxy_host_entry.grid(row=8, column=1, sticky=(tk.W, tk.E))
        self.proxy_host_entry.insert(0, "your_proxy_host")

        # Proxy Port
        ttk.Label(main_frame, text="Proxy Port:").grid(row=9, column=0, sticky=tk.W)
        self.proxy_port_entry = ttk.Entry(main_frame, width=50)
        self.proxy_port_entry.grid(row=9, column=1, sticky=(tk.W, tk.E))
        self.proxy_port_entry.insert(0, "your_proxy_port")

        # Proxy Credentials
        ttk.Label(main_frame, text="Proxy Username (optional):").grid(row=10, column=0, sticky=tk.W)
        self.proxy_user_entry = ttk.Entry(main_frame, width=50)
        self.proxy_user_entry.grid(row=10, column=1, sticky=(tk.W, tk.E))

        ttk.Label(main_frame, text="Proxy Password (optional):").grid(row=11, column=0, sticky=tk.W)
        self.proxy_pass_entry = ttk.Entry(main_frame, width=50, show="*")
        self.proxy_pass_entry.grid(row=11, column=1, sticky=(tk.W, tk.E))

        # SSL Verification Checkbox
        self.ssl_verify = tk.BooleanVar(value=True)
        self.ssl_checkbox = ttk.Checkbutton(
            main_frame, text="Verify SSL Certificates", variable=self.ssl_verify
        )
        self.ssl_checkbox.grid(row=12, column=0, columnspan=2, sticky=tk.W)

        # Status Label
        self.status_label = ttk.Label(main_frame, text="Ready", foreground="green")
        self.status_label.grid(row=13, column=0, columnspan=2, sticky=tk.W)

        # Send Button
        self.send_button = ttk.Button(main_frame, text="Send Request", command=self.start_request_thread)
        self.send_button.grid(row=14, column=0, columnspan=2, pady=10)

        # Response Section
        ttk.Label(main_frame, text="Response").grid(row=15, column=0, columnspan=2, sticky=tk.W)
        self.response_text = scrolledtext.ScrolledText(main_frame, width=60, height=10)
        self.response_text.grid(row=16, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # Cookies Section
        ttk.Label(main_frame, text="Stored Cookies").grid(row=17, column=0, columnspan=2, sticky=tk.W)
        self.cookies_text = scrolledtext.ScrolledText(main_frame, width=60, height=5)
        self.cookies_text.grid(row=18, column=0, columnspan=2, sticky=(tk.W, tk.E))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

    def start_request_thread(self):
        if self.request_in_progress:
            return  # Prevent multiple clicks
        self.request_in_progress = True
        self.send_button.state(['disabled'])
        self.status_label.config(text="Sending request...", foreground="blue")
        self.root.update()
        threading.Thread(target=self.send_request, daemon=True).start()

    def send_request(self):
        # Suppress SSL warnings if verification is disabled
        if not self.ssl_verify.get():
            import requests.packages.urllib3
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        # Update proxy settings if enabled
        proxies = {}
        if self.proxy_enabled.get():
            proxy_host = self.proxy_host_entry.get()
            proxy_port = self.proxy_port_entry.get()
            proxy_user = self.proxy_user_entry.get()
            proxy_pass = self.proxy_pass_entry.get()

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
        url = self.url_entry.get()
        method = self.method_combo.get()
        try:
            headers = json.loads(self.headers_text.get("1.0", tk.END).strip())
            body = json.loads(self.body_text.get("1.0", tk.END).strip()) if method == "POST" else None
        except json.JSONDecodeError as e:
            self.root.after(0, lambda: self.response_text.delete("1.0", tk.END))
            self.root.after(0, lambda: self.response_text.insert(tk.END, f"Error: Invalid JSON in headers or body: {e}"))
            self.logger.error(f"JSON decode error: {e}")
            self.root.after(0, self.reset_ui)
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
        self.root.after(0, lambda: self.history_combo.config(values=[f"{r['method']} {r['url']}" for r in self.request_history]))

        # Send request
        try:
            start_time = datetime.now()
            if method == "POST":
                response = self.session.post(url, headers=headers, json=body, verify=self.ssl_verify.get())
            else:
                response = self.session.get(url, headers=headers, verify=self.ssl_verify.get())
            response.raise_for_status()
            response_time = (datetime.now() - start_time).total_seconds()
            
            # Update UI
            self.root.after(0, lambda: self.response_text.delete("1.0", tk.END))
            self.root.after(0, lambda: self.response_text.insert(tk.END, f"Status: {response.status_code}\n"))
            self.root.after(0, lambda: self.response_text.insert(tk.END, f"Response Time: {response_time:.2f} seconds\n"))
            self.root.after(0, lambda: self.response_text.insert(tk.END, f"Body:\n{response.text}\n"))
            
            # Update cookies
            cookies = self.session.cookies.get_dict()
            self.root.after(0, lambda: self.cookies_text.delete("1.0", tk.END))
            self.root.after(0, lambda: self.cookies_text.insert(tk.END, json.dumps(cookies, indent=2)))
            
            self.logger.info(f"Request successful: {response.status_code}, {response.text[:100]}...")
        except requests.exceptions.RequestException as e:
            self.root.after(0, lambda: self.response_text.delete("1.0", tk.END))
            self.root.after(0, lambda: self.response_text.insert(tk.END, f"Request failed: {e}"))
            self.logger.error(f"Request failed: {e}")
        finally:
            self.root.after(0, self.reset_ui)

    def reset_ui(self):
        self.request_in_progress = False
        self.send_button.state(['!disabled'])
        self.status_label.config(text="Ready", foreground="green")

    def load_history(self, event):
        selected_index = self.history_combo.current()
        if selected_index >= 0:
            request = self.request_history[selected_index]
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, request["url"])
            self.method_combo.set(request["method"])
            self.headers_text.delete("1.0", tk.END)
            self.headers_text.insert(tk.END, json.dumps(request["headers"], indent=2))
            self.body_text.delete("1.0", tk.END)
            if request["body"]:
                self.body_text.insert(tk.END, json.dumps(request["body"], indent=2))

if __name__ == "__main__":
    root = tk.Tk()
    app = APITesterApp(root)
    root.mainloop()