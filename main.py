

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.font as tkfont
import re
import subprocess
import sys
import queue
import threading
import math
from datetime import datetime

from wifi_scanner import scan_wifi, get_connected_network
from risk_engine import assess_network, compare_connected_network
from device_scanner import (
    NmapScanner,
    detect_local_ipv4_subnet,
    find_nmap_executable,
    scan_devices,
    validate_nmap_target,
)
from device_intelligence import DeviceHistoryStore, assess_device, fingerprint_device
from evil_twin_detector import detect_evil_twins
from wifi_reputation import load_database, normalize_bssid
from wifi_map import build_wifi_map_layout


class WiTrustApp:

    def __init__(self, root):

        self.root = root
        self.root.title("WiTrust - Wi-Fi Security Assistant")
        self.root.geometry("1100x720")
        self.root.minsize(950, 620)
        self.root.configure(bg="#f3f5f8")

        self.networks = []
        self.evil_twin_findings = {}
        self.reputation_records = {}
        self.reputation_warning = ""
        self.current_ssid = ""
        self.active_nmap_cancel_events = set()
        try:
            self.device_history = DeviceHistoryStore()
            self.device_history_error = ""
        except OSError as error:
            self.device_history = None
            self.device_history_error = str(error)
        self.device_records = {}
        self.device_scan_queue = queue.Queue()
        self.device_scan_in_progress = False
        self.wifi_scan_queue = queue.Queue()
        self.wifi_scan_in_progress = False
        self.root.protocol("WM_DELETE_WINDOW", self.close_app)

        self.setup_style()
        self.build_ui()


    def setup_style(self):

        style = ttk.Style()
        self.ui_font = tkfont.nametofont("TkDefaultFont").actual("family")
        self.mono_font = tkfont.nametofont("TkFixedFont").actual("family")

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", background="#f3f5f8", foreground="#172033")
        style.configure("TFrame", background="#f3f5f8")
        style.configure("TLabel", background="#f3f5f8", foreground="#172033")
        style.configure(
            "TLabelframe",
            background="#f3f5f8",
            bordercolor="#d5dce5",
        )
        style.configure(
            "TLabelframe.Label",
            background="#f3f5f8",
            foreground="#172033",
        )
        style.configure(
            "Treeview",
            background="#ffffff",
            fieldbackground="#ffffff",
            foreground="#172033",
            rowheight=28,
        )
        style.configure(
            "Treeview.Heading",
            background="#e8edf3",
            foreground="#172033",
            font=(self.ui_font, 10, "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", "#cfe3ff")],
            foreground=[("selected", "#172033")],
        )
        style.map(
            "Action.TButton",
            background=[("active", "#dce8f5"), ("pressed", "#cbd9e8")],
            foreground=[("disabled", "#748094")],
        )

        style.configure(
            "Title.TLabel",
            font=(self.ui_font, 24, "bold")
        )

        style.configure(
            "Sub.TLabel",
            font=(self.ui_font, 11)
        )

        style.configure(
            "Action.TButton",
            font=(self.ui_font, 11, "bold"),
            padding=9,
            background="#e8edf3",
            foreground="#172033",
        )


    def build_ui(self):

        # ==============================
        # HEADER
        # ==============================

        header = ttk.Frame(
            self.root,
            padding=(24, 20, 24, 10)
        )

        header.pack(fill="x")


        ttk.Label(
            header,
            text="🛡 WiTrust",
            style="Title.TLabel"
        ).pack(anchor="w")


        ttk.Label(
            header,
            text="Wi-Fi security assistant — scan, analyze and understand network risk",
            style="Sub.TLabel"
        ).pack(
            anchor="w",
            pady=(4, 0)
        )


        # ==============================
        # ACTION BUTTONS
        # ==============================

        actions = ttk.Frame(
            self.root,
            padding=(24, 8)
        )

        actions.pack(fill="x")


        self.scan_button = ttk.Button(
            actions,
            text="🔍 Scan Wi-Fi",
            command=self.scan_networks,
            style="Action.TButton"
        )
        self.scan_button.pack(
            side="left",
            padx=(0, 8)
        )


        devices_button = ttk.Button(
            actions,
            text="🖥 Scan Local Devices",
            command=self.scan_devices,
            style="Action.TButton"
        )
        devices_button.pack(
            side="left",
            padx=(0, 8)
        )

        report_button = ttk.Button(
            actions,
            text="📄 Generate Security Report",
            command=self.generate_report,
            style="Action.TButton"
        )
        report_button.pack(
            side="left",
            padx=(0, 8)
        )


        self.compare_button = ttk.Button(
            actions,
            text="📊 Compare Current Network",
            command=self.compare_current_network,
            style="Action.TButton"
        )
        self.compare_button.pack(
            side="left"
        )

        ttk.Button(
            actions,
            text="📡 Wi-Fi Map",
            command=self.show_wifi_map,
            style="Action.TButton",
        ).pack(side="left", padx=(8, 0))


        self.status = tk.StringVar(
            value="Ready to scan."
        )


        ttk.Label(
            actions,
            textvariable=self.status
        ).pack(
            side="right"
        )


        # ==============================
        # CURRENT NETWORK
        # ==============================

        self.current_network_frame = ttk.LabelFrame(
            self.root,
            text="Current Network",
            padding=12
        )

        self.current_network_frame.pack(
            fill="x",
            padx=24,
            pady=(0, 8)
        )


        self.current_network_label = ttk.Label(
            self.current_network_frame,
            text="No connected network information yet.",
            font=(self.ui_font, 10),
            justify="left",
            wraplength=1000,
        )

        self.current_network_label.pack(
            anchor="w"
        )


        # ==============================
        # MAIN CONTENT
        # ==============================

        content = ttk.Frame(
            self.root,
            padding=(24, 8)
        )

        content.pack(
            fill="both",
            expand=True
        )


        # ==================================================
        # LEFT SIDE - NETWORK TABLE
        # ==================================================

        left = ttk.Frame(content)

        left.pack(
            side="left",
            fill="both",
            expand=True
        )


        ttk.Label(
            left,
            text="Nearby Networks",
            font=(self.ui_font, 14, "bold")
        ).pack(anchor="w")


        columns = (
            "ssid",
            "security",
            "encryption",
            "signal",
            "risk"
        )


        self.tree = ttk.Treeview(
            left,
            columns=columns,
            show="headings",
            height=17
        )


        self.tree.tag_configure(
            "LOW",
            foreground="green"
        )

        self.tree.tag_configure(
            "MEDIUM",
            foreground="orange"
        )

        self.tree.tag_configure(
            "HIGH",
            foreground="red"
        )

        self.tree.tag_configure(
            "EVIL_TWIN",
            foreground="#b00020",
            font=(self.ui_font, 9, "bold"),
        )

        self.tree.tag_configure(
            "CURRENT",
            font=(self.ui_font, 9, "bold")
        )


        headings = {
            "ssid": "SSID",
            "security": "Security",
            "encryption": "Encryption",
            "signal": "Signal",
            "risk": "Risk"
        }


        widths = {
            "ssid": 210,
            "security": 140,
            "encryption": 110,
            "signal": 75,
            "risk": 130
        }


        for col in columns:

            self.tree.heading(
                col,
                text=headings[col]
            )

            self.tree.column(
                col,
                width=widths[col],
                anchor="center"
            )


        scrollbar = ttk.Scrollbar(
            left,
            orient="vertical",
            command=self.tree.yview
        )


        self.tree.configure(
            yscrollcommand=scrollbar.set
        )


        self.tree.pack(
            side="left",
            fill="both",
            expand=True,
            pady=(10, 0)
        )


        scrollbar.pack(
            side="right",
            fill="y",
            pady=(10, 0)
        )


        self.tree.bind(
            "<<TreeviewSelect>>",
            self.show_selected
        )


        # ==================================================
        # RIGHT SIDE
        # ==================================================

        right = ttk.Frame(
            content,
            padding=(18, 0, 0, 0)
        )


        right.pack(
            side="right",
            fill="both",
            expand=True
        )


        self.right_title = ttk.Label(
            right,
            text="WiTrust Assessment",
            font=(self.ui_font, 14, "bold")
        )


        self.right_title.pack(
            anchor="w"
        )


        # ==============================
        # RISK SUMMARY
        # ==============================

        self.risk_summary = tk.Label(
            right,
            text="No network selected",
            font=(self.ui_font, 14, "bold"),
            background="#ffffff",
            foreground="#172033",
            padx=12,
            pady=12,
            relief="groove",
            bd=1,
            justify="center"
        )


        self.risk_summary.pack(
            fill="x",
            pady=(10, 8)
        )


        # ==============================
        # WI-TRUST SCORE GUIDE
        # ==============================

        score_guide = ttk.LabelFrame(
            right,
            text="WiTrust Score Guide",
            padding=8
        )

        score_guide.pack(
            fill="x",
            pady=(0, 8)
        )


        ttk.Label(
            score_guide,
            text="🟢 0–29   LOW     — No major risk indicators",
            font=(self.ui_font, 9)
        ).pack(
            anchor="w"
        )


        ttk.Label(
            score_guide,
            text="🟠 30–59  MEDIUM  — Some caution indicators",
            font=(self.ui_font, 9)
        ).pack(
            anchor="w"
        )


        ttk.Label(
            score_guide,
            text="🔴 60–100 HIGH    — Strong risk indicators",
            font=(self.ui_font, 9)
        ).pack(
            anchor="w"
        )


        ttk.Label(
            score_guide,
            text="Prototype score — not proof that a network is malicious.",
            font=(self.ui_font, 8),
            wraplength=450
        ).pack(
            anchor="w",
            pady=(4, 0)
        )


        # ==============================
        # RESULT FRAME
        # ==============================

        result_frame = ttk.Frame(right)

        result_frame.pack(
            fill="both",
            expand=True
        )


        self.result = tk.Text(
            result_frame,
            height=25,
            width=48,
            wrap="word",
            font=(self.ui_font, 10),
            background="#ffffff",
            foreground="#172033",
            insertbackground="#172033",
            padx=12,
            pady=12
        )


        result_scrollbar = ttk.Scrollbar(
            result_frame,
            orient="vertical",
            command=self.result.yview
        )


        self.result.configure(
            yscrollcommand=result_scrollbar.set
        )


        self.result.pack(
            side="left",
            fill="both",
            expand=True
        )


        result_scrollbar.pack(
            side="right",
            fill="y"
        )


        self.result.insert(
            "1.0",
            "Run a Wi-Fi scan to see network assessments."
        )


        self.result.configure(
            state="disabled"
        )


        # ==============================
        # LOCAL DEVICE TABLE
        # ==============================

        device_frame = ttk.Frame(
            result_frame
        )

        self.device_overview = ttk.Label(
            device_frame,
            text="No device scan yet.",
            wraplength=520,
        )
        self.device_overview.pack(fill="x", pady=(0, 6))

        device_actions = ttk.Frame(device_frame)
        device_actions.pack(fill="x", pady=(0, 6))
        ttk.Button(
            device_actions,
            text="Refresh Devices",
            command=self.scan_devices,
            style="Action.TButton",
        ).pack(side="left", padx=(0, 6))
        ttk.Button(
            device_actions,
            text="Run Nmap Assessment",
            command=self.scan_devices_with_nmap,
            style="Action.TButton",
        ).pack(side="left")
        ttk.Button(
            device_actions,
            text="Threat Graph",
            command=self.show_device_graph,
            style="Action.TButton",
        ).pack(side="left", padx=(6, 0))


        device_columns = (
            "device",
            "ip",
            "mac",
            "vendor",
            "trust",
            "risk",
            "last_seen",
        )


        self.device_tree = ttk.Treeview(
            device_frame,
            columns=device_columns,
            show="headings"
        )


        device_headings = {
            "device": "Device",
            "ip": "IP Address",
            "mac": "MAC Address",
            "vendor": "Vendor",
            "trust": "Trust",
            "risk": "Risk",
            "last_seen": "Last Seen",
        }


        device_widths = {
            "device": 140,
            "ip": 105,
            "mac": 135,
            "vendor": 125,
            "trust": 65,
            "risk": 85,
            "last_seen": 105,
        }


        for col in device_columns:

            self.device_tree.heading(
                col,
                text=device_headings[col]
            )

            self.device_tree.column(
                col,
                width=device_widths[col],
                anchor="center"
            )


        device_scrollbar = ttk.Scrollbar(
            device_frame,
            orient="vertical",
            command=self.device_tree.yview
        )


        self.device_tree.configure(
            yscrollcommand=device_scrollbar.set
        )


        self.device_tree.pack(
            side="left",
            fill="both",
            expand=True
        )


        device_scrollbar.pack(
            side="right",
            fill="y"
        )


        device_frame.pack_forget()

        device_horizontal_scrollbar = ttk.Scrollbar(
            device_frame,
            orient="horizontal",
            command=self.device_tree.xview,
        )
        self.device_tree.configure(xscrollcommand=device_horizontal_scrollbar.set)
        device_horizontal_scrollbar.pack(side="bottom", fill="x")

        self.device_tree.tag_configure("LOW", foreground="#16833b")
        self.device_tree.tag_configure("MEDIUM", foreground="#b76b00")
        self.device_tree.tag_configure("HIGH", foreground="#b00020")
        self.device_tree.tag_configure("CRITICAL", foreground="#7a0014", font=(self.ui_font, 9, "bold"))
        self.device_tree.bind("<<TreeviewSelect>>", self.show_device_details)

        self.device_details = tk.Text(
            device_frame,
            height=9,
            wrap="word",
            font=(self.ui_font, 9),
            background="#ffffff",
            foreground="#172033",
            padx=8,
            pady=8,
            state="disabled",
        )
        self.device_details.pack(fill="x", pady=(6, 0))

        self.device_frame = device_frame


        self.risk_summary_colors = {
            "LOW": "green",
            "MEDIUM": "orange",
            "HIGH": "red"
        }


    # ==================================================
    # SHOW WIFI PANEL
    # ==================================================

    def show_wifi_panel(self):

        self.device_frame.pack_forget()

        self.result.pack(
            side="left",
            fill="both",
            expand=True
        )

        self.right_title.config(
            text="WiTrust Assessment"
        )

        self.risk_summary.pack(
            fill="x",
            pady=(10, 8)
        )

    def show_wifi_map(self):
        if not self.networks:
            messagebox.showinfo("Wi-Fi Map", "Scan Wi-Fi before opening the map.")
            return

        assessments = [
            assess_network(network, context=self.assessment_context(index, network))
            for index, network in enumerate(self.networks)
        ]
        layout = build_wifi_map_layout(self.networks, assessments)
        window = tk.Toplevel(self.root)
        window.title("WiTrust - Relative Wi-Fi Map")
        window.geometry("1000x690")
        window.minsize(820, 580)

        ttk.Label(
            window,
            text="Relative Wi-Fi proximity",
            font=(self.ui_font, 17, "bold"),
        ).pack(anchor="w", padx=18, pady=(14, 2))
        ttk.Label(
            window,
            text=(
                "Rings estimate relative signal only—not meters or direction. "
                "Walls, interference, and device hardware affect signal strength."
            ),
            wraplength=950,
        ).pack(anchor="w", padx=18, pady=(0, 10))

        body = ttk.Frame(window, padding=(12, 0, 12, 12))
        body.pack(fill="both", expand=True)
        canvas = tk.Canvas(body, background="#ffffff", highlightthickness=1)
        canvas.pack(side="left", fill="both", expand=True)
        details = tk.Text(
            body,
            width=38,
            wrap="word",
            font=(self.ui_font, 10),
            background="#f3f5f8",
            foreground="#172033",
            padx=10,
            pady=10,
        )
        details.pack(side="right", fill="y", padx=(10, 0))

        center_x, center_y = layout["center"]
        for tier, radius in layout["rings"]:
            canvas.create_oval(
                center_x - radius,
                center_y - radius,
                center_x + radius,
                center_y + radius,
                outline="#c9d1dc",
                dash=(3, 4),
            )
            canvas.create_text(
                center_x + 6,
                center_y - radius + 12,
                text=tier,
                fill="#596579",
                font=(self.ui_font, 9),
            )

        canvas.create_oval(
            center_x - 18, center_y - 18, center_x + 18, center_y + 18,
            fill="#24334a", outline="",
        )
        canvas.create_text(
            center_x, center_y + 31, text="This device", fill="#24334a",
            font=(self.ui_font, 9, "bold"),
        )

        for node in layout["nodes"]:
            canvas.create_oval(
                node["x"] - 10,
                node["y"] - 10,
                node["x"] + 10,
                node["y"] + 10,
                fill=node["color"],
                outline="#ffffff",
                width=2,
            )
            canvas.create_text(
                node["x"], node["y"], text=str(node["index"]),
                fill="#ffffff", font=(self.ui_font, 8, "bold"),
            )
            details.insert(
                "end",
                f"{node['index']}. {node['ssid']}\n"
                f"   {node['level']} RISK — {node['score']}/100\n"
                f"   Signal: {node['signal']} · {node['tier']}\n\n",
            )
        canvas.create_text(
            12, 12, anchor="nw",
            text="Ring placement shows signal tier; node angle is arbitrary.",
            fill="#596579", font=(self.ui_font, 9),
        )
        details.configure(state="disabled")


    # ==================================================
    # SHOW DEVICE PANEL
    # ==================================================

    def show_device_panel(self):

        self.result.pack_forget()

        self.risk_summary.pack_forget()

        self.device_frame.pack(
            fill="both",
            expand=True,
            pady=(10, 0)
        )

        self.right_title.config(
            text="Local Network Devices"
        )

    def close_app(self):
        for cancel_event in tuple(self.active_nmap_cancel_events):
            cancel_event.set()
        self.root.destroy()


    # ==================================================
    # DISPLAY RESULT
    # ==================================================

    def set_result(self, text):

        self.result.configure(
            state="normal"
        )

        self.result.delete(
            "1.0",
            "end"
        )

        self.result.insert(
            "1.0",
            text
        )

        self.result.configure(
            state="disabled"
        )


    # ==================================================
    # UPDATE CURRENT NETWORK
    # ==================================================

    def update_current_network(self, network=None):

        try:

            if network is None:
                network = get_connected_network()

            self.current_ssid = network.get("ssid") or ""


            if not network["ssid"]:

                if network.get("connected"):
                    self.current_network_label.config(
                        text=(
                            "Connected to Wi-Fi, but macOS is withholding the "
                            "network name and BSSID. Turn on Location Services "
                            "and enable WiTrust in System Settings > Privacy & "
                            "Security > Location Services. VS Code permission "
                            "alone does not grant WiTrust access."
                        )
                    )
                    return

                self.current_network_label.config(
                    text="No Wi-Fi network is currently connected."
                )

                return


            assessment = assess_network(
                network
            )


            text = (
                f"SSID          : {network['ssid'] or 'Unknown'}\n"
                f"Security      : {network['authentication'] or 'Unknown'}\n"
                f"Encryption    : {network['encryption'] or 'Unknown'}\n"
                f"Signal        : {network['signal'] or 'Unknown'}\n"
                f"Band          : {network['band'] or 'Unknown'}\n"
                f"Channel       : {network['channel'] or 'Unknown'}\n"
                f"Status        : {assessment['security_status']}\n"
                f"Risk          : {assessment['score']}/100 - "
                f"{assessment['level']}"
            )


            self.current_network_label.config(
                text=text
            )


        except Exception as exc:

            self.current_ssid = ""

            self.current_network_label.config(
                text=f"Could not get current Wi-Fi information: {exc}"
            )


    # ==================================================
    # SCAN WI-FI
    # ==================================================

    def assessment_context(self, network_index, network, findings=None, reputation_records=None):
        context = {}
        findings = self.evil_twin_findings if findings is None else findings
        reputation_records = (
            self.reputation_records if reputation_records is None else reputation_records
        )
        finding = findings.get(network_index)
        if finding:
            context["evil_twin_finding"] = finding

        bssid = normalize_bssid(network.get("bssid"))
        reputation = reputation_records.get(bssid)
        if reputation:
            context["reputation"] = reputation

        return context or None

    def scan_networks(self):
        if self.wifi_scan_in_progress:
            return

        self.wifi_scan_in_progress = True
        self.show_wifi_panel()
        self.scan_button.config(state="disabled")
        self.compare_button.config(state="disabled")
        self.status.set("Scanning nearby Wi-Fi…")
        self.current_ssid = ""
        self.networks = []
        self.evil_twin_findings = {}
        self.reputation_records = {}
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.risk_summary.config(text="Scanning Wi-Fi…", foreground="#172033")
        self.set_result("Scanning nearby networks. WiTrust will remain responsive.")
        self.current_network_label.config(text="Checking the connected Wi-Fi network…")

        def collect_scan_data():
            current_network = None
            current_error = ""
            try:
                current_network = get_connected_network()
            except Exception as error:
                current_error = str(error)

            try:
                networks = scan_wifi()
                findings = detect_evil_twins(networks)
                try:
                    reputation_records = load_database()["networks"]
                    reputation_warning = ""
                except ValueError:
                    reputation_records = {}
                    reputation_warning = " Local reputation data could not be loaded."
            except Exception as error:
                self.wifi_scan_queue.put(("error", (str(error), current_network, current_error)))
                return

            self.wifi_scan_queue.put(("success", {
                "networks": networks,
                "findings": findings,
                "reputation_records": reputation_records,
                "reputation_warning": reputation_warning,
                "current_network": current_network,
                "current_error": current_error,
            }))

        threading.Thread(target=collect_scan_data, daemon=True).start()
        self.root.after(100, self._poll_wifi_scan)

    def _poll_wifi_scan(self):
        if not self.wifi_scan_in_progress:
            return
        try:
            result_type, payload = self.wifi_scan_queue.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_wifi_scan)
            return

        self.wifi_scan_in_progress = False
        self.scan_button.config(state="normal")
        self.compare_button.config(state="normal")

        if result_type == "error":
            error, current_network, current_error = payload
            if current_network is not None:
                self.update_current_network(current_network)
            elif current_error:
                self.current_network_label.config(
                    text=f"Could not get current Wi-Fi information: {current_error}"
                )
            self.status.set("Wi-Fi scan failed.")
            self.risk_summary.config(text="Scan failed", foreground="#b00020")
            self.set_result(f"Wi-Fi scan failed.\n\n{error}")
            self._show_scan_error(error)
            return

        self.networks = payload["networks"]
        self.evil_twin_findings = payload["findings"]
        self.reputation_records = payload["reputation_records"]
        self.reputation_warning = payload["reputation_warning"]
        if payload["current_network"] is not None:
            self.update_current_network(payload["current_network"])
        elif payload["current_error"]:
            self.current_network_label.config(
                text=f"Could not get current Wi-Fi information: {payload['current_error']}"
            )
        self._render_wifi_networks()

    def _show_scan_error(self, error):
        if sys.platform == "darwin" and "location services" in str(error).casefold():
            open_settings = messagebox.askyesno(
                "Location Services Required",
                "macOS is withholding Wi-Fi names. Enable WiTrust in System Settings > "
                "Privacy & Security > Location Services. If WiTrust is not listed, "
                "quit and relaunch WiTrust, then scan once to register its request.\n\n"
                "Open Location Services settings?",
            )
            if open_settings:
                try:
                    subprocess.Popen(
                        [
                            "open",
                            "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except OSError as settings_error:
                    messagebox.showerror("WiTrust", str(settings_error))
        else:
            messagebox.showerror("WiTrust", str(error))

    def _render_wifi_networks(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for i, network in enumerate(self.networks):
            assessment = assess_network(
                network,
                context=self.assessment_context(i, network),
            )
            is_current = (
                network.get("ssid", "") == self.current_ssid
                and self.current_ssid != ""
            )
            display_ssid = network.get("ssid") or "<Hidden>"
            if is_current:
                display_ssid = f"★ {display_ssid} [CURRENT]"
            if i in self.evil_twin_findings:
                display_ssid = f"⚠ {display_ssid}"
            tags = [assessment["level"]]
            if i in self.evil_twin_findings:
                tags.append("EVIL_TWIN")
            if is_current:
                tags.append("CURRENT")
            self.tree.insert(
                "",
                "end",
                iid=str(i),
                values=(
                    display_ssid,
                    network.get("authentication") or "Unknown",
                    network.get("encryption") or "Unknown",
                    network.get("signal") or "Unknown",
                    f'{assessment["score"]}/100 - '
                    f'{assessment["level"]}'
                ),
                tags=tuple(tags)
            )


        finding_count = len(self.evil_twin_findings)
        status_text = f"{len(self.networks)} network(s) found."
        if finding_count:
            status_text += f" {finding_count} possible evil-twin indicator(s)."
        status_text += self.reputation_warning
        self.status.set(status_text)
        if self.networks:
            first = self.tree.get_children()[0]
            self.tree.selection_set(first)
            self.tree.focus(first)
            self.show_selected()
        else:
            self.risk_summary.config(text="No nearby networks found", foreground="#172033")
            self.set_result(
                "The Wi-Fi scan completed, but no nearby networks were returned. "
                "Check that Wi-Fi is enabled and scan again."
            )


    # ==================================================
    # SHOW SELECTED NETWORK
    # ==================================================

    def show_selected(self, event=None):

        selection = self.tree.selection()


        if not selection:

            return


        self.show_wifi_panel()


        network = self.networks[
            int(selection[0])
        ]
        finding = self.evil_twin_findings.get(int(selection[0]))


        assessment = assess_network(
            network,
            context=self.assessment_context(int(selection[0]), network),
        )


        level = assessment["level"]

        score = assessment["score"]

        security_status = assessment[
            "security_status"
        ]


        summary_text = (
            f"{level} RISK\n"
            f"{score}/100  •  SECURITY: {security_status}"
        )
        if finding:
            summary_text = f"POSSIBLE EVIL TWIN\n{summary_text}"

        self.risk_summary.config(
            text=summary_text,
            foreground=(
                "#b00020"
                if finding
                else self.risk_summary_colors.get(level, "black")
            ),
        )


        lines = [

            "WI-TRUST NETWORK ASSESSMENT",

            "",

            f"SSID: "
            f"{network['ssid'] or '<Hidden>'}",

            f"BSSID: "
            f"{network['bssid'] or 'Unknown'}",

            f"Signal: "
            f"{network['signal'] or 'Unknown'}",

            f"Channel: "
            f"{network['channel'] or 'Unknown'}",

            f"Band: "
            f"{network['band'] or 'Unknown'}",

            f"Authentication: "
            f"{network['authentication'] or 'Unknown'}",

            f"Encryption: "
            f"{network['encryption'] or 'Unknown'}",

            "",

            f"SECURITY STATUS: "
            f"{security_status}",

            "",

            f"RISK SCORE: "
            f"{score}/100",

            f"RISK LEVEL: "
            f"{level}",

            f"SCAN DATA QUALITY: "
            f"{assessment['data_quality']}",

            f"SCAN DATA COVERAGE: "
            f"{assessment['data_coverage_score']}% (field completeness, not probability)",

            "",

            "SCORE FACTORS:",

        ]

        if assessment["signals"]:
            lines.extend(
                f"• {signal['code'].replace('_', ' ').title()}: +{signal['points']}"
                for signal in assessment["signals"]
            )
        else:
            lines.append("• No scored risk factors detected.")

        lines.extend(["", "WHY:"])

        if assessment["reasons"]:

            lines.extend(
                [
                    f"• {reason}"
                    for reason in assessment["reasons"]
                ]
            )

        else:

            lines.append(
                "• No major risk indicators were detected "
                "by the current rules."
            )

        lines.extend(
            f"• Data limitation: {limitation}"
            for limitation in assessment["limitations"]
        )

        lines.extend(
            f"• Context: {observation}"
            for observation in assessment["observations"]
        )


        lines += [
            "",
            "RECOMMENDATION:"
        ]


        lines.extend(
            [
                f"• {tip}"
                for tip in assessment[
                    "recommendations"
                ]
            ]
        )


        lines += [

            "",

            "Note: This is a prototype risk assessment. "
            "A high score means the network has indicators "
            "that deserve caution; it does not prove that "
            "the network is malicious."

        ]


        self.set_result(
            "\n".join(lines)
        )


    # ==================================================
    # BUILD REPORT
    # ==================================================

    def build_report(self, network, assessment):

        lines = [

            "============================================",
            "           WI-TRUST SECURITY REPORT",
            "============================================",
            "",

            f"Network       : "
            f"{network['ssid'] or '<Hidden>'}",

            f"Security      : "
            f"{network['authentication'] or 'Unknown'}",

            f"Encryption    : "
            f"{network['encryption'] or 'Unknown'}",

            f"Signal        : "
            f"{network['signal'] or 'Unknown'}",

            f"Band          : "
            f"{network['band'] or 'Unknown'}",

            f"Channel       : "
            f"{network['channel'] or 'Unknown'}",

            "",

            "--------------------------------------------",

            f"SECURITY STATUS : "
            f"{assessment['security_status']}",

            f"RISK SCORE      : "
            f"{assessment['score']}/100",

            f"RISK LEVEL      : "
            f"{assessment['level']}",

            "--------------------------------------------",

            "",

            "WHY:"
        ]


        if assessment["reasons"]:

            lines.extend(
                [
                    f"• {reason}"
                    for reason in assessment["reasons"]
                ]
            )

        else:

            lines.append(
                "• No major risk indicators were detected."
            )

        lines.extend(
            ["", f"Scan data quality: {assessment['data_quality']}"]
        )
        lines.append(
            f"Scan data coverage: {assessment['data_coverage_score']}% "
            "(field completeness, not probability)"
        )
        lines.extend(
            ["", "Score factors:"]
        )
        if assessment["signals"]:
            lines.extend(
                f"• {signal['code'].replace('_', ' ').title()}: +{signal['points']}"
                for signal in assessment["signals"]
            )
        else:
            lines.append("• No scored risk factors detected.")
        lines.extend(
            f"Data limitation: {limitation}"
            for limitation in assessment["limitations"]
        )


        lines += [

            "",

            "RECOMMENDATIONS:"
        ]


        lines.extend(
            [
                f"• {tip}"
                for tip in assessment[
                    "recommendations"
                ]
            ]
        )


        lines += [

            "",

            "--------------------------------------------",

            "NOTE:",

            "This is a prototype risk assessment.",

            "A high score means the network has "
            "indicators that deserve caution.",

            "It does not prove that the network "
            "is malicious.",

            "",

            "Generated by WiTrust"
        ]


        return "\n".join(lines)


    # ==================================================
    # GENERATE SECURITY REPORT
    # ==================================================

    def generate_report(self):

        selection = self.tree.selection()


        if not selection:

            messagebox.showinfo(
                "WiTrust",
                "Please select a Wi-Fi network first."
            )

            return


        selected_index = int(selection[0])
        network = self.networks[selected_index]


        assessment = assess_network(
            network,
            context=self.assessment_context(selected_index, network),
        )


        report = self.build_report(network, assessment)


        report_window = tk.Toplevel(
            self.root
        )


        report_window.title(
            "WiTrust - Security Report"
        )


        report_window.geometry(
            "700x650"
        )


        report_window.minsize(
            600,
            500
        )


        ttk.Label(
            report_window,
            text="📄 WiTrust Security Report",
            font=(self.ui_font, 20, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 5)
        )


        ttk.Label(
            report_window,
            text="Generated from the selected Wi-Fi network",
            font=(self.ui_font, 10)
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 10)
        )


        report_frame = ttk.Frame(
            report_window,
            padding=20
        )

        report_frame.pack(
            fill="both",
            expand=True
        )


        report_text = tk.Text(
            report_frame,
            wrap="word",
            font=(self.mono_font, 10),
            background="#ffffff",
            foreground="#172033",
            insertbackground="#172033",
            padx=15,
            pady=15
        )


        report_scrollbar = ttk.Scrollbar(
            report_frame,
            orient="vertical",
            command=report_text.yview
        )


        report_text.configure(
            yscrollcommand=report_scrollbar.set
        )


        report_text.pack(
            side="left",
            fill="both",
            expand=True
        )


        report_scrollbar.pack(
            side="right",
            fill="y"
        )


        report_text.insert(
            "1.0",
            report
        )


        report_text.configure(
            state="disabled"
        )


        button_frame = ttk.Frame(
            report_window
        )

        button_frame.pack(
            pady=(0, 20)
        )


        ttk.Button(
            button_frame,
            text="💾 Save Report",
            command=lambda: self.save_report(
                report,
                network["ssid"]
            )
        ).pack(
            side="left",
            padx=5
        )


        ttk.Button(
            button_frame,
            text="Close",
            command=report_window.destroy
        ).pack(
            side="left",
            padx=5
        )


    # ==================================================
    # SAVE REPORT
    # ==================================================

    def save_report(self, report, ssid):

        safe_name = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "_", str(ssid or ""))
        safe_name = safe_name.strip(" .")[:100] or "Unknown_Network"
        reserved_names = {"CON", "PRN", "AUX", "NUL"}
        reserved_names.update(f"COM{index}" for index in range(1, 10))
        reserved_names.update(f"LPT{index}" for index in range(1, 10))
        if safe_name.split(".", 1)[0].upper() in reserved_names:
            safe_name = f"_{safe_name}"


        filename = (
            f"WiTrust_Report_{safe_name}.txt"
        )


        file_path = filedialog.asksaveasfilename(
            title="Save WiTrust Security Report",
            defaultextension=".txt",
            initialfile=filename,
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )


        if not file_path:

            return


        try:

            with open(
                file_path,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(report)


            messagebox.showinfo(
                "WiTrust",
                "Security report saved successfully."
            )


        except Exception as exc:

            messagebox.showerror(
                "WiTrust",
                f"Could not save the report.\n\n{exc}"
            )


    # ==================================================
    # COMPARE CURRENT NETWORK
    # ==================================================

    def compare_current_network(self):
        if self.wifi_scan_in_progress:
            return

        self.wifi_scan_in_progress = True
        self.scan_button.config(state="disabled")
        self.compare_button.config(state="disabled")
        self.status.set("Comparing current and nearby Wi-Fi networks…")

        def collect_comparison():
            try:
                current_network = get_connected_network()
                nearby_networks = scan_wifi()
                findings = detect_evil_twins(nearby_networks)
                try:
                    reputation_records = load_database()["networks"]
                except ValueError:
                    reputation_records = {}
                nearby_contexts = [
                    self.assessment_context(index, network, findings, reputation_records)
                    for index, network in enumerate(nearby_networks)
                ]
                current_bssid = normalize_bssid(current_network.get("bssid"))
                current_index = next(
                    (
                        index
                        for index, network in enumerate(nearby_networks)
                        if normalize_bssid(network.get("bssid")) == current_bssid
                        and current_bssid
                    ),
                    None,
                )
                current_context = (
                    self.assessment_context(
                        current_index,
                        current_network,
                        findings,
                        reputation_records,
                    )
                    if current_index is not None
                    else self.assessment_context(-1, current_network, {}, reputation_records)
                )
                result = compare_connected_network(
                    current_network,
                    nearby_networks,
                    current_context=current_context,
                    nearby_contexts=nearby_contexts,
                )
                self.wifi_scan_queue.put(("comparison_success", result))
            except Exception as error:
                self.wifi_scan_queue.put(("comparison_error", str(error)))

        def poll_comparison():
            try:
                result_type, payload = self.wifi_scan_queue.get_nowait()
            except queue.Empty:
                self.root.after(100, poll_comparison)
                return

            self.wifi_scan_in_progress = False
            self.scan_button.config(state="normal")
            self.compare_button.config(state="normal")
            if result_type == "comparison_error":
                self.status.set("Comparison failed.")
                messagebox.showerror("WiTrust", str(payload))
                return

            self.status.set("Network comparison complete.")
            self._show_comparison_result(payload)

        threading.Thread(target=collect_comparison, daemon=True).start()
        self.root.after(100, poll_comparison)

    def _show_comparison_result(self, result):


        # ==============================
        # COMPARISON WINDOW
        # ==============================

        comparison_window = tk.Toplevel(
            self.root
        )


        comparison_window.title(
            "WiTrust - Connected Network Check"
        )


        comparison_window.geometry(
            "700x600"
        )


        comparison_window.minsize(
            600,
            500
        )


        ttk.Label(
            comparison_window,
            text="📊 Connected Network Check",
            font=(self.ui_font, 20, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 5)
        )


        ttk.Label(
            comparison_window,
            text="Comparison between your current network and nearby Wi-Fi networks",
            font=(self.ui_font, 10)
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 15)
        )


        comparison_frame = ttk.Frame(
            comparison_window,
            padding=20
        )

        comparison_frame.pack(
            fill="both",
            expand=True
        )


        comparison_text = tk.Text(
            comparison_frame,
            wrap="word",
            font=(self.ui_font, 11),
            background="#ffffff",
            foreground="#172033",
            insertbackground="#172033",
            padx=15,
            pady=15
        )


        comparison_scrollbar = ttk.Scrollbar(
            comparison_frame,
            orient="vertical",
            command=comparison_text.yview
        )


        comparison_text.configure(
            yscrollcommand=comparison_scrollbar.set
        )


        comparison_text.pack(
            side="left",
            fill="both",
            expand=True
        )


        comparison_scrollbar.pack(
            side="right",
            fill="y"
        )


        lines = [

            "CONNECTED NETWORK CHECK",

            "",

            "CURRENT NETWORK",
            "----------------------------"

        ]


        for line in result["comparison"]:

            lines.append(
                line
            )


        lines += [

            "",

            "Note: This comparison is based on "
            "WiTrust's prototype risk rules.",

            "A lower risk score does not guarantee "
            "that a network is completely safe."

        ]


        comparison_text.insert(
            "1.0",
            "\n".join(lines)
        )


        comparison_text.configure(
            state="disabled"
        )


        ttk.Button(
            comparison_window,
            text="Close",
            command=comparison_window.destroy
        ).pack(
            pady=(0, 20)
        )


    # ==================================================
    # SCAN LOCAL DEVICES
    # ==================================================

    def scan_devices(self):
        if self.device_scan_in_progress:
            return
        self.device_scan_in_progress = True
        self.show_device_panel()
        self.device_overview.config(text="Scanning the local ARP table…")
        self.status.set("Checking devices on the local network…")

        def collect_devices():
            try:
                devices = scan_devices()
                try:
                    connected_network = get_connected_network()
                except (OSError, RuntimeError):
                    connected_network = None
                self.device_scan_queue.put(("success", (devices, connected_network, "ARP", False)))
            except Exception as error:
                self.device_scan_queue.put(("error", str(error)))

        def poll_devices():
            if not self.root.winfo_exists():
                self.device_scan_in_progress = False
                return
            try:
                result_type, payload = self.device_scan_queue.get_nowait()
            except queue.Empty:
                self.root.after(100, poll_devices)
                return
            self.device_scan_in_progress = False
            if result_type == "error":
                self.device_overview.config(text="Device scan failed.")
                self.status.set("Device scan failed.")
                messagebox.showerror("WiTrust", str(payload))
                return
            devices, connected_network, source, ports_scanned = payload
            self._display_device_records(devices, connected_network, source, ports_scanned)

        threading.Thread(target=collect_devices, daemon=True).start()
        self.root.after(100, poll_devices)

    def _display_device_records(self, devices, connected_network=None, source="ARP", ports_scanned=False):
        self.device_records = {}
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)

        records = []
        seen_device_ids = set()
        for device in devices:
            observed_device = dict(device)
            observed_device["ports_scanned"] = ports_scanned
            observed_device.setdefault("interface", source)
            try:
                identity = fingerprint_device(observed_device, connected_network)["device_id"]
                if identity in seen_device_ids:
                    continue
                seen_device_ids.add(identity)
                if self.device_history:
                    record = self.device_history.observe(observed_device, connected_network)
                else:
                    fingerprint = fingerprint_device(observed_device, connected_network)
                    record = {**fingerprint, **assess_device(fingerprint)}
            except Exception as error:
                self.device_history_error = str(error)
                fingerprint = fingerprint_device(observed_device, connected_network)
                record = {**fingerprint, **assess_device(fingerprint)}
            records.append(record)

        for index, record in enumerate(records):
            item_id = str(index)
            self.device_records[item_id] = record
            label = record.get("hostname") or record.get("mac") or record.get("device_id")
            self.device_tree.insert(
                "", "end", iid=item_id,
                values=(
                    label,
                    record.get("ip") or "Unknown",
                    record.get("mac") or "Unknown",
                    record.get("vendor") or "Unknown (not available)",
                    f"{record['trust_score']}/100",
                    f"{record['risk_level']} ({record['risk_score']})",
                    record.get("last_seen", "")[:19].replace("T", " "),
                ),
                tags=(record["risk_level"],),
            )

        high_count = sum(record["risk_level"] in {"HIGH", "CRITICAL"} for record in records)
        trusted_count = sum(record["risk_level"] == "LOW" for record in records)
        unknown_count = len(records) - trusted_count - high_count
        timestamp = datetime.now().astimezone().strftime("%H:%M:%S")
        self.device_overview.config(
            text=(
                f"NETWORK OVERVIEW · {source} · {timestamp}\n"
                f"Devices discovered: {len(records)}   Low risk: {trusted_count}   "
                f"Medium: {unknown_count}   High/Critical: {high_count}"
                + (f"   · History unavailable: {self.device_history_error}" if self.device_history_error else "")
            )
        )
        self.status.set(f"{len(records)} device(s) observed via {source} at {timestamp}.")
        self.risk_summary.pack_forget()
        self.device_details.configure(state="normal")
        self.device_details.delete("1.0", "end")
        self.device_details.insert("1.0", "Select a device to inspect its fingerprint, history, trust drift, and explanation.")
        self.device_details.configure(state="disabled")
        if records:
            self.device_tree.selection_set("0")
            self.show_device_details()
        else:
            self.device_details.configure(state="normal")
            self.device_details.delete("1.0", "end")
            self.device_details.insert("1.0", "No devices were returned by this scan. The ARP table only lists devices your Mac has recently contacted; use an authorized Nmap scan for active discovery.")
            self.device_details.configure(state="disabled")

    def show_device_details(self, _event=None):
        selected = self.device_tree.selection()
        if not selected:
            return
        record = self.device_records.get(selected[0])
        if not record:
            return
        try:
            history = self.device_history.get_history(record["device_id"], 8) if self.device_history else []
        except Exception as error:
            history = []
            self.device_history_error = str(error)
        drift = record.get("trust_drift")
        drift_text = "First observation" if drift is None else f"{drift:+d} points since previous observation"
        reasons = "\n".join(
            f"  {'+' if reason['weight'] >= 0 else ''}{reason['weight']}  {reason['description']}"
            for reason in record["reasons"]
        ) or "  No risk indicators from available evidence."
        history_lines = "\n".join(
            f"  {item['observed_at'][:19].replace('T', ' ')} · trust {item['trust_score']} · {item['ip'] or 'IP unknown'}"
            for item in history
        ) or "  No prior snapshots."
        recommendation = (
            "Investigate and verify whether this device is authorized; consider isolating it only if confirmed unauthorized."
            if record["risk_level"] in {"HIGH", "CRITICAL"}
            else "Verify unfamiliar devices and review again after a service scan."
            if record["risk_level"] == "MEDIUM"
            else "No major device-level indicators found in the available scan data."
        )
        ports_observation = (
            "Current service scan"
            if record.get("ports_scanned")
            else "Retained from prior service scan"
            if record.get("service_details")
            else "Not scanned"
        )
        details = (
            f"DEVICE INTELLIGENCE · {record['risk_level']} RISK\n"
            f"Device: {record.get('hostname') or 'Unknown hostname'}\n"
            f"IP: {record.get('ip') or 'Unknown'}   MAC: {record.get('mac') or 'Unknown'}\n"
            f"Vendor: {record.get('vendor', 'Unknown')}   Interface: {record.get('interface') or 'Unknown'}\n"
            f"SSID: {record.get('ssid') or 'Unavailable'}   BSSID: {record.get('bssid') or 'Unavailable'}\n"
            f"Wi-Fi security: {record.get('wifi_security') or 'Unavailable'}   Adapter RSSI: {record.get('signal') or 'Unavailable'}\n"
            f"First seen: {record.get('first_seen', 'Not persisted')[:19].replace('T', ' ')}   "
            f"Last seen: {record.get('last_seen', 'Not persisted')[:19].replace('T', ' ')}   "
            f"Observations: {record.get('observation_count', 1)}\n"
            f"Trust: {record['trust_score']}/100   Risk: {record['risk_score']}/100   "
            f"Trust drift: {drift_text}   Evidence coverage: {record['confidence']:.0%}\n"
            f"Open services: {', '.join(record.get('services', [])) or 'Not observed'}\n"
            f"Service details: {', '.join(record.get('service_details', [])) or 'Not observed'}\n"
            f"Open ports: {', '.join(record.get('open_ports', [])) or 'Not observed'} ({ports_observation})\n\n"
            f"WHY?\n{reasons}\n\nHISTORY\n{history_lines}\n\n"
            f"RECOMMENDED ACTION\n{recommendation}\n\n"
            "Heuristic result from available observations; not proof of malicious activity."
        )
        self.device_details.configure(state="normal")
        self.device_details.delete("1.0", "end")
        self.device_details.insert("1.0", details)
        self.device_details.configure(state="disabled")

    def show_device_graph(self):
        records = list(self.device_records.values())
        if not records:
            messagebox.showinfo("Threat Graph", "Scan devices before opening the relationship graph.")
            return
        window = tk.Toplevel(self.root)
        window.title("WiTrust · Device Relationship Graph")
        window.geometry("760x600")
        canvas = tk.Canvas(window, background="#ffffff", highlightthickness=0)
        canvas.pack(fill="both", expand=True, padx=12, pady=12)
        center_x, center_y = 380, 100
        canvas.create_oval(center_x - 55, center_y - 24, center_x + 55, center_y + 24, fill="#24334a", outline="")
        center_label = next((record.get("ssid") for record in records if record.get("ssid")), "Local network")
        canvas.create_text(center_x, center_y, text=center_label[:22], fill="white", font=(self.ui_font, 10, "bold"))
        for index, record in enumerate(records[:16]):
            angle = (index / max(1, min(len(records), 16))) * 6.28318
            node_x = center_x + 250 * math.cos(angle)
            node_y = 330 + 175 * math.sin(angle)
            color = {"LOW": "#24a148", "MEDIUM": "#f1a208", "HIGH": "#da1e28", "CRITICAL": "#7a0014"}[record["risk_level"]]
            canvas.create_line(center_x, center_y + 24, node_x, node_y - 23, fill="#aab4c0")
            canvas.create_oval(node_x - 48, node_y - 23, node_x + 48, node_y + 23, fill=color, outline="")
            name = record.get("hostname") or record.get("ip") or "Device"
            canvas.create_text(node_x, node_y, text=f"{name}\n{record['trust_score']} trust", fill="white", font=(self.ui_font, 8, "bold"))
            for service_index, service in enumerate(record.get("service_details", [])[:3]):
                service_y = node_y + 33 + service_index * 15
                canvas.create_line(node_x, node_y + 23, node_x, service_y - 5, fill="#aab4c0")
                canvas.create_text(node_x, service_y, text=service[:30], fill="#39465a", font=(self.ui_font, 8))
        ttk.Label(
            window,
            text="Edges show local scan grouping, not verified wireless association. Service visibility depends on an Nmap service scan; device placement is illustrative, not physical distance.",
            wraplength=720,
        ).pack(anchor="w", padx=18, pady=(0, 12))

    def scan_devices_with_nmap(self):
        if not find_nmap_executable():
            messagebox.showerror(
                "Nmap Not Found",
                "Install Nmap and reopen WiTrust. Download it from nmap.org/download.html.",
            )
            return

        window = tk.Toplevel(self.root)
        window.title("Nmap Network Assessment")
        window.geometry("550x390")
        window.resizable(False, False)
        frame = ttk.Frame(window, padding=18)
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame,
            text="Authorized local network scan",
            font=(self.ui_font, 15, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            frame,
            text=(
                "Only scan networks you own or have permission to assess. "
                "WiTrust accepts private IPv4 subnets of up to 256 addresses."
            ),
            wraplength=500,
        ).pack(anchor="w", pady=(4, 14))

        ttk.Label(frame, text="Private IPv4 subnet (CIDR)").pack(anchor="w")
        target_var = tk.StringVar(value="Detecting local private subnet…")
        target_entry = ttk.Entry(frame, textvariable=target_var)
        target_entry.pack(fill="x", pady=(3, 12))

        ttk.Label(frame, text="Scan profile").pack(anchor="w")
        profile_options = {
            "Host discovery only (no ports)": "discovery",
            "Common TCP ports + light service detection (top 100)": "common_tcp",
        }
        profile_var = tk.StringVar(value=next(iter(profile_options)))
        profile_box = ttk.Combobox(
            frame,
            textvariable=profile_var,
            values=tuple(profile_options),
            state="readonly",
        )
        profile_box.pack(fill="x", pady=(3, 4))
        description = tk.StringVar()
        description_label = ttk.Label(frame, textvariable=description, wraplength=500)
        description_label.pack(anchor="w", pady=(0, 12))
        target_queue = queue.Queue()

        def detect_target_in_background():
            target_entry.config(state="disabled")

            def detect_target():
                try:
                    target = detect_local_ipv4_subnet()
                except Exception:
                    target = None
                target_queue.put(target)

            def apply_detected_target(target):
                if not window.winfo_exists():
                    return
                target_entry.config(state="normal")
                if target and target_var.get() in {"", "Detecting local private subnet…"}:
                    target_var.set(target)
                elif target is None and target_var.get() == "Detecting local private subnet…":
                    target_var.set("")

            def poll_target():
                if not window.winfo_exists():
                    return
                try:
                    target = target_queue.get_nowait()
                except queue.Empty:
                    window.after(100, poll_target)
                    return
                apply_detected_target(target)

            threading.Thread(target=detect_target, daemon=True).start()
            window.after(100, poll_target)

        detect_target_in_background()

        def update_profile_description(_event=None):
            if profile_options[profile_var.get()] == "discovery":
                description.set("Finds responding hosts. Does not probe ports or services.")
            else:
                description.set(
                    "Checks Nmap's 100 most common TCP ports and performs light service "
                    "identification. No UDP, OS detection, or vulnerability scripts."
                )

        profile_box.bind("<<ComboboxSelected>>", update_profile_description)
        update_profile_description()

        authorized_var = tk.BooleanVar(value=False)
        authorized_check = ttk.Checkbutton(
            frame,
            text="I own this subnet or have explicit permission to scan it",
            variable=authorized_var,
        )
        authorized_check.pack(anchor="w", pady=(0, 8))
        scan_status = tk.StringVar(value="Enter a target and confirm authorization to continue.")
        ttk.Label(frame, textvariable=scan_status, wraplength=500).pack(anchor="w")

        buttons = ttk.Frame(frame)
        buttons.pack(side="bottom", fill="x", pady=(16, 0))
        result_queue = queue.Queue()
        cancel_event = threading.Event()
        scanning = False

        def poll_result():
            nonlocal scanning
            if not window.winfo_exists():
                return
            try:
                result_type, payload = result_queue.get_nowait()
            except queue.Empty:
                window.after(100, poll_result)
                return

            if result_type == "error":
                self.active_nmap_cancel_events.discard(cancel_event)
                scan_status.set(str(payload))
                if "cancelled" in str(payload).casefold():
                    self.status.set("Nmap scan cancelled.")
                else:
                    self.status.set(f"Nmap scan failed: {payload}")
                scanning = False
                scan_button.config(state="normal")
                target_entry.config(state="normal")
                profile_box.config(state="readonly")
                authorized_check.config(state="normal")
                close_button.config(text="Close", command=window.destroy, state="normal")
                return

            devices, connected_network = payload
            self.active_nmap_cancel_events.discard(cancel_event)
            self._display_device_records(
                devices,
                connected_network,
                "Nmap",
                ports_scanned=(profile == "common_tcp"),
            )
            self.status.set(f"Nmap found {len(devices)} up host(s).")
            scan_status.set(
                f"Completed. Found {len(devices)} responsive host(s). "
                "Hostnames require reverse-DNS records. Port results depend on the selected profile."
            )
            scanning = False
            scan_button.config(state="disabled")
            close_button.config(text="Close", command=window.destroy, state="normal")

        def cancel_or_close():
            if scanning:
                cancel_event.set()
                scan_status.set("Stopping Nmap scan…")
                close_button.config(state="disabled")
            else:
                window.destroy()

        def start_scan():
            nonlocal scanning
            try:
                target = str(validate_nmap_target(target_var.get()))
            except ValueError as error:
                scan_status.set(str(error))
                return
            if not authorized_var.get():
                scan_status.set("Confirm that you are authorized to scan this subnet.")
                return

            profile = profile_options[profile_var.get()]
            scanning = True
            cancel_event.clear()
            self.active_nmap_cancel_events.add(cancel_event)
            scan_status.set("Nmap is scanning. WiTrust remains responsive…")
            self.show_device_panel()
            self.status.set("Nmap scan in progress…")
            scan_button.config(state="disabled")
            close_button.config(
                text="Cancel scan",
                command=cancel_or_close,
                state="normal",
            )
            target_entry.config(state="disabled")
            profile_box.config(state="disabled")
            authorized_check.config(state="disabled")

            def run_scan():
                try:
                    devices = NmapScanner().scan(
                        target, profile=profile, cancel_event=cancel_event
                    )
                    try:
                        connected_network = get_connected_network()
                    except (OSError, RuntimeError):
                        connected_network = None
                    result_queue.put(("success", (devices, connected_network)))
                except (RuntimeError, ValueError) as error:
                    result_queue.put(("error", str(error)))

            threading.Thread(target=run_scan, daemon=True).start()
            window.after(100, poll_result)

        scan_button = ttk.Button(buttons, text="Start scan", command=start_scan)
        scan_button.pack(side="right", padx=(8, 0))
        close_button = ttk.Button(buttons, text="Close", command=cancel_or_close)
        close_button.pack(side="right")
        window.protocol("WM_DELETE_WINDOW", cancel_or_close)


# ==================================================
# START APPLICATION
# ==================================================

if __name__ == "__main__":

    tcl_version = tuple(
        int(part)
        for part in tk.Tcl().eval("info patchlevel").split(".")[:2]
    )

    if tcl_version < (8, 6):
        raise SystemExit(
            "WiTrust needs Tcl/Tk 8.6 or later for its desktop interface. "
            f"This Python provides Tcl/Tk {tk.Tcl().eval('info patchlevel')}. "
            "Install a recent Python from python.org, then launch with that Python."
        )

    root = tk.Tk()

    app = WiTrustApp(root)

    root.mainloop()
