

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from wifi_scanner import scan_wifi, get_connected_network
from risk_engine import assess_network, compare_connected_network
from device_scanner import scan_devices


class WiTrustApp:

    def __init__(self, root):

        self.root = root
        self.root.title("WiTrust - Wi-Fi Security Assistant")
        self.root.geometry("1100x720")
        self.root.minsize(950, 620)

        self.networks = []
        self.current_ssid = ""

        self.setup_style()
        self.build_ui()


    def setup_style(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 24, "bold")
        )

        style.configure(
            "Sub.TLabel",
            font=("Segoe UI", 11)
        )

        style.configure(
            "Action.TButton",
            font=("Segoe UI", 11, "bold"),
            padding=9
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


        ttk.Button(
            actions,
            text="🔍 Scan Wi-Fi",
            command=self.scan_networks,
            style="Action.TButton"
        ).pack(
            side="left",
            padx=(0, 8)
        )


        ttk.Button(
            actions,
            text="🖥 Scan Local Devices",
            command=self.scan_devices,
            style="Action.TButton"
        ).pack(
            side="left",
            padx=(0, 8)
        )


        ttk.Button(
            actions,
            text="📄 Generate Security Report",
            command=self.generate_report,
            style="Action.TButton"
        ).pack(
            side="left",
            padx=(0, 8)
        )


        ttk.Button(
            actions,
            text="📊 Compare Current Network",
            command=self.compare_current_network,
            style="Action.TButton"
        ).pack(
            side="left"
        )


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
            font=("Segoe UI", 10),
            justify="left"
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
            font=("Segoe UI", 14, "bold")
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
            "CURRENT",
            font=("Segoe UI", 9, "bold")
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
            font=("Segoe UI", 14, "bold")
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
            font=("Segoe UI", 14, "bold"),
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
            font=("Segoe UI", 9)
        ).pack(
            anchor="w"
        )


        ttk.Label(
            score_guide,
            text="🟠 30–59  MEDIUM  — Some caution indicators",
            font=("Segoe UI", 9)
        ).pack(
            anchor="w"
        )


        ttk.Label(
            score_guide,
            text="🔴 60–100 HIGH    — Strong risk indicators",
            font=("Segoe UI", 9)
        ).pack(
            anchor="w"
        )


        ttk.Label(
            score_guide,
            text="Prototype score — not proof that a network is malicious.",
            font=("Segoe UI", 8),
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
            font=("Segoe UI", 10),
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


        device_columns = (
            "ip",
            "mac",
            "interface"
        )


        self.device_tree = ttk.Treeview(
            device_frame,
            columns=device_columns,
            show="headings"
        )


        device_headings = {
            "ip": "IP Address",
            "mac": "MAC Address",
            "interface": "Interface"
        }


        device_widths = {
            "ip": 130,
            "mac": 170,
            "interface": 130
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

    def update_current_network(self):

        try:

            network = get_connected_network()

            self.current_ssid = network["ssid"]


            if not network["ssid"]:

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


        except Exception:

            self.current_ssid = ""

            self.current_network_label.config(
                text="Could not get current Wi-Fi information."
            )


    # ==================================================
    # SCAN WI-FI
    # ==================================================

    def scan_networks(self):

        self.show_wifi_panel()

        self.update_current_network()


        self.status.set(
            "Scanning nearby Wi-Fi..."
        )


        self.root.update_idletasks()


        try:

            self.networks = scan_wifi()


        except Exception as exc:

            self.status.set(
                "Scan failed."
            )

            messagebox.showerror(
                "WiTrust",
                str(exc)
            )

            return


        for item in self.tree.get_children():

            self.tree.delete(item)


        for i, network in enumerate(self.networks):

            assessment = assess_network(
                network
            )


            is_current = (
                network["ssid"] == self.current_ssid
                and self.current_ssid != ""
            )


            display_ssid = (
                f"★ {network['ssid']} [CURRENT]"
                if is_current
                else network["ssid"] or "<Hidden>"
            )


            tags = [assessment["level"]]


            if is_current:

                tags.append("CURRENT")


            self.tree.insert(
                "",
                "end",
                iid=str(i),
                values=(
                    display_ssid,
                    network["authentication"] or "Unknown",
                    network["encryption"] or "Unknown",
                    network["signal"] or "Unknown",
                    f'{assessment["score"]}/100 - '
                    f'{assessment["level"]}'
                ),
                tags=tuple(tags)
            )


        self.status.set(
            f"{len(self.networks)} network(s) found."
        )


        if self.networks:

            first = self.tree.get_children()[0]

            self.tree.selection_set(
                first
            )

            self.tree.focus(
                first
            )

            self.show_selected()


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


        assessment = assess_network(
            network
        )


        level = assessment["level"]

        score = assessment["score"]

        security_status = assessment[
            "security_status"
        ]


        self.risk_summary.config(
            text=(
                f"{level} RISK\n"
                f"{score}/100  •  SECURITY: {security_status}"
            ),
            foreground=self.risk_summary_colors.get(
                level,
                "black"
            )
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
                "• No major risk indicators were detected "
                "by the current rules."
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


        network = self.networks[
            int(selection[0])
        ]


        assessment = assess_network(
            network
        )


        report = self.build_report(
            network,
            assessment
        )


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
            font=("Segoe UI", 20, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 5)
        )


        ttk.Label(
            report_window,
            text="Generated from the selected Wi-Fi network",
            font=("Segoe UI", 10)
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
            font=("Consolas", 10),
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

        safe_name = ssid or "Unknown_Network"


        safe_name = (
            safe_name
            .replace(" ", "_")
            .replace("/", "_")
            .replace("\\", "_")
            .replace(":", "_")
            .replace("*", "_")
            .replace("?", "_")
            .replace('"', "_")
            .replace("<", "_")
            .replace(">", "_")
            .replace("|", "_")
        )


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

        self.status.set(
            "Comparing current network with nearby networks..."
        )

        self.root.update_idletasks()


        try:

            current_network = get_connected_network()

            nearby_networks = scan_wifi()


            result = compare_connected_network(
                current_network,
                nearby_networks
            )


        except Exception as exc:

            self.status.set(
                "Comparison failed."
            )

            messagebox.showerror(
                "WiTrust",
                str(exc)
            )

            return


        self.status.set(
            "Network comparison complete."
        )


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
            font=("Segoe UI", 20, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 5)
        )


        ttk.Label(
            comparison_window,
            text="Comparison between your current network and nearby Wi-Fi networks",
            font=("Segoe UI", 10)
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
            font=("Segoe UI", 11),
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

        self.show_device_panel()


        self.status.set(
            "Checking devices on the local network..."
        )


        self.root.update_idletasks()


        try:

            devices = scan_devices()


        except Exception as exc:

            messagebox.showerror(
                "WiTrust",
                str(exc)
            )


            self.status.set(
                "Device scan failed."
            )


            return


        for item in self.device_tree.get_children():

            self.device_tree.delete(item)


        if not devices:

            messagebox.showinfo(
                "WiTrust",
                "No local devices were found from "
                "the available Windows ARP table."
            )


            self.status.set(
                "No devices found."
            )


            return


        for device in devices:

            self.device_tree.insert(
                "",
                "end",
                values=(
                    device["ip"],
                    device["mac"],
                    device["interface"]
                )
            )


        self.status.set(
            f"{len(devices)} local device(s) found."
        )


        self.risk_summary.pack_forget()


# ==================================================
# START APPLICATION
# ==================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = WiTrustApp(root)

    root.mainloop()