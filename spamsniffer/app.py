from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from spamsniffer.classifier import NaiveBayesSpamClassifier
from spamsniffer.email_sources import parse_email_file, scan_imap_mailbox
from spamsniffer.header_analyzer import analyze_headers
from spamsniffer.storage import ScanLogStore
from spamsniffer.utils import shorten, utc_now_iso


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "spamsniffer" / "data"
DB_PATH = BASE_DIR / "spamsniffer.db"

BG = "#f3f5f7"
PANEL = "#ffffff"
SURFACE = "#e7ebef"
TEXT = "#1f2933"
MUTED = "#5b6773"
ACCENT = "#2f5d7e"
INPUT_BG = "#fbfcfd"


class SpamSnifferApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("SPAMSNIFFER")
        self.root.geometry("1160x780")
        self.root.minsize(980, 700)
        self.root.configure(bg=BG)

        self.classifier = NaiveBayesSpamClassifier(DATA_DIR / "training_corpus.json")
        self.store = ScanLogStore(DB_PATH)

        self.text_subject_var = tk.StringVar()
        self.mail_host_var = tk.StringVar(value="imap.gmail.com")
        self.mail_user_var = tk.StringVar()
        self.mail_pass_var = tk.StringVar()
        self.mailbox_var = tk.StringVar(value="INBOX")
        self.mail_limit_var = tk.StringVar(value="10")
        self.status_var = tk.StringVar(value="Ready")

        self.style = ttk.Style()
        self._configure_styles()
        self._build_ui()
        self.refresh_logs()

    def _configure_styles(self) -> None:
        if "vista" in self.style.theme_names():
            self.style.theme_use("vista")
        elif "clam" in self.style.theme_names():
            self.style.theme_use("clam")

        self.style.configure(".", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        self.style.configure("App.TFrame", background=BG)
        self.style.configure("Panel.TFrame", background=PANEL)
        self.style.configure("Header.TFrame", background=PANEL)
        self.style.configure("Field.TFrame", background=PANEL)
        self.style.configure("Title.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 22, "bold"))
        self.style.configure("Subtitle.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 10))
        self.style.configure("SectionTitle.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 11, "bold"))
        self.style.configure("Body.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 10))
        self.style.configure("Field.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 10))
        self.style.configure(
            "Primary.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 8),
            background=ACCENT,
            foreground="#ffffff",
        )
        self.style.map(
            "Primary.TButton",
            background=[("active", "#3d6f92")],
            foreground=[("disabled", "#7b8794")],
        )
        self.style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 10),
            padding=(12, 8),
            background=SURFACE,
            foreground=TEXT,
        )
        self.style.map(
            "Secondary.TButton",
            background=[("active", "#d9e0e7")],
            foreground=[("active", TEXT)],
        )
        self.style.configure(
            "App.TNotebook",
            background=BG,
            borderwidth=0,
            tabmargins=(0, 0, 0, 0),
        )
        self.style.configure(
            "App.TNotebook.Tab",
            padding=(16, 10),
            font=("Segoe UI", 10, "bold"),
            background=SURFACE,
            foreground=MUTED,
        )
        self.style.map(
            "App.TNotebook.Tab",
            background=[("selected", PANEL), ("active", "#dfe6ed")],
            foreground=[("selected", TEXT), ("active", TEXT)],
        )
        self.style.configure(
            "App.Treeview",
            rowheight=28,
            font=("Segoe UI", 9),
            fieldbackground=PANEL,
            background=PANEL,
            foreground=TEXT,
        )
        self.style.configure("App.Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_ui(self) -> None:
        wrapper = ttk.Frame(self.root, padding=16, style="App.TFrame")
        wrapper.pack(fill="both", expand=True)

        header = ttk.Frame(wrapper, padding=(18, 18, 18, 14), style="Header.TFrame")
        header.pack(fill="x")

        ttk.Label(header, text="SPAMSNIFFER", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Spam detection for pasted text, files, mailbox scans, and email headers.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        status_row = ttk.Frame(header, style="Header.TFrame")
        status_row.pack(fill="x", pady=(12, 0))
        ttk.Label(status_row, text="Status", style="SectionTitle.TLabel").pack(side="left")
        ttk.Label(status_row, textvariable=self.status_var, style="Body.TLabel").pack(side="left", padx=(10, 0))

        notebook = ttk.Notebook(wrapper, style="App.TNotebook")
        notebook.pack(fill="both", expand=True, pady=(14, 0))

        self.text_tab = ttk.Frame(notebook, padding=16, style="Panel.TFrame")
        self.file_tab = ttk.Frame(notebook, padding=16, style="Panel.TFrame")
        self.mail_tab = ttk.Frame(notebook, padding=16, style="Panel.TFrame")
        self.header_tab = ttk.Frame(notebook, padding=16, style="Panel.TFrame")
        self.logs_tab = ttk.Frame(notebook, padding=16, style="Panel.TFrame")

        notebook.add(self.text_tab, text="Text Check")
        notebook.add(self.file_tab, text="File Scan")
        notebook.add(self.mail_tab, text="Mailbox Scan")
        notebook.add(self.header_tab, text="Header Review")
        notebook.add(self.logs_tab, text="Scan Logs")

        self._build_text_tab()
        self._build_file_tab()
        self._build_mail_tab()
        self._build_header_tab()
        self._build_logs_tab()

    def _build_text_tab(self) -> None:
        self.text_tab.columnconfigure(0, weight=3)
        self.text_tab.columnconfigure(1, weight=2)
        self.text_tab.rowconfigure(0, weight=1)

        left = ttk.Frame(self.text_tab, padding=16, style="Panel.TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        right = ttk.Frame(self.text_tab, padding=16, style="Panel.TFrame")
        right.grid(row=0, column=1, sticky="nsew")

        left.columnconfigure(0, weight=1)
        left.rowconfigure(5, weight=1)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(2, weight=1)

        ttk.Label(left, text="Paste Email Text", style="SectionTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(left, text="Add the subject and message body to check whether it looks legitimate.", style="Body.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 14))

        ttk.Label(left, text="Subject", style="Field.TLabel").grid(row=2, column=0, sticky="w")
        subject_entry = ttk.Entry(left, textvariable=self.text_subject_var, width=80)
        subject_entry.grid(row=3, column=0, sticky="ew", pady=(6, 14), ipady=6)

        ttk.Label(left, text="Message Body", style="Field.TLabel").grid(row=4, column=0, sticky="w")
        self.text_input = self._build_text_widget(left, height=14)
        self.text_input.grid(row=5, column=0, sticky="nsew", pady=(6, 0))

        button_row = ttk.Frame(left, style="Panel.TFrame")
        button_row.grid(row=6, column=0, sticky="w", pady=(14, 0))
        self._make_button(button_row, "Start Scan", self.analyze_text, primary=True).pack(side="left")
        self._make_button(button_row, "Clear", self._clear_text_tab, primary=False).pack(side="left", padx=(10, 0))

        ttk.Label(right, text="Analysis Summary", style="SectionTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(right, text="The result panel keeps the verdict easy to scan.", style="Body.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 14))
        self.text_result = self._build_text_widget(right, height=18, readonly=True)
        self.text_result.grid(row=2, column=0, sticky="nsew")

    def _build_file_tab(self) -> None:
        top = ttk.Frame(self.file_tab, style="Panel.TFrame")
        top.pack(fill="x")
        ttk.Label(top, text="Import Email Content", style="SectionTitle.TLabel").pack(anchor="w")
        ttk.Label(
            top,
            text="Supported formats: .txt, .log, .eml, .csv, .json",
            style="Body.TLabel",
        ).pack(anchor="w", pady=(4, 12))
        self._make_button(top, "Choose File", self.scan_file, primary=True).pack(anchor="w")

        self.file_result = self._build_text_widget(self.file_tab, height=30, readonly=True)
        self.file_result.pack(fill="both", expand=True, pady=(16, 0))

    def _build_mail_tab(self) -> None:
        self.mail_tab.columnconfigure(0, weight=2)
        self.mail_tab.columnconfigure(1, weight=3)
        self.mail_tab.rowconfigure(0, weight=1)

        form_panel = ttk.Frame(self.mail_tab, padding=16, style="Panel.TFrame")
        form_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        result_panel = ttk.Frame(self.mail_tab, padding=16, style="Panel.TFrame")
        result_panel.grid(row=0, column=1, sticky="nsew")

        ttk.Label(form_panel, text="Connect Mailbox", style="SectionTitle.TLabel").pack(anchor="w")
        ttk.Label(
            form_panel,
            text="Use IMAP details and an app password where your provider requires one.",
            style="Body.TLabel",
        ).pack(anchor="w", pady=(4, 14))

        fields = [
            ("IMAP Host", self.mail_host_var, False),
            ("Email Address", self.mail_user_var, False),
            ("App Password", self.mail_pass_var, True),
            ("Mailbox", self.mailbox_var, False),
            ("Recent Emails", self.mail_limit_var, False),
        ]
        for label_text, variable, secret in fields:
            field = ttk.Frame(form_panel, style="Field.TFrame")
            field.pack(fill="x", pady=(0, 12))
            ttk.Label(field, text=label_text, style="Field.TLabel").pack(anchor="w")
            entry = ttk.Entry(field, textvariable=variable)
            if secret:
                entry.configure(show="*")
            entry.pack(fill="x", pady=(6, 0))

        self._make_button(form_panel, "Scan Mailbox", self.scan_mailbox, primary=True).pack(anchor="w", pady=(4, 0))

        ttk.Label(result_panel, text="Mailbox Results", style="SectionTitle.TLabel").pack(anchor="w")
        ttk.Label(result_panel, text="Recent messages and likely spam hits will appear here.", style="Body.TLabel").pack(anchor="w", pady=(4, 14))
        self.mail_result = self._build_text_widget(result_panel, height=28, readonly=True)
        self.mail_result.pack(fill="both", expand=True)

    def _build_header_tab(self) -> None:
        self.header_tab.columnconfigure(0, weight=3)
        self.header_tab.columnconfigure(1, weight=2)
        self.header_tab.rowconfigure(0, weight=1)

        left = ttk.Frame(self.header_tab, padding=16, style="Panel.TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        right = ttk.Frame(self.header_tab, padding=16, style="Panel.TFrame")
        right.grid(row=0, column=1, sticky="nsew")

        left.columnconfigure(0, weight=1)
        left.rowconfigure(2, weight=1)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(2, weight=1)

        ttk.Label(left, text="Raw Header Review", style="SectionTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(left, text="Paste full email headers to check legitimacy signals such as SPF, DKIM, and DMARC.", style="Body.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 14))
        self.header_input = self._build_text_widget(left, height=26)
        self.header_input.grid(row=2, column=0, sticky="nsew")
        self._make_button(left, "Inspect Headers", self.inspect_headers, primary=True).grid(row=3, column=0, sticky="w", pady=(14, 0))

        ttk.Label(right, text="Header Findings", style="SectionTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(right, text="Risk notes and classifier output are summarized here.", style="Body.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 14))
        self.header_result = self._build_text_widget(right, height=28, readonly=True)
        self.header_result.grid(row=2, column=0, sticky="nsew")

    def _build_logs_tab(self) -> None:
        top = ttk.Frame(self.logs_tab, style="Panel.TFrame")
        top.pack(fill="x")
        ttk.Label(top, text="Recent Scan Activity", style="SectionTitle.TLabel").pack(anchor="w")
        ttk.Label(top, text="SQLite-backed history of recent checks.", style="Body.TLabel").pack(anchor="w", pady=(4, 12))
        self._make_button(top, "Refresh Logs", self.refresh_logs, primary=False).pack(anchor="w")

        columns = ("time", "type", "name", "label", "legit", "spam", "confidence", "notes")
        self.logs_tree = ttk.Treeview(self.logs_tab, columns=columns, show="headings", height=18, style="App.Treeview")
        headings = {
            "time": "Scanned At",
            "type": "Source",
            "name": "Name",
            "label": "Verdict",
            "legit": "Legit %",
            "spam": "Spam %",
            "confidence": "Confidence",
            "notes": "Notes",
        }
        widths = {
            "time": 170,
            "type": 90,
            "name": 220,
            "label": 90,
            "legit": 80,
            "spam": 80,
            "confidence": 90,
            "notes": 300,
        }
        for key in columns:
            self.logs_tree.heading(key, text=headings[key])
            self.logs_tree.column(key, width=widths[key], anchor="w")
        self.logs_tree.pack(fill="both", expand=True, pady=(16, 0))

    def _build_text_widget(self, parent: ttk.Frame, height: int, readonly: bool = False) -> tk.Text:
        widget = tk.Text(
            parent,
            height=height,
            wrap="word",
            bg=INPUT_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            bd=0,
            padx=12,
            pady=12,
            font=("Consolas", 10) if readonly else ("Segoe UI", 10),
            spacing1=2,
            spacing3=4,
        )
        if readonly:
            widget.configure(state="disabled")
        return widget

    def _make_button(self, parent, text: str, command, primary: bool = True) -> tk.Button:
        if primary:
            return tk.Button(
                parent,
                text=text,
                command=command,
                bg="#d7dee7",
                fg="#000000",
                activebackground="#c6d0db",
                activeforeground="#000000",
                relief="solid",
                bd=1,
                padx=16,
                pady=8,
                font=("Segoe UI", 10, "bold"),
            )
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg="#f2f4f7",
            fg="#000000",
            activebackground="#e3e8ee",
            activeforeground="#000000",
            relief="solid",
            bd=1,
            padx=14,
            pady=8,
            font=("Segoe UI", 10),
        )

    def _set_text_widget(self, widget: tk.Text, content: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def _set_status(self, message: str) -> None:
        self.status_var.set(message)

    def analyze_text(self) -> None:
        subject = self.text_subject_var.get().strip()
        body = self.text_input.get("1.0", "end").strip()
        result = self.classifier.classify(subject=subject, body=body)
        self._write_text_result(result)
        self._log_result(
            source_type="text",
            source_name="Manual Text",
            result=result,
            notes="Text tab analysis",
        )
        self.refresh_logs()
        self._set_status(f"Text analyzed: {result.label.upper()} with {result.legit_probability}% legit probability.")

    def scan_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Choose a file",
            filetypes=[
                ("Supported files", "*.txt *.log *.eml *.csv *.json"),
                ("All files", "*.*"),
            ],
        )
        if not file_path:
            return
        path = Path(file_path)
        try:
            items = parse_email_file(path)
        except Exception as exc:
            messagebox.showerror("File Scan Error", str(exc))
            return

        lines = [f"File: {path.name}", f"Detected items: {len(items)}", ""]
        for item in items:
            header_report = analyze_headers(item.headers_text) if item.headers_text else None
            penalty = header_report.header_penalty if header_report else 0.0
            result = self.classifier.classify(
                subject=item.subject,
                body=item.body,
                headers_text=item.headers_text,
                header_penalty=penalty,
            )
            lines.extend(self._format_result_block(item.source_name, result, item.subject, header_report))
            self._log_result(
                source_type="file",
                source_name=item.source_name,
                result=result,
                notes=f"Imported from {path.name}",
            )
        self._set_text_widget(self.file_result, "\n".join(lines))
        self.refresh_logs()
        self._set_status(f"Scanned file: {path.name}")

    def scan_mailbox(self) -> None:
        host = self.mail_host_var.get().strip()
        email_address = self.mail_user_var.get().strip()
        password = self.mail_pass_var.get()
        mailbox = self.mailbox_var.get().strip() or "INBOX"
        try:
            limit = int(self.mail_limit_var.get().strip() or "10")
        except ValueError:
            messagebox.showerror("Invalid Limit", "Recent Emails must be a number.")
            return

        try:
            items = scan_imap_mailbox(
                host=host,
                email_address=email_address,
                password=password,
                mailbox=mailbox,
                limit=max(1, min(limit, 50)),
            )
        except Exception as exc:
            messagebox.showerror("Mailbox Scan Error", str(exc))
            return

        spam_hits = 0
        lines = [f"Mailbox: {mailbox}", f"Messages scanned: {len(items)}", ""]
        for item in items:
            header_report = analyze_headers(item.headers_text)
            result = self.classifier.classify(
                subject=item.subject,
                body=item.body,
                headers_text=item.headers_text,
                header_penalty=header_report.header_penalty,
            )
            if result.label == "spam":
                spam_hits += 1
            lines.extend(
                self._format_result_block(
                    item.source_name,
                    result,
                    item.subject,
                    header_report,
                    sender=item.sender,
                )
            )
            self._log_result(
                source_type="mailbox",
                source_name=item.source_name,
                result=result,
                notes=f"Sender: {item.sender}",
            )
        lines.insert(2, f"Spam-like messages found: {spam_hits}")
        self._set_text_widget(self.mail_result, "\n".join(lines))
        self.refresh_logs()
        self._set_status(f"Mailbox scan complete: {spam_hits} spam-like messages found.")

    def inspect_headers(self) -> None:
        headers_text = self.header_input.get("1.0", "end").strip()
        report = analyze_headers(headers_text)
        result = self.classifier.classify(headers_text=headers_text, header_penalty=report.header_penalty)
        lines = [
            f"Header Verdict: {report.verdict}",
            f"Header Risk Score: {report.risk_score}",
            f"Classifier Verdict: {result.label.upper()}",
            f"Legit Probability: {result.legit_probability}%",
            f"Spam Probability: {result.spam_probability}%",
            "",
            "Findings:",
        ]
        for finding in report.findings:
            lines.append(f"- {finding}")
        lines.append("")
        lines.append("Classifier Notes:")
        for reason in result.reasons:
            lines.append(f"- {reason}")
        self._set_text_widget(self.header_result, "\n".join(lines))
        self._log_result(
            source_type="headers",
            source_name="Manual Header Review",
            result=result,
            notes=report.verdict,
        )
        self.refresh_logs()
        self._set_status(f"Header review complete: {report.verdict}.")

    def refresh_logs(self) -> None:
        for item in self.logs_tree.get_children():
            self.logs_tree.delete(item)
        for row in self.store.recent_scans():
            self.logs_tree.insert("", "end", values=row)

    def _clear_text_tab(self) -> None:
        self.text_subject_var.set("")
        self.text_input.delete("1.0", "end")
        self._set_text_widget(self.text_result, "")
        self._set_status("Text input cleared.")

    def _write_text_result(self, result) -> None:
        tone = self._result_tone(result.label)
        lines = [
            f"Verdict: {result.label.upper()}",
            f"Legit Probability: {result.legit_probability}%",
            f"Spam Probability: {result.spam_probability}%",
            f"Confidence Gap: {result.confidence}",
            f"Tokens Checked: {result.tokens_checked}",
            f"Risk Tone: {tone}",
            "",
            "Why:",
        ]
        for reason in result.reasons:
            lines.append(f"- {reason}")
        self._set_text_widget(self.text_result, "\n".join(lines))

    def _format_result_block(self, name, result, subject, header_report=None, sender="") -> list[str]:
        lines = [
            f"[{name}]",
            f"Subject: {subject or '(no subject)'}",
        ]
        if sender:
            lines.append(f"From: {sender}")
        lines.extend(
            [
                f"Verdict: {result.label.upper()}",
                f"Legit Probability: {result.legit_probability}%",
                f"Spam Probability: {result.spam_probability}%",
                f"Confidence Gap: {result.confidence}",
                f"Risk Tone: {self._result_tone(result.label)}",
            ]
        )
        if header_report:
            lines.append(f"Header Verdict: {header_report.verdict} (risk {header_report.risk_score})")
        for reason in result.reasons:
            lines.append(f"- {reason}")
        lines.append("")
        return lines

    def _result_tone(self, label: str) -> str:
        if label == "spam":
            return "Elevated"
        if label == "legit":
            return "Calm"
        return "Neutral"

    def _log_result(self, source_type: str, source_name: str, result, notes: str) -> None:
        self.store.log_scan(
            scanned_at=utc_now_iso(),
            source_type=source_type,
            source_name=source_name,
            label=result.label,
            legit_probability=result.legit_probability,
            spam_probability=result.spam_probability,
            confidence=result.confidence,
            notes=shorten(notes),
        )


def main() -> None:
    root = tk.Tk()
    SpamSnifferApp(root)
    root.mainloop()
