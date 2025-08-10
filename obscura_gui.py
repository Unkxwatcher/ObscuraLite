# obscura_gui.py
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import scrolledtext
import threading
import time
import platform
import subprocess
import os
import json
from datetime import datetime
from collections import deque

# optional modules
try:
    from scapy.all import sniff, TCP, Raw, IP  # scapy for packet analysis
    SCAPY_AVAILABLE = True
except Exception:
    sniff = None
    TCP = Raw = IP = None
    SCAPY_AVAILABLE = False

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except Exception:
    geoip2 = None
    GEOIP_AVAILABLE = False

try:
    from network_monitor import NetworkMonitor
except Exception:
    NetworkMonitor = None

try:
    import incognito
except Exception:
    incognito = None

try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    psutil = None
    PSUTIL_AVAILABLE = False

# Configs
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
LOG_PATH = os.path.join(DATA_DIR, "obscura_gui.log")
BLOCKED_IPS_FILE = os.path.join(DATA_DIR, "blocked_ips.json")
EXPORT_FILE = os.path.join(DATA_DIR, "suspicious_export.json")
LABELED_FILE = os.path.join(DATA_DIR, "obscura_labeled.json")
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), "GeoLite2-City.mmdb")
ICON_PATH = os.path.join(os.path.dirname(__file__), "icon.ico")

os.makedirs(DATA_DIR, exist_ok=True)

# UI colors
BG = "#121212"
FG = "#e0e0e0"
TREE_ALT_BG = "#1c1c1c"
LOG_BG = "#111111"
LOG_FG = "#e6e6e6"
TEXT_BG = "#1b1b1b"
TEXT_FG = "#eee"

# Threat display mapping
THREAT_DISPLAY = {
    "low": ("LOW", "#9e9e9e"),
    "medium": ("MEDIUM", "#ffb74d"),
    "high": ("HIGH", "#e57373"),
    "critical": ("CRITICAL", "#ef5350")
}

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def write_log_file(line: str):
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# --- R.U.D.Y. Analyzer (basic) ---
class RudyAnalyzer:
    """
    Basic R.U.D.Y. (slow POST) detection using packet sniffing.
    - Tracks connections that begin with HTTP POST and monitors duration/data size.
    - Emits events when a connection exceeds slow_threshold_sec but has small data length.
    Degrades gracefully if scapy not available.
    """
    def __init__(self, iface=None, port=80, slow_threshold_sec=25, min_data_bytes=2048, event_max=1000):
        self.iface = iface
        self.port = port
        self.slow_threshold_sec = slow_threshold_sec
        self.min_data_bytes = min_data_bytes
        self.connections = {}  # conn_id -> {start,last,data_len,ip,...}
        self.lock = threading.Lock()
        self.events = deque(maxlen=event_max)
        self.running = False
        self.thread = None

    def start(self):
        if not SCAPY_AVAILABLE:
            return
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    def _sniff_loop(self):
        try:
            sniff(filter=f"tcp port {self.port}", prn=self._packet_callback, store=False, iface=self.iface, stop_filter=lambda x: not self.running)
        except Exception:
            # sniff might require admin/pcap driver; just stop gracefully
            self.running = False

    def _packet_callback(self, pkt):
        try:
            if not pkt.haslayer(TCP):
                return
            tcp = pkt[TCP]
            ip = pkt[IP]
            conn_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
            nowt = time.time()
            with self.lock:
                if pkt.haslayer(Raw):
                    raw = pkt[Raw].load
                    # detect start of POST
                    # Note: HTTP may be chunked/fragmented; this heuristic catches common cases
                    if raw.startswith(b"POST ") or b"\r\nContent-Length:" in raw[:200].lower():
                        # start tracking
                        self.connections[conn_id] = {
                            "start": nowt,
                            "last": nowt,
                            "data_len": len(raw),
                            "ip": ip.src,
                            "status": "open"
                        }
                    else:
                        info = self.connections.get(conn_id)
                        if info:
                            info["last"] = nowt
                            info["data_len"] += len(raw)
                            duration = nowt - info["start"]
                            if duration > self.slow_threshold_sec and info["data_len"] < self.min_data_bytes:
                                if info["status"] != "rudy":
                                    info["status"] = "rudy"
                                    ev = {
                                        "ip": info["ip"],
                                        "duration_sec": round(duration, 1),
                                        "data_len": info["data_len"],
                                        "timestamp": nowt,
                                        "type": "rudy",
                                        "desc": f"Slow POST suspected: {round(duration,1)}s, {info['data_len']} bytes"
                                    }
                                    self.events.append(ev)
                else:
                    # If no Raw payload, just update last
                    if conn_id in self.connections:
                        self.connections[conn_id]["last"] = nowt

                # cleanup stale
                stale = []
                for k, v in list(self.connections.items()):
                    if nowt - v["last"] > 60:
                        stale.append(k)
                for k in stale:
                    try:
                        del self.connections[k]
                    except KeyError:
                        pass
        except Exception:
            pass

    def get_events(self):
        with self.lock:
            evs = list(self.events)
            self.events.clear()
        return evs

# --- Main GUI class ---
class ObscuraGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Obscura Watch — Obscura")
        # keep your geometry values
        self.root.geometry("1400x720")
        self.root.minsize(1600, 720)
        self.root.configure(bg=BG)

        try:
            if os.path.exists(ICON_PATH):
                self.root.iconbitmap(ICON_PATH)
        except Exception:
            pass

        # load blocked IPs
        self.blocked_ips = self.load_blocked_ips()

        # states
        self.incognito_active = False
        self.suspended = False
        self.suspicious_map = {}

        # flags/messages to show after UI created
        self.startup_messages = []

        # init geo reader if available (but do not call UI logging now)
        self.geo_reader = None
        if GEOIP_AVAILABLE:
            try:
                if os.path.exists(GEOIP_DB_PATH):
                    self.geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
                    self.startup_messages.append(("INFO", f"GeoIP DB loaded: {GEOIP_DB_PATH}"))
                else:
                    self.startup_messages.append(("WARN", "GeoIP DB not found at " + GEOIP_DB_PATH))
            except Exception as e:
                self.geo_reader = None
                self.startup_messages.append(("WARN", f"GeoIP load error: {e}"))
        else:
            self.startup_messages.append(("WARN", "geoip2 not installed; GeoIP disabled"))

        # NetworkMonitor optional
        self.netmon = None
        if NetworkMonitor is not None:
            try:
                self.netmon = NetworkMonitor()
                self.startup_messages.append(("INFO", "NetworkMonitor loaded"))
            except Exception as e:
                self.netmon = None
                self.startup_messages.append(("WARN", f"NetworkMonitor init error: {e}"))
        else:
            self.startup_messages.append(("WARN", "network_monitor module not available"))

        # RUDY analyzer
        self.rudy = RudyAnalyzer() if SCAPY_AVAILABLE else None
        if self.rudy is None:
            self.startup_messages.append(("WARN", "scapy not available; packet analysis disabled"))
        else:
            # will start after UI creation
            self.startup_messages.append(("INFO", "R.U.D.Y. analyzer ready (scapy available)"))

        # build UI
        self.create_widgets()

        # now log startup messages (safe because widgets created)
        for lvl, msg in self.startup_messages:
            if lvl == "INFO":
                self._log(msg, "INFO")
            else:
                self._log(msg, lvl)

        # start rudy if available
        if self.rudy:
            try:
                self.rudy.start()
                self._log("R.U.D.Y. analyzer started", "INFO")
            except Exception as e:
                self._log(f"Failed to start R.U.D.Y. analyzer: {e}", "WARN")

        # start monitor thread
        self.stop_event = threading.Event()
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()

        # start UI update for rudy events
        self.root.after(2000, self.update_rudy_events_ui)

    def create_widgets(self):
        # Styles
        style = ttk.Style(self.root)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure(".", background=BG, foreground=FG, fieldbackground=BG)
        style.configure("Treeview", background=TREE_ALT_BG, foreground=FG, fieldbackground=TREE_ALT_BG)
        style.map("Treeview", background=[('selected', '#005f5f')], foreground=[('selected', '#ffffff')])
        style.configure("TButton", background="#222222", foreground=FG)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("TEntry", fieldbackground=TEXT_BG, foreground=TEXT_FG)

        # layout
        self.root.columnconfigure(0, weight=3)
        self.root.columnconfigure(1, weight=2)
        self.root.rowconfigure(0, weight=8)
        self.root.rowconfigure(1, weight=2)

        # Left frame: suspicious connections
        left = ttk.Frame(self.root)
        left.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        ttk.Label(left, text="Подозрительные подключения", font=("Consolas", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0,6))

        cols = ("ip", "port", "process", "pid", "status", "country", "threat")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse", height=18)
        for col in cols:
            self.tree.heading(col, text=col.capitalize())
        self.tree.column("ip", width=160, anchor="w")
        self.tree.column("port", width=60, anchor="center")
        self.tree.column("process", width=180, anchor="w")
        self.tree.column("pid", width=60, anchor="center")
        self.tree.column("status", width=90, anchor="center")
        self.tree.column("country", width=140, anchor="center")
        self.tree.column("threat", width=80, anchor="center")
        self.tree.grid(row=1, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        vsb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.grid(row=1, column=1, sticky="ns")

        # Right frame: details and controls
        right = ttk.Frame(self.root)
        right.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        ttk.Label(right, text="Детали и управление", font=("Consolas", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0,6))

        self.details = tk.Text(right, height=12, bg=TEXT_BG, fg=TEXT_FG, insertbackground=FG, font=("Consolas", 11))
        self.details.grid(row=1, column=0, sticky="nsew", pady=(0,6))
        self.details.configure(state="disabled", wrap="word")

        ctrl = ttk.Frame(right)
        ctrl.grid(row=2, column=0, sticky="ew", pady=(6,0))
        ctrl.columnconfigure(1, weight=1)

        ttk.Label(ctrl, text="Selected IP:", font=("Consolas", 10)).grid(row=0, column=0, sticky="w", padx=(0,6))
        self.sel_ip_var = tk.StringVar()
        self.sel_ip_entry = ttk.Entry(ctrl, textvariable=self.sel_ip_var, font=("Consolas", 11))
        self.sel_ip_entry.grid(row=0, column=1, sticky="ew", padx=(0,6))

        self.btn_block = ttk.Button(ctrl, text="Блокировать IP", command=self.on_block_ip)
        self.btn_block.grid(row=0, column=2, sticky="e", padx=(0,4))
        self.btn_unblock = ttk.Button(ctrl, text="Разблокировать IP", command=self.on_unblock_ip)
        self.btn_unblock.grid(row=0, column=3, sticky="e")

        ctrl2 = ttk.Frame(right)
        ctrl2.grid(row=3, column=0, sticky="ew", pady=(8,0))
        ctrl2.columnconfigure(1, weight=1)

        self.incognito_btn = ttk.Button(ctrl2, text="Включить Incognito", command=self.toggle_incognito)
        self.incognito_btn.grid(row=0, column=0, sticky="w")

        self.auto_clear_var = tk.BooleanVar(value=False)
        self.auto_clear_chk = ttk.Checkbutton(ctrl2, text="Авто-очистка логов при Incognito", variable=self.auto_clear_var)
        self.auto_clear_chk.grid(row=0, column=1, sticky="w", padx=(8,0))

        self.export_btn = ttk.Button(ctrl2, text="Экспорт подозрительных", command=self.on_export)
        self.export_btn.grid(row=0, column=2, sticky="w", padx=(8,0))

        self.show_hidden_info = ttk.Label(ctrl2, text="", font=("Consolas", 9, "italic"))
        self.show_hidden_info.grid(row=1, column=0, columnspan=3, sticky="w", pady=(6,0))

        # Bottom: log + blocked label + R.U.D.Y panel
        bottom = ttk.Frame(self.root)
        bottom.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=8, pady=(0,8))
        bottom.rowconfigure(0, weight=1)
        bottom.columnconfigure(0, weight=3)
        bottom.columnconfigure(1, weight=2)

        self.log_widget = scrolledtext.ScrolledText(bottom, height=8, bg=LOG_BG, fg=LOG_FG, font=("Consolas", 10))
        self.log_widget.grid(row=0, column=0, sticky="nsew")
        self.log_widget.configure(state="disabled")

        right_bottom = ttk.Frame(bottom)
        right_bottom.grid(row=0, column=1, sticky="nsew", padx=(8,0))
        right_bottom.rowconfigure(1, weight=1)
        right_bottom.columnconfigure(0, weight=1)

        ttk.Label(right_bottom, text="R.U.D.Y. события", font=("Consolas", 11, "bold")).grid(row=0, column=0, sticky="w")
        rudy_cols = ("time", "ip", "duration", "bytes", "desc")
        self.rudy_tree = ttk.Treeview(right_bottom, columns=rudy_cols, show="headings", height=6)
        for c in rudy_cols:
            self.rudy_tree.heading(c, text=c.capitalize())
        self.rudy_tree.column("time", width=90, anchor="center")
        self.rudy_tree.column("ip", width=110, anchor="w")
        self.rudy_tree.column("duration", width=80, anchor="center")
        self.rudy_tree.column("bytes", width=80, anchor="center")
        self.rudy_tree.column("desc", width=220, anchor="w")
        self.rudy_tree.grid(row=1, column=0, sticky="nsew")
        vsb_r = ttk.Scrollbar(right_bottom, orient="vertical", command=self.rudy_tree.yview)
        self.rudy_tree.configure(yscrollcommand=vsb_r.set)
        vsb_r.grid(row=1, column=1, sticky="ns")

        self.blocked_label = ttk.Label(bottom, text=f"Заблокированные IP: {', '.join(sorted(self.blocked_ips))}")
        self.blocked_label.grid(row=1, column=0, sticky="w", pady=(4,0))

        # initial note
        self._log("Obscura Watch initialized.", "INFO")

    # logging
    def _log(self, text: str, level: str = "INFO"):
        line = f"{now_ts()} [{level}] {text}"
        def append():
            try:
                self.log_widget.configure(state="normal")
                self.log_widget.insert("end", line + "\n")
                self.log_widget.see("end")
                self.log_widget.configure(state="disabled")
            except Exception:
                pass
        try:
            self.root.after(0, append)
        except Exception:
            # fallback
            pass
        write_log_file(line)

    def _log_internal(self, text, level="INFO"):
        write_log_file(f"{now_ts()} [{level}] {text}")

    # monitoring loop
    def monitor_loop(self):
        while not getattr(self, "stop_event", threading.Event()).is_set():
            if self.suspended:
                time.sleep(1)
                continue
            try:
                new_map = {}
                if self.netmon:
                    try:
                        conns = self.netmon.scan_connections()
                        for c in conns:
                            ip = c.get("remote_addr")
                            if not ip:
                                continue
                            new_map[ip] = {
                                "ip": ip,
                                "port": c.get("remote_port"),
                                "process": c.get("process_name", "Unknown"),
                                "pid": c.get("pid", 0),
                                "status": c.get("status", ""),
                            }
                    except Exception as e:
                        self._log(f"Ошибка при использовании NetworkMonitor: {e}", "ERROR")
                        new_map = self._fallback_scan()
                else:
                    new_map = self._fallback_scan()

                # enrich with geo and threat
                for ip, info in new_map.items():
                    info["country"] = self.get_country(ip)
                    info["threat_score"] = self.calc_threat_score(info)

                if new_map != self.suspicious_map:
                    self.suspicious_map = new_map
                    self.root.after(0, self.refresh_treeview)
                    self._log(f"Обнаружено подозрительных IP: {len(self.suspicious_map)}", "INFO")
            except Exception as e:
                self._log(f"Ошибка мониторинга: {e}", "ERROR")

            for _ in range(3):
                if getattr(self, "stop_event", threading.Event()).is_set():
                    break
                time.sleep(1)

    def _fallback_scan(self):
        new_map = {}
        if not PSUTIL_AVAILABLE:
            self._log("psutil not available: fallback scan disabled", "WARN")
            return new_map
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                if not c.raddr:
                    continue
                ip = c.raddr.ip
                pid = c.pid or 0
                try:
                    proc_name = psutil.Process(pid).name() if pid else "Unknown"
                except Exception:
                    proc_name = "Unknown"
                new_map[ip] = {
                    "ip": ip,
                    "port": c.raddr.port if c.raddr else None,
                    "process": proc_name,
                    "pid": pid,
                    "status": c.status
                }
        except Exception as e:
            self._log(f"Fallback scan error: {e}", "ERROR")
        return new_map

    # geo
    def get_country(self, ip):
        if not GEOIP_AVAILABLE or not self.geo_reader:
            return "N/A"
        try:
            resp = self.geo_reader.city(ip)
            return resp.country.names.get("en") or resp.country.name or "Unknown"
        except Exception:
            return "Unknown"

    # threat scoring
    def calc_threat_score(self, info):
        score = 0
        proc = (info.get("process") or "").lower()
        status = (info.get("status") or "").upper()
        port = info.get("port") or 0
        ip = info.get("ip")

        suspicious_procs = ["cmd.exe", "powershell.exe", "nc.exe", "netcat", "python", "perl", "java", "node"]
        if any(sp in proc for sp in suspicious_procs):
            score += 3
        if status in ["TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "SYN_SENT"]:
            score += 2
        # low ports usage might be system services; suspicious when paired with suspicious process
        if port and 0 < port < 1024 and "unk" in proc:
            score += 1
        if ip in self.blocked_ips:
            score += 4

        # Normalize to categories:
        # 0-2: low, 3-5: medium, 6-8: high, 9+: critical
        return min(score, 10)

    def refresh_treeview(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for ip, info in self.suspicious_map.items():
            port = info.get("port") or ""
            proc = info.get("process") or ""
            pid = info.get("pid") or ""
            status = info.get("status") or ""
            country = info.get("country") or ""
            threat_score = info.get("threat_score", 0)
            # map score to label
            if threat_score >= 9:
                threat_label, color = THREAT_DISPLAY["critical"]
            elif threat_score >= 6:
                threat_label, color = THREAT_DISPLAY["high"]
            elif threat_score >= 3:
                threat_label, color = THREAT_DISPLAY["medium"]
            else:
                threat_label, color = THREAT_DISPLAY["low"]

            row_id = self.tree.insert("", "end", values=(ip, port, proc, pid, status, country, threat_label))
            # tags for styling
            if ip in self.blocked_ips:
                self.tree.item(row_id, tags=("blocked",))
            else:
                tag = f"threat_{threat_label.lower()}"
                self.tree.item(row_id, tags=(tag,))
                self.tree.tag_configure(tag, foreground=color)

        self.tree.tag_configure("blocked", background="#002233", foreground="#ffffff")
        self.blocked_label.config(text=f"Заблокированные IP: {', '.join(sorted(self.blocked_ips))}")

    def on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        ip = vals[0]
        self.sel_ip_var.set(ip)
        info = self.suspicious_map.get(ip, {})
        lines = [
            f"IP: {ip}",
            f"Process: {info.get('process', '-')}",
            f"PID: {info.get('pid', '-')}",
            f"Status: {info.get('status', '-')}",
            f"Country: {info.get('country', '-')}",
            f"Threat Score: {info.get('threat_score', 0)}",
            f"Blocked: {'YES' if ip in self.blocked_ips else 'NO'}"
        ]
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("end", "\n".join(lines))
        self.details.configure(state="disabled")

    # block/unblock
    def on_block_ip(self):
        ip = self.sel_ip_var.get().strip()
        if not ip:
            messagebox.showinfo("Обскура", "Выберите IP для блокировки.")
            return
        if ip in self.blocked_ips:
            messagebox.showinfo("Обскура", f"IP {ip} уже заблокирован.")
            return
        if self.block_ip(ip):
            self.blocked_ips.add(ip)
            self.save_blocked_ips()
            self._log(f"IP {ip} заблокирован.", "ACTION")
            self.refresh_treeview()
            self.on_tree_select(None)
        else:
            messagebox.showerror("Обскура", f"Не удалось заблокировать IP {ip}.")

    def on_unblock_ip(self):
        ip = self.sel_ip_var.get().strip()
        if not ip:
            messagebox.showinfo("Обскура", "Выберите IP для разблокировки.")
            return
        if ip not in self.blocked_ips:
            messagebox.showinfo("Обскура", f"IP {ip} не заблокирован.")
            return
        if self.unblock_ip(ip):
            self.blocked_ips.discard(ip)
            self.save_blocked_ips()
            self._log(f"IP {ip} разблокирован.", "ACTION")
            self.refresh_treeview()
            self.on_tree_select(None)
        else:
            messagebox.showerror("Обскура", f"Не удалось разблокировать IP {ip}.")

    def block_ip(self, ip):
        if platform.system() != "Windows":
            self._log("Блокировка IP доступна только под Windows.", "WARN")
            return False
        rule_name = f"Obscura_Block_{ip}"
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip}'
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            return proc.returncode == 0
        except Exception as e:
            self._log(f"Exception block_ip: {e}", "ERROR")
            return False

    def unblock_ip(self, ip):
        if platform.system() != "Windows":
            self._log("Разблокировка IP доступна только под Windows.", "WARN")
            return False
        rule_name = f"Obscura_Block_{ip}"
        cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            # Accept either localized or english output
            out = (proc.stdout or "").lower()
            if proc.returncode == 0 and ("deleted" in out or "удал" in out or "success" in out):
                return True
            return proc.returncode == 0
        except Exception as e:
            self._log(f"Exception unblock_ip: {e}", "ERROR")
            return False

    # blocked ips persistence
    def load_blocked_ips(self):
        if os.path.exists(BLOCKED_IPS_FILE):
            try:
                with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return set(data)
            except Exception:
                pass
        return set()

    def save_blocked_ips(self):
        try:
            with open(BLOCKED_IPS_FILE, "w", encoding="utf-8") as f:
                json.dump(list(self.blocked_ips), f, indent=2)
        except Exception as e:
            self._log(f"Не удалось сохранить список заблокированных IP: {e}", "ERROR")

    # export suspicious data
    def export_suspicious_data(self, filepath=EXPORT_FILE):
        try:
            data = []
            ts = now_ts()
            for ip, info in self.suspicious_map.items():
                data.append({
                    "timestamp": ts,
                    "ip": ip,
                    "port": info.get("port"),
                    "process": info.get("process"),
                    "pid": info.get("pid"),
                    "status": info.get("status"),
                    "country": info.get("country"),
                    "threat_score": info.get("threat_score", 0)
                })
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self._log(f"Экспортировано {len(data)} подозрительных записей в {filepath}", "INFO")
            return True
        except Exception as e:
            self._log(f"Ошибка экспорта подозрительных данных: {e}", "ERROR")
            return False

    def on_export(self):
        ok = self.export_suspicious_data()
        if ok:
            messagebox.showinfo("Обскура", f"Данные экспортированы в {EXPORT_FILE}")
        else:
            messagebox.showerror("Обскура", "Ошибка при экспорте данных. Смотри лог.")

    # R.U.D.Y. UI updater
    def update_rudy_events_ui(self):
        if self.rudy:
            events = self.rudy.get_events()
            for ev in events:
                t = time.strftime("%H:%M:%S", time.localtime(ev["timestamp"]))
                ip = ev["ip"]
                dur = f"{ev['duration_sec']}s"
                b = ev["data_len"]
                desc = ev.get("desc", "")
                self.rudy_tree.insert("", "end", values=(t, ip, dur, b, desc))
                self._log(f"R.U.D.Y. suspected from {ip}: {desc}", "WARN")
        # schedule next
        try:
            self.root.after(2500, self.update_rudy_events_ui)
        except Exception:
            pass

    # Incognito
    def toggle_incognito(self):
        if incognito is None:
            messagebox.showerror("Обскура", "Модуль incognito не найден.")
            return
        if not self.incognito_active:
            confirm = messagebox.askyesno("Incognito", "Включить Incognito? Мониторинг будет приостановлен, и (по опции) логи очищены.")
            if not confirm:
                return
            try:
                if hasattr(incognito, "start_incognito"):
                    incognito.start_incognito()
                self.incognito_active = True
                self.suspended = True
                if self.auto_clear_var.get():
                    self.clear_logs()
                self.incognito_btn.config(text="Выключить Incognito")
                self._log("Incognito: включён. Мониторинг приостановлен.", "SEC")
                self.tree.delete(*self.tree.get_children())
                self.details.configure(state="normal")
                self.details.delete("1.0", "end")
                self.details.insert("end", "Incognito active — данные скрыты.")
                self.details.configure(state="disabled")
                self.show_hidden_info.config(text="Incognito: активен — мониторинг скрыт")
            except Exception as e:
                self._log(f"Ошибка включения Incognito: {e}", "ERROR")
                messagebox.showerror("Обскура", f"Ошибка включения Incognito:\n{e}")
        else:
            try:
                if hasattr(incognito, "stop_incognito"):
                    incognito.stop_incognito()
                self.incognito_active = False
                self.suspended = False
                self.incognito_btn.config(text="Включить Incognito")
                self._log("Incognito: выключен. Мониторинг возобновляется.", "SEC")
                self.show_hidden_info.config(text="")
                self.root.after(100, self.refresh_treeview)
            except Exception as e:
                self._log(f"Ошибка выключения Incognito: {e}", "ERROR")
                messagebox.showerror("Обскура", f"Ошибка выключения Incognito:\n{e}")

    def clear_logs(self):
        try:
            self.log_widget.configure(state="normal")
            self.log_widget.delete("1.0", "end")
            self.log_widget.configure(state="disabled")
        except Exception:
            pass
        try:
            open(LOG_PATH, "w").close()
        except Exception:
            pass

    def on_close(self):
        # stop background threads and close DB
        self.stop_event.set()
        try:
            if self.rudy:
                self.rudy.stop()
        except Exception:
            pass
        try:
            if self.geo_reader:
                self.geo_reader.close()
        except Exception:
            pass
        self.root.destroy()

# main
def main():
    root = tk.Tk()
    style = ttk.Style(root)
    root.configure(bg=BG)
    try:
        style.theme_use('clam')
    except Exception:
        pass
    style.configure(".", background=BG, foreground=FG, fieldbackground=BG)
    style.configure("Treeview", background=TREE_ALT_BG, foreground=FG, fieldbackground=TREE_ALT_BG)
    style.map("Treeview", background=[('selected', '#005f5f')], foreground=[('selected', '#ffffff')])
    style.configure("TButton", background="#222222", foreground=FG)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("TEntry", fieldbackground=TEXT_BG, foreground=TEXT_FG)
    app = ObscuraGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

if __name__ == "__main__":
    main()
