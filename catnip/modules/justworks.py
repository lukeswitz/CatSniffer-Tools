#!/usr/bin/env python3
"""JustWorks BLE scanner — serial-to-TUI/PCAP capture for the justworks_scanner firmware.

Parses `[SCAN] ADV`, `[CONN]`, and `[PAIR]` lines, maintains a live device table,
and optionally writes advertisements to a Wireshark-compatible PCAP (DLT_PPI).
"""

__all__ = ["run"]

import os
import queue
import random
import re
import select
import struct
import sys
import termios
import time
import threading
import tty
from datetime import datetime

import serial
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from scapy.all import PcapWriter
from scapy.packet import Raw

_VERSION = "3.3.1.0"
_COMPANY = "Electronic Cats — PWNLAB"

_PHRASES = [
    "BLE: Basically Leaking Everything.",
    "BLE doesn't lie. People do.",
    "Your fitness tracker has secrets.",
    "Catching packets like mice.",
    "Pairing is caring.",
    "Who said curiosity killed the cat?",
    "Not all heroes wear capes. Some carry antennas.",
    "Legally (probably) sniffing since 2024.",
    "Because plaintext is a lifestyle choice.",
    "BLE: Basically Leaking Everything."
]
_PHRASE = random.choice(_PHRASES)

_CAT = f"""\
      :-:              :--       |
      ++++=.        .=++++       |
      =+++++===++===++++++       |
      -++++++++++++++++++-       |
 .:   =++---++++++++---++=   :.  |  JustWorks BLE Scanner
 ::---+++.   -++++-   .+++---::  |  v{_VERSION}
::1..:-++++:   ++++   :++++-::.::|  {_PHRASE}
.:...:=++++++++++++++++++=:...:. |
 :---.  -++++++++++++++-  .---:  |
 ..        .:------:.        ..  |"""

ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

ADV_RE = re.compile(
    r'\[SCAN\]\s+ADV\s+from\s+(0x[0-9A-Fa-f]+)'
    r'(?:\s*\|\s*name:\(?([^|]*)\)?)?'
    r'(?:\s*\|\s*RSSI:(-?\d+)\s*dBm)?'
    r'(?:\s*\|\s*addrType:(\w+))?'
    r'(?:\s*\|\s*primPHY:([\w]+))?'
    r'(?:\s*\|\s*secPHY:(\S+))?'
    r'(?:\s*\|\s*evt:([\w|]+))?'
)

CONN_RE = re.compile(
    r'\[CONN\]\s+(\w.*?):\s+(0x[0-9A-Fa-f]+)'
    r'(?:\s*\|\s*name:([^|]*))?'
    r'(?:\s*\|\s*RSSI:(-?\d+))?'
)

PAIR_RE = re.compile(r'\[PAIR\]\s+(.*)')


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def format_mac(mac_hex: str) -> str:
    h = mac_hex[2:] if mac_hex[:2] in ("0x", "0X") else mac_hex
    h = h.zfill(12).upper()
    return ":".join(h[i:i+2] for i in range(0, 12, 2))


def safe_printable(s: str) -> str:
    return "".join(c if (c.isprintable() and ord(c) < 128) else "?" for c in s)


def parse_line(line: str) -> dict | None:
    line = strip_ansi(line).strip()
    if not line:
        return None

    m = ADV_RE.search(line)
    if m:
        mac, name, rssi, addr_type, prim_phy, sec_phy, evt_raw = m.groups()
        name = (name or "").strip().strip(")").strip("(").strip()
        if name.lower() == "no-name":
            name = ""
        evt_raw = (evt_raw or "").strip()
        return {
            "type":      "ADV",
            "mac":       format_mac(mac),
            "name":      name,
            "rssi":      int(rssi) if rssi else -99,
            "addr_type": addr_type or "?",
            "prim_phy":  prim_phy or "?",
            "sec_phy":   sec_phy or "?",
            "events":    [e.strip() for e in evt_raw.split("|") if e.strip()],
            "raw_evt":   evt_raw,
            "ts":        time.time(),
        }

    m = CONN_RE.search(line)
    if m:
        action, mac, name, rssi = m.groups()
        return {
            "type":   "CONN",
            "action": action.strip(),
            "mac":    format_mac(mac),
            "name":   (name or "").strip(),
            "rssi":   int(rssi) if rssi else None,
            "ts":     time.time(),
        }

    m = PAIR_RE.search(line)
    if m:
        return {
            "type": "PAIR",
            "msg":  m.group(1).strip(),
            "ts":   time.time(),
        }

    return None


def mac_str_to_bytes(mac_str: str) -> bytes:
    h = mac_str.replace(":", "")
    return bytes(reversed(int(h, 16).to_bytes(6, "big")))


def pdu_type_from_events(events: list[str]) -> int:
    evts = [e.upper() for e in events]
    if "NONCONNECTABLE" in evts:
        return 0x02
    if "CONNECTABLE" in evts:
        return 0x00
    if "SCANNABLE" in evts:
        return 0x06
    return 0x00


def build_ble_packet(entry: dict) -> bytes:
    mac_bytes = mac_str_to_bytes(entry["mac"])
    pdu_type = pdu_type_from_events(entry["events"])
    tx_add = 1 if entry["addr_type"].upper() == "RANDOM" else 0
    adv_payload = b""
    if entry["name"]:
        enc = entry["name"].encode("utf-8")[:29]
        adv_payload = bytes([len(enc) + 1, 0x09]) + enc
    pdu_len = 6 + len(adv_payload)
    header = struct.pack("<BB", (tx_add << 6) | (pdu_type & 0x0F), pdu_len)
    return b"\xD6\xBE\x89\x8E" + header + mac_bytes + adv_payload + b"\x00\x00\x00"


def build_ppi_packet(ll_frame: bytes, rssi: int) -> bytes:
    field = struct.pack("<HHiHH", 0xA002, 10, rssi, 2402, 0x0000)
    header = struct.pack("<BBHI", 0, 0, 8 + len(field), 251)
    return header + field + ll_frame


class PcapCapture:
    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._writer = PcapWriter(path, linktype=192, sync=True)

    def write(self, entry: dict):
        ppi = build_ppi_packet(build_ble_packet(entry), entry["rssi"])
        pkt = Raw(load=ppi)
        pkt.time = entry["ts"]
        with self._lock:
            self._writer.write(pkt)

    def close(self):
        with self._lock:
            self._writer.close()


EVENTS_ROWS = 8
DEVICES_ROWS = 15
MAX_LOG = 50


class State:
    def __init__(self):
        self._lock = threading.Lock()
        self.devices: dict[str, dict] = {}
        self.conn_log: list[dict] = []
        self.pair_log: list[dict] = []
        self.total_adv = 0
        self.total_conn = 0
        self.total_pair = 0
        self.events_offset: int = 0
        self.devices_offset: int = 0
        self.privacy: bool = False

    def toggle_privacy(self) -> None:
        self.privacy = not self.privacy

    def scroll_events(self, delta: int) -> None:
        with self._lock:
            total = len(self.conn_log) + len(self.pair_log)
            max_off = max(0, total - EVENTS_ROWS)
            self.events_offset = max(0, min(self.events_offset + delta, max_off))

    def scroll_devices(self, delta: int) -> None:
        with self._lock:
            max_off = max(0, len(self.devices) - DEVICES_ROWS)
            self.devices_offset = max(0, min(self.devices_offset + delta, max_off))

    def update(self, entry: dict):
        with self._lock:
            t = entry["type"]
            if t == "ADV":
                mac = entry["mac"]
                self.total_adv += 1
                if mac not in self.devices:
                    self.devices[mac] = {
                        **entry,
                        "count":    1,
                        "rssi_min": entry["rssi"],
                        "rssi_max": entry["rssi"],
                        "conn":     False,
                        "paired":   False,
                    }
                else:
                    d = self.devices[mac]
                    d["count"] += 1
                    d["rssi"] = entry["rssi"]
                    d["ts"] = entry["ts"]
                    d["rssi_min"] = min(d["rssi_min"], entry["rssi"])
                    d["rssi_max"] = max(d["rssi_max"], entry["rssi"])
                    d["raw_evt"] = entry["raw_evt"]
                    if entry["name"]:
                        d["name"] = entry["name"]

            elif t == "CONN":
                self.total_conn += 1
                self.conn_log.append(entry)
                self.conn_log = self.conn_log[-MAX_LOG:]
                mac = entry["mac"]
                if mac in self.devices:
                    self.devices[mac]["conn"] = "Connected" in entry["action"]
                    if entry["name"]:
                        self.devices[mac]["name"] = entry["name"]
            elif t == "PAIR":
                self.total_pair += 1
                self.pair_log.append(entry)
                self.pair_log = self.pair_log[-MAX_LOG:]

    def snapshot(self) -> tuple[list, list, list]:
        with self._lock:
            devs = sorted(self.devices.values(), key=lambda x: x["rssi"], reverse=True)
            return devs, list(self.conn_log), list(self.pair_log)


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def rssi_bar(rssi: int) -> str:
    filled = max(0, min(10, (rssi + 100) // 10))
    return "[" + "#" * filled + "-" * (10 - filled) + "]"


def activity_bar(age: float) -> Text:
    FULL, EMPTY = "▰", "▱"
    if age < 2:
        segs, style = 5, "bold green"
    elif age < 5:
        segs, style = 4, "green"
    elif age < 10:
        segs, style = 3, "yellow"
    elif age < 20:
        segs, style = 2, "yellow"
    elif age < 60:
        segs, style = 1, "red"
    else:
        segs, style = 0, "bright_black"
    return Text(FULL * segs + EMPTY * (5 - segs), style=style)


def rssi_style(rssi: int) -> str:
    if rssi > -60:
        return "bold green"
    if rssi > -75:
        return "yellow"
    return "red"


def _mask(s: str, privacy: bool, placeholder: str = "**:**:**:**:**:**") -> str:
    return placeholder if privacy else s


def build_ui(state: State, pcap_path: str | None, port: str) -> Layout:
    devices, conn_log, pair_log = state.snapshot()
    privacy = state.privacy
    now = time.time()

    dev_off = state.devices_offset
    visible_devs = devices[dev_off:dev_off + DEVICES_ROWS]
    dev_scroll_hint = ""
    if len(devices) > DEVICES_ROWS:
        dev_scroll_hint = f"  [/]{dev_off + 1}-{min(dev_off + DEVICES_ROWS, len(devices))}/{len(devices)}  [ / ]"

    dev_table = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        expand=True,
        padding=(0, 1),
    )
    dev_table.add_column("MAC", style="bold white", min_width=20, no_wrap=True)
    dev_table.add_column("Name", style="yellow", min_width=18)
    dev_table.add_column("RSSI", min_width=8, justify="right")
    dev_table.add_column("Signal", min_width=12)
    dev_table.add_column("Type", min_width=7)
    dev_table.add_column("PHY", min_width=3)
    dev_table.add_column("Activity", min_width=7)
    dev_table.add_column("C", min_width=1, justify="center")
    dev_table.add_column("#", min_width=5, justify="right")
    dev_table.add_column("Age", min_width=6, justify="right")

    for d in visible_devs:
        age = now - d["ts"]
        rs = rssi_style(d["rssi"])
        conn_mark = Text("*", style="bold magenta") if d.get("conn") else Text("")
        dev_table.add_row(
            _mask(d["mac"], privacy),
            "" if privacy else (d["name"] or Text("(no-name)", style="bright_black")),
            Text(f"{d['rssi']} dBm", style=rs),
            Text(rssi_bar(d["rssi"]), style=rs),
            d["addr_type"],
            d["prim_phy"],
            activity_bar(age),
            conn_mark,
            str(d["count"]),
            f"{age:.0f}s",
        )

    all_events: list[tuple] = []
    for e in reversed(conn_log):
        detail = "" if privacy else (e["name"] or "")
        if e["rssi"] and not privacy:
            detail += f" {e['rssi']}dBm"
        all_events.append((_fmt_time(e["ts"]), Text(e["action"], style="magenta"), _mask(e["mac"], privacy), detail))
    for e in reversed(pair_log):
        msg = "" if privacy else safe_printable(e["msg"])[:40]
        all_events.append((_fmt_time(e["ts"]), Text("PAIR", style="bold yellow"), "", msg))

    total_events = len(all_events)
    off = state.events_offset
    visible = all_events[off:off + EVENTS_ROWS]

    scroll_hint = ""
    if total_events > EVENTS_ROWS:
        scroll_hint = f"  ↑/↓  {off + 1}-{min(off + EVENTS_ROWS, total_events)}/{total_events}"

    event_table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="bright_black",
        expand=True,
        padding=(0, 1),
    )
    event_table.add_column("Time", min_width=8, no_wrap=True)
    event_table.add_column("Event", min_width=12)
    event_table.add_column("MAC", min_width=20, no_wrap=True)
    event_table.add_column("Detail", min_width=20)

    for row in visible:
        event_table.add_row(*row)

    privacy_badge = "  [bold red]REDACTED[/bold red]" if privacy else ""
    status = "  ".join(filter(None, [
        f"[bold cyan]port:[/] {port}",
        f"[bold cyan]devices:[/] {len(devices)}",
        f"[bold cyan]adv:[/] {state.total_adv}",
        f"[bold cyan]conn:[/] {state.total_conn}",
        f"[bold yellow]pair:[/] {state.total_pair}" if state.total_pair else None,
        f"[bold cyan]pcap:[/] {pcap_path}" if pcap_path else None,
        f"[bold cyan]{datetime.now().strftime('%H:%M:%S')}[/]",
    ])) + privacy_badge

    keymap = (
        "[dim]↑/↓[/dim] scroll events  "
        "[dim][ / ][/dim] scroll devices  "
        "[dim]^P[/dim] privacy  "
        "[dim]q[/dim] quit"
    )

    sections = [
        Layout(
            Panel(f"[cyan bold]{_CAT}[/cyan bold]", title=f"[cyan]{_COMPANY}[/cyan]",
                  border_style="cyan bold", title_align="left", padding=(0, 1)),
            name="header",
            size=12,
        ),
        Layout(
            Panel(dev_table, title=f"BLE Devices{dev_scroll_hint}", border_style="cyan"),
            name="top",
            ratio=3,
        ),
    ]

    sections += [
        Layout(
            Panel(event_table, title=f"CONN / PAIR Events{scroll_hint}", border_style="magenta"),
            name="bottom",
            ratio=1,
        ),
        Layout(
            Panel(status, border_style="bright_black"),
            name="status",
            size=3,
        ),
        Layout(
            Panel(keymap, border_style="bright_black"),
            name="keymap",
            size=3,
        ),
    ]

    layout = Layout()
    layout.split_column(*sections)
    return layout


def serial_reader(
    port: str,
    baud: int,
    state: State,
    pcap: PcapCapture | None,
    line_q: queue.Queue,
    stop: threading.Event,
):
    try:
        ser = serial.Serial(port, baud, timeout=1)
        ser.reset_input_buffer()
    except serial.SerialException as e:
        line_q.put(f"[red]Failed to open {port}: {e}[/red]")
        stop.set()
        return

    while not stop.is_set():
        try:
            raw = ser.readline()
            if not raw:
                continue
            line = strip_ansi(raw.decode("utf-8", errors="replace")).strip()
            if not line:
                continue
            line_q.put(line)
            entry = parse_line(line)
            if entry:
                state.update(entry)
                if pcap and entry["type"] == "ADV":
                    pcap.write(entry)
        except serial.SerialException:
            break
        except Exception:
            continue


def _handle_key(ch: str, fd: int, state: State, stop: threading.Event) -> None:
    if ch == "\x1b":
        seq = ""
        while select.select([fd], [], [], 0.05)[0]:
            c = os.read(fd, 1).decode("utf-8", errors="replace")
            seq += c
            if c.isalpha() or c == "~":
                break
        if seq == "[A":
            state.scroll_events(-1)
        elif seq == "[B":
            state.scroll_events(1)
    elif ch == "[":
        state.scroll_devices(-1)
    elif ch == "]":
        state.scroll_devices(1)
    elif ch == "\x10":      # Ctrl+P
        state.toggle_privacy()
    elif ch in ("\x03", "q", "Q"):
        stop.set()


def run(port: str, baud: int = 115200, pcap: str | None = None, no_tui: bool = False) -> None:
    """Run the JustWorks BLE capture on the given serial port.

    Args:
        port:    serial device path (e.g. /dev/cu.usbmodem*, COM3)
        baud:    serial baudrate
        pcap:    optional path to write captured ADVs as a PCAP (DLT_PPI)
        no_tui:  if True, stream raw lines to the console instead of the live UI
    """
    if not port:
        print("No serial port provided.")
        sys.exit(1)

    pcap_capture = PcapCapture(pcap) if pcap else None
    state = State()
    line_q: queue.Queue = queue.Queue()
    stop = threading.Event()

    threading.Thread(
        target=serial_reader,
        args=(port, baud, state, pcap_capture, line_q, stop),
        daemon=True,
    ).start()

    if no_tui:
        console = Console()
        console.print(f"[cyan]Listening on {port} @ {baud}[/cyan]")
        try:
            while True:
                try:
                    line = line_q.get(timeout=0.1)
                    console.print(line)
                except queue.Empty:
                    pass
        except KeyboardInterrupt:
            pass
    else:
        console = Console()
        fd = sys.stdin.fileno()
        old_term = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            with Live(
                console=console,
                refresh_per_second=4,
                screen=True,
                redirect_stdout=False,
                redirect_stderr=False,
            ) as live:
                while not stop.is_set():
                    live.update(build_ui(state, pcap, port))
                    deadline = time.monotonic() + 0.25
                    while time.monotonic() < deadline and not stop.is_set():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        if select.select([fd], [], [], remaining)[0]:
                            ch = os.read(fd, 1).decode("utf-8", errors="replace")
                            _handle_key(ch, fd, state, stop)
        except KeyboardInterrupt:
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_term)

    stop.set()
    if pcap_capture:
        pcap_capture.close()
        print(f"\nPCAP saved to {pcap}")
    print(f"Captured {state.total_adv} adv, {state.total_conn} connections from {len(state.devices)} devices.")
