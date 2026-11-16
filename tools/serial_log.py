"""Read-only capture of the RBR10's serial console (the boot log) through a CP2102 USB-serial cable.

Usage:  python -I serial_log.py [--port COM5] [--baud 115200] [--seconds 120] [--quiet-stop 20]
        python -I serial_log.py --list      (show the serial ports this PC has)
Wiring: cable GND to the router's ground (the shield can), cable RX to the header pin you are
        trying. Cable TX and 5V stay unconnected. Start this tool first, then power the router on.

This tool only listens. It never sends a byte: the port classes have no write method, flow
control is off (no XON/XOFF), and the port is opened read-only (on Windows, when the driver
allows it; the summary says which). Keeping the cable's TX unconnected makes that certain. The
OS may still raise DTR/RTS when the port opens; they aren't wired, so that is harmless. It also means it never stops U-Boot's autoboot, so the router boots stock firmware.

When it stops (time limit, --quiet-stop seconds with no data once 16 bytes have come, or Ctrl+C)
it says what it heard: nothing, too few bytes to judge, a stuck line, garbage, or readable text.
That tells you whether the RX pin and the baud rate are right. Exit code: 0 for text, 2 for no
text, 1 for an error. Without --port it looks for the CP2102 (USB ID 10C4:EA60).

Each run writes to a new folder, ../serial/<date-time-us>/ (next to tools/, us = microseconds):
  boot.raw       every byte exactly as received, written as it arrives
  boot.log       the text, one line each with the seconds since the first byte (when the
                 line's first byte came), control and escape bytes and blank lines removed
  summary.txt    the verdict, what to try next, and the landmarks found (first line of each,
                 every signature and root filesystem line): U-Boot banner, partitions, ...
  manifest.json  port, baud, handle type, times, byte counts, the verdict, the landmarks, why
                 it stopped, and any error
The files are finished in a finally block, each step on its own, so Ctrl+C, an unplugged cable
or a failed write keeps everything received up to that point.
They can hold MACs and the serial number: the project's .gitignore keeps serial/ out of git.
Python standard library only (ctypes on Windows, termios on Linux), Python 3.8 or later.
"""
import argparse
import codecs
import datetime
import glob
import json
import math
import os
import pathlib
import re
import signal
import sys
import threading
import time

DEFAULT_BAUD = 115200
DEFAULT_SECONDS = 120
DEFAULT_QUIET_STOP = 20
DEFAULT_OUT = pathlib.Path(__file__).resolve().parent.parent / "serial"
CP210X_VID, CP210X_PID = "10C4", "EA60"
READ_SIZE = 4096
READ_TIMEOUT_MS = 100

# Verdict thresholds. Text from the right pin at the right baud is almost all printable; a wrong
# baud gives mostly non-printable bytes; a held-low line (RX on ground) usually gives nothing or
# a 0x00 or two (breaks), and a much slower baud can also give runs of 0x00.
MIN_VERDICT_BYTES = 16  # fewer is a glitch (touching a pin, power-on), too few to judge
MIN_QUIET_BYTES = 16    # --quiet-stop counts only from here, so a glitch can't end the capture
MIN_TEXT_BYTES = 64
MIN_PRINTABLE = 0.90
MAX_ZEROS = 0.50

LANDMARKS = [
    ("U-Boot banner", re.compile(r"U-Boot \d")),
    ("autoboot prompt", re.compile(r"Hit any key to stop autoboot|autoboot in", re.I)),
    ("machine ID", re.compile(r"machid", re.I)),
    ("flash", re.compile(r"\bNAND\b|\bSPI\b|flash", re.I)),
    ("partition", re.compile(r"0x[0-9a-f]+-0x[0-9a-f]+ : \"", re.I)),
    ("boot command", re.compile(r"bootcmd|bootargs|bootm\b", re.I)),
    # A FIT hash check (sha1/crc) is not a signature check; a signed FIT names its key, e.g.
    # "sha1,rsa2048:dev+". Kept apart so a plain hash line can't pass for a signature check.
    ("image hash check", re.compile(r"Verifying (Hash Integrity|Checksum)", re.I)),
    # Does this U-Boot check signatures? The stock kernel image carries a Qualcomm signature
    # header (SW_ID 0x17) and a cert chain (found by unpacking it); ours is unsigned. Every
    # matching line is kept (see MULTI_LANDMARKS), so a later "authentication failed" shows.
    ("signature or secure boot", re.compile(
        r"secure ?boot|\bsignature|\bsigned\b|\bauthenticat|\bSW_ID\b|\b(rsa|ecdsa)\d+\b"
        r"|\bimage auth|\bsig(nature)? (check|verif)", re.I)),
    ("root filesystem", re.compile(
        r"\brootfs\b|\bubi\d: attach|VFS: |Mounted root|Cannot open root device", re.I)),
    ("handing over to the kernel", re.compile(r"Starting kernel", re.I)),
    ("Linux version", re.compile(r"Linux version")),
    ("kernel command line", re.compile(r"Kernel command line")),
    ("console prompt", re.compile(r"Please press Enter|login:", re.I)),
]
# These keep every matching line (up to MAX_MULTI_LINES), not just the first.
MULTI_LANDMARKS = {"signature or secure boot", "root filesystem"}
MAX_MULTI_LINES = 20
LANDMARK_TEXT = 160  # characters of each line shown, cut around the match

ADVICE = {
    "too few bytes": "Only a few bytes, too few to judge (a glitch from touching the pin or "
                     "from power-on). Power-cycle the router while this runs.",
    "nothing": "No bytes at all. Check that GND is on the shield can, move RX to the next pin, "
               "start this tool again and power-cycle the router after it starts.",
    "stuck": "Mostly 0x00 bytes: the line is held low (RX on a GND pin) or the baud is far too "
             "fast for it. Try --baud 9600 once; if that isn't text either, move RX to the next pin.",
    "garbage": "Bytes arrived but they aren't text. RX may be on the right pin at the wrong "
               "baud (try --baud 57600 or 9600), or on a floating pin picking up noise. If no "
               "baud gives text, move RX to the next pin.",
    "a little text": "Some readable text, but very little. Power-cycle the router while this "
                     "runs to catch the whole boot log.",
    "text": "Readable text: this is almost certainly the router's TX pin, at the right baud.",
}

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(text):
    """Remove ANSI escape introducers and control characters (tabs stay), so router text can't
    drive the terminal. An OSC payload's text stays (ESC]0;title BEL becomes 0;title)."""
    return _CONTROL.sub("", _ANSI.sub("", text))


def is_printable_byte(b):
    return 0x20 <= b <= 0x7E or b in (9, 10, 13)


def verdict(total, printable, zeros):
    """What the byte counts say about the wiring and the baud rate (a key of ADVICE)."""
    if total == 0:
        return "nothing"
    if total < MIN_VERDICT_BYTES:
        return "too few bytes"
    if zeros / total > MAX_ZEROS:
        return "stuck"
    if printable / total < MIN_PRINTABLE:
        return "garbage"
    if total < MIN_TEXT_BYTES:
        return "a little text"
    return "text"


class Capture:
    """Turns received chunks into boot.raw, timestamped lines in boot.log, byte counts and
    landmarks. Holds no port, so it is easy to test."""

    def __init__(self, raw_f, log_f, echo=None):
        self.raw_f, self.log_f, self.echo = raw_f, log_f, echo
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.total = self.printable = self.zeros = 0
        self.first_t = None
        self.partial, self.partial_t = "", None
        self.lines = 0
        self.landmarks = {}  # label -> {"line": n, "t": seconds, "text": first matching line}
        self.partitions = 0
        self.echo_error = None  # why echo was switched off, if it failed
        self.last_t = None

    def feed(self, chunk, t):
        if not chunk:
            return
        if self.first_t is None:
            self.first_t = t
        self.last_t = t
        self.raw_f.write(chunk)
        self.raw_f.flush()
        self.total += len(chunk)
        self.printable += sum(1 for b in chunk if is_printable_byte(b))
        self.zeros += chunk.count(0)
        text = self.decoder.decode(chunk).replace("\r\n", "\n").replace("\r", "\n")
        for piece in text.split("\n")[:-1]:
            self._line(self.partial + piece, self.partial_t if self.partial else t)
            self.partial, self.partial_t = "", None
        tail = text.split("\n")[-1]
        if tail:
            if not self.partial:
                self.partial_t = t
            self.partial += tail
        self.log_f.flush()

    def finish(self):
        """Write out a last line that never got its newline."""
        rest = self.decoder.decode(b"", final=True)
        if self.partial or rest:
            self._line(self.partial + rest, self.partial_t if self.partial_t is not None
                       else self.last_t)
            self.partial, self.partial_t = "", None
        self.log_f.flush()

    def _line(self, line, t):
        line = clean(line)
        if not line.strip():
            return
        self.lines += 1
        rel = (t - self.first_t) if t is not None and self.first_t is not None else 0.0
        self.log_f.write(f"[{rel:9.3f}] {line}\n")
        if self.echo:
            try:
                self.echo(line)
            except Exception as e:  # a closed pipe or odd console: stop echoing, keep capturing
                self.echo = None
                self.echo_error = f"{type(e).__name__}: {e}"
        for label, rx in LANDMARKS:
            m = rx.search(line)
            if not m:
                continue
            if label == "partition":
                self.partitions += 1
            start = max(0, min(m.start() - 40, len(line) - LANDMARK_TEXT))
            hit = {"line": self.lines, "t": round(rel, 3),
                   "text": line[start:start + LANDMARK_TEXT]}
            first = self.landmarks.setdefault(label, dict(hit))
            if label in MULTI_LANDMARKS:
                first["count"] = first.get("count", 0) + 1
                more = first.setdefault("all", [])
                if len(more) < MAX_MULTI_LINES:
                    more.append(hit)

    def verdict(self):
        return verdict(self.total, self.printable, self.zeros)


def summary_text(cap, info):
    v = cap.verdict()
    out = [f"Port {info['port']} at {info['baud']} baud ({info.get('handle', 'unknown')}), "
           f"stopped by: {info['stopped_by']}",
           f"Received {cap.total} bytes, {cap.lines} lines.",
           "", f"Verdict: {v}", ADVICE[v]]
    if info.get("error"):
        out += ["", f"Error: {info['error']}"]
    if info.get("echo_error"):
        out += [f"Note: {info['echo_error']} (the files have every line)"]
    if v == "text" and "U-Boot banner" not in cap.landmarks:
        out += ["", "No U-Boot banner: the capture probably started after the boot. Power-cycle "
                    "the router while this runs to get the whole log."]
    if cap.landmarks:
        out += ["", "Landmarks (first line of each, every line of the multi-line ones; in the "
                    "order seen; seconds since the first byte):"]
        for label, m in sorted(cap.landmarks.items(), key=lambda kv: kv[1]["line"]):
            if label in MULTI_LANDMARKS:
                hits = m["all"]
                more = "" if m["count"] <= len(hits) else f", first {len(hits)} shown"
                out.append(f"  {label} ({m['count']} lines{more}):")
                out += [f"    [{h['t']:.3f}] {h['text']}" for h in hits]
            else:
                extra = f" ({cap.partitions} lines)" if label == "partition" else ""
                out.append(f"  {label}{extra}: [{m['t']:.3f}] {m['text']}")
    if "U-Boot banner" in cap.landmarks and "signature or secure boot" not in cap.landmarks:
        out += ["", "No signature or secure-boot line was seen. U-Boot may still check quietly: "
                    "look in boot.log around the kernel load."]
    return "\n".join(out) + "\n"


def run_capture(port, run_dir, info, seconds, quiet_stop, clock=time, echo=None, held=None):
    """Read until the time limit, a quiet spell after data, Ctrl+C or a read error, then
    finish every file. Returns the Capture."""
    start = clock.monotonic()
    info["started"] = datetime.datetime.now().isoformat(timespec="seconds")
    last = None  # when data last came, once MIN_QUIET_BYTES have arrived

    def add_error(msg):
        info["error"] = f"{info['error']}; {msg}" if info.get("error") else msg

    # Ctrl+C sets a flag that the loop checks, so it can't land between a read and the write to
    # boot.raw and drop that chunk. (Only possible in the main thread; elsewhere it still raises.)
    stop = [False]  # a plain flag: the handler only assigns, so a second Ctrl+C can't deadlock
    installed, old_handler = False, None
    with open(run_dir / "boot.raw", "wb") as raw_f, \
            open(run_dir / "boot.log", "w", encoding="utf-8", newline="\n") as log_f:
        cap = Capture(raw_f, log_f, echo)
        if held is not None:
            held.append(cap)
        try:
            if threading.current_thread() is threading.main_thread():
                old_handler = signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
                installed = True
            while True:
                if stop[0]:
                    info["stopped_by"] = "Ctrl+C"
                    break
                now = clock.monotonic()
                if now - start >= seconds:
                    info["stopped_by"] = f"time limit ({seconds} s)"
                    break
                if last is not None and now - last >= quiet_stop:
                    info["stopped_by"] = f"no data for {quiet_stop} s"
                    break
                try:
                    chunk = port.read(READ_SIZE)
                except OSError as e:  # only the port read means "cable": not the file writes
                    info["stopped_by"] = "read error"
                    add_error(f"{type(e).__name__}: {e} (cable unplugged?)")
                    break
                if chunk:
                    cap.feed(chunk, clock.monotonic())
                    if cap.total >= MIN_QUIET_BYTES:
                        last = clock.monotonic()
        except KeyboardInterrupt:
            info["stopped_by"] = "Ctrl+C"
        except OSError as e:
            info["stopped_by"] = "save error"
            add_error(f"saving the capture or printing it: {type(e).__name__}: {e}")
        except BaseException as e:
            info["stopped_by"] = "crashed"
            add_error(f"{type(e).__name__}: {e}")
            raise
        finally:
            # Each step on its own, so one failure can't stop the others or hide the first error.
            # Ctrl+C stays a flag until the files are written; the old handler comes back last.
            info.setdefault("stopped_by", "stopped early")
            try:
                cap.finish()
            except Exception as e:
                add_error(f"finishing boot.log: {type(e).__name__}: {e}")
            info["ended"] = datetime.datetime.now().isoformat(timespec="seconds")
            if cap.echo_error:
                info["echo_error"] = f"echo to the terminal stopped: {cap.echo_error}"
            info.update(bytes=cap.total, printable_bytes=cap.printable, zero_bytes=cap.zeros,
                        lines=cap.lines, verdict=cap.verdict(), partition_lines=cap.partitions,
                        landmarks=cap.landmarks)
            try:
                (run_dir / "summary.txt").write_text(summary_text(cap, info), encoding="utf-8")
            except Exception as e:
                add_error(f"writing summary.txt: {type(e).__name__}: {e}")
            try:
                (run_dir / "manifest.json").write_text(json.dumps(info, indent=2) + "\n",
                                                       encoding="utf-8")
            except Exception as e:
                add_error(f"writing manifest.json: {type(e).__name__}: {e}")
            if installed:
                signal.signal(signal.SIGINT,
                              old_handler if old_handler is not None else signal.SIG_DFL)
    return cap


# ---- ports ---------------------------------------------------------------------------------

class PortNotFound(Exception):
    """The port can't be found or opened, with a message that says what to do."""


ERROR_NO_MORE_ITEMS = 259
SILABS_DEVICE = "\\Device\\Silabser"  # SERIALCOMM value name of a live CP210x port


def _reg_items(next_item):
    """Call next_item(0), next_item(1), ... until the registry says there are no more. Any
    other registry error is raised, not taken as the end of the list."""
    i = 0
    while True:
        try:
            yield next_item(i)
        except OSError as e:
            if getattr(e, "winerror", None) == ERROR_NO_MORE_ITEMS:
                return
            raise
        i += 1


def serialcomm_windows(winreg=None):
    """{device name: COM name} for the serial ports Windows has right now
    (HKLM\\HARDWARE\\DEVICEMAP\\SERIALCOMM). The key is absent when there are none."""
    if winreg is None:
        import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\SERIALCOMM")
    except FileNotFoundError:
        return {}
    with key:
        return {name: port for name, port, _ in _reg_items(lambda i: winreg.EnumValue(key, i))}


def _com_order(name):
    m = re.fullmatch(r"COM(\d+)", name, re.I)
    return (0, int(m.group(1)), "") if m else (1, 0, name)


def list_ports_windows(winreg=None):
    return sorted(set(serialcomm_windows(winreg).values()), key=_com_order)


def find_cp210x_windows(winreg=None):
    """COM name of the connected CP210x, from the registry (read only)."""
    if winreg is None:
        import winreg
    live = sorted({port for dev, port in serialcomm_windows(winreg).items()
                   if dev.startswith(SILABS_DEVICE)}, key=_com_order)
    if len(live) == 1:
        return live[0]
    if len(live) > 1:
        raise PortNotFound(f"more than one CP210x is connected ({', '.join(live)}): pick one "
                           "with --port")
    # None live: say why, from what the registry remembers about the cable.
    base = rf"SYSTEM\CurrentControlSet\Enum\USB\VID_{CP210X_VID}&PID_{CP210X_PID}"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
    except FileNotFoundError:
        raise PortNotFound("no CP2102 has ever been plugged into this PC. Plug the cable in, "
                           "or give --port") from None
    names = set()
    with key:
        for sub in list(_reg_items(lambda i: winreg.EnumKey(key, i))):
            try:
                dp = winreg.OpenKey(key, sub + r"\Device Parameters")
            except FileNotFoundError:
                continue
            with dp:
                try:
                    names.add(winreg.QueryValueEx(dp, "PortName")[0])
                except FileNotFoundError:
                    pass
    if names:
        raise PortNotFound(f"the CP2102 isn't plugged in now (it was "
                           f"{', '.join(sorted(names, key=_com_order))} before). Plug it in, "
                           "or give --port")
    raise PortNotFound("the CP2102 has no COM port. Its driver is probably missing (Device "
                       "Manager shows it with code 28): install the Silicon Labs CP210x "
                       "driver from Windows Update's optional updates or silabs.com, then "
                       "plug the cable in again")


def find_cp210x_linux(sys_root="/sys/class/tty"):
    found = []
    for tty in sorted(glob.glob(os.path.join(sys_root, "ttyUSB*"))):
        d = os.path.realpath(os.path.join(tty, "device"))
        for _ in range(4):  # port -> interface -> USB device, which has idVendor
            try:
                with open(os.path.join(d, "idVendor")) as f:
                    vid = f.read().strip().upper()
                with open(os.path.join(d, "idProduct")) as f:
                    pid = f.read().strip().upper()
            except FileNotFoundError:
                d = os.path.dirname(d)
                continue
            if (vid, pid) == (CP210X_VID, CP210X_PID):
                found.append("/dev/" + os.path.basename(tty))
            break
    if not found:
        raise PortNotFound("no CP210x found under /dev/ttyUSB*: plug the cable in, or give --port")
    if len(found) > 1:
        raise PortNotFound(f"more than one CP210x is connected ({', '.join(found)}): pick one "
                           "with --port")
    return found[0]


class WindowsPort:
    """A COM port opened for reading only, 8N1, no flow control (DTR/RTS set low once the
    settings land). There is no write method."""

    def __init__(self, name, baud):
        import ctypes
        from ctypes import wintypes as w
        self._c, k = ctypes, ctypes.WinDLL("kernel32", use_last_error=True)
        self._k, self._h = k, None

        class DCB(ctypes.Structure):
            _fields_ = [("DCBlength", w.DWORD), ("BaudRate", w.DWORD), ("fBits", w.DWORD),
                        ("wReserved", w.WORD), ("XonLim", w.WORD), ("XoffLim", w.WORD),
                        ("ByteSize", w.BYTE), ("Parity", w.BYTE), ("StopBits", w.BYTE),
                        ("XonChar", ctypes.c_char), ("XoffChar", ctypes.c_char),
                        ("ErrorChar", ctypes.c_char), ("EofChar", ctypes.c_char),
                        ("EvtChar", ctypes.c_char), ("wReserved1", w.WORD)]

        class COMMTIMEOUTS(ctypes.Structure):
            _fields_ = [(n, w.DWORD) for n in (
                "ReadIntervalTimeout", "ReadTotalTimeoutMultiplier", "ReadTotalTimeoutConstant",
                "WriteTotalTimeoutMultiplier", "WriteTotalTimeoutConstant")]

        k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD,
                                  w.HANDLE]
        k.CreateFileW.restype = w.HANDLE
        k.ReadFile.argtypes = [w.HANDLE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]
        k.CloseHandle.argtypes = [w.HANDLE]
        k.GetCommState.argtypes = k.SetCommState.argtypes = [w.HANDLE, ctypes.POINTER(DCB)]
        k.SetCommTimeouts.argtypes = [w.HANDLE, ctypes.POINTER(COMMTIMEOUTS)]

        GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING, MAXDWORD = 0x80000000, 0x40000000, 3, 0xFFFFFFFF
        invalid = w.HANDLE(-1).value
        path = name if name.startswith("\\\\.\\") else "\\\\.\\" + name
        last_err, step = None, "open"
        # Read-only first. Some drivers refuse a read-only open or port settings on one; then the
        # handle is read/write, but this class still has no way to write.
        for access, label in ((GENERIC_READ, "read-only"),
                              (GENERIC_READ | GENERIC_WRITE, "read/write handle, never written")):
            h = k.CreateFileW(path, access, 0, None, OPEN_EXISTING, 0, None)
            if h is None or h == invalid:
                last_err, step = ctypes.get_last_error(), "open"
                if last_err in (2, 3):  # file or path not found
                    raise PortNotFound(f"{name} doesn't exist. See --list")
                continue
            try:
                dcb = DCB()
                dcb.DCBlength = ctypes.sizeof(DCB)
                ok = k.GetCommState(h, ctypes.byref(dcb))
                if ok:
                    dcb.BaudRate, dcb.ByteSize, dcb.Parity, dcb.StopBits = baud, 8, 0, 0
                    dcb.fBits = 1  # fBinary only: no parity check, no flow control, DTR/RTS low
                    dcb.XonChar, dcb.XoffChar = b"\x11", b"\x13"  # some drivers refuse equal ones
                    ok = k.SetCommState(h, ctypes.byref(dcb))
                if ok:
                    # Return what has arrived at once, or nothing after READ_TIMEOUT_MS.
                    ok = k.SetCommTimeouts(h, ctypes.byref(COMMTIMEOUTS(
                        MAXDWORD, MAXDWORD, READ_TIMEOUT_MS, 0, 0)))
            except BaseException:
                k.CloseHandle(h)
                raise
            if ok:
                self._h, self.access = h, label
                self._buf = ctypes.create_string_buffer(READ_SIZE)
                return
            last_err, step = ctypes.get_last_error(), "settings"
            k.CloseHandle(h)
        if step == "open" and last_err == 5:
            raise PortNotFound(f"{name} is in use by another program (close PuTTY etc.)")
        what = "open" if step == "open" else f"set {baud} baud 8N1 on"
        raise OSError(f"could not {what} {name} (Windows error {last_err}: "
                      f"{ctypes.FormatError(last_err).strip()})")

    def read(self, n):
        if self._h is None:
            raise OSError("the port is closed")
        got = self._c.c_ulong(0)
        n = min(n, READ_SIZE)
        if not self._k.ReadFile(self._h, self._buf, n, self._c.byref(got), None):
            err = self._c.get_last_error()
            raise OSError(f"ReadFile failed (Windows error {err}: "
                          f"{self._c.FormatError(err).strip()})")
        return self._buf.raw[:got.value]

    def close(self):
        if self._h is not None:
            self._k.CloseHandle(self._h)
            self._h = None


def raw_8n1(attrs, termios, speed):
    """termios attributes for raw 8N1 input with no echo and no flow control (what tty.cfmakeraw
    does, written out so it works before Python 3.12)."""
    a = list(attrs)
    a[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP | termios.INLCR
              | termios.IGNCR | termios.ICRNL | termios.IXON | termios.IXOFF
              | getattr(termios, "IXANY", 0))
    a[1] &= ~termios.OPOST
    a[2] &= ~(termios.CSIZE | termios.PARENB | termios.CSTOPB | getattr(termios, "CRTSCTS", 0))
    a[2] |= termios.CS8 | termios.CLOCAL | termios.CREAD
    a[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
    a[4] = a[5] = speed
    a[6] = list(a[6])
    a[6][termios.VMIN], a[6][termios.VTIME] = 0, 0
    return a


class PosixPort:
    """A tty opened O_RDONLY, raw 8N1, no echo, no flow control. There is no write method.
    Until the settings land (microseconds after the open) the tty has its old settings, which
    may include echo: with the cable's TX unconnected, as the wiring note says, nothing can go
    out even then."""

    def __init__(self, name, baud):
        import select
        import termios
        self._select, self._fd = select.select, None
        speed = getattr(termios, f"B{baud}", None)
        if speed is None:
            raise PortNotFound(f"this system has no {baud} baud setting")
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
        except FileNotFoundError:
            raise PortNotFound(f"{name} doesn't exist. See --list") from None
        except PermissionError:
            raise PortNotFound(f"no permission to open {name}: add yourself to the dialout group "
                               "(sudo usermod -aG dialout $USER), then log in again") from None
        try:
            termios.tcsetattr(fd, termios.TCSANOW, raw_8n1(termios.tcgetattr(fd), termios, speed))
        except (termios.error, OSError) as e:
            os.close(fd)
            raise PortNotFound(f"{name} can't be set up as a serial port ({e})") from None
        self._fd, self.access = fd, "read-only"

    def read(self, n):
        if self._fd is None:
            raise OSError("the port is closed")
        ready, _, _ = self._select([self._fd], [], [], READ_TIMEOUT_MS / 1000)
        if not ready:
            return b""
        try:
            data = os.read(self._fd, n)
        except BlockingIOError:
            return b""
        if not data:  # readable but empty: the tty was hung up (cable unplugged)
            raise OSError("the port closed (cable unplugged?)")
        return data

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


def open_port(name, baud):
    return (WindowsPort if os.name == "nt" else PosixPort)(name, baud)


def find_port():
    return find_cp210x_windows() if os.name == "nt" else find_cp210x_linux()


def list_ports():
    if os.name == "nt":
        return list_ports_windows()
    return sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))


# ---- main ----------------------------------------------------------------------------------

def make_run_dir(out_root):
    out_root.mkdir(parents=True, exist_ok=True)
    while True:
        run_dir = out_root / datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        try:
            run_dir.mkdir()
            return run_dir
        except FileExistsError:
            continue


def main(argv=None, out_root=DEFAULT_OUT, opener=open_port, finder=find_port, lister=list_ports,
         clock=time, out=None):
    out = out or sys.stdout
    ap = argparse.ArgumentParser(description="Read-only capture of the RBR10 serial console.")
    ap.add_argument("--port", help="COM5, /dev/ttyUSB0, ... (default: find the CP2102)")
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD, help="default 115200")
    ap.add_argument("--seconds", type=float, default=DEFAULT_SECONDS,
                    help=f"stop after this long (default {DEFAULT_SECONDS})")
    ap.add_argument("--quiet-stop", type=float, default=DEFAULT_QUIET_STOP,
                    help="stop this long after the last byte, once 16 have come "
                         f"(default {DEFAULT_QUIET_STOP})")
    ap.add_argument("--list", action="store_true", help="list serial ports and exit")
    ap.add_argument("--no-echo", action="store_true", help="don't print lines as they arrive")
    a = ap.parse_args(argv)
    if not (math.isfinite(a.seconds) and math.isfinite(a.quiet_stop)) or \
            a.seconds <= 0 or a.quiet_stop <= 0 or a.baud <= 0:
        ap.error("--seconds, --quiet-stop and --baud must be finite numbers above 0")

    if a.list:
        ports = lister()
        print("\n".join(ports) if ports else "No serial ports.", file=out)
        return 0
    try:
        name = a.port or finder()
        port = opener(name, a.baud)
    except (PortNotFound, OSError) as e:
        print(f"Can't open the serial port: {e}", file=out)
        return 1

    try:
        run_dir = make_run_dir(out_root)
    except OSError as e:
        port.close()
        print(f"Can't make the output folder: {e}", file=out)
        return 1
    info = {"tool": "serial_log.py", "port": name, "baud": a.baud,
            "handle": getattr(port, "access", "unknown"), "seconds": a.seconds,
            "quiet_stop": a.quiet_stop}

    def say(text, **kw):
        """Print ASCII only (router text can hold U+FFFD; the files keep it). A closed or odd
        terminal must not turn a finished capture into a crash, so print errors are ignored."""
        try:
            print(text.encode("ascii", "replace").decode("ascii"), file=out, **kw)
        except (OSError, ValueError):
            pass

    echo = None if a.no_echo else (
        lambda line: print(line.encode("ascii", "replace").decode("ascii"), file=out, flush=True))
    held = []  # run_capture puts its Capture here, so it's still there if closing the files fails
    try:
        say(f"Listening on {name} at {a.baud} baud ({info['handle']}). Power the router on "
            f"now. Ctrl+C stops. Saving to {run_dir}")
        run_capture(port, run_dir, info, a.seconds, a.quiet_stop, clock=clock, echo=echo,
                    held=held)
    except OSError as e:  # boot.raw/boot.log couldn't be made or closed
        if "verdict" not in info:
            say(f"Can't save the capture in {run_dir}: {e}")
            return 1
        msg = f"closing boot.raw/boot.log: {type(e).__name__}: {e}"
        info["error"] = f"{info['error']}; {msg}" if info.get("error") else msg
        # summary.txt and manifest.json were written before the files closed: redo both.
        for fname, text in (("summary.txt", lambda: summary_text(held[0], info)),
                            ("manifest.json", lambda: json.dumps(info, indent=2) + "\n")):
            try:
                (run_dir / fname).write_text(text(), encoding="utf-8")
            except OSError:
                pass
    finally:
        port.close()
    say("\n" + summary_text(held[0], info), end="")
    if info.get("error"):
        return 1
    return 0 if info["verdict"] in ("text", "a little text") else 2


if __name__ == "__main__":
    sys.exit(main())
