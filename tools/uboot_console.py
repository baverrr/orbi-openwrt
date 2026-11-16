"""Talk to the RBR10's U-Boot over the CP2102 cable, with a fixed allowlist of commands.

Usage:  python -I uboot_console.py [--port COM4] [--cmd "printenv"] [--cmd ...] [--wait 180]
        (no --cmd: printenv, version, bdinfo, then help, a look-only pass)
Wiring: cable GND on header pin 1, cable RX on pin 3 (router TX), cable TX on pin 2 (router RX,
        inferred from the RBR20's order, not measured). 3.3 V logic only: pin 4 (VCC) and the
        cable's 5V wire are never connected. Start this tool, then power the router on.

This is the only tool here that sends anything. It waits for U-Boot's "Hit any key to stop
autoboot", sends one key to stop it, then sends each --cmd in turn and waits for the prompt
(learned exactly, right after the key). Every command is checked against ALLOWED in main before
the port is opened, and again by Session.send_command as it goes out. Anything else is refused:
no saveenv, no nand/sf/mmc writes or erases, no fw_recovery, no boot_partition_set, no env
changes except ipaddr/serverip/netmask, fdt_high set to exactly 0x87000000, and bootargs set to
exactly "console=ttyMSM0,115200n8", optionally with "earlycon=msm_serial_dm,0x78af000".
setenv without saveenv only lives in RAM; tftpboot also sets filesize/fileaddr, and ping or
tftpboot sets ethact when it's unset, all in RAM. Addresses must be in RAM
(0x80000000-0x9fffffff), so tftpboot
and md can't touch the flash controller's registers, and tftpboot and bootm only take
0x84000000. So U-Boot itself never writes the flash
and a power cycle brings back the stock boot.

U-Boot 2012.07's tftpboot doesn't check the file size. From 0x84000000 a big file would first
reach U-Boot's own reserved memory: it placed the DTB top-down at 0x871e7000, so something of
U-Boot's (likely its stack and heap) starts near 0x871e8000, about 51.9 MiB in. SMEM/TrustZone
at 0x87e00000 is 62 MiB in. tftp_serve.py refuses files of 65535 blocks (32 MiB) or more, and
the 7.6 MB initramfs ends far below either. If the env had autostart=yes, tftpboot would boot the file by itself; the env
here is U-Boot's built-in default ("bad CRC", printenv 2026-11-15) and has no autostart.
md needs a count of at most 0x400, an address aligned to its width (U-Boot aborts on an unaligned
read), must end inside RAM, and can't touch 0x87e00000-0x87ffffff (SMEM/TrustZone, no-map in the
DTS; a read there can reset the board).

`bootm` is the exception to that promise: it starts the image loaded into RAM, and that image
can do anything, including write the flash. Only boot an image you trust not to (an initramfs
that leaves the stock flash alone). bootm is only taken as the last command, after a tftpboot in
the same run, and if tftpboot doesn't report "Bytes transferred" the run stops before bootm.
After bootm the tool listens (--listen). It's a failure if the prompt comes back (U-Boot refused
the image), if U-Boot resets or starts again before "Starting kernel", if the kernel prints no
"Linux version" (no console), or if it panics or reboots.

If the key gets no prompt, it stops. Most likely the cable's TX isn't on the router's RX (pin 2
inferred), though a key that came too late looks the same. Never try TX on pin 4.

Each run writes to a new folder, ../serial/<date-time-us>/, the same files as serial_log.py
(boot.raw, boot.log, summary.txt, manifest.json), with "sent" in the manifest: every send, with
its time, recorded before it goes out. Windows only (the same ctypes setup as serial_log.py).
"""
import argparse
import datetime
import json
import math
import pathlib
import re
import signal
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import serial_log as sl  # noqa: E402

_IP = r"[0-9]{1,3}(\.[0-9]{1,3}){3}"
_RAM = r"0x[89][0-9a-fA-F]{7}"  # 0x80000000-0x9fffffff: the 512 MB of DDR
LOAD_ADDR = "0x84000000"  # the only address tftpboot and bootm take (where stock loads its FIT)
# Each is matched against the whole command, ASCII only, so no ; && || $() or line break can
# chain a second command onto an allowed one.
ALLOWED = [re.compile(p, re.ASCII) for p in (
    r"printenv( [A-Za-z0-9_]{1,32})?",
    r"version",
    r"bdinfo",
    r"help( [a-z_]{1,32})?",
    r"smeminfo",
    rf"setenv (ipaddr|serverip|netmask) {_IP}",
    # The only bootargs: the serial console, so a RAM-booted kernel prints to the cable. The
    # stock env has no bootargs (serial/20261115-215402-552261 printenv) and the RAM-test DTB has
    # no /chosen bootargs or stdout-path. It replaces bootargs, in RAM only. The earlycon form
    # names the console UART (serial@78af000 in the DTS) so a kernel that dies before its serial
    # driver starts still prints.
    r"setenv bootargs console=ttyMSM0,115200n8( earlycon=msm_serial_dm,0x78af000)?",
    # Keep the DTB below 0x87000000, as stock's bootcmd does; without it U-Boot put it at
    # 0x871e7000 (serial/20261115-221849-588795), and that run printed nothing after "Starting
    # kernel". Stock's bootcmd sets it (printenv in serial/20261115-215402-552261).
    r"setenv fdt_high 0x87000000",
    rf"ping {_IP}",
    rf"tftpboot {LOAD_ADDR} [A-Za-z0-9_.\-]{{1,128}}",
    # The count is required: without one U-Boot reuses the last md count. Hex, 0x optional.
    rf"md(\.[bwl])? {_RAM} (0x)?[0-9a-fA-F]{{1,4}}",
    rf"bootm {LOAD_ADDR}(#config@[0-9]{{1,2}})?",
)]
LOOK_ONLY = ["printenv", "version", "bdinfo", "help"]

AUTOBOOT = re.compile(r"Hit any key to stop autoboot")
# Any prompt-like last line, e.g. "(IPQ40xx) # ". Only used once, right after the stop key, to
# learn the exact prompt; later waits look for that exact text.
PROMPT = re.compile(r"(^|\n)([^\n]{1,40}[#>] )$")
TFTP_OK = re.compile(r"Bytes transferred")
# Failure text per command (checked once the prompt is back); "Unknown command" for all.
FAILS = {
    "tftpboot": re.compile(r"TFTP error|Retry count exceeded|not found|Abort", re.I),
    "ping": re.compile(r"is not alive|failed", re.I),
    "bootm": re.compile(r"Bad Magic|Wrong Image Format|can't get kernel|ERROR|"
                        r"Failed using fdt_high|FDT creation failed", re.I),
}
UNKNOWN = re.compile(r"Unknown command")
# Failure text for any command; "Usage:" is a failure except for help, which prints it.
ANY_FAIL = re.compile(r"## Error|data abort|Usage:")
# Before "Starting kernel": U-Boot reset itself or started again (a stock boot would follow).
RESET = re.compile(r"U-Boot 20|Hit any key to stop autoboot|resetting", re.I)
# After "Starting kernel": the kernel died or the board came back to U-Boot.
KERNEL_BAD = re.compile(r"Kernel panic|Rebooting in|U-Boot 20|Hit any key to stop autoboot|"
                        r"Oops|Unable to handle kernel|Internal error")
LINUX = re.compile(r"Starting kernel|Linux version|Please press Enter")
# Autoboot already under way: U-Boot reading or checking the stock image, or Linux.
BOOTING = re.compile(r"## Booting|## Loading|## Checking|Loading DNI|NAND read|FW is SIGNED|"
                     r"Starting kernel|Linux version")
POWER_CYCLE = " Power-cycle the router to get back to the stock boot."
STOP_KEY = b" "


RAM_END = 0x9FFFFFFF  # U-Boot prints "DRAM: 512 MiB" from 0x80000000
RESERVED = (0x87E00000, 0x87FFFFFF)  # SMEM + TrustZone (no-map in the DTS)
MD_MAX = 0x400
HEAD_MAX = 4096  # chars kept from the start of each reply, for the echo check
TAIL_MAX = 65536  # chars kept for matching: more than any allowed command prints

MD_WIDTH = {"md": 4, "md.l": 4, "md.w": 2, "md.b": 1}


def allowed(cmd):
    if not (cmd.isascii() and cmd.isprintable() and any(rx.fullmatch(cmd) for rx in ALLOWED)):
        return False
    parts = cmd.split()
    for part in parts[1:]:
        if re.fullmatch(_IP, part, re.ASCII) and any(int(o) > 255 for o in part.split(".")):
            return False
    if parts[0] in MD_WIDTH:  # the whole dump must stay inside RAM, aligned, off the reserved part
        width, start, count = MD_WIDTH[parts[0]], int(parts[1], 16), int(parts[2], 16)
        end = start + count * width - 1
        if (count == 0 or count > MD_MAX or start % width or end > RAM_END
                or (start <= RESERVED[1] and end >= RESERVED[0])):
            return False
    return True


class RWPort:
    """A COM port opened read/write, 8N1, no flow control. Only uboot_console uses it."""

    def __init__(self, name, baud):
        import ctypes
        from ctypes import wintypes as w
        self._c, k = ctypes, ctypes.WinDLL("kernel32", use_last_error=True)
        self._k, self._h = k, None
        # Same structures and settings as serial_log.WindowsPort.
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
        k.WriteFile.argtypes = [w.HANDLE, w.LPCVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]
        k.CloseHandle.argtypes = [w.HANDLE]
        k.GetCommState.argtypes = k.SetCommState.argtypes = [w.HANDLE, ctypes.POINTER(DCB)]
        k.SetCommTimeouts.argtypes = [w.HANDLE, ctypes.POINTER(COMMTIMEOUTS)]
        path = name if name.startswith("\\\\.\\") else "\\\\.\\" + name
        h = k.CreateFileW(path, 0xC0000000, 0, None, 3, 0, None)
        if h is None or h == w.HANDLE(-1).value:
            err = ctypes.get_last_error()
            if err in (2, 3):
                raise sl.PortNotFound(f"{name} doesn't exist. See serial_log.py --list")
            if err == 5:
                raise sl.PortNotFound(f"{name} is in use by another program")
            raise OSError(f"could not open {name} (Windows error {err}: "
                          f"{ctypes.FormatError(err).strip()})")
        try:
            dcb = DCB()
            dcb.DCBlength = ctypes.sizeof(DCB)
            ok = k.GetCommState(h, ctypes.byref(dcb))
            if ok:
                dcb.BaudRate, dcb.ByteSize, dcb.Parity, dcb.StopBits = baud, 8, 0, 0
                dcb.fBits = 1
                dcb.XonChar, dcb.XoffChar = b"\x11", b"\x13"
                ok = k.SetCommState(h, ctypes.byref(dcb))
            if ok:
                ok = k.SetCommTimeouts(h, ctypes.byref(COMMTIMEOUTS(
                    0xFFFFFFFF, 0xFFFFFFFF, sl.READ_TIMEOUT_MS, 0, 2000)))
            if not ok:
                err = ctypes.get_last_error()
                raise OSError(f"could not set {baud} baud 8N1 on {name} (Windows error {err})")
        except BaseException:
            k.CloseHandle(h)
            raise
        self._h, self.access = h, "read/write"
        self._buf = ctypes.create_string_buffer(sl.READ_SIZE)

    def read(self, n):
        if self._h is None:
            raise OSError("the port is closed")
        got = self._c.c_ulong(0)
        if not self._k.ReadFile(self._h, self._buf, min(n, sl.READ_SIZE), self._c.byref(got),
                                None):
            raise OSError(f"ReadFile failed (Windows error {self._c.get_last_error()})")
        return self._buf.raw[:got.value]

    def write(self, data):
        if self._h is None:
            raise OSError("the port is closed")
        done = self._c.c_ulong(0)
        if not self._k.WriteFile(self._h, data, len(data), self._c.byref(done), None) \
                or done.value != len(data):
            raise OSError(f"WriteFile sent {done.value} of {len(data)} bytes (Windows error "
                          f"{self._c.get_last_error()})")

    def close(self):
        if self._h is not None:
            self._k.CloseHandle(self._h)
            self._h = None


class StepFailed(Exception):
    """A step didn't get the answer it waits for (no autoboot prompt, no U-Boot prompt)."""


class Session:
    """The only way anything is sent: one stop key, then allowlisted commands. Reads go into a
    Capture (the same files as serial_log's); `tail` holds the text since the last send."""

    def __init__(self, port, cap, info, clock=time):
        self._port, self.cap, self.info, self.clock = port, cap, info, clock
        self.tail = ""
        self.head = ""  # the first HEAD_MAX chars since the last send, for the echo check
        self.prompt = None
        self.sent = info.setdefault("sent", [])
        self._stopped = False
        self.stop = [False]  # set by main's SIGINT handler

    def pump(self):
        chunk = self._port.read(sl.READ_SIZE)
        if chunk:
            self.cap.feed(chunk, self.clock.monotonic())
            text = chunk.decode("utf-8", "replace").replace("\r", "")
            self.tail = (self.tail + text)[-TAIL_MAX:]
            if len(self.head) < HEAD_MAX:
                self.head = (self.head + text)[:HEAD_MAX]
        if self.stop[0]:  # Ctrl+C, checked only after the chunk is saved
            raise KeyboardInterrupt
        return chunk

    def wait_for(self, rx, seconds):
        end = self.clock.monotonic() + seconds
        while self.clock.monotonic() < end:
            self.pump()
            if rx.search(self.tail):
                return True
        return False

    def at_prompt(self):
        p = self.prompt
        return p is not None and (self.tail == p or self.tail.endswith("\n" + p))

    def wait_prompt(self, seconds):
        end = self.clock.monotonic() + seconds
        while self.clock.monotonic() < end:
            self.pump()
            if self.at_prompt():
                return True
        return False

    def _send(self, data, drain=True):
        # Anything already waiting belongs to before this send: read it, then start a new tail.
        # Not for the stop key: the autoboot window is 1 s, so it goes out at once.
        for _ in range(50 if drain else 0):
            if not self.pump():
                break
        self.tail = self.head = ""
        entry = {"t": round(self.clock.monotonic(), 3), "data": data.decode("ascii")}
        self.sent.append(entry)  # recorded first, so a partial write still shows
        try:
            self._port.write(data)
        except OSError:
            entry["failed"] = True
            raise

    def send_stop_key(self):
        if self._stopped:
            raise ValueError("the stop key was already sent")
        self._send(STOP_KEY, drain=False)
        self._stopped = True
        if not self.wait_for(PROMPT, 5):
            if BOOTING.search(self.tail):
                raise StepFailed("the key came too late: the stock kernel was already starting. "
                                 "The wiring is fine; try again." + POWER_CYCLE)
            return False
        # "## " is the start of a cut-off "## Booting ..." line, not a prompt.
        if BOOTING.search(self.tail) or PROMPT.search(self.tail).group(2).startswith("#"):
            raise StepFailed("the key came too late: the stock boot was already under way. "
                             "The wiring is fine; try again." + POWER_CYCLE)
        if LINUX.search(self.tail) or "@" in PROMPT.search(self.tail).group(2):
            raise StepFailed("the prompt after the key is a Linux shell, not U-Boot: the key "
                             "came too late. Nothing else was sent." + POWER_CYCLE)
        self.prompt = PROMPT.search(self.tail).group(2)
        self.info["prompt"] = self.prompt
        return True

    def send_command(self, cmd):
        if not allowed(cmd):
            raise ValueError(f"not on the allowlist: {cmd!r}")
        if self.prompt is None:
            raise ValueError("no U-Boot prompt yet: stop autoboot first")
        self._send(cmd.encode("ascii") + b"\r")

    def listen_after_bootm(self, seconds, cmd):
        """Listen for up to `seconds`, stopping early on a garbled echo, a U-Boot failure or
        reset, the prompt coming back, kernel trouble, or "Please press Enter". Returns (back at
        the prompt, kernel started, the text before the kernel started). Checked on every read,
        so a long kernel log can't push "Starting kernel" out of the capped tail first."""
        end = self.clock.monotonic() + seconds
        started, before = False, None
        self.info.update(kernel_started=False, kernel_output=False, reached_userspace=False)
        while self.clock.monotonic() < end:
            self.pump()
            # A garbled bootm (e.g. "boot ...") would run the stock bootcmd: stop on any echo
            # that isn't exactly the command.
            if "\n" in self.head and not self.head.startswith(cmd + "\n"):
                self.info["echo_mismatch"] = self.head.partition("\n")[0]
                return False, False, self.tail
            if not started:
                at = self.tail.find("Starting kernel")
                pre = self.tail if at < 0 else self.tail[:at]
                if RESET.search(pre):
                    self.info["reset_before_start"] = True
                    return False, False, self.tail
                if at < 0 and FAILS["bootm"].search(pre):  # e.g. "FDT creation failed! hanging"
                    return False, False, self.tail
                if at >= 0:
                    started, before = True, self.tail
                    self.info["kernel_started"] = True  # recorded now, in case of Ctrl+C
                    self.tail = self.tail[at:]
                elif self.at_prompt():
                    return True, False, self.tail
            if started:
                if "Linux version" in self.tail:
                    self.info["kernel_output"] = True
                bad = KERNEL_BAD.search(self.tail)
                if bad:
                    self.info["kernel_trouble"] = bad.group(0)
                    return False, True, before
                if "Please press Enter" in self.tail:  # OpenWrt's userspace is up: done
                    self.info["reached_userspace"] = True
                    return False, True, before
        return False, started, before if started else self.tail


def run(session, cmds, wait, cmd_timeout, listen):
    """Stop autoboot, then run each command. Raises StepFailed with what to do next."""
    if not session.wait_for(AUTOBOOT, wait):
        raise StepFailed(f"no 'Hit any key to stop autoboot' within {wait} s. Power the router "
                         "on after starting this tool, and check RX is on pin 3")
    if not session.send_stop_key():
        raise StepFailed("autoboot didn't stop (no U-Boot prompt after the key). Most likely "
                         "the cable's TX isn't on the router's RX: leave pin 4 alone. The router "
                         "boots stock as usual")
    session.info["autoboot_stopped"] = True
    for cmd in cmds:
        word = cmd.split()[0]
        session.send_command(cmd)
        if word == "bootm":
            back, started, before = session.listen_after_bootm(listen, cmd)
            dt = re.search(r"Loading Device Tree to ([0-9a-fA-F]{8})", before or "")
            session.info["fdt_addr"] = "0x" + dt.group(1) if dt else None
            if "echo_mismatch" in session.info:
                raise StepFailed(f"U-Boot echoed {session.info['echo_mismatch']!r}, not {cmd!r}: "
                                 "line noise on the serial wires?" + POWER_CYCLE)
            if session.info.get("reset_before_start"):
                raise StepFailed("U-Boot reset or started again after bootm, before the image "
                                 "started; anything that boots now is stock (see boot.log)."
                                 + POWER_CYCLE)
            if back or (not started and FAILS["bootm"].search(before)):
                raise StepFailed("bootm didn't start the image (see boot.log): U-Boot refused "
                                 "it." + POWER_CYCLE)
            if not started:
                raise StepFailed(f"no 'Starting kernel' within {listen} s of bootm (see "
                                 "boot.log)." + POWER_CYCLE)
            if session.info.get("kernel_trouble"):
                raise StepFailed(f"the kernel started, then '{session.info['kernel_trouble']}' "
                                 "(see boot.log)." + POWER_CYCLE)
            if (dt and "setenv fdt_high 0x87000000" in cmds
                    and int(dt.group(1), 16) >= 0x87000000):
                raise StepFailed(f"U-Boot put the DTB at {session.info['fdt_addr']}, above the "
                                 "fdt_high that was set (see boot.log)." + POWER_CYCLE)
            if not session.info["kernel_output"]:
                hint = ("" if any(c.startswith("setenv bootargs") for c in cmds)
                        else " This run didn't set bootargs, and the stock env names no console.")
                raise StepFailed(f"the kernel started but printed no 'Linux version' within "
                                 f"{listen} s: no console, or it hung (see boot.log)." + hint
                                 + POWER_CYCLE)
            if not session.info["reached_userspace"]:
                raise StepFailed(f"the kernel printed but didn't reach 'Please press Enter' "
                                 f"within {listen} s: it hung or lost its console (see the end "
                                 "of boot.log)." + POWER_CYCLE)
            return
        if not session.wait_prompt(cmd_timeout):
            raise StepFailed(f"'{cmd}' didn't return to the prompt within {cmd_timeout} s. "
                             "Nothing after it was sent." + POWER_CYCLE)
        # U-Boot echoes what it received. A different echo means line noise changed the command
        # (a setenv prints nothing either way), so stop before anything else is sent.
        if not session.head.startswith(cmd + "\n"):
            echo = session.head.partition("\n")[0]
            raise StepFailed(f"U-Boot echoed {echo!r}, not {cmd!r}: line noise on the serial "
                             "wires? Nothing after it was sent." + POWER_CYCLE)
        body = session.tail  # without the echoed command, unless the cap already dropped it
        if body.startswith(cmd + "\n"):
            body = body[len(cmd) + 1:]
        # tftpboot names its file ("Filename 'abort.itb'."): drop that line before matching, and
        # judge only what came after the last "Bytes transferred" (a retry can come first).
        body = re.sub(r"(?m)^Filename '.*$", "", body)
        if word == "tftpboot":
            ok = list(TFTP_OK.finditer(body))
            body = body[ok[-1].end():] if ok else None
        # md's dump can hold any text in its ASCII column: only a first line that isn't a dump
        # line ("84000000: ...") is checked, since that's where U-Boot prints Usage or an error.
        elif word.startswith("md"):
            body = body.partition("\n")[0]
            if re.match(r"[0-9a-fA-F]{8}:", body):
                body = ""
        failed = (body is None
                  or UNKNOWN.search(body)
                  or (word != "help" and ANY_FAIL.search(body))
                  or (word in FAILS and FAILS[word].search(body))
                  or (word == "ping" and "is alive" not in body))
        if failed:
            raise StepFailed(f"'{cmd}' failed (see boot.log). Nothing after it was sent."
                             + POWER_CYCLE)


def finish(run_dir, cap, info):
    """Write summary.txt, then manifest.json, each on its own so one failure can't stop the
    other; the manifest is last so it records a summary failure too."""
    def add_error(msg):
        info["error"] = f"{info['error']}; {msg}" if info.get("error") else msg

    info.setdefault("stopped_by", "stopped early")
    try:
        cap.finish()
    except Exception as e:
        add_error(f"finishing boot.log: {e}")
    info["ended"] = datetime.datetime.now().isoformat(timespec="seconds")
    try:
        info.update(bytes=cap.total, lines=cap.lines, verdict=cap.verdict(),
                    landmarks=cap.landmarks)
    except Exception as e:
        add_error(f"counting the capture: {e}")
    for fname, make in (("summary.txt", lambda: sl.summary_text(cap, info)),
                        ("manifest.json", lambda: json.dumps(info, indent=2) + "\n")):
        try:
            (run_dir / fname).write_text(make(), encoding="utf-8")
        except Exception as e:
            add_error(f"writing {fname}: {e}")


def main(argv=None, out_root=sl.DEFAULT_OUT, opener=RWPort, finder=sl.find_port, clock=time,
         out=None):
    out = out or sys.stdout
    ap = argparse.ArgumentParser(description="Allowlisted U-Boot console for the RBR10.")
    ap.add_argument("--port", help="default: find the CP2102")
    ap.add_argument("--baud", type=int, default=sl.DEFAULT_BAUD)
    ap.add_argument("--cmd", action="append", help="a U-Boot command (repeat); see ALLOWED")
    ap.add_argument("--wait", type=float, default=180, help="seconds to wait for autoboot")
    ap.add_argument("--cmd-timeout", type=float, default=60)
    ap.add_argument("--listen", type=float, default=180, help="seconds to listen after bootm")
    a = ap.parse_args(argv)
    if not all(math.isfinite(v) for v in (a.wait, a.cmd_timeout, a.listen)) or \
            min(a.wait, a.cmd_timeout, a.listen, a.baud) <= 0:
        ap.error("--wait, --cmd-timeout, --listen and --baud must be finite and above 0")
    cmds = a.cmd or LOOK_ONLY
    bad = [c for c in cmds if not allowed(c)]
    if bad:
        print(f"Refused (not on the allowlist): {', '.join(ascii(c) for c in bad)}", file=out)
        return 2
    if any(c.startswith("bootm") for c in cmds[:-1]):
        print("Refused: bootm must be the last command", file=out)
        return 2
    if cmds[-1].startswith("bootm") and not any(c.startswith("tftpboot") for c in cmds):
        print("Refused: bootm needs a tftpboot before it in the same run", file=out)
        return 2
    # Ctrl+C only sets this flag, from here to the end, so it can't land between steps: the
    # first read of the run raises it, and finish() still writes the files.
    stop = [False]
    installed, old = False, None
    if threading.current_thread() is threading.main_thread():
        old = signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
        installed = True
    try:
        return _main(a, cmds, stop, out_root, opener, finder, clock, out)
    finally:
        if installed:
            signal.signal(signal.SIGINT, old if old is not None else signal.SIG_DFL)


def _main(a, cmds, stop, out_root, opener, finder, clock, out):
    try:
        name = a.port or finder()
        port = opener(name, a.baud)
    except (sl.PortNotFound, OSError) as e:
        print(f"Can't open the serial port: {e}", file=out)
        return 1
    code = 0
    try:
        info = {"tool": "uboot_console.py", "port": name, "baud": a.baud,
                "handle": getattr(port, "access", "unknown"), "commands": cmds,
                "started": datetime.datetime.now().isoformat(timespec="seconds")}
        run_dir = sl.make_run_dir(out_root)
        print(f"Ready on {name}. Power the router on now. Commands: {cmds}. Saving to "
              f"{run_dir}", file=out, flush=True)
        with open(run_dir / "boot.raw", "wb") as raw_f, \
                open(run_dir / "boot.log", "w", encoding="utf-8", newline="\n") as log_f:
            cap = sl.Capture(raw_f, log_f)
            session = Session(port, cap, info, clock)
            session.stop = stop
            try:
                run(session, cmds, a.wait, a.cmd_timeout, a.listen)
                info["stopped_by"] = "done"
            except StepFailed as e:
                info["stopped_by"], info["error"], code = "step failed", str(e), 1
            except KeyboardInterrupt:
                info["stopped_by"], code = "Ctrl+C", 1
                info["error"] = "stopped with Ctrl+C." + POWER_CYCLE
            except OSError as e:
                info["stopped_by"], info["error"], code = "port or file error", f"{e}", 1
            except BaseException as e:
                info["stopped_by"], info["error"] = "crashed", f"{type(e).__name__}: {e}"
                raise
            finally:
                finish(run_dir, cap, info)
                if info.get("error"):  # a result file that failed to save is not success
                    code = code or 1
    except OSError as e:  # the run folder or its files couldn't be made
        print(f"Can't save the run: {e}", file=out)
        return 1
    finally:
        port.close()
    msg = info.get("error") or "done"
    print(msg.encode("ascii", "replace").decode("ascii"), file=out)
    return code


if __name__ == "__main__":
    sys.exit(main())
