"""Read-only recon of a Netgear Orbi RBR10 over telnet.

Usage:  python -I orbi_telnet.py [HOST]          (HOST defaults to 192.168.1.1)
        python -I orbi_telnet.py --probe [HOST]  (instead of the recon: with you at the router,
            find the LAN switch port and which GPIO the Sync button moves; see probe())
        python -I orbi_telnet.py --secboot [HOST] (instead of the recon: the secure-boot evidence in
            SECBOOT_COMMANDS, gathered into secboot_summary.txt; nothing to press)
Needs:  telnet running on the Orbi (debug.htm on older firmware, or telnetenable on
        newer firmware), and a real terminal, because the admin password is read with
        getpass so your typing stays hidden. If telnet is off you'll get a connection
        refused; switch it on first.

The password is typed by you, sent once to the router and never stored or printed, and
no router text is put into error messages after the password is sent. Telnet itself sends
the password unencrypted, as telnet always does: run this only on your own LAN.

Each run writes to a new folder, ../recon/<date-time-us>/ (next to tools/, us = microseconds):
  <name>.txt     one file per command: its output with the echoed command removed, line
                 endings normalised to LF and trailing blank lines trimmed (so empty
                 output is saved as a single newline). A command that times out leaves a
                 partial <name>.txt with rc null, and so does a lost
                 connection (flagged "connection_lost" in the manifest). If that file
                 can't be written, the partial output is still in manifest.json.
  recon.txt      every output in one file, with the command and exit code above each
  manifest.json  host, times, each command's exit code, warnings, an "error" field if a
                 run stopped early, and "complete": true/false
  --probe writes dt_model.txt and fw_version.txt (the identity check runs first), probe_*.txt
  (one per step), probe_summary.txt (written even if a step fails) and a "probe" key in
  manifest.json, instead of the full recon.
  --secboot writes dt_model.txt, fw_version.txt, one <name>.txt per SECBOOT_COMMANDS entry and
  secboot_summary.txt (written even if a command fails; it marks failed reads NOT EVIDENCE).
A caught failure (OSError/RuntimeError/LoginFailed) writes manifest.json with
"complete": false and an "error"; an uncaught one (Ctrl+C, EOF, a bug) still writes the
manifest in a finally block, then re-raises.
The files hold MACs, IPs and maybe the serial number (e.g. in appsblenv, the U-Boot env, and
boarddata1_head): a .gitignore beside this project keeps recon/ out of git.
Flash is only ever read (hexdump/tr/wc of /dev/mtdN, never mtd/flash_erase/nandwrite/dd).

Python 3.13 and later have no telnetlib (PEP 594), so this has a small telnet client of its own.
"""
import argparse
import collections
import datetime
import getpass
import json
import pathlib
import re
import socket
import sys
import time

# Telnet command bytes (RFC 854/855).
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
CR, NUL = 13, 0

DEFAULT_HOST = "192.168.1.1"
DEFAULT_OUT = pathlib.Path(__file__).resolve().parent.parent / "recon"


def _if_exists(path, cmd):
    """Shell $(...) that runs `cmd` if `path` exists, else prints "absent" (no error text)."""
    return f"$(if [ -e {path} ]; then {cmd}; else echo absent; fi)"


def _dt_str(path):
    """Shell $(...) printing a single-string DT property (NUL dropped), or "absent"."""
    return _if_exists(path, f"tr -d '\\0' < {path}")


def _dt_cells(path):
    """Shell $(...) printing a DT property as big-endian 32-bit cells in hex."""
    return f"$(hexdump -v -e '4/1 \"%02x\" \" \"' {path})"


def _on_mtd(name, body):
    """Shell line that finds the mtd device named `name` in /proc/mtd and runs `body` with it
    in $d. If there is not exactly one match it says so and exits 1, so a renamed partition
    can never make `body` read /dev/ or the wrong device."""
    return (f"d=$(grep '\"{name}\"' /proc/mtd | cut -d: -f1);"
            f' if [ -z "$d" ] || [ "${{d#*[!a-z0-9]}}" != "$d" ]; then'
            f' echo "no single mtd named {name} in /proc/mtd"; false;'
            f' else echo "device: /dev/$d"; {body}; fi')


# rc is the exit code of the LAST command on the line, so for ';' lists and 'for' loops
# (fw_version, tools) rc 0 does not mean every part worked; errors land in the output
# instead, and check_warnings() flags common error phrases there. (dt_model uses '&&', so
# there rc 0 does mean both parts ran.)
# Every entry must stay read-only. CommandListTests in tests/test_orbi_telnet.py blocks the
# write commands it knows about; it cannot prove a command is read-only, so review every new
# entry by hand. "config show" is left out on purpose: it dumps the whole NVRAM config,
# including the admin and Wi-Fi passwords and any ISP login. No head/tail: they would cut
# output short without saying so. (The one vetted exception is orbi_backup's --rehash, which uses
# `head -c N /dev/mtdX` as a deliberate byte-bounded read for hashing; FORBIDDEN allows only that
# `head -c <digits>` form, still blocking bare head/tail line-truncation.)
COMMANDS = {
    # The first two confirm this is an Orbi RBR before the rest run; collect() needs
    # dt_model before fw_version. && so a missing first file shows up as a non-zero rc.
    "dt_model": "tr '\\0' '\\n' < /proc/device-tree/model && tr '\\0' '\\n' < /proc/device-tree/compatible",
    "fw_version": 'for f in /module_name /hardware_version /firmware_version; do echo "$f: $(cat $f 2>&1)"; done',
    "version": "cat /proc/version",
    "cpuinfo": "cat /proc/cpuinfo",
    "meminfo": "cat /proc/meminfo",
    "mtd": "cat /proc/mtd",
    "partitions": "cat /proc/partitions",
    "cmdline": "cat /proc/cmdline",
    "dmesg": "dmesg",
    "dt_tree": "find /proc/device-tree",
    "fdt": "ls -l /sys/firmware/fdt",
    "fw_printenv": "fw_printenv",
    "fw_env_config": "cat /etc/fw_env.config",
    "ifconfig": "ifconfig -a",
    "bridges": "brctl show",
    "net_dev": "cat /proc/net/dev",
    "leds": "ls -l /sys/class/leds",
    "gpio_debugfs": "cat /sys/kernel/debug/gpio",
    "gpio_sysfs": "ls -l /sys/class/gpio",
    "mounts": "mount",
    "df": "df",
    "dev": "ls -l /dev",
    "busybox": "busybox",
    # command -v finds builtins and anything on PATH; busybox --list also finds applets
    # that aren't symlinked into PATH.
    "tools": (
        "for t in nc tftp base64 hexdump od uuencode dd md5sum sha256sum gzip httpd wget curl"
        " dtc fw_printenv artmtd; do"
        ' if command -v $t >/dev/null 2>&1; then echo "$t: $(command -v $t)";'
        ' elif busybox --list 2>/dev/null | grep -qx $t; then echo "$t: busybox applet";'
        ' else echo "$t: missing"; fi; done'
    ),
    "board_data": "ls -lR /lib/firmware",
    # --- Flash layout for the device tree. Summing /proc/mtd sizes does NOT give offsets (the
    # live DT node partition@4c80000 doesn't fit a plain sum), so read them from the source. ---
    # Per partition (the *ro read-only twins skipped): name, offset, size, erasesize, type from
    # sysfs. Kernel 3.14 may have no `offset` attribute; then it prints offset=absent and
    # check_warnings says so (an unreadable one shows cat's error instead).
    "mtd_sysfs": (
        "for d in /sys/class/mtd/mtd*; do n=${d##*/}; case $n in *ro) continue;; esac;"
        ' echo "$n name=$(cat $d/name) offset=' + _if_exists("$d/offset", "cat $d/offset") +
        ' size=$(cat $d/size) erasesize=$(cat $d/erasesize) type=$(cat $d/type)"; done'
    ),
    # The DT partition nodes U-Boot adds under the QPIC NAND controller: label, then reg as
    # big-endian 32-bit cells in hex (address, size).
    "dt_partitions": (
        "for p in /proc/device-tree/soc/qcom,nand@7980000/partition@*; do"
        ' echo "${p##*/} label=' + _dt_str("$p/label") + " reg=" + _dt_cells("$p/reg") + '"; done'
    ),
    # Qualcomm's SMEM partition table lives at the start of 0:MIBIB (page 0 header, page 1
    # table). 8 KB (4 pages) covers both with room to spare; hexdump -C squashes repeated lines.
    "mibib_ptable": _on_mtd("0:MIBIB", "hexdump -C -n 8192 /dev/$d"),
    # The U-Boot environment, for bootcmd/bootargs/mtdparts: where the loader reads the kernel.
    # Raw hex (CRC, then NUL-separated name=value strings), decoded on the PC afterwards: a
    # tr|grep filter here would hide tr's exit code and glue printable CRC bytes onto the first
    # name. 64 KB holds the whole env in practice; the rest of the partition is padding.
    "appsblenv": _on_mtd("0:APPSBLENV", "hexdump -C -n 65536 /dev/$d"),
    # Start of boarddata1, to find the MAC fields instead of copying the RBR20's cell offsets.
    "boarddata1_head": _on_mtd("boarddata1", "hexdump -C -n 64 /dev/$d"),
    # Radio calibration source per wifi node: which mtd and which ART offset/length.
    # status=absent means the node has no status property, which in a device tree means okay.
    "dt_wifi_cal": (
        "for w in /proc/device-tree/soc/wifi@*; do"
        ' echo "${w##*/} status=' + _dt_str("$w/status") + " mtd=" + _dt_str("$w/qcom,mtd-name") +
        " cal-offset=" + _dt_cells("$w/qcom,cal-offset") + " cal-len=" + _dt_cells("$w/qcom,cal-len") +
        '"; done'
    ),
    # Is a PCIe radio (QCA9888) actually there? DT status plus any enumerated PCI device. A
    # missing PCI bus is a valid answer ("no PCI ..."), not an error.
    "pcie": (
        'echo "pcie@80000 status=' + _dt_str("/proc/device-tree/soc/qcom,pcie@80000/status") + '";'
        " if [ -d /sys/bus/pci/devices ]; then ls -l /sys/bus/pci/devices/; else echo 'no PCI bus in sysfs'; fi;"
        " if [ -e /proc/bus/pci/devices ]; then cat /proc/bus/pci/devices; else echo 'no PCI devices in /proc'; fi"
    ),
    # Which mtd each UBI device is attached to (secdata/ntgrdata per the stock layout). *_*
    # skips the volumes (ubi0_0) and the ubi_ctrl node.
    "ubi": (
        "for u in /sys/class/ubi/ubi*; do n=${u##*/}; case $n in *_*) continue;; esac;"
        ' echo "$n mtd_num=$(cat $u/mtd_num) volumes=$(cat $u/volumes_count)"; done'
    ),
}

# --- --secboot: does this unit's boot chain enforce Qualcomm secure boot? The stock kernel is a
# signed image (a 40-byte MBN header, image_id 0x17, before the FIT, then a signature and a Netgear cert
# chain). A signed stock image does NOT show that the fuses enforce signatures; an unsigned OpenWrt
# FIT only boots if they don't. All read-only, like COMMANDS (the same FORBIDDEN test covers these,
# and SecbootTests pins every flash access to `< /dev/$d` or a bounded hexdump).
# The result decides whether flashing is safe, so every command prints its own status lines and
# check_warnings flags a failed or partial read: a missing answer must never look like "no secure boot".
# ---
# Printable runs of 6+ characters (like `strings`) of one whole partition. "size" (sysfs) and
# "bytes read" (a first full read) must match; the second read, by tr, prints TR-FAILED if it fails,
# since the pipe's exit code is grep's. Tool errors land in the output as "tr: ..." lines. mtdchar
# doesn't skip bad blocks and returns uncorrectable (ECC) data as success, so the partition's bad-block
# count and its ECC-failure count before and after the reads are printed too.
_MTD_ATTR = "$(cat /sys/class/mtd/$d/{0} 2>/dev/null || echo unknown)"
_STRINGS = ("echo \"size: $(cat /sys/class/mtd/$d/size 2>&1)\"; "
            f"echo \"bad_blocks: {_MTD_ATTR.format('bad_blocks')}\"; "
            f"echo \"ecc_failures before: {_MTD_ATTR.format('ecc_failures')}\"; "
            "echo \"bytes read: $(wc -c < /dev/$d)\"; "
            # ' -~' is space..tilde as literal characters, so no BusyBox escape handling is involved
            "{ tr -c ' -~' '\\n' < /dev/$d || echo \"TR-FAILED rc=$?\"; } | grep -E '.{6,}'; "
            f"echo \"ecc_failures after: {_MTD_ATTR.format('ecc_failures')}\"")
SECBOOT_COMMANDS = {
    # QSDK kernels expose the secure-boot fuse state here: qfprom0/authenticate is the answer, the
    # other files are context. Every file but uevent is read and printed as "path: value (rc=N)"
    # ("(empty, rc=0)" for no value), then "qfprom values read: N" counts the non-empty clean reads;
    # a missing directory prints "absent". The fuse state counts as known only if authenticate itself
    # read cleanly. A store-only attribute refuses the open ("can't open ...: Permission denied", even
    # for root): it is listed as write-only and skipped. A read that fails any other way, including a
    # show handler that returns Permission denied, prints its error and rc. Reading a sysfs attribute
    # only calls its show handler; for qfprom that is a TrustZone call that reads the fuses.
    "sec_qfprom": (
        "for d in /sys/devices/system/qfprom /sys/devices/system/qfprom/qfprom0; do"
        ' echo "== $d"; if [ -d $d ]; then ls -l $d; else echo absent; fi; done;'
        " n=0; for f in /sys/devices/system/qfprom/qfprom0/*; do"
        ' if [ "${f##*/}" = uevent ]; then continue; fi;'
        ' if [ -f "$f" ]; then v=$(cat "$f" 2>&1); r=$?;'
        ' case "$r:$v" in 0:) echo "$f: (empty, rc=0)";;'
        ' 0:*) n=$((n+1)); echo "$f: $v (rc=0)";;'
        ' *"can\'t open"*"Permission denied"*) echo "$f: (write-only, skipped)";;'
        ' *) echo "$f: $v (rc=$r)";; esac; fi; done;'
        ' echo "qfprom values read: $n"'
    ),
    # Kernel messages about secure boot, TrustZone or signatures. dmesg's exit code and first line
    # are printed, so a failed dmesg or a wrapped ring buffer (early-boot lines gone) is flagged.
    "sec_dmesg": (
        "o=$(dmesg 2>&1); echo \"dmesg rc=$?\";"
        " echo \"$o\" | awk 'NR==1 {print \"first line: \" $0}';"
        " echo \"$o\" | grep -i -E 'secur|qfprom|authent|sec_boot|signed|signature|qsee|tzbsp|scm';"
        " echo grep-done"
    ),
    "sbl1_strings": _on_mtd("0:SBL1", _STRINGS),
    "appsbl_strings": _on_mtd("0:APPSBL", _STRINGS),
    # The start of the stock kernel on flash: a 0x17 MBN header means the IMAGE is signed (not that
    # the fuses enforce it). mtdchar doesn't skip bad blocks, so the partition's count is shown too.
    "kernel_head": _on_mtd("kernel", f"echo \"bad_blocks: {_MTD_ATTR.format('bad_blocks')}\";"
                                     " hexdump -C -n 128 /dev/$d"),
    # Anything else in sysfs or the device tree that names secure boot or the fuses. Last, so a slow
    # walk can't cost the flash reads above. Errors are kept and find's own exit code is printed, so a
    # find that failed can't look like "nothing found".
    "sec_sysfs_find": (
        "find /sys /proc/device-tree/ -maxdepth 8 \\( -iname '*qfprom*' -o -iname '*sec_boot*'"
        " -o -iname '*secboot*' -o -iname '*authent*' -o -iname '*secure*' \\) 2>&1; echo \"find rc=$?\""
    ),
}
# Lines pulled out of the strings dumps into secboot_summary.txt (case-insensitive). STRONG ones are
# listed in full; WEAK ones (boot-flow words, which also match U-Boot's help texts) are capped.
SECBOOT_STRONG = re.compile(r"secur|authent|signat|signed|\bsign\b|sec_boot|qfprom|fuse|certif", re.I)
SECBOOT_WEAK = re.compile(
    r"bootcmd|bootm|bootipq|bootargs|config@|\bfdt\b|\bfit\b|rootfs|uimage|0x84000000|hd_id|board_id|"
    r"iminfo|fw_recovery|magic|dniimg|boot_partition|"
    r"\brsa\b|sha256|\bhash\b", re.I)
# A shell or tool error line inside a strings dump (BusyBox prints "tr: read error: ..." etc.).
TOOL_ERROR_RE = re.compile(r"^(?:-?sh|ash|tr|wc|grep|cat|hexdump|awk): ", re.M)

# Phrases that mean a command printed an error even though rc may be 0 (see the rc note above).
ERROR_PHRASES = ("can't open", "cannot open", "No such file", "not found", "applet not found",
                 "Permission denied", "Operation not permitted", "read error", "Input/output error",
                 "Invalid argument")

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# Netgear's telnetd prompts "telnet account:" then "telnet password:", so "account" counts as a
# login prompt alongside the usual "login:"/"username:" (the account is the web-GUI admin login).
LOGIN_RE = re.compile(r"(login|username|account)\s*:\s*$", re.I)
PASSWORD_RE = re.compile(r"password\s*:\s*$", re.I)
SHELL_RE = re.compile(r"(?:^|[^#$])[#$]\s*$")  # real prompt ends "... # "/"$ "; reject "####" borders
IDENT_RE = re.compile(r"\bRBR\d+\b", re.I)


class LoginFailed(Exception):
    pass


class Telnet:
    """Telnet client that refuses every option and keeps parser state between reads, so a
    telnet command sequence (IAC ...) split across two recv() calls is still handled."""

    def __init__(self, sock):
        self.s = sock
        self.buf = b""
        self._state = "data"
        self._cmd = 0
        self._last_cr = False
        self._replied = set()
        self.output_started = False  # set by run_command; collect() uses it after a timeout

    @classmethod
    def connect(cls, host, port=23):
        return cls(socket.create_connection((host, port), timeout=10))

    def feed(self, data):
        """Strip telnet commands from received bytes, answer option requests, return plain data."""
        out = bytearray()
        for b in data:
            st = self._state
            if st == "data":
                if b == IAC:
                    self._state = "iac"
                    self._last_cr = False
                elif b == NUL and self._last_cr:
                    self._last_cr = False  # CR NUL is how telnet sends a bare CR
                else:
                    out.append(b)
                    self._last_cr = b == CR
            elif st == "iac":
                if b == IAC:
                    out.append(IAC)  # IAC IAC is one literal 0xFF byte
                    self._state = "data"
                elif b in (DO, DONT, WILL, WONT):
                    self._cmd = b
                    self._state = "opt"
                elif b == SB:
                    self._state = "sb"
                else:
                    self._state = "data"  # NOP, GA and other two-byte commands
            elif st == "opt":
                self._refuse(self._cmd, b)
                self._state = "data"
            elif st == "sb":
                if b == IAC:
                    self._state = "sb_iac"
            elif st == "sb_iac":
                self._state = "data" if b == SE else "sb"
        return bytes(out)

    def _refuse(self, cmd, opt):
        reply = WONT if cmd == DO else DONT if cmd == WILL else None
        # Answer each option once, so a server that re-asks can't start a loop.
        if reply is not None and (reply, opt) not in self._replied:
            self._replied.add((reply, opt))
            self._send_raw(bytes([IAC, reply, opt]))

    def _send_raw(self, data):
        self.s.settimeout(10)
        self.s.sendall(data)

    def _recv_raw(self, wait):
        """One recv, waiting up to max(0.05, wait) seconds. Returns b"" on timeout.
        Raises ConnectionError if the router closed the connection."""
        self.s.settimeout(max(0.05, wait))
        try:
            data = self.s.recv(4096)
        except socket.timeout:
            return b""
        if not data:
            raise ConnectionError("the router closed the telnet connection")
        return data

    def read_until(self, pattern, timeout, what):
        """Read until the bytes regex `pattern` matches. Returns (bytes before the match, match).
        Bytes after the match stay in self.buf for the next read. The TimeoutError names
        `what` and the timeout but never includes received text, so nothing can leak."""
        rx = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while True:
            m = rx.search(self.buf)
            if m:
                before, self.buf = self.buf[: m.start()], self.buf[m.end():]
                return before, m
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"no {what} from the router after {timeout}s")
            self.buf += self.feed(self._recv_raw(min(left, 1.0)))

    def wait_for_prompt(self, timeout):
        """Read until the last non-blank line looks like a shell, login or password prompt,
        however long the router takes (handles BusyBox login's multi-second fail delay).
        Returns 'shell' | 'login' | 'password'. No received text goes into any error."""
        deadline = time.monotonic() + timeout
        while True:
            line = last_line(self.buf)
            # login/password prompts end in ":" and shell prompts in #/$, so a line matches at most
            # one; the tightened SHELL_RE above (not this order) is what rejects "####" borders.
            # Order is just defensive.
            for kind, rx in (("login", LOGIN_RE), ("password", PASSWORD_RE), ("shell", SHELL_RE)):
                if rx.search(line):
                    self.buf = b""  # consume it, so a later wait doesn't re-match this prompt
                    return kind
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"no prompt from the router after {timeout}s")
            self.buf += self.feed(self._recv_raw(min(left, 1.0)))

    def send(self, line):
        # UTF-8 never contains byte 0xFF, so no IAC escaping is needed on send.
        self._send_raw(line.encode() + b"\r\n")

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def last_line(data):
    text = ANSI_RE.sub("", data.decode("utf-8", "backslashreplace"))
    lines = [ln for ln in text.replace("\r", "\n").split("\n") if ln.strip()]
    return lines[-1] if lines else ""


def login(t, ask_user, ask_password):
    """Log in if the router asks. Returns when a shell prompt is reached.
    Raises LoginFailed on wrong credentials, RuntimeError on an unexpected sequence."""
    kind = t.wait_for_prompt(20)
    if kind == "shell":
        return  # a shell with no login
    if kind == "login":
        t.send(ask_user())
        kind = t.wait_for_prompt(20)
        if kind == "shell":
            return
        if kind != "password":
            raise RuntimeError("no password prompt after the username")
    # kind == "password" (asked straight away, or after the username)
    t.send(ask_password())
    # From here nothing received is shown, in case the router echoed the password.
    kind = t.wait_for_prompt(25)
    if kind == "shell":
        return
    raise LoginFailed("login failed: wrong username or password (or an unexpected post-login prompt)")


def run_command(t, n, cmd, timeout=60):
    """Run `cmd` between two marker lines and return (output, exit code).

    The markers are typed as __B''n__ / __E''n__ and printed by the shell as __Bn__ / __En__,
    so the echo of the typed line can never contain a whole marker line. The echo is dropped
    because it comes before the start marker; the next prompt is dropped because it comes
    after the end marker; whole-line (?m)^ matching stops a marker matching mid-line. The
    extra `echo` makes the end marker start its own line even when the output has no trailing
    newline. `timeout` applies to the end marker; the start marker has a fixed 30 s. `cmd`
    must be one complete shell line."""
    # Reset before sending, so a send that times out isn't read as the previous command's output.
    t.output_started = False
    t.send(f"echo __B''{n}__; {cmd}; __rc=$?; echo; echo __E''{n}__ rc=$__rc")
    t.read_until(rb"(?m)^__B%d__\r?\n" % n, 30, f"start of output for command {n}")
    t.output_started = True
    before, m = t.read_until(rb"(?m)^__E%d__ rc=(\d+)\r?\n" % n, timeout, f"end of output for command {n}")
    return clean(before), int(m.group(1))


def clean(raw):
    """Normalise CRLF to LF and trim trailing blank lines; always end in exactly one LF."""
    text = raw.decode("utf-8", "backslashreplace").replace("\r\n", "\n").replace("\r", "\n")
    return text.rstrip("\n") + "\n"


def _secboot_warnings(name, body):
    """Warnings for the --secboot commands' own status lines (see SECBOOT_COMMANDS). Each one says
    when an answer is missing, so a failed read can't pass as evidence of "no secure boot"."""
    w = []
    if name.endswith("_strings"):
        size = re.search(r"^size: (\d+)$", body, re.M)
        got = re.search(r"^bytes read: (\d+)$", body, re.M)
        if not got or int(got.group(1)) == 0:
            w.append(f"{name}: the partition could not be read (no byte count), so its strings are "
                     "missing; NOT evidence")
        elif not size:
            w.append(f"{name}: the partition size is unknown, so a partial read can't be ruled out")
        elif int(got.group(1)) != int(size.group(1)):
            w.append(f"{name}: read only {got.group(1)} of {size.group(1)} bytes, so the strings are "
                     "partial; NOT evidence")
        if "TR-FAILED" in body:
            w.append(f"{name}: the strings read (tr) failed, so the strings are partial; NOT evidence")
        if TOOL_ERROR_RE.search(body):
            w.append(f"{name}: a shell or tool error is in the output, so the read may be partial")
        w += _bad_block_warnings(name, body)
        before = re.search(r"^ecc_failures before: (\d+)$", body, re.M)
        after = re.search(r"^ecc_failures after: (\d+)$", body, re.M)
        if not before or not after:
            w.append(f"{name}: the ECC-failure count is unknown, so uncorrectable blocks can't be ruled out")
        elif int(after.group(1)) > int(before.group(1)):
            w.append(f"{name}: {int(after.group(1)) - int(before.group(1))} ECC failure(s) during the read, "
                     "so some strings may be garbage or missing; NOT evidence")
        status = ("device:", "size:", "bad_blocks:", "ecc_failures", "bytes read:", "TR-FAILED")
        if got and not [ln for ln in body.splitlines() if ln.strip() and not ln.startswith(status)]:
            w.append(f"{name}: no strings found (an erased or unreadable partition?)")
    elif name == "sec_qfprom":
        if not re.search(r"/authenticate: (?!\(empty)\S.* \(rc=0\)$", body, re.M):
            w.append("sec_qfprom: the authenticate fuse could not be read, so the secure-boot fuse state "
                     "is UNKNOWN (this is NOT evidence that secure boot is off)")
        if re.search(r"\(rc=[1-9]\d*\)$", body, re.M):
            w.append("sec_qfprom: at least one qfprom file failed to read")
    elif name == "sec_sysfs_find":
        if not re.search(r"^find rc=0$", body, re.M):
            w.append("sec_sysfs_find: find failed, so an empty result is NOT evidence")
    elif name == "sec_dmesg":
        if not re.search(r"^dmesg rc=0$", body, re.M):
            w.append("sec_dmesg: dmesg failed, so an empty result is NOT evidence")
        first = re.search(r"^first line: (?:<\d+>)?(.*)$", body, re.M)
        if not first:
            w.append("sec_dmesg: dmesg's first line couldn't be read (is awk missing?), so whether the "
                     "log starts at boot is unknown")
        elif not first.group(1).startswith("[    0.000000] Booting Linux"):
            w.append("sec_dmesg: the kernel log doesn't start at boot (ring buffer wrapped), so early "
                     "secure-boot messages are gone; reboot the router first for a full log")
    elif name == "kernel_head":
        w += _bad_block_warnings(name, body)
    return w


def _bad_block_warnings(name, body):
    bb = re.search(r"^bad_blocks: (\S+)$", body, re.M)
    if not bb or not bb.group(1).isdigit():
        return [f"{name}: the bad-block count is unknown, so a bad block in what was read can't be "
                "ruled out"]
    if int(bb.group(1)) > 0:
        return [f"{name}: the partition has {bb.group(1)} bad block(s); what was read may not be the "
                "real data there"]
    return []


def check_warnings(name, body, rc):
    warnings = []
    if rc != 0:
        warnings.append(f"{name}: exit code {rc}; the output may be partial or only an error")
    # Strings dumps and filtered logs quote the firmware's own messages ("not found" etc.), so the
    # phrase check would misfire on them; their rc and empty-output checks still apply.
    elif not name.endswith("_strings") and name != "sec_dmesg" and any(p in body for p in ERROR_PHRASES):
        warnings.append(f"{name}: output contains an error message though exit code was 0")
    if not body.strip():
        warnings.append(f"{name}: empty output")
    if name == "fw_printenv" and "bad crc" in body.lower():
        warnings.append("fw_printenv: Bad CRC, so it printed built-in defaults, not the real U-Boot env")
    warnings += _secboot_warnings(name, body)
    if name == "mtd_sysfs" and "offset=absent" in body:
        warnings.append("mtd_sysfs: this kernel has no per-partition offset in sysfs; "
                        "take offsets from mibib_ptable and dt_partitions instead")
    if name == "dmesg" and body.strip():
        first = re.sub(r"^<\d+>", "", body.lstrip())  # drop an optional <6> priority prefix
        if not first.startswith("[    0.000000]"):
            warnings.append("dmesg: the log doesn't start at boot (ring buffer wrapped); "
                            "reboot the Orbi before a rerun to capture early boot")
    return warnings


def run_and_save(t, n, name, cmd, run_dir, manifest):
    """Run one command, save <name>.txt and its manifest entry, print a line. Returns (body, rc).
    On a timeout or a lost connection (any other socket error counts as lost), saves whatever
    came back (with a note when nothing did) and its manifest entry, then raises TimeoutError or
    ConnectionError naming the command. The manifest entry is filled in before the file is
    written, so a failed write loses neither the output nor the real error."""
    try:
        body, rc = run_command(t, n, cmd)
    except OSError as e:  # TimeoutError, ConnectionError, or e.g. EHOSTUNREACH after a cable move
        lost = not isinstance(e, TimeoutError)
        # Before the start marker t.buf holds only the echoed command line, not output.
        partial = (clean(t.buf) if t.output_started
                   else "(no output: the start marker never came, so the command may not have run)\n")
        manifest["commands"][name] = {"cmd": cmd, "rc": None, "bytes": len(partial.encode()),
                                      "output": partial,
                                      "connection_lost" if lost else "timed_out": True}
        try:
            (run_dir / f"{name}.txt").write_text(partial, encoding="utf-8", newline="\n")
        except OSError as we:
            manifest["warnings"].append(f"{name}: could not write {name}.txt ({we}); the partial "
                                        "output is in manifest.json")
        if lost:
            manifest["warnings"].append(f"{name}: telnet connection lost, partial output saved")
            raise ConnectionError(
                f"telnet session lost during {name!r} ({e}). Was the laptop's cable moved, or did "
                "the router reboot? Unlock telnet again and rerun; partial output saved") from e
        manifest["warnings"].append(f"{name}: timed out, partial output saved")
        raise TimeoutError(f"command {name!r} timed out; partial output saved") from e
    warnings = check_warnings(name, body, rc)
    manifest["commands"][name] = {"cmd": cmd, "rc": rc, "bytes": len(body.encode()), "output": body}
    manifest["warnings"] += warnings
    (run_dir / f"{name}.txt").write_text(body, encoding="utf-8", newline="\n")
    print(f"saved {name}.txt ({len(body.encode())} bytes, exit {rc})")
    for w in warnings:
        print(f"  WARN {w}")
    return body, rc


def collect(t, run_dir, manifest, commands=None):
    """Run `commands` (default: all of COMMANDS) in order. dt_model and fw_version, when both are
    in it, must come first: the run stops after fw_version unless the router names itself RBR."""
    commands = COMMANDS if commands is None else commands
    # stty must be the LAST command on the line so run_command's `__rc=$?` measures stty, not a
    # trailing echo; otherwise a failed stty (e.g. no pty) would be masked as rc 0.
    _, setup_rc = run_command(t, 0, "stty cols 1000 2>/dev/null")  # widen tty so echoes don't wrap
    manifest["setup_rc"] = setup_rc
    if setup_rc != 0:
        manifest["warnings"].append(
            f"setup: disabling echo line-wrap returned exit {setup_rc}; long command echoes may "
            "wrap and a command's output could be misread")
    for n, (name, cmd) in enumerate(commands.items(), 1):
        body, rc = run_and_save(t, n, name, cmd, run_dir, manifest)
        if name == "fw_version":
            ident = manifest["commands"].get("dt_model", {}).get("output", "") + body
            if not IDENT_RE.search(ident):
                raise RuntimeError("this doesn't look like an Orbi RBR router, stopping "
                                   "(see dt_model.txt, fw_version.txt)")


# --- --probe: find the Sync button's GPIO and the LAN switch port, with you at the router. ---
# Everything here only reads too. FORBIDDEN in the tests checks these lines like COMMANDS.

IDENT_COMMANDS = {k: COMMANDS[k] for k in ("dt_model", "fw_version")}

# Run an optional tool under a 3 s BusyBox timeout (old applets take -t SECS, newer ones SECS), with
# stdin from /dev/null so it can never sit waiting on the telnet tty. $T stays empty if neither works.
_PICK_TIMEOUT = ("if timeout -t 1 true </dev/null 2>/dev/null; then T='timeout -t 3';"
                 " elif timeout 1 true </dev/null 2>/dev/null; then T='timeout 3'; else T=''; fi;")

# Link state, one self-labelled line per item, so a before/after diff shows which port changed.
#  - ssdk_sh (Qualcomm's switch shell; /dev/switch_ssdk exists on stock): per-port linkstatus,
#    read-only "get". swconfig: its "link" lines plus its exit code. Each says "absent" if missing.
#  - eth0/eth1 carrier (stock: eth0 = WAN in brwan, eth1 = LAN in br0). On this driver they may show
#    the CPU-side link rather than the jacks, so they are a hint only.
#  - the kernel's link messages.
# The final `echo` keeps rc 0: "no link messages" is a normal answer. Failures show as text.
PROBE_LINK_CMD = (
    _PICK_TIMEOUT +
    " if command -v ssdk_sh >/dev/null 2>&1; then for p in 1 2 3 4 5; do"
    ' echo "ssdk port $p: $($T ssdk_sh port linkstatus get $p </dev/null 2>&1 | tr \'\\n\' \' \')"; done;'
    " else echo 'ssdk_sh: absent'; fi;"
    " if command -v swconfig >/dev/null 2>&1; then o=$($T swconfig dev switch0 show </dev/null 2>&1);"
    ' echo "swconfig rc=$?"; echo "$o" | grep -i link; else echo \'swconfig: absent\'; fi;'
    ' for n in eth0 eth1; do echo "$n carrier=$(cat /sys/class/net/$n/carrier 2>/dev/null'
    " || echo 'unreadable (interface down?)')\"; done;"
    " dmesg | grep -iE 'link (is )?(up|down)|port [0-9].*(up|down)'; echo"
)

GPIO_WINDOW_S = 10
TLMM_IO_BASE = 0x01000004  # IPQ4019 TLMM: pin n's GPIO_IN_OUT register is base + 0x1000 * n, bit 0 = level
GPIO_SAMPLE_RE = re.compile(r"^gpio(\d+) (0x[0-9a-fA-F]+)\s*$")


def probe_gpio_cmd(window_s=GPIO_WINDOW_S):
    """Shell line that reads the LEVEL of every input pin in GPIO mode, again and again for
    about `window_s` seconds (always at least one round), printing "#<i>" before each round and
    "gpio<n> 0x<register>" per pin.

    /sys/kernel/debug/gpio on this 3.14 kernel prints each pin's mux function after in/out, not its
    level (that's why it shows values like "in 3"), so it is used only to pick the pins: inputs with
    function 0 (= GPIO). The level comes from the pin's TLMM GPIO_IN_OUT register, read with
    BusyBox devmem ADDRESS 32. devmem is only ever given those two arguments (a third would write)."""
    return ("c=$(grep -E '^ *gpio[0-9]+ *: *in +0 ' /sys/kernel/debug/gpio | grep -oE 'gpio[0-9]+');"
            " if [ -z \"$c\" ]; then echo 'no GPIO-mode input pins found in /sys/kernel/debug/gpio'; false;"
            f" else echo \"pins: $(echo $c)\"; end=$(($(date +%s)+{window_s})); i=0;"
            " while [ $i -eq 0 ] || [ $(date +%s) -lt $end ]; do echo \"#$i\"; for g in $c; do"
            f" a=$(({TLMM_IO_BASE:#x} + ${{g#gpio}} * 4096)); echo \"$g $(devmem $a 32 2>&1)\"; done;"
            " i=$((i+1)); done; fi")


def parse_gpio_samples(text):
    """{gpio number: [level 0/1 per round, in order]} from probe_gpio_cmd output. A line whose
    register value didn't parse (a devmem error) is skipped."""
    seen = {}
    for line in text.splitlines():
        m = GPIO_SAMPLE_RE.match(line.strip())
        if m:
            seen.setdefault(int(m.group(1)), []).append(int(m.group(2), 16) & 1)
    return seen


def changed_gpios(samples):
    """{gpio: (idle level, rounds at the other level)} for pins whose level changed. Idle is the
    level seen most often, so a press caught in the first round doesn't flip it. If both levels
    were seen equally often, idle is None (polarity unknown) and the count is the rounds at 0."""
    out = {}
    for g, vals in samples.items():
        if len(set(vals)) > 1:
            (top, k1), (_, k2) = collections.Counter(vals).most_common(2)
            idle = None if k1 == k2 else top
            out[g] = (idle, sum(v != (1 if idle is None else idle) for v in vals))
    return out


def count_rounds(text):
    """How many "#<i>" round markers probe_gpio_cmd printed."""
    return sum(1 for ln in text.splitlines() if re.fullmatch(r"#\d+", ln.strip()))


def link_diff(before, after):
    """(lines new in `after`, lines gone from `before`), counting repeats, order kept."""
    b, a = collections.Counter(before.splitlines()), collections.Counter(after.splitlines())
    added, removed = a - b, b - a

    def pick(lines, extra):
        out = []
        for ln in lines:
            if extra[ln] > 0:
                extra[ln] -= 1
                out.append(ln)
        return out
    return pick(after.splitlines(), added), pick(before.splitlines(), removed)


# No Reset step: Reset (GPIO 18, active-low) was measured once, and on stock firmware a press of
# only ~1.5 s still factory-reset the RBR10. Never ask anyone to press Reset on stock firmware.
RESET_GPIO = 18  # a Sync result on this pin means the wrong button was pressed
# The no-press check before the Sync window. `date +%s` ticks once a second, so a 1 s check can be
# a single round; 3 s gives several. A pin's idle level is trusted only from enough samples.
IDLE_CHECK_S = 3
MIN_IDLE_SAMPLES = 3
BUTTONS = (
    ("sync", "Sync/WPS",
     "Press and hold it for about 2 seconds, then let go. On stock firmware this starts WPS pairing "
     "for about 2 minutes: any nearby device that also presses WPS can join the Wi-Fi without the "
     "password in that time."),
)


LINK_UP_RES = (re.compile(r"^ssdk port (\d+):.*\[Status\]:ENABLE"),
               re.compile(r"\bport:(\d+) link:up\b"))


def ports_up(link_text):
    """Switch ports with link in PROBE_LINK_CMD output (from ssdk_sh or swconfig). Port 0 is the
    CPU port, so it never counts."""
    up = set()
    for line in link_text.splitlines():
        for rx in LINK_UP_RES:
            m = rx.search(line.strip())
            if m and m.group(1) != "0":
                up.add(int(m.group(1)))
    return up


ANSWER_QUICKLY = ("Answer each question within a few minutes: a telnet session left idle for long "
                  "can be dropped.")


def probe(t, run_dir, manifest, ask=input, first_n=100):
    """Interactive checks, all read-only:
      1. link state now. The laptop's cable is in the LAN jack and the WAN jack must be empty, so
         the one switch port with link is the LAN jack;
      2. optionally, which port a second cable in the WAN jack brings up;
      3. which GPIO the Sync button moves, and its polarity (Reset is never pressed; see BUTTONS).
    After each question a quick round trip checks the session is still alive, so a session that
    died while you were away is reported as that, not as a slow command.
    Results go to manifest["probe"] (one entry per step, each with a "status"; a step cut short
    is "failed: ...") and to probe_summary.txt, which is written even if a step fails."""
    n = first_n
    res = manifest.setdefault("probe", {})
    lines = []
    step = "link"

    def warn(msg):
        manifest["warnings"].append(msg)
        lines.append(f"WARNING: {msg}")

    def asked(prompt):
        nonlocal n
        start = time.monotonic()
        answer = ask(prompt)
        waited = time.monotonic() - start
        try:
            run_command(t, n, "true", timeout=10)
        except OSError as e:  # TimeoutError, ConnectionError and other socket errors
            raise ConnectionError(
                f"telnet session lost while waiting {waited:.0f} s at a question ({e}). Unlock "
                "telnet again and rerun --probe, answering within a few minutes") from e
        finally:
            n += 1
        return answer

    try:
        print("\n" + ANSWER_QUICKLY + " Make sure the WAN jack is empty and only this laptop's "
              "cable is plugged in (into the LAN jack).")
        base, _ = run_and_save(t, n, "probe_link", PROBE_LINK_CMD, run_dir, manifest)
        n += 1
        up = ports_up(base)
        res["link"] = {"status": "ok", "ports_up": sorted(up), "lines": base.splitlines()}
        lines += ["== Link state now (laptop in the LAN jack, WAN jack empty):", base.rstrip(), ""]
        if len(up) == 1:
            lines += [f"LAN jack = switch port {next(iter(up))}", ""]
        else:
            res["link"]["status"] = "unclear"
            if not up and "ssdk_sh: absent" in base and "swconfig: absent" in base:
                warn("probe link: neither ssdk_sh nor swconfig is on the router, so the switch ports "
                     "can't be read; see probe_link.txt for carrier and kernel link lines")
            else:
                warn(f"probe link: switch ports with link: {sorted(up) or 'none'}; expected exactly "
                     "one (the LAN jack). Was something in the WAN jack?")

        step = "wan"
        answer = asked(
            "\nOptional WAN check. It needs a SECOND cable; keep this laptop's cable in the LAN jack\n"
            "(moving it ends this session). Plug the second cable into the RBR10's WAN jack, other\n"
            "end into another PC (not this laptop) or a switch that is powered and NOT on your home\n"
            "network (if that also uses 192.168.1.x, the RBR10 moves its LAN to another subnet and\n"
            "this session drops). Wait a few seconds after plugging in, then type y and Enter.\n"
            "Or just press Enter to skip: ").strip().lower()
        if answer in ("y", "yes"):
            time.sleep(3)  # give the link a moment to come up before reading it
            wan, _ = run_and_save(t, n, "probe_link_wan", PROBE_LINK_CMD, run_dir, manifest)
            n += 1
            added, removed = link_diff(base, wan)
            new = sorted(ports_up(wan) - up)
            res["wan"] = {"status": "ok" if new else "no change", "new_ports": new,
                          "added": added, "removed": removed}
            lines += ["== After plugging the WAN cable:", *(f"+ {ln}" for ln in added),
                      *(f"- {ln}" for ln in removed)]
            if len(new) == 1:
                lines += [f"WAN jack = switch port {new[0]}", ""]
            else:
                res["wan"]["status"] = "no change" if not new else "unclear"
                lines.append("")
                warn(f"probe WAN: new switch ports with link: {new or 'none'}; expected exactly one. "
                     "Is the other end powered, and is the cable in WAN (not LAN)?")
        else:
            print("  skipped the WAN check")
            res["wan"] = {"status": "skipped"}

        # Check the pin reads work before asking anyone to press anything.
        step = "buttons"
        check, _ = run_and_save(t, n, "probe_gpio_check", probe_gpio_cmd(IDLE_CHECK_S), run_dir,
                                manifest)
        n += 1
        idle_samples = parse_gpio_samples(check)
        if not idle_samples:
            warn("probe GPIO: no pin levels could be read (see probe_gpio_check.txt); skipped the "
                 "button checks")
            res["buttons"] = {"status": "pin reads failed"}
            return
        # Nobody presses anything during the check, so a pin that moves there moves by itself.
        idle_movers = set(changed_gpios(idle_samples))

        for key, label, how in BUTTONS:
            step = f"button_{key}"
            asked(f"\nButton check: {label}. {how}\nAfter you press Enter you have {GPIO_WINDOW_S} "
                  "seconds to do it. Press Enter when ready: ")
            print(f"  watching the pins for {GPIO_WINDOW_S} s, press the button now...")
            body, _ = run_and_save(t, n, f"probe_gpio_{key}", probe_gpio_cmd(), run_dir, manifest)
            n += 1
            samples = parse_gpio_samples(body)
            moved = changed_gpios(samples)
            idle_guessed = set()  # pins whose idle level only comes from the window's majority
            for g in moved:
                before = idle_samples.get(g, [])
                if len(before) < MIN_IDLE_SAMPLES:
                    idle_guessed.add(g)
                elif len(set(before)) == 1:  # steady with nothing pressed: its idle level
                    idle = before[0]
                    moved[g] = (idle, sum(v != idle for v in samples[g]))
            rounds = count_rounds(body)
            entry = {"pins": {str(g): {"idle": idle, "rounds_changed": k} for g, (idle, k) in moved.items()},
                     "rounds": rounds}
            if rounds and GPIO_WINDOW_S / rounds > 1.0:
                warn(f"probe {key}: only {rounds} rounds in {GPIO_WINDOW_S} s (over 1 s each), so a "
                     "2 s hold could be missed")
            if not samples:
                # The 1 s check passed, but no pin could be read in this window: not a missed press.
                entry["status"] = "pin reads failed"
                warn(f"probe {key}: no pin levels could be read in the window (see "
                     f"probe_gpio_{key}.txt), so this says nothing about the button")
                verdict = "pin reads failed"
            elif not moved:
                entry["status"] = "no change"
                warn(f"probe {key}: no pin changed; hold the button about 2 s inside the window")
                verdict = "no pin changed"
            else:
                entry["status"] = "ok" if len(moved) == 1 else "ambiguous"
                if len(moved) > 1:
                    warn(f"probe {key}: {len(moved)} pins changed, so the result is ambiguous")
                def suspect(msg):
                    if entry["status"] == "ok":
                        entry["status"] = "suspect"
                    warn(msg)
                for g, (idle, k) in sorted(moved.items()):
                    if g in idle_guessed and idle is not None:
                        suspect(f"probe {key}: GPIO {g} was read fewer than {MIN_IDLE_SAMPLES} "
                                "times in the idle check, so its idle level (and the polarity) is "
                                "a guess from the window")
                    if g in idle_movers:
                        suspect(f"probe {key}: GPIO {g} also changed in the idle check with nothing "
                             "pressed, so it probably moves by itself")
                    if g == RESET_GPIO:
                        suspect(f"probe {key}: GPIO {g} is the Reset button, not {label}. If Reset was "
                             "pressed, the router may now factory-reset")
                    if idle is None:
                        suspect(f"probe {key}: GPIO {g} was 0 and 1 equally often, so its polarity "
                             "(active-low or active-high) is unknown")
                    elif rounds and k * GPIO_WINDOW_S / rounds < 1.0:
                        suspect(f"probe {key}: GPIO {g} changed for under 1 s ({k} of {rounds} "
                             "rounds), too short for a 2 s hold; it may be noise")
                verdict = "; ".join(
                    f"GPIO {g} idles {idle}, was {1 - idle} in {k} round(s)"
                    f" ({'active-low' if idle == 1 else 'active-high'})" if idle is not None else
                    f"GPIO {g} was 0 and 1 equally often, so its polarity is unclear (check polarity)"
                    for g, (idle, k) in sorted(moved.items()))
            res[step] = entry
            lines += [f"== {label} ({rounds} rounds in about {GPIO_WINDOW_S} s): {verdict}", ""]
            print(f"  {label}: {verdict}")
    except BaseException as e:
        res[step] = {**res.get(step, {}), "status": f"failed: {type(e).__name__}"}
        lines += [f"STOPPED during the {step} step: {type(e).__name__}: {e}", ""]
        raise
    finally:
        lines.append("Compare with the keys and switch ports in dts/qcom-ipq4019-rbr10.dts.")
        try:
            (run_dir / "probe_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8",
                                                       newline="\n")
            print(f"\nProbe summary: {run_dir / 'probe_summary.txt'}")
        except OSError as e:
            manifest["warnings"].append(f"probe: could not write probe_summary.txt: {e}")
            print(f"could not write probe_summary.txt: {e}")


SECBOOT_MAX_WEAK = 150  # boot-flow lines per strings dump; STRONG (secure-boot) lines are never capped


def _secboot_state(manifest, name):
    """(ok, notes) for one --secboot command: ok only if it ran to the end with rc 0 and no warning
    of its own. notes say why not."""
    c = manifest["commands"].get(name)
    if c is None:
        return False, ["not run"]
    notes = [k.replace("_", " ").upper() for k in ("timed_out", "connection_lost") if c.get(k)]
    if c["rc"] is None and not notes:
        notes.append("NO EXIT CODE")
    elif c["rc"] not in (0, None):
        notes.append(f"exit code {c['rc']}")
    notes += [w[len(name) + 2:] for w in manifest.get("warnings", []) if w.startswith(f"{name}: ")]
    return not notes, notes


def secboot_summary(manifest, error=None):
    """Text for secboot_summary.txt. It opens with what is and isn't known, marks every command that
    failed or was cut short as NOT EVIDENCE, and ends with all warnings and why the run stopped. It
    only gathers; reading it is a person's job."""
    cmds = manifest["commands"]
    order = ("sec_qfprom", "sec_dmesg", "kernel_head", "sbl1_strings", "appsbl_strings", "sec_sysfs_find")
    states = {n: _secboot_state(manifest, n) for n in order}
    out = ["Secure-boot evidence, read-only. Only lines under a command marked OK count as evidence;",
           "an empty or missing answer is never evidence that secure boot is off.", "",
           "== Evidence status"]
    # The fuse state is known only if sec_qfprom is OK, and then it is the authenticate value itself.
    auth = re.search(r"/authenticate: (?!\(empty)(\S.*) \(rc=0\)$",
                     cmds.get("sec_qfprom", {}).get("output", ""), re.M)
    fuse = f"authenticate = {auth.group(1)}" if states["sec_qfprom"][0] and auth else "UNKNOWN"
    out.append(f"fuse state: {fuse}")
    for n in order:
        ok, notes = states[n]
        out.append(f"{n}: {'OK' if ok else 'NOT EVIDENCE: ' + '; '.join(notes)}")
    if manifest.get("setup_rc") not in (0, None):
        out.append(f"run-wide: the tty setup (stty) returned {manifest['setup_rc']}, so long command echoes "
                   "may wrap; check odd-looking output against the full *.txt files")
    if error is not None:
        out.append(f"run stopped early: {type(error).__name__}: {error}")
    out.append("")
    for n in order:
        ok, notes = states[n]
        c = cmds.get(n)
        out.append(f"== {n}: {'OK' if ok else 'NOT EVIDENCE: ' + '; '.join(notes)}")
        if c is None:
            out.append("")
            continue
        if not n.endswith("_strings"):
            out += [c["output"].rstrip(), ""]
            continue
        lines = c["output"].splitlines()
        status = [ln for ln in lines if ln.startswith(("device:", "size:", "bad_blocks:", "ecc_failures",
                                                       "bytes read:", "TR-FAILED"))
                  or TOOL_ERROR_RE.match(ln)]
        strong = [ln for ln in lines if SECBOOT_STRONG.search(ln)]
        weak = [ln for ln in lines if SECBOOT_WEAK.search(ln) and not SECBOOT_STRONG.search(ln)]
        out += [*status, f"-- secure-boot lines ({len(strong)}):", *strong,
                f"-- boot-flow lines ({len(weak)}):", *weak[:SECBOOT_MAX_WEAK]]
        if len(weak) > SECBOOT_MAX_WEAK:
            out.append(f"... and {len(weak) - SECBOOT_MAX_WEAK} more (see {n}.txt)")
        out.append("")
    out.append("== All warnings")
    out += manifest.get("warnings") or ["(none)"]
    return "\n".join(out) + "\n"


def write_summary(run_dir, manifest):
    blocks = [f"===== {name}  (exit {c['rc']})\n$ {c['cmd']}\n{c['output']}"
              for name, c in manifest["commands"].items()]
    if manifest["warnings"]:
        blocks.append("===== warnings\n" + "\n".join(manifest["warnings"]) + "\n")
    (run_dir / "recon.txt").write_text("\n".join(blocks), encoding="utf-8", newline="\n")
    slim = {**manifest, "commands": {k: {kk: vv for kk, vv in v.items() if kk != "output"}
                                     for k, v in manifest["commands"].items()}}
    (run_dir / "manifest.json").write_text(json.dumps(slim, indent=2), encoding="utf-8", newline="\n")


def make_run_dir(out_root):
    for _ in range(5):
        run_dir = out_root / datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        try:
            run_dir.mkdir(parents=True)
            return run_dir
        except FileExistsError:
            time.sleep(0.01)
    raise RuntimeError("could not make a unique run folder")


def main(argv=None, out_root=DEFAULT_OUT, connect=Telnet.connect, ask_user=None, ask_password=None,
         require_tty=True, ask=input):
    # out_root/connect/ask_user/ask_password/require_tty/ask are injection points for the tests.
    ap = argparse.ArgumentParser(description="Read-only telnet recon of a Netgear Orbi RBR10.")
    ap.add_argument("host", nargs="?", default=DEFAULT_HOST)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--probe", action="store_true",
                      help="instead of the full recon: find the LAN switch port and the Sync button's GPIO "
                           "(you press Sync for about 2 s when asked)")
    mode.add_argument("--secboot", action="store_true",
                      help="instead of the full recon: collect secure-boot evidence (qfprom fuses, "
                           "bootloader strings, the stock kernel's header) into secboot_summary.txt")
    args = ap.parse_args(argv)
    if require_tty and not sys.stdin.isatty():
        print("Run this in a real terminal (Windows Terminal, PowerShell or cmd): the password "
              "prompt needs one to keep your typing hidden.")
        return 2
    # Netgear's "telnet account:" is the web-GUI login ("same with DUT GUI"), i.e. admin.
    ask_user = ask_user or (lambda: input("Orbi telnet username [admin]: ").strip() or "admin")
    ask_password = ask_password or (lambda: getpass.getpass("Orbi admin password (hidden): "))

    run_dir = make_run_dir(out_root)
    manifest = {"host": args.host, "started": datetime.datetime.now().isoformat(timespec="seconds"),
                "complete": False, "warnings": [], "commands": {}}
    t = None
    shell_reached = False
    summary_ok = True
    try:
        t = connect(args.host)
        login(t, ask_user, ask_password)
        shell_reached = True
        if args.probe:
            collect(t, run_dir, manifest, IDENT_COMMANDS)  # still check it's an Orbi first
            probe(t, run_dir, manifest, ask)
        elif args.secboot:
            stopped = None  # the error that stopped the run, if any, named in the summary
            try:
                collect(t, run_dir, manifest, {**IDENT_COMMANDS, **SECBOOT_COMMANDS})
            except BaseException as e:
                stopped = e
                raise
            finally:  # written even if a command fails, from whatever was collected
                try:
                    (run_dir / "secboot_summary.txt").write_text(
                        secboot_summary(manifest, stopped), encoding="utf-8", newline="\n")
                    print(f"\nSecure-boot summary: {run_dir / 'secboot_summary.txt'}")
                except Exception as e:  # never replace the error in flight with one from the summary
                    manifest["warnings"].append(f"secboot: could not make or write secboot_summary.txt: {e}")
                    print(f"could not make or write secboot_summary.txt: {e}")
        else:
            collect(t, run_dir, manifest)
        manifest["complete"] = True
    except (OSError, RuntimeError, LoginFailed) as e:  # OSError covers timeouts and lost connections
        manifest["error"] = f"{type(e).__name__}: {e}"
        print(f"\nStopped: {e}")
    except BaseException as e:  # Ctrl+C, EOF at a prompt, or a bug: record, then re-raise
        manifest["error"] = f"{type(e).__name__}: {e}"
        raise
    finally:
        manifest["finished"] = datetime.datetime.now().isoformat(timespec="seconds")
        if t is not None and shell_reached:  # don't type "exit" at a login prompt
            try:
                t.send("exit")
            except OSError:
                pass
        try:
            write_summary(run_dir, manifest)
        except OSError as we:
            summary_ok = False
            print(f"could not write the summary files: {we}")
        if t is not None:
            t.close()
    if not summary_ok:
        print("The on-disk manifest/summary could not be fully written, so this run has no durable "
              "record; treating it as not clean.")
    clean_run = manifest["complete"] and not manifest["warnings"] and summary_ok
    status = "complete" if manifest["complete"] else "NOT complete"
    print(f"\nRun {status}, {len(manifest['warnings'])} warning(s). Files: {run_dir}")
    return 0 if clean_run else 1


if __name__ == "__main__":
    sys.exit(main())
