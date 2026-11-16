"""Full read-only backup of a Netgear Orbi RBR10's NAND, over telnet + a TCP data channel.

Usage:  python -I orbi_backup.py [HOST]            (HOST defaults to 192.168.1.1)
        python -I orbi_backup.py --verify DIR      (re-check an existing backup against the stock
                                                     firmware image, no router needed)
        python -I orbi_backup.py --rehash DIR      (re-read the LIVE flash and compare to the backup in
                                                     DIR, to prove a RAM boot wrote nothing to the
                                                     read-only flash regions; read-only)

It logs in (reusing orbi_telnet.py's telnet client and login), reads /proc/mtd, and copies every raw
mtd partition (mtd0..mtd24; the vol_* UBI volumes inside ntgrdata are skipped, they are a view of
ntgrdata which is already captured). Each partition is streamed over a SEPARATE TCP connection so the
128 MB does not crawl through the telnet channel; nothing but telnet and that one data socket is used.

READ-ONLY on the router. The only commands sent are `cat /proc/mtd`, `sha256sum < /dev/mtdN`,
`nc ... < /dev/mtdN` (serve a partition), `head -c N /dev/mtdN | sha256sum` and `head -c N /dev/mtdN |
wc -c` (--rehash, byte-bounded reads) and reads of /sys/class/mtd. No dd, no write of any kind. The
device tree stays as it is.

Integrity, per partition: the router hashes it with sha256 BEFORE and AFTER the transfer, the laptop
hashes what it received, and the byte count must equal the /proc/mtd size. A partition is "stable"
only if all three hashes match and the size is right. A partition whose two device hashes differ was
written by the running stock firmware mid-read (rootfs_data, secdata, ntgrdata, pot can do this); it
kept and labelled "unstable" when its copy still matches a device state (the boot chain, ART and
boarddata1 must be stable; a wrong-size or wrong-hash read is retried and then failed, not kept).
bad_blocks and ecc_failures are recorded before and after, as in orbi_telnet --secboot.

Output: backup/<date-time-us>/ next to tools/. One <mtdN_name>.bin per partition, plus manifest.json
(sizes, hashes, per-partition status; NO partition contents) and backup_summary.txt.
PRIVACY: the `config` partition holds the admin and Wi-Fi passwords and `cert` may hold keys, so the
files stay on this PC only (backup/ is gitignored); never copy them off or print their contents.

The data channel: the router serves each partition with `nc -l` and the laptop connects to it, so the
bytes go OUT from the laptop's side of the cable and Windows Firewall's inbound block doesn't apply.
If this BusyBox nc has no `-l`, the tool falls back to the router connecting to a listener here (which
may need a firewall allow). A tiny probe transfer picks the working direction before the real copy.
SECURITY: in the preferred direction the router's `nc -l` port is unauthenticated, so the first host
to connect wins; run this only over the direct RBR10<->laptop cable (or an otherwise trusted link),
never across a shared LAN, because `config` and `cert` cross that port in the clear. The fallback
direction checks the connecting peer is the router, but the preferred direction cannot.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import socket
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import orbi_telnet as ot  # noqa: E402  (same folder; reuse the telnet client and helpers)

DEFAULT_HOST = ot.DEFAULT_HOST
DEFAULT_OUT = pathlib.Path(__file__).resolve().parent.parent / "backup"
NAND_SIZE = 0x8000000  # 128 MB; the top-level partitions must tile exactly this
# Sub-partitions that live inside another, so they must NOT be counted in the tiling check:
# kernel/rootfs/rootfs_data are carved from "firmware"; vol_* are UBI volumes inside "ntgrdata".
SUBPARTITIONS = ("kernel", "rootfs", "rootfs_data")
# Partitions the running stock firmware may rewrite at any time, so an "unstable" (changed mid-read,
# captured as a consistent snapshot) result is expected and not a problem. "firmware" and "rootfs" also
# carry the writable rootfs_data overlay as their tail, so they too can change mid-read without it being a
# fault (their read-only kernel+squashfs prefix is what matters, and that part doesn't move). Every OTHER
# partition must read "ok": the boot chain, ART, boarddata1 and the like don't change at runtime, so a
# change or a failure there is a real fault. The per-unit irreplaceables (ART + boarddata1, and their .bak)
# must be present and "ok" or the backup can't restore the unit.
VOLATILE = ("config", "pot", "secdata", "ntgrdata", "rootfs_data")
MAY_CHANGE_MIDREAD = VOLATILE + ("firmware", "rootfs")  # unstable here is a note, not a warning
CRITICAL = ("0:ART", "0:ART.bak", "boarddata1", "boarddata1.bak")
MAGIC = b"ORBIBK01"  # probe handshake marker
RETRIES = 3
ROUTER_PORT = 51515  # the router's nc -l data port (the laptop connects out to it); patchable in tests


class BackupError(Exception):
    pass


# --- marker protocol, split so a data transfer can happen between the start and end markers ---
# Same markers as orbi_telnet.run_command: __B''n__ / __E''n__ typed, printed as __Bn__ / __En__.
# An nc command writes to the data socket, not to telnet, so nothing comes between the markers here.

def _send_marked(t, n, cmd):
    """Send `cmd` wrapped in markers and consume up to the start marker. Read-only commands only."""
    t.output_started = False
    t.send(f"echo __B''{n}__; {cmd}; __rc=$?; echo; echo __E''{n}__ rc=$__rc")
    t.read_until(rb"(?m)^__B%d__\r?\n" % n, 30, f"start of command {n}")
    t.output_started = True


def _read_marked_end(t, n, timeout=60):
    """Consume up to and including the end marker; return the command's exit code (int)."""
    _, m = t.read_until(rb"(?m)^__E%d__ rc=(\d+)\r?\n" % n, timeout, f"end of command {n}")
    return int(m.group(1))


def _drain_marked_end(t, n, timeout=20):
    """Best-effort consume of a marker end that may never come (a probe that didn't connect)."""
    try:
        return _read_marked_end(t, n, timeout)
    except (TimeoutError, ot.socket.timeout, ConnectionError):
        return None


def parse_proc_mtd(text):
    """[(dev, size, name), ...] from /proc/mtd, in file order. dev is 'mtd0', size is an int."""
    parts = []
    for line in text.splitlines():
        m = ot.re.match(r'(mtd\d+):\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+"([^"]*)"', line)
        if m:
            parts.append((m.group(1), int(m.group(2), 16), m.group(3)))
    return parts


def safe_name(dev, name):
    """A filesystem-safe '<dev>_<name>.bin', e.g. mtd14_boarddata1.bin or mtd0_0_SBL1.bin."""
    clean = ot.re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return f"{dev}_{clean}.bin"


def device_hash(t, n, dev, size):
    """sha256 of /dev/<dev> as the router sees it, plus its size, bad_blocks and ecc_failures.
    Returns (sha_hex_or_None, info_dict). The hash read is `sha256sum < /dev/dev` (read-only).
    `size` scales the timeout (hashing 60 MB on the stock CPU is slow)."""
    cmd = (f'echo "sha: $(sha256sum < /dev/{dev} | cut -d" " -f1)";'
           f' echo "size: $(cat /sys/class/mtd/{dev}/size 2>/dev/null || echo unknown)";'
           f' echo "bad_blocks: $(cat /sys/class/mtd/{dev}/bad_blocks 2>/dev/null || echo unknown)";'
           f' echo "ecc: $(cat /sys/class/mtd/{dev}/ecc_failures 2>/dev/null || echo unknown)"')
    out, rc = ot.run_command(t, n, cmd, timeout=_hash_timeout(size))
    sha = _grep1(out, r"^sha: ([0-9a-f]{64})$")
    info = {"size": _grep1(out, r"^size: (\d+)$"), "bad_blocks": _grep1(out, r"^bad_blocks: (\S+)$"),
            "ecc": _grep1(out, r"^ecc: (\S+)$"), "rc": rc}
    return sha, info


def _grep1(text, pattern):
    m = ot.re.search(pattern, text, ot.re.M)
    return m.group(1) if m else None


def _hash_timeout(size):
    # sha256 of ~60 MB over the slow stock CPU takes a while; scale generously by size (bytes).
    return max(120, int(size / (1 << 20)) * 6 + 60)


def open_listener(bind_ip):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, 0))
    srv.listen(1)
    srv.settimeout(30)
    return srv, srv.getsockname()[1]


def choose_direction(t, counter, host, local_ip):
    """Send MAGIC once each way and keep the direction that arrives. Returns 'router_listens' or
    'laptop_listens'. 'router_listens' (the laptop connects out to the router) is tried first: it
    needs the router's nc to support -l but isn't blocked by the laptop firewall."""
    rport = ROUTER_PORT  # the router's nc listener port
    # Direction B (preferred): the router listens, we connect out to it (no laptop-inbound firewall).
    n = counter()
    _send_marked(t, n, f"echo {MAGIC.decode()} | nc -l -p {rport}")
    got = _probe_connect(host, rport)
    if got == MAGIC:
        _read_marked_end(t, n)
        return "router_listens"
    _drain_marked_end(t, n)  # the router's nc -l may still be blocked; read its marker if/when it ends
    # Direction A (fallback): we listen, the router connects to us.
    srv, lport = open_listener(local_ip)
    try:
        n = counter()
        _send_marked(t, n, f"echo {MAGIC.decode()} | nc {local_ip} {lport}")
        srv.settimeout(15)
        conn, peer = srv.accept()
        with conn:
            if peer[0] != host:
                raise BackupError(f"a host other than the router ({peer[0]}) connected to the backup port")
            conn.settimeout(10)
            got = _recv_all(conn, limit=len(MAGIC)).strip()
        _read_marked_end(t, n)
        if got == MAGIC:
            return "laptop_listens"
    except OSError:
        pass
    finally:
        srv.close()
    raise BackupError("neither nc direction worked: the router's nc may lack -l, or the laptop "
                      "firewall may be blocking inbound on the Ethernet network. Allow python through "
                      "the firewall on the 192.168.1.x network, or run nc on the router by hand.")


def _probe_connect(host, port):
    for _ in range(20):  # the router's nc -l needs a moment to start listening
        try:
            with socket.create_connection((host, port), timeout=2) as s:
                s.settimeout(5)
                return _recv_all(s, limit=len(MAGIC)).strip()
        except OSError:
            time.sleep(0.25)
    return b""


def _recv_all(sock, into=None, limit=None):
    """Read until EOF. If `into` (a file) is given, write there and return (bytes, sha256). Else
    return the bytes (capped at `limit`)."""
    h = hashlib.sha256()
    total = 0
    buf = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        total += len(chunk)
        if into is not None:
            into.write(chunk)
            h.update(chunk)
        else:
            buf.extend(chunk)
            if limit and len(buf) >= limit:
                return bytes(buf[:limit])
    if into is not None:
        return total, h.hexdigest()
    return bytes(buf)


def transfer(t, n, direction, host, local_ip, dev, dest, size):
    """Stream /dev/<dev> over one TCP connection into `dest` (a Path). Returns (bytes, sha256, rc).
    Read-only: the router only does `nc ... < /dev/dev`."""
    timeout = _hash_timeout(size)
    rport = ROUTER_PORT
    with open(dest, "wb") as f:
        if direction == "router_listens":
            _send_marked(t, n, f"nc -l -p {rport} < /dev/{dev}")
            sock = _connect_retry(host, rport)
            with sock:
                sock.settimeout(timeout)
                total, sha = _recv_all(sock, into=f)
            rc = _read_marked_end(t, n, timeout)
        else:  # laptop_listens
            srv, lport = open_listener(local_ip)
            try:
                _send_marked(t, n, f"nc {local_ip} {lport} < /dev/{dev}")
                srv.settimeout(timeout)
                conn, peer = srv.accept()
                with conn:
                    if peer[0] != host:  # only the router may deliver this partition (it holds secrets)
                        raise BackupError(f"a host other than the router ({peer[0]}) connected to the "
                                          f"backup port while serving {dev}")
                    conn.settimeout(timeout)
                    total, sha = _recv_all(conn, into=f)
                rc = _read_marked_end(t, n, timeout)
            finally:
                srv.close()
    return total, sha, rc


def _connect_retry(host, port, tries=40):
    last = None
    for _ in range(tries):
        try:
            return socket.create_connection((host, port), timeout=5)
        except OSError as e:
            last = e
            time.sleep(0.25)
    raise BackupError(f"could not connect to the router's data port {port}: {last}")


def backup_partition(t, counter, direction, host, local_ip, dev, name, size, run_dir, manifest):
    """Back up one partition. Each attempt hashes the device before and after, transfers it, and the
    received bytes are accepted only when the byte count is right AND the received hash equals a real
    device state (before or after). A transfer error retries instead of killing the run. Status:
      ok        size right and the device didn't change: a clean, verified copy.
      unstable  the device changed mid-read but the copy still matches one device state (a consistent
                snapshot of a live partition) - fine for MAY_CHANGE_MIDREAD (the VOLATILE partitions plus
                firmware/rootfs, which carry the writable overlay tail), a fault for the rest.
      failed    no attempt produced a copy matching a device state at the right size.
    Fills and returns the manifest entry."""
    dest = run_dir / safe_name(dev, name)
    entry = {"dev": dev, "name": name, "size": size, "file": dest.name, "status": "failed",
             "size_read": None, "sha256": None, "attempts": 0}
    warn, note = manifest["warnings"].append, manifest["notes"].append
    last = None
    for attempt in range(1, RETRIES + 1):
        entry["attempts"] = attempt
        try:
            sha_before, info_before = device_hash(t, counter(), dev, size)
            got, sha_rx, rc = transfer(t, counter(), direction, host, local_ip, dev, dest, size)
            sha_after, info_after = device_hash(t, counter(), dev, size)
        except (OSError, BackupError) as e:  # a socket/marker glitch: retry, don't abort the whole run
            last = f"attempt {attempt}: {e}"
            warn(f"{dev} ({name}): {last}")
            continue
        entry.update(size_read=got, sha256=sha_rx, transfer_rc=rc, sha_before=sha_before,
                     sha_after=sha_after, bad_blocks=info_before.get("bad_blocks"),
                     ecc_before=info_before.get("ecc"), ecc_after=info_after.get("ecc"))
        if not sha_before or not sha_after:
            last = f"attempt {attempt}: the router could not hash /dev/{dev}"
            warn(f"{dev} ({name}): {last}")
            continue
        size_ok = got == size
        matches_a_state = size_ok and sha_rx in (sha_before, sha_after)
        if not matches_a_state:  # wrong size, or the copy's hash equals no device state: a bad transfer
            last = (f"attempt {attempt}: read {got} of {size} bytes" if not size_ok
                    else f"attempt {attempt}: the copy's hash matches neither device state (corruption)")
            warn(f"{dev} ({name}): {last}")
            continue
        if sha_before == sha_after:
            entry["status"] = "ok"
        else:
            entry["status"] = "unstable"
            expected = name in MAY_CHANGE_MIDREAD
            (note if expected else warn)(
                f"{dev} ({name}): changed mid-read but the {got}-byte copy matches a device state "
                f"(a live-partition snapshot){'' if expected else '; this partition should NOT change at runtime'}")
        break
    else:
        warn(f"{dev} ({name}): no clean copy after {RETRIES} attempts ({last}); the .bin is NOT verified")
    _blockcheck(entry, warn, note)
    manifest["partitions"].append(entry)
    print(f"  {dev:6} {name:16} {entry['status']:9} {entry['size_read']}/{size} bytes")
    return entry


def _blockcheck(entry, warn, note):
    """bad_blocks / ecc_failures reporting. This kernel's sysfs may not expose them (they read
    'unknown'); then it is an informational note, not a warning, because a hard read error would
    instead show as a short read, which backup_partition already checks."""
    dev, name = entry["dev"], entry["name"]
    bb = entry.get("bad_blocks")
    if bb in (None, "unknown"):
        note(f"{dev} ({name}): bad_blocks not reported by this kernel; latent bad blocks can't be read "
             "from sysfs (a hard read error would show as a short read, which is checked)")
    elif bb != "0":
        warn(f"{dev} ({name}): bad_blocks={bb}; a plain mtd read skips no bad blocks and this backup "
             "has no OOB, so a restore of this partition may be incomplete")
    eb, ea = entry.get("ecc_before"), entry.get("ecc_after")
    if eb in (None, "unknown") or ea in (None, "unknown"):
        note(f"{dev} ({name}): ecc_failures not reported by this kernel")
    elif ea != eb:
        warn(f"{dev} ({name}): ecc_failures rose {eb}->{ea} during the read; some bytes may be uncorrectable")


def check_coverage(manifest):
    """Warn unless the top-level partitions (everything but the firmware sub-parts and UBI volumes)
    tile exactly 128 MB, so we know nothing was missed."""
    top = [p for p in manifest["partitions"] if p["name"] not in SUBPARTITIONS]
    total = sum(p["size"] for p in top)
    manifest["top_level_bytes"] = total
    if total != NAND_SIZE:
        manifest["warnings"].append(
            f"coverage: the top-level partitions sum to {total:#x}, not {NAND_SIZE:#x} (128 MB); the "
            "backup may be missing a partition or double-counting one")
    return total == NAND_SIZE


def verify_against_stock(run_dir, stock_img, manifest):
    """Independent, re-reads-the-files check of an existing backup. Returns (ok, notes). ok is False
    if ANY check fails or a check it should run couldn't: every saved .bin is re-hashed against the
    manifest; the firmware dump must equal the stock .img body in full (not just a prefix); boarddata1
    must hold a plausible MAC; and ART must carry calibration at 0x1000/0x5000. A note starting 'FAIL'
    or 'SKIP' means not-ok."""
    notes, ok = [], True

    def record(good, msg):  # good is a bool; a FAIL note is prefixed and flips ok to False
        nonlocal ok
        ok = ok and good
        notes.append(("" if good else "FAIL: ") + msg)

    # 1. Re-hash every saved file against the manifest, and refuse a run that wasn't complete/clean.
    if not manifest.get("complete"):
        record(False, f"the backup run did not complete (error: {manifest.get('error', 'unknown')})")
    # The firmware image and the per-unit primaries MUST be present, or this isn't a restorable backup.
    # (The .bak copies are checked during the backup run's CRITICAL-present check; here we require the
    # irreplaceable primaries, which is enough to catch a gutted or truncated backup folder.)
    present = {p["name"] for p in manifest.get("partitions", [])}
    for name in ("firmware", "0:ART", "boarddata1"):
        if name not in present:
            record(False, f"{name} is missing from the backup (not a complete, restorable backup)")
    for p in manifest.get("partitions", []):
        f = run_dir / p["file"]
        if p["status"] == "failed":
            record(False, f"{p['name']}: recorded as failed, not a verified copy")
            continue
        if not f.exists():
            record(False, f"{p['name']}: {p['file']} is missing")
            continue
        actual = hashlib.sha256(f.read_bytes()).hexdigest()
        if p.get("sha256") and actual != p["sha256"]:
            record(False, f"{p['name']}: {p['file']} sha256 no longer matches the manifest")
        elif f.stat().st_size != p["size"] and p["name"] not in SUBPARTITIONS and p["status"] == "ok":
            record(False, f"{p['name']}: {p['file']} is {f.stat().st_size} bytes, expected {p['size']}")

    # 2. Firmware dump vs the stock image body (after its 128-byte DNI header) - a full-length compare.
    fw = next((p for p in manifest.get("partitions", []) if p["name"] == "firmware"), None)
    if not stock_img:
        notes.append("SKIP: no --stock-img given, so the firmware-vs-stock check did not run")
        ok = False
    elif not pathlib.Path(stock_img).exists():
        record(False, f"stock image {stock_img} not found")
    elif fw and (run_dir / fw["file"]).exists():
        body = pathlib.Path(stock_img).read_bytes()[128:]
        dump = (run_dir / fw["file"]).read_bytes()
        if not body:
            record(False, "the stock image has no body after its 128-byte header")
        elif len(dump) < len(body):
            record(False, f"firmware dump is {len(dump)} bytes, shorter than the stock body {len(body)}")
        else:
            record(dump[:len(body)] == body, f"firmware vs stock .img body ({len(body)} bytes): "
                   + ("MATCH" if dump[:len(body)] == body else "DIFFER"))

    # 3. boarddata1 holds a plausible MAC (not empty, not all 00 / all FF).
    bd = next((p for p in manifest.get("partitions", []) if p["name"] == "boarddata1"), None)
    if bd and (run_dir / bd["file"]).exists():
        head = (run_dir / bd["file"]).read_bytes()[:6]
        trivial = len(head) < 6 or all(b == 0 for b in head) or all(b == 0xff for b in head)
        record(not trivial, "boarddata1 MAC " + (":".join(f"{b:02x}" for b in head) if head else "(empty)")
               + (" looks blank/invalid" if trivial else ""))

    # 4. ART has calibration at both radio offsets.
    art = next((p for p in manifest.get("partitions", []) if p["name"] == "0:ART"), None)
    if art and (run_dir / art["file"]).exists():
        d = (run_dir / art["file"]).read_bytes()
        for off in (0x1000, 0x5000):
            chunk = d[off:off + 0x2f20]
            blank = not chunk or all(c == 0xff for c in chunk)
            record(not blank, f"0:ART @ {off:#x}: {'BLANK (no calibration!)' if blank else 'has calibration data'}")

    manifest["verify"] = notes
    manifest["verify_ok"] = ok
    return ok, notes


def _verify_state(manifest):
    """Three states: the independent stock cross-check PASSed, FAILed, or was not requested (no
    --stock-img). Never report PASS for a check that didn't run."""
    if not manifest.get("verify_requested"):
        return "not run (no --stock-img)"
    return "PASS" if manifest.get("verify_ok") else "FAIL"


# ---------------- read-only re-hash: prove the live flash still matches an existing backup ----------------
# After a RAM boot (an OpenWrt test image loaded into RAM, never flashed), this re-reads the live NAND and
# compares it to a backup's manifest to show nothing reached the READ-ONLY flash regions. It stays
# read-only: beyond device_hash the only commands are `head -c N /dev/mtdX | sha256sum` and `head -c N
# /dev/mtdX | wc -c` (byte-bounded reads; no dd, no write).
#
# A hash cannot prove every partition, and it does NOT prove "nothing was written anywhere". The stock
# firmware rewrites config/pot/secdata/ntgrdata and the rootfs_data overlay at runtime, so those differ
# after ANY normal reboot and a changed hash there is not evidence of a write. "firmware" (kernel +
# squashfs + rootfs_data) carries that overlay as its tail, so only its stable prefix - everything before
# rootfs_data, which is kernel+squashfs - is compared; "rootfs" is the same partition region (its squashfs
# bytes coincide with that prefix, its tail is the same overlay), so it is not hashed separately. The
# prefix covers the OpenWrt "kernel" partition and the start of the "ubi" partition; the ubi tail (all of
# rootfs_data) lies PAST the prefix, so a stray write THERE is invisible to this hash and is covered only
# by the serial UBI-attach lines. A write that lands in the kernel+squashfs prefix does show up here as a
# mismatch. (The prefix end L is erase-block aligned and the squashfs ends well before it, so the whole
# squashfs plus its padding is inside [0, L) and fully covered; only the rootfs_data overlay past L is not.)

def rehash_mode(name):
    """How a partition is checked on re-hash: whole-device hash, read-only prefix, skipped-volatile, or
    covered-by-the-firmware-prefix."""
    if name == "firmware":
        return "prefix"      # kernel+squashfs prefix is read-only; the rootfs_data tail is not
    if name == "rootfs":
        return "covered"     # same squashfs region as the firmware prefix; don't read it twice
    if name in VOLATILE:
        return "volatile"    # stock rewrites these at runtime; a hash proves nothing
    return "whole"           # boot chain, ART, boarddata1, kernel, language, cert: must be byte-identical


def local_prefix_sha(path, nbytes):
    """sha256 of the first nbytes of a local file, with the count actually read (to catch a short file)."""
    h = hashlib.sha256()
    got = 0
    with open(path, "rb") as f:
        while got < nbytes:
            chunk = f.read(min(1 << 20, nbytes - got))
            if not chunk:
                break
            h.update(chunk)
            got += len(chunk)
    return h.hexdigest(), got


def prefix_hash(t, n, dev, nbytes):
    """sha256 of the first nbytes of /dev/<dev>, read with `head -c` (read-only). Returns (sha_or_None, rc).
    NB: the pipeline's rc is `cut`'s (always 0), so a short read is NOT caught here; confirm the byte
    count with prefix_bytecount before calling a mismatch a change."""
    cmd = f'head -c {nbytes} /dev/{dev} | sha256sum | cut -d" " -f1'
    out, rc = ot.run_command(t, n, cmd, timeout=_hash_timeout(nbytes))
    return _grep1(out, r"^([0-9a-f]{64})$"), rc


def prefix_bytecount(t, n, dev, nbytes):
    """How many bytes `head -c nbytes /dev/<dev>` actually yields, so a short/failed read can be told apart
    from a real change. Returns an int, or None if it couldn't be read."""
    out, rc = ot.run_command(t, n, f"head -c {nbytes} /dev/{dev} | wc -c", timeout=_hash_timeout(nbytes))
    m = ot.re.search(r"^\s*(\d+)\s*$", out, ot.re.M)
    return int(m.group(1)) if (not rc and m) else None


def selftest_prefix(t, n, live):
    """Confirm `head -c` yields exactly N bytes on this router, so a BusyBox without it reports 'method
    unavailable' instead of a false 'firmware changed'. Content-independent: it counts bytes, it does not
    compare to the backup. N is capped to the probed partition's size so a short partition still reads in
    full. Returns (ok, reason_if_not)."""
    # Probe on any partition except firmware/rootfs (in practice the largest is ntgrdata): this only asks
    # "does head -c exist", so a read error in firmware itself must surface later as a short prefix read
    # (UNREADABLE), not a false "no head -c". Pick the largest so a 0-length /proc/mtd entry can't mislead.
    candidates = [ds for nm, ds in live.items() if nm not in ("firmware", "rootfs")] or list(live.values())
    dev, size = max(candidates, key=lambda ds: ds[1])
    N = min(0x10000, size)
    if N <= 0:
        return False, "no partition large enough to self-test the prefix read"
    out, rc = ot.run_command(t, n, f"head -c {N} /dev/{dev} | wc -c", timeout=120)
    m = ot.re.search(r"^\s*(\d+)\s*$", out, ot.re.M)
    if rc or not m:
        return False, "head -c produced no byte count"
    got = int(m.group(1))
    if got != N:
        return False, f"head -c returned {got} bytes, not {N} (no byte-bounded read on this BusyBox)"
    return True, ""


def local_file_sha(path):
    """sha256 of a whole local file, streamed, plus its length. Raises OSError if it can't be read."""
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def run_rehash(t, backup_dir, manifest):
    """Re-hash the live flash and compare to the backup's manifest. Returns (passed, results), where each
    result is {name, mode, verdict, detail}; verdict is one of proven, CHANGED, MISSING, UNREADABLE,
    unprovable, no-baseline, uncovered, volatile, covered. PASS means every non-volatile partition the
    backup recorded was read and matched, every non-volatile partition on the LIVE flash is covered by the
    backup, and the firmware read-only prefix was proven - never merely 'nothing flagged'. The caller must
    reject an incomplete backup before trusting a PASS."""
    n = [0]

    def counter():
        n[0] += 1
        return n[0]

    # Same identity guard as the backup: do not read a stranger's flash.
    dt_model, _ = ot.run_command(t, counter(), ot.COMMANDS["dt_model"])
    fw_version, _ = ot.run_command(t, counter(), ot.COMMANDS["fw_version"])
    if not ot.IDENT_RE.search(dt_model + fw_version):
        raise BackupError("this doesn't look like an Orbi RBR router; refusing to re-hash")

    mtd_out, _ = ot.run_command(t, counter(), ot.COMMANDS["mtd"])
    # Skip the vol_* UBI volumes exactly as run_backup does: they are gluebi views of ntgrdata (already
    # captured and classified volatile), never in the manifest, so the coverage check must not flag them.
    live = {nm: (dev, size) for dev, size, nm in parse_proc_mtd(mtd_out) if not nm.startswith("vol_")}
    if not live:
        raise BackupError("no mtd partitions found in /proc/mtd")

    by_name = {p["name"]: p for p in manifest.get("partitions", [])}
    fw_size = by_name.get("firmware", {}).get("size")
    rd_size = by_name.get("rootfs_data", {}).get("size")

    results = []
    passed = True

    def add(name, mode, verdict, detail, is_fail=False):
        nonlocal passed
        if is_fail:
            passed = False
        results.append({"name": name, "mode": mode, "verdict": verdict, "detail": detail})

    prefix_ok, prefix_why = selftest_prefix(t, counter(), live)

    # Coverage: a non-volatile partition that is on the live flash but NOT in the backup manifest can't be
    # proven unchanged, so it must fail the run (otherwise it would be silently skipped and still PASS).
    for nm in sorted(live):
        if rehash_mode(nm) != "volatile" and nm not in by_name:
            add(nm, rehash_mode(nm), "uncovered",
                "on the live flash but not in the backup manifest; can't prove it unchanged", is_fail=True)

    for p in manifest.get("partitions", []):
        name, exp_sha, exp_size = p["name"], p.get("sha256"), p["size"]
        mode = rehash_mode(name)
        # Structural checks apply to EVERY partition, volatile included: a partition that has vanished or
        # changed size is a flash-layout change, not the content rewrite that 'volatile' tolerates.
        if name not in live:
            add(name, mode, "MISSING", "not present in the live /proc/mtd", is_fail=True)
            continue
        dev, live_size = live[name]
        if live_size != exp_size:
            add(name, mode, "CHANGED", f"size is {live_size} live, backup had {exp_size}", is_fail=True)
            continue
        if mode == "volatile":
            # Only rootfs_data sits under the OpenWrt "ubi" range (0x1900000-0x3a00000), so only its note
            # points at the serial UBI-attach lines; the others just differ through normal stock operation.
            detail = ("the writable overlay under the OpenWrt ubi range; the serial UBI-attach lines cover it"
                      if name == "rootfs_data"
                      else "stock rewrites this at runtime; not checked, expected to differ")
            add(name, mode, "volatile", detail)
            continue
        if mode == "covered":
            # rootfs = squashfs + the rootfs_data overlay tail. Its read-only squashfs bytes coincide with
            # the firmware prefix, so they stand or fall with the firmware line; its tail is volatile.
            add(name, mode, "covered",
                "not hashed directly; its read-only squashfs bytes coincide with the firmware prefix (see "
                "the firmware line), its overlay tail is volatile")
            continue
        if not exp_sha or p.get("status") == "failed":
            add(name, mode, "no-baseline", "the backup has no trustworthy hash for this partition",
                is_fail=True)
            continue
        if mode == "whole":
            live_sha, info = device_hash(t, counter(), dev, exp_size)
            isize = info.get("size")
            if not live_sha:  # a read error makes sha256sum fail and the 'sha:' line empty
                add(name, mode, "UNREADABLE", "the router could not hash this partition", is_fail=True)
            elif isize and isize.isdigit() and int(isize) != exp_size:
                add(name, mode, "UNREADABLE",
                    f"the device now reports {isize} bytes, backup had {exp_size}", is_fail=True)
            elif live_sha == exp_sha:
                add(name, mode, "proven", "identical to the backup")
            else:
                add(name, mode, "CHANGED", "hash differs from the backup - this partition was written",
                    is_fail=True)
        else:  # prefix (firmware)
            if fw_size is None or rd_size is None:
                add(name, mode, "no-baseline",
                    "need firmware and rootfs_data sizes to locate the read-only prefix", is_fail=True)
                continue
            L = fw_size - rd_size
            if not 0 < L < fw_size:  # a degenerate/corrupt manifest: never 'prove' zero or negative bytes
                add(name, mode, "no-baseline",
                    f"the read-only prefix length ({L}) is out of range for a {fw_size}-byte firmware",
                    is_fail=True)
                continue
            if not prefix_ok:
                add(name, mode, "unprovable", f"can't read a byte prefix here ({prefix_why}); firmware not "
                    "proven - the serial UBI-attach lines are the evidence for this region", is_fail=True)
                continue
            fw_file = backup_dir / p["file"]
            # The backup .bin is the prefix baseline, so verify IT first (as --verify does): a rotted or
            # truncated local file must read as a bad baseline, never as "the router's flash changed".
            try:
                whole_sha, _ = local_file_sha(fw_file)
            except OSError as e:
                add(name, mode, "no-baseline", f"can't read the backup {p['file']} ({e}); no prefix baseline",
                    is_fail=True)
                continue
            if exp_sha and whole_sha != exp_sha:
                add(name, mode, "no-baseline",
                    f"the backup {p['file']} no longer matches its manifest hash (bit-rot?); not a baseline",
                    is_fail=True)
                continue
            local_sha, got = local_prefix_sha(fw_file, L)
            if got != L:
                add(name, mode, "no-baseline", f"backup {p['file']} is shorter than the {L}-byte prefix",
                    is_fail=True)
                continue
            live_sha, _ = prefix_hash(t, counter(), dev, L)
            if not live_sha:
                add(name, mode, "UNREADABLE", "the router could not hash the firmware prefix", is_fail=True)
            elif live_sha == local_sha:
                add(name, mode, "proven",
                    f"read-only prefix ({L} bytes, kernel+squashfs) identical to the backup")
            else:
                # The pipe's rc was cut's, so a mismatch could be a short read, not a write. Confirm the
                # byte count before calling it CHANGED: a short/failed read is UNREADABLE, not evidence.
                nread = prefix_bytecount(t, counter(), dev, L)
                if nread != L:
                    add(name, mode, "UNREADABLE",
                        f"only read {nread} of {L} prefix bytes - a short read, not proof of a change",
                        is_fail=True)
                else:
                    add(name, mode, "CHANGED",
                        f"read-only prefix ({L} bytes) differs - the kernel/squashfs region was written",
                        is_fail=True)

    # PASS requires firmware to have been positively proven, not just "no partition flagged".
    if not any(r["name"] == "firmware" and r["verdict"] == "proven" for r in results):
        passed = False
    return passed, results


REHASH_LABEL = {"proven": "PROVEN UNCHANGED", "CHANGED": "CHANGED (!)", "MISSING": "MISSING (!)",
                "UNREADABLE": "UNREADABLE (!)", "unprovable": "NOT PROVABLE (read method)",
                "no-baseline": "NO BASELINE (!)", "uncovered": "NOT IN BACKUP (!)",
                "covered": "covered by the firmware prefix",
                "volatile": "not provable by hash (volatile)"}
REHASH_ORDER = ["CHANGED", "MISSING", "UNREADABLE", "uncovered", "no-baseline", "unprovable",
                "proven", "covered", "volatile"]


def write_rehash_report(backup_dir, manifest, passed, results, host):
    ts = datetime.datetime.now()
    buckets = {}
    for r in results:
        buckets.setdefault(r["verdict"], []).append(r)
    fw = next((r for r in results if r["name"] == "firmware"), None)
    fw_proven = bool(fw) and fw["verdict"] == "proven"
    prefix_line = ("The read-only region a stray write would hit - the kernel+squashfs firmware prefix - "
                   "was checked byte for byte and matched."
                   if fw_proven else
                   "NOTE: the firmware read-only prefix was NOT proven this run (see the firmware line "
                   "below), so the read-only claim is not established.")
    lines = [f"RBR10 read-only re-hash   {ts.isoformat(timespec='seconds')}",
             f"host: {host}",
             f"compared against backup: {backup_dir.name}  (taken {manifest.get('started', '?')})",
             "result: " + ("PASS - no write to the read-only flash regions detected" if passed
                           else "FAIL - see the flagged lines"),
             "",
             "This re-reads the live NAND and compares it to the backup. It proves only the READ-ONLY flash",
             "regions (boot chain, ART, boarddata1, kernel, language, cert, and the kernel+squashfs firmware",
             "prefix). The volatile partitions (config/pot/secdata/ntgrdata and the rootfs_data overlay) are",
             "rewritten by the running stock firmware, so they differ after any normal reboot and a hash",
             "can't prove them; the overlay/ubi tail is covered by the serial UBI-attach lines, not here.",
             prefix_line, ""]
    for v in REHASH_ORDER:
        rs = buckets.get(v)
        if not rs:
            continue
        lines.append(f"{REHASH_LABEL.get(v, v)}:")
        lines += [f"  {r['name']:16} {r['detail']}" for r in rs]
        lines.append("")
    report = "\n".join(lines).rstrip() + "\n"
    out = backup_dir / f"rehash-{ts.strftime('%Y%m%d-%H%M%S-%f')}.txt"
    out.write_text(report, encoding="utf-8", newline="\n")
    return out, report


def rehash_main(host, backup_dir, connect, ask_user, ask_password):
    backup_dir = pathlib.Path(backup_dir)
    mpath = backup_dir / "manifest.json"
    if not mpath.exists():
        print(f"no manifest.json in {backup_dir}; not a backup folder")
        return 2
    try:
        manifest = json.loads(mpath.read_text())
    except (OSError, ValueError) as e:
        print(f"could not read {mpath}: {e}")
        return 2
    if not isinstance(manifest, dict):
        print(f"{mpath} is not a backup manifest (expected a JSON object)")
        return 2
    # An incomplete backup is missing partitions, so a PASS against it would be unsound (the uncaptured
    # partitions are simply absent from the manifest and never checked). Refuse it, as --verify does.
    if not manifest.get("complete"):
        print(f"the backup in {backup_dir} is marked incomplete (error: {manifest.get('error', 'unknown')}); "
              "refusing to re-hash against an unfinished baseline")
        return 2
    t, shell_reached, passed, results = None, False, False, []
    try:
        t = connect(host)
        ot.login(t, ask_user, ask_password)
        shell_reached = True
        passed, results = run_rehash(t, backup_dir, manifest)
    except Exception as e:  # any failure ends as a FAIL with a written report, never a bare traceback
        print(f"\nStopped: {type(e).__name__}: {e}")
        results.append({"name": "-", "mode": "-", "verdict": "UNREADABLE",
                        "detail": f"{type(e).__name__}: {e}"})
        passed = False
    finally:
        if t is not None and shell_reached:
            try:
                t.send("exit")
            except OSError:
                pass
        if t is not None:
            t.close()
    try:
        out, report = write_rehash_report(backup_dir, manifest, passed, results, host)
        print(report)
        print(f"Re-hash report: {out}")
    except OSError as e:  # couldn't write the report file: still report the verdict on the console
        print(f"could not write the re-hash report: {e}")
        for r in results:
            print(f"  {REHASH_LABEL.get(r['verdict'], r['verdict'])}: {r['name']} {r['detail']}")
        print("PASS" if passed else "FAIL")
    return 0 if passed else 1


def write_summary(run_dir, manifest):
    done = manifest.get("complete")
    lines = [f"RBR10 flash backup  {manifest.get('started', '')}", f"host: {manifest.get('host')}",
             f"transfer: {manifest.get('direction')}",
             f"run: {'COMPLETE' if done else 'INCOMPLETE'}"
             + ("" if done else f'  (stopped: {manifest.get("error", "unknown")})'), ""]
    lines.append(f"{'dev':6} {'name':16} {'status':9} {'read':>10} / {'size':<10}  sha256")
    for p in manifest["partitions"]:
        read = p["size"] if p["status"] == "ok" else p.get("size_read")
        read = "-" if read is None else read
        lines.append(f"{p['dev']:6} {p['name']:16} {p['status']:9} {str(read):>10} / {p['size']:<10}  "
                     f"{(p.get('sha256') or '-')[:16]}")
    counts = {s: sum(p["status"] == s for p in manifest["partitions"]) for s in ("ok", "unstable", "failed")}
    lines += ["", f"ok {counts['ok']}  unstable {counts['unstable']}  failed {counts['failed']}  "
              f"of {len(manifest['partitions'])}",
              f"top-level coverage: {manifest.get('top_level_bytes', 0):#x} of {NAND_SIZE:#x}",
              f"independent verify: {_verify_state(manifest)}"]
    if manifest.get("verify"):
        lines += ["", "independent checks:"] + [f"  {v}" for v in manifest["verify"]]
    lines += ["", "warnings (these make the backup not-clean):"] + (
        [f"  {w}" for w in manifest["warnings"]] or ["  (none)"])
    if manifest.get("notes"):
        lines += ["", "notes (informational):"] + [f"  {nn}" for nn in manifest["notes"]]
    lines += ["", "PRIVACY: config holds the admin/Wi-Fi passwords and cert may hold keys. Keep this "
              "folder on this PC only; never copy it off or print the .bin contents."]
    (run_dir / "backup_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    write_sha256sums(run_dir, manifest)


def write_sha256sums(run_dir, manifest):
    """A `sha256sum -c`-compatible sha256sums.txt over the captured .bin files, so a restore can be
    verified with one command. Only partitions whose received hash was recorded are listed; a failed
    partition is left out (there is no trustworthy hash for it)."""
    rows = [f"{p['sha256']}  {p['file']}" for p in manifest["partitions"]
            if p.get("sha256") and p["status"] in ("ok", "unstable")]
    (run_dir / "sha256sums.txt").write_text("\n".join(rows) + ("\n" if rows else ""),
                                            encoding="utf-8", newline="\n")


def run_backup(t, run_dir, manifest, host, local_ip):
    """Identity check, then back up every raw partition. Returns when done; raises on a fatal error."""
    n = [0]

    def counter():
        n[0] += 1
        return n[0]

    # Confirm it's an Orbi RBR before reading its flash. The stock /proc/device-tree/model is the
    # Qualcomm reference-board string ("...IPQ40xx/AP-DK04.1-C1"), NOT "RBR10"; the RBR10 name lives
    # in fw_version (/module_name etc.), so check both, as orbi_telnet's recon does.
    dt_model, _ = ot.run_command(t, counter(), ot.COMMANDS["dt_model"])
    fw_version, _ = ot.run_command(t, counter(), ot.COMMANDS["fw_version"])
    (run_dir / "dt_model.txt").write_text(dt_model, encoding="utf-8", newline="\n")
    (run_dir / "fw_version.txt").write_text(fw_version, encoding="utf-8", newline="\n")
    if not ot.IDENT_RE.search(dt_model + fw_version):
        raise BackupError("this doesn't look like an Orbi RBR router; refusing to back up")
    mtd_out, _ = ot.run_command(t, counter(), ot.COMMANDS["mtd"])
    parts = parse_proc_mtd(mtd_out)
    (run_dir / "proc_mtd.txt").write_text(mtd_out, encoding="utf-8", newline="\n")
    to_copy = [(d, s, nm) for d, s, nm in parts if not nm.startswith("vol_")]
    if not to_copy:
        raise BackupError("no raw mtd partitions found in /proc/mtd")
    print(f"backing up {len(to_copy)} partitions (skipping {len(parts) - len(to_copy)} UBI volumes)")

    direction = choose_direction(t, counter, host, local_ip)
    manifest["direction"] = direction
    print(f"data channel: {direction}")

    for dev, size, name in to_copy:
        backup_partition(t, counter, direction, host, local_ip, dev, name, size, run_dir, manifest)
    check_coverage(manifest)
    # The per-unit irreplaceables must each be present and "ok", or the backup can't restore the unit.
    have = {p["name"]: p["status"] for p in manifest["partitions"]}
    for name in CRITICAL:
        if name not in have:
            manifest["warnings"].append(f"critical partition {name} was not found in /proc/mtd")
        elif have[name] != "ok":
            manifest["warnings"].append(f"critical partition {name} is '{have[name]}', not a clean copy")
    # Non-volatile partitions should read "ok"; an "unstable" one there is flagged by backup_partition.


def main(argv=None, out_root=DEFAULT_OUT, connect=ot.Telnet.connect, ask_user=None, ask_password=None,
         require_tty=True, stock_img=None):
    ap = argparse.ArgumentParser(description="Read-only full-flash backup of a Netgear Orbi RBR10.")
    ap.add_argument("host", nargs="?", default=DEFAULT_HOST)
    ap.add_argument("--verify", metavar="DIR",
                    help="re-check an existing backup folder against the stock firmware image; no router")
    ap.add_argument("--rehash", metavar="DIR",
                    help="re-read the LIVE router's flash and compare to an existing backup folder, to "
                         "prove a RAM boot wrote nothing to the read-only flash regions; read-only, "
                         "needs the router")
    ap.add_argument("--stock-img", default=stock_img,
                    help="path to the stock RBR10-V*.img, for the independent firmware check")
    args = ap.parse_args(argv)

    if args.verify:
        run_dir = pathlib.Path(args.verify)
        mpath = run_dir / "manifest.json"
        if not mpath.exists():
            print(f"no manifest.json in {run_dir}; not a backup folder")
            return 2
        try:
            manifest = json.loads(mpath.read_text())
        except ValueError as e:
            print(f"could not parse {mpath}: {e}")
            return 2
        if not isinstance(manifest, dict):
            print(f"{mpath} is not a backup manifest (expected a JSON object)")
            return 2
        manifest.setdefault("notes", [])
        ok, notes = verify_against_stock(run_dir, args.stock_img, manifest)
        for v in notes:
            print(v)
        print(f"\nVerify: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1

    if require_tty and not sys.stdin.isatty():
        print("Run this in a real terminal: the password prompt needs one to keep your typing hidden.")
        return 2
    ask_user = ask_user or (lambda: input("Orbi telnet username [admin]: ").strip() or "admin")
    ask_password = ask_password or (lambda: ot.getpass.getpass("Orbi admin password (hidden): "))

    if args.rehash:
        return rehash_main(args.host, args.rehash, connect, ask_user, ask_password)

    run_dir = ot.make_run_dir(out_root)
    manifest = {"host": args.host, "started": datetime.datetime.now().isoformat(timespec="seconds"),
                "complete": False, "warnings": [], "notes": [], "partitions": [],
                "verify_requested": bool(args.stock_img)}
    t = None
    shell_reached = False
    verify_ok = True
    # If a stock image was asked for, the verify MUST complete; if it raises mid-read it stays "not
    # done" and the run is not clean, so a crashed verify can never pass as success.
    verify_done = not bool(args.stock_img)
    try:
        t = connect(args.host)
        local_ip = t.s.getsockname()[0]
        router_ip = t.s.getpeername()[0]  # the resolved router IP, so the data-channel peer check is
        ot.login(t, ask_user, ask_password)  # correct even when host was given as a name
        shell_reached = True
        run_backup(t, run_dir, manifest, router_ip, local_ip)
        manifest["complete"] = True  # the partition loop finished; set before verify, which gates on it
        if args.stock_img:
            verify_ok, _ = verify_against_stock(run_dir, args.stock_img, manifest)
            verify_done = True
    except (OSError, RuntimeError, BackupError, ot.LoginFailed) as e:
        manifest["error"] = f"{type(e).__name__}: {e}"
        print(f"\nStopped: {e}")
    except BaseException as e:
        manifest["error"] = f"{type(e).__name__}: {e}"
        raise
    finally:
        manifest["finished"] = datetime.datetime.now().isoformat(timespec="seconds")
        if t is not None and shell_reached:
            try:
                t.send("exit")
            except OSError:
                pass
        records_ok = True
        try:
            (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8",
                                                   newline="\n")
            write_summary(run_dir, manifest)
        except OSError as e:
            records_ok = False
            print(f"could not write the backup records: {e} (no durable record; treat as not clean)")
        if t is not None:
            t.close()

    # A clean run: it finished, the records are on disk, the independent verify passed (when run), every
    # partition is ok/unstable (none failed), and there are no warnings (an unexpected-unstable, a failed
    # or missing critical partition, a coverage gap, etc. each add one).
    statuses = [p["status"] for p in manifest["partitions"]]
    none_failed = bool(statuses) and "failed" not in statuses
    clean = (manifest["complete"] and records_ok and verify_ok and verify_done and none_failed
             and not manifest["warnings"])
    for w in manifest["warnings"]:  # surface the content on the console, not just a count
        print(f"  WARN {w}")
    print(f"\nBackup {'COMPLETE' if manifest['complete'] else 'INCOMPLETE'}, "
          f"{len(manifest['warnings'])} warning(s), verify {_verify_state(manifest)}. "
          f"Files: {run_dir}")
    if not clean:
        print("NOT a clean backup: review the warnings above and backup_summary.txt before relying on it "
              "for a restore (especially the ART and boarddata1 partitions).")
    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main())
