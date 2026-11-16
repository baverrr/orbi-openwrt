"""Tests for tools/orbi_backup.py. The telnet channel uses a fake socket (reused from
test_orbi_telnet); the data channel uses real loopback sockets, so the nc transfer path is
exercised for real. No router needed.

Run:  python -I tests/test_orbi_backup.py   (from the orbi-openwrt folder)
"""
import hashlib
import io
import json
import pathlib
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
import unittest.mock
from contextlib import redirect_stdout

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
sys.path.insert(0, str(HERE))
import orbi_backup as ob  # noqa: E402
import orbi_telnet as ot  # noqa: E402
import test_orbi_telnet as tt  # noqa: E402  (FakeRouter, FakeSock, PASSWORD, FORBIDDEN)

PASSWORD = tt.PASSWORD
FAKE_MAC = b"\x02\x11\x22\x33\x44\x55"  # locally-administered, not the real unit's MAC


def sha(b):
    return hashlib.sha256(b).hexdigest()


class FakeBackupRouter(tt.FakeRouter):
    """A FakeRouter that also drives REAL loopback sockets for nc, so transfer()/choose_direction()
    run their true socket code.

    data      dev -> (name, bytes): the partition's true content, what sha256sum hashes.
    serve     dev -> list of payloads to send over nc, one per transfer (falls back to data[dev]
              when the list runs out); use to model a corrupt or short stream, or corrupt-then-good.
    unstable  devs whose device hash differs on the 'after' read (a live partition).
    bad_blocks/ecc  dev -> value the fake's sysfs reports ("unknown" models this 3.14 kernel).
    no_listen a BusyBox nc without -l (its `nc -l` serves nothing)."""

    def __init__(self, clock, data=None, serve=None, unstable=(), bad_blocks=None, ecc=None,
                 no_listen=False, no_head=False, short_head=(), **kw):
        super().__init__(clock, netgear_prompts=True, **kw)
        self.data = data or {}
        self.mtd_text = "".join(f'{d}: {len(v):08x} 00020000 "{n}"\n' for d, (n, v) in self.data.items())
        self.serve = {d: list(v) for d, v in (serve or {}).items()}
        self.unstable = set(unstable)
        self.bad_blocks = bad_blocks or {}
        self.ecc = ecc or {}
        self.no_listen = no_listen
        self.no_head = no_head  # model a BusyBox without `head -c` (the --rehash prefix read)
        self.short_head = set(short_head)  # devs whose `head -c N` returns only N//2 bytes (a short read)
        self.threads = []
        self._hash_reads = {}  # dev -> device-hash reads so far (to flip unstable ones)

    def getsockname(self):
        return ("127.0.0.1", 12345)

    def getpeername(self):
        return ("127.0.0.1", 23)

    def _shell(self, line):
        m = re.match(r"echo __B''(\d+)__; (.*); __rc=\$\?; echo; echo __E''\1__ rc=\$__rc$", line)
        if not m:
            return super()._shell(line)
        n, cmd = m.group(1), m.group(2)
        self._maybe_nc(cmd)
        out, rc = self._canned(cmd)
        echo = line.encode()
        body = (out.rstrip("\n").encode().replace(b"\n", b"\r\n") + (b"\r\n" if out.endswith("\n") else b""))
        self.chunks.append(echo + b"\r\n")
        self.chunks.append(f"__B{n}__\r\n".encode() + body + f"\r\n__E{n}__ rc={rc}\r\nroot@RBR10:/# ".encode())
        self.commands_run += 1

    def _canned(self, cmd):
        if cmd == ot.COMMANDS["dt_model"]:
            # the REAL stock model is the Qualcomm reference-board string, with no "RBR" in it, so the
            # identity check must fall through to fw_version (regression guard for the dt_model-only bug)
            return "Qualcomm Technologies, Inc. IPQ40xx/AP-DK04.1-C1\nqcom,ipq40xx\n", 0
        if cmd == ot.COMMANDS["fw_version"]:
            return "/module_name: RBR10\n/hardware_version: RBR10\n/firmware_version: V2.7.5.6\n", 0
        if cmd == ot.COMMANDS["mtd"]:
            return self.mtd_text, 0
        hm = re.search(r"sha256sum < /dev/(mtd\d+)", cmd)
        if hm:
            dev = hm.group(1)
            payload = self.data.get(dev, (None, b""))[1]
            self._hash_reads[dev] = self._hash_reads.get(dev, 0) + 1
            h = sha(payload)
            if dev in self.unstable and self._hash_reads[dev] % 2 == 0:  # the 'after' read differs
                h = sha(payload + b"!")
            return (f"sha: {h}\nsize: {len(payload)}\n"
                    f"bad_blocks: {self.bad_blocks.get(dev, 'unknown')}\n"
                    f"ecc: {self.ecc.get(dev, 'unknown')}\n"), 0
        pm = re.search(r"head -c (\d+) /dev/(mtd\d+) \| sha256sum", cmd)  # --rehash prefix hash
        if pm:
            if self.no_head:
                return "head: unrecognized option: c\n", 1
            nbytes, dev = int(pm.group(1)), pm.group(2)
            payload = self.data.get(dev, (None, b""))[1]
            got = nbytes // 2 if dev in self.short_head else nbytes  # model a short read
            return sha(payload[:got]) + "\n", 0  # rc 0: the pipe's rc is cut's, as on the router
        wm = re.search(r"head -c (\d+) /dev/(mtd\d+) \| wc -c", cmd)  # --rehash head -c count / self-test
        if wm:
            if self.no_head:
                return "0\n", 0
            nbytes, dev = int(wm.group(1)), wm.group(2)
            payload = self.data.get(dev, (None, b""))[1]
            got = min(nbytes, len(payload))
            if dev in self.short_head:
                got = nbytes // 2
            return f"{got}\n", 0
        return "", 0  # nc commands produce nothing on the telnet channel

    def _payload_for(self, dev):
        q = self.serve.get(dev)
        if q:
            return q.pop(0)
        return self.data.get(dev, (None, b""))[1]

    def _maybe_nc(self, cmd):
        lm = re.match(r"(?:echo (\S+) \| )?nc -l -p (\d+)(?: < /dev/(mtd\d+))?$", cmd)
        if lm and not self.no_listen:
            magic, port, dev = lm.group(1), int(lm.group(2)), lm.group(3)
            self._serve(port, magic.encode() if magic else self._payload_for(dev))
            return
        cm = re.match(r"(?:echo (\S+) \| )?nc (\S+) (\d+)(?: < /dev/(mtd\d+))?$", cmd)
        if cm:
            magic, ip, port, dev = cm.group(1), cm.group(2), int(cm.group(3)), cm.group(4)
            self._connect_send(ip, port, magic.encode() if magic else self._payload_for(dev))

    def _serve(self, port, payload):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(10)

        def run():
            try:
                conn, _ = srv.accept()
                with conn:
                    conn.sendall(payload)
            except OSError:
                pass
            finally:
                srv.close()
        th = threading.Thread(target=run, daemon=True)
        th.start()
        self.threads.append(th)

    def _connect_send(self, ip, port, payload):
        def run():
            for _ in range(40):
                try:
                    with socket.create_connection((ip, port), timeout=5) as s:
                        s.sendall(payload)
                    return
                except OSError:
                    time.sleep(0.05)
        th = threading.Thread(target=run, daemon=True)
        th.start()
        self.threads.append(th)


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = tt.FakeClock()
        fake_time = types.SimpleNamespace(monotonic=self.clock.monotonic, sleep=self.clock.sleep)
        p = unittest.mock.patch.object(ot, "time", fake_time)
        p.start()
        self.addCleanup(p.stop)
        ps = unittest.mock.patch.object(ob.time, "sleep", lambda s: None)  # no real socket-retry waits
        ps.start()
        self.addCleanup(ps.stop)

    def tmpdir(self):
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    _port = 51600

    def _next_port(self):  # a unique data port per run, so loopback tests don't race on a fixed one
        Base._port += 1
        return Base._port

    def run_main(self, router, stock_img=None, nand_size=None):
        tmp = self.tmpdir()
        buf = io.StringIO()
        ctx = unittest.mock.patch.object(ob, "NAND_SIZE", nand_size) if nand_size else _null()
        with redirect_stdout(buf), ctx, unittest.mock.patch.object(ob, "ROUTER_PORT", self._next_port()):
            code = ob.main(["127.0.0.1"], out_root=tmp, connect=lambda host: ot.Telnet(router),
                           ask_user=lambda: "admin", ask_password=lambda: PASSWORD,
                           require_tty=False, stock_img=stock_img)
        run_dir = next(tmp.iterdir())
        m = json.loads((run_dir / "manifest.json").read_text())
        return code, run_dir, buf.getvalue(), m


class _null:
    def __enter__(self): return self
    def __exit__(self, *a): return False


# ---------------- pure-logic unit tests ----------------

class PureTests(Base):
    def test_parse_proc_mtd(self):
        txt = 'dev: size erasesize name\nmtd0: 00100000 00020000 "0:SBL1"\nmtd24: 03c00000 00020000 "ntgrdata"\n'
        self.assertEqual(ob.parse_proc_mtd(txt), [("mtd0", 0x100000, "0:SBL1"), ("mtd24", 0x3c00000, "ntgrdata")])

    def test_safe_name(self):
        self.assertEqual(ob.safe_name("mtd0", "0:SBL1"), "mtd0_0_SBL1.bin")
        self.assertEqual(ob.safe_name("mtd22", "rootfs_data"), "mtd22_rootfs_data.bin")
        self.assertNotIn("/", ob.safe_name("mtd1", "a/b"))

    def test_hash_timeout_scales_with_size(self):
        self.assertEqual(ob._hash_timeout(0), 120)
        self.assertGreater(ob._hash_timeout(0x4000000), ob._hash_timeout(0x100000))

    def test_coverage_tiles_to_128mb(self):
        sizes = {"0:SBL1": 0x100000, "0:MIBIB": 0x100000, "0:BOOTCONFIG": 0x100000, "0:QSEE": 0x100000,
                 "0:QSEE_1": 0x100000, "0:CDT": 0x80000, "0:CDT_1": 0x80000, "0:BOOTCONFIG1": 0x80000,
                 "0:APPSBLENV": 0x80000, "0:APPSBL": 0x200000, "0:APPSBL_1": 0x200000, "0:ART": 0x80000,
                 "0:ART.bak": 0x80000, "config": 0x100000, "boarddata1": 0x80000, "pot": 0x80000,
                 "boarddata1.bak": 0x80000, "language": 0x300000, "cert": 0x80000, "firmware": 0x2800000,
                 "kernel": 0x320000, "rootfs": 0x24e0000, "rootfs_data": 0x720000, "secdata": 0xa00000,
                 "ntgrdata": 0x3c00000}
        m = {"partitions": [{"name": k, "size": v} for k, v in sizes.items()], "warnings": []}
        self.assertTrue(ob.check_coverage(m), m["warnings"])
        self.assertEqual(m["top_level_bytes"], 0x8000000)
        self.assertEqual(m["warnings"], [])

    def test_coverage_warns_when_a_partition_is_missing(self):
        m = {"partitions": [{"name": "0:SBL1", "size": 0x100000}], "warnings": []}
        self.assertFalse(ob.check_coverage(m))
        self.assertTrue(any("missing" in w for w in m["warnings"]))

    # --- backup_partition verdicts (transfer + device_hash stubbed) ---

    def _run_partition(self, name, dev, payload, device_hashes, served_results, bad_blocks="0", ecc="0"):
        """device_hashes: list of (sha, info) returned by successive device_hash calls.
        served_results: list of (bytes_written, sha_rx, rc) returned by successive transfer calls."""
        run_dir = self.tmpdir()
        manifest = {"partitions": [], "warnings": [], "notes": []}
        dh = iter(device_hashes)
        sv = iter(served_results)
        with unittest.mock.patch.object(ob, "device_hash", lambda *a, **k: next(dh)), \
             unittest.mock.patch.object(ob, "transfer", lambda *a, **k: next(sv)):
            e = ob.backup_partition(None, iter(range(999)).__next__, "router_listens", "h", "l",
                                    dev, name, len(payload), run_dir, manifest)
        return e, manifest

    def test_partition_ok(self):
        p = b"ART-cal" * 100
        info = {"bad_blocks": "0", "ecc": "0"}
        e, m = self._run_partition("0:ART", "mtd11", p, [(sha(p), info), (sha(p), info)],
                                   [(len(p), sha(p), 0)])
        self.assertEqual(e["status"], "ok")
        self.assertEqual(m["warnings"], [])

    def test_full_size_wrong_content_is_not_ok(self):
        # the single most important case: right byte count, wrong bytes -> must fail, never "ok"
        p = b"real" * 300
        bad = sha(b"corrupt" * 171)[:64]  # a hash that is neither sha_before nor sha_after
        info = {"bad_blocks": "0", "ecc": "0"}
        hashes = [(sha(p), info), (sha(p), info)] * ob.RETRIES
        served = [(len(p), bad, 0)] * ob.RETRIES
        e, m = self._run_partition("0:ART", "mtd11", p, hashes, served)
        self.assertEqual(e["status"], "failed")
        self.assertEqual(e["attempts"], ob.RETRIES)
        self.assertTrue(any("matches neither device state" in w for w in m["warnings"]))

    def test_short_read_on_a_changed_partition_is_not_unstable(self):
        p = b"live" * 300
        info = {"bad_blocks": "0", "ecc": "0"}
        # device changes across each read AND the transfer is short -> must retry/fail, not "unstable"
        hashes = [(sha(p), info), (sha(p + b"x"), info)] * ob.RETRIES
        served = [(10, sha(b"live" * 2)[:64], 0)] * ob.RETRIES
        e, m = self._run_partition("ntgrdata", "mtd24", p, hashes, served)
        self.assertEqual(e["status"], "failed")
        self.assertFalse(any("snapshot" in n for n in m["notes"]))

    def test_volatile_unstable_snapshot_is_a_note_not_a_warning(self):
        p = b"ntgr" * 300
        info = {"bad_blocks": "0", "ecc": "0"}
        # changed across the read, but the full-size copy matches the 'before' state: a clean snapshot
        e, m = self._run_partition("ntgrdata", "mtd24", p, [(sha(p), info), (sha(p + b"!"), info)],
                                   [(len(p), sha(p), 0)])
        self.assertEqual(e["status"], "unstable")
        self.assertEqual(m["warnings"], [])
        self.assertTrue(any("snapshot" in n for n in m["notes"]))

    def test_nonvolatile_unstable_is_a_warning(self):
        p = b"lang" * 300
        info = {"bad_blocks": "0", "ecc": "0"}
        e, m = self._run_partition("language", "mtd17", p, [(sha(p), info), (sha(p + b"!"), info)],
                                   [(len(p), sha(p), 0)])
        self.assertEqual(e["status"], "unstable")
        self.assertTrue(any("should NOT change at runtime" in w for w in m["warnings"]))

    def test_firmware_unstable_is_a_note_not_a_warning(self):
        # firmware carries the writable rootfs_data overlay as its tail, so an unstable mid-read is a
        # note (MAY_CHANGE_MIDREAD), not the "should NOT change" warning language/ART etc. would get
        p = b"fw" * 300
        info = {"bad_blocks": "0", "ecc": "0"}
        e, m = self._run_partition("firmware", "mtd19", p, [(sha(p), info), (sha(p + b"!"), info)],
                                   [(len(p), sha(p), 0)])
        self.assertEqual(e["status"], "unstable")
        self.assertEqual(m["warnings"], [])
        self.assertTrue(any("snapshot" in n for n in m["notes"]))

    def test_transfer_exception_retries_then_recovers(self):
        p = b"ok" * 500
        info = {"bad_blocks": "0", "ecc": "0"}
        hashes = [(sha(p), info), (sha(p), info), (sha(p), info), (sha(p), info)]
        calls = [ob.BackupError("socket reset"), (len(p), sha(p), 0)]

        def transfer(*a, **k):
            r = calls.pop(0)
            if isinstance(r, Exception):
                raise r
            return r
        run_dir = self.tmpdir()
        manifest = {"partitions": [], "warnings": [], "notes": []}
        dh = iter(hashes)
        with unittest.mock.patch.object(ob, "device_hash", lambda *a, **k: next(dh)), \
             unittest.mock.patch.object(ob, "transfer", transfer):
            e = ob.backup_partition(None, iter(range(999)).__next__, "router_listens", "h", "l",
                                    "mtd11", "0:ART", len(p), run_dir, manifest)
        self.assertEqual(e["status"], "ok")
        self.assertEqual(e["attempts"], 2)

    def test_missing_device_hash_is_not_corruption(self):
        p = b"x" * 100
        info = {"bad_blocks": "0", "ecc": "0"}
        e, m = self._run_partition("0:ART", "mtd11", p, [(None, info), (sha(p), info)] * ob.RETRIES,
                                   [(len(p), sha(p), 0)] * ob.RETRIES)
        self.assertEqual(e["status"], "failed")
        self.assertTrue(any("could not hash" in w for w in m["warnings"]))

    def test_unknown_bad_blocks_is_a_note_real_count_is_a_warning(self):
        p = b"x" * 100
        e, m = self._run_partition("cert", "mtd18", p,
                                   [(sha(p), {"bad_blocks": "unknown", "ecc": "unknown"})] * 2,
                                   [(len(p), sha(p), 0)])
        self.assertTrue(any("bad_blocks not reported" in n for n in m["notes"]))
        self.assertFalse(any("bad_blocks" in w for w in m["warnings"]))
        e, m = self._run_partition("cert", "mtd18", p,
                                   [(sha(p), {"bad_blocks": "2", "ecc": "0"})] * 2, [(len(p), sha(p), 0)])
        self.assertTrue(any("bad_blocks=2" in w for w in m["warnings"]))

    # --- verify_against_stock ---

    def _verify_dir(self, firmware=None, board=None, art=None, extra=None, complete=True):
        run_dir = self.tmpdir()
        parts = []
        if firmware is not None:
            (run_dir / "firmware.bin").write_bytes(firmware)
            parts.append({"name": "firmware", "file": "firmware.bin", "size": len(firmware),
                          "status": "ok", "sha256": sha(firmware)})
        if board is not None:
            (run_dir / "bd.bin").write_bytes(board)
            parts.append({"name": "boarddata1", "file": "bd.bin", "size": len(board), "status": "ok",
                          "sha256": sha(board)})
        if art is not None:
            (run_dir / "art.bin").write_bytes(art)
            parts.append({"name": "0:ART", "file": "art.bin", "size": len(art), "status": "ok",
                          "sha256": sha(art)})
        for p in extra or []:
            (run_dir / p["file"]).write_bytes(p.pop("_bytes"))
            parts.append(p)
        return run_dir, {"partitions": parts, "complete": complete, "notes": []}

    def _good_art(self):
        a = bytearray(b"\xff" * 0x8000)
        a[0x1000:0x1000 + 0x2f20] = b"\xa5" * 0x2f20
        a[0x5000:0x5000 + 0x2f20] = b"\x5a" * 0x2f20
        return bytes(a)

    def test_verify_pass(self):
        body = bytes(range(256)) * 200
        run_dir, m = self._verify_dir(firmware=body, board=FAKE_MAC + b"\0" * 10, art=self._good_art())
        stock = self.tmpdir() / "s.img"
        stock.write_bytes(b"\0" * 128 + body)
        ok, notes = ob.verify_against_stock(run_dir, str(stock), m)
        self.assertTrue(ok, notes)

    def test_verify_fails_on_firmware_differ(self):
        run_dir, m = self._verify_dir(firmware=b"A" * 1000, board=FAKE_MAC + b"\0" * 10, art=self._good_art())
        stock = self.tmpdir() / "s.img"
        stock.write_bytes(b"\0" * 128 + b"B" * 1000)
        ok, notes = ob.verify_against_stock(run_dir, str(stock), m)
        self.assertFalse(ok)
        self.assertTrue(any("DIFFER" in n for n in notes))

    def test_verify_fails_on_empty_firmware_dump(self):
        run_dir, m = self._verify_dir(firmware=b"", board=FAKE_MAC + b"\0" * 10, art=self._good_art())
        stock = self.tmpdir() / "s.img"
        stock.write_bytes(b"\0" * 128 + b"B" * 1000)
        ok, notes = ob.verify_against_stock(run_dir, str(stock), m)
        self.assertFalse(ok)  # must NOT report "first 0 bytes MATCH"
        self.assertFalse(any("MATCH" in n for n in notes))

    def test_verify_fails_on_blank_art(self):
        a = bytearray(self._good_art())
        a[0x5000:0x5000 + 0x2f20] = b"\xff" * 0x2f20  # wifi1 calibration blank
        run_dir, m = self._verify_dir(firmware=b"A" * 1000, board=FAKE_MAC + b"\0" * 10, art=bytes(a))
        stock = self.tmpdir() / "s.img"
        stock.write_bytes(b"\0" * 128 + b"A" * 1000)
        ok, notes = ob.verify_against_stock(run_dir, str(stock), m)
        self.assertFalse(ok)
        self.assertTrue(any("BLANK" in n for n in notes))

    def test_verify_fails_on_trivial_boarddata(self):
        run_dir, m = self._verify_dir(firmware=b"A" * 1000, board=b"\xff" * 16, art=self._good_art())
        stock = self.tmpdir() / "s.img"
        stock.write_bytes(b"\0" * 128 + b"A" * 1000)
        ok, notes = ob.verify_against_stock(run_dir, str(stock), m)
        self.assertFalse(ok)
        self.assertTrue(any("blank/invalid" in n for n in notes))

    def test_verify_fails_when_no_stock_img(self):
        run_dir, m = self._verify_dir(firmware=b"A" * 1000, board=FAKE_MAC + b"\0" * 10, art=self._good_art())
        ok, notes = ob.verify_against_stock(run_dir, None, m)
        self.assertFalse(ok)
        self.assertTrue(any("SKIP" in n for n in notes))

    def test_verify_fails_on_rehash_mismatch(self):
        body = b"A" * 1000
        run_dir, m = self._verify_dir(firmware=body, board=FAKE_MAC + b"\0" * 10, art=self._good_art())
        (run_dir / "firmware.bin").write_bytes(b"A" * 999 + b"B")  # file changed since the manifest hash
        stock = self.tmpdir() / "s.img"
        stock.write_bytes(b"\0" * 128 + body)
        ok, notes = ob.verify_against_stock(run_dir, str(stock), m)
        self.assertFalse(ok)
        self.assertTrue(any("no longer matches the manifest" in n for n in notes))

    def test_verify_fails_when_run_incomplete(self):
        run_dir, m = self._verify_dir(firmware=b"A" * 1000, complete=False)
        m["error"] = "boom"
        ok, notes = ob.verify_against_stock(run_dir, None, m)
        self.assertFalse(ok)
        self.assertTrue(any("did not complete" in n for n in notes))


# ---------------- loopback integration tests (real sockets) ----------------

class IntegrationTests(Base):
    def _data(self):
        return {"mtd0": ("0:SBL1", b"SBL1" * 300), "mtd11": ("0:ART", bytes(range(256)) * 20),
                "mtd12": ("0:ART.bak", bytes(range(256)) * 20),
                "mtd14": ("boarddata1", FAKE_MAC + b"BD" * 100),
                "mtd16": ("boarddata1.bak", FAKE_MAC + b"BK" * 100),
                "mtd24": ("ntgrdata", b"NTGR" * 500)}

    def _total(self, data):
        return sum(len(v) for _, v in data.values())

    def test_full_backup_over_loopback(self):
        data = self._data()
        r = FakeBackupRouter(self.clock, data=data)
        code, run_dir, out, m = self.run_main(r, nand_size=self._total(data))
        self.assertEqual(code, 0, out + "\n" + json.dumps(m["warnings"], indent=2))
        self.assertEqual(m["direction"], "router_listens")
        self.assertTrue(m["complete"])
        self.assertEqual([p["status"] for p in m["partitions"]], ["ok"] * len(data))
        for dev, (name, payload) in data.items():
            f = run_dir / ob.safe_name(dev, name)
            self.assertEqual(f.read_bytes(), payload, dev)
            p = next(x for x in m["partitions"] if x["dev"] == dev)
            self.assertEqual(p["sha256"], sha(payload))
        self.assertEqual(m["warnings"], [])
        sums = (run_dir / "sha256sums.txt").read_text().splitlines()
        self.assertEqual(len(sums), len(data))

    def test_falls_back_to_laptop_listener_when_router_nc_has_no_l(self):
        data = self._data()
        r = FakeBackupRouter(self.clock, data=data, no_listen=True)
        code, run_dir, out, m = self.run_main(r, nand_size=self._total(data))
        self.assertEqual(m["direction"], "laptop_listens", out)
        self.assertEqual([p["status"] for p in m["partitions"]], ["ok"] * len(data))
        self.assertEqual(code, 0, out)

    def test_volatile_unstable_is_still_a_clean_backup(self):
        data = self._data()
        r = FakeBackupRouter(self.clock, data=data, unstable={"mtd24"})  # ntgrdata is volatile
        code, run_dir, out, m = self.run_main(r, nand_size=self._total(data))
        statuses = {p["dev"]: p["status"] for p in m["partitions"]}
        self.assertEqual(statuses["mtd24"], "unstable")
        self.assertEqual(code, 0, out + "\n" + json.dumps(m["warnings"]))  # volatile snapshot is fine

    def test_critical_partition_unstable_fails_the_run(self):
        data = self._data()
        r = FakeBackupRouter(self.clock, data=data, unstable={"mtd11"})  # 0:ART must be stable
        code, run_dir, out, m = self.run_main(r, nand_size=self._total(data))
        self.assertEqual(code, 1)
        self.assertTrue(any("0:ART" in w and ("unstable" in w or "should NOT" in w) for w in m["warnings"]))
        self.assertIn("NOT a clean backup", out)

    def test_full_size_corrupt_transfer_fails_over_loopback(self):
        data = {"mtd0": ("0:SBL1", b"good" * 300)}
        # serve same-length wrong bytes every attempt while sha256sum hashes the real data
        r = FakeBackupRouter(self.clock, data=data, serve={"mtd0": [b"evil" * 300] * ob.RETRIES})
        code, run_dir, out, m = self.run_main(r, nand_size=self._total(data))
        self.assertEqual(m["partitions"][0]["status"], "failed")
        self.assertEqual(code, 1)

    def test_corrupt_then_good_recovers_over_loopback(self):
        data = {"mtd0": ("0:SBL1", b"good" * 300)}
        r = FakeBackupRouter(self.clock, data=data, serve={"mtd0": [b"evil" * 300]})  # 1 bad then real
        code, run_dir, out, m = self.run_main(r, nand_size=self._total(data))
        self.assertEqual(m["partitions"][0]["status"], "ok")
        self.assertEqual(m["partitions"][0]["attempts"], 2)
        self.assertEqual((run_dir / "mtd0_0_SBL1.bin").read_bytes(), b"good" * 300)

    def test_not_an_orbi_refuses_before_any_flash_read(self):
        r = FakeBackupRouter(self.clock, data=self._data())
        orig = r._canned
        # neither the model NOR fw_version names an RBR -> refuse (both are checked)
        def other(cmd):
            if cmd == ot.COMMANDS["dt_model"]:
                return "TP-Link Archer C7\nqcom,ipq40xx\n", 0
            if cmd == ot.COMMANDS["fw_version"]:
                return "/module_name: Archer\n", 0
            return orig(cmd)
        r._canned = other
        code, run_dir, out, m = self.run_main(r)
        self.assertEqual(code, 1)
        self.assertIn("doesn't look like an Orbi", m["error"])
        self.assertEqual(list(run_dir.glob("*.bin")), [])

    def test_identity_passes_on_fw_version_when_model_lacks_rbr(self):
        # the exact real-unit case: dt_model is the Qualcomm string, fw_version carries RBR10
        data = {"mtd0": ("0:SBL1", b"x" * 64)}
        r = FakeBackupRouter(self.clock, data=data)  # fake's dt_model has no RBR; fw_version does
        code, run_dir, out, m = self.run_main(r, nand_size=self._total(data))
        self.assertNotIn("doesn't look like an Orbi", m.get("error", ""))
        self.assertTrue((run_dir / "fw_version.txt").exists())

    def test_missing_critical_partition_warns(self):
        data = {"mtd0": ("0:SBL1", b"x" * 64)}  # no ART/boarddata1 at all
        r = FakeBackupRouter(self.clock, data=data)
        code, run_dir, out, m = self.run_main(r, nand_size=self._total(data))
        self.assertEqual(code, 1)
        self.assertTrue(any("0:ART" in w and "not found" in w for w in m["warnings"]))

    def test_every_command_sent_is_read_only_both_directions(self):
        for no_listen in (False, True):  # router_listens and laptop_listens use different nc forms
            data = self._data()
            r = FakeBackupRouter(self.clock, data=data, no_listen=no_listen)
            code, run_dir, out, m = self.run_main(r, nand_size=self._total(data))
            shell_lines = [ln for ln in r.lines if "__B''" in ln]
            self.assertTrue(shell_lines)
            for ln in shell_lines:
                inner = re.search(r"__B''\d+__; (.*); __rc=", ln).group(1)
                self.assertIsNone(tt.FORBIDDEN.search(inner), f"write verb in: {inner}")
                for use in re.findall(r"\S* /dev/mtd\d+", inner):
                    self.assertRegex(use, r"< /dev/mtd\d+", f"/dev used without input redirect: {inner}")

    def test_inline_stock_img_verify_passes_on_a_clean_backup(self):
        # the strongest way to run it: `orbi_backup --stock-img stock.img`. A flawless backup must
        # come out exit 0 / verify PASS (regression guard for the complete-before-verify ordering).
        art = bytearray(b"\xff" * 0x8000)
        art[0x1000:0x1000 + 0x2f20] = b"\xa5" * 0x2f20
        art[0x5000:0x5000 + 0x2f20] = b"\x5a" * 0x2f20
        fw = bytes(range(256)) * 50
        data = {"mtd11": ("0:ART", bytes(art)), "mtd12": ("0:ART.bak", bytes(art)),
                "mtd14": ("boarddata1", FAKE_MAC + b"BD" * 100),
                "mtd16": ("boarddata1.bak", FAKE_MAC + b"BK" * 100),
                "mtd19": ("firmware", fw)}
        stock = self.tmpdir() / "stock.img"
        stock.write_bytes(b"\0" * 128 + fw)
        r = FakeBackupRouter(self.clock, data=data)
        code, run_dir, out, m = self.run_main(r, stock_img=str(stock), nand_size=self._total(data))
        self.assertTrue(m["verify_ok"], m.get("verify"))
        self.assertEqual(code, 0, out + "\n" + json.dumps(m.get("verify", []), indent=2))

    def test_verify_mode_cli_pass_and_fail(self):
        data = self._data()
        r = FakeBackupRouter(self.clock, data=data)
        code, run_dir, out, m = self.run_main(r, nand_size=self._total(data))
        self.assertEqual(code, 0)
        # --verify with no stock image -> FAIL (the firmware check could not run)
        buf = io.StringIO()
        with redirect_stdout(buf):
            vcode = ob.main(["--verify", str(run_dir)], require_tty=False)
        self.assertEqual(vcode, 1, buf.getvalue())
        self.assertIn("FAIL", buf.getvalue())

    def test_no_stock_img_reports_verify_not_run_not_pass(self):
        data = self._data()
        r = FakeBackupRouter(self.clock, data=data)
        code, run_dir, out, m = self.run_main(r, nand_size=self._total(data))  # no stock image
        self.assertEqual(code, 0)
        self.assertIn("verify not run", out)
        self.assertNotIn("verify PASS", out)
        self.assertIn("not run", (run_dir / "backup_summary.txt").read_text())
        self.assertFalse(m.get("verify_requested"))

    def test_verify_fails_when_a_critical_partition_is_absent(self):
        # a manifest (complete) that is missing firmware/ART/boarddata1 must FAIL --verify, not pass
        run_dir = self.tmpdir()
        (run_dir / "mtd0_0_SBL1.bin").write_bytes(b"x" * 64)
        manifest = {"complete": True, "notes": [], "partitions": [
            {"name": "0:SBL1", "file": "mtd0_0_SBL1.bin", "size": 64, "status": "ok", "sha256": sha(b"x" * 64)}]}
        (run_dir / "manifest.json").write_text(json.dumps(manifest))
        stock = self.tmpdir() / "s.img"
        stock.write_bytes(b"\0" * 128 + b"A" * 100)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ob.main(["--verify", str(run_dir), "--stock-img", str(stock)], require_tty=False)
        self.assertEqual(code, 1, buf.getvalue())
        self.assertIn("missing from the backup", buf.getvalue())

    def test_verify_mode_missing_manifest(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ob.main(["--verify", str(self.tmpdir())], require_tty=False)
        self.assertEqual(code, 2)
        self.assertIn("not a backup folder", buf.getvalue())


# ---------------- --rehash: prove a RAM boot wrote nothing to the read-only flash regions ----------------

class RehashTests(Base):
    SQ = b"SQFS" * 256    # 1024-byte read-only squashfs/kernel prefix
    OVL = b"\xff" * 512   # 512-byte writable overlay (rootfs_data), the firmware tail

    def _base(self, fw=None, art=None, bd=None):
        fw = (self.SQ + self.OVL) if fw is None else fw
        return {"mtd0": ("0:SBL1", b"SBL1" * 64),
                "mtd11": ("0:ART", art if art is not None else bytes(range(256)) * 4),
                "mtd14": ("boarddata1", bd if bd is not None else FAKE_MAC + b"BD" * 50),
                "mtd13": ("config", b"CFG" * 40),       # volatile: stock rewrites it
                "mtd19": ("firmware", fw),
                "mtd22": ("rootfs_data", fw[-512:])}    # the overlay == the firmware tail

    def _backup(self, data):
        """A backup dir + manifest consistent with `data`. Only firmware.bin is written, since --rehash
        re-reads only it from disk (for the prefix compare); the rest are compared live-hash vs manifest."""
        backup_dir = self.tmpdir()
        parts = []
        for dev, (name, payload) in data.items():
            f = ob.safe_name(dev, name)
            parts.append({"dev": dev, "name": name, "file": f, "size": len(payload),
                          "status": "ok", "sha256": sha(payload)})
            if name == "firmware":
                (backup_dir / f).write_bytes(payload)
        manifest = {"started": "2026-11-15T21:45:33", "complete": True, "partitions": parts}
        (backup_dir / "manifest.json").write_text(json.dumps(manifest))
        return backup_dir, manifest

    def _rehash(self, backup_data, router_data, **router_kw):
        backup_dir, manifest = self._backup(backup_data)
        fake = FakeBackupRouter(self.clock, data=router_data, **router_kw)
        t = ot.Telnet(fake)
        ot.login(t, lambda: "admin", lambda: PASSWORD)
        buf = io.StringIO()
        with redirect_stdout(buf):
            passed, results = ob.run_rehash(t, backup_dir, manifest)
        return passed, {r["name"]: r for r in results}, fake, backup_dir, manifest

    # --- pure helpers ---

    def test_rehash_mode_classifies_each_partition(self):
        self.assertEqual(ob.rehash_mode("firmware"), "prefix")
        self.assertEqual(ob.rehash_mode("rootfs"), "covered")
        self.assertEqual(ob.rehash_mode("rootfs_data"), "volatile")
        self.assertEqual(ob.rehash_mode("config"), "volatile")
        self.assertEqual(ob.rehash_mode("ntgrdata"), "volatile")
        self.assertEqual(ob.rehash_mode("0:ART"), "whole")
        self.assertEqual(ob.rehash_mode("kernel"), "whole")

    def test_local_prefix_sha_counts_and_hashes(self):
        d = self.tmpdir()
        (d / "f.bin").write_bytes(b"abcdef")
        self.assertEqual(ob.local_prefix_sha(d / "f.bin", 3), (sha(b"abc"), 3))
        self.assertEqual(ob.local_prefix_sha(d / "f.bin", 99), (sha(b"abcdef"), 6))  # short file: got < n

    def test_rehash_commands_are_read_only(self):
        for cmd in (f'head -c {ob.NAND_SIZE} /dev/mtd19 | sha256sum | cut -d" " -f1',
                    "head -c 65536 /dev/mtd0 | wc -c"):
            self.assertIsNone(tt.FORBIDDEN.search(cmd), cmd)

    # --- verdicts ---

    def test_rehash_pass_when_nothing_changed(self):
        base = self._base()
        passed, res, fake, *_ = self._rehash(base, dict(base))
        self.assertTrue(passed, res)
        self.assertEqual(res["firmware"]["verdict"], "proven")
        self.assertEqual(res["0:ART"]["verdict"], "proven")
        self.assertEqual(res["config"]["verdict"], "volatile")      # not provable, expected
        self.assertEqual(res["rootfs_data"]["verdict"], "volatile")

    def test_rehash_pass_when_only_the_overlay_moved(self):
        # the case that must not false-alarm: stock rewrote the overlay after the backup, prefix is intact
        backup = self._base()
        moved = self._base(fw=self.SQ + b"\x00" * 512)  # same squashfs prefix, different overlay tail
        passed, res, *_ = self._rehash(backup, moved)
        self.assertTrue(passed, res)
        self.assertEqual(res["firmware"]["verdict"], "proven")

    def test_rehash_fail_when_squashfs_prefix_changed(self):
        backup = self._base()
        tampered = self._base(fw=b"XQFS" + self.SQ[4:] + self.OVL)  # first bytes of the squashfs differ
        passed, res, *_ = self._rehash(backup, tampered)
        self.assertFalse(passed)
        self.assertEqual(res["firmware"]["verdict"], "CHANGED")
        self.assertIn("kernel/squashfs", res["firmware"]["detail"])

    def test_rehash_fail_when_a_boot_or_cal_partition_changed(self):
        # same length, one byte flipped: must reach the hash-compare branch, not stop at the size check
        for dev, name in (("mtd11", "0:ART"), ("mtd14", "boarddata1"), ("mtd0", "0:SBL1")):
            backup = self._base()
            router = dict(backup)
            orig = backup[dev][1]
            router[dev] = (name, bytes([orig[0] ^ 0xff]) + orig[1:])  # differ, same length
            passed, res, *_ = self._rehash(backup, router)
            self.assertFalse(passed, name)
            self.assertEqual(res[name]["verdict"], "CHANGED", name)
            self.assertIn("hash differs", res[name]["detail"], name)

    def test_rehash_fail_when_a_partition_grew(self):
        backup = self._base()
        router = dict(backup)
        router["mtd14"] = ("boarddata1", backup["mtd14"][1] + b"!!")  # size changed
        passed, res, *_ = self._rehash(backup, router)
        self.assertFalse(passed)
        self.assertEqual(res["boarddata1"]["verdict"], "CHANGED")
        self.assertIn("size", res["boarddata1"]["detail"])

    def test_rehash_short_prefix_read_is_unreadable_not_changed(self):
        # a truncated prefix read (the pipe rc is cut's, always 0) must read UNREADABLE, never CHANGED
        base = self._base()
        passed, res, *_ = self._rehash(base, dict(base), short_head={"mtd19"})
        self.assertFalse(passed)
        self.assertEqual(res["firmware"]["verdict"], "UNREADABLE")
        self.assertIn("short read", res["firmware"]["detail"])

    def test_rehash_fail_when_a_partition_is_missing(self):
        backup = self._base()
        router = dict(backup)
        del router["mtd14"]  # boarddata1 gone from the live /proc/mtd
        passed, res, *_ = self._rehash(backup, router)
        self.assertFalse(passed)
        self.assertEqual(res["boarddata1"]["verdict"], "MISSING")

    def test_rehash_fail_on_unreadable_hash(self):
        base = self._base()
        with unittest.mock.patch.object(ob, "device_hash", lambda *a, **k: (None, {"rc": 0})):
            passed, res, *_ = self._rehash(base, dict(base))
        self.assertFalse(passed)
        self.assertEqual(res["0:ART"]["verdict"], "UNREADABLE")

    def test_rehash_method_unavailable_is_unprovable_not_changed(self):
        # a BusyBox without `head -c`: firmware must read UNPROVABLE (method), never a false CHANGED
        base = self._base()
        passed, res, *_ = self._rehash(base, dict(base), no_head=True)
        self.assertFalse(passed)
        self.assertEqual(res["firmware"]["verdict"], "unprovable")
        self.assertNotIn("CHANGED", res["firmware"]["verdict"])
        self.assertIn("UBI-attach", res["firmware"]["detail"])

    def test_rehash_cannot_pass_without_firmware_proven(self):
        base = {k: v for k, v in self._base().items() if v[0] != "firmware"}
        passed, res, *_ = self._rehash(base, dict(base))
        self.assertFalse(passed)  # no firmware to prove -> never PASS, even with nothing flagged

    def test_rehash_sends_no_nc_and_no_write_commands(self):
        base = self._base()
        passed, res, fake, *_ = self._rehash(base, dict(base))
        self.assertTrue(passed)
        shell_lines = [ln for ln in fake.lines if "__B''" in ln]
        self.assertTrue(shell_lines)
        for ln in shell_lines:
            inner = re.search(r"__B''\d+__; (.*); __rc=", ln).group(1)
            self.assertIsNone(tt.FORBIDDEN.search(inner), f"write verb in: {inner}")
            self.assertNotIn(" nc ", f" {inner} ")  # no data-channel commands on a rehash
        self.assertEqual(fake.threads, [])          # and no data sockets were opened

    # --- CLI path ---

    def _rehash_cli(self, backup_data, router_data, **router_kw):
        backup_dir, _ = self._backup(backup_data)
        fake = FakeBackupRouter(self.clock, data=router_data, **router_kw)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ob.main(["--rehash", str(backup_dir), "127.0.0.1"],
                           connect=lambda host: ot.Telnet(fake),
                           ask_user=lambda: "admin", ask_password=lambda: PASSWORD, require_tty=False)
        return code, buf.getvalue(), backup_dir

    def test_rehash_cli_pass_writes_report(self):
        base = self._base()
        code, out, backup_dir = self._rehash_cli(base, dict(base))
        self.assertEqual(code, 0, out)
        self.assertIn("PASS", out)
        reports = list(backup_dir.glob("rehash-*.txt"))
        self.assertEqual(len(reports), 1, reports)
        self.assertIn("PROVEN UNCHANGED", reports[0].read_text())

    def test_rehash_cli_fail_exit_code(self):
        backup = self._base()
        router = dict(backup)
        orig = backup["mtd11"][1]
        router["mtd11"] = ("0:ART", bytes([orig[0] ^ 0xff]) + orig[1:])  # same length -> hash-diff path
        code, out, backup_dir = self._rehash_cli(backup, router)
        self.assertEqual(code, 1)
        self.assertIn("CHANGED (!)", out)          # not the "PROVEN UNCHANGED" substring
        self.assertIn("FAIL", out)
        self.assertEqual(len(list(backup_dir.glob("rehash-*.txt"))), 1, "a FAIL run still writes a report")

    def _run_on(self, backup_dir, manifest, router_data, **kw):
        """Run run_rehash against a fake router, using an already-built (possibly hand-edited) manifest."""
        t = ot.Telnet(FakeBackupRouter(self.clock, data=router_data, **kw))
        ot.login(t, lambda: "admin", lambda: PASSWORD)
        with redirect_stdout(io.StringIO()):
            passed, results = ob.run_rehash(t, backup_dir, manifest)
        return passed, {r["name"]: r for r in results}

    # --- coverage / structural / baseline integrity (review findings) ---

    def test_rehash_uncovered_live_partition_fails(self):
        # a strict partition on the live router but absent from the backup manifest -> can't prove -> FAIL
        backup = self._base()
        router = dict(backup)
        router["mtd17"] = ("language", b"LANG" * 80)  # live-only, not in the backup
        passed, res, *_ = self._rehash(backup, router)
        self.assertFalse(passed)
        self.assertEqual(res["language"]["verdict"], "uncovered")

    def test_rehash_ignores_vol_ubi_volumes(self):
        # the real router exposes vol_* gluebi views of ntgrdata that the backup never captures; the
        # coverage check must NOT flag them 'uncovered' (regression: it broke every real-device run)
        backup = self._base()
        router = dict(backup)
        router["mtd25"] = ("vol_ntgrdata", b"V" * 200)
        router["mtd26"] = ("vol_traffic", b"T" * 200)
        passed, res, *_ = self._rehash(backup, router)
        self.assertTrue(passed, res)
        self.assertNotIn("vol_ntgrdata", res)  # ignored entirely, not reported
        self.assertNotIn("vol_traffic", res)

    def test_rehash_volatile_disappearing_is_structural_fail(self):
        backup = self._base()
        router = dict(backup)
        del router["mtd13"]  # config vanished from /proc/mtd: a layout change, not a content rewrite
        passed, res, *_ = self._rehash(backup, router)
        self.assertFalse(passed)
        self.assertEqual(res["config"]["verdict"], "MISSING")

    def test_rehash_volatile_resized_is_structural_fail(self):
        backup = self._base()
        router = dict(backup)
        router["mtd13"] = ("config", backup["mtd13"][1] + b"XX")  # config resized
        passed, res, *_ = self._rehash(backup, router)
        self.assertFalse(passed)
        self.assertEqual(res["config"]["verdict"], "CHANGED")

    def test_rehash_no_baseline_when_status_failed(self):
        backup = self._base()
        backup_dir, manifest = self._backup(backup)
        for p in manifest["partitions"]:
            if p["name"] == "0:ART":
                p["status"], p["sha256"] = "failed", None
        passed, res = self._run_on(backup_dir, manifest, dict(backup))
        self.assertFalse(passed)
        self.assertEqual(res["0:ART"]["verdict"], "no-baseline")

    def test_rehash_refuses_a_non_orbi(self):
        backup = self._base()
        backup_dir, manifest = self._backup(backup)
        fake = FakeBackupRouter(self.clock, data=dict(backup))
        orig = fake._canned

        def other(cmd):
            if cmd == ot.COMMANDS["dt_model"]:
                return "TP-Link Archer\nqcom,ipq40xx\n", 0
            if cmd == ot.COMMANDS["fw_version"]:
                return "/module_name: Archer\n", 0
            return orig(cmd)
        fake._canned = other
        t = ot.Telnet(fake)
        ot.login(t, lambda: "admin", lambda: PASSWORD)
        with redirect_stdout(io.StringIO()), self.assertRaises(ob.BackupError):
            ob.run_rehash(t, backup_dir, manifest)

    def test_rehash_corrupt_backup_file_is_baseline_not_a_write(self):
        # a rotted local firmware.bin must read as a bad baseline, never as "the router's flash changed"
        backup = self._base()
        backup_dir, manifest = self._backup(backup)
        fwfile = backup_dir / ob.safe_name("mtd19", "firmware")
        b = bytearray(fwfile.read_bytes())
        b[0] ^= 0xff
        fwfile.write_bytes(bytes(b))
        passed, res = self._run_on(backup_dir, manifest, dict(backup))  # router pristine
        self.assertFalse(passed)
        self.assertEqual(res["firmware"]["verdict"], "no-baseline")
        self.assertNotIn("written", res["firmware"]["detail"])

    def test_rehash_fail_when_last_prefix_byte_changed(self):
        # a write to the final byte of the read-only prefix (offset L-1) must FAIL, not pass as overlay
        backup = self._base()
        L = len(self.SQ)  # firmware = SQ + OVL, so the prefix length is len(SQ)
        fw = bytearray(backup["mtd19"][1])
        fw[L - 1] ^= 0xff
        router = dict(backup)
        router["mtd19"] = ("firmware", bytes(fw))
        router["mtd22"] = ("rootfs_data", bytes(fw)[-512:])
        passed, res, *_ = self._rehash(backup, router)
        self.assertFalse(passed)
        self.assertEqual(res["firmware"]["verdict"], "CHANGED")

    def test_rehash_zero_length_prefix_is_not_proven(self):
        # degenerate manifest: rootfs_data size == firmware size -> L==0 must NOT "prove" zero bytes
        backup = self._base()
        backup_dir, manifest = self._backup(backup)
        fw_size = next(p["size"] for p in manifest["partitions"] if p["name"] == "firmware")
        for p in manifest["partitions"]:
            if p["name"] == "rootfs_data":
                p["size"] = fw_size
        router = dict(backup)
        router["mtd22"] = ("rootfs_data", backup["mtd19"][1])  # match the forced size
        passed, res = self._run_on(backup_dir, manifest, router)
        self.assertFalse(passed)
        self.assertEqual(res["firmware"]["verdict"], "no-baseline")

    def test_rehash_rootfs_is_covered_not_hashed(self):
        backup = self._base()
        backup["mtd21"] = ("rootfs", b"RFS" * 100)  # covered: coincides with the firmware prefix
        passed, res, fake, *_ = self._rehash(backup, dict(backup))
        self.assertTrue(passed, res)
        self.assertEqual(res["rootfs"]["verdict"], "covered")
        self.assertFalse(any("sha256sum < /dev/mtd21" in ln for ln in fake.lines))  # never whole-hashed

    def test_rehash_cli_refuses_incomplete_backup(self):
        backup = self._base()
        backup_dir, manifest = self._backup(backup)
        manifest["complete"] = False
        manifest["error"] = "interrupted"
        (backup_dir / "manifest.json").write_text(json.dumps(manifest))
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ob.main(["--rehash", str(backup_dir), "127.0.0.1"],
                           connect=lambda h: ot.Telnet(FakeBackupRouter(self.clock, data=dict(backup))),
                           ask_user=lambda: "admin", ask_password=lambda: PASSWORD, require_tty=False)
        self.assertEqual(code, 2)
        self.assertIn("incomplete", buf.getvalue())

    def test_rehash_cli_error_path_writes_fail_report(self):
        backup = self._base()
        backup_dir, _ = self._backup(backup)

        def bad_connect(host):
            raise OSError("no route to host")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ob.main(["--rehash", str(backup_dir), "127.0.0.1"], connect=bad_connect,
                           ask_user=lambda: "admin", ask_password=lambda: PASSWORD, require_tty=False)
        self.assertEqual(code, 1)
        self.assertIn("Stopped", buf.getvalue())
        self.assertEqual(len(list(backup_dir.glob("rehash-*.txt"))), 1)  # a report is still written

    def test_rehash_missing_backup_firmware_file_is_no_baseline(self):
        backup = self._base()
        backup_dir, manifest = self._backup(backup)
        (backup_dir / ob.safe_name("mtd19", "firmware")).unlink()  # the prefix baseline is gone
        passed, res = self._run_on(backup_dir, manifest, dict(backup))  # router pristine
        self.assertFalse(passed)
        self.assertEqual(res["firmware"]["verdict"], "no-baseline")

    def test_rehash_cli_non_dict_manifest(self):
        d = self.tmpdir()
        (d / "manifest.json").write_text("[]")  # valid JSON, but not an object -> graceful exit, no crash
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ob.main(["--rehash", str(d), "127.0.0.1"], connect=lambda h: None,
                           ask_user=lambda: "admin", ask_password=lambda: PASSWORD, require_tty=False)
        self.assertEqual(code, 2)
        self.assertIn("not a backup manifest", buf.getvalue())

    def test_rehash_cli_missing_manifest(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ob.main(["--rehash", str(self.tmpdir()), "127.0.0.1"],
                           connect=lambda host: None, ask_user=lambda: "admin",
                           ask_password=lambda: PASSWORD, require_tty=False)
        self.assertEqual(code, 2)
        self.assertIn("not a backup folder", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
