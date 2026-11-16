"""Tests for tools/serial_log.py with a fake port, a fake clock and a fake winreg. No cable needed.

Run:  python -I -m unittest discover -s tests   (from the orbi-openwrt folder)
"""
import io
import json
import os
import pathlib
import shutil
import sys
import signal
import tempfile
import types
import unittest
import unittest.mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import serial_log as sl  # noqa: E402

BOOT = (b"\r\nU-Boot 2012.07 [Standard IPQ40XX,r39102] (Jun 10 2019)\r\n"
        b"machid: 8010100\r\nNAND:  ONFI device found\r\n128 MiB\r\n"
        b"Hit any key to stop autoboot:  2 \x08\x08\x08 1 \x08\x08\x08 0\r\n"
        b"## Starting kernel ...\r\n"
        b"Linux version 3.14.77 (dni@build)\r\n"
        b"0x000000000000-0x000000100000 : \"0:SBL1\"\r\n"
        b"0x000000100000-0x000000200000 : \"0:MIBIB\"\r\n"
        b"\x1b[1;32mPlease press Enter to activate this console.\x1b[0m\r\n")


class FakeClock:
    def __init__(self):
        self.t = 100.0

    def monotonic(self):
        return self.t


class FakePort:
    """Gives one chunk per read; None means nothing arrived. Each read takes `step` seconds.
    An exception in the list is raised. It has a write method that fails the test if called."""

    def __init__(self, clock, chunks, step=0.1):
        self.clock, self.chunks, self.step = clock, list(chunks), step
        self.closed = False
        self.access = "read-only"

    def read(self, n):
        self.clock.t += self.step
        if not self.chunks:
            return b""
        c = self.chunks.pop(0)
        if isinstance(c, BaseException):
            raise c
        return c or b""

    def write(self, data):  # pragma: no cover - must never run
        raise AssertionError("serial_log wrote to the port")

    def close(self):
        self.closed = True


class Base(unittest.TestCase):
    def tmpdir(self):
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        return d

    def run_main(self, chunks, argv=(), step=0.1, finder=lambda: "COM9", out=None, port=None):
        clock = FakeClock()
        port = port or FakePort(clock, chunks, step)
        port.clock = clock
        out_root = self.tmpdir()
        buf = out if out is not None else io.StringIO()
        opened = []

        def opener(name, baud):
            opened.append((name, baud))
            return port

        code = sl.main(list(argv), out_root=out_root, opener=opener, finder=finder,
                       clock=clock, out=buf)
        runs = sorted(out_root.iterdir()) if out_root.exists() else []
        run_dir = runs[0] if runs else None
        m = json.loads((run_dir / "manifest.json").read_text()) if run_dir else None
        text = buf.getvalue() if isinstance(buf, io.StringIO) else None
        return code, run_dir, text, m, port, opened


class VerdictTests(unittest.TestCase):
    def test_nothing(self):
        self.assertEqual(sl.verdict(0, 0, 0), "nothing")

    def test_stuck_line(self):
        self.assertEqual(sl.verdict(100, 0, 90), "stuck")

    def test_garbage(self):
        self.assertEqual(sl.verdict(200, 100, 0), "garbage")

    def test_little_text(self):
        self.assertEqual(sl.verdict(20, 20, 0), "a little text")

    def test_text(self):
        self.assertEqual(sl.verdict(1000, 990, 0), "text")

    def test_every_verdict_has_advice(self):
        for args in ((0, 0, 0), (5, 5, 0), (100, 0, 90), (200, 100, 0), (20, 20, 0),
                     (1000, 990, 0)):
            self.assertIn(sl.verdict(*args), sl.ADVICE)


class CleanTests(unittest.TestCase):
    def test_escape_sequences_and_controls_go(self):
        self.assertEqual(sl.clean("\x1b[1;32mhi\x1b[0m\x07\x08 there\tx"), "hi there\tx")

    def test_osc_and_c1_controls_go(self):
        self.assertEqual(sl.clean("a\x1b]0;title\x07b\x9bc"), "a0;titlebc")


class CaptureTests(Base):
    def capture(self, chunks):
        raw, log = io.BytesIO(), io.StringIO()
        cap = sl.Capture(raw, log)
        t = 10.0
        for c in chunks:
            cap.feed(c, t)
            t += 1.0
        cap.finish()
        return cap, raw.getvalue(), log.getvalue()

    def test_lines_split_across_chunks_keep_the_first_chunk_time(self):
        cap, raw, log = self.capture([b"U-Bo", b"ot 2012\r\nnext", b" line\n"])
        self.assertEqual(raw, b"U-Boot 2012\r\nnext line\n")
        self.assertEqual(log, "[    0.000] U-Boot 2012\n[    1.000] next line\n")

    def test_last_line_without_newline_is_kept(self):
        cap, _, log = self.capture([b"line one\nhalf"])
        self.assertEqual(log.splitlines()[-1], "[    0.000] half")

    def test_multibyte_char_split_across_chunks(self):
        cap, _, log = self.capture([b"caf\xc3", b"\xa9\n"])
        self.assertIn("café", log)

    def test_bare_cr_is_a_line_end(self):
        cap, _, log = self.capture([b"a\rb\n"])
        self.assertEqual(cap.lines, 2)

    def test_landmarks_and_partitions(self):
        cap, _, _ = self.capture([BOOT])
        for label in ("U-Boot banner", "autoboot prompt", "machine ID", "flash",
                      "handing over to the kernel", "Linux version", "partition",
                      "console prompt"):
            self.assertIn(label, cap.landmarks)
        self.assertEqual(cap.partitions, 2)
        self.assertEqual(cap.landmarks["U-Boot banner"]["line"], 1)

    def test_counts(self):
        cap, _, _ = self.capture([b"ab\x00\xff"])
        self.assertEqual((cap.total, cap.printable, cap.zeros), (4, 2, 1))


class MainTests(Base):
    def test_boot_log_is_text_and_files_are_written(self):
        code, run_dir, out, m, port, opened = self.run_main([None, BOOT])
        self.assertEqual(code, 0, out)
        self.assertEqual(opened, [("COM9", 115200)])
        self.assertTrue(port.closed)
        self.assertEqual((run_dir / "boot.raw").read_bytes(), BOOT)
        self.assertEqual(m["verdict"], "text")
        self.assertEqual(m["bytes"], len(BOOT))
        self.assertEqual(m["handle"], "read-only")
        self.assertIn("no data for", m["stopped_by"])
        summary = (run_dir / "summary.txt").read_text()
        self.assertIn("Verdict: text", summary)
        self.assertIn("partition (2 lines)", summary)
        self.assertNotIn("No U-Boot banner", summary)
        self.assertNotIn("\x1b", (run_dir / "boot.log").read_text())
        self.assertNotIn("\x1b", out)

    def test_nothing_received_stops_at_the_time_limit(self):
        code, run_dir, out, m, *_ = self.run_main([], ["--seconds", "5"])
        self.assertEqual(code, 2)  # no text
        self.assertEqual(m["verdict"], "nothing")
        self.assertEqual(m["stopped_by"], "time limit (5.0 s)")
        self.assertIn("move RX to the next pin", out)

    def test_quiet_stop_only_counts_once_data_has_come(self):
        # 30 s of silence before the boot (> quiet-stop 20 s) must not end the capture.
        code, run_dir, out, m, *_ = self.run_main([None] * 300 + [BOOT])
        self.assertEqual(m["verdict"], "text")
        self.assertEqual(m["stopped_by"], "no data for 20 s")

    def test_garbage_says_try_another_baud(self):
        code, run_dir, out, m, *_ = self.run_main([bytes(range(128, 256)) * 2])
        self.assertEqual(m["verdict"], "garbage")
        self.assertIn("--baud 57600", out)

    def test_stuck_line(self):
        code, run_dir, out, m, *_ = self.run_main([b"\x00" * 200])
        self.assertEqual(m["verdict"], "stuck")

    def test_text_without_banner_says_power_cycle(self):
        code, run_dir, out, m, *_ = self.run_main([b"kernel: some later message\n" * 5])
        self.assertIn("No U-Boot banner", (run_dir / "summary.txt").read_text())

    def test_ctrl_c_keeps_everything(self):
        code, run_dir, out, m, port, _ = self.run_main([BOOT[:100], KeyboardInterrupt()])
        self.assertEqual(code, 0)
        self.assertEqual(m["stopped_by"], "Ctrl+C")
        self.assertEqual((run_dir / "boot.raw").read_bytes(), BOOT[:100])
        self.assertTrue(port.closed)

    def test_read_error_keeps_the_data_and_exits_1(self):
        code, run_dir, out, m, port, _ = self.run_main([BOOT, OSError("device gone")])
        self.assertEqual(code, 1)
        self.assertEqual(m["stopped_by"], "read error")
        self.assertIn("device gone", m["error"])
        self.assertEqual(m["verdict"], "text")
        self.assertTrue(port.closed)

    def test_non_ascii_echo_does_not_stop_the_capture(self):
        code, run_dir, out, m, *_ = self.run_main([b"\xff\xfe ok line\n" + BOOT])
        self.assertEqual(m["bytes"], len(BOOT) + 11)

    def test_no_echo(self):
        code, run_dir, out, m, *_ = self.run_main([BOOT], ["--no-echo"])
        self.assertNotIn("Linux version 3.14.77 (dni@build)\n", out.split("Verdict")[0])

    def test_port_and_baud_options(self):
        code, run_dir, out, m, port, opened = self.run_main([BOOT], ["--port", "COM3",
                                                                     "--baud", "57600"])
        self.assertEqual(opened, [("COM3", 57600)])
        self.assertEqual(m["baud"], 57600)

    def test_port_not_found_writes_nothing(self):
        def finder():
            raise sl.PortNotFound("the CP2102 has no COM port")
        code, run_dir, out, m, *_ = self.run_main([BOOT], finder=finder)
        self.assertEqual(code, 1)
        self.assertIsNone(run_dir)
        self.assertIn("no COM port", out)

    def test_bad_numbers_are_refused(self):
        with self.assertRaises(SystemExit):
            with unittest.mock.patch("sys.stderr", io.StringIO()):
                self.run_main([], ["--seconds", "0"])

    def test_list(self):
        buf = io.StringIO()
        self.assertEqual(sl.main(["--list"], lister=lambda: ["COM1", "COM9"], out=buf), 0)
        self.assertEqual(buf.getvalue(), "COM1\nCOM9\n")


class MoreMainTests(Base):
    def test_summary_print_survives_a_cp1252_stdout(self):
        out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        chunk = b"\xff\x00U-Boot 2012.07 test\r\n" + b"x" * 100 + b"\r\n"
        code, run_dir, _, m, *_ = self.run_main([chunk], out=out)
        self.assertEqual(code, 0)
        out.flush()
        printed = out.buffer.getvalue().decode("cp1252")
        self.assertIn("Verdict: text", printed)
        self.assertIn("�", (run_dir / "summary.txt").read_text(encoding="utf-8"))

    def test_echo_to_a_strict_ascii_stdout_keeps_capturing(self):
        out = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
        code, run_dir, _, m, *_ = self.run_main([b"caf\xc3\xa9 \xff line\n" + BOOT], out=out)
        self.assertEqual(code, 0)
        self.assertEqual(m["bytes"], len(BOOT) + 13)
        self.assertNotIn("echo_error", m)

    def test_lines_are_echoed_by_default(self):
        code, run_dir, out, m, *_ = self.run_main([BOOT])
        self.assertIn("Linux version 3.14.77 (dni@build)\n", out.split("Verdict")[0])

    def test_failing_echo_is_switched_off_not_fatal(self):
        class Broken(io.StringIO):  # fails once, on the first echoed Linux line
            failed = False

            def write(self, s):
                if "Linux" in s and not self.failed:
                    self.failed = True
                    raise BrokenPipeError("pipe closed")
                return super().write(s)
        code, run_dir, out, m, *_ = self.run_main([BOOT], out=Broken())
        self.assertEqual(m["bytes"], len(BOOT))
        self.assertIn("BrokenPipeError", m["echo_error"])
        self.assertIn("Please press Enter", (run_dir / "boot.log").read_text())

    def test_too_few_bytes_is_not_judged(self):
        code, run_dir, out, m, *_ = self.run_main([b"\x8f\x02"], ["--seconds", "3"])
        self.assertEqual(code, 2)
        self.assertEqual(m["verdict"], "too few bytes")

    def test_a_glitch_does_not_start_the_quiet_timer(self):
        # 2 glitch bytes, then 30 s of nothing, then the boot: the boot must still be caught.
        code, run_dir, out, m, *_ = self.run_main([b"\x8f\x02"] + [None] * 300 + [BOOT])
        self.assertEqual(m["verdict"], "text")
        self.assertEqual(m["bytes"], len(BOOT) + 2)

    def test_save_error_is_not_blamed_on_the_cable_and_files_still_finish(self):
        real_feed = sl.Capture.feed

        def feed(self, chunk, t):
            if self.total:
                raise OSError(28, "No space left on device")
            return real_feed(self, chunk, t)
        with unittest.mock.patch.object(sl.Capture, "feed", feed):
            code, run_dir, out, m, *_ = self.run_main([BOOT, b"more\n"])
        self.assertEqual(code, 1)
        self.assertEqual(m["stopped_by"], "save error")
        self.assertIn("No space left", m["error"])
        self.assertNotIn("cable", m["error"])
        self.assertTrue((run_dir / "summary.txt").exists())

    def test_failing_finish_still_writes_the_summary_and_manifest(self):
        with unittest.mock.patch.object(sl.Capture, "finish", side_effect=OSError("disk gone")):
            code, run_dir, out, m, *_ = self.run_main([BOOT])
        self.assertEqual(code, 1)
        self.assertIn("finishing boot.log", m["error"])
        self.assertTrue((run_dir / "summary.txt").exists())

    def test_unexpected_exception_is_recorded_then_raised(self):
        clock = FakeClock()
        port = FakePort(clock, [BOOT[:50], ValueError("bug")])
        out_root = self.tmpdir()
        with self.assertRaises(ValueError):
            sl.main([], out_root=out_root, opener=lambda n, b: port, finder=lambda: "COM9",
                    clock=clock, out=io.StringIO())
        m = json.loads((next(out_root.iterdir()) / "manifest.json").read_text())
        self.assertEqual(m["stopped_by"], "crashed")
        self.assertIn("ValueError: bug", m["error"])
        self.assertTrue(port.closed)

    def test_ctrl_c_signal_keeps_the_chunk_read_with_it(self):
        # The signal comes in while read() is running; that chunk must still reach boot.raw.
        clock = FakeClock()
        port = FakePort(clock, [])

        def read(n):
            clock.t += 0.1
            signal.raise_signal(signal.SIGINT)
            return BOOT
        port.read = read
        code, run_dir, out, m, *_ = self.run_main([], port=port)
        self.assertEqual(m["stopped_by"], "Ctrl+C")
        self.assertEqual((run_dir / "boot.raw").read_bytes(), BOOT)
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)

    def test_opener_oserror_is_reported_and_makes_no_folder(self):
        def opener(name, baud):
            raise OSError("could not open COM9 (Windows error 31: A device attached ...)")
        out_root = self.tmpdir() / "serial"
        buf = io.StringIO()
        code = sl.main([], out_root=out_root, opener=opener, finder=lambda: "COM9", out=buf)
        self.assertEqual(code, 1)
        self.assertIn("Can't open the serial port", buf.getvalue())
        self.assertFalse(out_root.exists())

    def test_bad_numbers_are_refused(self):
        for argv in (["--quiet-stop", "0"], ["--baud", "0"], ["--baud", "-1"],
                     ["--seconds", "nan"], ["--quiet-stop", "inf"]):
            with self.assertRaises(SystemExit):
                with unittest.mock.patch("sys.stderr", io.StringIO()):
                    sl.main(argv, out=io.StringIO())


    def test_handler_is_restored_even_when_the_old_one_was_none(self):
        calls = []
        real = signal.signal

        def fake_signal(sig, handler):
            calls.append(handler)
            real(sig, handler)
            return None if len(calls) == 1 else signal.default_int_handler
        with unittest.mock.patch.object(sl.signal, "signal", fake_signal):
            self.run_main([BOOT])
        real(signal.SIGINT, signal.default_int_handler)
        self.assertEqual(calls[-1], signal.SIG_DFL)

    def test_closed_stdout_keeps_the_verdict_exit_code(self):
        class Closed(io.StringIO):
            def write(self, s):
                raise BrokenPipeError("closed")
        code, run_dir, out, m, *_ = self.run_main([BOOT], out=Closed())
        self.assertEqual(code, 0)
        self.assertEqual(m["verdict"], "text")

    def test_boot_raw_that_cant_be_made_is_a_clear_error(self):
        out_root = self.tmpdir()
        clock = FakeClock()
        port = FakePort(clock, [BOOT])
        buf = io.StringIO()
        real_open = open

        def bad_open(path, *a, **kw):
            if str(path).endswith("boot.raw"):
                raise PermissionError(13, "Permission denied")
            return real_open(path, *a, **kw)
        with unittest.mock.patch("builtins.open", bad_open):
            code = sl.main([], out_root=out_root, opener=lambda n, b: port,
                           finder=lambda: "COM9", clock=clock, out=buf)
        self.assertEqual(code, 1)
        self.assertIn("Can't save the capture", buf.getvalue())
        self.assertTrue(port.closed)


    def test_error_closing_the_files_keeps_the_verdict(self):
        real_open = open

        class BadClose:
            def __init__(self, f):
                self.f = f

            def __getattr__(self, name):
                return getattr(self.f, name)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self.f.close()
                raise OSError(5, "I/O error on close")

        def wrapped_open(path, *a, **kw):
            f = real_open(path, *a, **kw)
            return BadClose(f) if str(path).endswith("boot.log") else f
        with unittest.mock.patch("builtins.open", wrapped_open):
            code, run_dir, out, m, *_ = self.run_main([BOOT])
        self.assertEqual(code, 1)
        self.assertIn("closing boot.raw/boot.log", m["error"])
        self.assertIn("Verdict: text", out)
        self.assertIn("closing boot.raw/boot.log", (run_dir / "summary.txt").read_text())


class MoreCaptureTests(Base):
    capture = CaptureTests.capture

    def test_hash_check_is_not_a_signature_check_and_every_signature_line_is_kept(self):
        cap, _, _ = self.capture([b"## Loading kernel from FIT Image at 84000000 ...\r\n",
                                  b"   Verifying Hash Integrity ... sha1+ OK\r\n",
                                  b"   Verifying Hash Integrity ... sha1,rsa2048:dev+ OK\r\n",
                                  b"Image authentication failed\r\n",
                                  b"ubi0: attaching mtd1\r\n"])
        self.assertIn("sha1+ OK", cap.landmarks["image hash check"]["text"])
        sig = [h["text"] for h in cap.landmarks["signature or secure boot"]["all"]]
        self.assertEqual(len(sig), 2)
        self.assertIn("rsa2048", sig[0])
        self.assertEqual(sig[1], "Image authentication failed")
        self.assertEqual(cap.landmarks["root filesystem"]["line"], 5)

    def test_ordinary_words_are_not_signature_lines(self):
        cap, _, _ = self.capture([b"pci 0000:01:00.0: BAR 0: assigned [mem 0x40000000]\r\n",
                                  b"unsigned image\r\n", b"Verifying Checksum ... OK\r\n",
                                  b"designed by\r\n", b"nand verify done\r\n"])
        self.assertNotIn("signature or secure boot", cap.landmarks)

    def test_summary_lists_every_signature_line_and_says_when_none_was_seen(self):
        raw, log = io.BytesIO(), io.StringIO()
        cap = sl.Capture(raw, log)
        cap.feed(b"U-Boot 2012.07\r\nsecure boot enabled\r\nImage authentication failed\r\n", 1.0)
        info = {"port": "COM4", "baud": 115200, "stopped_by": "Ctrl+C"}
        text = sl.summary_text(cap, info)
        self.assertIn("signature or secure boot (2 lines):", text)
        self.assertIn("Image authentication failed", text)
        cap2 = sl.Capture(io.BytesIO(), io.StringIO())
        cap2.feed(b"U-Boot 2012.07\r\nStarting kernel ...\r\n", 1.0)
        self.assertIn("No signature or secure-boot line was seen", sl.summary_text(cap2, info))

    def test_multi_landmark_counts_every_line_but_keeps_twenty(self):
        info = {"port": "COM4", "baud": 115200, "stopped_by": "Ctrl+C"}
        for n, note in ((20, False), (25, True)):
            cap, _, _ = self.capture([b"secure boot check %d\r\n" % i for i in range(n)])
            m = cap.landmarks["signature or secure boot"]
            self.assertEqual((m["count"], len(m["all"])), (n, 20))
            text = sl.summary_text(cap, info)
            self.assertIn(f"signature or secure boot ({n} lines", text)
            self.assertEqual("first 20 shown" in text, note, text)
            json.dumps(cap.landmarks)  # the first hit is a copy, so no circular reference

    def test_long_line_is_cut_around_the_match(self):
        cap, _, _ = self.capture([b"Kernel command line: " + b"x=1 " * 60 + b"rootfs=ubi0\r\n"])
        self.assertIn("rootfs=ubi0", cap.landmarks["root filesystem"]["text"])

    def test_crlf_split_across_reads_is_one_line_end(self):
        cap, _, log = self.capture([b"abc\r", b"\ndef\n"])
        self.assertEqual(cap.lines, 2)

    def test_trailing_half_char_gets_the_last_time(self):
        cap, _, log = self.capture([b"ok\n", b"\xc3"])
        self.assertEqual(log.splitlines()[-1], "[    1.000] �")


class NoMore(OSError):
    winerror = sl.ERROR_NO_MORE_ITEMS


class Node(dict):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeWinreg:
    """Just enough of winreg: keys are Nodes of subkeys, with values under "values"."""
    HKEY_LOCAL_MACHINE = "HKLM"

    def __init__(self, tree, deny=()):
        self.tree, self.deny = self.wrap(tree), set(deny)

    def wrap(self, d):
        return Node({k: self.wrap(v) if isinstance(v, dict) and k != "values" else v
                     for k, v in d.items()})

    def OpenKey(self, parent, path):
        node = self.tree if parent == "HKLM" else parent
        if path in self.deny:
            raise PermissionError(13, "Access is denied")
        for part in path.split("\\"):
            if part not in node:
                raise FileNotFoundError(path)
            node = node[part]
        return node

    def EnumKey(self, key, i):
        subs = [k for k in key if k != "values"]
        if i >= len(subs):
            raise NoMore("no more")
        return subs[i]

    def EnumValue(self, key, i):
        vals = list(key.get("values", {}).items())
        if i >= len(vals):
            raise NoMore("no more")
        return (vals[i][0], vals[i][1], 1)

    def QueryValueEx(self, key, name):
        if name not in key.get("values", {}):
            raise FileNotFoundError(name)
        return (key["values"][name], 1)


def winreg_tree(instances, live, deny=()):
    usb = {f"VID_{sl.CP210X_VID}&PID_{sl.CP210X_PID}": instances}
    return FakeWinreg({"SYSTEM": {"CurrentControlSet": {"Enum": {"USB": usb}}},
                       "HARDWARE": {"DEVICEMAP": {"SERIALCOMM": {"values": live}}}}, deny)


class FindPortTests(unittest.TestCase):
    def inst(self, port):
        return {"Device Parameters": {"values": {"PortName": port}}}

    def test_found(self):
        reg = winreg_tree({"0001": self.inst("COM5")}, {"\\Device\\Silabser0": "COM5"})
        self.assertEqual(sl.find_cp210x_windows(reg), "COM5")

    def test_live_one_among_stale_entries(self):
        reg = winreg_tree({"a": self.inst("COM5"), "b": self.inst("COM6")},
                          {"\\Device\\Silabser0": "COM6", "\\Device\\Serial0": "COM1"})
        self.assertEqual(sl.find_cp210x_windows(reg), "COM6")

    def test_stale_name_now_used_by_another_device_is_not_picked(self):
        reg = winreg_tree({"a": self.inst("COM5")}, {"\\Device\\Serial2": "COM5"})
        with self.assertRaisesRegex(sl.PortNotFound, "isn't plugged in now"):
            sl.find_cp210x_windows(reg)

    def test_driver_missing(self):
        reg = winreg_tree({"0001": {}}, {})
        with self.assertRaisesRegex(sl.PortNotFound, "driver is probably missing"):
            sl.find_cp210x_windows(reg)

    def test_unplugged_says_plug_it_in_not_install_a_driver(self):
        reg = winreg_tree({"0001": self.inst("COM5")}, {"\\Device\\Serial0": "COM1"})
        with self.assertRaises(sl.PortNotFound) as cm:
            sl.find_cp210x_windows(reg)
        self.assertIn("isn't plugged in now (it was COM5 before)", str(cm.exception))
        self.assertNotIn("driver", str(cm.exception))

    def test_never_plugged_in(self):
        reg = FakeWinreg({"SYSTEM": {"CurrentControlSet": {"Enum": {"USB": {}}}}})
        with self.assertRaisesRegex(sl.PortNotFound, "ever been plugged"):
            sl.find_cp210x_windows(reg)

    def test_two_cables(self):
        reg = winreg_tree({"a": self.inst("COM5"), "b": self.inst("COM6")},
                          {"\\Device\\Silabser0": "COM5", "\\Device\\Silabser1": "COM6"})
        with self.assertRaisesRegex(sl.PortNotFound, r"more than one CP210x is connected \(COM5, COM6\)"):
            sl.find_cp210x_windows(reg)

    def test_access_denied_is_not_hidden(self):
        reg = winreg_tree({}, {}, deny={r"HARDWARE\DEVICEMAP\SERIALCOMM"})
        with self.assertRaises(PermissionError):
            sl.list_ports_windows(reg)

    def test_list_ports_sorts_by_number(self):
        reg = winreg_tree({}, {"x": "COM10", "y": "COM2", "z": "COM1"})
        self.assertEqual(sl.list_ports_windows(reg), ["COM1", "COM2", "COM10"])

    def test_no_serialcomm_key_means_no_ports(self):
        reg = FakeWinreg({"HARDWARE": {"DEVICEMAP": {}}})
        self.assertEqual(sl.list_ports_windows(reg), [])

    def test_linux_sysfs_two_levels_up(self):
        # Real sysfs: ttyUSB0/device links to the port folder; the IDs are two folders up
        # (port -> interface -> USB device). realpath is patched to follow the "link".
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        usb = root / "devices" / "1-1"
        port = usb / "1-1.0" / "ttyUSB0"
        port.mkdir(parents=True)
        (usb / "idVendor").write_text("10c4\n")
        (usb / "idProduct").write_text("ea60\n")
        cls = root / "class" / "ttyUSB0"
        cls.mkdir(parents=True)
        with unittest.mock.patch.object(sl.os.path, "realpath", lambda p: str(port)):
            self.assertEqual(sl.find_cp210x_linux(str(root / "class")), "/dev/ttyUSB0")

    def linux_tree(self, devices):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        ports = {}
        for name, (vid, pid) in devices.items():
            usb = root / "devices" / name
            port = usb / "iface" / name
            port.mkdir(parents=True)
            (usb / "idVendor").write_text(vid + "\n")
            (usb / "idProduct").write_text(pid + "\n")
            (root / "class" / name).mkdir(parents=True)
            ports[os.path.join(str(root / "class"), name, "device")] = str(port)
        return str(root / "class"), ports

    def test_linux_skips_other_vendors(self):
        cls, ports = self.linux_tree({"ttyUSB0": ("0403", "6001"), "ttyUSB1": ("10c4", "ea60")})
        with unittest.mock.patch.object(sl.os.path, "realpath", lambda p: ports[p]):
            self.assertEqual(sl.find_cp210x_linux(cls), "/dev/ttyUSB1")

    def test_linux_two_cables(self):
        cls, ports = self.linux_tree({"ttyUSB0": ("10c4", "ea60"), "ttyUSB1": ("10c4", "ea60")})
        with unittest.mock.patch.object(sl.os.path, "realpath", lambda p: ports[p]):
            with self.assertRaisesRegex(sl.PortNotFound, "more than one"):
                sl.find_cp210x_linux(cls)

    def test_linux_none(self):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        with self.assertRaises(sl.PortNotFound):
            sl.find_cp210x_linux(str(root))


class PosixPortTests(unittest.TestCase):
    def port(self, ready=True, data=b""):
        p = sl.PosixPort.__new__(sl.PosixPort)
        p._fd = 99
        p._select = lambda r, w, x, t: (r if ready else [], [], [])
        return p

    def test_hangup_is_an_error_not_silence(self):
        p = self.port()
        with unittest.mock.patch.object(sl.os, "read", return_value=b""):
            with self.assertRaisesRegex(OSError, "cable unplugged"):
                p.read(10)

    def test_eagain_is_just_no_data(self):
        p = self.port()
        with unittest.mock.patch.object(sl.os, "read", side_effect=BlockingIOError()):
            self.assertEqual(p.read(10), b"")

    def test_not_ready_is_no_data(self):
        self.assertEqual(self.port(ready=False).read(10), b"")

    def test_read_after_close(self):
        p = self.port()
        p._fd = None
        with self.assertRaises(OSError):
            p.read(1)

    def test_raw_8n1_turns_off_echo_and_flow_control(self):
        names = ("IGNBRK BRKINT PARMRK ISTRIP INLCR IGNCR ICRNL IXON IXOFF IXANY OPOST CSIZE "
                 "PARENB CSTOPB CRTSCTS CS8 CLOCAL CREAD ECHO ECHONL ICANON ISIG IEXTEN").split()
        t = types.SimpleNamespace(**{n: 1 << i for i, n in enumerate(names)}, VMIN=0, VTIME=1)
        t.CS8 = t.CSIZE  # as on Linux, CS8 is all of CSIZE
        allbits = (1 << len(names)) - 1
        a = sl.raw_8n1([allbits, allbits, allbits, allbits, 0, 0, [5, 5]], t, "B115200")
        for flag in ("IXON", "IXOFF", "IXANY", "ICRNL"):
            self.assertFalse(a[0] & getattr(t, flag), flag)
        self.assertFalse(a[1] & t.OPOST)
        self.assertFalse(a[2] & (t.PARENB | t.CSTOPB | t.CRTSCTS))
        self.assertTrue(a[2] & t.CLOCAL and a[2] & t.CREAD)
        self.assertEqual(a[2] & t.CSIZE, t.CS8)
        for flag in ("ECHO", "ECHONL", "ICANON", "ISIG", "IEXTEN"):
            self.assertFalse(a[3] & getattr(t, flag), flag)
        self.assertEqual((a[4], a[5], a[6]), ("B115200", "B115200", [0, 0]))


@unittest.skipUnless(os.name == "nt", "Windows only")
class WindowsPortTests(unittest.TestCase):
    """WindowsPort against a fake kernel32 that records calls."""

    def fake(self, create_errors=(), set_ok=(True, True)):
        import ctypes
        calls = {"create": [], "closed": [], "dcb": []}
        create_errors, set_ok = list(create_errors), list(set_ok)

        class Fn:
            def __init__(self, f):
                self.f = f

            def __call__(self, *a):
                return self.f(*a)

        def create(path, access, *rest):
            calls["create"].append(access)
            if create_errors:
                err = create_errors.pop(0)
                if err:
                    ctypes.set_last_error(err)
                    return ctypes.c_void_p(-1).value
            return 1000 + len(calls["create"])

        def set_state(h, ref):
            dcb = ref._obj
            calls["dcb"].append((dcb.BaudRate, dcb.fBits, dcb.ByteSize, dcb.XonChar, dcb.XoffChar))
            ok = set_ok.pop(0) if set_ok else True
            if not ok:
                ctypes.set_last_error(87)
            return ok

        k = types.SimpleNamespace(
            CreateFileW=Fn(create), ReadFile=Fn(lambda *a: 0), GetCommState=Fn(lambda h, r: 1),
            SetCommState=Fn(set_state), SetCommTimeouts=Fn(lambda h, r: 1),
            CloseHandle=Fn(lambda h: calls["closed"].append(h)))
        patch = unittest.mock.patch.object(ctypes, "WinDLL", lambda *a, **kw: k)
        patch.start()
        self.addCleanup(patch.stop)
        return calls

    def test_opens_read_only_first_with_no_flow_control(self):
        calls = self.fake()
        p = sl.WindowsPort("COM5", 115200)
        self.assertEqual(calls["create"], [0x80000000])
        self.assertEqual(p.access, "read-only")
        self.assertEqual(calls["dcb"], [(115200, 1, 8, b"\x11", b"\x13")])

    def test_falls_back_to_read_write_when_settings_are_refused(self):
        calls = self.fake(set_ok=(False, True))
        p = sl.WindowsPort("COM5", 115200)
        self.assertEqual(calls["create"], [0x80000000, 0xC0000000])
        self.assertEqual(calls["closed"], [1001])
        self.assertEqual(p.access, "read/write handle, never written")

    def test_access_denied_on_read_only_tries_read_write_then_says_in_use(self):
        calls = self.fake(create_errors=(5, 5))
        with self.assertRaisesRegex(sl.PortNotFound, "in use"):
            sl.WindowsPort("COM5", 115200)
        self.assertEqual(len(calls["create"]), 2)

    def test_not_found(self):
        self.fake(create_errors=(2,))
        with self.assertRaisesRegex(sl.PortNotFound, "doesn't exist"):
            sl.WindowsPort("COM5", 115200)

    def test_both_settings_fail_closes_both_handles(self):
        calls = self.fake(set_ok=(False, False))
        with self.assertRaisesRegex(OSError, "could not set 115200 baud 8N1 on COM5"):
            sl.WindowsPort("COM5", 115200)
        self.assertEqual(calls["closed"], [1001, 1002])

    def test_read_failure_is_an_oserror(self):
        self.fake()
        p = sl.WindowsPort("COM5", 115200)
        with self.assertRaisesRegex(OSError, "ReadFile failed"):
            p.read(10)
        p.close()
        with self.assertRaisesRegex(OSError, "closed"):
            p.read(10)


class NeverWritesTests(unittest.TestCase):
    def test_port_classes_have_no_write(self):
        for cls in (sl.WindowsPort, sl.PosixPort):
            self.assertFalse(any(n.startswith("write") for n in dir(cls)), cls)

    def test_source_never_calls_a_write_api(self):
        src = (pathlib.Path(sl.__file__)).read_text(encoding="utf-8")
        for bad in ("WriteFile", "os.write", "TransmitCommChar", "EscapeCommFunction",
                    "SetCommBreak"):
            self.assertNotIn(bad, src)

    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_missing_com_port_is_a_clear_error(self):
        with self.assertRaisesRegex(sl.PortNotFound, "doesn't exist"):
            sl.WindowsPort("COM250", 115200)


if __name__ == "__main__":
    unittest.main()
