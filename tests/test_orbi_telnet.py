"""Tests for tools/orbi_telnet.py with a fake socket and a fake clock. No router needed.

Run:  python -I -m unittest discover -s tests   (from the orbi-openwrt folder)
A fake clock (ot.time) means no real waiting, so the suite is fast and can model the
multi-second delay BusyBox login uses before it says "Login incorrect".
"""
import io
import json
import pathlib
import re
import shutil
import socket
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import orbi_telnet as ot  # noqa: E402

IAC, DO, WILL, WONT, DONT, SB, SE = 255, 253, 251, 252, 254, 250, 240
PASSWORD = "s3cret-pass"  # nosec B105 - fake value for the mock router, not a real credential


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += s


class FakeSock:
    """recv() hands out queued items. A bytes item is returned as data. A ("delay", secs)
    item advances the clock by secs and returns b"" (a timeout). An empty queue advances the
    clock by the last settimeout and returns b"" (so reads eventually hit their deadline).
    A queued b"" means the connection closed. A queued Exception is raised."""

    def __init__(self, chunks=(), clock=None):
        self.chunks = list(chunks)
        self.clock = clock or FakeClock()
        self.sent = []
        self.closed = False
        self._timeout = 1.0

    def settimeout(self, t):
        self._timeout = t

    def recv(self, n):
        if not self.chunks:
            self.clock.sleep(self._timeout)
            raise socket.timeout()
        item = self.chunks.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, tuple) and item[0] == "delay":
            self.clock.sleep(item[1])
            raise socket.timeout()
        if item == b"":
            return b""  # a real socket returns empty bytes on close; _recv_raw turns it into ConnectionError
        return item

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class FakeRouter(FakeSock):
    """A scripted BusyBox-like router driven by wait_for_prompt (last-line based)."""

    def __init__(self, clock, outputs=None, rcs=None, wrap_echo=False, hang_after=None,
                 needs_login=True, fail_delay=0.0, echo_password=False, netgear_prompts=False):
        # netgear_prompts=True models this RBR10's "telnet account:"/"telnet password:" login
        # instead of the generic BusyBox "RBR10 login:"/"Password:".
        self.netgear_prompts = netgear_prompts
        first = b"\r\ntelnet account:" if netgear_prompts else b"\r\nRBR10 login: "
        super().__init__([first if needs_login else b"\r\nroot@RBR10:/# "], clock)
        self.outputs = outputs or {}
        self.rcs = rcs or {}
        self.wrap_echo = wrap_echo
        self.hang_after = hang_after
        self.fail_delay = fail_delay
        self.echo_password = echo_password
        self.state = "user" if needs_login else "shell"
        self.commands_run = 0
        self.lines = []

    def sendall(self, data):
        FakeSock.sendall(self, data)
        if data.startswith(bytes([IAC])):
            return
        line = data.decode().rstrip("\r\n")
        self.lines.append(line)
        if self.state == "user":
            pw_prompt = b"\r\ntelnet password:" if self.netgear_prompts else b"\r\nPassword: "
            self.chunks.append(line.encode() + pw_prompt)
            self.state = "pass"
        elif self.state == "pass":
            echoed = (self.password.encode() if self.echo_password else b"")
            if line == self.password:
                self.chunks.append(echoed + b"\r\n\r\nBusyBox v1.x (ash)\r\n\r\nroot@RBR10:/# ")
                self.state = "shell"
            else:
                self.chunks.append(echoed + b"\r\n")
                if self.fail_delay:
                    self.chunks.append(("delay", self.fail_delay))
                reprompt = b"telnet account:" if self.netgear_prompts else b"RBR10 login: "
                self.chunks.append(b"Login incorrect\r\n" + reprompt)
                self.state = "user"
        elif self.state == "shell":
            self._shell(line)

    @property
    def password(self):
        return PASSWORD

    def _shell(self, line):
        m = re.match(r"echo __B''(\d+)__; (.*); __rc=\$\?; echo; echo __E''\1__ rc=\$__rc$", line)
        echo = line.encode()
        if self.wrap_echo and len(echo) > 60:
            echo = echo[:60] + b"\r\n" + echo[60:]
        if not m:
            self.chunks.append(echo + b"\r\nroot@RBR10:/# ")
            return
        n, cmd = m.group(1), m.group(2)
        if self.hang_after is not None and self.commands_run >= self.hang_after:
            # start marker + some output, but never the end marker (command hangs)
            self.chunks.append(echo + b"\r\n")
            self.chunks.append(f"__B{n}__\r\nsome partial output".encode())
            return
        self.commands_run += 1
        out = self.outputs.get(cmd, f"output of {cmd}\n")
        if isinstance(out, list):  # one output per call, in order
            out = out.pop(0)
        rc = self.rcs.get(cmd, 0)
        trailing = b"\r\n" if out.endswith("\n") else b""  # model both newline cases
        body = out.rstrip("\n").encode().replace(b"\n", b"\r\n") + trailing
        self.chunks.append(echo + b"\r\n")
        self.chunks.append(f"__B{n}__\r\n".encode() + body + f"\r\n__E{n}__ rc={rc}\r\nroot@RBR10:/# ".encode())


def ident_outputs(model="Netgear RBR10\nqcom,ipq4019\n"):
    return {ot.COMMANDS["dt_model"]: model, ot.COMMANDS["fw_version"]: "/module_name: RBR10\n"}


def clean_outputs():
    # ident, plus a dmesg that starts at boot so no "ring buffer wrapped" warning fires
    return {**ident_outputs(), ot.COMMANDS["dmesg"]: "[    0.000000] Booting Linux on physical CPU 0x0\n"}


class Base(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        fake_time = types.SimpleNamespace(monotonic=self.clock.monotonic, sleep=self.clock.sleep)
        patcher = unittest.mock.patch.object(ot, "time", fake_time)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tmpdir(self):
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def run_main(self, router, password=PASSWORD):  # nosec B107 # nosemgrep: hardcoded-password-default-argument
        tmp = self.tmpdir()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ot.main([], out_root=tmp, connect=lambda host: ot.Telnet(router),
                           ask_user=lambda: "root", ask_password=lambda: password, require_tty=False)
        run_dir = next(tmp.iterdir())
        return code, run_dir, buf.getvalue()


import unittest.mock  # noqa: E402  (after Base so patch.object is available above)


class ParserTests(Base):
    def setUp(self):
        super().setUp()
        self.sock = FakeSock(clock=self.clock)
        self.t = ot.Telnet(self.sock)

    def test_plain_data_passes_through(self):
        self.assertEqual(self.t.feed(b"hello\r\n"), b"hello\r\n")

    def test_do_and_will_refused_once(self):
        out = self.t.feed(bytes([IAC, DO, 1, IAC, WILL, 3, IAC, DO, 1]) + b"x")
        self.assertEqual(out, b"x")
        self.assertEqual(self.sock.sent, [bytes([IAC, WONT, 1]), bytes([IAC, DONT, 3])])

    def test_dont_wont_no_reply(self):
        self.assertEqual(self.t.feed(bytes([IAC, DONT, 1, IAC, WONT, 1])), b"")
        self.assertEqual(self.sock.sent, [])

    def test_iac_split_across_chunks(self):
        out = self.t.feed(b"abc\xff") + self.t.feed(bytes([DO, 1]) + b"xyz")
        self.assertEqual(out, b"abcxyz")
        self.assertEqual(self.sock.sent, [bytes([IAC, WONT, 1])])

    def test_option_byte_in_next_chunk(self):
        out = self.t.feed(bytes([ord("a"), IAC, DO])) + self.t.feed(b"\x01b")
        self.assertEqual(out, b"ab")
        self.assertEqual(self.sock.sent, [bytes([IAC, WONT, 1])])

    def test_sb_split_across_chunks(self):
        out = self.t.feed(bytes([IAC, SB, 24])) + self.t.feed(b"\x01ABC" + bytes([IAC, SE]) + b"z")
        self.assertEqual(out, b"z")

    def test_iac_iac_is_one_ff(self):
        self.assertEqual(self.t.feed(b"a\xff\xffb"), b"a\xffb")

    def test_iac_iac_split(self):
        self.assertEqual(self.t.feed(b"a\xff") + self.t.feed(b"\xffb"), b"a\xffb")

    def test_cr_nul_becomes_cr(self):
        self.assertEqual(self.t.feed(b"a\r\x00b\x00"), b"a\rb\x00")

    def test_nop_and_ga_ignored(self):
        self.assertEqual(self.t.feed(bytes([ord("a"), IAC, 241, IAC, 249, ord("b")])), b"ab")

    def test_send_is_utf8_with_crlf(self):
        self.t.send("caf\u00e9")
        self.assertEqual(self.sock.sent[-1], "caf\u00e9".encode() + b"\r\n")


class ReadTests(Base):
    def test_match_across_chunks_keeps_rest(self):
        t = ot.Telnet(FakeSock([b"Pass", b"word: tail"], self.clock))
        before, _ = t.read_until(rb"word: ", 2, "prompt")
        self.assertEqual(before, b"Pass")
        self.assertEqual(t.buf, b"tail")

    def test_timeout_message_has_no_received_text(self):
        t = ot.Telnet(FakeSock([b"secret stuff"], self.clock))
        with self.assertRaises(TimeoutError) as cm:
            t.read_until(rb"never", 3, "the prompt")
        self.assertNotIn("secret", str(cm.exception))
        self.assertIn("the prompt", str(cm.exception))

    def test_closed_connection_raises(self):
        t = ot.Telnet(FakeSock([b""], self.clock))
        with self.assertRaises(ConnectionError):
            t.read_until(rb"x", 2, "x")

    def test_wait_for_prompt_kinds(self):
        for text, kind in [(b"root@x:/# ", "shell"), (b"x login: ", "login"), (b"Password: ", "password"),
                           (b"telnet account:", "login"), (b"telnet password:", "password")]:
            t = ot.Telnet(FakeSock([text], self.clock))
            self.assertEqual(t.wait_for_prompt(5), kind)

    def test_wait_for_prompt_times_out(self):
        t = ot.Telnet(FakeSock([b"banner with no prompt\r\n"], self.clock))
        with self.assertRaises(TimeoutError):
            t.wait_for_prompt(5)

    def test_shell_regex_rejects_banner_border(self):
        # a row of '#' (a banner border) must NOT be read as a shell prompt
        t = ot.Telnet(FakeSock([b"##################\r\n"], self.clock))
        with self.assertRaises(TimeoutError):
            t.wait_for_prompt(3)

    def test_last_line_wins_over_earlier_account_line(self):
        # an "account:" line earlier in the buffer is ignored; the real shell prompt is last
        t = ot.Telnet(FakeSock([b"Create your account:\r\nroot@RBR10:/# "], self.clock))
        self.assertEqual(t.wait_for_prompt(5), "shell")


class RunCommandTests(Base):
    def _shell(self, **kw):
        r = FakeRouter(self.clock, needs_login=False, **kw)
        t = ot.Telnet(r)
        t.wait_for_prompt(5)
        return r, t

    def test_echo_not_saved_output_right(self):
        r, t = self._shell(outputs={"cat /proc/version": "Linux version 3.14\n"})
        self.assertEqual(ot.run_command(t, 1, "cat /proc/version"), ("Linux version 3.14\n", 0))

    def test_output_without_trailing_newline(self):
        r, t = self._shell(outputs={"cat x": "no newline here"})
        self.assertEqual(ot.run_command(t, 1, "cat x"), ("no newline here\n", 0))

    def test_wrapped_echo_not_saved(self):
        cmd = ot.COMMANDS["tools"]
        r, t = self._shell(wrap_echo=True, outputs={cmd: "nc: missing\n"})
        self.assertEqual(ot.run_command(t, 1, cmd), ("nc: missing\n", 0))

    def test_exit_code_returned(self):
        r, t = self._shell(rcs={"brctl show": 127}, outputs={"brctl show": "sh: brctl: not found\n"})
        self.assertEqual(ot.run_command(t, 1, "brctl show"), ("sh: brctl: not found\n", 127))

    def test_leading_whitespace_kept(self):
        r, t = self._shell(outputs={"cat x": "major minor\n\n   31  0 mtd0\n"})
        body, _ = ot.run_command(t, 1, "cat x")
        self.assertTrue(body.startswith("major minor\n\n   31"))


class LoginTests(Base):
    def test_good_login(self):
        r = FakeRouter(self.clock)
        ot.login(ot.Telnet(r), lambda: "root", lambda: PASSWORD)
        self.assertEqual(r.state, "shell")

    def test_wrong_password_with_busybox_delay(self):
        r = FakeRouter(self.clock, fail_delay=3.0)
        with self.assertRaises(ot.LoginFailed):
            ot.login(ot.Telnet(r), lambda: "root", lambda: "wrong")
        self.assertEqual(len(r.lines), 2)  # nothing typed after the failed login

    def test_password_not_in_prompt_timeout_error(self):
        # the router echoes the password then never shows a prompt: the error must not leak it
        t = ot.Telnet(FakeSock([PASSWORD.encode() + b"\r\nnoise\r\n"], self.clock))
        with self.assertRaises(TimeoutError) as cm:
            t.wait_for_prompt(3)
        self.assertNotIn(PASSWORD, str(cm.exception))

    def test_shell_without_login(self):
        r = FakeRouter(self.clock, needs_login=False)
        ot.login(ot.Telnet(r), lambda: self.fail("asked user"), lambda: self.fail("asked pw"))

    def test_slow_greeting_not_cut_short(self):
        # banner, then a 3s gap, then the login prompt: must still be seen
        r = ot.Telnet(FakeSock([b"\r\nissue banner\r\n", ("delay", 3.0), b"RBR10 login: "], self.clock))
        self.assertEqual(r.wait_for_prompt(20), "login")

    def test_netgear_account_prompt_login(self):
        # This RBR10's telnetd uses "telnet account:" / "telnet password:" (not login:/Password:)
        # and sends the banner only after telnet option negotiation. The leading bytes are the
        # router's real on-connect options: IAC DO ECHO, IAC DO FLOW(0x21), IAC WILL ECHO,
        # IAC WILL SGA(0x03); feed() refuses each before the banner is read.
        account = (b"\xff\xfd\x01\xff\xfd\x21\xff\xfb\x01\xff\xfb\x03"
                   b" === LOGIN ===\r\n  It's the same with DUT GUI\r\ntelnet account:")
        passwd = b"\r\n\r\ntelnet password:\r\n"
        shell = b"\r\n\r\nBusyBox v1.x (ash)\r\nroot@RBR10:/# "
        r = FakeSock([account, passwd, shell], self.clock)
        ot.login(ot.Telnet(r), lambda: "admin", lambda: PASSWORD)
        typed = [d.decode().rstrip("\r\n") for d in r.sent if not d.startswith(bytes([IAC]))]
        self.assertEqual(typed, ["admin", PASSWORD])  # username first, then password, then shell reached

    def test_netgear_wrong_password_reprompt(self):
        # Wrong password at the Netgear prompts: the "Login incorrect\r\ntelnet account:" re-prompt
        # must be classified as login and raise LoginFailed, not hang or mis-dispatch.
        account = b"\xff\xfd\x01 === LOGIN ===\r\ntelnet account:"
        passwd = b"\r\ntelnet password:\r\n"
        fail = b"\r\nLogin incorrect\r\ntelnet account:"
        r = FakeSock([account, passwd, fail], self.clock)
        with self.assertRaises(ot.LoginFailed):
            ot.login(ot.Telnet(r), lambda: "admin", lambda: "wrong")  # nosec B106

    def test_netgear_runtime_error_without_password_prompt(self):
        # account prompt, then another account prompt instead of a password prompt
        r = FakeSock([b"telnet account:", b"telnet account:"], self.clock)
        with self.assertRaises(RuntimeError):
            ot.login(ot.Telnet(r), lambda: "admin", lambda: self.fail("asked pw"))

    def test_connection_closed_after_password(self):
        # router drops the socket right after the password instead of giving a shell
        r = FakeSock([b"telnet account:", b"telnet password:", b""], self.clock)
        with self.assertRaises(ConnectionError):
            ot.login(ot.Telnet(r), lambda: "admin", lambda: PASSWORD)

    def test_account_prompt_split_across_recv(self):
        r = ot.Telnet(FakeSock([b"telnet acc", b"ount:"], self.clock))
        self.assertEqual(r.wait_for_prompt(5), "login")


class MainTests(Base):
    def test_full_run_writes_every_file(self):
        code, run_dir, out = self.run_main(FakeRouter(self.clock, outputs=clean_outputs()))
        self.assertEqual(code, 0)
        for name in ot.COMMANDS:
            self.assertTrue((run_dir / f"{name}.txt").exists(), name)
        self.assertEqual((run_dir / "version.txt").read_text(), "output of cat /proc/version\n")
        manifest = json.loads((run_dir / "manifest.json").read_text())
        self.assertTrue(manifest["complete"])
        self.assertEqual(manifest["warnings"], [])
        self.assertEqual(manifest["commands"]["mtd"]["rc"], 0)
        self.assertNotIn("output", manifest["commands"]["mtd"])  # slimmed out of manifest
        self.assertNotIn(b"\r\n", (run_dir / "recon.txt").read_bytes())

    def test_admin_is_default_username(self):
        # pressing Enter at the username prompt (input -> "") must send "admin"
        r = FakeRouter(self.clock, outputs=clean_outputs())
        tmp = self.tmpdir()
        with unittest.mock.patch("builtins.input", return_value=""):
            with redirect_stdout(io.StringIO()):
                ot.main([], out_root=tmp, connect=lambda h: ot.Telnet(r),
                        ask_user=None, ask_password=lambda: PASSWORD, require_tty=False)
        self.assertEqual(r.lines[0], "admin")

    def test_full_run_through_netgear_prompts(self):
        code, run_dir, out = self.run_main(
            FakeRouter(self.clock, outputs=clean_outputs(), netgear_prompts=True))
        self.assertEqual(code, 0)
        self.assertTrue((run_dir / "mtd.txt").exists())

    def test_setup_failure_warns(self):
        # a non-zero rc from the stty setup command must surface as a warning (and non-clean exit)
        r = FakeRouter(self.clock, outputs=clean_outputs(), rcs={"stty cols 1000 2>/dev/null": 1})
        code, run_dir, out = self.run_main(r)
        m = json.loads((run_dir / "manifest.json").read_text())
        self.assertTrue(any("echo line-wrap" in w for w in m["warnings"]))
        self.assertEqual(code, 1)

    def test_password_never_written_or_printed(self):
        r = FakeRouter(self.clock, outputs=clean_outputs(), echo_password=True)
        code, run_dir, out = self.run_main(r)
        self.assertNotIn(PASSWORD, out)
        for f in run_dir.iterdir():
            self.assertNotIn(PASSWORD, f.read_text(), f.name)

    def test_wrong_password_stops_cleanly(self):
        code, run_dir, out = self.run_main(FakeRouter(self.clock, fail_delay=3.0), password="Zzz9!")  # nosec B106
        self.assertEqual(code, 1)
        self.assertIn("login failed", out)
        m = json.loads((run_dir / "manifest.json").read_text())
        self.assertFalse(m["complete"])
        self.assertIn("LoginFailed", m["error"])

    def test_not_an_orbi_stops_after_identity(self):
        r = FakeRouter(self.clock, outputs={ot.COMMANDS["dt_model"]: "TP-Link Archer\n",
                                            ot.COMMANDS["fw_version"]: "x\n"})
        code, run_dir, out = self.run_main(r)
        self.assertEqual(code, 1)
        self.assertEqual(r.commands_run, 3)  # setup + dt_model + fw_version
        self.assertIn("doesn't look like an Orbi", out)

    def test_command_timeout_saves_partial(self):
        r = FakeRouter(self.clock, outputs=ident_outputs(), hang_after=4)
        code, run_dir, out = self.run_main(r)
        self.assertEqual(code, 1)
        m = json.loads((run_dir / "manifest.json").read_text())
        self.assertFalse(m["complete"])
        self.assertIn("timed out", m["error"])
        hung = [n for n, c in m["commands"].items() if c["rc"] is None]
        self.assertEqual(len(hung), 1)
        self.assertIn("some partial output", (run_dir / f"{hung[0]}.txt").read_text())

    def test_timeout_before_start_marker_saves_no_echo(self):
        class NoStart(FakeRouter):
            def _shell(self, line):
                if self.commands_run >= 3:  # setup, dt_model, fw_version ran; then only the echo
                    self.chunks.append(line.encode() + b"\r\n")
                    return
                super()._shell(line)
        r = NoStart(self.clock, outputs=ident_outputs())
        code, run_dir, out = self.run_main(r)
        self.assertEqual(code, 1)
        m = json.loads((run_dir / "manifest.json").read_text())
        hung = [n for n, c in m["commands"].items() if c["rc"] is None]
        self.assertEqual(len(hung), 1)
        text = (run_dir / f"{hung[0]}.txt").read_text()
        self.assertIn("start marker never came", text)
        self.assertNotIn("__B", text)

    def test_warning_for_error_text_with_rc0(self):
        r = FakeRouter(self.clock, outputs={**ident_outputs(), "cat /proc/mtd": "cat: can't open\n"})
        code, run_dir, out = self.run_main(r)
        m = json.loads((run_dir / "manifest.json").read_text())
        self.assertTrue(any("mtd" in w and "error message" in w for w in m["warnings"]))
        self.assertEqual(code, 1)  # warnings make it non-clean

    def test_connect_refused_writes_manifest(self):
        def refuse(host):
            raise ConnectionRefusedError("no telnet")
        tmp = self.tmpdir()
        with redirect_stdout(io.StringIO()):
            code = ot.main([], out_root=tmp, connect=refuse, ask_user=lambda: "root",
                           ask_password=lambda: PASSWORD, require_tty=False)
        self.assertEqual(code, 1)
        m = json.loads((next(tmp.iterdir()) / "manifest.json").read_text())
        self.assertIn("ConnectionRefusedError", m["error"])

    def test_keyboardinterrupt_records_and_reraises(self):
        def boom(host):
            raise KeyboardInterrupt()
        tmp = self.tmpdir()
        with self.assertRaises(KeyboardInterrupt):
            ot.main([], out_root=tmp, connect=boom, ask_user=lambda: "root",
                    ask_password=lambda: PASSWORD, require_tty=False)
        m = json.loads((next(tmp.iterdir()) / "manifest.json").read_text())
        self.assertIn("KeyboardInterrupt", m["error"])

    def test_exit_not_sent_after_failed_login(self):
        r = FakeRouter(self.clock, fail_delay=1.0)
        self.run_main(r, password="nope")  # nosec B106
        self.assertNotIn("exit", r.lines)

    def test_two_runs_same_root_distinct_folders(self):
        tmp = self.tmpdir()
        for _ in range(2):
            with redirect_stdout(io.StringIO()):
                ot.main([], out_root=tmp, connect=lambda h: ot.Telnet(FakeRouter(self.clock, outputs=clean_outputs())),
                        ask_user=lambda: "root", ask_password=lambda: PASSWORD, require_tty=False)
        self.assertEqual(len(list(tmp.iterdir())), 2)

    def test_refuses_without_terminal(self):
        tmp = self.tmpdir()
        with unittest.mock.patch.object(sys, "stdin", io.StringIO()):
            with redirect_stdout(io.StringIO()):
                code = ot.main([], out_root=tmp, connect=lambda h: self.fail("connected"), require_tty=True)
        self.assertEqual(code, 2)
        self.assertEqual(list(tmp.iterdir()), [])


class WarningTests(Base):
    def test_nonzero_exit(self):
        self.assertTrue(any("exit code" in w for w in ot.check_warnings("x", "data\n", 1)))

    def test_error_phrase_with_rc0(self):
        self.assertTrue(any("error message" in w for w in ot.check_warnings("bridges", "sh: brctl: not found\n", 0)))

    def test_empty_output(self):
        self.assertTrue(any("empty" in w for w in ot.check_warnings("x", "\n", 0)))

    def test_bad_crc(self):
        self.assertTrue(any("Bad CRC" in w for w in ot.check_warnings(
            "fw_printenv", "Warning: bad crc, using default environment\nbootcmd=x\n", 0)))

    def test_mtd_sysfs_missing_offset(self):
        body = "mtd0 name=0:SBL1 offset=absent size=1048576\n"
        self.assertTrue(any("mibib_ptable" in w for w in ot.check_warnings("mtd_sysfs", body, 0)))
        good = "mtd0 name=0:SBL1 offset=0 size=1048576 erasesize=131072 type=nand\n"
        self.assertFalse(ot.check_warnings("mtd_sysfs", good, 0))

    def test_flash_layout_commands_present(self):
        for name in ("mtd_sysfs", "dt_partitions", "mibib_ptable", "appsblenv",
                     "boarddata1_head", "dt_wifi_cal", "pcie", "ubi"):
            self.assertIn(name, ot.COMMANDS)
        # flash is only read: every /dev/$d use in COMMANDS is a bounded "hexdump -C -n N /dev/$d"
        uses = 0
        for name, cmd in ot.COMMANDS.items():
            for m in re.finditer(r"/dev/\$d\b", cmd):
                if cmd[:m.start()].endswith("device: "):  # the echo, not a read
                    continue
                uses += 1
                self.assertRegex(cmd[:m.end()], r"hexdump -C -n \d+ /dev/\$d$", name)
        self.assertEqual(uses, 3)

    @unittest.skipUnless(shutil.which("sh"), "needs a POSIX sh")
    def test_mtd_sysfs_and_ubi_run_in_sh(self):
        # Run the real shell lines against a fake /sys tree; mtd0ro and ubi0_0 must be skipped.
        import subprocess  # nosec B404 - runs a local sh on test fixtures only
        root = self.tmpdir()
        for n, (label, off) in {"mtd0": ("0:SBL1", "0"), "mtd0ro": ("x", "0"),
                                "mtd14": ("boarddata1", "13631488")}.items():
            d = root / "mtd" / n
            d.mkdir(parents=True)
            for f, v in {"name": label, "offset": off, "size": "524288",
                         "erasesize": "131072", "type": "nand"}.items():
                (d / f).write_text(v + "\n")
        for n in ("ubi0", "ubi0_0"):
            d = root / "ubi" / n
            d.mkdir(parents=True)
            (d / "mtd_num").write_text("24\n")
            (d / "volumes_count").write_text("3\n")
        base = root.as_posix()
        cmds = (ot.COMMANDS["mtd_sysfs"].replace("/sys/class/mtd", base + "/mtd") + "; "
                + ot.COMMANDS["ubi"].replace("/sys/class/ubi", base + "/ubi"))
        out = subprocess.run([shutil.which("sh"), "-c", cmds], capture_output=True, text=True,
                             check=True).stdout  # nosec B603
        self.assertIn("mtd14 name=boarddata1 offset=13631488 size=524288", out)
        self.assertNotIn("mtd0ro", out)
        self.assertIn("ubi0 mtd_num=24 volumes=3", out)
        self.assertNotIn("ubi0_0", out)

    def _sh(self, cmd, swaps, path_dirs=()):
        """Run a COMMANDS line in a real sh with router paths swapped for fixture paths. rc is the
        line's last command, as in run_command. Returns (stdout + stderr, rc)."""
        import os
        import subprocess  # nosec B404 - runs a local sh on test fixtures only
        for a, b in swaps.items():
            cmd = cmd.replace(a, b)
        env = dict(os.environ)
        if path_dirs:
            env["PATH"] = os.pathsep.join([*map(str, path_dirs), env.get("PATH", "")])
        r = subprocess.run([shutil.which("sh"), "-c", cmd + "; echo __rc=$?"], capture_output=True,
                           text=True, env=env, check=False)  # nosec B603
        m = re.search(r"__rc=(\d+)\s*$", r.stdout)
        return r.stdout[:m.start()] + r.stderr, int(m.group(1))

    def _fake_hexdump(self):
        # A stand-in hexdump on PATH (this PC has none) that prints its arguments, so a test can
        # see which file and length the router's hexdump would read.
        d = self.tmpdir()
        (d / "hexdump").write_text('#!/bin/sh\necho "HEX $*"\n', newline="\n")
        return d

    @unittest.skipUnless(shutil.which("sh"), "needs a POSIX sh")
    def test_every_command_parses_in_sh(self):
        import subprocess  # nosec B404
        every = {**ot.COMMANDS, "probe_link": ot.PROBE_LINK_CMD, "probe_gpio": ot.probe_gpio_cmd()}
        for name, cmd in every.items():
            r = subprocess.run([shutil.which("sh"), "-n", "-c", cmd], capture_output=True,
                               text=True, check=False)  # nosec B603
            self.assertEqual(r.returncode, 0, f"{name}: {r.stderr}")

    @unittest.skipUnless(shutil.which("sh"), "needs a POSIX sh")
    def test_on_mtd_needs_exactly_one_match(self):
        root = self.tmpdir()
        hd = self._fake_hexdump()
        mtd = root / "mtd"
        dev = (root / "dev").as_posix()
        swaps = {"/proc/mtd": mtd.as_posix(), "hexdump -C -n 64 /dev/$d": f"hexdump -C -n 64 {dev}/$d"}
        cmd = ot.COMMANDS["boarddata1_head"]
        mtd.write_text('mtd13: 00100000 00020000 "config"\n')  # no boarddata1
        out, rc = self._sh(cmd, swaps, [hd])
        self.assertNotEqual(rc, 0)
        self.assertIn("no single mtd named boarddata1", out)
        self.assertNotIn("HEX", out)  # never reads /dev/
        mtd.write_text('mtd14: 0 0 "boarddata1"\nmtd99: 0 0 "boarddata1"\n')  # two matches
        out, rc = self._sh(cmd, swaps, [hd])
        self.assertNotEqual(rc, 0)
        self.assertNotIn("HEX", out)
        # "boarddata1.bak" must not count as a second match
        mtd.write_text('mtd14: 0 0 "boarddata1"\nmtd16: 0 0 "boarddata1.bak"\n')
        out, rc = self._sh(cmd, swaps, [hd])
        self.assertEqual(rc, 0, out)
        self.assertIn("device: /dev/mtd14", out)
        self.assertIn(f"HEX -C -n 64 {dev}/mtd14", out)

    @unittest.skipUnless(shutil.which("sh"), "needs a POSIX sh")
    def test_dt_status_absent_and_no_pci_are_not_errors(self):
        root = self.tmpdir()
        hd = self._fake_hexdump()
        w = root / "dt" / "soc" / "wifi@a000000"
        w.mkdir(parents=True)
        (w / "qcom,mtd-name").write_bytes(b"0:ART\0")  # no status property
        (w / "qcom,cal-offset").write_bytes(b"\0\0\x10\0")
        (w / "qcom,cal-len").write_bytes(b"\0\0\x2f\x20")
        out, rc = self._sh(ot.COMMANDS["dt_wifi_cal"], {"/proc/device-tree": (root / "dt").as_posix()}, [hd])
        self.assertEqual(rc, 0, out)
        self.assertIn("wifi@a000000 status=absent mtd=0:ART cal-offset=HEX", out)
        self.assertFalse(ot.check_warnings("dt_wifi_cal", out, 0))
        swaps = {"/proc/device-tree": (root / "dt").as_posix(), "/sys/bus/pci": (root / "nopci").as_posix(),
                 "/proc/bus/pci": (root / "nopci").as_posix()}
        out, rc = self._sh(ot.COMMANDS["pcie"], swaps)
        self.assertEqual(rc, 0, out)
        self.assertIn("pcie@80000 status=absent", out)
        self.assertIn("no PCI bus in sysfs", out)
        self.assertFalse(ot.check_warnings("pcie", out, 0))

    @unittest.skipUnless(shutil.which("sh"), "needs a POSIX sh")
    def test_mtd_sysfs_offset_absent_gives_one_warning(self):
        d = self.tmpdir() / "mtd" / "mtd0"
        d.mkdir(parents=True)
        for f, v in {"name": "0:SBL1", "size": "1048576", "erasesize": "131072", "type": "nand"}.items():
            (d / f).write_text(v + "\n")
        out, rc = self._sh(ot.COMMANDS["mtd_sysfs"], {"/sys/class/mtd": d.parent.as_posix()})
        self.assertEqual(rc, 0)
        self.assertIn("mtd0 name=0:SBL1 offset=absent size=1048576", out)
        w = ot.check_warnings("mtd_sysfs", out, 0)
        self.assertEqual(len(w), 1, w)
        self.assertIn("mibib_ptable", w[0])

    def test_dmesg_scrolled(self):
        self.assertTrue(any("wrapped" in w for w in ot.check_warnings("dmesg", "[ 1234.5] eth0 up\n", 0)))
        self.assertTrue(any("wrapped" in w for w in ot.check_warnings("dmesg", "<6>[ 50.0] late\n", 0)))
        self.assertFalse(ot.check_warnings("dmesg", "[    0.000000] Booting Linux\n", 0))
        self.assertFalse(ot.check_warnings("dmesg", "<6>[    0.000000] Booting\n", 0))


# Real /sys/kernel/debug/gpio lines from this RBR10 (recon 20261115-041036-501381). The number
# after in/out is the pin's mux FUNCTION (hence "in  3"), not its level.
REAL_DEBUGFS = (" gpio8   : out 1 2mA no pull\n"
                " gpio18  : in  0 4mA keeper\n"
                " gpio19  : in  1 2mA pull down\n"
                " gpio32  : in  0 2mA keeper\n"
                " gpio36  : in  3 2mA pull down\n")


def gpio_rounds(idle, pressed, at=(5, 6, 7), rounds=20):
    """probe_gpio_cmd output: levels `idle` ({gpio: 0/1}), `pressed` overriding in rounds `at`.
    Register values carry other bits too (0x2 = output bit), to check only bit 0 is used."""
    out = "pins: " + " ".join(f"gpio{g}" for g in idle) + "\n"
    for i in range(rounds):
        out += f"#{i}\n" + "".join(f"gpio{g} 0x{0x2 | v:08x}\n"
                                   for g, v in {**idle, **(pressed if i in at else {})}.items())
    return out


class ProbeParseTests(Base):
    def test_parse_uses_bit0_of_register(self):
        samples = ot.parse_gpio_samples(gpio_rounds({18: 1, 32: 1}, {18: 0}))
        self.assertEqual(len(samples[18]), 20)
        self.assertEqual(set(samples[32]), {1})
        self.assertEqual(ot.changed_gpios(samples), {18: (1, 3)})

    def test_devmem_errors_and_debugfs_lines_ignored(self):
        text = "pins: gpio18\n#0\ngpio18 devmem: /dev/mem: Permission denied\n" + REAL_DEBUGFS
        self.assertEqual(ot.parse_gpio_samples(text), {})

    def test_tie_means_polarity_unknown(self):
        samples = {18: [1, 0, 1, 0]}
        self.assertEqual(ot.changed_gpios(samples), {18: (None, 2)})

    def test_count_rounds(self):
        self.assertEqual(ot.count_rounds(gpio_rounds({18: 1}, {}, rounds=7)), 7)

    def test_press_in_first_round_keeps_polarity(self):
        samples = ot.parse_gpio_samples(gpio_rounds({18: 1}, {18: 0}, at=(0, 1)))
        self.assertEqual(ot.changed_gpios(samples), {18: (1, 2)})  # idle = most common level

    def test_link_diff_counts_repeats_and_removals(self):
        before = "ssdk port 1: [Status]:DISABLE\nssdk port 5: [Status]:ENABLE\nx\nx\n"
        after = "ssdk port 1: [Status]:ENABLE\nssdk port 5: [Status]:ENABLE\nx\n"
        self.assertEqual(ot.link_diff(before, after),
                         (["ssdk port 1: [Status]:ENABLE"], ["ssdk port 1: [Status]:DISABLE", "x"]))
        self.assertEqual(ot.link_diff("a\n", "a\n"), ([], []))


class ProbeMainTests(Base):
    IDLE = {18: 1, 32: 1, 49: 1, 25: 0}
    CHECK = ot.probe_gpio_cmd(ot.IDLE_CHECK_S)
    WINDOW = ot.probe_gpio_cmd()

    def run_probe(self, outputs, answers, router=None):
        router = router or FakeRouter(self.clock, outputs={**clean_outputs(), **outputs})
        tmp = self.tmpdir()
        asked = []
        script = iter(answers)

        def ask(prompt):
            asked.append(prompt)
            return next(script)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ot.main(["--probe"], out_root=tmp, connect=lambda h: ot.Telnet(router),
                           ask_user=lambda: "root", ask_password=lambda: PASSWORD,
                           require_tty=False, ask=ask)
        run_dir = next(tmp.iterdir())
        m = json.loads((run_dir / "manifest.json").read_text())
        return code, run_dir, buf.getvalue(), asked, m

    def outputs(self, windows, link="ssdk port 5: [Status]:ENABLE\neth1 carrier=1\n"):
        return {ot.PROBE_LINK_CMD: link, self.CHECK: gpio_rounds(self.IDLE, {}, rounds=3),
                self.WINDOW: windows}

    def test_probe_finds_buttons_and_skips_wan(self):
        windows = [gpio_rounds(self.IDLE, {49: 0})]
        code, run_dir, out, asked, m = self.run_probe(self.outputs(windows), ["", ""])
        self.assertEqual(code, 0, out)
        self.assertTrue(m["complete"])
        self.assertEqual(m["probe"]["button_sync"],
                         {"pins": {"49": {"idle": 1, "rounds_changed": 3}}, "rounds": 20, "status": "ok"})
        self.assertNotIn("button_reset", m["probe"])
        self.assertEqual(m["probe"]["wan"], {"status": "skipped"})
        summary = (run_dir / "probe_summary.txt").read_text()
        self.assertIn("(20 rounds in about 10 s): GPIO 49 idles 1, was 0 in 3 round(s) (active-low)", summary)
        self.assertIn("Compare with the keys and switch ports in dts/qcom-ipq4019-rbr10.dts.", summary)
        self.assertIn("ssdk port 5: [Status]:ENABLE", summary)
        self.assertIn("dt_model", m["commands"])  # identity check ran ...
        self.assertNotIn("mtd", m["commands"])    # ... the full recon didn't
        # Reset factory-resets stock firmware even on a short press, so nobody is asked to press it.
        self.assertEqual(len(asked), 2, asked)
        self.assertFalse(any("reset" in a.lower() for a in asked), asked)
        wan_q = asked[0]
        for must in ("SECOND cable", "keep this laptop's cable in the LAN jack", "moving it ends this session",
                     "not this laptop", "NOT on your home"):
            self.assertIn(must, wan_q)
        self.assertEqual(m["probe"]["link"]["ports_up"], [5])
        self.assertIn("LAN jack = switch port 5", summary)

    def test_wan_step_names_the_port_that_came_up(self):
        windows = [gpio_rounds(self.IDLE, {49: 0})]
        links = ["ssdk port 4: [Status]:DISABLE\nssdk port 5: [Status]:ENABLE\n",
                 "ssdk port 4: [Status]:ENABLE\nssdk port 5: [Status]:ENABLE\n"]
        code, run_dir, out, asked, m = self.run_probe(
            {**self.outputs(windows), ot.PROBE_LINK_CMD: links}, ["y", ""])
        self.assertEqual(code, 0, out)
        self.assertEqual(m["probe"]["wan"]["added"], ["ssdk port 4: [Status]:ENABLE"])
        self.assertEqual(m["probe"]["wan"]["new_ports"], [4])
        summary = (run_dir / "probe_summary.txt").read_text()
        self.assertIn("+ ssdk port 4: [Status]:ENABLE", summary)
        self.assertIn("WAN jack = switch port 4", summary)

    def test_slow_rounds_warn(self):
        windows = [gpio_rounds(self.IDLE, {49: 0}, at=(1,), rounds=4)]
        code, run_dir, out, asked, m = self.run_probe(self.outputs(windows), ["", ""])
        self.assertEqual(code, 1)
        self.assertTrue(any("only 4 rounds" in w for w in m["warnings"]), m["warnings"])

    def test_only_y_or_yes_runs_the_wan_step(self):
        windows = lambda: [gpio_rounds(self.IDLE, {49: 0})]
        for answer in ("n", "no", "ok", "ye"):
            code, run_dir, out, asked, m = self.run_probe(self.outputs(windows()), [answer, ""])
            self.assertEqual(m["probe"]["wan"], {"status": "skipped"}, answer)
            self.assertNotIn("probe_link_wan", m["commands"], answer)
        code, run_dir, out, asked, m = self.run_probe(self.outputs(windows()), [" Y ", ""])
        self.assertIn("probe_link_wan", m["commands"])

    def test_two_ports_up_is_unclear(self):
        windows = [gpio_rounds(self.IDLE, {49: 0})]
        link = "ssdk port 4: [Status]:ENABLE\nssdk port 5: [Status]:ENABLE\n"
        code, run_dir, out, asked, m = self.run_probe(self.outputs(windows, link=link), ["", ""])
        self.assertEqual(code, 1)
        self.assertEqual(m["probe"]["link"]["status"], "unclear")
        self.assertTrue(any("expected exactly one" in w for w in m["warnings"]), m["warnings"])

    def test_ports_up_reads_ssdk_and_swconfig(self):
        text = ("ssdk port 1:   SSDK Init OK! Illegal parameter(s)\n"
                "ssdk port 4:   SSDK Init OK![Status]:ENABLE operate done.\n"
                "ssdk port 5:   SSDK Init OK![Status]:DISABLE operate done.\n"
                "        link: port:0 link:up speed:1000baseT full-duplex\n"
                "        link: port:4 link:up speed:1000baseT full-duplex\n"
                "        link: port:5 link:down\n")
        self.assertEqual(ot.ports_up(text), {4})  # port 0 (CPU) never counts

    def test_wan_no_change_warns(self):
        windows = [gpio_rounds(self.IDLE, {49: 0})]
        code, run_dir, out, asked, m = self.run_probe(self.outputs(windows), ["yes", ""])
        self.assertEqual(code, 1)
        self.assertEqual(m["probe"]["wan"]["status"], "no change")

    def test_no_press_and_ambiguity_warn(self):
        code, run_dir, out, asked, m = self.run_probe(self.outputs([gpio_rounds(self.IDLE, {})]), ["", ""])
        self.assertEqual(code, 1)
        self.assertEqual(m["probe"]["button_sync"]["status"], "no change")
        self.assertTrue(any("no pin changed" in w for w in m["warnings"]), m["warnings"])
        windows = [gpio_rounds(self.IDLE, {25: 1, 49: 0})]
        code, run_dir, out, asked, m = self.run_probe(self.outputs(windows), ["", ""])
        self.assertEqual(code, 1)
        self.assertEqual(m["probe"]["button_sync"]["status"], "ambiguous")
        self.assertTrue(any("2 pins changed" in w for w in m["warnings"]), m["warnings"])

    def assert_suspect(self, windows, must, check=None):
        outs = self.outputs(windows)
        if check is not None:
            outs[self.CHECK] = check
        code, run_dir, out, asked, m = self.run_probe(outs, ["", ""])
        self.assertEqual(code, 1, out)
        self.assertEqual(m["probe"]["button_sync"]["status"], "suspect")
        self.assertTrue(any(must in w for w in m["warnings"]), m["warnings"])

    def test_pin_moving_at_idle_is_suspect(self):
        self.assert_suspect([gpio_rounds(self.IDLE, {49: 0})], "also changed in the idle check",
                            check=gpio_rounds(self.IDLE, {49: 0}, at=(1,), rounds=3))

    def test_reset_pin_in_the_sync_window_is_suspect(self):
        self.assert_suspect([gpio_rounds(self.IDLE, {18: 0})], "is the Reset button")

    def test_blip_shorter_than_a_hold_is_suspect(self):
        self.assert_suspect([gpio_rounds(self.IDLE, {49: 0}, at=(5,))], "too short for a 2 s hold")

    def test_unknown_polarity_is_suspect(self):
        no49 = {g: v for g, v in self.IDLE.items() if g != 49}  # 49 not read in the idle check
        self.assert_suspect([gpio_rounds(self.IDLE, {49: 0}, at=(0, 1), rounds=4)],
                            "polarity (active-low or active-high) is unknown",
                            check=gpio_rounds(no49, {}, rounds=3))

    def test_one_round_idle_check_is_not_trusted(self):
        windows = [gpio_rounds(self.IDLE, {49: 0}, at=range(3, 18))]  # held 15 of 20 rounds
        self.assert_suspect(windows, "its idle level (and the polarity) is a guess",
                            check=gpio_rounds(self.IDLE, {49: 0}, at=(0,), rounds=1))

    def test_long_hold_keeps_polarity_from_the_idle_check(self):
        windows = [gpio_rounds(self.IDLE, {49: 0}, at=range(3, 18))]  # held 15 of 20 rounds
        code, run_dir, out, asked, m = self.run_probe(self.outputs(windows), ["", ""])
        self.assertEqual(code, 0, out)
        self.assertEqual(m["probe"]["button_sync"]["pins"], {"49": {"idle": 1, "rounds_changed": 15}})
        self.assertIn("GPIO 49 idles 1, was 0 in 15 round(s) (active-low)",
                      (run_dir / "probe_summary.txt").read_text())

    def test_ambiguous_is_not_overwritten_by_suspect(self):
        code, run_dir, out, asked, m = self.run_probe(
            self.outputs([gpio_rounds(self.IDLE, {18: 0, 49: 0})]), ["", ""])
        self.assertEqual(m["probe"]["button_sync"]["status"], "ambiguous")
        self.assertTrue(any("is the Reset button" in w for w in m["warnings"]), m["warnings"])

    def test_only_sync_is_ever_asked_for(self):
        self.assertEqual([k for k, _, _ in ot.BUTTONS], ["sync"])

    def test_pin_reads_failing_in_the_window_are_not_a_missed_press(self):
        window = "pins: gpio18 gpio49\n#0\ngpio18 devmem: bad\ngpio49 devmem: bad\n#1\ngpio18 devmem: bad\n"
        code, run_dir, out, asked, m = self.run_probe(self.outputs([window]), ["", ""])
        self.assertEqual(code, 1)
        self.assertEqual(m["probe"]["button_sync"]["status"], "pin reads failed")
        self.assertTrue(any("no pin levels could be read in the window" in w for w in m["warnings"]),
                        m["warnings"])
        self.assertFalse(any("hold the button" in w for w in m["warnings"]), m["warnings"])

    def test_failed_pin_reads_skip_button_prompts(self):
        outs = {**self.outputs([]), self.CHECK: "pins: gpio18\n#0\ngpio18 devmem: bad\n"}
        code, run_dir, out, asked, m = self.run_probe(outs, [""])
        self.assertEqual(code, 1)
        self.assertEqual(len(asked), 1)  # only the WAN question; nobody is asked to press a button
        self.assertEqual(m["probe"]["buttons"], {"status": "pin reads failed"})
        self.assertTrue((run_dir / "probe_summary.txt").exists())

    def test_not_an_orbi_stops_before_any_question(self):
        router = FakeRouter(self.clock, outputs={ot.COMMANDS["dt_model"]: "TP-Link\n",
                                                 ot.COMMANDS["fw_version"]: "x\n"})
        code, run_dir, out, asked, m = self.run_probe({}, [], router=router)
        self.assertEqual(code, 1)
        self.assertEqual(asked, [])
        self.assertFalse(list(run_dir.glob("probe_*")))

    def test_timeout_mid_probe_still_writes_summary(self):
        class HangOnGpio(FakeRouter):
            def _shell(self, line):
                if "devmem" in line and "+10" in line:  # the 10 s window, not the 1 s check
                    self.chunks.append(line.encode() + b"\r\n")  # echo only, never the markers
                    return
                super()._shell(line)
        router = HangOnGpio(self.clock, outputs={**clean_outputs(), **self.outputs([])})
        code, run_dir, out, asked, m = self.run_probe({}, ["", ""], router=router)
        self.assertEqual(code, 1)
        self.assertFalse(m["complete"])
        self.assertIn("timed out", m["error"])
        summary = (run_dir / "probe_summary.txt").read_text()
        self.assertIn("ssdk port 5", summary)  # the link step's result survived
        self.assertIn("STOPPED during the button_sync step", summary)

    def test_connection_lost_mid_step_is_recorded(self):
        class DropOnGpio(FakeRouter):
            def _shell(self, line):
                if "devmem" in line and "+10" in line:  # the Sync window
                    self.chunks.append(line.encode() + b"\r\n__B%d__\r\npartial rounds" %
                                       int(re.match(r"echo __B''(\d+)", line).group(1)))
                    self.chunks.append(b"")  # then the router closes the connection
                    return
                super()._shell(line)
        router = DropOnGpio(self.clock, outputs={**clean_outputs(), **self.outputs([])})
        code, run_dir, out, asked, m = self.run_probe({}, ["", ""], router=router)
        self.assertEqual(code, 1)
        self.assertFalse(m["complete"])
        self.assertIn("telnet session lost during 'probe_gpio_sync'", m["error"])
        self.assertTrue(m["commands"]["probe_gpio_sync"]["connection_lost"])
        self.assertIn("partial rounds", (run_dir / "probe_gpio_sync.txt").read_text())
        self.assertEqual(m["probe"]["button_sync"]["status"], "failed: ConnectionError")
        self.assertIn("STOPPED during the button_sync step", (run_dir / "probe_summary.txt").read_text())

    def test_session_dead_after_a_question_is_named(self):
        class DieWhileWaiting(FakeRouter):
            def _shell(self, line):
                if "; true; __rc" in line:  # the alive check right after the WAN question
                    self.chunks.append(b"")
                    return
                super()._shell(line)
        router = DieWhileWaiting(self.clock, outputs={**clean_outputs(), **self.outputs([])})
        code, run_dir, out, asked, m = self.run_probe({}, [""], router=router)
        self.assertEqual(code, 1)
        self.assertIn("lost while waiting", m["error"])
        self.assertEqual(m["probe"]["wan"]["status"], "failed: ConnectionError")
        self.assertIn("STOPPED during the wan step", (run_dir / "probe_summary.txt").read_text())

    @unittest.skipUnless(shutil.which("sh"), "needs a POSIX sh")
    def test_probe_lines_run_in_sh(self):
        import os
        import subprocess  # nosec B404 - runs a local sh on test fixtures only
        root = self.tmpdir()
        shim = root / "bin"
        shim.mkdir()
        log = (root / "devmem.log").as_posix()
        # stand-ins for router tools: devmem logs its arguments and returns "level 1, output bit set"
        (shim / "devmem").write_text(f'#!/bin/sh\necho "$*" >> {log}\necho 0x00000003\n', newline="\n")
        (shim / "ssdk_sh").write_text('#!/bin/sh\necho "[Status]:ENABLE"\necho "[x]:$4"\n', newline="\n")
        (shim / "dmesg").write_text("#!/bin/sh\necho 'eth1: port 3 link up'\necho noise\n", newline="\n")
        dbg = root / "gpio"
        dbg.write_text(REAL_DEBUGFS)
        env = dict(os.environ, PATH=os.pathsep.join([str(shim), os.environ.get("PATH", "")]))
        cmd = ot.probe_gpio_cmd(1).replace("/sys/kernel/debug/gpio", dbg.as_posix())
        r = subprocess.run([shutil.which("sh"), "-c", cmd], capture_output=True, text=True,
                           env=env, check=True)  # nosec B603
        self.assertIn("pins: gpio18 gpio32", r.stdout)  # function-0 inputs only: not 8, 19, 36
        samples = ot.parse_gpio_samples(r.stdout)
        self.assertEqual(set(samples), {18, 32})
        self.assertEqual(set(samples[18]), {1})
        calls = set(pathlib.Path(log).read_text().split("\n")) - {""}
        self.assertEqual(calls, {f"{0x01000004 + 18 * 0x1000} 32", f"{0x01000004 + 32 * 0x1000} 32"})
        net = root / "net" / "eth1"
        net.mkdir(parents=True)
        (net / "carrier").write_text("1\n")
        cmd = ot.PROBE_LINK_CMD.replace("/sys/class/net", (root / "net").as_posix())
        r = subprocess.run([shutil.which("sh"), "-c", cmd + "; echo __rc=$?"], capture_output=True,
                           text=True, env=env, check=False)  # nosec B603
        self.assertIn("ssdk port 4: [Status]:ENABLE [x]:4", r.stdout)  # one line per port
        self.assertIn("eth0 carrier=unreadable (interface down?)", r.stdout)
        self.assertIn("eth1 carrier=1", r.stdout)
        self.assertIn("eth1: port 3 link up", r.stdout)
        self.assertNotIn("noise", r.stdout)
        self.assertTrue(r.stdout.rstrip().endswith("__rc=0"))


class CommandListTests(Base):
    # A pattern blocklist, not a proof of read-only: it must reject known write commands and
    # accept the real ones. Review every new COMMANDS entry by hand too.
    MUST_REJECT = [
        "config set x y", "config commit", "config show", "nvram set a b", "artmtd -w",
        "mtd write fw.bin firmware", "mtd -r write fw.bin firmware", "mtd erase rootfs",
        "flash_erase /dev/mtd0 0 0", "dd if=x of=/dev/mtdblock0", "rm -f x", "reboot", "poweroff",
        "halt", "mkfs.ext4 /dev/x", "fw_setenv bootcmd x", "dmesg -c", "dmesg -C", "dmesg -n 1",
        "sysupgrade x", "firstboot", "flashcp a b", "nandwrite x", "uci set a=b", "uci commit",
        "mv a b", "cp a b", "touch x", "mkdir x", "chmod 777 x", "kill 1", "killall x",
        "insmod m", "rmmod m", "sysctl -w a=b", "ln -s a b", "echo x > /etc/passwd", "sed -i s/a/b/ f",
        # wrappers and other ways to reach a write verb outside plain command position
        "busybox dd if=a of=b", "env rm x", "xargs rm", "exec rm x", "nohup rm x", "timeout 5 rm x",
        "find / -exec rm {} ;", "find /tmp -delete", "{ rm x; }", "! rm x", "if rm x; then :; fi",
        # flash/UBI writers and state changers
        "mtd_debug write /dev/mtd0 0 1 f", "flash_eraseall /dev/mtd0", "flash_unlock /dev/mtd0",
        "ubiformat /dev/mtd24", "ubiupdatevol /dev/ubi0_0 f", "ubirmvol /dev/ubi0 -n 0",
        "ubimkvol /dev/ubi0 -N x -s 1", "ubiattach -m 24", "ubidetach -m 24", "umount /tmp",
        "mount -o remount,rw /", "ifconfig eth0 down", "brctl delbr br0",
        "devmem 0x1000004 32 1", "devmem $a 32 0x0",  # a third devmem argument writes
        "devmem $a 32 2>&1 1", "devmem 2>/dev/null $a 32 1",
        # wrapper forms this file itself uses ($T is _PICK_TIMEOUT's), and other ways to run a verb
        "timeout -t 3 rm x", "$T rm x", "${T} rm x", "sh -c 'rm x'", 'sh -c "dd if=a of=/dev/mtd0"',
        "eval rm x", "command rm x", "time rm x", "nice -n 5 rm x", "xargs -0 rm", "chroot / rm x",
        "echo ok\nrm x", "bash -c 'rm x'", "sh -ec 'rm x'", "nice -5 rm x", "xargs -n 1 rm",
        "env A=1 rm x", "A=1 rm x", "timeout -s KILL 3 rm x", "time -p rm x",
        "head -n 5 /etc/passwd", "head /proc/mtd", "tail -c 10 /dev/mtd0",  # line-cut/tail stay blocked
        "head -c foo /dev/mtd0", "head --bytes=10 /dev/mtd0",  # only `head -c <digits>` is allowed
    ]
    MUST_ACCEPT = [c for c in ot.COMMANDS.values()] + [*ot.SECBOOT_COMMANDS.values()] + [
        "cat /proc/mtd", "ls -l /dev", "echo x > /dev/null", "find /proc/device-tree", "df",
        # orbi_backup --rehash: a byte-bounded device read for hashing (head -c <N>), vetted read-only.
        'head -c 34471936 /dev/mtd19 | sha256sum | cut -d" " -f1', "head -c 65536 /dev/mtd0 | wc -c",
    ]

    def test_rejects_write_commands(self):
        for cmd in self.MUST_REJECT:
            self.assertIsNotNone(FORBIDDEN.search(cmd), f"not rejected: {cmd}")

    def test_accepts_read_commands(self):
        for cmd in self.MUST_ACCEPT:
            self.assertIsNone(FORBIDDEN.search(cmd), f"wrongly rejected: {cmd}")

    def test_real_commands_are_read_only(self):
        for name, cmd in ot.COMMANDS.items():
            self.assertIsNone(FORBIDDEN.search(cmd), f"{name}: {cmd}")

    def test_probe_commands_are_read_only(self):
        for cmd in (ot.PROBE_LINK_CMD, ot.probe_gpio_cmd(), ot.probe_gpio_cmd(1)):
            self.assertIsNone(FORBIDDEN.search(cmd), cmd)
        self.assertIn("devmem $a 32 2>&1", ot.probe_gpio_cmd())  # exactly two devmem arguments
        # ssdk_sh and swconfig only ever "get"/"show"
        self.assertRegex(ot.PROBE_LINK_CMD, r"ssdk_sh port linkstatus get \$p")
        self.assertNotRegex(ot.PROBE_LINK_CMD, r"ssdk_sh .*\bset\b|swconfig .*\bset\b")


# A write verb is dangerous only in command position (line start, or after ; | & ( $( ` do/then/else),
# so tool NAMES like "dd" probed by `command -v` in the tools command aren't flagged.
FORBIDDEN = re.compile(
    r"""
    (?: ^ | [;&|({!] | \$\( | ` | \b(?:do|then|else|if)\s | \b(?:ba|a)?sh\s+-\w*c\s+['"]? ) \s*
    (?: (?:busybox|env(?:\s+\w+=\S*)*|exec|eval|command|time(?:\s+-p)?|nohup|chroot\s+\S+
         |nice(?:\s+-n)?(?:\s*-?\d+)?|xargs(?:\s+-\S+(?:\s+\d+)?)*|timeout(?:\s+-s\s+\S+)?(?:\s+-t)?\s+\S+
         |\$\{?\w+\}?|\w+=[^\s;|&]*)\s+ )*
    (?: config\s+(?:set|commit|show|unset) | nvram | artmtd | fw_setenv | flash_erase | flashcp
      | nandwrite | sysupgrade | firstboot | mkfs\w* | reboot | poweroff | halt
      | dd | rm | mv | cp | ln | touch | mkdir | chmod | chown | kill | killall
      | insmod | rmmod | sysctl | sed | tee | head(?!\s+-c\s+\d) | tail | uci | mtd_debug | flash_eraseall
      | flash_unlock | ubiformat | ubiupdatevol | ubirmvol | ubimkvol | ubiattach | ubidetach
      | umount )\b
    | \s-(?:exec|execdir|ok|delete)\b
    | \bmount\s+(?:-\S+\s+)*-o\s
    | \bifconfig\s+(?!-a\b)\S+\s+\S
    | \bbrctl\s+(?:add|del|set|stp)
    | \bdevmem(?:\s+[0-9]*[<>]&?[^\s;|&)<>]*)*(?:\s+(?![0-9]*[<>])[^\s;|&)<>]+(?:\s+[0-9]*[<>]&?[^\s;|&)<>]*)*){3}
    | \bmtd\s+(?:-\S+\s+)*(?:write|erase|unlock)\b
    | \bdmesg\s+-[a-zA-Z]
    | >\s*(?!/dev/null\b|&)[^\s&]""",
    re.X | re.M,  # re.M: a command with a newline is checked on every line
)



class RunAndSaveErrorTests(Base):
    def call(self, exc, run_dir):
        t = types.SimpleNamespace(buf=b"partial out\n", output_started=True)  # bytes, as in Telnet
        manifest = {"commands": {}, "warnings": []}
        with unittest.mock.patch.object(ot, "run_command", side_effect=exc):
            with self.assertRaises(Exception) as cm:
                ot.run_and_save(t, 1, "x", "echo x", run_dir, manifest)
        return cm.exception, manifest

    def test_other_socket_errors_count_as_a_lost_session(self):
        err, m = self.call(OSError(113, "No route to host"), self.tmpdir())
        self.assertIsInstance(err, ConnectionError)
        self.assertIn("telnet session lost during 'x'", str(err))
        self.assertTrue(m["commands"]["x"]["connection_lost"])

    def test_failed_write_keeps_the_timeout_and_the_output(self):
        err, m = self.call(TimeoutError("slow"), self.tmpdir() / "missing" / "dir")
        self.assertIsInstance(err, TimeoutError)  # not the FileNotFoundError from the write
        self.assertEqual(m["commands"]["x"]["output"], "partial out\n")
        self.assertTrue(any("could not write x.txt" in w for w in m["warnings"]), m["warnings"])


QF = "/sys/devices/system/qfprom/qfprom0"
GOOD_SECBOOT = {
    "sec_qfprom": f"== {QF}\n-r--r--r-- 1 root root 4096 authenticate\n{QF}/authenticate: 1 (rc=0)\n"
                  "qfprom values read: 1\n",
    "sec_sysfs_find": f"{QF}/authenticate\nfind rc=0\n",
    "sec_dmesg": "dmesg rc=0\nfirst line: [    0.000000] Booting Linux\n[    1.0] scm: secure boot on\n"
                 "grep-done\n",
    "kernel_head": "device: /dev/mtd19\nbad_blocks: 0\n00000000  17 00 00 00 03 00\n",
    "sbl1_strings": ("device: /dev/mtd0\nsize: 1048576\nbad_blocks: 0\necc_failures before: 0\n"
                     "bytes read: 1048576\nhello world\necc_failures after: 0\n"),
    "appsbl_strings": ("device: /dev/mtd9\nsize: 2097152\nbad_blocks: 0\necc_failures before: 0\n"
                       "bytes read: 2097152\nbootcmd=bootipq\nImage authentication failed\n"
                       "nothing to see here\nfile not found\necc_failures after: 0\n"),
}


def secboot_outputs(**over):
    """Router outputs for a clean --secboot run; keyword arguments replace one command's output."""
    return {**ident_outputs(),
            **{ot.SECBOOT_COMMANDS[k]: v for k, v in {**GOOD_SECBOOT, **over}.items()}}


class SecbootTests(Base):
    def run_secboot(self, router):
        tmp = self.tmpdir()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ot.main(["--secboot"], out_root=tmp, connect=lambda h: ot.Telnet(router),
                           ask_user=lambda: "root", ask_password=lambda: PASSWORD, require_tty=False)
        run_dir = next(tmp.iterdir())
        m = json.loads((run_dir / "manifest.json").read_text())
        return code, run_dir, buf.getvalue(), m

    def summary(self, **over):
        code, run_dir, out, m = self.run_secboot(FakeRouter(self.clock, outputs=secboot_outputs(**over)))
        return (run_dir / "secboot_summary.txt").read_text(), m, code

    # --- read-only guarantee ---

    def test_commands_are_read_only(self):
        for name, cmd in ot.SECBOOT_COMMANDS.items():
            self.assertIsNone(FORBIDDEN.search(cmd), f"{name}: {cmd}")

    @unittest.skipUnless(shutil.which("sh"), "needs a POSIX sh")
    def test_commands_parse_in_sh(self):
        import subprocess  # nosec B404 - sh -n only parses
        for name, cmd in ot.SECBOOT_COMMANDS.items():
            r = subprocess.run([shutil.which("sh"), "-n", "-c", cmd], capture_output=True,
                               text=True, check=False)  # nosec B603
            self.assertEqual(r.returncode, 0, f"{name}: {r.stderr}")

    def test_flash_is_only_read_by_redirect_or_bounded_hexdump(self):
        uses = []
        for name, cmd in ot.SECBOOT_COMMANDS.items():
            cmd = cmd.replace('echo "device: /dev/$d"', "")  # _on_mtd's label, not a read
            for m in re.finditer(r"(?:\S+\s+){0,4}/dev/\$d", cmd):
                uses.append((name, m.group(0)))
        for name, use in uses:
            self.assertRegex(use, r"(?:< /dev/\$d$|hexdump -C -n \d+ /dev/\$d$)", f"{name}: {use}")
        # wc + tr for each of the two strings dumps, and one hexdump of the kernel
        self.assertEqual(len(uses), 5, uses)

    # --- a clean run ---

    def test_clean_run_is_complete_with_no_warnings(self):
        r = FakeRouter(self.clock, outputs=secboot_outputs())
        code, run_dir, out, m = self.run_secboot(r)
        self.assertEqual(r.commands_run, 1 + 2 + len(ot.SECBOOT_COMMANDS), out)  # setup + ident + secboot
        self.assertEqual(m["warnings"], [])
        self.assertEqual(code, 0, out)
        self.assertEqual(set(m["commands"]), {"dt_model", "fw_version", *ot.SECBOOT_COMMANDS})
        s = (run_dir / "secboot_summary.txt").read_text()
        self.assertIn("fuse state: authenticate = 1", s)
        for n in ot.SECBOOT_COMMANDS:
            self.assertIn(f"{n}: OK", s)
        self.assertIn(f"{QF}/authenticate: 1 (rc=0)", s)
        self.assertIn("17 00 00 00 03 00", s)
        self.assertIn("bytes read: 2097152", s)
        self.assertIn("Image authentication failed", s.split("-- secure-boot lines")[2])
        self.assertIn("bootcmd=bootipq", s)
        self.assertNotIn("nothing to see here", s)
        self.assertIn("== All warnings\n(none)", s)

    def test_not_an_orbi_stops_before_any_flash_read(self):
        r = FakeRouter(self.clock, outputs={ot.COMMANDS["dt_model"]: "TP-Link Archer\n",
                                            ot.COMMANDS["fw_version"]: "x\n"})
        code, run_dir, out, m = self.run_secboot(r)
        self.assertEqual(code, 1)
        self.assertEqual(r.commands_run, 3)
        self.assertFalse(any(s in ln for ln in r.lines for s in ("/dev/$d", "/proc/mtd", "qfprom", "dmesg")),
                         r.lines)

    def test_secboot_and_probe_are_exclusive(self):
        with redirect_stdout(io.StringIO()), unittest.mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                ot.main(["--secboot", "--probe"], out_root=self.tmpdir(), require_tty=False)

    # --- a missing or partial answer must never pass as evidence ---

    def test_failed_command_is_marked_not_evidence_and_the_stop_is_named(self):
        # setup, dt_model, fw_version, sec_qfprom, sec_dmesg run; sbl1_strings hangs
        r = FakeRouter(self.clock, outputs=secboot_outputs(), hang_after=5)
        code, run_dir, out, m = self.run_secboot(r)
        self.assertEqual(code, 1)
        s = (run_dir / "secboot_summary.txt").read_text()
        self.assertIn("sec_qfprom: OK", s)  # collected before the hang
        self.assertIn("sec_dmesg: OK", s)
        self.assertRegex(s, r"sbl1_strings: NOT EVIDENCE: TIMED OUT")
        self.assertIn("appsbl_strings: NOT EVIDENCE: not run", s)
        self.assertIn("run stopped early: TimeoutError", s)

    def test_strings_with_no_partition_is_not_evidence(self):
        s, m, code = self.summary(sbl1_strings="no single mtd named 0:SBL1 in /proc/mtd\n")
        self.assertIn("sbl1_strings: NOT EVIDENCE", s)
        self.assertIn("could not be read", s)
        self.assertEqual(code, 1)

    def test_partial_read_warns(self):
        w = ot.check_warnings("appsbl_strings", "size: 2097152\nbytes read: 4096\nx\n", 0)
        self.assertTrue(any("read only 4096 of 2097152" in x for x in w), w)
        w = ot.check_warnings("appsbl_strings", "size: 5\nbytes read: 5\nTR-FAILED rc=1\n", 0)
        self.assertTrue(any("tr) failed" in x for x in w), w)
        w = ot.check_warnings("appsbl_strings", "size: 5\nbytes read: 5\ntr: read error: I/O\n", 0)
        self.assertTrue(any("tool error" in x for x in w), w)
        w = ot.check_warnings("appsbl_strings", "bytes read: 5\nabcdef\n", 0)
        self.assertTrue(any("size is unknown" in x for x in w), w)
        for body in ("device: /dev/mtd9\n", "size: 0\nbytes read: 0\n"):
            w = ot.check_warnings("appsbl_strings", body, 0)
            self.assertTrue(any("could not be read" in x for x in w), (body, w))
        # the firmware's own "not found" text in a full read is fine
        self.assertEqual(ot.check_warnings("appsbl_strings", "size: 5\nbad_blocks: 0\necc_failures before: 0\n"
                                           "bytes read: 5\nnot found\necc_failures after: 0\n", 0), [])
        w = ot.check_warnings("appsbl_strings", "size: 5\nbad_blocks: 3\necc_failures before: 1\n"
                                                "bytes read: 5\nabcdef\necc_failures after: 2\n", 0)
        self.assertTrue(any("3 bad block" in x for x in w), w)
        self.assertTrue(any("1 ECC failure" in x for x in w), w)
        w = ot.check_warnings("appsbl_strings", "size: 5\nbad_blocks: unknown\nbytes read: 5\nabcdef\n", 0)
        self.assertTrue(any("bad-block count is unknown" in x for x in w), w)
        self.assertTrue(any("ECC-failure count is unknown" in x for x in w), w)
        w = ot.check_warnings("appsbl_strings", "size: 5\nbad_blocks: 0\necc_failures before: 0\n"
                                                "bytes read: 5\necc_failures after: 0\n", 0)
        self.assertTrue(any("no strings found" in x for x in w), w)

    def test_unknown_fuse_state_warns(self):
        for body in (f"== {QF}\nabsent\nqfprom values read: 0\n", f"== {QF}\nabsent\n",
                     f"{QF}/authenticate: cat: read error: Input/output error (rc=1)\nqfprom values read: 0\n"):
            w = ot.check_warnings("sec_qfprom", body, 0)
            self.assertTrue(any("UNKNOWN" in x for x in w), (body, w))
        s, m, code = self.summary(sec_qfprom=f"== {QF}\nabsent\nqfprom values read: 0\n")
        self.assertIn("fuse state: UNKNOWN", s)
        self.assertEqual(code, 1)
        # a store-only attribute is skipped, not a failure, as long as authenticate was read
        self.assertEqual(ot.check_warnings(
            "sec_qfprom", f"{QF}/sec_auth: (write-only, skipped)\n{QF}/authenticate: 1 (rc=0)\n"
                          "qfprom values read: 1\n", 0), [])
        # other files reading fine never stand in for authenticate
        for auth in ("(write-only, skipped)", "(empty, rc=0)", "cat: read error: Permission denied (rc=1)"):
            body = f"{QF}/authenticate: {auth}\n{QF}/version: 0x3 (rc=0)\nqfprom values read: 1\n"
            w = ot.check_warnings("sec_qfprom", body, 0)
            self.assertTrue(any("UNKNOWN" in x for x in w), (auth, w))
            s = ot.secboot_summary({"commands": {"sec_qfprom": {"rc": 0, "output": body}}, "warnings": w})
            self.assertIn("fuse state: UNKNOWN", s)

    def test_stopped_is_not_taken_from_an_outer_handler(self):
        r = FakeRouter(self.clock, outputs=secboot_outputs())
        try:
            raise ValueError("outer")
        except ValueError:
            code, run_dir, out, m = self.run_secboot(r)
        self.assertNotIn("run stopped early", (run_dir / "secboot_summary.txt").read_text())

    @unittest.skipUnless(shutil.which("sh") and shutil.which("find"), "needs sh and find")
    def test_dmesg_and_find_lines_report_failure_in_real_sh(self):
        import subprocess  # nosec B404 - runs a local sh on test fixtures only
        shim = self.tmpdir() / "dmesg.sh"  # a failing dmesg, run with sh so it needs no exec bit
        shim.write_text("echo 'dmesg: klogctl: Operation not permitted'\nexit 1\n", newline="\n")
        cmd = ot.SECBOOT_COMMANDS["sec_dmesg"]
        self.assertIn("$(dmesg 2>&1)", cmd)
        cmd = cmd.replace("$(dmesg 2>&1)", f"$(sh {shim.as_posix()} 2>&1)")
        out = subprocess.run([shutil.which("sh"), "-c", cmd], capture_output=True,
                             text=True, check=False).stdout  # nosec B603
        self.assertIn("dmesg rc=1", out)
        self.assertTrue(ot.check_warnings("sec_dmesg", out, 0))
        missing = (self.tmpdir() / "nope").as_posix()
        cmd = ot.SECBOOT_COMMANDS["sec_sysfs_find"].replace("/sys /proc/device-tree/", missing)
        out = subprocess.run([shutil.which("sh"), "-c", cmd], capture_output=True, text=True,
                             check=False).stdout  # nosec B603
        self.assertRegex(out, r"find rc=[1-9]")
        self.assertTrue(ot.check_warnings("sec_sysfs_find", out, 0))

    def test_summary_without_a_warnings_list(self):
        s = ot.secboot_summary({"commands": {}})
        self.assertIn("fuse state: UNKNOWN", s)
        self.assertIn("== All warnings\n(none)", s)

    @unittest.skipUnless(shutil.which("sh"), "needs a POSIX sh")
    def test_qfprom_line_in_real_sh(self):
        root = self.tmpdir()
        q = root / "qfprom" / "qfprom0"
        q.mkdir(parents=True)
        (q / "authenticate").write_text("1\n")
        (q / "version").write_text("0x3\n")
        (q / "uevent").write_text("DRIVER=qfprom\n")
        (q / "spare").write_text("")
        out = self._sh(ot.SECBOOT_COMMANDS["sec_qfprom"].replace("/sys/devices/system/qfprom",
                                                                (root / "qfprom").as_posix()), root)
        self.assertIn("/authenticate: 1 (rc=0)", out)
        self.assertIn("qfprom values read: 2", out)  # authenticate and version; uevent skipped
        self.assertNotIn("/uevent:", out)
        self.assertIn("/spare: (empty, rc=0)", out)
        self.assertEqual(ot.check_warnings("sec_qfprom", out, 0), [])

    def test_failed_find_and_dmesg_warn(self):
        self.assertTrue(ot.check_warnings("sec_sysfs_find", "find: unrecognized: -iname\nfind rc=1\n", 0))
        self.assertTrue(ot.check_warnings("sec_sysfs_find", "", 0))
        self.assertTrue(ot.check_warnings("sec_dmesg", "dmesg rc=1\nfirst line: dmesg: klogctl\ngrep-done\n", 0))
        w = ot.check_warnings("sec_dmesg", "dmesg rc=0\nfirst line: [ 4021.2] eth0 up\ngrep-done\n", 0)
        self.assertTrue(any("wrapped" in x for x in w), w)
        self.assertEqual(ot.check_warnings(
            "sec_dmesg", "dmesg rc=0\nfirst line: <6>[    0.000000] Booting Linux on CPU 0\ngrep-done\n", 0), [])
        # 0.000000 lines after a slight wrap still lose "Booting Linux"
        w = ot.check_warnings("sec_dmesg", "dmesg rc=0\nfirst line: [    0.000000] Memory: 512MB\n", 0)
        self.assertTrue(any("wrapped" in x for x in w), w)
        w = ot.check_warnings("sec_dmesg", "dmesg rc=0\nsh: awk: not found\ngrep-done\n", 0)
        self.assertTrue(any("awk" in x for x in w), w)

    def test_bad_blocks_in_kernel_partition_warn(self):
        w = ot.check_warnings("kernel_head", "bad_blocks: 2\n00000000  ff ff\n", 0)
        self.assertTrue(any("bad block" in x for x in w), w)
        w = ot.check_warnings("kernel_head", "bad_blocks: unknown\n00000000  17\n", 0)
        self.assertTrue(any("unknown" in x for x in w), w)
        self.assertEqual(ot.check_warnings("kernel_head", "bad_blocks: 0\n00000000  17\n", 0), [])

    def test_weak_lines_are_capped_but_secure_boot_lines_never(self):
        weak = [f"bootcmd {i}" for i in range(ot.SECBOOT_MAX_WEAK + 5)]
        m = {"commands": {"appsbl_strings": {"rc": 0, "output": "\n".join(weak + ["secure boot on"])}},
             "warnings": []}
        s = ot.secboot_summary(m)
        self.assertIn("... and 5 more", s)
        self.assertIn("secure boot on", s)
        self.assertNotIn(f"bootcmd {ot.SECBOOT_MAX_WEAK}\n", s)

    def test_summary_error_never_replaces_the_run_error(self):
        r = FakeRouter(self.clock, outputs=secboot_outputs(), hang_after=5)
        with unittest.mock.patch.object(ot, "secboot_summary", side_effect=KeyError("boom")):
            code, run_dir, out, m = self.run_secboot(r)
        self.assertEqual(code, 1)
        self.assertIn("TimeoutError", m["error"])
        self.assertTrue(any("could not make or write secboot_summary.txt" in w for w in m["warnings"]))

    # --- the real shell lines ---

    def _sh(self, cmd, root):
        import os
        import subprocess  # nosec B404 - runs a local sh on test fixtures only
        cmd = (cmd.replace("/proc/mtd", (root / "mtd").as_posix())
               .replace("/sys/class/mtd", (root / "sys").as_posix())
               .replace("/dev/$d", (root / "dev").as_posix() + "/$d"))
        r = subprocess.run([shutil.which("sh"), "-c", cmd], capture_output=True, text=True,
                           env=dict(os.environ), check=False)  # nosec B603
        return r.stdout + r.stderr

    def _fixture(self, data, size=None):
        root = self.tmpdir()
        (root / "mtd").write_text('mtd9: 00200000 00020000 "0:APPSBL"\n'
                                  'mtd10: 00200000 00020000 "0:APPSBL_1"\n')
        (root / "sys" / "mtd9").mkdir(parents=True)
        (root / "sys" / "mtd9" / "size").write_text(f"{len(data) if size is None else size}\n")
        (root / "sys" / "mtd9" / "bad_blocks").write_text("0\n")
        (root / "sys" / "mtd9" / "ecc_failures").write_text("0\n")
        (root / "dev").mkdir()
        if data is not None:
            (root / "dev" / "mtd9").write_bytes(data)
        return root

    @unittest.skipUnless(shutil.which("sh") and shutil.which("tr") and shutil.which("wc"),
                         "needs sh, tr and wc")
    def test_strings_pipeline_in_real_sh(self):
        data = b"\x00\x01bootcmd=bootipq\x00ab\x00\xffsecure boot on\xfe"
        out = self._sh(ot.SECBOOT_COMMANDS["appsbl_strings"], self._fixture(data))
        lines = out.splitlines()
        self.assertIn("size: 37", lines, out)
        self.assertIn("bytes read: 37", lines)
        self.assertIn("bootcmd=bootipq", lines)
        self.assertIn("secure boot on", lines)
        self.assertNotIn("ab", lines)  # under 6 characters
        self.assertEqual(ot.check_warnings("appsbl_strings", out, 0), [])

    @unittest.skipUnless(shutil.which("sh") and shutil.which("tr") and shutil.which("wc"),
                         "needs sh, tr and wc")
    def test_strings_pipeline_with_a_missing_device_warns_in_real_sh(self):
        out = self._sh(ot.SECBOOT_COMMANDS["appsbl_strings"], self._fixture(None, size=2097152))
        w = ot.check_warnings("appsbl_strings", out, 0)
        self.assertTrue(any("could not be read" in x for x in w), (out, w))
        self.assertTrue(any("TR-FAILED" in out or "tool error" in x for x in w), (out, w))

    @unittest.skipUnless(shutil.which("sh") and shutil.which("tr") and shutil.which("wc"),
                         "needs sh, tr and wc")
    def test_strings_pipeline_with_a_short_device_warns_in_real_sh(self):
        out = self._sh(ot.SECBOOT_COMMANDS["appsbl_strings"], self._fixture(b"abcdefgh", size=2097152))
        w = ot.check_warnings("appsbl_strings", out, 0)
        self.assertTrue(any("read only 8 of 2097152" in x for x in w), (out, w))


if __name__ == "__main__":
    unittest.main()
