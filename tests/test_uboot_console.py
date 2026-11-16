"""Tests for tools/uboot_console.py with a fake U-Boot on a fake port. No cable needed.

Run:  python -I -m unittest discover -s tests   (from the orbi-openwrt folder)
"""
import io
import json
import pathlib
import shutil
import signal
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import uboot_console as uc  # noqa: E402

PROMPT = b"(IPQ40xx) # "
NEVER = object()  # an answer that never comes


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t


class FakeUBoot:
    """Prints a boot up to the autoboot line, stops on the key, answers commands (echo, answer,
    prompt), in chunks of `chunk` bytes."""

    DEFAULTS = {"tftpboot": b"Bytes transferred = 7679668 (752eb4 hex)",
                "ping": b"host 192.168.1.10 is alive"}

    def __init__(self, clock, stops=True, answers=None, boot_delay=1.0, chunk=4096,
                 after_key=b"\r\n" + PROMPT, bootm=b"## Booting kernel ...\r\nStarting kernel ...\r\n"
                       b"[    0.000000] Linux version 6.6.73\r\n"
                       b"Please press Enter to activate this console.\r\n"):
        self.clock, self.stops = clock, stops
        self.answers = answers or {}
        self.pending = b""
        self.sent = []
        self.closed = False
        self.access = "read/write"
        self.boot_at, self.booted = boot_delay, False
        self.chunk, self.after_key, self.bootm = chunk, after_key, bootm

    def read(self, n):
        self.clock.t += 0.1
        if not self.booted and self.clock.t >= self.boot_at:
            self.booted = True
            self.pending += b"U-Boot 2012.07\r\nHit any key to stop autoboot:  1 "
        out, self.pending = self.pending[:self.chunk], self.pending[self.chunk:]
        return out

    def write(self, data):
        self.sent.append(data)
        if data == uc.STOP_KEY:
            if self.stops:
                self.pending += self.after_key
            return
        cmd = data.decode().rstrip("\r")
        word = cmd.split()[0]
        if word == "bootm":
            self.pending += cmd.encode() + b"\r\n" + self.bootm
            return
        ans = self.answers.get(cmd, self.answers.get(word, self.DEFAULTS.get(word, b"ok")))
        if ans is NEVER:
            return
        self.pending += cmd.encode() + b"\r\n" + ans + b"\r\n" + PROMPT

    def close(self):
        self.closed = True


class Base(unittest.TestCase):
    def run_main(self, argv=(), port=None, finder=lambda: "COM4", **kw):
        clock = FakeClock()
        port = port or FakeUBoot(clock, **kw)
        port.clock = clock
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        buf = io.StringIO()
        code = uc.main(list(argv), out_root=root, opener=lambda n, b: port,
                       finder=finder, clock=clock, out=buf)
        runs = list(root.iterdir())
        m = json.loads((runs[0] / "manifest.json").read_text()) if runs else None
        return code, port, m, buf.getvalue(), runs[0] if runs else None


class AllowlistTests(unittest.TestCase):
    def test_allowed(self):
        for c in ("printenv", "printenv bootcmd", "version", "bdinfo", "help", "help tftpboot",
                  "setenv ipaddr 192.168.1.1", "setenv serverip 192.168.1.10",
                  "setenv bootargs console=ttyMSM0,115200n8",
                  "setenv bootargs console=ttyMSM0,115200n8 earlycon=msm_serial_dm,0x78af000",
                  "setenv fdt_high 0x87000000",
                  "tftpboot 0x84000000 openwrt-initramfs.itb", "bootm 0x84000000#config@1",
                  "md 0x84000000 40", "md.l 0x9fff0000 0x100", "ping 192.168.1.10"):
            self.assertTrue(uc.allowed(c), c)

    def test_refused(self):
        for c in ("saveenv", "nand erase 0x0 0x100000", "nand write 0x84000000 0x0 0x100",
                  "sf erase 0 100", "mmc write 0 0 0", "fw_recovery", "boot_partition_set 1",
                  "setenv bootcmd run x", "setenv ipaddr 1.2.3.4; saveenv",
                  "setenv bootargs console=ttyMSM0,115200n8 init=/bin/sh",
                  "setenv bootargs console=ttyMSM0,115200n8; saveenv", "setenv bootargs",
                  "setenv bootargs ubi.mtd=ubi root=/dev/ubiblock0_0",
                  "setenv bootargs console=ttyMSM1,115200n8",
                  "setenv bootargs earlycon=msm_serial_dm,0x78af000",
                  "setenv bootargs console=ttyMSM0,115200n8 earlycon=msm_serial_dm,0x78b0000",
                  "setenv bootargs console=ttyMSM0,115200n8 earlycon=msm_serial_dm,0x78af000 "
                  "init=/bin/sh",
                  "setenv fdt_high 0xffffffff", "setenv fdt_high 0x87000000; saveenv",
                  "setenv fdt_high", "setenv initrd_high 0x87000000",
                  "setenv fdt_high 0x87e00000", "setenv fdt_high 0x9fffffff",
                  "setenv fdt_high 0x87000001", "setenv fdt_high 0x870000000",
                  "setenv bootargs console=ttyMSM0,9600n8",
                  "setenv bootargs console=ttyMSM0,115200n8 earlycon=uart8250,0x78af000",
                  "printenv && saveenv", "run bootcmd", "reset", "env default -a",
                  "tftpboot 0x84000000 ../x; nand erase", "bootm 0x84000000; saveenv", "",
                  "printenv\rsaveenv", "printenv\nsaveenv", "setenv ipaddr 1.2.3.4\rsaveenv",
                  "version\n", " version", "version ",
                  "ping 1.2.3.٤", "md 0x84000000 １", "setenv ipaddr ١.2.3.4",
                  "tftpboot 0x07980000 x.itb", "tftpboot 0x88000000 x.itb",
                  "bootm 0x00000000", "md 0x07980000", "md 0x84000000 12345",
                  "md.l 0x9fff0000 0xffff", "md 0x9fffffff", "md.b 0x9fffffff 2",
                  "md 0x84000000", "md;b 0x84000000 40", "mdxl 0x84000000 40",
                  "md.q 0x84000000 40"):
            self.assertFalse(uc.allowed(c), ascii(c))


class RunTests(Base):
    def test_look_only_pass(self):
        code, port, m, out, run_dir = self.run_main(answers={"printenv": b"bootcmd=bootipq"})
        self.assertEqual(code, 0, out)
        self.assertEqual(port.sent[0], uc.STOP_KEY)
        self.assertEqual(port.sent[1:], [c.encode() + b"\r" for c in uc.LOOK_ONLY])
        self.assertTrue(m["autoboot_stopped"])
        self.assertEqual(m["prompt"], "(IPQ40xx) # ")
        self.assertEqual(m["stopped_by"], "done")
        self.assertTrue(port.closed)
        self.assertIn("bootcmd=bootipq", (run_dir / "boot.log").read_text())

    def test_every_byte_sent_is_the_key_or_an_allowed_command(self):
        cmds = ["version", "setenv ipaddr 192.168.1.1", "md 0x84000000 10", "printenv"]
        code, port, m, out, _ = self.run_main([x for c in cmds for x in ("--cmd", c)])
        self.assertEqual(code, 0, out)
        for data in port.sent:
            self.assertTrue(data == uc.STOP_KEY or uc.allowed(data.decode()[:-1]), data)
        self.assertEqual([s["data"] for s in m["sent"]], [" "] + [c + "\r" for c in cmds])

    def test_prompt_split_across_reads_is_still_found(self):
        code, port, m, out, _ = self.run_main(["--cmd", "version", "--cmd", "printenv"], chunk=3)
        self.assertEqual(code, 0, out)
        self.assertEqual(len(port.sent), 3)

    def test_prompt_like_text_in_output_is_not_the_prompt(self):
        # "x # " looks like a prompt but isn't the learned one, so printenv waits for the real one.
        code, port, m, out, run_dir = self.run_main(
            ["--cmd", "printenv", "--cmd", "version"],
            answers={"printenv": b"a=1\r\nx # \r\nb=2"}, chunk=5)
        self.assertEqual(code, 0, out)
        self.assertIn("b=2", (run_dir / "boot.log").read_text())

    def test_disallowed_command_is_refused_before_the_port_opens(self):
        buf = io.StringIO()
        code = uc.main(["--cmd", "printenv", "--cmd", "saveenv"],
                       opener=lambda n, b: self.fail("opened"), finder=lambda: "COM4", out=buf)
        self.assertEqual(code, 2)
        self.assertIn("'saveenv'", buf.getvalue())

    def test_unicode_digit_is_refused_before_the_port_opens(self):
        buf = io.StringIO()
        code = uc.main(["--cmd", "ping 1.2.3.٤"], opener=lambda n, b: self.fail("opened"),
                       finder=lambda: "COM4", out=buf)
        self.assertEqual(code, 2)

    def test_bootm_must_be_last(self):
        buf = io.StringIO()
        code = uc.main(["--cmd", "bootm 0x84000000", "--cmd", "printenv"],
                       opener=lambda n, b: self.fail("opened"), finder=lambda: "COM4", out=buf)
        self.assertEqual(code, 2)
        self.assertIn("bootm must be the last", buf.getvalue())

    def test_bad_numbers_are_refused(self):
        for argv in (["--wait", "0"], ["--listen", "inf"], ["--cmd-timeout", "nan"],
                     ["--baud", "0"]):
            with self.assertRaises(SystemExit):
                with unittest.mock.patch("sys.stderr", io.StringIO()):
                    uc.main(argv, opener=lambda n, b: self.fail("opened"), out=io.StringIO())

    def test_no_answer_to_the_key_stops_and_sends_nothing_more(self):
        code, port, m, out, _ = self.run_main(stops=False)
        self.assertEqual(code, 1)
        self.assertEqual(port.sent, [uc.STOP_KEY])
        self.assertIn("leave pin 4 alone", m["error"])

    def test_linux_prompt_after_a_late_key_is_not_u_boot(self):
        code, port, m, out, _ = self.run_main(
            after_key=b"Starting kernel ...\r\nPlease press Enter\r\nroot@RBR10:/# ")
        self.assertEqual(code, 1)
        self.assertEqual(port.sent, [uc.STOP_KEY])
        self.assertIn("came too late", m["error"])

    def test_no_autoboot_line(self):
        code, port, m, out, _ = self.run_main(["--wait", "2"], boot_delay=1000)
        self.assertEqual(code, 1)
        self.assertEqual(port.sent, [])
        self.assertIn("no 'Hit any key", m["error"])

    def test_command_that_never_returns_stops_the_run(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "version", "--cmd", "printenv", "--cmd-timeout", "3"],
            answers={"version": NEVER})
        self.assertEqual(code, 1)
        self.assertEqual(port.sent, [uc.STOP_KEY, b"version\r"])
        self.assertIn("Power-cycle", m["error"])

    def test_unknown_command_stops_the_run(self):
        code, port, m, out, _ = self.run_main(["--cmd", "smeminfo", "--cmd", "printenv"],
                                              answers={"smeminfo": b"Unknown command 'smeminfo'"})
        self.assertEqual(code, 1)
        self.assertEqual(port.sent[-1], b"smeminfo\r")

    def test_failed_tftp_never_reaches_bootm(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000#config@1"],
            answers={"tftpboot": b"TFTP from server 192.168.1.10\r\nRetry count exceeded"})
        self.assertEqual(code, 1)
        self.assertNotIn(b"bootm 0x84000000#config@1\r", port.sent)
        self.assertIn("tftpboot 0x84000000 x.itb' failed", m["error"])

    def test_tftp_then_bootm_listens_after(self):
        code, port, m, out, run_dir = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000#config@1",
             "--listen", "5"])
        self.assertEqual(code, 0, out)
        self.assertEqual(port.sent[-1], b"bootm 0x84000000#config@1\r")
        self.assertTrue(m["kernel_started"])
        self.assertEqual(m["stopped_by"], "done")

    def test_long_kernel_log_after_bootm_still_counts_as_started(self):
        kernel = b"## Booting kernel ...\r\nStarting kernel ...\r\nLinux version 6.6\r\n" + b"".join(
            b"[  %4d.000] some driver error line %d\r\n" % (i, i) for i in range(400)) + \
            b"Please press Enter to activate this console.\r\n"
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000", "--listen", "60"],
            bootm=kernel, chunk=512)
        self.assertEqual(code, 0, out)
        self.assertTrue(m["kernel_started"])
        self.assertTrue(m["reached_userspace"])

    def test_hang_after_linux_version_is_not_success(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000", "--listen", "5"],
            bootm=b"Starting kernel ...\r\nLinux version 6.6\r\nsome driver probe\r\n")
        self.assertEqual(code, 1)
        self.assertTrue(m["kernel_output"])
        self.assertFalse(m["reached_userspace"])
        self.assertIn("Please press Enter", m["error"])

    def test_silent_kernel_is_recorded_and_names_missing_bootargs(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000", "--listen", "5"],
            bootm=b"Loading Device Tree to 871e7000, end 871eee5d ... OK\r\nStarting kernel ...\r\n")
        self.assertEqual(code, 1)
        self.assertIs(m["kernel_output"], False)
        self.assertEqual(m["fdt_addr"], "0x871e7000")
        self.assertIn("didn't set bootargs", m["error"])

    def test_dtb_above_fdt_high_fails(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "setenv fdt_high 0x87000000", "--cmd", "tftpboot 0x84000000 x.itb",
             "--cmd", "bootm 0x84000000", "--listen", "5"],
            answers={"setenv": b""},
            bootm=b"Loading Device Tree to 871e7000, end 871eee5d ... OK\r\nStarting kernel ...\r\n"
                  b"Linux version 6.6\r\nPlease press Enter to activate this console.\r\n")
        self.assertEqual(code, 1)
        self.assertIn("above the fdt_high", m["error"])

    def test_garbled_bootm_echo_is_not_success(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000", "--listen", "5"],
            port=None, bootm=b"")
        self.assertEqual(code, 1)  # sanity: an empty reply is a failure too

        port = FakeUBoot(FakeClock())
        real = port.write

        def write(data):
            if data.startswith(b"bootm"):
                port.sent.append(data)
                port.pending += (b"boot 0x84000000\r\nStarting kernel ...\r\nLinux version 3.14\r\n"
                                 b"Please press Enter to activate this console.\r\n")
                return
            real(data)
        port.write = write
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000"], port=port)
        self.assertEqual(code, 1)
        self.assertIn("echoed 'boot 0x84000000'", m["error"])

    def test_fdt_creation_failure_stops_at_once(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000", "--listen", "100"],
            bootm=b"FDT creation failed! hanging...### ERROR ### Please RESET the board ###\r\n")
        self.assertEqual(code, 1)
        self.assertIn("refused", m["error"])
        self.assertLess(port.clock.t, 50)

    def test_dtb_below_fdt_high_passes(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "setenv fdt_high 0x87000000", "--cmd", "tftpboot 0x84000000 x.itb",
             "--cmd", "bootm 0x84000000", "--listen", "5"],
            answers={"setenv": b""},
            bootm=b"Loading Device Tree to 86ff7000, end 86ffee5d ... OK\r\nStarting kernel ...\r\n"
                  b"Linux version 6.6\r\nPlease press Enter to activate this console.\r\n")
        self.assertEqual(code, 0, out)
        self.assertEqual(m["fdt_addr"], "0x86ff7000")

    def test_garbled_echo_stops_the_run(self):
        port = FakeUBoot(FakeClock())
        real = port.write

        def write(data):
            if data.startswith(b"setenv"):
                port.sent.append(data)
                port.pending += b"setenv fdt_hgh 0x87000000\r\n" + PROMPT
                return
            real(data)
        port.write = write
        code, port, m, out, _ = self.run_main(
            ["--cmd", "setenv fdt_high 0x87000000", "--cmd", "printenv"], port=port)
        self.assertEqual(code, 1)
        self.assertIn("echoed", m["error"])
        self.assertNotIn(b"printenv\r", port.sent)

    def test_bootm_needs_a_tftpboot_first(self):
        buf = io.StringIO()
        code = uc.main(["--cmd", "bootm 0x84000000"], opener=lambda n, b: self.fail("opened"),
                       finder=lambda: "COM4", out=buf)
        self.assertEqual(code, 2)
        self.assertIn("needs a tftpboot", buf.getvalue())

    def test_reset_after_bootm_is_not_success(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000", "--listen", "10"],
            bootm=b"## Booting kernel ...\r\nmust RESET board to recover\r\nresetting ...\r\n"
                  b"U-Boot 2012.07\r\nHit any key to stop autoboot:  1\r\nStarting kernel ...\r\n")
        self.assertEqual(code, 1)
        self.assertIn("reset or started again", m["error"])
        self.assertFalse(m["kernel_started"])

    def test_silent_kernel_is_not_success(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000", "--listen", "5"],
            bootm=b"## Booting kernel ...\r\nStarting kernel ...\r\n")
        self.assertEqual(code, 1)
        self.assertIn("no 'Linux version'", m["error"])

    def test_kernel_panic_is_not_success(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000", "--listen", "10"],
            bootm=b"Starting kernel ...\r\nLinux version 6.6\r\nKernel panic - not syncing\r\n")
        self.assertEqual(code, 1)
        self.assertIn("Kernel panic", m["error"])

    def test_prompt_like_boot_fragment_is_a_late_key(self):
        code, port, m, out, _ = self.run_main(after_key=b"\r\n## ")
        self.assertEqual(code, 1)
        self.assertEqual(port.sent, [uc.STOP_KEY])
        self.assertIn("came too late", m["error"])

    def test_error_text_fails_a_setenv(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "setenv bootargs console=ttyMSM0,115200n8", "--cmd", "printenv"],
            answers={"setenv": b"## Error: Can't overwrite"})
        self.assertEqual(code, 1)
        self.assertNotIn(b"printenv\r", port.sent)

    def test_help_may_print_usage(self):
        code, port, m, out, _ = self.run_main(["--cmd", "help tftpboot"],
                                              answers={"help": b"Usage:\ntftpboot [loadAddress]"})
        self.assertEqual(code, 0, out)

    def test_filename_word_in_the_echo_is_not_a_failure(self):
        code, port, m, out, _ = self.run_main(["--cmd", "tftpboot 0x84000000 abort.itb"])
        self.assertEqual(code, 0, out)

    def test_tftp_filename_and_retry_are_not_failures(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 abort.itb"],
            answers={"tftpboot": b"Filename 'abort.itb'.\r\nRetry count exceeded; starting again"
                                 b"\r\nFilename 'abort.itb'.\r\nBytes transferred = 7679656"})
        self.assertEqual(code, 0, out)

    def test_tftp_error_after_success_fails(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb"],
            answers={"tftpboot": b"Bytes transferred = 5\r\nTFTP error: 'File not found'"})
        self.assertEqual(code, 1)

    def test_md_dump_text_is_not_a_failure(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "md.b 0x84000000 10"],
            answers={"md.b": b"84000000: 55 73 61 67 65 3a  Usage:\r\n84000010: ## Error"})
        self.assertEqual(code, 0, out)

    def test_md_usage_on_its_first_line_fails(self):
        code, port, m, out, _ = self.run_main(["--cmd", "md.b 0x84000000 10"],
                                              answers={"md.b": b"Usage:\nmd [.b, .w, .l]"})
        self.assertEqual(code, 1)

    def test_oops_after_start_is_not_success(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000", "--listen", "10"],
            bootm=b"Starting kernel ...\r\nLinux version 6.6\r\nUnable to handle kernel NULL\r\n")
        self.assertEqual(code, 1)
        self.assertIn("Unable to handle kernel", m["error"])

    def test_ctrl_c_before_the_port_opens_still_writes_a_manifest(self):
        def finder():
            signal.raise_signal(signal.SIGINT)
            return "COM4"
        code, port, m, out, _ = self.run_main(finder=finder)
        self.assertEqual(code, 1)
        self.assertEqual(m["stopped_by"], "Ctrl+C")
        self.assertEqual(port.sent, [])
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)

    def test_md_limits(self):
        for c in ("md.l 0x84000001 4", "md.w 0x84000001 1", "md 0x87e00000 1",
                  "md.b 0x87dfffff 2", "md 0x87fffffc 1", "md 0x84000000 0", "md 0x84000000 401",
                  "md 0x9ffffffd 1", "md.w 0x9fffffff 1", "setenv ipaddr 999.1.1.1",
                  "ping 192.168.1.256", "mw 0x84000000 0 1", "cp.b 0x84000000 0x0 0x100",
                  "md 0x84000000 40; saveenv", "ping 192.168.1.1; saveenv"):
            self.assertFalse(uc.allowed(c), c)
        for c in ("md 0x84000000 400", "md.w 0x9ffffffe 1", "md.b 0x87dfffff 1",
                  "md 0x88000000 1", "setenv netmask 255.255.255.0"):
            self.assertTrue(uc.allowed(c), c)

    def test_md_end_must_be_inside_ram(self):
        self.assertTrue(uc.allowed("md.b 0x9fffffff 1"))
        self.assertTrue(uc.allowed("md.l 0x9ffffff0 4"))
        self.assertFalse(uc.allowed("md.l 0x9ffffff0 5"))

    def test_late_key_is_not_blamed_on_the_wiring(self):
        code, port, m, out, _ = self.run_main(after_key=b"\r\nStarting kernel ...\r\nLinux version 3.14\r\n")
        self.assertEqual(code, 1)
        self.assertIn("came too late", m["error"])
        self.assertNotIn("pin 4", m["error"])

    def test_key_during_the_nand_read_is_too_late_not_wiring(self):
        code, port, m, out, _ = self.run_main(
            after_key=b"\r\nLoading DNI firmware for checking...\r\nNAND read: device 0\r\n")
        self.assertEqual(code, 1)
        self.assertIn("came too late", m["error"])

    def test_bootm_back_at_the_prompt_is_a_failure(self):
        code, port, m, out, _ = self.run_main(
            ["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000", "--listen", "5"],
            bootm=b"## Booting kernel ...\r\nWrong Image Format for bootm command\r\n" + PROMPT)
        self.assertEqual(code, 1)
        self.assertFalse(m["kernel_started"])
        self.assertIn("refused", m["error"])

    def test_bootm_with_no_kernel_start_is_a_failure(self):
        code, port, m, out, _ = self.run_main(["--cmd", "tftpboot 0x84000000 x.itb", "--cmd", "bootm 0x84000000", "--listen", "3"],
                                              bootm=b"## Booting kernel ...\r\n")
        self.assertEqual(code, 1)
        self.assertIn("no 'Starting kernel'", m["error"])

    def test_ctrl_c_keeps_the_chunk_and_is_not_success(self):
        clock = FakeClock()
        port = FakeUBoot(clock)
        real = port.read

        def read(n):
            data = real(n)
            if data and b"Hit any key" in data:
                signal.raise_signal(signal.SIGINT)
            return data
        port.read = read
        code, port, m, out, run_dir = self.run_main(port=port)
        self.assertEqual(code, 1)
        self.assertEqual(m["stopped_by"], "Ctrl+C")
        self.assertIn("Hit any key", (run_dir / "boot.log").read_text())
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)

    def test_port_error_still_writes_the_files(self):
        clock = FakeClock()
        port = FakeUBoot(clock)

        def boom(n):
            raise OSError("device gone")
        port.read = boom
        code, port, m, out, run_dir = self.run_main(port=port)
        self.assertEqual(code, 1)
        self.assertEqual(m["stopped_by"], "port or file error")
        self.assertTrue((run_dir / "summary.txt").exists())
        self.assertTrue(port.closed)

    def test_crash_still_writes_the_manifest(self):
        clock = FakeClock()
        port = FakeUBoot(clock)

        def boom(n):
            raise ValueError("bug")
        port.read = boom
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        with self.assertRaises(ValueError):
            uc.main([], out_root=root, opener=lambda n, b: port, finder=lambda: "COM4",
                    clock=clock, out=io.StringIO())
        m = json.loads((next(root.iterdir()) / "manifest.json").read_text())
        self.assertEqual(m["stopped_by"], "crashed")
        self.assertTrue(port.closed)

    def test_run_folder_failure_closes_the_port(self):
        clock = FakeClock()
        port = FakeUBoot(clock)
        buf = io.StringIO()
        with unittest.mock.patch.object(uc.sl, "make_run_dir", side_effect=PermissionError("no")):
            code = uc.main([], opener=lambda n, b: port, finder=lambda: "COM4", clock=clock,
                           out=buf)
        self.assertEqual(code, 1)
        self.assertTrue(port.closed)
        self.assertIn("Can't save the run", buf.getvalue())


class SessionTests(unittest.TestCase):
    def session(self):
        clock = FakeClock()
        port = FakeUBoot(clock)
        cap = uc.sl.Capture(io.BytesIO(), io.StringIO())
        return uc.Session(port, cap, {}, clock), port

    def test_send_command_checks_the_allowlist_itself(self):
        s, port = self.session()
        s.prompt = "(IPQ40xx) # "
        with self.assertRaises(ValueError):
            s.send_command("saveenv")
        self.assertEqual(port.sent, [])

    def test_no_command_before_the_prompt(self):
        s, port = self.session()
        with self.assertRaises(ValueError):
            s.send_command("version")
        self.assertEqual(port.sent, [])

    def test_partial_write_is_still_recorded(self):
        s, port = self.session()
        s.prompt = "(IPQ40xx) # "

        def fail(data):
            raise OSError("short write")
        port.write = fail
        with self.assertRaises(OSError):
            s.send_command("version")
        self.assertEqual(s.sent, [{"t": s.sent[0]["t"], "data": "version\r", "failed": True}])


if __name__ == "__main__":
    unittest.main()
