"""Tests for tools/orbi_telnet_enable.py (the telnetenable CLI wrapper).

The point of these: a bad or placeholder MAC (or a bad username) must be rejected BEFORE any
magic packet is built or sent. HOST/MAC/USER are read from sys.argv at import time and main()
reads those module globals, so every test sets them explicitly and spies on send_packet so
nothing ever hits the network.

Run:  python -I tests/test_orbi_telnet_enable.py   (from the orbi-openwrt folder)
"""
import io
import pathlib
import sys
import types
import unittest
import unittest.mock
from contextlib import redirect_stdout

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import orbi_telnet_enable as ote  # noqa: E402


class TelnetEnableValidation(unittest.TestCase):
    # nosemgrep: python.lang.security.audit.hardcoded-password-default-argument.hardcoded-password-default-argument -- fake test default in a test helper, not production code
    def run_main(self, *, mac, host="192.168.1.1", user="admin",
                 password="pw",  # nosec B107 - fake, non-empty on purpose (see below)
                 isatty=True, send_result=("noreply", None)):
        """main() with the argv-derived globals set, a tty forced, and send_packet/getpass spied.
        Returns (exit_code, stdout, list-of-send_packet-calls).

        password defaults to a non-empty value on purpose. With an empty password main() bails at
        the "No password entered" guard (code 2, no send) BEFORE building a packet, so a negative
        test asserting only code==2 / sends==[] would pass even if MAC or username validation were
        deleted. A non-empty default lets a validation regression fall through to genhash/send_packet,
        making `sends` non-empty so the test actually fails. Tests that need the empty-password path
        pass password="" explicitly."""
        sends = []

        def fake_send(host_arg, packet, timeout=4.0):
            sends.append((host_arg, packet))
            return send_result

        buf = io.StringIO()
        with unittest.mock.patch.object(ote, "HOST", host), \
                unittest.mock.patch.object(ote, "MAC", mac), \
                unittest.mock.patch.object(ote, "USER", user), \
                unittest.mock.patch.object(ote, "send_packet", fake_send), \
                unittest.mock.patch.object(ote.getpass, "getpass", lambda *a, **k: password), \
                unittest.mock.patch.object(ote.sys, "stdin",
                                           types.SimpleNamespace(isatty=lambda: isatty)), \
                redirect_stdout(buf):
            code = ote.main()
        return code, buf.getvalue(), sends

    # --- the security-relevant guarantee: a bad/placeholder MAC never builds or sends a packet ---

    def test_placeholder_mac_rejected_nothing_sent(self):
        code, out, sends = self.run_main(mac="XX:XX:XX:XX:XX:XX")  # the shipped default
        self.assertEqual(code, 2)
        self.assertIn("is not a MAC address", out)
        self.assertEqual(sends, [])  # no packet built, nothing sent

    def test_malformed_macs_rejected(self):
        for bad in ("aa:bb:cc:dd:ee", "gg:bb:cc:dd:ee:ff", "zz:zz:zz:zz:zz:zz", "", "1234"):
            code, out, sends = self.run_main(mac=bad)
            self.assertEqual(code, 2, bad)
            self.assertEqual(sends, [], bad)
            # Assert the MAC-rejection message, not just the exit code: with a non-empty default
            # password, a missing validation check would fall through to a send instead of this.
            self.assertIn("is not a MAC address", out, bad)

    def test_not_a_tty_refuses_before_anything(self):
        code, out, sends = self.run_main(mac="aa:bb:cc:dd:ee:ff", isatty=False)
        self.assertEqual(code, 2)
        self.assertIn("real terminal", out)
        self.assertEqual(sends, [])

    # --- username byte-length check (stricter than the vendored genhash's character count) ---

    def test_username_over_16_bytes_rejected(self):
        code, out, sends = self.run_main(mac="aa:bb:cc:dd:ee:ff", user="u" * 17)
        self.assertEqual(code, 2)
        self.assertIn("bytes", out)
        self.assertEqual(sends, [])

    def test_multibyte_username_counted_in_bytes(self):
        # 9 x "é" is 9 chars but 18 bytes in UTF-8, so it must be rejected (the byte check, not chars)
        code, out, sends = self.run_main(mac="aa:bb:cc:dd:ee:ff", user="é" * 9)
        self.assertEqual(code, 2)
        # Assert the byte-length message: a char-counting bug would pass validation (9 <= 16) and,
        # with the non-empty default password, reach a send instead of printing this.
        self.assertIn("bytes", out)
        self.assertEqual(sends, [])

    # --- positive controls: a valid MAC gets past validation ---

    def test_valid_mac_empty_password_reaches_getpass(self):
        code, out, sends = self.run_main(mac="aa:bb:cc:dd:ee:ff", password="")  # nosec B106 - fake
        self.assertEqual(code, 2)                 # empty password stops it AFTER validation
        self.assertIn("No password entered", out)
        self.assertEqual(sends, [])

    def test_valid_mac_and_password_sends_and_acks(self):
        code, out, sends = self.run_main(mac="aa:bb:cc:dd:ee:ff", password="pw",  # nosec B106 - fake
                                         send_result=("ack", b"ACK"))
        self.assertEqual(code, 0)
        self.assertTrue(sends)                    # a packet was built and sent
        self.assertIn("ACKed", out)

    # --- the non-ACK outcomes: each failure cause must report its own distinct diagnostic (the
    #     tool's stated purpose) and return 1, not be mislabelled as another cause or as success ---

    def test_reply_without_ack_reports_wrong_password_and_returns_1(self):
        # Router answers every packet but never ACKs: it's reachable, so report "replied but didn't
        # ACK" (wrong password form), return 1, and do NOT claim telnet was unlocked.
        code, out, sends = self.run_main(mac="aa:bb:cc:dd:ee:ff", password="pw",  # nosec B106 - fake
                                         send_result=("other", b"NOPE"))
        self.assertEqual(code, 1)
        self.assertTrue(sends)                    # packets were built and sent
        self.assertIn("didn't ACK", out)
        self.assertNotIn("Telnet is unlocked", out)

    def test_all_sends_error_reports_unreachable_and_returns_1(self):
        # Every packet errors at the socket and nothing times out: report the errored-send cause.
        code, out, sends = self.run_main(mac="aa:bb:cc:dd:ee:ff", password="pw",  # nosec B106 - fake
                                         send_result=("error", "network unreachable"))
        self.assertEqual(code, 1)
        self.assertTrue(sends)                    # packets were built and sent before the diagnostic
        self.assertIn("errored", out)

    def test_no_reply_reports_nothing_replied_and_returns_1(self):
        # Nothing comes back at all: the generic "Nothing replied" branch, return 1.
        code, out, sends = self.run_main(mac="aa:bb:cc:dd:ee:ff", password="pw",  # nosec B106 - fake
                                         send_result=("noreply", None))
        self.assertEqual(code, 1)
        self.assertTrue(sends)                    # packets were built and sent before the diagnostic
        self.assertIn("Nothing replied", out)

    def test_packet_cannot_be_built_reports_and_returns_1(self):
        # If genhash raises for every form/mode, no packet is ever built: say so, return 1, send
        # nothing. Patching genhash to raise drives the `not sent_any` branch that a valid MAC skips.
        with unittest.mock.patch.object(ote.nte, "genhash", side_effect=ValueError("boom")):
            code, out, sends = self.run_main(mac="aa:bb:cc:dd:ee:ff", password="pw")  # nosec B106 - fake
        self.assertEqual(code, 1)
        self.assertIn("No packet could be built", out)
        self.assertEqual(sends, [])               # nothing was sent because nothing could be built


if __name__ == "__main__":
    unittest.main()
