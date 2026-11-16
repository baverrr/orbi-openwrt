"""Tests for tools/tftp_serve.py: packet parsing, real transfers over loopback UDP, Transfer and
the listening loop with fake sockets. No router or cable needed, and nothing binds port 69.

Run:  python -I -m unittest discover -s tests -p test_tftp_serve.py   (from the orbi-openwrt folder)
"""
import argparse
import errno
import hashlib
import io
import math
import pathlib
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import tftp_serve as ts  # noqa: E402

LO = "127.0.0.1"
ROUTER = ("192.168.100.1", 2000)


def rrq(name, mode="octet", op=ts.RRQ, extra=b""):
    return struct.pack("!H", op) + name.encode() + b"\0" + mode.encode() + b"\0" + extra


def ack(block):
    return struct.pack("!HH", ts.ACK, block)


def block_of(data):
    return struct.unpack("!H", data[2:4])[0]


def win_error(code):
    exc = OSError(errno.EINVAL, "fake")
    exc.winerror = code
    return exc


def args_for(**kw):
    base = dict(bind=LO, file="test.itb", sha256=None, client=None, port=0, timeout=0.2,
                retries=3, wait=0, keep=False)
    base.update(kw)
    return argparse.Namespace(**base)


class Parsing(unittest.TestCase):
    def test_rrq_with_options(self):
        self.assertEqual(ts.parse_request(rrq("test.itb", "OCTET", extra=b"blksize\x001468\x00")),
                         (ts.RRQ, "test.itb", "octet"))

    def test_wrq(self):
        self.assertEqual(ts.parse_request(rrq("x", op=ts.WRQ))[0], ts.WRQ)

    def test_bad_requests(self):
        for data in (b"\x00\x01", b"\x00\x01name", b"\x00\x01\x00octet\x00", b"\x00\x01name\x00\x00",
                     b"\x00\x03\x00\x01abc", b"\x00\x01\xff\xfe\x00octet\x00"):
            with self.subTest(data=data), self.assertRaises(ts.BadPacket):
                ts.parse_request(data)

    def test_parse_ack(self):
        self.assertEqual(ts.parse_ack(ack(7)), 7)
        self.assertIsNone(ts.parse_ack(ack(7) + b"x"))
        self.assertIsNone(ts.parse_ack(struct.pack("!HH", ts.DATA, 7)))

    def test_block_count(self):
        self.assertEqual([ts.block_count(n) for n in (0, 1, 511, 512, 1023, 1024)], [1, 1, 1, 2, 2, 3])

    def test_size_cap(self):
        self.assertEqual(ts.block_count(ts.MAX_SIZE), ts.MAX_BLOCKS)
        self.assertEqual(ts.block_count(ts.MAX_SIZE + 1), ts.MAX_BLOCKS + 1)  # would need block 65536
        ts.check_file(b"\0" * 10)
        with self.assertRaises(ValueError):
            ts.check_file(bytes(ts.MAX_SIZE + 1))

    def test_sha256(self):
        digest = hashlib.sha256(b"abc").hexdigest()
        self.assertEqual(ts.check_file(b"abc", " " + digest.upper() + "\n"), digest)
        with self.assertRaises(ValueError):
            ts.check_file(b"abd", digest)

    def test_bind(self):
        self.assertEqual(ts.check_bind("192.168.100.10"), "192.168.100.10")
        # These are the addresses check_bind must REFUSE, not ones we bind.
        for bad in ("0.0.0.0", "255.255.255.255", "224.0.0.1", "abc", "", "::1"):  # nosec B104
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ts.check_bind(bad)

    def test_name(self):
        self.assertEqual(ts.check_name("openwrt-initramfs.itb"), "openwrt-initramfs.itb")
        for bad in ("caf\u00e9.itb", "a b.itb", "x\tz"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ts.check_name(bad)

    def test_error_text_never_breaks_on_odd_bytes(self):
        self.assertEqual(ts.error_text(ts.error_packet(0, "x")[:4] + b"bad \xff\x00"), "bad \\xff")


class ConsoleLog(unittest.TestCase):
    def test_non_ascii_is_escaped(self):
        out = io.StringIO()
        with unittest.mock.patch("sys.stdout", out):
            ts.console_log("caf\u00e9 \ufffd")
        self.assertEqual(out.getvalue(), "caf\\xe9 \\ufffd\n")

    def test_closed_stdout_is_ignored(self):
        with unittest.mock.patch("builtins.print", side_effect=BrokenPipeError()):
            ts.console_log("hello")  # must not raise


class Client:
    """A minimal U-Boot-like client over loopback."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LO, 0))
        self.sock.settimeout(3)

    def recv(self):
        return self.sock.recvfrom(ts.RECV_BUF)

    def close(self):
        self.sock.close()


class Loopback(unittest.TestCase):
    """handle_request on a real listening socket, run in a thread, with a real client."""

    def setUp(self):
        self._fresh()

    def _fresh(self):
        self.listen = ts.open_socket(LO, 0)
        self.port = self.listen.getsockname()[1]
        self.client = Client()
        self.logs, self.result, self.exc = [], None, None

    def tearDown(self):
        self.listen.close()
        self.client.close()

    def start(self, payload, request, name="test.itb", **kw):
        args = args_for(**kw)

        def server():
            try:
                self.listen.settimeout(3)
                data, src = self.listen.recvfrom(ts.RECV_BUF)
                self.result = ts.handle_request(self.listen, data, src, name, LO, payload, args,
                                                self.logs.append)
            except BaseException as exc:  # surfaced by join()
                self.exc = exc

        self.thread = threading.Thread(target=server, daemon=True)
        self.thread.start()
        self.client.sock.sendto(request, (LO, self.port))

    def join(self):
        self.thread.join(10)
        self.assertFalse(self.thread.is_alive(), "server thread hung")
        if self.exc:
            raise self.exc

    def fetch(self, drop_first=False):
        """Ack every block (optionally ignoring the first DATA once); return (bytes, src)."""
        out, expect, dropped = b"", 1, False
        while True:
            data, src = self.client.recv()
            op, block = struct.unpack("!HH", data[:4])
            self.assertEqual(op, ts.DATA)
            if drop_first and not dropped:
                dropped = True
                continue  # no ACK: the server must resend after its timeout
            if block == expect:
                out += data[4:]
                expect += 1
            self.client.sock.sendto(ack(block), src)
            if block == expect - 1 and len(data) - 4 < ts.BLOCK:
                return out, src

    def test_full_transfer(self):
        payload = bytes(range(256)) * 6  # 1536 bytes: 3 full blocks + an empty one
        self.start(payload, rrq("test.itb"))
        got, _ = self.fetch()
        self.join()
        self.assertEqual((got, self.result), (payload, "acked"))

    def test_exact_multiple_ends_with_empty_block(self):
        self.start(b"x" * 1024, rrq("test.itb"))
        sizes = []
        while True:
            data, src = self.client.recv()
            sizes.append(len(data) - 4)
            self.client.sock.sendto(ack(block_of(data)), src)
            if sizes[-1] < ts.BLOCK:
                break
        self.join()
        self.assertEqual(sizes, [512, 512, 0])

    def test_short_file(self):
        self.start(b"hi", rrq("test.itb"))
        got, _ = self.fetch()
        self.join()
        self.assertEqual((got, self.result), (b"hi", "acked"))

    def test_data_comes_from_a_new_port(self):
        self.start(b"hi", rrq("test.itb"))
        _, src = self.fetch()
        self.join()
        self.assertNotEqual(src[1], self.port)

    def assert_refused(self, request, code, name="test.itb"):
        self.start(b"payload", request, name=name)
        data, src = self.client.recv()
        self.join()
        self.assertEqual(struct.unpack("!HH", data[:4]), (ts.ERROR, code))
        self.assertEqual(src[1], self.port)
        self.assertIsNone(self.result)

    def test_write_refused(self):
        self.assert_refused(rrq("test.itb", op=ts.WRQ), ts.ERR_ACCESS)
        self.assertTrue(any("never writes" in line for line in self.logs))

    def test_other_names_refused(self):
        for name in ("other.itb", "../test.itb", "build/test.itb", "TEST.ITB", "test.itb "):
            with self.subTest(name=name):
                self.tearDown()
                self._fresh()
                self.assert_refused(rrq(name), ts.ERR_NOT_FOUND)

    def test_netascii_refused(self):
        self.assert_refused(rrq("test.itb", "netascii"), ts.ERR_UNDEFINED)

    def test_garbage_refused(self):
        self.assert_refused(b"\x00\x09junk", ts.ERR_ILLEGAL)

    def test_error_on_request_port_is_not_answered(self):
        self.start(b"payload", ts.error_packet(0, "hello"))
        self.join()
        self.client.sock.settimeout(0.3)
        with self.assertRaises(socket.timeout):
            self.client.recv()
        self.assertIsNone(self.result)

    def test_resend_after_timeout(self):
        payload = b"y" * 700
        self.start(payload, rrq("test.itb"), timeout=0.2)
        got, _ = self.fetch(drop_first=True)
        self.join()
        self.assertEqual((got, self.result), (payload, "acked"))

    def test_duplicate_ack_is_ignored_and_timeout_resends(self):
        self.start(b"z" * 1500, rrq("test.itb"), timeout=1.0)
        data, src = self.client.recv()          # block 1
        self.client.sock.sendto(ack(1), src)
        data, src = self.client.recv()          # block 2
        self.assertEqual(block_of(data), 2)
        for _ in range(3):                      # three stale ACKs of block 1
            self.client.sock.sendto(ack(1), src)
        self.client.sock.settimeout(0.4)        # well inside the 1 s timeout: nothing comes
        with self.assertRaises(socket.timeout):
            self.client.recv()
        self.client.sock.settimeout(3)
        data, _ = self.client.recv()            # the timeout's resend of block 2
        self.assertEqual(block_of(data), 2)
        self.client.sock.sendto(ack(2), src)
        data, src = self.client.recv()
        self.client.sock.sendto(ack(3), src)
        self.join()
        self.assertEqual(self.result, "acked")

    def test_stranger_gets_unknown_tid_and_transfer_goes_on(self):
        self.start(b"q" * 600, rrq("test.itb"), timeout=1.0)
        data, src = self.client.recv()
        stranger = Client()
        try:
            stranger.sock.sendto(ack(1), src)
            err, _ = stranger.recv()
            self.assertEqual(struct.unpack("!HH", err[:4]), (ts.ERROR, ts.ERR_UNKNOWN_TID))
            stranger.sock.sendto(ts.error_packet(0, "x"), src)  # an ERROR is never answered
            stranger.sock.settimeout(0.3)
            with self.assertRaises(socket.timeout):
                stranger.recv()
        finally:
            stranger.close()
        self.client.sock.sendto(ack(1), src)
        data, src = self.client.recv()
        self.client.sock.sendto(ack(2), src)
        self.join()
        self.assertEqual(self.result, "acked")

    def test_missing_last_ack(self):
        self.start(b"w" * 600, rrq("test.itb"), timeout=0.1, retries=1)
        data, src = self.client.recv()
        self.client.sock.sendto(ack(1), src)
        self.client.recv()  # block 2, never acked
        self.join()
        self.assertEqual(self.result, "no-last-ack")

    def test_one_block_file_with_no_ack_is_a_failure(self):
        self.start(b"hi", rrq("test.itb"), timeout=0.1, retries=1)
        self.client.recv()
        self.join()
        self.assertTrue(self.result.startswith("failed: no ACK for block 1 of 1"), self.result)

    def test_no_ack_midway_fails(self):
        self.start(b"w" * 600, rrq("test.itb"), timeout=0.1, retries=1)
        self.client.recv()
        self.join()
        self.assertTrue(self.result.startswith("failed: no ACK for block 1 of 2"), self.result)

    def test_client_error_stops(self):
        self.start(b"w" * 600, rrq("test.itb"))
        _, src = self.client.recv()
        self.client.sock.sendto(ts.error_packet(0, "abort"), src)
        self.join()
        self.assertEqual(self.result, "failed: client sent an error at block 1: abort")


class FakeTransferSock:
    """A transfer socket: records sends; recvfrom plays a script, then ACKs the last block sent."""

    def __init__(self, script=(), sendto_raises=None):
        self.sent, self.script, self.sendto_raises = [], list(script), sendto_raises

    def settimeout(self, _):
        pass

    def sendto(self, data, dst):
        if self.sendto_raises and self.sendto_raises(data, dst):
            raise OSError(errno.EHOSTUNREACH, "unreachable")
        self.sent.append((data, dst))

    def recvfrom(self, _):
        if self.script:
            item = self.script.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        return ack(block_of(self.sent[-1][0])), ROUTER


class TransferUnits(unittest.TestCase):
    def run_transfer(self, payload, **kw):
        sock = FakeTransferSock(**kw)
        return ts.Transfer(sock, ROUTER, payload, 1.0, 3, lambda _: None).run(), sock

    def test_largest_file_uses_block_65535_and_no_more(self):
        result, sock = self.run_transfer(bytes(ts.MAX_SIZE))
        self.assertEqual(result, "acked")
        blocks = [block_of(d) for d, _ in sock.sent]
        self.assertEqual((len(blocks), blocks[-1], len(sock.sent[-1][0]) - 4), (65535, 65535, 511))

    def test_too_big_payload_refused(self):
        with self.assertRaises(ValueError):
            ts.Transfer(FakeTransferSock(), ROUTER, bytes(ts.MAX_SIZE + 1), 1.0, 3, print)

    def test_oversized_datagram_is_ignored(self):
        result, _ = self.run_transfer(b"a" * 600, script=[win_error(ts.WSAEMSGSIZE)])
        self.assertEqual(result, "acked")

    def test_stranger_reply_failure_does_not_abort(self):
        stranger = ("192.168.100.99", 5)
        result, _ = self.run_transfer(b"a" * 600, script=[(ack(1), stranger)],
                                      sendto_raises=lambda d, dst: dst == stranger)
        self.assertEqual(result, "acked")

    def test_network_error_names_the_block(self):
        result, _ = self.run_transfer(b"a" * 1500, script=[(ack(1), ROUTER), OSError(errno.ENETDOWN, "down")])
        self.assertEqual(result, "failed: network error at block 2 of 3: [Errno %d] down" % errno.ENETDOWN)

    def test_resets_are_counted_in_the_failure(self):
        clock = [0.0]

        def tick():
            clock[0] += 0.6
            return clock[0]

        sock = FakeTransferSock(script=[ConnectionResetError()] * 20)
        result = ts.Transfer(sock, ROUTER, b"a" * 600, 1.0, 1, lambda _: None, clock=tick).run()
        self.assertTrue(result.startswith("failed: no ACK for block 1 of 2"), result)
        self.assertIn("client port unreachable", result)

    def test_exactly_retries_plus_one_sends(self):
        clock = [0.0]

        def tick():
            clock[0] += 0.6
            return clock[0]

        sock = FakeTransferSock(script=[socket.timeout()] * 100)
        result = ts.Transfer(sock, ROUTER, b"a" * 600, 1.0, 3, lambda _: None, clock=tick).run()
        self.assertEqual(result, "failed: no ACK for block 1 of 2 after 4 sends")
        self.assertEqual([block_of(d) for d, _ in sock.sent], [1, 1, 1, 1])


class RealSockets(unittest.TestCase):
    def test_address_present(self):
        self.assertTrue(ts.address_present(LO))
        self.assertFalse(ts.address_present("192.0.2.77"))  # TEST-NET-1, never on this PC

    def test_address_present_other_errors_are_not_gone(self):
        with unittest.mock.patch.object(ts, "open_socket", side_effect=OSError(errno.ENOBUFS, "no buffers")):
            self.assertTrue(ts.address_present(LO))

    def test_drain_repeats_on_a_real_socket(self):
        listen, a, b = ts.open_socket(LO, 0), Client(), Client()
        try:
            port = listen.getsockname()[1]
            for pkt, c in ((rrq("t"), a), (rrq("t"), a), (rrq("t", op=ts.WRQ), a), (rrq("t"), b)):
                c.sock.sendto(pkt, (LO, port))
            time.sleep(0.2)
            logs = []
            kept = ts.drain_repeats(listen, a.sock.getsockname(), logs.append)
            self.assertEqual([(ts.opcode(d), f) for d, f in kept],
                             [(ts.WRQ, a.sock.getsockname()), (ts.RRQ, b.sock.getsockname())])
            self.assertIn("dropped 2 repeat", logs[0])
            self.assertEqual(listen.gettimeout(), 0.5)
        finally:
            listen.close()
            a.close()
            b.close()

    def test_serve_end_to_end(self):
        """The real serve -> handle_request -> Transfer path, with --file in a folder and an RRQ
        that asks for options: plain 512-byte DATA comes back, no OACK."""
        payload = bytes(range(256)) * 9  # 2304 bytes, 5 blocks
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "sub" / "test.itb"
            f.parent.mkdir()
            f.write_bytes(payload)
            args = args_for(file=str(f), timeout=1.0, retries=5, wait=20)
            opened, real_open = [], ts.open_socket

            def recording_open(addr, port):
                s = real_open(addr, port)
                opened.append(s)
                return s

            box, logs = {}, []
            with unittest.mock.patch.object(ts, "open_socket", recording_open):
                th = threading.Thread(target=lambda: box.update(code=ts.serve(args, payload, log=logs.append)),
                                      daemon=True)
                th.start()
                for _ in range(50):
                    if opened:
                        break
                    time.sleep(0.05)
                port = opened[0].getsockname()[1]
                c = Client()
                try:
                    c.sock.sendto(rrq("test.itb", extra=b"blksize\x001468\x00timeout\x005\x00"), (LO, port))
                    out, sizes = b"", []
                    while True:
                        data, src = c.recv()
                        self.assertEqual(ts.opcode(data), ts.DATA)
                        sizes.append(len(data) - 4)
                        out += data[4:]
                        c.sock.sendto(ack(block_of(data)), src)
                        if sizes[-1] < ts.BLOCK:
                            break
                finally:
                    c.close()
                th.join(10)
            self.assertFalse(th.is_alive())
            self.assertEqual((box.get("code"), out, sizes), (ts.EXIT_OK, payload, [512] * 4 + [256]))
            self.assertTrue(any("sending test.itb" in line for line in logs))


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


class FakeListen:
    """A listening socket whose recvfrom plays back a script; each timeout costs 0.5 s."""

    def __init__(self, clock, script):
        self.clock, self.script, self.sent, self.closed = clock, list(script), [], False
        self.timeout = 0.5

    def settimeout(self, t):
        self.timeout = t

    def recvfrom(self, _):
        if self.timeout == 0:  # drain_repeats: only what's queued "now"
            if self.script and not isinstance(self.script[0], (BaseException, str)):
                return self.script.pop(0)
            raise BlockingIOError()
        if not self.script:
            self.clock.t += 0.5
            raise socket.timeout()
        item = self.script.pop(0)
        if item == "later":  # what follows arrives after the transfer, not during it
            self.clock.t += 0.5
            raise socket.timeout()
        if isinstance(item, BaseException):
            raise item
        return item

    def sendto(self, data, dst):
        self.sent.append((data, dst))

    def close(self):
        self.closed = True


class Serve(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.handled = []

    def run_serve(self, opens, results=(), present=True, **kw):
        """opens: what each open_socket(port=69) call gives (a FakeListen or an exception); once
        they run out, the last FakeListen is reopened. wait defaults to 10 s, so a lost packet
        fails the test (exit 4) instead of hanging it."""
        clock, logs = self.clock, []
        opens, results = list(opens), list(results)
        last = [None]
        kw.setdefault("wait", 10)

        self.opened = 0

        def fake_open(addr, port):
            self.opened += 1
            item = opens.pop(0) if opens else last[0]
            if isinstance(item, BaseException):
                raise item
            item.closed = False
            last[0] = item
            return item

        def fake_handle(sock, data, src, *a, **k):
            self.handled.append(src)
            item = results.pop(0) if results else None
            if isinstance(item, BaseException):
                raise item
            return item

        presence = present if callable(present) else (lambda _: present)
        args = args_for(port=69, **kw)
        with unittest.mock.patch.object(ts, "open_socket", fake_open), \
                unittest.mock.patch.object(ts, "handle_request", fake_handle), \
                unittest.mock.patch.object(ts, "address_present", presence):
            code = ts.serve(args, b"x", log=logs.append, clock=clock, sleep=clock.sleep)
        return code, logs

    def req(self, src=ROUTER):
        return (rrq("test.itb"), src)

    def test_done_after_one_transfer(self):
        sock = FakeListen(self.clock, [self.req()])
        code, _ = self.run_serve([sock], ["acked"])
        self.assertEqual(code, ts.EXIT_OK)
        self.assertTrue(sock.closed)

    def test_no_last_ack_has_its_own_exit(self):
        sock = FakeListen(self.clock, [self.req()])
        code, logs = self.run_serve([sock], ["no-last-ack"])
        self.assertEqual(code, ts.EXIT_NO_LAST_ACK)
        self.assertIn("Bytes transferred", logs[-1])

    def test_failed_transfer_keeps_listening_until_wait(self):
        sock = FakeListen(self.clock, [self.req()])
        code, logs = self.run_serve([sock], ["failed: no ACK"], wait=5)
        self.assertEqual(code, ts.EXIT_NO_TRANSFER)
        self.assertIn("U-Boot's RAM: failed: no ACK", logs[-1])

    def test_keep_reports_the_last_transfer_good(self):
        sock = FakeListen(self.clock, [self.req(), "later", self.req(("192.168.100.1", 2001))])
        code, logs = self.run_serve([sock], ["failed: no ACK", "acked"], keep=True, wait=5)
        self.assertEqual(code, ts.EXIT_OK)
        self.assertIn("2 transfer(s): failed, acked", logs[-1])

    def test_keep_a_later_failure_overrides_an_earlier_success(self):
        # RAM now holds a partly overwritten image: exit 0 would wrongly say "go ahead and bootm".
        sock = FakeListen(self.clock, [self.req(), "later", self.req(("192.168.100.1", 2001))])
        code, logs = self.run_serve([sock], ["acked", "failed: no ACK"], keep=True, wait=5)
        self.assertEqual(code, ts.EXIT_NO_TRANSFER)
        self.assertIn("U-Boot's RAM: failed: no ACK", logs[-1])

    def test_repeats_already_in_pending_are_dropped_too(self):
        a, b = ("192.168.100.1", 2000), ("192.168.100.1", 3000)
        sock = FakeListen(self.clock, [self.req(a), self.req(b), self.req(b)])
        code, _ = self.run_serve([sock], ["failed: no ACK", "acked", "failed: x"], keep=True, wait=3)
        self.assertEqual(self.handled, [a, b])
        self.assertEqual(code, ts.EXIT_OK)

    def test_ctrl_c_logs_the_results_first(self):
        sock = FakeListen(self.clock, [self.req(), self.req(("192.168.100.1", 2001))])
        logs, results = [], ["acked", KeyboardInterrupt()]

        def handle(*a, **k):
            item = results.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item

        args = args_for(port=69, keep=True, wait=10)
        with unittest.mock.patch.object(ts, "open_socket", lambda *_: sock), \
                unittest.mock.patch.object(ts, "handle_request", handle), \
                unittest.mock.patch.object(ts, "address_present", lambda _: True), \
                self.assertRaises(KeyboardInterrupt):
            ts.serve(args, b"x", log=logs.append, clock=self.clock, sleep=self.clock.sleep)
        # Ctrl+C landed inside the second transfer: RAM is not the earlier good image any more.
        self.assertIn("cut off partway", logs[-1])
        self.assertIn("don't bootm", logs[-1])
        self.assertIn("Before it: acked", logs[-1])

    def test_ctrl_c_between_transfers_names_the_last_result(self):
        sock = FakeListen(self.clock, [self.req()])
        logs, calls = [], [0]

        def recv_then_stop(_):
            calls[0] += 1
            if calls[0] == 1:
                return self.req()
            raise KeyboardInterrupt()

        sock.recvfrom = recv_then_stop
        args = args_for(port=69, keep=True, wait=10)
        with unittest.mock.patch.object(ts, "open_socket", lambda *_: sock), \
                unittest.mock.patch.object(ts, "handle_request", lambda *a, **k: "acked"), \
                unittest.mock.patch.object(ts, "drain_repeats", lambda *a: []), \
                unittest.mock.patch.object(ts, "address_present", lambda _: True), \
                self.assertRaises(KeyboardInterrupt):
            ts.serve(args, b"x", log=logs.append, clock=self.clock, sleep=self.clock.sleep)
        self.assertIn("Stopping: 1 transfer(s): acked. The last one is what's in U-Boot's RAM: acked", logs[-1])

    def test_quiet_reopen_keeps_a_request_that_just_arrived(self):
        sock = FakeListen(self.clock, [])
        req = self.req()
        orig = sock.recvfrom

        def recv(n):  # the request lands at the 5 s probe, right before the quiet reopen
            if sock.timeout == 0 and self.clock.t >= 5 and req not in self.handled_reqs:
                self.handled_reqs.append(req)
                return req
            return orig(n)

        self.handled_reqs = []
        sock.recvfrom = recv
        code, _ = self.run_serve([sock], ["acked"])
        self.assertEqual((code, self.handled), (ts.EXIT_OK, [ROUTER]))

    def test_quiet_reopen_when_nothing_is_heard(self):
        sock = FakeListen(self.clock, [])
        code, logs = self.run_serve([sock], wait=12)
        self.assertEqual(code, ts.EXIT_NO_TRANSFER)
        self.assertEqual(self.opened, 3)  # at 0 s, then quietly at 5 s and 10 s
        self.assertEqual(sum("Listening on" in line for line in logs), 1)

    def test_bind_that_never_comes_back(self):
        gone = win_error(ts.WSAEADDRNOTAVAIL)
        code, logs = self.run_serve([gone] * 50, wait=3)
        self.assertEqual(code, ts.EXIT_NO_TRANSFER)
        self.assertEqual(sum("isn't on this PC" in line for line in logs), 1)

    def test_keep_with_only_no_last_ack(self):
        sock = FakeListen(self.clock, [self.req()])
        code, _ = self.run_serve([sock], ["no-last-ack"], keep=True, wait=3)
        self.assertEqual(code, ts.EXIT_NO_LAST_ACK)

    def test_repeat_requests_queued_during_a_transfer_are_dropped(self):
        other = ("192.168.100.1", 3000)
        sock = FakeListen(self.clock, [self.req(), self.req(), self.req(), self.req(other)])
        code, logs = self.run_serve([sock], ["failed: no ACK", "acked"])
        self.assertEqual(code, ts.EXIT_OK)
        self.assertEqual(self.handled, [ROUTER, other])  # the two repeats never started a transfer
        self.assertTrue(any("dropped 2 repeat" in line for line in logs))

    def test_client_filter_logs_each_stranger_once(self):
        stranger = ("192.168.1.1", 2000)
        sock = FakeListen(self.clock, [self.req(stranger), self.req(stranger), self.req()])
        code, logs = self.run_serve([sock], ["acked"], client="192.168.100.1")
        self.assertEqual(code, ts.EXIT_OK)
        self.assertEqual(sum("ignored" in line for line in logs), 1)
        self.assertEqual(self.handled, [ROUTER])

    def test_oversized_and_huge_packets_are_skipped(self):
        sock = FakeListen(self.clock, [win_error(ts.WSAEMSGSIZE), (b"\x00\x01" + b"a" * 2000, ROUTER),
                                       self.req()])
        code, _ = self.run_serve([sock], ["acked"])
        self.assertEqual(code, ts.EXIT_OK)
        self.assertEqual(self.handled, [ROUTER])  # the socket stayed open: no "lost" reopen

    def test_bind_retried_while_address_is_gone(self):
        gone = win_error(ts.WSAEADDRNOTAVAIL)
        sock = FakeListen(self.clock, [self.req()])
        code, logs = self.run_serve([gone, gone, gone, sock], ["acked"])
        self.assertEqual(code, ts.EXIT_OK)
        self.assertEqual(sum("isn't on this PC" in line for line in logs), 1)

    def test_other_bind_errors_are_raised(self):
        with self.assertRaises(OSError):
            self.run_serve([OSError(errno.EACCES, "denied")])

    def test_lost_socket_is_reopened_after_a_pause(self):
        first = FakeListen(self.clock, [OSError(errno.ENETDOWN, "network down")])
        second = FakeListen(self.clock, [self.req()])
        code, _ = self.run_serve([first, second], ["acked"])
        self.assertEqual(code, ts.EXIT_OK)
        self.assertTrue(first.closed and second.closed)
        self.assertGreaterEqual(self.clock.t, 1.0)

    def test_a_socket_that_keeps_failing_does_not_spin(self):
        socks = [FakeListen(self.clock, [OSError(errno.ENETDOWN, "down")]) for _ in range(20)]
        code, _ = self.run_serve(socks, wait=5)
        self.assertEqual(code, ts.EXIT_NO_TRANSFER)
        self.assertLessEqual(sum(s.closed for s in socks), 6)  # about one reopen per second

    def test_address_that_vanishes_while_listening_reopens(self):
        first = FakeListen(self.clock, [])
        second = FakeListen(self.clock, [self.req()])
        states = iter([False])
        code, logs = self.run_serve([first, second], ["acked"],
                                    present=lambda _: next(states, True))
        self.assertEqual(code, ts.EXIT_OK)
        self.assertTrue(first.closed)
        self.assertTrue(any("went away" in line for line in logs))

    def test_connreset_is_ignored(self):
        sock = FakeListen(self.clock, [ConnectionResetError(), self.req()])
        code, _ = self.run_serve([sock], ["acked"])
        self.assertEqual(code, ts.EXIT_OK)

    def test_wait_runs_out(self):
        sock = FakeListen(self.clock, [])
        code, _ = self.run_serve([sock], wait=3)
        self.assertEqual(code, ts.EXIT_NO_TRANSFER)
        self.assertGreaterEqual(self.clock.t, 3)


class Main(unittest.TestCase):
    def test_refuses_before_serving(self):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "test.itb"
            f.write_bytes(b"abc")
            odd = pathlib.Path(d) / "caf\u00e9.itb"
            odd.write_bytes(b"abc")
            # The first case is an address main must refuse, not one we bind.
            cases = [["--bind", "0.0.0.0", "--file", str(f)],  # nosec B104
                     ["--bind", LO, "--file", str(f), "--sha256", "00" * 32],
                     ["--bind", LO, "--file", str(pathlib.Path(d) / "missing.itb")],
                     ["--bind", LO, "--file", str(odd)],
                     ["--bind", LO, "--file", str(f), "--client", "nope"],
                     ["--bind", LO, "--file", str(f), "--port", "70000"],
                     ["--bind", LO, "--file", str(f), "--port", "0"],
                     ["--bind", LO, "--file", str(f), "--timeout", "0"],
                     ["--bind", LO, "--file", str(f), "--timeout", "nan"],
                     ["--bind", LO, "--file", str(f), "--wait", "nan"],
                     ["--bind", LO, "--file", str(f), "--wait", "-1"],
                     ["--bind", LO, "--file", str(f), "--timeout", "1", "--retries", "3"],  # 4 s window
                     ["--bind", LO, "--file", str(f), "--retries", "51"],
                     ["--bind", LO, "--file", str(f), "--retries", "-1"],
                     ["--bind", LO, "--file", d],
                     ["--bind", LO, "--file", str(f), "--client", "0.0.0.0"]]  # nosec B104
            with unittest.mock.patch.object(ts, "serve") as serve:
                for argv in cases:
                    with self.subTest(argv=argv), unittest.mock.patch.object(ts, "console_log"):
                        self.assertEqual(ts.main(argv), ts.EXIT_ARGS)
                serve.assert_not_called()

    def test_oversize_file_refused_and_six_second_window_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "test.itb"
            f.write_bytes(b"abc")
            with unittest.mock.patch.object(ts, "serve", return_value=0) as serve, \
                    unittest.mock.patch.object(ts, "console_log"):
                with unittest.mock.patch.object(ts, "MAX_SIZE", 2):
                    self.assertEqual(ts.main(["--bind", LO, "--file", str(f)]), ts.EXIT_ARGS)
                serve.assert_not_called()
                self.assertEqual(ts.main(["--bind", LO, "--file", str(f), "--timeout", "1.5",
                                          "--retries", "3"]), 0)
                serve.assert_called_once()

    def test_unreadable_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "test.itb"
            f.write_bytes(b"abc")
            with unittest.mock.patch.object(pathlib.Path, "read_bytes", side_effect=PermissionError("locked")), \
                    unittest.mock.patch.object(ts, "console_log") as log:
                self.assertEqual(ts.main(["--bind", LO, "--file", str(f)]), ts.EXIT_ARGS)
            self.assertIn("can't read", log.call_args[0][0])

    def test_good_args_reach_serve(self):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "test.itb"
            f.write_bytes(b"abc")
            digest = hashlib.sha256(b"abc").hexdigest()
            with unittest.mock.patch.object(ts, "serve", return_value=0) as serve, \
                    unittest.mock.patch.object(ts, "console_log"):
                self.assertEqual(ts.main(["--bind", LO, "--file", str(f), "--sha256", digest]), 0)
            self.assertEqual(serve.call_args[0][1], b"abc")
            self.assertTrue(math.isclose(serve.call_args[0][0].timeout, 2.0))

    def test_ctrl_c(self):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "test.itb"
            f.write_bytes(b"abc")
            with unittest.mock.patch.object(ts, "serve", side_effect=KeyboardInterrupt), \
                    unittest.mock.patch.object(ts, "console_log"):
                self.assertEqual(ts.main(["--bind", LO, "--file", str(f)]), ts.EXIT_INTERRUPTED)

    def test_port_in_use_hint(self):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "test.itb"
            f.write_bytes(b"abc")
            with unittest.mock.patch.object(ts, "serve", side_effect=win_error(ts.WSAEADDRINUSE)), \
                    unittest.mock.patch.object(ts, "console_log") as log:
                self.assertEqual(ts.main(["--bind", LO, "--file", str(f)]), ts.EXIT_ERROR)
            self.assertIn("in use", log.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
