"""A read-only TFTP server for the RBR10's RAM boot: it serves one file, and nothing else.

Usage:  python -I tftp_serve.py --bind 192.168.100.10 --file build\\test.itb [--sha256 HEX]
            [--client 192.168.100.1] [--port 69] [--timeout 2] [--retries 4] [--wait 600] [--keep]

What it does: U-Boot's `tftpboot 0x84000000 <name>` asks for <name>; if <name> is exactly the
file's own name (no folders), this sends it in plain 512-byte blocks (RFC 1350). Everything
else is refused: write requests (WRQ) get "access violation", other names get "file not found",
and any mode but octet gets an error. It never writes a file and never reads one other than
--file, which it reads once, at start, into memory.

Why so plain: any options in the request (timeout, blksize, ...) are ignored and answered with
plain DATA, which RFC 2347 allows; the client then falls back to 512-byte blocks. This server does
no block-number rollover (old U-Boots handle it badly), so the 16-bit block number allows 65535
blocks: the largest file is 65535 * 512 - 1 = 33,553,919 bytes (just under 32 MiB), and bigger
ones are refused. A file whose size is an exact multiple of 512 ends with an empty block, or U-Boot never
sees the end and never prints "Bytes transferred".

Retries: a block is resent after --timeout seconds without its ACK, up to --retries times. A
repeated ACK of the previous block is ignored (RFC 1350: resending on it is what starts the
"sorcerer's apprentice" doubling); the timeout does the resending. U-Boot 2012.07 ignores a
block it already has without ACKing it again and re-ACKs only on its own ~5 s timeout, so a lost
ACK is only recovered if --timeout * (--retries + 1) is more than that: under 6 s is refused.

Network: --bind must be one address on the cable NIC (never 0.0.0.0). The laptop's Wi-Fi owns
192.168.1.0/24, so put the cable on its own subnet (for example 192.168.100.10/24 on the NIC and
`setenv ipaddr 192.168.100.1; setenv serverip 192.168.100.10` in U-Boot), or replies leave over
Wi-Fi. Windows drops a static address while the link is down (the router power-cycling), so the
bind is retried until --wait runs out, the address is re-checked every few seconds while
listening, and a socket that loses its address is reopened. Python can't switch off Windows'
UDP "connection reset" reports (SIO_UDP_CONNRESET isn't exposed), so ConnectionResetError is
caught wherever we read; on the transfer socket it is counted, as a sign U-Boot's port is gone.

Exit: 0 = the last transfer had every block acknowledged; 3 = all of it was sent but the last ACK
never came (U-Boot may still have it all; check its "Bytes transferred" line); 1 = error;
2 = bad arguments; 4 = --wait ran out with neither of those; 130 = Ctrl+C. A failed transfer
doesn't stop it (U-Boot retries). Without --keep it stops after the first transfer that reached
the last block; with --keep it runs until --wait. Either way the exit code is about the LAST
transfer, because U-Boot writes blocks into RAM as they arrive: a later failed transfer leaves a
damaged image even after an earlier good one. On Ctrl+C or an error it logs every result first,
and says so if a transfer was cut off. Use --client with --keep, so a transfer to some other
host on the link can't count as U-Boot's.
"""
import argparse
import hashlib
import ipaddress
import math
import pathlib
import socket
import struct
import sys
import time

RRQ, WRQ, DATA, ACK, ERROR = 1, 2, 3, 4, 5
ERR_UNDEFINED, ERR_NOT_FOUND, ERR_ACCESS, ERR_ILLEGAL, ERR_UNKNOWN_TID = 0, 1, 2, 4, 5
BLOCK = 512
MAX_BLOCKS = 0xFFFF
MAX_SIZE = MAX_BLOCKS * BLOCK - 1  # the largest file that fits in 65535 blocks, the last one short
RECV_BUF = 65536  # bigger than any UDP datagram: Windows raises WSAEMSGSIZE for a too-small buffer
MAX_REQUEST = 512 + 4  # RFC 1350 requests and ACKs are small; anything bigger is junk
UBOOT_REACK_S = 5.0  # U-Boot 2012.07's own TFTP timeout, after which it re-sends its last ACK
MIN_WINDOW_S = 6.0
PROBE_EVERY_S = 5.0
WSAEMSGSIZE, WSAEADDRINUSE, WSAEADDRNOTAVAIL, WSAEACCES = 10040, 10048, 10049, 10013
EXIT_OK, EXIT_ERROR, EXIT_ARGS, EXIT_NO_LAST_ACK, EXIT_NO_TRANSFER, EXIT_INTERRUPTED = 0, 1, 2, 3, 4, 130


def console_log(line):
    """print() that can't take the server down: non-ASCII becomes escapes (a cp1252 pipe can't
    encode everything), and a closed stdout is ignored."""
    try:
        print(line.encode("ascii", "backslashreplace").decode("ascii"), flush=True)
    except (OSError, ValueError):
        pass


class BadPacket(ValueError):
    """A request we can't parse; it gets an ERROR reply, never a crash."""


def opcode(data):
    return struct.unpack("!H", data[:2])[0] if len(data) >= 2 else None


def parse_request(data):
    """RRQ/WRQ packet -> (opcode, filename, mode). Options after the mode are ignored."""
    if len(data) < 4:
        raise BadPacket("packet too short")
    op = opcode(data)
    if op not in (RRQ, WRQ):
        raise BadPacket(f"opcode {op} is not a request")
    parts = data[2:].split(b"\0")
    if len(parts) < 3 or not parts[0] or not parts[1]:  # name \0 mode \0 [...], so 3+ parts
        raise BadPacket("request has no filename or mode")
    try:
        name, mode = parts[0].decode("ascii"), parts[1].decode("ascii").lower()
    except UnicodeDecodeError:
        raise BadPacket("filename or mode is not ASCII") from None
    return op, name, mode


def parse_ack(data):
    """ACK packet -> block number, or None for anything that isn't a well-formed ACK."""
    if len(data) != 4:
        return None
    op, block = struct.unpack("!HH", data)
    return block if op == ACK else None


def data_packet(block, payload):
    return struct.pack("!HH", DATA, block) + payload


def error_packet(code, message):
    return struct.pack("!HH", ERROR, code) + message.encode("ascii", "replace") + b"\0"


def error_text(data):
    return data[4:].split(b"\0")[0].decode("ascii", "backslashreplace")


def block_count(size):
    """Blocks needed for `size` bytes, counting the short (maybe empty) last block."""
    return size // BLOCK + 1


def check_file(payload, expected_sha256=None):
    """Return the payload's sha256; raise ValueError if it's too big or the hash is wrong."""
    if len(payload) > MAX_SIZE:
        raise ValueError(f"file is {len(payload)} bytes; this server (no block rollover) caps it at {MAX_SIZE}")
    digest = hashlib.sha256(payload).hexdigest()
    if expected_sha256 and digest != expected_sha256.strip().lower():
        raise ValueError(f"sha256 is {digest}, not the expected {expected_sha256.strip().lower()}")
    return digest


def check_bind(addr):
    """--bind must be one real IPv4 address, never a wildcard or broadcast."""
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        raise ValueError(f"--bind {addr!r} is not an IPv4 address") from None
    if ip.is_unspecified or ip == ipaddress.IPv4Address("255.255.255.255") or ip.is_multicast:
        raise ValueError(f"--bind {addr} would listen on every interface; give the cable NIC's address")
    return str(ip)


def check_name(name):
    """U-Boot asks in ASCII with no spaces; a name it can't send could never be served."""
    if not name.isascii() or not name.isprintable() or " " in name:
        raise ValueError(f"--file name {name!r} must be plain ASCII with no spaces")
    return name


def open_socket(addr, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((addr, port))
    except OSError:
        sock.close()
        raise
    return sock


def _addr_gone(exc):
    return getattr(exc, "winerror", None) == WSAEADDRNOTAVAIL or exc.errno in (99, 49)  # Linux, macOS


def _oversized(exc):
    return getattr(exc, "winerror", None) == WSAEMSGSIZE


def address_present(addr):
    """True if `addr` is still on this PC (a throwaway bind to it works)."""
    try:
        open_socket(addr, 0).close()
        return True
    except OSError as exc:
        # Anything but "address gone" is no proof it went away; the read loop will see real trouble.
        return not _addr_gone(exc)


class Transfer:
    """Send one file to one client from a fresh socket (its own TID), in lockstep."""

    def __init__(self, sock, client, payload, timeout, retries, log, clock=time.monotonic):
        self.sock, self.client, self.payload = sock, client, payload
        self.timeout, self.retries, self.log, self.clock = timeout, retries, log, clock
        if len(payload) > MAX_SIZE:
            raise ValueError(f"payload of {len(payload)} bytes needs block-number rollover")
        self.blocks = block_count(len(payload))
        self.resets = 0

    def _send(self, block):
        start = (block - 1) * BLOCK
        self.sock.sendto(data_packet(block, self.payload[start:start + BLOCK]), self.client)

    def _tell_stranger(self, src):
        """Someone else's packet on our TID: tell them (RFC 1350) and keep going, whatever happens."""
        try:
            self.sock.sendto(error_packet(ERR_UNKNOWN_TID, "unknown transfer ID"), src)
        except OSError as exc:
            self.log(f"  (couldn't answer stray packet from {src[0]}:{src[1]}: {exc})")

    def run(self):
        """Return 'acked' (every block acknowledged), 'no-last-ack' (all sent and every block
        but the last acknowledged) or 'failed: <why>'."""
        block = 0
        try:
            for block in range(1, self.blocks + 1):
                result = self._one_block(block)
                if result:
                    return result
        except OSError as exc:
            return f"failed: network error at block {block} of {self.blocks}: {exc}"
        return "acked"

    def _one_block(self, block):
        self._send(block)
        sends, self.resets = 1, 0
        deadline = self.clock() + self.timeout
        while True:
            remaining = deadline - self.clock()
            if remaining <= 0:
                if sends > self.retries:
                    if block == self.blocks and block > 1:
                        return "no-last-ack"
                    why = f"no ACK for block {block} of {self.blocks} after {sends} sends"
                    if self.resets:
                        why += f" (client port unreachable x{self.resets})"
                    return f"failed: {why}"
                self._send(block)
                sends += 1
                deadline = self.clock() + self.timeout
                continue
            self.sock.settimeout(remaining)
            try:
                data, src = self.sock.recvfrom(RECV_BUF)
            except socket.timeout:
                continue
            except ConnectionResetError:
                self.resets += 1
                continue
            except OSError as exc:
                if _oversized(exc):
                    continue
                raise
            if src != self.client:
                if opcode(data) != ERROR:  # never answer an ERROR (RFC 1350)
                    self._tell_stranger(src)
                continue
            if opcode(data) == ERROR:
                return f"failed: client sent an error at block {block}: {error_text(data)}"
            if parse_ack(data) == block:
                return None
            # an old ACK again (U-Boot's own timeout) or junk: ignored; our timeout resends


def _reply(sock, src, packet, log):
    try:
        sock.sendto(packet, src)
    except OSError as exc:
        log(f"{src[0]}:{src[1]}: couldn't send the refusal: {exc}")


def handle_request(sock, data, src, name, bind_addr, payload, args, log, transfer_cls=Transfer):
    """Answer one packet on the listening socket. Return None when no transfer ran, or the
    transfer's result string."""
    who = f"{src[0]}:{src[1]}"
    if opcode(data) in (DATA, ACK, ERROR):
        log(f"{who}: ignored a stray {('DATA', 'ACK', 'ERROR')[opcode(data) - DATA]} on the request port")
        return None  # never answer an ERROR (RFC 1350), nor a late ACK/DATA
    try:
        op, req_name, mode = parse_request(data)
    except BadPacket as exc:
        log(f"{who}: refused, {exc}")
        _reply(sock, src, error_packet(ERR_ILLEGAL, str(exc)), log)
        return None
    if op == WRQ:
        log(f"{who}: refused a write of {req_name!r} (this server never writes)")
        _reply(sock, src, error_packet(ERR_ACCESS, "read-only server"), log)
        return None
    if req_name != name:
        log(f"{who}: refused {req_name!r} (only {name!r} is served)")
        _reply(sock, src, error_packet(ERR_NOT_FOUND, "file not found"), log)
        return None
    if mode != "octet":
        log(f"{who}: refused mode {mode!r} (octet only)")
        _reply(sock, src, error_packet(ERR_UNDEFINED, "octet mode only"), log)
        return None
    log(f"{who}: sending {name} ({len(payload)} bytes, {block_count(len(payload))} blocks)")
    started = time.monotonic()
    try:
        tsock = open_socket(bind_addr, 0)
    except OSError as exc:
        result = f"failed: couldn't open a transfer socket on {bind_addr}: {exc}"
    else:
        try:
            result = transfer_cls(tsock, src, payload, args.timeout, args.retries, log).run()
        finally:
            tsock.close()
    log(f"{who}: {result} after {time.monotonic() - started:.1f} s")
    return result


def drain_repeats(sock, src, log):
    """Drop RRQ resends from `src` that queued up while its transfer ran, so they don't start
    pointless transfers to a port that has moved on. Other packets are kept for the loop."""
    dropped, kept = 0, []
    sock.settimeout(0)
    try:
        while True:
            try:
                data, frm = sock.recvfrom(RECV_BUF)
            except (BlockingIOError, socket.timeout):
                break
            except ConnectionResetError:
                continue
            except OSError as exc:
                if _oversized(exc):
                    continue
                break  # a real socket problem; the loop's own read will see it
            if frm == src and opcode(data) == RRQ:
                dropped += 1
            else:
                kept.append((data, frm))
    finally:
        sock.settimeout(0.5)
    if dropped:
        log(f"{src[0]}:{src[1]}: dropped {dropped} repeat request(s) queued during the transfer")
    return kept


def serve(args, payload, log=console_log, clock=time.monotonic, sleep=time.sleep):
    """The listening loop. Returns an exit code (see the module docstring)."""
    name = pathlib.Path(args.file).name
    end = None if args.wait == 0 else clock() + args.wait
    sock, waiting_said, next_probe, heard = None, False, 0.0, False
    history, ignored_sources, pending = [], set(), []
    in_flight = False  # a transfer is running: if it's cut off, RAM holds a partial image

    def summary():
        if in_flight:
            return ("a transfer was cut off partway, so U-Boot's RAM may hold a partly overwritten"
                    " image: don't bootm it." + (f" Before it: {', '.join(r.split(':')[0] for r in history)}."
                                                  if history else ""))
        if not history:
            return "no transfer ran."
        return (f"{len(history)} transfer(s): " + ", ".join(r.split(":")[0] for r in history)
                + f". The last one is what's in U-Boot's RAM: {history[-1]}")

    def finish():
        # U-Boot writes each block into RAM as it arrives, so a later transfer that failed
        # partway leaves a damaged image even after an earlier good one: report the LAST.
        if not history:
            return EXIT_NO_TRANSFER
        return {"acked": EXIT_OK, "no-last-ack": EXIT_NO_LAST_ACK}.get(history[-1], EXIT_NO_TRANSFER)

    def reopen(quiet):
        nonlocal sock, waiting_said, next_probe, heard
        sock = open_socket(args.bind, args.port)
        if not quiet:
            log(f"Listening on {args.bind}:{args.port} for {name!r}"
                + (f" from {args.client} only" if args.client else "") + ". Ctrl+C stops.")
        waiting_said, next_probe, heard = False, clock() + PROBE_EVERY_S, False

    try:
        while True:
            if end is not None and clock() >= end:
                log(f"--wait {args.wait:g} s ran out: {summary()}")
                return finish()
            if sock is None:
                try:
                    reopen(quiet=False)
                except OSError as exc:
                    if not _addr_gone(exc):
                        raise
                    if not waiting_said:
                        log(f"{args.bind} isn't on this PC right now (link down?); retrying until it is.")
                        waiting_said = True
                    sleep(1.0)
                    continue
            if clock() >= next_probe:
                if not address_present(args.bind):
                    log(f"{args.bind} went away (link down?); reopening when it's back.")
                    sock.close()
                    sock = None
                    continue
                if not heard:
                    # Nothing arrived in the last few seconds. If the address dropped and came
                    # back in between, Windows may leave the old socket deaf, so reopen it. Keep
                    # anything that slipped in just now; one landing in the instant between close
                    # and bind is lost, and U-Boot resends its request after ~5 s.
                    pending.extend(drain_repeats(sock, None, log))
                    sock.close()
                    sock = None
                    try:
                        reopen(quiet=True)
                    except OSError as exc:
                        if not _addr_gone(exc):
                            raise
                        continue
                next_probe, heard = clock() + PROBE_EVERY_S, False
            if pending:
                data, src = pending.pop(0)
            else:
                sock.settimeout(0.5)
                try:
                    data, src = sock.recvfrom(RECV_BUF)
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    continue
                except OSError as exc:
                    if _oversized(exc):
                        continue
                    log(f"Listening socket lost ({exc}); reopening in 1 s.")
                    sock.close()
                    sock = None
                    sleep(1.0)
                    continue
                heard = True
            if len(data) > MAX_REQUEST:
                continue
            if args.client and src[0] != args.client:
                if src[0] not in ignored_sources:
                    log(f"{src[0]}: ignored (not --client {args.client}); further packets from it too")
                    ignored_sources.add(src[0])
                continue
            in_flight = True
            result = handle_request(sock, data, src, name, args.bind, payload, args, log)
            in_flight = False
            if result is None:
                continue
            history.append(result)
            # Drop this client's request resends, both those already pulled into `pending` and
            # those still queued on the socket: they'd start transfers to a port that moved on.
            before = len(pending)
            pending = [(d, f) for d, f in pending if not (f == src and opcode(d) == RRQ)]
            if len(pending) != before:
                log(f"{src[0]}:{src[1]}: dropped {before - len(pending)} repeat request(s) already queued")
            pending.extend(drain_repeats(sock, src, log))
            if result.startswith("failed") or args.keep:
                continue
            if result == "acked":
                log("Done: every block was acknowledged.")
            else:
                log("Every block was sent, but the last ACK never came. U-Boot may still have the"
                    " whole file: check that it printed 'Bytes transferred'.")
            return finish()
    except (KeyboardInterrupt, OSError):
        if history or in_flight:
            log(f"Stopping: {summary()}")
        raise
    finally:
        if sock is not None:
            sock.close()


def build_parser():
    p = argparse.ArgumentParser(description="Read-only, one-file TFTP server for a U-Boot RAM boot.")
    p.add_argument("--bind", required=True, help="the cable NIC's own IPv4 address (never 0.0.0.0)")
    p.add_argument("--file", required=True, help="the one file to serve; asked for by its name alone")
    p.add_argument("--sha256", help="refuse to start unless the file has this sha256")
    p.add_argument("--client", help="answer only this IPv4 address (the router)")
    p.add_argument("--port", type=int, default=69)
    p.add_argument("--timeout", type=float, default=2.0, help="seconds to wait for each ACK (default 2)")
    p.add_argument("--retries", type=int, default=4, help="resends per block after a timeout (default 4)")
    p.add_argument("--wait", type=float, default=600, help="seconds to run in all, 0 = until Ctrl+C (default 600)")
    p.add_argument("--keep", action="store_true", help="keep serving after a transfer, until --wait")
    return p


def check_numbers(args):
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be 1-65535")
    if not (math.isfinite(args.timeout) and 0.05 <= args.timeout <= 30):
        raise ValueError("--timeout must be 0.05-30")
    if not 0 <= args.retries <= 50:
        raise ValueError("--retries must be 0-50")
    if not (math.isfinite(args.wait) and args.wait >= 0):
        raise ValueError("--wait must be 0 (no limit) or more")
    window = args.timeout * (args.retries + 1)
    if window < MIN_WINDOW_S:
        raise ValueError(f"--timeout x (--retries + 1) is {window:g} s; U-Boot re-sends a lost ACK only"
                         f" after ~{UBOOT_REACK_S:g} s, so it must be at least {MIN_WINDOW_S:g} s")


def main(argv=None):
    p = build_parser()
    args = p.parse_args(argv)
    try:
        args.bind = check_bind(args.bind)
        if args.client:
            try:
                client = ipaddress.IPv4Address(args.client)
            except ValueError:
                raise ValueError(f"--client {args.client!r} is not an IPv4 address") from None
            if client.is_unspecified or client.is_multicast or client == ipaddress.IPv4Address("255.255.255.255"):
                raise ValueError(f"--client {args.client} can't be a router's address")
            args.client = str(client)
        check_numbers(args)
        path = pathlib.Path(args.file)
        check_name(path.name)
        if not path.is_file():
            raise ValueError(f"--file {args.file} is not a file")
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"can't read --file {args.file}: {exc}") from None
        digest = check_file(payload, args.sha256)
    except ValueError as exc:
        console_log(f"ERROR: {exc}")
        return EXIT_ARGS
    console_log(f"{path.name}: {len(payload)} bytes, sha256 {digest}"
                + (" (matches --sha256)" if args.sha256 else " (no --sha256 given, not checked)"))
    try:
        return serve(args, payload)
    except KeyboardInterrupt:
        console_log("Stopped (Ctrl+C).")
        return EXIT_INTERRUPTED
    except OSError as exc:
        console_log(f"ERROR: {exc}")
        if getattr(exc, "winerror", None) in (WSAEACCES, WSAEADDRINUSE) or exc.errno in (13, 98):
            console_log("The port is in use or blocked: is another TFTP server (or nmrpflash) running?")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
