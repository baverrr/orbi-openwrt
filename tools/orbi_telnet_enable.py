"""Unlock telnet on the Orbi RBR10 by sending the Netgear 'telnetenable' UDP magic packet.

You run this yourself in a real terminal, because it needs your Orbi admin password; the
password is read with getpass (never shown, never stored, never on the command line) and is
used only to build the local packet that is sent to the router. Nothing is written to disk.

Usage:  python -I orbi_telnet_enable.py [HOST] [MAC] [USER]
Defaults: HOST 192.168.1.1, USER admin. Pass your unit's br0 MAC (the wired LAN side) as the 2nd arg.
The MAC must be the RBR10's br0 MAC: telnetenable checks it and silently drops a mismatch.
Don't pass another device's MAC by mistake.

Only the crypto (genhash) is taken from tools/vendor/netgear_telnet_enable.py, a reviewed
verbatim copy of bkerler/netgear_telnet (MIT), confirmed to work on Orbi firmware V2.7.5.6 (this
unit). The UDP send and the reply handling are done here, so success/failure is reported straight:
  - a reply containing "ACK"  -> telnet unlocked (we stop there)
  - some other reply          -> the router answered but didn't ACK (wrong password form, usually)
  - no reply in the timeout    -> nothing came back; wrong IP/MAC, router off, or a silent firmware
After a successful unlock, run orbi_telnet.py to capture the recon.
"""
import getpass
import importlib.util
import pathlib
import socket
import sys
from hashlib import sha256

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"
MAC = sys.argv[2] if len(sys.argv) > 2 else "XX:XX:XX:XX:XX:XX"  # placeholder: pass your unit's br0 MAC as argv[2]
USER = sys.argv[3] if len(sys.argv) > 3 else "admin"

MAX_PW = 0x40  # genhash() asserts len(password) <= 64 chars; we pre-check (in bytes, stricter) to warn clearly

# Load the vendored crypto module by path (importing runs only class/function defs, no side effects).
_vendor = pathlib.Path(__file__).resolve().parent / "vendor" / "netgear_telnet_enable.py"
_spec = importlib.util.spec_from_file_location("netgear_telnet_enable", _vendor)
nte = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nte)


def send_packet(host, packet, timeout=4.0):
    """Send one magic packet over UDP to port 23 and wait for a reply.
    Returns ("ack", reply) | ("other", reply) | ("noreply", None) | ("error", message).
    A connected-UDP send() 'succeeding' proves nothing, so only a real reply is trusted."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, 23))
            s.send(packet)
            try:
                data, _ = s.recvfrom(1024)
            except socket.timeout:
                return "noreply", None
            return ("ack" if b"ACK" in data else "other"), data
    except OSError as e:  # DNS failure, network unreachable, ICMP port-unreachable on recv, etc.
        return "error", str(e)


def main():
    if not sys.stdin.isatty():
        print("Run this in a real terminal: the password prompt needs one to stay hidden.")
        return 2
    mac = MAC.replace(":", "").replace("-", "").upper()
    if len(mac) != 12 or any(c not in "0123456789ABCDEF" for c in mac):
        print(f"{MAC!r} is not a MAC address (want 12 hex digits, e.g. aa:bb:cc:dd:ee:ff); nothing sent.")
        return 2
    if len(USER.encode()) > 0x10:  # genhash checks characters; the packet field is 16 bytes
        print(f"Username is {len(USER.encode())} bytes; the packet holds at most 16. Nothing sent.")
        return 2
    print(f"Unlocking telnet on {HOST} (MAC {mac}, user {USER})...")
    password = getpass.getpass("Orbi admin password (hidden): ")
    if not password:
        print("No password entered; nothing sent.")
        return 2

    # The password forms and payload modes Netgear firmware has used. After the 2026-11-15 factory
    # reset, V2.7.5.6 on this unit ACKed the sha256-upper form (mode 1); the others are kept for
    # other firmware and are harmless (a wrong form just gets no ACK).
    pw_forms = [
        ("plain", password),
        ("sha256-lower", sha256(password.encode()).hexdigest().lower()),
        ("sha256-upper", sha256(password.encode()).hexdigest().upper()),
    ]
    recon = pathlib.Path(__file__).with_name("orbi_telnet.py")
    saw_reply = saw_error = saw_noreply = sent_any = False
    errors = []
    for label, pw in pw_forms:
        if len(pw.encode()) > MAX_PW:
            print(f"  skipped {label} form: {len(pw.encode())} bytes is over the {MAX_PW}-byte limit")
            continue
        for mode in (1, 2, 3):
            try:
                full = nte.genhash(mac, USER, pw, mode=mode)
            except (AssertionError, UnicodeError, ValueError) as e:
                errors.append(f"{label}/mode{mode}: could not build the packet: {e}")
                continue
            for hlen in (0xB0, 0xF8):
                sent_any = True
                result, reply = send_packet(HOST, full[:hlen])
                if result == "ack":
                    print(f"\nRouter ACKed ({label} form, mode {mode}). Telnet is unlocked.")
                    print(f"Now capture recon:  python -I \"{recon}\"")
                    return 0
                if result == "other":
                    saw_reply = True
                elif result == "noreply":
                    saw_noreply = True
                elif result == "error":
                    saw_error = True
                    errors.append(f"{label}/mode{mode} len{hex(hlen)}: {reply}")

    # No ACK from any attempt: say what we actually saw, so the user can tell the cause apart.
    print("\nNo unlock confirmation (no reply contained 'ACK').")
    if not sent_any:
        print("No packet could be built, so nothing was sent (see the errors below).")
    elif saw_reply:
        # The router answered, so it's reachable; telnet was NOT unlocked, so don't point at recon.
        print("The router replied but didn't ACK: the password form it wants wasn't among those tried,")
        print("or the password is wrong. Re-run with the admin password used for the Orbi web login.")
    elif saw_error and not saw_noreply:  # every packet errored at the socket, nothing timed out
        print(f"Every packet to {HOST}:23 errored (see below): a wrong IP or DNS name, an unreachable")
        print("network, or telnet/UDP refused or filtered. Check the IP and that telnet isn't blocked.")
    else:
        print(f"Nothing replied from {HOST}. Check the IP and MAC, that the router is on, and that the")
        print("ACER is on the Orbi's LAN. Some firmware unlocks silently, so you can still try:")
        print(f"  python -I \"{recon}\"")
    if errors:
        print("\nAttempts that couldn't build or send a packet:")
        for e in errors:
            print(f"  {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
