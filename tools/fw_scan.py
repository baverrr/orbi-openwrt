"""List the known blocks inside a firmware image (a tiny binwalk). Read-only.

Usage: python -I fw_scan.py IMAGE

Sizes are printed as each format reports them: uImage = payload (excludes the 64-byte
header), squashfs = bytes_used, FDT = totalsize. A block whose size field runs past the end
of the file is still listed, with a "size overruns file" note, because that usually means a
truncated download rather than no such block.
"""
import struct
import sys

# magic -> (name, min bytes needed after the offset to read this entry's fields)
MAGICS = {
    b"\xd0\x0d\xfe\xed": ("FDT/FIT (device tree or FIT image)", 8),
    b"\x27\x05\x19\x56": ("U-Boot uImage", 64),
    b"UBI#": ("UBI erase-counter header", 4),
    b"hsqs": ("squashfs (little-endian)", 48),
    b"\xfd7zXZ\x00": ("xz", 6),
}


def main(path):
    data = open(path, "rb").read()
    print(f"{path}: {len(data)} bytes")
    hits = []
    for magic, (name, _) in MAGICS.items():
        start = 0
        while (i := data.find(magic, start)) >= 0:
            hits.append((i, name, MAGICS[magic][1]))
            start = i + 1
    for off, name, need in sorted(hits):
        avail = len(data) - off
        if avail < need:
            print(f"0x{off:08x}  {name}  (truncated: only {avail} bytes to end of file)")
            continue
        note = ""
        if name.startswith("FDT"):
            total = struct.unpack(">I", data[off + 4:off + 8])[0]
            if total < 64:
                continue  # too small to be a real FDT; a false-positive magic
            if total > avail:
                note = f" size={total} (size overruns file by {total - avail} bytes)"
            else:
                note = f" size={total}"
        elif name.startswith("U-Boot"):
            size = struct.unpack(">I", data[off + 12:off + 16])[0]
            nm = data[off + 32:off + 64].split(b"\0")[0].decode("latin1")
            # No CRC is checked, so a coincidental magic can show garbage; flag an impossible size.
            over = " (size overruns file)" if size > avail else ""
            note = f" size={size} name={nm!r}{over}"
        elif name.startswith("squashfs"):
            size = struct.unpack("<Q", data[off + 40:off + 48])[0]
            if size > avail:
                note = f" size={size} (size overruns file by {size - avail} bytes)"
            else:
                note = f" size={size}"
        elif name.startswith("UBI"):
            if off % 4096:
                # UBI PEB headers sit on erase-block boundaries; an unaligned one is usually noise.
                note = f" (unaligned at 0x{off:x}, likely a false positive)"
        print(f"0x{off:08x}  {name}{note}")


if __name__ == "__main__":
    main(sys.argv[1])
