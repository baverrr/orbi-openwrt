"""Unpack a FIT image's parts and print every device tree as DTS-like text. Read-only on the input.

Usage: python -I fdt_dump.py IMAGE OFFSET OUTDIR
  IMAGE   firmware .img     OFFSET  where the FIT starts (e.g. 0xa8)     OUTDIR  where to write
Writes OUTDIR/fit.txt (the FIT's own tree), OUTDIR/<image>.bin for each part,
and OUTDIR/<image>.dts for each part that is itself a device tree.
"""
import pathlib
import struct
import sys

FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9


def parse(blob):
    """Return the tree as nested dicts: {"props": {name: bytes}, "children": {name: node}}."""
    magic, total, off_struct, off_strings = struct.unpack(">IIII", blob[:16])
    if magic != 0xD00DFEED:
        raise ValueError("not a device tree")
    strings = blob[off_strings:]
    pos = off_struct
    root, stack = None, []
    while True:
        tok = struct.unpack(">I", blob[pos:pos + 4])[0]
        pos += 4
        if tok == FDT_BEGIN_NODE:
            end = blob.index(b"\0", pos)
            name = blob[pos:end].decode("latin1") or "/"
            pos = (end + 4) & ~3
            node = {"props": {}, "children": {}}
            if stack:
                stack[-1]["children"][name] = node
            else:
                root = node
            stack.append(node)
        elif tok == FDT_END_NODE:
            stack.pop()
        elif tok == FDT_PROP:
            length, nameoff = struct.unpack(">II", blob[pos:pos + 8])
            pos += 8
            pname = strings[nameoff:strings.index(b"\0", nameoff)].decode("latin1")
            stack[-1]["props"][pname] = blob[pos:pos + length]
            pos = (pos + length + 3) & ~3
        elif tok == FDT_NOP:
            continue
        elif tok == FDT_END:
            return root
        else:
            raise ValueError(f"bad token {tok} at {pos - 4}")


def fmt(value):
    if not value:
        return None
    parts = value.split(b"\0")
    if value.endswith(b"\0") and all(p and all(32 <= c < 127 for c in p) for p in parts[:-1]):
        return ", ".join(f'"{p.decode()}"' for p in parts[:-1])
    if len(value) % 4 == 0 and len(value) <= 256:
        return "<" + " ".join(f"0x{v:x}" for v in struct.unpack(f">{len(value) // 4}I", value)) + ">"
    if len(value) > 256:
        return f"[{len(value)} bytes]"
    return "[" + " ".join(f"{c:02x}" for c in value) + "]"


def dump(node, name="/", indent=0):
    pad = "\t" * indent
    lines = [f"{pad}{name} {{"]
    for k, v in node["props"].items():
        f = fmt(v)
        lines.append(f"{pad}\t{k};" if f is None else f"{pad}\t{k} = {f};")
    for cname, child in node["children"].items():
        lines += dump(child, cname, indent + 1)
    lines.append(f"{pad}}};")
    return lines


def safe_name(name, out):
    """A filename for an image, taken only from its basename, guaranteed to stay inside `out`.
    The FIT comes from untrusted firmware, so a node named '../x' or '/etc/x' must not escape."""
    base = pathlib.PurePosixPath(name.replace("\\", "/")).name  # drop any directory part
    if not base or base in (".", ".."):
        base = "unnamed"
    target = (out / base).resolve()
    if out.resolve() not in target.parents and target != out.resolve():
        raise ValueError(f"refusing to write outside {out}: image name {name!r}")
    return base


def get_node(fit, name):
    """Return the named child node, or None with a printed warning if it's missing."""
    node = fit["children"].get(name)
    if node is None:
        print(f"WARNING: no '{name}' node in the FIT")
    return node


def main(image, offset, outdir):
    data = pathlib.Path(image).read_bytes()
    off = int(offset, 0)
    total = struct.unpack(">I", data[off + 4:off + 8])[0]
    fit = parse(data[off:off + total])
    out = pathlib.Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "fit.txt").write_text("\n".join(dump(fit)) + "\n", encoding="utf-8")

    images = get_node(fit, "images")
    for name, img in (images["children"].items() if images else []):
        safe = safe_name(name, out)
        blob = img["props"].get("data", b"")
        # FIT images built with external data (mkimage -E) keep the bytes outside the tree.
        if not blob and any(k in img["props"] for k in ("data-size", "data-position", "data-offset")):
            print(f"{name}: external-data image, bytes are outside the FIT and NOT extracted "
                  f"(data-size={fmt(img['props'].get('data-size', b''))})")
            continue
        (out / f"{safe}.bin").write_bytes(blob)
        desc = img["props"].get("description", b"").rstrip(b"\0").decode("latin1")
        kind = img["props"].get("type", b"").rstrip(b"\0").decode("latin1")
        line = f"{name}: type={kind} desc={desc!r} size={len(blob)}"
        if blob[:4] == b"\xd0\x0d\xfe\xed":
            tree = parse(blob)
            (out / f"{safe}.dts").write_text("\n".join(dump(tree)) + "\n", encoding="utf-8")
            model = tree["props"].get("model", b"").rstrip(b"\0").decode("latin1")
            line += f" model={model!r}"
        print(line)

    configs = get_node(fit, "configurations")
    if configs:
        default = configs["props"].get("default", b"").rstrip(b"\0").decode("latin1")
        if default:
            print(f"config default: {default}")
        for name, conf in configs["children"].items():
            props = {k: v.rstrip(b"\0").decode("latin1") for k, v in conf["props"].items()}
            print(f"config {name}: {props}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
