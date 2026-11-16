#!/bin/sh
# Build the OpenWrt images for the Netgear RBR10 (run from the OpenWrt source root on the build
# machine, detached: setsid nohup ./build-rbr10.sh > build-rbr10.log 2>&1 < /dev/null &).
# It prints exactly one last line: "BUILD OK ..." only if all three images were written by this
# run, are byte-identical to the build's own copies and fit their partitions; otherwise
# "BUILD FAILED (...)", also when the run is killed.
cd "$(dirname "$0")" || { echo "BUILD FAILED (cd)"; exit 1; }

done_ok=0
trap 'rc=$?; [ $done_ok = 1 ] || date "+BUILD FAILED (exit $rc) %F %T"' EXIT
trap 'exit 130' INT TERM HUP

fail() { echo "$1"; exit 1; }

B=bin/targets/ipq40xx/generic/openwrt-ipq40xx-generic-netgear_rbr10
FACTORY=$B-squashfs-factory.img
SYSUP=$B-squashfs-sysupgrade.bin
INITRAMFS=$B-initramfs-zImage.itb
KERNEL_PART=$((0x700000))   # "kernel" partition, = KERNEL_SIZE in the recipe
# "ubi" is 0x2100000 = 264 PEBs of 128 KiB. UBI keeps 4 for itself and 20 for bad blocks, leaving
# 240 LEBs of 0x1f000 bytes for volumes: that is what the rootfs must fit in.
UBI_USABLE=$((240 * 0x1f000))
FW_PART=$((0x2800000))      # stock "firmware" partition, 40 MiB, = IMAGE_SIZE
# To stop a run: kill -TERM -<pid> (the whole process group); killing the script alone leaves make running.

# Move last run's images aside into prev-images/ (outside bin/, so OpenWrt's sha256sums never
# lists them; kept until this run succeeds), and delete the build's own copies too, so an image
# that exists afterwards was written by this run.
PREV=prev-images
mkdir -p "$PREV" || fail "could not make $PREV"
for f in "$FACTORY" "$SYSUP" "$INITRAMFS"; do
  if [ -e "$f" ]; then mv -f "$f" "$PREV/" || fail "could not move $f aside"; fi
done
rm -f build_dir/target-*/linux-ipq40xx_generic/tmp/"$(basename "$B")"-* || fail "could not clear old build copies"

date '+start %F %T'
make download -j8 || fail "download failed"
if ! make -j12; then
  echo "parallel build failed; retrying -j1 V=s to show the error"
  make -j1 V=s || fail "build failed"
fi

KTMP=
for d in build_dir/target-*/linux-ipq40xx_generic/tmp; do
  if [ -f "$d/$(basename "$FACTORY")" ]; then KTMP=$d; break; fi
done
[ -n "$KTMP" ] || fail "no build_dir/.../linux-ipq40xx_generic/tmp holds $(basename "$FACTORY")"

ok=1
is_num() { case $1 in ''|*[!0-9]*) return 1;; esac; }
size_of() { s=$(stat -L -c %s -- "$1" 2>/dev/null) && is_num "$s" && echo "$s"; }

check() {  # bin/ file, max bytes
  f=$1; max=$2
  if [ ! -s "$f" ]; then echo "MISSING or EMPTY: $f"; ok=0; return; fi
  # The bin/ copy is a plain cp whose failure make ignores; compare it with the build's own copy.
  if ! cmp -s "$f" "$KTMP/$(basename "$f")"; then echo "COPY DIFFERS from $KTMP (truncated?): $f"; ok=0; return; fi
  s=$(size_of "$f") || { echo "SIZE UNREADABLE: $f"; ok=0; return; }
  if [ "$s" -gt "$max" ]; then echo "TOO BIG: $f ($s > $max)"; ok=0; return; fi
  echo "ok: $f ($s bytes)"
}

check "$FACTORY" $((FW_PART + 128 + 1))       # 40 MiB body + 128-byte DNI header + 1-byte checksum
check "$SYSUP" "$FW_PART"
check "$INITRAMFS" $((64 * 1024 * 1024))       # RAM boot only; never write it to the kernel partition

# The sysupgrade tar's kernel goes to "kernel" and its rootfs to "ubi": check each part.
if [ -s "$SYSUP" ]; then
  if members=$(tar tvf "$SYSUP" 2>/dev/null); then
    ksz=$(printf '%s\n' "$members" | awk '$NF ~ /\/kernel$/ {print $3}')
    rsz=$(printf '%s\n' "$members" | awk '$NF ~ /\/root$/ {print $3}')
    if ! is_num "$ksz" || ! is_num "$rsz"; then echo "sysupgrade tar: no single kernel and root size ($ksz / $rsz)"; ok=0
    elif [ "$ksz" -gt "$KERNEL_PART" ]; then echo "sysupgrade kernel too big ($ksz > $KERNEL_PART)"; ok=0
    elif [ "$rsz" -gt "$UBI_USABLE" ]; then echo "sysupgrade rootfs too big for UBI ($rsz > $UBI_USABLE)"; ok=0
    else echo "ok: sysupgrade kernel $ksz, rootfs $rsz bytes"
    fi
  else echo "sysupgrade tar unreadable"; ok=0
  fi
fi

[ $ok = 1 ] || fail "image check"
rm -rf "$PREV"
done_ok=1
date '+BUILD OK %F %T'
