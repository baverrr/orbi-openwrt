#!/bin/sh
# Compile an ipq40xx device tree the way OpenWrt does: cpp, then dtc.
# Usage (from the repo root): sh build/compile-dts.sh dts/qcom-ipq4019-rbr10.dts
# Needs MSYS2's cpp and dtc (C:\msys64\usr\bin) and the sources in build/src
# (OpenWrt main + Linux v6.18 with OpenWrt's ipq40xx dts patches applied).
set -e
[ -f "${1:-}" ] || { echo "usage: sh build/compile-dts.sh path/to/board.dts (run from the repo root)" >&2; exit 2; }
src="$1"; name=$(basename "$src" .dts)
mkdir -p build/out
rm -f "build/out/$name.pre.dts" "build/out/$name.dtb"  # never leave an old dtb that looks current
BIN=/c/msys64/usr/bin
PATH="$BIN:$PATH"; export PATH  # cc1 needs the MSYS2 DLLs
OWRT=build/src/openwrt/target/linux/ipq40xx/dts
LNX=build/src/linux
"$BIN/cpp.exe" -nostdinc -undef -D__DTS__ -x assembler-with-cpp \
  -I "$(dirname "$src")" -I "$OWRT" -I "$LNX/arch/arm/boot/dts/qcom" -I "$LNX/include" \
  -I build/src/openwrt/target/linux/generic/files/include \
  -o "build/out/$name.pre.dts" "$src"
"$BIN/dtc.exe" -I dts -O dtb -W no-unit_address_vs_reg \
  -o "build/out/$name.dtb" "build/out/$name.pre.dts"
echo "built build/out/$name.dtb ($(wc -c < "build/out/$name.dtb") bytes)"
