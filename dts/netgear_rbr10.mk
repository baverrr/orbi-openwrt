# OpenWrt image recipe for the Netgear Orbi RBR10, for target/linux/ipq40xx/image/generic.mk
# (goes after Device/netgear_rbr20). Built on Device/netgear_rbx20 from openwrt main 7424e2c.
#
# Layout (see qcom-ipq4019-rbr10.dts): the stock "firmware" partition at 0x1200000 is 40 MB.
# factory.img = kernel padded to KERNEL_SIZE (7 MB, with the 64-byte fake uImage header the Orbi
# loader checks, from append-uImage-fakehdr), then UBI. The first check-size keeps the padded,
# headed kernel within KERNEL_SIZE: without it, a kernel within 64 bytes of 7 MB grows past it
# and pad-to silently rounds up to 14 MB, moving UBI off 0x1900000. The second keeps the whole
# body within IMAGE_SIZE (those 40 MB), so UBI is at most 0x2100000 (33 MB), the DTS "ubi".
# check-size deletes an oversized image but exits 0; the next step then fails on the missing
# file, and the build-rbr10.sh script also checks each image exists and fits.
#
# Also needed: netgear,rbr10 in package/boot/uboot-tools/uboot-envtools/files/ipq40xx next to
# netgear,rbr20 (0:APPSBLENV is mtd8 here too), so fw_printenv/fw_setenv work.
#
# NETGEAR_HW_ID and NETGEAR_BOARD_ID: from the DNI header of the stock RBR10-V2.7.5.6.img
# ("device:RBR10", "hd_id:29766105+0+128+512+2x2+2x2": 128 MB flash, 512 MB RAM, two 2x2 radios).
#
# DEVICE_PACKAGES: empty on purpose. No kmod-leds-tlc591xx: the RBR10 has no TLC59208F (nothing
# ACKs i2c 0x27, RAM boot 2026-11-16); its status LEDs are plain GPIOs. No QCA9888 firmware (no
# PCIe radio). No ipq-wifi package yet: an
# ipq-wifi-netgear_rbk10 board-data package still has to be made from the stock DK04 board
# files, so until then ath10k uses the generic ath10k-board-qca4019 (a default package).
#
# Also needed outside this file: netgear,rbr10 next to netgear,rbr20 in
# base-files/etc/board.d/02_network ("lan" "wan") and base-files/lib/upgrade/platform.sh
# (nand_do_upgrade).

define Device/netgear_rbr10
	$(call Device/DniImage)
	SOC := qcom-ipq4019
	DEVICE_VENDOR := NETGEAR
	DEVICE_MODEL := RBR10
	NETGEAR_BOARD_ID := RBR10
	NETGEAR_HW_ID := 29766105+0+128+512+2x2+2x2
	KERNEL_SIZE := 7340032
	BLOCKSIZE := 128k
	PAGESIZE := 2048
	UBINIZE_OPTS := -E 5
	IMAGE_SIZE := 40960k
	IMAGE/factory.img := append-kernel | pad-offset $$$$(BLOCKSIZE) 64 | \
		append-uImage-fakehdr filesystem | check-size $$$$(KERNEL_SIZE) | \
		pad-to $$$$(KERNEL_SIZE) | append-ubi | check-size | netgear-dni
	IMAGE/sysupgrade.bin := append-kernel | pad-offset $$$$(BLOCKSIZE) 64 | \
		append-uImage-fakehdr filesystem | check-size $$$$(KERNEL_SIZE) | \
		sysupgrade-tar kernel=$$$$@ | append-metadata
	DEVICE_PACKAGES :=
endef
TARGET_DEVICES += netgear_rbr10
