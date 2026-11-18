# Building the travel-router image and upgrading in place

This is how the second image was made: the same OpenWrt port, plus the packages a travel router needs
built in, then tested from RAM and installed with `sysupgrade` while keeping all settings.

## What the image adds

On top of OpenWrt's defaults for the RBR10 (`build/rbr10.diffconfig` has the exact selection):

| Package(s) | What for |
| --- | --- |
| `luci`, `luci-ssl` | The web interface, over HTTPS |
| `travelmate`, `luci-app-travelmate` | Joins hotel or hotspot Wi-Fi as the internet uplink, with captive-portal detection |
| `tailscale`, `kmod-tun` | Reach your own network from the travel Wi-Fi without a client on each device |
| `kmod-wireguard`, `wireguard-tools`, `luci-proto-wireguard` | Send the whole travel network through a WireGuard VPN |
| `sqm-scripts`, `luci-app-sqm`, `kmod-sched-cake`, `kmod-ifb` | Keep calls smooth on a slow, busy link (bufferbloat control) |
| `https-dns-proxy`, `luci-app-https-dns-proxy` | Encrypted DNS (DNS over HTTPS) |

Packages added by hand after flashing live in the small writable overlay, and kernel modules from the
download servers don't load into a self-built kernel. Building them into the image avoids both problems:
Tailscale alone is about 26 MB unpacked, but about half that inside the compressed rootfs.

## Build

From an OpenWrt checkout with `build/rbr10-openwrt.patch` applied (see the README):

```bash
./scripts/feeds update -a
./scripts/feeds install luci luci-ssl luci-app-travelmate travelmate https-dns-proxy luci-app-https-dns-proxy sqm-scripts luci-app-sqm luci-proto-wireguard tailscale
cp /path/to/orbi-openwrt/build/rbr10.diffconfig .config
make defconfig
cp /path/to/orbi-openwrt/build/build-rbr10.sh .
setsid nohup ./build-rbr10.sh > build-rbr10.log 2>&1 < /dev/null &
```

`build-rbr10.sh` prints exactly one last line, `BUILD OK` or `BUILD FAILED (...)`. Before saying OK it
checks that:

- all three images (factory, sysupgrade, initramfs) were written by this run and fit their partitions;
- at least 8 MiB stays free for settings and add-ons (`overlay: about N MiB left`);
- neither kernel nor the rootfs contains the build machine's login or host name (set
  `CONFIG_KERNEL_BUILD_USER` and `CONFIG_KERNEL_BUILD_DOMAIN` to generic values; the diffconfig does).

The reference build (OpenWrt snapshot r38384, Linux 6.18.60) left about 16 MiB for settings.

## Test it from RAM first

Boot the new `initramfs` image once over serial and TFTP, as in the README, before touching flash. The
existing UBI area is only attached, not written. Check that the kernel, both radios and the new modules
come up (`lsmod` for `tun`, `wireguard`, `sch_cake`, `ifb`; `tailscale version`). A power cycle returns
to the installed firmware.

## Upgrade in place

On the router, keeping all settings:

```bash
sysupgrade -b /tmp/settings-backup.tar.gz    # copy this off the router first; it holds your secrets
sha256sum /tmp/sysupgrade.bin                # compare with the build's own hash
sysupgrade -T -v /tmp/sysupgrade.bin         # test only: must pass with no warnings
sysupgrade -v /tmp/sysupgrade.bin            # never -F
```

The session ends with `ubus call system sysupgrade ... (Connection failed)`: that is normal. The router
was back on SSH about 85 seconds later with every setting, Wi-Fi network and key in place. If it doesn't
come back, the NMRP recovery in the README still works.

## Afterwards

- Tailscale needs one `tailscale up` and a browser login. Its state lives in `/etc/tailscale/`, which
  sysupgrade keeps.
- `https-dns-proxy` starts on its own with default resolvers. Behind a hotel login page, encrypted DNS
  can't connect until you log in, so plan a fallback to the network's DNS for that case.
- SQM needs per-network speeds; leave it off until you measure the uplink.
