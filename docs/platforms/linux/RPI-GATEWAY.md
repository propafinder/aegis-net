# Raspberry Pi WiFi gateway (transparent tunnel for LAN/WiFi devices)

Turn an RPi into a transparent AEGIS gateway: phones/laptops that connect to the
Pi's WiFi are tunnelled over the relay with **zero config on the device**. Only
downstream **TCP** is tunnelled (see the DNS note at the end).

## Topology — you need TWO network paths
The Pi must have a separate **uplink** (to the internet) and **AP** (for clients):

- **Two WiFi radios** (recommended if no cable): `--uplink wlan0` (STA → your
  router) + `--lan wlan1` (AP for phones).
- **Ethernet uplink**: `--uplink eth0` (cable → router) + `--lan wlan0` (AP).

A single radio cannot reliably be both STA and AP at once — don't try.

## 0. Preflight (do this ON the Pi, once)
```bash
# TPROXY kernel support — the gateway needs it. On a pure-nft RPi:
sudo modprobe nft_tproxy nft_socket && echo "nft TPROXY ok"
# (the installer's helper also probes this and fails fast with a clear message)
```

## 1. Install the client in gateway mode

Use an approved exact ARM64 package, authenticated bootstrap and separately
transferred private access record. Raspberry Pi hardware and AP forwarding
acceptance are separate from the portable ARM64 build; this recipe does not
assert that the current package has passed those gates. Follow
[INSTALL](../../../INSTALL.md) for independent package/script pins and
[private input custody](../../operations/private-installer-inputs.md).

```bash
sudo bash /trusted/bootstrap-install.sh client \
  --source https://downloads.example.org/EXACT_TAG/client-release.manifest-aarch64.json \
  --bundle-url-file /root/aegis-access/client-access-url.txt \
  --profile gateway-tproxy --wide-interface wlan1
```

Replace `EXACT_TAG` and the mirror using the authenticated receipt; do not infer
`latest`. Root must own the mode-`0600` URL record and its trusted private parent.
Remote access acquisition requires HTTPS and validated CA trust (or an
independently authenticated SPKI pin for the explicit insecure/pinned path).
`--wide-interface` MUST be the **AP** interface (the one clients connect to).

## 2. Bring up the gateway plumbing (forwarding + NAT + capture)
```bash
sudo /usr/local/lib/aegis/helpers/aegis-rpi-gateway.sh apply --uplink wlan0 --lan wlan1
```
Confirm that the selected package actually installed this helper before applying
routing; fetching a bootstrap without executing a verified installation installs
nothing. The reviewed helper sets `ip_forward`, `route_localnet`, loose `rp_filter` (all mandatory for the
forwarded TPROXY path), NAT on the uplink, and the TPROXY capture scoped to the
AP interface. Teardown restores every sysctl it changed:
```bash
sudo /usr/local/lib/aegis/helpers/aegis-rpi-gateway.sh teardown --uplink wlan0 --lan wlan1
```

## 3. Operator steps AEGIS does NOT do (you set these up)
AEGIS handles capture+tunnel; it does **not** run the WiFi AP or DHCP. You need:

1. **hostapd** on the AP interface — SSID + WPA2. (Static IP on the AP iface, e.g.
   `10.99.1.1/24`.)
2. **dnsmasq** for DHCP on the AP subnet — hand out IP + gateway (the Pi's AP IP)
   + DNS. Bind it to the AP iface only so it does not collide with anything on
   `127.0.0.1:53`:
   ```
   interface=wlan1
   bind-interfaces
   dhcp-range=10.99.1.50,10.99.1.200,12h
   ```
3. **Un-manage the AP iface from NetworkManager** (RPi OS bookworm default) so it
   does not fight hostapd:
   ```bash
   sudo nmcli device set wlan1 managed no
   ```

## 4. Verify
Connect a phone to the Pi's WiFi, then on the phone open any IP checker — it
should show the **relay's IP**, not your ISP's. On the Pi:
```bash
sudo /usr/local/lib/aegis/helpers/setup-wide-linux-tproxy.sh doctor
```

## DNS note (honest)
Only downstream **TCP** is tunnelled. AP-client **DNS/UDP egresses directly** via
the uplink (plaintext), by design (`capture_dns=false`). If you need the phones'
DNS private too, that is a separate configuration (point the AP's DHCP DNS at a
DoH/DoT forwarder on the Pi).
