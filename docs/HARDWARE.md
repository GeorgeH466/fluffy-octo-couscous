# HARDWARE

What cyberdeck-arsenal can drive, what it does with each device, and how to
verify that a device you just plugged in is actually usable — as opposed to
merely detected, which is the mistake that wastes afternoons.

Every capability is optional. The suite detects what is present, records it in
`state/hardware.json`, and skips the parts of itself that have no hardware with
an explanatory message rather than an error.

---

## Contents

1. [Verify what you have](#verify-what-you-have)
2. [Reference platforms](#reference-platforms)
3. [WiFi adapter](#wifi-adapter)
4. [Bluetooth](#bluetooth)
5. [SDR receivers](#sdr-receivers)
6. [GPS](#gps)
7. [GPIO, LEDs, buttons, OLED](#gpio-leds-buttons-oled)
8. [Proxmark3 and RFID](#proxmark3-and-rfid)
9. [Storage and USB](#storage-and-usb)
10. [Power, thermals, displays](#power-thermals-displays)
11. [Antennas](#antennas)
12. [Diagnosing a device](#diagnosing-a-device)

---

## Verify what you have

```bash
tests/test_hardware.sh            # human-readable, exits with the failure count
tests/test_hardware.sh --json     # machine-readable inventory
tests/test_hardware.sh --watch 5  # re-check every 5s; highlights changes
cdeck hardware                    # the same information from the CLI
cdeck hardware --write            # write state/hardware.json
```

`utilities/hardware_detect.sh` is the engine behind all of these. It probes by
class, so you can also ask about one subsystem:

```bash
utilities/hardware_detect.sh --check wifi,sdr
utilities/hardware_detect.sh --json --quiet | jq '.devices'
```

Capability classes: `wifi`, `sdr`, `gpio`, `gps`, `bluetooth`, `battery`,
`ethernet`, `display`, `proxmark`, `i2c`.

## Reference platforms

| Platform | WiFi | SDR | GPIO | Notes |
| --- | --- | --- | --- | --- |
| ThinkPad / Dell laptop | built-in | via USB | no | The reference x86 deck. Everything except GPIO/OLED. |
| Raspberry Pi 4B / 5 | via USB | via USB | yes | The reference ARM deck. I2C OLED and LEDs work out of the box. |
| Raspberry Pi Zero 2W | via USB | via USB | yes | Usable, but the HUD is slow; set `display.compact: true`. |
| Orange Pi / Rock Pi | via USB | via USB | usually | GPIO support depends on the kernel's sysfs interface. |
| x86 tablet | built-in | via USB | no | Check the thermal sensors; `display.fancy_borders: false` helps. |

## WiFi adapter

The single most important component. Two radios turn the deck from a laptop into
a platform: one stays connected, one monitors.

**Requirements for the full arsenal**

| Capability | Needed for | How to check |
| --- | --- | --- |
| Monitor mode | probe logging, `airodump-ng`, rogue AP detection | `iw list \| grep -A8 'Supported interface modes'` |
| Packet injection | deauth, handshake capture, PMKID, evil twin | `aireplay-ng --test wlan1mon` |
| 5 GHz | dual-band survey work | `iw phy phy0 info \| grep -A6 'Frequencies'` |
| AP mode | evil twin, captive portal | `iw list \| grep -A12 'Supported interface modes' \| grep AP` |

**Chipsets known to work well**

| Chipset | Driver | Monitor | Injection | Notes |
| --- | --- | --- | --- | --- |
| RTL8812AU / 8814AU | `rtl8812au-dkms` | yes | yes | The most common Alfa. Needs the DKMS package. |
| RTL8811CU / 8821CU | `rtl8821cu-dkms` | yes | yes | Small and cheap; fine for a travel deck. |
| MT7601U | `mt7601u` | yes | partial | Injection is unreliable; monitor mode is solid. |
| Atheros AR9271 | `ath9k_htc` | yes | yes | Best-in-class injection. Getting scarce. |
| MediaTek MT7921 | `mt7921e` | yes | partial | Common built-in in 2021+ laptops. |

**Configuration**

```yaml
network:
  primary_interface: wlan0     # connectivity
  monitor_interface: wlan1     # monitoring
scanning:
  nmap_timing: T4
```

The monitor interface may be the same as the primary one if you only have one
radio; the passive services then pause while you are connected. See the
"One radio" recipe in [CONFIGURATION.md](CONFIGURATION.md).

**Getting monitor mode up**

```bash
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
iw dev wlan1 info             # Type: monitor
```

The deck's own scripts do this for themselves; `cdeck wifi` wraps the whole
arsenal (`aircrack-ng`, `airodump-ng`, `aireplay-ng`) and refuses to start on an
interface that cannot do it.

## Bluetooth

Any adapter the kernel exposes under `/sys/class/bluetooth` works for passive
BLE work.

```bash
hciconfig -a                  # or: bluetoothctl list
cdeck ble --list              # observed devices with the vulnerability lookup applied
```

`recon/passive/ble_scanner.py` records address, name, manufacturer (from the OUI
database), RSSI history, and matches each device against
`data/ble_vulnerability_db.json` — 15 classes of known BLE weaknesses, from
unauthenticated GATT writes to vulnerable tracker firmware.

Adapter makes a difference for range: an Intel AX210 reaches further than a
cheap CSR dongle. If you are hunting a specific device, attach an external
antenna rather than buying a new adapter.

## SDR receivers

The SDR modules talk to the hardware through `rtl_sdr`, `rtl_power`, `rtl_fm`
and, where relevant, `dump1090` or `multimon-ng`.

| Device | Coverage | Modules that use it |
| --- | --- | --- |
| RTL-SDR (RTL2832U + R820T2) | 24–1766 MHz, RX only | `sdr_scanner.py`, `adsb_tracker.py`, `pager_decoder.py`, `tpms_monitor.py`, `rf_spectrum.py` |
| HackRF One | 1 MHz–6 GHz, TX/RX | `keyfob_analyzer.py` (sub-GHz capture and replay where lawful) |
| Yard Stick One | sub-GHz, TX/RX | `keyfob_analyzer.py` |
| Airspy / SDRplay | wideband RX | generic modules through `rtl_power`-compatible tooling |

**Verify**

```bash
rtl_test -t                   # device present, tuner identified, no lost samples
cdeck rf                      # live spectrum around the configured range
cdeck sdr --scan --range 88-108
```

**Configuration**

```yaml
sdr:
  enabled: true
  device_index: 0
  gain: auto            # or e.g. 32.8
  sample_rate: 2048000
  sweep_start_mhz: 88
  sweep_end_mhz: 108
  capture_dir: /opt/cyberdeck-arsenal/data/rf
```

**Modules and their typical settings**

| Module | Suggested range | Notes |
| --- | --- | --- |
| `sdr_scanner.py` | 300–500 MHz | Generic peak detection; set the range per engagement. |
| `adsb_tracker.py` | 1090 MHz | 2.4 MS/s minimum; `gain: auto` works well. |
| `pager_decoder.py` | 153/158/466 MHz | POCSAG and FLEX; regional. Check your local allocation. |
| `tpms_monitor.py` | 315/433.92 MHz | Vehicle sensor IDs and pressures. |
| `keyfob_analyzer.py` | 315/433.92/868 MHz | Needs a transmit-capable radio for replay. |

Every SDR module exits `3` when no receiver is present — that is by design, so
scripts can tell "no hardware" apart from "failed".

## GPS

An NMEA receiver on a serial port gives the deck time, position and the geofence
triggers.

```bash
ls /dev/ttyACM* /dev/ttyUSB*   # the deck's own probe order
cdeck gps --once               # or: gpspipe -w -n 1
```

```yaml
gps:
  enabled: true
  device: /dev/ttyACM0
  baud: 9600
  show_coordinates: true
  geofences:
    - {name: home, lat: 51.8091, lon: -0.2897, radius_m: 300}
    - {name: lab,  lat: 51.5074, lon: -0.1278, radius_m: 150}
```

With `automation.geofence_enabled: true`, entering and leaving a fence raises an
event. `setup.sh` writes the detected device into `gps.device` for you.

## GPIO, LEDs, buttons, OLED

Raspberry Pi (and most Pi-compatible boards) via the sysfs interface, `lgpio`
or `RPi.GPIO`. The suite prefers a Python library and falls back to
`/sys/class/gpio`, and falls back again to a simulation backend, so GPIO code
runs — and can be tested — on a laptop.

**Wiring reference**

| Function | BCM pin | Physical pin | Notes |
| --- | --- | --- | --- |
| Status LED | 17 | 11 | Series 330 Ω resistor to GND |
| Alert LED | 27 | 13 | Series 330 Ω resistor to GND |
| Button | 22 | 15 | To GND; internal pull-up enabled, active low |
| OLED SDA | 2 | 3 | I2C bus 1 |
| OLED SCL | 3 | 5 | I2C bus 1 |
| OLED VCC | — | 1 or 17 | 3V3 |
| OLED GND | — | 6 or 9 | — |

**Enable the parts you have**

```yaml
gpio:
  enabled: true
  status_led_pin: 17
  alert_led_pin: 27
  button_pin: 22
  oled_enabled: true
  oled_i2c_address: "0x3C"
  oled_bus: 1
  blink_interval: 0.5
```

Also add `dtparam=i2c_arm=on` to `/boot/config.txt` (or use `raspi-config`) for
I2C.

**Verify**

```bash
sudo python3 lib/cybergpio.py --detect            # which backend is in use
sudo python3 lib/cybergpio.py --i2c-scan          # finds the OLED at 0x3C
cdeck led --test                                  # both LEDs, all patterns
cdeck oled --page status                          # render a page
cdeck buttons --list-actions                      # what each press does
cdeck led --simulate --pattern heartbeat          # no hardware? still works
```

**Button actions** (override with `gpio.button_actions` in the config):

| Press | Default action |
| --- | --- |
| short | `cdeck dashboard` |
| double | `theme_switcher.sh --cycle` |
| long | `utilities/self_destruct.sh --soft` (confirmation required) |
| triple | `cdeck status` |
| emergency | `cdeck panic --soft` |

**OLED pages**: `status`, `network`, `vitals`, `alerts`, `sdr`, `engage`,
`clock`, `splash`. Cycle them with `cdeck oled --watch`.

## Proxmark3 and RFID

```bash
proxmark3 /dev/ttyACM0        # the client ships with the package
utilities/hardware_detect.sh --check proxmark
```

The deck does not wrap the Proxmark client — it is a deep tool with its own
excellent CLI. The platform's job here is detection, logging and making sure the
right serial device permissions are in place (the shipped udev rules cover it).

## Storage and USB

`utilities/usb_handler.py` reacts to insertions according to
`usb.auto_actions`: `image`, `hash`, `log`, `mount-ro`.

```yaml
usb:
  auto_actions: [hash, log, mount-ro]
  image_dir: /opt/cyberdeck-arsenal/captures/usb
  max_image_size_gb: 128
  image_block_size: 4M
```

* **hash** — SHA-256 plus a manifest line, useful for chain-of-custody.
* **log** — an `usb` table row plus a `logs/usb-watcher.log` entry.
* **mount-ro** — read-only mount, never writes to the stick.
* **image** — `dd` with `bs=4M`, `conv=noerror,sync`, followed by a hash of the
  image. Devices larger than `max_image_size_gb` are refused.

Check the deck's view of what has been plugged in:

```bash
cdeck usb --history
cdeck usb --list
```

## Power, thermals, displays

* **Battery** — percentage and charge state from `/sys/class/power_supply/BAT*`.
  `automation.low_battery_exfil` copies logs to `exfil_destination` below
  `battery_threshold` percent.
* **Thermals** — every zone under `/sys/class/thermal/` appears in the HUD's
  vitals page and in `cdeck status`.
* **Displays** — a 7" panel or a narrow terminal is served by
  `display.compact: true`; the HUD then drops to a single column and shortens
  labels. On a Pi Zero also set `display.fancy_borders: false`.

## Antennas

| Antenna | Use |
| --- | --- |
| 2.4 GHz 5 dBi omni | general WiFi survey |
| 2.4 GHz 9 dBi omni | gain at a distance, at the cost of vertical coverage |
| 2.4 GHz Yagi / panel | directional work: finding one AP in a building |
| 433.92 MHz whip | TPMS and key fobs |
| 1090 MHz | ADS-B; a small ground plane makes a real difference |
| Wideband discone | SDR scanning across bands |

Attach the antenna before powering the adapter. Transmitting into a mismatched
load damages the radio.

## Diagnosing a device

Work outwards:

```bash
lsusb                                        # 1. does the bus see it?
dmesg | tail -30                             # 2. did the driver bind?
lsmod | grep -i <driver>                     # 3. is the module loaded?
ip link                                      # 4. is there an interface?
sudo dmesg -w                                # 5. re-plug and watch what happens
```

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Device in `lsusb`, no interface | Driver/module missing | Install the DKMS package, `modprobe`, re-plug |
| Interface present, no monitor mode | Chipset limitation | Check `iw list`; use a different adapter |
| Injection test fails | Driver or channel | Lock to a channel first; try another card |
| `rtl_test` reports lost samples | USB power or hub bandwidth | Powered hub, shorter cable, lower sample rate |
| OLED not found | I2C disabled, wiring, address | Enable I2C, check SDA/SCL, try `0x3D` |
| LED does not light | Polarity, resistor, pin number | Confirm BCM pin, check `cdeck led --test --verbose` |
| Device disappears under load | Power draw | Powered hub; a Pi's USB port budget is finite |
| `--i2c-scan` exits 3 | No I2C bus at all | Enable `i2c-dev`; on x86 there is no bus, which is normal |

When a hardware module reports a problem it names the exact device, the exact
package that provides the missing tool, and the command that would confirm the
fix. `cdeck doctor` collects all of that in one place:

```bash
cdeck doctor --full
```

---

*Related: [QUICKSTART.md](QUICKSTART.md) · [CONFIGURATION.md](CONFIGURATION.md) · [TROUBLESHOOTING.md](TROUBLESHOOTING.md)*
