# TROUBLESHOOTING

Start here:

```bash
cdeck doctor --full                # everything at once, with explanations
cdeck status                       # effective configuration
tail -50 /opt/cyberdeck-arsenal/logs/cyberdeck.log
tail -50 /opt/cyberdeck-arsenal/logs/setup.log
```

`cdeck doctor` runs the four test suites, checks permissions, databases,
services and hardware, and tells you which single thing to fix first. When a
module fails it names the exact package, device or key that caused it — read the
error message before reaching for a bigger hammer.

---

## Contents

1. [Installation](#installation)
2. [Permissions](#permissions)
3. [Login, MOTD and shell](#login-motd-and-shell)
4. [Services and systemd](#services-and-systemd)
5. [Dashboards and the HUD](#dashboards-and-the-hud)
6. [Wireless](#wireless)
7. [SDR](#sdr)
8. [GPS](#gps)
9. [GPIO, I2C and the OLED](#gpio-i2c-and-the-oled)
10. [Vault and encryption](#vault-and-encryption)
11. [USB handling](#usb-handling)
12. [Databases and data](#databases-and-data)
13. [Automation](#automation)
14. [Connectivity and DNS](#connectivity-and-dns)
15. [Performance](#performance)
16. [Uninstalling](#uninstalling)
17. [Getting help](#getting-help)

---

## Installation

| Symptom | Cause | Fix |
| --- | --- | --- |
| `this script must run as root` | Ran without sudo | `sudo ./setup.sh` |
| `unsupported distribution` | Not Arch/BlackArch | The suite targets Arch-family systems; `/etc/os-release` must say `arch` or `blackarch` |
| `no connectivity` | Offline | The installer needs the network; use `--minimal` on a mirrored/local repo if you must |
| `not enough disk space` | Under 10 GB free | Free space, or point the install at another filesystem |
| Installer stops mid-run | Package conflict, mirror timeout | Fix the cause and re-run `sudo ./setup.sh` — it resumes at the failed step |
| `pacman` lock held | Another pacman is running | `sudo rm /var/lib/pacman/db.lck` **only** after confirming nothing else is running |
| A Python package fails to build | Missing build tools or headers | `sudo pacman -S base-devel python-pip`; check `logs/setup.log` for the exact wheel |
| Wordlist download fails | Network or upstream moved | Re-run `sudo data/wordlists/download_wordlists.sh`; the deck works without them |

Everything the installer does is recorded in `logs/setup.log` with timestamp,
step, verdict and elapsed time:

```
2026-10-16_151204 | 07/installing systemd units | OK  | 7 units enabled | 1.4s
```

## Permissions

The most common class of problem, because the deck touches radios, `/root`-owned
state and raw devices.

| Symptom | Cause | Fix |
| --- | --- | --- |
| `permission denied` opening a capture | Monitor mode needs root | `sudo cdeck wifi`, `sudo cdeck packets wlan0` |
| Can read `cyberdeck.conf` but not write it | File is `0600 root:root` | `sudo cdeck config key=value` |
| `Operation not permitted` on an LED | GPIO export needs root | `sudo cdeck led --state scanning` |
| Vault cannot create `/run/cyberdeck-vault.*` | `/run` not writable | The vault falls back to `/tmp/cyberdeck-vault.*`; that is expected in containers |
| `usb_handler` cannot read a device | udev rules not installed | Re-run `sudo ./setup.sh` (it writes the rules), then `sudo udevadm control --reload-rules` |
| `logs/` not writable by your user | Installed as root | `sudo chown -R "$USER" /opt/cyberdeck-arsenal/logs` |

Check the expected modes:

```bash
tests/test_installation.sh | grep -i permission
stat -c '%a %U:%G %n' /opt/cyberdeck-arsenal/cyberdeck.conf
find /opt/cyberdeck-arsenal -maxdepth 3 -type f -perm -0002   # should be empty
```

## Login, MOTD and shell

| Symptom | Cause | Fix |
| --- | --- | --- |
| No MOTD on login | Shell integration not sourced | `source /etc/profile.d/cyberdeck-aliases.sh`; check the file exists |
| MOTD prints escape codes | Colour on a non-terminal | `aesthetic/motd.sh --no-colour`, or set `general.color_output: false` |
| `cdeck: command not found` | Session predates the install | `exec bash -l`, or `/opt/cyberdeck-arsenal/bin/cdeck` |
| Aliases missing | Non-interactive shell, or `--no-rc` | Aliases live in `/etc/profile.d/`, not `~/.bashrc`; log in afresh |
| MOTD slows login | It probes services | Use `cdeck config display.compact=true`, or edit the MOTD calls: `aesthetic/motd.sh --short` |

## Services and systemd

```bash
tests/test_services.sh              # the full picture
systemctl status cyberdeck-monitor.service
journalctl -u probe-logger.service -n 50 --no-pager
cdeck services restart
```

| Symptom | Cause | Fix |
| --- | --- | --- |
| Unit `failed` | Its dependency is missing | `journalctl -u <unit> -n 50`; usually a missing package or interface |
| Unit restarts in a loop | Interface vanished | Set `network.monitor_interface` to an interface that exists, then restart |
| `Unit not found` | Units never installed | `sudo ./setup.sh` — it installs and enables all seven |
| Timer never fires | Timer not enabled | `sudo systemctl enable --now mac-rotator.timer` |
| No data written to `probes.db` | Service is running but the radio is elsewhere | `iw dev` to confirm the monitor interface, then `cdeck services restart` |
| Two tools fighting over one radio | `airodump-ng` and the passive logger, typically | Stop one: `cdeck services stop probe-logger`, or use a second radio |
| Service runs but does nothing | Config says the feature is off | `monitoring.probe_log_enabled`, `monitoring.arp_monitor_enabled`, etc. |

Restart just the passive layer:

```bash
sudo systemctl restart probe-logger.service ble-scanner.service rogue-ap-detector.service usb-watcher.service
```

## Dashboards and the HUD

| Symptom | Cause | Fix |
| --- | --- | --- |
| `rich is not installed` | Virtualenv not used | `cdeck` sets it up; or `sudo /opt/cyberdeck-arsenal/venv/bin/pip install rich` |
| Boxes look like `â”€â”€` | Old terminal or locale | `export LANG=en_GB.UTF-8`, use a UTF-8 terminal, or `display.fancy_borders: false` |
| HUD flickers or eats CPU | Refresh too fast for the board | `cdeck config display.hud_refresh_rate=5`, `display.fancy_borders=false` |
| Garbled output, no colours | Output piped | Colour is disabled when stdout is not a TTY; `--no-colour` forced it |
| Packet weather is empty | Wrong interface or no privileges | `sudo cdeck packets`; `capture.interface` overrides the default |
| Threat ticker shows nothing | No events yet | `cdeck threats --demo`, or let the passive services run for a few minutes |
| Terminal left in a bad state | Killed mid-render | `reset` or `stty sane` |
| Panels are empty | Probes returned nothing (common in VMs) | Expected: the pages tolerate missing data rather than failing |

## Wireless

```bash
tests/test_hardware.sh --check wifi
iw dev; iw list | head -40
sudo cdeck doctor --full
```

| Symptom | Cause | Fix |
| --- | --- | --- |
| `monitor mode not supported` | Adapter/driver limitation | Use a monitor-capable radio; check `iw list` for `* monitor` |
| `monitor mode not enabled` | Interface still managed | `sudo ip link set wlan1 down && sudo iw dev wlan1 set type monitor && sudo ip link set wlan1 up` |
| `injection test failed` | Driver or wrong channel | Lock the channel first; some drivers inject only on 2.4 GHz |
| No networks found | rfkill, NetworkManager interference, or wrong interface | `rfkill list`; `sudo airmon-ng check kill` before monitoring |
| SSID shows as `\x00` | Hidden network | Normal: the SSID is only revealed by a client probe |
| `airodump-ng` finds nothing but `iw` does | Card in the wrong band | `airodump-ng --band abg` |
| Interface renamed after plugging | Udev naming | Use `ip -br link` and update `network.monitor_interface` |
| Handshake never captured | Client not present, or no traffic | Wait for a client, or use PMKID (clientless) instead |
| `wlan1` does not exist on a one-radio deck | Config assumes two radios | Set `primary_interface` and `monitor_interface` to the same interface |

## SDR

| Symptom | Cause | Fix |
| --- | --- | --- |
| Module exits `3` | No receiver present — by design | `rtl_test -t`; plug the dongle in |
| `usb_claim_interface error -6` | Another program holds the device | Close `gqrx`/`dump1090`; check `fuser -v /dev/bus/usb/*/*` |
| Lost samples, choppy audio | Sample rate too high for the bus | Lower `sdr.sample_rate`, use a powered hub |
| ADS-B shows no aircraft | Wrong frequency, wrong rate, or nothing nearby | 1090 MHz, ≥2.4 MS/s, aerial with a view |
| Pager decoding is silent | Wrong band for your region | Check local allocations and set the frequency explicitly |
| TPMS finds nothing | 315 vs 433.92 MHz region mismatch | Sweep both: `cdeck tpms --frequencies 315,433.92` |
| Spectrum is flat | Gain too low | `sdr.gain: auto` or a fixed value such as `32.8` |

## GPS

| Symptom | Cause | Fix |
| --- | --- | --- |
| No fix | Indoors, or antenna not attached | Move outdoors; a fix can take minutes from cold |
| Device not found | Wrong port | `ls /dev/ttyACM* /dev/ttyUSB*`; set `gps.device` |
| `gpsd` not answering | Not running | `sudo systemctl enable --now gpsd.socket` |
| Coordinates jump | Doppler/urban canyon | Normal; the trigger engine debounces fence crossings |

## GPIO, I2C and the OLED

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no GPIO backend available` | x86 machine, or no library | Expected; use `--simulate`, or `sudo pacman -S lgpio` on a Pi |
| LED does not light | Wiring, polarity, pin number | Confirm the BCM pin, check the resistor, `cdeck led --test --verbose` |
| LED is inverted | Active-low wiring | Invert the pattern or rewire to the other leg |
| Button fires constantly | Floating input | The suite enables a pull-up; short the pin to GND, not 3V3 |
| `--i2c-scan` exits 3 | No `/dev/i2c-*` at all | Enable I2C; on x86 there is no bus, which is correct behaviour |
| OLED stays dark | Wrong address or bus | Try `0x3D`; `sudo python3 lib/cybergpio.py --i2c-scan` |
| OLED shows garbage | Wrong controller | SSD1306 vs SH1106: `--controller` / the panel model matters |
| Pin busy | Exported by a previous run | `sudo python3 lib/cybergpio.py --detect --verbose`, then unexport or reboot |

## Vault and encryption

| Symptom | Cause | Fix |
| --- | --- | --- |
| `gpg not found` | GPG not installed | `sudo pacman -S gnupg`; the vault can also use `openssl enc` |
| Wrong passphrase | — | There is no recovery. This is the point. Keep a copy in a safe place |
| `/run` not writable | Container, or hardened host | It falls back to `/tmp/cyberdeck-vault.*` automatically |
| Vault never auto-locks | No idle lock configured | `vault.auto_lock_minutes: 15` |
| `--verify` fails | Container modified or truncated | Restore from backup; the sha256 manifest tells you which file |
| Plaintext left in `/tmp` | Session closed uncleanly | `cdeck vault --close` shreds it; check `ls /tmp | grep cyberdeck-vault` |

## USB handling

| Symptom | Cause | Fix |
| --- | --- | --- |
| Nothing happens on insert | Service not running | `systemctl status usb-watcher.service` |
| Device ignored | Not mass storage | Only mass storage is handled; other classes are logged only |
| Image refused | Over `usb.max_image_size_gb` | Raise the limit deliberately, or image it by hand |
| Mount fails on read-only media | Dirty filesystem | `mount -o ro,noload`, or image it and mount the image instead |
| Rules do not apply | udev cache | `sudo udevadm control --reload-rules && sudo udevadm trigger` — the rules are written by `setup.sh` into `/etc/udev/rules.d/99-cyberdeck-usb.rules` |

## Databases and data

| Symptom | Cause | Fix |
| --- | --- | --- |
| `database is locked` | Two writers | Stop the other writer: `cdeck services stop <unit>`; the modules use WAL and short transactions |
| Database is corrupt | Power loss, full disk | Check the log, then `.recover` with `sqlite3`, or delete the file — it is regenerated |
| History disappeared | Retention pruning | `monitoring.retention_days: 30`; raise it |
| OUI lookups return unknown | Vendor not in the local table | `sudo cdeck update` refreshes it; unknown vendors are normal for randomised MACs |
| Reports show `{{TOKEN}}` | Template placeholder never substituted | Report a bug: every token must be filled by `report_generator.py` |

```bash
sqlite3 /opt/cyberdeck-arsenal/data/events.db 'select count(*) from events;'
sqlite3 /opt/cyberdeck-arsenal/data/events.db 'select * from alerts order by id desc limit 5;'
sudo cdeck update            # refresh DBs, OUI, feeds, wordlists
```

## Automation

| Symptom | Cause | Fix |
| --- | --- | --- |
| Triggers never fire | Engine not running | `systemctl status cyberdeck-monitor.service`, or run `cdeck triggers --daemon` |
| Rule fires constantly | Threshold too tight | `cdeck triggers --list`, then raise the cooldown/`min_count` |
| `resolve_command failed` | The action's binary is missing | `cdeck triggers --doctor`; install the package or fix the path |
| Scheduled task never runs | Scheduler not running, or a bad schedule | `cdeck schedule --list`, then `cdeck schedule run <id>` to test it |
| Task ran but produced nothing | Non-zero exit swallowed | Check `logs/scheduler.log` for the recorded exit code |
| Webhook never arrives | URL, TLS, or egress | `cdeck config alerts.webhook_url`, then `cdeck triggers --test-alert` |

## Connectivity and DNS

```bash
tests/test_connectivity.sh              # link, route, DNS, HTTP, tunnel, feeds
tests/test_connectivity.sh --quick      # skip the slow checks
```

| Symptom | Cause | Fix |
| --- | --- | --- |
| `default interface: none` | No route | Plug in, or `sudo cdeck profiles --apply <profile>` |
| DNS fails but ICMP works | Resolver unreachable | `cdeck config network.dns_servers`, reapply the profile |
| HTTPS works, HTTP is redirected | Captive portal | Log in, then re-test; the suite reports this explicitly |
| Everything is slow | tunnel or MTU | `cdeck vpn --check-leaks`; `tests/test_connectivity.sh` reports path MTU |
| Tor/proxychains fails | Tor not running | `sudo cdeck vpn --tor on` |
| API enrichment is skipped | No key configured | Set `api_keys.*`; empty keys are a supported state, not an error |
| Leak test says traffic is not tunnelled | Kill switch off or route leak | `sudo cdeck vpn --kill-switch on` |

## Performance

| Symptom | Cause | Fix |
| --- | --- | --- |
| HUD is sluggish | Refresh rate, fancy borders, slow board | `display.hud_refresh_rate=5`, `display.compact=true`, `display.fancy_borders=false` |
| Pi heats up | Continuous monitoring | `cap` the CPU, add a heatsink/fan; disable `service_watch_enabled` |
| Disk fills | Captures, reports, databases | `monitoring.retention_days`; prune `captures/` and `reports/` |
| `tshark` eats CPU | Only the summary is needed | Set `capture.bpf_filter` to narrow it |
| Scanning saturates the link | nmap timing | `scanning.nmap_timing: T2`, `scanning.max_parallel_jobs: 2` |

```bash
du -sh /opt/cyberdeck-arsenal/{logs,captures,reports,data,vault}
cdeck update --prune
```

## Uninstalling

```bash
sudo /opt/cyberdeck-arsenal/uninstall.sh             # remove the suite, keep your data
sudo /opt/cyberdeck-arsenal/uninstall.sh --purge     # remove everything
```

If the uninstaller itself is missing (someone deleted it):

```bash
sudo systemctl disable --now cyberdeck-monitor probe-logger ble-scanner rogue-ap-detector usb-watcher mac-rotator.timer
sudo rm -f /etc/systemd/system/{cyberdeck-monitor,probe-logger,ble-scanner,rogue-ap-detector,usb-watcher}.service \
           /etc/systemd/system/mac-rotator.{service,timer}
sudo rm -f /etc/profile.d/{cyberdeck-aliases.sh,cyberdeck-motd.sh,cyberdeck-theme.sh,cyberdeck-bashrc.sh}
sudo rm -f /etc/udev/rules.d/{99-cyberdeck-usb.rules,99-cyberdeck-gpio.rules}
sudo rm -f /usr/local/bin/{cdeck,cyberdeck}
sudo rm -rf /opt/cyberdeck-arsenal
sudo systemctl daemon-reload
```

Back up `vault/` and any reports you need **before** the last line.

## Getting help

Collect the facts first — it saves a round trip:

```bash
cdeck doctor --full --json > /tmp/doctor.json
cdeck status --json > /tmp/status.json
tests/test_hardware.sh --json > /tmp/hardware.json
dmesg | tail -50 > /tmp/dmesg.txt
lsusb > /tmp/lsusb.txt
journalctl -u cyberdeck-monitor -n 100 --no-pager > /tmp/monitor.log
```

Then open an issue at
<https://github.com/GeorgeH466/fluffy-octo-couscous/issues> with those attached.
**Redact** MAC addresses, SSIDs, IPs, capture contents and API keys before
posting — the JSON reports include hardware identifiers and the operator name.

---

*Related: [QUICKSTART.md](QUICKSTART.md) · [CONFIGURATION.md](CONFIGURATION.md) · [HARDWARE.md](HARDWARE.md) · [KEYBINDS.md](KEYBINDS.md) · [LEGAL.md](LEGAL.md)*
