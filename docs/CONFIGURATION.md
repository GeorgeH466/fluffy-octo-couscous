# CONFIGURATION

Everything in cyberdeck-arsenal is driven by a single YAML file:

```
/opt/cyberdeck-arsenal/cyberdeck.conf
```

The copy in the repository (`config/cyberdeck.conf`) is the one `setup.sh`
installs, mode `0600`, owned by root. There is exactly one configuration file —
the Python modules, the shell modules, the systemd units and the HUD all read
this same file through `lib/cyberlib.py` (`Config`) or `lib/cyberdeck_common.sh`
(`cdeck::conf_get`). Nothing is configured twice, and nothing is hard-coded.

---

## Contents

1. [Editing the file](#editing-the-file)
2. [Precedence and overrides](#precedence-and-overrides)
3. [File format rules](#file-format-rules)
4. [Key reference](#key-reference)
   - [general](#general)
   - [network](#network)
   - [monitoring](#monitoring)
   - [mac_rotation](#mac_rotation)
   - [api_keys](#api_keys)
   - [alerts](#alerts)
   - [automation](#automation)
   - [scanning](#scanning)
   - [sdr](#sdr)
   - [gps](#gps)
   - [gpio](#gpio)
   - [display](#display)
   - [vault](#vault)
   - [usb](#usb)
   - [payloads](#payloads)
   - [capture](#capture)
   - [testing](#testing)
5. [Recipes](#recipes)
6. [Validation and troubleshooting](#validation-and-troubleshooting)

---

## Editing the file

Three ways, all equivalent:

```bash
cdeck config                      # opens $EDITOR on the file
cdeck config display.theme        # read one value
cdeck config display.theme=matrix # set one value (comment-preserving write)
sudo nano /opt/cyberdeck-arsenal/cyberdeck.conf
```

`cdeck config <key>=<value>` uses `Config.set()` followed by `Config.save()`,
which patches only the affected lines: your comments, blank lines and ordering
survive every edit. Setting a key does **not** require root unless the file is
root-owned — on a normal install the file is `0600 root:root`, so use `sudo
cdeck config display.theme=matrix`.

Nothing needs restarting for most keys: modules read the file when they start.
The long-running services (`cyberdeck-monitor`, `probe-logger`, `ble-scanner`,
`rogue-ap-detector`, `usb-watcher`) re-read it on their next cycle, or
immediately after:

```bash
cdeck services restart
```

## Precedence and overrides

From lowest to highest priority:

| Priority | Source | Notes |
| --- | --- | --- |
| 1 | Defaults compiled into each module | Used when a key is absent |
| 2 | `cyberdeck.conf` | The normal case |
| 3 | `CYBERDECK_INSTALL_DIR` environment variable | Redirects every path; useful for testing |
| 4 | `CYBERDECK_CONF` environment variable | Point a script at an alternate config file |
| 5 | `CYBERDECK_LOG_LEVEL` | Overrides `general.log_level` for one process |
| 6 | Command-line flags | Always win, and are shown in `--help` |

Two environment variables are therefore very handy:

```bash
# Test a change without touching the live installation
CYBERDECK_INSTALL_DIR=/tmp/sandbox CYBERDECK_CONF=/tmp/sandbox/cyberdeck.conf \
    /opt/cyberdeck-arsenal/dashboard/main_hud.py

# One noisy debug run
CYBERDECK_LOG_LEVEL=DEBUG /opt/cyberdeck-arsenal/recon/passive/arp_mapper.py --once
```

## File format rules

* Two-space indentation. Tabs are not valid YAML.
* One blank line between sections is conventional but optional.
* Lists use inline flow syntax: `interfaces: [wlan0, wlan1]`.
* Booleans are lowercase `true` / `false` (also accepted: `yes`, `no`, `on`, `off`).
* Empty strings disable a feature: `webhook_url: ""`.
* Quote anything starting with `0x`, containing `:`, or that looks numeric when
  it is not — e.g. `oled_i2c_address: "0x3C"`, `vendor_prefix: "00:11:22"`.
* `#` starts a comment and may follow a value on the same line.
* Keys you have never seen before are harmless: unknown keys are preserved by
  `cdeck config` and ignored by the code that does not know them.

---

## Key reference

### general

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `install_dir` | path | `/opt/cyberdeck-arsenal` | Installation root. Every other path is derived from it. Only change this if you also move the directory. |
| `log_level` | enum | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. Applies to console and file logging. |
| `color_output` | bool | `true` | ANSI colour. Disabled automatically when stdout is not a terminal. |
| `authorised_use_acknowledged` | bool | `false` | The legal gate. While `false`, active/attack modules refuse to run. Set by `setup.sh` or after reading the notice. |
| `operator_name` | string | `operator` | Appears in reports, the MOTD and evidence manifests. |

### network

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `primary_interface` | iface | `wlan0` | Default interface for scanning and general traffic. |
| `monitor_interface` | iface | `wlan1` | Used for monitor mode: probe logging, `aircrack-ng`, rogue AP detection. |
| `ethernet_interface` | iface | `eth0` | Wired interface used by `utilities/network_profile_manager.sh`. |
| `default_vpn_config` | path | `/etc/openvpn/client.conf` | Profile brought up by `utilities/vpn_switcher.sh --up`. |
| `vpn_profile_dir` | path | `/etc/openvpn/profiles` | Directory of extra profiles for `--rotate`. |
| `wireguard_interface` | iface | `wg0` | WireGuard interface name. |
| `tor_enabled` | bool | `false` | Start in Tor mode. `vpn_switcher.sh --tor on` applies transparent proxy 9040 / DNS 5353. |
| `dns_servers` | list | `[1.1.1.1, 9.9.9.9]` | Resolvers written by the network profile manager and the kill switch. |
| `kill_switch` | bool | `true` | Default-deny everything outside the tunnel while a VPN is up. |
| `leak_test_url` | URL | `http://ifconfig.me/ip` | Plain-HTTP service used to read your public address. Must not redirect. |

> **Two-radio decks.** The design assumption is `wlan0` for connectivity and
> `wlan1` for monitoring. With one radio, set both keys to the same interface and
> expect the passive services to pause while you are connected.

### monitoring

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ble_scan_interval` | seconds | `30` | Gap between BLE scan windows in `recon/passive/ble_scanner.py`. |
| `probe_log_enabled` | bool | `true` | Enable the passive WiFi probe logger. |
| `arp_monitor_enabled` | bool | `true` | Enable passive ARP/neighbour monitoring. |
| `rogue_ap_check_interval` | seconds | `300` | Comparison period for the rogue AP baseline. |
| `service_watch_enabled` | bool | `true` | mDNS/SSDP/LLMNR discovery. |
| `hud_refresh_rate` | seconds | `2` | UI refresh interval (mirrored by `display.hud_refresh_rate`). |
| `alert_feed_limit` | count | `200` | Rows kept in the alert feed before pruning. |
| `retention_days` | days | `30` | History retained in the SQLite databases; pruned by `cdeck update`. |

### mac_rotation

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Master switch for `mac_rotator.py` and `mac-rotator.timer`. |
| `interval` | seconds | `3600` | Rotation period used by the timer. |
| `vendor_prefix` | enum/MAC | `random` | `random`, an OUI such as `"00:11:22"`, or a full MAC. |
| `interfaces` | list | `[wlan0]` | Interfaces to randomise. |
| `preserve_oui` | bool | `false` | Keep the vendor OUI and randomise only the device part. |

### api_keys

All keys are empty by default. Empty keys mean the corresponding enrichment
stage is skipped with a message — nothing fails, you simply get less context.
Free tiers are enough for field use.

| Key | Free tier | Powers |
| --- | --- | --- |
| `abuseipdb` | 1000 checks/day | IP reputation in `recon/active/target_profiler.sh` |
| `alienvault_otx` | unlimited | Domain/hash reputation, pulse feeds |
| `greynoise` | community | "Is this IP scanning the internet?" classification |
| `shodan` | limited | Host intelligence for the target profile |
| `nvd` | optional | CVE lookups for detected service versions |
| `urlscan` | optional | Historical scan data for a hostname |
| `cache_ttl` | seconds | `900` — on-disk cache lifetime for feed responses |

The keys are read by the modules at runtime; they are never written to logs.
Keep the file `0600` and never commit a filled-in copy.

### alerts

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `new_device_alert` | bool | `true` | Alert on an unknown MAC in the neighbour table. |
| `rogue_ap_alert` | bool | `true` | Alert when an AP deviates from the baseline. |
| `usb_insert_alert` | bool | `true` | Alert on USB insertion. |
| `webhook_url` | URL | `""` | Slack/Discord/ntfy/generic JSON webhook. Empty disables. |
| `desktop_notifications` | bool | `true` | `notify-send` on the operator's desktop. |
| `min_severity` | enum | `WARNING` | `INFO`, `WARNING`, `ALERT`, `ERROR`, `CRITICAL`. |
| `audible` | bool | `false` | Terminal bell on alert. |

Alerts are delivered through `cyberlib.Alerts`, which fans out to the SQLite
`alerts` table, the webhook, `notify-send`, the LED controller (if a status LED
is configured) and the OLED (if a panel is configured).

### automation

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `auto_recon_on_connect` | bool | `true` | Run passive recon automatically on joining a new SSID. |
| `auto_hash_usb` | bool | `true` | Hash USB mass storage on insertion. |
| `low_battery_exfil` | bool | `false` | Copy logs to `exfil_destination` below the battery threshold. |
| `battery_threshold` | percent | `15` | Battery level that triggers the exfil action. |
| `exfil_destination` | string | `""` | `user@host:/path` for `rsync`/`scp`. |
| `autostart_monitors` | bool | `false` | Start the monitoring services at boot. |
| `geofence_enabled` | bool | `false` | Enable GPS enter/exit rules (needs `gps.enabled`). |
| `trigger_poll_interval` | seconds | `10` | Trigger engine evaluation period. |

### scanning

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `default_depth` | enum | `standard` | `quick`, `standard`, `deep` for `target_profiler.sh`. |
| `output_dir` | path | `.../reports` | One timestamped directory per engagement. |
| `nmap_timing` | enum | `T4` | `T2` stealth → `T5` insane (no leading dash). |
| `nmap_extra_args` | string | `""` | Extra nmap flags, e.g. `--randomize-hosts` or `--data-length 50`. |
| `max_parallel_jobs` | count | `4` | Concurrency limit for background recon jobs. |
| `auto_target_ranges` | list | `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12` | Hosts outside these ranges are never auto-selected. |

### sdr

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | `false` disables every module under `sdr/`. |
| `device_index` | int | `0` | rtl_sdr device index (`rtl_test -t` lists them). |
| `gain` | auto/float | `auto` | Manual gain in dB, e.g. `32.8`. |
| `sample_rate` | Hz | `2048000` | Generic scanner sample rate. |
| `sweep_start_mhz` / `sweep_end_mhz` | MHz | `88` / `108` | Default sweep range (FM broadcast band out of the box). |
| `rtl_power_bin_size` | Hz | `20000` | FFT bin width. |
| `rtl_power_interval` | seconds | `2` | Integration time per step. |
| `dump1090_url` | URL | `http://127.0.0.1:8080` | Upstream feed for `adsb_tracker.py`. |
| `dump1090_binary` | string | `dump1090-mutability` | Local decoder used when no remote feed is configured. |
| `capture_dir` | path | `.../data/rf` | Recorded IQ captures. |

### gps

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Only meaningful when a receiver is present. |
| `device` | path | `/dev/ttyACM0` | Serial device; `setup.sh` fills this in when it finds one. |
| `baud` | int | `9600` | Serial speed. |
| `show_coordinates` | bool | `true` | Show a fix in the HUD. |
| `geofences` | list | `[]` | `[{name, lat, lon, radius_m}]` consumed by the trigger engine. |

### gpio

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Ignored on hardware without a GPIO header. |
| `status_led_pin` | BCM | `17` | Status LED. |
| `alert_led_pin` | BCM | `27` | Alert LED. |
| `button_pin` | BCM | `22` | Physical button. |
| `oled_enabled` | bool | `false` | Enable the I2C OLED. |
| `oled_i2c_address` | hex | `"0x3C"` | `0x3C` (SSD1306) or `0x3D`. |
| `oled_bus` | int | `1` | I2C bus number. |
| `blink_interval` | seconds | `0.5` | Base flash interval for patterns. |

### display

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `theme` | enum | `cyberpunk` | `cyberpunk`, `stealth`, `matrix`. Files in `aesthetic/themes/`. |
| `hud_refresh_rate` | seconds | `2` | HUD refresh interval. |
| `show_gps` | bool | `false` | GPS panel when a fix exists. |
| `show_sdr` | bool | `true` | Spectrum panel when SDR hardware is present. |
| `compact` | bool | `false` | Tight layout for 7" panels and narrow terminals. |
| `fancy_borders` | bool | `true` | Box drawing costs CPU — disable on slow boards. |

### vault

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `path` | path | `.../vault` | Encrypted container location (mode `0700`). |
| `gpg_recipient` | string | `""` | Empty = symmetric passphrase. A key id/fingerprint switches to asymmetric. |
| `auto_lock_minutes` | minutes | `15` | Idle lock time (`0` = never). |
| `editor` | string | `""` | Overrides `$EDITOR` for note editing. |

### usb

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `auto_actions` | list | `[hash, log, mount-ro]` | What `usb_handler.py` does on insertion: `image`, `hash`, `log`, `mount-ro`. |
| `image_dir` | path | `.../captures/usb` | Forensic images. |
| `max_image_size_gb` | GB | `128` | Refuse to auto-image bigger devices. |
| `image_block_size` | string | `4M` | `dd` block size. |

### payloads

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `http_port` / `https_port` | port | `8000` / `8443` | Listener ports. |
| `tls_cert` / `tls_key` | path | `.../state/payload.{crt,key}` | Generated on first run if absent. |
| `root` | path | `.../captures/payloads` | Directory served, and where new payloads are written. |
| `index_name` | filename | `Update-Setup.exe` | Lure name shown in directory listings. |

### capture

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `interface` | iface | `""` | tshark interface for `packet_weather.py`; empty = `network.primary_interface`. |
| `window_seconds` | seconds | `60` | History shown in the packet weather chart. |
| `refresh_interval` | seconds | `1` | Display refresh. |
| `bpf_filter` | BPF | `""` | Capture filter, e.g. `not port 22`. |
| `rotation_seconds` | seconds | `300` | Counter rotation period. |

### testing

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `connectivity_host` | IP/host | `1.1.1.1` | Target for `tests/test_connectivity.sh`. |
| `skip_hardware_tests` | bool | `false` | Skip hardware-specific checks. |
| `strict` | bool | `false` | Fail when optional components are missing. |

---

## Recipes

**One radio, monitor on demand.** Use `wlan0` for everything, and let the
passive services pause while connected:

```yaml
network:
  primary_interface: wlan0
  monitor_interface: wlan0
monitoring:
  probe_log_enabled: false
automation:
  auto_recon_on_connect: false
```

**Quiet deck.** No desktop popups, no bell, webhook only, and nothing green:

```yaml
alerts:
  desktop_notifications: false
  audible: false
  webhook_url: "https://ntfy.sh/mydeck"
  min_severity: ALERT
display:
  theme: stealth
```

**Client engagement defaults.** Stealthy timing, evidence kept, capture filter
narrowed to the engagement subnet:

```yaml
scanning:
  default_depth: quick
  nmap_timing: T2
  nmap_extra_args: "--max-rate 200 --randomize-hosts"
capture:
  bpf_filter: "net 10.10.10.0/24"
alerts:
  min_severity: WARNING
```

**Transportable deck.** Rotate MACs more often, kill switch on, Tor available:

```yaml
network:
  tor_enabled: true
  kill_switch: true
mac_rotation:
  enabled: true
  interval: 900
  interfaces: [wlan0, wlan1]
```

**Air-gapped work.** Stop the deck reaching for anything:

```yaml
api_keys: {}
automation:
  low_battery_exfil: false
  exfil_destination: ""
monitoring:
  service_watch_enabled: true
```

`cdeck profiles --save airgapped` captures the live state as a profile for later.

## Validation and troubleshooting

```bash
cdeck status                    # renders the effective configuration
cdeck doctor                    # validates the whole install, including the config
tests/test_installation.sh      # checks the specific keys the suite depends on
python3 -c "import yaml,sys; yaml.safe_load(open('/opt/cyberdeck-arsenal/cyberdeck.conf'))"
```

| Symptom | Cause | Fix |
| --- | --- | --- |
| `config: not a mapping` | A tab, or a list where a mapping belongs | Use spaces; check the indentation of the section |
| Values ignored | Key inside the wrong section | Sections matter: `display.hud_refresh_rate`, not `network.hud_refresh_rate` |
| `active modules refuse to run` | `authorised_use_acknowledged: false` | Run `setup.sh`, or `cdeck config general.authorised_use_acknowledged=true` |
| Editing fails with permission denied | File is `0600 root:root` | `sudo cdeck config <key>=<value>` |
| `Config` file replaced wholesale | An editor rewrote the file | Restore from `config/cyberdeck.conf`; `Config.save()` only patches lines and will not do this |
| Interface changes do nothing | The passive services cache the value | `cdeck services restart` |

If you make a mess of it:

```bash
sudo cp /opt/cyberdeck-arsenal/config/cyberdeck.conf /opt/cyberdeck-arsenal/cyberdeck.conf
sudo chmod 600 /opt/cyberdeck-arsenal/cyberdeck.conf
```

`config/cyberdeck.conf` in the install directory is the pristine reference copy
`setup.sh` lays down.

---

*Related: [QUICKSTART.md](QUICKSTART.md) · [HARDWARE.md](HARDWARE.md) · [TROUBLESHOOTING.md](TROUBLESHOOTING.md) · [KEYBINDS.md](KEYBINDS.md)*
