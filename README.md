# cyberdeck-arsenal

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███████╗ ██████╗██╗  ██╗    ║
║   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║ ██╔╝    ║
║   ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║█████╗  ██║     █████╔╝     ║
║   ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║██╔══╝  ██║     ██╔═██╗     ║
║   ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝███████╗╚██████╗██║  ██╗    ║
║    ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝    ║
║                    a r s e n a l                                              ║
║   turn a base BlackArch install into a complete cyberdeck platform            ║
║                                                                               ║
║   [ always-on recon ] [ situational HUD ] [ RF & SDR ] [ hardware deck ]      ║
║   [ automation engine ] [ encrypted evidence ] [ panic button ] [ 3 themes ]  ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

**cyberdeck-arsenal** is a turnkey suite that turns a plain BlackArch (or Arch)
installation into an integrated cyberdeck: always-on passive recon, live
dashboards, an RF/SDR workbench, an automation engine, hardware control for LEDs,
buttons and an OLED, encrypted evidence handling, and a single entry point that
ties all of it together.

One command installs it. One command runs it.

```bash
sudo ./setup.sh        # ~15 minutes, unattended, idempotent, resumable
cdeck                  # the deck
```

---

> ## ⚠ AUTHORISED USE ONLY
>
> This software contains wireless, network and radio tools that are **illegal to
> use against systems you do not own or do not have written permission to test**.
> Unauthorised access to computer systems is a criminal offence nearly
> everywhere — Computer Misuse Act 1990 (UK), 18 U.S.C. § 1030 (US), Directive
> 2013/40/EU, and their equivalents. Transmitting on regulated frequencies and
> intercepting communications are separately criminal in many jurisdictions.
>
> **Read [docs/LEGAL.md](docs/LEGAL.md) before you use any active module.** The
> first run requires you to acknowledge this, and until you do, the attack and
> active modules refuse to run.

---

## Contents

- [Highlights](#highlights)
- [Screens](#screens)
- [Install](#install)
- [The entry point](#the-entry-point)
- [What is in the box](#what-is-in-the-box)
  - [Passive recon — `recon/passive/`](#passive-recon--reconpassive)
  - [Active recon — `recon/active/`](#active-recon--reconactive)
  - [Reporting — `recon/reporting/`](#reporting--reconreporting)
  - [Attack — `attack/`](#attack--attack)
  - [Utilities — `utilities/`](#utilities--utilities)
  - [SDR — `sdr/`](#sdr--sdr)
  - [Dashboards — `dashboard/`](#dashboards--dashboard)
  - [Automation — `automation/`](#automation--automation)
  - [Aesthetic — `aesthetic/`](#aesthetic--aesthetic)
  - [Hardware — `gpio/`](#hardware--gpio)
  - [Services — `config/systemd/`](#services--configsystemd)
  - [Data — `data/`](#data--data)
  - [Tests — `tests/`](#tests--tests)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Documentation](#documentation)
- [Repository layout](#repository-layout)
- [Contributing and licence](#contributing-and-licence)

---

## Highlights

* **One installer that finishes the job.** `setup.sh` runs pre-flight checks,
  installs the full tool set, builds a virtualenv, lays down configs, udev rules
  and systemd units, initialises the databases, downloads wordlists, detects
  hardware, hardens the host, runs the test suite and writes its own uninstaller.
  It is idempotent, resumable and logged.
* **One entry point.** `cdeck` (also `cyberdeck`) dispatches to every module with
  consistent flags, consistent output and consistent logging. `cdeck dashboard`,
  `cdeck scan <target>`, `cdeck wifi`, `cdeck rf`, `cdeck vault`, `cdeck panic`…
* **Always-on awareness.** Seven systemd units run the passive monitors as
  services: WiFi probe requests, BLE devices, rogue APs, USB insertions, ARP
  changes, telemetry and schedule rotation.
* **Live visuals.** Five rich/textual dashboards: a main HUD, packet weather, a
  threat ticker, a network map and an RF spectrum view.
* **Everything shares one brain.** A single YAML configuration, one shared Python
  library (`lib/cyberlib.py`), one shared shell library
  (`lib/cyberdeck_common.sh`), one GPIO/I2C layer (`lib/cybergpio.py`), one log
  directory and SQLite databases that every module writes to.
* **Physical deck support.** Status and alert LEDs with semantic states, a
  multi-function button (short/long/double/triple/emergency), and a 128×64 I2C
  OLED with eight pages — all with a simulation backend so the code runs, and can
  be tested, on hardware that has none of it.
* **Evidence discipline.** SHA-256 evidence hashing with manifests, chain of
  custody notes, forensic USB imaging, and an encrypted vault for notes.
* **A panic button.** `cdeck panic` kills active tools, wipes captures and
  randomises MACs, with a dry run you can rehearse first.
* **Built to be verified.** Four test suites (installation, hardware, services,
  connectivity) plus `cdeck doctor`, all with `--json`.

## Screens

```text
┌─ cyberdeck ─────────────────────────────── ⚡ CYBERDECK ── 21:14:02 ─┬─ vitals ─────────┐
│  ▄▄▄▄▄  ▄  ▄ ▄▄▄▄ ▄▄▄▄  ▄▄▄▄ ▄▄▄▄ ▄▄▄▄   │ cpu  ███████░░░  41%   │
│  interfaces   wlan0 10.20.0.14/24         │ mem  █████░░░░░  52%   │
│               wlan1 monitor · 5 GHz       │ disk ███░░░░░░░  27%   │
│  services     7/7 active                  │ temp 48C   bat 87%    │
│  sdr          rtl-sdr @ 1090 MHz          │ up   3h 12m           │
├─ packet weather ──────────────────────────┴───────────────────────┴───────────────────┤
│       ▁▂▃▅▇▇▅▃▂▁▂▄▆█▇▅▃▂▁▁▂▃▅▆▇▆▄▃▂▁▁▂▃▄▅▆▇▆▅▄▃▂▁▁▂▃▄▅▆▇▆▅▄▃▂▁▂▃▄▅▆▇▇▆▅▄▃▂▁       │
│       tcp 1.2k/s  udp 340/s  icmp 12/s   dns 44/s   retrans 0.2%                     │
├─ threat ticker ──────────────────────────────────────────────────────────────────────┤
│  21:13:55  ALERT   rogue-ap  unknown BSSID 02:1A:C5:xx:xx:xx advertising "Corp-Guest"│
│  21:12:41  WARN    arp        new device 192.168.1.77 → de:ad:be:ef:12:34 (Unknown)   │
│  21:11:02  INFO    ble        3 new BLE advertisers · 1 matches the vuln database     │
│  21:09:38  INFO    wifi       4 probes for "Starbucks-WiFi" (randomised MAC)          │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

```text
$ cdeck rf --range 88-108
  RF SPECTRUM  rtl-sdr #0 · 88–108 MHz · gain auto · 2.048 MS/s
  108.0 ┤                                        ░
  104.0 ┤                          ░░░          ░░░░░
  100.0 ┤      ░░                ░░░░░░░        ░░░░   ← FM broadcast carriers
   96.0 ┤     ░░░░░    ░░       ░░░░░░░░░      ░░░░░
   92.0 ┤    ░░░░░░░  ░░░░     ░░░░░░░░░░░    ░░░░░░░
   88.0 ┼────────────────────────────────────────────────
        peaks: 99.5 101.9 104.4 106.2 MHz    noise −78 dBm
```

```text
$ cdeck status
  hardware     Raspberry Pi 4 Model B · aarch64 · 4 cores · 3.8 GB
  wifi         wlan0 managed ↑ · wlan1 monitor ↑ (RTL8812AU, injection ok)
  sdr          rtl-sdr #0 (R820T2) at 1090 MHz · 1 aircraft tracked
  gpio         sysfs backend · status LED 17 · alert LED 27 · button 22
  oled         SSD1306 0x3C on i2c-1 · page: status
  services     7 active / 7 installed · timer next in 41m
  databases    events 18 402 · alerts 27 · probes 9 118 · ble 1 044
  vault        locked · 12 notes · auto-lock 15m
  vpn          wg0 up · exit 185.x.x.x · kill switch on · no leaks
```

## Install

```bash
git clone https://github.com/GeorgeH466/fluffy-octo-couscous.git cyberdeck-arsenal
cd cyberdeck-arsenal
sudo ./setup.sh
```

Pre-flight checks, a printed plan, one confirmation, then roughly fifteen
unattended minutes. Full walkthrough: **[docs/QUICKSTART.md](docs/QUICKSTART.md)**.

| Flag | Effect |
| --- | --- |
| `--minimal` | core packages only; skips optional tooling and wordlists |
| `--full` | everything, including optional packages and full wordlist sets |
| `--yes` | non-interactive (the legal acknowledgement is still required) |
| `--no-hardening` | skip the firewall/fail2ban/SSH steps |
| `--uninstall [--purge]` | remove the suite, optionally with its data |

## The entry point

```text
cdeck                     launch the main HUD
cdeck status              hardware, service and configuration summary
cdeck doctor              diagnose installation and hardware problems
cdeck config [k[=v]]      read, set or edit the configuration
cdeck update              refresh databases, OUI, feeds and wordlists
cdeck hardware            detailed inventory and capabilities
cdeck help                the full command list

Recon
cdeck scan <target> [stealth|aggressive|vuln|udp|full]
cdeck profile <target> [quick|standard|deep]
cdeck packets [iface]  cdeck threats  cdeck netmap  cdeck rf
cdeck services         cdeck ble      cdeck arpmap  cdeck rogue

Attack                                                                 (authorised targets only)
cdeck wifi             cdeck responder  cdeck mitm  cdeck payloads

Utilities
cdeck vault            cdeck vpn      cdeck rotmac  cdeck profiles
cdeck usb              cdeck sdr      cdeck adsb     cdeck pager
cdeck tpms             cdeck keyfob

Automation and deck hardware
cdeck triggers         cdeck schedule  cdeck keybinds
cdeck led              cdeck oled      cdeck buttons

Aesthetics
cdeck theme <cyberpunk|stealth|matrix>
cdeck splash   cdeck decoy   cdeck fake-desktop

Emergency
cdeck panic [--soft] [--keep-reports] [--keep-captures]
```

Every module accepts `--help`, `--json` where a machine-readable form makes
sense, and `--simulate` where hardware is involved.

## What is in the box

### Passive recon — `recon/passive/`

| Module | What it does |
| --- | --- |
| `wifi_probe_logger.py` | Monitor-mode probe request capture: SSIDs sought, client MACs, randomised-MAC detection, vendor lookup, PNL analysis, signal history. Writes `probes.db` and stays under a channel hop plan. |
| `ble_scanner.py` | Continuous BLE enumeration with RSSI tracking, manufacturer resolution, and matching against 15 classes of known BLE weakness in `data/ble_vulnerability_db.json`. |
| `arp_mapper.py` | Passive ARP/neighbour monitoring that builds a device inventory, spots MAC/IP conflicts and unexpected gateways, and alerts on new devices. |
| `rogue_ap_detector.py` | Learns a baseline of legitimate BSSIDs and flags deviations: unexpected BSSID for a known SSID, security downgrade, channel anomaly, evil-twin patterns. |
| `service_watcher.py` | mDNS/SSDP/LLMNR discovery that names the hosts and printers on the network without sending a single probe packet. |

All five run as systemd services, write to the shared SQLite databases, raise
alerts through `cyberlib.Alerts`, and degrade to a skip message when the radio,
interface or package they need is missing.

### Active recon — `recon/active/`

| Module | What it does |
| --- | --- |
| `network_scanner.sh` | nmap orchestration with selectable profiles (`stealth`, `aggressive`, `vuln`, `udp`, `full`), timing from config, organised per-engagement output, and host discovery that respects `scanning.auto_target_ranges`. |
| `target_profiler.sh` | End-to-end target workflow: port and service discovery, OS and version fingerprinting, web fingerprint, SMB/SNMP enumeration, TLS inspection, API enrichment (Shodan/AbuseIPDB/GreyNoise/OTX when keys are set), and a written profile. |
| `web_recon.sh` | Web stack workflow: whatweb/wafw00f fingerprinting, nikto/gobuster/dirb directory discovery, subfinder/amass subdomains, screenshots where a headless browser exists. |
| `osint_gatherer.py` | Open-source intelligence: DNS records, WHOIS, certificate transparency, GitHub and search-engine dorking, email and username pivots, optional API enrichment, JSON output. |

Active modules refuse to run without the legal acknowledgement, warn about
authorisation, and check the target looks like something you should be testing.

### Reporting — `recon/reporting/`

| Module | What it does |
| --- | --- |
| `report_generator.py` | Renders findings into Markdown and HTML from the `{{TOKEN}}` templates in `data/templates/`, with an executive summary, severity table, per-host detail, timeline, and an evidence appendix. |
| `evidence_hasher.py` | SHA-256 (and optionally MD5/SHA-1) hashing of captures and reports, a signed manifest with timestamps and sizes, verification mode (`--verify`), and chain-of-custody notes. |

### Attack — `attack/`

| Module | What it does |
| --- | --- |
| `wifi_arsenal.sh` | Menu-driven WiFi tooling: monitor mode, surveys, targeted handshake capture, clientless PMKID capture, deauthentication, evil twin with a captive portal, and hashcat/john cracking handoff — always after an explicit authorisation confirmation. |
| `responder_launcher.sh` | Responder orchestration: interface checks, poison lists, analysis-only vs full capture, log parsing into the platform's event stream, and an always-on-scope guard. |
| `mitm_toolkit.sh` | Man-in-the-middle orchestration: ARP/DNS spoofing with bettercap or ettercap, sslstrip/bettercap HTTPS downgrade, transparent proxying, capture organisation and cleanup that restores the victim's ARP state. |
| `payload_server.py` | Flask-based delivery server: HTTP and HTTPS listeners with generated self-signed TLS, a directory index with a configurable lure name, upload endpoint, request logging with user agents, and payload metadata in `payloads.db`. |

**These modules exist for authorised testing.** They warn, they confirm, and they
log — they do not judge. Read [docs/LEGAL.md](docs/LEGAL.md).

### Utilities — `utilities/`

| Module | What it does |
| --- | --- |
| `hardware_detect.sh` | Probes ten hardware classes, writes `state/hardware.json`, prints a human or JSON report, and feeds setup and auto-configuration. |
| `mac_rotator.py` | Randomises MAC addresses (fully random, vendor-prefixed or a specific OUI), per interface, on demand or on a timer; records history and restores the original on request. |
| `vpn_switcher.sh` | B rings OpenVPN and WireGuard tunnels up and down, lists and rotates profiles, verifies the exit address against the leak URL, configures Tor with proxychains, and runs a default-deny kill switch. |
| `encrypted_vault.sh` | Passphrase or GPG-recipient encrypted note and file vault: `--init --open --close --add --rm --ls --cat --extract --verify --rekey`, with a tmpfs plaintext mount, shred-on-close and auto-lock. |
| `usb_handler.py` | udev-driven USB response: forensic `dd` imaging, hashing, read-only mounting, insertion logging into `usb.db`, and alerting on unexpected devices. |
| `self_destruct.sh` | The panic button: kills active tools, closes the vault, shreds captures/reports/state, randomises MACs, optionally powers off — with `--dry-run` so you can rehearse it, and `--keep-*` for the things you cannot lose. |
| `network_profile_manager.sh` | Saves the live network configuration as named profiles (interface, addressing, DNS, MTU, proxy, MAC policy), applies them in one command, and exports/imports them as tar archives. |

### SDR — `sdr/`

| Module | What it does |
| --- | --- |
| `sdr_scanner.py` | Wideband sweep-and-analyse: `rtl_power` heatmaps, peak detection with a noise floor estimate, persistent signal logging, and IQ capture of interesting bins. |
| `adsb_tracker.py` | ADS-B at 1090 MHz: reads a `dump1090` feed or decodes directly, tracks aircraft with positions, altitude, speed, heading and callsign, and writes a flight log plus a live map view. |
| `pager_decoder.py` | POCSAG and FLEX decoding from IQ or audio, with capcode extraction, message assembly, and a database of decoded pages — for lawful reception only. |
| `tpms_monitor.py` | Vehicle tyre-pressure sensor monitoring: decodes 315/433.92 MHz bursts into sensor IDs, pressures and temperatures, and tracks sensors over time. |
| `keyfob_analyzer.py` | Sub-GHz capture and analysis of fixed-code and rolling-code remotes: waveform capture, timing measurement, code extraction, and replay where the hardware supports it and the law allows it. |

All five exit `3` when no receiver is present, so scripts and services can tell
"no hardware" from "failed".

### Dashboards — `dashboard/`

| Module | What it does |
| --- | --- |
| `main_hud.py` | The main HUD: clock, uptime, interfaces, services, database counts, vitals (CPU, memory, disk, battery, temperature, GPS), recent alerts and a scrolling event feed, refreshed live with rich/textual. |
| `packet_weather.py` | Traffic as weather: tshark-driven packet rates, per-protocol breakdown, sparkline history, top talkers, and a rotating counter window. |
| `threat_ticker.py` | A live alert and event ticker with severity colouring, source filtering, acknowledgement, and a summary footer of counts by severity. |
| `network_map.py` | Topology view built from the neighbour table, ARP history and service discovery: gateway, subnets, devices with vendor and open ports, rendered as an ASCII graph. |
| `rf_spectrum.py` | Live RF spectrum: `rtl_power` sweeps rendered as a spectrum plot with peak labelling, waterfall mode, and capture of a selected bin to IQ. |

### Automation — `automation/`

| Module | What it does |
| --- | --- |
| `triggers.py` | Event-driven rule engine: conditions over events, database counts, time, interfaces, battery and GPS fences; actions that run commands, raise alerts, write reports or call the payload server; cooldowns, dry-run, daemon mode and an audit trail. |
| `scheduler.py` | Cron-like task scheduling with named jobs, intervals and calendars, run history, exit-code recording, concurrency limits, and `--run-now` for testing. |
| `keybinds.sh` | The single source of truth for every keybinding: installs blocks into sxhkd, sway, i3 and tmux, verifies the tools each binding calls, prints a cheat sheet, and uninstalls cleanly. |

### Aesthetic — `aesthetic/`

| Item | What it does |
| --- | --- |
| `themes/{cyberpunk,stealth,matrix}.theme` | Complete terminal themes: colours, prompt, borders, tmux/conky palettes, glyph sets. |
| `theme_switcher.sh` | Applies a theme to the terminal, tmux, conky, Xresources and the login profile; `--cycle`, `--preview`, `--json`. |
| `motd.sh` | Login MOTD: hardware summary, network state, recent alerts, tip of the day, three lengths, always exits 0. |
| `boot_splash.sh` | Nine-stage boot animation (`hardware`, `filesystem`, `network`, `wireless`, `sdr`, `databases`, `services`, `display`, `self-test`) that ends in a real health verdict; exit code is the number of failed stages; can install itself as a boot service. |
| `decoy/hollywood_mode.sh` | Believable "work is happening" terminal theatre: six scenes, adjustable speed, logging and an exit key. |
| `decoy/fake_desktop.sh` | Plausible full-screen productivity windows — spreadsheet, email, code, report, terminal, browser — rendered as HTML or directly in the terminal, for social camouflage. |

### Hardware — `gpio/`

| Module | What it does |
| --- | --- |
| `led_controller.py` | Status and alert LEDs with named states (`idle`, `scanning`, `capturing`, `vpn`, `alert`, `critical`, `panic`…) mapped to patterns (breathe, heartbeat, strobe, SOS…), alert hook, watch mode and a test mode. |
| `button_handler.py` | Multi-function button: short, long, double, triple and emergency presses mapped to configurable actions with confirmation for anything destructive, a JSONL audit trail, and a simulator. |
| `oled_display.py` | 128×64 SSD1306/SH1106 panel with eight pages (`status`, `network`, `vitals`, `alerts`, `sdr`, `engage`, `clock`, `splash`), alert badges, theme-aware chrome, rotation and an ASCII dump mode. |

All three share `lib/cybergpio.py` — a dependency-free I2C/GPIO layer with a
sysfs, Python-library and simulation backend, and its own 95-glyph 5×7 font.

### Services — `config/systemd/`

| Unit | Purpose |
| --- | --- |
| `cyberdeck-monitor.service` | Always-on situational awareness: runs the trigger engine in monitor profile. |
| `probe-logger.service` | Passive WiFi probe request logging. |
| `ble-scanner.service` | Continuous BLE enumeration. |
| `rogue-ap-detector.service` | Baseline comparison and rogue AP alerting. |
| `usb-watcher.service` | USB insertion handling. |
| `mac-rotator.service` / `mac-rotator.timer` | Scheduled MAC rotation. |

`setup.sh` installs and enables them; it deliberately does not start the attack
tooling.

### Data — `data/`

| Item | Contents |
| --- | --- |
| `oui_database.txt` | MAC vendor prefixes for offline vendor resolution. |
| `ble_vulnerability_db.json` | 15 classes of known BLE weaknesses with descriptions, affected devices and references. |
| `pager_capcodes.json` | Capcode ranges and agency labels for pager traffic interpretation. |
| `templates/` | `report_template.html`, `report_template.md`, `executive_summary.md`, plus payload templates. |
| `wordlists/download_wordlists.sh` | Fetches rockyou and SecLists subsets, verifies them, and installs them where the tools expect. |

### Tests — `tests/`

| Suite | Scope |
| --- | --- |
| `test_installation.sh` | Files, permissions, module compilation, config keys, databases, templates, units, entry point. |
| `test_hardware.sh` | Ten hardware classes, capability probing, `--watch` for flaky connectors. |
| `test_services.sh` | Unit state, enablement, restart counts, journal errors, timers, data freshness, stale locks. |
| `test_connectivity.sh` | Link, layer 3, DNS, HTTP/TLS, captive portal, path MTU, tunnel and leak state, feed reachability. |

Each exits with the number of failures, supports `--json`, and is safe to run at
any time. `cdeck doctor` runs all four and summarises.

## Configuration

One file: `/opt/cyberdeck-arsenal/cyberdeck.conf` — 17 sections, ~108 keys,
comment-annotated. `cdeck config key=value` edits it in place without destroying
your comments.

```yaml
general:
  install_dir: /opt/cyberdeck-arsenal
  log_level: INFO
network:
  monitor_interface: wlan1
  kill_switch: true
gpio:
  enabled: true
  status_led_pin: 17
  alert_led_pin: 27
  button_pin: 22
monitoring:
  retention_days: 30
```

Key-by-key reference and recipes: **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**.

## Architecture

```
                        ┌──────────────┐
                        │  bin/cdeck   │   the single entry point
                        └──────┬───────┘
        ┌──────────────────────┼───────────────────────┐
        ▼                      ▼                       ▼
  ┌───────────┐        ┌─────────────┐         ┌─────────────┐
  │ dashboard │        │ modules     │         │  services   │
  │ HUD etc.  │        │ recon/attack│         │  systemd    │
  │           │        │ utilities   │         │  passive    │
  └─────┬─────┘        │ sdr  gpio    │         └──────┬──────┘
        │              └──────┬───────┘                │
        └──────────┬──────────┴────────────────────────┘
                   ▼
        ┌──────────────────────────────────────────────┐
        │ lib/cyberlib.py      Config · Logger · DB    │
        │ lib/cybergpio.py     GPIO · I2C · OLED       │
        │ lib/cyberdeck_common.sh  bash equivalent     │
        └──────────┬───────────────────────┬───────────┘
                   ▼                       ▼
        ┌────────────────────┐   ┌──────────────────────┐
        │ cyberdeck.conf     │   │ data/*.db  logs/     │
        │ one YAML, 17 sects │   │ state/  captures/    │
        └────────────────────┘   └──────────────────────┘
```

Design rules the whole repository follows:

* One configuration file, read through one loader. Nothing is hard-coded.
* One logger per language, writing to `/opt/cyberdeck-arsenal/logs/`.
* Every script has a shebang, a header block (description, author, version,
  dependencies), `--help`, dependency checks, colour-coded output and graceful
  error handling; bash uses `set -euo pipefail`; Python uses type hints and
  docstrings.
* Root is required only where root is needed; hardware that is absent is skipped
  with an explanation, never a crash; services and schedulers never fail hard.
* Every module is runnable, testable and observable on a machine that has none
  of the hardware it can drive.

## Requirements

| | |
| --- | --- |
| **OS** | Arch Linux or BlackArch (x86_64, aarch64, armv7) |
| **Runtime** | Python 3.8+, bash 4.4+ |
| **Disk** | 10 GB free |
| **Optional** | monitor-mode WiFi adapter (for the wireless modules), Bluetooth adapter, RTL-SDR or HackRF, GPS receiver, Raspberry Pi GPIO header, I2C OLED, Proxmark3 |

Nothing optional is required to install, run or test the platform.

## Documentation

| Document | Contents |
| --- | --- |
| [QUICKSTART.md](docs/QUICKSTART.md) | Install, first run, five-minute tour, everyday commands |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | Every key, precedence rules, recipes, validation |
| [HARDWARE.md](docs/HARDWARE.md) | Supported devices, wiring, antennas, diagnosis |
| [KEYBINDS.md](docs/KEYBINDS.md) | Desktop, tmux, shell aliases, hardware button, LED states |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Symptom-by-symptom fixes, log locations, performance |
| [LEGAL.md](docs/LEGAL.md) | Authorised use, computer misuse, radio law, engagements, disclosure |

## Repository layout

```
cyberdeck-arsenal/
├── setup.sh                    installer, uninstaller and hardener
├── bin/cdeck                   the one entry point
├── lib/
│   ├── cyberlib.py             config · logging · databases · hardware · alerts
│   ├── cybergpio.py            GPIO · I2C · OLED (SSD1306/SH1106) layer
│   └── cyberdeck_common.sh     the same, for bash
├── config/
│   ├── cyberdeck.conf          the single configuration file
│   ├── aliases.sh              shell aliases
│   ├── bashrc_cyberdeck        shell integration
│   ├── tmux.conf               tmux: prefix, layouts, popups
│   ├── conky/                  desktop conky configuration
│   └── systemd/                7 units and timers
├── dashboard/                  5 live visualisations
├── recon/
│   ├── passive/                5 always-on monitors
│   ├── active/                 4 active tooling modules
│   └── reporting/              report generator and evidence hasher
├── attack/                     4 authorised-use attack modules
├── utilities/                  7 platform utilities
├── sdr/                        5 software-defined-radio modules
├── automation/                 trigger engine, scheduler, keybinds
├── aesthetic/                  themes, MOTD, boot splash, decoys
├── gpio/                       LED, button and OLED controllers
├── data/                       OUI, BLE vuln DB, capcodes, templates, wordlists
├── tests/                      4 test suites
└── docs/                       6 documents
```

## Contributing and licence

Bug reports and pull requests are welcome — especially hardware reports: if a
radio, SDR, GPS or GPIO device works (or does not work) on your deck, that is
useful information. Please redact MAC addresses, SSIDs, IPs, API keys and capture
contents from anything you post.

MIT Licence — see [LICENSE](LICENSE). You are responsible for how you use this
software; see [docs/LEGAL.md](docs/LEGAL.md) for what that means in practice.
