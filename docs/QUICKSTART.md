# QUICKSTART

From a bare BlackArch (or Arch) installation to a working cyberdeck in one
command. Budget fifteen minutes for the installer, most of it package downloads.

---

## 1. What you need

| | |
| --- | --- |
| **OS** | Arch Linux or BlackArch, x86_64 / aarch64 / armv7 |
| **Privileges** | root (the installer runs as root; the tools mostly do not) |
| **Disk** | 10 GB free minimum, 16 GB comfortable |
| **Network** | an internet connection for the package and wordlist downloads |
| **Time** | 10–20 minutes |

Nice to have, but not required: a monitor-mode-capable USB WiFi adapter
(Alfa/Alfa-like with RTL8812AU or MT7601U), an RTL-SDR dongle, a Raspberry Pi
header for the LEDs, an I2C OLED.

The installer detects and adapts to whatever is present. Missing hardware is
skipped, never fatal.

## 2. Install

```bash
git clone https://github.com/GeorgeH466/fluffy-octo-couscous.git cyberdeck-arsenal
cd cyberdeck-arsenal
sudo ./setup.sh
```

`setup.sh` will:

1. run pre-flight checks — root, distribution, connectivity, disk space, CPU
   architecture, and print the plan it intends to execute;
2. ask you to confirm **and** to acknowledge the authorised-use notice;
3. `pacman -Syu` and install the tool set appropriate to the detected hardware;
4. build the Python virtual environment at `/opt/cyberdeck-arsenal/venv`;
5. install the configuration, tmux/aliases/shell integration, MOTD and udev rules;
6. install and enable the systemd units and the MAC rotation timer;
7. create every SQLite database, install the OUI and BLE vulnerability databases;
8. download the wordlist subsets;
9. detect hardware and write `/opt/cyberdeck-arsenal/state/hardware.json`;
10. harden the host — default-deny inbound, UFW, fail2ban, SSH restrictions;
11. run the four test suites;
12. print the summary, your hardware, the quickstart card, and write
    `/opt/cyberdeck-arsenal/uninstall.sh`.

Useful variants:

```bash
sudo ./setup.sh --minimal      # skip the heavier optional packages and wordlists
sudo ./setup.sh --full         # everything, including optional tooling
sudo ./setup.sh --yes          # non-interactive (still requires the acknowledgement)
sudo ./setup.sh --uninstall    # remove the suite, keep your data unless --purge
```

The installer is **idempotent** and **resumable**: run it again after a failure
and it picks up at the step that failed. Everything it does is appended to
`/opt/cyberdeck-arsenal/logs/setup.log`.

## 3. First run

```bash
cdeck
```

If `cdeck` is not on your `PATH` yet, reopen your shell, or:

```bash
exec bash -l
/opt/cyberdeck-arsenal/bin/cdeck
```

The first launch shows the legal notice, explains what the deck can do, and asks
you to confirm that you are authorised to use the wireless and network tools. If
you decline, the passive and defensive parts still work; the active modules stay
locked.

You should now be looking at the main HUD: clock and uptime, network state,
wireless interface, vitals, recent alerts, and a scrolling event feed.

## 4. The five-minute tour

```bash
cdeck status                 # what the deck is, and what hardware it found
cdeck doctor                 # is anything broken?
cdeck hardware               # full inventory + capabilities
cdeck scan 192.168.1.0/24    # quick network scan of YOUR OWN network
cdeck netmap                 # visual topology of what you found
cdeck threats                # live threat/event ticker
cdeck packets wlan0          # packet weather
cdeck theme matrix           # aesthetic
cdeck keybinds --install     # wire the desktop hotkeys
cdeck help                   # everything else
```

Press `q` or `Ctrl-C` to leave any of the live views.

## 5. Configure it

The deck is usable with the defaults, but two settings are worth setting
immediately:

```bash
sudo cdeck config general.operator_name="Your Name"
sudo cdeck config network.monitor_interface=wlan1     # if it is not wlan1
cdeck config display.theme                            # check the current theme
```

Full key reference: [CONFIGURATION.md](CONFIGURATION.md).

## 6. Check the deck is healthy

```bash
cd /opt/cyberdeck-arsenal
tests/test_installation.sh     # files, permissions, modules, config
tests/test_hardware.sh         # radios, SDR, GPIO, I2C, GPS
tests/test_services.sh         # systemd units and their data
tests/test_connectivity.sh     # link, DNS, HTTP, tunnel, feeds
```

Each script exits with the number of failures, so `echo $?` after a run tells
you everything at a glance. `cdeck doctor` runs all four and summarises them.

## 7. Before you go anywhere

```bash
cdeck vault --init             # create the encrypted notes vault
cdeck profiles --save home     # snapshot the current network configuration
cdeck profiles --save lab      # ... and one for the lab
cdeck schedule --add "... "    # optional: periodic tasks
```

The panic button kills active tools, wipes captures and randomises MACs:

```bash
utilities/self_destruct.sh --soft --dry-run    # always rehearse it first
cdeck panic --soft                             # the real thing, soft mode
```

Bind it to a key and to the physical button before you need it
([KEYBINDS.md](KEYBINDS.md)).

---

## Everyday commands

| Task | Command |
| --- | --- |
| Main HUD | `cdeck` |
| Status one-liner | `cdeck status --oneline` |
| Network scan | `cdeck scan <target> [stealth\|aggressive\|vuln\|udp\|full]` |
| Full target profile | `cdeck profile <target> [quick\|standard\|deep]` |
| Packet weather | `cdeck packets [iface]` |
| Threat ticker | `cdeck threats` |
| Network map | `cdeck netmap` |
| RF spectrum | `cdeck rf` |
| Passive services | `cdeck services` |
| WiFi arsenal | `sudo cdeck wifi` |
| Vault | `cdeck vault [--open\|--close\|--add FILE]` |
| VPN | `cdeck vpn --up <profile>` · `cdeck vpn --status` |
| Rotate MAC | `cdeck rotmac --rotate` |
| SDR | `cdeck sdr --scan` · `cdeck adsb` · `cdeck pager` · `cdeck tpms` · `cdeck keyfob` |
| Themes | `cdeck theme <cyberpunk\|stealth\|matrix>` |
| Decoy screens | `cdeck decoy [scene]` · `cdeck fake-desktop [app]` |
| LEDs / OLED / buttons | `cdeck led` · `cdeck oled` · `cdeck buttons` |
| Automation | `cdeck triggers --list` · `cdeck schedule --list` |
| Report | `cdeck report --target <dir>` |
| Update | `sudo cdeck update` |
| Panic | `cdeck panic --soft` |

Every module also has `--help`, `--json` where a machine-readable form makes
sense, and `--simulate` where hardware is involved. Try
`cdeck led --simulate --pattern heartbeat`.

## Where things live

```
/opt/cyberdeck-arsenal/
├── cyberdeck.conf         the one configuration file
├── bin/cdeck              the entry point (symlinked to /usr/local/bin/cdeck)
├── dashboard/ recon/ attack/ utilities/ sdr/ automation/ gpio/ aesthetic/
├── data/                  databases, OUI, BLE vuln DB, templates, wordlists
├── logs/                  every module logs here
├── captures/              pcaps, handshakes, images, payloads
├── reports/               generated reports, one directory per engagement
├── profiles/              saved network profiles
├── vault/                 encrypted notes
└── state/                 runtime state: theme, hardware inventory, PID/lock files
```

## Getting rid of it

```bash
sudo /opt/cyberdeck-arsenal/uninstall.sh            # keep data
sudo /opt/cyberdeck-arsenal/uninstall.sh --purge    # remove everything
```

---

**Next:** [CONFIGURATION.md](CONFIGURATION.md) to tune it ·
[HARDWARE.md](HARDWARE.md) to plug things in ·
[KEYBINDS.md](KEYBINDS.md) to make it fast ·
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) when something misbehaves ·
[LEGAL.md](LEGAL.md) before you point it at a network you do not own.
