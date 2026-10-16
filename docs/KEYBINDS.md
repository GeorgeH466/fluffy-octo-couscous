# KEYBINDS

The deck is built to be driven from the keyboard. There are four layers, and
they do not fight each other:

| Layer | Applies to | Installed by | Where the bindings live |
| --- | --- | --- | --- |
| Shell aliases | any shell | `setup.sh` → `config/aliases.sh` | `/etc/profile.d/cyberdeck-aliases.sh` |
| tmux | inside a tmux session | `setup.sh` → `config/tmux.conf` | `/opt/cyberdeck-arsenal/config/tmux.conf` |
| Desktop (X11 — sxhkd) | global, in X sessions | `cdeck keybinds --install` | `~/.config/sxhkd/sxhkdrc` |
| Desktop (Wayland — sway) | global, in sway | `cdeck keybinds --install` | `~/.config/sway/config` |
| Hardware button | physical, on the deck | `config/cyberdeck.conf` → `gpio.button_actions` | `gpio/button_handler.py` |

Install every applicable layer at once:

```bash
cdeck keybinds --install                  # detect the session and install
cdeck keybinds --install --session x11    # force the X11 layer
cdeck keybinds --install --dry-run        # show what would be written
cdeck keybinds --list                     # every binding in a table
cdeck keybinds --cheatsheet               # print this cheat sheet in the terminal
cdeck keybinds --test                     # verify the tools each binding calls
cdeck keybinds --uninstall                # remove the blocks it added
```

`keybinds.sh` writes clearly marked blocks, so it never fights a config file you
maintain by hand:

```
# >>> cyberdeck-arsenal keybinds >>>
...
# <<< cyberdeck-arsenal keybinds <<<
```

---

## Desktop — X11 (sxhkd)

| Keys | Action |
| --- | --- |
| `Super+Shift+h` | Launch the main HUD |
| `Super+Shift+t` | Deck status one-liner in a notification/terminal |
| `Super+Shift+p` | Profile the target in `$TARGET` |
| `Super+Shift+y` | Cycle the theme |
| `Super+Shift+d` | Full health check (`cdeck doctor --full`) |
| `Super+Shift+v` | Open the encrypted vault |
| `Super+Shift+x` | Panic button — dry run first, by design |
| `Super+Shift+n` | Open the network map |
| `Super+Shift+r` | Open the RF spectrum view |
| `Super+Shift+k` | Show the cheat sheet |

## Desktop — Wayland (sway)

| Keys | Action |
| --- | --- |
| `Super+Shift+h` | Launch the main HUD |
| `Super+Shift+t` | Deck status one-liner |
| `Super+Shift+y` | Cycle the theme |
| `Super+Shift+v` | Open the encrypted vault |
| `Super+Shift+x` | Panic button (dry run) |

i3 is supported too: `cdeck keybinds --install` appends the same `bindsym`
block to `~/.config/i3/config` when i3 is the session, and everything tmux
handles is unaffected.

> The panic binding deliberately runs `--dry-run`. If you want the real thing on
> a key, edit the block after installation — but rehearse it first, and keep in
> mind that it wipes `captures/` and `reports/` unless you pass `--keep-*`.

## tmux

Prefix is **`C-a`** (not `C-b`), base index 1, vi mode, mouse on, 50 000 lines of
history.

### Navigation and panes

| Keys | Action |
| --- | --- |
| `C-a` | prefix |
| `C-a c` | new window |
| `C-a \|` or `C-a \\` | split vertically |
| `C-a -` or `C-a _` | split horizontally |
| `C-a h/j/k/l` | move between panes |
| `C-a H/J/K/L` | resize (repeatable) |
| `C-a z` | zoom the pane |
| `C-a q` | kill pane |
| `C-a x` | kill window (confirms) |
| `C-a X` | kill session (confirms) |
| `C-a m` | rename the pane |
| `C-a C-h` / `C-a C-l` | previous / next window |
| `C-a C-a` | send a literal `C-a` to the pane |

### Deck-specific workspace layouts

| Keys | Action |
| --- | --- |
| `C-a d` | **Dashboard layout** — HUD on the right, live log tail below |
| `C-a r` | **Recon layout** — scanner and the probe logger's log |
| `C-a a` | **Attack layout** — WiFi arsenal and its log (confirms: authorised targets only) |
| `C-a s` | **Services** — `watch` over `systemctl list-units 'cyberdeck-*'` |

### Popups

| Keys | Action |
| --- | --- |
| `C-a H` | Help / this document |
| `C-a t` | Status popup |
| `C-a Y` | Threat ticker popup |
| `C-a P` | Packet weather popup |
| `C-a N` | Network map popup |
| `C-a F` | RF spectrum popup |
| `C-a S` | Full status, paged |
| `C-a C-t` | Theme switcher |
| `C-a C` | Capture the pane (last 3 000 lines) to a file |

### Copy mode (vi)

| Keys | Action |
| --- | --- |
| `C-a [` | enter copy mode |
| `v` | begin selection |
| `y` / `Enter` | copy and exit (pipe to `xclip`/`xsel` when present) |
| `/` / `?` | incremental search down / up |
| `C-a p` | paste |

### Session handling

| Keys | Action |
| --- | --- |
| `C-a d` (in the tmux table above) | the dashboard layout — this is *not* detach |
| `C-a D` | attach or create the session named `deck` |
| `C-a r` (alias) | reload the deck tmux config |

Detaching is `C-a` then `d` **only** when the deck's config is not loaded; with
`config/tmux.conf` sourced, `C-a d` builds the dashboard layout and detach moves
to `C-a C-d`-style escape or simply closing the terminal. If you prefer the
classic binding, edit `config/tmux.conf` and reload with `C-a :source-file`.

## Shell aliases

Installed to `/etc/profile.d/cyberdeck-aliases.sh`; `cdeck` and `cyberdeck` are
the same program.

### Deck and dashboards

| Alias | Expands to |
| --- | --- |
| `cyberdeck`, `cdeck`, `deck`, `hud` | `bin/cdeck dashboard` |
| `packets`, `packet-weather` | `bin/cdeck packets` |
| `threats`, `threat-ticker` | `bin/cdeck threats` |
| `netmap`, `network-map` | `bin/cdeck netmap` |
| `rf`, `rf-spectrum`, `spectrum` | `bin/cdeck rf` |
| `stats` | `bin/cdeck status` |

### Recon

| Alias | Expands to |
| --- | --- |
| `surveys`, `services` | `cdeck services` (passive service discovery) |
| `probe-log` | `recon/passive/wifi_probe_logger.py` |
| `ble` | `recon/passive/ble_scanner.py` |
| `arpmap` | `recon/passive/arp_mapper.py` |
| `rogue` | `recon/passive/rogue_ap_detector.py` |
| `osint` | `recon/active/osint_gatherer.py` |
| `arsonal` | `attack/wifi_arsenal.sh` |
| `report` | `recon/reporting/report_generator.py` |
| `reportdir` | `cd .../reports` |
| `hash` / `hashfile` | `evidence_hasher.py` (full / `--shallow`) |

### Attack and defence

| Alias | Expands to |
| --- | --- |
| `wifiar` | `attack/wifi_arsenal.sh` |
| `responder` | `attack/responder_launcher.sh` |
| `mitm` | `attack/mitm_toolkit.sh` |
| `payloads`, `payload-recipes` | `attack/payload_server.py` |
| `panic` | `utilities/self_destruct.sh` |
| `vault`, `rotmac`, `vpn`, `usb`, `profiles`, `hardware`/`hwd` | the matching `utilities/` module |

### SDR, GPIO, automation, aesthetics

| Alias | Expands to |
| --- | --- |
| `sdr`, `adsb`, `pager`, `tpms`, `keyfob` | `sdr/*.py` |
| `leds`, `oled`, `buttons` | `gpio/*.py` |
| `triggers`, `scheduler`/`jobs` | `automation/*.py` |
| `bootsplash`, `motd`, `theme` | `aesthetic/*.sh` |
| `hollywood`, `fakedesktop` | `aesthetic/decoy/*.sh` |
| `cheat` | the `deck-help` cheat sheet |
| `cdeckcheck` / `selftest` | `cdeck doctor` / `cdeck doctor --full` |
| `caps` | `ls -lht /opt/cyberdeck-arsenal/captures` |
| `decklog` | `tail -f /opt/cyberdeck-arsenal/logs/cyberdeck.log` |

List them all with `alias | grep -i cyber` or read
`/opt/cyberdeck-arsenal/config/aliases.sh`.

## Hardware button

Configured with `gpio.button_actions`; defaults:

| Press | Default action | Confirmation |
| --- | --- | --- |
| short | `bin/cdeck dashboard` | no |
| double | `aesthetic/theme_switcher.sh --cycle` | no |
| triple | `bin/cdeck status` | no |
| long | `utilities/self_destruct.sh --soft` | **yes** |
| emergency | `bin/cdeck panic --soft` | **yes** |

```yaml
gpio:
  button_pin: 22
  button_actions:
    short: "bin/cdeck dashboard"
    double: "aesthetic/theme_switcher.sh --cycle"
    triple: "bin/cdeck status"
    long: "utilities/self_destruct.sh --soft"
    emergency: "bin/cdeck panic --soft"
```

Test without touching the hardware:

```bash
cdeck buttons --list-actions
cdeck buttons --simulate short --dry-run
cdeck buttons --simulate sequence --dry-run --json
cdeck buttons --status
```

Long press and emergency prompt on the terminal unless you pass `--yes` or
`--dry-run`. Every press is written to `state/button_events.jsonl` and to the
`events` table, so you always have a record of what the deck was told to do and
when.

## LEDs as a status channel

No keys, but worth knowing: the status and alert LEDs report state without you
looking at a screen.

| State | Pattern |
| --- | --- |
| `idle` | slow breathe |
| `ready` | steady on |
| `scanning` | fast blink |
| `capturing` | double blink |
| `vpn` | slow blink |
| `alert` / `warning` | alert pattern |
| `critical` / `panic` | strobe |
| `off` | dark |

```bash
cdeck led --list-patterns
cdeck led --state scanning          # hand it a semantic state
cdeck led --pattern sos --duration 5
cdeck led --watch                   # follow the deck's real state
```

---

*Related: [QUICKSTART.md](QUICKSTART.md) · [CONFIGURATION.md](CONFIGURATION.md) · [HARDWARE.md](HARDWARE.md)*
