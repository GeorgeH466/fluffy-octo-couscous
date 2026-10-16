#!/usr/bin/env bash
# =============================================================================
# fake_desktop.sh - a believable "just a normal laptop" screen
# =============================================================================
#
# Description
# -----------
# The other half of the decoy pair. Where hollywood_mode.sh looks busy, this one
# looks *boring*: a spreadsheet, an inbox, a document, a code editor or a
# terminal full of ordinary work. It is what you put on the screen when somebody
# walks over and you would rather they saw a quarterly budget than a network map.
#
# Three renderers, chosen automatically:
#
#   window   a real fullscreen window (python3 tkinter) that ignores nothing -
#            click-through is deliberately not implemented, it is a decoy screen
#   browser  an HTML mock-up written to state/decoy/ and opened in a browser
#            (useful for kiosk mode or a screenshot)
#   tty      an ANSI full-screen rendering that works on any console, in tmux,
#            over SSH and on a serial terminal
#
# Every app is generated from local templates with plausible data. No file is
# read, no message is sent, and no network syscall is made. The privacy mode
# (--privacy) wipes the decoy artefacts on exit.
#
# Author      : cyberdeck-arsenal contributors
# Version     : 1.0.0
# Dependencies: bash; optional: python3 (tkinter for a real window)
# Licence     : MIT - authorised use only (see docs/LEGAL.md)
#
# Usage
# -----
#   ./fake_desktop.sh                          # spreadsheet on the terminal
#   ./fake_desktop.sh --app email --renderer window
#   ./fake_desktop.sh --app code --company "Northwind Trading Ltd"
#   ./fake_desktop.sh --app report --html-only # write the mock-up and exit
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../../lib/cyberdeck_common.sh" ]]; then
    # shellcheck source=lib/cyberdeck_common.sh
    source "${SCRIPT_DIR}/../../lib/cyberdeck_common.sh"
elif [[ -f /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh ]]; then
    source /opt/cyberdeck-arsenal/lib/cyberdeck_common.sh
else
    echo "fatal: cyberdeck_common.sh not found" >&2
    exit 1
fi

cdeck::init "fake_desktop"

INSTALL_DIR="$(cdeck::conf_get general.install_dir /opt/cyberdeck-arsenal)"
COMPANY="$(cdeck::conf_get general.operator_name operator) Holdings Ltd"
APP="spreadsheet"
RENDERER="auto"
OUTPUT_DIR=""
EXIT_KEY=""
DURATION=0
COLOUR=1
QUIET=0
PRIVACY=0
OPEN=0
KEEP=0
HTML_ONLY=0

usage() {
    cdeck::usage_header \
        "Show a thoroughly boring desktop so nobody looks twice" \
        "$0 [--app NAME] [--renderer auto|window|browser|tty] [--company NAME] [--duration SEC] [--exit-key K]" \
        "$0                              # quarterly budget on the console" \
        "$0 --app email --renderer window    # a fullscreen inbox" \
        "$0 --app code --html-only           # write the HTML mock-up and exit" \
        "$0 --privacy                        # wipe the artefacts on exit"
    cat <<EOF

${C_BOLD}APPS${C_RESET}
  spreadsheet   quarterly budget with formulas and a chart
  email         an inbox with routine business mail
  code          an editor open on a plausible service module
  report        a slide-deck / report page with charts
  terminal      a shell history of ordinary administration
  browser       a documentation portal page

${C_BOLD}OPTIONS${C_RESET}
  -a, --app NAME         which app to fake (default: spreadsheet)
  -r, --renderer WHICH   auto | window | browser | tty
  --company NAME         name used throughout the mock-up
  -d, --duration SEC     close after this long (default: until you quit)
  --exit-key KEY         quit when this key is pressed (tty renderer)
  --output-dir PATH      where the HTML mock-up is written (${INSTALL_DIR}/state/decoy)
  --html-only            write the mock-up and exit without displaying it
  --open                 after the tty renderer closes, write and report the HTML path
  --privacy              delete the generated mock-up on exit
  --keep                 keep the generated HTML (default for --html-only)
  --no-colour            plain output
  -q, --quiet            write nothing, just report the path
  -h, --help             this help
  -V, --version          version

${C_YELLOW}⚠${C_RESET} All content is generated locally. Nothing is read from your accounts.
EOF
}

# --------------------------------------------------------------------------- #
# Plausible data
# --------------------------------------------------------------------------- #
FIRST_NAMES=( Amir Beth Chloe Dan Priya Marcus Lena Tomas Sofia Grace Yusuf Hannah )
LAST_NAMES=( Okafor Whitfield Nakamura Brennan Iyer Alvarez Novak Kowalski Duarte
             Lindqvist Haddad Moreau )
DEPARTMENTS=( Finance Operations Procurement Legal Logistics Sales Support Engineering )
PROJECTS=( "Q4 budget review" "Vendor consolidation" "Warehouse migration" "ISO audit prep"
           "Payroll cycle" "Fleet maintenance" "Supplier onboarding" "Annual stocktake" )
SUBJECTS=( "Re: Q4 supplier terms" "Budget sign-off for the Frankfurt trip"
           "Invoice INV-2026-{n} query" "Weekly ops summary - W41"
           "ACTION: updated travel policy" "Minutes of the Tuesday stand-up"
           "Fwd: delivery window change" "Reminder: timesheets by Friday"
           "Re: contract renewal draft v3" "Sickness absence report"
           "Meeting room booking clash" "New starter IT checklist" )
BODY_LINES=(
    "Thanks for the update - I have added the figures to the tracker."
    "Can you confirm the numbers on rows 12 to 18 before I send this on?"
    "Finance have asked for a slightly different split this quarter."
    "No objections from my side, please go ahead once legal have signed off."
    "I will pick this up on Monday, unless it is more urgent than it looks."
    "Please keep the client copy free of internal comments."
)

pick() { local -a items=("$@"); printf '%s' "${items[$(( RANDOM % ${#items[@]} ))]}"; }

fake_name() { printf '%s %s' "$(pick "${FIRST_NAMES[@]}")" "$(pick "${LAST_NAMES[@]}")"; }

fake_email() {
    local name="$1"
    printf '%s.%s@%s.example' \
        "$(printf '%s' "${name%% *}" | tr '[:upper:]' '[:lower:]')" \
        "$(printf '%s' "${name##* }" | tr '[:upper:]' '[:lower:]')" \
        "$(printf '%s' "${COMPANY%% *}" | tr '[:upper:]' '[:lower:]')"
}

random_date() {
    local offset=$(( RANDOM % 20 ))
    date -d "-${offset} days" '+%d %b %Y' 2>/dev/null || date '+%d %b %Y'
}

# --------------------------------------------------------------------------- #
# HTML mock-ups
# --------------------------------------------------------------------------- #
html_header() {
    local title="$1"
    cat <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>${title} - ${COMPANY}</title>
<style>
 :root { --ink:#1f2430; --line:#d7dbe3; --head:#eef1f6; --accent:#2b5c9b; --ok:#1d7a45; }
 * { box-sizing:border-box; }
 body { margin:0; font:14px/1.45 "Liberation Sans",Arial,Helvetica,sans-serif; color:var(--ink);
        background:#f4f6f9; }
 header { background:var(--accent); color:#fff; padding:8px 14px; display:flex; gap:18px;
          align-items:center; }
 header .brand { font-weight:700; letter-spacing:.02em; }
 header nav { display:flex; gap:14px; font-size:13px; opacity:.92; }
 main { padding:18px 20px 40px; }
 h1 { font-size:20px; margin:.2em 0 .6em; }
 h2 { font-size:15px; margin:1.4em 0 .4em; }
 table { border-collapse:collapse; background:#fff; box-shadow:0 1px 2px rgba(0,0,0,.06);
         width:100%; max-width:1100px; }
 th, td { border:1px solid var(--line); padding:5px 8px; text-align:left; font-size:13px; }
 th { background:var(--head); font-weight:600; }
 td.num { text-align:right; font-variant-numeric:tabular-nums; }
 tr.total td { background:#f7f9fc; font-weight:700; }
 .pill { display:inline-block; padding:1px 8px; border-radius:10px; font-size:11px;
         background:#e6ebf3; color:#31405a; }
 .pill.ok { background:#e2f2e8; color:var(--ok); }
 .toolbar { display:flex; gap:8px; margin:0 0 10px; }
 .toolbar span { border:1px solid var(--line); background:#fff; border-radius:4px;
                 padding:3px 10px; font-size:12px; color:#40506b; }
 .mail { display:grid; grid-template-columns:280px 1fr; gap:0; background:#fff;
         border:1px solid var(--line); max-width:1100px; }
 .list { border-right:1px solid var(--line); }
 .list div { padding:9px 12px; border-bottom:1px solid #eef1f6; font-size:13px; }
 .list div.active { background:#eaf1fb; }
 .list small { display:block; color:#67748c; }
 .msg { padding:14px 18px; }
 .msg h3 { margin:.1em 0 .5em; font-size:16px; }
 .msg .meta { color:#67748c; font-size:12px; margin-bottom:12px; }
 pre { background:#0f1420; color:#d6e0f5; padding:14px 16px; overflow:auto;
       font:12.5px/1.5 "DejaVu Sans Mono",Consolas,monospace; border-radius:6px;
       max-width:1100px; }
 .slide { background:#fff; border:1px solid var(--line); box-shadow:0 2px 6px rgba(0,0,0,.08);
          max-width:900px; aspect-ratio:16/9; padding:34px 40px; position:relative; }
 .slide h1 { font-size:30px; } .slide ul { line-height:1.9; font-size:17px; }
 .slide footer { position:absolute; bottom:14px; right:20px; color:#8b93a5; font-size:12px; }
 .chart { display:flex; align-items:flex-end; gap:14px; height:190px; margin:18px 0 6px;
          max-width:760px; }
 .chart div { flex:1; background:linear-gradient(#4a86d8,#2b5c9b); position:relative;
              border-radius:3px 3px 0 0; }
 .chart div span { position:absolute; bottom:-22px; width:100%; text-align:center;
                   font-size:11px; color:#67748c; }
 footer.page { color:#8b93a5; font-size:12px; margin-top:26px; }
 a { color:var(--accent); }
</style></head><body>
<header>
  <span class="brand">${COMPANY}</span>
  <nav><span>Home</span><span>Finance</span><span>Operations</span><span>Shared drive</span>
       <span>Directory</span></nav>
  <span style="margin-left:auto;opacity:.9" id="clock"></span>
</header>
<main>
EOF
}

html_footer() {
    local stamp="$1"
    cat <<EOF
<footer class="page">Generated locally for screen-privacy purposes on ${stamp} ·
 internal wiki: policy/screen-lock · nothing on this page is real.</footer>
</main>
<script>
 (function () {
   var el = document.getElementById("clock");
   function tick() { el.textContent = new Date().toLocaleString(); }
   tick(); setInterval(tick, 1000);
 })();
</script>
</body></html>
EOF
}

write_spreadsheet_html() {
    local file="$1" i row total=0
    {
        html_header "Q4 Budget"
        printf '<h1>Q4 Budget Review &mdash; FY2026</h1>\n'
        printf '<div class="toolbar"><span>File</span><span>Edit</span><span>View</span>'
        printf '<span>Formulas</span><span>Share</span><span class="pill">Draft v4</span></div>\n'
        printf '<table><thead><tr><th>Line item</th><th>Supplier</th><th>Owner</th>'
        printf '<th>Budget</th><th>Committed</th><th>Variance</th><th>Status</th></tr></thead><tbody>\n'
        local -a suppliers=( Northwind Acme Logistics Volt Services Halden Freight
                             Bright Print Orion Parts Kestrel IT )
        local -a statuses=( "on track" "on track" "review" "on track" "pending" )
        for i in $(seq 1 22); do
            local item budget committed variance supplier owner status pill
            item="$(pick "${PROJECTS[@]}") line $(( i ))"
            supplier="$(pick "${suppliers[@]}")"
            owner="$(fake_name)"
            budget=$(( (RANDOM % 400 + 60) * 100 ))
            committed=$(( budget - (RANDOM % 30000) + 4000 ))
            variance=$(( budget - committed ))
            status="$(pick "${statuses[@]}")"
            total=$(( total + budget ))
            [[ "${status}" == "on track" ]] && pill="ok" || pill=""
            printf '<tr><td>%s</td><td>%s</td><td>%s</td><td class="num">%s</td>' \
                "${item}" "${supplier}" "${owner}" "$(printf '%'\''d' "${budget}")"
            printf '<td class="num">%s</td><td class="num">%s</td>' \
                "$(printf '%'\''d' "${committed}")" "$(printf '%'\''d' "${variance}")"
            printf '<td><span class="pill %s">%s</span></td></tr>\n' "${pill}" "${status}"
        done
        printf '<tr class="total"><td colspan="3">Total</td><td class="num">%s</td>' \
            "$(printf '%'\''d' "${total}")"
        printf '<td class="num">%s</td><td></td><td></td></tr>\n' "$(printf '%'\''d' "$(( total - 41000 ))")"
        printf '</tbody></table>\n'
        printf '<h2>Quarterly spend by department</h2>\n<div class="chart">\n'
        local department months
        for department in "${DEPARTMENTS[@]:0:7}"; do
            local height=$(( RANDOM % 60 + 35 ))
            printf '<div style="height:%d%%"><span>%s</span></div>\n' "${height}" "${department:0:8}"
        done
        printf '</div>\n'
        printf '<h2>Notes</h2>\n<table>\n'
        printf '<tr><th>Cell</th><th>Comment</th><th>Author</th></tr>\n'
        for i in C$(( RANDOM % 20 + 4 )) D$(( RANDOM % 20 + 4 )) F$(( RANDOM % 20 + 4 )); do
            printf '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' "${i}" \
                "$(pick "${BODY_LINES[@]}")" "$(fake_name)"
        done
        printf '</table>\n'
        html_footer "$(date '+%d %b %Y %H:%M')"
    } > "${file}"
}

write_email_html() {
    local file="$1" i
    {
        html_header "Inbox"
        printf '<h1>Inbox <span class="pill">17 unread</span></h1>\n'
        printf '<div class="mail"><div class="list">\n'
        local -a senders=() subjects=() dates=()
        for i in $(seq 1 12); do
            local sender subject when
            sender="$(fake_name)"
            subject="$(pick "${SUBJECTS[@]}")"
            subject="${subject//\{n\}/$(( RANDOM % 90000 + 10000 ))}"
            when="$(random_date)"
            senders+=("${sender}"); subjects+=("${subject}"); dates+=("${when}")
            printf '<div%s><b>%s</b><small>%s</small><small>%s</small></div>\n' \
                "$([[ ${i} -eq 1 ]] && echo ' class="active"')" "${sender}" "${subject}" "${when}"
        done
        printf '</div><div class="msg">\n'
        printf '<h3>%s</h3>\n' "${subjects[0]}"
        printf '<div class="meta">%s &lt;%s&gt; to me · %s</div>\n' \
            "${senders[0]}" "$(fake_email "${senders[0]}")" "${dates[0]}"
        printf '<p>Hi,</p>\n'
        for i in 1 2 3; do printf '<p>%s</p>\n' "$(pick "${BODY_LINES[@]}")"; done
        printf '<p>The updated spreadsheet is on the shared drive under '
        printf '<b>Finance/2026/Q4</b> &mdash; tab 2 has the revised phasing.</p>\n'
        printf '<p>Thanks,<br>%s<br><small>%s · %s</small></p>\n' \
            "${senders[0]}" "${COMPANY}" "$(fake_email "${senders[0]}")"
        printf '<p style="color:#8b93a5;font-size:12px">This message was generated '
        printf 'locally as a screen decoy. It is not a real email.</p>\n'
        printf '</div></div>\n'
        html_footer "$(date '+%d %b %Y %H:%M')"
    } > "${file}"
}

write_code_html() {
    local file="$1"
    {
        html_header "Editor"
        printf '<h1>services/billing/invoice_router.py <span class="pill">modified</span></h1>\n'
        printf '<pre>'
        cat <<'CODE'
 1  """Invoice routing for the finance pipeline."""
 2
 3  from __future__ import annotations
 4
 5  import logging
 6  from dataclasses import dataclass
 7  from datetime import date, timedelta
 8  from decimal import Decimal
 9  from typing import Iterable
10
11  LOG = logging.getLogger(__name__)
12
13  VAT_RATE = Decimal("0.20")
14  NET_TERMS_DAYS = 30
15
16
17  @dataclass(frozen=True)
18  class Invoice:
19      reference: str
20      supplier: str
21      cost_centre: str
22      net: Decimal
23      raised: date
24
25      @property
26      def vat(self) -> Decimal:
27          return (self.net * VAT_RATE).quantize(Decimal("0.01"))
28
29      @property
30      def gross(self) -> Decimal:
31          return self.net + self.vat
32
33      @property
34      def due(self) -> date:
35          return self.raised + timedelta(days=NET_TERMS_DAYS)
36
37
38  def route(invoices: Iterable[Invoice], approver: str) -> dict[str, list[Invoice]]:
39      """Group invoices by cost centre, oldest first."""
40      buckets: dict[str, list[Invoice]] = {}
41      for invoice in invoices:
42          if invoice.net <= 0:
43              LOG.warning("skipping %s: non-positive net", invoice.reference)
44              continue
45          buckets.setdefault(invoice.cost_centre, []).append(invoice)
46      for centre, items in buckets.items():
47          items.sort(key=lambda item: item.due)
48          LOG.info("%s: %d invoice(s) outstanding", centre, len(items))
49      LOG.debug("approver=%s centres=%d", approver, len(buckets))
50      return buckets
CODE
        printf '</pre>\n'
        printf '<h2>Problems</h2>\n<table><tr><th>Severity</th><th>Line</th><th>Message</th></tr>\n'
        printf '<tr><td>Information</td><td>48</td><td>Variable <code>items</code> is '
        printf 'reassigned inside the loop</td></tr>\n'
        printf '<tr><td>Hint</td><td>43</td><td>Consider using a logger with '
        printf 'structured context</td></tr>\n'
        printf '</table>\n'
        html_footer "$(date '+%d %b %Y %H:%M')"
    } > "${file}"
}

write_report_html() {
    local file="$1"
    {
        html_header "Board pack"
        printf '<h1>Operations Board Pack &mdash; November</h1>\n'
        printf '<div class="slide"><h1>Headlines</h1><ul>\n'
        printf '<li>Throughput up 4.1%% quarter on quarter</li>\n'
        printf '<li>Two suppliers consolidated into the framework agreement</li>\n'
        printf '<li>Stock accuracy holding at 99.2%%</li>\n'
        printf '<li>Open actions: 11 (4 overdue, none critical)</li>\n'
        printf '</ul><footer>%s · page 1 of 6</footer></div>\n' "${COMPANY}"
        printf '<h2>Spend by month</h2>\n<div class="chart">\n'
        local month
        for month in J F M A M J J A S O N D; do
            printf '<div style="height:%d%%"><span>%s</span></div>\n' "$(( RANDOM % 55 + 35 ))" "${month}"
        done
        printf '</div>\n'
        printf '<h2>Actions</h2>\n<table><tr><th>Ref</th><th>Action</th><th>Owner</th>'
        printf '<th>Due</th><th>State</th></tr>\n'
        local i
        for i in $(seq 1 11); do
            local due state pill
            due="$(random_date)"
            state="$(pick open open progress done)"
            [[ "${state}" == "done" ]] && pill="ok" || pill=""
            printf '<tr><td>A-%02d</td><td>%s</td><td>%s</td><td>%s</td>' \
                "${i}" "$(pick "${PROJECTS[@]}")" "$(fake_name)" "${due}"
            printf '<td><span class="pill %s">%s</span></td></tr>\n' "${pill}" "${state}"
        done
        printf '</table>\n'
        html_footer "$(date '+%d %b %Y %H:%M')"
    } > "${file}"
}

write_terminal_html() {
    local file="$1"
    {
        html_header "Terminal"
        printf '<h1>ops@bastion: ~ <span class="pill">session idle 4m</span></h1>\n<pre>'
        cat <<TERM
ops@bastion:~$ df -h /srv
Filesystem      Size  Used Avail Use% Mounted on
/dev/mapper/vg0-srv  1.8T  1.1T  620G  64% /srv

ops@bastion:~$ systemctl --failed
  UNIT LOAD ACTIVE SUB DESCRIPTION
0 loaded units listed.

ops@bastion:~$ tail -n 12 /var/log/backup/daily.log
${STAMP} INFO  starting incremental backup set=home
${STAMP} INFO  scanned 218441 files, 41.2 GiB changed
${STAMP} INFO  wrote nightly-$(date '+%Y%m%d').snar
${STAMP} INFO  verifying 218441 files against manifest
${STAMP} INFO  verification complete: 0 mismatches
${STAMP} INFO  backup finished in 00:41:02 (status ok)

ops@bastion:~$ psql -c "select count(*) from orders where created_at > now() - interval '1 day';"
 count
-------
 18422
(1 row)

ops@bastion:~$ make -C /srv/app check
pytest -q tests/
.............................................................. [100%]
62 passed in 41.77s

ops@bastion:~$ git -C /srv/app status -sb
## main...origin/main
 M docs/runbook.md

ops@bastion:~$ _
TERM
        printf '</pre>\n'
        html_footer "$(date '+%d %b %Y %H:%M')"
    } > "${file}"
}

write_browser_html() {
    local file="$1"
    {
        html_header "Runbook"
        printf '<h1>Runbook &mdash; nightly operations</h1>\n'
        printf '<div class="toolbar"><span>Search</span><span>Recent</span><span>Edit</span>'
        printf '<span class="pill">internal</span></div>\n'
        printf '<h2>1. Backup verification</h2>\n<pre>sudo /usr/local/sbin/backup-verify --set all --report\n</pre>\n'
        printf '<h2>2. Overnight batch</h2>\n'
        printf '<table><tr><th>Stage</th><th>Starts</th><th>Duration</th><th>Owner</th></tr>\n'
        printf '<tr><td>Extract</td><td>00:30</td><td>18m</td><td>data-eng</td></tr>\n'
        printf '<tr><td>Transform</td><td>00:50</td><td>44m</td><td>data-eng</td></tr>\n'
        printf '<tr><td>Load</td><td>01:40</td><td>12m</td><td>data-eng</td></tr>\n'
        printf '<tr><td>Reconcile</td><td>02:05</td><td>6m</td><td>finance</td></tr>\n'
        printf '</table>\n'
        printf '<h2>3. Escalation</h2>\n<p>If the reconcile stage reports a variance '
        printf 'above 0.5%%, raise it with the on-call finance analyst and record the '
        printf 'variance in the exception log.</p>\n'
        printf '<h2>Recent changes</h2><table><tr><th>Date</th><th>Author</th><th>Change</th></tr>\n'
        printf '<tr><td>%s</td><td>%s</td><td>Clarified the exception threshold</td></tr>\n' \
            "$(random_date)" "$(fake_name)"
        printf '<tr><td>%s</td><td>%s</td><td>Added the Kestrel depot steps</td></tr>\n' \
            "$(random_date)" "$(fake_name)"
        printf '</table>\n'
        html_footer "$(date '+%d %b %Y %H:%M')"
    } > "${file}"
}

# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #
renderer_available() {
    case "$1" in
        window)
            cdeck::has_cmd python3 && "${CDECK_PYTHON:-python3}" - <<'PYEOF' >/dev/null 2>&1
import tkinter  # noqa: F401
PYEOF
            ;;
        browser) cdeck::has_cmd xdg-open || cdeck::has_cmd firefox || cdeck::has_cmd chromium ;;
        tty) [[ -t 1 ]] ;;
        *) return 1 ;;
    esac
}

choose_renderer() {
    if [[ "${RENDERER}" != "auto" ]]; then
        printf '%s' "${RENDERER}"
        return 0
    fi
    if [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] && renderer_available window; then
        printf 'window'; return 0
    fi
    if renderer_available tty; then
        printf 'tty'; return 0
    fi
    printf 'browser'
}

write_mockup() {
    local app="$1" file="$2"
    STAMP="$(date '+%Y-%m-%d %H:%M:%S')"
    case "${app}" in
        spreadsheet) write_spreadsheet_html "${file}" ;;
        email)       write_email_html "${file}" ;;
        code)        write_code_html "${file}" ;;
        report)      write_report_html "${file}" ;;
        terminal)    write_terminal_html "${file}" ;;
        browser)     write_browser_html "${file}" ;;
        *)           return 1 ;;
    esac
    return 0
}

show_window() {
    # A real fullscreen Tk window: plain, boring, and nothing else.
    local app="$1" seconds="$2"
    local window_script
    window_script="$(mktemp /tmp/cyberdeck_decoy_XXXXXX.py)"
    cat > "${window_script}" <<PYEOF
import sys
try:
    import tkinter as tk
except Exception:
    sys.exit(3)

app = "${app}"
seconds = ${seconds}
company = """${COMPANY}"""
name = "${FAKE_USER:-operator}"
host = "${FAKE_HOST_NAME:-$(hostname -s 2>/dev/null || echo deck)}"

root = tk.Tk()
root.title(company)
root.configure(bg="#1b2430")
root.attributes("-fullscreen", True)
root.bind("<Escape>", lambda _event: root.destroy())
root.bind("<Control-q>", lambda _event: root.destroy())

head = tk.Frame(root, bg="#2b5c9b", height=34)
head.pack(fill="x")
tk.Label(head, text=company, bg="#2b5c9b", fg="white",
         font=("Helvetica", 13, "bold")).pack(side="left", padx=14)
clock = tk.Label(head, bg="#2b5c9b", fg="white", font=("Helvetica", 11))
clock.pack(side="right", padx=14)

body = tk.Text(root, bg="#11161f", fg="#cfd8e6", insertbackground="#cfd8e6",
               font=("DejaVu Sans Mono", 11), wrap="none", padx=16, pady=12)
body.pack(fill="both", expand=True)


def tick():
    import time
    clock.config(text=time.strftime("%a %d %b  %H:%M:%S"))
    root.after(1000, tick)


def quit_after():
    root.destroy()


content = {
    "spreadsheet": ["Budget review FY2026", "", "Press Escape to leave this screen.", "",
                    "The window renderer shows a neutral work surface.",
                    "The HTML mock-up has the full spreadsheet:",
                    "  ${MOCKUP_PATH}"],
    "email": ["Inbox (17 unread)", "", "Press Escape to leave this screen.",
              "The HTML mock-up has the full inbox:", "  ${MOCKUP_PATH}"],
    "code": ["services/billing/invoice_router.py", "", "Press Escape to leave.",
             "The HTML mock-up has the file:", "  ${MOCKUP_PATH}"],
    "report": ["Operations Board Pack", "", "Press Escape to leave.",
               "The HTML mock-up has the deck:", "  ${MOCKUP_PATH}"],
    "terminal": ["ops@bastion:~", "", "Press Escape to leave.",
                 "The HTML mock-up has the session:", "  ${MOCKUP_PATH}"],
    "browser": ["Runbook - nightly operations", "", "Press Escape to leave.",
                "The HTML mock-up has the page:", "  ${MOCKUP_PATH}"],
}
for number, line in enumerate(content.get(app, content["spreadsheet"])):
    body.insert("end", line + "\n")
body.config(state="disabled")

tick()
if seconds:
    root.after(int(seconds * 1000), quit_after)
root.mainloop()
PYEOF
    MOCKUP_PATH="${MOCKUP}" FAKE_HOST_NAME="${FAKE_HOST_NAME:-}" \
        "${CDECK_PYTHON:-python3}" "${window_script}"
    local status=$?
    rm -f "${window_script}"
    return ${status}
}

render_tty() {
    # A full-screen ANSI rendering that works on any console or over SSH
    local app="$1" seconds="$2"
    local alt=$'\033[?1049h' restore=$'\033[?1049l' hide=$'\033[?25l' show=$'\033[?25h'
    local bold=$'\033[1m' dim=$'\033[90m' reset=$'\033[0m'
    local accent=$'\033[44;97m' okc=$'\033[32m' warnc=$'\033[33m'
    if (( ! COLOUR )) || [[ ! -t 1 ]]; then
        alt=""; restore=""; hide=""; show=""; bold=""; dim=""; reset=""; accent=""; okc=""; warnc=""
    fi
    cleanup() {
        printf '%s%s%s' "${show}" "${restore}" "${reset}"
        trap - EXIT
        exit 0
    }
    trap cleanup EXIT INT TERM
    printf '%s%s' "${alt}" "${hide}"
    clear 2>/dev/null || printf '\033[2J\033[H'

    local width height
    width="$(tput cols 2>/dev/null || echo 100)"
    height="$(tput lines 2>/dev/null || echo 30)"
    (( width > 160 )) && width=160
    (( width < 60 )) && width=60

    printf '%s%-*s%s\n' "${accent}" "${width}" "  ${COMPANY}    ${FAKE_USER}@${FAKE_HOST_NAME:-$(hostname -s 2>/dev/null || echo deck)}    $(date '+%a %d %b %H:%M')" "${reset}"
    printf '\n'

    case "${app}" in
        spreadsheet)
            printf '%s%s%s\n' "${bold}" "Q4 Budget Review — FY2026" "${reset}"
            printf '%s' "  | Line item                | Supplier        | Owner            |     Budget |    Variance |"
            printf '\n'
            printf '%s' "  |--------------------------|-----------------|------------------|------------|-------------|"
            printf '\n'
            local i
            for i in $(seq 1 $(( height - 12 ))); do
                printf '  | %-24s | %-15s | %-16s | %10s | %11s |\n' \
                    "$(pick "${PROJECTS[@]}")" "$(pick Northwind Acme Volt Halden Kestrel)" \
                    "$(fake_name)" "$(( (RANDOM % 300 + 40) * 100 ))" "$(( RANDOM % 20000 ))"
            done
            printf '\n%s  Sheet 1 of 3 · autosaved %s · press Escape (or Ctrl-C) to leave%s\n' \
                "${dim}" "$(date '+%H:%M:%S')" "${reset}"
            ;;
        email)
            printf '%s%s%s\n\n' "${bold}" "Inbox — 17 unread" "${reset}"
            for i in $(seq 1 $(( height - 8 ))); do
                case $(( RANDOM % 6 )) in
                    0) printf '  %s*%s %-22s %-38s %s\n' "${warnc}" "${reset}" "$(fake_name)" \
                           "$(pick "${SUBJECTS[@]}")" "$(random_date)" ;;
                    *) printf '    %-22s %-38s %s\n' "$(fake_name)" \
                           "$(pick "${SUBJECTS[@]}")" "$(random_date)" ;;
                esac
            done
            printf '\n%s  Folder: Inbox · press Escape (or Ctrl-C) to leave%s\n' "${dim}" "${reset}"
            ;;
        code)
            printf '%s%s%s\n' "${bold}" "services/billing/invoice_router.py  —  modified" "${reset}"
            printf '%s' "$(cat <<'CODESNIP'
  17  @dataclass(frozen=True)
  18  class Invoice:
  19      reference: str
  20      supplier: str
  21      cost_centre: str
  22      net: Decimal
  23      raised: date
  24
  25      @property
  26      def vat(self) -> Decimal:
  27          return (self.net * VAT_RATE).quantize(Decimal("0.01"))
  28
  29      @property
  30      def gross(self) -> Decimal:
  31          return self.net + self.vat
  32
  33      def route(invoices, approver: str) -> dict[str, list[Invoice]]:
  34          buckets: dict[str, list[Invoice]] = {}
  35          for invoice in invoices:
  36              if invoice.net <= 0:
  37                  continue
  38              buckets.setdefault(invoice.cost_centre, []).append(invoice)
  39          return buckets
CODESNIP
)"
            printf '\n%s  0 errors · 1 hint · python 3.12 · utf-8 · press Escape (or Ctrl-C) to leave%s\n' \
                "${dim}" "${reset}"
            ;;
        report)
            printf '%s%s%s\n\n' "${bold}" "Operations Board Pack — November" "${reset}"
            printf '  Headlines\n'
            printf '    • Throughput up 4.1%% quarter on quarter\n'
            printf '    • Two suppliers consolidated into the framework agreement\n'
            printf '    • Stock accuracy holding at 99.2%%\n\n'
            printf '  Spend by month\n  '
            local month
            for month in J F M A M J J A S O N D; do
                printf '%s%s ' "${okc}" "$(printf '█%.0s' $(seq 1 $(( RANDOM % 4 + 1 ))))"
            done
            printf '%s\n  %s\n' "${reset}" "J F M A M J J A S O N D"
            printf '\n%s  page 1 of 6 · press Escape (or Ctrl-C) to leave%s\n' "${dim}" "${reset}"
            ;;
        terminal)
            printf '%s' "$(cat <<TERMSNIP
ops@bastion:~$ df -h /srv
Filesystem            Size  Used Avail Use% Mounted on
/dev/mapper/vg0-srv  1.8T  1.1T  620G  64% /srv

ops@bastion:~$ systemctl --failed
  UNIT LOAD ACTIVE SUB DESCRIPTION
0 loaded units listed.

ops@bastion:~$ tail -n 5 /var/log/backup/daily.log
INFO  starting incremental backup set=home
INFO  scanned 218441 files, 41.2 GiB changed
INFO  verifying 218441 files against manifest
INFO  verification complete: 0 mismatches
INFO  backup finished in 00:41:02 (status ok)

ops@bastion:~$ make -C /srv/app check
62 passed in 41.77s

ops@bastion:~$ _
TERMSNIP
)"
            printf '\n%s  press Escape (or Ctrl-C) to leave%s\n' "${dim}" "${reset}"
            ;;
        browser)
            printf '%s%s%s\n\n' "${bold}" "Runbook — nightly operations" "${reset}"
            printf '  1. Backup verification\n'
            printf '     sudo /usr/local/sbin/backup-verify --set all --report\n\n'
            printf '  2. Overnight batch\n'
            printf '     %-12s %-8s %-10s %s\n' "Stage" "Starts" "Duration" "Owner"
            printf '     %-12s %-8s %-10s %s\n' "Extract" "00:30" "18m" "data-eng"
            printf '     %-12s %-8s %-10s %s\n' "Transform" "00:50" "44m" "data-eng"
            printf '     %-12s %-8s %-10s %s\n' "Load" "01:40" "12m" "data-eng"
            printf '     %-12s %-8s %-10s %s\n' "Reconcile" "02:05" "6m" "finance"
            printf '\n  3. Escalation\n     Raise variances above 0.5%% with the on-call analyst.\n'
            printf '\n%s  internal wiki · press Escape (or Ctrl-C) to leave%s\n' "${dim}" "${reset}"
            ;;
    esac
    printf '\n%s  decoy screen: every value above was generated locally. Nothing was executed.%s\n' \
        "${dim}" "${reset}"

    if (( seconds > 0 )); then
        sleep "${seconds}" &
        WATCH=$!
        if [[ -n "${EXIT_KEY}" ]]; then
            local key=""
            read -r -t "${seconds}" -n 1 key 2>/dev/null || true
            kill "${WATCH}" 2>/dev/null || true
        else
            wait "${WATCH}" 2>/dev/null || true
        fi
    elif [[ -n "${EXIT_KEY}" ]]; then
        local key=""
        read -r -s -n 1 key 2>/dev/null || true
    elif [[ -t 0 ]]; then
        printf '%s  press Enter to return to the shell%s\n' "${dim}" "${reset}"
        read -r _ 2>/dev/null || true
    fi
    cleanup
}

render_browser() {
    local mockup="$1"
    if cdeck::has_cmd xdg-open; then
        xdg-open "${mockup}" >/dev/null 2>&1 &
        cdeck::ok "mock-up opened in your browser"
    elif cdeck::has_cmd firefox; then
        firefox --new-window "${mockup}" >/dev/null 2>&1 &
        cdeck::ok "mock-up opened in firefox"
    else
        cdeck::warn "no browser found - open the file yourself"
    fi
    cdeck::info "file: ${mockup}"
}

# --------------------------------------------------------------------------- #
# Arguments and dispatch
# --------------------------------------------------------------------------- #
FAKE_HOST_NAME="$(hostname -s 2>/dev/null || echo deck)"

while (( $# )); do
    case "$1" in
        --help|-h)        usage; exit 0 ;;
        --version|-V)     printf 'fake_desktop %s\n' "${CDECK_VERSION}"; exit 0 ;;
        -a|--app)         shift; APP="${1:-spreadsheet}" ;;
        -r|--renderer)    shift; RENDERER="${1:-auto}" ;;
        --company)        shift; COMPANY="${1:-${COMPANY}}" ;;
        -d|--duration)    shift; DURATION="${1:-0}" ;;
        --exit-key)       shift; EXIT_KEY="${1:-}" ;;
        --output-dir)     shift; OUTPUT_DIR="${1:-}" ;;
        --html-only)      HTML_ONLY=1; OPEN=0; QUIET=1 ;;
        --open)           OPEN=1 ;;
        --privacy)        PRIVACY=1 ;;
        --keep)           KEEP=1 ;;
        --no-colour|--no-color) COLOUR=0 ;;
        -q|--quiet)       QUIET=1 ;;
        *)                cdeck::error "unknown option: $1"; usage; exit 2 ;;
    esac
    shift
done

case "${APP}" in
    spreadsheet|email|code|report|terminal|browser) : ;;
    *) cdeck::error "unknown app: ${APP}"
       cdeck::info "apps: spreadsheet email code report terminal browser"
       exit 2 ;;
esac
case "${RENDERER}" in
    auto|window|browser|tty) : ;;
    *) cdeck::error "renderer must be auto, window, browser or tty"; exit 2 ;;
esac

OUTPUT_DIR="${OUTPUT_DIR:-${INSTALL_DIR}/state/decoy}"
MOCKUP="${OUTPUT_DIR}/${APP}_$(date '+%Y%m%d_%H%M%S').html"
mkdir -p "${OUTPUT_DIR}" 2>/dev/null || { OUTPUT_DIR="/tmp/cyberdeck-decoy"; mkdir -p "${OUTPUT_DIR}"; MOCKUP="${OUTPUT_DIR}/${APP}.html"; }

if ! (( QUIET )); then
    cdeck::banner "decoy desktop" "app ${APP} · company ${COMPANY}"
fi

if ! write_mockup "${APP}" "${MOCKUP}"; then
    cdeck::error "could not generate the ${APP} mock-up"
    exit 1
fi
chmod 0644 "${MOCKUP}" 2>/dev/null || true

if ! (( QUIET )); then
    cdeck::ok "mock-up written to ${MOCKUP}"
fi

if (( HTML_ONLY )); then
    printf '%s\n' "${MOCKUP}"
    exit 0
fi

CHOSEN="$(choose_renderer)"
if ! (( QUIET )); then
    cdeck::info "renderer: ${CHOSEN}"
fi

case "${CHOSEN}" in
    window)
        show_window "${APP}" "${DURATION}"
        status=$?
        if (( status != 0 )); then
            cdeck::warn "the window renderer is unavailable (python3-tk missing?) - using the console"
            render_tty "${APP}" "${DURATION}"
        fi
        ;;
    browser)
        if [[ -z "${DISPLAY:-}" && "${RENDERER}" == "browser" ]] && (( DURATION == 0 )); then
            # No display: print the path and stop rather than pretending
            cdeck::info "no display server - the mock-up is ready to open manually"
        fi
        render_browser "${MOCKUP}"
        ;;
    tty)
        render_tty "${APP}" "${DURATION}"
        ;;
esac

if (( OPEN )) && [[ "${CHOSEN}" != "browser" ]]; then
    render_browser "${MOCKUP}"
fi

if (( PRIVACY )); then
    if (( KEEP )); then
        cdeck::info "keeping ${MOCKUP} (--keep given)"
    else
        rm -f "${MOCKUP}"
        rmdir "${OUTPUT_DIR}" 2>/dev/null || true
        cdeck::ok "decoy artefacts removed"
    fi
fi

if ! (( QUIET )); then
    printf '\n'
    cdeck::info "nothing was read, written or sent outside ${OUTPUT_DIR}"
    cdeck::info "the HTML mock-up can be opened any time: ${MOCKUP}"
fi

exit 0
