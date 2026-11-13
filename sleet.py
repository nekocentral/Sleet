#!/usr/bin/env python3
"""sleet - ServiceNow from the terminal, using your own SSO browser session.

Config:   ~/.config/sleet/config.json    (instance, presets, extra detail fields)
Cookie:   ~/.config/sleet/cookie         (browser Cookie header, chmod 600)
Board:    ~/.config/sleet/sections.json  (optional, dashboard-style sections)
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import webbrowser

import requests

__version__ = "0.1.0"
from urllib.parse import quote

CONFIG_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "sleet")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
COOKIE_FILE = os.path.join(CONFIG_DIR, "cookie")
SECTIONS_FILE = os.path.join(CONFIG_DIR, "sections.json")


def load_config():
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        sys.exit(f"[sleet] {CONFIG_FILE}: {e}")


CFG = load_config()
INSTANCE = os.environ.get("SLEET_INSTANCE") or CFG.get("instance", "")
BASE = f"https://{INSTANCE}.service-now.com"
PRESETS = CFG.get("presets", {})
ME = "javascript:gs.getUserID()"
MY_GROUPS = "javascript:getMyGroups()"

TASK_FIELDS = "sys_id,number,sys_class_name,short_description,state,priority,sys_updated_on"
CHG_FIELDS = "sys_id,number,type,state,risk,approval,start_date,end_date,short_description"
DONE = {"Resolved", "Closed", "Cancelled", "Canceled",
        "Closed Complete", "Closed Incomplete", "Closed Skipped"}

# (label, short tag, sys_class_name) - anything not listed lands in "Other"
SECTIONS = [
    ("Incidents", "INC", "incident"),
    ("Incident Task", "INCTask", "incident_task"),
    ("Problems", "PRB", "problem"),
    ("Problem Task", "PRBTask", "problem_task"),
    ("Changes", "CHG", "change_request"),
    ("Change Task", "CHGTask", "change_task"),
]

LINKS = sys.stdout.isatty()                              # OSC 8 hyperlinks only on a real terminal
TTY = LINKS or os.environ.get("SLEET_COLOR") == "1"         # colours also in fzf preview


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if TTY else str(s)


def count(n):
    return c("1;31" if n else "1;32", n)


def die(msg):
    sys.exit(f"[sleet] {msg}")


def session():
    try:
        raw = open(COOKIE_FILE).read().strip()
    except FileNotFoundError:
        die(f"no cookie file at {COOKIE_FILE} - paste your browser Cookie header there (chmod 600)")
    s = requests.Session()
    s.headers.update({"Cookie": raw, "Accept": "application/json"})
    if os.environ.get("SLEET_GCK"):
        s.headers["X-UserToken"] = os.environ["SLEET_GCK"]
        return s
    r = s.get(f"{BASE}/incident_list.do", allow_redirects=False, timeout=30)
    if r.status_code in (301, 302):
        die(f"session expired - refresh {COOKIE_FILE}")
    m = re.search(r"g_ck\s*=\s*['\"]([a-f0-9]+)['\"]", r.text)
    if not m:
        die("g_ck not found - grab it from DevTools console and set SLEET_GCK")
    s.headers["X-UserToken"] = m.group(1)
    return s


def get(s, table, query, fields):
    r = s.get(f"{BASE}/api/now/table/{table}", timeout=60, params={
        "sysparm_query": query,
        "sysparm_fields": fields,
        "sysparm_display_value": "all",
        "sysparm_exclude_reference_link": "true",
        "sysparm_limit": "500",
    })
    if r.status_code == 401:
        die(f"401 - session expired or token rejected, refresh {COOKIE_FILE}")
    r.raise_for_status()
    out = []
    for row in r.json()["result"]:
        d = {k: (v.get("display_value") if isinstance(v, dict) else v) or "" for k, v in row.items()}
        d["_raw"] = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in row.items()}
        out.append(d)
    return out


def fetch_tasks(s, a):
    who = (f"assignment_group={MY_GROUPS}^assigned_toISEMPTY" if a.unassigned
           else f"assignment_group={MY_GROUPS}" if a.group else f"assigned_to={ME}")
    rows = get(s, "task", f"active=true^{who}^ORDERBYDESCsys_updated_on", TASK_FIELDS)
    return rows if a.all else [t for t in rows if t["state"] not in DONE]


def fetch_changes(s, a):
    who = (f"assignment_group={MY_GROUPS}^assigned_toISEMPTY" if a.unassigned
           else f"assignment_group={MY_GROUPS}" if a.group else f"assigned_to={ME}^ORrequested_by={ME}")
    return get(s, "change_request", f"active=true^{who}^ORDERBYstart_date", CHG_FIELDS)


def record_url(t, table=None):
    raw = t.get("_raw", {})
    table = table or raw.get("sys_class_name") or "task"
    target = f"{table}.do?sys_id={raw['sys_id']}" if raw.get("sys_id") \
        else f"{table}.do?sysparm_query=number={t['number']}"
    return f"{BASE}/now/nav/ui/classic/params/target/{quote(target, safe='')}"


def num_cell(t, width, table=None):
    """Ticket number as a clickable OSC 8 hyperlink (Cmd-click), padded to width."""
    n = t["number"]
    cell = f"\033]8;;{record_url(t, table)}\033\\{n}\033]8;;\033\\" if LINKS else n
    return cell + " " * max(1, width - len(n))


def task_line(t, table=None):
    return (f"  {num_cell(t, 14, table)}{t['priority'][:12]:<12} {t['state'][:14]:<14} "
            f"{t['sys_updated_on'][:16]:<16}  {t['short_description'][:70]}")


def chg_line(ch):
    return (f"  {num_cell(ch, 14, 'change_request')}{ch['state'][:12]:<12} {ch['approval'][:10]:<10} "
            f"{ch['start_date'][:16]:<16}  {ch['short_description'][:70]}")


def strip(rows):
    return [{k: v for k, v in r.items() if k != "_raw"} for r in rows]


def board(s, a):
    tasks = fetch_tasks(s, a)
    chgs = fetch_changes(s, a)
    known = {cls for _, _, cls in SECTIONS}
    buckets = {cls: [t for t in tasks if t["_raw"]["sys_class_name"] == cls] for cls in known}
    other = [t for t in tasks if t["_raw"]["sys_class_name"] not in known]
    std = [x for x in chgs if x["_raw"]["type"] == "standard"]
    nonstd = [x for x in chgs if x["_raw"]["type"] != "standard"]

    if a.json:
        out = {label: strip(buckets[cls]) for label, _, cls in SECTIONS if cls != "change_request"}
        out["Changes"] = {"standard": strip(std), "non_standard": strip(nonstd)}
        out["Other"] = strip(other)
        print(json.dumps(out, indent=2))
        return

    summary = []
    for label, tag, cls in SECTIONS:
        if cls == "change_request":
            summary.append(f"{tag} {count(len(std))}/{count(len(nonstd))}")
        else:
            summary.append(f"{tag} {count(len(buckets[cls]))}")
    summary.append(f"Other {count(len(other))}")
    print("  ·  ".join(summary))
    if a.summary:
        return

    for label, _, cls in SECTIONS:
        if cls == "change_request":
            print(f"\n{c('1', label)}  standard {count(len(std))}  non-standard {count(len(nonstd))}")
            for tag, rows in (("std", std), ("non-std", nonstd)):
                for ch in rows:
                    print(chg_line(ch) + c("2", f"  [{tag}]"))
            continue
        rows = buckets[cls]
        print(f"\n{c('1', label)}  {count(len(rows))}")
        for t in rows:
            print(task_line(t))
    print(f"\n{c('1', 'Other')}  {count(len(other))}")
    for t in other:
        print(task_line(t))


LINE_FIELDS = "sys_id,number,short_description,state,priority,sys_updated_on"


def config_board(s, a):
    """Board driven by encoded queries copied from the dashboard tiles."""
    try:
        cfg = json.load(open(SECTIONS_FILE))
    except json.JSONDecodeError as e:
        die(f"{SECTIONS_FILE}: {e}")
    results = [(sec, get(s, sec["table"], sec["query"], LINE_FIELDS)) for sec in cfg]

    if a.json:
        print(json.dumps({sec["label"]: strip(rows) for sec, rows in results}, indent=2))
        return
    print("  ·  ".join(f"{sec['label']} {count(len(rows))}" for sec, rows in results))
    if a.summary:
        return
    for sec, rows in results:
        print(f"\n{c('1', sec['label'])}  {count(len(rows))}")
        for t in rows:
            print(task_line(t, sec["table"]))


def pick(s, a):
    """Interactive picker: fzf list with live ticket preview."""
    global TTY, LINKS
    if not shutil.which("fzf"):
        die("needs fzf: brew install fzf")
    tty, links = TTY, LINKS
    TTY = LINKS = False
    rows = fetch_tasks(s, a)
    lines = "\n".join(task_line(t).strip() for t in rows)
    TTY, LINKS = tty, links
    me = f"'{sys.executable}' '{os.path.realpath(__file__)}'"
    r = subprocess.run([
        "fzf", "--ansi", "--no-sort", "--layout=reverse",
        "--header", "enter: open here · ctrl-o: browser · esc: quit",
        "--preview", f"SLEET_COLOR=1 {me} {{1}} -n 3",
        "--preview-window", "right,60%,wrap",
        "--bind", f"ctrl-o:execute-silent({me} {{1}} -w)",
    ], input=lines, text=True, stdout=subprocess.PIPE)
    if r.returncode != 0 or not r.stdout.strip():
        return
    a.number = r.stdout.split()[0]
    show(s, a)


def flat(s, a):
    rows = fetch_tasks(s, a)
    if a.json:
        return print(json.dumps(strip(rows), indent=2))
    for t in rows:
        print(task_line(t))
    print(f"\n{len(rows)} tickets")


def changes(s, a):
    rows = fetch_changes(s, a)
    if a.json:
        return print(json.dumps(strip(rows), indent=2))
    for ch in rows:
        print(chg_line(ch) + c("2", f"  [{ch['type']}]"))
    print(f"\n{len(rows)} active changes")


DETAIL_FIELDS = ",".join([
    "sys_id", "number", "short_description", "state", "priority", "type", "risk",
    "approval", "assigned_to", "assignment_group", "caller_id", "opened_by", "requested_by",
    "opened_at", "sys_updated_on", "start_date", "end_date", "cmdb_ci", "problem_id", "parent",
    "description", "implementation_plan", "backout_plan", "test_plan", "close_notes",
    "comments_and_work_notes",
] + [f for f, _ in CFG.get("detail_fields", [])])
HEADER = [("state", "State"), ("priority", "Priority")] + \
         [tuple(x) for x in CFG.get("detail_fields", [])] + \
         [("type", "Type"), ("risk", "Risk"), ("approval", "Approval"),
          ("assigned_to", "Assigned to"), ("assignment_group", "Group"), ("caller_id", "Caller"),
          ("requested_by", "Requested by"), ("opened_by", "Opened by"), ("opened_at", "Opened"),
          ("sys_updated_on", "Updated"), ("start_date", "Planned start"), ("end_date", "Planned end"),
          ("cmdb_ci", "CI"), ("problem_id", "Problem"), ("parent", "Parent")]
BLOCKS = [("description", "Description"), ("implementation_plan", "Implementation plan"),
          ("backout_plan", "Backout plan"), ("test_plan", "Test plan"), ("close_notes", "Close notes")]
JOURNAL_SPLIT = re.compile(r"(?m)^(?=\d{2,4}[-/.]\d{2}[-/.]\d{2,4} \d{2}:\d{2}:\d{2} - )")


JOURNAL = {"work_notes", "comments"}


def read_text(v):
    return sys.stdin.read().strip() if v == "-" else v


def ask(msg):
    try:
        with open("/dev/tty") as tty:          # works even when stdin is piped
            print(msg, end=" ", flush=True)
            return tty.readline().strip().lower()
    except OSError:
        return ""


def preview_confirm(a, title, table, body):
    print(f"{c('1', title)}  {c('2', table)}")
    for k, v in body.items():
        tag = c("33", "CUSTOMER-VISIBLE comment") if k == "comments" else k
        first, *rest = v.splitlines() or [""]
        print(f"  {tag}: {first}" + (c("2", f"  (+{len(rest)} lines)") if rest else ""))
    while not a.yes:
        ans = ask("Apply? [y/N/v=view full]")
        if ans in ("y", "yes"):
            return
        if ans == "v":
            for k, v in body.items():
                print(f"\n{c('1', k)}\n{v}")
            print()
            continue
        die("aborted")


def common_fields(s, a, body):
    """--note/--comment/--set/--assign, shared by update and create."""
    if a.note:
        body["work_notes"] = read_text(a.note)
    if a.comment:
        body["comments"] = read_text(a.comment)
    for kv in a.set or []:
        k, sep, v = kv.partition("=")
        if not sep:
            die(f"--set expects field=value, got '{kv}'")
        body[k.strip()] = v
    if a.assign:
        body["assigned_to"] = (get(s, "sys_user", f"sys_id={ME}", "sys_id")[0]["_raw"]["sys_id"]
                               if a.assign == "me" else a.assign)


def verify(a, body, res):
    """ServiceNow silently drops writes blocked by ACLs or invalid choices: compare what came back."""
    skip = JOURNAL | ({"assigned_to"} if a.assign == "me" else set())   # "me" is sent as a sys_id
    bad = [k for k, v in body.items() if k not in skip and str(res.get(k, "")).lower() != v.lower()]
    for k in bad:
        print(c("31", f"  {k} not applied: wanted '{body[k]}', is '{res.get(k)}'"))
    return bad


def api_error(r):
    try:
        err = r.json().get("error", {})
        return f"{err.get('message', '')} {err.get('detail') or ''}".strip()
    except ValueError:
        return r.text[:300]


def create(s, a):
    tmpl = CFG.get("templates", {}).get(a.new)
    table = tmpl["table"] if tmpl else a.new
    body = dict(tmpl.get("fields", {})) if tmpl else {}
    if a.title:
        body["short_description"] = a.title
    if a.desc:
        body["description"] = read_text(a.desc)
    common_fields(s, a, body)
    if not body.get("short_description"):
        die("a new record needs a title: -t \"short description\"")

    preview_confirm(a, f"NEW {a.new}", table, body)
    fields = ",".join(["sys_id", "number", "state", "assigned_to"] + [k for k in body if k not in JOURNAL])
    r = s.post(f"{BASE}/api/now/table/{table}", timeout=60, json=body, params={
        "sysparm_input_display_value": "true",
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true",
        "sysparm_fields": fields,
    })
    if r.status_code == 401:
        die(f"401 - session expired or token rejected, refresh {COOKIE_FILE}")
    if r.status_code >= 400:
        die(f"{r.status_code} - not created: {api_error(r)}")
    res = r.json()["result"]
    t = {"number": res["number"], "_raw": {"sys_id": res["sys_id"]}}
    cell = num_cell(t, 0, table).rstrip()
    print(c("32", "created") + f"  {cell}  state: {res.get('state')}  assigned: {res.get('assigned_to') or '-'}")
    if verify(a, body, res):
        sys.exit(1)


def writing(a):
    return any([a.note, a.comment, a.set, a.assign, a.preset, a.hours is not None])


def update(s, a, table, sys_id, num):
    body = {}
    preset = {}
    if a.preset:
        name, text = a.preset
        if name not in PRESETS:
            die(f"no preset '{name}' in {CONFIG_FILE} (have: {', '.join(PRESETS) or 'none'})")
        preset = PRESETS[name]
        if preset.get("tables") and table not in preset["tables"]:
            die(f"preset '{name}' is for {', '.join(preset['tables'])}, not {table}")
        if preset.get("require_hours") and a.hours is None:
            die(f"preset '{name}' needs --hours N")
        body.update(preset.get("fields", {}))
        body[preset.get("notes_field", "close_notes")] = read_text(text)
    if a.hours is not None:
        hours_field = preset.get("hours_field") or CFG.get("hours_field")
        if not hours_field:
            die("--hours needs 'hours_field' in the preset or in config.json")
        body[hours_field] = str(a.hours)
    common_fields(s, a, body)
    if not any(v.strip() for v in body.values()):
        die("nothing to write (empty text?)")

    preview_confirm(a, num, table, body)

    fields = ",".join(["number", "state", "assigned_to"] + [k for k in body if k not in JOURNAL])
    r = s.patch(f"{BASE}/api/now/table/{table}/{sys_id}", timeout=60, json=body, params={
        "sysparm_input_display_value": "true",   # allows state="In Progress", assigned_to="Name"
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true",
        "sysparm_fields": fields,
    })
    if r.status_code == 401:
        die(f"401 - session expired or token rejected, refresh {COOKIE_FILE}")
    if r.status_code >= 400:
        die(f"{r.status_code} - not updated: {api_error(r)}")
    res = r.json()["result"]
    print(c("32", "updated") + f"  state: {res.get('state')}  assigned: {res.get('assigned_to')}")
    if verify(a, body, res):
        sys.exit(1)


def show(s, a):
    num = a.number.upper()
    hit = get(s, "task", f"number={num}", "sys_id,sys_class_name")
    if not hit:
        die(f"{num} not found")
    table = hit[0]["_raw"]["sys_class_name"]
    sys_id = hit[0]["_raw"]["sys_id"]

    if writing(a):
        return update(s, a, table, sys_id, num)
    if a.web:
        webbrowser.open(record_url({"number": num, "_raw": {"sys_id": sys_id}}, table))
        return
    t = get(s, table, f"sys_id={sys_id}", DETAIL_FIELDS)[0]
    if a.json:
        return print(json.dumps(strip([t])[0], indent=2))

    print(f"{c('1', t['number'])}  {c('2', table)}\n{t['short_description']}\n")
    for f, label in HEADER:
        if t.get(f):
            print(f"  {label + ':':<15} {t[f]}")
    for f, label in BLOCKS:
        if t.get(f, "").strip():
            print(f"\n{c('1', label)}\n{t[f].strip()}")

    entries = [e.strip() for e in JOURNAL_SPLIT.split(t.get("comments_and_work_notes", "")) if e.strip()]
    if entries:
        shown = entries if a.notes == 0 else entries[:a.notes]
        print(f"\n{c('1', 'Activity')}  {c('2', f'{len(shown)} of {len(entries)}, newest first')}")
        for e in shown:
            head, _, body = e.partition("\n")
            print(f"\n  {c('36', head)}")
            for line in body.strip().splitlines():
                print(f"    {line}")


def main():
    p = argparse.ArgumentParser(prog="sleet", description="Sleet: ServiceNow from the terminal, via your SSO session")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("-c", "--changes", action="store_true", help="changes assigned to or requested by you")
    mode.add_argument("-i", "--pick", action="store_true", help="interactive picker (fzf) with preview")
    mode.add_argument("-f", "--flat", action="store_true", help="single list instead of the board")
    p.add_argument("-V", "--version", action="version", version=f"sleet {__version__}")
    p.add_argument("-g", "--group", action="store_true", help="your assignment groups instead of you")
    p.add_argument("-u", "--unassigned", action="store_true",
                   help="unassigned tickets in your assignment groups (the queue)")
    p.add_argument("-a", "--all", action="store_true", help="include resolved items")
    p.add_argument("-s", "--summary", action="store_true", help="board counts only")
    p.add_argument("-j", "--json", action="store_true", help="JSON output")
    p.add_argument("number", nargs="?", help="ticket number to open, e.g. INC0012345")
    p.add_argument("-w", "--web", action="store_true", help="with a number: open it in the browser")
    p.add_argument("-n", "--notes", type=int, default=5, metavar="N",
                   help="with a number: activity entries to show (0 = all, default 5)")
    n = p.add_argument_group("create (no number)")
    n.add_argument("--new", metavar="TEMPLATE|TABLE",
                   help="create a record from a config template (e.g. inc) or a table (e.g. incident)")
    n.add_argument("-t", "--title", metavar="TEXT", help="short description of the new record")
    n.add_argument("--desc", metavar="TEXT", help="description of the new record; '-' reads stdin")
    w = p.add_argument_group("write (needs a number; -m/--comment/--set/--assign also work with --new)")
    w.add_argument("-m", "--note", metavar="TEXT", help="add work note (internal); '-' reads stdin")
    w.add_argument("--comment", metavar="TEXT", help="add CUSTOMER-VISIBLE comment; '-' reads stdin")
    w.add_argument("--set", action="append", metavar="FIELD=VALUE",
                   help="set a field by display value, repeatable (e.g. state='In Progress')")
    w.add_argument("--assign", metavar="me|NAME", help="assign to yourself or a user by name")
    w.add_argument("-p", "--preset", nargs=2, metavar=("NAME", "NOTES"),
                   help="apply a preset from config.json; NOTES goes to its notes field; '-' reads stdin")
    w.add_argument("-r", "--resolve", metavar="NOTES", help="shortcut for --preset resolve NOTES")
    w.add_argument("--review", metavar="NOTES", help="shortcut for --preset review NOTES")
    w.add_argument("--hours", type=int, metavar="N", help="hours worked, whole hours (field set in config)")
    w.add_argument("-y", "--yes", action="store_true", help="skip confirmation")
    a = p.parse_args()
    shortcuts = [("resolve", a.resolve), ("review", a.review)]
    if sum(v is not None for _, v in shortcuts) + (a.preset is not None) > 1:
        p.error("use only one of --preset/--resolve/--review")
    for name, text in shortcuts:
        if text is not None:
            a.preset = [name, text]
    if not INSTANCE:
        p.error(f"no instance: set \"instance\" in {CONFIG_FILE} or export SLEET_INSTANCE")
    if a.new and a.number:
        p.error("--new creates a record; leave out the ticket number")
    if a.new and (a.preset or a.hours is not None):
        p.error("presets and --hours are for existing tickets")
    if (a.title or a.desc) and not a.new:
        p.error("-t/--desc need --new")
    if writing(a) and not (a.number or a.new):
        p.error("write options need a ticket number")
    if [a.note, a.comment, a.desc, a.preset and a.preset[1]].count("-") > 1:
        p.error("only one of --note/--comment/--desc/--preset can read stdin")

    s = session()
    if a.new:
        create(s, a)
    elif a.number:
        show(s, a)
    elif a.changes:
        changes(s, a)
    elif a.pick:
        pick(s, a)
    elif a.flat:
        flat(s, a)
    elif os.path.exists(SECTIONS_FILE) and not (a.group or a.unassigned):
        config_board(s, a)
    else:
        board(s, a)


def run():
    """Console-script entry point."""
    try:
        main()
    except requests.exceptions.ConnectionError as e:
        die(f"cannot reach {BASE}: {e.__class__.__name__} (VPN/DNS?)")
    except KeyboardInterrupt:
        die("interrupted")


if __name__ == "__main__":
    run()
