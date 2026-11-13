#!/usr/bin/env python3
"""sleet - ServiceNow from the terminal, using your own SSO browser session.

Config:   ~/.config/sleet/config.json    (instance, presets, extra detail fields)
Cookie:   ~/.config/sleet/cookie         (browser Cookie header, chmod 600)
Token:    ~/.config/sleet/token          (cached session token, written by sleet)
Board:    ~/.config/sleet/sections.json  (optional, dashboard-style sections)
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import webbrowser
from urllib.parse import quote

import requests

__version__ = "0.1.1"

CONFIG_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "sleet")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
COOKIE_FILE = os.path.join(CONFIG_DIR, "cookie")
SECTIONS_FILE = os.path.join(CONFIG_DIR, "sections.json")
TOKEN_FILE = os.path.join(CONFIG_DIR, "token")


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
# state labels hidden unless -a; override with "done_states" in config.json (e.g. non-English instances)
DONE = set(CFG.get("done_states") or ["Resolved", "Closed", "Cancelled", "Canceled",
                                      "Closed Complete", "Closed Incomplete", "Closed Skipped"])
PAGE = 500          # rows per request
MAX_ROWS = 5000     # stop paging here and say so

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


# control characters (incl. ESC) and bidi overrides: ticket text is untrusted, never let it drive the terminal
UNSAFE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def clean(v):
    return UNSAFE.sub("", v) if isinstance(v, str) else v


def read_cookie():
    try:
        mode = os.stat(COOKIE_FILE).st_mode
        with open(COOKIE_FILE) as f:
            raw = f.read().strip()
    except FileNotFoundError:
        die(f"no cookie file at {COOKIE_FILE} - paste your browser Cookie header there (chmod 600)")
    if mode & 0o077:
        print(f"[sleet] warning: {COOKIE_FILE} is readable by others - run: chmod 600 {COOKIE_FILE}",
              file=sys.stderr)
    if raw.lower().startswith("cookie:"):                # pasted with the header name
        raw = raw[len("cookie:"):].strip()
    if not raw or "\n" in raw or "\r" in raw:
        die(f"{COOKIE_FILE} must hold exactly one line: the value of the Cookie request header")
    return raw


def cached_token(key):
    try:
        with open(TOKEN_FILE) as f:
            d = json.load(f)
        return d["g_ck"] if d.get("key") == key and isinstance(d["g_ck"], str) else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save_token(key, token):
    try:
        fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"key": key, "g_ck": token}, f)
        os.chmod(TOKEN_FILE, 0o600)
    except OSError:
        pass                                             # the cache is only a speed-up


def forget_token():
    try:
        os.remove(TOKEN_FILE)
    except OSError:
        pass


def fetch_token(s):
    """Read g_ck from a page of the web UI; this is also the check that the session is alive."""
    r = s.get(f"{BASE}/incident_list.do", allow_redirects=False, timeout=30)
    if 300 <= r.status_code < 400 or r.status_code == 401:
        forget_token()
        die(f"session expired - refresh {COOKIE_FILE}")
    m = re.search(r"g_ck\s*=\s*['\"]([a-f0-9]+)['\"]", r.text)
    if not m:
        die("g_ck not found - grab it from DevTools console and set SLEET_GCK")
    s.headers["X-UserToken"] = m.group(1)
    save_token(s.token_key, m.group(1))


def session():
    raw = read_cookie()
    s = requests.Session()
    s.headers.update({"Cookie": raw, "Accept": "application/json"})
    s.token_key = hashlib.sha256(f"{INSTANCE}\n{raw}".encode()).hexdigest()   # ties the cache to this session
    s.token_cached = False
    if os.environ.get("SLEET_GCK"):
        s.headers["X-UserToken"] = os.environ["SLEET_GCK"]
        return s
    token = cached_token(s.token_key)
    if token:
        s.headers["X-UserToken"] = token
        s.token_cached = True
    else:
        fetch_token(s)
    return s


def api_error(r):
    try:
        err = r.json().get("error", {})
        return clean(f"{err.get('message', '')} {err.get('detail') or ''}".strip())
    except (ValueError, AttributeError):
        return clean(r.text[:300])


def call(s, method, path, **kw):
    """One API request. Never follows redirects (they lead to the SSO page and would carry the
    token along), turns every failure into a one-line message, and returns the "result"."""
    write = method != "GET"
    unsure = "it may or may not have been applied - check the ticket before you retry"
    while True:
        try:
            r = s.request(method, f"{BASE}{path}", timeout=60, allow_redirects=False, **kw)
        except requests.exceptions.RequestException as e:
            if write:
                die(f"{e.__class__.__name__} during the write: {unsure}")
            raise
        if r.status_code == 401 and s.token_cached:      # cached token gone stale: fetch a fresh one, once
            s.token_cached = False
            fetch_token(s)
            continue
        break
    if r.status_code == 401 or 300 <= r.status_code < 400:
        forget_token()
        die(f"{r.status_code} - session expired or token rejected, refresh {COOKIE_FILE}")
    if r.status_code >= 400:
        die(f"{r.status_code} - {'not written' if write else 'request refused'}: {api_error(r)}")
    try:
        return r.json()["result"]
    except (ValueError, KeyError, TypeError):
        if write:
            die(f"unreadable response to the write ({r.status_code}): {unsure}")
        die(f"unexpected response from {BASE} (not JSON) - is the session still valid? refresh {COOKIE_FILE}")


def get(s, table, query, fields):
    out = []
    while True:
        page = call(s, "GET", f"/api/now/table/{table}", params={
            "sysparm_query": query,
            "sysparm_fields": fields,
            "sysparm_display_value": "all",
            "sysparm_exclude_reference_link": "true",
            "sysparm_limit": str(PAGE),
            "sysparm_offset": str(len(out)),
        })
        for row in page:
            d = {k: clean(v.get("display_value") if isinstance(v, dict) else v) or "" for k, v in row.items()}
            d["_raw"] = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in row.items()}
            out.append(d)
        if len(page) < PAGE:
            return out
        if len(out) >= MAX_ROWS:
            print(f"[sleet] warning: {table} has more than {MAX_ROWS} matches, showing the first {len(out)}",
                  file=sys.stderr)
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
        with open(SECTIONS_FILE) as f:
            cfg = json.load(f)
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
    me = f"{shlex.quote(sys.executable)} {shlex.quote(os.path.realpath(__file__))}"
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
        if k == "assigned_to" and getattr(a, "assign_label", None):
            v = a.assign_label
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


def as_text(v):
    """Config values may be numbers or booleans; the API and the preview want text."""
    return ("true" if v else "false") if isinstance(v, bool) else str(v)


def config_fields(entry):
    return {k: as_text(v) for k, v in (entry.get("fields") or {}).items() if not k.startswith("_")}


def resolve_user(s, who):
    """(sys_id, label) for --assign. A bare display name can match several people, so look the
    user up by name, user name or email and refuse to guess."""
    if who == "me":
        rows = get(s, "sys_user", f"sys_id={ME}", "sys_id,name,user_name")
        if not rows:
            die("cannot read your own user record - use --assign with your user name")
    else:
        if "^" in who:
            die("--assign: '^' is not allowed in a name")
        rows = get(s, "sys_user", f"active=true^name={who}^ORuser_name={who}^ORemail={who}",
                   "sys_id,name,user_name,email")
        if not rows:
            return None, None                            # not visible to us: let ServiceNow match the name
        if len(rows) > 1:
            names = "; ".join(f"{u['name']} ({u['user_name']})" for u in rows[:10])
            die(f"--assign '{who}' matches {len(rows)} users: {names} - pass the user name or email instead")
    u = rows[0]
    return u["_raw"]["sys_id"], f"{u['name']} ({u['user_name']})"


def common_fields(s, a, body):
    """--note/--comment/--set/--assign, shared by update and create."""
    a.assign_label = None
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
        sys_id, a.assign_label = resolve_user(s, a.assign)
        body["assigned_to"] = sys_id or a.assign


def same(want, got):
    """Loose comparison for the read-back: case, line endings and number formatting don't count."""
    x, y = (clean(str("" if v is None else v)).strip().lower() for v in (want, got))
    if x == y:
        return True
    try:
        return float(x) == float(y)                      # 4 == 4.00
    except ValueError:
        return False


def verify(a, body, res):
    """ServiceNow silently drops writes blocked by ACLs or invalid choices: compare what came back."""
    skip = JOURNAL | ({"assigned_to"} if a.assign_label else set())     # sent as a sys_id, comes back as a name
    bad = [k for k, v in body.items() if k not in skip and not same(v, res.get(k, ""))]
    for k in bad:
        print(c("31", f"  {k} not applied: wanted '{body[k]}', is '{res.get(k)}'"))
    return bad


def create(s, a):
    tmpl = None if a.new.startswith("_") else CFG.get("templates", {}).get(a.new)
    if tmpl is not None and not (isinstance(tmpl, dict) and tmpl.get("table")):
        die(f"template '{a.new}' in {CONFIG_FILE} needs a \"table\"")
    table = tmpl["table"] if tmpl else a.new
    if not re.fullmatch(r"[a-z][a-z0-9_]*", table):
        die(f"'{table}' is neither a template in {CONFIG_FILE} nor a table name")
    body = config_fields(tmpl) if tmpl else {}
    if a.title:
        body["short_description"] = a.title
    if a.desc:
        body["description"] = read_text(a.desc)
    common_fields(s, a, body)
    if not body.get("short_description"):
        die("a new record needs a title: -t \"short description\"")

    preview_confirm(a, f"NEW {a.new}", table, body)
    fields = ",".join(["sys_id", "number", "state", "assigned_to"] + [k for k in body if k not in JOURNAL])
    res = call(s, "POST", f"/api/now/table/{table}", json=body, params={
        "sysparm_input_display_value": "true",
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true",
        "sysparm_fields": fields,
    })
    res = {k: clean(v) for k, v in res.items()}
    sys_id = res.get("sys_id") or ""
    t = {"number": res.get("number") or sys_id or "(no number)", "_raw": {"sys_id": sys_id}}   # not every table numbers
    cell = num_cell(t, 0, table).rstrip() if sys_id else t["number"]
    print(c("32", "created") + f"  {cell}  state: {res.get('state') or '-'}  assigned: {res.get('assigned_to') or '-'}")
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
        body.update(config_fields(preset))
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
    res = call(s, "PATCH", f"/api/now/table/{table}/{sys_id}", json=body, params={
        "sysparm_input_display_value": "true",   # allows state="In Progress", assigned_to="Name"
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true",
        "sysparm_fields": fields,
    })
    res = {k: clean(v) for k, v in res.items()}
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
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", INSTANCE):     # it becomes the host the cookie is sent to
        p.error(f"instance '{INSTANCE}' must be only the name before .service-now.com (letters, digits, hyphens)")
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
    except requests.exceptions.RequestException as e:
        die(f"request to {BASE} failed: {e.__class__.__name__}")
    except KeyboardInterrupt:
        die("interrupted")


if __name__ == "__main__":
    run()
