#!/usr/bin/env python3
"""sleet - ServiceNow from the terminal, using your own SSO browser session.

Config:   ~/.config/sleet/config.json    (instance, presets, extra detail fields; config.yaml with PyYAML)
Cookie:   ~/.config/sleet/cookie         (browser Cookie header, chmod 600; written by sleet --refresh-cookie)
Token:    ~/.config/sleet/token          (cached session token, written by sleet)
Board:    ~/.config/sleet/sections.json  (optional, dashboard-style sections; sections.yaml with PyYAML)
"""
import argparse
import contextlib
import ctypes
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
import webbrowser
from urllib.parse import quote

import requests

try:
    import yaml          # optional: only a config.yaml or sections.yaml needs it
except ImportError:
    yaml = None

__version__ = "0.3.0"

PLATFORM = sys.platform          # one place to ask which system this is (the tests switch it)
FILE_MODES = os.name == "posix"  # Windows has no owner-only permission bits to check or set
CONFIG_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "sleet")


def config_path(name):
    """name.yaml or name.yml in CONFIG_DIR when one exists, else name.json."""
    for ext in (".yaml", ".yml"):
        if os.path.exists(os.path.join(CONFIG_DIR, name + ext)):
            return os.path.join(CONFIG_DIR, name + ext)
    return os.path.join(CONFIG_DIR, name + ".json")


def is_yaml(path):
    return path.endswith((".yaml", ".yml"))


CONFIG_FILE = config_path("config")
COOKIE_FILE = os.path.join(CONFIG_DIR, "cookie")
SECTIONS_FILE = config_path("sections")
TOKEN_FILE = os.path.join(CONFIG_DIR, "token")
REFRESH = ("sign in to ServiceNow in your browser and run: sleet --refresh-cookie" if PLATFORM == "darwin"
           else "sign in to ServiceNow in your browser, copy a request as cURL and run: "
                "sleet --refresh-cookie --browser clipboard (steps: \"Session cookie\" in the README)")
G_CK = re.compile(r"g_ck\s*=\s*['\"]([a-f0-9]+)['\"]")

# --refresh-cookie: where the browsers keep their cookies (Chrome and Edge are read on macOS only)
APP_SUPPORT = os.path.expanduser("~/Library/Application Support")
CHROMIUM = {   # browser: (profile root under APP_SUPPORT, Keychain item holding its cookie key)
    "chrome": ("Google/Chrome", "Chrome Safe Storage"),
    "edge": ("Microsoft Edge", "Microsoft Edge Safe Storage"),
}
SAFARI_HELP = ("Safari keeps the session in memory only. In Safari: open ServiceNow, Develop > Show Web Inspector "
               "> Network, reload, right-click a request to your instance > Copy as cURL, then run this again "
               "(no Develop menu? Settings > Advanced > Show features for web developers)")
CLIPBOARD_HELP = ("In your browser: open ServiceNow, press F12 > Network, reload, right-click a request to your "
                  "instance > Copy > Copy as cURL, then run this again")
# Chrome and Edge lock their cookie file on Windows and encrypt it with a key only the browser may use
NOT_READABLE = ("{browser} cookies can only be read on macOS; on this system use the clipboard: "
                "sleet --refresh-cookie --browser clipboard")


def read_config(path):
    """Parse a config file: YAML for .yaml/.yml (needs PyYAML), JSON otherwise."""
    with open(path, encoding="utf-8") as f:              # not the Windows code page
        if not is_yaml(path):
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                sys.exit(f"[sleet] {path}: {e}")
        if yaml is None:
            sys.exit(f"[sleet] {path} needs PyYAML: pip install pyyaml (or use a .json file)")
        try:
            return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            sys.exit(f"[sleet] {path}: {e}")


def load_config():
    try:
        return read_config(CONFIG_FILE)
    except FileNotFoundError:
        return {}


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

def ansi_terminal():
    """True when stdout is a terminal that understands escape sequences; switches them on in a Windows console."""
    if not sys.stdout.isatty():
        return False
    if PLATFORM != "win32":
        return True
    try:
        k32 = ctypes.windll.kernel32
        handle, mode = k32.GetStdHandle(-11), ctypes.c_uint32()          # STD_OUTPUT_HANDLE
        return bool(k32.GetConsoleMode(handle, ctypes.byref(mode))
                    and k32.SetConsoleMode(handle, mode.value | 4))      # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except (AttributeError, OSError):
        return False


LINKS = ansi_terminal()                                  # OSC 8 hyperlinks only on a real terminal
TTY = LINKS or os.environ.get("SLEET_COLOR") == "1"         # colours also in fzf preview


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if TTY else str(s)


def count(n):
    return c("1;31" if n else "1;32", n)


def die(msg):
    sys.exit(f"[sleet] {msg}")


# Ticket text is untrusted: never let it drive the terminal. Removed are the C0 controls except tab and
# newline (this includes ESC), DEL and the C1 controls, and the bidi overrides and isolates.
UNSAFE = dict.fromkeys(
    [c for c in range(0x20) if c not in (0x09, 0x0A)]
    + list(range(0x7F, 0xA0))
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A))
)


def clean(v):
    return v.translate(UNSAFE) if isinstance(v, str) else v


def read_cookie():
    try:
        mode = os.stat(COOKIE_FILE).st_mode
        with open(COOKIE_FILE, encoding="utf-8") as f:
            raw = f.read().strip()
    except FileNotFoundError:
        die(f"no cookie file at {COOKIE_FILE} - {REFRESH}")
    if FILE_MODES and mode & 0o077:
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
        die(f"session expired - {REFRESH}")
    m = G_CK.search(r.text)
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


# --- --refresh-cookie: copy the session out of a browser's cookie store (macOS) ---

def note(msg):
    print(f"[sleet] {msg}", file=sys.stderr)


def for_instance(domain):
    """True if a browser sends cookies of this domain to BASE."""
    d = domain.lstrip(".").lower()
    host = f"{INSTANCE.lower()}.service-now.com"
    return host == d or host.endswith("." + d)


@contextlib.contextmanager
def db_copy(path):
    """Open a copy of a browser's SQLite file: the browser locks it and may hold recent writes in -wal."""
    with tempfile.TemporaryDirectory() as tmp:
        for ext in ("", "-wal"):
            if os.path.exists(path + ext):
                shutil.copyfile(path + ext, os.path.join(tmp, "db" + ext))
        con = sqlite3.connect(os.path.join(tmp, "db"))
        try:
            yield con
        finally:
            con.close()


def aes_decrypt(key, data):
    """AES-128-CBC the way Chromium encrypts cookies on macOS, via CommonCrypto (no extra package)."""
    cc = ctypes.CDLL("/usr/lib/libSystem.dylib")
    cc.CCCrypt.argtypes = [ctypes.c_uint32] * 3 + [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    out, n = ctypes.create_string_buffer(len(data)), ctypes.c_size_t()
    # kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding; the IV is 16 spaces
    if cc.CCCrypt(1, 0, 1, key, len(key), b" " * 16, data, len(data), out, len(data), ctypes.byref(n)):
        raise ValueError("cannot decrypt cookie")
    return out.raw[:n.value]


# what a broken, half-written or unexpected browser file can raise: such a profile is skipped, not fatal
READ_ERRORS = (sqlite3.Error, OSError, ValueError, KeyError, IndexError, TypeError)


def unreadable(label, e):
    note(f"{label}: cannot read its cookies ({e.__class__.__name__}), skipped")


def cookie_header(cookies):
    """Cookie header from (domain, name, value). A name set on several domains is sent once, with the
    value of the domain closest to the instance, so a cookie on .service-now.com cannot hide the real one."""
    best = {}
    for domain, name, value in cookies:
        rank = len(domain.lstrip("."))
        if name not in best or rank >= best[name][0]:
            best[name] = (rank, value)
    return "; ".join(f"{name}={value}" for name, (_, value) in best.items())


def chromium_cookies(browser):
    """Chrome and Edge write session cookies to disk while they run; the values are encrypted."""
    root, keychain = CHROMIUM[browser]
    key = None
    now = (time.time() + 11644473600) * 1_000_000          # Chromium counts microseconds since 1601
    for db in sorted(glob.glob(os.path.join(APP_SUPPORT, root, "*", "Cookies"))):
        label = f"{browser} ({os.path.basename(os.path.dirname(db))})"
        try:
            with db_copy(db) as con:
                version = int(con.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()[0])
                rows = [r for r in con.execute(
                    "SELECT host_key, name, value, encrypted_value FROM cookies WHERE host_key LIKE "
                    "'%service-now.com' AND (expires_utc = 0 OR expires_utc > ?)", (now,)) if for_instance(r[0])]
            if not rows:
                continue
            if key is None:                                 # first use asks for Keychain access
                pw = subprocess.run(["security", "find-generic-password", "-w", "-s", keychain],
                                    capture_output=True, text=True)
                if pw.returncode:
                    return note(f"{browser}: no access to '{keychain}' in your Keychain")
                key = hashlib.pbkdf2_hmac("sha1", pw.stdout.strip().encode(), b"saltysalt", 1003, 16)
            jar, unknown = [], 0
            for host, name, value, enc in rows:
                if enc[:3] == b"v10":
                    value = aes_decrypt(key, enc[3:])
                    value = (value[32:] if version >= 24 else value).decode()   # 24+: SHA-256 of the domain first
                elif enc:                                   # a format this code does not know: never send it empty
                    unknown += 1
                    continue
                jar.append((host, name, value))
            if unknown:
                note(f"{label}: left out {unknown} cookie{'s' * (unknown != 1)} in an unknown format")
        except READ_ERRORS as e:
            unreadable(label, e)
            continue
        if jar:
            yield label, cookie_header(jar)


def lz4_block(src):
    """Decompress one LZ4 block, the format of Firefox's .jsonlz4 files, without the lz4 package."""
    out, i = bytearray(), 0

    def length(n):
        nonlocal i
        if n == 15:
            while True:
                i += 1
                n += src[i - 1]
                if src[i - 1] != 255:
                    break
        return n

    while True:
        token = src[i]
        i += 1
        n = length(token >> 4)                              # literals
        out += src[i:i + n]
        i += n
        if i >= len(src):                                   # the last sequence has literals only
            return bytes(out)
        offset = src[i] | src[i + 1] << 8
        i += 2
        n = length(token & 15) + 4                          # match copied from earlier output
        start = len(out) - offset
        if offset >= n:
            out += out[start:start + n]
        else:                                               # overlapping match repeats a pattern
            for k in range(n):
                out.append(out[start + k])


def firefox_profile(prof):
    """(domain, name, value) of one Firefox profile: persistent cookies plus the session store."""
    jar = []
    if os.path.exists(prof + "cookies.sqlite"):
        with db_copy(prof + "cookies.sqlite") as con:       # expiry is in seconds, or milliseconds in newer versions
            jar += [row for row in con.execute(
                "SELECT host, name, value FROM moz_cookies WHERE host LIKE '%service-now.com' AND "
                "CASE WHEN expiry > 99999999999 THEN expiry / 1000 ELSE expiry END > ?", (time.time(),))
                if for_instance(row[0])]
    # session cookies (the session itself) live only in the session store, saved every 15 s
    for store in ("sessionstore-backups/recovery.jsonlz4", "sessionstore.jsonlz4"):
        if os.path.exists(prof + store):
            with open(prof + store, "rb") as f:
                data = f.read()
            if data[:8] == b"mozLz40\0":                      # then 4 bytes of size, then the block
                jar += [(ck["host"], ck["name"], ck.get("value", ""))
                        for ck in json.loads(lz4_block(data[12:])).get("cookies", [])
                        if for_instance(ck.get("host", ""))]
            break
    return jar


def firefox_profiles():
    """Profile folders, each with a trailing separator. The file formats are the same on every system."""
    if PLATFORM == "darwin":
        roots = [os.path.join(APP_SUPPORT, "Firefox", "Profiles")]
    elif PLATFORM == "win32":
        roots = [os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~/AppData/Roaming"),
                              "Mozilla", "Firefox", "Profiles")]
    else:                                                   # package, snap and flatpak installs
        roots = [os.path.expanduser(d) for d in ("~/.mozilla/firefox", "~/snap/firefox/common/.mozilla/firefox",
                                                 "~/.var/app/org.mozilla.firefox/.mozilla/firefox")]
    return [p for root in roots for p in sorted(glob.glob(os.path.join(root, "*", "")))]


def firefox_cookies():
    for prof in firefox_profiles():
        label = f"firefox ({os.path.basename(os.path.dirname(prof))})"
        try:
            jar = firefox_profile(prof)
        except READ_ERRORS as e:
            unreadable(label, e)
            continue
        if jar:
            yield label, cookie_header(jar)


# a bare clipboard line counts as a Cookie header only if it is nothing but name=value pairs
COOKIE_PAIRS = re.compile(r"[!#$%&'*+\-.^_`|~\w]+=[^;\s]*(?:;\s*[!#$%&'*+\-.^_`|~\w]+=[^;\s]*)*;?")


def clipboard_text():
    """The text on the clipboard, with whatever tool this system has for that."""
    if PLATFORM == "darwin":
        cmd = ["pbpaste"]
    elif PLATFORM == "win32":
        cmd = ["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"]
    else:
        tools = (["wl-paste", "--no-newline"], ["xclip", "-o", "-selection", "clipboard"], ["xsel", "-ob"])
        cmd = next((t for t in tools if shutil.which(t[0])), None)
        if not cmd:
            die("reading the clipboard needs wl-paste (Wayland), xclip or xsel")
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout.strip()


PS_COOKIE = re.compile(r'System\.Net\.Cookie\(' + r',\s*'.join([r'"((?:[^"`]|`.)*)"'] * 4) + r'\)')


def cookie_from_text(text):
    """The Cookie header in a copied request: "Copy as cURL" in its bash and Windows cmd forms,
    "Copy as PowerShell", a Cookie header line, or the bare header value. '' when there is none."""
    ps = [[re.sub(r"`(.)", r"\1", part) for part in m] for m in PS_COOKIE.findall(text)]
    if ps:                                                  # (name, value, path, domain) per cookie
        return cookie_header([(domain, name, value) for name, value, _, domain in ps if for_instance(domain)])
    if '^"' in text:                                        # cmd.exe form: ^ escapes the next character
        text = re.sub(r"\^(.)", r"\1", text, flags=re.S)
    m = re.search(r"(?:-b|--cookie)\s+\$?(?:'([^']+)'|\"([^\"]+)\")|cookie:\s*([^'\"\r\n]+)", text, re.I)
    if m:
        return next(g for g in m.groups() if g).strip()
    return text if COOKIE_PAIRS.fullmatch(text) else ""


def clipboard_cookies(help_text=CLIPBOARD_HELP):
    """Any browser on any system: read a request the user copied in the developer tools."""
    raw = cookie_from_text(clipboard_text())
    if not raw:
        die(f"no cookie on the clipboard. {help_text}")
    yield "the clipboard", raw


def safari_cookies():
    """Safari never writes session cookies to disk, so read a 'Copy as cURL' from the clipboard."""
    return clipboard_cookies(SAFARI_HELP)


def mac_only(browser):
    def read():
        if PLATFORM != "darwin":
            die(NOT_READABLE.format(browser=browser.capitalize()))
        return chromium_cookies(browser)
    return read


BROWSERS = {
    "chrome": mac_only("chrome"),
    "edge": mac_only("edge"),
    "firefox": firefox_cookies,
    "safari": safari_cookies,
    "clipboard": clipboard_cookies,
}


def signed_in(raw):
    """Same check as fetch_token: a web UI page with a g_ck, without following the SSO redirect."""
    r = requests.get(f"{BASE}/incident_list.do", headers={"Cookie": raw}, allow_redirects=False, timeout=30)
    return r.status_code == 200 and bool(G_CK.search(r.text))


def save_cookie(raw):
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    fd = os.open(COOKIE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if hasattr(os, "fchmod"):                               # not on Windows
        os.fchmod(fd, 0o600)                                # also when the file already existed
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(raw + "\n")


def refresh_cookie(browser):
    """Save the first signed-in session found in the browser(s) to COOKIE_FILE; only a working one."""
    rejected = False
    mac = PLATFORM == "darwin"
    for b in [browser] if browser else ["chrome", "edge", "firefox"] if mac else ["firefox"]:
        for label, raw in BROWSERS[b]():
            if signed_in(raw):
                save_cookie(raw)
                return note(f"cookie refreshed from {label}")
            rejected = True
            note(f"{label}: its session is not accepted by {BASE}")
    # cookies were there but refused: the session timed out behind an open tab, or the browser has not
    # written the new one yet (it saves cookies every 30 seconds or so)
    die(("the session in your browser has expired or is not saved yet - reload a ServiceNow page there, "
         "wait 30 seconds and retry" if rejected and browser not in ("safari", "clipboard") else
         f"no signed-in session found - sign in to {BASE} in your browser and retry")
        + ("" if browser else " (Safari: add --browser safari)" if mac else
           " (only Firefox is read automatically here; for Edge and Chrome copy a request as cURL and add "
           "--browser clipboard)"))


def api_error(r):
    try:
        err = r.json().get("error", {})
        return clean(f"{err.get('message', '')} {err.get('detail') or ''}".strip())
    except (ValueError, AttributeError):
        return clean(r.text[:300])


def call(s, method, path, soft=False, **kw):
    """One API request. Never follows redirects (they lead to the SSO page and would carry the
    token along), turns every failure into a one-line message, and returns the "result".
    soft=True returns None when the instance refuses or doesn't know the request (optional lookups)."""
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
        die(f"{r.status_code} - session expired or token rejected - {REFRESH}")
    if r.status_code >= 400:
        if soft:
            return None
        die(f"{r.status_code} - {'not written' if write else 'request refused'}: {api_error(r)}")
    try:
        return r.json()["result"]
    except (ValueError, KeyError, TypeError):
        if soft:
            return None
        if write:
            die(f"unreadable response to the write ({r.status_code}): {unsure}")
        die(f"unexpected response from {BASE} (not JSON) - is the session still valid? {REFRESH}")


def get(s, table, query, fields, soft=False):
    out = []
    while True:
        page = call(s, "GET", f"/api/now/table/{table}", soft=soft, params={
            "sysparm_query": query,
            "sysparm_fields": fields,
            "sysparm_display_value": "all",
            "sysparm_exclude_reference_link": "true",
            "sysparm_limit": str(PAGE),
            "sysparm_offset": str(len(out)),
        })
        if not isinstance(page, list):                   # soft lookup refused
            return None
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
    cfg = read_config(SECTIONS_FILE)
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
        die("needs fzf: https://github.com/junegunn/fzf (brew, apt, winget and scoop all have it)")
    tty, links = TTY, LINKS
    TTY = LINKS = False
    rows = fetch_tasks(s, a)
    lines = "\n".join(task_line(t).strip() for t in rows)
    TTY, LINKS = tty, links
    me = [sys.executable, os.path.realpath(__file__)]       # fzf runs its commands through cmd.exe on Windows
    me = subprocess.list2cmdline(me) if PLATFORM == "win32" else " ".join(map(shlex.quote, me))
    r = subprocess.run([
        "fzf", "--ansi", "--no-sort", "--layout=reverse",
        "--header", "enter: open here · ctrl-o: browser · esc: quit",
        "--preview", f"{me} {{1}} -n 3",
        "--preview-window", "right,60%,wrap",
        "--bind", f"ctrl-o:execute-silent({me} {{1}} -w)",
    ], input=lines, text=True, encoding="utf-8", stdout=subprocess.PIPE,
        env={**os.environ, "SLEET_COLOR": "1", "PYTHONIOENCODING": "utf-8"})    # colours in the preview
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
        # the terminal itself, so it works even when stdin is piped
        with open("CONIN$" if PLATFORM == "win32" else "/dev/tty") as tty:
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
    """Field values of a template or preset. "_keys" are notes; empty values are placeholders, never sent."""
    return {k: as_text(v) for k, v in (entry.get("fields") or {}).items()
            if not k.startswith("_") and as_text(v).strip()}


def check_required(kind, name, entry, body):
    """The API accepts records the form would refuse; "required" in config.json puts that check back."""
    missing = [f for f in entry.get("required") or [] if not str(body.get(f, "")).strip()]
    if missing:
        die(f"{kind} '{name}' requires {', '.join(missing)} - set it in {CONFIG_FILE} or pass --set FIELD=VALUE")


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
    templates = {k: v for k, v in CFG.get("templates", {}).items() if not k.startswith("_")}
    tmpl = templates.get(a.new)
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
    if tmpl:
        check_required("template", a.new, tmpl, body)

    if not tmpl:                                         # a mistyped template name would otherwise go out as a table
        print(c("33", f"no template '{a.new}' in {CONFIG_FILE} (have: {', '.join(templates) or 'none'})"
                      f" - creating directly in table '{table}'"))
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


NAME = re.compile(r"[a-z][a-z0-9_]*")
SYSTEM = re.compile(r"sys_|number$|opened_|closed_|resolved_")     # filled in by ServiceNow itself


def table_chain(s, table):
    """The table and its parents, nearest first: fields, choices and policies are inherited."""
    chain = [table]
    rows = get(s, "sys_db_object", f"name={table}", "name,super_class", soft=True)
    readable = bool(rows)
    while rows and rows[0]["_raw"].get("super_class") and len(chain) < 10:
        rows = get(s, "sys_db_object", f"sys_id={rows[0]['_raw']['super_class']}", "name,super_class", soft=True)
        if rows and rows[0]["_raw"].get("name"):
            chain.append(rows[0]["_raw"]["name"])
    if not readable and table != "task":
        chain.append("task")                             # hierarchy not readable: ticket tables extend task
    return chain


def policy_rules(s, chain, rule_table, parent, table_field):
    """Fields a UI or data policy makes mandatory: {field: [condition, ...]}, None when not readable.
    Filtered again on our side, because ServiceNow ignores query terms it doesn't understand."""
    p = f"{parent}."
    rows = get(s, rule_table, f"{p}{table_field}IN{','.join(chain)}^{p}active=true^mandatory=true",
               f"field,mandatory,{p}{table_field},{p}active,{p}inherit,{p}conditions,{p}short_description", soft=True)
    if rows is None:
        return None
    out = {}
    for r in rows:
        raw = r["_raw"]
        tbl = raw.get(p + table_field)
        if str(raw.get("mandatory")) != "true" or str(raw.get(p + "active")) != "true" or tbl not in chain:
            continue
        if tbl != chain[0] and str(raw.get(p + "inherit")) != "true":
            continue
        cond = re.sub(r"\^EQ$", "", clean(str(raw.get(p + "conditions") or "")))
        out.setdefault(str(raw.get("field") or ""), []).append(cond)
    out.pop("", None)
    return out


def describe(s, table):
    """({field: {label, type, reference, choices, required}}, notes) for a table.
    "required" is a list of reasons: "mandatory field" (the field definition), "on the form" and
    "on the form when <condition>" (policies). The API enforces none of them reliably."""
    probe = call(s, "GET", f"/api/now/table/{table}", soft=True,
                 params={"sysparm_limit": "1", "sysparm_fields": "sys_id"})
    if probe is None:                                    # tell a wrong name apart from missing rights
        die(f"no table '{table}' that you can read - check the name (tables are singular: incident, change_request)")
    chain = table_chain(s, table)
    fields, notes = {}, []
    meta = call(s, "GET", f"/api/now/ui/meta/{table}", soft=True)
    cols = meta.get("columns") if isinstance(meta, dict) else None
    if isinstance(cols, dict) and cols:
        for name, col in cols.items():
            if isinstance(col, dict):
                fields[name] = {
                    "label": clean(str(col.get("label") or "")), "type": str(col.get("type") or ""),
                    "reference": str(col.get("reference") or ""),
                    "choices": [[clean(str(ch.get("label") or "")), str(ch.get("value") or "")]
                                for ch in col.get("choices") or []
                                if isinstance(ch, dict) and str(ch.get("value") or "")],     # drop "-- None --"
                    "required": ["mandatory field"] if col.get("mandatory") is True and not name.startswith("sys_") else [],
                }
    else:
        rows = get(s, "sys_dictionary", f"nameIN{','.join(chain)}^elementISNOTEMPTY^active=true",
                   "name,element,column_label,internal_type,mandatory,reference", soft=True)
        if rows is None:
            die(f"cannot read the field definitions of '{table}': the metadata API and sys_dictionary both refused")
        for r in sorted(rows, key=lambda r: -chain.index(r["_raw"]["name"]) if r["_raw"]["name"] in chain else 0):
            raw = r["_raw"]
            fields[raw["element"]] = {
                "label": r["column_label"], "type": str(raw.get("internal_type") or ""),
                "reference": str(raw.get("reference") or ""), "choices": [],
                "required": (["mandatory field"] if str(raw.get("mandatory")) == "true"
                             and not raw["element"].startswith("sys_") else []),
            }
    if not fields:
        die(f"no fields found for table '{table}' - is the name right?")

    if not any(f["choices"] for f in fields.values()):   # no choices from the metadata call: read them directly
        rows = get(s, "sys_choice", f"nameIN{','.join(chain)}^inactive=false^ORDERBYsequence",
                   "name,element,label,value,language", soft=True)
        if rows is None:
            notes.append("choice lists are not readable with your rights")
        for name, f in fields.items():
            mine = [r for r in rows or [] if r["_raw"]["element"] == name]
            for t in chain:                              # the nearest table that defines choices wins
                here = [r for r in mine if r["_raw"]["name"] == t]
                if here:
                    langs = {r["_raw"]["language"] for r in here}
                    f["choices"] = [[r["label"] + (f" [{r['_raw']['language']}]" if len(langs) > 1 else ""),
                                     str(r["_raw"]["value"])] for r in here if str(r["_raw"]["value"])]
                    break

    hidden = []
    for what, rules in (("UI policies", policy_rules(s, chain, "sys_ui_policy_action", "ui_policy", "table")),
                        ("data policies", policy_rules(s, chain, "sys_data_policy_rule", "sys_data_policy",
                                                       "model_table"))):
        if rules is None:
            hidden.append(what)
            continue
        for name, conds in rules.items():
            if name in fields:
                fields[name]["required"] += [f"on the form when {c}" if c else "on the form" for c in conds]
    if hidden:
        notes.append(f"{' and '.join(hidden)} are not readable with your rights; "
                     "fields that only they make required are not marked")
    return fields, notes


def always_required(f):
    return any(r in ("mandatory field", "on the form") for r in f["required"])


def lookup_table(name):
    """--fields/--template accept a template name from config.json as well as a table name."""
    tmpl = CFG.get("templates", {}).get(name)
    table = tmpl["table"] if isinstance(tmpl, dict) and tmpl.get("table") else name
    if not NAME.fullmatch(table):
        die(f"'{table}' is not a table name")
    return table


def show_fields(s, a):
    table = lookup_table(a.fields[0])
    fields, notes = describe(s, table)
    if len(a.fields) == 2:                               # one field: its choices
        name = a.fields[1]
        f = fields.get(name) or die(f"{table} has no field '{name}' - run: sleet --fields {a.fields[0]}")
        if a.json:
            return print(json.dumps({name: f}, indent=2))
        print(f"{c('1', f'{table}.{name}')}  {f['label']}  {c('2', f['type'])}")
        if f["required"]:
            print(f"  required: {', '.join(f['required'])}")
        if f["choices"]:
            print(c("2", "  use the label on the left with --set and in config.json"))
            for label, value in f["choices"]:
                print(f"  {label:<40} {c('2', value)}")
        elif f["reference"]:
            print(f"  a reference to {f['reference']}: use the display value, exactly as the form shows it")
        else:
            print("  no choice list: free text or a value of this type")
    else:
        if a.json:
            return print(json.dumps(fields, indent=2))
        order = sorted(fields, key=lambda n: (not always_required(fields[n]), not fields[n]["required"], n))
        width = max(len(n) for n in order)
        print(f"{c('1', table)}  {len(fields)} fields  {c('2', 'required first')}")
        for n in order:
            f = fields[n]
            kind = (f"{len(f['choices'])} choice{'s' * (len(f['choices']) != 1)}" if f["choices"] else
                    f"-> {f['reference']}" if f["reference"] else f["type"])
            req = c("33", "  required: " + ", ".join(dict.fromkeys(f["required"]))) if f["required"] else ""
            print(f"  {n:<{width}}  {f['label'][:28]:<28}  {kind}{req}")
    for n in notes:
        print(f"[sleet] note: {n}", file=sys.stderr)


def make_template(s, a):
    """Print a template for --new, ready to paste under "templates" in the config file."""
    table = lookup_table(a.template)
    fields, notes = describe(s, table)
    skip = {"short_description", "description"}          # come from -t and --desc
    req = [n for n in sorted(fields) if always_required(fields[n]) and n not in skip and not SYSTEM.match(n)]
    body = {}
    for n in req:
        if fields[n]["choices"]:
            body["_" + n] = "one of: " + " | ".join(label for label, _ in fields[n]["choices"])
        elif fields[n]["reference"]:
            body["_" + n] = f"display value of a {fields[n]['reference']} record"
        body[n] = ""
    tmpl = {table: {"table": table, "required": req, "fields": body}}
    if yaml and is_yaml(CONFIG_FILE):                    # indented to sit under "templates:"
        print(textwrap.indent(yaml.safe_dump(tmpl, sort_keys=False, allow_unicode=True), "  "), end="")
    else:
        print(json.dumps(tmpl, indent=2))
    later = {n: [r for r in f["required"] if r.startswith("on the form when")] for n, f in fields.items()}
    hints = [f"paste this under \"templates\" in {os.path.basename(CONFIG_FILE)}, rename the key if you like, "
             "and fill in the empty values",
             "empty values are not sent; \"required\" makes sleet stop when one is still empty"]
    hints += [f"{n} is required {', '.join(w)}; add it to a preset for that step" for n, w in sorted(later.items()) if w and n not in req]
    for n in hints + notes:
        print(f"[sleet] note: {n}", file=sys.stderr)


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
    if a.preset:
        check_required("preset", a.preset[0], preset, body)

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
    k = p.add_argument_group("session cookie")
    k.add_argument("--refresh-cookie", action="store_true",
                   help="first copy your ServiceNow session from the browser into the cookie file")
    k.add_argument("--browser", choices=list(BROWSERS),
                   help="with --refresh-cookie: where to read (default on macOS: chrome, edge, firefox in turn; "
                        "elsewhere: firefox); clipboard reads a request you copied as cURL, from any browser")
    d = p.add_argument_group("discover (read-only)")
    d.add_argument("--fields", nargs="+", metavar=("TABLE", "FIELD"),
                   help="fields of a table with the required ones first; add a field name to list its choices")
    d.add_argument("--template", metavar="TABLE",
                   help="print a --new template for a table, with its required fields, to paste into config.json")
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
    if a.fields and len(a.fields) > 2:
        p.error("--fields takes a table and at most one field")
    if (a.fields or a.template) and (a.number or a.new or writing(a) or (a.fields and a.template)):
        p.error("--fields and --template stand alone")
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
    if a.browser and not a.refresh_cookie:
        p.error("--browser needs --refresh-cookie")

    if a.refresh_cookie:
        refresh_cookie(a.browser)
    s = session()
    if a.fields:
        show_fields(s, a)
    elif a.template:
        make_template(s, a)
    elif a.new:
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
    for stream in (sys.stdout, sys.stderr):                 # a redirected stream may not be UTF-8: never crash on it
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
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
