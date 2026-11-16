"""
Unit tests for sleet.

Run them from the repository root:

    python3 -m unittest discover

The suite covers the cookie and token files, the request layer (call/get), the
board, the ticket view, writes with their preview, presets and read-back, record
creation from templates, the argument checks in main(), and --refresh-cookie:
the Chrome, Edge, Firefox and Safari readers, the LZ4 and AES helpers behind
them, and the choice of which session gets saved.

Nothing here touches the network, the real ~/.config/sleet, the Keychain or the
clipboard: ServiceNow is a fake behind requests, browser profiles are built in a
temporary directory, and `security` and `pbpaste` are replaced. The LZ4 and AES
vectors were made with the lz4 package and `openssl enc`, so the decoders are
checked against independent implementations. Real AES runs only on macOS.
"""

import atexit
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

# sleet reads its configuration at import time: point it at an empty directory first
_HOME = tempfile.mkdtemp(prefix="sleet-test-")
atexit.register(shutil.rmtree, _HOME, ignore_errors=True)
os.environ["XDG_CONFIG_HOME"] = _HOME
os.environ["SLEET_INSTANCE"] = "example"
for _var in ("SLEET_GCK", "SLEET_COLOR"):
    os.environ.pop(_var, None)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sleet  # noqa: E402

REAL_AES_DECRYPT = sleet.aes_decrypt
HOST = "example.service-now.com"
GCK = "0123abcd"

# Chrome-style cookie: PBKDF2 key from this Keychain password, AES-128-CBC with an IV of 16 spaces,
# plaintext = SHA-256(HOST) + value (cookie DB version 24+). Made with `openssl enc -aes-128-cbc`.
AES_PASSWORD = "test-safe-storage-password"
AES_VALUE = b"session-0123456789abcdef"
AES_CIPHERTEXT = bytes.fromhex(
    "9dbf00bae631406711e23764e5aa1f33304d62e0841e962426f8551129fdb488"
    "94db01972de12b8c067d953410bc59760fa174b6ce24ba237073b4503680b89a")

# LZ4 blocks made with lz4.block.compress(data, store_size=False)
LZ4_SHORT = bytes.fromhex("3e6162630300642068656c6c6f060050656c6c6f21")
LZ4_RUN = bytes.fromhex("1f780100ffffffd2507878787878")
LZ4_LONG = bytes.fromhex(
    "ffff326e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d4bf5122f344554c53bde2ebb8c"
    "d2b7e3d1600ad631c385a5d7cce23c7785459adbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea9864"
    "57d986084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5e52d9c508c502347344d8c07ad"
    "91cbd6068afc75ff6292f062a09ca381c89e71e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5a"
    "b743db67586e98fad27da0b9968bc039a1ef34c939b9b8e523a8bef89d478608c5ecf6ca358758f6d27e6cf452729379"
    "77a748fd88391db679ceda7dc7bf1f005ee879beead77994cf573341ec17b58bbf7eb34d2711c993c1d976b128b3188d"
    "c1829a2b4c342f5433ebe591a1da77e013d1b72475562d48578dca8b84bac6651c3cb94001ff2950c6651c3cb9")


def noise(n):
    """Incompressible test data: n SHA-256 digests (the input of LZ4_LONG is noise(10) * 2)."""
    return b"".join(hashlib.sha256(bytes([i])).digest() for i in range(n))


def lz4_literals(data):
    """An LZ4 block that holds data as literals only, enough to build a Firefox session store."""
    if len(data) < 15:
        return bytes([len(data) << 4]) + data
    rest, ext = len(data) - 15, bytearray()
    while rest >= 255:
        ext.append(255)
        rest -= 255
    ext.append(rest)
    return bytes([0xF0]) + bytes(ext) + data


def row(**fields):
    """A Table API row as sysparm_display_value=all returns it; a tuple is (display value, value)."""
    return {k: {"display_value": v[0], "value": v[1]} if isinstance(v, tuple) else {"display_value": v, "value": v}
            for k, v in fields.items()}


class FakeResponse:

    def __init__(self, status=200, result=None, error=None, text=None):
        self.status_code = status
        self._json = {"result": result} if result is not None else {"error": error} if error else None
        self.text = text if text is not None else json.dumps(self._json) if self._json else ""

    def json(self):
        if self._json is None:
            raise ValueError("not JSON")
        return self._json


class FakeServer:
    """A ServiceNow instance behind a requests.Session double.

    incident_list.do answers with a page holding g_ck, or with the SSO redirect when not signed in.
    Other requests go through routes: {(method, path): response | [responses...] | callable(kwargs)};
    a list hands out its responses in turn and repeats the last. Every request is recorded."""

    def __init__(self, routes=None, signed_in=True, gck=GCK):
        self.routes = routes or {}
        self.signed_in = signed_in
        self.gck = gck
        self.headers = {}
        self.calls = []

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def request(self, method, url, **kw):
        path = url[len(sleet.BASE):]
        self.calls.append(dict(kw, method=method, path=path, sent=dict(self.headers, **kw.get("headers", {}))))
        if path == "/incident_list.do":
            return (FakeResponse(200, text=f"<script>var g_ck = '{self.gck}';</script>") if self.signed_in
                    else FakeResponse(302))
        answer = self.routes.get((method, path), FakeResponse(404, error={"message": "No such path"}))
        if isinstance(answer, list):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        if isinstance(answer, BaseException):
            raise answer
        return answer(kw) if callable(answer) else answer

    def api_calls(self, method=None):
        return [c for c in self.calls if c["path"] != "/incident_list.do" and method in (None, c["method"])]


class QuietTestCase(unittest.TestCase):
    """Capture output as self.out / self.err, switch off colours and links, and give every test an
    empty configuration directory and browser data directory of its own."""

    def setUp(self):
        self._out, self._err = io.StringIO(), io.StringIO()
        self.dir = tempfile.mkdtemp(prefix="sleet-test-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        cfg = os.path.join(self.dir, "sleet")
        os.makedirs(cfg, mode=0o700)
        self.patch(sys, "stdout", self._out)
        self.patch(sys, "stderr", self._err)
        for name, value in (("TTY", False), ("LINKS", False), ("CFG", {}), ("PRESETS", {}),
                            ("PLATFORM", "darwin"),      # the browser tests describe macOS unless they say otherwise
                            ("FILE_MODES", os.name == "posix"),
                            ("CONFIG_DIR", cfg),
                            ("CONFIG_FILE", os.path.join(cfg, "config.json")),
                            ("COOKIE_FILE", os.path.join(cfg, "cookie")),
                            ("TOKEN_FILE", os.path.join(cfg, "token")),
                            ("SECTIONS_FILE", os.path.join(cfg, "sections.json")),
                            ("APP_SUPPORT", os.path.join(self.dir, "Application Support"))):
            self.patch(sleet, name, value)

    def patch(self, target, name, value):
        patcher = mock.patch.object(target, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    @property
    def out(self):
        return self._out.getvalue()

    @property
    def err(self):
        return self._err.getvalue()

    def assertDies(self, text, fn, *args, **kw):
        """fn exits through die() with a message that contains text."""
        with self.assertRaises(SystemExit) as cm:
            fn(*args, **kw)
        self.assertIn(text, str(cm.exception.code))

    def write(self, path, text, mode=0o600):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, mode)


class ServerTestCase(QuietTestCase):
    """QuietTestCase with a FakeServer in place of requests, and a cookie file."""

    def serve(self, **kw):
        server = FakeServer(**kw)
        self.patch(sleet.requests, "Session", lambda: server)
        self.patch(sleet.requests, "get", server.get)
        return server

    def setUp(self):
        super().setUp()
        self.write(sleet.COOKIE_FILE, "JSESSIONID=abc; glide_session_store=def\n")

    def run_main(self, *argv):
        with mock.patch.object(sys, "argv", ["sleet", *argv]):
            sleet.main()

    def assertUsageError(self, text, *argv):
        with self.assertRaises(SystemExit) as cm:
            self.run_main(*argv)
        self.assertEqual(cm.exception.code, 2)
        self.assertIn(text, self.err)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

class CleanTest(unittest.TestCase):

    def test_strips_escape_sequences_so_a_ticket_cannot_drive_the_terminal(self):
        self.assertEqual(sleet.clean("\x1b]8;;http://evil\x1b\\click\x1b[31m"), "]8;;http://evil\\click[31m")

    def test_strips_bidi_overrides(self):
        self.assertEqual(sleet.clean("abc‮def⁦"), "abcdef")

    def test_keeps_newlines_and_tabs(self):
        self.assertEqual(sleet.clean("a\nb\tc"), "a\nb\tc")

    def test_leaves_non_strings_alone(self):
        self.assertIsNone(sleet.clean(None))
        self.assertEqual(sleet.clean(4), 4)


class SameTest(unittest.TestCase):

    def test_ignores_case_and_surrounding_space(self):
        self.assertTrue(sleet.same("In Progress", " in progress "))

    def test_numbers_compare_by_value(self):
        self.assertTrue(sleet.same("4", "4.00"))
        self.assertFalse(sleet.same("4", "5"))

    def test_none_is_empty(self):
        self.assertTrue(sleet.same("", None))


class ConfigFieldsTest(unittest.TestCase):

    def test_drops_notes_and_empty_placeholders(self):
        entry = {"fields": {"_impact": "a note", "impact": "3 - Low", "caller_id": "", "urgency": "  "}}
        self.assertEqual(sleet.config_fields(entry), {"impact": "3 - Low"})

    def test_turns_numbers_and_booleans_into_text(self):
        entry = {"fields": {"u_hours": 4, "u_flag": True, "u_off": False}}
        self.assertEqual(sleet.config_fields(entry), {"u_hours": "4", "u_flag": "true", "u_off": "false"})

    def test_no_fields(self):
        self.assertEqual(sleet.config_fields({}), {})


class RecordUrlTest(unittest.TestCase):

    def test_by_sys_id_inside_the_classic_ui_frame(self):
        url = sleet.record_url({"number": "INC1", "_raw": {"sys_id": "s1", "sys_class_name": "incident"}})
        self.assertEqual(url, f"{sleet.BASE}/now/nav/ui/classic/params/target/incident.do%3Fsys_id%3Ds1")

    def test_by_number_when_there_is_no_sys_id(self):
        url = sleet.record_url({"number": "INC1"}, "incident")
        self.assertTrue(url.endswith("incident.do%3Fsysparm_query%3Dnumber%3DINC1"))


# --------------------------------------------------------------------------- #
# configuration files: JSON, or YAML with PyYAML
# --------------------------------------------------------------------------- #

def without_notes(data):
    """data with every "_key" removed, at any depth."""
    if isinstance(data, dict):
        return {k: without_notes(v) for k, v in data.items() if not k.startswith("_")}
    if isinstance(data, list):
        return [without_notes(v) for v in data]
    return data


class ConfigFileTest(QuietTestCase):

    def path(self, name):
        return os.path.join(sleet.CONFIG_DIR, name)

    def test_json_without_a_yaml_file(self):
        self.assertEqual(sleet.config_path("config"), self.path("config.json"))
        self.write(self.path("config.json"), "{}")
        self.assertEqual(sleet.config_path("config"), self.path("config.json"))

    def test_yaml_before_yml_before_json(self):
        self.write(self.path("config.json"), "{}")
        self.write(self.path("config.yml"), "")
        self.assertEqual(sleet.config_path("config"), self.path("config.yml"))
        self.write(self.path("config.yaml"), "")
        self.assertEqual(sleet.config_path("config"), self.path("config.yaml"))

    def test_reads_json(self):
        self.write(self.path("config.json"), '{"instance": "x"}')
        self.assertEqual(sleet.read_config(self.path("config.json")), {"instance": "x"})

    def test_bad_json_names_the_file(self):
        self.write(self.path("config.json"), "{not json")
        self.assertDies(self.path("config.json"), sleet.read_config, self.path("config.json"))

    @unittest.skipUnless(sleet.yaml, "needs PyYAML")
    def test_reads_yaml(self):
        self.write(self.path("config.yaml"), "instance: x  # a comment\npresets: {}\n")
        self.assertEqual(sleet.read_config(self.path("config.yaml")), {"instance": "x", "presets": {}})

    @unittest.skipUnless(sleet.yaml, "needs PyYAML")
    def test_empty_yaml_is_empty(self):
        self.write(self.path("config.yaml"), "# nothing yet\n")
        self.assertEqual(sleet.read_config(self.path("config.yaml")), {})

    @unittest.skipUnless(sleet.yaml, "needs PyYAML")
    def test_bad_yaml_names_the_file(self):
        self.write(self.path("config.yaml"), "presets: [unclosed\n")
        self.assertDies(self.path("config.yaml"), sleet.read_config, self.path("config.yaml"))

    def test_yaml_without_pyyaml_says_so(self):
        self.patch(sleet, "yaml", None)
        self.write(self.path("config.yaml"), "instance: x\n")
        self.assertDies("needs PyYAML", sleet.read_config, self.path("config.yaml"))

    def test_missing_config_is_empty(self):
        self.assertEqual(sleet.load_config(), {})

    @unittest.skipUnless(sleet.yaml, "needs PyYAML")
    def test_examples_agree(self):
        here = os.path.dirname(os.path.abspath(__file__))
        for name in ("config", "sections"):
            with self.subTest(name):
                with open(os.path.join(here, f"{name}.example.json")) as f:
                    expected = without_notes(json.load(f))
                actual = without_notes(sleet.read_config(os.path.join(here, f"{name}.example.yaml")))
                self.assertEqual(actual, expected)


class MakeTemplateTest(QuietTestCase):

    FIELDS = {
        "impact": {"label": "Impact", "type": "integer", "reference": "",
                   "choices": [["1 - High", "1"], ["3 - Low", "3"]], "required": ["mandatory field"]},
        "caller_id": {"label": "Caller", "type": "reference", "reference": "sys_user",
                      "choices": [], "required": ["on the form"]},
        "short_description": {"label": "Short description", "type": "string", "reference": "",
                              "choices": [], "required": ["mandatory field"]},
        "urgency": {"label": "Urgency", "type": "integer", "reference": "", "choices": [], "required": []},
    }
    EXPECTED = {"incident": {"table": "incident", "required": ["caller_id", "impact"], "fields": {
        "_caller_id": "display value of a sys_user record", "caller_id": "",
        "_impact": "one of: 1 - High | 3 - Low", "impact": ""}}}

    def setUp(self):
        super().setUp()
        self.patch(sleet, "describe", lambda s, table: (self.FIELDS, []))

    def test_json_for_a_json_config(self):
        sleet.make_template(None, mock.Mock(template="incident"))
        self.assertEqual(json.loads(self.out), self.EXPECTED)
        self.assertIn('under "templates" in config.json', self.err)

    @unittest.skipUnless(sleet.yaml, "needs PyYAML")
    def test_yaml_for_a_yaml_config_ready_to_paste(self):
        self.patch(sleet, "CONFIG_FILE", os.path.join(sleet.CONFIG_DIR, "config.yaml"))
        sleet.make_template(None, mock.Mock(template="incident"))
        self.assertTrue(self.out.startswith("  incident:\n"))
        self.assertEqual(sleet.yaml.safe_load("templates:\n" + self.out), {"templates": self.EXPECTED})
        self.assertIn('under "templates" in config.yaml', self.err)


# --------------------------------------------------------------------------- #
# cookie and token files
# --------------------------------------------------------------------------- #

class ReadCookieTest(QuietTestCase):

    def test_reads_one_line(self):
        self.write(sleet.COOKIE_FILE, "a=1; b=2\n")
        self.assertEqual(sleet.read_cookie(), "a=1; b=2")

    def test_strips_a_pasted_header_name(self):
        self.write(sleet.COOKIE_FILE, "Cookie: a=1; b=2")
        self.assertEqual(sleet.read_cookie(), "a=1; b=2")

    def test_missing_file_points_to_the_refresh(self):
        self.assertDies(sleet.REFRESH, sleet.read_cookie)

    def test_refuses_more_than_one_line(self):
        self.write(sleet.COOKIE_FILE, "a=1\nb=2")
        self.assertDies("exactly one line", sleet.read_cookie)

    def test_refuses_an_empty_file(self):
        self.write(sleet.COOKIE_FILE, "\n")
        self.assertDies("exactly one line", sleet.read_cookie)

    @unittest.skipUnless(os.name == "posix", "Windows has no owner-only file permissions")
    def test_warns_when_others_can_read_it(self):
        self.write(sleet.COOKIE_FILE, "a=1", mode=0o644)
        sleet.read_cookie()
        self.assertIn("readable by others", self.err)

    def test_no_warning_at_600(self):
        self.write(sleet.COOKIE_FILE, "a=1")
        sleet.read_cookie()
        self.assertEqual(self.err, "")


class TokenCacheTest(QuietTestCase):

    @unittest.skipUnless(os.name == "posix", "Windows has no owner-only file permissions")
    def test_round_trip(self):
        sleet.save_token("k", "tok")
        self.assertEqual(sleet.cached_token("k"), "tok")
        self.assertEqual(os.stat(sleet.TOKEN_FILE).st_mode & 0o777, 0o600)

    def test_belongs_to_one_cookie(self):
        sleet.save_token("k", "tok")
        self.assertIsNone(sleet.cached_token("other"))

    def test_unreadable_cache_is_ignored(self):
        self.write(sleet.TOKEN_FILE, "{not json")
        self.assertIsNone(sleet.cached_token("k"))

    def test_forget(self):
        sleet.save_token("k", "tok")
        sleet.forget_token()
        self.assertFalse(os.path.exists(sleet.TOKEN_FILE))
        sleet.forget_token()                             # a missing file is fine

    def test_save_never_fails(self):
        self.patch(sleet, "TOKEN_FILE", os.path.join(self.dir, "no", "such", "dir", "token"))
        sleet.save_token("k", "tok")


# --------------------------------------------------------------------------- #
# session and the request layer
# --------------------------------------------------------------------------- #

class SessionTest(ServerTestCase):

    def test_fetches_the_token_and_caches_it(self):
        server = self.serve()
        s = sleet.session()
        self.assertEqual(s.headers["X-UserToken"], GCK)
        self.assertEqual(s.headers["Cookie"], "JSESSIONID=abc; glide_session_store=def")
        self.assertFalse(s.token_cached)
        self.assertEqual(sleet.cached_token(s.token_key), GCK)
        self.assertFalse(server.calls[0]["allow_redirects"])

    def test_uses_the_cached_token_without_a_request(self):
        server = self.serve()
        key = sleet.session().token_key
        server.calls.clear()
        s = sleet.session()
        self.assertEqual(s.token_key, key)
        self.assertTrue(s.token_cached)
        self.assertEqual(server.calls, [])

    def test_sleet_gck_wins(self):
        server = self.serve()
        with mock.patch.dict(os.environ, {"SLEET_GCK": "fromenv"}):
            s = sleet.session()
        self.assertEqual(s.headers["X-UserToken"], "fromenv")
        self.assertEqual(server.calls, [])

    def test_expired_session(self):
        self.serve(signed_in=False)
        self.assertDies("session expired", sleet.session)

    def test_page_without_g_ck(self):
        self.serve(gck="")
        self.assertDies("g_ck not found", sleet.session)


class CallTest(ServerTestCase):

    def call(self, server, method="GET", path="/api/now/table/incident", **kw):
        s = sleet.session()
        return sleet.call(s, method, path, **kw)

    def test_returns_the_result_and_never_follows_redirects(self):
        server = self.serve(routes={("GET", "/api/now/table/incident"): FakeResponse(result=[{"a": 1}])})
        self.assertEqual(self.call(server), [{"a": 1}])
        self.assertFalse(server.api_calls()[0]["allow_redirects"])

    def test_sso_redirect_means_expired_and_drops_the_token(self):
        server = self.serve(routes={("GET", "/api/now/table/incident"): FakeResponse(302)})
        self.assertDies("302 - session expired", self.call, server)
        self.assertFalse(os.path.exists(sleet.TOKEN_FILE))

    def test_stale_cached_token_is_renewed_once(self):
        server = self.serve(routes={("GET", "/api/now/table/incident"): [FakeResponse(401), FakeResponse(result=[])]})
        sleet.save_token(sleet.session().token_key, "stale")
        server.calls.clear()
        self.assertEqual(self.call(server), [])
        self.assertEqual([c["path"] for c in server.calls],
                         ["/api/now/table/incident", "/incident_list.do", "/api/now/table/incident"])
        self.assertEqual(server.calls[0]["sent"]["X-UserToken"], "stale")
        self.assertEqual(server.calls[2]["sent"]["X-UserToken"], GCK)

    def test_401_with_a_fresh_token_dies(self):
        server = self.serve(routes={("GET", "/api/now/table/incident"): FakeResponse(401)})
        self.assertDies("401 - session expired or token rejected", self.call, server)
        self.assertEqual(len(server.api_calls()), 1)

    def test_refused_read(self):
        server = self.serve(routes={("GET", "/api/now/table/incident"):
                                    FakeResponse(403, error={"message": "Denied", "detail": "ACL"})})
        self.assertDies("403 - request refused: Denied ACL", self.call, server)

    def test_refused_write(self):
        server = self.serve(routes={("PATCH", "/api/now/table/incident"): FakeResponse(400, error={"message": "Bad"})})
        self.assertDies("400 - not written: Bad", self.call, server, "PATCH")

    def test_soft_returns_none(self):
        server = self.serve()
        self.assertIsNone(self.call(server, soft=True))

    def test_error_text_that_is_not_json_is_cleaned(self):
        server = self.serve(routes={("GET", "/api/now/table/incident"): FakeResponse(500, text="boom\x1b[2J")})
        self.assertDies("500 - request refused: boom[2J", self.call, server)

    def test_write_that_times_out_may_have_been_applied(self):
        server = self.serve(routes={("PATCH", "/api/now/table/incident"): sleet.requests.exceptions.Timeout()})
        self.assertDies("Timeout during the write: it may or may not have been applied", self.call, server, "PATCH")

    def test_read_that_times_out_is_raised(self):
        server = self.serve(routes={("GET", "/api/now/table/incident"): sleet.requests.exceptions.Timeout()})
        with self.assertRaises(sleet.requests.exceptions.Timeout):
            self.call(server)

    def test_answer_that_is_not_json(self):
        server = self.serve(routes={("GET", "/api/now/table/incident"): FakeResponse(200, text="<html>")})
        self.assertDies("not JSON", self.call, server)

    def test_write_answer_that_is_not_json(self):
        server = self.serve(routes={("POST", "/api/now/table/incident"): FakeResponse(201, text="<html>")})
        self.assertDies("unreadable response to the write (201)", self.call, server, "POST")


class GetTest(ServerTestCase):

    def test_splits_display_values_from_raw_values_and_cleans_them(self):
        server = self.serve(routes={("GET", "/api/now/table/task"): FakeResponse(
            result=[row(number="INC1", state=("In \x1bProgress", "2"))])})
        rows = sleet.get(sleet.session(), "task", "active=true", "number,state")
        self.assertEqual(rows[0]["state"], "In Progress")
        self.assertEqual(rows[0]["_raw"]["state"], "2")
        params = server.api_calls()[0]["params"]
        self.assertEqual((params["sysparm_query"], params["sysparm_display_value"]), ("active=true", "all"))

    def test_pages_until_a_short_page(self):
        pages = {"0": [row(n="1"), row(n="2")], "2": [row(n="3")]}
        server = self.serve(routes={("GET", "/api/now/table/task"):
                                    lambda kw: FakeResponse(result=pages[kw["params"]["sysparm_offset"]])})
        self.patch(sleet, "PAGE", 2)
        rows = sleet.get(sleet.session(), "task", "", "n")
        self.assertEqual([r["n"] for r in rows], ["1", "2", "3"])
        self.assertEqual(len(server.api_calls()), 2)

    def test_stops_at_max_rows_and_says_so(self):
        self.serve(routes={("GET", "/api/now/table/task"): FakeResponse(result=[row(n="x"), row(n="y")])})
        self.patch(sleet, "PAGE", 2)
        self.patch(sleet, "MAX_ROWS", 4)
        self.assertEqual(len(sleet.get(sleet.session(), "task", "", "n")), 4)
        self.assertIn("more than 4 matches", self.err)

    def test_limit_stops_paging_and_asks_for_no_more_than_it_needs(self):
        pages = {"0": [row(n="1"), row(n="2")], "2": [row(n="3")]}
        server = self.serve(routes={("GET", "/api/now/table/task"):
                                    lambda kw: FakeResponse(result=pages[kw["params"]["sysparm_offset"]])})
        self.patch(sleet, "PAGE", 2)
        rows = sleet.get(sleet.session(), "task", "", "n", limit=3)
        self.assertEqual([r["n"] for r in rows], ["1", "2", "3"])
        self.assertEqual([c["params"]["sysparm_limit"] for c in server.api_calls()], ["2", "1"])

    def test_soft_lookup_refused(self):
        self.serve()
        self.assertIsNone(sleet.get(sleet.session(), "sys_ui_policy", "", "x", soft=True))


# --------------------------------------------------------------------------- #
# reading: board and ticket view
# --------------------------------------------------------------------------- #

TASKS = [
    row(number="INC1", sys_class_name="incident", state="In Progress", priority="3", sys_id="1",
        short_description="disk full", sys_updated_on="2026-11-13 10:00:00", assigned_to="Ann Admin"),
    row(number="INC2", sys_class_name="incident", state="Resolved", priority="3", sys_id="2",
        short_description="done", sys_updated_on="2026-11-12 10:00:00"),
    row(number="PRB1", sys_class_name="problem", state="New", priority="2", sys_id="3",
        short_description="root cause", sys_updated_on="2026-11-11 10:00:00"),
    row(number="SCTASK1", sys_class_name="sc_task", state="Open", priority="4", sys_id="4",
        short_description="request", sys_updated_on="2026-11-10 10:00:00"),
]
CHANGES = [
    row(number="CHG1", type="standard", state="Scheduled", approval="Approved", start_date="2026-11-14",
        sys_id="5", short_description="patch", risk="Low", end_date="", assigned_to="Ann Admin"),
    row(number="CHG2", type="normal", state="Assess", approval="Requested", start_date="2026-11-15",
        sys_id="6", short_description="upgrade", risk="High", end_date=""),
]


class BoardTest(ServerTestCase):

    def setUp(self):
        super().setUp()
        self.server = self.serve(routes={("GET", "/api/now/table/task"): FakeResponse(result=TASKS),
                                         ("GET", "/api/now/table/change_request"): FakeResponse(result=CHANGES)})

    def test_summary_counts_open_tickets_by_type(self):
        self.run_main("-s")
        self.assertEqual(self.out.strip(),
                         "INC 1  ·  INCTask 0  ·  PRB 1  ·  PRBTask 0  ·  CHG 1/1  ·  CHGTask 0  ·  Other 1")

    def test_all_includes_resolved(self):
        self.run_main("-s", "-a")
        self.assertTrue(self.out.startswith("INC 2  ·"))

    def line(self, number):
        return next(line for line in self.out.splitlines() if number in line)

    def out_reset(self):
        self._out.seek(0)
        self._out.truncate()

    def test_group_board_shows_who_has_each_ticket(self):
        self.run_main("-g")
        self.assertIn("Ann Admin", self.line("INC1"))
        self.assertIn("Ann Admin", self.line("CHG1"))
        self.assertRegex(self.line("PRB1"), r"New\s+-\s")             # nobody has it
        self.assertRegex(self.line("CHG2"), r"Assess\s+-\s")

    def test_assignee_is_only_shown_with_g(self):
        for argv in ((), ("-u",), ("-a",)):
            with self.subTest(argv=argv):
                self.out_reset()
                self.run_main(*argv)
                self.assertNotIn("Ann Admin", self.out)

    def test_group_flat_list_and_changes_show_the_assignee(self):
        for argv in (("-f", "-g"), ("-c", "-g")):
            with self.subTest(argv=argv):
                self.out_reset()
                self.run_main(*argv)
                self.assertIn("Ann Admin", self.out)

    def test_assignee_is_fetched_and_in_the_json(self):
        self.run_main("-j", "-g")
        for call in self.server.api_calls():
            self.assertIn("assigned_to", call["params"]["sysparm_fields"])
        self.assertEqual(json.loads(self.out)["Incidents"][0]["assigned_to"], "Ann Admin")

    def test_json_groups_by_section(self):
        self.run_main("-j")
        out = json.loads(self.out)
        self.assertEqual([t["number"] for t in out["Incidents"]], ["INC1"])
        self.assertEqual([t["number"] for t in out["Other"]], ["SCTASK1"])
        self.assertEqual([c["number"] for c in out["Changes"]["standard"]], ["CHG1"])
        self.assertEqual([c["number"] for c in out["Changes"]["non_standard"]], ["CHG2"])
        self.assertNotIn("_raw", out["Incidents"][0])

    def test_mine_by_default_groups_with_g_queue_with_u(self):
        for flag, expected in ((None, "assigned_to=javascript:gs.getUserID()"),
                               ("-g", "assignment_group=javascript:getMyGroups()^ORDERBY"),
                               ("-u", "assignment_group=javascript:getMyGroups()^assigned_toISEMPTY")):
            self.server.calls.clear()
            self.run_main("-s", *([flag] if flag else []))
            self.assertIn(expected, self.server.api_calls()[0]["params"]["sysparm_query"])

    def test_sections_file_replaces_the_board(self):
        self.write(sleet.SECTIONS_FILE, json.dumps([{"label": "Mine", "table": "incident", "query": "active=true"}]))
        self.server.routes[("GET", "/api/now/table/incident")] = FakeResponse(result=TASKS[:1])
        self.run_main("-j")
        self.assertEqual([t["number"] for t in json.loads(self.out)["Mine"]], ["INC1"])

    @unittest.skipUnless(sleet.yaml, "needs PyYAML")
    def test_yaml_sections_file_replaces_the_board(self):
        self.patch(sleet, "SECTIONS_FILE", os.path.join(sleet.CONFIG_DIR, "sections.yaml"))
        self.write(sleet.SECTIONS_FILE, "- label: Mine\n  table: incident\n  query: 'active=true'  # a comment\n")
        self.server.routes[("GET", "/api/now/table/incident")] = FakeResponse(result=TASKS[:1])
        self.run_main("-j")
        self.assertEqual([t["number"] for t in json.loads(self.out)["Mine"]], ["INC1"])


class ShowTest(ServerTestCase):

    def setUp(self):
        super().setUp()
        journal = ("2026-11-13 10:00:00 - Alex (Work notes)\nsecond note\n\n"
                   "2026-11-12 09:00:00 - Alex (Work notes)\nfirst note\n")
        self.serve(routes={
            ("GET", "/api/now/table/task"): FakeResponse(result=[row(sys_id="s1", sys_class_name="incident")]),
            ("GET", "/api/now/table/incident"): FakeResponse(result=[row(
                number="INC1", short_description="disk full", state="In Progress", priority="3",
                description="the disk is full", comments_and_work_notes=journal)]),
        })

    def test_header_description_and_newest_activity_first(self):
        self.run_main("inc1", "-n", "1")
        self.assertIn("INC1  incident\ndisk full", self.out)
        self.assertIn("State:          In Progress", self.out)
        self.assertIn("the disk is full", self.out)
        self.assertIn("1 of 2, newest first", self.out)
        self.assertIn("second note", self.out)
        self.assertNotIn("first note", self.out)

    def test_json(self):
        self.run_main("INC1", "-j")
        self.assertEqual(json.loads(self.out)["short_description"], "disk full")

    def test_not_found(self):
        self.serve(routes={("GET", "/api/now/table/task"): FakeResponse(result=[])})
        self.assertDies("INC9 not found", self.run_main, "INC9")


# --------------------------------------------------------------------------- #
# writing
# --------------------------------------------------------------------------- #

def echo(**overrides):
    """A write route that returns the record as the body set it, with overrides applied on top."""
    return lambda kw: FakeResponse(result={"number": "INC1", "state": "In Progress", "assigned_to": "",
                                           "sys_id": "s1", **kw["json"], **overrides})


class WriteTestCase(ServerTestCase):
    """INC1 is incident s1; a PATCH returns what it was sent; the confirmation question says yes."""

    def setUp(self):
        super().setUp()
        self.server = self.serve(routes={
            ("GET", "/api/now/table/task"): FakeResponse(result=[row(sys_id="s1", sys_class_name="incident")]),
            ("PATCH", "/api/now/table/incident/s1"): echo(),
        })
        self.patch(sleet, "ask", mock.Mock(return_value="y"))

    def body(self):
        return self.server.api_calls("PATCH")[0]["json"]


class UpdateTest(WriteTestCase):

    def test_set_and_note_with_display_values(self):
        self.run_main("INC1", "--set", "state=In Progress", "-m", "looked at it", "-y")
        self.assertEqual(self.body(), {"work_notes": "looked at it", "state": "In Progress"})
        params = self.server.api_calls("PATCH")[0]["params"]
        self.assertEqual(params["sysparm_input_display_value"], "true")
        self.assertIn("updated", self.out)
        sleet.ask.assert_not_called()

    def test_asks_first_and_aborts_on_no(self):
        sleet.ask.return_value = "n"
        self.assertDies("aborted", self.run_main, "INC1", "-m", "x")
        self.assertEqual(self.server.api_calls("PATCH"), [])

    def test_v_shows_the_full_text_then_asks_again(self):
        sleet.ask.side_effect = ["v", "y"]
        self.run_main("INC1", "-m", "line one\nline two")
        self.assertIn("(+1 lines)", self.out)
        self.assertIn("line one\nline two", self.out)
        self.assertEqual(len(self.server.api_calls("PATCH")), 1)

    def test_customer_visible_comment_is_flagged(self):
        self.run_main("INC1", "--comment", "hello", "-y")
        self.assertIn("CUSTOMER-VISIBLE comment: hello", self.out)

    def test_dropped_field_is_reported_and_exits_1(self):
        self.server.routes[("PATCH", "/api/now/table/incident/s1")] = echo(urgency="3 - Low")
        with self.assertRaises(SystemExit) as cm:
            self.run_main("INC1", "--set", "urgency=1 - High", "-y")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("urgency not applied: wanted '1 - High', is '3 - Low'", self.out)

    def test_note_from_stdin(self):
        with mock.patch.object(sys, "stdin", io.StringIO("piped text\n")):
            self.run_main("INC1", "-m", "-", "-y")
        self.assertEqual(self.body(), {"work_notes": "piped text"})

    def test_nothing_to_write(self):
        self.assertDies("nothing to write", self.run_main, "INC1", "-m", " ", "-y")

    def test_set_needs_field_equals_value(self):
        self.assertDies("--set expects field=value", self.run_main, "INC1", "--set", "state", "-y")


class PresetTest(WriteTestCase):

    PRESETS = {
        "resolve": {"tables": ["incident"], "fields": {"state": "Resolved", "close_code": "Solved"},
                    "required": ["close_code"]},
        "review": {"tables": ["change_request"], "fields": {"state": "Review"}},
        "hours": {"fields": {"state": "Closed"}, "notes_field": "work_notes", "hours_field": "u_hours",
                  "require_hours": True},
    }

    def setUp(self):
        super().setUp()
        self.patch(sleet, "PRESETS", self.PRESETS)

    def test_resolve_shortcut(self):
        self.run_main("INC1", "-r", "fixed", "-y")
        self.assertEqual(self.body(), {"state": "Resolved", "close_code": "Solved", "close_notes": "fixed"})

    def test_set_overrides_a_preset_value(self):
        self.run_main("INC1", "-r", "fixed", "--set", "close_code=Workaround", "-y")
        self.assertEqual(self.body()["close_code"], "Workaround")

    def test_required_field_emptied(self):
        self.assertDies("preset 'resolve' requires close_code", self.run_main,
                        "INC1", "-r", "fixed", "--set", "close_code=", "-y")

    def test_wrong_table(self):
        self.assertDies("preset 'review' is for change_request, not incident", self.run_main,
                        "INC1", "--review", "x", "-y")

    def test_hours_go_to_the_preset_field(self):
        self.run_main("INC1", "-p", "hours", "notes", "--hours", "3", "-y")
        self.assertEqual(self.body(), {"state": "Closed", "work_notes": "notes", "u_hours": "3"})

    def test_require_hours(self):
        self.assertDies("preset 'hours' needs --hours N", self.run_main, "INC1", "-p", "hours", "x", "-y")

    def test_hours_without_a_field(self):
        self.assertDies("--hours needs 'hours_field'", self.run_main, "INC1", "--hours", "2", "-y")

    def test_unknown_preset(self):
        self.assertDies("no preset 'nope'", self.run_main, "INC1", "-p", "nope", "x", "-y")


class AssignTest(WriteTestCase):

    def users(self, rows):
        self.server.routes[("GET", "/api/now/table/sys_user")] = FakeResponse(result=rows)

    def test_assign_me_sends_my_sys_id(self):
        self.users([row(sys_id="u1", name="Alex", user_name="alex")])
        self.server.routes[("PATCH", "/api/now/table/incident/s1")] = echo(assigned_to="Alex")
        self.run_main("INC1", "--assign", "me", "-y")
        self.assertEqual(self.body(), {"assigned_to": "u1"})
        self.assertIn("assigned_to: Alex (alex)", self.out)

    def test_ambiguous_name(self):
        self.users([row(sys_id="u1", name="Jan", user_name="jan1", email=""),
                    row(sys_id="u2", name="Jan", user_name="jan2", email="")])
        self.assertDies("--assign 'Jan' matches 2 users: Jan (jan1); Jan (jan2)", self.run_main,
                        "INC1", "--assign", "Jan", "-y")

    def test_unknown_name_goes_to_servicenow_as_typed(self):
        self.users([])
        self.server.routes[("PATCH", "/api/now/table/incident/s1")] = echo()
        self.run_main("INC1", "--assign", "Some One", "-y")
        self.assertEqual(self.body(), {"assigned_to": "Some One"})

    def test_caret_is_refused(self):
        self.assertDies("'^' is not allowed", self.run_main, "INC1", "--assign", "a^ORb", "-y")


class CreateTest(ServerTestCase):

    TEMPLATES = {
        "inc": {"table": "incident", "required": ["assignment_group"],
                "fields": {"impact": "3 - Low", "_caller_id": "a note", "caller_id": "", "assignment_group": ""}},
        "broken": {"fields": {}},
    }

    def setUp(self):
        super().setUp()
        self.server = self.serve(routes={("POST", "/api/now/table/incident"): echo(number="INC0000100")})
        self.patch(sleet, "CFG", {"templates": self.TEMPLATES})

    def test_from_a_template(self):
        self.run_main("--new", "inc", "-t", "Title", "--set", "assignment_group=Team", "-y")
        self.assertEqual(self.server.api_calls("POST")[0]["json"],
                         {"impact": "3 - Low", "short_description": "Title", "assignment_group": "Team"})
        self.assertIn("created  INC0000100", self.out)

    def test_template_required_field_missing(self):
        self.assertDies("template 'inc' requires assignment_group", self.run_main, "--new", "inc", "-t", "T", "-y")
        self.assertEqual(self.server.api_calls("POST"), [])

    def test_unknown_template_falls_back_to_a_table_and_says_so(self):
        self.run_main("--new", "incident", "-t", "Title", "--desc", "Longer", "-y")
        self.assertIn("no template 'incident'", self.out)
        self.assertEqual(self.server.api_calls("POST")[0]["json"], {"short_description": "Title", "description": "Longer"})

    def test_needs_a_title(self):
        self.assertDies("needs a title", self.run_main, "--new", "incident", "-y")

    def test_template_without_table(self):
        self.assertDies("template 'broken'", self.run_main, "--new", "broken", "-t", "T", "-y")

    def test_not_a_table_name(self):
        self.assertDies("neither a template", self.run_main, "--new", "Bad-Name", "-t", "T", "-y")


# --------------------------------------------------------------------------- #
# main(): argument checks and order
# --------------------------------------------------------------------------- #

class SearchTest(ServerTestCase):

    def setUp(self):
        super().setUp()
        self.server = self.serve(routes={("GET", "/api/now/table/task"): FakeResponse(result=TASKS)})

    def query(self):
        return self.server.api_calls()[0]["params"]["sysparm_query"]

    def test_search_matches_the_number_and_the_short_description(self):
        self.run_main("--search", "disk")
        self.assertEqual(self.query(), "short_descriptionLIKEdisk^ORnumberLIKEdisk^ORDERBYDESCsys_updated_on")
        self.assertEqual(self.server.api_calls()[0]["path"], "/api/now/table/task")

    def test_search_lists_every_state_and_counts(self):
        self.run_main("--search", "disk")
        for number in ("INC1", "INC2", "PRB1", "SCTASK1"):
            self.assertIn(number, self.out)
        self.assertIn("4 matches", self.out)

    def test_search_with_no_matches(self):
        self.server.routes[("GET", "/api/now/table/task")] = FakeResponse(result=[])
        self.run_main("--search", "nothing")
        self.assertIn("0 matches", self.out)

    def test_in_desc_also_searches_the_description(self):
        self.run_main("--search", "disk", "--in", "desc")
        self.assertEqual(self.query(), "short_descriptionLIKEdisk^ORnumberLIKEdisk^ORdescriptionLIKEdisk"
                                       "^ORDERBYDESCsys_updated_on")

    def test_a_caret_in_the_text_cannot_add_query_terms(self):
        self.run_main("--search", "x^ORactive=true")
        self.assertIn("short_descriptionLIKEx^^ORactive=true^ORnumberLIKEx^^ORactive=true", self.query())

    def test_group_and_queue_limit_the_search(self):
        for flag, scope in (("-g", "assignment_group=javascript:getMyGroups()^"),
                            ("-u", "assignment_group=javascript:getMyGroups()^assigned_toISEMPTY^")):
            self.server.calls.clear()
            self.run_main("--search", "disk", flag)
            self.assertTrue(self.query().startswith(scope + "short_descriptionLIKEdisk"), self.query())

    def test_query_is_sent_as_written_and_newest_first(self):
        self.run_main("--query", "active=true^priority=1")
        self.assertEqual(self.query(), "active=true^priority=1^ORDERBYDESCsys_updated_on")

    def test_query_keeps_its_own_ordering(self):
        self.run_main("--query", "active=true^ORDERBYnumber")
        self.assertEqual(self.query(), "active=true^ORDERBYnumber")

    def test_table_picks_the_table(self):
        self.server.routes[("GET", "/api/now/table/incident")] = FakeResponse(result=TASKS[:1])
        self.run_main("--table", "incident", "--query", "category=network")
        self.assertEqual(self.server.api_calls()[0]["path"], "/api/now/table/incident")
        self.assertIn("INC1", self.out)

    def test_a_table_without_ticket_numbers_is_refused(self):
        self.server.routes[("GET", "/api/now/table/sys_user")] = FakeResponse(result=[row(name="x")])
        self.assertDies("sys_user has no ticket numbers", self.run_main,
                        "--table", "sys_user", "--query", "active=true")

    def test_limit_is_sent_and_the_cut_is_reported(self):
        self.run_main("--search", "disk")
        self.assertEqual(self.server.api_calls()[0]["params"]["sysparm_limit"], "50")
        self.server.calls.clear()
        self.run_main("--search", "disk", "--limit", "4")
        self.assertEqual(self.server.api_calls()[0]["params"]["sysparm_limit"], "4")
        self.assertIn("showing the first 4", self.out)

    def test_json(self):
        self.run_main("--search", "disk", "-j")
        out = json.loads(self.out)
        self.assertEqual([t["number"] for t in out], ["INC1", "INC2", "PRB1", "SCTASK1"])
        self.assertNotIn("_raw", out[0])


class MainArgsTest(ServerTestCase):

    def setUp(self):
        super().setUp()
        self.serve()

    def test_search_needs_some_text(self):
        self.assertUsageError("--search needs some text", "--search", " ")

    def test_search_and_query_are_alternatives(self):
        self.assertUsageError("not allowed with", "--search", "x", "--query", "active=true")

    def test_search_options_need_a_search(self):
        for opt in (["--in", "desc"], ["--table", "incident"], ["--limit", "5"]):
            with self.subTest(opt=opt):
                self.assertUsageError("need --search or --query", *opt)

    def test_in_desc_is_for_search_text(self):
        self.assertUsageError("--in is for --search", "--query", "active=true", "--in", "desc")

    def test_query_is_used_as_written(self):
        self.assertUsageError("-g/-u do not apply to --query", "--query", "active=true", "-g")

    def test_search_includes_resolved_tickets_already(self):
        self.assertUsageError("always include resolved tickets", "--search", "x", "-a")

    def test_search_stands_alone(self):
        self.assertUsageError("--search and --query stand alone", "INC1", "--search", "x")
        self.assertUsageError("--search and --query stand alone", "--query", "active=true", "-m", "x")

    def test_limit_is_a_positive_number(self):
        self.assertUsageError("--limit must be 1 or more", "--search", "x", "--limit", "0")

    def test_no_instance(self):
        self.patch(sleet, "INSTANCE", "")
        self.assertUsageError("no instance", "-s")

    def test_instance_must_be_a_host_label(self):
        self.patch(sleet, "INSTANCE", "evil.example.com/")
        self.assertUsageError("must be only the name before .service-now.com", "-s")

    def test_write_options_need_a_number(self):
        self.assertUsageError("write options need a ticket number", "-m", "x")

    def test_only_one_preset(self):
        self.assertUsageError("use only one of --preset/--resolve/--review", "INC1", "-r", "a", "--review", "b")

    def test_only_one_stdin(self):
        self.assertUsageError("only one of --note/--comment/--desc/--preset can read stdin",
                              "INC1", "-m", "-", "--comment", "-")

    def test_new_takes_no_number(self):
        self.assertUsageError("leave out the ticket number", "INC1", "--new", "inc")

    def test_title_needs_new(self):
        self.assertUsageError("-t/--desc need --new", "-t", "x")

    def test_fields_stands_alone(self):
        self.assertUsageError("--fields and --template stand alone", "INC1", "--fields", "incident")

    def test_fields_takes_at_most_one_field(self):
        self.assertUsageError("at most one field", "--fields", "incident", "a", "b")

    def test_browser_needs_refresh_cookie(self):
        self.assertUsageError("--browser needs --refresh-cookie", "--browser", "chrome")

    def test_refresh_cookie_runs_on_every_system(self):
        for system in ("linux", "win32", "darwin"):
            with self.subTest(system=system):
                steps = []
                self.patch(sleet, "PLATFORM", system)
                self.patch(sleet, "refresh_cookie", lambda browser: steps.append(browser))
                self.patch(sleet, "session", lambda: None)
                self.patch(sleet, "board", lambda s, a: None)
                self.run_main("--refresh-cookie", "--browser", "clipboard", "-s")
                self.assertEqual(steps, ["clipboard"])

    def test_refresh_cookie_runs_before_the_session_and_then_the_command(self):
        steps = []
        self.patch(sleet, "refresh_cookie", lambda browser: steps.append(("refresh", browser)))
        self.patch(sleet, "session", lambda: steps.append("session"))
        self.patch(sleet, "board", lambda s, a: steps.append("board"))
        self.run_main("--refresh-cookie", "--browser", "firefox", "-s")
        self.assertEqual(steps, [("refresh", "firefox"), "session", "board"])

    def test_run_turns_connection_errors_into_one_line(self):
        self.patch(sleet, "main", mock.Mock(side_effect=sleet.requests.exceptions.ConnectionError()))
        self.assertDies("cannot reach https://example.service-now.com: ConnectionError (VPN/DNS?)", sleet.run)


# --------------------------------------------------------------------------- #
# --refresh-cookie
# --------------------------------------------------------------------------- #

class ForInstanceTest(unittest.TestCase):

    def test_host_only_cookie(self):
        self.assertTrue(sleet.for_instance(HOST))

    def test_domain_cookies_of_parents(self):
        self.assertTrue(sleet.for_instance(".service-now.com"))
        self.assertTrue(sleet.for_instance("." + HOST))

    def test_case_does_not_matter(self):
        self.assertTrue(sleet.for_instance("Example.Service-Now.com"))

    def test_other_instances_are_not_sent(self):
        self.assertFalse(sleet.for_instance("other.service-now.com"))
        self.assertFalse(sleet.for_instance("xexample.service-now.com"))
        self.assertFalse(sleet.for_instance("now.com"))


class Lz4Test(unittest.TestCase):

    def test_literals_and_short_matches(self):
        self.assertEqual(sleet.lz4_block(LZ4_SHORT), b"abcabcabcabcabcabcabc hello hello hello!")

    def test_overlapping_match_repeats_a_byte(self):
        self.assertEqual(sleet.lz4_block(LZ4_RUN), b"x" * 1000)

    def test_long_literal_run_and_long_match(self):
        self.assertEqual(sleet.lz4_block(LZ4_LONG), noise(10) * 2)

    def test_literal_only_blocks(self):
        for n in (0, 14, 15, 269, 270, 600):
            data = noise(20)[:n]
            self.assertEqual(sleet.lz4_block(lz4_literals(data)), data)


class DbCopyTest(QuietTestCase):

    def test_sees_writes_still_in_the_wal_and_leaves_the_original_alone(self):
        path = os.path.join(self.dir, "Cookies")
        writer = sqlite3.connect(path)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE t (v)")
        writer.execute("INSERT INTO t VALUES ('in the wal')")
        writer.commit()                                  # kept open: the row stays in Cookies-wal
        self.assertTrue(os.path.getsize(path + "-wal"))
        before = open(path, "rb").read()
        with sleet.db_copy(path) as con:
            self.assertEqual(con.execute("SELECT v FROM t").fetchall(), [("in the wal",)])
        self.assertEqual(open(path, "rb").read(), before)


@unittest.skipUnless(sys.platform == "darwin", "CommonCrypto is macOS only")
class AesDecryptTest(unittest.TestCase):

    def key(self, password):
        return hashlib.pbkdf2_hmac("sha1", password.encode(), b"saltysalt", 1003, 16)

    def test_matches_openssl(self):
        plain = sleet.aes_decrypt(self.key(AES_PASSWORD), AES_CIPHERTEXT)
        self.assertEqual(plain, hashlib.sha256(HOST.encode()).digest() + AES_VALUE)

    def test_wrong_key_does_not_give_the_value(self):
        try:
            plain = sleet.aes_decrypt(self.key("wrong"), AES_CIPHERTEXT)
        except ValueError:
            return
        self.assertNotIn(AES_VALUE, plain)


class FakeTools:
    """Stand-in for subprocess.run: answers `security` from a Keychain dict and `pbpaste` from a
    clipboard string, and records every command."""

    def __init__(self, keychain=None, clipboard=""):
        self.keychain = keychain if keychain is not None else {"Chrome Safe Storage": AES_PASSWORD,
                                                               "Microsoft Edge Safe Storage": AES_PASSWORD}
        self.clipboard = clipboard
        self.commands = []

    def __call__(self, cmd, **kw):
        self.commands.append(cmd)
        if cmd[0] == "security":
            pw = self.keychain.get(cmd[-1])
            return subprocess.CompletedProcess(cmd, 0 if pw else 44, f"{pw}\n" if pw else "", "not found")
        if cmd[0] in ("pbpaste", "powershell", "wl-paste", "xclip", "xsel"):
            return subprocess.CompletedProcess(cmd, 0, self.clipboard, "")
        raise AssertionError(f"unexpected command {cmd}")

    def keychain_lookups(self):
        return [cmd[-1] for cmd in self.commands if cmd[0] == "security"]


class ChromiumCookiesTest(QuietTestCase):
    """The SQLite reading and filtering. Decryption is replaced by a marker so this runs anywhere;
    AesDecryptTest and test_real_decryption cover the real thing on macOS."""

    def setUp(self):
        super().setUp()
        self.tools = FakeTools()
        self.patch(sleet.subprocess, "run", self.tools)
        self.patch(sleet, "aes_decrypt", lambda key, data: data[len(b"ENC:"):])

    def profile(self, cookies, name="Default", root="Google/Chrome", version=24, encrypt=None):
        """A Cookies DB with (host, name, value, expires_utc) rows, encrypted like Chromium."""
        encrypt = encrypt or (lambda host, value: b"v10ENC:" + (hashlib.sha256(host.encode()).digest()
                                                                 if version >= 24 else b"") + value.encode())
        d = os.path.join(sleet.APP_SUPPORT, root, name)
        os.makedirs(d)
        con = sqlite3.connect(os.path.join(d, "Cookies"))
        con.execute("CREATE TABLE meta (key, value)")
        con.execute("INSERT INTO meta VALUES ('version', ?)", (str(version),))
        con.execute("CREATE TABLE cookies (host_key, name, value, encrypted_value, expires_utc)")
        for host, cname, value, expires in cookies:
            con.execute("INSERT INTO cookies VALUES (?, ?, '', ?, ?)", (host, cname, encrypt(host, value), expires))
        con.commit()
        con.close()

    def read(self, browser="chrome"):
        return list(sleet.chromium_cookies(browser))

    def test_only_cookies_the_browser_would_send_to_the_instance(self):
        self.profile([(HOST, "JSESSIONID", "s1", 0), (".service-now.com", "wide", "w", 0),
                      ("other.service-now.com", "BIGip", "x", 0), ("example.com", "nope", "y", 0)])
        self.assertEqual(self.read(), [("chrome (Default)", "JSESSIONID=s1; wide=w")])

    def test_version_24_strips_the_domain_hash_and_older_versions_do_not_have_one(self):
        self.profile([(HOST, "a", "new", 0)], name="Default", version=24)
        self.profile([(HOST, "b", "old", 0)], name="Profile 1", version=23)
        self.assertEqual(self.read(), [("chrome (Default)", "a=new"), ("chrome (Profile 1)", "b=old")])

    def test_skips_expired_cookies_but_keeps_session_cookies(self):
        future = int((time.time() + 11644473600 + 3600) * 1_000_000)
        self.profile([(HOST, "session", "1", 0), (HOST, "later", "2", future), (HOST, "gone", "3", 1)])
        self.assertEqual(self.read(), [("chrome (Default)", "session=1; later=2")])

    def test_unencrypted_values_are_used_as_they_are(self):
        self.profile([(HOST, "plain", "", 0)], encrypt=lambda host, value: b"")
        d = os.path.join(sleet.APP_SUPPORT, "Google/Chrome", "Default", "Cookies")
        with sqlite3.connect(d) as con:
            con.execute("UPDATE cookies SET value = 'clear'")
        self.assertEqual(self.read(), [("chrome (Default)", "plain=clear")])

    def test_asks_the_keychain_once_for_all_profiles(self):
        self.profile([(HOST, "a", "1", 0)], name="Default")
        self.profile([(HOST, "b", "2", 0)], name="Profile 1")
        self.assertEqual(len(self.read()), 2)
        self.assertEqual(self.tools.keychain_lookups(), ["Chrome Safe Storage"])

    def test_no_keychain_prompt_without_servicenow_cookies(self):
        self.profile([("example.com", "a", "1", 0)])
        self.assertEqual(self.read(), [])
        self.assertEqual(self.tools.commands, [])

    def test_keychain_refused(self):
        self.tools.keychain = {}
        self.profile([(HOST, "a", "1", 0)])
        self.assertEqual(self.read(), [])
        self.assertIn("chrome: no access to 'Chrome Safe Storage' in your Keychain", self.err)

    def test_edge_has_its_own_folder_and_keychain_item(self):
        self.profile([(HOST, "a", "1", 0)], root="Microsoft Edge")
        self.assertEqual(self.read("edge"), [("edge (Default)", "a=1")])
        self.assertEqual(self.tools.keychain_lookups(), ["Microsoft Edge Safe Storage"])
        self.assertEqual(self.read("chrome"), [])

    def test_browser_not_installed(self):
        self.assertEqual(self.read(), [])

    def cookies_file(self, name="Default"):
        return os.path.join(sleet.APP_SUPPORT, "Google/Chrome", name, "Cookies")

    def test_a_corrupt_profile_is_skipped_and_the_next_one_is_still_read(self):
        os.makedirs(os.path.dirname(self.cookies_file()))
        with open(self.cookies_file(), "wb") as f:
            f.write(b"not a database at all" * 50)
        self.profile([(HOST, "a", "1", 0)], name="Profile 1")
        self.assertEqual(self.read(), [("chrome (Profile 1)", "a=1")])
        self.assertIn("chrome (Default): cannot read its cookies (DatabaseError), skipped", self.err)

    def test_a_profile_without_a_version_is_skipped(self):
        self.profile([(HOST, "a", "1", 0)])
        with sqlite3.connect(self.cookies_file()) as con:
            con.execute("DELETE FROM meta")
        self.profile([(HOST, "b", "2", 0)], name="Profile 1")
        self.assertEqual(self.read(), [("chrome (Profile 1)", "b=2")])
        self.assertIn("chrome (Default): cannot read its cookies (TypeError), skipped", self.err)

    def test_a_cookie_that_does_not_decrypt_skips_its_profile_only(self):
        def decrypt(key, data):
            if data.endswith(b"broken"):
                raise ValueError("cannot decrypt cookie")
            return data[len(b"ENC:"):]
        self.patch(sleet, "aes_decrypt", decrypt)
        self.profile([(HOST, "a", "broken", 0)])
        self.profile([(HOST, "b", "2", 0)], name="Profile 1")
        self.assertEqual(self.read(), [("chrome (Profile 1)", "b=2")])
        self.assertIn("chrome (Default): cannot read its cookies (ValueError), skipped", self.err)

    def test_a_value_that_decrypts_to_no_text_skips_its_profile(self):
        self.patch(sleet, "aes_decrypt", lambda key, data: b"\xff\xfe" * 20)
        self.profile([(HOST, "a", "1", 0)], version=23)
        self.assertEqual(self.read(), [])
        self.assertIn("cannot read its cookies (UnicodeDecodeError), skipped", self.err)

    def test_an_unknown_encryption_format_is_left_out_and_never_sent_empty(self):
        self.profile([(HOST, "known", "1", 0), (HOST, "future", "2", 0)],
                     encrypt=lambda host, value: (b"v11" if value == "2" else b"v10ENC:" +
                                                  hashlib.sha256(host.encode()).digest()) + value.encode())
        self.assertEqual(self.read(), [("chrome (Default)", "known=1")])
        self.assertIn("chrome (Default): left out 1 cookie in an unknown format", self.err)

    def test_only_unknown_formats_yields_nothing(self):
        self.profile([(HOST, "future", "2", 0)], encrypt=lambda host, value: b"v11" + value.encode())
        self.assertEqual(self.read(), [])

    def test_the_host_cookie_wins_over_one_set_on_the_parent_domain(self):
        self.profile([(".service-now.com", "JSESSIONID", "tossed", 0), (HOST, "JSESSIONID", "real", 0),
                      (HOST, "other", "o", 0), (".service-now.com", "other", "wide", 0)])
        self.assertEqual(self.read(), [("chrome (Default)", "JSESSIONID=real; other=o")])

    @unittest.skipUnless(sys.platform == "darwin", "CommonCrypto is macOS only")
    def test_real_decryption(self):
        self.patch(sleet, "aes_decrypt", REAL_AES_DECRYPT)
        self.profile([(HOST, "JSESSIONID", "", 0)], encrypt=lambda host, value: b"v10" + AES_CIPHERTEXT)
        self.assertEqual(self.read(), [("chrome (Default)", "JSESSIONID=" + AES_VALUE.decode())])


class FirefoxCookiesTest(QuietTestCase):

    def profile(self, persistent=(), session=(), store="sessionstore-backups/recovery.jsonlz4", name="abc.default"):
        d = os.path.join(sleet.APP_SUPPORT, "Firefox", "Profiles", name)
        os.makedirs(os.path.join(d, "sessionstore-backups"))
        con = sqlite3.connect(os.path.join(d, "cookies.sqlite"))
        con.execute("CREATE TABLE moz_cookies (host, name, value, expiry)")
        con.executemany("INSERT INTO moz_cookies VALUES (?, ?, ?, ?)",       # 3 values: expires in an hour
                        [tuple(c) + (int(time.time()) + 3600,) * (4 - len(c)) for c in persistent])
        con.commit()
        con.close()
        if store:
            data = json.dumps({"windows": [], "cookies": [{"host": h, "name": n, "value": v, "path": "/"}
                                                          for h, n, v in session]}).encode()
            with open(os.path.join(d, store), "wb") as f:
                f.write(b"mozLz40\0" + len(data).to_bytes(4, "little") + lz4_literals(data))
        return d

    def read(self):
        return list(sleet.firefox_cookies())

    def test_persistent_cookies_plus_session_cookies_from_the_session_store(self):
        self.profile(persistent=[(HOST, "glide_user_route", "r"), ("other.service-now.com", "x", "y")],
                     session=[(HOST, "JSESSIONID", "s"), ("example.com", "nope", "n")])
        self.assertEqual(self.read(), [("firefox (abc.default)", "glide_user_route=r; JSESSIONID=s")])

    def test_after_a_clean_shutdown_the_store_is_sessionstore_jsonlz4(self):
        self.profile(session=[(HOST, "JSESSIONID", "s")], store="sessionstore.jsonlz4")
        self.assertEqual(self.read(), [("firefox (abc.default)", "JSESSIONID=s")])

    def test_the_running_session_wins_over_the_last_shutdown(self):
        d = self.profile(session=[(HOST, "JSESSIONID", "running")])
        data = json.dumps({"cookies": [{"host": HOST, "name": "JSESSIONID", "value": "old"}]}).encode()
        with open(os.path.join(d, "sessionstore.jsonlz4"), "wb") as f:
            f.write(b"mozLz40\0" + len(data).to_bytes(4, "little") + lz4_literals(data))
        self.assertEqual(self.read(), [("firefox (abc.default)", "JSESSIONID=running")])

    def test_a_file_that_is_not_mozlz4_is_ignored(self):
        d = self.profile(persistent=[(HOST, "glide_user_route", "r")], store=None)
        with open(os.path.join(d, "sessionstore-backups", "recovery.jsonlz4"), "wb") as f:
            f.write(b"garbage")
        self.assertEqual(self.read(), [("firefox (abc.default)", "glide_user_route=r")])

    def test_profiles_without_servicenow_cookies_are_skipped(self):
        self.profile(persistent=[("example.com", "a", "b")], session=[("example.com", "c", "d")])
        self.assertEqual(self.read(), [])


class FirefoxRobustnessTest(QuietTestCase):

    def profile_dir(self, name="abc.default"):
        d = os.path.join(sleet.APP_SUPPORT, "Firefox", "Profiles", name)
        os.makedirs(os.path.join(d, "sessionstore-backups"))
        return d

    def store(self, d, payload, path="sessionstore-backups/recovery.jsonlz4"):
        with open(os.path.join(d, path), "wb") as f:
            f.write(b"mozLz40\0" + len(payload).to_bytes(4, "little") + payload)

    def cookies_db(self, d, rows):
        con = sqlite3.connect(os.path.join(d, "cookies.sqlite"))
        con.execute("CREATE TABLE moz_cookies (host, name, value, expiry)")
        con.executemany("INSERT INTO moz_cookies VALUES (?, ?, ?, ?)", rows)
        con.commit()
        con.close()

    def read(self):
        return list(sleet.firefox_cookies())

    def test_a_truncated_session_store_skips_that_profile_only(self):
        self.store(self.profile_dir("a.broken"), b"\xf0")
        good = json.dumps({"cookies": [{"host": HOST, "name": "JSESSIONID", "value": "s"}]}).encode()
        self.store(self.profile_dir("b.good"), lz4_literals(good))
        self.assertEqual(self.read(), [("firefox (b.good)", "JSESSIONID=s")])
        self.assertIn("firefox (a.broken): cannot read its cookies (IndexError), skipped", self.err)

    def test_a_session_store_that_is_not_json_is_skipped(self):
        self.store(self.profile_dir(), lz4_literals(b"{not json"))
        self.assertEqual(self.read(), [])
        self.assertIn("cannot read its cookies (JSONDecodeError), skipped", self.err)

    def test_a_corrupt_cookie_database_is_skipped(self):
        d = self.profile_dir()
        with open(os.path.join(d, "cookies.sqlite"), "wb") as f:
            f.write(b"not a database at all" * 50)
        self.assertEqual(self.read(), [])
        self.assertIn("firefox (abc.default): cannot read its cookies (DatabaseError), skipped", self.err)

    def test_a_session_cookie_without_a_value_is_empty_not_an_error(self):
        entries = [{"host": HOST, "name": "flag"}, {"name": "no-host", "value": "x"}]
        self.store(self.profile_dir(), lz4_literals(json.dumps({"cookies": entries}).encode()))
        self.assertEqual(self.read(), [("firefox (abc.default)", "flag=")])

    def test_expired_persistent_cookies_are_left_out_in_seconds_and_milliseconds(self):
        now = int(time.time())
        d = self.profile_dir()
        self.cookies_db(d, [(HOST, "gone", "1", now - 60), (HOST, "gone_ms", "2", (now - 60) * 1000),
                            (HOST, "kept", "3", now + 3600), (HOST, "kept_ms", "4", (now + 3600) * 1000)])
        self.assertEqual(self.read(), [("firefox (abc.default)", "kept=3; kept_ms=4")])

    def test_the_session_store_wins_over_a_persistent_cookie_of_the_same_name(self):
        d = self.profile_dir()
        self.cookies_db(d, [(HOST, "JSESSIONID", "persisted", int(time.time()) + 3600)])
        live = json.dumps({"cookies": [{"host": HOST, "name": "JSESSIONID", "value": "live"}]}).encode()
        self.store(d, lz4_literals(live))
        self.assertEqual(self.read(), [("firefox (abc.default)", "JSESSIONID=live")])


class CookieHeaderTest(unittest.TestCase):

    def test_keeps_the_order_in_which_names_first_appear(self):
        self.assertEqual(sleet.cookie_header([(HOST, "b", "2"), (HOST, "a", "1")]), "b=2; a=1")

    def test_the_most_specific_domain_wins_whatever_the_order(self):
        wide, host = (".service-now.com", "s", "wide"), (HOST, "s", "host")
        self.assertEqual(sleet.cookie_header([wide, host]), "s=host")
        self.assertEqual(sleet.cookie_header([host, wide]), "s=host")

    def test_a_leading_dot_does_not_count(self):
        self.assertEqual(sleet.cookie_header([("." + HOST, "s", "first"), (HOST, "s", "last")]), "s=last")

    def test_nothing(self):
        self.assertEqual(sleet.cookie_header([]), "")


class SafariCookiesTest(QuietTestCase):

    def clipboard(self, text):
        self.patch(sleet.subprocess, "run", FakeTools(clipboard=text))
        return list(sleet.safari_cookies())

    def test_safari_copy_as_curl(self):
        text = ("curl 'https://example.service-now.com/incident_list.do' \\\n"
                "-H 'Accept: text/html' \\\n-H 'Cookie: JSESSIONID=s; glide_session_store=g' \\\n"
                "-H 'User-Agent: Safari'")
        self.assertEqual(self.clipboard(text), [("the clipboard", "JSESSIONID=s; glide_session_store=g")])

    def test_chrome_copy_as_curl_uses_b(self):
        text = "curl 'https://example.service-now.com/' \\\n  -b 'JSESSIONID=s; a=b' \\\n  -H 'accept: */*'"
        self.assertEqual(self.clipboard(text), [("the clipboard", "JSESSIONID=s; a=b")])

    def test_bash_ansi_quoting(self):
        self.assertEqual(self.clipboard("curl 'x' -b $'JSESSIONID=s; a=b'"), [("the clipboard", "JSESSIONID=s; a=b")])

    def test_a_header_line(self):
        self.assertEqual(self.clipboard("Cookie: JSESSIONID=s; a=b"), [("the clipboard", "JSESSIONID=s; a=b")])

    def test_a_bare_header_value(self):
        self.assertEqual(self.clipboard("JSESSIONID=s; a=b\n"), [("the clipboard", "JSESSIONID=s; a=b")])

    def test_anything_else_explains_what_to_copy(self):
        self.assertDies("Copy as cURL", self.clipboard, "some notes\nfrom a meeting")

    def test_unrelated_clipboard_text_is_never_taken_for_a_cookie(self):
        for text in ("https://intranet.example/reset?token=SECRET123", "user@example.com: pass=word",
                     "x = 1", "export API_KEY=abc def", "a=b, c=d"):
            with self.subTest(text=text):
                self.assertDies("no cookie on the clipboard", self.clipboard, text)

    def test_a_bare_value_with_one_pair_and_a_trailing_semicolon(self):
        self.assertEqual(self.clipboard("JSESSIONID=s;"), [("the clipboard", "JSESSIONID=s;")])
        self.assertEqual(self.clipboard("glide.session-1=a%3Db"), [("the clipboard", "glide.session-1=a%3Db")])


class SignedInTest(QuietTestCase):

    def check(self, **kw):
        server = FakeServer(**kw)
        self.patch(sleet.requests, "get", server.get)
        return sleet.signed_in("JSESSIONID=s"), server.calls[0]

    def test_page_with_g_ck(self):
        ok, call = self.check()
        self.assertTrue(ok)
        self.assertEqual(call["sent"]["Cookie"], "JSESSIONID=s")
        self.assertFalse(call["allow_redirects"])

    def test_sso_redirect(self):
        self.assertFalse(self.check(signed_in=False)[0])

    def test_page_without_g_ck(self):
        self.assertFalse(self.check(gck="")[0])


class SaveCookieTest(QuietTestCase):

    def test_creates_a_private_directory_and_file(self):
        shutil.rmtree(sleet.CONFIG_DIR)
        sleet.save_cookie("a=1; b=2")
        if os.name == "posix":                               # Windows has no owner-only permissions
            self.assertEqual(os.stat(sleet.CONFIG_DIR).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(sleet.COOKIE_FILE).st_mode & 0o777, 0o600)
        self.assertEqual(sleet.read_cookie(), "a=1; b=2")

    @unittest.skipUnless(os.name == "posix", "Windows has no owner-only file permissions")
    def test_tightens_an_existing_file(self):
        self.write(sleet.COOKIE_FILE, "old=1; and=more", mode=0o644)
        sleet.save_cookie("new=1")
        self.assertEqual(os.stat(sleet.COOKIE_FILE).st_mode & 0o777, 0o600)
        with open(sleet.COOKIE_FILE) as f:
            self.assertEqual(f.read(), "new=1\n")


class RefreshCookieTest(QuietTestCase):

    def setUp(self):
        super().setUp()
        self.read = []
        self.patch(sleet, "BROWSERS", {
            "chrome": lambda: self.candidates("chrome", [("chrome (Default)", "old=1"), ("chrome (Work)", "good=1")]),
            "edge": lambda: self.candidates("edge", [("edge (Default)", "good=2")]),
            "firefox": lambda: self.candidates("firefox", []),
            "safari": lambda: self.candidates("safari", [("the clipboard", "good=3")]),
        })
        self.patch(sleet, "signed_in", lambda raw: raw.startswith("good"))

    def candidates(self, browser, found):
        self.read.append(browser)
        yield from found

    def saved(self):
        with open(sleet.COOKIE_FILE) as f:
            return f.read().strip()

    def test_saves_the_first_working_session_and_reads_no_further(self):
        sleet.refresh_cookie(None)
        self.assertEqual(self.saved(), "good=1")
        self.assertEqual(self.read, ["chrome"])
        self.assertIn("chrome (Default): its session is not accepted", self.err)
        self.assertIn("cookie refreshed from chrome (Work)", self.err)

    def test_one_browser_only(self):
        sleet.refresh_cookie("edge")
        self.assertEqual(self.saved(), "good=2")
        self.assertEqual(self.read, ["edge"])

    def test_nothing_signed_in_keeps_the_old_cookie_and_mentions_safari(self):
        self.write(sleet.COOKIE_FILE, "still=valid")
        self.patch(sleet, "signed_in", lambda raw: False)
        self.assertDies("(Safari: add --browser safari)", sleet.refresh_cookie, None)
        self.assertEqual(self.read, ["chrome", "edge", "firefox"])
        self.assertEqual(self.saved(), "still=valid")

    def test_auto_mode_never_reads_the_clipboard(self):
        self.patch(sleet, "signed_in", lambda raw: False)
        with self.assertRaises(SystemExit):
            sleet.refresh_cookie(None)
        self.assertNotIn("safari", self.read)

    def test_one_unreadable_profile_does_not_stop_the_refresh(self):
        self.patch(sleet, "BROWSERS", dict(sleet.BROWSERS, chrome=lambda: sleet.chromium_cookies("chrome")))
        self.patch(sleet.subprocess, "run", FakeTools())
        d = os.path.join(sleet.APP_SUPPORT, "Google/Chrome", "Default")
        os.makedirs(d)
        with open(os.path.join(d, "Cookies"), "wb") as f:
            f.write(b"garbage" * 100)
        sleet.refresh_cookie(None)
        self.assertEqual(self.saved(), "good=2")
        self.assertIn("chrome (Default): cannot read its cookies", self.err)
        self.assertIn("cookie refreshed from edge (Default)", self.err)

    def test_cookies_that_are_refused_say_to_reload_the_page_and_wait(self):
        self.patch(sleet, "signed_in", lambda raw: False)
        self.assertDies("reload a ServiceNow page there, wait 30 seconds and retry", sleet.refresh_cookie, "chrome")

    def test_no_cookies_at_all_says_to_sign_in(self):
        self.assertDies("no signed-in session found - sign in to", sleet.refresh_cookie, "firefox")

    def test_a_refused_clipboard_cookie_is_not_blamed_on_the_browser_cache(self):
        self.patch(sleet, "signed_in", lambda raw: False)
        self.assertDies("no signed-in session found", sleet.refresh_cookie, "safari")

    def test_failing_named_browser_has_no_safari_hint(self):
        self.patch(sleet, "signed_in", lambda raw: False)
        with self.assertRaises(SystemExit) as cm:
            sleet.refresh_cookie("firefox")
        self.assertNotIn("Safari", str(cm.exception.code))


class ClipboardTest(QuietTestCase):
    """--browser clipboard: the same on every system, only the tool that reads the clipboard differs."""

    def read(self, text, system="darwin", tools=("wl-paste", "xclip", "xsel")):
        self.tools = FakeTools(clipboard=text)
        self.patch(sleet, "PLATFORM", system)
        self.patch(sleet.subprocess, "run", self.tools)
        self.patch(sleet.shutil, "which", lambda name: name if name in tools else None)
        return list(sleet.clipboard_cookies())

    def test_each_system_has_its_own_clipboard_tool(self):
        for system, tool in (("darwin", "pbpaste"), ("win32", "powershell"), ("linux", "wl-paste")):
            with self.subTest(system=system):
                self.assertEqual(self.read("a=b", system), [("the clipboard", "a=b")])
                self.assertEqual(self.tools.commands[0][0], tool)

    def test_linux_uses_the_first_tool_that_is_installed(self):
        self.read("a=b", "linux", tools=("xsel",))
        self.assertEqual(self.tools.commands, [["xsel", "-ob"]])
        self.read("a=b", "linux", tools=("xclip", "xsel"))
        self.assertEqual(self.tools.commands[0][0], "xclip")

    def test_linux_without_a_clipboard_tool_says_what_to_install(self):
        self.assertDies("needs wl-paste (Wayland), xclip or xsel", self.read, "a=b", "linux", tools=())

    def test_windows_copy_as_curl_cmd(self):
        text = ('curl ^"https://example.service-now.com/incident_list.do^" ^\n'
                '  -H ^"accept: text/html^" ^\n'
                '  -b ^"JSESSIONID=abc123; glide_session_store=X^%^3D1; route=a^|b^" ^\n'
                '  -H ^"user-agent: Mozilla/5.0 ^(Windows NT 10.0^)^"')
        self.assertEqual(self.read(text, "win32"),
                         [("the clipboard", "JSESSIONID=abc123; glide_session_store=X%3D1; route=a|b")])

    def test_windows_copy_as_curl_cmd_with_a_cookie_header(self):
        text = 'curl ^"https://example.service-now.com/^" ^\n  -H ^"Cookie: JSESSIONID=s; a=b^" ^\n  -H ^"x: y^"'
        self.assertEqual(self.read(text, "win32"), [("the clipboard", "JSESSIONID=s; a=b")])

    def test_double_quoted_b(self):
        self.assertEqual(self.read('curl "https://x" -b "JSESSIONID=s; a=b" -H "x: y"'),
                         [("the clipboard", "JSESSIONID=s; a=b")])

    def test_copy_as_powershell_keeps_only_cookies_for_the_instance(self):
        text = ('$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession\n'
                '$session.UserAgent = "Mozilla/5.0"\n'
                '$session.Cookies.Add((New-Object System.Net.Cookie("JSESSIONID", "abc", "/", "example.service-now.com")))\n'
                '$session.Cookies.Add((New-Object System.Net.Cookie("_ga", "GA1.2", "/", ".service-now.com")))\n'
                '$session.Cookies.Add((New-Object System.Net.Cookie("other", "x", "/", "other.example.com")))\n'
                'Invoke-WebRequest -UseBasicParsing -Uri "https://example.service-now.com/incident_list.do" `\n'
                '-WebSession $session')
        self.assertEqual(self.read(text, "win32"), [("the clipboard", "JSESSIONID=abc; _ga=GA1.2")])

    def test_copy_as_powershell_unescapes_backticks(self):
        text = '$session.Cookies.Add((New-Object System.Net.Cookie("n", "a`$b`"c", "/", "example.service-now.com")))'
        self.assertEqual(self.read(text, "win32"), [("the clipboard", 'n=a$b"c')])

    def test_copy_as_powershell_without_a_cookie_for_the_instance(self):
        text = '$session.Cookies.Add((New-Object System.Net.Cookie("n", "v", "/", "other.example.com")))'
        self.assertDies("no cookie on the clipboard", self.read, text, "win32")

    def test_nothing_useful_explains_the_steps_for_any_browser(self):
        self.assertDies("press F12 > Network", self.read, "meeting notes", "win32")

    def test_safari_keeps_its_own_explanation(self):
        self.patch(sleet.subprocess, "run", FakeTools(clipboard="meeting notes"))
        self.assertDies("Develop > Show Web Inspector", lambda: list(sleet.safari_cookies()))


class OtherSystemsTest(QuietTestCase):
    """What differs outside macOS. PLATFORM is switched; the real Windows behaviour is covered by CI."""

    def home(self, system):
        """Point the home folder and %APPDATA% at the test directory."""
        self.patch(sleet, "PLATFORM", system)
        env = mock.patch.dict(os.environ, {"HOME": self.dir, "USERPROFILE": self.dir,
                                           "APPDATA": os.path.join(self.dir, "AppData", "Roaming")})
        env.start()
        self.addCleanup(env.stop)

    def firefox_profile(self, *parts):
        d = os.path.join(self.dir, *parts)
        os.makedirs(d)
        data = json.dumps({"cookies": [{"host": HOST, "name": "JSESSIONID", "value": "s"}]}).encode()
        with open(os.path.join(d, "sessionstore.jsonlz4"), "wb") as f:
            f.write(b"mozLz40\0" + len(data).to_bytes(4, "little") + lz4_literals(data))

    def test_firefox_on_windows_lives_under_appdata(self):
        self.home("win32")
        self.firefox_profile("AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "abc.default-release")
        self.assertEqual(list(sleet.firefox_cookies()), [("firefox (abc.default-release)", "JSESSIONID=s")])

    def test_firefox_on_linux_as_package_snap_or_flatpak(self):
        self.home("linux")
        self.firefox_profile(".mozilla", "firefox", "a.default")
        self.firefox_profile("snap", "firefox", "common", ".mozilla", "firefox", "b.snap")
        self.firefox_profile(".var", "app", "org.mozilla.firefox", ".mozilla", "firefox", "c.flatpak")
        self.assertEqual([label for label, _ in sleet.firefox_cookies()],
                         ["firefox (a.default)", "firefox (b.snap)", "firefox (c.flatpak)"])

    def test_the_macos_folder_is_not_read_elsewhere(self):
        self.home("linux")
        self.firefox_profile("Application Support", "Firefox", "Profiles", "mac.default")
        self.assertEqual(list(sleet.firefox_cookies()), [])

    def test_chrome_and_edge_are_refused_with_the_clipboard_route(self):
        for system in ("win32", "linux"):
            for browser in ("chrome", "edge"):
                with self.subTest(system=system, browser=browser):
                    self.patch(sleet, "PLATFORM", system)
                    self.assertDies(f"{browser.capitalize()} cookies can only be read on macOS",
                                    sleet.refresh_cookie, browser)
                    self.assertDies("--browser clipboard", sleet.refresh_cookie, browser)

    def test_chrome_and_edge_never_touch_the_keychain_tool_elsewhere(self):
        self.patch(sleet, "PLATFORM", "win32")
        tools = FakeTools()
        self.patch(sleet.subprocess, "run", tools)
        with self.assertRaises(SystemExit):
            sleet.refresh_cookie("edge")
        self.assertEqual(tools.commands, [])

    def test_without_a_browser_only_firefox_is_tried_and_the_hint_names_the_clipboard(self):
        tried = []
        self.patch(sleet, "PLATFORM", "win32")
        self.patch(sleet, "BROWSERS", {b: (lambda b=b: tried.append(b) or iter(())) for b in sleet.BROWSERS})
        self.assertDies("for Edge and Chrome copy a request as cURL and add --browser clipboard",
                        sleet.refresh_cookie, None)
        self.assertEqual(tried, ["firefox"])

    def test_config_files_are_read_as_utf_8_whatever_the_code_page(self):
        path = os.path.join(sleet.CONFIG_DIR, "config.json")
        with open(path, "wb") as f:
            f.write('{"done_states": ["Opgelöst", "Geschlossen ✓"]}'.encode("utf-8"))
        self.assertEqual(sleet.read_config(path), {"done_states": ["Opgelöst", "Geschlossen ✓"]})

    @unittest.skipUnless(sleet.yaml, "needs PyYAML")
    def test_yaml_files_are_read_as_utf_8_whatever_the_code_page(self):
        path = os.path.join(sleet.CONFIG_DIR, "config.yaml")
        with open(path, "wb") as f:
            f.write('done_states: ["Opgelöst", "Geschlossen ✓"]\n'.encode("utf-8"))
        self.assertEqual(sleet.read_config(path), {"done_states": ["Opgelöst", "Geschlossen ✓"]})

    def test_no_permission_warning_where_there_are_no_permissions(self):
        self.patch(sleet, "FILE_MODES", False)
        self.write(sleet.COOKIE_FILE, "a=1", mode=0o644)
        sleet.read_cookie()
        self.assertEqual(self.err, "")

    def test_the_prompt_reads_the_console_device_of_the_system(self):
        for system, device in (("win32", "CONIN$"), ("linux", "/dev/tty"), ("darwin", "/dev/tty")):
            with self.subTest(system=system):
                self.patch(sleet, "PLATFORM", system)
                opened = mock.mock_open(read_data="Y\n")
                with mock.patch("builtins.open", opened):
                    self.assertEqual(sleet.ask("Apply?"), "y")
                opened.assert_called_once_with(device)

    def test_the_prompt_without_a_terminal_answers_nothing(self):
        with mock.patch("builtins.open", side_effect=OSError):
            self.assertEqual(sleet.ask("Apply?"), "")

    def picker(self, system, python, script):
        self.patch(sleet, "PLATFORM", system)
        self.patch(sleet.shutil, "which", lambda name: name)
        self.patch(sleet.sys, "executable", python)
        self.patch(sleet.os.path, "realpath", lambda path: script)
        self.patch(sleet, "fetch_tasks", lambda s, a: [])
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 130, "", ""))
        self.patch(sleet.subprocess, "run", run)
        sleet.pick(None, None)
        argv = run.call_args.args[0]
        return argv[argv.index("--preview") + 1], run.call_args.kwargs["env"]

    def test_the_picker_quotes_its_command_for_cmd_exe_on_windows(self):
        preview, env = self.picker("win32", r"C:\Program Files\Python\python.exe", r"C:\Users\A B\sleet.py")
        self.assertEqual(preview, r'"C:\Program Files\Python\python.exe" "C:\Users\A B\sleet.py" {1} -n 3')
        self.assertEqual(env["SLEET_COLOR"], "1")

    def test_the_picker_quotes_its_command_for_a_posix_shell_elsewhere(self):
        preview, env = self.picker("linux", "/opt/my python/bin/python", "/home/a b/sleet.py")
        self.assertEqual(preview, "'/opt/my python/bin/python' '/home/a b/sleet.py' {1} -n 3")
        self.assertEqual(env["SLEET_COLOR"], "1")

    def test_output_that_cannot_be_encoded_never_crashes(self):
        out, err = mock.Mock(), mock.Mock()
        self.patch(sys, "stdout", out)
        self.patch(sys, "stderr", err)
        self.patch(sleet, "main", lambda: None)
        sleet.run()
        out.reconfigure.assert_called_once_with(errors="replace")
        err.reconfigure.assert_called_once_with(errors="replace")

    def test_colours_are_off_when_output_is_not_a_terminal(self):
        self.assertFalse(sleet.ansi_terminal())                # stdout is a StringIO here


if __name__ == "__main__":
    unittest.main()
