# Sleet: ServiceNow from the terminal

Sleet reads and updates ServiceNow tickets from your terminal. It uses the same REST API as the web UI, authenticated with your own SSO browser session, so it has exactly your permissions and nothing more.

- Read a board of your incidents, problems, changes and tasks, a full ticket view with work notes, or pick tickets interactively with a live preview.
- Write work notes, customer-visible comments and field changes, or apply presets such as "resolve" in one command.

> **Note:** Sleet reuses a browser session cookie. It isn't an official integration. Check that this fits your organization's ServiceNow usage policy before you use it.

## Requirements

- macOS, Linux or Windows with Python 3.9 or later.
- Optional: [fzf](https://github.com/junegunn/fzf) for the interactive picker, and `jq` for scripting with `-j`.
- Optional: [PyYAML](https://pypi.org/project/PyYAML/), for a [YAML configuration](#yaml-instead-of-json).

## Install

1. Install Sleet with [pipx](https://pipx.pypa.io) or [uv](https://docs.astral.sh/uv/):

    ```bash
    pipx install git+https://github.com/nekocentral/sleet
    # or
    uv tool install git+https://github.com/nekocentral/sleet
    ```

    To update later, run `pipx upgrade sleet` or `uv tool upgrade sleet`.

2. Create the configuration file from the example, and set `instance` to the part of your ServiceNow URL before `.service-now.com`:

    ```bash
    mkdir -p ~/.config/sleet && chmod 700 ~/.config/sleet
    curl -fsSL https://raw.githubusercontent.com/nekocentral/sleet/main/config.example.json \
      -o ~/.config/sleet/config.json
    ```

    On Windows, in PowerShell:

    ```powershell
    New-Item -ItemType Directory -Force "$HOME\.config\sleet" | Out-Null
    Invoke-WebRequest https://raw.githubusercontent.com/nekocentral/sleet/main/config.example.json `
      -OutFile "$HOME\.config\sleet\config.json"
    ```

    To use YAML instead, see [YAML instead of JSON](#yaml-instead-of-json).

3. Sign in to ServiceNow in your browser, and save your session cookie. On macOS with Chrome, Edge or Firefox, and on Windows or Linux with Firefox:

    ```bash
    sleet --refresh-cookie
    ```

    For Edge and Chrome on Windows or Linux, and for Safari, see [Session cookie](#session-cookie).

4. Run `sleet -f`. You see a list of your active tickets.

When `sleet` reports that the session expired, repeat step 3.

### Install without pipx or uv

On macOS and Linux, clone the repository and run the installer. It creates a private virtual environment with `requests` and PyYAML, writes a `sleet` launcher to `~/bin` (or the directory you pass), and copies the example configuration if you don't have one yet:

```bash
git clone https://github.com/nekocentral/sleet ~/src/sleet
~/src/sleet/install.sh
```

## Session cookie

Sleet uses the session of your browser, so when that session expires, you sign in to ServiceNow in your browser again and save the new cookie. `sleet` tells you when this is needed.

| Browser | macOS | Windows and Linux |
| --- | --- | --- |
| Firefox | `sleet --refresh-cookie` | `sleet --refresh-cookie` |
| Chrome, Edge | `sleet --refresh-cookie` | From the clipboard |
| Safari | From the clipboard | Not applicable |

Whichever way the cookie is read, Sleet checks that the session works before it saves anything.

### Read it from the browser

```bash
sleet --refresh-cookie                     # macOS: Chrome, Edge and Firefox in turn. Elsewhere: Firefox
sleet --refresh-cookie --browser firefox   # one browser only
sleet --refresh-cookie -s                  # refresh, then continue with any other command
```

Sleet reads the cookies of your instance from the browser's cookie store. No browser settings are needed: the browsers keep the session on disk while they run.

If Sleet says the session in your browser has expired or isn't saved yet, reload a ServiceNow page in the browser, wait 30 seconds and run the command again. A tab can look signed in after its session has timed out, and browsers write new cookies to disk with a delay.

On macOS, Chrome and Edge encrypt their cookies with a key in your Keychain. The first time, macOS asks whether `security` may use "Chrome Safe Storage" (or "Microsoft Edge Safe Storage"). **Always Allow** stops the question, but then any program that runs as you can read that key. **Allow** asks again at the next refresh.

On Windows, Chrome and Edge keep their cookie file locked and encrypt it with a key that only the browser itself may use. Sleet doesn't work around that protection. Use the clipboard instead.

### Read it from the clipboard

This works with every browser on every system:

1. On a ServiceNow page, open the developer tools (F12, or **Develop** > **Show Web Inspector** in Safari), go to **Network**, and reload the page.
2. Right-click a request to your instance and select **Copy** > **Copy as cURL**. On Windows, **Copy as cURL (bash)**, **Copy as cURL (cmd)** and **Copy as PowerShell** all work.
3. Run:

    ```bash
    sleet --refresh-cookie --browser clipboard
    ```

Sleet takes only the cookie out of what you copied. Text that isn't a copied request or a cookie is refused, and nothing is sent to your instance.

In Safari, turn on the Develop menu first: **Settings** > **Advanced** > **Show features for web developers**. On Linux, the clipboard is read with `wl-paste`, `xclip` or `xsel`, whichever is installed.

### By hand

1. Open the developer tools, go to **Network**, and reload the page.
2. Select any request to your instance and copy the full value of the `Cookie` request header.
3. Save that one line as `~/.config/sleet/cookie`. On macOS and Linux, make it private with `chmod 600 ~/.config/sleet/cookie`.

## Windows notes

- **Install:** use pipx or uv. `install.sh` is for macOS and Linux.
- **Configuration folder:** `%USERPROFILE%\.config\sleet`, the same place as on the other systems.
- **File permissions:** Windows has no `chmod 600`. The cookie file is protected by your user profile folder, so don't move it to a shared location.
- **Terminal:** use Windows Terminal or PowerShell 7 for colours and clickable ticket numbers.
- **Picker:** `sleet -i` needs fzf, for example `winget install fzf`.

## Read tickets

| Command | Shows |
| --- | --- |
| `sleet` | A board grouped by ticket type, assigned to you |
| `sleet -s` | Board counts on one line |
| `sleet -g` | The board for your assignment groups |
| `sleet -u` | Unassigned tickets in your groups |
| `sleet -f` / `sleet -c` | A flat list / changes only |
| `sleet -a` | Include resolved items |
| `sleet -i` | An interactive picker with preview (needs fzf) |
| `sleet INC0012345` | The full ticket, with the last 5 activity entries (`-n 0` for all) |
| `sleet INC0012345 -w` | The ticket in your browser |
| `sleet -j` | JSON output, combinable with the others |

## Update tickets

Every write shows a preview and asks for confirmation. Press `v` to view the full text first. After writing, `sleet` reads the record back and reports any field that ServiceNow didn't accept.

```bash
sleet INC0012345 -m "Work note, internal"
sleet INC0012345 --comment "Customer-visible comment"
sleet INC0012345 --set state="In Progress" --assign me
sleet INC0012345 --assign "Full Name"           # or a user name or email
some_command | sleet INC0012345 -m -            # stdin into a work note
sleet INC0012345 -r "Close notes"               # preset "resolve"
sleet CHG0012345 --review "Close notes" --hours 4
sleet INC0012345 -p mypreset "Notes"            # any preset from config.json
```

### Create tickets

`--new` creates a record from a template in `config.json`, or directly in a table:

```bash
sleet --new inc -t "Short description" --desc "Longer description" --assign me
sleet --new incident -t "Short description" --set caller_id="Full Name" --set category=Network
echo "details" | sleet --new inc -t "Title" --desc -
```

Templates hold the fields you always set, such as caller, group, category and impact. `-m`, `--comment`, `--set` and `--assign` work as for updates and override template values. The new number is printed as a link. If ServiceNow refuses the record, `sleet` prints its error. Most of the time it doesn't refuse: the API accepts records with fields missing that the form requires, so list those under `required` in the template (see [Find fields and build templates](#find-fields-and-build-templates)).

`--assign` looks the user up by full name, user name or email. If a name matches more than one active user, `sleet` lists them and stops, so you can pass the user name or email instead.

If a write times out or the connection drops, `sleet` can't tell whether ServiceNow applied it. It says so, and you should check the ticket before you retry.

`--set` takes the technical field name and the *display value* exactly as the form shows it. Labels are case-sensitive. To find field names and labels, use `--fields`.

## Find fields and build templates

Labels and required fields differ per instance. These commands only read:

| Command | Shows |
| --- | --- |
| `sleet --fields incident` | Every field of the table, with the required ones first |
| `sleet --fields incident impact` | The choices of one field, with the labels to use in `--set` and `config.json` |
| `sleet --template incident` | A template for `--new` with the required fields, to paste under `templates` in `config.json` |

Instead of a table name you can pass a template name from `config.json`. Add `-j` for JSON.

ServiceNow checks most required fields only in the web form, not in the API, so `--new` can create a record that the form would refuse. `--fields` marks a field as required when its definition says "mandatory field", or when a UI policy or data policy requires it "on the form". Policies are only readable with the right roles; a note tells you when they aren't. Put the fields in `required` in a template or preset, and `sleet` stops before writing when one is empty.

A generated template has empty values for you to fill in. Empty values are never sent, and keys that start with `_` are notes.

## Configure

All configuration lives in `~/.config/sleet/` (or `$XDG_CONFIG_HOME/sleet/`):

| File | Purpose |
| --- | --- |
| `config.json` or `config.yaml` | Instance, presets, templates for `--new`, extra fields for the detail view |
| `cookie` | Your session, written by `sleet --refresh-cookie` or by hand. Treat it as a password. |
| `token` | The session token, cached by `sleet` so commands start faster. Treat it as a password. |
| `sections.json` or `sections.yaml` | Optional: custom board sections, one encoded query each |

### YAML instead of JSON

`config.yaml` and `sections.yaml` can replace the JSON files. They hold the same keys, and they allow `#` comments. YAML needs [PyYAML](https://pypi.org/project/PyYAML/), which Sleet doesn't install by default. The installer includes it. With pipx or uv:

```bash
pipx inject sleet pyyaml
# or
uv tool install --with pyyaml git+https://github.com/nekocentral/sleet
```

Start from `config.example.yaml` and `sections.example.yaml`.

- When there is more than one, `config.yaml` comes before `config.yml`, which comes before `config.json`. The same goes for `sections`.
- With a YAML configuration, `sleet --template` prints YAML, indented to paste under `templates:`.
- Quote a display label that YAML reads as a boolean, such as `"Yes"`, `"No"`, `"On"` or `"Off"`. Unquoted, Sleet would send `true` or `false`.

### Templates

A template is the starting point for `--new NAME`. Generate one with `sleet --template TABLE`.

| Key | Meaning |
| --- | --- |
| `table` | The table the record is created in, for example `incident` |
| `fields` | Field names and display values to set |
| `required` | Fields that must have a value, from the template or from `--set`, before `sleet` creates the record |

### Presets

A preset is a named set of field values plus a notes field. `-r` and `--review` are shortcuts for the presets named `resolve` and `review`. See `config.example.json` or `config.example.yaml`:

| Key | Meaning |
| --- | --- |
| `tables` | Optional: tables the preset applies to, for example `["incident"]` |
| `fields` | Field names and display values to set |
| `notes_field` | The field that receives the notes text, `close_notes` by default |
| `hours_field` | The field that receives `--hours` |
| `require_hours` | When `true`, the preset refuses to run without `--hours` |
| `required` | Fields that must have a value before `sleet` writes, for example `["close_code"]` |

Any `--set` in the same command overrides a preset value.

### Other settings

| Key | Meaning |
| --- | --- |
| `detail_fields` | Extra fields for the ticket view, as `[field, label]` pairs |
| `hours_field` | The default field for `--hours` when the preset doesn't name one |
| `done_states` | State labels that count as done and are hidden without `-a`. Set this when your instance isn't in English, for example `["Opgelost", "Gesloten"]` |

### Board sections

Without a sections file, the board groups tickets by type. With it, every section runs its own encoded query, so you can mirror a team dashboard exactly. Start from `sections.example.json` or `sections.example.yaml`. To copy a query from a ServiceNow list, right-click the last breadcrumb of its filter and select **Copy query**.

### Environment variables

| Variable | Effect |
| --- | --- |
| `SLEET_INSTANCE` | Overrides `instance` from the configuration file |
| `SLEET_GCK` | Session token, if Sleet can't read it from the page (`g_ck` in the browser console) |
| `XDG_CONFIG_HOME` | Moves the configuration folder |

## Security

- Keep `~/.config/sleet/cookie` private (`chmod 600`). Anyone who has it can act as you until the session expires.
- `--refresh-cookie` reads only the cookies your browser would send to your instance, sends them only to your instance to check them, and writes the cookie file with `chmod 600`. Chrome and Edge also need access to the browser's key in your Keychain.
- Writes go to production under your name. Don't use `-y` in scripts that touch many tickets.
- Never commit `cookie`, `token`, or your configuration and sections files, JSON or YAML. The `.gitignore` excludes them.
- Ticket text is shown with control characters removed, so a ticket can't send escape sequences to your terminal. This also applies to `-j` output.

## License

MIT. See [LICENSE](LICENSE).
