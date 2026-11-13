# Sleet: ServiceNow from the terminal

Sleet reads and updates ServiceNow tickets from your terminal. It uses the same REST API as the web UI, authenticated with your own SSO browser session, so it has exactly your permissions and nothing more.

- Read a board of your incidents, problems, changes and tasks, a full ticket view with work notes, or pick tickets interactively with a live preview.
- Write work notes, customer-visible comments and field changes, or apply presets such as "resolve" in one command.

> **Note:** Sleet reuses a browser session cookie. It isn't an official integration. Check that this fits your organization's ServiceNow usage policy before you use it.

## Requirements

- macOS or Linux with Python 3.9 or later.
- Optional: [fzf](https://github.com/junegunn/fzf) for the interactive picker, and `jq` for scripting with `-j`.

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

3. Save your session cookie:
    1. Sign in to ServiceNow in your browser.
    2. Open the developer tools, go to **Network**, and reload the page.
    3. Select any request to your instance and copy the full value of the `Cookie` request header.
    4. Save it:

        ```bash
        pbpaste > ~/.config/sleet/cookie && chmod 600 ~/.config/sleet/cookie   # Linux: xclip -o
        ```

4. Run `sleet -f`. You see a list of your active tickets.

When `sleet` reports that the session expired, repeat step 3.

### Install without pipx or uv

Clone the repository and run the installer. It creates a private virtual environment, writes a `sleet` launcher to `~/bin` (or the directory you pass), and copies the example configuration if you don't have one yet:

```bash
git clone https://github.com/nekocentral/sleet ~/src/sleet
~/src/sleet/install.sh
```

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

Templates hold the fields you always set, such as caller, group, category and impact. `-m`, `--comment`, `--set` and `--assign` work as for updates and override template values. The new number is printed as a link. If ServiceNow refuses the record, `sleet` prints its error, which usually names the missing mandatory field.

`--assign` looks the user up by full name, user name or email. If a name matches more than one active user, `sleet` lists them and stops, so you can pass the user name or email instead.

If a write times out or the connection drops, `sleet` can't tell whether ServiceNow applied it. It says so, and you should check the ticket before you retry.

`--set` takes the technical field name and the *display value* exactly as the form shows it. Labels are case-sensitive. To find a field name, right-click its label on the classic form.

## Configure

All configuration lives in `~/.config/sleet/` (or `$XDG_CONFIG_HOME/sleet/`):

| File | Purpose |
| --- | --- |
| `config.json` | Instance, presets, templates for `--new`, extra fields for the detail view |
| `cookie` | Your session. Treat it as a password. |
| `token` | The session token, cached by `sleet` so commands start faster. Treat it as a password. |
| `sections.json` | Optional: custom board sections, one encoded query each |

### Presets

A preset is a named set of field values plus a notes field. `-r` and `--review` are shortcuts for the presets named `resolve` and `review`. See `config.example.json`:

| Key | Meaning |
| --- | --- |
| `tables` | Optional: tables the preset applies to, for example `["incident"]` |
| `fields` | Field names and display values to set |
| `notes_field` | The field that receives the notes text, `close_notes` by default |
| `hours_field` | The field that receives `--hours` |
| `require_hours` | When `true`, the preset refuses to run without `--hours` |

Any `--set` in the same command overrides a preset value.

### Other settings

| Key | Meaning |
| --- | --- |
| `detail_fields` | Extra fields for the ticket view, as `[field, label]` pairs |
| `hours_field` | The default field for `--hours` when the preset doesn't name one |
| `done_states` | State labels that count as done and are hidden without `-a`. Set this when your instance isn't in English, for example `["Opgelost", "Gesloten"]` |

### Board sections

Without `sections.json`, the board groups tickets by type. With it, every section runs its own encoded query, so you can mirror a team dashboard exactly. Start from `sections.example.json`. To copy a query from a ServiceNow list, right-click the last breadcrumb of its filter and select **Copy query**.

### Environment variables

| Variable | Effect |
| --- | --- |
| `SLEET_INSTANCE` | Overrides `instance` from `config.json` |
| `SLEET_GCK` | Session token, if Sleet can't read it from the page (`g_ck` in the browser console) |
| `XDG_CONFIG_HOME` | Moves the configuration folder |

## Security

- Keep `~/.config/sleet/cookie` private (`chmod 600`). Anyone who has it can act as you until the session expires.
- Writes go to production under your name. Don't use `-y` in scripts that touch many tickets.
- Never commit `cookie`, `token`, `config.json` or `sections.json`. The `.gitignore` excludes them.
- Ticket text is shown with control characters removed, so a ticket can't send escape sequences to your terminal. This also applies to `-j` output.

## License

MIT. See [LICENSE](LICENSE).
