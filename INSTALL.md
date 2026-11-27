# Installing credveil

Written for the agent (or person) wiring credveil into a machine. Steps 1–4 can be done by an
agent; step 5 and every credential value are the operator's. Each step ends with a check.

Requirements: Python 3.11+ (standard library only), `git`, `curl`, OpenSSH (Linux/macOS) or
PuTTY `plink` ≥ 0.75 (Windows; Git Bash provides `bash` for the hooks). Linux and macOS:
`python3`; Windows: `python`.

## 1. Clone as a Claude Code skill

```bash
git clone https://github.com/tomasvitha/credveil ~/.claude/skills/credveil
```

Elsewhere works too (a symlink into `~/.claude/skills/`, or a project's `.claude/skills/`):
the skill-scoped hooks find their own directory. Only the always-on hook in step 3 names the
path, so adjust it there.

**Check:** `python3 ~/.claude/skills/credveil/scripts/credveil.py vendors` lists vendors, and
`cd ~/.claude/skills/credveil && python3 -m unittest discover tests` ends with `OK`.

## 2. Create the configuration

```bash
mkdir -p ~/.config/credveil/creds
cp ~/.claude/skills/credveil/inventory.example.toml ~/.config/credveil/inventory.toml
```

Fill in one `[device.<alias>]` per device: `host`, `vendor` (see `credveil vendors`), `user`,
and the paths of its credential files. `$CREDVEIL_HOME` moves the whole directory. The
inventory holds no secrets, only paths.

Do this before step 3. Once an inventory exists, the always-on guard stops agents from writing
into this directory, and from then on the operator edits it.

**Check:** `credveil list` shows the aliases.

## 3. Wire the always-on guard

Add to `~/.claude/settings.json`, merging into any existing `hooks.PreToolUse` list:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Read|Grep|Edit|Write|MultiEdit|NotebookEdit",
        "hooks": [
          {"type": "command",
           "command": "bash \"$HOME/.claude/skills/credveil/hooks/run-py.sh\" pre home"}
        ]
      }
    ]
  }
}
```

It does exactly three things: credential files stay unread, `$CREDVEIL_HOME` stays unwritten,
and `CREDVEIL_HOME` cannot be overridden in a command. It does not touch device access, so
it adds no friction to unrelated work. The device-access guard and the output net live in
`SKILL.md`'s frontmatter and start when the skill is invoked.

**Check:** in a new session, ask the agent to `cat ~/.config/credveil/inventory.toml`. The
command is blocked with "Blocked by the credveil guard". Reading the file with the Read tool is
allowed, because the inventory holds no secrets.

## 4. Pin the device keys

- **SSH:** `credveil hostkey <alias>` prints the fingerprint. The operator verifies it out of
  band. Then either set `hostkey = "SHA256:…"` in the inventory (plink), or append
  `ssh-keyscan -p <port> <host>` output to `~/.config/credveil/known_hosts` (OpenSSH).
- **REST:** set `tls_pin` to the SPKI hash `sha256//<base64>`, computed with:
  `openssl s_client -connect <host>:443 </dev/null | openssl x509 -pubkey -noout | openssl pkey
  -pubin -outform der | openssl dgst -sha256 -binary | base64`.

## 5. Credentials (operator only)

Put one value per file into `~/.config/credveil/creds/` (for example `fw1.pw`, `fw1.token`).
The source of truth stays in your password manager. An agent must never see or type these
values, and the guard blocks it from reading them.

**Check:** `credveil run <alias> -c '<a harmless show/get command>'` prints masked output, and
stderr ends with `credveil: masked …`.

## Other agent runtimes

Without hooks, the CLI still masks everything that goes through it. Tell the agent to use
`credveil run|get|mask` for device access and raw exports. Hook support for another runtime is
one adapter module next to `credveil/adapters/claude_code.py`, on top of the harness-neutral
`credveil.policy` and `credveil.mask`.

## Updating

```bash
git -C ~/.claude/skills/credveil pull
```
