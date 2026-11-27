# credveil — observed false positives and friction

A queue of input for later tuning. Each entry names the layer, a **synthetic** example (never the
real value), what it cost, and a fix idea. Append when one is seen live;
mark an entry **fixed** with the commit when a rule change and a test close it.

Layers: `secretmask` rule (masks too much), `guard` (blocks a harmless command), `outnet`
(PostToolUse net), tooling (not a mask decision, but friction in using credveil).

## Masking (over-masked, not a credential)

### FP-1 — 32-hex identity in a log field masked as `<hex:N>` (2026-11-27) — **fixed 2026-11-27**
- Layer: `secretmask` generic `LONGHEX_RE` (≥32 hex), applied to JSON values by `mask_json`.
- Seen: FortiAnalyzer VPN log JSON, field `xauthuser` holding a 32-character hex string (a
  SAML/IdP user identifier) → `<hex:32>`.
- Cost: the user behind a VPN session could not be identified; a value in `user`/`xauthuser`
  fields is an identifier, not a secret.
- Fix idea: in `mask_json`, exempt identity keys (`user`, `xauthuser`, `srcuser`, `dstuser`,
  `unauthuser`, `group`, `xauthgroup`) from the generic hex/b64 backstops; keep keyword and PEM
  rules. Alternative: a stable fingerprint (`<hex:32 #a1b2>`) so equal values stay comparable.
  Test: identity field with 32 hex survives; `psksecret`/`key` fields still masked.
- Fix (decision: usernames pass, only secrets and their hashes are masked): `IDENTITY_KEYS` in
  `secretmask.py`. JSON identity values skip the hex/base64 backstops; in text a value right
  after `user=`, `xauthuser=`, `XAUTH user:` etc. does too. PEM, `ENC`, crypt hashes and known
  credentials still apply there. Tests: `test_secretmask.Identity`.

## Guard (blocked a harmless command)

### FP-2 — device name plus "SSH" in prose (2026-11-27) — **fixed 2026-11-27**
- Layer: `guard` `check_command`: an inventory host name (`[guard] hosts`) anywhere in the
  command together with any transport word anywhere, case-insensitive.
- Seen: `git commit` with a message like "<device-name> checked via SSH" → blocked as a direct
  connection.
- Cost: one blocked call, a rewrite through a script file.
- Fix idea: require the transport word in command position (start of the command or after
  `|`, `;`, `&&`, `$(`), not inside quoted strings or heredoc bodies; or skip heredoc bodies
  and `-m`/`-c` message arguments of git. Test: `git commit -m "<host> via SSH"` passes,
  `ssh <host>` and `plink … <host>` still block.
- Fix: transports count only in command position (after env assignments and wrappers,
  `-c`/`-Command` strings checked recursively); quoted text and heredoc bodies are ignored;
  client libraries count only when an interpreter runs. **And the hooks are skill-scoped now**
  (decision: credveil is opt-in and does not police your own git): SKILL.md frontmatter, global
  copies in settings.json retired. Checked in a headless Claude Code run: no block before the
  skill is invoked, block after. Tests: `test_hooks.Guard.test_transport_*`.

## Tooling friction (not a mask decision)

### TF-1 — Git Bash rewrites `/api/v2/…` (2026-11-27) — **fixed 2026-11-27**
`credveil get` rejects `C:/Program Files/Git/api/v2/…` after MSYS path conversion. Documented in
SKILL.md (`MSYS_NO_PATHCONV=1`). Fix idea: `credveil get` detects a path ending in `/api/v2/…` with
a drive prefix and strips it, so the doc line can go.
Fix: `undo_msys_path()` in `credveil.py` (drive prefix + `api/v2/` → `/api/v2/…`, then the usual
prefix/`..`/`?` checks). Checked live from Git Bash without `MSYS_NO_PATHCONV`. Test:
`test_get_undoes_git_bash_path_rewrite`.

### TF-2 — CRLF on Windows stdout (2026-11-27) — **fixed 2026-11-27**
`credveil mask` on Windows writes CRLF, so `diff raw masked` reports every line changed and hides
the real changes. Fix idea: write stdout with `newline=''` / reconfigure to `\n`, keeping the
input's line endings.
Fix (OS-aware endings were considered; the input file decides instead, because a Windows box
also handles LF exports and the diff only stays clean when output matches input): stdout
and stderr never translate newlines; `run`/`get` are LF; `mask` reads with `newline=''` and
writes CRLF only when the input is mostly CRLF. Test: `test_mask_keeps_input_line_endings`.
